use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::Notify,
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    Saturated,
    Cancelled,
    Deadline,
    Draining,
}

#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub child: String,
    pub child_limit: usize,
    pub tool: String,
    pub tool_limit: usize,
}

struct Pending {
    id: u64,
    spec: RequestSpec,
}
struct State {
    next_id: u64,
    queue: VecDeque<Pending>,
    global_active: usize,
    child_active: BTreeMap<String, usize>,
    tool_active: BTreeMap<String, usize>,
}

pub struct Coordinator {
    global_limit: usize,
    queue_limit: usize,
    wait: Duration,
    open: AtomicBool,
    state: Mutex<State>,
    notify: Notify,
}

pub struct Lease {
    coordinator: Arc<Coordinator>,
    child: String,
    tool: String,
}

impl Coordinator {
    pub fn new(global_limit: usize, queue_limit: usize, wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            global_limit,
            queue_limit,
            wait,
            open: AtomicBool::new(true),
            state: Mutex::new(State {
                next_id: 0,
                queue: VecDeque::new(),
                global_active: 0,
                child_active: BTreeMap::new(),
                tool_active: BTreeMap::new(),
            }),
            notify: Notify::new(),
        })
    }

    pub async fn acquire(
        self: &Arc<Self>,
        spec: RequestSpec,
        cancelled: CancellationToken,
    ) -> Result<Lease, AdmissionError> {
        let id = {
            let mut state = self.state.lock().expect("request coordinator poisoned");
            if !self.open.load(Ordering::Acquire) {
                return Err(AdmissionError::Draining);
            }
            if state.queue.len() >= self.queue_limit {
                return Err(AdmissionError::Saturated);
            }
            let id = state.next_id;
            state.next_id += 1;
            state.queue.push_back(Pending {
                id,
                spec: spec.clone(),
            });
            id
        };
        let deadline = Instant::now() + self.wait;
        loop {
            let notified = self.notify.notified();
            if !self.open.load(Ordering::Acquire) {
                self.remove(id);
                return Err(AdmissionError::Draining);
            }
            if let Some(lease) = self.try_dispatch(id) {
                return Ok(lease);
            }
            tokio::select! {
                _ = cancelled.cancelled() => { self.remove(id); return Err(AdmissionError::Cancelled); }
                _ = sleep(deadline.saturating_duration_since(Instant::now())) => { self.remove(id); return Err(AdmissionError::Deadline); }
                _ = notified => {}
            }
        }
    }

    fn try_dispatch(self: &Arc<Self>, id: u64) -> Option<Lease> {
        let mut state = self.state.lock().expect("request coordinator poisoned");
        if !self.open.load(Ordering::Acquire) {
            return None;
        }
        let selected = state.queue.iter().position(|pending| {
            state.global_active < self.global_limit
                && state
                    .child_active
                    .get(&pending.spec.child)
                    .copied()
                    .unwrap_or(0)
                    < pending.spec.child_limit
                && state
                    .tool_active
                    .get(&pending.spec.tool)
                    .copied()
                    .unwrap_or(0)
                    < pending.spec.tool_limit
        })?;
        if state.queue[selected].id != id {
            return None;
        }
        let pending = state.queue.remove(selected)?;
        state.global_active += 1;
        *state
            .child_active
            .entry(pending.spec.child.clone())
            .or_default() += 1;
        *state
            .tool_active
            .entry(pending.spec.tool.clone())
            .or_default() += 1;
        Some(Lease {
            coordinator: Arc::clone(self),
            child: pending.spec.child,
            tool: pending.spec.tool,
        })
    }

    fn remove(&self, id: u64) {
        self.state
            .lock()
            .expect("request coordinator poisoned")
            .queue
            .retain(|pending| pending.id != id);
        self.notify.notify_waiters();
    }
    fn release(&self, child: &str, tool: &str) {
        let mut state = self.state.lock().expect("request coordinator poisoned");
        state.global_active -= 1;
        let count = state
            .child_active
            .get_mut(child)
            .expect("leased child must be active");
        *count -= 1;
        if *count == 0 {
            state.child_active.remove(child);
        }
        let count = state
            .tool_active
            .get_mut(tool)
            .expect("leased tool must be active");
        *count -= 1;
        if *count == 0 {
            state.tool_active.remove(tool);
        }
        drop(state);
        self.notify.notify_waiters();
    }
    pub fn queued(&self) -> usize {
        self.state
            .lock()
            .expect("request coordinator poisoned")
            .queue
            .len()
    }

    pub fn active(&self) -> usize {
        self.state
            .lock()
            .expect("request coordinator poisoned")
            .global_active
    }

    pub fn close_admission(&self) {
        self.open.store(false, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn open_admission(&self) {
        self.open.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_accepting(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .state
                .lock()
                .expect("request coordinator poisoned")
                .global_active
                == 0
            {
                return true;
            }
            let notified = self.notify.notified();
            if tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), notified)
                .await
                .is_err()
            {
                return false;
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.coordinator.release(&self.child, &self.tool);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(child: &str) -> RequestSpec {
        spec_with_limits(child, "tool", 1, 1)
    }

    fn spec_with_limits(
        child: &str,
        tool: &str,
        child_limit: usize,
        tool_limit: usize,
    ) -> RequestSpec {
        RequestSpec {
            child: child.into(),
            child_limit,
            tool: format!("{child}:{tool}"),
            tool_limit,
        }
    }

    #[tokio::test]
    async fn cancellation_before_admission_never_leases() {
        let coordinator = Coordinator::new(1, 1, Duration::from_secs(1));
        let first = coordinator
            .acquire(spec("a"), CancellationToken::new())
            .await
            .unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            coordinator.acquire(spec("a"), cancelled).await,
            Err(AdmissionError::Cancelled)
        ));
        assert_eq!(coordinator.queued(), 0);
        drop(first);
    }

    #[tokio::test]
    async fn queued_cancellation_never_dispatches_after_capacity_returns() {
        let coordinator = Coordinator::new(1, 2, Duration::from_secs(1));
        let first = coordinator
            .acquire(spec("a"), CancellationToken::new())
            .await
            .unwrap();
        let cancelled = CancellationToken::new();
        let waiting_coordinator = Arc::clone(&coordinator);
        let waiting_cancelled = cancelled.clone();
        let waiting = tokio::spawn(async move {
            waiting_coordinator
                .acquire(spec("a"), waiting_cancelled)
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(coordinator.queued(), 1);
        cancelled.cancel();
        assert!(matches!(
            waiting.await.unwrap(),
            Err(AdmissionError::Cancelled)
        ));
        assert_eq!(coordinator.queued(), 0);
        assert_eq!(coordinator.active(), 1);
        drop(first);
        assert_eq!(coordinator.active(), 0);
    }

    #[tokio::test]
    async fn saturated_and_expired_queue_entries_never_lease() {
        let coordinator = Coordinator::new(1, 1, Duration::from_millis(20));
        let first = coordinator
            .acquire(spec("a"), CancellationToken::new())
            .await
            .unwrap();
        let waiting_coordinator = Arc::clone(&coordinator);
        let waiting = tokio::spawn(async move {
            waiting_coordinator
                .acquire(spec("a"), CancellationToken::new())
                .await
        });
        tokio::task::yield_now().await;
        assert!(matches!(
            coordinator
                .acquire(spec("b"), CancellationToken::new())
                .await,
            Err(AdmissionError::Saturated)
        ));
        assert!(matches!(
            waiting.await.unwrap(),
            Err(AdmissionError::Deadline)
        ));
        assert_eq!(coordinator.queued(), 0);
        assert_eq!(coordinator.active(), 1);
        drop(first);
    }

    #[tokio::test]
    async fn later_eligible_child_bypasses_blocked_head() {
        let coordinator = Coordinator::new(2, 4, Duration::from_secs(1));
        let first = coordinator
            .acquire(spec("a"), CancellationToken::new())
            .await
            .unwrap();
        let blocked = Arc::clone(&coordinator);
        tokio::spawn(async move { blocked.acquire(spec("a"), CancellationToken::new()).await });
        tokio::task::yield_now().await;
        let other = coordinator
            .acquire(spec("b"), CancellationToken::new())
            .await
            .unwrap();
        drop(other);
        drop(first);
    }

    #[tokio::test]
    async fn closed_admission_rejects_new_requests() {
        let coordinator = Coordinator::new(1, 1, Duration::from_secs(1));
        coordinator.close_admission();
        assert!(matches!(
            coordinator
                .acquire(spec("a"), CancellationToken::new(),)
                .await,
            Err(AdmissionError::Draining)
        ));
        assert_eq!(coordinator.queued(), 0);
    }

    #[tokio::test]
    async fn drain_rejects_mixed_reads_and_mutations_until_dispatched_work_finishes() {
        let coordinator = Coordinator::new(1, 2, Duration::from_secs(1));
        let mutation = coordinator
            .acquire(
                spec_with_limits("filesystem", "write_text_file", 1, 1),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        coordinator.close_admission();

        for tool in ["read_text_file", "write_text_file"] {
            assert!(matches!(
                coordinator
                    .acquire(
                        spec_with_limits("filesystem", tool, 1, 1),
                        CancellationToken::new(),
                    )
                    .await,
                Err(AdmissionError::Draining)
            ));
        }
        assert!(!coordinator.wait_idle(Duration::from_millis(1)).await);
        drop(mutation);
        assert!(coordinator.wait_idle(Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn wait_idle_waits_for_dispatched_work() {
        let coordinator = Coordinator::new(1, 1, Duration::from_secs(1));
        let lease = coordinator
            .acquire(spec("a"), CancellationToken::new())
            .await
            .unwrap();
        assert!(!coordinator.wait_idle(Duration::from_millis(1)).await);
        drop(lease);
        assert!(coordinator.wait_idle(Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn per_tool_limit_does_not_block_another_tool_in_same_child() {
        let coordinator = Coordinator::new(2, 4, Duration::from_secs(1));
        let first = coordinator
            .acquire(
                spec_with_limits("a", "first", 2, 1),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let other = coordinator
            .acquire(
                spec_with_limits("a", "second", 2, 1),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let blocked = Arc::clone(&coordinator);
        let waiting = tokio::spawn(async move {
            blocked
                .acquire(
                    spec_with_limits("a", "first", 2, 1),
                    CancellationToken::new(),
                )
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(coordinator.queued(), 1);
        drop(first);
        let third = waiting.await.unwrap().unwrap();
        drop(third);
        drop(other);
    }

    #[tokio::test]
    async fn bounded_scheduler_soak_releases_all_capacity_without_leaks() {
        const GLOBAL_LIMIT: usize = 8;
        const QUEUE_LIMIT: usize = 32;
        const BATCH: usize = GLOBAL_LIMIT + QUEUE_LIMIT;
        const ROUNDS: usize = 100;

        let coordinator = Coordinator::new(GLOBAL_LIMIT, QUEUE_LIMIT, Duration::from_secs(2));

        for round in 0..ROUNDS {
            let mut tasks = Vec::with_capacity(BATCH);
            for index in 0..BATCH {
                let coordinator = Arc::clone(&coordinator);
                tasks.push(tokio::spawn(async move {
                    let child = format!("child-{}", index % 4);
                    let tool = format!("tool-{}", index % 8);
                    let lease = coordinator
                        .acquire(
                            spec_with_limits(&child, &tool, GLOBAL_LIMIT, GLOBAL_LIMIT),
                            CancellationToken::new(),
                        )
                        .await
                        .expect("bounded soak admission should fit active + queue capacity");

                    assert!(coordinator.active() <= GLOBAL_LIMIT);
                    assert!(coordinator.queued() <= QUEUE_LIMIT);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    drop(lease);
                }));
            }

            for task in tasks {
                task.await.expect("bounded soak task must finish");
            }

            assert_eq!(
                coordinator.active(),
                0,
                "round {round} leaked active scheduler capacity"
            );
            assert_eq!(
                coordinator.queued(),
                0,
                "round {round} leaked queued scheduler capacity"
            );
        }

        assert!(coordinator.is_accepting());
        assert!(coordinator.wait_idle(Duration::from_secs(1)).await);
    }
}
