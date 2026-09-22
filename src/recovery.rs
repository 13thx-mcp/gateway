use serde::Serialize;

use crate::policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Healthy,
    BackingOff,
    Restarting,
    CircuitOpen,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub max_attempts: usize,
    pub stability_window_ms: u64,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub cooldown_ms: u64,
}

impl From<&policy::Restart> for Policy {
    fn from(value: &policy::Restart) -> Self {
        Self {
            max_attempts: value.max_attempts,
            stability_window_ms: value.stability_window_ms,
            initial_backoff_ms: value.backoff.initial_ms,
            max_backoff_ms: value.backoff.max_ms,
            cooldown_ms: value.circuit.cooldown_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChildRecovery {
    generation: u64,
    consecutive_failures: usize,
    state: State,
    retry_at_ms: Option<u64>,
    healthy_since_ms: Option<u64>,
}

impl Default for ChildRecovery {
    fn default() -> Self {
        Self {
            generation: 0,
            consecutive_failures: 0,
            state: State::Restarting,
            retry_at_ms: None,
            healthy_since_ms: None,
        }
    }
}

impl ChildRecovery {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }

    pub fn retry_at_ms(&self) -> Option<u64> {
        self.retry_at_ms
    }

    pub fn promote_candidate(&mut self, now_ms: u64) {
        self.generation += 1;
        self.state = State::Healthy;
        self.retry_at_ms = None;
        self.healthy_since_ms = Some(now_ms);
    }

    pub fn reset_if_stable(&mut self, now_ms: u64, policy: Policy) {
        if self.state == State::Healthy
            && self
                .healthy_since_ms
                .is_some_and(|since| now_ms.saturating_sub(since) >= policy.stability_window_ms)
        {
            self.consecutive_failures = 0;
        }
    }

    pub fn failure(&mut self, now_ms: u64, policy: Policy) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.healthy_since_ms = None;
        if self.consecutive_failures >= policy.max_attempts {
            self.state = State::CircuitOpen;
            self.retry_at_ms = Some(now_ms.saturating_add(policy.cooldown_ms));
            return;
        }
        self.state = State::BackingOff;
        self.retry_at_ms =
            Some(now_ms.saturating_add(backoff_delay(self.consecutive_failures, policy)));
    }

    pub fn begin_due_recovery(&mut self, now_ms: u64) -> bool {
        match self.state {
            State::BackingOff if self.retry_at_ms.is_some_and(|retry| now_ms >= retry) => {
                self.state = State::Restarting;
                true
            }
            State::CircuitOpen if self.retry_at_ms.is_some_and(|retry| now_ms >= retry) => {
                self.state = State::HalfOpen;
                true
            }
            _ => false,
        }
    }
}

pub fn backoff_delay(attempt: usize, policy: Policy) -> u64 {
    let exponent = attempt.saturating_sub(1).min(63) as u32;
    policy
        .initial_backoff_ms
        .saturating_mul(2u64.saturating_pow(exponent))
        .min(policy.max_backoff_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            max_attempts: 3,
            stability_window_ms: 30_000,
            initial_backoff_ms: 500,
            max_backoff_ms: 30_000,
            cooldown_ms: 60_000,
        }
    }

    #[test]
    fn bounded_backoff_opens_circuit_after_three_failures() {
        let mut recovery = ChildRecovery::default();
        recovery.failure(0, policy());
        assert_eq!(recovery.retry_at_ms(), Some(500));
        recovery.failure(500, policy());
        assert_eq!(recovery.retry_at_ms(), Some(1500));
        recovery.failure(1500, policy());
        assert_eq!(recovery.state(), State::CircuitOpen);
        assert_eq!(recovery.retry_at_ms(), Some(61_500));
    }

    #[test]
    fn circuit_allows_one_half_open_attempt_after_cooldown() {
        let mut recovery = ChildRecovery::default();
        for now in [0, 500, 1500] {
            recovery.failure(now, policy());
        }
        assert!(!recovery.begin_due_recovery(61_499));
        assert!(recovery.begin_due_recovery(61_500));
        assert_eq!(recovery.state(), State::HalfOpen);
        assert!(!recovery.begin_due_recovery(61_500));
    }

    #[test]
    fn only_stable_health_resets_failure_episode() {
        let mut recovery = ChildRecovery::default();
        recovery.failure(0, policy());
        recovery.promote_candidate(500);
        recovery.reset_if_stable(30_499, policy());
        assert_eq!(recovery.consecutive_failures(), 1);
        recovery.reset_if_stable(30_500, policy());
        assert_eq!(recovery.consecutive_failures(), 0);
    }

    #[test]
    fn one_child_crash_loop_does_not_change_healthy_sibling_generation() {
        let mut failed_child = ChildRecovery::default();
        let mut healthy_sibling = ChildRecovery::default();
        failed_child.promote_candidate(0);
        healthy_sibling.promote_candidate(0);
        let sibling_generation = healthy_sibling.generation();

        for now in [1, 501, 1_501] {
            failed_child.failure(now, policy());
        }

        assert_eq!(failed_child.state(), State::CircuitOpen);
        assert_eq!(healthy_sibling.state(), State::Healthy);
        assert_eq!(healthy_sibling.generation(), sibling_generation);
        healthy_sibling.reset_if_stable(30_000, policy());
        assert_eq!(healthy_sibling.generation(), sibling_generation);
    }
}
