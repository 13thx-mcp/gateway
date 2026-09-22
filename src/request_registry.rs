use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use uuid::Uuid;

const MAX_ACTIVE_REQUESTS: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Dispatched,
    Pending,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct View {
    pub request_id: String,
    pub child: String,
    pub tool: String,
    pub phase: Phase,
    pub child_request_id: Option<String>,
    pub started_at_ms: u128,
}

pub struct Registry {
    active: Mutex<BTreeMap<String, View>>,
}

pub struct Ticket {
    registry: Arc<Registry>,
    request_id: String,
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn begin(self: &Arc<Self>, child: String, tool: String) -> Option<Ticket> {
        let mut active = self.active.lock().expect("request registry poisoned");
        if active.len() >= MAX_ACTIVE_REQUESTS {
            return None;
        }
        let request_id = Uuid::new_v4().to_string();
        active.insert(
            request_id.clone(),
            View {
                request_id: request_id.clone(),
                child,
                tool,
                phase: Phase::Queued,
                child_request_id: None,
                started_at_ms: now_ms(),
            },
        );
        Some(Ticket {
            registry: Arc::clone(self),
            request_id,
        })
    }

    pub fn active(&self) -> Vec<View> {
        self.active
            .lock()
            .expect("request registry poisoned")
            .values()
            .cloned()
            .collect()
    }
}

impl Ticket {
    pub fn id(&self) -> &str {
        &self.request_id
    }

    pub fn dispatched(&self, child_request_id: String) {
        self.update(Phase::Dispatched, Some(child_request_id));
    }

    pub fn pending(&self) {
        self.update(Phase::Pending, None);
    }

    fn update(&self, phase: Phase, child_request_id: Option<String>) {
        if let Some(entry) = self
            .registry
            .active
            .lock()
            .expect("request registry poisoned")
            .get_mut(&self.request_id)
        {
            entry.phase = phase;
            if child_request_id.is_some() {
                entry.child_request_id = child_request_id;
            }
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.registry
            .active
            .lock()
            .expect("request registry poisoned")
            .remove(&self.request_id);
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_only_active_requests_with_generated_correlation_ids() {
        let registry = Registry::new();
        let ticket = registry
            .begin("filesystem".into(), "read_text_file".into())
            .unwrap();
        let id = ticket.id().to_owned();
        assert!(Uuid::parse_str(&id).is_ok());
        assert_eq!(registry.active()[0].phase, Phase::Queued);
        ticket.dispatched("child-42".into());
        ticket.pending();
        let view = registry.active().pop().unwrap();
        assert_eq!(view.request_id, id);
        assert_eq!(view.child_request_id.as_deref(), Some("child-42"));
        assert_eq!(view.phase, Phase::Pending);
        drop(ticket);
        assert!(registry.active().is_empty());
    }
}
