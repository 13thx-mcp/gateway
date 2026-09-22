use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

const MAX_EVENTS: usize = 256;
const MAX_BATCH_EVENTS: usize = 16;

/// M7 history boundary: values here are safe observation identifiers and scalar
/// measurements only. Tool arguments, results, credentials, paths, and artifact
/// data do not have a representation in this DTO.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Event {
    pub sequence: u64,
    pub observed_at_ms: u128,
    #[serde(flatten)]
    pub observation: Observation,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation {
    Request {
        request_id: String,
        child: String,
        tool: String,
        outcome: RequestOutcome,
        queue_ms: u64,
        execution_ms: u64,
        response_bytes: usize,
        guard: GuardAction,
        catalog_generation: u64,
        profile_generation: u64,
    },
    Catalog {
        catalog_generation: u64,
        profile_generation: u64,
        catalog_fingerprint: String,
        profile_fingerprint: String,
    },
    ChildRecovery {
        child: String,
        state: RecoveryState,
        generation: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RequestObservation {
    pub child: String,
    pub tool: String,
    pub outcome: RequestOutcome,
    pub queue_ms: u64,
    pub execution_ms: u64,
    pub response_bytes: usize,
    pub guard: GuardAction,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestOutcome {
    Returned,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardAction {
    NotApplied,
    Passed,
    Guarded,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Restarting,
    CircuitOpen,
    HalfOpen,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Batch {
    pub first_available_sequence: u64,
    pub last_sequence: u64,
    pub events: Vec<Event>,
}

pub struct Store {
    state: Mutex<State>,
}

struct State {
    next_sequence: u64,
    events: VecDeque<Event>,
}

impl Store {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                next_sequence: 1,
                events: VecDeque::with_capacity(MAX_EVENTS),
            }),
        })
    }

    pub fn record(&self, observation: Observation) {
        let mut state = self.state.lock().expect("telemetry state poisoned");
        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.saturating_add(1);
        if state.events.len() == MAX_EVENTS {
            state.events.pop_front();
        }
        state.events.push_back(Event {
            sequence,
            observed_at_ms: now_ms(),
            observation,
        });
    }

    pub fn after(&self, after_sequence: u64) -> Batch {
        let state = self.state.lock().expect("telemetry state poisoned");
        let first_available_sequence = state
            .events
            .front()
            .map(|event| event.sequence)
            .unwrap_or(state.next_sequence);
        let events = state
            .events
            .iter()
            .filter(|event| event.sequence > after_sequence)
            .take(MAX_BATCH_EVENTS)
            .cloned()
            .collect::<Vec<_>>();
        let last_sequence = events
            .last()
            .map(|event| event.sequence)
            .unwrap_or(after_sequence.min(state.next_sequence.saturating_sub(1)));
        Batch {
            first_available_sequence,
            last_sequence,
            events,
        }
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
    fn bounded_batch_contains_only_sanitized_fields() {
        let store = Store::new();
        store.record(Observation::Request {
            request_id: "request-1".into(),
            child: "filesystem".into(),
            tool: "read_text_file".into(),
            outcome: RequestOutcome::Returned,
            queue_ms: 4,
            execution_ms: 12,
            response_bytes: 28,
            guard: GuardAction::Passed,
            catalog_generation: 2,
            profile_generation: 3,
        });
        let json = serde_json::to_string(&store.after(0)).unwrap();
        assert!(json.contains("read_text_file"));
        assert!(!json.contains("arguments"));
        assert!(!json.contains("result"));
        assert_eq!(store.after(1).events.len(), 0);
    }

    #[test]
    fn retention_is_bounded_and_reports_gap() {
        let store = Store::new();
        for _ in 0..=MAX_EVENTS {
            store.record(Observation::Catalog {
                catalog_generation: 1,
                profile_generation: 1,
                catalog_fingerprint: "a".repeat(64),
                profile_fingerprint: "b".repeat(64),
            });
        }
        let batch = store.after(241);
        assert_eq!(batch.events.len(), MAX_BATCH_EVENTS);
        assert_eq!(batch.first_available_sequence, 2);
        assert_eq!(batch.last_sequence, 257);
    }
}
