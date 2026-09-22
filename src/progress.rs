use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rmcp::{
    ClientHandler,
    model::{NumberOrString, ProgressNotificationParam, ProgressToken},
    service::{NotificationContext, Peer, RoleServer},
};
use uuid::Uuid;

const MAX_ACTIVE_PROGRESS: usize = 256;
const MAX_PROGRESS_MESSAGE_BYTES: usize = 256;

pub struct Relay {
    upstream: Mutex<Option<Peer<RoleServer>>>,
    mappings: Mutex<HashMap<ProgressToken, ProgressToken>>,
}

pub struct Lease {
    relay: Arc<Relay>,
    child_token: ProgressToken,
}

pub struct Client {
    relay: Arc<Relay>,
}

impl Relay {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            upstream: Mutex::new(None),
            mappings: Mutex::new(HashMap::new()),
        })
    }

    pub fn client(self: &Arc<Self>) -> Client {
        Client {
            relay: Arc::clone(self),
        }
    }

    pub fn set_upstream(&self, peer: Peer<RoleServer>) {
        *self.upstream.lock().expect("progress upstream poisoned") = Some(peer);
    }

    pub fn register(self: &Arc<Self>, upstream_token: ProgressToken) -> Option<Lease> {
        let mut mappings = self.mappings.lock().expect("progress mappings poisoned");
        if mappings.len() >= MAX_ACTIVE_PROGRESS {
            return None;
        }
        let child_token = ProgressToken(NumberOrString::String(
            format!("gateway-{}", Uuid::new_v4()).into(),
        ));
        mappings.insert(child_token.clone(), upstream_token);
        Some(Lease {
            relay: Arc::clone(self),
            child_token,
        })
    }

    pub async fn forward(&self, mut notification: ProgressNotificationParam) {
        let Some(upstream_token) = self
            .mappings
            .lock()
            .expect("progress mappings poisoned")
            .get(&notification.progress_token)
            .cloned()
        else {
            return;
        };
        notification.progress_token = upstream_token;
        notification.meta = None;
        notification.message = notification.message.map(|message| truncate(&message));
        let peer = self
            .upstream
            .lock()
            .expect("progress upstream poisoned")
            .clone();
        if let Some(peer) = peer
            && let Err(error) = peer.notify_progress(notification).await
        {
            tracing::debug!(%error, "failed to forward child progress notification");
        }
    }
}

impl Lease {
    pub fn child_token(&self) -> ProgressToken {
        self.child_token.clone()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.relay
            .mappings
            .lock()
            .expect("progress mappings poisoned")
            .remove(&self.child_token);
    }
}

impl ClientHandler for Client {
    fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        _context: NotificationContext<rmcp::service::RoleClient>,
    ) -> impl std::future::Future<Output = ()> + rmcp::service::MaybeSendFuture + '_ {
        self.relay.forward(notification)
    }
}

fn truncate(value: &str) -> String {
    let mut end = value.len().min(MAX_PROGRESS_MESSAGE_BYTES);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_child_token_is_distinct_and_drop_removes_mapping() {
        let relay = Relay::new();
        let upstream = ProgressToken(NumberOrString::String("client-token".into()));
        let lease = relay.register(upstream).unwrap();
        assert_ne!(
            lease.child_token(),
            ProgressToken(NumberOrString::String("client-token".into()))
        );
        assert_eq!(relay.mappings.lock().unwrap().len(), 1);
        drop(lease);
        assert!(relay.mappings.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_message_is_bounded_without_changing_utf8() {
        let message = "é".repeat(200);
        let bounded = truncate(&message);
        assert!(bounded.len() <= MAX_PROGRESS_MESSAGE_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
    }
}
