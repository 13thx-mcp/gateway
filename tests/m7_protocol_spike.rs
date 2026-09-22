use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rmcp::{
    ClientHandler, ErrorData as McpError, RoleClient, RoleServer, ServerHandler, ServiceError,
    ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ClientRequest, ContentBlock,
        ListResourcesResult, PaginatedRequestParams, ProgressNotificationParam, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Request, RequestId,
        Resource, ResourceContents, ServerCapabilities, ServerConfig,
    },
    service::{
        ClientLifecycleMode, ClientServiceExt, PeerRequestOptions, RequestContext, RunningService,
    },
};
use tokio::sync::Notify;

#[derive(Clone, Default)]
struct ProbeState {
    started: Arc<Notify>,
    cancelled: Arc<Notify>,
    completed: Arc<Notify>,
    calls: Arc<AtomicUsize>,
    cancellations: Arc<AtomicUsize>,
    completions: Arc<AtomicUsize>,
    request_ids: Arc<Mutex<Vec<RequestId>>>,
    protocol_versions: Arc<Mutex<Vec<Option<String>>>>,
}

#[derive(Clone)]
struct ProbeServer {
    state: ProbeState,
    work_duration: Duration,
    emit_progress: bool,
}

impl ProbeServer {
    fn new(state: ProbeState, work_duration: Duration) -> Self {
        Self {
            state,
            work_duration,
            emit_progress: false,
        }
    }

    fn with_progress(mut self) -> Self {
        self.emit_progress = true;
        self
    }
}

impl ServerHandler for ProbeServer {
    #[allow(deprecated)]
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.state.calls.fetch_add(1, Ordering::SeqCst);
        self.state
            .request_ids
            .lock()
            .expect("request_ids mutex poisoned")
            .push(context.id.clone());
        self.state
            .protocol_versions
            .lock()
            .expect("protocol_versions mutex poisoned")
            .push(
                context
                    .protocol_version()
                    .map(|version| version.as_str().to_owned()),
            );
        self.state.started.notify_one();

        if self.emit_progress
            && let Some(token) = context.meta.get_progress_token()
        {
            context
                .peer
                .notify_progress(
                    ProgressNotificationParam::new(token, 1.0)
                        .with_total(2.0)
                        .with_message("probe-progress"),
                )
                .await
                .map_err(|error| McpError::internal_error(error.to_string(), None))?;
        }

        tokio::select! {
            _ = context.ct.cancelled() => {
                self.state.cancellations.fetch_add(1, Ordering::SeqCst);
                self.state.cancelled.notify_one();
                Ok(CallToolResult::success(vec![ContentBlock::text("cancelled")]).into())
            }
            _ = tokio::time::sleep(self.work_duration) => {
                self.state.completions.fetch_add(1, Ordering::SeqCst);
                self.state.completed.notify_one();
                Ok(CallToolResult::success(vec![ContentBlock::text("completed")]).into())
            }
        }
    }
}

#[derive(Clone, Default)]
struct ProgressClient {
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
    received: Arc<Notify>,
}

impl ClientHandler for ProgressClient {
    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) {
        self.progress
            .lock()
            .expect("progress mutex poisoned")
            .push(params);
        self.received.notify_one();
    }
}

async fn start_pair<C>(
    server: ProbeServer,
    client: C,
) -> anyhow::Result<RunningService<RoleClient, C>>
where
    C: ClientHandler,
{
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
    tokio::spawn(async move {
        let service = server.serve(server_transport).await?;
        service.waiting().await?;
        anyhow::Ok(())
    });

    Ok(client.serve(client_transport).await?)
}

#[derive(Clone, Default)]
struct ResourceProbeServer;

impl ServerHandler for ResourceProbeServer {
    #[allow(deprecated)]
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_resources().build())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![Resource::new(
            "gateway://status",
            "gateway-status",
        )]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if request.uri != "gateway://status" {
            return Err(McpError::resource_not_found("unknown resource", None));
        }
        Ok(ReadResourceResult::new(vec![ResourceContents::text("ready", request.uri)]).into())
    }
}

async fn start_resource_pair() -> anyhow::Result<RunningService<RoleClient, ()>> {
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
    tokio::spawn(async move {
        let service = ResourceProbeServer.serve(server_transport).await?;
        service.waiting().await?;
        anyhow::Ok(())
    });

    Ok(().serve(client_transport).await?)
}

fn call_request(name: &str) -> ClientRequest {
    ClientRequest::CallToolRequest(Request::new(CallToolRequestParams::new(name.to_owned())))
}

#[tokio::test]
async fn outer_timeout_drops_waiter_but_does_not_cancel_dispatched_child_call() -> anyhow::Result<()>
{
    let state = ProbeState::default();
    let client = start_pair(
        ProbeServer::new(state.clone(), Duration::from_millis(180)),
        (),
    )
    .await?;

    let result = tokio::time::timeout(
        Duration::from_millis(40),
        client.peer().call_tool(CallToolRequestParams::new("probe")),
    )
    .await;

    assert!(
        result.is_err(),
        "the outer timeout should expire before the child responds"
    );
    tokio::time::timeout(Duration::from_secs(1), state.completed.notified())
        .await
        .expect("child should continue to completion after the caller stops waiting");

    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.cancellations.load(Ordering::SeqCst), 0);
    assert_eq!(state.completions.load(Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn explicit_request_handle_cancel_reaches_child_request_context() -> anyhow::Result<()> {
    let state = ProbeState::default();
    let client = start_pair(ProbeServer::new(state.clone(), Duration::from_secs(30)), ()).await?;

    let handle = client
        .send_cancellable_request(call_request("probe"), PeerRequestOptions::no_options())
        .await?;

    tokio::time::timeout(Duration::from_secs(1), state.started.notified())
        .await
        .expect("child should start before cancellation");

    let child_request_id = handle.id.clone();
    handle.cancel(Some("m7 protocol spike".to_owned())).await?;

    tokio::time::timeout(Duration::from_secs(1), state.cancelled.notified())
        .await
        .expect("explicit cancellation should reach RequestContext::ct");

    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(
        state
            .request_ids
            .lock()
            .expect("request_ids mutex poisoned")
            .as_slice(),
        &[child_request_id]
    );

    Ok(())
}

#[tokio::test]
async fn rmcp_owned_request_timeout_sends_cancel_notification_to_child() -> anyhow::Result<()> {
    let state = ProbeState::default();
    let client = start_pair(ProbeServer::new(state.clone(), Duration::from_secs(30)), ()).await?;

    let handle = client
        .send_cancellable_request(
            call_request("probe"),
            PeerRequestOptions::with_timeout(Duration::from_millis(50)),
        )
        .await?;

    let response = handle.await_response().await;
    assert!(matches!(response, Err(ServiceError::Timeout { .. })));

    tokio::time::timeout(Duration::from_secs(1), state.cancelled.notified())
        .await
        .expect("rmcp timeout should emit notifications/cancelled");

    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(state.completions.load(Ordering::SeqCst), 0);

    Ok(())
}

#[tokio::test]
async fn request_context_exposes_request_identity_and_negotiated_protocol() -> anyhow::Result<()> {
    let state = ProbeState::default();
    let client = start_pair(
        ProbeServer::new(state.clone(), Duration::from_millis(1)),
        (),
    )
    .await?;

    client
        .peer()
        .call_tool(CallToolRequestParams::new("probe"))
        .await?;

    let ids = state
        .request_ids
        .lock()
        .expect("request_ids mutex poisoned")
        .clone();
    let versions = state
        .protocol_versions
        .lock()
        .expect("protocol_versions mutex poisoned")
        .clone();

    assert_eq!(ids.len(), 1);
    assert_eq!(versions.len(), 1);
    assert_eq!(
        versions[0].as_deref(),
        Some("2025-11-25"),
        "the rmcp 3.4.0 default pair currently negotiates the SDK LATEST revision"
    );

    Ok(())
}

#[tokio::test]
async fn child_progress_uses_generated_progress_token_visible_to_client_handler()
-> anyhow::Result<()> {
    let state = ProbeState::default();
    let progress_client = ProgressClient::default();
    let progress_observer = progress_client.clone();
    let client = start_pair(
        ProbeServer::new(state.clone(), Duration::from_millis(100)).with_progress(),
        progress_client,
    )
    .await?;

    let handle = client
        .send_cancellable_request(call_request("probe"), PeerRequestOptions::no_options())
        .await?;
    let generated_token = handle.progress_token.clone();

    tokio::time::timeout(
        Duration::from_secs(1),
        progress_observer.received.notified(),
    )
    .await
    .expect("progress should reach the child client handler");

    let progress = progress_observer
        .progress
        .lock()
        .expect("progress mutex poisoned")
        .clone();
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0].progress_token, generated_token);

    let _ = handle.await_response().await?;

    Ok(())
}

#[tokio::test]
async fn rmcp_resources_list_and_read_are_available_for_gateway_aggregation() -> anyhow::Result<()>
{
    let client = start_resource_pair().await?;

    let listed = client.peer().list_resources(None).await?;
    assert_eq!(listed.resources.len(), 1);
    assert_eq!(listed.resources[0].uri, "gateway://status");

    let read = client
        .peer()
        .read_resource(ReadResourceRequestParams::new("gateway://status"))
        .await?;
    assert_eq!(read.contents.len(), 1);
    match &read.contents[0] {
        ResourceContents::TextResourceContents { text, uri, .. } => {
            assert_eq!(text, "ready");
            assert_eq!(uri, "gateway://status");
        }
        other => panic!("expected text resource, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn protocol_2026_07_28_requires_discover_lifecycle_opt_in() -> anyhow::Result<()> {
    let state = ProbeState::default();
    let server = ProbeServer::new(state.clone(), Duration::from_millis(1));
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);

    tokio::spawn(async move {
        let service = server.serve(server_transport).await?;
        service.waiting().await?;
        anyhow::Ok(())
    });

    let client = ()
        .serve_with_lifecycle(
            client_transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;

    client
        .peer()
        .call_tool(CallToolRequestParams::new("probe"))
        .await?;

    let versions = state
        .protocol_versions
        .lock()
        .expect("protocol_versions mutex poisoned")
        .clone();
    assert_eq!(versions.as_slice(), &[Some("2026-07-28".to_owned())]);

    Ok(())
}
