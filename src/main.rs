mod artifact;
mod control;
mod policy;
mod progress;
mod recovery;
mod request;
mod request_registry;
mod telemetry;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceError, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CancelledNotification,
        CancelledNotificationParam, ClientRequest, ContentBlock, JsonObject, ListResourcesResult,
        ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
        ReadResourceResult, Request, RequestParamsMeta, ResourceContents, ServerCapabilities,
        ServerConfig, ServerResult, Tool,
    },
    service::{
        Peer, PeerRequestOptions, RequestContext, RequestHandle, RoleClient, RoleServer,
        RunningServiceCancellationToken,
    },
    transport::{TokioChildProcess, stdio},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    process::Command,
    sync::{Mutex, RwLock},
    time::timeout,
};

const TOOL_LIST_SERVERS: &str = "gateway_list_servers";
const TOOL_RELOAD: &str = "gateway_reload";
const TOOL_SET_ENABLED: &str = "gateway_set_server_enabled";
const TOOL_READ_ARTIFACT: &str = "gateway_read_artifact";
const CAPABILITIES: &str = r#"{"gateway_policy_schemas":[1],"control_protocol_versions":[1]}"#;
const OUTCOME_OBSERVATION_WINDOW: Duration = Duration::from_secs(30);
const RESOURCE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AGGREGATED_RESOURCES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainPhase {
    Running,
    Draining,
    Drained,
}

impl DrainPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Draining => "DRAINING",
            Self::Drained => "DRAINED",
        }
    }
}

struct DrainState {
    phase: DrainPhase,
    generation: u64,
}

#[derive(Debug, Parser)]
#[command(version, about = "Dynamic workspace MCP gateway")]
struct Cli {
    /// Print side-effect-free Gateway protocol and policy compatibility data.
    #[arg(long)]
    capabilities_json: bool,

    /// Directory containing one child MCP definition per *.yaml / *.yml file.
    #[arg(long, env = "MCP_GATEWAY_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    /// Disable automatic config-directory watching and dead-child restart checks.
    #[arg(long, env = "MCP_GATEWAY_NO_WATCH", default_value_t = false)]
    no_watch: bool,

    /// Poll interval for config changes and child health.
    #[arg(long, env = "MCP_GATEWAY_WATCH_INTERVAL_MS", default_value_t = 1500)]
    watch_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    name: String,

    #[serde(default = "default_true")]
    enabled: bool,

    command: String,

    #[serde(default)]
    args: Vec<String>,

    #[serde(default)]
    env: BTreeMap<String, String>,

    /// Optional prefix added to every exposed tool name from this child.
    /// Leave unset when the child already uses unique names (for example git_*).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_prefix: Option<String>,

    /// Optional allowlist of original child tool names to expose.
    /// Empty means expose every child tool. Matching happens before tool_prefix is applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tool_allowlist: Vec<String>,

    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,

    #[serde(default)]
    restart: RestartConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RestartConfig {
    #[serde(default)]
    policy: RestartPolicy,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            policy: RestartPolicy::OnFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RestartPolicy {
    Never,
    #[default]
    OnFailure,
}

#[derive(Debug, Clone)]
struct LoadedConfig {
    source: PathBuf,
    config: ChildConfig,
}

#[derive(Clone)]
struct ChildCancellation(Arc<StdMutex<Option<RunningServiceCancellationToken>>>);

impl ChildCancellation {
    fn new(cancel: RunningServiceCancellationToken) -> Self {
        Self(Arc::new(StdMutex::new(Some(cancel))))
    }

    fn cancel(&self) {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cancel) = guard.take() {
            cancel.cancel();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSignature {
    canonical_path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Clone)]
struct ChildRuntime {
    peer: Peer<RoleClient>,
    cancel: ChildCancellation,
    timeout: Duration,
    restart_policy: RestartPolicy,
    config: ChildConfig,
    command_signature: Option<CommandSignature>,
    tools: Vec<Tool>,
    recovery: Arc<StdMutex<recovery::ChildRecovery>>,
    recovery_policy: Arc<StdMutex<Option<recovery::Policy>>>,
}

#[derive(Debug, Clone)]
struct ToolRoute {
    child: String,
    original_name: String,
}

#[derive(Debug, Clone, Serialize)]
struct ChildStatus {
    name: String,
    enabled: bool,
    running: bool,
    command: String,
    source: String,
    tool_prefix: Option<String>,
    tool_count: usize,
    timeout_ms: u64,
    restart_policy: RestartPolicy,
    generation: u64,
    recovery_state: recovery::State,
    consecutive_failures: usize,
    retry_at_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Clone, Default)]
struct Snapshot {
    tools: Vec<Tool>,
    routes: BTreeMap<String, ToolRoute>,
    children: BTreeMap<String, ChildRuntime>,
    statuses: BTreeMap<String, ChildStatus>,
}

#[derive(Debug, Serialize)]
struct ReloadSummary {
    configured_servers: usize,
    enabled_servers: usize,
    running_servers: usize,
    exposed_child_tools: usize,
    failed_servers: Vec<String>,
}

struct GatewayCore {
    config_dir: PathBuf,
    artifact_store: artifact::Store,
    policy: RwLock<policy::Mode>,
    coordinator: Arc<request::Coordinator>,
    request_registry: Arc<request_registry::Registry>,
    progress: Arc<progress::Relay>,
    telemetry: Arc<telemetry::Store>,
    state: RwLock<Snapshot>,
    reload_lock: Mutex<()>,
    drain_lock: Mutex<()>,
    drain: Mutex<DrainState>,
    catalog_generation: AtomicU64,
    profile_generation: AtomicU64,
    instance_id: String,
    upstream_peer: Mutex<Option<Peer<RoleServer>>>,
}

#[derive(Clone)]
struct Gateway {
    core: Arc<GatewayCore>,
}

#[derive(Debug, Deserialize)]
struct SetEnabledArgs {
    name: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ReadArtifactArgs {
    id: String,
    #[serde(default)]
    offset: usize,
    max_bytes: usize,
}

fn default_true() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn scheduler_limits(mode: &policy::Mode) -> (usize, usize, Duration) {
    match mode {
        policy::Mode::LegacyCompat => (16, 64, Duration::from_secs(30)),
        policy::Mode::Strict(policy) => (
            policy.limits.global_active,
            policy.limits.global_queue,
            Duration::from_millis(policy.limits.queue_wait_ms),
        ),
    }
}

fn active_profile_name(mode: &policy::Mode) -> Option<&str> {
    match mode {
        policy::Mode::LegacyCompat => None,
        policy::Mode::Strict(policy) => Some(&policy.active_profile),
    }
}

impl GatewayCore {
    fn new(config_dir: PathBuf) -> Result<Self> {
        let policy = policy::load(&config_dir)?;
        let (global_active, global_queue, queue_wait) = scheduler_limits(&policy);
        let artifact_store = artifact::Store::new(config_dir.join("artifacts"))?;
        if let policy::Mode::Strict(policy) = &policy
            && policy.artifacts.enabled
        {
            artifact_store.cleanup(Duration::from_secs(policy.artifacts.ttl_seconds))?;
        }
        Ok(Self {
            config_dir,
            artifact_store,
            policy: RwLock::new(policy),
            coordinator: request::Coordinator::new(global_active, global_queue, queue_wait),
            request_registry: request_registry::Registry::new(),
            progress: progress::Relay::new(),
            telemetry: telemetry::Store::new(),
            state: RwLock::new(Snapshot::default()),
            reload_lock: Mutex::new(()),
            drain_lock: Mutex::new(()),
            drain: Mutex::new(DrainState {
                phase: DrainPhase::Running,
                generation: 0,
            }),
            catalog_generation: AtomicU64::new(0),
            profile_generation: AtomicU64::new(1),
            instance_id: format!("{}-{}", std::process::id(), unix_millis()),
            upstream_peer: Mutex::new(None),
        })
    }

    async fn remember_upstream_peer(&self, peer: Peer<RoleServer>) {
        *self.upstream_peer.lock().await = Some(peer.clone());
        self.progress.set_upstream(peer);
    }

    async fn notify_tool_list_changed(&self) {
        let peer = self.upstream_peer.lock().await.clone();
        if let Some(peer) = peer
            && let Err(error) = peer.notify_tool_list_changed().await
        {
            tracing::debug!(%error, "failed to send tools/list_changed notification");
        }
    }

    async fn notify_resource_list_changed(&self) {
        let peer = self.upstream_peer.lock().await.clone();
        if let Some(peer) = peer
            && let Err(error) = peer.notify_resource_list_changed().await
        {
            tracing::debug!(%error, "failed to send resources/list_changed notification");
        }
    }

    async fn route_limits(&self, child: &str, tool: &str) -> Option<(usize, usize)> {
        match &*self.policy.read().await {
            policy::Mode::LegacyCompat => Some((4, 4)),
            policy::Mode::Strict(policy) => {
                let child_policy = policy.children.get(child)?;
                let tool_policy = child_policy.tools.get(tool)?;
                if !tool_policy.profiles.contains(&policy.active_profile) {
                    return None;
                }
                let class_limit = policy.tool_class_defaults.get(&tool_policy.class)?;
                Some((
                    child_policy.concurrency,
                    tool_policy.concurrency.min(class_limit.concurrency),
                ))
            }
        }
    }

    async fn request_budget(&self) -> usize {
        match &*self.policy.read().await {
            policy::Mode::LegacyCompat => usize::MAX,
            policy::Mode::Strict(policy) => policy.payload.request_bytes,
        }
    }

    async fn response_guard_limits(&self) -> Option<(policy::Payload, artifact::Limits)> {
        let policy::Mode::Strict(policy) = &*self.policy.read().await else {
            return None;
        };
        Some((
            policy.payload.clone(),
            artifact::Limits {
                ttl: Duration::from_secs(policy.artifacts.ttl_seconds),
                max_item_bytes: policy.artifacts.max_item_bytes,
                max_total_bytes: policy.artifacts.max_total_bytes,
            },
        ))
    }

    async fn artifact_enabled(&self) -> bool {
        matches!(&*self.policy.read().await, policy::Mode::Strict(policy) if policy.artifacts.enabled)
    }

    async fn reload(&self) -> Result<ReloadSummary> {
        let _reload_guard = self.reload_lock.lock().await;
        let loaded = load_configs(&self.config_dir)?;
        let policy_configs = loaded.clone();
        let next_policy = policy::load(&self.config_dir)?;
        let profile_changed = {
            let current = self.policy.read().await;
            active_profile_name(&current) != active_profile_name(&next_policy)
        };
        let previous = self.state.read().await.clone();
        let previous_children = previous.children.clone();

        let mut next = Snapshot {
            tools: builtin_tools(),
            ..Snapshot::default()
        };
        let mut reused_children = BTreeSet::new();
        let mut tool_names: BTreeSet<String> = next
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();

        for item in loaded {
            let config = item.config.clone();
            let source = item.source.display().to_string();
            let mut status = ChildStatus {
                name: config.name.clone(),
                enabled: config.enabled,
                running: false,
                command: config.command.clone(),
                source,
                tool_prefix: config.tool_prefix.clone(),
                tool_count: 0,
                timeout_ms: config.timeout_ms,
                restart_policy: config.restart.policy,
                generation: 0,
                recovery_state: recovery::State::Restarting,
                consecutive_failures: 0,
                retry_at_ms: None,
                error: None,
            };

            if !config.enabled {
                next.statuses.insert(config.name.clone(), status);
                continue;
            }

            let current_command_signature = command_signature(&config.command).ok();
            let reusable = previous_children
                .get(&config.name)
                .filter(|runtime| {
                    runtime.config == config
                        && !runtime.peer.is_transport_closed()
                        && current_command_signature.as_ref().is_some_and(|signature| {
                            runtime.command_signature.as_ref() == Some(signature)
                        })
                })
                .cloned();
            let was_reused = reusable.is_some();
            let child_result = match reusable {
                Some(runtime) => Ok((runtime.clone(), runtime.tools.clone())),
                None => start_child(&config, Arc::clone(&self.progress)).await,
            };

            match child_result {
                Ok((runtime, child_tools)) => {
                    if !was_reused
                        && let Some(previous_runtime) = previous_children.get(&config.name)
                        && previous_runtime.peer.is_transport_closed()
                    {
                        let mut recovered = previous_runtime
                            .recovery
                            .lock()
                            .expect("recovery state poisoned")
                            .clone();
                        recovered.promote_candidate(unix_millis() as u64);
                        *runtime.recovery.lock().expect("recovery state poisoned") = recovered;
                        *runtime
                            .recovery_policy
                            .lock()
                            .expect("recovery policy poisoned") = *previous_runtime
                            .recovery_policy
                            .lock()
                            .expect("recovery policy poisoned");
                    }
                    if let policy::Mode::Strict(policy) = &next_policy
                        && let Some(child_policy) = policy.children.get(&config.name)
                    {
                        *runtime
                            .recovery_policy
                            .lock()
                            .expect("recovery policy poisoned") =
                            Some(recovery::Policy::from(&child_policy.restart));
                    }
                    {
                        let recovery = runtime.recovery.lock().expect("recovery state poisoned");
                        status.generation = recovery.generation();
                        status.recovery_state = recovery.state();
                        status.consecutive_failures = recovery.consecutive_failures();
                        status.retry_at_ms = recovery.retry_at_ms();
                    }
                    let mut transformed = Vec::with_capacity(child_tools.len());
                    let mut routes = Vec::with_capacity(child_tools.len());

                    let discovered_names: BTreeSet<String> = child_tools
                        .iter()
                        .map(|tool| tool.name.to_string())
                        .collect();
                    if let Some(missing) = config
                        .tool_allowlist
                        .iter()
                        .find(|name| !discovered_names.contains(name.as_str()))
                    {
                        if !was_reused {
                            runtime.cancel.cancel();
                        }
                        status.error = Some(format!(
                            "tool_allowlist references unknown child tool '{}'",
                            missing
                        ));
                        next.statuses.insert(config.name.clone(), status);
                        continue;
                    }

                    for tool in child_tools {
                        let original_name = tool.name.to_string();
                        if !tool_is_exposed(&config, &original_name) {
                            continue;
                        }
                        if let policy::Mode::Strict(policy) = &next_policy {
                            let Some(tool_policy) = policy
                                .children
                                .get(&config.name)
                                .and_then(|child| child.tools.get(&original_name))
                            else {
                                continue;
                            };
                            if !tool_policy.profiles.contains(&policy.active_profile) {
                                continue;
                            }
                        }
                        let exposed_name = exposed_tool_name(&config, &original_name);

                        if !valid_tool_name(&exposed_name) {
                            cancel_snapshot_except(next, &reused_children);
                            if !was_reused {
                                runtime.cancel.cancel();
                            }
                            bail!(
                                "child '{}' produced invalid exposed tool name '{}'",
                                config.name,
                                exposed_name
                            );
                        }
                        if !tool_names.insert(exposed_name.clone()) {
                            cancel_snapshot_except(next, &reused_children);
                            if !was_reused {
                                runtime.cancel.cancel();
                            }
                            bail!(
                                "duplicate exposed tool name '{}'; set tool_prefix on one child",
                                exposed_name
                            );
                        }

                        let mut exposed = tool.clone();
                        exposed.name = Cow::Owned(exposed_name.clone());
                        let existing = exposed
                            .description
                            .as_deref()
                            .unwrap_or("Child MCP tool")
                            .to_owned();
                        exposed.description =
                            Some(Cow::Owned(format!("[{}] {}", config.name, existing)));

                        transformed.push(exposed);
                        routes.push((
                            exposed_name,
                            ToolRoute {
                                child: config.name.clone(),
                                original_name,
                            },
                        ));
                    }

                    status.running = true;
                    status.tool_count = transformed.len();
                    next.tools.extend(transformed);
                    next.routes.extend(routes);
                    if was_reused {
                        reused_children.insert(config.name.clone());
                    }
                    next.children.insert(config.name.clone(), runtime);
                }
                Err(error) => {
                    let error = format!("{error:#}");
                    if let Some(previous_runtime) = previous.children.get(&config.name)
                        && previous_runtime.peer.is_transport_closed()
                        && let Some(recovery_policy) = *previous_runtime
                            .recovery_policy
                            .lock()
                            .expect("recovery policy poisoned")
                    {
                        let mut recovery = previous_runtime
                            .recovery
                            .lock()
                            .expect("recovery state poisoned");
                        recovery.failure(unix_millis() as u64, recovery_policy);
                        status.generation = recovery.generation();
                        status.recovery_state = recovery.state();
                        status.consecutive_failures = recovery.consecutive_failures();
                        status.retry_at_ms = recovery.retry_at_ms();
                    }
                    if let Some(previous_runtime) = previous.children.get(&config.name)
                        && !previous_runtime.peer.is_transport_closed()
                    {
                        let prior_routes = previous
                            .routes
                            .iter()
                            .filter(|(_, route)| route.child == config.name)
                            .map(|(name, route)| (name.clone(), route.clone()))
                            .collect::<Vec<_>>();
                        let prior_tool_names = prior_routes
                            .iter()
                            .map(|(name, _)| name.as_str())
                            .collect::<BTreeSet<_>>();
                        let prior_tools = previous
                            .tools
                            .iter()
                            .filter(|tool| prior_tool_names.contains(tool.name.as_ref()))
                            .cloned()
                            .collect::<Vec<_>>();
                        if prior_tools.len() != prior_routes.len()
                            || prior_routes
                                .iter()
                                .any(|(name, _)| !tool_names.insert(name.clone()))
                        {
                            cancel_snapshot_except(next, &reused_children);
                            bail!(
                                "cannot retain last known good child '{}' after candidate failure",
                                config.name
                            );
                        }
                        status.enabled = previous_runtime.config.enabled;
                        status.running = true;
                        status.command = previous_runtime.config.command.clone();
                        status.tool_prefix = previous_runtime.config.tool_prefix.clone();
                        status.tool_count = prior_tools.len();
                        status.timeout_ms = previous_runtime.config.timeout_ms;
                        status.restart_policy = previous_runtime.restart_policy;
                        {
                            let recovery = previous_runtime
                                .recovery
                                .lock()
                                .expect("recovery state poisoned");
                            status.generation = recovery.generation();
                            status.recovery_state = recovery.state();
                            status.consecutive_failures = recovery.consecutive_failures();
                            status.retry_at_ms = recovery.retry_at_ms();
                        }
                        status.error = Some(format!(
                            "candidate replacement failed; retaining last known good generation: {error}"
                        ));
                        next.tools.extend(prior_tools);
                        next.routes.extend(prior_routes);
                        next.children
                            .insert(config.name.clone(), previous_runtime.clone());
                        reused_children.insert(config.name.clone());
                    } else {
                        status.error = Some(error);
                    }
                    tracing::error!(
                        child = %config.name,
                        error = %status.error.as_deref().unwrap_or("unknown error"),
                        "failed to start child MCP; gateway remains available"
                    );
                }
            }

            next.statuses.insert(config.name.clone(), status);
        }

        if let policy::Mode::Strict(policy) = &next_policy {
            let children = next
                .children
                .iter()
                .map(|(name, runtime)| {
                    (
                        name.clone(),
                        runtime
                            .tools
                            .iter()
                            .map(|tool| tool.name.to_string())
                            .collect(),
                    )
                })
                .collect();
            let allowlists = policy_configs
                .iter()
                .map(|item| {
                    (
                        item.config.name.clone(),
                        item.config.tool_allowlist.iter().cloned().collect(),
                    )
                })
                .collect();
            if let Err(error) = policy::validate_catalog(policy, &children, &allowlists) {
                cancel_snapshot_except(next, &reused_children);
                return Err(error);
            }
        }

        let summary = summarize(&next);
        let catalog_fingerprint = catalog_fingerprint(&next);
        let profile_fingerprint = profile_fingerprint(&next_policy);
        let old = {
            let mut state = self.state.write().await;
            std::mem::replace(&mut *state, next)
        };
        *self.policy.write().await = next_policy;
        cancel_snapshot_except(old, &reused_children);
        self.catalog_generation.fetch_add(1, Ordering::Release);
        if profile_changed {
            self.profile_generation.fetch_add(1, Ordering::Release);
        }
        self.telemetry.record(telemetry::Observation::Catalog {
            catalog_generation: self.catalog_generation.load(Ordering::Acquire),
            profile_generation: self.profile_generation.load(Ordering::Acquire),
            catalog_fingerprint,
            profile_fingerprint,
        });

        Ok(summary)
    }

    async fn drain_deadline(&self) -> Duration {
        match &*self.policy.read().await {
            policy::Mode::Strict(policy) => Duration::from_millis(policy.drain.deadline_ms),
            policy::Mode::LegacyCompat => Duration::from_secs(60),
        }
    }

    async fn begin_drain(&self) -> (u64, bool) {
        let generation = {
            let mut state = self.drain.lock().await;
            if state.phase == DrainPhase::Running {
                state.generation += 1;
                state.phase = DrainPhase::Draining;
                self.coordinator.close_admission();
            }
            state.generation
        };
        let drained = self
            .coordinator
            .wait_idle(self.drain_deadline().await)
            .await;
        if drained {
            self.drain.lock().await.phase = DrainPhase::Drained;
        }
        (generation, drained)
    }

    async fn resume(&self, generation: u64) -> Result<()> {
        let _drain_guard = self.drain_lock.lock().await;
        let mut state = self.drain.lock().await;
        if state.generation != generation || state.phase == DrainPhase::Running {
            bail!("drain generation does not match an active drain")
        }
        state.phase = DrainPhase::Running;
        self.coordinator.open_admission();
        Ok(())
    }

    async fn finish_lifecycle(&self) {
        self.drain.lock().await.phase = DrainPhase::Running;
        self.coordinator.open_admission();
    }

    async fn drain_and_reload(&self) -> Result<ReloadSummary> {
        let _drain_guard = self.drain_lock.lock().await;
        let (_, drained) = self.begin_drain().await;
        if !drained {
            bail!("gateway drain timed out with dispatched requests still active")
        }
        let result = self.reload().await;
        self.finish_lifecycle().await;
        result
    }

    async fn list_server_status(&self) -> Value {
        let state = self.state.read().await;
        let mut statuses = Vec::with_capacity(state.statuses.len());

        for (name, stored) in &state.statuses {
            let mut status = stored.clone();
            if let Some(child) = state.children.get(name) {
                status.running = !child.peer.is_transport_closed();
                let recovery = child.recovery.lock().expect("recovery state poisoned");
                status.generation = recovery.generation();
                status.recovery_state = recovery.state();
                status.consecutive_failures = recovery.consecutive_failures();
                status.retry_at_ms = recovery.retry_at_ms();
            }
            statuses.push(status);
        }

        json!({
            "config_dir": self.config_dir,
            "servers": statuses,
            "exposed_child_tools": state.routes.len(),
            "gateway_tools": [TOOL_LIST_SERVERS, TOOL_RELOAD, TOOL_SET_ENABLED, TOOL_READ_ARTIFACT],
            "policy_schema_version": self.policy.read().await.schema_version(),
            "active_profile": match &*self.policy.read().await {
                policy::Mode::LegacyCompat => Value::Null,
                policy::Mode::Strict(policy) => Value::String(policy.active_profile.clone()),
            },
            "profile_generation": self.profile_generation.load(Ordering::Acquire),
            "queued_requests": self.coordinator.queued(),
            "active_requests": self.request_registry.active(),
            "admission_open": self.coordinator.is_accepting()
        })
    }

    async fn list_resources(&self) -> ListResourcesResult {
        let children = self
            .state
            .read()
            .await
            .children
            .iter()
            .map(|(name, runtime)| (name.clone(), runtime.peer.clone()))
            .collect::<Vec<_>>();
        let mut resources = Vec::new();
        for (child, peer) in children {
            let Ok(Ok(result)) =
                timeout(RESOURCE_OPERATION_TIMEOUT, peer.list_resources(None)).await
            else {
                continue;
            };
            for mut resource in result.resources {
                if resources.len() >= MAX_AGGREGATED_RESOURCES || resource.uri.len() > 2048 {
                    break;
                }
                resource.uri = gateway_resource_uri(&child, &resource.uri);
                resource.name = format!("{child}:{}", resource.name);
                resources.push(resource);
            }
        }
        ListResourcesResult {
            resources,
            ..Default::default()
        }
    }

    async fn read_resource(&self, uri: &str) -> std::result::Result<ReadResourceResult, McpError> {
        let (child, child_uri) = parse_gateway_resource_uri(uri)
            .ok_or_else(|| McpError::resource_not_found("unknown Gateway resource", None))?;
        let peer = self
            .state
            .read()
            .await
            .children
            .get(&child)
            .map(|runtime| runtime.peer.clone())
            .ok_or_else(|| {
                McpError::resource_not_found("Gateway resource child is unavailable", None)
            })?;
        let mut result = timeout(
            RESOURCE_OPERATION_TIMEOUT,
            peer.read_resource(ReadResourceRequestParams::new(child_uri)),
        )
        .await
        .map_err(|_| McpError::internal_error("Gateway resource read timed out", None))?
        .map_err(|error| {
            McpError::internal_error(format!("Gateway resource read failed: {error}"), None)
        })?;
        if serde_json::to_vec(&result)
            .map(|bytes| bytes.len() > 1024 * 1024)
            .unwrap_or(true)
        {
            return Err(McpError::invalid_params(
                "Gateway resource response exceeds 1 MiB bound",
                None,
            ));
        }
        for content in &mut result.contents {
            match content {
                ResourceContents::TextResourceContents {
                    uri: content_uri, ..
                }
                | ResourceContents::BlobResourceContents {
                    uri: content_uri, ..
                } => {
                    *content_uri = uri.to_owned();
                }
                _ => {}
            }
        }
        Ok(result)
    }

    async fn control_response(&self, error: Option<control::Error>) -> control::Response {
        let drain = self.drain.lock().await;
        control::Response {
            ok: error.is_none(),
            instance_id: self.instance_id.clone(),
            state: drain.phase.as_str().to_owned(),
            drain_generation: drain.generation,
            active_requests: self.coordinator.active(),
            queued_requests: self.coordinator.queued(),
            catalog_generation: self.catalog_generation.load(Ordering::Acquire),
            profile_generation: self.profile_generation.load(Ordering::Acquire),
            history: None,
            error,
        }
    }

    fn record_request(
        &self,
        ticket: &request_registry::Ticket,
        observation: telemetry::RequestObservation,
    ) {
        self.telemetry.record(telemetry::Observation::Request {
            request_id: ticket.id().to_owned(),
            child: observation.child,
            tool: observation.tool,
            outcome: observation.outcome,
            queue_ms: observation.queue_ms,
            execution_ms: observation.execution_ms,
            response_bytes: observation.response_bytes,
            guard: observation.guard,
            catalog_generation: self.catalog_generation.load(Ordering::Acquire),
            profile_generation: self.profile_generation.load(Ordering::Acquire),
        });
    }

    async fn set_enabled(&self, name: &str, enabled: bool) -> Result<ReloadSummary> {
        let _drain_guard = self.drain_lock.lock().await;
        let (_, drained) = self.begin_drain().await;
        if !drained {
            bail!("gateway drain timed out with dispatched requests still active")
        }
        let result = {
            async {
                validate_child_name(name)?;
                let loaded = load_configs(&self.config_dir)?;
                let target = loaded
                    .into_iter()
                    .find(|item| item.config.name == name)
                    .ok_or_else(|| anyhow!("unknown child MCP '{name}'"))?;

                let mut config = target.config;
                config.enabled = enabled;
                write_config_atomic(&target.source, &config)?;
                self.reload().await
            }
            .await
        };
        self.finish_lifecycle().await;
        result
    }

    async fn has_dead_restartable_child(&self) -> bool {
        let state = self.state.read().await;
        let now_ms = unix_millis() as u64;
        state.children.values().any(|child| {
            if child.restart_policy != RestartPolicy::OnFailure || !child.peer.is_transport_closed()
            {
                return false;
            }
            let Some(policy) = *child
                .recovery_policy
                .lock()
                .expect("recovery policy poisoned")
            else {
                return true;
            };
            let mut recovery = child.recovery.lock().expect("recovery state poisoned");
            recovery.reset_if_stable(now_ms, policy);
            let before = recovery.state();
            if recovery.state() == recovery::State::Healthy {
                recovery.failure(now_ms, policy);
            }
            let due = recovery.begin_due_recovery(now_ms);
            let state = recovery.state();
            if state != before {
                let observation = match state {
                    recovery::State::Restarting => telemetry::RecoveryState::Restarting,
                    recovery::State::CircuitOpen => telemetry::RecoveryState::CircuitOpen,
                    recovery::State::HalfOpen => telemetry::RecoveryState::HalfOpen,
                    recovery::State::Healthy | recovery::State::BackingOff => return due,
                };
                self.telemetry
                    .record(telemetry::Observation::ChildRecovery {
                        child: child.config.name.clone(),
                        state: observation,
                        generation: recovery.generation(),
                    });
            }
            due
        })
    }
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_list_changed()
                .build(),
        )
        .with_instructions(
            "Workspace MCP gateway. Child MCP tools are aggregated dynamically from servers.d.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        self.core.remember_upstream_peer(context.peer.clone()).await;
        let tools = self.core.state.read().await.tools.clone();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListResourcesResult, McpError> {
        self.core.remember_upstream_peer(context.peer.clone()).await;
        Ok(self.core.list_resources().await)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ReadResourceResponse, McpError> {
        self.core.remember_upstream_peer(context.peer.clone()).await;
        Ok(self.core.read_resource(&request.uri).await?.into())
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, McpError> {
        self.core.remember_upstream_peer(context.peer.clone()).await;
        let requested_name = request.name.to_string();

        match requested_name.as_str() {
            TOOL_LIST_SERVERS => {
                return Ok(CallToolResult::structured(self.core.list_server_status().await).into());
            }
            TOOL_RELOAD => {
                let result = self.core.drain_and_reload().await;
                return Ok(match result {
                    Ok(summary) => {
                        self.core.notify_tool_list_changed().await;
                        self.core.notify_resource_list_changed().await;
                        CallToolResult::structured(
                            serde_json::to_value(summary).unwrap_or_else(|_| json!({})),
                        )
                        .into()
                    }
                    Err(error) => tool_error(format!("gateway reload failed: {error:#}")).into(),
                });
            }
            TOOL_SET_ENABLED => {
                let args = match decode_args::<SetEnabledArgs>(request.arguments.take()) {
                    Ok(args) => args,
                    Err(error) => return Ok(tool_error(error).into()),
                };
                let result = self.core.set_enabled(&args.name, args.enabled).await;
                return Ok(match result {
                    Ok(summary) => {
                        self.core.notify_tool_list_changed().await;
                        self.core.notify_resource_list_changed().await;
                        CallToolResult::structured(json!({
                            "server": args.name,
                            "enabled": args.enabled,
                            "reload": summary
                        }))
                        .into()
                    }
                    Err(error) => tool_error(format!(
                        "failed to set child '{}' enabled={}: {error:#}",
                        args.name, args.enabled
                    ))
                    .into(),
                });
            }
            TOOL_READ_ARTIFACT => {
                let args = match decode_args::<ReadArtifactArgs>(request.arguments.take()) {
                    Ok(args) => args,
                    Err(error) => return Ok(tool_error(error).into()),
                };
                return Ok(self.read_artifact(args).await.into());
            }
            _ => {}
        }

        let request_bytes = match serde_json::to_vec(&request.arguments) {
            Ok(bytes) => bytes.len(),
            Err(_) => return Ok(tool_error("Gateway cannot encode tool arguments").into()),
        };
        let request_budget = self.core.request_budget().await;
        if request_bytes > request_budget {
            return Ok(tool_payload_too_large("request", request_bytes, request_budget).into());
        }

        let (peer, original_name, child_timeout, child_name) = {
            let state = self.core.state.read().await;
            let route = state.routes.get(&requested_name).cloned().ok_or_else(|| {
                McpError::invalid_params(format!("unknown tool '{requested_name}'"), None)
            })?;
            let child = state.children.get(&route.child).ok_or_else(|| {
                McpError::invalid_params(
                    format!("child MCP '{}' is not running", route.child),
                    None,
                )
            })?;
            (
                child.peer.clone(),
                route.original_name,
                child.timeout,
                route.child,
            )
        };
        let Some((child_limit, tool_limit)) =
            self.core.route_limits(&child_name, &original_name).await
        else {
            return Ok(tool_error("tool is not allowed by active Gateway profile").into());
        };
        let ticket = match self
            .core
            .request_registry
            .begin(child_name.clone(), original_name.clone())
        {
            Some(ticket) => ticket,
            None => return Ok(tool_error("Gateway active request registry is full").into()),
        };
        let queued_at = Instant::now();

        let lease = match self
            .core
            .coordinator
            .acquire(
                request::RequestSpec {
                    tool: format!("{child_name}:{original_name}"),
                    child: child_name.clone(),
                    child_limit,
                    tool_limit,
                },
                context.ct.clone(),
            )
            .await
        {
            Ok(lease) => lease,
            Err(request::AdmissionError::Saturated) => {
                self.core.record_request(
                    &ticket,
                    request_observation(
                        &child_name,
                        &original_name,
                        telemetry::RequestOutcome::Failed,
                        queued_at.elapsed(),
                        Duration::ZERO,
                        0,
                        telemetry::GuardAction::NotApplied,
                    ),
                );
                return Ok(tool_error("Gateway request queue is full").into());
            }
            Err(request::AdmissionError::Cancelled) => {
                self.core.record_request(
                    &ticket,
                    request_observation(
                        &child_name,
                        &original_name,
                        telemetry::RequestOutcome::Failed,
                        queued_at.elapsed(),
                        Duration::ZERO,
                        0,
                        telemetry::GuardAction::NotApplied,
                    ),
                );
                return Ok(tool_error("Gateway request cancelled before dispatch").into());
            }
            Err(request::AdmissionError::Deadline) => {
                self.core.record_request(
                    &ticket,
                    request_observation(
                        &child_name,
                        &original_name,
                        telemetry::RequestOutcome::Failed,
                        queued_at.elapsed(),
                        Duration::ZERO,
                        0,
                        telemetry::GuardAction::NotApplied,
                    ),
                );
                return Ok(tool_error("Gateway request expired before dispatch").into());
            }
            Err(request::AdmissionError::Draining) => {
                self.core.record_request(
                    &ticket,
                    request_observation(
                        &child_name,
                        &original_name,
                        telemetry::RequestOutcome::Failed,
                        queued_at.elapsed(),
                        Duration::ZERO,
                        0,
                        telemetry::GuardAction::NotApplied,
                    ),
                );
                return Ok(tool_error(
                    "Gateway is draining; retry after lifecycle change completes",
                )
                .into());
            }
        };

        let queue_elapsed = queued_at.elapsed();
        let execution_started = Instant::now();
        request.name = Cow::Owned(original_name.clone());
        let progress_lease = request
            .progress_token()
            .and_then(|token| self.core.progress.register(token.clone()));
        if let Some(lease) = &progress_lease {
            request.set_progress_token(lease.child_token());
        }
        let child_request = ClientRequest::CallToolRequest(Request::new(request));
        let mut handle = match peer
            .send_cancellable_request(child_request, PeerRequestOptions::no_options())
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                self.core.record_request(
                    &ticket,
                    request_observation(
                        &child_name,
                        &original_name,
                        telemetry::RequestOutcome::Failed,
                        queue_elapsed,
                        execution_started.elapsed(),
                        0,
                        telemetry::GuardAction::NotApplied,
                    ),
                );
                return Ok(tool_error(format!(
                    "child MCP call could not be dispatched for '{requested_name}': {error}"
                ))
                .into());
            }
        };
        ticket.dispatched(format!("{:?}", handle.id));

        let mut deadline = Box::pin(tokio::time::sleep(child_timeout));
        enum DispatchWait {
            Response(Box<Result<ServerResult, ServiceError>>),
            Cancelled,
            TimedOut,
        }
        let response = tokio::select! {
            biased;
            response = &mut handle.rx => {
                DispatchWait::Response(Box::new(response.unwrap_or(Err(ServiceError::TransportClosed))))
            }
            _ = context.ct.cancelled() => DispatchWait::Cancelled,
            _ = &mut deadline => DispatchWait::TimedOut,
        };

        if matches!(response, DispatchWait::Cancelled | DispatchWait::TimedOut) {
            let child_request_id = handle.id.clone();
            let reason = if matches!(response, DispatchWait::Cancelled) {
                "upstream gateway request cancelled".to_owned()
            } else {
                format!(
                    "gateway child timeout after {} ms",
                    child_timeout.as_millis()
                )
            };
            let cancel_error = send_child_cancel(&handle, reason).await.err();
            let gateway_request_id = ticket.id().to_owned();
            ticket.pending();
            self.core.record_request(
                &ticket,
                request_observation(
                    &child_name,
                    &original_name,
                    telemetry::RequestOutcome::Unknown,
                    queue_elapsed,
                    execution_started.elapsed(),
                    0,
                    telemetry::GuardAction::NotApplied,
                ),
            );
            tokio::spawn(observe_child_outcome(PendingChildOutcome {
                handle,
                _lease: lease,
                _progress: progress_lease,
                ticket,
                core: Arc::clone(&self.core),
                child: child_name.clone(),
                tool: original_name.clone(),
                queue_elapsed,
                execution_started,
                request_id: child_request_id,
            }));
            return Ok(tool_unknown_outcome_with_correlation(
                format!(
                "child MCP call ended upstream wait after dispatch for '{requested_name}'; outcome is pending; do not automatically retry; cancel_error={cancel_error:?}"
                ),
                gateway_request_id,
            )
            .into());
        }

        match response {
            DispatchWait::Response(response) => {
                match *response {
                    Ok(ServerResult::CallToolResult(result)) => {
                        let (response, response_bytes, guard) =
                            self.guard_child_response(result).await;
                        self.core.record_request(
                            &ticket,
                            request_observation(
                                &child_name,
                                &original_name,
                                telemetry::RequestOutcome::Returned,
                                queue_elapsed,
                                execution_started.elapsed(),
                                response_bytes,
                                guard,
                            ),
                        );
                        Ok(response.into())
                    }
                    Ok(_) => {
                        self.core.record_request(
                            &ticket,
                            request_observation(
                                &child_name,
                                &original_name,
                                telemetry::RequestOutcome::Failed,
                                queue_elapsed,
                                execution_started.elapsed(),
                                0,
                                telemetry::GuardAction::NotApplied,
                            ),
                        );
                        Ok(tool_error(format!("child MCP call returned an unexpected response type for '{requested_name}'")).into())
                    }
                    Err(ServiceError::TransportClosed) => {
                        self.core.record_request(
                            &ticket,
                            request_observation(
                                &child_name,
                                &original_name,
                                telemetry::RequestOutcome::Unknown,
                                queue_elapsed,
                                execution_started.elapsed(),
                                0,
                                telemetry::GuardAction::NotApplied,
                            ),
                        );
                        Ok(tool_unknown_outcome(format!("child MCP transport closed after dispatch for '{requested_name}'; outcome is unknown; do not automatically retry")).into())
                    }
                    Err(ServiceError::Cancelled { reason }) => {
                        self.core.record_request(
                            &ticket,
                            request_observation(
                                &child_name,
                                &original_name,
                                telemetry::RequestOutcome::Unknown,
                                queue_elapsed,
                                execution_started.elapsed(),
                                0,
                                telemetry::GuardAction::NotApplied,
                            ),
                        );
                        Ok(tool_unknown_outcome(format!(
                        "child MCP call was cancelled after dispatch for '{requested_name}'{}; outcome is unknown; do not automatically retry",
                        reason.as_deref().map(|reason| format!(": {reason}")).unwrap_or_default()
                    )).into())
                    }
                    Err(error) => {
                        self.core.record_request(
                            &ticket,
                            request_observation(
                                &child_name,
                                &original_name,
                                telemetry::RequestOutcome::Failed,
                                queue_elapsed,
                                execution_started.elapsed(),
                                0,
                                telemetry::GuardAction::NotApplied,
                            ),
                        );
                        Ok(tool_error(format!(
                            "child MCP call failed for '{requested_name}': {error}"
                        ))
                        .into())
                    }
                }
            }
            DispatchWait::Cancelled | DispatchWait::TimedOut => unreachable!("handled above"),
        }
    }
}

impl Gateway {
    async fn guard_child_response(
        &self,
        result: CallToolResult,
    ) -> (CallToolResult, usize, telemetry::GuardAction) {
        let Some((payload, artifacts)) = self.core.response_guard_limits().await else {
            let bytes = serde_json::to_vec(&result)
                .map(|value| value.len())
                .unwrap_or(0);
            return (result, bytes, telemetry::GuardAction::NotApplied);
        };
        let encoded = match serde_json::to_vec(&result) {
            Ok(encoded) => encoded,
            Err(_) => {
                return (
                    tool_error("Gateway cannot encode child response"),
                    0,
                    telemetry::GuardAction::NotApplied,
                );
            }
        };
        let Some((kind, actual, limit)) = response_budget_violation(&result, &encoded, &payload)
        else {
            return (result, encoded.len(), telemetry::GuardAction::Passed);
        };
        let artifact =
            if self.core.artifact_enabled().await && encoded.len() <= artifacts.max_item_bytes {
                match self.core.artifact_store.put(&encoded, artifacts) {
                    Ok(stored) => Some(json!({
                        "id": stored.id,
                        "sha256": stored.sha256,
                        "bytes": stored.bytes,
                        "expires_at_unix_seconds": stored.expires_at_unix_seconds,
                    })),
                    Err(error) => Some(json!({"unavailable": true, "reason": error.to_string()})),
                }
            } else {
                None
            };
        (
            tool_response_guard(
                kind,
                actual,
                limit,
                safe_text_preview(&result, payload.text_preview_bytes),
                artifact,
            ),
            encoded.len(),
            telemetry::GuardAction::Guarded,
        )
    }

    async fn read_artifact(&self, args: ReadArtifactArgs) -> CallToolResult {
        let Some((payload, artifacts)) = self.core.response_guard_limits().await else {
            return tool_error("artifact retrieval requires strict Gateway policy");
        };
        if !self.core.artifact_enabled().await {
            return tool_error("artifact persistence is disabled by Gateway policy");
        }
        let max_bytes = args
            .max_bytes
            .min(payload.binary_bytes)
            .min(artifacts.max_item_bytes);
        match self
            .core
            .artifact_store
            .read(&args.id, args.offset, max_bytes, artifacts)
        {
            Ok(read) => CallToolResult::structured(json!({
                "id": args.id,
                "offset": args.offset,
                "total_bytes": read.total_bytes,
                "sha256": read.sha256,
                "encoding": "base64",
                "data": base64_encode(&read.bytes),
            })),
            Err(error) => tool_error(format!("artifact read failed: {error:#}")),
        }
    }
}

async fn send_child_cancel(
    handle: &RequestHandle<RoleClient>,
    reason: String,
) -> Result<(), ServiceError> {
    handle
        .peer
        .send_notification(
            CancelledNotification::new(CancelledNotificationParam::new(
                Some(handle.id.clone()),
                Some(reason),
            ))
            .into(),
        )
        .await
}

struct PendingChildOutcome {
    handle: RequestHandle<RoleClient>,
    _lease: request::Lease,
    _progress: Option<progress::Lease>,
    ticket: request_registry::Ticket,
    core: Arc<GatewayCore>,
    child: String,
    tool: String,
    queue_elapsed: Duration,
    execution_started: Instant,
    request_id: rmcp::model::RequestId,
}

async fn observe_child_outcome(mut pending: PendingChildOutcome) {
    let outcome = match tokio::time::timeout(OUTCOME_OBSERVATION_WINDOW, &mut pending.handle.rx)
        .await
    {
        Ok(Ok(Ok(_))) => {
            tracing::info!(tool = %pending.tool, request_id = ?pending.request_id, "child outcome observed after upstream wait");
            telemetry::RequestOutcome::Returned
        }
        Ok(Ok(Err(error))) => {
            tracing::warn!(tool = %pending.tool, request_id = ?pending.request_id, %error, "child terminal error observed after upstream wait");
            telemetry::RequestOutcome::Failed
        }
        Ok(Err(_)) => {
            tracing::warn!(tool = %pending.tool, request_id = ?pending.request_id, "child transport closed with unknown outcome");
            telemetry::RequestOutcome::Unknown
        }
        Err(_) => {
            let _ = pending
                .handle
                .cancel(Some("Gateway outcome observation window expired".into()))
                .await;
            tracing::warn!(tool = %pending.tool, request_id = ?pending.request_id, "child outcome remained unknown after observation window");
            telemetry::RequestOutcome::Unknown
        }
    };
    pending.core.record_request(
        &pending.ticket,
        request_observation(
            &pending.child,
            &pending.tool,
            outcome,
            pending.queue_elapsed,
            pending.execution_started.elapsed(),
            0,
            telemetry::GuardAction::NotApplied,
        ),
    );
}

async fn start_child(
    config: &ChildConfig,
    progress: Arc<progress::Relay>,
) -> Result<(ChildRuntime, Vec<Tool>)> {
    validate_config(config)?;
    let launch_command_signature = command_signature(&config.command).ok();

    let mut command = Command::new(&config.command);
    command.args(&config.args).envs(&config.env);

    let transport = TokioChildProcess::new(command)
        .with_context(|| format!("failed to spawn '{}'", config.command))?;
    let running = progress.client().serve(transport).await.with_context(|| {
        format!(
            "MCP initialize handshake failed for child '{}'",
            config.name
        )
    })?;

    let child_timeout = Duration::from_millis(config.timeout_ms);
    let tools = match timeout(child_timeout, running.list_all_tools()).await {
        Ok(Ok(tools)) => tools,
        Ok(Err(error)) => {
            let _ = running.cancel().await;
            return Err(anyhow!("tools/list failed for '{}': {error}", config.name));
        }
        Err(_) => {
            let _ = running.cancel().await;
            return Err(anyhow!(
                "tools/list timed out for '{}' after {} ms",
                config.name,
                config.timeout_ms
            ));
        }
    };

    let peer = running.peer().clone();
    let cancel = running.cancellation_token();
    let child_name = config.name.clone();
    tokio::spawn(async move {
        match running.waiting().await {
            Ok(reason) => tracing::warn!(child = %child_name, ?reason, "child MCP stopped"),
            Err(error) => tracing::error!(child = %child_name, %error, "child MCP join failed"),
        }
    });

    Ok((
        ChildRuntime {
            peer,
            cancel: ChildCancellation::new(cancel),
            timeout: child_timeout,
            restart_policy: config.restart.policy,
            config: config.clone(),
            command_signature: launch_command_signature,
            tools: tools.clone(),
            recovery: Arc::new(StdMutex::new({
                let mut recovery = recovery::ChildRecovery::default();
                recovery.promote_candidate(unix_millis() as u64);
                recovery
            })),
            recovery_policy: Arc::new(StdMutex::new(None)),
        },
        tools,
    ))
}

fn load_configs(config_dir: &Path) -> Result<Vec<LoadedConfig>> {
    let mut entries = std::fs::read_dir(config_dir)
        .with_context(|| format!("cannot read config directory {}", config_dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    let mut loaded = Vec::new();
    let mut names = BTreeSet::new();

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if !matches!(extension, "yaml" | "yml") {
            continue;
        }

        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("child MCP config must not be a symlink: {}", path.display());
        }

        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let config: ChildConfig = serde_yaml::from_str(&text)
            .with_context(|| format!("invalid YAML in {}", path.display()))?;
        validate_config(&config)
            .with_context(|| format!("invalid child config {}", path.display()))?;

        if !names.insert(config.name.clone()) {
            bail!("duplicate child MCP name '{}'", config.name);
        }

        loaded.push(LoadedConfig {
            source: path,
            config,
        });
    }

    Ok(loaded)
}

fn validate_config(config: &ChildConfig) -> Result<()> {
    validate_child_name(&config.name)?;
    if config.command.trim().is_empty() || config.command.as_bytes().contains(&0) {
        bail!("command must be non-empty and contain no NUL");
    }
    if config.timeout_ms == 0 || config.timeout_ms > 600_000 {
        bail!("timeout_ms must be between 1 and 600000");
    }
    if let Some(prefix) = &config.tool_prefix
        && (prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        bail!("tool_prefix may contain only ASCII letters, digits, '_', '-' and '.'");
    }
    if config.tool_allowlist.len() > 256 {
        bail!("tool_allowlist may contain at most 256 entries");
    }
    let mut seen_tools = BTreeSet::new();
    for tool_name in &config.tool_allowlist {
        if !valid_tool_name(tool_name) {
            bail!("tool_allowlist contains invalid tool name '{}'", tool_name);
        }
        if !seen_tools.insert(tool_name) {
            bail!(
                "tool_allowlist contains duplicate tool name '{}'",
                tool_name
            );
        }
    }
    Ok(())
}

fn validate_child_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        bail!("child name may contain only ASCII letters, digits, '_', '-' and '.'");
    }
    Ok(())
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn tool_is_exposed(config: &ChildConfig, original_name: &str) -> bool {
    config.tool_allowlist.is_empty()
        || config
            .tool_allowlist
            .iter()
            .any(|tool_name| tool_name == original_name)
}

fn exposed_tool_name(config: &ChildConfig, original_name: &str) -> String {
    match &config.tool_prefix {
        Some(prefix) => format!("{prefix}{original_name}"),
        None => original_name.to_owned(),
    }
}

fn builtin_tools() -> Vec<Tool> {
    vec![
        Tool::new(
            TOOL_LIST_SERVERS,
            "List configured child MCP servers, runtime status, and tool counts.",
            object_schema(json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            })),
        ),
        Tool::new(
            TOOL_RELOAD,
            "Reload servers.d, preserve healthy unchanged children, replace changed or stopped children, and refresh the exposed tool catalog.",
            object_schema(json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            })),
        ),
        Tool::new(
            TOOL_SET_ENABLED,
            "Persistently enable or disable one child MCP server and reload the gateway.",
            object_schema(json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "enabled": {"type": "boolean"}
                },
                "required": ["name", "enabled"],
                "additionalProperties": false
            })),
        ),
        Tool::new(
            TOOL_READ_ARTIFACT,
            "Read a bounded base64 range from an explicitly enabled ephemeral Gateway artifact.",
            object_schema(json!({
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "offset": {"type": "integer", "minimum": 0},
                    "max_bytes": {"type": "integer", "minimum": 1}
                },
                "required": ["id", "max_bytes"],
                "additionalProperties": false
            })),
        ),
    ]
}

fn object_schema(value: Value) -> Arc<JsonObject> {
    Arc::new(
        value
            .as_object()
            .cloned()
            .expect("gateway tool schema must be a JSON object"),
    )
}

fn decode_args<T: for<'de> Deserialize<'de>>(
    arguments: Option<JsonObject>,
) -> std::result::Result<T, String> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
        .map_err(|error| format!("invalid arguments: {error}"))
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

fn tool_unknown_outcome(message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "code": "child_outcome_unknown",
        "message": message.into(),
        "retryable": false,
        "outcome": "unknown"
    }))
}

fn tool_unknown_outcome_with_correlation(
    message: impl Into<String>,
    gateway_request_id: String,
) -> CallToolResult {
    let mut result = tool_unknown_outcome(message);
    if let Some(structured) = result.structured_content.as_mut() {
        structured["gateway_request_id"] = Value::String(gateway_request_id);
    }
    result
}

fn tool_payload_too_large(kind: &str, actual: usize, limit: usize) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "code": "payload_too_large",
        "kind": kind,
        "actual_bytes": actual,
        "limit_bytes": limit,
        "retryable": false,
        "guidance": "Narrow the requested path, range, query, or result set before issuing a new request."
    }))
}

fn tool_response_guard(
    kind: &str,
    actual: usize,
    limit: usize,
    preview: Option<String>,
    artifact: Option<Value>,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "code": "response_guarded",
        "kind": kind,
        "actual_bytes": actual,
        "limit_bytes": limit,
        "retryable": false,
        "guidance": "Narrow the requested path, range, query, or result set before issuing a new request.",
        "preview": preview,
        "artifact": artifact,
    }))
}

fn response_budget_violation(
    result: &CallToolResult,
    encoded: &[u8],
    limits: &policy::Payload,
) -> Option<(&'static str, usize, usize)> {
    if encoded.len() > limits.response_bytes {
        return Some(("response", encoded.len(), limits.response_bytes));
    }
    let value = serde_json::to_value(result).ok()?;
    let structured = value
        .get("structuredContent")
        .or_else(|| value.get("structured_content"));
    if let Some(structured) = structured {
        let bytes = serde_json::to_vec(structured).ok()?.len();
        if bytes > limits.structured_bytes {
            return Some(("structured", bytes, limits.structured_bytes));
        }
    }
    for content in value
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let text = content.get("text").and_then(Value::as_str);
        if let Some(text) = text {
            if text.len() > limits.text_preview_bytes {
                return Some(("text", text.len(), limits.text_preview_bytes));
            }
        } else {
            let bytes = serde_json::to_vec(content).ok()?.len();
            if bytes > limits.binary_bytes {
                return Some(("binary", bytes, limits.binary_bytes));
            }
        }
    }
    None
}

fn safe_text_preview(result: &CallToolResult, max_bytes: usize) -> Option<String> {
    let value = serde_json::to_value(result).ok()?;
    let text = value
        .get("content")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|content| content.get("text").and_then(Value::as_str))?;
    let mut end = text.len().min(max_bytes);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    Some(text[..end].to_owned())
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 0b11) << 4 | (second >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((second & 0b1111) << 2 | (third >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(third & 0b11_1111) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn gateway_resource_uri(child: &str, uri: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(uri.len() * 2);
    for byte in uri.bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("gateway-resource://{child}/{encoded}")
}

fn parse_gateway_resource_uri(uri: &str) -> Option<(String, String)> {
    let encoded = uri.strip_prefix("gateway-resource://")?;
    let (child, encoded) = encoded.split_once('/')?;
    if !valid_tool_name(child)
        || encoded.is_empty()
        || encoded.len() > 4096
        || encoded.len() % 2 != 0
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    let (pairs, []) = encoded.as_bytes().as_chunks::<2>() else {
        return None;
    };
    for [high_byte, low_byte] in pairs {
        let high = (*high_byte as char).to_digit(16)?;
        let low = (*low_byte as char).to_digit(16)?;
        bytes.push(((high << 4) | low) as u8);
    }
    String::from_utf8(bytes)
        .ok()
        .map(|resource| (child.to_owned(), resource))
}

fn summarize(snapshot: &Snapshot) -> ReloadSummary {
    let configured_servers = snapshot.statuses.len();
    let enabled_servers = snapshot.statuses.values().filter(|s| s.enabled).count();
    let running_servers = snapshot.statuses.values().filter(|s| s.running).count();
    let failed_servers = snapshot
        .statuses
        .values()
        .filter_map(|status| status.error.as_ref().map(|_| status.name.clone()))
        .collect();

    ReloadSummary {
        configured_servers,
        enabled_servers,
        running_servers,
        exposed_child_tools: snapshot.routes.len(),
        failed_servers,
    }
}

fn cancel_snapshot_except(snapshot: Snapshot, keep: &BTreeSet<String>) {
    for (name, child) in snapshot.children {
        if !keep.contains(&name) {
            child.cancel.cancel();
        }
    }
}

fn write_config_atomic(path: &Path, config: &ChildConfig) -> Result<()> {
    let yaml = serde_yaml::to_string(config)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("invalid config file name"))?;
    let temp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));

    std::fs::write(&temp, yaml)
        .with_context(|| format!("cannot write temporary config {}", temp.display()))?;
    std::fs::rename(&temp, path)
        .with_context(|| format!("cannot replace config {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigSignature(Vec<(String, u64, Option<SystemTime>)>);

fn command_signature(command: &str) -> Result<CommandSignature> {
    let canonical_path = std::fs::canonicalize(command)
        .with_context(|| format!("cannot resolve child executable {command}"))?;
    let metadata = std::fs::metadata(&canonical_path)
        .with_context(|| format!("cannot stat child executable {}", canonical_path.display()))?;
    if !metadata.is_file() {
        bail!(
            "child executable is not a regular file: {}",
            canonical_path.display()
        );
    }
    Ok(CommandSignature {
        canonical_path,
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    })
}

fn config_signature(config_dir: &Path) -> Result<ConfigSignature> {
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(config_dir)? {
        let entry = entry?;
        let path = entry.path();
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if !matches!(extension, "yaml" | "yml") || !entry.file_type()?.is_file() {
            continue;
        }
        let metadata = entry.metadata()?;
        rows.push((
            entry.file_name().to_string_lossy().into_owned(),
            metadata.len(),
            metadata.modified().ok(),
        ));
    }
    rows.sort();
    Ok(ConfigSignature(rows))
}

async fn supervisor(core: Arc<GatewayCore>, interval: Duration) {
    let mut last_signature = config_signature(&core.config_dir).ok();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let signature = config_signature(&core.config_dir).ok();
        let configs_changed = signature != last_signature;
        let dead_child = core.has_dead_restartable_child().await;

        if !configs_changed && !dead_child {
            continue;
        }

        let reason = match (configs_changed, dead_child) {
            (true, true) => "config changed and child stopped",
            (true, false) => "config changed",
            (false, true) => "child stopped",
            (false, false) => unreachable!(),
        };
        tracing::info!(reason, "gateway supervisor reloading child MCP catalog");

        match core.drain_and_reload().await {
            Ok(summary) => {
                tracing::info!(?summary, "gateway reload completed");
                last_signature = config_signature(&core.config_dir).ok();
                core.notify_tool_list_changed().await;
                core.notify_resource_list_changed().await;
            }
            Err(error) => {
                tracing::error!(%error, "gateway automatic reload failed; keeping previous catalog");
            }
        }
    }
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn catalog_fingerprint(snapshot: &Snapshot) -> String {
    let mut catalog = String::new();
    for (name, route) in &snapshot.routes {
        catalog.push_str(name);
        catalog.push('\0');
        catalog.push_str(&route.child);
        catalog.push('\0');
        catalog.push_str(&route.original_name);
        catalog.push('\n');
    }
    sha256_hex(catalog.as_bytes())
}

fn profile_fingerprint(policy: &policy::Mode) -> String {
    let profile = match policy {
        policy::Mode::Strict(policy) => policy.active_profile.as_str(),
        policy::Mode::LegacyCompat => "legacy",
    };
    sha256_hex(profile.as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn request_observation(
    child: &str,
    tool: &str,
    outcome: telemetry::RequestOutcome,
    queue: Duration,
    execution: Duration,
    response_bytes: usize,
    guard: telemetry::GuardAction,
) -> telemetry::RequestObservation {
    telemetry::RequestObservation {
        child: child.to_owned(),
        tool: tool.to_owned(),
        outcome,
        queue_ms: u64::try_from(queue.as_millis()).unwrap_or(u64::MAX),
        execution_ms: u64::try_from(execution.as_millis()).unwrap_or(u64::MAX),
        response_bytes,
        guard,
    }
}

async fn control_server(core: Arc<GatewayCore>, listener: control::Listener) {
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::error!(%error, "gateway control socket accept failed");
                continue;
            }
        };
        let request_core = Arc::clone(&core);
        tokio::spawn(async move {
            let mut stream = stream;
            let response = match control::read_request(&mut stream).await {
                Ok(request) => match request.action {
                    control::Action::Status => request_core.control_response(None).await,
                    control::Action::History => {
                        let mut response = request_core.control_response(None).await;
                        response.history = Some(
                            request_core
                                .telemetry
                                .after(request.after_sequence.unwrap_or_default()),
                        );
                        response
                    }
                    control::Action::Drain => {
                        let _drain_guard = request_core.drain_lock.lock().await;
                        let (_, drained) = request_core.begin_drain().await;
                        request_core
                            .control_response((!drained).then_some(control::Error {
                                code: "drain_timeout",
                            }))
                            .await
                    }
                    control::Action::Resume => {
                        let error = match request_core
                            .resume(
                                request
                                    .drain_generation
                                    .expect("control parser requires drain generation"),
                            )
                            .await
                        {
                            Ok(()) => None,
                            Err(_) => Some(control::Error {
                                code: "stale_drain_generation",
                            }),
                        };
                        request_core.control_response(error).await
                    }
                    control::Action::Reload => {
                        let error = match request_core.drain_and_reload().await {
                            Ok(_) => None,
                            Err(_) => Some(control::Error {
                                code: "reload_failed",
                            }),
                        };
                        request_core.control_response(error).await
                    }
                },
                Err(error) => request_core.control_response(Some(error)).await,
            };
            if let Err(error) = control::write_response(&mut stream, &response).await {
                tracing::debug!(%error, "gateway control socket response failed");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_mcp_gateway=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    if cli.capabilities_json {
        println!("{CAPABILITIES}");
        return Ok(());
    }
    let configured_path = cli
        .config_dir
        .context("--config-dir or MCP_GATEWAY_CONFIG_DIR is required")?;
    let config_dir = std::fs::canonicalize(&configured_path).with_context(|| {
        format!(
            "cannot resolve gateway config directory {}",
            configured_path.display()
        )
    })?;
    if !config_dir.is_dir() {
        bail!("gateway config path is not a directory");
    }

    let core = Arc::new(GatewayCore::new(config_dir)?);
    let summary = core.reload().await?;
    tracing::info!(?summary, "initial child MCP catalog loaded");

    let control_listener = control::bind(&core.config_dir)?;
    tokio::spawn(control_server(Arc::clone(&core), control_listener));

    if !cli.no_watch {
        let watch_core = Arc::clone(&core);
        let interval = Duration::from_millis(cli.watch_interval_ms.clamp(250, 60_000));
        tokio::spawn(supervisor(watch_core, interval));
    }

    let gateway = Gateway { core };
    tracing::info!("starting workspace MCP gateway over stdio");
    let service = gateway.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ChildConfig {
        ChildConfig {
            name: "git".into(),
            enabled: true,
            command: "/tmp/git-mcp".into(),
            args: vec![],
            env: BTreeMap::new(),
            tool_prefix: None,
            tool_allowlist: Vec::new(),
            timeout_ms: 30_000,
            restart: RestartConfig::default(),
        }
    }

    #[test]
    fn strict_policy_sets_scheduler_limits() {
        let config: policy::Config = serde_yaml::from_str(
            "schema_version: 1\nactive_profile: develop\nlimits: {global_active: 3, global_queue: 7, queue_wait_ms: 42, default_child_active: 2}\ntool_class_defaults: {read: {concurrency: 2}, mutation: {concurrency: 1}, long-running: {concurrency: 1}, control: {concurrency: 1}}\ndrain: {deadline_ms: 1, allow_safe_reads: false}\npayload: {request_bytes: 1, response_bytes: 1, text_preview_bytes: 1, structured_bytes: 1, binary_bytes: 1}\nartifacts: {enabled: false, ttl_seconds: 1, max_item_bytes: 1, max_total_bytes: 1}\nprofiles: {develop: {}}\nchildren: {}\n",
        )
        .unwrap();
        assert_eq!(
            scheduler_limits(&policy::Mode::Strict(Box::new(config))),
            (3, 7, Duration::from_millis(42))
        );
    }

    #[test]
    fn profile_identity_distinguishes_legacy_and_named_profiles() {
        let strict: policy::Config = serde_yaml::from_str(
            "schema_version: 1\nactive_profile: develop\nlimits: {global_active: 1, global_queue: 1, queue_wait_ms: 1, default_child_active: 1}\ntool_class_defaults: {read: {concurrency: 1}, mutation: {concurrency: 1}, long-running: {concurrency: 1}, control: {concurrency: 1}}\ndrain: {deadline_ms: 1, allow_safe_reads: false}\npayload: {request_bytes: 1, response_bytes: 1, text_preview_bytes: 1, structured_bytes: 1, binary_bytes: 1}\nartifacts: {enabled: false, ttl_seconds: 1, max_item_bytes: 1, max_total_bytes: 1}\nprofiles: {develop: {}}\nchildren: {}\n",
        )
        .unwrap();
        assert_eq!(active_profile_name(&policy::Mode::LegacyCompat), None);
        assert_eq!(
            active_profile_name(&policy::Mode::Strict(Box::new(strict))),
            Some("develop")
        );
    }

    #[test]
    fn keeps_child_tool_name_without_prefix() {
        assert_eq!(exposed_tool_name(&config(), "git_status"), "git_status");
    }

    #[test]
    fn prefixes_child_tool_name_when_configured() {
        let mut config = config();
        config.tool_prefix = Some("other_".into());
        assert_eq!(
            exposed_tool_name(&config, "status"),
            "other_status".to_owned()
        );
    }

    #[test]
    fn validates_child_names() {
        assert!(validate_child_name("filesystem").is_ok());
        assert!(validate_child_name("repo.tools-v2").is_ok());
        assert!(validate_child_name("../escape").is_err());
        assert!(validate_child_name("bad name").is_err());
    }

    #[test]
    fn validates_tool_prefixes() {
        let mut config = config();
        config.tool_prefix = Some("safe_".into());
        assert!(validate_config(&config).is_ok());
        config.tool_prefix = Some("bad prefix/".into());
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn filters_tools_by_allowlist() {
        let mut config = config();
        assert!(tool_is_exposed(&config, "git_status"));
        config.tool_allowlist = vec!["git_status".into(), "git_log".into()];
        assert!(tool_is_exposed(&config, "git_status"));
        assert!(tool_is_exposed(&config, "git_log"));
        assert!(!tool_is_exposed(&config, "git_push"));
    }

    #[test]
    fn unknown_outcome_is_structured_non_retryable_error() {
        let result = tool_unknown_outcome("pending side effect");
        assert_eq!(result.is_error, Some(true));
        let structured = result
            .structured_content
            .expect("unknown outcome should carry structured content");
        assert_eq!(structured["code"], "child_outcome_unknown");
        assert_eq!(structured["retryable"], false);
        assert_eq!(structured["outcome"], "unknown");
        assert_eq!(structured["message"], "pending side effect");
    }

    #[test]
    fn pending_outcome_includes_gateway_correlation_id() {
        let result =
            tool_unknown_outcome_with_correlation("pending side effect", "request-1".into());
        assert_eq!(
            result.structured_content.unwrap()["gateway_request_id"],
            "request-1"
        );
    }

    #[test]
    fn resource_routes_are_child_scoped_and_non_ambiguous() {
        let filesystem = gateway_resource_uri("filesystem", "file:///workspace/notes.txt");
        let git = gateway_resource_uri("git", "file:///workspace/notes.txt");
        assert_ne!(filesystem, git);
        assert_eq!(
            parse_gateway_resource_uri(&filesystem),
            Some(("filesystem".into(), "file:///workspace/notes.txt".into()))
        );
        assert!(parse_gateway_resource_uri("gateway-resource://filesystem/%2f").is_none());
        assert!(parse_gateway_resource_uri("file:///workspace/notes.txt").is_none());
    }

    #[test]
    fn response_guard_keeps_only_bounded_text_preview() {
        let result = CallToolResult::error(vec![ContentBlock::text("abcdef")]);
        let encoded = serde_json::to_vec(&result).unwrap();
        let limits = policy::Payload {
            request_bytes: 1,
            response_bytes: usize::MAX,
            text_preview_bytes: 3,
            structured_bytes: usize::MAX,
            binary_bytes: usize::MAX,
        };
        assert_eq!(
            response_budget_violation(&result, &encoded, &limits),
            Some(("text", 6, 3))
        );
        assert_eq!(safe_text_preview(&result, 3).as_deref(), Some("abc"));
        assert_eq!(base64_encode(b"abcde"), "YWJjZGU=");
    }

    #[cfg(unix)]
    #[test]
    fn command_signature_detects_atomic_replacement() {
        let root =
            std::env::temp_dir().join(format!("rust-mcp-gateway-signature-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let command = root.join("child");
        let replacement = root.join("replacement");
        std::fs::write(&command, b"v1").unwrap();
        let first = command_signature(command.to_str().unwrap()).unwrap();
        std::fs::write(&replacement, b"v2").unwrap();
        std::fs::rename(&replacement, &command).unwrap();
        let second = command_signature(command.to_str().unwrap()).unwrap();
        assert_ne!(first, second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn validates_tool_allowlist() {
        let mut config = config();
        config.tool_allowlist = vec!["git_status".into(), "git_status".into()];
        assert!(validate_config(&config).is_err());

        config.tool_allowlist = vec!["bad tool".into()];
        assert!(validate_config(&config).is_err());

        config.tool_allowlist = vec!["git_status".into(), "git_log".into()];
        assert!(validate_config(&config).is_ok());
    }
}
