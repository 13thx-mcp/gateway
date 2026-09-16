use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    service::{Peer, RequestContext, RoleClient, RoleServer, RunningServiceCancellationToken},
    transport::{TokioChildProcess, stdio},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    process::Command,
    sync::{Mutex, RwLock},
    time::timeout,
};

const TOOL_LIST_SERVERS: &str = "gateway_list_servers";
const TOOL_RELOAD: &str = "gateway_reload";
const TOOL_SET_ENABLED: &str = "gateway_set_server_enabled";

#[derive(Debug, Parser)]
#[command(version, about = "Dynamic workspace MCP gateway")]
struct Cli {
    /// Directory containing one child MCP definition per *.yaml / *.yml file.
    #[arg(long, env = "MCP_GATEWAY_CONFIG_DIR")]
    config_dir: PathBuf,

    /// Disable automatic config-directory watching and dead-child restart checks.
    #[arg(long, env = "MCP_GATEWAY_NO_WATCH", default_value_t = false)]
    no_watch: bool,

    /// Poll interval for config changes and child health.
    #[arg(long, env = "MCP_GATEWAY_WATCH_INTERVAL_MS", default_value_t = 1500)]
    watch_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

struct ChildRuntime {
    peer: Peer<RoleClient>,
    cancel: RunningServiceCancellationToken,
    timeout: Duration,
    restart_policy: RestartPolicy,
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
    error: Option<String>,
}

#[derive(Default)]
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
    state: RwLock<Snapshot>,
    reload_lock: Mutex<()>,
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

fn default_true() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    30_000
}

impl GatewayCore {
    fn new(config_dir: PathBuf) -> Self {
        Self {
            config_dir,
            state: RwLock::new(Snapshot::default()),
            reload_lock: Mutex::new(()),
            upstream_peer: Mutex::new(None),
        }
    }

    async fn remember_upstream_peer(&self, peer: Peer<RoleServer>) {
        *self.upstream_peer.lock().await = Some(peer);
    }

    async fn notify_tool_list_changed(&self) {
        let peer = self.upstream_peer.lock().await.clone();
        if let Some(peer) = peer
            && let Err(error) = peer.notify_tool_list_changed().await
        {
            tracing::debug!(%error, "failed to send tools/list_changed notification");
        }
    }

    async fn reload(&self) -> Result<ReloadSummary> {
        let _reload_guard = self.reload_lock.lock().await;
        let loaded = load_configs(&self.config_dir)?;

        let mut next = Snapshot {
            tools: builtin_tools(),
            ..Snapshot::default()
        };
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
                error: None,
            };

            if !config.enabled {
                next.statuses.insert(config.name.clone(), status);
                continue;
            }

            match start_child(&config).await {
                Ok((runtime, child_tools)) => {
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
                        runtime.cancel.cancel();
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
                        let exposed_name = exposed_tool_name(&config, &original_name);

                        if !valid_tool_name(&exposed_name) {
                            cancel_snapshot(next);
                            runtime.cancel.cancel();
                            bail!(
                                "child '{}' produced invalid exposed tool name '{}'",
                                config.name,
                                exposed_name
                            );
                        }
                        if !tool_names.insert(exposed_name.clone()) {
                            cancel_snapshot(next);
                            runtime.cancel.cancel();
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
                    next.children.insert(config.name.clone(), runtime);
                }
                Err(error) => {
                    status.error = Some(format!("{error:#}"));
                    tracing::error!(
                        child = %config.name,
                        error = %status.error.as_deref().unwrap_or("unknown error"),
                        "failed to start child MCP; gateway remains available"
                    );
                }
            }

            next.statuses.insert(config.name.clone(), status);
        }

        let summary = summarize(&next);
        let old = {
            let mut state = self.state.write().await;
            std::mem::replace(&mut *state, next)
        };
        cancel_snapshot(old);

        Ok(summary)
    }

    async fn list_server_status(&self) -> Value {
        let state = self.state.read().await;
        let mut statuses = Vec::with_capacity(state.statuses.len());

        for (name, stored) in &state.statuses {
            let mut status = stored.clone();
            if let Some(child) = state.children.get(name) {
                status.running = !child.peer.is_transport_closed();
            }
            statuses.push(status);
        }

        json!({
            "config_dir": self.config_dir,
            "servers": statuses,
            "exposed_child_tools": state.routes.len(),
            "gateway_tools": [TOOL_LIST_SERVERS, TOOL_RELOAD, TOOL_SET_ENABLED]
        })
    }

    async fn set_enabled(&self, name: &str, enabled: bool) -> Result<ReloadSummary> {
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

    async fn has_dead_restartable_child(&self) -> bool {
        let state = self.state.read().await;
        state.children.values().any(|child| {
            child.restart_policy == RestartPolicy::OnFailure && child.peer.is_transport_closed()
        })
    }
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
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
                let result = self.core.reload().await;
                return Ok(match result {
                    Ok(summary) => {
                        self.core.notify_tool_list_changed().await;
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
            _ => {}
        }

        let (peer, original_name, child_timeout) = {
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
            (child.peer.clone(), route.original_name, child.timeout)
        };

        request.name = Cow::Owned(original_name);
        match timeout(child_timeout, peer.call_tool(request)).await {
            Ok(Ok(result)) => Ok(result.into()),
            Ok(Err(error)) => Ok(tool_error(format!(
                "child MCP call failed for '{requested_name}': {error}"
            ))
            .into()),
            Err(_) => Ok(tool_error(format!(
                "child MCP call timed out for '{requested_name}' after {} ms",
                child_timeout.as_millis()
            ))
            .into()),
        }
    }
}

async fn start_child(config: &ChildConfig) -> Result<(ChildRuntime, Vec<Tool>)> {
    validate_config(config)?;

    let mut command = Command::new(&config.command);
    command.args(&config.args).envs(&config.env);

    let transport = TokioChildProcess::new(command)
        .with_context(|| format!("failed to spawn '{}'", config.command))?;
    let running = ().serve(transport).await.with_context(|| {
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
            cancel,
            timeout: child_timeout,
            restart_policy: config.restart.policy,
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
            "Reload servers.d, restart child MCP processes, and refresh the exposed tool catalog.",
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

fn cancel_snapshot(snapshot: Snapshot) {
    for (_, child) in snapshot.children {
        child.cancel.cancel();
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

        match core.reload().await {
            Ok(summary) => {
                tracing::info!(?summary, "gateway reload completed");
                last_signature = config_signature(&core.config_dir).ok();
                core.notify_tool_list_changed().await;
            }
            Err(error) => {
                tracing::error!(%error, "gateway automatic reload failed; keeping previous catalog");
            }
        }
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
    let config_dir = std::fs::canonicalize(&cli.config_dir).with_context(|| {
        format!(
            "cannot resolve gateway config directory {}",
            cli.config_dir.display()
        )
    })?;
    if !config_dir.is_dir() {
        bail!("gateway config path is not a directory");
    }

    let core = Arc::new(GatewayCore::new(config_dir));
    let summary = core.reload().await?;
    tracing::info!(?summary, "initial child MCP catalog loaded");

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
