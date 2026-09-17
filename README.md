# Workspace MCP Gateway

`rust-mcp-gateway` exposes multiple local stdio MCP servers through one MCP server. The tunnel only needs the `main` channel, while child MCPs remain isolated executables.

## Topology

```text
ChatGPT Plugin
    |
    v
Tunnel main
    |
    v
rust-mcp-gateway
    |-- filesystem MCP
    |-- git MCP
    `-- future MCPs
```

## Child definitions

Runtime child definitions are host-local generated files. In the deployed layout they live under `mcp-server/bin/gateway/servers.d`; source control keeps only templates/candidates, not active host-specific YAML. Each active `*.yaml` file defines one child:

```yaml
name: git
enabled: true
command: "/absolute/path/to/rust-mcp-git"
args:
  - "--root"
  - "/absolute/workspace"
tool_allowlist:
  - git_status
  - git_log
  - git_dev_control_readiness
timeout_ms: 30000
restart:
  policy: on-failure
```

Optional `tool_prefix` can resolve tool-name collisions. By default child tool names are preserved.

Optional `tool_allowlist` limits the tools exposed by the gateway while leaving the child MCP's full capability set intact. The entries are the child's original tool names before `tool_prefix` is applied. An omitted or empty allowlist preserves backward-compatible behavior and exposes every child tool.

The gateway validates an allowlist against the tool catalog returned by the child at startup. Duplicate, invalid, or unknown names are rejected instead of being silently ignored, so a typo cannot accidentally produce a misleading partial surface.

This is useful for keeping a broad child MCP internally capable while presenting a smaller, policy-oriented tool set to ChatGPT. For example, the Git MCP can retain generic and recovery operations while its default surface favors `dev-git-control` workflow commands.

Files with extensions other than `.yaml` / `.yml` are ignored. Candidate configurations can therefore be prepared with names such as `git.yaml.candidate` and activated only after the gateway binary supporting their fields has been built.

## Git UX profile

The recommended default Git profile exposes 21 tools and keeps the underlying Git MCP at its full 28-tool capability set.

Exposed by default:

```text
git_list_repositories
git_status
git_diff
git_log
git_show
git_branches
git_history_plan
git_dev_control_readiness
git_create_branch
git_switch
git_merge
git_delete_branch
git_stage
git_commit
git_reword_commits
git_squash_commits
git_verify_unpublished
git_rewind_merge
git_replace_local_tag
git_release_tag
git_fetch
```

Hidden from the default surface, but still implemented by the Git MCP:

```text
git_validate_merge_readiness  # generic gate; dev-control gate is the normal path
git_amend_commit              # advanced history rewrite
git_unstage                   # low-level index helper
git_restore                   # destructive-ish low-level working-tree helper
git_tag                       # generic tagging; release workflow uses git_release_tag
git_pull                      # controlled workflow prefers fetch + explicit integration
git_push                      # hidden while gateway starts Git with remote-read only
```

If remote publication is intentionally enabled later, `git_push` can be added to the allowlist together with the Git MCP remote-write flag.

The prepared `servers.d/git.yaml.candidate` contains this default profile. Do not rename it over the live config until the gateway binary has been rebuilt with `tool_allowlist` support because `ChildConfig` uses strict unknown-field validation.

## Applying the allowlist source patch

The repository includes an idempotent one-shot patcher:

```bash
cd /path/to/workspace/mcp-server/src/gateway
python3 scripts/apply_tool_allowlist.py
```

The script updates `src/main.rs` atomically and refuses to continue if the expected source anchors no longer match. Re-running it after a successful application is a no-op.

After applying it, run the normal quality gates and build the release binary:

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --all-targets --all-features
cargo build --release --locked
```

Then render/activate host-local runtime configuration through the fleet tool rather than committing an active YAML file:

```bash
cd /path/to/workspace/mcp-server/src/fleet
python3 scripts/fleetctl.py render-gateway --host aira
```

The gateway watcher can reload automatically, or `gateway_reload` can be invoked explicitly. The expected Git child `tool_count` is 21 while the Git child binary itself still implements 28 tools.

## Gateway administration tools

- `gateway_list_servers` — list configured child MCPs and runtime health.
- `gateway_reload` — reload `servers.d`, restart child processes, and emit `notifications/tools/list_changed`.
- `gateway_set_server_enabled` — persist `enabled: true/false` for a child and reload.

The config directory is watched by default. A changed YAML file triggers reload. A previously-running child whose transport closes is restarted when `restart.policy` is `on-failure`.

## Build

```bash
cd /path/to/workspace/mcp-server/src/gateway
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --locked
```

For the first build before `Cargo.lock` exists:

```bash
cargo build --release
```

Then commit `Cargo.lock` and use `--locked` for subsequent builds.

## Run standalone

```bash
/path/to/workspace/mcp-server/bin/gateway/rust-mcp-gateway \
  --config-dir /path/to/workspace/mcp-server/bin/gateway/servers.d
```

Use `--no-watch` to disable automatic reload/health polling.

## Security model

Child definition files are trusted configuration because `command` executes a local program. YAML child files must be regular files, not symlinks. Commands are launched directly with `tokio::process::Command`; no shell is involved.

Tool filtering occurs only at the gateway exposure/routing layer. A filtered-out tool is not routable through the gateway, but the child executable still retains that capability when connected directly or exposed under another gateway profile.
