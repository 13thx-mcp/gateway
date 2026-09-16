#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import os
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "main.rs"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def replace_if_present(text: str, old: str, new: str) -> tuple[str, bool]:
    if old not in text:
        return text, False
    return text.replace(old, new, 1), True


def atomic_write(path: Path, text: str) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def apply_allowlist_patch(text: str) -> tuple[str, bool]:
    if "tool_allowlist: Vec<String>" in text:
        return text, False

    text = replace_once(
        text,
        '''    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_prefix: Option<String>,

    #[serde(default = "default_timeout_ms")]
''',
        '''    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_prefix: Option<String>,

    /// Optional allowlist of original child tool names to expose.
    /// Empty means expose every child tool. Matching happens before tool_prefix is applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tool_allowlist: Vec<String>,

    #[serde(default = "default_timeout_ms")]
''',
        "ChildConfig field",
    )

    text = replace_once(
        text,
        '''                    for tool in child_tools {
                        let original_name = tool.name.to_string();
                        let exposed_name = exposed_tool_name(&config, &original_name);
''',
        '''                    let discovered_names: BTreeSet<String> = child_tools
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
''',
        "reload filtering",
    )

    text = replace_once(
        text,
        '''    if let Some(prefix) = &config.tool_prefix {
        if prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            bail!("tool_prefix may contain only ASCII letters, digits, '_', '-' and '.'");
        }
    }
    Ok(())
}
''',
        '''    if let Some(prefix) = &config.tool_prefix {
        if prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            bail!("tool_prefix may contain only ASCII letters, digits, '_', '-' and '.'");
        }
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
            bail!("tool_allowlist contains duplicate tool name '{}'", tool_name);
        }
    }
    Ok(())
}
''',
        "config validation",
    )

    text = replace_once(
        text,
        '''fn exposed_tool_name(config: &ChildConfig, original_name: &str) -> String {
''',
        '''fn tool_is_exposed(config: &ChildConfig, original_name: &str) -> bool {
    config.tool_allowlist.is_empty()
        || config
            .tool_allowlist
            .iter()
            .any(|tool_name| tool_name == original_name)
}

fn exposed_tool_name(config: &ChildConfig, original_name: &str) -> String {
''',
        "tool exposure helper",
    )

    text = replace_once(
        text,
        '''            env: BTreeMap::new(),
            tool_prefix: None,
            timeout_ms: 30_000,
''',
        '''            env: BTreeMap::new(),
            tool_prefix: None,
            tool_allowlist: Vec::new(),
            timeout_ms: 30_000,
''',
        "test config",
    )

    text = replace_once(
        text,
        '''    #[test]
    fn validates_tool_prefixes() {
        let mut config = config();
        config.tool_prefix = Some("safe_".into());
        assert!(validate_config(&config).is_ok());
        config.tool_prefix = Some("bad prefix/".into());
        assert!(validate_config(&config).is_err());
    }
}
''',
        '''    #[test]
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
''',
        "allowlist tests",
    )

    return text, True


def apply_clippy_cleanup(text: str) -> tuple[str, int]:
    changes = 0

    text, changed = replace_if_present(
        text,
        '''#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RestartPolicy {
    Never,
    OnFailure,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self::OnFailure
    }
}
''',
        '''#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RestartPolicy {
    Never,
    #[default]
    OnFailure,
}
''',
    )
    changes += int(changed)

    text, changed = replace_if_present(
        text,
        '''        if let Some(peer) = peer {
            if let Err(error) = peer.notify_tool_list_changed().await {
                tracing::debug!(%error, "failed to send tools/list_changed notification");
            }
        }
''',
        '''        if let Some(peer) = peer
            && let Err(error) = peer.notify_tool_list_changed().await
        {
            tracing::debug!(%error, "failed to send tools/list_changed notification");
        }
''',
    )
    changes += int(changed)

    text, changed = replace_if_present(
        text,
        '''    if let Some(prefix) = &config.tool_prefix {
        if prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            bail!("tool_prefix may contain only ASCII letters, digits, '_', '-' and '.'");
        }
    }
''',
        '''    if let Some(prefix) = &config.tool_prefix
        && (prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        bail!("tool_prefix may contain only ASCII letters, digits, '_', '-' and '.'");
    }
''',
    )
    changes += int(changed)

    return text, changes


def main() -> None:
    original = TARGET.read_text(encoding="utf-8")
    text, allowlist_changed = apply_allowlist_patch(original)
    text, clippy_changes = apply_clippy_cleanup(text)

    if text == original:
        print("tool_allowlist and clippy cleanup already applied")
        return

    atomic_write(TARGET, text)
    details = []
    if allowlist_changed:
        details.append("tool_allowlist")
    if clippy_changes:
        details.append(f"clippy_cleanup={clippy_changes}")
    print(f"patched {TARGET} ({', '.join(details)})")


if __name__ == "__main__":
    main()
