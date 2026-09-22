use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    LegacyCompat,
    Strict(Box<Config>),
}

impl Mode {
    pub fn schema_version(&self) -> Option<u32> {
        match self {
            Self::LegacyCompat => None,
            Self::Strict(config) => Some(config.schema_version),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub active_profile: String,
    pub limits: Limits,
    pub tool_class_defaults: BTreeMap<ToolClass, ClassLimits>,
    pub drain: Drain,
    pub payload: Payload,
    pub artifacts: Artifacts,
    pub profiles: BTreeMap<String, EmptyProfile>,
    pub children: BTreeMap<String, Child>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub global_active: usize,
    pub global_queue: usize,
    pub queue_wait_ms: u64,
    pub default_child_active: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClassLimits {
    pub concurrency: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ToolClass {
    Read,
    Mutation,
    LongRunning,
    Control,
}

impl ToolClass {
    const ALL: [Self; 4] = [Self::Read, Self::Mutation, Self::LongRunning, Self::Control];
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Drain {
    pub deadline_ms: u64,
    pub allow_safe_reads: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub text_preview_bytes: usize,
    pub structured_bytes: usize,
    pub binary_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifacts {
    pub enabled: bool,
    pub ttl_seconds: u64,
    pub max_item_bytes: usize,
    pub max_total_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EmptyProfile {}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Child {
    pub concurrency: usize,
    pub restart: Restart,
    pub tools: BTreeMap<String, Tool>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Restart {
    pub policy: RestartMode,
    pub max_attempts: usize,
    pub stability_window_ms: u64,
    pub backoff: Backoff,
    pub circuit: Circuit,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartMode {
    Never,
    OnFailure,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Backoff {
    pub initial_ms: u64,
    pub max_ms: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Circuit {
    pub cooldown_ms: u64,
    pub half_open_attempts: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub class: ToolClass,
    pub profiles: Vec<String>,
    pub concurrency: usize,
}

pub fn load(config_dir: &Path) -> Result<Mode> {
    let parent = config_dir
        .parent()
        .context("Gateway config directory has no parent")?;
    let path = parent.join("gateway.yaml");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Mode::LegacyCompat);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "Gateway policy must be a regular non-symlink file: {}",
            path.display()
        );
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let config: Config = serde_yaml::from_str(&text)
        .with_context(|| format!("invalid Gateway policy {}", path.display()))?;
    validate(&config)?;
    Ok(Mode::Strict(Box::new(config)))
}

pub fn validate(config: &Config) -> Result<()> {
    if config.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported Gateway policy schema_version {}",
            config.schema_version
        );
    }
    if config.profiles.is_empty()
        || !valid_name(&config.active_profile)
        || !config.profiles.contains_key(&config.active_profile)
        || config.profiles.keys().any(|name| !valid_name(name))
    {
        bail!("Gateway active_profile must name a declared valid profile");
    }
    if config.limits.global_active == 0
        || config.limits.global_queue == 0
        || config.limits.queue_wait_ms == 0
        || config.limits.default_child_active == 0
    {
        bail!("Gateway scheduler limits must be non-zero");
    }
    for class in ToolClass::ALL {
        let Some(limit) = config.tool_class_defaults.get(&class) else {
            bail!("Gateway policy lacks a default limit for {class:?}");
        };
        if limit.concurrency == 0 || limit.concurrency > config.limits.global_active {
            bail!("Gateway class limit for {class:?} is out of bounds");
        }
    }
    if config.drain.deadline_ms == 0
        || config.payload.request_bytes == 0
        || config.payload.response_bytes == 0
        || config.payload.text_preview_bytes == 0
        || config.payload.structured_bytes == 0
        || config.payload.binary_bytes == 0
        || config.artifacts.ttl_seconds == 0
        || config.artifacts.max_item_bytes == 0
        || config.artifacts.max_total_bytes == 0
        || config.artifacts.max_item_bytes > config.artifacts.max_total_bytes
    {
        bail!("Gateway drain, payload and artifact limits must be non-zero and bounded");
    }
    for (child, child_policy) in &config.children {
        if !valid_name(child)
            || child_policy.concurrency == 0
            || child_policy.concurrency > config.limits.global_active
            || child_policy.restart.max_attempts == 0
            || child_policy.restart.stability_window_ms == 0
            || child_policy.restart.backoff.initial_ms == 0
            || child_policy.restart.backoff.initial_ms > child_policy.restart.backoff.max_ms
            || child_policy.restart.circuit.cooldown_ms == 0
            || child_policy.restart.circuit.half_open_attempts == 0
        {
            bail!("Gateway child policy for {child} is invalid");
        }
        for (tool, tool_policy) in &child_policy.tools {
            if !valid_name(tool)
                || tool_policy.concurrency == 0
                || tool_policy.concurrency > config.limits.global_active
                || tool_policy.profiles.is_empty()
                || tool_policy
                    .profiles
                    .iter()
                    .any(|profile| !config.profiles.contains_key(profile))
            {
                bail!("Gateway tool policy for {child}.{tool} is invalid");
            }
        }
    }
    Ok(())
}

pub fn validate_catalog(
    config: &Config,
    children: &BTreeMap<String, BTreeSet<String>>,
    allowlists: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    for (child, child_policy) in &config.children {
        let Some(discovered) = children.get(child) else {
            bail!("Gateway policy references unknown child {child}");
        };
        for tool in child_policy.tools.keys() {
            if !discovered.contains(tool) {
                bail!("Gateway policy references unknown tool {child}.{tool}");
            }
            if let Some(allowlist) = allowlists.get(child)
                && !allowlist.is_empty()
                && !allowlist.contains(tool)
            {
                bail!("Gateway policy exposes tool excluded by child allowlist: {child}.{tool}");
            }
        }
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        serde_yaml::from_str("schema_version: 1\nactive_profile: develop\nlimits: {global_active: 16, global_queue: 64, queue_wait_ms: 30000, default_child_active: 4}\ntool_class_defaults: {read: {concurrency: 4}, mutation: {concurrency: 1}, long-running: {concurrency: 1}, control: {concurrency: 1}}\ndrain: {deadline_ms: 60000, allow_safe_reads: false}\npayload: {request_bytes: 1, response_bytes: 2, text_preview_bytes: 1, structured_bytes: 1, binary_bytes: 1}\nartifacts: {enabled: false, ttl_seconds: 1, max_item_bytes: 1, max_total_bytes: 1}\nprofiles: {inspect: {}, develop: {}}\nchildren:\n  filesystem:\n    concurrency: 4\n    restart: {policy: on-failure, max_attempts: 3, stability_window_ms: 30000, backoff: {initial_ms: 500, max_ms: 30000}, circuit: {cooldown_ms: 60000, half_open_attempts: 1}}\n    tools:\n      read_text_file: {class: read, profiles: [inspect, develop], concurrency: 4}\n").unwrap()
    }

    #[test]
    fn valid_policy_is_accepted() {
        validate(&config()).unwrap();
    }

    #[test]
    fn unknown_fields_and_invalid_limits_fail_closed() {
        let mut invalid = config();
        invalid.limits.global_active = 0;
        assert!(validate(&invalid).is_err());
        assert!(serde_yaml::from_str::<Config>("schema_version: 1\nunexpected: true\n").is_err());
    }

    #[test]
    fn catalog_validation_rejects_unexposed_tools() {
        let children = BTreeMap::from([(
            "filesystem".into(),
            BTreeSet::from(["read_text_file".into()]),
        )]);
        let allowlists = BTreeMap::from([("filesystem".into(), BTreeSet::new())]);
        validate_catalog(&config(), &children, &allowlists).unwrap();
        let blocked = BTreeMap::from([("filesystem".into(), BTreeSet::from(["other".into()]))]);
        assert!(validate_catalog(&config(), &children, &blocked).is_err());
    }
}
