use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    time::timeout,
};

use crate::telemetry;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Status,
    History,
    Drain,
    Resume,
    Reload,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DrainReason {
    GatewayUpdate,
    Reconciliation,
    Operator,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    version: u8,
    action: Action,
    #[serde(default)]
    reason: Option<DrainReason>,
    #[serde(default)]
    drain_generation: Option<u64>,
    #[serde(default)]
    after_sequence: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub action: Action,
    pub drain_generation: Option<u64>,
    pub after_sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub ok: bool,
    pub instance_id: String,
    pub state: String,
    pub drain_generation: u64,
    pub active_requests: usize,
    pub queued_requests: usize,
    pub catalog_generation: u64,
    pub profile_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<telemetry::Batch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Error {
    pub code: &'static str,
}

pub struct Listener {
    listener: UnixListener,
    path: PathBuf,
}

impl Listener {
    pub async fn accept(&self) -> Result<UnixStream> {
        let (stream, _) = self.listener.accept().await?;
        Ok(stream)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn bind(config_dir: &Path) -> Result<Listener> {
    let runtime_root = config_dir
        .parent()
        .context("gateway config directory must have a runtime parent")?;
    let control_dir = runtime_root.join("control");
    match fs::symlink_metadata(&control_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("gateway control path is not a direct directory")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&control_dir)
                .with_context(|| format!("cannot create {}", control_dir.display()))?;
            #[cfg(unix)]
            fs::set_permissions(&control_dir, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }

    let path = control_dir.join("gateway.sock");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("gateway control socket path already exists"),
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("cannot bind gateway control socket {}", path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(Listener { listener, path })
}

pub async fn read_request(stream: &mut UnixStream) -> std::result::Result<Request, Error> {
    let mut line = Vec::new();
    let read = {
        let mut reader = BufReader::new(&mut *stream);
        timeout(REQUEST_TIMEOUT, reader.read_until(b'\n', &mut line)).await
    };
    let count = match read {
        Ok(Ok(count)) => count,
        _ => {
            return Err(Error {
                code: "invalid_request",
            });
        }
    };
    if count == 0 || count > MAX_REQUEST_BYTES || line.last() != Some(&b'\n') {
        return Err(Error {
            code: "invalid_request",
        });
    }
    let wire: WireRequest = serde_json::from_slice(&line[..line.len() - 1]).map_err(|_| Error {
        code: "invalid_request",
    })?;
    if wire.version != PROTOCOL_VERSION {
        return Err(Error {
            code: "unsupported_version",
        });
    }
    match wire.action {
        Action::Drain
            if wire.reason.is_none()
                || wire.drain_generation.is_some()
                || wire.after_sequence.is_some() =>
        {
            Err(Error {
                code: "invalid_request",
            })
        }
        Action::Resume
            if wire.reason.is_some()
                || wire.drain_generation.is_none()
                || wire.after_sequence.is_some() =>
        {
            Err(Error {
                code: "invalid_request",
            })
        }
        Action::History if wire.reason.is_some() || wire.drain_generation.is_some() => Err(Error {
            code: "invalid_request",
        }),
        Action::Status | Action::Reload
            if wire.reason.is_some()
                || wire.drain_generation.is_some()
                || wire.after_sequence.is_some() =>
        {
            Err(Error {
                code: "invalid_request",
            })
        }
        action => Ok(Request {
            action,
            drain_generation: wire.drain_generation,
            after_sequence: wire.after_sequence,
        }),
    }
}

pub async fn write_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let mut encoded = serde_json::to_vec(response).map_err(|error| anyhow!(error))?;
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_and_invalid_resume() {
        assert!(
            serde_json::from_str::<WireRequest>(
                r#"{"version":1,"action":"status","unexpected":true}"#
            )
            .is_err()
        );
        let request: WireRequest =
            serde_json::from_str(r#"{"version":1,"action":"resume"}"#).unwrap();
        assert!(matches!(request.action, Action::Resume));
        assert!(request.drain_generation.is_none());
    }
}
