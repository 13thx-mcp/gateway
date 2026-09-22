#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn request(socket: &Path, body: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    serde_json::to_writer(&mut stream, &body).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn control_socket_owns_drain_generation_and_lifecycle() {
    let root = std::env::temp_dir().join(format!(
        "gateway-control-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let servers = root.join("servers.d");
    fs::create_dir(&servers).unwrap();
    let socket = root.join("control/gateway.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rust-mcp-gateway"))
        .arg("--config-dir")
        .arg(&servers)
        .arg("--no-watch")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let started = Instant::now();
    while !socket.exists() {
        assert!(started.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }

    let status = request(&socket, json!({"version": 1, "action": "status"}));
    assert_eq!(status["ok"], true);
    assert_eq!(status["state"], "RUNNING");
    assert_eq!(status["drain_generation"], 0);
    assert_eq!(status["catalog_generation"], 1);
    assert!(status["instance_id"].as_str().is_some());

    let invalid = request(&socket, json!({"version": 1, "action": "drain"}));
    assert_eq!(invalid["ok"], false);
    assert_eq!(invalid["error"]["code"], "invalid_request");

    let drained = request(
        &socket,
        json!({"version": 1, "action": "drain", "reason": "gateway_update"}),
    );
    assert_eq!(drained["ok"], true);
    assert_eq!(drained["state"], "DRAINED");
    assert_eq!(drained["drain_generation"], 1);

    let stale = request(
        &socket,
        json!({"version": 1, "action": "resume", "drain_generation": 2}),
    );
    assert_eq!(stale["ok"], false);
    assert_eq!(stale["error"]["code"], "stale_drain_generation");

    let resumed = request(
        &socket,
        json!({"version": 1, "action": "resume", "drain_generation": 1}),
    );
    assert_eq!(resumed["ok"], true);
    assert_eq!(resumed["state"], "RUNNING");

    let reloaded = request(&socket, json!({"version": 1, "action": "reload"}));
    assert_eq!(reloaded["ok"], true);
    assert_eq!(reloaded["state"], "RUNNING");
    assert_eq!(reloaded["catalog_generation"], 2);

    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
}
