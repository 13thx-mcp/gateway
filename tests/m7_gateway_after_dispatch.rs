#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = PathBuf::from("/private/tmp").join(format!(
            "gateway-after-dispatch-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<impl std::io::Read>,
    id: u64,
    body: Value,
) -> Value {
    serde_json::to_writer(&mut *stdin, &body).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "Gateway closed stdout"
        );
        let response: Value = serde_json::from_str(&line).unwrap();
        if response["id"] == id {
            return response;
        }
    }
}

fn request_collecting_notifications(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<impl std::io::Read>,
    id: u64,
    body: Value,
    notifications: &mut Vec<Value>,
) -> Value {
    serde_json::to_writer(&mut *stdin, &body).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "Gateway closed stdout"
        );
        let response: Value = serde_json::from_str(&line).unwrap();
        if response["id"] == id {
            return response;
        }
        notifications.push(response);
    }
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn control_request(socket: &Path, body: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    serde_json::to_writer(&mut stream, &body).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn strict_policy(active_profile: &str) -> String {
    format!(
        "schema_version: 1\nactive_profile: {active_profile}\nlimits: {{global_active: 2, global_queue: 4, queue_wait_ms: 1000, default_child_active: 1}}\ntool_class_defaults: {{read: {{concurrency: 1}}, mutation: {{concurrency: 1}}, long-running: {{concurrency: 1}}, control: {{concurrency: 1}}}}\ndrain: {{deadline_ms: 1000, allow_safe_reads: false}}\npayload: {{request_bytes: 1024, response_bytes: 1024, text_preview_bytes: 64, structured_bytes: 512, binary_bytes: 512}}\nartifacts: {{enabled: false, ttl_seconds: 60, max_item_bytes: 512, max_total_bytes: 1024}}\nprofiles: {{develop: {{}}, inspect: {{}}}}\nchildren:\n  profile:\n    concurrency: 1\n    restart: {{policy: on-failure, max_attempts: 3, stability_window_ms: 1000, backoff: {{initial_ms: 1, max_ms: 2}}, circuit: {{cooldown_ms: 10, half_open_attempts: 1}}}}\n    tools:\n      mutate: {{class: mutation, profiles: [develop], concurrency: 1}}\n"
    )
}

#[test]
fn timeout_after_dispatch_returns_unknown_without_replaying_child_mutation() {
    let root = TestRoot::new();
    let servers = root.0.join("servers.d");
    fs::create_dir(&servers).unwrap();
    let marker = root.0.join("child-events");
    let child = root.0.join("delayed-child.py");
    fs::write(
        &child,
        format!(
            r#"import json
import sys
import threading
import time

marker = {marker:?}
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        result = {{
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "delayed-child", "version": "test"}},
        }}
    elif method == "tools/list":
        result = {{"tools": [{{
            "name": "mutate",
            "description": "delayed mutation",
            "inputSchema": {{"type": "object", "properties": {{}}}},
        }}]}}
    elif method == "tools/call":
        with open(marker, "a", encoding="utf-8") as events:
            events.write("started\n")
        def complete():
            time.sleep(0.2)
            with open(marker, "a", encoding="utf-8") as events:
                events.write("completed\n")
        threading.Thread(target=complete, daemon=True).start()
        continue
    elif method == "notifications/cancelled":
        with open(marker, "a", encoding="utf-8") as events:
            events.write("cancelled\n")
        continue
    else:
        continue
    if request_id is not None:
        print(json.dumps({{"jsonrpc": "2.0", "id": request_id, "result": result}}), flush=True)
"#,
        ),
    )
    .unwrap();
    fs::write(
        servers.join("delayed.yaml"),
        format!(
            "name: delayed\ncommand: python3\nargs: [{}]\ntimeout_ms: 40\n",
            serde_json::to_string(&child).unwrap()
        ),
    )
    .unwrap();

    let mut gateway = Command::new(env!("CARGO_BIN_EXE_rust-mcp-gateway"))
        .arg("--config-dir")
        .arg(&servers)
        .arg("--no-watch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = gateway.stdin.take().unwrap();
    let mut stdout = BufReader::new(gateway.stdout.take().unwrap());

    let initialized = request(
        &mut stdin,
        &mut stdout,
        1,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "m7-test", "version": "1"}
            }
        }),
    );
    assert!(initialized["result"]["serverInfo"]["name"].is_string());
    serde_json::to_writer(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();

    let tools = request(
        &mut stdin,
        &mut stdout,
        2,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    );
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "mutate")
    );

    let result = request(
        &mut stdin,
        &mut stdout,
        3,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "mutate", "arguments": {}}
        }),
    );
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["structuredContent"]["code"],
        "child_outcome_unknown"
    );
    assert_eq!(result["result"]["structuredContent"]["retryable"], false);
    assert_eq!(result["result"]["structuredContent"]["outcome"], "unknown");

    let started = Instant::now();
    while !fs::read_to_string(&marker)
        .unwrap_or_default()
        .contains("started\n")
    {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "child events: {}",
            fs::read_to_string(&marker).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
    let events = fs::read_to_string(&marker).unwrap();
    assert_eq!(events.matches("started\n").count(), 1);
    assert!(events.contains("cancelled\n"));
    stop(&mut gateway);
}

#[test]
fn repeated_failed_child_catalog_refreshes_retain_last_known_good_generation() {
    let root = TestRoot::new();
    let servers = root.0.join("servers.d");
    fs::create_dir(&servers).unwrap();
    let child = root.0.join("catalog-child.py");
    fs::write(
        &child,
        r#"import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    request_id = message.get("id")
    if message.get("method") == "initialize":
        result = {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "catalog-child", "version": "test"},
        }
    elif message.get("method") == "tools/list":
        result = {"tools": [{
            "name": "mutate",
            "description": "catalog mutation",
            "inputSchema": {"type": "object", "properties": {}},
        }]}
    else:
        continue
    if request_id is not None:
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)
"#,
    )
    .unwrap();
    let config = servers.join("catalog.yaml");
    fs::write(
        &config,
        format!(
            "name: catalog\ncommand: python3\nargs: [{}]\ntimeout_ms: 1000\n",
            serde_json::to_string(&child).unwrap()
        ),
    )
    .unwrap();
    let socket = root.0.join("control/gateway.sock");
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_rust-mcp-gateway"))
        .arg("--config-dir")
        .arg(&servers)
        .arg("--no-watch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = gateway.stdin.take().unwrap();
    let mut stdout = BufReader::new(gateway.stdout.take().unwrap());
    let started = Instant::now();
    while !socket.exists() {
        assert!(started.elapsed() < Duration::from_secs(2));
        thread::sleep(Duration::from_millis(10));
    }

    let before = control_request(&socket, json!({"version": 1, "action": "status"}));
    let _initialized = request(
        &mut stdin,
        &mut stdout,
        10,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "m7-test", "version": "1"}
            }
        }),
    );
    serde_json::to_writer(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let initial_tools = request(
        &mut stdin,
        &mut stdout,
        11,
        json!({"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}}),
    );
    assert!(
        initial_tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "mutate")
    );

    fs::write(
        &config,
        "name: catalog\ncommand: missing-m7-catalog-child\ntimeout_ms: 1000\n",
    )
    .unwrap();
    for _ in 0..32 {
        let reloaded = control_request(&socket, json!({"version": 1, "action": "reload"}));
        assert_eq!(reloaded["ok"], true);
    }
    let after = control_request(&socket, json!({"version": 1, "action": "status"}));
    let retained_tools = request(
        &mut stdin,
        &mut stdout,
        12,
        json!({"jsonrpc": "2.0", "id": 12, "method": "tools/list", "params": {}}),
    );
    assert!(
        retained_tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "mutate")
    );
    assert_eq!(
        after["catalog_generation"].as_u64(),
        before["catalog_generation"]
            .as_u64()
            .map(|value| value + 32)
    );
    stop(&mut gateway);
}

#[test]
fn profile_reload_hides_disallowed_tool_and_notifies_tool_list_change() {
    let root = TestRoot::new();
    let servers = root.0.join("servers.d");
    fs::create_dir(&servers).unwrap();
    let child = root.0.join("profile-child.py");
    fs::write(
        &child,
        r#"import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    request_id = message.get("id")
    if message.get("method") == "initialize":
        result = {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "profile-child", "version": "test"},
        }
    elif message.get("method") == "tools/list":
        result = {"tools": [{
            "name": "mutate",
            "description": "profile mutation",
            "inputSchema": {"type": "object", "properties": {}},
        }]}
    else:
        continue
    if request_id is not None:
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)
"#,
    )
    .unwrap();
    fs::write(
        servers.join("profile.yaml"),
        format!(
            "name: profile\ncommand: python3\nargs: [{}]\ntimeout_ms: 1000\n",
            serde_json::to_string(&child).unwrap()
        ),
    )
    .unwrap();
    let policy = root.0.join("gateway.yaml");
    fs::write(&policy, strict_policy("develop")).unwrap();

    let mut gateway = Command::new(env!("CARGO_BIN_EXE_rust-mcp-gateway"))
        .arg("--config-dir")
        .arg(&servers)
        .arg("--no-watch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = gateway.stdin.take().unwrap();
    let mut stdout = BufReader::new(gateway.stdout.take().unwrap());
    let _initialized = request(
        &mut stdin,
        &mut stdout,
        20,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "m7-test", "version": "1"}
            }
        }),
    );
    serde_json::to_writer(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let initial_tools = request(
        &mut stdin,
        &mut stdout,
        21,
        json!({"jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {}}),
    );
    assert!(
        initial_tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "mutate")
    );

    fs::write(&policy, strict_policy("inspect")).unwrap();
    let mut notifications = Vec::new();
    let reloaded = request_collecting_notifications(
        &mut stdin,
        &mut stdout,
        22,
        json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {"name": "gateway_reload", "arguments": {}}
        }),
        &mut notifications,
    );
    assert!(reloaded["result"].is_object());
    assert!(
        notifications
            .iter()
            .any(|notification| notification["method"] == "notifications/tools/list_changed")
    );
    let filtered_tools = request(
        &mut stdin,
        &mut stdout,
        23,
        json!({"jsonrpc": "2.0", "id": 23, "method": "tools/list", "params": {}}),
    );
    assert!(
        !filtered_tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "mutate")
    );
    stop(&mut gateway);
}
