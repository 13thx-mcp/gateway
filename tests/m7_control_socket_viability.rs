use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use serde::{Deserialize, Serialize};

static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

fn private_socket_path() -> PathBuf {
    // Keep the sockaddr_un path short for macOS compatibility.
    // pid + a process-local monotonic counter avoids parallel-test collisions.
    let id = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("m7-{}-{id}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("c")).unwrap();
    root.join("c/g.sock")
}

fn cleanup(socket: &PathBuf) {
    let _ = fs::remove_file(socket);
    let _ = fs::remove_dir_all(socket.parent().unwrap().parent().unwrap());
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlAction {
    Status,
    Drain,
    Resume,
    Reload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControlRequest {
    version: u8,
    action: ControlAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StatusResponse {
    state: String,
    drain_generation: u64,
}

#[test]
fn private_unix_control_socket_can_round_trip_framed_typed_request() {
    let socket = private_socket_path();
    let listener = UnixListener::bind(&socket).unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request_line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request_line)
            .unwrap();

        let request: ControlRequest = serde_json::from_str(request_line.trim_end()).unwrap();
        assert_eq!(
            request,
            ControlRequest {
                version: 1,
                action: ControlAction::Status,
            }
        );

        let response = StatusResponse {
            state: "RUNNING".to_owned(),
            drain_generation: 0,
        };
        serde_json::to_writer(&mut stream, &response).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    });

    let mut client = UnixStream::connect(&socket).unwrap();
    serde_json::to_writer(
        &mut client,
        &ControlRequest {
            version: 1,
            action: ControlAction::Status,
        },
    )
    .unwrap();
    client.write_all(b"\n").unwrap();
    client.flush().unwrap();

    let mut response_line = String::new();
    BufReader::new(client)
        .read_line(&mut response_line)
        .unwrap();
    let response: StatusResponse = serde_json::from_str(response_line.trim_end()).unwrap();

    assert_eq!(
        response,
        StatusResponse {
            state: "RUNNING".to_owned(),
            drain_generation: 0,
        }
    );

    server.join().unwrap();
    cleanup(&socket);
}

#[test]
fn stale_socket_path_is_not_silently_reused() {
    let socket = private_socket_path();
    fs::write(&socket, b"not-a-socket").unwrap();

    assert!(UnixListener::bind(&socket).is_err());

    cleanup(&socket);
}

#[test]
fn drain_contract_carries_server_owned_generation() {
    let response = StatusResponse {
        state: "DRAINING".to_owned(),
        drain_generation: 7,
    };

    let encoded = serde_json::to_string(&response).unwrap();
    let decoded: StatusResponse = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded.state, "DRAINING");
    assert_eq!(decoded.drain_generation, 7);
}
