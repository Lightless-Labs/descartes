//! Linux-only integration tests: run the BUILT BINARY against real `/proc` state for the test's
//! own process. The whole file compiles to nothing on non-Linux targets (see the inner
//! `#![cfg(...)]` below), rather than gating every individual test -- there is no Linux
//! resolution behavior to exercise elsewhere.

#![cfg(target_os = "linux")]

use std::net::TcpListener;
use std::process::Command;

fn bin_path() -> String {
    std::env::var("CARGO_BIN_EXE_descartes-root-helper").expect(
        "cargo sets CARGO_BIN_EXE_descartes-root-helper for integration tests in this package",
    )
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin_path())
        .args(args)
        .output()
        .expect("failed to spawn the built helper binary")
}

fn current_uid() -> u32 {
    // Dependency-free: read our own status the same way the helper reads any pid's, rather than
    // pulling in libc for geteuid().
    let status = std::fs::read_to_string(format!("/proc/{}/status", std::process::id())).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|s| s.parse::<u32>().ok())
        .expect("must be able to read our own real uid from /proc/self-equivalent status")
}

#[test]
fn resolve_pid_on_the_test_s_own_pid_returns_a_verified_matching_json_blob() {
    let own_pid = std::process::id();
    let output = run(&["--resolve-pid", &own_pid.to_string()]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a single JSON object");

    assert_eq!(
        parsed["requested"]["pid"], own_pid,
        "requested.pid must echo the numeric request exactly"
    );
    assert_eq!(parsed["resolved"]["pid"], own_pid);
    assert_eq!(parsed["resolved"]["uid"], current_uid());
    assert!(
        parsed["resolved"]["executable_path"]
            .as_str()
            .unwrap()
            .len()
            > 0
    );
    assert!(parsed["resolved"]["command"].as_str().unwrap().len() > 0);
}

#[test]
fn resolve_port_on_a_freshly_bound_listener_resolves_back_to_the_test_process() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();

    let output = run(&["--resolve-port", &port.to_string()]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a single JSON object");

    assert_eq!(parsed["requested"]["port"], port as u64);
    assert_eq!(parsed["resolved"]["pid"], std::process::id());
    assert_eq!(parsed["resolved"]["uid"], current_uid());

    drop(listener);
}

#[test]
fn resolve_pid_for_a_nonexistent_pid_fails_cleanly_with_no_stdout() {
    let output = run(&["--resolve-pid", "4294967294"]); // u32::MAX - 1, astronomically unlikely to be a real pid.
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn resolve_port_for_a_port_nobody_listens_on_fails_cleanly_with_no_stdout() {
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let output = run(&["--resolve-port", &port.to_string()]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
