//! Linux-only integration tests: run the BUILT BINARY against real `/proc` state for the test's
//! own process. The whole file compiles to nothing on non-Linux targets (see the inner
//! `#![cfg(...)]` below), rather than gating every individual test -- there is no Linux
//! resolution behavior to exercise elsewhere.

#![cfg(target_os = "linux")]

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::thread;
use std::time::Duration;

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

fn duplicate_without_cloexec(listener: &TcpListener) -> OwnedFd {
    // SAFETY: duplicating a live listener fd creates an independently-owned descriptor; F_DUPFD
    // deliberately leaves FD_CLOEXEC clear so the child process can inherit this exact socket.
    let fd = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_DUPFD, 0) };
    assert!(
        fd >= 0,
        "F_DUPFD failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `fd` was returned by fcntl and is valid; explicitly clear the flag to make the
    // inheritance precondition visible even if the duplication primitive changes later.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    assert_eq!(
        ret,
        0,
        "F_SETFD failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `fd` is now owned solely by this OwnedFd.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn wait_for_inherited_socket(pid: u32, fd: i32, inode: &str) {
    let target = format!("socket:[{inode}]");
    for _ in 0..100 {
        let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}"));
        if link.is_ok_and(|path| path.to_string_lossy() == target) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("child {pid} did not retain fd {fd} for {target}");
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
    assert!(!parsed["resolved"]["executable_path"]
        .as_str()
        .unwrap()
        .is_empty());
    assert!(!parsed["resolved"]["command"].as_str().unwrap().is_empty());
}

/// Inode of the test's own socket bound to `port` in `/proc/net/<table>` (optionally filtered on
/// the `st` column). Read with plain std::fs -- this test process is not under the filter.
fn inode_for(table: &str, port: u16, state: Option<&str>) -> String {
    let text = std::fs::read_to_string(format!("/proc/net/{table}")).expect("socket table");
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let local_port = f
            .get(1)
            .and_then(|a| a.rsplit(':').next())
            .and_then(|h| u16::from_str_radix(h, 16).ok());
        let state_ok = state.is_none_or(|s| f.get(3).is_some_and(|st| st.eq_ignore_ascii_case(s)));
        if local_port == Some(port) && state_ok {
            return f[9].to_string();
        }
    }
    panic!("no /proc/net/{table} row for port {port}");
}

#[test]
fn resolve_socket_on_a_freshly_bound_listener_resolves_back_to_the_test_process() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let inode = inode_for("tcp", port, Some("0A"));

    let output = run(&["--resolve-socket", "tcp", &port.to_string(), &inode]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a single JSON object");

    // The full bound identity is echoed, so Node can verify it is the socket it observed.
    assert_eq!(parsed["requested"]["protocol"], "tcp");
    assert_eq!(parsed["requested"]["port"], port as u64);
    assert_eq!(parsed["requested"]["inode"], inode.as_str());
    assert_eq!(parsed["resolved"]["pid"], std::process::id());
    assert_eq!(parsed["resolved"]["uid"], current_uid());
    assert!(
        parsed["resolved"]["holders"]
            .as_u64()
            .is_some_and(|n| n >= 1),
        "the scan must report at least the test process as a holder"
    );

    drop(listener);
}

#[test]
fn resolve_socket_on_a_udp_socket_resolves_back_to_the_test_process() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral udp port");
    let port = socket.local_addr().unwrap().port();
    let inode = inode_for("udp", port, None);

    let output = run(&["--resolve-socket", "udp", &port.to_string(), &inode]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
    assert_eq!(parsed["requested"]["protocol"], "udp");
    assert_eq!(parsed["resolved"]["pid"], std::process::id());
}

/// Research finding 2's race classes, end to end through the built binary under the live filter:
/// wrong protocol for the inode, wrong port for the inode, and a socket that no longer exists (the
/// port rebound to a NEW socket) are all exit 1 with empty stdout -- never a confident answer.
#[test]
fn resolve_socket_never_attributes_a_different_or_vanished_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let inode = inode_for("tcp", port, Some("0A"));

    for (protocol, port_arg) in [("udp", port), ("tcp6", port), ("tcp", port.wrapping_add(1))] {
        let output = run(&["--resolve-socket", protocol, &port_arg.to_string(), &inode]);
        assert_eq!(output.status.code(), Some(1), "{protocol} {port_arg}");
        assert!(output.stdout.is_empty());
    }

    drop(listener);
    let rebound = TcpListener::bind(("127.0.0.1", port));
    let output = run(&["--resolve-socket", "tcp", &port.to_string(), &inode]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the observed socket is gone (rebound: {}); never attribute the new one",
        rebound.is_ok()
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn resolve_socket_rejects_a_tcp_socket_that_is_not_listening() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    let client_port = client.local_addr().unwrap().port();
    let inode = inode_for("tcp", client_port, Some("01"));

    let output = run(&["--resolve-socket", "tcp", &client_port.to_string(), &inode]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    drop(client);
    drop(listener);
}

#[test]
fn resolve_socket_streams_many_same_exe_holders_but_rejects_different_exes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let inode = inode_for("tcp", port, Some("0A"));
    let inherited = duplicate_without_cloexec(&listener);
    let inherited_fd = inherited.as_raw_fd();

    let mut different_exe = Command::new("sleep")
        .arg("5")
        .spawn()
        .expect("spawn a different-executable holder");
    wait_for_inherited_socket(different_exe.id(), inherited_fd, &inode);
    let output = run(&["--resolve-socket", "tcp", &port.to_string(), &inode]);
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    let _ = different_exe.kill();
    let _ = different_exe.wait();

    // A forked child has the same executable as this test process. Both holders are therefore
    // one program, and the streaming selector must retain the lowest-pid same-uid candidate.
    // SAFETY: the child executes only async-signal-safe libc sleep/_exit and inherits the already
    // opened listener; it performs no Rust runtime work after fork.
    let same_exe = unsafe { libc::fork() };
    assert!(
        same_exe >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if same_exe == 0 {
        unsafe {
            libc::sleep(5);
            libc::_exit(0);
        }
    }
    let same_exe = same_exe as u32;
    wait_for_inherited_socket(same_exe, inherited_fd, &inode);
    let output = run(&["--resolve-socket", "tcp", &port.to_string(), &inode]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(parsed["resolved"]["pid"], std::process::id());
    assert!(parsed["resolved"]["holders"]
        .as_u64()
        .is_some_and(|n| n >= 2));
    // SAFETY: terminate and reap the forked child so it cannot outlive the test or hold the fd.
    unsafe {
        libc::kill(same_exe as libc::pid_t, libc::SIGTERM);
        libc::waitpid(same_exe as libc::pid_t, std::ptr::null_mut(), 0);
    }
}

#[test]
fn resolve_pid_for_a_nonexistent_pid_fails_cleanly_with_no_stdout() {
    let output = run(&["--resolve-pid", "4294967294"]); // u32::MAX - 1, astronomically unlikely to be a real pid.
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
