//! Linux-only `/proc` resolution. Compiled and tested ONLY on `target_os = "linux"` -- see
//! `main.rs` for the non-Linux stub path, which never reaches any code in this module.
//!
//! Slice 3 deliberately keeps resolution all-or-nothing: `resolve_pid` returns `None` unless the
//! uid, executable path, AND cmdline all read successfully. In particular, a status file that
//! reads fine but an unreadable `exe` symlink (EACCES on another UID's process today) still fails
//! the whole lookup -- we never emit a partial resolution. Cross-UID reads are exactly the gap
//! Slice 5's CAP_SYS_PTRACE grant unlocks; until then, this binary can only ever fully resolve
//! processes it already shares a UID with, which is also all that's needed for the unit/
//! integration tests in this crate (they resolve the test's own process).

use std::collections::HashSet;
use std::fs;

use crate::json::Resolved;

/// Upper bound on file-descriptor symlinks scanned per candidate process while hunting for the
/// socket inode that owns a requested port. Bounds worst-case syscall cost against a process with
/// a huge (possibly adversarial) fd table -- CAP_SYS_PTRACE will later let this scan reach
/// other-UID processes, so the bound also caps how much of another user's fd table this helper
/// will ever walk on their behalf in a single call.
const MAX_FDS_PER_PROCESS: usize = 4096;

/// Upper bound on the number of numeric `/proc/<pid>` directories scanned while hunting for a
/// port's owning process. A real `/proc` realistically holds far fewer entries than this; the
/// bound exists so a pathological or adversarial `/proc` (e.g. a fork bomb mid-scan) cannot make
/// a single `--resolve-port` call run unbounded.
const MAX_PROCESSES_SCANNED: usize = 65536;

/// Resolves a single pid to its real uid, executable path, and command line. `None` on ANY
/// failure (no such pid, unreadable status/exe/cmdline, empty cmdline) -- see the module doc for
/// why this is intentionally all-or-nothing.
pub fn resolve_pid(pid: u32) -> Option<Resolved> {
    let uid = read_uid(pid)?;
    let executable_path = read_exe(pid)?;
    let command = read_cmdline(pid)?;
    Some(Resolved {
        pid,
        uid,
        executable_path,
        command,
    })
}

/// Resolves the pid of the process holding a LISTEN-state socket bound to `port`. `None` if no
/// such listening socket exists, or if the owning process cannot be found or fully resolved.
///
/// A port with multiple listening owners (SO_REUSEPORT, or a race during handoff) resolves to
/// whichever owning pid `find_owning_pid` happens to encounter first while walking `/proc` --
/// this is a recorded, deferred limitation (Layer B plan, Slice 3 section), not solved here.
pub fn resolve_port(port: u32) -> Option<Resolved> {
    let inodes = listening_inodes_for_port(port);
    if inodes.is_empty() {
        return None;
    }
    let owning_pid = find_owning_pid(&inodes)?;
    resolve_pid(owning_pid)
}

/// Reads the real uid from `/proc/<pid>/status`'s `Uid:` line, whose format is
/// `Uid:\t<real>\t<effective>\t<saved>\t<fs>` -- the real uid is the first whitespace-separated
/// field after the label.
fn read_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let real = rest.split_whitespace().next()?;
            return real.parse::<u32>().ok();
        }
    }
    None
}

fn read_exe(pid: u32) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    // Non-UTF-8 path bytes are lossily replaced with U+FFFD -- documented here rather than
    // rejecting the whole resolution over an unusual filename.
    Some(target.to_string_lossy().into_owned())
}

/// Reads `/proc/<pid>/cmdline` (NUL-separated argv, lossily decoded) and space-joins it into a
/// single display string. An empty cmdline (kernel threads, or a zombie mid-reap) is treated as a
/// failed resolution, not an empty-string success.
fn read_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(" "))
}

/// Parses `/proc/net/tcp` and `/proc/net/tcp6` for LISTEN-state (`st == "0A"`) sockets whose
/// local port matches `port`, returning their socket inode numbers as decimal strings (matching
/// the `socket:[<inode>]` fd-symlink target format used by `find_owning_pid`). A missing/
/// unreadable file (e.g. no IPv6 on this host) is skipped, not fatal -- the other family may
/// still yield a match.
fn listening_inodes_for_port(port: u32) -> HashSet<String> {
    const LOCAL_ADDRESS_COLUMN: usize = 1;
    const STATE_COLUMN: usize = 3;
    const INODE_COLUMN: usize = 9;
    const LISTEN_STATE: &str = "0A";

    let mut inodes = HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local_address), Some(state), Some(inode)) = (
                fields.get(LOCAL_ADDRESS_COLUMN),
                fields.get(STATE_COLUMN),
                fields.get(INODE_COLUMN),
            ) else {
                continue;
            };
            if !state.eq_ignore_ascii_case(LISTEN_STATE) {
                continue;
            }
            let Some(local_port_hex) = local_address.rsplit(':').next() else {
                continue;
            };
            let Ok(local_port) = u32::from_str_radix(local_port_hex, 16) else {
                continue;
            };
            if local_port == port {
                inodes.insert((*inode).to_string());
            }
        }
    }
    inodes
}

/// Scans `/proc/[0-9]*/fd/*` symlinks for a `socket:[<inode>]` target matching one of `inodes`.
/// Unreadable `/proc/<pid>/fd` directories (EACCES on another UID's process today) are skipped
/// SILENTLY -- that gap is exactly what CAP_SYS_PTRACE unlocks in a later slice, not an error
/// condition here. First match wins (see `resolve_port`'s doc on the multi-owner limitation).
fn find_owning_pid(inodes: &HashSet<String>) -> Option<u32> {
    let proc_dir = fs::read_dir("/proc").ok()?;
    let mut scanned_processes = 0usize;

    for entry in proc_dir.flatten() {
        if scanned_processes >= MAX_PROCESSES_SCANNED {
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue; // not a pid directory (e.g. "self", "net", "sys", ...).
        }
        scanned_processes += 1;

        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(fd_entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };

        for (scanned_fds, fd_entry) in fd_entries.flatten().enumerate() {
            if scanned_fds >= MAX_FDS_PER_PROCESS {
                break;
            }
            let Ok(target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let matches = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .is_some_and(|inode| inodes.contains(inode));
            if matches {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn resolve_pid_resolves_the_test_process_itself() {
        let own_pid = std::process::id();
        let resolved = resolve_pid(own_pid).expect("must resolve our own, same-uid pid");
        assert_eq!(resolved.pid, own_pid);
        // SAFETY-free: geteuid via std would need libc; comparing against /proc/self/status's own
        // reported uid is equivalent and dependency-free.
        let self_uid = read_uid(std::process::id()).expect("self status must be readable");
        assert_eq!(resolved.uid, self_uid);
        assert!(!resolved.executable_path.is_empty());
        assert!(!resolved.command.is_empty());
    }

    #[test]
    fn resolve_pid_fails_for_a_pid_that_almost_certainly_does_not_exist() {
        assert_eq!(resolve_pid(u32::MAX - 1), None);
    }

    #[test]
    fn resolve_port_resolves_back_to_the_test_process_for_a_socket_it_owns() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().unwrap().port() as u32;
        let resolved = resolve_port(port).expect("must resolve the listener's owning pid");
        assert_eq!(resolved.pid, std::process::id());
        drop(listener);
    }

    #[test]
    fn resolve_port_fails_for_a_port_nothing_is_listening_on() {
        // Bind-then-drop to get a port number that's very likely free right after; not
        // fully race-proof, but adequate for a negative-path sanity test.
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = probe.local_addr().unwrap().port() as u32;
        drop(probe);
        assert_eq!(resolve_port(port), None);
    }

    #[test]
    fn listening_inodes_for_port_finds_this_process_own_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().unwrap().port() as u32;
        let inodes = listening_inodes_for_port(port);
        assert!(
            !inodes.is_empty(),
            "expected at least one LISTEN-state inode for our own bound port"
        );
        drop(listener);
    }
}
