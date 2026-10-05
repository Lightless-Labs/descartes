//! Linux-only `/proc` resolution. Compiled and tested ONLY on `target_os = "linux"` -- see
//! `main.rs` for the non-Linux stub path, which never reaches any code in this module.
//!
//! Slice 3 deliberately keeps resolution all-or-nothing: `resolve_pid` returns `None` unless the
//! uid, executable path, AND cmdline all read successfully. In particular, a status file that
//! reads fine but an unreadable `exe` symlink (EACCES on another UID's process today) still fails
//! the whole lookup -- we never emit a partial resolution. Cross-UID reads are exactly the gap
//! Slice 5/6's grant unlocks -- empirically the UNION `cap_sys_ptrace,cap_dac_read_search=ep`, not
//! `cap_sys_ptrace` alone (a real privileged CI run proved `cap_sys_ptrace`-only insufficient for
//! `scan_holders` below). `/proc/<pid>/fd` is a DIRECTORY whose kernel permission hook
//! (`proc_fd_permission`) is DAC/same-thread-group gated, NOT `ptrace_may_access` -- so
//! *enumerating* another UID's fd table (this module's `getdents64` via
//! `procfs::read_dir_entries_at`) needs `cap_dac_read_search`; `cap_sys_ptrace` only covers the
//! subsequent `readlinkat` of the fd targets and of `exe`. Until the grant, this binary can only
//! ever fully resolve processes it already shares a UID with, which is also all that's needed for
//! the unit/integration tests in this crate (they resolve the test's own process).
//!
//! Slice 5 Part A: every per-pid read (status/cmdline/exe, and the `"fd"` table walked below)
//! goes through a `/proc/<pid>` DIRFD pinned ONCE via `descartes_root_helper::procfs::open_pid_dir`
//! -- never by re-opening `/proc/<pid>/...` by absolute path a second time. A bare pid number is
//! reusable by the kernel the instant its owning process is reaped; a multi-read window keyed
//! only on that number could silently read a mix of two different processes' data, or a fully
//! self-consistent record for the WRONG process. Pinning a dirfd at first contact and doing every
//! subsequent read relative to it removes that window: once the process behind a pinned dirfd
//! exits, `/proc` invalidates that directory's entries and every relative read fails closed (see
//! `procfs`'s dead-pid test) -- it can never start resolving a DIFFERENT process that later
//! reuses the same numeric pid. `scan_holders` in particular is PIN-THEN-VERIFY: it opens each
//! candidate's dirfd before it ever inspects that candidate's fd table, and on a match resolves
//! identity off that SAME dirfd -- it never returns a bare pid for a second, independent lookup.
//!
//! 2026-10 (`--resolve-socket`, research finding 2): socket resolution is bound to the exact
//! socket identity the caller observed -- protocol + port + inode -- not a bare port. See
//! `socket.rs` (the pure, host-tested decision logic) for the full rationale and contract.
//! `scan_holders` keeps the same PIN-THEN-VERIFY discipline as before, but now collects EVERY
//! holder of the inode (not the first), so disagreeing holders can be reported as ambiguous.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use descartes_root_helper::procfs;

use crate::json::Resolved;
use crate::socket::{self, SocketRow, SocketTarget};

// 2026-10: this file uses NO `std::fs` and NO `HashSet`. Every read -- the global
// `/proc/net/<protocol>` socket table and the top-level `/proc` pid listing included, not just
// the per-pid identity files -- goes through `procfs`'s raw `openat`/`read`/`getdents64`/
// `readlinkat` primitives, because the tightened seccomp policy (`seccomp_policy.rs`) no longer
// admits the statx/fstat/lseek that std's `read_to_string`/`read_dir` issue, nor the getrandom
// that `HashSet`'s RandomState seed draws. A future refactor back to `std::fs` here would
// self-SIGSYS under the live filter (caught by the CI live-filter tests in tests/hardening.rs and
// tests/linux_resolution.rs).

/// Bound on one `/proc/net/<protocol>` read. Each row is ~150 bytes, so this covers ~100k sockets
/// -- far beyond a realistic host -- while still bounding a single call. Hitting it is reported as
/// a truncated (uncertain) search, never a definitive negative.
const MAX_NET_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// Upper bound on file-descriptor symlinks scanned per candidate process while hunting for the
/// socket inode. Bounds worst-case syscall cost against a process with a huge (possibly
/// adversarial) fd table, and caps how much of another user's fd table this helper will ever walk
/// on their behalf in a single call.
const MAX_FDS_PER_PROCESS: usize = 4096;

/// Upper bound on `/proc` entries listed while hunting for holders. A real `/proc` holds far fewer;
/// the bound exists so a pathological `/proc` (e.g. a fork bomb mid-scan) cannot make a single call
/// run unbounded.
const MAX_PROCESSES_SCANNED: usize = 65536;

/// Resolves a single pid to its real uid, executable path, and command line. `None` on ANY
/// failure (no such pid, unreadable status/exe/cmdline, empty cmdline) -- see the module doc for
/// why this is intentionally all-or-nothing.
pub fn resolve_pid(pid: u32) -> Option<Resolved> {
    let pid_dir = procfs::open_pid_dir(pid).ok()?;
    resolve_from_pid_dir(pid, pid_dir.as_fd())
}

/// Reads uid/exe/cmdline relative to an already-pinned `pid_dir`, all-or-nothing (see the module
/// doc). Shared by `resolve_pid` (which pins its own dirfd) and `scan_holders` (which pins a dirfd
/// per candidate and, on a match, resolves identity off that SAME dirfd).
fn resolve_from_pid_dir(pid: u32, pid_dir: BorrowedFd<'_>) -> Option<Resolved> {
    let uid = read_uid(pid_dir)?;
    let executable_path = read_exe(pid_dir)?;
    let command = read_cmdline(pid_dir)?;
    Some(Resolved {
        pid,
        uid,
        executable_path,
        command,
    })
}

/// Outcome of `resolve_socket`; `main.rs` maps each variant to one exit code.
#[derive(Debug, PartialEq, Eq)]
pub enum SocketOutcome {
    /// Exit 0: `resolved` holds the exact socket; `holders` processes (all one executable) do.
    Resolved { resolved: Resolved, holders: usize },
    /// Exit 1: the socket no longer exists as observed (gone, rebound, different port, no longer
    /// LISTENing), no live holder was found, or it changed during resolution.
    NotFound,
    /// Exit 3: no holder found, but a bound was hit somewhere (socket table, `/proc` listing, or a
    /// non-holder's fd table) -- "not found" is uncertain.
    Truncated,
    /// Exit 5: holders disagree on executable: no single process can honestly be named the owner.
    Ambiguous,
}

/// One process found holding the target socket, with everything pinned for the consistency
/// re-check: its `/proc/<pid>` dirfd, its `fd` dirfd, and the fd name that linked to the socket.
struct Holder {
    resolved: Resolved,
    _pid_dir: OwnedFd,
    fd_dir: OwnedFd,
    fd_name: String,
}

/// See `socket.rs` for the contract. Sequence: admit the live row for the exact inode -> collect
/// every holder (pin-then-verify) -> select (or ambiguous) -> consistency re-check of BOTH the
/// chosen holder's fd link and the socket row against what was admitted.
pub fn resolve_socket(target: &SocketTarget) -> SocketOutcome {
    let Ok(proc_root) = procfs::open_proc_root() else {
        return SocketOutcome::NotFound;
    };
    let (row, table_truncated) = read_socket_row(proc_root.as_fd(), target);
    let Some(row) = row else {
        return if table_truncated {
            SocketOutcome::Truncated
        } else {
            SocketOutcome::NotFound
        };
    };
    if !socket::row_admits(&row, target) {
        return SocketOutcome::NotFound;
    }

    let scan = scan_holders(proc_root.as_fd(), &target.fd_link(), row.uid);
    if scan_requires_truncated_outcome(scan.truncated, scan.holder_count) {
        return SocketOutcome::Truncated;
    }
    if scan.ambiguous {
        return SocketOutcome::Ambiguous;
    }
    let Some(holder) = scan.selected else {
        return if scan.truncated {
            SocketOutcome::Truncated
        } else {
            SocketOutcome::NotFound
        };
    };
    let holders = scan.holder_count;

    // Consistency ("generation") re-check: the chosen holder must STILL hold this exact socket
    // (a close/handoff since the scan would otherwise be reported as current), and the socket row
    // must be unchanged (same address/port/state/uid) -- a rebind of the port to a new socket
    // gives a new inode and fails the row lookup; a state change fails the equality.
    let still_held = procfs::read_link_at(holder.fd_dir.as_fd(), &holder.fd_name)
        .ok()
        .is_some_and(|link| link.to_str() == Some(target.fd_link().as_str()));
    let (row_again, _) = read_socket_row(proc_root.as_fd(), target);
    if !still_held || row_again.as_ref() != Some(&row) {
        return SocketOutcome::NotFound;
    }

    SocketOutcome::Resolved {
        resolved: holder.resolved,
        holders,
    }
}

/// Reads ONLY `/proc/net/<target.protocol>` and returns the row whose inode is exactly
/// `target.inode` (no port/state judgement here -- see `socket::row_admits`), plus whether the
/// table read was truncated at `MAX_NET_TABLE_BYTES`.
fn read_socket_row(proc_root: BorrowedFd<'_>, target: &SocketTarget) -> (Option<SocketRow>, bool) {
    let Ok(net_dir) = procfs::open_dir_at(proc_root, "net") else {
        return (None, true);
    };
    let table = target
        .protocol
        .net_table()
        .strip_prefix("net/")
        .expect("socket protocol table must be relative to /proc/net");
    let Ok((bytes, truncated)) =
        procfs::read_file_at_bounded(net_dir.as_fd(), table, MAX_NET_TABLE_BYTES)
    else {
        return (None, true);
    };
    (
        socket::find_row(&String::from_utf8_lossy(&bytes), target.inode),
        truncated,
    )
}

struct HolderScan {
    selected: Option<Holder>,
    holder_count: usize,
    first_executable_path: Option<String>,
    ambiguous: bool,
    /// A bound was hit on a NON-holder (or on the `/proc` listing): another holder may be unseen.
    truncated: bool,
}

fn is_vanished_proc_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
}

fn scan_error_is_truncated(error: &std::io::Error) -> bool {
    !is_vanished_proc_error(error)
}

fn candidate_is_better(candidate: &Holder, current: &Holder, socket_uid: u32) -> bool {
    let candidate_matches_uid = candidate.resolved.uid == socket_uid;
    let current_matches_uid = current.resolved.uid == socket_uid;
    match (candidate_matches_uid, current_matches_uid) {
        (true, false) => true,
        (false, true) => false,
        _ => candidate.resolved.pid < current.resolved.pid,
    }
}

fn scan_requires_truncated_outcome(truncated: bool, holder_count: usize) -> bool {
    truncated && holder_count > 0
}

/// Scans `/proc/[0-9]*/fd/*` for EVERY process holding `needle` (`socket:[<inode>]`), resolving
/// each holder's identity off the SAME pinned dirfd its fd table was read through.
///
/// PIN-THEN-VERIFY: each candidate's `/proc/<pid>` dirfd is opened BEFORE its fd table is
/// inspected, `"fd"` is opened relative to THAT dirfd once, and identity is resolved off the same
/// `pid_dir` -- never a fresh `/proc/<pid>` lookup by number -- so a pid recycled mid-scan either
/// keeps resolving the process the fd was opened for or fails closed (see `procfs`'s dead-pid
/// test). Unreadable/vanished candidates are skipped; ENOENT/ESRCH are expected procfs races, while
/// every other open/getdents error also marks the scan uncertain. A holder whose identity cannot
/// be fully resolved (it exited between the fd match and the identity read) no longer holds
/// anything and is skipped too.
fn scan_holders(proc_root: BorrowedFd<'_>, needle: &str, socket_uid: u32) -> HolderScan {
    let mut scan = HolderScan {
        selected: None,
        holder_count: 0,
        first_executable_path: None,
        ambiguous: false,
        truncated: false,
    };
    // The listing cap counts every `/proc` entry (a few dozen non-pid names included).
    let (_listing_fd, entries) =
        match procfs::read_dir_entries_at(proc_root, ".", MAX_PROCESSES_SCANNED) {
            Ok(result) => result,
            Err(error) => {
                // ENOENT/ESRCH is the normal race where the procfs directory vanished; every other
                // open or getdents failure makes a no-holder result uncertain.
                scan.truncated = scan_error_is_truncated(&error);
                return scan;
            }
        };
    scan.truncated = crate::scan::fd_scan_truncated(entries.len(), MAX_PROCESSES_SCANNED);
    let mut link_buf = vec![0u8; procfs::MAX_LINK_TARGET_BYTES];

    for name in &entries {
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue; // not a pid directory (e.g. "self", "net", "sys", ...).
        }
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        // Pin identity FIRST -- see the function doc.
        let pid_dir = match procfs::open_pid_dir(pid) {
            Ok(pid_dir) => pid_dir,
            Err(error) => {
                if scan_error_is_truncated(&error) {
                    scan.truncated = true;
                }
                continue;
            }
        };
        let (fd_dir, fd_names) =
            match procfs::read_dir_entries_at(pid_dir.as_fd(), "fd", MAX_FDS_PER_PROCESS) {
                Ok(result) => result,
                Err(error) => {
                    if scan_error_is_truncated(&error) {
                        scan.truncated = true;
                    }
                    continue;
                }
            };

        let mut matched_fd = None;
        for name in &fd_names {
            let Some(fd_name) = name.to_str() else {
                continue;
            };
            let Ok(target) = procfs::read_link_at_into(fd_dir.as_fd(), fd_name, &mut link_buf)
            else {
                continue;
            };
            if target == needle.as_bytes() {
                matched_fd = Some(fd_name.to_string());
                break;
            }
        }

        match matched_fd {
            Some(fd_name) => {
                if let Some(resolved) = resolve_from_pid_dir(pid, pid_dir.as_fd()) {
                    scan.holder_count += 1;
                    match scan.first_executable_path.as_ref() {
                        Some(first) if first != &resolved.executable_path => scan.ambiguous = true,
                        None => scan.first_executable_path = Some(resolved.executable_path.clone()),
                        _ => {}
                    }
                    let candidate = Holder {
                        resolved,
                        _pid_dir: pid_dir,
                        fd_dir,
                        fd_name,
                    };
                    if scan
                        .selected
                        .as_ref()
                        .is_none_or(|current| candidate_is_better(&candidate, current, socket_uid))
                    {
                        scan.selected = Some(candidate);
                    }
                }
            }
            None => {
                // This candidate did not show the socket; if its fd table was capped, it may hold
                // it beyond the fds enumerated.
                if crate::scan::fd_scan_truncated(fd_names.len(), MAX_FDS_PER_PROCESS) {
                    scan.truncated = true;
                }
            }
        }
    }
    scan
}

/// Reads the real uid from `/proc/<pid>/status`'s `Uid:` line, whose format is
/// `Uid:\t<real>\t<effective>\t<saved>\t<fs>` -- the real uid is the first whitespace-separated
/// field after the label. Reads relative to `pid_dir`, the dirfd pinned once for this whole
/// resolution -- see the module doc.
fn read_uid(pid_dir: BorrowedFd<'_>) -> Option<u32> {
    let status = procfs::read_file_at(pid_dir, "status").ok()?;
    let status = String::from_utf8_lossy(&status);
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let real = rest.split_whitespace().next()?;
            return real.parse::<u32>().ok();
        }
    }
    None
}

/// Reads relative to `pid_dir` -- see the module doc.
fn read_exe(pid_dir: BorrowedFd<'_>) -> Option<String> {
    let target = procfs::read_link_at(pid_dir, "exe").ok()?;
    // Non-UTF-8 path bytes are lossily replaced with U+FFFD -- documented here rather than
    // rejecting the whole resolution over an unusual filename.
    Some(target.to_string_lossy().into_owned())
}

/// Reads `/proc/<pid>/cmdline` (NUL-separated argv, lossily decoded) and space-joins it into a
/// single display string. An empty cmdline (kernel threads, or a zombie mid-reap) is treated as a
/// failed resolution, not an empty-string success. Reads relative to `pid_dir` -- see the module
/// doc.
fn read_cmdline(pid_dir: BorrowedFd<'_>) -> Option<String> {
    let raw = procfs::read_file_at(pid_dir, "cmdline").ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::Protocol;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    /// Looks up the inode of the socket bound to `port` in `/proc/net/<protocol>` (the test's own
    /// socket), filtering on `state` when given.
    fn inode_for(protocol: Protocol, port: u16, state: Option<&str>) -> u64 {
        let root = procfs::open_proc_root().expect("/proc must open");
        let (bytes, _) = procfs::read_file_at_bounded(root.as_fd(), protocol.net_table(), 1 << 24)
            .expect("socket table must read");
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local_port = f
                .get(1)
                .and_then(|a| a.rsplit(':').next())
                .and_then(|h| u16::from_str_radix(h, 16).ok());
            let state_ok =
                state.is_none_or(|s| f.get(3).is_some_and(|st| st.eq_ignore_ascii_case(s)));
            if local_port == Some(port) && state_ok {
                return f[9].parse().expect("inode column");
            }
        }
        panic!("no {protocol:?} row for port {port}");
    }

    fn target(protocol: Protocol, port: u16, inode: u64) -> SocketTarget {
        SocketTarget {
            protocol,
            port,
            inode,
        }
    }

    #[test]
    fn resolve_pid_resolves_the_test_process_itself() {
        let own_pid = std::process::id();
        let resolved = resolve_pid(own_pid).expect("must resolve our own, same-uid pid");
        assert_eq!(resolved.pid, own_pid);
        let pid_dir = procfs::open_pid_dir(own_pid).expect("self /proc/<pid> dir must open");
        let self_uid = read_uid(pid_dir.as_fd()).expect("self status must be readable");
        assert_eq!(resolved.uid, self_uid);
        assert!(!resolved.executable_path.is_empty());
        assert!(!resolved.command.is_empty());
    }

    #[test]
    fn resolve_pid_fails_for_a_pid_that_almost_certainly_does_not_exist() {
        assert_eq!(resolve_pid(u32::MAX - 1), None);
    }

    #[test]
    fn resolve_socket_resolves_our_own_tcp_listener_with_one_holder() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let inode = inode_for(Protocol::Tcp, port, Some("0A"));
        match resolve_socket(&target(Protocol::Tcp, port, inode)) {
            SocketOutcome::Resolved { resolved, holders } => {
                assert_eq!(resolved.pid, std::process::id());
                assert!(holders >= 1);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
        drop(listener);
    }

    #[test]
    fn resolve_socket_resolves_a_udp_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral udp port");
        let port = socket.local_addr().unwrap().port();
        let inode = inode_for(Protocol::Udp, port, None);
        assert!(matches!(
            resolve_socket(&target(Protocol::Udp, port, inode)),
            SocketOutcome::Resolved { .. }
        ));
    }

    #[test]
    fn resolve_socket_rejects_a_mismatched_protocol_port_or_stale_inode() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let inode = inode_for(Protocol::Tcp, port, Some("0A"));
        // Right inode, wrong table (TCP/UDP collision class): never attributed.
        assert_eq!(
            resolve_socket(&target(Protocol::Udp, port, inode)),
            SocketOutcome::NotFound
        );
        // Right inode, wrong port.
        assert_eq!(
            resolve_socket(&target(Protocol::Tcp, port.wrapping_add(1), inode)),
            SocketOutcome::NotFound
        );
        drop(listener);
        // The observed socket is gone; even if the port were rebound, the inode would differ.
        assert_eq!(
            resolve_socket(&target(Protocol::Tcp, port, inode)),
            SocketOutcome::NotFound
        );
    }

    #[test]
    fn resolve_socket_rejects_a_rebind_of_the_same_port_to_a_new_socket() {
        let first = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = first.local_addr().unwrap().port();
        let observed_inode = inode_for(Protocol::Tcp, port, Some("0A"));
        drop(first);
        // Something rebinds the same port between observation and helper resolution.
        let Ok(second) = TcpListener::bind(("127.0.0.1", port)) else {
            return; // port grabbed by someone else in between; nothing to assert.
        };
        assert_ne!(inode_for(Protocol::Tcp, port, Some("0A")), observed_inode);
        assert_eq!(
            resolve_socket(&target(Protocol::Tcp, port, observed_inode)),
            SocketOutcome::NotFound,
            "the observed socket is gone; the new listener on the same port must not be attributed"
        );
        drop(second);
    }

    #[test]
    fn resolve_socket_rejects_a_tcp_socket_that_is_not_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let client_port = client.local_addr().unwrap().port();
        let inode = inode_for(Protocol::Tcp, client_port, Some("01"));
        assert_eq!(
            resolve_socket(&target(Protocol::Tcp, client_port, inode)),
            SocketOutcome::NotFound
        );
        drop(client);
        drop(listener);
    }

    #[test]
    fn scan_holders_reports_a_complete_scan_as_not_truncated() {
        let root = procfs::open_proc_root().expect("/proc must open");
        let scan = scan_holders(root.as_fd(), "socket:[18446744073709551615]", u32::MAX);
        assert_eq!(scan.holder_count, 0);
        assert!(!scan.ambiguous);
    }

    #[test]
    fn only_non_vanished_scan_errors_make_a_scan_truncated() {
        for errno in [libc::EACCES, libc::EBADF, libc::EIO] {
            assert!(scan_error_is_truncated(&std::io::Error::from_raw_os_error(
                errno
            )));
        }
        for errno in [libc::ENOENT, libc::ESRCH] {
            assert!(!scan_error_is_truncated(
                &std::io::Error::from_raw_os_error(errno)
            ));
        }
    }

    #[test]
    fn a_truncated_scan_with_a_holder_must_not_resolve() {
        assert!(scan_requires_truncated_outcome(true, 1));
        assert!(!scan_requires_truncated_outcome(true, 0));
        assert!(!scan_requires_truncated_outcome(false, 1));
    }
}
