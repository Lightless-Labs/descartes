//! Linux-only `/proc` resolution. Compiled and tested ONLY on `target_os = "linux"` -- see
//! `main.rs` for the non-Linux stub path, which never reaches any code in this module.
//!
//! Slice 3 deliberately keeps resolution all-or-nothing: `resolve_pid` returns `None` unless the
//! uid, executable path, AND cmdline all read successfully. In particular, a status file that
//! reads fine but an unreadable `exe` symlink (EACCES on another UID's process today) still fails
//! the whole lookup -- we never emit a partial resolution. Cross-UID reads are exactly the gap
//! Slice 5/6's grant unlocks -- empirically the UNION `cap_sys_ptrace,cap_dac_read_search=ep`, not
//! `cap_sys_ptrace` alone (a real privileged CI run proved `cap_sys_ptrace`-only insufficient for
//! `find_owning_pid` below). `/proc/<pid>/fd` is a DIRECTORY whose kernel permission hook
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
//! reuses the same numeric pid. `find_owning_pid` in particular is PIN-THEN-VERIFY: it opens each
//! candidate's dirfd before it ever inspects that candidate's fd table, and on a match resolves
//! identity off that SAME dirfd -- it never returns a bare pid for a second, independent lookup.

use std::collections::HashSet;
use std::fs;
use std::os::fd::{AsFd, BorrowedFd};

use descartes_root_helper::procfs;

use crate::json::Resolved;

// This file itself still uses std free functions only (fs::read_to_string/read_dir), never `Read`
// trait methods on an open `File`, for the two things that are NOT per-pid identity data: the
// global /proc/net/tcp[6] listen-socket tables and the top-level /proc/[0-9]* directory listing
// (just pid numbers -- not that pid's own files). See the allowlist note on SYS_lseek in
// hardening.rs for why the free-functions-vs-Read-trait distinction matters under the seccomp
// filter. Every per-pid read (status/cmdline/exe/fd) is delegated to `procfs`, which uses raw
// `libc::read`/`readlinkat`/`getdents64` internally -- not `std::fs` at all -- see that module's
// doc for why (CLOEXEC-via-open-flag, not fcntl; bounded reads; dirfd-relative, never by path).

/// Upper bound on file-descriptor symlinks scanned per candidate process while hunting for the
/// socket inode that owns a requested port. Bounds worst-case syscall cost against a process with
/// a huge (possibly adversarial) fd table -- the `cap_sys_ptrace,cap_dac_read_search` grant
/// (Slice 5/6; see the module doc for why both capabilities, not `cap_sys_ptrace` alone) will
/// later let this scan reach other-UID processes, so the bound also caps how much of another
/// user's fd table this helper will ever walk on their behalf in a single call.
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
    let pid_dir = procfs::open_pid_dir(pid).ok()?;
    resolve_from_pid_dir(pid, pid_dir.as_fd())
}

/// Reads uid/exe/cmdline relative to an already-pinned `pid_dir`, all-or-nothing (see the module
/// doc). Shared by `resolve_pid` (which pins its own dirfd) and `find_owning_pid` (which pins a
/// dirfd while scanning for the owning pid and, on a match, resolves identity off that SAME
/// dirfd -- see that function for why never re-opening by pid number matters here).
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

/// Outcome of a port owner search. `resolved` is `Some` only on a complete resolution (all-or-
/// nothing, per the module doc). `truncated` is meaningful ONLY when `resolved` is `None`: the
/// search gave up short of a full scan (a candidate's `/proc/<pid>/fd` table hit
/// `MAX_FDS_PER_PROCESS`, or the pid walk hit `MAX_PROCESSES_SCANNED`), so "no owner" is UNCERTAIN
/// — the real owner may have been beyond a bound. It is NEVER set when an owner was resolved (the
/// answer is then complete regardless of any earlier candidate having been capped).
#[derive(Debug, PartialEq, Eq)]
pub struct PortResolution {
    pub resolved: Option<Resolved>,
    pub truncated: bool,
}

/// Resolves the pid of the process holding a LISTEN-state socket bound to `port`, plus whether the
/// (unsuccessful) owner search was truncated at a scan bound — see `PortResolution`. `resolved` is
/// `None` if no such listening socket exists, or if the owning process cannot be found or fully
/// resolved (Codex-hardening #6: a capped scan is then reported as `truncated`, observable rather
/// than a silent negative).
///
/// A port with multiple listening owners (SO_REUSEPORT, or a race during handoff) resolves to
/// whichever owning pid `find_owning_pid` happens to encounter first while walking `/proc` --
/// this is a recorded, deferred limitation (Layer B plan, Slice 3 section), not solved here.
pub fn resolve_port_detailed(port: u32) -> PortResolution {
    let inodes = listening_inodes_for_port(port);
    if inodes.is_empty() {
        // No listening socket at all: a definitive negative, nothing was scanned.
        return PortResolution {
            resolved: None,
            truncated: false,
        };
    }
    find_owning_pid(&inodes)
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

/// Scans `/proc/[0-9]*/fd/*` symlinks for a `socket:[<inode>]` target matching one of `inodes`,
/// and returns the FULLY RESOLVED record of the first match -- never a bare pid number that a
/// caller would then have to re-look-up.
///
/// PIN-THEN-VERIFY: each candidate's `/proc/<pid>` dirfd is opened (`pid_dir`) BEFORE its fd
/// table is ever inspected, and `"fd"` is opened (`fd_dir`) relative to THAT dirfd, once, and
/// reused for every `readlinkat` in the inner loop. On a match, identity is resolved off the SAME
/// `pid_dir` (`resolve_from_pid_dir`), never a fresh `/proc/<pid>` lookup by number. The earlier
/// shape here -- match a socket inode to a bare pid, then separately re-resolve that pid -- had a
/// reuse window right at the boundary between those two steps: the pid could be recycled in
/// between, producing a fully self-consistent record for the WRONG process at "confidence 1".
/// Pinning first removes that window entirely: everything below reads through ONE open directory
/// description per candidate, so a pid recycled mid-scan either keeps resolving against the
/// process this fd was opened for, or (once that process has actually exited) fails closed on the
/// very next relative read -- see `procfs`'s dead-pid test for why that failure is guaranteed, not
/// just likely.
///
/// Unreadable/vanished `/proc/<pid>` or `/proc/<pid>/fd` (EACCES on another UID's process today,
/// or ESRCH because the process already exited) are skipped SILENTLY -- EACCES on `/proc/<pid>/fd`
/// is exactly the gap `cap_dac_read_search` unlocks in a later slice (the fd DIRECTORY's
/// permission check, `proc_fd_permission`, is DAC-gated, not `ptrace_may_access` -- `cap_sys_ptrace`
/// alone does not reach it; `cap_sys_ptrace` covers the readlink of what's found once the
/// directory can be enumerated -- see the module doc), not an error condition here, and a
/// since-exited process is precisely the reuse hazard this module defends against, so it fails
/// closed the same way. First match wins (see `resolve_port_detailed`'s doc on the multi-owner limitation).
fn find_owning_pid(inodes: &HashSet<String>) -> PortResolution {
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return PortResolution {
            resolved: None,
            truncated: false,
        };
    };
    let mut scanned_processes = 0usize;
    // Codex-hardening #6: accumulate whether the search gave up short of a full scan. Only reported
    // on the no-owner path (a match makes any earlier cap-hit moot). A candidate whose fd table was
    // capped, OR hitting the pid-walk cap, means the eventual "no owner" is UNCERTAIN.
    let mut truncated = false;

    for entry in proc_dir.flatten() {
        if scanned_processes >= MAX_PROCESSES_SCANNED {
            truncated = true; // did not finish the pid walk -- a None below is uncertain.
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

        // Pin identity FIRST -- see the function doc.
        let Ok(pid_dir) = procfs::open_pid_dir(pid) else {
            continue; // gone or inaccessible by the time we got here -- skip, not fatal.
        };

        // "fd" opened and scanned ONCE per candidate, off the same pinned `pid_dir`; `fd_dir` is
        // reused for every `read_link_at` call below so the whole fd-table walk for this
        // candidate stays pinned to one open directory description.
        let Ok((fd_dir, fd_names)) =
            procfs::read_dir_entries_at(pid_dir.as_fd(), "fd", MAX_FDS_PER_PROCESS)
        else {
            continue;
        };

        for fd_name in &fd_names {
            let Some(fd_name) = fd_name.to_str() else {
                continue;
            };
            let Ok(target) = procfs::read_link_at(fd_dir.as_fd(), fd_name) else {
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
                // Resolve off the SAME already-open `pid_dir` -- never a fresh lookup by the bare
                // `pid` number. See the function doc. Truncation is moot once we have the owner.
                return PortResolution {
                    resolved: resolve_from_pid_dir(pid, pid_dir.as_fd()),
                    truncated: false,
                };
            }
        }

        // This candidate did not hold the socket; if its fd table was capped, the target could have
        // been among the fds we never enumerated -- so a final "no owner" is uncertain.
        if crate::scan::fd_scan_truncated(fd_names.len(), MAX_FDS_PER_PROCESS) {
            truncated = true;
        }
    }
    PortResolution {
        resolved: None,
        truncated,
    }
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
    fn resolve_port_resolves_back_to_the_test_process_for_a_socket_it_owns() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().unwrap().port() as u32;
        let resolved = resolve_port_detailed(port)
            .resolved
            .expect("must resolve the listener's owning pid");
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
        assert_eq!(resolve_port_detailed(port).resolved, None);
    }

    #[test]
    fn resolve_port_detailed_reports_a_complete_resolution_as_not_truncated() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().unwrap().port() as u32;
        let resolution = resolve_port_detailed(port);
        assert_eq!(
            resolution.resolved.map(|r| r.pid),
            Some(std::process::id())
        );
        assert!(
            !resolution.truncated,
            "a successful owner resolution is never flagged truncated"
        );
        drop(listener);
    }

    #[test]
    fn resolve_port_detailed_reports_a_definitive_no_owner_as_not_truncated() {
        // No listener on this port: a DEFINITIVE negative. On a normal test host /proc holds far
        // fewer than MAX_PROCESSES_SCANNED pids and no candidate has > MAX_FDS_PER_PROCESS fds, so
        // the search completes in full -- `truncated` must be false, distinguishing this genuine
        // "no owner" from the capped-scan "uncertain" case (Codex-hardening #6). The >cap truncated
        // case itself is covered by scan::fd_scan_truncated's host unit tests + the wiring above.
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = probe.local_addr().unwrap().port() as u32;
        drop(probe);
        let resolution = resolve_port_detailed(port);
        assert_eq!(resolution.resolved, None);
        assert!(
            !resolution.truncated,
            "a full-scan no-owner result is a definitive negative, not truncated"
        );
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
