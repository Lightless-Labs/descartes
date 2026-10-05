//! Linux-only `/proc` resolution. Compiled and tested ONLY on `target_os = "linux"` -- see
//! `main.rs` for the non-Linux stub path, which never reaches any code in this module.
//!
//! Slice 3 deliberately keeps resolution all-or-nothing: `resolve_pid` returns `None` unless the
//! uid, executable path, AND cmdline all read successfully. A blank cmdline is valid when the
//! executable link is readable; the executable remains the identity key. In particular, a status
//! file that reads fine but an unreadable `exe` symlink (EACCES on another UID's process today)
//! still fails the whole lookup -- we never emit a partial resolution. Cross-UID reads are exactly the gap
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
// `readlinkat`/`fstat` primitives, because the tightened seccomp policy (`seccomp_policy.rs`) no
// longer admits pathname-stat/newfstatat/lseek calls that std's `read_to_string`/`read_dir` issue,
// nor the getrandom
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

/// A bounded stable-enumeration proof may need another full `/proc` pass when a new process or a
/// reused PID appears between the holder scan and its selected-owner recheck.
const MAX_HOLDER_STABILITY_PASSES: usize = 3;

/// Resolves a single pid to its real uid, executable path, and command line. `None` on ANY
/// failure (no such pid, unreadable status/exe/cmdline) -- see the module doc for why this is
/// intentionally all-or-nothing. A blank cmdline is retained when exe is readable.
pub fn resolve_pid(pid: u32) -> Option<Resolved> {
    for attempt in 0..2 {
        let pid_dir = procfs::open_pid_dir(pid).ok()?;
        match resolve_from_pid_dir(pid, pid_dir.as_fd()) {
            Ok(resolved) => return Some(resolved),
            Err(IdentityFailure::GenerationChanged) if attempt == 0 => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Reads uid/exe/cmdline relative to an already-pinned `pid_dir`, all-or-nothing (see the module
/// doc). Shared by `resolve_pid` (which pins its own dirfd) and `scan_holders` (which pins a dirfd
/// per candidate and, on a match, resolves identity off that SAME dirfd).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityFailure {
    UnreadableUid,
    UnreadableExe,
    UnreadableCommand,
    GenerationChanged,
}

fn resolve_from_pid_dir(pid: u32, pid_dir: BorrowedFd<'_>) -> Result<Resolved, IdentityFailure> {
    let uid = read_uid(pid_dir).ok_or(IdentityFailure::UnreadableUid)?;
    let start_time = read_process_start_time(pid_dir).ok_or(IdentityFailure::UnreadableUid)?;
    let executable_path = read_exe(pid_dir).ok_or(IdentityFailure::UnreadableExe)?;
    let exe_identity = executable_identity(pid_dir)
        .map(|identity| (identity.device, identity.inode))
        .map_err(|_| IdentityFailure::UnreadableExe)?;
    let (argv, argv_truncated) = read_cmdline(pid_dir).ok_or(IdentityFailure::UnreadableCommand)?;
    // Bind the argv to the executable generation observed before it. A process can exec while
    // retaining its pid and socket; the path check catches a different target and the dev+ino
    // check catches an atomically replaced binary at the same path. Socket resolution retries the
    // whole attempt once.
    if read_exe(pid_dir).as_deref() != Some(executable_path.as_str())
        || executable_identity(pid_dir)
            .ok()
            .map(|identity| (identity.device, identity.inode))
            != Some(exe_identity)
    {
        return Err(IdentityFailure::GenerationChanged);
    }
    Ok(Resolved {
        pid,
        tgid: pid,
        start_time,
        executable_identity: exe_identity,
        uid,
        executable_path,
        argv,
        argv_truncated,
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
    /// Exit 6: the helper's `/proc` mount is from a different PID namespace than its own pid.
    ProcfsNamespaceMismatch,
    /// Internal retry signal: executable generation changed while the socket was being pinned.
    #[doc(hidden)]
    GenerationChanged,
}

/// One process found holding the target socket, with everything pinned for the consistency
/// re-check: its `/proc/<pid>` dirfd, its `fd` dirfd, and the fd name that linked to the socket.
struct Holder {
    resolved: Resolved,
    _pid_dir: OwnedFd,
    fd_dir: OwnedFd,
    fd_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    tgid: u32,
    start_time: u64,
}

/// See `socket.rs` for the contract. Sequence: admit the live row for the exact inode -> collect
/// every holder (pin-then-verify) -> select (or ambiguous) -> consistency re-check of BOTH the
/// chosen holder's fd link and the socket row against what was admitted -> re-enumerate `/proc`
/// until the PID set is stable. A non-converging set is ambiguous, never a sole-owner answer.
pub fn resolve_socket(target: &SocketTarget) -> SocketOutcome {
    resolve_with_one_generation_retry(|| resolve_socket_once(target))
}

fn resolve_with_one_generation_retry<F>(mut resolve_once: F) -> SocketOutcome
where
    F: FnMut() -> SocketOutcome,
{
    for attempt in 0..2 {
        match resolve_once() {
            SocketOutcome::GenerationChanged if attempt == 0 => continue,
            SocketOutcome::GenerationChanged => return SocketOutcome::Ambiguous,
            outcome => return outcome,
        }
    }
    SocketOutcome::Ambiguous
}

fn resolve_socket_once(target: &SocketTarget) -> SocketOutcome {
    let Ok(proc_root) = procfs::open_proc_root() else {
        return SocketOutcome::NotFound;
    };
    let (row, table_status) = read_socket_row(target);
    if table_status == SocketTableStatus::NamespaceMismatch {
        return SocketOutcome::ProcfsNamespaceMismatch;
    }
    let Some(row) = row else {
        return if table_status == SocketTableStatus::Truncated {
            SocketOutcome::Truncated
        } else {
            SocketOutcome::NotFound
        };
    };
    if !socket::row_admits(&row, target) {
        return SocketOutcome::NotFound;
    }

    let mut scan = scan_holders(proc_root.as_fd(), &target.fd_link(), row.uid);
    for pass in 0..MAX_HOLDER_STABILITY_PASSES {
        if scan.generation_changed {
            return SocketOutcome::GenerationChanged;
        }
        if scan.ambiguous {
            return SocketOutcome::Ambiguous;
        }
        if scan_requires_truncated_outcome(scan.truncated, scan.holder_count) {
            return SocketOutcome::Truncated;
        }
        let Some(holder) = scan.selected.as_ref() else {
            return if scan.truncated {
                SocketOutcome::Truncated
            } else {
                SocketOutcome::NotFound
            };
        };

        // Consistency ("generation") re-check: the chosen holder must STILL hold this exact
        // socket (a close/handoff since the scan would otherwise be reported as current), and the
        // socket row must be unchanged (same address/port/state/uid). A rebind of the port to a
        // new socket gives a new inode and fails the row lookup; a state change fails equality.
        let still_held = procfs::read_link_at(holder.fd_dir.as_fd(), &holder.fd_name)
            .ok()
            .is_some_and(|link| link.to_str() == Some(target.fd_link().as_str()));
        if !still_held {
            return SocketOutcome::GenerationChanged;
        }
        let (row_again, row_again_status) = read_socket_row(target);
        if row_again_status == SocketTableStatus::NamespaceMismatch {
            return SocketOutcome::ProcfsNamespaceMismatch;
        }
        if row_again.as_ref() != Some(&row) {
            return SocketOutcome::NotFound;
        }
        // Final executable-generation check closes the window between the holder identity read
        // and the fd/socket recheck. A changed path retries once, then becomes ambiguous.
        if procfs::read_link_at(holder._pid_dir.as_fd(), "exe")
            .ok()
            .is_none_or(|link| link.to_string_lossy() != holder.resolved.executable_path)
            || executable_identity(holder._pid_dir.as_fd())
                .ok()
                .map(|identity| (identity.device, identity.inode))
                != Some(holder.resolved.executable_identity)
        {
            return SocketOutcome::GenerationChanged;
        }

        let mut refreshed = scan_holders(proc_root.as_fd(), &target.fd_link(), row.uid);
        if refreshed.generation_changed {
            return SocketOutcome::GenerationChanged;
        }
        if crate::scan::snapshot_has_new_or_reused_pid(&scan.snapshot, &refreshed.snapshot) {
            if pass + 1 == MAX_HOLDER_STABILITY_PASSES {
                return SocketOutcome::Ambiguous;
            }
            scan = refreshed;
            continue;
        }

        // The final holder count comes from the stable enumeration, not the pre-recheck scan.
        if refreshed.ambiguous {
            return SocketOutcome::Ambiguous;
        }
        if scan_requires_truncated_outcome(refreshed.truncated, refreshed.holder_count) {
            return SocketOutcome::Truncated;
        }
        let Some(final_holder) = refreshed.selected.take() else {
            return if refreshed.truncated {
                SocketOutcome::Truncated
            } else {
                SocketOutcome::NotFound
            };
        };
        if procfs::read_link_at(final_holder.fd_dir.as_fd(), &final_holder.fd_name)
            .ok()
            .is_none_or(|link| link.to_str() != Some(target.fd_link().as_str()))
        {
            return SocketOutcome::GenerationChanged;
        }
        return SocketOutcome::Resolved {
            resolved: final_holder.resolved,
            holders: refreshed.holder_count,
        };
    }
    SocketOutcome::Ambiguous
}

/// Reads ONLY `/proc/<helper-pid>/net/<target.protocol>` and returns the row whose inode is exactly
/// `target.inode` (no port/state judgement here -- see `socket::row_admits`), plus whether the
/// table read was truncated at `MAX_NET_TABLE_BYTES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketTableStatus {
    Complete,
    Truncated,
    NamespaceMismatch,
}

fn read_socket_row(target: &SocketTarget) -> (Option<SocketRow>, SocketTableStatus) {
    let net_dir = match procfs::open_proc_net() {
        Ok(net_dir) => net_dir,
        Err(error) if error.to_string() == procfs::PROCFS_NAMESPACE_MISMATCH_REASON => {
            return (None, SocketTableStatus::NamespaceMismatch);
        }
        Err(_) => return (None, SocketTableStatus::Truncated),
    };
    let table = target
        .protocol
        .net_table()
        .strip_prefix("net/")
        .expect("socket protocol table must be relative to /proc/net");
    let Ok((bytes, truncated)) =
        procfs::read_file_at_bounded(net_dir.as_fd(), table, MAX_NET_TABLE_BYTES)
    else {
        return (None, SocketTableStatus::Truncated);
    };
    (
        socket::find_row(&String::from_utf8_lossy(&bytes), target.inode),
        if truncated {
            SocketTableStatus::Truncated
        } else {
            SocketTableStatus::Complete
        },
    )
}

struct HolderScan {
    selected: Option<Holder>,
    holder_count: usize,
    first_identity: Option<ProcessIdentity>,
    ambiguous: bool,
    generation_changed: bool,
    snapshot: Vec<crate::scan::ProcessSnapshot>,
    /// A bound was hit on a NON-holder (or on the `/proc` listing): another holder may be unseen.
    truncated: bool,
}

impl HolderScan {
    fn record_fd_link_failure(&mut self) {
        // A failed readlink can hide a matching holder; it is never a clean non-match.
        self.truncated = true;
    }

    fn record_identity_failure(&mut self, failure: IdentityFailure) {
        match failure {
            IdentityFailure::UnreadableExe => {
                // An unreadable executable is an explicit ambiguity: another executable may be
                // hidden behind the failed identity read.
                self.ambiguous = true;
                self.truncated = true;
            }
            IdentityFailure::GenerationChanged => self.generation_changed = true,
            IdentityFailure::UnreadableUid | IdentityFailure::UnreadableCommand => {
                // A known matching holder was omitted even if its executable could be read.
                self.truncated = true;
            }
        }
    }
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
/// test). Candidates that vanish before they are matched may be skipped, but every fd readlink
/// error and every matched holder identity failure marks the scan uncertain. An unreadable
/// executable is explicitly ambiguous; a blank cmdline is compared by executable path.
fn scan_holders(proc_root: BorrowedFd<'_>, needle: &str, socket_uid: u32) -> HolderScan {
    let mut scan = HolderScan {
        selected: None,
        holder_count: 0,
        first_identity: None,
        ambiguous: false,
        generation_changed: false,
        snapshot: Vec::new(),
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
        let Some(start_time) = read_process_start_time(pid_dir.as_fd()) else {
            scan.truncated = true;
            continue;
        };
        scan.snapshot.push(crate::scan::ProcessSnapshot {
            pid,
            tgid: pid,
            start_time,
        });
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
                scan.record_fd_link_failure();
                continue;
            };
            if target == needle.as_bytes() {
                matched_fd = Some(fd_name.to_string());
                break;
            }
        }

        match matched_fd {
            Some(fd_name) => {
                match resolve_from_pid_dir(pid, pid_dir.as_fd()) {
                    Ok(resolved) => {
                        scan.holder_count += 1;
                        let identity = ProcessIdentity {
                            tgid: resolved.tgid,
                            start_time: resolved.start_time,
                        };
                        match scan.first_identity {
                            Some(first) if first != identity => scan.ambiguous = true,
                            None => scan.first_identity = Some(identity),
                            _ => {}
                        }
                        let candidate = Holder {
                            resolved,
                            _pid_dir: pid_dir,
                            fd_dir,
                            fd_name,
                        };
                        if scan.selected.as_ref().is_none_or(|current| {
                            candidate_is_better(&candidate, current, socket_uid)
                        }) {
                            scan.selected = Some(candidate);
                        }
                    }
                    Err(failure) => scan.record_identity_failure(failure),
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

/// Reads field 22 (`starttime`) from `/proc/<pid>/stat`. The command name is parenthesized and may
/// itself contain `)`, so split at the final closing parenthesis before indexing the remaining
/// fields. Top-level `/proc/<pid>` entries are TGIDs, so the caller's pid is the TGID in the
/// process identity tuple.
fn read_process_start_time(pid_dir: BorrowedFd<'_>) -> Option<u64> {
    let stat = procfs::read_file_at(pid_dir, "stat").ok()?;
    let stat = String::from_utf8_lossy(&stat);
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Reads relative to `pid_dir` -- see the module doc.
fn read_exe(pid_dir: BorrowedFd<'_>) -> Option<String> {
    let target = procfs::read_link_at(pid_dir, "exe").ok()?;
    // Non-UTF-8 path bytes are lossily replaced with U+FFFD -- documented here rather than
    // rejecting the whole resolution over an unusual filename.
    Some(target.to_string_lossy().into_owned())
}

/// Opens the fixed procfs `exe` entry and obtains its mapped file identity from the already-open
/// descriptor. This deliberately avoids pathname-based metadata (`newfstatat`); the descriptor is
/// tied to the pinned `/proc/<pid>` directory and `fstat` has no path argument.
fn executable_identity(pid_dir: BorrowedFd<'_>) -> std::io::Result<procfs::FileIdentity> {
    let exe = procfs::open_exe_at(pid_dir)?;
    procfs::fstat(exe.as_fd())
}

/// Reads `/proc/<pid>/cmdline` as NUL-separated argv elements. An empty cmdline (blanked argv, a
/// kernel thread, or a zombie mid-reap) is a valid identity component when the executable link is
/// readable. The JSON boundary preserves these elements so downstream redaction cannot mistake
/// spaces inside one argument for separate argv values. Reads relative to `pid_dir`.
fn read_cmdline(pid_dir: BorrowedFd<'_>) -> Option<(Vec<String>, bool)> {
    let (raw, truncated) = procfs::read_file_at_bounded(pid_dir, "cmdline", 65_536).ok()?;
    Some((decode_cmdline(&raw), truncated))
}

fn decode_cmdline(raw: &[u8]) -> Vec<String> {
    if raw.is_empty() {
        return Vec::new();
    }
    let mut parts = raw.split(|&b| b == 0).collect::<Vec<_>>();
    // A complete proc cmdline has one framing NUL after the final argv element. Remove only that
    // terminator; empty elements inside argv (including an empty argv[0]) remain observable.
    if raw.last() == Some(&0) {
        parts.pop();
    }
    parts
        .into_iter()
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::Protocol;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    /// Looks up the inode of the socket bound to `port` in `/proc/net/<protocol>` (the test's own
    /// socket), filtering on `state` when given.
    fn inode_for(protocol: Protocol, port: u16, state: Option<&str>) -> u64 {
        let net_dir = procfs::open_proc_net().expect("/proc/<pid>/net must open");
        let table = protocol
            .net_table()
            .strip_prefix("net/")
            .expect("socket protocol table must be relative to /proc/net");
        let (bytes, _) = procfs::read_file_at_bounded(net_dir.as_fd(), table, 1 << 24)
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
        assert!(!resolved.argv.is_empty());
    }

    #[test]
    fn blank_cmdline_is_not_an_identity_read_failure_when_exe_is_available() {
        assert_eq!(decode_cmdline(b"\0\0"), vec!["", ""]);
        assert_eq!(decode_cmdline(b"app\0--serve\0"), vec!["app", "--serve"]);
        assert_eq!(
            decode_cmdline(b"app\0\0--serve\0"),
            vec!["app", "", "--serve"]
        );
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
    fn matched_holder_read_failures_are_never_silently_dropped() {
        let mut scan = HolderScan {
            selected: None,
            holder_count: 0,
            first_identity: None,
            ambiguous: false,
            generation_changed: false,
            snapshot: Vec::new(),
            truncated: false,
        };
        scan.record_fd_link_failure();
        assert!(scan.truncated);

        scan.truncated = false;
        scan.record_identity_failure(IdentityFailure::UnreadableCommand);
        assert!(scan.truncated);
        assert!(!scan.ambiguous);

        scan.record_identity_failure(IdentityFailure::UnreadableExe);
        assert!(scan.truncated);
        assert!(scan.ambiguous);
    }

    #[test]
    fn holder_identity_uses_tgid_and_start_time_not_executable_path() {
        let same_executable_different_processes = [
            ProcessIdentity {
                tgid: 100,
                start_time: 10,
            },
            ProcessIdentity {
                tgid: 101,
                start_time: 11,
            },
        ];
        assert_ne!(
            same_executable_different_processes[0],
            same_executable_different_processes[1]
        );
        assert_eq!(
            ProcessIdentity {
                tgid: 100,
                start_time: 10,
            },
            ProcessIdentity {
                tgid: 100,
                start_time: 10,
            }
        );
    }

    #[test]
    fn a_truncated_scan_with_a_holder_must_not_resolve() {
        assert!(scan_requires_truncated_outcome(true, 1));
        assert!(!scan_requires_truncated_outcome(true, 0));
        assert!(!scan_requires_truncated_outcome(false, 1));
    }

    #[test]
    fn executable_generation_change_retries_once_then_becomes_ambiguous() {
        let mut calls = 0;
        let outcome = resolve_with_one_generation_retry(|| {
            calls += 1;
            SocketOutcome::GenerationChanged
        });
        assert_eq!(outcome, SocketOutcome::Ambiguous);
        assert_eq!(calls, 2);

        let mut calls = 0;
        let outcome = resolve_with_one_generation_retry(|| {
            calls += 1;
            if calls == 1 {
                SocketOutcome::GenerationChanged
            } else {
                SocketOutcome::NotFound
            }
        });
        assert_eq!(outcome, SocketOutcome::NotFound);
        assert_eq!(calls, 2);
    }
}
