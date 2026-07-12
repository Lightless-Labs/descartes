//! Raw `/proc/<pid>` DIRFD-pinning primitives (S3-priv Slice 5 Part A). INTERNAL CONTRACT, NO
//! EXTERNAL CONSUMER -- this module exists solely so `proc_linux.rs` (a separate, `bin`-crate
//! module) can pin process identity to an open directory description instead of re-resolving a
//! bare pid number by path on every read. See `lib.rs`'s doc comment on the `pub mod procfs;`
//! declaration for why this has to be `pub` rather than `pub(crate)`.
//!
//! THE HAZARD THIS MODULE CLOSES: `proc_linux.rs` previously opened `/proc/<pid>/{status,cmdline,
//! exe}` by ABSOLUTE PATH, once per file, across a multi-read window. Between any two of those
//! opens, the kernel is free to reap `<pid>` and hand the same numeric pid to a brand-new,
//! unrelated process -- at which point the second open transparently starts reading THAT
//! process's files instead. The resulting record is fully self-consistent (every field came from
//! a real, currently-alive process) and therefore looks like a correct, high-confidence
//! resolution of the WRONG process. Every helper below instead opens `/proc/<pid>` ONCE
//! (`open_pid_dir`) and does every subsequent read relative to that one directory description
//! (`openat`/`readlinkat`/`getdents64` against the dirfd, never a second absolute-path lookup).
//! Once the pinned process exits, `/proc` invalidates that directory's dentries, so every relative
//! read through the pinned dirfd fails closed from then on -- it can never silently start
//! resolving whichever new process later reuses the same pid number. `proc_linux.rs`'s
//! `find_owning_pid` builds on this pin-then-verify: it opens a candidate's dirfd before ever
//! inspecting that candidate's fd table, and on a match resolves identity off that SAME dirfd,
//! never a bare pid handed back for a second, independent lookup.
//!
//! RAW `libc` ONLY -- no `rustix`/`nix`. `rustix` in particular can emit `openat2`, a syscall NOT
//! in `hardening.rs`'s seccomp allowlist; pulling it in (even unused) would risk a silent ABI/
//! syscall surface change this crate's zero-runtime-dep-beyond-`libc` policy exists to prevent
//! (see the Cargo.toml comment on the `libc` dependency). Every unsafe block below carries a
//! `// SAFETY:` comment -- `lib.rs` is `#![deny(unsafe_op_in_unsafe_fn)]`, and this file is one of
//! the few in this crate where `unsafe` is allowed at all (see `lib.rs` and `hardening.rs`'s
//! module docs).
//!
//! `O_CLOEXEC` is set via the OPEN FLAG on every `openat` call below, NEVER retrofitted with a
//! later `fcntl(F_SETFD)`. That rule is unchanged; only its enforcement moved. `fcntl` IS in
//! `hardening.rs`'s seccomp allowlist -- but solely because std's `OwnedFd` `Drop`, in
//! debug-assertions builds only, issues `fcntl(fd, F_GETFD)` as an fd-validity assertion before
//! `close` (which self-SIGSYSed every debug `cargo test` of resolution until it was allowlisted).
//! This module still never issues `fcntl` itself; the "via open flag, never F_SETFD" rule is now
//! enforced by review + the security-review-required rule on any allowlist change, not by the
//! filter. Even so, an fd stripped of CLOEXEC could not escape this process: no `exec*` and no
//! `socket*` are allowlisted, so there is nothing to survive an exec or pass it over.
//!
//! Every public function here returns an owned, safe value (`OwnedFd`, `Vec<u8>`, `OsString`) --
//! never a raw fd or pointer -- so callers in `proc_linux.rs` never touch `unsafe` themselves.
//! Syscalls issued in this file: `openat`, `read`, `readlinkat`, `getdents64` (plus `close`, and --
//! in debug-assertions builds only -- `fcntl(F_GETFD)`, both via `OwnedFd`'s `Drop` impl in std).
//! All are in `hardening.rs`'s `allowed_syscalls()` allowlist; this module issues no syscall that
//! isn't already allowed there.

use std::ffi::{CString, OsString};
use std::io;
use std::mem::offset_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;

/// Bound applied to every `read_file_at` call, regardless of which `/proc/<pid>` file is being
/// read. Generous for both of this crate's callers -- `status` is a few hundred bytes; `cmdline`
/// can run much longer for a process with many/long arguments -- but the helper's own JSON
/// contract (`json::MAX_FIELD_BYTES`, 2048 bytes) truncates whatever this yields for display
/// anyway, so there is no real caller need for anything close to this bound in practice. It
/// exists purely so a read through this function can never be unbounded, matching this module's
/// fail-closed, bounded-everything posture (see `MAX_FDS_PER_PROCESS` / `MAX_PROCESSES_SCANNED`
/// in `proc_linux.rs` for the same philosophy applied to directory scans).
const MAX_READ_BYTES: usize = 65_536;

/// Bound applied to `read_link_at`'s output buffer. `PATH_MAX` on Linux is 4096; a target longer
/// than that is returned truncated (`readlinkat`'s own documented silent-truncation contract)
/// rather than as an error, since a bounded prefix is still useful for display/comparison and a
/// hard error here would turn an unusually long (but legitimate) path into a resolution failure.
const MAX_LINK_TARGET_BYTES: usize = 4096;

/// Stack buffer size for each individual `getdents64` call inside `read_dir_entries_at`. Purely a
/// per-syscall I/O chunk size, NOT the total-entries bound -- that's the caller-supplied
/// `max_entries` parameter.
const GETDENTS_BUF_BYTES: usize = 8192;

/// Builds a NUL-terminated C string from `s`, mapping an embedded NUL (impossible for every
/// caller in this crate today -- digit-only pids, static file names, and getdents64-derived
/// directory-entry names, none of which can contain a NUL) to an `io::Error` rather than
/// panicking, so a future caller mistake fails closed instead of aborting the process.
fn cpath(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Opens `/proc/<pid>` as a directory fd, pinning process identity for every subsequent relative
/// read. `pid` is a validated `u32`, so `format!("/proc/{pid}")` is digit-only by construction --
/// no path-traversal surface, unlike an attacker-controlled path component would be.
///
/// `O_DIRECTORY` rejects anything that isn't a directory (defense in depth: `/proc/<pid>` is
/// always a directory when it exists at all); `O_CLOEXEC` is the open flag, never a later
/// `fcntl(F_SETFD)` -- see the module doc.
pub fn open_pid_dir(pid: u32) -> io::Result<OwnedFd> {
    let path = cpath(&format!("/proc/{pid}"))?;
    // SAFETY: `path` is a valid, NUL-terminated C string live for the whole call. `AT_FDCWD` is
    // the documented "resolve relative to the current working directory" sentinel, not a real fd
    // -- there is no fd-lifetime concern on that argument.
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by the `openat` call directly above, is not yet owned by
    // anything else, and is a valid open fd (checked `>= 0` above) -- wrapping it in `OwnedFd`
    // hands the caller sole RAII-close ownership with no other owner ever existing for this value.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens `name` as a directory, relative to the already-pinned `dirfd`. Used to open `"fd"`
/// relative to a pinned `/proc/<pid>` dir without ever touching an absolute path.
///
/// `O_NOFOLLOW` refuses to traverse a symlink at `name` -- defense in depth against a swapped-in
/// symlink where a real subdirectory is expected. `O_CLOEXEC` via the open flag, never `fcntl`.
pub fn open_dir_at(dirfd: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    let path = cpath(name)?;
    // SAFETY: `dirfd` is a live, valid directory fd for the whole call (the `BorrowedFd<'_>`
    // parameter's lifetime is exactly the caller's guarantee of that); `path` is a valid,
    // NUL-terminated C string live for the whole call.
    let fd = unsafe {
        libc::openat(
            dirfd.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see `open_pid_dir` -- `fd` is freshly opened above and exclusively owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens `name` as a regular file relative to `dirfd`, reads up to `MAX_READ_BYTES` of it via a
/// bounded raw `libc::read` loop (never `std::fs`/`Read` trait methods -- see `proc_linux.rs`'s
/// module doc for why that distinction matters under the seccomp filter), and closes it (`OwnedFd`
/// RAII, on every return path).
///
/// `O_NOFOLLOW` refuses to traverse a symlink at `name` -- every file this is called on today
/// (`status`, `cmdline`) is a regular pseudo-file, never a symlink, so this is defense in depth,
/// not a behavior change. `O_CLOEXEC` via the open flag, never `fcntl`.
pub fn read_file_at(dirfd: BorrowedFd<'_>, name: &str) -> io::Result<Vec<u8>> {
    let path = cpath(name)?;
    // SAFETY: `dirfd` is live for the whole call; `path` is a valid NUL-terminated C string.
    let fd = unsafe {
        libc::openat(
            dirfd.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is freshly opened above and exclusively owned here; RAII-closed when `file`
    // drops, on every return path below (early `Err` returns included).
    let file = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut buf = vec![0u8; MAX_READ_BYTES];
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: `file` is a valid, open, readable fd for the duration of this call;
        // `buf[total..]` is a valid, writable slice of at least `buf.len() - total` bytes that
        // outlives the call (it is not moved or reallocated while the syscall is in flight).
        let n = unsafe {
            libc::read(
                file.as_raw_fd(),
                buf[total..].as_mut_ptr().cast(),
                buf.len() - total,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue; // EINTR: retry, no bytes were consumed.
            }
            return Err(err);
        }
        if n == 0 {
            break; // EOF.
        }
        total += n as usize;
    }
    buf.truncate(total);
    Ok(buf)
}

/// Reads the symlink target of `name` relative to `dirfd` (e.g. `"exe"`), bounded to
/// `MAX_LINK_TARGET_BYTES`. `readlinkat` never NUL-terminates its output, so the syscall's
/// returned byte count is used verbatim as the length -- there is no NUL to search for.
pub fn read_link_at(dirfd: BorrowedFd<'_>, name: &str) -> io::Result<OsString> {
    let path = cpath(name)?;
    let mut buf = vec![0u8; MAX_LINK_TARGET_BYTES];
    // SAFETY: `dirfd` is live for the whole call; `path` is a valid NUL-terminated C string;
    // `buf` is a valid, writable buffer of `buf.len()` bytes for the kernel to fill with at most
    // that many bytes.
    let n = unsafe {
        libc::readlinkat(
            dirfd.as_raw_fd(),
            path.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(OsString::from_vec(buf))
}

// Offsets of the fields this module actually reads out of a `getdents64` record, computed
// against libc's own (kernel-UAPI-matching) `dirent64` struct rather than hand-rolled -- same
// technique `hardening.rs` uses for `seccomp_data` (see its module doc). NOTE: `libc::dirent64`
// declares `d_name` as a fixed `[c_char; 256]` array for ergonomic field access, but the kernel's
// actual wire format is a PACKED, variable-length record whose true length is `d_reclen` (usually
// far less than `256` once past `d_name`'s start) -- so this module only ever uses these offsets
// to index into the raw byte buffer within `[record_start, record_start + d_reclen)`, and never
// casts a buffer position directly to `&libc::dirent64` (which would read up to 256 bytes of
// `d_name`, well past the real record and potentially past the end of the read buffer itself).
const D_RECLEN_OFFSET: usize = offset_of!(libc::dirent64, d_reclen);
const D_NAME_OFFSET: usize = offset_of!(libc::dirent64, d_name);

/// Opens `name` as a directory relative to `dirfd`, then `getdents64`-scans it for up to
/// `max_entries` entry names (excluding `"."`/`".."`). Returns the OPENED DIRECTORY FD alongside
/// the names -- not just the names -- so the caller can do further `readlinkat` calls relative to
/// that SAME already-open directory (e.g. `find_owning_pid`'s per-candidate `"fd"` dir), rather
/// than re-opening `name` a second time by path. Bounded both per-syscall (`GETDENTS_BUF_BYTES`)
/// and in total (`max_entries`, e.g. `proc_linux::MAX_FDS_PER_PROCESS` at the call site) so a
/// directory with a huge or adversarial entry count cannot make a single call unbounded.
pub fn read_dir_entries_at(
    dirfd: BorrowedFd<'_>,
    name: &str,
    max_entries: usize,
) -> io::Result<(OwnedFd, Vec<OsString>)> {
    let scan_dir = open_dir_at(dirfd, name)?;
    let mut entries = Vec::new();
    let mut buf = [0u8; GETDENTS_BUF_BYTES];

    'outer: loop {
        // SAFETY: `scan_dir` is a valid, open directory fd for the duration of this call; `buf`
        // is a valid, writable buffer of `buf.len()` bytes for the kernel to fill with at most
        // that many bytes.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                scan_dir.as_raw_fd(),
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            break; // EOF: no more entries.
        }
        let n = n as usize;

        let mut pos = 0usize;
        while pos < n {
            if pos + D_RECLEN_OFFSET + 2 > n {
                break; // not enough bytes left for a full d_reclen field -- truncated read, stop.
            }
            let reclen =
                u16::from_ne_bytes([buf[pos + D_RECLEN_OFFSET], buf[pos + D_RECLEN_OFFSET + 1]])
                    as usize;
            if reclen == 0 || pos + reclen > n {
                break; // malformed record -- stop rather than misparse past the valid region.
            }
            if pos + D_NAME_OFFSET <= pos + reclen {
                let name_region = &buf[pos + D_NAME_OFFSET..pos + reclen];
                let nul_at = name_region
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_region.len());
                let entry_name = &name_region[..nul_at];
                if entry_name != b"." && entry_name != b".." {
                    entries.push(OsString::from_vec(entry_name.to_vec()));
                    if entries.len() >= max_entries {
                        break 'outer;
                    }
                }
            }
            pos += reclen;
        }
    }

    Ok((scan_dir, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn open_pid_dir_succeeds_for_our_own_pid() {
        assert!(open_pid_dir(std::process::id()).is_ok());
    }

    #[test]
    fn open_pid_dir_fails_closed_for_a_pid_that_almost_certainly_does_not_exist() {
        assert!(open_pid_dir(u32::MAX - 1).is_err());
    }

    #[test]
    fn read_file_at_reads_our_own_status_and_it_contains_uid() {
        let pid_dir = open_pid_dir(std::process::id()).expect("must open our own /proc/<pid> dir");
        let status = read_file_at(pid_dir.as_fd(), "status").expect("status must be readable");
        let status = String::from_utf8_lossy(&status);
        assert!(status.contains("Uid:"));
    }

    #[test]
    fn read_link_at_reads_our_own_exe_as_a_non_empty_path() {
        let pid_dir = open_pid_dir(std::process::id()).expect("must open our own /proc/<pid> dir");
        let exe = read_link_at(pid_dir.as_fd(), "exe").expect("exe symlink must be readable");
        assert!(!exe.is_empty());
    }

    #[test]
    fn read_dir_entries_at_finds_our_own_stdio_fds() {
        let pid_dir = open_pid_dir(std::process::id()).expect("must open our own /proc/<pid> dir");
        let (_fd_dir, entries) =
            read_dir_entries_at(pid_dir.as_fd(), "fd", 4096).expect("fd dir must be scannable");
        // fd 0/1/2 (stdio) are always open in a `cargo test` process; "." and ".." must never
        // appear (excluded by construction above).
        assert!(!entries.is_empty());
        assert!(!entries.iter().any(|e| e == "." || e == ".."));
    }

    /// By-construction fail-closed guarantee this whole module exists to provide: a `/proc/<pid>`
    /// dirfd pinned BEFORE a process exits observes that specific process for as long as it lives,
    /// and once it is reaped, `/proc` invalidates that directory's dentries -- every subsequent
    /// relative read through the SAME dirfd then fails, rather than silently starting to resolve
    /// whichever new process later reuses the same numeric pid. `Child::wait()` blocks until the
    /// child has both exited AND been reaped (no sleep/poll loop, hence no flakiness): by the time
    /// it returns, the kernel has already run `release_task`/`proc_flush_pid` for that pid.
    #[test]
    fn dirfd_pinned_to_a_reaped_child_fails_closed_on_relative_reads() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("must be able to spawn a short-lived child (`true`) for this test");
        let child_pid = child.id();
        let pid_dir =
            open_pid_dir(child_pid).expect("child is alive at spawn time; its dir must open");
        let status = child.wait().expect("must be able to wait for the child");
        assert!(status.success(), "`true` must exit 0");

        let read = read_file_at(pid_dir.as_fd(), "status");
        assert!(
            read.is_err(),
            "a relative read through a dirfd pinned to a reaped pid must fail closed, not \
             silently succeed against whatever process now (or later) reuses that pid number"
        );
    }
}
