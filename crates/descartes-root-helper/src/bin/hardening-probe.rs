//! Out-of-process test support for `hardening.rs` (S3-priv Slice 4, D8). NOT the shipped helper:
//! this binary exists so `tests/hardening.rs` can observe `SECCOMP_RET_KILL_PROCESS` actually
//! killing a process, from OUTSIDE that process. `hardening::engage()` must never run inside the
//! (multithreaded) `cargo test` harness itself -- a KILL_PROCESS default action would be free to
//! kill the whole harness process on its very next non-allowlisted syscall.
//!
//! This bin calls the exact same `descartes_root_helper::hardening::engage()` /
//! `drop_capabilities()` the production binary uses -- one source of truth, no drift between what
//! is tested and what ships -- then performs ONE action selected by its own tiny fixed argv,
//! deliberately separate from (and never merged into) the production helper's 3-form argv contract
//! in `argv.rs`/pinned by `tests/cli_contract.rs`. That separation is itself a security property:
//! no hidden test flags on the binary that will eventually carry a real capability.
//!
//! `#![allow(unsafe_code)]`: this is test-support code making raw ptrace/socket/process_vm_readv
//! calls specifically so the seccomp filter has something forbidden to deny -- not a relaxation of
//! the production `#![deny(unsafe_code)]` policy, which this bin never ships under.

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux_probe {
    use std::os::fd::AsFd;
    use std::ptr;

    use descartes_root_helper::{hardening, procfs};

    /// Runs the one action named by `mode`. Returns an exit code; for the `--do-*` actions this
    /// return value is only ever observed if the syscall was NOT denied (a bug) -- a real
    /// SECCOMP_RET_KILL_PROCESS kill never returns here at all, it terminates the process via
    /// SIGSYS, which the caller observes as a signal, not an exit code.
    pub fn run(mode: &str) -> i32 {
        match mode {
            "--do-ptrace" => {
                hardening::engage();
                do_ptrace();
                1
            }
            "--do-socket" => {
                hardening::engage();
                do_socket();
                1
            }
            "--do-process-vm-readv" => {
                hardening::engage();
                do_process_vm_readv();
                1
            }
            "--do-process-vm-writev" => {
                hardening::engage();
                do_process_vm_writev();
                1
            }
            "--do-open-by-handle-at" => {
                hardening::engage();
                do_open_by_handle_at();
                1
            }
            "--check-nnp" => {
                hardening::engage();
                check_nnp()
            }
            "--check-capdrop" => {
                hardening::engage();
                hardening::drop_capabilities();
                check_capdrop()
            }
            // 2026-10 positive control: the exact read path the production binary uses (pid dir,
            // status, exe link, fd listing, /proc listing, net/tcp) succeeds under the live filter.
            "--read-allowed-paths" => {
                hardening::engage();
                read_allowed_paths()
            }
            mode => match deny_probe(mode) {
                Some(action) => {
                    hardening::engage();
                    action();
                    1
                }
                None => 2,
            },
        }
    }

    /// 2026-10 tightened-policy deny probes (docs/research/2026-09-26-sandbox-and-microvm-
    /// boundaries-research.md, finding 1 + "real-grant helper breakout suite"). Each action must be
    /// SIGSYS-killed by the filter; returning to the caller (exit 1) is a policy failure.
    fn deny_probe(mode: &str) -> Option<fn()> {
        let action: fn() = match mode {
            "--do-openat-wronly" => || {
                raw_openat(c"/dev/null", libc::O_WRONLY | libc::O_CLOEXEC);
            },
            "--do-openat-proc-mem-rdwr" => || {
                raw_openat(c"/proc/self/mem", libc::O_RDWR | libc::O_CLOEXEC);
            },
            "--do-openat-creat" => || {
                // Under a broken filter the kernel would still refuse (no such dir); the point is
                // that O_CREAT never reaches it.
                raw_openat(
                    c"/proc/self/descartes-probe-nonexistent/x",
                    libc::O_RDONLY | libc::O_CREAT | libc::O_CLOEXEC,
                );
            },
            "--do-openat-o-path" => || {
                raw_openat(c"/proc", libc::O_PATH | libc::O_CLOEXEC);
            },
            "--do-lseek-proc-mem" => || {
                // Opening /proc/self/mem READ-ONLY is admitted (openat can't see paths); reading
                // anything meaningful from it needs a seek to a mapped address -- killed here.
                let fd = raw_openat(c"/proc/self/mem", libc::O_RDONLY | libc::O_CLOEXEC);
                // SAFETY: plain lseek on an fd we own (or -1 if the open failed).
                unsafe { libc::syscall(libc::SYS_lseek, fd, 4096i64, libc::SEEK_SET) };
            },
            "--do-pread" => || {
                let fd = raw_openat(c"/proc/self/status", libc::O_RDONLY | libc::O_CLOEXEC);
                let mut buf = [0u8; 8];
                // SAFETY: `buf` is a valid writable 8-byte buffer for the duration of the call.
                unsafe {
                    libc::syscall(libc::SYS_pread64, fd, buf.as_mut_ptr(), buf.len(), 4096i64)
                };
            },
            "--do-write-non-stdio-fd" => || {
                let fd = raw_openat(c"/proc/self/status", libc::O_RDONLY | libc::O_CLOEXEC);
                let byte = [0u8; 1];
                // SAFETY: `byte` is a valid 1-byte buffer.
                unsafe { libc::syscall(libc::SYS_write, fd, byte.as_ptr(), 1usize) };
            },
            "--do-mmap-exec" => || {
                // SAFETY: anonymous mapping request; never executes past syscall entry under the
                // filter, and would only create a private anonymous page otherwise.
                unsafe {
                    libc::mmap(
                        ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
            },
            "--do-mprotect-exec" => || {
                // SAFETY: maps one private anonymous RW page (admitted), then asks to make it
                // executable (killed). The page is never touched.
                unsafe {
                    let page = libc::mmap(
                        ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    );
                    libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_EXEC);
                }
            },
            "--do-newfstatat" => || {
                // SAFETY: `st` is a valid, writable stat buffer for the duration of the call.
                unsafe {
                    let mut st: libc::stat = std::mem::zeroed();
                    libc::syscall(
                        libc::SYS_newfstatat,
                        libc::AT_FDCWD,
                        c"/etc/shadow".as_ptr(),
                        &mut st as *mut libc::stat,
                        0,
                    );
                }
            },
            "--do-statx" => || {
                // SAFETY: `buf` is a valid, writable statx buffer for the duration of the call.
                unsafe {
                    let mut buf: libc::statx = std::mem::zeroed();
                    libc::syscall(
                        libc::SYS_statx,
                        libc::AT_FDCWD,
                        c"/etc/shadow".as_ptr(),
                        0,
                        libc::STATX_BASIC_STATS,
                        &mut buf as *mut libc::statx,
                    );
                }
            },
            "--do-getrandom" => || {
                let mut buf = [0u8; 8];
                // SAFETY: `buf` is a valid writable 8-byte buffer.
                unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), 0) };
            },
            "--do-prctl-dumpable" => || {
                // SAFETY: PR_SET_DUMPABLE reads no pointer argument.
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
            },
            "--do-tgkill-other" => || {
                // Signal 0 to pid 1: a pure permission probe even if it were admitted.
                // SAFETY: no pointer arguments.
                unsafe { libc::syscall(libc::SYS_tgkill, 1, 1, 0) };
            },
            "--do-fcntl-setfd" => || {
                // SAFETY: F_SETFD on stdin with FD_CLOEXEC; no pointer arguments.
                unsafe { libc::fcntl(0, libc::F_SETFD, libc::FD_CLOEXEC) };
            },
            "--do-execve" => || {
                let argv = [c"/bin/true".as_ptr(), ptr::null()];
                let envp = [ptr::null::<libc::c_char>()];
                // SAFETY: NUL-terminated argv/envp arrays of valid C strings.
                unsafe { libc::execve(c"/bin/true".as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            },
            _ => return None,
        };
        Some(action)
    }

    /// Raw `openat(AT_FDCWD, path, flags)` -- bypasses std so the probe controls the exact flags
    /// the kernel (and the filter) sees. Returns the raw fd or -1.
    fn raw_openat(path: &std::ffi::CStr, flags: libc::c_int) -> libc::c_long {
        // SAFETY: `path` is a valid NUL-terminated C string for the duration of the call; mode
        // 0600 is only consulted with O_CREAT.
        unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                path.as_ptr(),
                flags,
                0o600,
            )
        }
    }

    /// Positive control: exits 0 iff every read the production binary performs still works under
    /// the live filter (and 1 if any returns an error -- a SIGSYS kill would show as a signal).
    fn read_allowed_paths() -> i32 {
        let own = std::process::id();
        let ok = (|| -> std::io::Result<bool> {
            let root = procfs::open_proc_root()?;
            let (_listing, entries) = procfs::read_dir_entries_at(root.as_fd(), ".", 1 << 20)?;
            let own_name = own.to_string();
            let listed = entries
                .iter()
                .any(|e| e.to_str() == Some(own_name.as_str()));
            let (_tcp, _truncated) =
                procfs::read_file_at_bounded(root.as_fd(), "net/tcp", 1 << 24)?;
            let pid_dir = procfs::open_pid_dir(own)?;
            let status = procfs::read_file_at(pid_dir.as_fd(), "status")?;
            let cmdline = procfs::read_file_at(pid_dir.as_fd(), "cmdline")?;
            let exe = procfs::read_link_at(pid_dir.as_fd(), "exe")?;
            let (fd_dir, fds) = procfs::read_dir_entries_at(pid_dir.as_fd(), "fd", 4096)?;
            let first_fd = fds
                .first()
                .and_then(|f| f.to_str())
                .unwrap_or("0")
                .to_string();
            let _target = procfs::read_link_at(fd_dir.as_fd(), &first_fd)?;
            Ok(listed && !status.is_empty() && !cmdline.is_empty() && !exe.is_empty())
        })();
        match ok {
            Ok(true) => {
                println!("ok");
                eprintln!("read-allowed-paths: ok");
                0
            }
            _ => 1,
        }
    }

    /// Reads our own `/proc/<pid>/status` and returns the whitespace-split fields on the first line
    /// whose label matches `label` exactly (e.g. `"NoNewPrivs:"`). Goes through the SAME raw
    /// `procfs` primitives as the production binary (2026-10): `std::fs::read_to_string` issues
    /// statx/fstat, which the tightened policy kills -- so this read also proves, under the live
    /// filter, that the helper's real read path is still admitted.
    fn status_fields(label: &str) -> Vec<String> {
        let pid_dir = procfs::open_pid_dir(std::process::id()).expect("must open our own pid dir");
        let status =
            procfs::read_file_at(pid_dir.as_fd(), "status").expect("must read our own status");
        String::from_utf8_lossy(&status)
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .map(|rest| rest.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// crit2 (NNP): exits 0 iff `NoNewPrivs` reads exactly `1` after `engage()`.
    fn check_nnp() -> i32 {
        match status_fields("NoNewPrivs:").first().map(String::as_str) {
            Some("1") => 0,
            _ => 1,
        }
    }

    /// crit1 (cap-drop): exits 0 iff `CapEff`/`CapPrm` are both all-zero hex after
    /// `engage()` + `drop_capabilities()`, run unprivileged (this crate carries no capability
    /// yet). This is a clean-no-op check, not a before/after transition -- observing an actual
    /// nonzero-to-zero transition needs a real capability to drop in the first place, which is
    /// Slice 6's CI-with-setcap job, not something this dev-host-less-Linux-VM setup can do.
    fn check_capdrop() -> i32 {
        let is_all_zero_hex = |fields: &[String]| {
            fields
                .first()
                .is_some_and(|value| !value.is_empty() && value.chars().all(|c| c == '0'))
        };
        let eff = status_fields("CapEff:");
        let prm = status_fields("CapPrm:");
        if is_all_zero_hex(&eff) && is_all_zero_hex(&prm) {
            0
        } else {
            1
        }
    }

    /// crit4 (no-ptrace probe): any `ptrace(2)` request is denied by the allowlist regardless of
    /// its arguments -- `PTRACE_TRACEME` is the simplest request to issue.
    fn do_ptrace() {
        // SAFETY: PTRACE_TRACEME takes no further arguments. Any outcome this call could legally
        // have (success, EPERM) is fine -- it exists only to be denied by the filter before the
        // kernel even inspects the request.
        unsafe {
            libc::ptrace(libc::PTRACE_TRACEME);
        }
    }

    /// crit5 (no-network probe): `socket` is not in the allowlist at all.
    fn do_socket() {
        // SAFETY: a plain AF_INET/SOCK_STREAM socket() call with no further resource handling --
        // under the filter this never returns, so there is no fd to leak or close.
        unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        }
    }

    /// crit5 (CAP_SYS_PTRACE-blast-radius regression probe): `process_vm_readv` reads another
    /// process's memory WITHOUT ever calling `ptrace()` -- D5's reason it needs its own explicit
    /// deny-probe rather than trusting the `ptrace`-shaped probe above to cover it.
    fn do_process_vm_readv() {
        let mut buf = [0u8; 1];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        };
        // SAFETY: targets our own pid with a zero-length remote range -- harmless even in the
        // hypothetical world where this call were reachable; under the filter it never executes
        // past syscall entry, so the (deliberately unused) buffers are never touched by the kernel.
        unsafe {
            libc::syscall(
                libc::SYS_process_vm_readv,
                std::process::id() as libc::pid_t,
                &local as *const libc::iovec,
                1u64,
                &remote as *const libc::iovec,
                1u64,
                0u64,
            );
        }
    }

    /// crit5 (CAP_SYS_PTRACE-blast-radius regression probe): `process_vm_writev` is the write half
    /// of the same blast radius as `process_vm_readv` above -- writes another process's memory
    /// WITHOUT ever calling `ptrace()`. Deny-probed on its own merits for the same reason.
    fn do_process_vm_writev() {
        let buf = [0u8; 1];
        let local = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        };
        // SAFETY: targets our own pid with a zero-length remote range -- harmless even in the
        // hypothetical world where this call were reachable; under the filter it never executes
        // past syscall entry, so the (deliberately unused) buffers are never touched by the kernel.
        unsafe {
            libc::syscall(
                libc::SYS_process_vm_writev,
                std::process::id() as libc::pid_t,
                &local as *const libc::iovec,
                1u64,
                &remote as *const libc::iovec,
                1u64,
                0u64,
            );
        }
    }

    /// crit5 (S3-priv Slice 6 fix, `cap_dac_read_search`'s own amplifier): `open_by_handle_at`
    /// opens an arbitrary file by an opaque on-disk handle, bypassing the normal directory-path
    /// permission walk that would otherwise gate access -- in the kernel it is gated by
    /// `capable(CAP_DAC_READ_SEARCH)` (see `fs/fhandle.c`), the exact capability the Slice 6 fix
    /// adds to this binary's file-capability grant (`cap_sys_ptrace,cap_dac_read_search=ep`) for
    /// cross-UID `/proc/<pid>/fd` enumeration. It is deliberately NOT admitted by `seccomp_policy`, so
    /// the default `SECCOMP_RET_KILL_PROCESS` action must still apply even though this binary now
    /// actually holds the capability that would otherwise make the syscall usable -- regression-
    /// proofing that the seccomp allowlist, not just "we don't call it," is what keeps this
    /// amplifier unreachable. The seccomp filter kills this at syscall ENTRY, before the kernel
    /// even inspects the arguments, so the dummy `mount_fd`/`handle`/`flags` below are never
    /// touched -- same reasoning as `do_process_vm_readv`/`do_process_vm_writev` above.
    fn do_open_by_handle_at() {
        // SAFETY: under the filter this never executes past syscall entry -- the kernel never
        // dereferences the null `handle` pointer or does anything with the dummy `mount_fd`/flags.
        unsafe {
            libc::syscall(
                libc::SYS_open_by_handle_at,
                -1,
                ptr::null::<libc::c_void>(),
                0,
            );
        }
    }
}

fn main() {
    let mode = std::env::args().nth(1);

    #[cfg(target_os = "linux")]
    {
        let code = match mode.as_deref() {
            Some(mode) => linux_probe::run(mode),
            None => 2,
        };
        std::process::exit(code);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = mode;
        eprintln!(
            "hardening-probe: Linux-only test-support binary (S3-priv Slice 4 D8); nothing to \
             probe on this platform"
        );
        std::process::exit(2);
    }
}
