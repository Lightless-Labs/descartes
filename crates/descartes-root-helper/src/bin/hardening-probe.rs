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
    use std::ptr;

    use descartes_root_helper::hardening;

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
            "--check-nnp" => {
                hardening::engage();
                check_nnp()
            }
            "--check-capdrop" => {
                hardening::engage();
                hardening::drop_capabilities();
                check_capdrop()
            }
            _ => 2,
        }
    }

    /// Reads `/proc/self/status` and returns the whitespace-split fields on the first line whose
    /// label matches `label` exactly (e.g. `"NoNewPrivs:"`).
    fn status_fields(label: &str) -> Vec<String> {
        let status =
            std::fs::read_to_string("/proc/self/status").expect("must read our own status");
        status
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
