//! Kernel-level defensive hardening for descartes-root-helper (S3-priv Slice 4; seccomp policy
//! re-derived 2026-10). The helper is installed with the file-capability grant
//! `cap_sys_ptrace,cap_dac_read_search=ep` (a manual `setcap` step outside this repo's code -- see
//! `proc_linux.rs`'s module doc for why the grant is that 2-capability UNION). The properties
//! installed here shrink what code running inside this process can do WITH that grant.
//!
//! Three properties, all KERNEL-enforced (never code-review-assumed):
//!   1. `PR_SET_NO_NEW_PRIVS` (`engage()`) -- this process can never gain privilege beyond what it
//!      already has (and no exec* syscall is allowlisted anyway).
//!   2. A seccomp-bpf ALLOWLIST with ARGUMENT predicates (`engage()`; default action
//!      `SECCOMP_RET_KILL_PROCESS`, the process-scoped kill). The policy itself lives in the pure,
//!      host-tested `seccomp_policy` module and is compiled by the pure `seccomp_bpf` module; this
//!      file only supplies the native syscall table and installs the program. See
//!      `seccomp_policy`'s module doc for EXACTLY what the policy closes -- and, honestly, what it
//!      cannot: seccomp never sees path strings, so read-only opens of arbitrary paths reachable
//!      by the capability pair (e.g. `/etc/shadow`, `/proc/<pid>/environ`) remain possible for
//!      code executing inside the helper, with output confined to stdout/stderr. The earlier claim
//!      that "everything sharing either capability's threat model" is unreachable was too strong
//!      (docs/research/2026-09-26-sandbox-and-microvm-boundaries-research.md, finding 1).
//!      Requires Linux >= 4.14 (KILL_PROCESS); CI runs 6.17.
//!   3. A capability drop (`drop_capabilities()`, called by `main.rs` AFTER the /proc reads that
//!      need the grant and BEFORE any output) that zeroes the effective/permitted/inheritable sets
//!      and the ambient set.
//!
//! FAIL-CLOSED: any unexpected error from any step -- including a policy that fails to compile --
//! aborts the process (stderr-only diagnostic, nonzero exit) rather than continuing without the
//! property.
//!
//! Any change to the policy is a security-review-required change. CI (the live-filter tests in
//! `tests/hardening.rs` + `tests/linux_resolution.rs`, and the privileged
//! `scripts/ci-elevated-provenance.sh` run of the release build) is the only oracle for the
//! "no self-SIGSYS" direction -- this dev host has no Linux virtualization.
//!
//! ALL unsafe code in this crate's production path lives in this file AND `src/procfs.rs`. The
//! other production modules stay `#![deny(unsafe_code)]`/`#![forbid(unsafe_code)]` clean.
//! `src/bin/hardening-probe.rs` is the one other file with unsafe, and it is test-support only.

/// Exit code for a fail-closed hardening abort. Deliberately DISTINCT from every code the
/// production binary's own paths return (see `main.rs`; pinned distinct by a host unit test
/// there). Before 2026-10 this was `3`, colliding with the truncated-scan code, so the Node side
/// labelled a confinement failure `fd_scan_truncated` exactly when the security boundary failed to
/// initialize (docs/research/2026-09-26-sandbox-and-microvm-boundaries-research.md, finding 8).
/// Defined on every platform so that distinctness is testable on any host.
pub const EXIT_HARDENING_FAILURE: i32 = 4;

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::ptr;

    use crate::seccomp_bpf::{compile, CompileError};
    use crate::seccomp_policy::{helper_policy, SyscallTable};

    // libc (the crate) gives us arch-correct SYS_*/PR_*/SECCOMP_* constants and the
    // `sock_filter`/`sock_fprog` structs, but NOT the capset(2) structs or the AUDIT_ARCH_*
    // constants -- both are hand-defined below, straight from the kernel UAPI headers.

    /// `<linux/capability.h>`: the version every kernel since 2.6.26 negotiates; pairs with the
    /// two-element `CapUserData` array below (32 capability bits per element, 64 bits total).
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    /// `<linux/audit.h>`: `EM_<arch> | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
    #[cfg(target_arch = "x86_64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E; // EM_X86_64 = 62

    #[cfg(target_arch = "aarch64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7; // EM_AARCH64 = 183

    /// x32-ABI syscalls report `AUDIT_ARCH_X86_64` but OR this bit into the syscall number.
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    // `seccomp_bpf` reads `seccomp_data.args` low/high words at little-endian offsets.
    #[cfg(not(target_endian = "little"))]
    compile_error!("descartes-root-helper's seccomp compiler assumes a little-endian target");

    /// The native table the policy (`seccomp_policy::helper_policy`) is written against, from
    /// `libc`'s arch-correct `SYS_*` numbers. The KERNEL-visible `O_LARGEFILE` bit is hand-defined
    /// per arch because glibc (and so the `libc` crate) defines it as 0 on 64-bit targets. The
    /// `const` assertion right below pins this table equal to `seccomp_policy`'s hand-written table
    /// for the target arch AT COMPILE TIME, so the host-tested policy and the installed one cannot
    /// drift -- and a cross-target `cargo check` verifies it for an arch no CI runner executes.
    pub(super) const fn native_table() -> SyscallTable {
        #[cfg(target_arch = "x86_64")]
        const KERNEL_O_LARGEFILE: u32 = 0o100000;
        #[cfg(target_arch = "aarch64")]
        const KERNEL_O_LARGEFILE: u32 = 0o400000;
        #[cfg(target_arch = "x86_64")]
        const X32: Option<u32> = Some(X32_SYSCALL_BIT);
        #[cfg(target_arch = "aarch64")]
        const X32: Option<u32> = None;

        SyscallTable {
            audit_arch: NATIVE_AUDIT_ARCH,
            x32_syscall_bit: X32,
            read: libc::SYS_read as u32,
            write: libc::SYS_write as u32,
            writev: libc::SYS_writev as u32,
            openat: libc::SYS_openat as u32,
            close: libc::SYS_close as u32,
            fcntl: libc::SYS_fcntl as u32,
            getdents64: libc::SYS_getdents64 as u32,
            readlinkat: libc::SYS_readlinkat as u32,
            mmap: libc::SYS_mmap as u32,
            mprotect: libc::SYS_mprotect as u32,
            munmap: libc::SYS_munmap as u32,
            brk: libc::SYS_brk as u32,
            mremap: libc::SYS_mremap as u32,
            madvise: libc::SYS_madvise as u32,
            exit: libc::SYS_exit as u32,
            exit_group: libc::SYS_exit_group as u32,
            futex: libc::SYS_futex as u32,
            capget: libc::SYS_capget as u32,
            capset: libc::SYS_capset as u32,
            prctl: libc::SYS_prctl as u32,
            rt_sigreturn: libc::SYS_rt_sigreturn as u32,
            rt_sigaction: libc::SYS_rt_sigaction as u32,
            rt_sigprocmask: libc::SYS_rt_sigprocmask as u32,
            sigaltstack: libc::SYS_sigaltstack as u32,
            clock_gettime: libc::SYS_clock_gettime as u32,
            getpid: libc::SYS_getpid as u32,
            gettid: libc::SYS_gettid as u32,
            tgkill: libc::SYS_tgkill as u32,
            o_cloexec: libc::O_CLOEXEC as u32,
            o_directory: libc::O_DIRECTORY as u32,
            o_nofollow: libc::O_NOFOLLOW as u32,
            o_largefile: KERNEL_O_LARGEFILE,
            f_getfd: libc::F_GETFD as u32,
            pr_cap_ambient: libc::PR_CAP_AMBIENT as u32,
            pr_cap_ambient_clear_all: libc::PR_CAP_AMBIENT_CLEAR_ALL as u32,
            prot_exec: libc::PROT_EXEC as u32,
            map_anonymous: libc::MAP_ANONYMOUS as u32,
        }
    }

    #[cfg(target_arch = "x86_64")]
    const _: () = assert!(
        crate::seccomp_policy::same_table(&native_table(), &crate::seccomp_policy::pinned_x86_64()),
        "libc's x86_64 syscall table drifted from seccomp_policy::pinned_x86_64"
    );
    #[cfg(target_arch = "aarch64")]
    const _: () = assert!(
        crate::seccomp_policy::same_table(
            &native_table(),
            &crate::seccomp_policy::pinned_aarch64()
        ),
        "libc's aarch64 syscall table drifted from seccomp_policy::pinned_aarch64"
    );

    /// Compiles the policy for THIS process (its pid is baked into the tgkill rule) into the
    /// kernel's `sock_filter` representation. See `seccomp_bpf` for the program shape.
    fn build_filter() -> Result<Vec<libc::sock_filter>, CompileError> {
        // Read BEFORE the filter installs; no fork/clone is allowlisted, so this stays this
        // process's pid for its whole remaining life.
        let own_pid = std::process::id();
        let program = compile(&helper_policy(&native_table(), own_pid))?;
        Ok(program
            .into_iter()
            .map(|insn| libc::sock_filter {
                code: insn.code,
                jt: insn.jt,
                jf: insn.jf,
                k: insn.k,
            })
            .collect())
    }

    fn abort_fail_closed(step: &str, err: io::Error) -> ! {
        // stderr ONLY -- never stdout, per the helper's stdout contract (main.rs), which a
        // hardening failure must not violate even while dying.
        eprintln!("descartes-root-helper: hardening failure at {step}: {err}");
        std::process::exit(super::EXIT_HARDENING_FAILURE);
    }

    fn set_no_new_privs() {
        // SAFETY: PR_SET_NO_NEW_PRIVS reads no pointer argument; the trailing zeros are the
        // prctl(2) contract for an option that only consumes arg2.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            abort_fail_closed("PR_SET_NO_NEW_PRIVS", io::Error::last_os_error());
        }
    }

    fn install_filter() {
        let program = match build_filter() {
            Ok(program) => program,
            Err(err) => abort_fail_closed(
                "seccomp policy compile",
                io::Error::other(format!("{err:?}")),
            ),
        };
        let prog = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: `prog.filter` points into `program`, which is still alive and unmoved for the
        // duration of this call (dropped only after the syscall returns); PR_SET_SECCOMP with
        // SECCOMP_MODE_FILTER reads `prog` once, synchronously, and does not retain the pointer.
        let ret = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
                0,
                0,
            )
        };
        if ret != 0 {
            abort_fail_closed("PR_SET_SECCOMP", io::Error::last_os_error());
        }
    }

    pub fn engage() {
        set_no_new_privs();
        install_filter();
    }

    /// Drops this process's capabilities to nothing: effective/permitted/inheritable sets via
    /// `capset(2)`, ambient set via `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)` (the ONLY
    /// prctl the seccomp policy still admits).
    ///
    /// Deliberately NOT `PR_CAPBSET_DROP`: that needs `CAP_SETPCAP`, which this binary never holds.
    /// The bounding set only constrains capability GAIN across execve, and this process can never
    /// execve (no exec* syscall is allowlisted; NO_NEW_PRIVS is set regardless).
    ///
    /// Called by the production binary right after a resolve attempt (success or failure) and
    /// before any output -- see `main.rs`. Unprivileged this is a verified no-op (a thread may
    /// always shrink its own capability sets).
    pub fn drop_capabilities() {
        // Version probe: confirm the running kernel accepts VERSION_3 rather than assume it. A
        // null second argument is the documented "probe only" form of capget(2).
        let mut header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: `header` is a valid `&mut` target for the kernel to write back into; passing
        // null for `datap` is the documented probe-only form (capget(2)).
        let probe = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapUserHeader,
                ptr::null_mut::<CapUserData>(),
            )
        };
        if probe != 0 {
            abort_fail_closed("capget version probe", io::Error::last_os_error());
        }
        if header.version != LINUX_CAPABILITY_VERSION_3 {
            abort_fail_closed(
                "capget version probe",
                io::Error::other(format!(
                    "kernel wants capability version {:#x}, not VERSION_3",
                    header.version
                )),
            );
        }

        let empty = [CapUserData::default(); 2];
        let header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: `header` and `empty` are valid, live for the duration of this synchronous
        // syscall; `empty` has exactly the two elements VERSION_3 requires.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &header as *const CapUserHeader,
                empty.as_ptr(),
            )
        };
        if ret != 0 {
            abort_fail_closed("capset", io::Error::last_os_error());
        }

        // SAFETY: PR_CAP_AMBIENT / PR_CAP_AMBIENT_CLEAR_ALL reads no pointer argument.
        let ret = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        };
        if ret != 0 {
            abort_fail_closed("PR_CAP_AMBIENT_CLEAR_ALL", io::Error::last_os_error());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The host-tested policy (`seccomp_policy`'s pinned tables, exercised on every host
        /// through the BPF interpreter) must be EXACTLY what gets installed here.
        #[test]
        fn native_table_matches_the_pinned_host_tested_table() {
            #[cfg(target_arch = "x86_64")]
            let pinned = crate::seccomp_policy::pinned_x86_64();
            #[cfg(target_arch = "aarch64")]
            let pinned = crate::seccomp_policy::pinned_aarch64();
            assert_eq!(native_table(), pinned);
        }

        #[test]
        fn the_native_policy_compiles() {
            assert!(build_filter().is_ok());
        }
    }
}

/// Engages NO_NEW_PRIVS and the seccomp policy. Must run before any argv-driven logic (see
/// `main.rs`) -- FAIL-CLOSED: on any error this aborts the process rather than continuing
/// unconfined. NOT idempotent (a second seccomp install only narrows further, and NNP can't be
/// unset) -- callers must call this exactly once, at startup.
#[cfg(target_os = "linux")]
pub fn engage() {
    linux::engage();
}

/// Drops all capabilities (effective/permitted/inheritable/ambient) to nothing. FAIL-CLOSED like
/// `engage()`. See `linux::drop_capabilities` for the full rationale.
#[cfg(target_os = "linux")]
pub fn drop_capabilities() {
    linux::drop_capabilities();
}

/// Non-Linux builds: this crate ships no non-Linux resolution path at all (see `main.rs`), so
/// `engage()` is a compile-time no-op. Still called unconditionally from `main()` so the call site
/// never needs a `#[cfg]`.
#[cfg(not(target_os = "linux"))]
pub fn engage() {}

/// See `engage()`'s doc for why this is a no-op on non-Linux builds.
#[cfg(not(target_os = "linux"))]
pub fn drop_capabilities() {}
