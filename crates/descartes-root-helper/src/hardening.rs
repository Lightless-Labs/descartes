//! Kernel-level defensive hardening for descartes-root-helper (S3-priv Slice 4). This crate is
//! currently unprivileged and stays that way in this slice (see `main.rs`'s module doc). The
//! properties installed here exist so that WHEN Slice 5 manually grants `cap_sys_ptrace=ep` (a
//! `setcap` step outside this repo's code), that capability's blast radius is structurally
//! confined: `ptrace(2)` and everything that shares its threat model become unreachable syscalls,
//! not merely policy the binary promises not to use.
//!
//! Three properties, all KERNEL-enforced (never code-review-assumed):
//!   1. `PR_SET_NO_NEW_PRIVS` (`engage()`) -- this process can never gain privilege beyond what it
//!      already has. It also can never usefully execve (nothing is allowlisted below to make
//!      execve succeed), so the bounding set is irrelevant here -- see `drop_capabilities()`.
//!   2. A seccomp-bpf syscall ALLOWLIST (`engage()`, default action `SECCOMP_RET_KILL_PROCESS`,
//!      the process-scoped kill, not the legacy thread-scoped `SECCOMP_RET_KILL`) that makes
//!      `ptrace`, `process_vm_readv`, `process_vm_writev`, and `pidfd_getfd` -- the whole
//!      CAP_SYS_PTRACE blast radius, not just `ptrace` itself -- unreachable. Requires a Linux
//!      kernel >= 4.14 (KILL_PROCESS's introduction); this repo's CI runs 6.17.
//!   3. A capability drop (`drop_capabilities()`, called separately by `main.rs` AFTER the /proc
//!      reads that need the future capability and BEFORE any output) that zeroes the
//!      effective/permitted/inheritable sets and the ambient set.
//!
//! FAIL-CLOSED: any unexpected error from any step aborts the process (stderr-only diagnostic,
//! nonzero exit) rather than continuing without the property. A silently-missing filter would gut
//! the whole safety argument, so there is no warn-and-continue path anywhere in this file.
//!
//! Allowlist re-derivation: `strace -f -c <bin> --resolve-pid $$` on a Linux host, cross-checked
//! against `proc_linux.rs`'s actual syscalls plus the Rust/glibc runtime's own (allocator, panic
//! path, vDSO fallback). The list in `allowed_syscalls` below is reasoned-then-CI-confirmed -- CI
//! is the only oracle available (this dev host has no Linux virtualization) -- and any future
//! addition to it is a security-review-required change, not a routine one.
//!
//! ALL unsafe code in this crate's production path lives in this file AND `src/procfs.rs`
//! (S3-priv Slice 5 Part A's `/proc/<pid>` dirfd-pinning primitives -- see that module's doc). The
//! other production modules -- `main.rs`, `argv.rs`, `json.rs`, `proc_linux.rs` -- stay
//! `#![deny(unsafe_code)]`/`#![forbid(unsafe_code)]` clean, i.e. would fail to compile if any of
//! them grew an unsafe block; `proc_linux.rs` calls into `procfs`'s safe-signature functions
//! exactly as it calls into this file's `engage()`/`drop_capabilities()`.
//! `src/bin/hardening-probe.rs` is the one other file in this crate with unsafe, and it is
//! test-support only, never shipped as the helper -- see its module doc.

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::mem::offset_of;
    use std::ptr;

    // libc (the crate) gives us arch-correct SYS_*/PR_*/BPF_*/SECCOMP_* constants and the
    // `seccomp_data`/`sock_filter`/`sock_fprog` structs, but NOT the capset(2) structs or the
    // AUDIT_ARCH_* constants -- both are hand-defined below, straight from the kernel UAPI headers
    // they come from (see the Cargo.toml comment on the libc dependency for why).

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

    /// `<linux/audit.h>`: `EM_<arch> | __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE
    /// (0x4000_0000)`. This binary is compiled per-target and never cross-arch at runtime, so only
    /// the native arch's constant needs to exist.
    #[cfg(target_arch = "x86_64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E; // EM_X86_64 = 62

    #[cfg(target_arch = "aarch64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7; // EM_AARCH64 = 183

    /// x32-ABI syscalls report `AUDIT_ARCH_X86_64` (identical to native x86_64) but OR this bit
    /// into the syscall number -- the classic hand-rolled-seccomp-filter bypass (D4). aarch64 has
    /// no x32 analog, hence no equivalent constant on that arch.
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    /// The reasoned allowlist. Each entry is justified against a real caller:
    ///   - openat, read, close, write, writev: file I/O throughout `proc_linux.rs`, plus stdout.
    ///   - getdents64: `fs::read_dir("/proc")` in `find_owning_pid`.
    ///   - readlink / readlinkat: `fs::read_link` for `/proc/<pid>/exe` and fd symlinks. aarch64
    ///     glibc has NO `readlink` syscall at all (issues `readlinkat` only); x86_64 glibc may use
    ///     either, so both are allowlisted on the arches where they exist (see the `#[cfg]` below).
    ///   - statx, newfstatat, fstat: std's file-size probing tries statx then falls back to the
    ///     others -- but under `KILL_PROCESS` a denied statx is SIGSYS, not ENOSYS, so the
    ///     fallback never gets a chance to run unless all three are present.
    ///   - getrandom: `HashSet`'s random seed, drawn on first use -- AFTER the filter installs.
    ///   - mmap, munmap, brk, mremap, madvise, mprotect: the allocator.
    ///   - exit_group, exit: normal and thread exit.
    ///   - futex: std/glibc lock implementations.
    ///   - capset, capget, prctl: `drop_capabilities()` below.
    ///   - rt_sigreturn: returning from ANY signal handler taken while the filter is active dies
    ///     without this -- including the panic path immediately below.
    ///   - clock_gettime: usually served by the vDSO (no syscall trap at all), allowlisted anyway
    ///     as insurance -- an strace-derived list systematically under-reports vDSO-served calls.
    ///   - lseek: `proc_linux.rs` today uses only std's free functions (`fs::read`,
    ///     `fs::read_to_string`, `fs::read_dir`, `fs::read_link`), none of which lseek. It is
    ///     allowlisted anyway as insurance in the same category as clock_gettime above: std's
    ///     `Read` trait methods (`read_to_string`/`read_to_end` on an open `File`) DO issue lseek
    ///     via stream-position probing, so a future refactor to `File::open(...).read_to_string()`
    ///     (or a std-internal change) would otherwise self-SIGSYS -- repositioning an fd this
    ///     process already owns is harmless. See `proc_linux.rs`'s module doc for the matching note
    ///     on that side of this coupling.
    ///   - fcntl: never emitted by a RELEASE build. std's `OwnedFd` `Drop`, in debug-assertions
    ///     builds ONLY, issues `fcntl(fd, F_GETFD)` as an fd-validity assertion before `close` -- so
    ///     every `cargo test` (debug) run of anything that drops an `OwnedFd` (`procfs.rs`, i.e. all
    ///     of resolution) self-SIGSYSed without this (empirically pinned by strace on the aarch64 CI
    ///     guest). Allowlisted number-only like every other entry: all fcntl cmds act only on fds
    ///     this process already owns, and with no `exec*` and no `socket*` allowlisted, an fd
    ///     stripped of CLOEXEC can never leave this process -- so the cmd breadth adds nothing to the
    ///     blast radius this filter confines. The "O_CLOEXEC via open flag, never fcntl(F_SETFD)"
    ///     rule (`procfs.rs` module doc) is enforced by review + the security-review-required rule on
    ///     any `allowed_syscalls()` addition from here on, not by this filter.
    ///   - rt_sigprocmask, getpid, gettid, tgkill: a Rust panic's abort path. Without these a panic
    ///     dies to SIGSYS instead of SIGABRT -- still loud, still a nonzero exit, but a SIGSYS core
    ///     from this binary should be read as "maybe just a panic", not only "attack".
    ///
    /// ptrace, process_vm_readv, process_vm_writev, pidfd_getfd, socket, and everything else are
    /// deliberately ABSENT here -- caught by the default KILL_PROCESS action, not an explicit deny
    /// (see `tests/hardening.rs`, which regression-proofs several of these by name).
    fn allowed_syscalls() -> Vec<libc::c_long> {
        // `mut` is only exercised on x86_64 (the push below); aarch64 has no such syscall to add.
        #[allow(unused_mut)]
        let mut allowed = vec![
            libc::SYS_openat,
            libc::SYS_read,
            libc::SYS_close,
            libc::SYS_fcntl,
            libc::SYS_write,
            libc::SYS_writev,
            libc::SYS_getdents64,
            libc::SYS_readlinkat,
            libc::SYS_statx,
            libc::SYS_newfstatat,
            libc::SYS_fstat,
            libc::SYS_getrandom,
            libc::SYS_lseek,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_mprotect,
            libc::SYS_exit_group,
            libc::SYS_exit,
            libc::SYS_futex,
            libc::SYS_capset,
            libc::SYS_capget,
            libc::SYS_prctl,
            libc::SYS_rt_sigreturn,
            libc::SYS_clock_gettime,
            libc::SYS_rt_sigprocmask,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_tgkill,
            // std::process::exit -> rt::cleanup() tears down the stack-overflow guard at process
            // exit: sigaltstack(SS_DISABLE) + munmap(alt-stack) + rt_sigaction to restore the
            // SIGSEGV/SIGBUS handlers. These run AFTER the filter installs, so without them EVERY
            // invocation self-SIGSYSes on the way out (empirically confirmed by strace on the CI
            // guest, build #127 -- the kill landed on the syscall right after PR_CAP_AMBIENT_CLEAR_ALL).
            // Neither is a blast-radius concern: both only touch this process's own signal handling.
            libc::SYS_sigaltstack,
            libc::SYS_rt_sigaction,
        ];
        // aarch64 has no `readlink` syscall at all (see the doc above) -- there is no constant to
        // reference on that arch, so this entry only exists to be pushed on x86_64.
        #[cfg(target_arch = "x86_64")]
        allowed.push(libc::SYS_readlink);
        allowed
    }

    fn bpf_stmt(code: u32, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        }
    }

    /// Builds the BPF program: arch gate -> (x86_64 only) x32 gate -> per-syscall allow cascade ->
    /// default KILL_PROCESS. See the module doc for the overall property and `allowed_syscalls`
    /// for the per-entry justification.
    fn build_filter() -> Vec<libc::sock_filter> {
        let arch_offset = offset_of!(libc::seccomp_data, arch) as u32;
        let nr_offset = offset_of!(libc::seccomp_data, nr) as u32;

        let mut program = vec![
            bpf_stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, arch_offset),
            // Non-native arch (e.g. the i386/arm32 compat ABI entered via a 32-bit int80/svc) hits
            // KILL_PROCESS below; the native arch skips over it (D4).
            bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                NATIVE_AUDIT_ARCH,
                1,
                0,
            ),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
            bpf_stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, nr_offset),
        ];

        #[cfg(target_arch = "x86_64")]
        {
            // x32 syscalls report AUDIT_ARCH_X86_64 (so they survive the gate above) but OR this
            // bit into `nr` -- the classic hand-rolled-filter bypass (D4). Kill before `nr` is ever
            // compared against the allowlist below, which is written in native x86_64 numbering.
            program.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
                X32_SYSCALL_BIT,
                0,
                1,
            ));
            program.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_KILL_PROCESS,
            ));
        }

        for syscall_nr in allowed_syscalls() {
            program.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                syscall_nr as u32,
                0,
                1,
            ));
            program.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ALLOW,
            ));
        }

        program.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS,
        ));
        program
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
        let program = build_filter();
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
    /// `capset(2)`, ambient set via `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`.
    ///
    /// Deliberately NOT `PR_CAPBSET_DROP`: that needs `CAP_SETPCAP`, which this binary never holds
    /// (EPERM both unprivileged today and under the real cap_sys_ptrace-only grant Slice 5 adds).
    /// Deliberately does not touch the bounding set at all: it only constrains capability GAIN
    /// across execve, and this process can never execve -- no exec* syscall is allowlisted above,
    /// and NO_NEW_PRIVS is set regardless.
    ///
    /// Called by the production binary right after a resolve attempt (success or failure) and
    /// before any output -- see `main.rs`. Unprivileged (this crate, today), this is a verified
    /// no-op: a thread may always shrink its own capability sets, so dropping an already-empty set
    /// always succeeds -- which is exactly what makes this genuinely uniform between CI (no caps
    /// at all) and the real Slice-5 grant (cap_sys_ptrace only).
    pub fn drop_capabilities() {
        // Version probe: confirm the running kernel accepts the version this file hand-rolled the
        // two-element CapUserData array for, rather than assume it. A null second argument is the
        // documented "probe only" form of capget(2). Every kernel since 2.6.26 accepts VERSION_3,
        // so in practice this is a sanity check, not live version-negotiation branching -- but it
        // is a real syscall this filter must allowlist (capget), not a no-op.
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
}

/// Exit code for a fail-closed hardening abort -- distinct from the production binary's
/// 0/1/2 (success / resolution failure / usage error) so a hardening abort is never mistaken for
/// an ordinary resolution failure.
#[cfg(target_os = "linux")]
const EXIT_HARDENING_FAILURE: i32 = 3;

/// Engages NO_NEW_PRIVS and the seccomp allowlist. Must run before any argv-driven logic (see
/// `main.rs`) -- FAIL-CLOSED: on any error this aborts the process rather than continuing
/// unconfined. Idempotent-in-intent but NOT idempotent in fact (a second seccomp install only
/// narrows further, and NNP can't be unset) -- callers must call this exactly once, at startup.
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

/// Non-Linux builds (this repo's macOS dev/CI host): no ptrace-blast-radius threat model applies
/// here -- this crate ships no non-Linux resolution path at all (see `main.rs`) -- so `engage()`
/// is a compile-time no-op. It is still called unconditionally from `main()` so the call site
/// never needs a `#[cfg]`.
#[cfg(not(target_os = "linux"))]
pub fn engage() {}

/// See `engage()`'s doc for why this is a no-op on non-Linux builds.
#[cfg(not(target_os = "linux"))]
pub fn drop_capabilities() {}
