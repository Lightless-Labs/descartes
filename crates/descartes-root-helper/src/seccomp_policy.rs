//! The helper's seccomp POLICY (2026-10 hardening), expressed against a per-arch `SyscallTable`
//! rather than `libc` constants directly so it is pure and host-testable: the unit tests below
//! compile the REAL policy for both shipped arches (pinned x86_64 + aarch64 tables) and run it
//! through `seccomp_bpf::evaluate` on any host -- including the macOS dev host, which cannot execute
//! Linux code. `hardening.rs` supplies the native table from `libc` on Linux, and a Linux-only test
//! there pins that native table equal to the hand-written one below, so the two cannot drift.
//!
//! WHAT THIS POLICY CAN AND CANNOT CONFINE (re-derived against the real grant,
//! `cap_sys_ptrace,cap_dac_read_search=ep`, per docs/research/2026-09-26-sandbox-and-microvm-
//! boundaries-research.md finding 1). seccomp sees the syscall number and six scalar arguments; it
//! can never read a path string. So:
//!
//!   CLOSED by this policy, even under arbitrary code execution inside the helper:
//!     - any write to any file (`openat` access mode must be O_RDONLY; O_CREAT/O_TRUNC/O_APPEND/
//!       O_TMPFILE/O_PATH and every other flag outside the four the helper uses are killed; every
//!       admitted open must also set O_NOFOLLOW);
//!     - writing another process's memory via `/proc/<pid>/mem` (needs O_RDWR/O_WRONLY);
//!     - READING another process's memory via `/proc/<pid>/mem`: `lseek`, `pread64`, `preadv*`
//!       are absent, so a `read` can only ever start at offset 0 (never a mapped address);
//!     - `ptrace`, `process_vm_readv/writev`, `pidfd_getfd`, `open_by_handle_at`, `openat2`,
//!       `execve*`, `socket*`, every `*stat*` (metadata oracle over DAC-protected paths);
//!     - writes to anything but stdout/stderr (fds 1, 2);
//!     - new executable memory (`PROT_EXEC` via mmap/mprotect) and file-backed mmaps;
//!     - every `prctl` except clearing the ambient capability set; `tgkill` of any other process;
//!       every `fcntl` except the F_GETFD validity probe.
//!
//!   NOT CLOSED (honest residual -- needs a different mechanism, see the research doc):
//!     - read-only `openat` + sequential `read`/`getdents64`/`readlinkat` of ANY non-symlink path
//!       component the capability pair reaches, e.g. `/etc/shadow` (CAP_DAC_READ_SEARCH bypasses
//!       file read DAC) and `/proc/<pid>/environ` (CAP_SYS_PTRACE satisfies ptrace_may_access),
//!       with the bytes able to leave only via stdout/stderr to the (helper-group) invoker.
//!       O_NOFOLLOW is required on every open and all helper path components are opened one at a
//!       time, so the helper does not intentionally traverse a symlink component. Path-scoped
//!       confinement would need Landlock, which was evaluated and REJECTED: Landlock's
//!       `ptrace_access_check` hook denies a landlocked process ptrace-mode access to tasks outside
//!       its domain, and `/proc/<pid>/exe` + `/proc/<pid>/fd/*` readlinks -- the helper's entire
//!       job -- go through `ptrace_may_access`. A mount/user namespace or chroot either needs
//!       capabilities this binary does not hold or re-scopes the granted ones away from the init
//!       namespace. The residual is therefore reachable only via a memory-safety bug in this small
//!       Rust binary whose only input is a digits-and-protocol-token argv.
#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::seccomp_bpf::{ArgCheck, Policy, Rule};

/// Per-arch syscall numbers and flag constants the policy is written against. Field names are the
/// syscall names; every one is justified against a real call site in `helper_policy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyscallTable {
    pub audit_arch: u32,
    pub x32_syscall_bit: Option<u32>,

    pub read: u32,
    pub write: u32,
    pub writev: u32,
    pub openat: u32,
    pub close: u32,
    pub fcntl: u32,
    pub getdents64: u32,
    pub readlinkat: u32,
    pub mmap: u32,
    pub mprotect: u32,
    pub munmap: u32,
    pub brk: u32,
    pub mremap: u32,
    pub madvise: u32,
    pub exit: u32,
    pub exit_group: u32,
    pub futex: u32,
    pub capget: u32,
    pub capset: u32,
    pub prctl: u32,
    pub rt_sigreturn: u32,
    pub rt_sigaction: u32,
    pub rt_sigprocmask: u32,
    pub sigaltstack: u32,
    pub clock_gettime: u32,
    pub getpid: u32,
    pub gettid: u32,
    pub tgkill: u32,

    /// KERNEL-visible open flag values (not glibc's: glibc defines O_LARGEFILE as 0 on 64-bit).
    pub o_cloexec: u32,
    pub o_directory: u32,
    pub o_nofollow: u32,
    pub o_largefile: u32,
    pub f_getfd: u32,
    pub pr_cap_ambient: u32,
    pub pr_cap_ambient_clear_all: u32,
    pub prot_exec: u32,
    pub map_anonymous: u32,
}

/// The only stdio fds the helper ever writes: stdout (JSON response) and stderr (diagnostics).
pub const STDOUT_FD: u32 = 1;
pub const STDERR_FD: u32 = 2;

/// Builds the helper's policy. `own_pid` is this process's pid, fixed at `engage()` time (no
/// fork/clone is allowlisted, so it can never change afterwards).
///
/// Call-site justification for every rule (see the module doc for what each restriction closes):
///   - openat [O_NOFOLLOW required; flags ⊆ CLOEXEC|DIRECTORY|NOFOLLOW|LARGEFILE, so access mode = O_RDONLY]:
///     `procfs::{open_proc_root, open_pid_dir, open_dir_at, read_file_at*}` -- the ONLY opens
///     after `engage()` (`proc_linux.rs` no longer uses `std::fs`, whose `read_to_string`/
///     `read_dir` paths needed statx/fstat).
///   - read: `procfs::read_file_at*`'s bounded raw `read` loop.
///   - getdents64: `procfs::read_dir_entries_at` (`/proc` and `/proc/<pid>/fd` listings).
///   - readlinkat: `procfs::read_link_at` (`exe`, fd symlinks).
///   - close: `OwnedFd` drop.
///   - fcntl [cmd == F_GETFD]: std's debug-assertions-only `OwnedFd` drop validity probe.
///   - write, writev [fd ∈ {1, 2}]: `println!`/`eprintln!` (stdout may use writev).
///   - mmap [no PROT_EXEC, MAP_ANONYMOUS required], mprotect [no PROT_EXEC], munmap, brk, mremap,
///     madvise: the glibc allocator (anonymous RW maps only) and std's exit-time alt-stack teardown.
///   - exit, exit_group: termination.
///   - futex [arg1 ∈ FUTEX_PRIVATE_FLAG|WAIT/WAKE/WAIT_BITSET, plus 393 for std compatibility]:
///     std/glibc locks (stdout's ReentrantLock, allocator).
///   - capget, capset, prctl [option == PR_CAP_AMBIENT, arg2 == CLEAR_ALL]: `drop_capabilities()`.
///   - rt_sigreturn, rt_sigaction, sigaltstack: signal return and std's exit-time
///     stack-overflow-guard teardown (empirically pinned on the CI guest, build #127).
///   - rt_sigprocmask, getpid, gettid, tgkill [tgid == own pid]: a Rust panic's abort path.
///   - clock_gettime: normally vDSO-served; allowlisted because strace under-reports vDSO calls.
///
/// REMOVED relative to the pre-2026-10 allowlist: lseek (the `/proc/<pid>/mem` read primitive),
/// statx/newfstatat/fstat (metadata oracle; only std::fs needed them), getrandom (the policy model
/// currently has only ALLOW/KILL actions, so it remains KILL rather than using SECCOMP_RET_ERRNO;
/// the helper no longer needs it), readlink (x86_64 path-based variant; only std::fs::read_link
/// needed it).
pub fn helper_policy(t: &SyscallTable, own_pid: u32) -> Policy {
    let allowed_open_flags = t.o_cloexec | t.o_directory | t.o_nofollow | t.o_largefile;
    let stdio_only = || ArgCheck::Low32OneOf {
        arg: 0,
        values: vec![STDOUT_FD, STDERR_FD],
    };
    let no_exec = || ArgCheck::Low32BitsClear {
        arg: 2,
        mask: t.prot_exec,
    };

    let rules = vec![
        Rule::when(
            t.openat,
            vec![
                ArgCheck::Low32BitsClear {
                    arg: 2,
                    mask: !allowed_open_flags,
                },
                ArgCheck::Low32BitsSet {
                    arg: 2,
                    mask: t.o_nofollow,
                },
            ],
        ),
        Rule::allow(t.read),
        Rule::allow(t.getdents64),
        Rule::allow(t.readlinkat),
        Rule::allow(t.close),
        Rule::when(
            t.fcntl,
            vec![ArgCheck::Low32OneOf {
                arg: 1,
                values: vec![t.f_getfd],
            }],
        ),
        Rule::when(t.write, vec![stdio_only()]),
        Rule::when(t.writev, vec![stdio_only()]),
        Rule::when(
            t.mmap,
            vec![
                no_exec(),
                ArgCheck::Low32BitsSet {
                    arg: 3,
                    mask: t.map_anonymous,
                },
            ],
        ),
        Rule::when(t.mprotect, vec![no_exec()]),
        Rule::allow(t.munmap),
        Rule::allow(t.brk),
        Rule::allow(t.mremap),
        Rule::allow(t.madvise),
        Rule::allow(t.exit),
        Rule::allow(t.exit_group),
        Rule::when(
            t.futex,
            vec![ArgCheck::Low32OneOf {
                arg: 1,
                values: vec![128, 129, 137, 393],
            }],
        ),
        Rule::allow(t.capget),
        Rule::allow(t.capset),
        Rule::when(
            t.prctl,
            vec![
                ArgCheck::Low32OneOf {
                    arg: 0,
                    values: vec![t.pr_cap_ambient],
                },
                ArgCheck::Low32OneOf {
                    arg: 1,
                    values: vec![t.pr_cap_ambient_clear_all],
                },
            ],
        ),
        Rule::allow(t.rt_sigreturn),
        Rule::allow(t.rt_sigaction),
        Rule::allow(t.sigaltstack),
        Rule::allow(t.rt_sigprocmask),
        Rule::allow(t.getpid),
        Rule::allow(t.gettid),
        Rule::when(
            t.tgkill,
            vec![ArgCheck::Low32OneOf {
                arg: 0,
                values: vec![own_pid],
            }],
        ),
        Rule::allow(t.clock_gettime),
    ];

    Policy {
        audit_arch: t.audit_arch,
        x32_syscall_bit: t.x32_syscall_bit,
        rules,
    }
}

/// Field-by-field equality usable in a `const` context. `hardening.rs` uses it in a COMPILE-TIME
/// assertion that the libc-derived native table equals the pinned table for the target arch, so a
/// plain `cargo check --target {x86_64,aarch64}-unknown-linux-gnu` verifies both pinned tables
/// (and therefore the policy the host tests interpret) against the real constants -- including
/// x86_64, which no CI runner executes.
pub const fn same_table(a: &SyscallTable, b: &SyscallTable) -> bool {
    let x32_same = match (a.x32_syscall_bit, b.x32_syscall_bit) {
        (Some(x), Some(y)) => x == y,
        (None, None) => true,
        _ => false,
    };
    x32_same
        && a.audit_arch == b.audit_arch
        && a.read == b.read
        && a.write == b.write
        && a.writev == b.writev
        && a.openat == b.openat
        && a.close == b.close
        && a.fcntl == b.fcntl
        && a.getdents64 == b.getdents64
        && a.readlinkat == b.readlinkat
        && a.mmap == b.mmap
        && a.mprotect == b.mprotect
        && a.munmap == b.munmap
        && a.brk == b.brk
        && a.mremap == b.mremap
        && a.madvise == b.madvise
        && a.exit == b.exit
        && a.exit_group == b.exit_group
        && a.futex == b.futex
        && a.capget == b.capget
        && a.capset == b.capset
        && a.prctl == b.prctl
        && a.rt_sigreturn == b.rt_sigreturn
        && a.rt_sigaction == b.rt_sigaction
        && a.rt_sigprocmask == b.rt_sigprocmask
        && a.sigaltstack == b.sigaltstack
        && a.clock_gettime == b.clock_gettime
        && a.getpid == b.getpid
        && a.gettid == b.gettid
        && a.tgkill == b.tgkill
        && a.o_cloexec == b.o_cloexec
        && a.o_directory == b.o_directory
        && a.o_nofollow == b.o_nofollow
        && a.o_largefile == b.o_largefile
        && a.f_getfd == b.f_getfd
        && a.pr_cap_ambient == b.pr_cap_ambient
        && a.pr_cap_ambient_clear_all == b.pr_cap_ambient_clear_all
        && a.prot_exec == b.prot_exec
        && a.map_anonymous == b.map_anonymous
}

/// Hand-pinned Linux x86_64 table (arch/x86/entry/syscalls/syscall_64.tbl + x86 uapi fcntl/mman).
/// Host tests interpret the real policy against it; on an x86_64 Linux target `hardening.rs`
/// asserts at COMPILE TIME that the libc-derived native table equals it exactly.
pub const fn pinned_x86_64() -> SyscallTable {
    SyscallTable {
        audit_arch: 0xC000_003E,
        x32_syscall_bit: Some(0x4000_0000),
        read: 0,
        write: 1,
        writev: 20,
        openat: 257,
        close: 3,
        fcntl: 72,
        getdents64: 217,
        readlinkat: 267,
        mmap: 9,
        mprotect: 10,
        munmap: 11,
        brk: 12,
        mremap: 25,
        madvise: 28,
        exit: 60,
        exit_group: 231,
        futex: 202,
        capget: 125,
        capset: 126,
        prctl: 157,
        rt_sigreturn: 15,
        rt_sigaction: 13,
        rt_sigprocmask: 14,
        sigaltstack: 131,
        clock_gettime: 228,
        getpid: 39,
        gettid: 186,
        tgkill: 234,
        o_cloexec: 0x80000,
        o_directory: 0x10000,
        o_nofollow: 0x20000,
        o_largefile: 0x8000,
        f_getfd: 1,
        pr_cap_ambient: 47,
        pr_cap_ambient_clear_all: 4,
        prot_exec: 4,
        map_anonymous: 0x20,
    }
}

/// Hand-pinned Linux aarch64 table (asm-generic unistd.h + arm64 uapi fcntl). See `pinned_x86_64`.
pub const fn pinned_aarch64() -> SyscallTable {
    SyscallTable {
        audit_arch: 0xC000_00B7,
        x32_syscall_bit: None,
        read: 63,
        write: 64,
        writev: 66,
        openat: 56,
        close: 57,
        fcntl: 25,
        getdents64: 61,
        readlinkat: 78,
        mmap: 222,
        mprotect: 226,
        munmap: 215,
        brk: 214,
        mremap: 216,
        madvise: 233,
        exit: 93,
        exit_group: 94,
        futex: 98,
        capget: 90,
        capset: 91,
        prctl: 167,
        rt_sigreturn: 139,
        rt_sigaction: 134,
        rt_sigprocmask: 135,
        sigaltstack: 132,
        clock_gettime: 113,
        getpid: 172,
        gettid: 178,
        tgkill: 131,
        o_cloexec: 0x80000,
        o_directory: 0x4000,
        o_nofollow: 0x8000,
        o_largefile: 0x20000,
        f_getfd: 1,
        pr_cap_ambient: 47,
        pr_cap_ambient_clear_all: 4,
        prot_exec: 4,
        map_anonymous: 0x20,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp_bpf::{
        compile, evaluate, SeccompData, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS,
    };

    const OWN_PID: u32 = 4242;

    /// Syscalls that must be KILLED unconditionally, per arch: (name, x86_64 nr, aarch64 nr).
    /// x86_64-only legacy syscalls use `None` on aarch64 (no such number exists there).
    const FORBIDDEN: &[(&str, u32, Option<u32>)] = &[
        ("lseek", 8, Some(62)),
        ("pread64", 17, Some(67)),
        ("preadv", 295, Some(69)),
        ("preadv2", 327, Some(286)),
        ("newfstatat", 262, Some(79)),
        ("fstat", 5, Some(80)),
        ("statx", 332, Some(291)),
        ("getrandom", 318, Some(278)),
        ("readlink", 89, None),
        ("open", 2, None),
        ("openat2", 437, Some(437)),
        ("ptrace", 101, Some(117)),
        ("process_vm_readv", 310, Some(270)),
        ("process_vm_writev", 311, Some(271)),
        ("pidfd_getfd", 438, Some(438)),
        ("open_by_handle_at", 304, Some(265)),
        ("socket", 41, Some(198)),
        ("execve", 59, Some(221)),
        ("execveat", 322, Some(281)),
        ("clone", 56, Some(220)),
        ("kill", 62, Some(129)),
        ("sendfile", 40, Some(71)),
        ("splice", 275, Some(76)),
        ("pwrite64", 18, Some(68)),
        ("mount", 165, Some(40)),
        ("unshare", 272, Some(97)),
        ("landlock_restrict_self", 446, Some(446)),
    ];

    struct Harness {
        t: SyscallTable,
        program: Vec<crate::seccomp_bpf::Insn>,
    }

    impl Harness {
        fn new(t: SyscallTable) -> Self {
            let program =
                compile(&helper_policy(&t, OWN_PID)).expect("the real policy must compile");
            Harness { t, program }
        }
        fn run(&self, nr: u32, args: [u64; 6]) -> u32 {
            evaluate(
                &self.program,
                &SeccompData {
                    nr,
                    arch: self.t.audit_arch,
                    args,
                },
            )
        }
        fn allowed(&self, nr: u32, args: [u64; 6]) -> bool {
            self.run(nr, args) == SECCOMP_RET_ALLOW
        }
        fn killed(&self, nr: u32, args: [u64; 6]) -> bool {
            self.run(nr, args) == SECCOMP_RET_KILL_PROCESS
        }
    }

    fn both_arches() -> [(SyscallTable, bool); 2] {
        [(pinned_x86_64(), true), (pinned_aarch64(), false)]
    }

    #[test]
    fn every_forbidden_syscall_is_killed_on_both_arches() {
        for (table, is_x86) in both_arches() {
            let h = Harness::new(table);
            for (name, x86, arm) in FORBIDDEN {
                let nr = if is_x86 { Some(*x86) } else { *arm };
                if let Some(nr) = nr {
                    assert!(
                        h.killed(nr, [0; 6]),
                        "{name} ({nr}) must be killed (x86_64={is_x86})"
                    );
                }
            }
        }
    }

    #[test]
    fn the_helper_s_own_opens_are_allowed() {
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            let at_fdcwd = (-100i64) as u64;
            // procfs::open_pid_dir / open_proc_root.
            let pid_dir = u64::from(t.o_directory | t.o_nofollow | t.o_cloexec);
            assert!(h.allowed(t.openat, [at_fdcwd, 0, pid_dir, 0, 0, 0]));
            // procfs::open_dir_at ("fd", ".").
            let sub_dir = u64::from(t.o_directory | t.o_nofollow | t.o_cloexec);
            assert!(h.allowed(t.openat, [3, 0, sub_dir, 0, 0, 0]));
            // procfs::read_file_at ("status", "cmdline", "net/tcp").
            let file = u64::from(t.o_nofollow | t.o_cloexec);
            assert!(h.allowed(t.openat, [3, 0, file, 0, 0, 0]));
            // A kernel-added/glibc-added O_LARGEFILE must not self-kill.
            assert!(h.allowed(t.openat, [3, 0, file | u64::from(t.o_largefile), 0, 0, 0]));
        }
    }

    #[test]
    fn every_openat_must_request_no_follow() {
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            let directory = u64::from(t.o_directory | t.o_cloexec);
            let file = u64::from(t.o_cloexec);
            assert!(h.killed(t.openat, [3, 0, directory, 0, 0, 0]));
            assert!(h.killed(t.openat, [3, 0, file, 0, 0, 0]));
            assert!(h.allowed(t.openat, [3, 0, file | u64::from(t.o_nofollow), 0, 0, 0]));
        }
    }

    #[test]
    fn writable_or_unexpected_open_flags_are_killed() {
        // O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, O_APPEND=0x400, O_NONBLOCK=0x800 on
        // both arches; O_PATH = 0x200000; __O_TMPFILE = 0x400000.
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            let base = u64::from(t.o_cloexec);
            for bad in [0x1u64, 0x2, 0x40, 0x200, 0x400, 0x800, 0x200000, 0x400000] {
                assert!(
                    h.killed(t.openat, [3, 0, base | bad, 0, 0, 0]),
                    "openat flag {bad:#x} must be killed"
                );
            }
            // /proc/<victim>/mem opened for writing: O_RDWR.
            assert!(h.killed(t.openat, [3, 0, 0x2, 0, 0, 0]));
        }
    }

    #[test]
    fn writes_are_confined_to_stdout_and_stderr() {
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            for nr in [t.write, t.writev] {
                assert!(h.allowed(nr, [1, 0, 0, 0, 0, 0]));
                assert!(h.allowed(nr, [2, 0, 0, 0, 0, 0]));
                assert!(h.killed(nr, [0, 0, 0, 0, 0, 0]));
                assert!(h.killed(nr, [3, 0, 0, 0, 0, 0]));
            }
        }
    }

    #[test]
    fn executable_or_file_backed_memory_is_killed() {
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            let rw = 0x3u64;
            let private_anon = 0x2u64 | u64::from(t.map_anonymous);
            assert!(h.allowed(t.mmap, [0, 4096, rw, private_anon, u64::MAX, 0]));
            assert!(h.allowed(t.mmap, [0, 4096, 0, private_anon, u64::MAX, 0])); // PROT_NONE guard.
            assert!(h.killed(t.mmap, [0, 4096, rw | 0x4, private_anon, u64::MAX, 0]));
            assert!(h.killed(t.mmap, [0, 4096, 0x1, 0x2, 3, 0])); // file-backed MAP_PRIVATE.
            assert!(h.allowed(t.mprotect, [0, 4096, rw, 0, 0, 0]));
            assert!(h.killed(t.mprotect, [0, 4096, 0x5, 0, 0, 0]));
        }
    }

    #[test]
    fn prctl_tgkill_and_fcntl_are_narrowed_to_their_single_use() {
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            assert!(h.allowed(t.prctl, [47, 4, 0, 0, 0, 0]));
            assert!(h.killed(t.prctl, [47, 2, 9, 0, 0, 0])); // PR_CAP_AMBIENT_RAISE.
            assert!(h.killed(t.prctl, [4, 1, 0, 0, 0, 0])); // PR_SET_DUMPABLE.
            assert!(h.killed(t.prctl, [22, 2, 0, 0, 0, 0])); // PR_SET_SECCOMP (re-install).
            assert!(h.allowed(t.tgkill, [u64::from(OWN_PID), 4243, 6, 0, 0, 0]));
            assert!(h.killed(t.tgkill, [1, 1, 9, 0, 0, 0]));
            assert!(h.allowed(t.fcntl, [3, 1, 0, 0, 0, 0])); // F_GETFD.
            assert!(h.killed(t.fcntl, [3, 2, 0, 0, 0, 0])); // F_SETFD.
            assert!(h.killed(t.fcntl, [3, 0, 10, 0, 0, 0])); // F_DUPFD.
        }
    }

    #[test]
    fn futex_is_limited_to_private_wait_and_wake_operations() {
        // FUTEX_PRIVATE_FLAG | WAIT/WAKE/WAIT_BITSET. 393 is retained for the std runtime's
        // observed compatibility operation on Linux; it remains a private, non-shared command.
        const PRIVATE_STD_FUTEX_OPS: &[u32] = &[128, 129, 137, 393];
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            for op in PRIVATE_STD_FUTEX_OPS {
                assert!(h.allowed(t.futex, [0, u64::from(*op), 0, 0, 0, 0]));
            }
            for op in [0u32, 1, 9, 10, 138, 141, 999] {
                assert!(
                    h.killed(t.futex, [0, u64::from(op), 0, 0, 0, 0]),
                    "shared or unsupported futex op {op} must be killed"
                );
            }
        }
    }

    #[test]
    fn every_number_only_allow_is_reachable() {
        for (t, _) in both_arches() {
            let h = Harness::new(t.clone());
            for nr in [
                t.read,
                t.getdents64,
                t.readlinkat,
                t.close,
                t.munmap,
                t.brk,
                t.mremap,
                t.madvise,
                t.exit,
                t.exit_group,
                t.capget,
                t.capset,
                t.rt_sigreturn,
                t.rt_sigaction,
                t.sigaltstack,
                t.rt_sigprocmask,
                t.getpid,
                t.gettid,
                t.clock_gettime,
            ] {
                assert!(h.allowed(nr, [0; 6]), "syscall {nr} must stay allowed");
            }
        }
    }
}
