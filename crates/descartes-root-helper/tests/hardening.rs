//! Kernel-enforced hardening properties (S3-priv Slice 4). Whole-file Linux-only: every property
//! exercised here is a Linux-specific kernel mechanism (seccomp, NO_NEW_PRIVS, capset) with no
//! analog to test elsewhere -- see `src/hardening.rs` for the properties themselves.
//!
//! Every case here spawns a SEPARATE process (`hardening-probe`, or the production binary) --
//! `hardening::engage()` installs a `SECCOMP_RET_KILL_PROCESS` default action, which must never
//! run inside this test binary's own (multithreaded) `cargo test` process. See
//! `src/bin/hardening-probe.rs`'s module doc for the full rationale.

#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

fn probe_path() -> &'static str {
    env!("CARGO_BIN_EXE_hardening-probe")
}

fn helper_path() -> String {
    std::env::var("CARGO_BIN_EXE_descartes-root-helper").expect(
        "cargo sets CARGO_BIN_EXE_descartes-root-helper for integration tests in this package",
    )
}

fn run_probe(mode: &str) -> ExitStatus {
    Command::new(probe_path())
        .arg(mode)
        .status()
        .expect("failed to spawn hardening-probe")
}

fn run_helper(args: &[&str]) -> std::process::Output {
    Command::new(helper_path())
        .args(args)
        .output()
        .expect("failed to spawn the built helper binary")
}

/// crit4 (no-ptrace): any ptrace(2) request is denied structurally -- SIGSYS-killed before the
/// kernel even inspects the request, not merely refused with EPERM the way an unprivileged process
/// would ordinarily be refused.
#[test]
fn ptrace_is_killed_by_seccomp_not_merely_refused() {
    let status = run_probe("--do-ptrace");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected SIGSYS (31), got {status:?}"
    );
}

/// crit5 (no-network): no network syscall is reachable at all.
#[test]
fn socket_is_killed_by_seccomp() {
    let status = run_probe("--do-socket");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected SIGSYS (31), got {status:?}"
    );
}

/// crit5 regression-proof (D5's correction): process_vm_readv shares ptrace's blast radius --
/// reads another process's memory -- WITHOUT ever calling ptrace() itself. It must be denied on
/// its own merits by the default action, not accidentally allowed because it "isn't ptrace".
#[test]
fn process_vm_readv_is_killed_by_seccomp() {
    let status = run_probe("--do-process-vm-readv");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected SIGSYS (31), got {status:?}"
    );
}

/// crit5 regression-proof, write half: process_vm_writev shares ptrace's/process_vm_readv's blast
/// radius -- writes another process's memory -- WITHOUT ever calling ptrace(). It must be denied on
/// its own merits by the default action, not accidentally allowed because it "isn't ptrace" or
/// "isn't the read half".
#[test]
fn process_vm_writev_is_killed_by_seccomp() {
    let status = run_probe("--do-process-vm-writev");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected SIGSYS (31), got {status:?}"
    );
}

/// crit5 regression-proof (S3-priv Slice 6 fix): `open_by_handle_at` is `CAP_DAC_READ_SEARCH`'s
/// own blast-radius amplifier -- it opens an arbitrary file by opaque handle, bypassing the normal
/// directory-permission walk, and is gated in the kernel by `capable(CAP_DAC_READ_SEARCH)`
/// (`fs/fhandle.c`) -- the exact capability Slice 6 adds to this binary's file-capability grant
/// (`cap_sys_ptrace,cap_dac_read_search=ep`) for cross-UID `/proc/<pid>/fd` enumeration (see
/// `proc_linux.rs`'s module doc). It is NOT in `allowed_syscalls()`, so the default
/// `KILL_PROCESS` action must still deny it even though this binary now actually holds the
/// capability that would otherwise make the syscall usable.
#[test]
fn open_by_handle_at_is_killed_by_seccomp() {
    let status = run_probe("--do-open-by-handle-at");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected SIGSYS (31), got {status:?}"
    );
}

/// crit2 (NNP): PR_SET_NO_NEW_PRIVS is actually set after engage(), read back from the kernel via
/// /proc/self/status rather than trusted from prctl()'s own return value.
#[test]
fn no_new_privs_is_set_after_engage() {
    let status = run_probe("--check-nnp");
    assert!(
        status.success(),
        "expected --check-nnp to exit 0 (NoNewPrivs == 1), got {status:?}"
    );
}

/// crit1 (cap-drop): drop_capabilities() run unprivileged is a verified no-op -- CapEff/CapPrm
/// read back empty from the kernel afterwards. NOTE: this only proves "shrinking nothing to
/// nothing works"; observing an actual nonzero-to-zero transition needs a real capability to drop
/// in the first place -- that's Slice 6's CI-with-setcap job, not something this Linux-VM-less dev
/// host (or ordinary CI runner, which also doesn't grant this binary anything) can exercise.
#[test]
fn cap_drop_is_a_clean_no_op_when_unprivileged() {
    let status = run_probe("--check-capdrop");
    assert!(
        status.success(),
        "expected --check-capdrop to exit 0 (CapEff/CapPrm empty), got {status:?}"
    );
}

/// crit3 (completeness): the PRODUCTION binary, which now engages the filter as the first
/// statement of main(), still succeeds under it end-to-end -- proves the allowlist covers what
/// `--probe` actually needs, with no self-inflicted SIGSYS. `tests/linux_resolution.rs` already
/// spawns this same built binary for `--resolve-pid`/`--resolve-port`, so those became live-filter
/// tests automatically the moment `engage()` started running at process start -- no changes needed
/// there, and no separate `--probe-under-filter` plumbing exists on the production binary (its
/// argv contract is exactly `--probe` already).
#[test]
fn probe_succeeds_under_the_live_filter() {
    let output = run_helper(&["--probe"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "expected --probe to print nothing to stdout, ever"
    );
}
