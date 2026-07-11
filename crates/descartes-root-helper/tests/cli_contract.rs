//! Integration tests that run the BUILT BINARY (never the crate's internal functions) via
//! `std::process::Command`, per the Slice 3 test plan. These exercise the argv contract and the
//! `--probe` exit-status contract cross-platform; Linux-only `/proc` resolution tests live in
//! `tests/linux_resolution.rs`.

use std::process::Command;

fn bin_path() -> String {
    std::env::var("CARGO_BIN_EXE_descartes-root-helper").expect(
        "cargo sets CARGO_BIN_EXE_descartes-root-helper for integration tests in this package",
    )
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin_path())
        .args(args)
        .output()
        .expect("failed to spawn the built helper binary")
}

#[test]
fn bad_argv_exits_nonzero_with_empty_stdout_never_partial_output() {
    let bad_argv_cases: &[&[&str]] = &[
        &[],
        &["--unknown"],
        &["--resolve-pid"],
        &["--resolve-port"],
        &["--resolve-pid", "abc"],
        &["--resolve-pid", "-5"],
        &["--resolve-pid", ""],
        &["--resolve-pid", "123", "456"],
        &["--probe", "--resolve-pid", "123"],
        &["--resolve-pid", "123", "--resolve-port", "456"],
        &["-p", "123"],
        &["--help"],
    ];

    for case in bad_argv_cases {
        let output = run(case);
        assert!(
            !output.status.success(),
            "expected nonzero exit for argv {case:?}, got {:?}",
            output.status
        );
        assert!(
            output.stdout.is_empty(),
            "expected empty stdout for argv {case:?}, got {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn bad_argv_exits_with_the_usage_error_code_specifically() {
    // Exit codes: 0 success, 1 resolution failure, 2 usage error -- bad argv must land on 2, not
    // collide with the resolution-failure code.
    let output = run(&["--nonsense"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn bad_argv_prints_the_usage_string_to_stderr() {
    let output = run(&["--nonsense"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage:"),
        "expected a usage string on stderr, got: {stderr}"
    );
}

// std::env::args() would panic (exit 101, raw panic text on stderr) on non-UTF-8 argv; the
// contract requires the ordinary usage-error path instead. Unix-only because building a
// non-UTF-8 OsStr portably requires the unix OsStrExt.
#[cfg(unix)]
#[test]
fn non_utf8_argv_is_a_usage_error_not_a_panic() {
    use std::os::unix::ffi::OsStrExt;

    let output = Command::new(bin_path())
        .arg("--resolve-pid")
        .arg(std::ffi::OsStr::from_bytes(b"\xff\xfe"))
        .output()
        .expect("failed to spawn the built helper binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "usage error, not a 101 panic exit"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout must stay empty on bad argv"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage:") && !stderr.contains("panicked"),
        "expected the usage string (and no panic trace) on stderr, got: {stderr}"
    );
}

#[test]
fn probe_behaves_per_platform_contract() {
    let output = run(&["--probe"]);

    #[cfg(target_os = "linux")]
    {
        assert!(
            output.status.success(),
            "expected --probe to exit 0 on Linux"
        );
        assert!(
            output.stdout.is_empty(),
            "expected --probe to print nothing to stdout, ever"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert!(
            !output.status.success(),
            "a non-Linux build must never report --probe as available"
        );
        assert!(
            output.stdout.is_empty(),
            "expected --probe to print nothing to stdout, ever"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn resolution_attempts_fail_cleanly_on_non_linux_with_no_stdout() {
    for args in [vec!["--resolve-pid", "1"], vec!["--resolve-port", "1"]] {
        let output = run(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
