//! descartes-root-helper -- fixed-argv `/proc` resolver for descartes-cli's opt-in elevated
//! read path (S3-priv). Slice 3 built the skeleton, argv contract, and JSON stdout. Slice 4
//! (`hardening::engage()`, called first thing below) adds the seccomp/no-new-privs/cap-drop
//! confinement a capability-bearing build of this binary requires. This binary is STILL granted
//! no capability by anything in this crate -- Slice 5/6 document (and, in CI, actually perform)
//! the (manual, out-of-code) `setcap cap_sys_ptrace,cap_dac_read_search=ep` install step -- the
//! minimal sufficient capability UNION for cross-UID `/proc/<pid>/fd` enumeration, not
//! `cap_sys_ptrace` alone (see `proc_linux.rs`'s module doc) -- that will eventually make the
//! hardening below matter.
//!
//! Contract (authoritative source: `tools/descartes-cli/src/tools/provenance-elevated.js`,
//! docs/plans/2026-07-11-s3-priv-elevated-read-path.md Slice 3):
//!   - argv is EXACTLY `--probe` | `--resolve-pid <digits>` |
//!     `--resolve-socket <tcp|tcp6|udp|udp6> <port> <inode>` (2026-10: replaces the unbound
//!     `--resolve-port <digits>`; see `socket.rs`).
//!   - `--probe`: exit 0 means "available", nothing is ever printed to stdout. On a non-Linux
//!     build this can never be true (there is no resolution mechanism), so `--probe` exits
//!     nonzero -- reporting available would be a lie.
//!   - A successful resolution prints ONE line of JSON to stdout and exits 0.
//!   - ANY failure (bad argv, not-found, unreadable /proc, non-Linux) exits nonzero and prints
//!     NOTHING to stdout -- never partial/malformed output. A short diagnostic on stderr is fine;
//!     bad argv prints the literal `argv::USAGE` string to stderr.
//!   - No env-based or config-file-based behavior of any kind.

// This bin crate (main.rs + argv.rs + json.rs + proc_linux.rs) contains zero unsafe blocks --
// all unsafe lives in the lib's `hardening`/`procfs` modules and the separate probe bin -- so
// `forbid` (the strictest of the two, unlike lib.rs's `deny`, it can never be locally relaxed)
// compiles clean.
#![forbid(unsafe_code)]

mod argv;
mod json;
#[cfg(target_os = "linux")]
mod proc_linux;
mod scan;
mod socket;

use argv::Command;
use descartes_root_helper::hardening;

// INVARIANT: every Linux exit path from this binary drops capabilities before terminating, not
// just the two --resolve-* paths that actually did anything with the (future) capability --
// `drop_capabilities()` is a documented no-op on non-Linux and a clean no-op when unprivileged, so
// calling it uniformly costs nothing and removes "which exit paths are covered" as a question.

// EXIT_SUCCESS is only ever returned on Linux (a --probe or successful resolution); on a
// non-Linux build every path is a resolution failure by design (see run_probe below), so this
// constant is legitimately unused there outside #[cfg(test)].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EXIT_SUCCESS: i32 = 0;
const EXIT_RESOLUTION_FAILURE: i32 = 1;
const EXIT_USAGE_ERROR: i32 = 2;
// Codex-hardening #6: a `--resolve-socket` that found no holder AND hit a bound (the socket table
// read, the `/proc` listing, or a non-holder's `/proc/<pid>/fd` table) -- so "not found" is
// UNCERTAIN, not definitive. A distinct nonzero code (still a failure to any caller that only
// checks exit==0) lets the Node side surface `fd_scan_truncated` in provenance instead of a silent,
// indistinguishable-from-genuine negative. Only ever returned on Linux `--resolve-socket`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EXIT_RESOLUTION_TRUNCATED: i32 = 3;
// 4 is `hardening::EXIT_HARDENING_FAILURE` (fail-closed confinement abort) -- never reused here.
// 2026-10 (research finding 2): the socket is held by more than one distinct process (or by more
// than the holder cap), so no single owner can be named. Nonzero + empty stdout like every
// failure; distinct so Node can surface `elevated_owner_ambiguous`. Linux `--resolve-socket` only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EXIT_OWNER_AMBIGUOUS: i32 = 5;

fn main() {
    // FIRST statement, unconditionally, before any argv logic: fail-closed by construction (see
    // hardening.rs) -- there is no code path in this binary that runs before confinement engages.
    hardening::engage();

    // args_os, not args: std::env::args() panics on non-UTF-8 argv, which would exit 101 with a
    // raw panic message instead of the contract's usage-error path (exit 2, USAGE on stderr).
    let mut args: Vec<String> = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(arg) => args.push(arg),
            Err(_) => {
                hardening::drop_capabilities();
                eprintln!("{}", argv::USAGE);
                std::process::exit(EXIT_USAGE_ERROR);
            }
        }
    }
    std::process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    match argv::parse(args) {
        Err(()) => {
            hardening::drop_capabilities();
            eprintln!("{}", argv::USAGE);
            EXIT_USAGE_ERROR
        }
        Ok(Command::Probe) => run_probe(),
        Ok(Command::ResolvePid(pid)) => run_resolve_pid(pid),
        Ok(Command::ResolveSocket(target)) => run_resolve_socket(target),
    }
}

#[cfg(target_os = "linux")]
fn run_probe() -> i32 {
    // --probe never reads anything a future capability would gate, but it still drops per the
    // "every Linux exit path drops" invariant above.
    hardening::drop_capabilities();
    // Print NOTHING on --probe, per contract -- the Node side's defaultProbeElevatedHelper only
    // ever inspects the exit status.
    EXIT_SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn run_probe() -> i32 {
    eprintln!("descartes-root-helper: elevated /proc resolution is only implemented on Linux");
    EXIT_RESOLUTION_FAILURE
}

#[cfg(target_os = "linux")]
fn run_resolve_pid(pid: u32) -> i32 {
    let resolved = proc_linux::resolve_pid(pid);
    // Drop right after the reads that need the (future) capability, before ANY output -- success
    // or failure, per hardening.rs's documented sequence: resolve -> drop -> emit.
    hardening::drop_capabilities();
    match resolved {
        Some(resolved) => {
            println!(
                "{}",
                json::emit_response(json::Requested::Pid(pid), &resolved, None)
            );
            EXIT_SUCCESS
        }
        None => {
            eprintln!("descartes-root-helper: could not resolve pid {pid}");
            EXIT_RESOLUTION_FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_resolve_pid(_pid: u32) -> i32 {
    eprintln!("descartes-root-helper: elevated /proc resolution is only implemented on Linux");
    EXIT_RESOLUTION_FAILURE
}

#[cfg(target_os = "linux")]
fn run_resolve_socket(target: socket::SocketTarget) -> i32 {
    use proc_linux::SocketOutcome;

    let outcome = proc_linux::resolve_socket(&target);
    // Drop right after the reads that need the capability, before ANY output -- success or
    // failure, per hardening.rs's documented sequence: resolve -> drop -> emit.
    hardening::drop_capabilities();
    let what = format!(
        "{} socket inode {} on port {}",
        target.protocol.token(),
        target.inode,
        target.port
    );
    match outcome {
        SocketOutcome::Resolved { resolved, holders } => {
            println!(
                "{}",
                json::emit_response(json::Requested::Socket(target), &resolved, Some(holders))
            );
            EXIT_SUCCESS
        }
        // Codex-hardening #6: distinguish "gave up at a bound (result uncertain)" from a
        // definitive "not found". Still nonzero + nothing on stdout, so the strict contract holds.
        SocketOutcome::Truncated => {
            eprintln!(
                "descartes-root-helper: could not resolve {what} (a scan bound was hit; result uncertain, not a definitive not-found)"
            );
            EXIT_RESOLUTION_TRUNCATED
        }
        SocketOutcome::Ambiguous => {
            eprintln!(
                "descartes-root-helper: {what} is held by multiple distinct processes (or too many holders); no single owner"
            );
            EXIT_OWNER_AMBIGUOUS
        }
        SocketOutcome::NotFound => {
            eprintln!(
                "descartes-root-helper: could not resolve {what} (gone, rebound, not listening, or changed during resolution)"
            );
            EXIT_RESOLUTION_FAILURE
        }
        // This is an internal retry signal and should be consumed by resolve_socket, but retain a
        // fail-closed mapping if a future refactor lets it escape.
        SocketOutcome::GenerationChanged => EXIT_OWNER_AMBIGUOUS,
    }
}

#[cfg(not(target_os = "linux"))]
fn run_resolve_socket(_target: socket::SocketTarget) -> i32 {
    eprintln!("descartes-root-helper: elevated /proc resolution is only implemented on Linux");
    EXIT_RESOLUTION_FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Research finding 8: every exit code means exactly one thing, so the Node side can never
    /// mislabel a confinement failure as a truncated scan (or vice versa). Host-runnable.
    #[test]
    fn every_exit_code_is_distinct_and_documented_in_usage() {
        let codes = [
            EXIT_SUCCESS,
            EXIT_RESOLUTION_FAILURE,
            EXIT_USAGE_ERROR,
            EXIT_RESOLUTION_TRUNCATED,
            hardening::EXIT_HARDENING_FAILURE,
            EXIT_OWNER_AMBIGUOUS,
        ];
        let unique: std::collections::BTreeSet<i32> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "exit codes collide: {codes:?}");
        for code in codes {
            assert!(
                argv::USAGE.contains(&format!("{code} ")),
                "USAGE must document exit code {code}"
            );
        }
    }

    #[test]
    fn bad_argv_never_reaches_a_command_variant() {
        assert_eq!(run(&[]), EXIT_USAGE_ERROR);
        assert_eq!(run(&["--nonsense".to_string()]), EXIT_USAGE_ERROR);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_probe_and_resolve_are_always_a_resolution_failure_never_a_lie() {
        assert_eq!(run_probe(), EXIT_RESOLUTION_FAILURE);
        assert_eq!(run_resolve_pid(1), EXIT_RESOLUTION_FAILURE);
        assert_eq!(
            run_resolve_socket(socket::SocketTarget {
                protocol: socket::Protocol::Tcp,
                port: 1,
                inode: 1
            }),
            EXIT_RESOLUTION_FAILURE
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_probe_succeeds_silently() {
        assert_eq!(run_probe(), EXIT_SUCCESS);
    }
}
