//! Pure, platform-independent policy for the per-process fd-table scan bound. Extracted from the
//! Linux `/proc` owner-search (`proc_linux::find_owning_pid`) specifically so the truncation
//! decision is HOST-unit-testable without `/proc` or any syscall — all of `proc_linux`/`procfs`
//! is `#[cfg(target_os = "linux")]` and unreachable on a non-Linux dev host, so a bound check left
//! inlined in those loops can never be exercised by a macOS `cargo test`. No I/O, no `libc`, no
//! `#[cfg]` gate: it compiles and runs everywhere.
//!
//! Its only production caller (`proc_linux::find_owning_pid`) is Linux-only, so on a non-Linux
//! `cargo build` this item is legitimately unused outside `#[cfg(test)]` — allowed here (mirroring
//! `json.rs`) rather than silenced case-by-case, so a genuinely dead item on Linux still warns.
#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// True when an fd enumeration that collected `entries_seen` entries under a per-process cap of
/// `cap` may have stopped short of the full `/proc/<pid>/fd` table (i.e. it hit the cap).
///
/// Codex-hardening #6 (observable truncation): when this is true AND the owner search found no
/// match, a "no owner" answer is UNCERTAIN — the socket that owns the port could be among the fds
/// the scan never enumerated — so the caller must SURFACE that (a distinct exit code / provenance
/// signal), never report a silent, indistinguishable-from-genuine negative.
///
/// `cap == 0` disables the bound (never truncated). Deliberately `>=`, not `==`: the collector
/// (`procfs::read_dir_entries_at`) stops the instant `entries.len()` reaches `max_entries`, so a
/// genuinely-truncated scan leaves `entries_seen == cap`; `>` would miss exactly that boundary.
pub fn fd_scan_truncated(entries_seen: usize, cap: usize) -> bool {
    cap != 0 && entries_seen >= cap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_the_cap_is_not_truncated() {
        assert!(!fd_scan_truncated(0, 4096));
        assert!(!fd_scan_truncated(1, 4096));
        assert!(!fd_scan_truncated(4095, 4096));
    }

    #[test]
    fn exactly_at_the_cap_is_truncated_boundary_inclusive() {
        // The collector breaks the instant it reaches the cap, so `== cap` is the truncated case.
        assert!(fd_scan_truncated(4096, 4096));
    }

    #[test]
    fn over_the_cap_is_truncated() {
        assert!(fd_scan_truncated(5000, 4096));
    }

    #[test]
    fn a_zero_cap_disables_the_bound_never_truncated() {
        assert!(!fd_scan_truncated(0, 0));
        assert!(!fd_scan_truncated(1_000_000, 0));
    }
}
