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

/// The point-in-time identity of one PID-directory entry. A numeric PID is reusable, so a
/// subsequent enumeration must treat either a new PID or a changed `(tgid, start_time)` tuple as
/// a new process that has to be included in the holder proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub tgid: u32,
    pub start_time: u64,
}

/// Returns whether `current` contains a PID that was not in `previous`, or a reused PID whose
/// process identity changed. Removed PIDs do not require another pass: they cannot introduce a
/// holder into the current point-in-time result.
pub fn snapshot_has_new_or_reused_pid(
    previous: &[ProcessSnapshot],
    current: &[ProcessSnapshot],
) -> bool {
    current.iter().any(|candidate| {
        previous
            .iter()
            .find(|observed| observed.pid == candidate.pid)
            .is_none_or(|observed| {
                observed.tgid != candidate.tgid || observed.start_time != candidate.start_time
            })
    })
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

    #[test]
    fn a_new_fork_is_a_new_snapshot_even_when_the_original_pid_is_still_present() {
        let original = [ProcessSnapshot {
            pid: 100,
            tgid: 100,
            start_time: 10,
        }];
        let after_fork = [
            original[0],
            ProcessSnapshot {
                pid: 200,
                tgid: 200,
                start_time: 20,
            },
        ];
        assert!(snapshot_has_new_or_reused_pid(&original, &after_fork));
    }

    #[test]
    fn an_unchanged_snapshot_is_stable() {
        let snapshot = [ProcessSnapshot {
            pid: 100,
            tgid: 100,
            start_time: 10,
        }];
        assert!(!snapshot_has_new_or_reused_pid(&snapshot, &snapshot));
    }

    #[test]
    fn a_reused_pid_is_a_new_snapshot() {
        let before = [ProcessSnapshot {
            pid: 100,
            tgid: 100,
            start_time: 10,
        }];
        let after_reuse = [ProcessSnapshot {
            pid: 100,
            tgid: 100,
            start_time: 11,
        }];
        assert!(snapshot_has_new_or_reused_pid(&before, &after_reuse));
    }

    #[test]
    fn a_churning_snapshot_never_converges_within_the_bound() {
        let mut previous = vec![ProcessSnapshot {
            pid: 100,
            tgid: 100,
            start_time: 10,
        }];
        let mut converged = false;
        for pid in [200, 300, 400] {
            let mut current = previous.clone();
            current.push(ProcessSnapshot {
                pid,
                tgid: pid,
                start_time: u64::from(pid),
            });
            if !snapshot_has_new_or_reused_pid(&previous, &current) {
                converged = true;
                break;
            }
            previous = current;
        }
        assert!(
            !converged,
            "continuous fork churn must remain ambiguous at the bound"
        );
    }
}
