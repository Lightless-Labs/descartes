# Fact-store concurrent-writer locking (N4)

**Created:** 2026-08-23
**Source:** `gpt-5.6-sol` round-3 adversarial impl-review of the completeness substrate (`docs/plans/2026-08-21-fact-store-completeness-hardening.md`), with a round-4 reachability correction. Deferred out of the completeness Slices 0+1 as out-of-scope + pre-existing.
**Status:** OPEN — deferred design/impl.
**Severity:** HIGH. **Reachable via a two-daemon misconfiguration** (sol round-4 corrected an earlier, wrong "unreachable" claim): nothing enforces single-instance, so the installed service (`daemon run --foreground`, `daemon.js:678`/`:692`) plus an independently-started `descartes daemon run --foreground[ --once]` (`daemon.js:1039`) against the same state dir can both reach the shared append (`daemon.js:520`) and race. Not reachable in normal single-instance operation (one daemon serializes its own ticks; no concurrent CLI append path today), but not impossible.

## The defect (N4)

`enforceFactRetention` snapshots `facts.jsonl` once, then later replaces the live file (tmp+rename) and writes its finalized ledger **without an interprocess lock or a pre-rename source re-check**. Under two concurrent writers this loses acknowledged history and still reads `intact`:

1. P1 snapshots committed `A`, pauses before renaming its `A` tmp file.
2. P2 appends `B`, retains `A+B`, finalizes, returns success.
3. P1 resumes, renames its stale `A` over `A+B`, writes its stale finalized ledger for `A` (`continuity_ok: true`).
4. `B` is lost; the live file matches P1's digest, so the digest cross-check (N2) does **not** reveal the loss; the next read is `intact`. P1 also overwrites P2's continuity-break timestamp and regresses `last_committed_pass_id`.

This violates the cardinal never-fabricate invariant (lost history reads as complete).

## Why it is deferred, not fixed in the substrate slice

- **Pre-existing.** The original committed `fact-store.js` (`HEAD` before the completeness work) already did tmp+rename with a PID-named temp and **no locking**; the concurrent-writer race predates this work. The completeness digest/continuity machinery surfaces it, it did not introduce it.
- **Reachable only via misconfiguration.** In normal single-instance operation there is exactly one writer (`enforceFactRetention` ← `appendFactPoints` ← `daemon.js:520`), and one daemon serializes its own ticks. The race needs two daemon instances against the same state dir (installed service + a manual `descartes daemon run --foreground`), which is a misconfiguration — but it is **not guarded**, so it is possible.
- **Cross-cutting.** The correct fix is a **store-wide** concurrency primitive (or a single-instance daemon guard), orthogonal to completeness — it also protects `history-store.js`, `shadow-store.js`, `constraint-store.js`, etc., all of which use the same tmp+rename idiom.

## Reachability triggers (when this becomes must-fix)

- Two daemon instances against the same state dir (installed service + manual `daemon run --foreground` — **already possible today**, see Severity).
- A second daemon instance from an intended multi-agent/fleet local topology (`docs/plans/2026-08-11-descartes-fleet-federated-topology.md`).
- Any CLI verb that gains the ability to append/retain facts concurrently with the daemon.
- `appendFactPoints`/`enforceFactRetention` gains a second caller.

## Fix sketch (for the dedicated slice)

- Cheapest partial: a **single-instance daemon guard** (pidfile / `O_EXCL` lock) that refuses a second daemon against the same state dir — closes the reachable path above. Evaluate against the `--once` use case.
- Full fix: a per-store **interprocess lock** (`O_CREAT|O_EXCL` lockfile or `flock`) wrapping the entire read → classify → write-tmp → rename → finalize-ledger transaction, used by direct retention calls too.
- Before the rename + final ledger write, **re-verify** the source `facts.jsonl` and the ledger `generation`/`last_committed_pass_id` still match the snapshot; abort **fail-closed** (skip this pass, leave state untouched) on any change.
- **Per-operation** temp names (not PID-only).
- Deterministic **two-writer barrier** test proving an interleaved P1/P2 cannot lose P2's acknowledged append nor leave an aligned `intact` ledger.

Apply the same `degrade-not-fabricate` posture: on any doubt the read is `unknown`, never `intact`.

## Related

- Completeness substrate: `docs/plans/2026-08-21-fact-store-completeness-hardening.md` (§2a digest addendum, §6 safety analysis N4 bullet).
- Store-wide concurrency also affects `history-store.js` / `shadow-store.js` / `constraint-store.js` — scope the lock as a shared primitive.
