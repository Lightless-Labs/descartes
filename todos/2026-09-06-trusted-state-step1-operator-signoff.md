# Operator sign-off: trusted-state step ① (the "updated (d)")

**Created:** 2026-09-06
**Status:** BLOCKED on operator decision — reverses deliberate, test-pinned behavior
**Owner:** operator (design call), then agent implements once signed off
**Plan:** `docs/plans/2026-09-06-trusted-state-step-1.md` (the scoped implementation plan)

## What needs the operator

daybreak's "trusted-state step ①" (canary-trip-as-append-only-event bound to the manifest digest at
observation; monotonic sequence + boot-id continuity replacing the wall clock; baselines as
disposable caches; the autonomous-safe `integrity_level: unprotected_same_uid` honest label) is a
sound first step toward closing the trusted-same-user-state boundary **without** waiting for full
off-host attestation. But parts of it **reverse behavior that current tests deliberately pin**, so it
cannot ship autonomously — the operator must sign off on each reversal.

## The test-pinned reversals (each needs an explicit yes/no)

**Authoritative sign-off surface: `docs/plans/2026-09-06-trusted-state-step-1.md` §8.1** — the plan
re-verified every ref against the current working tree (the sweep's earlier `:83/:109`-era numbers
had shifted after the re-gate commits). The scope was deliberately **minimized to exactly THREE
assertions**; the naive form of the fix would have flipped six more (a garbage-id trip fabrication +
five detector rollback-recovery tests) and introduced a fail-STUCK denial-of-detection — all
**avoided** by the corrected design (plan §8.2), which is why the sign-off ask is this small.

1. **R1 — fact-store #3, future-dated loss (`fact-store-integrity.test.js:149`, test `:131`).**
   `buildCompleteness` currently returns `status:"intact"` for a future `last_corrupt_ts`; the fix
   makes it `"degraded"`. **Reversal:** `intact → degraded` (+ rename the pinned title).
2. **R2 — fact-store #3, future continuity break (`fact-store-integrity.test.js:180`, test `:157`).**
   Same file, a future break with live `ok` currently reads `intact`; the fix makes it `"degraded"`.
   **Reversal:** `intact → degraded` (+ rename).
3. **R4 — canary clean-delete (`canary-baseline.test.js:396`, test `:363`).** A clean-deleted
   (`{canaries:[]}`, `read_ok:true`) established `credential` whose facts show a real
   `atime_advanced` trip is currently suppressed (`deepEqual([])`); the fix fires one genuine
   `canary.tripped`. **Reversal:** `[] → one trip` (cost: one trailing trip after a legitimate
   decommission — arguably desirable; + rename).

**Not a test reversal, but a public-surface ack (plan §8.4):** Component D introduces the honest
`integrity_level: unprotected_same_uid` label — no assertion flips, but it is a truthful
public-surface change worth an explicit yes. **Scope guard:** the fix to fact-store #3 is confined
to `buildCompleteness`; it deliberately does **not** touch `hasLossEventAfter` /
`factHistoryTrustworthy` (doing so is the withdrawn R3 — it would break the five rollback-recovery
tests and create the DoS). All manifest-digest work is deferred to the plan's Phase 3.

## Why it's safe to do step ① before full attestation

These are monotonic-continuity + honest-labeling changes, not a claim of tamper-proofing. They
raise the floor (a real loss/trip is no longer silently swallowed by a clock artifact or a manifest
delete) while the label stays honest about what is NOT yet protected. Full state-file attestation /
off-host signing remains the later slice. See the trusted-state threat model
(`docs/design/state-integrity-threat-model.md`) and [[descartes-autonomy-doctrine-no-uac-gate]].

Related deferred: [[2026-09-06-llm-budget-trusted-time]] (the LLM-budget clock class shares the
"no trusted time source yet" root).
