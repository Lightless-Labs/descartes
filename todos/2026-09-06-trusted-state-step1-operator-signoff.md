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

1. **fact-store #3 — future-dated loss currently reads `intact`.** `fact-store-integrity.test.js:83`
   and `:109` (and `fact-store-completeness.test.js:110`) assert `intact` for future-dated
   losses/breaks; the 361–375 comment defends it as a clock artifact. Step ① makes a real loss count
   (degraded) and clamps the loss timestamp down to `now` so it ages out normally. **Reversal:** three
   named test expectations flip to `degraded`/`unknown`.
2. **canary clean-delete — a removed manifest entry currently suppresses further trips.**
   `canary-baseline.test.js:363` (`:749/:868/:995`) pin "a canary removed from the current manifest
   produces no further trips" → `[]`. Step ①'s canary-trip-as-event (bound to the manifest digest at
   observation) means an attacker-forced clean-delete no longer silently suppresses an
   already-observed trip. **Reversal:** those decommission-suppression assertions flip (cost: one
   trailing trip after a legitimate decommission — arguably desirable).
3. **`integrity_level` honest label.** Introduces `unprotected_same_uid` as an explicit, truthful
   integrity label rather than an implied-trusted state. Low-risk, but it is a public-surface change
   worth an explicit ack.

## Why it's safe to do step ① before full attestation

These are monotonic-continuity + honest-labeling changes, not a claim of tamper-proofing. They
raise the floor (a real loss/trip is no longer silently swallowed by a clock artifact or a manifest
delete) while the label stays honest about what is NOT yet protected. Full state-file attestation /
off-host signing remains the later slice. See the trusted-state threat model
(`docs/design/state-integrity-threat-model.md`) and [[descartes-autonomy-doctrine-no-uac-gate]].

Related deferred: [[2026-09-06-llm-budget-trusted-time]] (the LLM-budget clock class shares the
"no trusted time source yet" root).
