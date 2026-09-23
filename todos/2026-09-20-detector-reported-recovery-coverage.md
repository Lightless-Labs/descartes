# Detector-reported recovery coverage (prerequisite for the watch-by-default flip)

**Created:** 2026-09-20
**Status:** PLAN REVISED post-triple-review (2026-09-23). Design confirmed right by all three (Fable/daybreak/Astra); mechanics rewritten in plan §7. Awaiting operator confirm on two flagged choices (C1 per-fingerprint timing, C2 canary rule split), then build.
**Plan:** `docs/plans/2026-09-20-detector-reported-recovery-coverage.md` (§7 supersedes §1–§6)

## Review outcome (2026-09-23) — scope grew
All three reviewers: NEEDS-REVISION, "design right, mechanics need rewriting." Synthesized into plan §7:
- **Universal coverage** (daybreak BLOCKER): ALL detector-owned security rules, not just history-dependent — `canary.tripped`/`credential.access`/provenance also silently []-recover.
- **Per-detector readiness predicate** (all 3): cold-start + completeness-count + census-freshness + confidence, NOT cold-start alone.
- **Canary rule-split** (C2) and **per-fingerprint coverage** (C1, credential-first) — rule-level clears all fingerprints.
- **Correlation predicate** fix (expiry=clear vs evidence-loss=not-clear vs overflow/warm-up=unevaluated).
- **Ownership registry** (owner-scoped coverage, fail-closed) — subsumes the tier sets.
- **Q1/Q2 redundancy: KEEP BOTH as intersection** (daybreak+Astra 2-of-3; Fable dissented retire-tier) — coverage ∩ tier-enabled ∩ global-trust; revisit retiring tier later.
- Land atomically (daemon-first internally); both persistence passes; config snapshot; churn≠statistical-warmup.
**Blocks:** the watch-by-default default-on flip (`docs/plans/2026-09-10-watch-by-default-slice-1.md`; `todos/2026-09-14-watch-by-default-implementation.md`) — operator chose fix-before-flip (2026-09-20).

## Why
daybreak-blue R3 found a pre-existing never-fabricate gap the default-on flip widens to every install: a detector returning `[]` because its OWN baseline store was lost/corrupt (per-detector cold-start) is indistinguishable, from the daemon's outside view, from a genuine clear → active alert fabricated-recovers. Also an attacker-evasion (delete a detector's store to clear its alert). The daemon's three recovery-exclusion sources (global historyTrust, failedDetectorLabels, tier-flags) never see a detector's own `coldStartPendingThisTick`.

## Fix (see plan §3)
Each history-dependent detector returns `{ candidates, evaluatedRuleIds }`; the daemon excludes from recovery any history-dependent rule-id NOT reported as evaluated this tick. Fail-safe: a bare array ⇒ no history-dependent coverage ⇒ freeze. Plus one immutable per-tick config snapshot (daybreak R3's mid-tick-flip note).

## Next action
Operator to weigh in on the plan's §6 open questions (esp. #1 keep-or-retire the redundant tier-ownership patches, #5 test-churn semantics) and/or greenlight the build. Then: daemon contract + fail-safe (TDD, daybreak-gated) → per-detector coverage (one file each) → config snapshot → test migration → daybreak gate → unblock the flip's steps 4–8 → operator-confirmed push.

## Verify-don't-worship note
This is the 4th finding in the recovery-`[]`-ambiguity class; the detector-reported-coverage contract is the root-cause fix that closes it (an empty list is only a "clear" if the detector says it evaluated). daybreak confirmed the prior three fixes (OR-gate, both-off, tier-ownership) are sound.
