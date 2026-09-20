# Detector-reported recovery coverage (prerequisite for the watch-by-default flip)

**Created:** 2026-09-20
**Status:** PLAN drafted; awaiting operator direction + adversarial review before build.
**Plan:** `docs/plans/2026-09-20-detector-reported-recovery-coverage.md`
**Blocks:** the watch-by-default default-on flip (`docs/plans/2026-09-10-watch-by-default-slice-1.md`; `todos/2026-09-14-watch-by-default-implementation.md`) — operator chose fix-before-flip (2026-09-20).

## Why
daybreak-blue R3 found a pre-existing never-fabricate gap the default-on flip widens to every install: a detector returning `[]` because its OWN baseline store was lost/corrupt (per-detector cold-start) is indistinguishable, from the daemon's outside view, from a genuine clear → active alert fabricated-recovers. Also an attacker-evasion (delete a detector's store to clear its alert). The daemon's three recovery-exclusion sources (global historyTrust, failedDetectorLabels, tier-flags) never see a detector's own `coldStartPendingThisTick`.

## Fix (see plan §3)
Each history-dependent detector returns `{ candidates, evaluatedRuleIds }`; the daemon excludes from recovery any history-dependent rule-id NOT reported as evaluated this tick. Fail-safe: a bare array ⇒ no history-dependent coverage ⇒ freeze. Plus one immutable per-tick config snapshot (daybreak R3's mid-tick-flip note).

## Next action
Operator to weigh in on the plan's §6 open questions (esp. #1 keep-or-retire the redundant tier-ownership patches, #5 test-churn semantics) and/or greenlight the build. Then: daemon contract + fail-safe (TDD, daybreak-gated) → per-detector coverage (one file each) → config snapshot → test migration → daybreak gate → unblock the flip's steps 4–8 → operator-confirmed push.

## Verify-don't-worship note
This is the 4th finding in the recovery-`[]`-ambiguity class; the detector-reported-coverage contract is the root-cause fix that closes it (an empty list is only a "clear" if the detector says it evaluated). daybreak confirmed the prior three fixes (OR-gate, both-off, tier-ownership) are sound.
