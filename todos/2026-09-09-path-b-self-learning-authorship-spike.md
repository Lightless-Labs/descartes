# Path B: finish the self-learning authorship spike to a real go/no-go

**Created:** 2026-09-09
**Status:** queued — **next-highest priority after Path A** (protection-contract slice, `docs/plans/2026-09-09-protection-contract-slice-1.md`)
**Area:** the learned subsystem (Slice-1 behavioral model) — `model-ir.js`, `model-ladder.js`, `constraint-miner.js`, `calibration.js`, promotion/tuning authority
**Relates to:** the standing self-learning initiative ([[descartes-self-learning-monitoring-initiative]]), `docs/plans/2026-09-03-slice-1-behavioral-model-spike.md`, `todos/2026-07-09-self-learning-stratified-monitoring.md`, `docs/design/autonomy-doctrine.md` ([[descartes-autonomy-doctrine-no-uac-gate]]), and the 2026-09-05 critique §5/§7.

## What

Take the thin authorship spike from "pure/offline foundation" to a real **go/no-go**: the agent drafts
its own detection models, shadow-tests them (no notifications, no actions), and earns promotion ONLY
if it beats a simple deterministic baseline on real evidence — with daemon integration and an actual
decision at the end. This is the autonomy doctrine's direction (earned trust, human on-the-loop,
autonomy scaling with reversibility × corroboration) — but held to an honest evaluation bar.

## Why it comes AFTER Path A (the dependency that sets the priority)

Path B's whole premise is *"do authored models improve OUTCOMES?"* — and that is **not measurable
without Path A's defined protected job + outcome records** to measure against. A synthetic step-change
only proves a statistic detects a step-change, not that the change was a real failure worth notifying.
So Path A gives B its yardstick. Do A first; then B is evaluable rather than self-referential.

## Evaluation discipline (from critique §5/§7 — non-negotiable for the go/no-go)

- **Compare against a simple deterministic baseline on the SAME corpus.** An authored model must beat a
  plain rule to justify itself — novelty is not a success criterion; economical competence is.
- **Held-out / unseen cases**, not just the fixtures it was tuned on (repeatedly adapting to known
  tests improves test-fit, not real performance). Include unseen normal workload changes, real/curated
  incidents, missing observations, and owner corrections.
- **Measure, don't assert:** false notifications per machine-day, detection delay, missed cases in
  labeled replay, coverage, and resource/model cost. Separate operational-fit results from
  program-conformance (a passing test count ≠ an operating guarantee).
- **Current calibration terms stay labeled PROXIES.** Fast recovery and model-suppression are NOT
  ground-truth false positives; notification delivery is not diagnosis quality. Add outcome + owner-
  correction records (Path A) before these signals support any broader authority.
- Keep the separation of trusted test fixtures from model-authored records; require BOTH positive and
  negative fixture performance (already a good decision in the spike).

## Acceptance (the go/no-go)

A written go/no-go verdict backed by: daemon-integrated shadow-mode authorship; a baseline-comparator
result on held-out labeled cases; the measured metrics above; and an explicit decision on whether to
**automate bounded promotion under an operator policy** (per the doctrine) — only if the evidence
justifies it. "Skip it / not yet" is a valid, documented outcome.

## Out of scope (stays deferred)

Host actions/execution (attestation-gated, separate); federation of shareable model packages; any
promotion that suppresses existing protection or broadens authority (its own reviewed policy tests).
