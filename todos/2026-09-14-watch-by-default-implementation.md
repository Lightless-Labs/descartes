# Implement watch-by-default slice 1

**Created:** 2026-09-14
**Status:** ready to build — plan is decision-complete
**Plan:** `docs/plans/2026-09-10-watch-by-default-slice-1.md` (the authoritative spec)
**Supersedes direction:** the protection-contract plans (`docs/plans/2026-09-09-protection-contract-slice-1*.md`, marked SUPERSEDED)
**Founds:** `todos/2026-09-09-path-b-self-learning-authorship-spike.md` (the deeper authorship spike rides on this)

## What

Turn Descartes into a default, no-config, discover→learn→flag-new/removed monitor. Split the coarse
`learned.json` kill switch so the deterministic change-detection runs **by default**, keep
constraint-authoring opt-in, make the cold-start learning phase visible/inspectable, and flag
new/removed honestly and calmly through the existing alert pipeline.

## Decisions locked (operator, 2026-09-14) — do NOT re-litigate

- **Default-on**, no consent ceremony / migration (single-user deployment).
- **Statistical detectors join the default-on WATCH tier** (`peer.count_spike/drop`,
  `session.churn/count_drop`) alongside the four novelty detectors (`service.appeared/disappeared`,
  `scheduled_job.appeared`, `process.lineage.novel_edge`). A **calibration pass is the first
  fast-follow** (statistical detectors are noisier than discrete novelty).
- **Naming: `baseline`.** `descartes baseline status` (per-domain phase: still-learning N/6 · watching
  · cannot-establish) + `descartes baseline inspect [--domain <n>]` (established set / learned-normal,
  recomputed live — no cache). `descartes alerts watch` (the live alert-tail) is UNCHANGED; no
  bare-`watch` command is added.

## Build order (TDD — see plan §8)

- **Step 0 (do FIRST):** survey the test-injection blast radius — ~21 `loadLearnedConfig` DI sites in
  `daemon.test.js` plus the baseline/store test files. Decide up front whether test helpers default
  `loadWatchConfig` to `{enabled:false}` (least churn) or every test gains a second injection.
- **⚠️ Load-bearing hazard (plan §3.2):** a naive gate-split REGRESSES last week's Fix-3
  (no-fabricated-recovery). The fact-history trust read (`daemon.js:811-845`, gated on the *author*
  flag today) MUST move to the WATCH flag, or the four/six default-on families lose recovery-restriction
  for the watch-on/author-off default population. There must be a red/green test proving this.
- Then: `watch.json` store (ENOENT→enabled) → daemon seam split (+ the Fix-3 move + nested author gate
  on shadow eval) → per-detector gate move → first-cold-start reason → `baseline status/inspect` CLI →
  correction-hook confirmation → migration tests → README/HANDOFF.

## Still open (implementation-time, not blocking)

- **#3 correction hook** — do "that's mine" (`alerts ack`) inside this slice (needs extending the
  cleartext-diagnostics decision to `service.appeared` etc., since they're hash-only today — its own
  scoped operator call) or as an immediate fast-follow? Operator to pick when we get there.
- **#4** — a lightweight idle-resource sanity check on the now-default-on structural collectors.
- **#6** — rewrite the README "off by default" language (now literally false): "structural watching is
  on by default; authoring/promotion stays opt-in."

## Process

Use the multi-model / ultracode workflow per `docs/solutions/2026-09-14-multi-model-review-and-planning-playbook.md`
— delegate implementation to Sonnet (TDD → 3-lens adversarial verify), gate the full suite yourself,
then a **daybreak-blue re-gate before shipping** (this is security-critical: a monitor that flips
default-on must never fabricate).
