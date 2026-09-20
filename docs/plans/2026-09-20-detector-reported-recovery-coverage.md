# Detector-Reported Recovery Coverage — Close the "empty ⇒ genuine clear" Fabrication Class at Its Root

**Date:** 2026-09-20
**Status:** PLAN (drafted; awaiting operator direction + adversarial review before build)
**Prerequisite for:** the watch-by-default default-on flip (`docs/plans/2026-09-10-watch-by-default-slice-1.md`), which is HELD until this lands (operator decision 2026-09-20: fix-before-flip).
**Origin:** daybreak-blue re-gate round 3 of the watch-by-default gate split found a pre-existing fabrication gap the default-on flip widens to every install.

---

## 1. The problem (root cause)

Descartes' #1 invariant is **never fabricate a security signal** — including never marking a persisted alert `recovered` unless a detector actually evaluated evidence and found the condition cleared.

Today the daemon INFERS recovery-eligibility from the OUTSIDE. `computeCoveredRuleIds` (`daemon.js:637-665`) authorizes recovery for a family unless one of three external signals excludes it: global `historyTrust.trust === false`, membership in `failedDetectorLabels` (a detector *threw*), or its owning tier being disabled (`WATCH_OWNED`/`AUTHOR_OWNED_HISTORY_DEPENDENT_RULE_IDS`). **None of these three ever sees a detector's own `coldStartPendingThisTick`.** So when a detector returns a bare `[]` for a reason that is neither a throw, nor global-history-distrust, nor tier-off — e.g. its OWN per-detector baseline store was deleted/corrupted, or it is in statistical warm-up, or this tick's census was partial — the daemon reads that `[]` as a genuine clear and fabricated-recovers the family's active alert.

This is the same class the watch-by-default gate split already closed three facets of (Fable's OR-gate, daybreak R1's both-off, daybreak R2's tier-ownership). Those were all *external-inference* patches. This plan closes the class at its **root**: make the detector — the only component that knows why it returned `[]` — the authority on its own recovery-eligibility.

**Verified pre-existing** (not introduced by the gate split): the "Fix 3 control" test (`daemon.test.js:4454-4490`) explicitly documents "`[]` + trustworthy history ⇒ recover" as "unchanged, pre-existing behavior." But the default-on flip turns the detectors on for every install, widening this from opt-in-only to everyone — and for a defensive tool it is a plausible **attacker-evasion**: delete a detector's baseline store to make its alert clear itself (the per-detector stores lack the fact store's integrity ledger).

---

## 2. Grounding (verified by direct read, 2026-09-20)

**The internal signal already exists.** Each of the six stateful detectors computes a single boolean `coldStartPendingThisTick` meaning "I could not establish a trustworthy baseline this tick": `service-baseline.js:548` (disappearance) and `:903` (appearance), `session-baseline.js:707`, `peer-baseline.js:790`, `persistence-baseline.js:341`, `process-lineage-baseline.js:386`. It is OR'd from: `factsCorruptThisTick`, `storeLossThisTick`, `persistedAnchorMissingOrFuture`, `!historyTrust.trust` (anchor-relative), `completenessLossAfterAnchor`, `lastFoldedWasFuture`. When true, the detector already returns `[]`. The signal is simply never surfaced past the bare-array return.

**Store-loss splits into two daemon-visibilities.** In every `readJsonFile` (e.g. `service-baseline.js:166-179`), a non-`ENOENT` read error is *re-thrown* → `safeCandidates` catches it → the label lands in `failedDetectorLabels` → daemon-visible → excluded. But *missing* / *corrupt-JSON* / *invalid-schema* store states are absorbed internally into `storeLossThisTick` → `cold_start_pending` → bare `[]` → **daemon-invisible**. (Canary is the outlier: it wraps its own store load in try/catch at `canary-baseline.js:518-531`, absorbing even a throw, and separately emits a positive `canary.tampered(baseline_store_error)` — the one place a store failure becomes a signal instead of silence.)

**A second, independent cold-start axis** lives in the statistical detectors: `confidence_state !== "established"` (Welford warm-up, ~30 complete tick-groups) inside `buildCountDropCandidate`/`buildCountSpikeCandidate` (`session-baseline.js:560-564`, `peer-baseline.js:619-623/659-663`) returns `undefined` identically for "not yet established" (warm-up) and "established, no deviation" (genuine clear) — indistinguishable at that return point, and NOT captured by `coldStartPendingThisTick`. `peer.count_drop` additionally has its own `dropRecoveryReady` gate (`peer-baseline.js:891-901`).

**Census-partial (e)** is filtered away *inside* each `detect*` (`.filter(g => g.censusState === "complete")` then a `< N` early-`[]`) and is invisible at the `compute*` return; the only trace is the fold-time-only `skipped_partial_tick_count` counter.

**Three disagreeing `factHistoryTrustworthy` calls:** the six stateful detectors call it anchor-relative (`{ anchorTs: cold_start_since_ts, nowMs }`); `incident-correlation.js:319` calls it `{ nowMs }` only (no anchor, no persisted lockout — it is stateless); `daemon.js:914` calls it with neither. These can disagree for the same tick. The detector's own anchor-relative notion is the authoritative one for that detector's recovery-eligibility.

**canary asymmetry:** `canary.tripped` (`CANARY_TRIPPED_RULE_ID`) is positive evidence, deliberately NOT in `HISTORY_DEPENDENT_ALERT_RULE_IDS` and never `coldStartPendingThisTick`-gated. `canary.tampered` (`CANARY_TAMPERED_RULE_ID`) IS history-dependent (wholesale), though only its `canary_vanished` reason is truly history-gated; its `manifest_unreadable`/`invalid_entries`/`baseline_store_error` reasons are non-gated positive I/O-failure signals.

**The aggregation seam** (`daemon.js:1042-1055`): twelve producers are called as `...await safeCandidates(label, () => compute(...), [], failedDetectorLabels)` and flat-spread into `mainExtraCandidates`; per-source metadata is discarded on concat. `safeCandidates` (`:572-581`) retains only the candidate array (success) or the `label` (throw → `failedDetectorLabels`). `coveredRuleIds` is computed at `:1118` (main pass) and `:1184` (containment pass), threaded to `evaluateAndPersistAlerts` at `:1135`/`:1197`. `DETECTOR_FAILURE_RULE_IDS` (`:595-607`) maps a failed label → its rule-ids (note the `service` label omits `SERVICE_APPEARED_RULE_ID`, which is the separate `service-appearance` label).

---

## 3. Design — detectors report what they evaluated

**Contract change.** Each history-dependent detector's `compute*Candidates` returns `{ candidates, evaluatedRuleIds }` instead of a bare array, where `evaluatedRuleIds` is the subset of the detector's owned rule-ids it GENUINELY evaluated this tick — i.e. established baseline, trustworthy (anchor-relative) history, complete census, not cold-start, not warm-up, not store-lost, not gate-off. A rule-id it owns but did NOT evaluate is omitted → the daemon excludes it from recovery this tick.

This is the single authoritative signal. It **subsumes** the external inferences:
- gate/kill-switch off → the detector reports `evaluatedRuleIds: []` (it short-circuits before evaluating) → its families excluded. (Makes the tier-ownership sets partly redundant — see §6.)
- `coldStartPendingThisTick` true → `evaluatedRuleIds: []` → excluded (closes the daybreak-R3 gap).
- per-detector store loss (missing/corrupt/invalid-schema) → folds into `coldStartPendingThisTick` already → excluded.
- statistical warm-up (`confidence_state !== established`) → that rule-id omitted from `evaluatedRuleIds` (per-rule-id granularity for session/peer).
- census-partial → the detector reports the affected rule-ids as un-evaluated.
- genuine clear → the detector DID evaluate → rule-id IS in `evaluatedRuleIds` → eligible → recovers correctly (preserves legitimate recovery, the "Fix 3 control" intent, now stated by the detector rather than inferred).

**Daemon side.** `safeCandidates` unpacks `{candidates, evaluatedRuleIds}`, spreads `candidates` into `mainExtraCandidates` as today, and collects `evaluatedRuleIds` per source. `computeCoveredRuleIds` gains a fourth exclusion source: for every history-dependent rule-id, exclude it from recovery unless it appears in some detector's `evaluatedRuleIds` this tick. A throw still excludes via `failedDetectorLabels` (a thrown detector reports nothing).

**Fail-safe default (the load-bearing decision).** A producer that returns a **bare array** (old shape — e.g. a positive-evidence detector, or a test injection that hasn't adopted the shape) is treated as **evaluated nothing history-dependent** → its history-dependent families are EXCLUDED from recovery (frozen), never recovered. Never-fabricate wins over recover-eagerly. Consequence: every test that injects a history-dependent detector as `async () => []` and expects its family to RECOVER (e.g. "Fix 3 control") must switch to `async () => ({ candidates: [], evaluatedRuleIds: [<rule-id>] })` to signal "I evaluated and it's a genuine clear." This test churn is semantically meaningful, not mechanical — it forces every genuine-clear expectation to be explicit.

**Config snapshot (daybreak R3's second note).** Resolve the mid-tick enablement-flip gap: load `watch.json` / `learned.json` ONCE per tick into an immutable snapshot and pass that snapshot to both the daemon ownership logic AND the detectors, so the daemon's view of "which tier is on" and the detector's own gate can never disagree within a tick.

---

## 4. Scope

**In:** the seven history-dependent producers (`service-baseline.js` ×2, `session-baseline.js`, `peer-baseline.js`, `persistence-baseline.js`, `process-lineage-baseline.js`, `incident-correlation.js`, and `canary-baseline.js` for `canary.tampered`), the daemon aggregation (`safeCandidates`, `mainExtraCandidates`, `computeCoveredRuleIds`), the per-tick config snapshot, and every test that injects these detectors.

**Out:** positive-evidence detectors that are deliberately never history-gated (`canary.tripped`, `credential.access`) keep bare-array returns and are never subject to coverage-based recovery restriction (they are not in `HISTORY_DEPENDENT_ALERT_RULE_IDS`). Non-history-dependent families (fixed resource rules, provenance-identity `constraint.violation.*`, containment) unchanged. No detector-detection-logic change — only the surfacing of an already-computed status.

---

## 5. Sequencing (TDD)

0. **Confirm the grounding table** in §2 against current HEAD before touching code (the Explore map may drift).
1. **Daemon contract + fail-safe default first (TDD).** Teach `safeCandidates`/`mainExtraCandidates`/`computeCoveredRuleIds` to accept `{candidates, evaluatedRuleIds}` AND a bare array (bare ⇒ no history-dependent coverage ⇒ exclude). Pin: a bare-array producer freezes its history-dependent families; a `{candidates:[], evaluatedRuleIds:[X]}` producer lets X recover. This is the security core → its own daybreak gate.
2. **Per-detector coverage reporting (TDD, one file/PR each).** Each detector returns `evaluatedRuleIds` derived from its EXISTING `coldStartPendingThisTick` (+ the per-rule-id `confidence_state` for session/peer, + `dropRecoveryReady` for peer.count_drop). No detection-logic change. Red→green: per-detector store-loss with intact fact-history + active alert ⇒ frozen (was: recovered).
3. **Per-tick config snapshot (TDD).** One load per tick, passed to daemon + detectors; pin a mid-tick flip cannot desync ownership from the gate.
4. **Migrate the test suite** to the new shape; every genuine-clear-recovers expectation becomes an explicit `evaluatedRuleIds`. Audit every `"recovered"` assertion and every `async () => []` detector injection.
5. **daybreak-blue gate** on the whole slice (this is security-critical never-fabricate logic).
6. **Then** unblock the watch-by-default flip: resume its steps 4–8 and the operator-confirmed push.

---

## 6. Open questions (for the operator / review)

1. **Keep or retire the tier-ownership + historyUntrusted external patches?** Detector-reported coverage subsumes both. Keeping them is harmless defense-in-depth (belt-and-suspenders) but adds two overlapping mechanisms; retiring them is cleaner but re-touches daybreak-confirmed code. Recommendation: KEEP as defense-in-depth, documented as redundant, to avoid re-opening confirmed-sound code — revisit later.
2. **`incident-correlation` is stateless** (no persisted lockout, no `coldStartPendingThisTick`). Its `evaluatedRuleIds` derives from its inline anchor/trust/qualifying-observation checks (`incident-correlation.js:313,319,338`). Confirm the correct predicate: it evaluated `correlation` iff it had anchors AND trustworthy history AND could inspect the peer stream.
3. **canary.tampered's mixed reasons.** `canary_vanished` is history-gated; the I/O-failure reasons are positive signals. `evaluatedRuleIds` for `canary.tampered` should reflect that a `canary_vanished` absence is only a "clear" when the detector genuinely evaluated a complete canary census — while the positive I/O-failure reasons are never subject to recovery restriction. Needs care so a store-error positive signal isn't itself frozen wrongly.
4. **Statistical warm-up as "not evaluated".** Freezing `session.count_drop`/`peer.count_*` recovery during Welford warm-up is the conservative choice, but it means a genuinely-cleared statistical alert won't recover until the baseline re-establishes. Acceptable per never-fabricate, but flag it.
5. **Test-churn magnitude.** Every history-dependent detector injection across the suite must adopt the new shape. Confirm the fail-safe default (bare ⇒ freeze) is the intended semantics before the migration, since it flips the meaning of every un-migrated injection.

---

## KEY CODE REFS

- Recovery authorization: `daemon.js:637-665` (`computeCoveredRuleIds`), `:595-607` (`DETECTOR_FAILURE_RULE_IDS`), `:572-581` (`safeCandidates`), `:1042-1055` (aggregation), `:1118`/`:1184` (covered-rule-ids calls), `:1135`/`:1197` (persist).
- Partition sets + history-dependent set: `daemon.js:100-142`.
- Detector cold-start booleans: `service-baseline.js:548,903`, `session-baseline.js:707`, `peer-baseline.js:790,891-901`, `persistence-baseline.js:341`, `process-lineage-baseline.js:386`; statistical warm-up `session-baseline.js:560-564`, `peer-baseline.js:619-623/659-663`; correlation `incident-correlation.js:313,319,338`; canary `canary-baseline.js:518-531,591,765,819-821`.
- Pre-existing behavior pinned: `daemon.test.js:4454-4490` ("Fix 3 control").
