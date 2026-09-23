# Detector-Reported Recovery Coverage — Close the "empty ⇒ genuine clear" Fabrication Class at Its Root

**Date:** 2026-09-20
**Status:** PLAN — REVISED post-review (2026-09-23). See §7, which supersedes §1–§6 where they disagree. Awaiting operator confirm on §7's flagged choices before build.
**Reviewed:** 2026-09-23 (triple adversarial review: Fable code-grounded, daybreak-blue frontier-security, Astra xhigh goal-alignment) — all three NEEDS-REVISION, all three "design is right, mechanics need rewriting." Synthesis in §7.
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

## 7. Post-review revision (2026-09-23) — supersedes §1–§6 where they disagree

Three independent adversarial reviews (Fable, daybreak-blue, Astra xhigh) all returned NEEDS-REVISION with the SAME conclusion: the detector-reports-coverage design is correct, but §3's derivation and §5's sequencing are wrong/underspecified. The synthesized required changes:

### 7.1 Coverage is UNIVERSAL, not history-dependent-only (daybreak BLOCKER) — the biggest scope change
§1/§3/§4 wrongly scoped coverage to `HISTORY_DEPENDENT_ALERT_RULE_IDS`. The "empty ⇒ genuine clear" fabrication applies to EVERY detector-owned security rule, including the positive-evidence ones that are deliberately NOT history-dependent: `canary.tripped` (`canary-baseline.js:482` gate-off, `:273` <2-census/stale), `credential.access` (`credential-access-baseline.js:282` gate-off/breaker-open/timeout/store-read-fail), and the provenance families. Concrete evasion (daybreak): enable AUTHOR → trip a canary → delete `learned.json` → canary returns `[]` → `canary.tripped` is in neither the tier sets nor `HISTORY_DEPENDENT` → `applyAlertCandidates` recovers it with no observation. **Every extraCandidates producer that owns a security rule must report coverage; a rule not reported evaluated by its owning producer is frozen.** (The FIXED core rules — memory/load/disk/daemon-staleness — are exempt: they always evaluate from current metrics.)

### 7.2 `evaluatedRuleIds` derives from a per-detector EVALUATION-READINESS PREDICATE, not `coldStartPendingThisTick` (all three: HIGH/BLOCKER)
§5 step 2's "derive from EXISTING `coldStartPendingThisTick`" is insufficient — it misses each `detect*` helper's own "cannot evaluate" gates: too-few-complete-groups AND **census staleness** (freshest complete census older than `ACTIVE_FRESHNESS_MULTIPLE(3) × structural interval` ≈ 3h): `service-baseline.js:340/348` & `:786/790`, `persistence-baseline.js:232/236`, `process-lineage-baseline.js:262/266`, canary vanished `:372`. Concrete (all three): established store + intact history + watch on, but structural collection stalls > freshness window → `detect*` returns `[]`, cold-start stays false → coverage-from-cold-start would fabricate a recovery. `factHistoryTrustworthy` does NOT test census freshness (`fact-store-completeness.js:54`). **Each producer computes an explicit readiness predicate matching its exact detection prerequisites** (sufficient complete history, fresh authoritative census, confidence established, direction-specific readiness). Recommended implementation: a sibling predicate in each `compute*` reusing the same `completeGroups`/latest/freshness computation the helper uses — keeps "no detection-logic change" honest without changing the exported helpers' return shape. **Do NOT infer readiness from the final candidate array or the cold-start flag alone.**

### 7.3 Rule-level coverage clears ALL fingerprints under a rule → per-entity handling (Astra BLOCKER)
`applyAlertCandidates` applies coverage to every persisted fingerprint under a rule-id (`alert-store.js:302`). So reporting `SESSION_CHURN_RULE_ID` evaluated clears EVERY churn alert — even a session the detector deliberately skipped as ambiguous this tick (`session-baseline.js:509/533/537`, not cold-start). **Initial contract (conservative, safe): a producer reports a rule-id evaluated ONLY when EVERY entity in that family was evaluable this tick; if any entity is ambiguous/unevaluable, freeze the whole family (omit the rule-id).** This never fabricates; its cost is collateral over-freeze for one tick. **Per-fingerprint coverage is the refinement** that avoids collateral over-freeze — flagged as the next increment, and it is what `credential.access` most wants (one unreadable watched path must not freeze the others). **CHOICE C1 (operator):** ship conservative rule-level first (freeze-whole-family) with per-fingerprint as a fast-follow, or build per-fingerprint coverage from the start (bigger). *Recommendation: conservative rule-level first; per-fingerprint fast-follow, credential first.*

### 7.4 `canary.tampered` cannot be represented at rule-level (daybreak BLOCKER / Astra HIGH / Fable MEDIUM) — SPLIT the rule-ids
All tamper reasons share `CANARY_TAMPERED_RULE_ID` with distinct fingerprints (`canary-baseline.js:459`), but `canary_vanished` is history-gated (`:748`, needs `manifestReadOk` `:757` + ≥2-complete + freshness) while `manifest_unreadable`/`invalid_entries`/`baseline_store_error` are independent POSITIVE conditions (`:711/:819`). daybreak's scenario: persisted `canary_vanished` (cold-start-blocked this tick) + `manifest_unreadable` (manifest now readable = genuine clear) → report the rule evaluated ⇒ vanished falsely recovers; omit it ⇒ manifest-unreadable wrongly frozen. **No correct rule-level answer.** **CHOICE C2 (operator):** split `canary.tampered` into a history-dependent `canary.vanished` rule-id and a positive `canary.integrity` (or similar) rule-id, so each carries its own coverage — OR adopt per-fingerprint coverage (C1) which subsumes it. *Recommendation: split the rule-ids (all three reviewers call it clean/preferable pre-1.0; no compat obligation at v0.0.50).* Note (Fable/Astra): coverage never suppresses a PRESENT positive candidate (`alert-store.js:274` activates before the recovery loop) — the issue is only recovery of an ABSENT one.

### 7.5 Correlation predicate — expiry vs. evidence-loss (all three: HIGH/MEDIUM)
`incident-correlation.js` is stateless. Correct coverage: **`correlation` is evaluated-clear when `anchors.length === 0` after a SUCCESSFUL alert-history read** (anchors aged past the 24h lookback `:52/:100/:313` = the alert's designed end-of-life; requiring anchors makes it immortal). It is **unevaluated** when anchors exist but the peer stream is not evaluable — overflow (`:159-160`) or insufficient peer history (`:177`), which today collapse into the same `continue` (`:338`) as a genuine non-match — or history is untrusted (`:319`). Distinguish (Astra) a verified-empty/expired anchor universe (clear) from LOST/quarantined anchor evidence (not clear): `readAlertRecords` re-throws on whole-file corruption → `failedDetectorLabels` handles that path, so an empty-anchor result after a clean read is genuinely empty.

### 7.6 Owner-scoped coverage via a canonical ownership registry (daybreak HIGH / Fable MEDIUM)
§3 said a rule is covered if it appears in "SOME detector's" `evaluatedRuleIds` — that permits cross-source authorization (a buggy `service` producer reporting `session.count_drop` would un-freeze an unevaluated session alert). **Build one canonical registry: producer label → owning tier → allowed rule-ids** (extend the existing `DETECTOR_FAILURE_RULE_IDS` map, `daemon.js:595-607`, which already distinguishes `service` from `service-appearance`). Accept a reported rule-id ONLY from its owning producer; **fail closed** on unknown ids, duplicate ownership, malformed result shape, or non-array fields. This registry ALSO subsumes the tier-ownership sets (§7.7).

### 7.7 Q1/Q2 (redundancy) — KEEP BOTH vetoes as an INTERSECTION (daybreak + Astra; Fable dissented "retire tier")
Final recovery eligibility = **producer-reported coverage ∩ owning-tier-enabled ∩ applicable-global-trust**. Rationale (2-of-3, the two strongest security/goal reviewers): both external vetoes overlap with correct coverage but are not valueless — each is an INDEPENDENT daemon-side check that still fires if a detector's coverage-REPORTING is buggy (not just gate-off). The global history veto is NOT pure redundancy: daemon and detectors do SEPARATE reads with DIFFERENT windows (daemon fixed 31-day `daemon.js:907`; detectors accept `baselineFactWindowMs` e.g. `session-baseline.js:634`), so they can genuinely diverge either direction — a real reverse case (Astra): an intact current window retains an older loss-ts newer than a detector's anchor → global trusts, anchor-relative rejects (`fact-store-completeness.js:84`) → detector coverage protects where global cannot. **Consolidate the tier-ownership sets into the §7.6 registry; keep the global history veto; revisit retiring the tier veto LATER once coverage is proven** (retirement gate: the BLOCKER-3 regression tests stay verbatim and green). Grounding fix (all three): §2's "three disagreeing trust calls" is really **two modes** — correlation's `{nowMs}` and the daemon's no-opts call take the identical no-anchor branch (`fact-store-completeness.js:74`); anchor-relative ADDS restrictions and never overrides degraded status, so a detector is never LOOSER than the daemon on the same read (different reads can still diverge).

### 7.8 Sequencing (revised; all three) — land atomically, do NOT ship a partial state
Keep daemon-contract-first INTERNALLY (unconverted producers conservatively freeze — safe), but land the daemon adapter + shape-validation-in-`safeCandidates` + the ownership registry + the config snapshot + ALL producer conversions as ONE atomic slice; never ship the contract alone (freezes everything) and never detector-first (the `daemon.js:1042` spread expects arrays; a pre-adapter `{...}` return aborts the tick — `safeCandidates` must validate shape and treat a bad shape as bare + warn). Thread the collected coverage into BOTH `computeCoveredRuleIds` passes (`daemon.js:1118` main, `:1184` containment). Migrate each detector's tests WITH its conversion (not deferred); `daemon.test.js` gets migrated up front (its `[]`-injections would otherwise fail once bare⇒freeze lands). Immutable per-tick config snapshot loaded once and passed to daemon + detectors. **daybreak gate on the whole slice before unblocking the watch-by-default flip.**

### 7.9 Confirmed by review (no change)
Bare-array ⇒ freeze is correct (no compat obligation at v0.0.50 — a bare array simply contributes no coverage). Statistical warm-up freezing is correct WHERE evaluation is impossible — but `session.churn` must NOT inherit the count-drop `confidence_state` warm-up gate (churn is fingerprint-diff, not statistical): session count-drop uses `windowed.confidence_state` (`session-baseline.js:741`); peer spike/drop use their own windowed states + `dropRecoveryReady` (`peer-baseline.js:894`, a drop-emission gate); churn's readiness is its own zero-complete-groups/ambiguity gate (`:469/:509`).

---

## KEY CODE REFS

- Recovery authorization: `daemon.js:637-665` (`computeCoveredRuleIds`), `:595-607` (`DETECTOR_FAILURE_RULE_IDS`), `:572-581` (`safeCandidates`), `:1042-1055` (aggregation), `:1118`/`:1184` (covered-rule-ids calls), `:1135`/`:1197` (persist).
- Partition sets + history-dependent set: `daemon.js:100-142`.
- Detector cold-start booleans: `service-baseline.js:548,903`, `session-baseline.js:707`, `peer-baseline.js:790,891-901`, `persistence-baseline.js:341`, `process-lineage-baseline.js:386`; statistical warm-up `session-baseline.js:560-564`, `peer-baseline.js:619-623/659-663`; correlation `incident-correlation.js:313,319,338`; canary `canary-baseline.js:518-531,591,765,819-821`.
- Pre-existing behavior pinned: `daemon.test.js:4454-4490` ("Fix 3 control").
