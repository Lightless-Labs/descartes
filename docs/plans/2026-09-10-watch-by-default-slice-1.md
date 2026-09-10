# Watch-by-Default Slice 1 — Learn the Machine, Then Flag New/Removed, Honestly

**Date:** 2026-09-10
**Status:** PLAN

**Goal (one line):** split Descartes' single `learnedConfig.enabled` kill switch into a default-on **WATCH** layer (structural inventory collection + the deterministic new/removed change-detectors) and a still-default-off **AUTHOR** layer (constraint mining/promotion/tuning), add a visible per-domain "still learning vs. watching" surface, and route the four watch-tier novelty detectors' output through the existing alert pipeline with honest labels — turning Descartes into a default, no-config, discover-and-flag monitor.

**Supersedes:** `docs/plans/2026-09-09-protection-contract-slice-1.md` (the "protection contract" direction — owner-declared subjects/thresholds/coverage view). Per the operator's re-scoping decision (2026-09-10), that direction is rejected as "OTel + local PagerDuty done worse" and is **not** revived by anything here. `docs/HANDOFF.md`'s 2026-09-09 entries describing Path A as chosen are stale as of this plan; `docs/HANDOFF.md` needs a new entry recording this re-scope (see §8, step 0).

**Foundation for:** `todos/2026-09-09-path-b-self-learning-authorship-spike.md` ("Path B," the self-learning authorship spike). That spike's whole premise — "do authored models beat a deterministic baseline?" — needs a population of hosts that are actually *watching* by default to generate the outcome/correction records it measures against. This slice is the near-term prerequisite, not a substitute for it.

---

## 1. Goal and scope

Descartes should, with **zero configuration**, discover what is running on a machine, spend an honest observation period learning what "normal" looks like, and then say two things calmly when the picture changes: *this wasn't here before* (unrecognized) and *this used to be here and isn't now* (gone). No owner-declared subjects, no thresholds, no notification config screen — the product's point per the owner.

Concretely, three moves, in this order:

1. **Split the gate** so structural inventory collection and the four existing deterministic "appeared/disappeared" detectors run by default, while constraint mining/promotion/tuning stays opt-in.
2. **Make the pre-existing cold-start learning phase visible and inspectable**, per detection domain, instead of a silent internal lockout.
3. **Route the (already honestly worded) novelty alerts through the existing alert pipeline** and name exactly where a minimal "that's mine / not mine" correction hook attaches.

### What this is NOT

- **Not** owner-declared subjects, thresholds, or per-item notification config (the rejected "protection contract" direction, `docs/plans/2026-09-09-protection-contract-slice-1.md`).
- **Not** making the AUTHOR layer (constraint mining/promotion/tuning, `learned mine/review/approve/tuning`) default-on. It stays exactly as opt-in as it is today.
- **Not** the full correction-teaching UI. This slice names the attachment point only (§6); building the UI is a follow-on.
- **Not** retuning the statistical baselines (peer count spike/drop, session churn/drop) or resolving their watch-vs-author tier — that is an explicit open question (§11), not a silent decision.
- **Not** a change to notification delivery, alert severity model, dedup, or cooldown. This slice reuses `alert-store.js` unchanged.
- **Not** new detectors. Every alert this slice can produce by default already exists in the codebase and already fires under `learned.json {enabled:true}` today; this slice only changes *when* four of them are reachable and *what the owner can see* about the learning state behind them.

---

## 2. Grounding: what already exists (verified by direct read)

**The single kill switch, today.** `configDir/learned.json`'s `{enabled}` field (`constraint-store.js:224-230` `normalizeLearnedConfig`, `:237-255` `loadLearnedConfig` — ENOENT defaults to `{enabled:false}`) is documented as gating "**ALL** automatic/background learned-constraint work" (`constraint-store.js:269-291`, the `learned enable/disable/status` usage text). In practice it gates far more than "constraint work" — it gates the entire structural collection tick, the fact-history trust computation, and six independent detector functions, each of which re-checks the exact same flag before any I/O:

- `service-baseline.js:466-468` (`computeServiceBaselineCandidates`, → `service.disappeared`, rule id `service-baseline.js:52`)
- `service-baseline.js:847-849` (`computeServiceAppearanceCandidates`, → `service.appeared`, rule id `service-baseline.js:659`)
- `persistence-baseline.js:295-297` (`computeScheduledJobBaselineCandidates`, → `scheduled_job.appeared`, rule id `persistence-baseline.js:32`)
- `process-lineage-baseline.js:309-311` (`computeProcessLineageBaselineCandidates`, → `process.lineage.novel_edge`, rule id `process-lineage-baseline.js:18`)
- `peer-baseline.js:704-706` (`computePeerBaselineCandidates`, → `peer.count_spike`/`peer.count_drop`)
- `session-baseline.js:624-626` (`computeSessionBaselineCandidates`, → `session.churn`/`session.count_drop`)

(Also gated the same way but out of this slice's scope: `computeProvenanceWarningCandidates`, `computeProvenanceIdentityCandidates`, `computeCredentialAccessCandidates`, `computeCorrelationCandidates`, `computeActiveConstraintCandidates` — see §7's "unchanged" list.)

**The structural collectors are already wired default-on** in `defaultDaemonProfile()` (`daemon.js:137-171`): `services`, `network`, `scheduled-jobs`, `provenance`, `sessions`, `vpn-peer-status`, `tailscale-status`, `canary`, `process-lineage` all have `enabled: true`, and every one of their doc comments says the same thing verbatim — "still safe/byte-identical for any operator who hasn't opted into learned features at all, because the outer configDir/learned.json {enabled:false} kill switch gates the entire structural tick... before any of it runs." The infrastructure to collect by default already exists; it is inert only because of the one outer flag. **This means "split the gate" is mostly a matter of relocating which flag the outer structural-tick block and the four watch-tier detector functions check — not building new collection.**

**The change-detectors are deterministic, completeness-gated, and already fail closed.** `service-baseline.js`'s module header (`:1-33`) states it is "DELIBERATELY STATELESS for detection purposes... a persisted `known_services` map was considered and rejected." Every one of the four watch-tier detectors recomputes from the bounded fact-history window on every call and carries its own persistent cold-start lockout (`service-baseline.js:494-547` for `service.disappeared`, `:877-901` for `service.appeared`; the equivalent shape in `persistence-baseline.js` and `process-lineage-baseline.js`, each with an exact-schema store validator per their own headers). While `cold_start_pending` is true, the detector "emits ZERO novelty" (`service-baseline.js:504-505`) — this is the existing mechanism that makes default-on safe: a fresh install has no history to be wrong about, and the detector already refuses to claim anything until it has enough of it.

**The wording is already largely honest.** Existing alert bodies do **not** say "malicious" or "failed":
- `service.disappeared`: title "Service disappeared", summary "A previously-established service stopped appearing in the latest complete service census." (`service-baseline.js:432-433`)
- `service.appeared`: title "New service appeared", summary "A service unit not seen in this host's recent history just appeared in the latest complete service census." (`service-baseline.js:832-833`)
- `scheduled_job.appeared`: title "Unexpected scheduled job" (`persistence-baseline.js:277`)
- `process.lineage.novel_edge`: title "Unexpected process lineage" (`process-lineage-baseline.js:300`)

This slice's §6 work is mostly *reuse*, with one asymmetry flagged below that needs an explicit decision.

**A genuine side benefit, not the point of this slice:** `descartes learned mine` is itself *not* gated by `learned.json` (`constraint-miner.js:325-330`, "Explicit, on-demand, human-invoked... convention #4 — that flag gates automatic/background work only") — but today it silently mines nothing on a fresh/disabled install, because the fact store it reads (`stateDir/learned/facts/facts.jsonl`) is only ever populated by the same gated structural tick. Splitting the gate means `learned mine` finally has real accumulated structural facts to work with the moment an operator opts into authoring, instead of a cold empty store.

---

## 3. The gate split

### 3.1 Two independent config files, not one field

Introduce **`configDir/watch.json`**, a new file mirroring `constraint-store.js`'s existing `learned.json` machinery exactly (`normalizeWatchConfig`, `loadWatchConfig`, `writeWatchConfig`), with one deliberate inversion: **ENOENT defaults to `{enabled: true}`**, not `false`. Keep `configDir/learned.json` byte-identical in shape and default (`{enabled: false}` on ENOENT) — it continues to mean exactly what it means today: the AUTHOR layer (mining, shadow-soak, promotion, tuning, and the daemon's automatic active-constraint/shadow-constraint evaluation).

A single file with two fields was considered and rejected: it would make `writeLearnedConfig` (today's atomic tmp+rename writer, `constraint-store.js:257-265`) responsible for a field it doesn't own, and would break `learned enable/disable`'s existing byte-identity guarantee for operators who only ever touch the AUTHOR flag.

### 3.2 The exact seam to move

In `daemon.js`, the structural-tick block currently reads:

```
if (structuralProfile?.interval_ms) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (learnedConfig.enabled) {           // <-- daemon.js:692
    ... readStructuralCheckpoint, collectStructuralEvidence, factPointsFrom*Evidence,
        appendFactPoints, evaluateAndLogShadowConstraints, writeStructuralCheckpoint ...
  }
}
```

Split this (`daemon.js:688-809`) into:
- **Outer gate → `watchConfig.enabled`** (new `loadWatchConfig`): checkpoint read, `collectStructuralEvidence`, all nine `factPointsFrom*Evidence` translations, `appendFactPoints`, `writeStructuralCheckpoint`. This is pure collection — every structural collector keeps running exactly as today, just under the new flag. (Facts for `provenance`, `sessions`, `vpn-peer-status`, `tailscale-status`, `canary` get persisted by default too, as an unavoidable consequence of moving the whole block — this is harmless and intentional: they're pure L0 fact sources with no `extraCandidates` addition today (`daemon.js:736-748`), so nothing alerts from them by default; only their *facts* accumulate, which is useful substrate for the AUTHOR layer later.)
- **Inner, additional gate → `learnedConfig.enabled`, nested inside the watch block**: `evaluateAndLogShadowConstraints` (`daemon.js:795-796`). Shadow-constraint evaluation only means anything once the AUTHOR pipeline has produced `status:"shadow"` constraints — it must not start running the moment watch turns on. This is a genuine two-flag AND, not a rename: `if (watchConfig.enabled && structuralDue) { ...collect/persist...; if (learnedConfig.enabled) { shadowEvaluation = ... } }`.

**The one finding that must not be missed:** the fact-history trust read immediately below (`daemon.js:811-845`, "Fix 2/Fix 3... ONE shared fact-history read this tick") is gated on a *separately loaded* `learnedConfigForHistory.enabled` (`daemon.js:830,833`). This computes `historyTrust`, which feeds `computeCoveredRuleIds` (`daemon.js:1002-1006,1056-1059`), which is what stops a currently-active `service.appeared`/`service.disappeared`/`scheduled_job.appeared`/`process.lineage.novel_edge` alert from being fabricated-"recovered" when this tick's fact-history can't be trusted (Fix 3, the anti-fabrication protection referenced in the grounding brief). **If this read stays gated on the AUTHOR flag while the four watch-tier detectors move to the WATCH flag, `historyTrust` stays `undefined` for the default (watch-on, author-off) population, and `computeCoveredRuleIds` falls back to unrestricted recovery for exactly the four alert families this slice turns on by default — silently reopening the fabricated-recovery hole Fix 3 closed.** This read must move to `watchConfig.enabled`, not stay on `learnedConfig.enabled`. Because AUTHOR is a strict addition on top of WATCH's fact substrate (mining/shadow/active-constraint evaluation are meaningless without structural facts, which now only exist when watch is on), gating this read on `watchConfig.enabled` alone is sufficient — no OR of the two flags is needed. `HISTORY_DEPENDENT_ALERT_RULE_IDS` itself (`daemon.js:99-110`) needs no change; only the condition that computes `historyTrust` does.

The `alwaysExcludedRuleIds: learnedConfigForHistory.enabled ? containmentRecommendationRuleIds() : []` line (`daemon.js:1005`) stays checking the **AUTHOR** flag (rename the local variable, not its meaning) — containment stays opt-in per §2's "What this is NOT."

### 3.3 The twelve-detector call site itself needs no change

`daemon.js:920-966` already calls all twelve `extraCandidates` producers unconditionally, every tick — the comment at `daemon.js:989-990` is explicit that this is deliberate ("NOT gated on learned.json: the 12 detectors above run regardless of the kill switch... the call is unconditional"). Each detector still self-gates at its own top (§3.4). No change needed at this call site beyond passing whichever config each detector's DI seam expects.

### 3.4 Per-detector change (four files)

In each of `service-baseline.js` (both `computeServiceBaselineCandidates` and `computeServiceAppearanceCandidates`), `persistence-baseline.js` (`computeScheduledJobBaselineCandidates`), and `process-lineage-baseline.js` (`computeProcessLineageBaselineCandidates`), replace the existing `const learnedConfig = await loadConfig(...); if (!learnedConfig.enabled) return [];` short-circuit with the equivalent read against `loadWatchConfig`. Everything below that line (cold-start lockout, `readFactPoints`, store load/write, candidate building) is unchanged — these functions already do the right thing; only the gate they check moves.

`peer-baseline.js` and `session-baseline.js` are **deliberately not touched by this sub-section** — see §11's open question on the statistical tier.

### 3.5 Migration for an existing install

Three cases, stated explicitly because this is the one place default behavior visibly changes for people who already have Descartes installed:

1. **`learned.json` absent (never touched).** Today: fully off. After this slice: `watch.json` absent too → **WATCH turns on**, AUTHOR stays off. This is the intended default-on flip and needs the consent treatment in §11 — it is a real behavior change for every untouched install, called out per the task's explicit instruction to flag any reversal of default-off.
2. **`learned.json {enabled:true}`** (operator already opted into everything). Today: full pipeline on. After: WATCH on (no change — they already had structural collection), AUTHOR on (no change — same file, same semantics). No behavior change for this population.
3. **`learned.json {enabled:false, updated_at:<pre-split-date>}`** — an operator who explicitly ran `learned disable`. This is genuinely ambiguous and is called out, unresolved, in §11: does an explicit pre-split "off" get honored as "and don't turn WATCH on either" (respect the operator's prior explicit choice), or is it ignored because it was never a WATCH decision at all (the field didn't distinguish the two things at the time)? The `updated_at` timestamp is what lets code tell "never touched" apart from "explicitly disabled" — but which way to resolve it is an operator call, not something to decide silently here.

---

## 4. The visible learning phase

The mechanism already exists and needs no new logic — it needs a name and a window onto it. Per detector, the persisted store already carries `cold_start_pending` (boolean), `cold_start_reason` (string|undefined), `cold_start_since_ts` (ISO string|undefined) — see `service-baseline.js:145-164` (`normalizeServiceBaselineState`) and the equivalent exact-schema shapes in `persistence-baseline.js:145-169` and `process-lineage-baseline.js:33-66`. On a genuinely fresh install the store is missing, so `storeLossThisTick` is true (`service-baseline.js:510`) and `cold_start_reason` defaults to `undefined` (`normalizeServiceBaselineState` only assigns `cold_start_reason` when the raw store already has a string — there is nothing to fall back to, since `enteringColdStart`'s own assignment at `service-baseline.js:557` is `storeLossThisTick ? persistedState.cold_start_reason : "corrupt_facts"`, and `persistedState.cold_start_reason` is itself `undefined` here). This is a real gap for the inspect surface (§5): a genuinely-fresh "first baseline in progress" install and a "we just lost/rebuilt history" re-learning event currently collapse to the same `cold_start_reason: undefined` on first loss. **This slice needs to give first-ever cold-start a distinct, explicit reason string** (e.g. `"initial_baseline"`, set when `storeLossThisTick` is true *and* there is no prior `cold_start_reason` at all — distinguishable from `storeLossThisTick` with a prior reason present, and from `"corrupt_facts"`), so the inspect surface can honestly say "first baseline in progress" rather than "history lost" for a machine that has no history to lose. This is a small, additive change to the four stores' cold-start-entry logic, not new architecture.

**Per-domain state, not one global flag.** Each of the four watch-tier detectors has its own store, its own `cold_start_since_ts` anchor, and its own re-accumulation counter (`service-baseline.js:588-594`, counting `censusState === "complete"` tick-groups since the anchor against `DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT = 6`, `service-baseline.js:78`; the sibling constants are `DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT = 6` and `DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT = 6`). A host can be "watching" for services while still "learning" scheduled jobs. The visible surface (§5) must report per-domain, not collapse to one binary.

**A third, honest state beyond learning/watching.** A host whose service census is truncated at `MAX_SERVICE_CENSUS_CEILING = 5000` (`tools/services.js:31`, raised from an old 80-item presentation-only cap by the already-shipped F3 fix — `tools/services.js:192-200` logs and marks the tick `census_state:"partial"` rather than silently dropping anything) can never accumulate `reestablishedTickCount >= 6` from `censusState === "complete"` groups and is honestly stuck. This is now a rare edge (5000 service units is pathological) rather than the common case the old 80-cap would have made it, but the inspect surface still needs a third rendering — "cannot establish: census incomplete" — distinct from "still learning," or "still learning" on a large/pathological host becomes a lie by omission.

**Cadence, stated plainly for expectation-setting.** Structural collection runs on `DEFAULT_STRUCTURAL_INTERVAL_MS = 60 * 60 * 1000` (one hour, `daemon.js:65`), gated by "due" checkpoint logic (`daemon.js:696`), against a fast tick of `DEFAULT_DAEMON_INTERVAL_MS = 60 * 1000` (`daemon.js:64`). Six required complete structural ticks means a freshly-installed, always-on host reaches "watching" roughly **six hours** after install in the default configuration. This is worth surfacing in the "still learning" copy (e.g., "usually ready within a few hours") rather than leaving the owner to guess, and worth flagging in §11 as a UX question (is six hours the right default learning window for a *default-on* product, versus the same window when it was an opt-in feature for an already-engaged operator?).

---

## 5. The inspect surface — "what have you learned"

**Recompute, don't read a cache.** `service-baseline.js`'s module header (`:24-33`) is explicit that this module is deliberately stateless for detection purposes — there is no persisted `known_services` list to read back (a persisted map was "considered and rejected" as a staleness/leak risk). The inspect surface must therefore call the same pure building blocks the detectors themselves use — `groupServiceFactsByTick` over `readFactPoints`'s bounded window, the same established-count gate — not a cached inventory. The same is true for scheduled jobs and process-lineage edges (their equivalent internal fold functions). Two consequences worth stating explicitly in the implementation: (a) this is genuinely new, additive code in each of the four files (a read-only "what does the current window say is established" query, reusing existing internal helpers, not a new detector), and (b) the CLI's answer can legitimately differ slightly from what the daemon's last tick actually alerted on if the fact-history window has moved since — this should be documented on the command itself, not hidden.

**Proposed command shape, separate from today's `learned status`.** Today's `descartes learned status` (`constraint-store.js:394-436`, wired at `index.js:217-221`) reports exactly two things: the AUTHOR `{enabled}` flag and `fact_store_completeness` (a store-health diagnostic, not an inventory). Keep it exactly as-is, scoped to AUTHOR only (its name already fits authoring semantics). Add:

```
descartes watch status [--json]                  # per-domain summary: watching | still learning (N/6, ~time remaining) | cannot establish (reason)
descartes watch inspect [--domain <name>] [--json]   # the actual current established set per domain (recomputed live, per above)
descartes watch enable|disable [--json]          # the new watch.json kill switch, for an operator who wants zero structural collection
```

`watch status` is the "ask what it's learned, still learning vs watching" surface from the skeleton; `watch inspect` is the deeper "what do you consider normal" listing. **Naming collision to flag, not silently resolve:** `descartes alerts watch [--json] [--interval] [--once] [--all]` already exists (`index.js:45`) as a live-tailing command for fired alerts — reusing the bare noun "watch" as a new top-level command risks operator confusion between "tail my alerts" and "show me the learning/inventory state." Alternatives (`descartes baseline status`, `descartes inventory status`, `descartes observe status`) are listed as options, not decided, in §11.

---

## 6. Honest, calm flagging

**Labels are already mostly right** — see §2's quoted titles/summaries. None of the four watch-tier detectors' output currently says "malicious" or "failed." The work here is presentation consistency (grouping these four under one calm "unrecognized / gone" framing when surfaced, e.g. in `watch status`'s recent-changes view) rather than rewriting the underlying alert bodies, which are reused unchanged.

**Pipeline reuse, no new mechanism.** All four detectors' candidates already flow through `evaluateAndPersistAlerts` → `applyAlertCandidates` (`alert-store.js:260,347`) exactly like every other alert family — same `DEFAULT_ALERT_COOLDOWN_MS = 15 * 60 * 1000` (`alert-store.js:6`), same dedup/recovery/acknowledgement state machine (`active/recovered/acknowledged/suppressed`, `alert-store.js:190,254`). Nothing new is required here; this slice's default-on flip inherits the calm-not-firehose behavior for free.

**One real asymmetry to flag, not silently decide.** `service.disappeared`'s diagnostics carry the sanitized service name in cleartext (a deliberate 2026-07-24 operator decision scoped explicitly to that one rule, `service-baseline.js:11-22`), but `service.appeared`'s diagnostics (`buildAppearedCandidates`, `service-baseline.js:818-838`) are hash-only — `entity_key_hash` and `first_seen_ts`, no name. `scheduled_job.appeared` and `process.lineage.novel_edge` need the same check before this slice ships (not yet verified here). This matters directly for §6's correction hook: **an owner cannot say "that's mine" about a hash they can't read.** Extending the 2026-07-24 cleartext decision to `service.appeared` (and possibly the other two appearance-shaped alerts) is a prerequisite for a usable correction hook, and it is exactly the kind of scoped reversal that decision's own text says was deliberately withheld — so it needs its own explicit operator sign-off, not an implicit one bundled into this slice. Listed in §11.

**The minimal correction hook.** The closest existing mechanism is `descartes alerts ack <alert-id> [--json]` (`index.js:46`) — it already exists, already moves an alert to `acknowledged` status, and (per §6's asymmetry note) is usable today for `service.disappeared` where the name is visible, and usable for `service.appeared`/`scheduled_job.appeared`/`process.lineage.novel_edge` once diagnostics carry a readable identity. **This slice's scope is exactly**: confirm `alerts ack` is the attachment point for "that's mine" (positive) — no new store, no new command — and name, as an explicit deferred follow-on (not built here), where "I didn't add that" (negative — the thing that makes an unrecognized entity *stay* flagged / escalate rather than quietly aging out) would need a second verb, since acknowledgement alone doesn't currently distinguish "seen and accepted" from "seen and rejected." That distinction, and any teaching-back into the detector's own "established" set, is explicitly the deferred full correction-teaching UI (§10).

---

## 7. Invariants preserved

- **Never-fabricate.** Every completeness gate, cold-start lockout, and exact-schema store validator in `service-baseline.js`, `persistence-baseline.js`, and `process-lineage-baseline.js` is reused byte-for-byte. This slice relocates *which flag* reaches those gates; it does not touch the gates themselves.
- **Fix 3's no-fabricated-recovery protection** is explicitly preserved by moving the `historyTrust` computation (`daemon.js:811-845`) onto `watchConfig.enabled` — see §3.2's flagged finding. This is the one place a naive gate-rename would have silently regressed a previously-hardened invariant, so it is called out here a second time deliberately.
- **Cold-start, honest-unknown.** Unchanged. A watch-tier detector still emits zero novelty while `cold_start_pending` (or an untrustworthy `historyTrust`) is true, regardless of which flag turned collection on.
- **Observation-only.** `safety: { read_only: true, background_llm_calls: false, telemetry: false, host_mutation: false }` (`daemon.js:173-178`) is untouched; nothing in this slice writes to the monitored host.
- **Why default-on is safe, stated plainly:** the detectors already fail closed on incomplete/untrustworthy history (§2), so flipping their upstream collection flag from off to on cannot, by construction, cause them to fabricate a claim on a fresh install — it can only ever make them *quieter for longer* (cold-start) or *silent* (census-incomplete), never wrong. The risk this slice actually introduces is not fabrication; it is unannounced resource/behavior change on every existing install (§3.5, §11) and the pre-existing appeared-vs-disappeared cleartext asymmetry (§6) — both named, neither silently absorbed.
- **Everything not named in §3.4 stays exactly as it is today**, still gated on `learned.json`/AUTHOR: `computeProvenanceWarningCandidates`, `computeProvenanceIdentityCandidates`, `computeCredentialAccessCandidates`, `computeCorrelationCandidates`, `computeActiveConstraintCandidates`, containment recommendation, and (pending §11) the two statistical detectors.

---

## 8. Sequencing (TDD)

**Step 0 — survey the test blast radius before writing any implementation code.** Every one of the four (soon-to-move) detectors' tests, and `daemon.test.js`, inject `loadLearnedConfig` via the existing `options.loadLearnedConfig ?? loadLearnedConfig` DI seam to pin "no I/O when disabled." After the split, a test that only injects `loadLearnedConfig: () => ({enabled:false})` will hit the new default-`true` `loadWatchConfig` path and perform I/O it didn't expect. Confirmed by direct grep, the files needing review before any test can be trusted green: `test/daemon.test.js` (21 injection sites — the highest-risk file), `test/service-baseline.test.js`, `test/persistence-baseline.test.js` (2), `test/process-lineage-baseline.test.js`, `test/peer-baseline.test.js`, `test/session-baseline.test.js`, `test/constraint-store.test.js`, plus `test/canary-baseline.test.js`, `test/containment-recommend.test.js`, `test/provenance-identity.test.js`, `test/provenance-warnings.test.js`, `test/credential-access-baseline.test.js`, `test/incident-correlation.test.js`, `test/calibration.test.js`, `test/evidence-freeze.test.js`, `test/provenance-elevated-config.test.js` (each reference `loadLearnedConfig` at least once; scope of change TBD per file during implementation). Decide up front: does test-helper default injection of `loadWatchConfig` stay `{enabled:false}` for every existing pinning test (least churn, explicit opt-in per test to exercise the new default-on path), or does every affected test gain a second injection? This decision belongs at the start of implementation, not discovered mid-slice.

1. **`watch.json` store (TDD).** `normalizeWatchConfig`/`loadWatchConfig`/`writeWatchConfig`, mirroring `constraint-store.js:224-265` with the ENOENT-default inverted. Unit tests: absent file → `{enabled:true}`; malformed JSON → fail-closed to the enabled default with a `corrupt:true` marker, mirroring `loadLearnedConfig`'s own corrupt-tolerance (`constraint-store.js:246-253`).
2. **Daemon seam split (TDD, `daemon.test.js`).** Move the structural-tick outer gate to `watchConfig.enabled`; add the nested `learnedConfig.enabled` check around `evaluateAndLogShadowConstraints` only; move the fact-history trust read (`daemon.js:829-845`) to `watchConfig.enabled`. New pinned tests: watch-on/author-off collects structural facts and computes `historyTrust` but never evaluates shadow constraints; watch-off/author-on collects nothing (AUTHOR starves without WATCH, by design — assert this explicitly, don't just leave it implicit); watch-on/author-off with untrustworthy history still withholds recovery for the four watch-tier rule ids (this is the Fix-3 regression test — it must exist and must fail on the naive implementation before the fix, to prove the finding in §3.2 is real).
3. **Per-detector gate move (TDD, one file/PR each — `service-baseline.js` ×2, `persistence-baseline.js`, `process-lineage-baseline.js`).** Swap the internal `loadLearnedConfig` short-circuit for `loadWatchConfig`. Existing cold-start/completeness tests should pass unchanged once the injected config in each test is updated per Step 0's decision.
4. **First-cold-start reason (TDD, same four files).** Give a genuinely-first cold-start a distinct `cold_start_reason` (§4) so "first baseline" and "history lost, re-learning" are distinguishable. Small, additive, test the two paths independently.
5. **`watch status`/`watch inspect`/`watch enable`/`watch disable` CLI (TDD).** New module (or extend `constraint-store.js`'s sibling pattern) implementing the recompute-live inspect logic (§5) against each detector's existing pure helpers; `--json` and human-readable renderings, mirroring `learned status`'s existing two-mode output shape.
6. **Correction hook confirmation.** Verify (do not newly build) that `alerts ack` works end-to-end against a `service.appeared` alert once its diagnostics carry a readable identity (§6, contingent on the cleartext decision in §11).
7. **Migration behavior tests (TDD).** The three cases in §3.5, encoded as tests against `loadWatchConfig`/`loadLearnedConfig` reading a pre-split `learned.json` fixture.
8. **README + HANDOFF.md.** Update the capabilities table and "off by default" framing (`README.md:46-77,272-296,341` — see §11's consent question for what the updated language should say) and record this re-scope + supersession of the 2026-09-09 Path-A entries in `docs/HANDOFF.md`.

---

## 9. Acceptance / demo

1. Fresh install, no config files present. `descartes daemon run --foreground` (or installed service). No alerts fire on the initial inventory — the cold-start lockout is active for every watch-tier domain.
2. `descartes watch status` shows, per domain (service, scheduled-job, process-lineage): `still learning — N of 6 complete observations` (or the census-incomplete variant if applicable), not `watching`.
3. With clock/tick injection accelerating the demo past real time (the existing `options.now` seam every detector already accepts, e.g. `service-baseline.js:485`, `:869` — no new mechanism needed for the demo itself), six complete structural ticks pass. `descartes watch status` flips that domain to `watching`, and `descartes watch inspect --domain service` lists the currently-established services.
4. A genuinely new service unit is introduced on the host. Within one structural tick, `service.appeared` fires exactly once (cooldown-respecting thereafter), with title "New service appeared" and a summary that says unrecognized, not malicious — surfaced via `descartes alerts list`.
5. `descartes alerts ack <id>` marks it acknowledged — the minimal "that's mine" hook — contingent on §6's cleartext-diagnostics decision landing first, else this step demonstrates the hash-only limitation directly instead.

---

## 10. Out of scope / deferred

- Extending the `service.disappeared`-style cleartext-diagnostics decision to `service.appeared`/`scheduled_job.appeared`/`process.lineage.novel_edge` — flagged as a prerequisite for a *usable* correction hook, not performed here (§6, §11).
- The full "I didn't add that" negative-correction verb and any teaching-back into a detector's established set — deferred; `alerts ack` alone doesn't distinguish accept from reject.
- Resolving the statistical-detector tier (peer/session) — §11.
- Any UI/UX beyond CLI text and `--json` (no TUI, no desktop notification copy changes beyond what the existing pipeline already sends).
- Retuning `DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT`/`DEFAULT_STRUCTURAL_INTERVAL_MS` or any other detector-tuned constant.
- Anything in `docs/plans/2026-09-09-protection-contract-slice-1.md` (superseded, §header).
- Path B (`todos/2026-09-09-path-b-self-learning-authorship-spike.md`) itself — this slice only supplies its prerequisite default-on population.

---

## 11. Open questions for the operator

1. **Statistical-tier placement (peer.count_spike/drop, session.churn/count_drop).** These are already completeness-gated and cold-start-protected exactly like the four watch-tier detectors (`peer-baseline.js`, `session-baseline.js` both import and use the same `factHistoryTrustworthy`/cold-start pattern) — so "safety" doesn't distinguish them. What does is alert *shape*: a novelty claim ("this specific thing appeared/vanished") versus a statistical-deviation claim ("the count moved N sigma from a rolling mean"). Do they join WATCH (default-on, same as the four), stay on AUTHOR (today's behavior, unchanged), or become a third, separately-named tier the owner opts into independently of both? Not resolved here.
2. **Naming collision.** `descartes watch ...` as a new top-level command reads confusingly next to the existing `descartes alerts watch` (a live-tail command, `index.js:45`). Alternatives: `baseline`, `inventory`, `observe`. Needs a decision before the CLI surface in §5 is built.
3. **Correction-hook timing.** Should the cleartext-diagnostics extension for `service.appeared`/`scheduled_job.appeared`/`process.lineage.novel_edge` (§6) land inside this slice (making the demo's step 5 real) or ship as an immediate, separate, fast-follow slice? Either is defensible; the plan doesn't presume one.
4. **Noise/resource defaults for default-on structural collection.** Moving structural collection from opt-in to default-on means every install now runs `services`/`network`/`scheduled-jobs`/`provenance`/`sessions`/`vpn-peer-status`/`tailscale-status`/`canary`/`process-lineage` collectors hourly, unconditionally, where before only operators who explicitly wanted the learned subsystem paid that cost. None of this was measured against "acceptable idle resource use for every default installation" as a product bar — worth a sanity pass (even lightweight) before shipping default-on broadly, not assumed free.
5. **Existing-install migration and consent.** Per §3.5's three cases: is there a first-run notice, an upgrade-time prompt, or any explicit consent surface for the population that goes from "Descartes does nothing extra" to "Descartes is now watching my machine's service/job/process inventory" with no action on their part? This is a real product decision for a defensive-security tool, not a formality — flagged explicitly per the task's own instruction to surface it. Relatedly, does an existing explicit `learned disable` (case 3, distinguishable via `updated_at`) get honored as "and don't turn WATCH on either," or is it ignored as out-of-scope for a flag that, at the time it was set, didn't distinguish watch from author?
6. **README/marketing-language consequence.** `README.md:52-58,272-296,341` currently states the self-learning/defensive-detection subsystem is uniformly "off by default" behind "one kill switch." This slice makes that literally false for four specific alert families. The updated language needs to say, accurately, "structural watching is on by default; authoring/promotion stays opt-in" — a wording and framing decision, not just a mechanical doc sync.
7. **Six-hour default learning window.** Reasonable for an operator who explicitly opted in; is it still the right default when watching turns on for everyone, unannounced, on install? No detector-constant retuning is in scope (§10), but the *product* question of whether the default learning window is appropriate for a default-on product is open.

---

## KEY CODE REFS VERIFIED

- `daemon.js:63-65` (interval constants), `:99-110` (`HISTORY_DEPENDENT_ALERT_RULE_IDS`), `:129-180` (`defaultDaemonProfile`, all-collectors-default-true), `:303-314` (`collectDaemonEvidence`, core/always-on), `:320-355` (`collectStructuralEvidence`), `:451-477` (`computeActiveConstraintCandidates`, AUTHOR-gated), `:677-809` (the structural-tick `learnedConfig.enabled` block — outer gate to move), `:811-845` (fact-history trust read — the load-bearing seam finding), `:920-1006` (twelve-detector unconditional call site + `coveredRuleIds`/containment exclusion at `:1005`)
- `constraint-store.js:224-230` (`normalizeLearnedConfig`), `:237-255` (`loadLearnedConfig`, ENOENT→disabled), `:257-265` (`writeLearnedConfig`), `:267-292` (CLI usage doc, "gates ALL automatic/background... work"), `:394-436` (`runLearnedConfigCommand`)
- `service-baseline.js:1-33` (module header, deliberately stateless), `:38,466-468` (`computeServiceBaselineCandidates` gate), `:52` (`SERVICE_DISAPPEARED_RULE_ID`), `:61` (`DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT=3`), `:78` (`DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT=6`), `:145-164` (`normalizeServiceBaselineState`), `:406-437` (`buildDisappearedCandidates`, cleartext), `:494-547` (cold-start lockout, `coldStartPendingThisTick`), `:645-668` (`service.appeared` gate-decision comment, rule id), `:818-838` (`buildAppearedCandidates`, hash-only), `:846-956` (`computeServiceAppearanceCandidates`)
- `persistence-baseline.js:22,294-297` (gate), `:32` (rule id), `:276-278` (title/summary), `:145-169` (exact-schema store)
- `process-lineage-baseline.js:8,308-311` (gate), `:18` (rule id), `:299-301` (title/summary), `:33-66` (store shape)
- `peer-baseline.js:24,703-706` (gate, unchanged this slice); `session-baseline.js:30,623-626` (gate, unchanged this slice)
- `index.js:36-72` (usage), `:46` (`alerts ack`), `:50-64` (`learned` subcommands), `:134-224` (`learned` dispatch)
- `alert-store.js:6` (`DEFAULT_ALERT_COOLDOWN_MS`), `:190,254,260,347` (status states, `applyAlertCandidates`, `evaluateAndPersistAlerts`)
- `fact-store-completeness.js` (`factHistoryTrustworthy`, anchor-relative loss check)
- `constraint-miner.js:325-330` (`learned mine` ungated by kill switch — side-benefit note)
- `tools/services.js:31` (`MAX_SERVICE_CENSUS_CEILING=5000`, F3 fix superseding the old 80-cap), `:192-200` (truncation → `census_state:"partial"`)
- `README.md:46-77,272-296,341` (current "off by default" framing, needs updating)
- `docs/plans/2026-09-09-protection-contract-slice-1.md` (superseded direction); `todos/2026-09-09-path-b-self-learning-authorship-spike.md` (the deeper spike this slice founds); `docs/HANDOFF.md` (2026-09-09 entries, now stale, need a new entry)
