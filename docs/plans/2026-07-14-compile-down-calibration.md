# Outcome-Informed Compile-Down & Calibration (Slices 14–15)

**Created:** 2026-07-14
**Status:** Proposed — implementation-ready dedicated plan (design-only pass; no code written under this doc yet)
**Reviewed:** 2026-07-14 (independent adversarial pass) — 9 must-fixes folded in; never-auto-apply spine verified sound and non-bypassable.
**Parent roadmap:** `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` — §5 ("Self-Audit / Verify / Maintain Loop"), §8 Slices 14–15, §3.1 artifacts table (`tuning-candidates.json`, `artifact-audit.jsonl`, `authority/promotions.json`)
**Scope:** the roadmap's "make-it-live remainder" — close the loop `learn → alert → measure outcomes → propose tuning (human-gated) → self-audit calibration`. Deterministic, read-only analysis. **No LLM anywhere in this plan.** A tuning proposal is an inert, review-ready artifact that is **never** auto-applied.

---

## 0. Ground truth vs. the roadmap's provisional design intent

The roadmap (§0) explicitly flags Slices 10–16 as "design-sketch… provisional design intent to be validated against real data, not frozen contracts." Validating against the real, shipped code turned up several load-bearing deltas this plan is written against, not the roadmap's original assumptions:

1. **No `baseline-store.js` / `baseline.*` rule_ids exist.** Roadmap Slice 10 ("Welford/EWMA per-metric baseline… `baseline.<metric>.deviation`") never shipped. What shipped instead, under a *different* initiative (`docs/plans/2026-07-13-observed-incident-collectors.md`), are `session-baseline.js` (`session.count_drop`, `session.churn`) and `peer-baseline.js` (`peer.count_spike`) — structural **fact-count** baselines, not per-metric numeric baselines. `"baseline"` and `"identity"` are pre-registered `alert-intelligence.js` namespaces (`KNOWN_ALERT_NAMESPACES`, `alert-intelligence.js:40`) with **zero emitters** today.
2. **`session.*` and `peer.*` are structurally unreachable by the LLM — but the scope of that claim was previously mis-stated as a blanket invariant (fixed 2026-07-14 review).** `classifyAlertNamespace` (`alert-intelligence.js:637-654`) only recognizes `daemon./system./disk.→metric`, `constraint.→constraint`, `provenance.→provenance`, `baseline.→baseline`, `identity.→identity`, `learned.→learned(hard-excluded)`. `session.` and `peer.` fall through to `namespace: undefined` (`unknown_namespace`) and are delivered instead through a deterministic, non-LLM bypass (`emitSessionAlertSignals`, mirrored for peer) — they can **never** appear in `llm-decisions.jsonl` as adjudicated, regardless of `enabled_namespaces`. **Corrected invariant:** this plan does **not** claim "only `constraint.*`, `provenance.*`, and `correlation.*` are ever LLM-eligible" — that is false: `metric.*` (`daemon./system./disk.`) is templated and **default-on** (`DEFAULT_ENABLED_NAMESPACES=["metric"]`), making it the *primary* LLM-adjudication path in the whole system, and `baseline.*`/`identity.*` are templated and consentable too (zero emitters today per point 1, but not structurally excluded). The honest, correctly-scoped split — restricted to the **six learned-derived families this plan calibrates** (§2.2) — is: `session.*`/`peer.*` are **structurally un-consentable** (`llm_namespace_enabled: null` — no `enable-namespace` switch can ever make them adjudicated, because `classifyAlertNamespace` has no branch for them at all); `constraint.*`/`provenance.*`/`correlation.*` are **consentable, default-off** (an operator can `alerts intelligence enable-namespace <ns>` to opt them in). `metric.*`/`baseline.*`/`identity.*` are real LLM-eligible namespaces but fall **outside** the learned-derived calibration scope of §2.2 — their eligibility is unrelated to, and does not contradict, the session/peer point being made here.
3. **Only two of six learned-derived families carry a persisted, stable artifact id.** `constraint.violation.<family>` candidates carry `diagnostics.constraint_id` (`constraint-eval.js:85`) — the exact key in `constraints.json`. `provenance.*` candidates carry `diagnostics.identity_hash` (`provenance-store.js:437,459` — `unknown_identity`/`new_public_bind`) or `diagnostics.new_identity_hash` (`provenance-store.js:480-481` — `identity_drift`; corrected 2026-07-14 review — `identity_drift` carries `old_identity_hash`/`new_identity_hash`, never a bare `identity_hash`, see §2.1's corrected attribution) — either way, the exact key in `signatures.json`. **`session.*`, `peer.*`, and `correlation.*` candidates carry no artifact id at all** — they're derived fresh every tick from a **singleton** rolling-stats record (`session-baseline.json`, `peer-baseline.json`) or recomputed **with no persisted record whatsoever** (`incident-correlation.js`, doc comment `:267-273`). There is nothing to "retire" or "retune" as a discrete object for these three families — only the shared numeric constants (`DEFAULT_DEVIATION_SIGMA`, `DEFAULT_MIN_SAMPLE_COUNT`, etc.) that parameterize the whole family.
4. **No fixture-replay/backtest mechanism exists anywhere.** Every constraint ships `fixtures: [{input, expect_match}]` (`constraint-store.js` `SEED_CONSTRAINTS`, `constraint-miner.js:148-151`), gated at promotion (`MIN_FIXTURE_COUNT=2`, `constraint-store.js:295`), but **no code executes them** — confirmed by a tree-wide grep for `backtest`/`replay`/`calibration`/`tuning-candidates`, all zero hits outside comments. This plan is what actually builds a backtest, not a wrapper around an existing one.
5. **Roadmap Slices 8–9 (self-audit: `chronically_firing`, `staleness`, `contradiction`, fixture regression, `learned.health.*`/`learned.audit.*`) have not shipped either.** `"learned."` has zero emitters in `src/` today. This plan cannot lean on an existing `chronically_firing` signal — it computes its own noise/chronic-fire proxy directly from `alerts.json` + `llm-decisions.jsonl` (§3 below), scoped narrowly to what Slice 14 needs. It does **not** attempt fixture-regression replay or emit `learned.health.*`/`learned.audit.*` — that remains S8/S9's separate, still-unpicked scope.
6. **`sanitizeDiagnostics()` is a syntactic gate, not a confidentiality control.** Its allowlist (`^[A-Za-z0-9][A-Za-z0-9._:-]*$`, ≤64 chars, or a fixed-length hex hash — `diagnostics-sanitizer.js:30,40,44`) happily passes a charset-safe-shaped raw IP, hostname, or session name — it cannot distinguish those from a closed-enum identifier. `alert-intelligence.js`'s `compactAlert` (`:438-450`) does call `sanitizeDiagnostics(alert.diagnostics)`, but per the `2026-07-13-observed-incident-collectors.md` plan's must-fix 3 (§1, restated there), this is **necessary, not sufficient** — real confidentiality requires hash-at-source in the candidate-builder. **This plan follows the same discipline**: every new persisted record (`tuning-candidates.json`, `authority/tuning-decisions.json`, `artifact-audit.jsonl`) carries only counts, closed enums, and fixed-length hashes constructed deliberately at the point of computation — never a value merely because it happened to survive `sanitizeDiagnostics`.
7. **`alerts.json` has no documented retention/eviction path** in the reviewed code (unlike `fact-store.js`'s 30-day/5MB cap or `history-store.js`'s window). Recovered/acknowledged alert records are flipped in place, never deleted. This plan therefore treats "the calibration window" as "all currently-retained `alerts.json` records" by default, narrowable via `--since`; if a retention mechanism is added later the window narrows automatically. This is flagged as an assumption to re-verify at implementation time, not a hard architectural fact.

---

## 1. Safety spine (restates `AGENTS.md` + the parent roadmap §11 against this plan's specifics)

- **Deterministic, read-only, no LLM — for real, not just "no `pi-harness.js` import."** Every function added by this plan is pure or read-only I/O (JSONL/JSON reads via the already-shipped reader functions). `calibration.js`, `tuning-store.js`, and `tuning-authority.js` **do not import** `pi-harness.js` or `alert-intelligence.js`'s adjudication path — verified the same way `promotion-store.js` already documents its own no-LLM claim (module-header assertion + a source-regex test, `promotion-store.js:19-20`).
- **Two hard invariants, proven not asserted (§6 has the full proof):**
  1. A `draft`/`review-ready` tuning candidate has **zero** effect on any live-evaluated threshold. `evaluateConstraints` (`constraint-eval.js:114`) has no import of and no runtime dependency on `tuning-store.js`/`tuning-authority.js` — the live read path is architecturally blind to the existence of a pending proposal, not merely gated by a status check.
  2. The **only** way a proposal changes a live value is an explicit `descartes learned tuning approve <id> --nonce <n>`, itself gated by a deny-by-default nonce/expiry/status match cloned from `promotion-store.js`'s already-adversarially-verified (`OVERALL_SAFE`) pattern.
- **Own approval store, not a shared one (Decision 3, justified in §6.1).** `stateDir/authority/tuning-decisions.json` is **separate** from `stateDir/authority/promotions.json`, following the same reasoning the parent roadmap already applied to keep witr's risky-action store separate from artifact-promotion (§6 of the roadmap): different risk domain (mutating a *value* on an already-active record vs. transitioning a *lifecycle status*), different foreign-key shape, and — decisively — reusing `decideConstraintPromotion` would mean growing an already safety-reviewed, `OVERALL_SAFE`-verified function's control flow, which is exactly the kind of change the roadmap already declined to make for witr.
- **Narrowly-scoped new mutators.** This plan adds exactly two new constraint-store.js functions that can ever change a live artifact (`retireActiveConstraint`, `applyApprovedRetune`), each with a single legal caller (`tuning-authority.js`'s `decideTuningApproval` approved branch) and a single legal precondition (`status === "active"`). Neither can be reached from the miner, from `descartes learned tuning mine`, or from a `review-ready` state.
- **Sanitized, bounded, counts/proxies/hashes only.** No raw path/username/IP/hostname is ever written into `tuning-candidates.json`, `authority/tuning-decisions.json`, or `artifact-audit.jsonl`. Every numeric field is a count, a ratio, or a proxy score; every identifier field is either an existing artifact id (`constraint_id`, `identity_hash` — themselves already-hashed/bounded values) or a rule_id-family string from the closed set in §2. All records additionally pass `sanitizeDiagnostics()` as defense-in-depth, but the actual control is field-selection discipline at construction time, per point 6 of §0.
- **Retired/rejected proposals are never deleted.** `tuning-candidates.json` and `authority/tuning-decisions.json` follow the exact `promotion_history`/`audit_transitions` append-only discipline already shipped in `constraint-store.js`/`promotion-store.js` — full history kept, mirroring "retired artifacts are never deleted" (roadmap §5).
- **Day-1: empty outcomes → empty report, no proposals.** `computeCalibrationReport` over empty `alerts.json`/`llm-decisions.jsonl`/`shadow-violations.jsonl` returns `{ artifacts: [] }`; `mineTuningCandidates` over an empty calibration report returns `[]`. No file is created until there is something to write (mirrors `loadConstraints`'s `ENOENT → { constraints: [] }` posture).
- **Behind `learned.json`, same as everything else in this subsystem.** `descartes learned calibration` and `descartes learned tuning mine` both short-circuit to an explicit `{ status: "disabled" }` when `loadLearnedConfig(...).enabled` is `false` — reusing the exact fail-closed corrupt-tolerant loader already shipped (`constraint-store.js:187-205`). (Read commands like `tuning list`/`tuning review` that only *display* already-mined state are **not** gated — mirroring `descartes learned review`'s own posture of listing existing state regardless of the enable switch, since disabling `learned.json` stops new emission, not visibility into what already exists.)
- **No new privilege, no new collector, no new host I/O.** This entire plan reads existing JSON/JSONL state files. Zero `execFile` calls, zero new tool-policy surface.

---

## 2. Outcome-signal inventory (what actually exists to compile down from)

| Source | File | Shape (verified) | Usable for calibration? |
|---|---|---|---|
| Alert lifecycle | `alerts.json` (`alert-store.js:161-184` `normalizeAlertRecord`) | `{id, rule_id, fingerprint, status: active\|recovered\|acknowledged\|suppressed, severity, title, summary, evidence_refs, first_seen, last_seen, last_notified, cooldown_until, acknowledged_at, diagnostics}` | **Yes — primary source.** `status`/`first_seen`/`last_seen`/`acknowledged_at` drive the noise proxies. **Caveat:** `"suppressed"` is a dead enum value (no code path ever sets it — confirmed by tree-wide grep); no `ack`-vs-`suppress` distinction exists today, only `acknowledgeAlert` (`alert-store.js:295-306`, CLI `descartes alerts ack`). `acknowledged` is therefore the *only* "a human looked at this and dismissed/accepted it" signal available. |
| LLM adjudication | `llm-decisions.jsonl` (`alert-intelligence.js:890-922`, read via `readAlertIntelligenceAudit`/`readAuditRecords`, `:203-226`) | `{ts, alert_id, rule_id, namespace, alert_severity, status: ok\|error\|audit_probe\|audit_write_degraded\|audit_unavailable, decision:{notify,severity,title,body,reason,evidence_refs,next_check_hint}, prompt_hash, prompt_template_version, delivery}` | **Yes, but namespace-confounded.** Only `constraint.*`, `provenance.*`, `correlation.*` can appear here at all (§0.2); `metric` (fixed rules) also appears. `session.*`/`peer.*` will **never** have a record here — this must be surfaced, not silently read as "0% escalated." No normalization function exists for this file (raw parsed array) — the calibration reader must defensively coerce. |
| Notification delivery | `notification-delivery.jsonl` (`notification-delivery.js:214-277`, read via `readNotificationDeliveryAudit`) | `{ts, status: skipped\|disabled\|cli_only\|unavailable\|delivered\|error, channel, payload:{alert_id,rule_id,severity,title,body}, reason?, command?, error?}` | **Supplementary.** Confirms whether a `notify:true` decision actually reached a channel — used only as a `delivered` vs `skipped/error` cross-check, not a primary proxy. |
| Shadow fires | `shadow-violations.jsonl` (`shadow-store.js` `normalizeShadowRecord`) | `{ts, constraint_id, family, target, expected, actual, fired}` | **Constraint-family only.** `checkShadowSoak` (`constraint-store.js:333-383`) is a **binary gate** (zero fires + full-day coverage), not a computed rate — no existing agreement/false-fire-rate function. This plan adds one (§4.5), scoped to constraints still in `status:"shadow"` (feeds `promote_shadow_hint`, §5.2). |
| Learned artifacts | `constraints.json` (`constraint-store.js`), `signatures.json` (`provenance-store.js`) | Full `LearnedArtifact`-shaped records with `expected`/`status`/`promotion_history`. | **Yes — the mutable target of retire/retune (constraint family only in v1, §5).** |
| Fact history | `stateDir/learned/facts/facts.jsonl` (`fact-store.js`, 30-day/5MB retention) | `{ts, fact_name, entity_key, attributes, source_envelope_id, source_tool, sensitivity}` | **Yes — the backtest substrate** for constraint-family retune proposals (§5.3). |

### 2.1 Attribution: which families have a stable artifact id

```
artifact_ref(alert) =
    alert.diagnostics.constraint_id      // constraint.violation.<family> — traceable to constraints.json
 ?? alert.diagnostics.identity_hash      // provenance.process.unknown_identity, provenance.port.new_public_bind — traceable to signatures.json
 ?? alert.diagnostics.new_identity_hash  // provenance.process.identity_drift — see fix note below
 ?? alert.rule_id                        // session.*, peer.*, correlation.* — no persisted artifact; family-level only
```

**Fixed 2026-07-14 review (was a silent granularity bug):** `provenance.process.identity_drift` diagnostics carry `old_identity_hash`/`new_identity_hash` (`provenance-store.js:480-481`), **not** a bare `identity_hash` — so the original two-line `??` chain fell all the way through to `alert.rule_id`, silently downgrading every `identity_drift` row to `granularity: "family"` even though it names one specific, traceable `signatures.json` record, contradicting §0 point 3's claim that `provenance.*` is one of the two families with a stable artifact id. **Fix:** the attribution chain adds an explicit third branch recognizing the drift shape and uses `new_identity_hash` — the live `signatures.json` key going forward for that identity — so `identity_drift` rows correctly attribute at `granularity: "artifact"`, consistent with the rest of `provenance.*`.

Every calibration row therefore carries an explicit **`granularity: "artifact" | "family"`** field — `"artifact"` when grouped by a real stored record id, `"family"` when grouped only by `rule_id` because no discrete artifact exists (§0.3). This is load-bearing: it is the single field that stops a downstream reader (agent or human) from treating a `session.*`/`peer.*`/`correlation.*` calibration row as if it named one mutable thing.

### 2.2 Closed rule_id-family set this plan scopes to

Learned-derived only (never fixed rules `daemon.*`/`system.*`/`disk.*` — those are hand-authored zero-learning reflexes, not learned artifacts, and are explicitly out of scope for calibration/compile-down):

`constraint.violation.<family>`, `provenance.process.unknown_identity`, `provenance.process.identity_drift`, `provenance.port.new_public_bind`, `session.count_drop`, `session.churn`, `peer.count_spike`, `correlation.login_kill_proximity`.

(`provenance.process.deleted_exe_running`/`provenance.socket.public_bind_no_supervisor` from `provenance-warnings.js` are fixed zero-learning rules, not mined/promoted artifacts — excluded from calibration/compile-down for the same reason as `daemon.*`/`system.*`/`disk.*`.)

---

## 3. The shared calibration computation

`calibration.js` exports one pure function that both `descartes learned calibration` (S15) and the S14 miner call — **S14 depends on S15, never the reverse**; this is enforced by the import graph itself, not just convention (§10).

```js
// calibration.js
export function computeCalibrationReport(alerts, auditRecords, deliveryRecords, shadowRecords, options = {}) {
  // pure: no I/O. Callers pass already-loaded arrays (readAlertRecords, readAlertIntelligenceAudit,
  // readNotificationDeliveryAudit, loadShadowViolations equivalents).
  ...
  return { generated_at, window: { since, until }, artifacts: [ /* CalibrationRow[] */ ] };
}
```

### 3.1 `CalibrationRow` shape

```
CalibrationRow {
  artifact_ref,                 // constraint_id | identity_hash | rule_id (§2.1)
  granularity: "artifact" | "family",
  rule_id_family,               // closed-set string from §2.2
  fired_count,                  // distinct alert ids with first_seen in window (see caveat below)
  auto_recovered_fast_count,
  never_escalated_count,        // number | null -- explicit JSON `null` (never a number, never 0)
                                 // whenever llm_namespace_enabled !== true; see §3.2 fix (2026-07-14 review)
  llm_adjudicated_count,        // count with >=1 llm-decisions.jsonl record, status:"ok"
  llm_suppressed_count,         // of adjudicated, latest decision.notify === false
  llm_namespace_enabled,        // bool | null — null when namespace can never reach LLM (session./peer.)
  precision_proxy,               // number in [0,1] | null (undefined when fired_count === 0)
  recall_proxy: null,             // ALWAYS null — see §3.4, never fabricated
  shadow_fire_rate,              // number in [0,1] | null — constraint-family, status:"shadow" only
  chronically_firing,            // bool — see §3.3
  schema_version,
}
```

### 3.2 Exact proxy formulas (stated honestly — these are PROXIES, not ground truth)

Let `W` = the report window (default: all retained `alerts.json` records; narrowable via `--since`). Let `A(ref)` = alerts in `W` whose `artifact_ref(alert) === ref`.

- **`fired_count = |A(ref)|`** — count of *distinct alert incidents* (unique `(rule_id, fingerprint)` ids), **not** tick-level re-fire frequency. **Honest limitation:** `alerts.json` is a live-status snapshot, not an append-only event log; a candidate that stays `"active"` across many daemon ticks without recovering is one incident, and a flap that recovers-then-refires *with the same fingerprint* re-uses the same record (`applyAlertCandidates`, `alert-store.js:236,240`) rather than creating a new one. `fired_count` is therefore a **lower bound** on true firing frequency for flapping artifacts, not an exact count. **Direction of the resulting bias, stated explicitly (2026-07-14 review):** undercounting a chronically-flapping-same-fingerprint artifact biases `chronically_firing` (§3.3, which requires `fired_count >= MIN_CHRONIC_FIRES`) toward a **false negative** — i.e., toward *not* flagging an artifact as chronic when it really is — which in turn biases `retire` (§5.2) toward **non-action**. This is the fail-safe direction: an under-flagged noisy artifact just keeps firing and stays visible rather than getting auto-proposed for retirement off a miscount. But it has a secondary failure mode worth naming: a chronically-flapping artifact whose undercounted `fired_count` lands inside the `retune` band (`MIN_RETUNE_FIRES ≤ fired_count < MIN_CHRONIC_FIRES`, §5.2) instead of at-or-above the `retire` threshold can be **misrouted into a retune proposal** (loosen the threshold) when retirement would have been more appropriate. The backtest (§5.3) and the mandatory human-gated approval (§6) both mitigate this — a human reviewing a retune proposal's `justification` still sees the true (if undercounted) `fired_count` and can recognize a flapping pattern and retire manually instead — but this is named here as a known proxy limitation, not silently absorbed into the chronic-fire math.
- **`auto_recovered_fast_count`** = `|{ a ∈ A(ref) : a.status === "recovered" ∧ (last_seen − first_seen) ≤ FAST_RECOVERY_THRESHOLD_MS }|`, default `FAST_RECOVERY_THRESHOLD_MS = 30min` (2× `alert-store.js`'s own `DEFAULT_ALERT_COOLDOWN_MS = 15min`). **Honest limitation:** a fast-recovering *real* incident that ops fixed quickly looks identical to a noise blip — this is a noise *proxy*, not a noise *proof*.
- **`never_escalated_count`** = `|{ a ∈ A(ref) : a.status ≠ "recovered" ∧ no llm-decisions.jsonl record for a.id has decision.notify === true }|`. **Critical honesty requirement:** this is only a meaningful signal when `llm_namespace_enabled` is `true` for that family. For `session.*`/`peer.*` (`llm_namespace_enabled: null`, §0.2) or for any family where the operator never ran `alerts intelligence enable-namespace <ns>`, **every** artifact will show 100% never-escalated — **this reflects consent configuration, not artifact quality**, and the report must render this distinction loudly — **not only in the human-readable renderer (§4.2), but in the machine-readable `--json` output itself (fixed 2026-07-14 review, was renderer-only)**: whenever `llm_namespace_enabled !== true`, `computeCalibrationReport` emits `never_escalated_count: null` — an explicit JSON `null`, never a computed number, never `0` — for that row. **Fix rationale:** a downstream agent or script consuming `--json` never sees the human-readable annotation from §4.2; if `never_escalated_count` were still a real number (e.g. `=== fired_count`) sitting next to `llm_namespace_enabled: null`, an automated consumer could read `never_escalated_count` in isolation and treat "100% never-escalated" as a genuine quality signal ("this artifact is never caught") rather than what it actually is ("this namespace cannot reach the LLM at all"). Making the field itself `null` — not just documenting the caveat in prose — is the only way the honesty requirement survives contact with a JSON-only consumer. The same null-out rule applies to any other field whose meaning is entirely namespace-gated (currently only `never_escalated_count`; `llm_suppressed_rate`, below, is already correctly `null` when `llm_adjudicated_count === 0`, which is a different, already-handled gate).
- **`llm_suppressed_count` / `llm_adjudicated_count`** → `llm_suppressed_rate = llm_suppressed_count / llm_adjudicated_count` when `llm_adjudicated_count > 0`, else **`null`** (never `0`, which would misleadingly read as "0% suppressed" rather than "never adjudicated").
- **`precision_proxy`** — **fixed 2026-07-14 review: the naive formula could go negative.** `auto_recovered_fast_count` and `llm_suppressed_count` are computed from **independent conditions on the same alert id** — an alert can be *both* fast-recovered *and* llm-suppressed (e.g. the adjudicator suppressed it, and it also happened to auto-recover quickly). Summing the two counts can therefore double-count a single alert, pushing `(auto_recovered_fast_count + llm_suppressed_count) / fired_count` above `1` and driving `precision_proxy` **negative** — a proxy that is supposed to live in `[0,1]` silently escaping that range would corrupt every downstream consumer (chronic-fire thresholding §3.3, retune banding §5.2) with no visible error. **Fix:** the numerator is the **deduplicated union by alert id**, not a sum of the two counts:
  `precision_proxy = 1 − |FastOrSuppressed(ref)| / fired_count` when `fired_count > 0`, else **`null`**, where
  `FastOrSuppressed(ref) = { a ∈ A(ref) : a is fast-recovered } ∪ { a ∈ A(ref) : a is llm-suppressed }` (a `Set` over alert ids, not `auto_recovered_fast_count + llm_suppressed_count`). `auto_recovered_fast_count` and `llm_suppressed_count` are still reported separately in `CalibrationRow`/`justification` for transparency — only the `precision_proxy` computation itself uses the union. Reads as "fraction of fired incidents that neither self-resolved fast nor were suppressed by an adjudicator" — a proxy for "this artifact's fires tend to matter," not a measured true-positive rate.
- **`recall_proxy` is always `null`.** §3.4 explains why this is a hard design decision, not an omission.
- **`shadow_fire_rate`** (constraint-family, `status:"shadow"` only) `= |{s ∈ shadow-violations.jsonl : s.constraint_id === ref ∧ s.fired}| / |{s : s.constraint_id === ref}|`, else `null` if no shadow records exist yet. For any constraint that has *already* been promoted past shadow, this is trivially `0` by construction of `checkShadowSoak`'s promotion gate (`constraint-store.js:333-383` requires zero fires to promote) — so it is only informative for **currently-shadow** constraints, feeding `promote_shadow_hint` (§5.2), not as a general precision metric for active constraints.

### 3.3 `chronically_firing` (the local proxy this plan needs, since roadmap S8 hasn't shipped)

```
chronically_firing(row) = fired_count >= MIN_CHRONIC_FIRES        // default 5
                        && precision_proxy !== null
                        && precision_proxy < CHRONIC_NOISE_THRESHOLD  // default 0.3
```

This is a locally-computed proxy, not a claim that this plan implements roadmap Slice 8's `learned.health.degraded`/fixture-regression audit — it satisfies only the narrow input Slice 14's `retire` proposal needs, and is named as such so a future S8/S9 pickup is not confused with this.

### 3.4 Why `recall_proxy` is always `null` — stated, not hidden

True recall requires a ground-truth signal of "there was a real incident we should have caught." **No such signal exists anywhere in this codebase** — there is no incident/postmortem log, no external ground-truth feed, no human-authored "this was a miss" marker. Fabricating a recall number from `fired_count`/`never_escalated_count` (e.g., inverting the noise proxy) would silently launder a precision-side signal into a recall-shaped number and mislead exactly the audience (an operator or an agent deciding whether to *loosen* a threshold) this report exists to inform. **The report explicitly renders `recall_proxy: null` with an attached one-line reason string** (`"no ground-truth incident signal available"`) rather than omitting the field or defaulting to a number — omission risks a caller assuming `undefined → 0` or `undefined → not applicable/skip`, whereas an explicit `null` + reason is unambiguous. Precision-adjacent signals (`precision_proxy`) are the only quantitative measure this substrate supports; the report and every consumer of it must not conflate "low precision_proxy" with "we should tighten" — a chronically-firing-but-precise artifact and a chronically-firing-and-noisy artifact both have high `fired_count`, only `precision_proxy` distinguishes them.

---

## 4. Slice 15 — Calibration report (ships first, read-only, foundation for Slice 14)

### 4.1 Goal

`descartes learned calibration [--json] [--since <duration>] [--family <rule_id-prefix>]` — a deterministic, read-only report joining `alerts.json` against outcome signals, producing one `CalibrationRow` per learned artifact/family (§3). Zero mutation. Zero LLM. Day-1 empty → empty report.

### 4.2 Rendering discipline (human-readable mode)

The non-`--json` renderer must, for every row where `llm_namespace_enabled` is `false`/`null`, print an explicit annotation (e.g. `"never_escalated: n/a — provenance namespace not LLM-enabled"`) rather than a bare percentage — directly enforcing the honesty requirement in §3.2. Rows are grouped by `granularity` (`artifact` rows first, `family` rows in their own clearly-labeled section) so the family-level rows for `session.*`/`peer.*`/`correlation.*` are never visually conflated with the per-instance `constraint.*`/`provenance.*` rows.

### 4.3 Files

- **New:** `tools/descartes-cli/src/calibration.js` — `computeCalibrationReport(...)` (pure, §3), `runLearnedCalibration(descartesPaths, args, runtime={})` (CLI handler: loads `learned.json`, short-circuits `{status:"disabled"}` if off; loads `alerts.json`/`llm-decisions.jsonl`/`notification-delivery.jsonl`/`shadow-violations.jsonl` via existing readers; calls `computeCalibrationReport`; renders; appends one summary record via `artifact-audit-store.js`).
- **New:** `tools/descartes-cli/src/artifact-audit-store.js` — `resolveArtifactAuditPaths` (`stateDir/learned/artifact-audit.jsonl`), `appendArtifactAuditRecord(descartesPaths, record)`, `readArtifactAuditRecords(descartesPaths)`. Append-only, `kind`-tagged so S8/S9 (if picked up later) and Slice 14's miner can share the same file without collision: `{ts, kind: "calibration_report" | "tuning_proposal_mined" | "tuning_decision", ...counts-only fields, schema_version}`. **The calibration run's own audit record is `{ts, kind:"calibration_report", window, artifact_count, family_counts:{<rule_id_family>: count}, schema_version}` — counts only, never a re-dump of per-artifact diagnostics** (mirrors the S13 precedent of a prompt-hash instead of a full payload copy, to avoid duplicating sensitive data at rest).
- **Modified:** `index.js` — dispatch `descartes learned calibration` to `calibration.js`; update top-level `usage()`.

### 4.4 TDD test surface

- Proxy math unit tests on synthetic `alerts.json`/`llm-decisions.jsonl` fixtures: `fired_count`, `auto_recovered_fast_count` (boundary at exactly `FAST_RECOVERY_THRESHOLD_MS`), `never_escalated_count` under both `llm_namespace_enabled: true` and `null`, `llm_suppressed_rate` returning `null` (not `0`) when `llm_adjudicated_count === 0`, `precision_proxy` returning `null` when `fired_count === 0`.
- **`precision_proxy` double-count fixture (must-fix, 2026-07-14 review).** An alert that is **both** fast-recovered **and** llm-suppressed must be counted **once** in the `FastOrSuppressed` union, and `precision_proxy` must stay within `[0,1]` for that fixture — asserting the naive-sum bug (`auto_recovered_fast_count + llm_suppressed_count`, which can exceed `fired_count` and drive the proxy negative) is not present in the shipped formula.
- **`never_escalated_count` JSON-null enforcement (must-fix, 2026-07-14 review).** A fixture with `llm_namespace_enabled !== true` asserts `never_escalated_count === null` in the **parsed `--json` output** specifically — a strict `=== null` assertion, not merely "falsy" or "renders as n/a" — proving the honesty fix is enforced in the JSON payload itself, not only the human-readable renderer.
- **`recall_proxy` is always exactly `null` with a reason string** — an explicit assertion, not merely "field is falsy," so a future edit cannot silently start computing a fabricated number without breaking a test.
- Namespace-confounding test: a `session.count_drop` artifact with `fired_count > 0` and zero `llm-decisions.jsonl` entries must render `llm_namespace_enabled: null` and `never_escalated_count: null` (both in `--json` and as a "not applicable" annotation in human-readable mode — not a raw `100%` in either), proving the honesty requirement is enforced in code, not just prose.
- `granularity` correctness: a `constraint.violation.*` row is `"artifact"`; a `session.*`/`peer.*`/`correlation.*` row is `"family"`.
- Day-1 empty: empty inputs → `{ artifacts: [] }`, and the CLI still appends exactly one `artifact_count:0` audit record (proves the report ran, not that it silently no-op'd).
- `learned.json` disabled → `{ status: "disabled" }`, zero reads of `alerts.json` attempted (DI-mockable read functions asserted not called).
- Sanitized diagnostics: any string field in the audit record passes `sanitizeDiagnostics`; a fixture with a raw-path-shaped `rule_id_family` (can't happen from the closed set, but defense-in-depth) gets redacted, proving the gate is live even though it's not the primary control.
- No-LLM static assertion: source-regex/import-graph test on `calibration.js` and `artifact-audit-store.js` mirroring `promotion-store.js`'s existing no-LLM-import test.
- CLI argument parsing (`--since`, `--family`, `--json`) + corrupt-input tolerance (matches the tolerant-read posture of every existing reader).

### 4.5 Safety

Pure read of five existing files + one new append-only counts-only audit record. No mutation of `constraints.json`, `signatures.json`, `authority/promotions.json`, or any live-evaluated state. No LLM import. Gated behind `learned.json`.

### 4.6 Definition of Done

- `descartes learned calibration --json` runs against a fresh install (empty state) and returns `{artifacts: []}` with no error.
- Against a fixture with a chronically-firing `constraint.violation.daemon-config` and a healthy `provenance.process.unknown_identity`, the report correctly computes `chronically_firing: true` for the former and `false` for the latter, with all formulas from §3.2 independently verified against hand-computed expected values.
- A `session.count_drop` row renders `granularity: "family"`, `llm_namespace_enabled: null`, and an explicit "not applicable" annotation for `never_escalated_count` in non-JSON mode.
- Full existing suite stays green; escalation-lint (if applicable to new files) unweakened.

---

## 5. Slice 14 — Outcome-informed compile-down: reviewable tuning proposals

### 5.1 Goal

Turn `computeCalibrationReport`'s output into **inert** `tuning-candidates.json` entries — `draft → review-ready → approved | rejected` — each carrying a deterministic backtest and counts-only justification. **Never auto-applied.**

**v1 scope, resolved (2026-07-14 review — the plan previously told two contradictory stories about non-constraint families; this is now the single, load-bearing one — see §5.2's note and §5.6):** only `constraint.*`-family calibration rows are minable in v1. `retire`/`retune`/`promote_shadow_hint` all require a comparator, an `observedValues` series, and/or a backtest, none of which exist for `provenance.*`/`session.*`/`peer.*`/`correlation.*` rows (§0 points 2–3) — no trigger in §5.2 emits a candidate for any of those four families in v1. Mining them is **Slice 14b** (§9), not this plan. `decideTuningApproval`'s `applied: false` branch is **kept** regardless — not as "the approval path for the other four families" (there is no mining path that reaches it from real v1 usage) but as a **fail-closed dispatch default**: if `decideTuningApproval` is ever asked to decide a candidate whose `kind`/`artifact_ref` does not resolve to a known, live-mutation-capable constraint-family case, the default branch is `applied: false` with an explicit `apply_note` — never a crash, never a silent no-op reporting `applied: true`, and never a fallback that guesses at some other mutator. In v1 this default is exercised only by a **hand-constructed synthetic candidate** in tests (§5.9), precisely because the real miner never produces one — it is defense-in-depth against a future dispatch-table edit gone wrong (§6.3 point 3), not a reachable v1 user flow.

### 5.2 Proposal kinds (closed set)

| `kind` | Trigger (from `CalibrationRow`) | Applies to (v1) |
|---|---|---|
| `retire` | `chronically_firing === true` | `constraint.*` only (`artifact_ref` resolves to an **active** `constraints.json` record) |
| `retune` | `fired_count` between a "some but not chronic" band (`MIN_RETUNE_FIRES ≤ fired_count < MIN_CHRONIC_FIRES`, defaults `2` and `5`) **and** the constraint's comparator is numeric (`gte`/`lte`, never `eq`) | `constraint.*` only, real apply |
| `promote_shadow_hint` | `shadow_fire_rate === 0` **and** full-day coverage already satisfies `checkShadowSoak` **and** (fixed 2026-07-14 review) the constraint's **current status in the live `constraints.json`** is still `"shadow"` at mine-time — checked directly against the live store, not inferred from `shadow_fire_rate` alone, since a constraint may already have been promoted or retired since its `shadow-violations.jsonl` records were written | `constraint.*` in `status:"shadow"` only — **zero live effect ever**, points at the pre-existing `learned soak`/`review`/`approve` commands |
| *(none)* | a row that matches no trigger above, **or** a row whose family is not `constraint.*` (v1 scope, below) | no candidate emitted — "nothing for a healthy artifact," and (v1-scoped) "nothing minable for a non-constraint family" |

**v1 scope note (resolves the contradiction the 2026-07-14 adversarial review flagged between this table and §5.6/§5.11):** only `constraint.*`-family calibration rows reach any trigger above. `provenance.*`/`session.*`/`peer.*`/`correlation.*` calibration rows (§3) are **not** fed to the miner in v1 at all — mining those families is Slice 14b (§9). This is now a single, one-directional scope decision (option (a) from the review): earlier drafts of this plan described both "all triggers are constraint-only" (this table) and "non-constraint families are minable and reviewable, just not appliable" (§5.6/§5.11) in different sections — those two stories contradicted each other and made the non-constraint approval branches unreachable/untestable. This version keeps only the constraint-only story for v1; see §5.6 for how `applied: false` is repurposed as a fail-closed dispatch default rather than a real per-family approval path.

**Deliberately conservative, loosen-only in v1:** `retune` proposals only ever *loosen* a threshold (§5.3) — tightening (which could newly fire on previously-quiet targets) is out of scope for v1 and named as a higher-scrutiny follow-up (§11). `eq`/pattern comparators (categorical) are never retune candidates — only `retire` applies to them.

### 5.3 The backtest (deterministic replay — the concrete meaning of "backtested against historical outcomes")

**Fixed 2026-07-14 review: the original draft replayed the wrong signal.** For a `retune` candidate on constraint `c` (numeric comparator), the backtest must replay the **exact same value-projection the live evaluator uses**, not raw `fact-store.js` records. **Why this is load-bearing, not a style choice:** fact records persist `attributes` as **strings** (`fact-store.js:36` `String`-coerces every value; there is no numeric field), and the live daemon tick does **not** evaluate raw points — the caller of `evaluateConstraints` builds a shared per-tick projection via `buildShadowFactLookup(points)` (`daemon.js:363`), which **excludes degraded observations** (`owner_known:"false"` / `confidence:0`) before handing values to the comparator. `buildShadowFactLookup` is the one and only ACTIVE/SHADOW value projection in this codebase. The original draft reused `evaluateExpected` (the comparator) but re-derived the numeric series independently ("extract the numeric observed values" from raw fact-store points) — that independent derivation would silently diverge from what the daemon actually saw and fed to the live constraint: degraded points that never would have fired live could inflate or deflate the backtest's `observedValues`, corrupting `would_fire_count_current`/`would_fire_count_proposed` in ways a reviewer has no way to detect from the numbers alone. That is not a true backtest.

**Fix:** derive `observedValues` by replaying `c`'s retained fact-history for `c.target` (`readFactPoints`, existing 30-day/5MB window, within the report window) through `buildShadowFactLookup` — the already-exported, shared builder — keyed by `c.target`. **Tick-slicing, specified:** group `c`'s retained fact points into per-tick buckets the same way the live daemon does — by `(entity_key, fact_name)` at each distinct observed-timestamp bucket already present in `facts.jsonl` (no new time-bucketing invented; the existing per-write granularity of `fact-store.js` is the tick) — run `buildShadowFactLookup` over each bucket's points, and take the resulting looked-up value for `c.target` **only when present** (a tick where the target was degraded/excluded is skipped, matching exactly what the live evaluator would have seen — not a gap the backtest introduces). The resulting `observedValues` array is therefore a *true* replay of what the live daemon tick would have handed to `evaluateExpected`, not an independent re-derivation.

```js
// tuning-store.js — pure, deterministic, no I/O
export function proposeRetune(comparator, observedValues, options = {}) {
  const marginPct = options.marginPct ?? 0.05;         // 5% safety margin past the extreme
  if (observedValues.length === 0) return undefined;   // guard (2026-07-14 review): Math.min/max over
                                                        // [] is +/-Infinity -- never propose against no data
  if (comparator === "gte") return Math.min(...observedValues) * (1 - marginPct);  // loosen floor down
  if (comparator === "lte") return Math.max(...observedValues) * (1 + marginPct);  // loosen ceiling up
  return undefined; // categorical -- no numeric retune possible
}
```

**Caveat (negative-value margin, noted 2026-07-14 review):** the `(1 - marginPct)`/`(1 + marginPct)` margin only "loosens away from zero" when the extreme value is positive. For a `gte` floor on a negative extreme (e.g. `Math.min(...observedValues) === -10`), `* (1 - marginPct)` moves the floor **toward** zero — i.e. it *tightens* a negative floor rather than loosening it — and symmetrically for `lte` on a negative ceiling. v1 does not special-case this; it is flagged here as a known sharp edge for any numeric target whose domain includes negative values (none of the currently-seeded constraint targets do, but a future family might) and should be revisited before `proposeRetune` is applied to a target with a negative-valued domain.

```js
export function backtestRetune(observedValues, currentExpected, proposedExpected) {
  // reuses the EXACT comparator logic the live evaluator uses -- requires a small, additive,
  // behavior-preserving export change: constraint-eval.js's currently-private `evaluateExpected`
  // (line 31) gains an `export` keyword (zero logic change; byte-identical regression test required
  // for evaluateConstraints/evaluateShadowConstraints, since both already call it internally).
  const wouldFireCurrent = observedValues.filter((v) => !evaluateExpected(currentExpected, v).satisfied).length;
  const wouldFireProposed = observedValues.filter((v) => !evaluateExpected(proposedExpected, v).satisfied).length;
  return { sample_ticks: observedValues.length, would_fire_count_current: wouldFireCurrent, would_fire_count_proposed: wouldFireProposed };
}
```

This is a *true* backtest: the exact same value-projection (`buildShadowFactLookup`) **and** the exact same comparator function (`evaluateExpected`) the live daemon tick uses, replayed against retained historical observations, comparing the current value against the proposed one. Deterministic (no `Date.now()`/`Math.random()` in the pure functions) — same inputs, byte-identical output, testable directly. **(Citation fix, 2026-07-14 review: an earlier internal note characterizing shadow/backtest evaluation as "not yet wired into the daemon loop" is stale — `buildShadowFactLookup` and the shadow-evaluation path it feeds ARE wired into the live daemon loop today, at `daemon.js:364` (call site) with `extraCandidates` threaded at `daemon.js:505` — this plan's backtest reuses that existing wiring, it does not newly wire anything.)

`retire` and `promote_shadow_hint` candidates have no "proposed value" to backtest in this sense — their "backtest" *is* the calibration proxy counts themselves, already a replay of the historical outcome record (§3), carried into `justification` rather than a separate `backtest` block.

### 5.4 `TuningCandidate` record shape

```
TuningCandidate {
  id,                          // "tuning.<16-hex sha256 of kind\0artifact_ref>" -- FIXED 2026-07-14 review:
                                // deliberately timestamp-free, mirroring minedId(family, entityKey)
                                // (constraint-miner.js:99-102). mined_at (below) is a separate field and is
                                // NOT part of the id -- see the correctness note under mergeMinedTuningCandidates
                                // (§5.5): including mined_at in the id would break idempotent re-mining.
  kind: "retire" | "retune" | "promote_shadow_hint",
  artifact_ref, rule_id_family, granularity,   // mirrors CalibrationRow (§3.1)
  status: "draft" | "review-ready" | "approved" | "rejected",
  current: { expected } | null,      // live snapshot at mine-time (retune only)
  proposed: { expected } | null,     // null for retire/promote_shadow_hint
  justification: {                  // COUNTS/PROXIES ONLY -- no raw diagnostics
    fired_count, auto_recovered_fast_count, never_escalated_count,
    llm_suppressed_count, llm_adjudicated_count, shadow_fire_rate,
    backtest: { sample_ticks, would_fire_count_current, would_fire_count_proposed } | null,
  },
  applied,                     // bool -- see §5.6 (resolved 2026-07-14 review); true ONLY for a
                                // constraint-family retire/retune whose approval actually wrote
                                // constraints.json; false for promote_shadow_hint (by construction,
                                // always) and for the fail-closed dispatch default (v1: the real miner
                                // never emits any other kind, per §5.1/§5.2 -- only reachable via a
                                // hand-constructed synthetic candidate in tests, §5.9)
  apply_note,                  // string | null -- present whenever applied === false, explains why
                                // (e.g. "no live-mutation path for this candidate in v1 -- see
                                // docs/plans/2026-07-14-compile-down-calibration.md §5.1/§9 (Slice 14b)")
  mined_at, backtested_at,
  promotion_history: [{ ts, from, to, actor, note }],  // identical discipline to constraint-store.js
  schema_version,
}
```

### 5.5 Lifecycle (deliberately no "shadow" phase)

`draft → review-ready → approved | rejected`. No shadow phase: the backtest (§5.3) *is* the silent-observation equivalent, computed instantly from retained history rather than requiring a new multi-day live soak — the task's own framing (`draft → review-ready → approved/rejected`) correctly omits it.

- `mineTuningCandidates(constraints, calibrationReport, factHistoryByTarget, options)` — pure, deterministic; the "propose or don't" decision table from §5.2; emits `status:"draft"`.
- `mergeMinedTuningCandidates(existing, mined)` — idempotent merge, mirrors `mergeMinedConstraints` (`constraint-miner.js:222`): new id → added draft; existing draft with the same id → refreshed; anything already `review-ready`/`approved`/`rejected` → untouched. **Correctness-critical (2026-07-14 review, must-fix):** this idempotency depends entirely on `TuningCandidate.id` being timestamp-free (§5.4's corrected id formula). An earlier draft of this plan included `mined_at` in the id hash — that breaks this exact merge: every `tuning mine` run would compute a new id for the same underlying `(kind, artifact_ref)` pair, so the "existing draft same id → refreshed" branch above would **never** trigger, and every re-mine would silently accumulate a duplicate draft forever rather than refreshing the existing one. The id must hash only `kind\0artifact_ref`.
- `promoteTuningDraftsToReviewReady(candidates, options)` — deterministic gate: `backtested_at` set **and** (`justification.backtest.sample_ticks >= MIN_BACKTEST_SAMPLES` default `10`, for `retune`) or (non-null `justification` counts present, for `retire`/`promote_shadow_hint`). Mirrors `promoteDraftsToShadow`'s `MIN_FIXTURE_COUNT` gate shape.
- CLI: `descartes learned tuning mine|promote|review|approve|reject|list [--json]`.

### 5.6 The `applied: false` fail-closed dispatch default (kept as defense-in-depth, not a v1 mining path)

**Resolved 2026-07-14 review (must-fix):** this section previously described `provenance.*`/`session.*`/`peer.*`/`correlation.*` as "minable and reviewable but not appliable," which directly contradicted §5.2's trigger table (constraint-only) and made §5.11's Definition-of-Done item about approving a non-constraint candidate unreachable/untestable — there was no miner path that could ever produce the candidate that DoD item claimed to approve. Per §5.1/§5.2, **only `constraint.*` candidates are minable in v1.** This section is therefore not describing four real, reachable per-family approval branches — it explains why `decideTuningApproval`'s dispatch table still has a fail-closed default branch for anything that is *not* a recognized constraint-family case, even though no v1 miner output can currently reach that branch:

- **`constraint.*` `retire`/`retune`** — `decideTuningApproval`'s approved branch calls `retireActiveConstraint`/`applyApprovedRetune` (§5.7), sets `applied: true`.
- **`constraint.*` `promote_shadow_hint`** — always `applied: false, apply_note: "run 'descartes learned soak' / 'descartes learned review' / 'descartes learned approve' — this hint carries no mutation of its own"`. This is true by construction, not a limitation: this kind is defined to never have a live-mutation branch, ever (§5.8 proves it).
- **Anything else — the fail-closed dispatch default.** Any candidate whose `kind`/`artifact_ref`/family does not match one of the two cases above (a malformed candidate, a future dispatch-table regression, or — in principle — a candidate for a non-constraint family, even though the v1 miner never emits one) falls into an explicit `else` branch: `applied: false, apply_note: "no live-mutation path for this candidate in v1 — see docs/plans/2026-07-14-compile-down-calibration.md §5.1/§9 (Slice 14b)"`. This branch is `applied: false` **by default**, never by accidentally falling through to `applied: true` via a loose match — proven by the fail-closed-default test in §5.9, exercised against a **hand-constructed synthetic candidate** since the real miner cannot produce one in v1 (§5.1).

**Slice 14b (§9)** is where `provenance.*`/`session.*`/`peer.*`/`correlation.*` mining AND their real `applied: true` apply paths would both need to ship **together** — there is no intermediate v1 state where those families are minable-but-inert; per this resolution, they are simply not minable at all yet.

This turns "we haven't built mining or an apply path for 4 of 6 families yet" from a silent gap into an auditable, explicit, testable fact: the miner provably never emits a candidate for those families (§5.9), and even if a malformed or synthetic one is force-fed to the approval gate, the fail-closed default keeps `applied: false` rather than crashing or silently mutating something.

### 5.7 New constraint-store.js functions (the only two ways this plan can ever mutate a live artifact)

```js
// retireActiveConstraint: active -> retired. Disjoint precondition from promotion-store.js's
// existing reject path (review-ready -> retired, for a constraint never promoted) -- these are
// two independent retirement paths for two disjoint lifecycle stages, not duplicate logic.
export function retireActiveConstraint(constraints, constraintId, options = {}) {
  // throws unless the matched record has status === "active"
  // appends promotion_history: { ts, from: "active", to: "retired", actor: "human-cli", note }
}

// applyApprovedRetune: the ONLY code path in the entire codebase that mutates `expected` on an
// already-active constraint record without a status transition (a logged self-loop, not silent).
//
// Shape-validation citation, CORRECTED (2026-07-14 review, must-fix): the original draft claimed
// this "reuses the expected-shape check factored out of validateConstraint" -- no such check
// exists. `validateConstraint` (constraint-store.js:95-97) only asserts `expected` is PRESENT; it
// has no numeric-shape check to reuse. Left unvalidated, a malformed proposedExpected (e.g. a
// stray `eq` comparator, a non-finite value, a missing `value` field) would persist into
// constraints.json fine, then `evaluateExpected` (constraint-eval.js:32-63) would return
// `{supported:false}` on every subsequent live tick -- silently DISABLING a live, already-promoted
// monitor via what looks like a routine tuning approval. applyApprovedRetune therefore performs
// its OWN, NEW numeric-shape validation before writing (not a reuse of anything):
export function applyApprovedRetune(constraints, constraintId, proposedExpected, options = {}) {
  // throws unless the matched record has status === "active"
  // throws / REJECTS (no write, no promotion_history entry) unless proposedExpected is exactly the
  // numeric shape evaluateExpected supports: comparator === "gte" or "lte" (never "eq"/pattern --
  // categorical targets have no retune path, per §5.2), and a finite numeric `value`
  // (Number.isFinite -- rejects NaN/Infinity/strings/undefined). A malformed shape is rejected
  // outright rather than persisted, so a bad retune approval can never silently stop the
  // constraint from firing.
  // appends promotion_history: { ts, from: "active", to: "active", actor: "human-cli",
  //   note: "tuning-approved retune (<tuning_candidate_id>)" }
}
```

Both functions have exactly one legal caller: `tuning-authority.js`'s `decideTuningApproval` approved branch — proven by a call-graph/source-regex test (mirrors `promoteReviewReadyToActive`'s existing "the ONLY code path" doc-comment discipline, `constraint-store.js:499-507`).

**The retune replay guard — a gap the 2026-07-14 review found and closed (must-fix, detailed in §5.8/§6.2).** `applyApprovedRetune` is a **self-loop** (`active → active`, above) — unlike `retireActiveConstraint` (`active → retired`) or `decideConstraintPromotion`'s promotion path (`review-ready → active`), the target constraint's *own* status never changes across a retune approval. That matters because `decideConstraintPromotion` (`promotion-store.js:329-331`) denies unless `constraint.status === "review-ready"`, and that check doubles as a replay guard — a successful approve moves the constraint OUT of `review-ready`, so the same nonce can never match twice. A retune approval has no equivalent second guard on the *constraint's* status, since it never moves. §5.8 pins the fix: the replay guard for retune lives on the **candidate's** status, not the constraint's.

### 5.8 Files

- **New:** `tools/descartes-cli/src/tuning-store.js` — `TUNING_STATUSES`, `validateTuningCandidate`, `loadTuningCandidates`/`writeTuningCandidates` (atomic tmp+rename, `0o600`/`0o700`, corrupt-tolerant — identical discipline to `constraint-store.js`), `resolveTuningStorePaths` → `stateDir/learned/tuning-candidates.json`, `proposeRetune`, `backtestRetune`, `mineTuningCandidates`, `mergeMinedTuningCandidates`, `promoteTuningDraftsToReviewReady`, CLI handlers `runLearnedTuningMine`/`runLearnedTuningPromote`/`runLearnedTuningList`.
- **New:** `tools/descartes-cli/src/tuning-authority.js` — near-structural-clone of `promotion-store.js`'s deny-by-default mechanics, pointed at a **separate** file: `resolveTuningAuthorityPaths` → `stateDir/authority/tuning-decisions.json`, `validateTuningDecisionRecord`, `loadTuningDecisions`/`writeTuningDecisions`, `mintPendingTuningApproval`, `decideTuningApproval(descartesPaths, tuningCandidateId, nonce, decision, options)` (dispatches by `candidate.kind` to §5.7's functions, or no-ops with `applied:false` per §5.6), CLI handlers `runLearnedTuningReview`/`runLearnedTuningApprove`/`runLearnedTuningReject`. Record ids use a distinct prefix (`tuning-approval.<16-hex>`, vs. `promotion.<16-hex>`) — defense-in-depth against ever conflating the two stores even if accidentally read from the wrong file.

  **The replay-guard parity fix, pinned as three explicit rules (2026-07-14 review, must-fix — see §5.7's lead-in and §6.2's proof):** `applyApprovedRetune` is a self-loop (`active → active`) rather than a status transition like `decideConstraintPromotion`'s `review-ready → active` — so if `decideTuningApproval` only checked the *target constraint's* status (a literal clone of the promotion check), it would have **one fewer replay guard** than the pattern it's cloned from: a stale or re-minted `(tuningCandidateId, nonce)` pair could be resubmitted indefinitely against an unchanging `active` constraint. Fix, pinned:
  1. `decideTuningApproval` **denies unless the CANDIDATE's own status** (in `tuning-candidates.json`) **is `"review-ready"`** — not the target artifact's status. This is the replay guard the self-loop shape cannot provide on its own.
  2. A decision (approve or reject) **flips the candidate itself**: `review-ready → approved` or `review-ready → rejected`, appended to the candidate's own `promotion_history` (§5.4). This is what makes rule 1 airtight — once decided, the candidate can never again present as `review-ready`, so a replay of the same `(tuningCandidateId, nonce)` fails rule 1 on the second attempt even though the underlying constraint's status never moved.
  3. `mintPendingTuningApproval` **refuses to mint a new pending-approval record for a candidate that is not currently `"review-ready"`** (mirrors `mintPendingPromotion`'s existing precondition in `promotion-store.js`) — closing the residual gap where a fresh nonce could otherwise be minted against an already-decided candidate and used to re-trigger `decideTuningApproval`.

  Tested explicitly in §5.9 (the retune replay-guard test) — a replayed or re-minted nonce against an already-decided candidate must hard-deny in both forms.

- **Modified:** `constraint-store.js` — add `retireActiveConstraint`, `applyApprovedRetune` (§5.7), appended near `promoteReviewReadyToActive` (current EOF, `constraint-store.js:533`). `applyApprovedRetune`'s numeric-shape validation (§5.7's corrected citation) is a **new** internal helper, not a reuse of any existing `validateConstraint` logic — none exists for this shape.
- **Modified:** `constraint-eval.js` — export the currently-private `evaluateExpected` (line 31) for backtest reuse. Zero logic change; byte-identical regression test on `evaluateConstraints`/`evaluateShadowConstraints`.
- **Modified:** `index.js` — dispatch `descartes learned tuning <mine|promote|review|approve|reject|list>`; update `usage()`.

### 5.9 TDD test surface

All of §4.4, plus:

- **A chronically-noisy artifact → a `retire` proposal.** Synthetic `alerts.json`+`llm-decisions.jsonl` fixture crossing `MIN_CHRONIC_FIRES`/`CHRONIC_NOISE_THRESHOLD` → `mineTuningCandidates` emits exactly one `kind:"retire"` draft for that `artifact_ref`.
- **A healthy artifact → no proposal.** Few fires, high `precision_proxy` → `mineTuningCandidates` returns `[]`.
- **`retune` direction correctness.** A `gte` constraint with observed values clustering below its floor → `proposeRetune` returns a *lower* value; a `lte` constraint clustering above its ceiling → a *higher* value; an `eq`/pattern constraint → `undefined` (no retune candidate emitted, only retire is possible). Include the empty-`observedValues` guard: `proposeRetune(comparator, [])` returns `undefined`, not `±Infinity`.
- **Backtest determinism.** Same `observedValues`/`currentExpected`/`proposedExpected` → byte-identical `backtestRetune` output across repeated calls; no wall-clock/random dependency.
- **Backtest replay fidelity (must-fix, 2026-07-14 review).** `observedValues` must come from replaying historical points through `buildShadowFactLookup` (`daemon.js:363`), not raw `fact-store.js` points read directly. A fixture containing a degraded observation (`owner_known:"false"`/`confidence:0`) at one tick proves that tick is **excluded** from `observedValues`, exactly matching what the live evaluator would have seen — i.e. the backtest's `would_fire_count_current` must match what `evaluateConstraints` would actually have computed against that same historical window, not a naively-re-derived numeric series.
- **THE NEVER-AUTO-APPLY INVARIANT (highest priority test in this plan).** Two-phase: (1) construct a `review-ready` tuning candidate proposing a new `expected` value for an active constraint; call `evaluateConstraints` against current facts; assert the candidate output is **byte-identical** to a run with no tuning candidates present at all (proves architectural blindness, not just "review-ready doesn't trigger a check"). (2) `decideTuningApproval(..., "approved", ...)`; assert `constraints.json`'s `expected` changed; re-run `evaluateConstraints`; assert the **new** value is now the one in effect.
- **Retune replay guard (must-fix, 2026-07-14 review — parity with promotion's status-based replay guard, §5.7/§5.8/§6.2).** (1) Approve a `retune` candidate once; assert the candidate's own status flips `review-ready → approved`. (2) Replay the exact same `(tuningCandidateId, nonce)` pair a second time — assert hard deny, `constraints.json` unchanged the second time. (3) Attempt `mintPendingTuningApproval` again for the same, now-`approved` candidate id — assert it refuses to mint (no new pending record written), proving the guard holds even against re-minting rather than nonce reuse.
- **Malformed-retune rejection (must-fix, 2026-07-14 review).** An approved retune whose `proposedExpected` has a non-finite `value` or an `eq`/pattern comparator is **rejected** by `applyApprovedRetune` (no write to `constraints.json`, no `promotion_history` entry appended); the constraint continues firing exactly as before — `evaluateConstraints` byte-identical before and after the rejected attempt.
- **Idempotent re-mine (must-fix, 2026-07-14 review).** Running `mineTuningCandidates`/`mergeMinedTuningCandidates` twice in a row (different `mined_at` wall-clock, same underlying calibration input) produces exactly **one** draft per `(kind, artifact_ref)`, not two — proving the id is timestamp-free (§5.4/§5.5) and the merge actually refreshes rather than duplicates.
- **Deny-by-default for `tuning-authority.js`**, independently re-verified (not "looks like promotion-store.js so it's fine" — a fresh adversarial pass per §6.1's risk list): missing/expired/wrong-nonce/wrong-status pending record all hard-deny, no fallback grant, mirrored 1:1 against `promotion-store.js`'s existing test suite as a template but run against the new file.
- **Sole-caller proof for `retireActiveConstraint`/`applyApprovedRetune`** — call-graph or source-regex test asserting the only call site in `src/` is `tuning-authority.js`'s approved branch.
- **`promote_shadow_hint` approval is a pure no-op on `constraints.json`.** Byte-identical `constraints.json` before/after approving a `promote_shadow_hint` candidate; `applied === false` asserted.
- **Miner never emits a non-constraint candidate (must-fix, 2026-07-14 review — v1 scope enforced in code, not just documented, per §5.1/§5.2/§5.6).** Feed `mineTuningCandidates` a calibration report containing chronically-firing `session.*`/`peer.*`/`correlation.*` family rows (`granularity:"family"`) that would satisfy the `retire` trigger's numeric conditions if evaluated — assert **zero** candidates are emitted for them.
- **`applied:false` fail-closed-default honesty (must-fix, 2026-07-14 review — synthetic candidate, since v1 mining never produces a non-constraint candidate per the bullet above).** Hand-construct a `provenance.*`/`session.*`-shaped `TuningCandidate` directly in test fixtures (bypassing the miner, which cannot emit one) and approve it through `decideTuningApproval`; assert it falls into the fail-closed default branch (§5.6), leaves `signatures.json`/`session-baseline.js` runtime behavior byte-identical, and `applied === false` with a non-empty `apply_note`.
- **`evaluateExpected` export is byte-identical-behavior.** Existing `evaluateConstraints`/`evaluateShadowConstraints` test suites re-run unmodified and pass after the export-only change.
- **Cross-cutting:** path-no-double-nest (`stateDir/learned/tuning-candidates.json`, `stateDir/authority/tuning-decisions.json`); atomic write + corrupt-tolerance for both new stores; sanitized-diagnostics fixture (a raw-path-shaped justification value gets redacted); no-LLM static assertion on `tuning-store.js`/`tuning-authority.js`; full existing suite + escalation-lint stays green.

### 5.10 Safety

Same spine as §1/§4.5, plus: the two new mutators are the entire attack surface for a live-value change, both single-callsite, both precondition-gated on `status === "active"`, both reached only through the cloned deny-by-default gate. See §6 for the full proof.

### 5.11 Definition of Done

- `descartes learned tuning mine` against the §5.9 chronically-noisy fixture produces exactly one `review-ready`-eligible `retire` draft with a populated `justification`; against a healthy fixture, produces nothing.
- The never-auto-apply invariant test (§5.9) passes: a `review-ready` proposal provably does not change `evaluateConstraints`'s output; an `approved` one provably does, and only after `decideTuningApproval`.
- `descartes learned tuning approve <id> --nonce <n>` on a **hand-constructed synthetic** non-constraint-family candidate (fixed 2026-07-14 review: there is no v1 miner path that produces one — see §5.1/§5.6) completes successfully via the fail-closed dispatch default, sets `applied: false` with a specific `apply_note`, and leaves every live store byte-identical — proving the default branch is safe even though it is not reachable from real v1 usage.
- Full existing suite green; escalation-lint unweakened; no new path escapes `stateDir/`/`configDir/`.

---

## 6. The never-auto-apply enforcement — deep dive (the critical safety design)

### 6.1 Why a separate store, restated precisely

`decideConstraintPromotion` (`promotion-store.js:312-396`) is hardcoded to (a) require `constraint.status === "review-ready"`, (b) on approval call `promoteReviewReadyToActive` — which only ever sets `status: "active"`, never edits `expected` — and (c) on rejection, hardcode `status: "retired"` inline. None of these three behaviors are what a `retune` approval needs (edit `expected`, no status change) or what a `retire`-of-an-**already-active**-constraint needs (precondition `status === "active"`, not `"review-ready"`). Retrofitting a `type` branch into this function means re-reviewing an already `OVERALL_SAFE`-verified, safety-critical function's control flow for a second time, with regression risk to the existing artifact-promotion path. A structurally near-identical **but separate** module (`tuning-authority.js`) costs some code duplication (nonce/expiry/validate/write plumbing, ~150-200 lines) in exchange for **zero regression risk to the shipped, verified gate**, and matches the precedent the roadmap already set for witr's approval store (§6 of the roadmap: "any future merge requires a closed `type` discriminant… we do not merge now").

### 6.2 The proof that a draft/review-ready proposal cannot change a live threshold

Three independent layers, not one:

1. **Architectural blindness (strongest).** `evaluateConstraints` (`constraint-eval.js:114`) and every daemon-loop caller of it have **zero import** of `tuning-store.js` or `tuning-authority.js`. The live evaluation path does not merely "check a status field and ignore drafts" — it has no code path capable of reading `tuning-candidates.json` at all. A tree-wide import-graph assertion (`grep`-based test, same style as `promotion-store.js`'s existing no-LLM-import test) proves this at CI time, not just by inspection.
2. **Single legal mutator, single legal caller.** `retireActiveConstraint`/`applyApprovedRetune` are the only two functions in the codebase that can change a live constraint's `status`-to-`retired` (from `active`) or `expected` value. Both are called from exactly one place: `decideTuningApproval`'s `"approved"` branch. No miner function, no `promoteTuningDraftsToReviewReady`, no CLI `list`/`review` command touches `constraints.json`'s write path.
3. **Deny-by-default at the one legal entry point.** `decideTuningApproval` requires an exact `(tuningCandidateId, nonce)` match against a `status:"pending"`, unexpired record in `authority/tuning-decisions.json` — cloned verbatim from `matchPendingPromotion`'s proven-safe logic (`promotion-store.js:237-247`: "every other case — no record, wrong nonce, expired, already decided — returns undefined; callers MUST treat 'no match' as a hard deny, never a fallback grant"). There is no code path where a `review-ready` status alone, without a matching approval record, reaches either mutator.
4. **The candidate-status replay guard — a fourth check this plan's own 2026-07-14 review found missing from a naive clone (must-fix; pinned in §5.7/§5.8).** `promotion-store.js`'s `decideConstraintPromotion` gates on `constraint.status === "review-ready"`, and because a successful approve moves the constraint OUT of `review-ready` (into `active`), that same check doubles as a replay guard. `applyApprovedRetune` is instead an `active → active` **self-loop** (§5.7) — the target constraint's own status never changes across an approval — so checking only the target's status would give `retune` approvals **one fewer replay guard** than the pattern they're cloned from, and a stale nonce could be resubmitted indefinitely. `decideTuningApproval` closes this by gating on the **candidate's own** status (`review-ready`, flipped to `approved`/`rejected` on decision, §5.4) as an independent replay guard layered on top of layer 3's nonce/expiry check.

The TDD invariant test in §5.9 empirically exercises layer 1 (byte-identical evaluation output with a pending proposal present) and layers 2/3/4 together (the value only changes after the full approve flow, and a replay or re-mint against an already-decided candidate hard-denies) — this is a behavioral proof, not just a structural one.

### 6.3 Top 3 safety risks for adversarial review

1. **Never-auto-apply enforcement correctness.** Specifically: (a) the import-graph assertion that `evaluateConstraints`/daemon-loop code has zero reference to `tuning-store.js`/`tuning-authority.js` must be re-verified, not assumed from "it's a new file so nothing imports it yet" — a future refactor could accidentally wire a read; (b) the sole-caller proof for `retireActiveConstraint`/`applyApprovedRetune` needs its own adversarial pass, not just a unit test that happens to pass; (c) `tuning-authority.js`, despite being a near-clone of an already-verified file, is a **fresh copy** and copy-paste safety-critical code is exactly the category of bug (e.g., an accidentally-loosened status check, a nonce-comparison that silently allows a partial match) that a structural clone can reintroduce even when the source was safe — it needs its own independent deny-by-default adversarial verification, not a "looks the same, ship it" pass; (d) **(added 2026-07-14 review)** the retune-specific candidate-status replay guard (§5.7/§5.8/§6.2 layer 4) is itself a *new* safety-critical mechanism this review's must-fix introduced — not present in the pattern being cloned, since `applyApprovedRetune`'s self-loop shape has no natural equivalent of promotion's constraint-status guard. It must be re-verified independently at implementation time with the same rigor as (a)–(c), not assumed correct merely because it is now documented and has a named test (§5.9).
2. **Honesty of the precision/recall proxy.** Specifically: (a) `recall_proxy` must render as an explicit `null` + reason in every code path, never a fabricated number under any input, including edge cases (all-zero data, a single artifact, a family with no LLM adjudication at all) — this needs an exhaustive-input adversarial check, not just the one happy-path test in §4.4; (b) **(fixed 2026-07-14 review, was open as a risk, now closed at the JSON level)** `never_escalated_count`'s namespace-confounding (§3.2) no longer relies on prose or renderer discipline alone — `never_escalated_count` emits as an explicit JSON `null` whenever `llm_namespace_enabled !== true`, verified by a strict `=== null` test (§4.4), so a downstream agent consuming `--json` output cannot observe a fabricated "100% never-escalated" number for a structurally-unreachable namespace even without reading the human-readable annotations. **Re-verify at implementation time**, though: a serialization quirk (e.g. a naive object-spread or a library that drops explicit-`null` keys) could turn an emitted `null` into an *omitted* key, silently reopening the exact ambiguity ("is this `undefined` because it's null, or because the field was dropped?") the fix is meant to close — the test must assert the key is *present* with value `null`, not merely that reading it yields a falsy value; (c) `fired_count`'s flapping-undercount limitation (§3.2) — direction now stated explicitly: it biases `chronically_firing`/`retire` toward **non-action** (fail-safe), but can misroute a genuinely chronic, same-fingerprint-flapping artifact into the `retune` band (2–4 fires) instead of `retire` — worth an adversarial fixture explicitly constructing this case to confirm the backtest (§5.3) and the mandatory human review together catch what the proxy alone misses, rather than assuming `chronically_firing` always catches it via `precision_proxy`.
3. **Family/artifact granularity conflation and the `applied:false` fail-closed default.** **(Reframed 2026-07-14 review to match the resolved v1 scope, §5.1/§5.2/§5.6 — the miner no longer has a code path that could even attempt to emit a non-constraint `retire`/`retune`, so this risk is now about proving that absence, not about a dispatch-table branch that has to catch a leak.)** Specifically: (a) the closed-set gate must be adversarially tested against a `session.*`/`peer.*`/`correlation.*` calibration row that happens to look chronically-firing — proving `mineTuningCandidates` **never emits** a candidate for a family with no backing mutable `constraints.json` record at all (v1 resolution: these families are not minable, not "minable but inert" — §5.9's dedicated test); (b) the `applied:false`/`apply_note` **fail-closed dispatch default** in `decideTuningApproval` must independently be proven tamper-resistant to a careless future edit — e.g., a test asserting that even if `decideTuningApproval`'s dispatch table is extended sloppily for a new family, the default/fallback branch is fail-closed (`applied:false`) rather than fail-open (silently calling a mutator that doesn't exist or, worse, an unrelated one via loose family-string matching) — exercised via the **synthetic candidate** from §5.9 since no real v1 flow reaches this branch.

---

## 7. New/changed files summary

| File | Status | Purpose |
|---|---|---|
| `tools/descartes-cli/src/calibration.js` | new | S15 report computation + CLI |
| `tools/descartes-cli/src/artifact-audit-store.js` | new | shared `artifact-audit.jsonl` append-only store |
| `tools/descartes-cli/src/tuning-store.js` | new | S14 `tuning-candidates.json` lifecycle + miner + backtest |
| `tools/descartes-cli/src/tuning-authority.js` | new | S14 deny-by-default approval gate, separate from `promotion-store.js` |
| `tools/descartes-cli/src/constraint-store.js` | modified | + `retireActiveConstraint`, `applyApprovedRetune` |
| `tools/descartes-cli/src/constraint-eval.js` | modified | export `evaluateExpected` (byte-identical behavior) |
| `tools/descartes-cli/src/index.js` | modified | dispatch `learned calibration`, `learned tuning <verb>`; usage update |

No changes to `alert-store.js`, `alert-intelligence.js`, `promotion-store.js`, `daemon.js`, any collector, or any tool-policy surface.

---

## 8. Build order & one-plan-vs-two-slices

**S15 (calibration) ships first, S14 (compile-down) second — enforced by the import graph, not just sequencing convention:** `tuning-store.js`'s miner literally calls `calibration.js`'s `computeCalibrationReport` as a library function to source its `justification` counts. S14 cannot be built, let alone tested, without S15 existing first. This is the concrete argument beyond "S15 is conceptually foundational."

**One dedicated plan file, two atomic shippable slices.** The two are documented together because they share the entire outcome-signal inventory (§2), the `CalibrationRow` shape (§3), and the safety spine (§1) — splitting into two plan files would duplicate all of that. They ship as **separate commits**: S15 lands as a complete, independently useful, read-only report with zero dependency on anything new besides existing readers; S14 lands additively on top, introducing the two new stores and the two new constraint-store.js mutators. This matches the roadmap's own "each slice independently shippable, TDD-first, atomic-commit-sized" discipline (§8 header).

---

## 9. Follow-ups / explicitly out of scope (named, not silently dropped)

- **Slice 14b — mine AND extend real `applied:true` apply paths for non-constraint families, together.** **(Scope corrected 2026-07-14 review, must-fix 6: v1 does not mine `provenance.*`/`session.*`/`peer.*`/`correlation.*` at all — §5.1/§5.2/§5.6 — so Slice 14b owns both halves, not just the apply side.)** Requires: (0) mining triggers for these families — comparator-free equivalents of §5.2's table, since none of these families have a numeric comparator/`observedValues`/backtest shape; (a) a live-patch function in `provenance-store.js` analogous to `applyApprovedRetune` for signature grace-window/threshold params; (b) a persisted per-family tuning-override store (or a new section of `configDir/learned.json`) that `daemon.js`'s `computeSessionBaselineCandidates`/`computePeerBaselineCandidates`/`computeCorrelationCandidates` call sites (`daemon.js:504-533`) read and thread into their existing `options.deviationSigma`/`options.minSampleCount`/etc. parameters (the function signatures already accept these as DI overrides — confirmed: `session-baseline.js:428`, `computeSessionBaselineCandidates(descartesPaths, options={})` — only the read-seam from a persisted, approved value is missing). Mining without an apply path (or vice versa) is exactly the two-contradictory-stories problem this plan's 2026-07-14 adversarial review flagged and resolved by deferring both together — Slice 14b ships them as one unit, not two. Each is its own reviewed change to a daemon-loop call site, at the same safety bar as S13's namespace-dispatch change.
- **Tightening retune proposals.** v1 only ever loosens a chronically-firing numeric threshold (§5.2). Proposing to *tighten* a threshold (e.g., an under-sensitive constraint that should fire more) is a materially different risk shape — it could newly fire on previously-quiet targets — and deserves its own scrutiny pass before being added, not bundled into this plan.
- **Roadmap Slices 8–9 (self-audit: fixture-regression replay, `staleness`, `contradiction`, `learned.health.*`/`learned.audit.*`).** Not built by this plan; `chronically_firing` (§3.3) is a narrow, locally-scoped proxy for this plan's own needs, not a substitute for that still-unpicked work.
- **`alerts.json` retention.** If a retention/eviction mechanism is added to `alert-store.js` later, the calibration window narrows automatically; if none is ever added, `--since` remains the only way to bound the window as `alerts.json` grows unboundedly. Worth a follow-up note in that file's own plan, not this one.

---
