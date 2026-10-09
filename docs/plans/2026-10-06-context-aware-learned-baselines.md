# Context-aware learned baselines

**Created:** 2026-10-06
**Status:** DRAFT v3. Designed to the operator decisions of 2026-10-06 (below), with the v2 re-review and the F-class opinions folded in. The remaining operator questions are in §16.
**Reviewed:** 2026-10-06 (gpt-6-astra xhigh + Opus 5.5 max; v1 NEEDS-REVISION 16 / 9)
**Reviewed:** 2026-10-06 (v2 re-review, Opus 5.5 max; NEEDS-REVISION 5: B1, H1–H4)
**Reviewed:** 2026-10-06 (F-class opinions, gpt-6-astra xhigh + Opus 5.5 max; both ALLOW WITH CONDITIONS)
**Revised:** 2026-10-06 (v2)
**Revised:** 2026-10-06 (v3 — operator decisions + v2 re-review + F-class opinions)
**Origin:** `todos/2026-10-06-session-peer-tuning.md` (operator reframe, 2026-10-06). This plan realizes Slice 12 of `docs/plans/2026-07-09-self-learning-stratified-monitoring.md:183` and generalizes it from time to all context.

**Inputs to v3:**
- Operator decisions D1–D4 (2026-10-06), recorded in the next section.
- v2 re-review: `docs/reviews/2026-10-06-context-plan-v2-rereview-opus.md` (B1, H1–H4, M1–M9, L1–L4).
- F-class opinions: `docs/reviews/2026-10-06-f-class-opinions.md` (Astra and Opus).
- v1 plan reviews: `docs/reviews/2026-10-06-context-plan-review-astra.md` (Astra 1–16) and `docs/reviews/2026-10-06-context-plan-review-opus.md` (B1, H1–H8, M1–M11, L1–L6).
- Principle audits: `docs/reviews/2026-10-06-learning-principle-audit-astra.md` and `docs/reviews/2026-10-06-learning-principle-audit-opus.md`.
- `docs/design/autonomy-doctrine.md`.
- Every finding is dispositioned in Appendix A.

**Depends on / relates to** (branch tips read for v3):
- `feat/fact-store-capacity-2026-10` @ 2dce005 (daybreak G3 READY, not merged): per-family stores, `fact-families.js`, `RULE_HORIZONS`, seen-sets. It also rewrites the session, peer and service baselines, `alert-store.js` and `daemon.js` (+715/−190 lines across those five files). **C1a and C2 are sequenced after it merges** (§14, H3).
- `feat/notify-once-2026-10` @ 25cf225 (not merged): R3, redesigned to **producer-declared `incident_key` episodes** with a single-writer daemon. This plan references it and does not duplicate it (§9, §12).
- `fix/collector-sources-2026-10` @ 3c18739 (not merged; worktree `.claude/worktrees/collector-sources`): pinned absolute-path binaries with writer-set trust (Opus H6), the real-output scutil parser (Opus H5), and census states that treat `not_found_on_known_paths` and `untrusted_binary` as incomplete, never as a zero. This plan adds one requirement to it before merge (C0.1b, M7).
- The trusted-state Phase 3 boot-identity primitive (`docs/plans/2026-09-06-trusted-state-step-1.md` §5.3, :141-148, open question 2 at :301) and `todos/2026-09-08-clamp-boot-identity-guard.md`. The primitive is built once and shared. It already relies on what v3 names F2 (§7.8).

**Verification note.** Claims marked *(verified 2026-10-06)* were checked for v2 against `main` @ daff6ed. Claims marked *(verified v3)* were checked for v3 against `main` @ 1ac41a2 (its code is identical to daff6ed: only docs changed in between), and against the three branch tips above, or on this dev host. The dev host is a Darwin 25.2 VM and is **not a corpus**:
- Its last boot was 2026-09-04 (`kern.boottime`), which is outside the 30-day retention.
- It has never slept (`kern.sleeptime` = `kern.waketime` = 0).
- Opus M7 found its structural checkpoint stale since 2026-10-05.

---

## Operator decisions (2026-10-06)

**Provenance.** These decisions were given by the operator during the 2026-10-06 planning session and relayed to this revision. They are not yet recorded in `todos/2026-10-06-session-peer-tuning.md`, whose decision table stops at R3–R10. Recording them there is an operator action (§16).

| # | Decision | Answers | Design consequence | Doctrine amendment to draft |
|---|---|---|---|---|
| **D1** | **Novelty is pending until explained.** This reverses the 2026-09-27 one-tick-recovery design (HANDOFF 2026-09-27; `service-baseline.js:455-476`). An explanation is one of: a context fact, an operator label, or bounded quiet. **Later**, federated layers may match known patterns or signatures as a further explanation source. | v2 Q4 | §6.3 admission paths; §6.6 novelty lifecycle; the closed set of explanation sources, with `federated_signature` reserved as an interface only (§6.3.1) | **DA3**: bounded on-host admission (re-review M4) |
| **D2** | **Replacement authority is a per-host opt-in envelope**: operator-ratified, reversible, set per host and per detector family. The old detector stays in code. Post-promotion refits are bounded by a cumulative drift budget anchored to the ratified snapshot. | v2 Q2 | §11.2, §11.3, C7b | **DA1**: replacement envelope |
| **D3** | **Shadow learners are default-on.** They raise no alerts of their own until promoted. This needs a policy amendment, strict compute, time and memory bounds, a kill switch, and no effect on the incumbent detectors. | v2 Q1 | §7.7, §13, C5 | **DA2**: default-on shadow |
| **D4** | **The F class is delegated to the reviewers.** Both said ALLOW WITH CONDITIONS, so v3 adopts exactly their narrowed form: F1 process instances are boot-scoped, as a *constraint* on what an observation means, never as an explanation or arbitration authority; F2 clock domains are boot-scoped; F3 suspend clock semantics; F4 suspend and hibernate preserve instances and boot identity, so a sleep never explains a departure; F5 is deferred. Every admission criterion, rejection, must-stay-scored item and test in the opinions is adopted. | v2 Q3 | §0.4, §7.1, §7.6, §7.8, I33, I36–I41 | None. Each fact needs its own F-card, daybreak review and operator ratification (§7.8.5). |

**The doctrine amendments are drafted, not enacted, by this plan.** DA1–DA3 are written as a separate reviewed change to `docs/design/autonomy-doctrine.md` (step DA, §14). Every step that depends on an amendment says so, and ships its amendment-free subset until the amendment is ratified.
- **DA1** (D2). Replacement reduces what alerts, which the doctrine places above the on-host ceiling (`autonomy-doctrine.md:61-68,126-129`). The amendment scopes an operator-accepted exception: per host, per detector family, ratified once, reversible by a routing flip, with the incumbent kept in code and in shadow.
- **DA2** (D3). "Default-OFF behind the `learned.json` kill switch" (`:134`) is narrowed: it keeps covering agent authoring and any model with alert authority. Declared shadow learners, which have no authority, may run default-on under `watch` within S resource bounds and behind their own kill switch.
- **DA3** (D1; re-review M4). Admitting unattested observations into an authority-bearing baseline is sticky adaptation, which the doctrine gates on attestation (`:103`, `:126-129`). D1 accepts on-host admission by context explanation, label and bounded quiet **for novelty**. v3 extends the same bounded mechanism to the incumbent statistical folds (§6.5, inherited from v2's path 3); ratifying DA3 is where the operator confirms or rejects that extension, and until then the folds admit by label only. The amendment records that as an explicit exception bounded by an S mechanism: the drift budget, the label budget, the `admitted_unexplained` log and digest, and reversibility of every admission. It is not a silent O constant.

---

## 0. Core principle

### 0.1 The test every section must pass

Descartes is a system that **learns and adapts**. It needs **data**, **context awareness** and **the ability to learn**. It must not become an expert system, meaning a growing set of hand-written rules and magic thresholds that encode a human's (or an AI assistant's) guesses about what is normal on this machine. Real attacks unfold over days, so memory must be long.

### 0.2 What that means here

- **P1. Data, not behaviour rules.** This plan adds data and the ability to use it. It adds no "suppress X after reboot", no "ignore peers after wake", no "critical only if ≥ N". The rejected R4–R10 stay rejected. Appendix A checks that v3 reintroduces none of them. A hand-written "X explains Y" mapping is a behaviour rule and is never an explanation (§6.3).
- **P2. The machine weighs context, within a declared hypothesis space.** The plan offers candidate context and the learner decides how much each candidate matters. The plan states plainly what the learner *cannot* learn: the representation is a declared hypothesis space (class H, §0.4). Raw resolution is retained so that alternative representations can be learned later.
- **P3. Long memory stays and grows.**
  - Raw facts are kept for 30 days (`fact-store.js:18`; capacity `fact-store.js:31`). The 31-day constant at `welford-stats.js:20` is a read window, not retention (Opus L4).
  - On top of that come a compact per-tick summary family, long-lived sufficient statistics, durable reference snapshots and the pending ledger, all of which outlive the raw window (§6.4, §8).
  - Aging out of the raw window is never an explanation (H2). A boot never resets or partitions memory (F-class opinions, Opus §2).
- **P4. Safety invariants stay**: never fabricate; completeness, freshness, coverage and integrity gates; resource bounds; privilege hardening. The doctrine's authority ceiling also stays: on-host, the ceiling is additive alerting (`autonomy-doctrine.md:61-68`). Anything that reduces what alerts is governed by §11 and DA1.
- **P5. Adaptation is arbitrated, never automatic** (`autonomy-doctrine.md:101-116`). Today the default tier adapts with no gate at all (§1.3). v3 fixes that for the statistical folds and, under D1, for novelty (§6.3–§6.6, C1a).
- **P6. Process rule.** A calibration finding becomes a missing-data or missing-context work item. It never becomes a new threshold or suppression (Opus audit §4 item 5).

### 0.3 Evidence limit (stated, not hidden)

No statistical method can tell a benign event from a malicious one when both produce identical observed evidence (Astra 4). Context-aware scoring raises the attacker's cost: they must reproduce a familiar transition, at a familiar time, with the familiar response. It does not make attacks impossible. Attacks that are indistinguishable from benign behaviour are an accepted evidence limit, not a defect to be patched with a rule.

The same limit applies at a boot: "sessions alive at 12:00, reboot at 12:30, absent at 13:00" cannot distinguish a 12:15 kill from termination by the reboot. Neither F1 nor a pure learner can recover information that was never observed (F-class opinions, Astra §2). v3 shrinks the unobserved gap with data (a +0 boundary census) and reports the remainder as abstention, never as "explained" (§7.8.3).

### 0.4 Classes

Every choice in the design is classified as one of the following. Anything unclassified is a defect.

| Class | Meaning | Obligation |
|---|---|---|
| **S** | Safety, integrity or authority invariant, a resource bound, or an admission **mechanism** | Never learned away. Exhaustion is visible. |
| **P** | A bootstrap prior that data overrides | Publish its strength and its time-to-override (§7.6). Provide a fixture showing contrary data wins. |
| **O** | Operator attention or authority policy: a **parameter** of an S mechanism, set once in the policy envelope | It is never a claim about the machine. It may *size* an S admission mechanism (the bounded-quiet period, the drift-budget size, the label budget), but it never *defines* admission, recovery, or what counts as a benign label (re-review M4). |
| **H** | Declared hypothesis space: the vocabulary, model families and resolutions | Stated as a limit of what can be learned. Raw resolution is retained so the space can be widened later through `model-ir` composition (doctrine :33). |
| **F** | An OS-semantics constraint, admitted per fact under §7.8 (D4) | It fixes what an identifier can mean and which observations can inform which parameter. It never says what is usual, expected or benign. It never recovers, closes or admits anything. A contradiction fires an integrity tripwire. It is inactive until its own F-card is ratified. |

**Amended from v2 (M4).** v2 said O "never controls training admission" while classing the bounded-quiet period, drift-budget size and label budget as O. v3 makes each admission mechanism S (I19, I20, I27) and keeps only its size as O. On-host admission itself is the doctrine exception DA3: accepted by the operator in D1 for novelty, and proposed for the statistical folds pending DA3 ratification.

### 0.5 Executable inventory

Each row becomes a named test in C0. Tests start pending, and the step that implements a row turns its test green. "Data can override" asks whether this host's own data can change the outcome. Rows I1–I35 keep their v2 numbers; I36 onward are new in v3.

| # | Choice | Class | Data can override? | Counterexample fixture |
|---|---|---|---|---|
| I1 | 30-day raw retention (`fact-store.js:18`), per-family budgets and entity caps (capacity `fact-families.js:240-249`) | S | No, by design. Exhaustion surfaces as `horizon_short`. | `inv_retention_exhaustion_visible` |
| I2 | `tick_summary` record ≤ 1 KiB with explicit per-field caps; T8 floor with a records-per-interval term; horizon ≥ 30 d registered in `RULE_HORIZONS`; per-family retention | S | No | `t8_tick_summary_worst_case`, `t8_records_per_interval`, `inv_summary_horizon_registered`, `inv_summary_field_caps` |
| I3 | Caps on long-lived statistics, reference snapshots and the pending ledger | S | No | `inv_longlived_cap_evicts_visibly`, `pending_overflow_fails_closed` |
| I4 | Candidate context vocabulary (§5) | H | Partly. Any dimension can shrink to ~0; a dimension outside the vocabulary can never be added. Dimensions never observed on this host are excluded from the host's vocabulary; their appearance is a structure-version change (H1). | `inv_irrelevant_dim_shrinks`, `inv_outside_vocab_documented`, `inv_never_observed_dim_excluded` |
| I5 | No dimension derived from the same **physical object** as a target it conditions, checked by field provenance, not by family (M6). `session_origin_mix` is removed; VPN-service state leaves the peer population; a WireGuard link is not context for its own peers; the Tailscale network-extension service is not context for the tailnet. | S | No | `inv_no_target_derived_dim` (static check over field-provenance tags), `inv_wg_link_not_context_for_wg_peers` |
| I6 | `since_*` bucket edges | H | Not within one structure version. A new version can re-bin from the retained raw seconds. | `inv_rebin_from_summary` |
| I7 | `net_config` top-K | K is S. The frequency ranking is learned in-fold. Pooling rare values into `other` is H. | Ranking yes, pooling no | `inv_topk_fitted_in_fold`, `cc_l_new_network_raises` |
| I8 | Hour-of-week (168 cells) partially pooled toward hour and day-of-week. This replaces weekday/weekend. | H | Yes: pooling merges days the host treats alike | `inv_tue_sat_schedule_learned` |
| I9 | Lattice back-off order | Eliminated by soft structure (§7.4) | n/a | `inv_dim_order_invariant` |
| I10 | Pooling strength (hyperprior) | P | Yes in dense cells. TTO is published, and prior-governed cells are labelled as such. | `inv_prior_overridden_dense_cell`, `inv_tto_reported` |
| I11 | Complexity penalty for hard selection | Removed (no hard keep/drop) | n/a | none |
| I12 | Model families (hazard, Poisson, smoothed categorical), plus an adequacy gate: PIT calibration; the mandatory scenario drops flagged at the stream's α_i; the verdict stable under ×0.1 / ×10 prior sensitivity. **No incumbent constant is the bar** (M3). | Families H; gate S; α_i O | A family that fails adequacy is ineligible | `adequacy_stable3_to0`, `adequacy_5_to_2`, `adequacy_excess_zeros`, `adequacy_regime_change`, `adequacy_prior_sensitivity_stable` |
| I13 | Aftermath shape | Learned. No shape is placed in initialisation, fixtures or admission rules. | Yes | `inv_inverse_aftermath_learned` (a host whose sessions *rise* after boot learns that) |
| I14 | Interval-event covariates (boot, suspend or transition inside the interval) | H | Their effects are learned and may be ~0 | `inv_boot_flag_effect_learned` |
| I15 | Transition-triggered census samples at **+0**, +2 and +10 min. The +0 sample is the boundary census (F-class opinions, Opus §2). | Offsets H; cost cap S (≤ 3 per transition, ≤ 4 extra per hour) | No | `inv_extra_samples_capped`, `inv_boundary_census_at_plus0` |
| I16 | Support floor before a cell counts as "evaluated" for recovery | S | No | `cc_l_*` (§6.2) |
| I17 | Coverage contract v3: stream kinds, CC1–CC8 | S | No | `cc_l_*`, `cc_e_*` (§6.2) |
| I18 | Pending state under arbitrated adaptation. It restricts authority; it is not a claim that the data is malicious. | S | No | `arb_alarmed_tick_not_folded`, `arb_pending_retained_for_challenger` |
| I19 | Bounded-quiet admission. The mechanism is S; the period is O. On-host admission is the doctrine exception DA3 (D1). For a sustained shift, quiet is measured on the stability of the new level (H2). | Mechanism S; period O | No (policy) | `arb_quiet_admission_consumes_budget`, `arb_sustained_shift_quiet_on_new_level` |
| I20 | Drift budget: mechanism, measure and size. Measures per kind: learned predictive divergence on reference cells; incumbent Welford |Δμ| in the incumbent's own z units; admitted unexplained entities per novelty family. | Mechanism S; measure H; size O | No | `drift_chain_exhausts_budget`, `drift_incumbent_anchor_measure`, `drift_seen_set_admissions_counted` |
| I21 | Novelty probability. Its own rate is scored for drift against the anchor, so toggling cheap dimensions cannot make novelty unremarkable (L3). | Learned (Good–Turing) | Yes | `inv_novelty_rate_learned`, `inv_novelty_rate_drift_scored` |
| I22 | Handling of `new`, `unknown`, `other` and `unstable`. `not_applicable` and a stable not-found are known values (H1). | S: they back off for raising, never go silent, and never recover | No | `cc_l_unknown_context_freezes`, `cc_l_new_network_raises`, `cc_l_not_applicable_is_known` |
| I23 | TTO definition, pinned (L1): for a Gamma(a0, b0) rate, data outweighs the prior once accrued exposure ≥ b0 **and** observed events ≥ a0; for a Beta(α0, β0) probability, once trials ≥ α0 + β0. Wall time is reported by dividing by the host's observed accrual rate. | S (an honesty-reporting rule) | No | `inv_tto_reported`, `inv_tto_units` |
| I24 | Clock-step detection resolution | S (measurement resolution, not a claim about normal) | No | `l1_clock_step_detected`, `l1_no_false_step_on_suspend` |
| I25 | Per-collector sub-deadlines | S | No | `c0_context_timeout_keeps_census` |
| I26 | Components of the network-configuration fingerprint | H | No | `c0_fingerprint_component_availability` |
| I27 | Label-poisoning bound | Mechanism S; label budget O | No | `label_burst_held_pending` |
| I28 | Surprise → notification (α allocation, N per week) | O. It never deletes a detection. | No | `budget_does_not_delete_detection`, `budget_not_raised_by_flood` |
| I29 | Surprise → severity mapping. Corroboration counts **distinct evidence sources**; a shared context event counts once (M2). | Mapping O; counting rule S | No | `severity_mapping_declared`, `corroboration_shared_context_counted_once` |
| I30 | Promotion bars | Minimum evidence S; operator tolerance O | No | `ladder_rejects_without_preregistered_evidence` |
| I31 | Fit cadence and runtime limits | S | No | `fit_abort_keeps_last_version`, `t9_read_cost` |
| I32 | `host.daemon_gap` | A fact only, never an alert from L1 | n/a | `l1_no_alert_candidates` |
| I33 | **F1: process instances are boot-scoped** (renamed from v2's "a boot ends all processes"). A constraint on observation meaning: across a verified boot boundary, instance identity is never compared and boundary-crossing departures leave the hazard likelihood. It never recovers, closes or admits. | F (per-fact ratification pending) | No: a contradiction is an integrity tripwire, not a learning signal | `f1_*` (§7.8.6). While F1 is inactive: `f1_kill_switch_reverts` (option D fallback) |
| I34 | R3 notify-once, with **producer-declared `incident_key`** episodes (`feat/notify-once-2026-10` @ 25cf225) | O | No | Tests on `feat/notify-once-2026-10` |
| I35 | Incumbent constants: σ 3/5, floor 0.5, N 30, `CORRELATION_ODD_HOURS`, R8 | Unchanged by this plan (the audits class them A/C). They are not an adequacy bar (M3). | No | None. They are retired only by per-host routing under C7b. |
| I36 | **F2: clock domains are boot-scoped.** Boot-relative counters (uptime, boottime, monotonic) are subtracted only within one boot identity. Already relied on by trusted-state §5.3 (`2026-09-06-trusted-state-step-1.md:145`). | F (ratification pending) | No: a contradiction is a tripwire | `f2_no_cross_boot_subtraction`, `f2_boot_id_regression_tripwire` |
| I37 | **F3: suspend clock semantics.** On each supported platform, the monotonic clock pauses across suspend and the boottime clock does not. Verified per platform by C0.9 (the A5 lesson, `trusted-state:146`). | F (ratification pending; inactive on any platform C0.9 has not verified) | No | `f3_paired_clock_delta_bounds_suspend`, `f3_inactive_on_unverified_platform` |
| I38 | **F4: suspend and hibernate preserve process instances and boot identity.** It rules an explanation *out*: a sleep never explains a departure. Linux hibernation boots a restore kernel and then restores the old kernel and userspace; that is not a boot (F-class opinions, Astra §4). | F (ratification pending) | No | `f4_sleep_never_explains_departure`, `f4_hibernate_not_a_boot` |
| I39 | F5: volatile kernel network state (sockets, WireGuard handshakes, interface instances) is boot-scoped | F, **deferred**: inactive until a learner needs it and its F-card is ratified | n/a | none until drafted |
| I40 | The F registry is closed. Each fact must meet admission criteria A1–A8 and carry an F-card. The agent can never author an entry (doctrine :33-37). Each fact has a kill switch. | S | No | `f_registry_closed_to_agent`, `f_card_required` |
| I41 | A boot boundary is **verified by conjunction** and fails closed: a never-seen boot id, a daemon restart, kernel boot time inside (last observation, now], uptime consistent with the gap, and no pre-boot instance after the boundary. Any inconsistency makes F1 inactive for that interval (departures are scored as ordinary) and raises an integrity notice. | S | No | `f1_fail_closed_daemon_not_restarted`, `f1_boot_id_regression`, `f1_tripwire_preboot_instance` |
| I42 | Every stream is declared **EVENT** or **LEVEL**, and its kind fixes its recovery contract (B1) | S | No | `cc_e_quiet_interval_after_kill_no_clear`, `cc_e_departed_entities_return_recovers` |
| I43 | Alert identity components: what enters the alert id, the `incident_key`, and `raise_ref` (§6.1) | S | No | `id_cell_change_no_new_identity`, `id_cell_change_no_new_incident`, `id_raise_ref_not_episode_state` |
| I44 | The pending ledger is integrity-protected. Loss, corruption or a chain break is a detected discontinuity: it fails closed, so pending stays pending and is never laundered into a baseline (H4). | S | No | `pending_alert_record_deleted_no_fold`, `pending_ledger_corrupt_fails_closed`, `pending_seen_set_reseed_keeps_pending` |
| I45 | Incumbent anchors and pre-episode snapshot scoring. A ratified anchor per incumbent at C1a landing; an open episode scores against the persisted pre-episode snapshot; re-warm-up ticks during an open episode are pending (H2, H3). | Mechanism S; anchor ratification O (once) | No | `arb_sustained_shift_not_absorbed_by_ageout`, `arb_rewarmup_ticks_pending`, `arb_incumbent_recovery_needs_snapshot` |
| I46 | Exposure interval rule: raise only if surprising under every admissible exposure; recover only if unsurprising under every admissible exposure (M9) | S | No | `exposure_raise_uses_max`, `exposure_recover_uses_worst_case` |
| I47 | Shadow isolation and resource bounds: no candidates, no coverage, no writes to incumbent state; CPU, wall-time and memory caps; kill switch. Default-on (D3). | Isolation and bounds S; default-on O | No | `shadow_no_effect_on_incumbents`, `shadow_emits_no_candidates`, `shadow_budget_abort_keeps_last`, `shadow_kill_switch_stops_all`, `shadow_failure_isolated` |
| I48 | Explanation sources form a closed set: `context_model`, `label`, `bounded_quiet`, and the reserved `federated_signature` (inactive) | S | No | `explanation_source_closed_set`, `federated_source_reserved_inactive` |
| I49 | Census universes keyed by binary availability: a source whose binary is stably `not_found_on_known_paths` is outside the universe; `untrusted_binary` and `unable` are always incomplete; a change in availability is a regime change, and intervals that cross it are `unknown` for transitions (M7) | S | No | `census_tmux_only_host_complete`, `census_untrusted_is_incomplete`, `census_availability_change_unknown_interval` |
| I50 | `tick_summary` chaining: every record carries its departure basis and a link to the previous record; the census chain state is ledger-stamped; a broken chain yields `unknown` transitions, never zero (M5) | S | No | `summary_chain_no_double_count`, `summary_chain_broken_unknown` |
| I51 | `created_vs_boot` ∈ {`after_boot`, `before_boot`, `unknown`}, computed at collection time (the creation fingerprint is an opaque hash and cannot be compared later) | S (data) | No | `l1_created_vs_boot_computed_at_collection` |

## 1. Problem (corrected from v1)

### 1.1 Symptom

The real-host calibration on 2026-10-05 showed the session and peer detectors alerting on ordinary events:
- reboots (sessions 3 → 0, then tmux-resurrect churn);
- wake from sleep (the tailnet not yet reconnected);
- tailnet devices coming and going.

The cause is missing context and missing learning machinery. Wrong thresholds are not the cause.

### 1.2 What exists today (with v1's inaccuracies corrected)

- **Session counts: one global fold.** Session counts use a single Welford fold over every complete tick (`session-baseline.js:407-438`), scored at fixed σ 3/5 with floor 0.5 (`:76-78`).
- **Peer counts: already one context stratum.** v1's claim of "no context dimension" was wrong (Opus L4, Astra 11):
  - Peer counts are already stratified by the regime of collector-availability signatures (`peer-baseline.js:544-548`).
  - Identities are already versioned per scope (`:50-61`).
  - That regime pattern is this plan's precedent, for alert identity and for census universes (I49).
- **Context that is collected and then thrown away** *(verified 2026-10-06)*:
  - Uptime is read (`tools/system.js:65`) and stored as a 24-hour metric (`daemon.js:307`, `history-store.js:4`). No model reads it.
  - `last` reboot/shutdown rows are fetched and then dropped (`vpn-peer-status.js:124,151`).
  - Tailscale's non-Running states are parsed (`tools/tailscale-status.js:137`, `logged_out`) but the envelope becomes `unable` (`:164`) and the translator skips it (`fact-translators.js:999`). As a result, "tailnet stopped" leaves no fact.
  - Interfaces, routes and DNS are collected (`tools/network.js:81-261`), but only listeners are persisted (`fact-translators.js:532`).
  - `login_hour_bucket` is the hour of the *tick*, not of the login (`fact-translators.js:887,937`).
- **Retention.** Raw facts are kept 30 days (`fact-store.js:18`) while the read window is 31 days (`welford-stats.js:20`). On `main` the 5 MB shared store (`:19`) holds about one day at measured volume (Opus audit §1d).

### 1.3 Adaptation without arbitration (both audits; Opus audit §1g)

- **Novelty detectors.** They report every entity in the historical union as evaluated (`service-baseline.js:455-476`). A new service or lineage edge therefore fires once, and its alert flips to `recovered` on the next tick. HANDOFF 2026-09-27 adjudicated this as "edge-triggered transition notices": it is safe against fabrication, but it absorbs an installed persistence as normal one hour later with no arbitration. **D1 reverses this** (§6.6).
- **Statistical detectors.**
  - Sessions score a tick and then fold it on the next call even when it alarmed (`session-baseline.js:415-428`).
  - Peers exclude only overflow and invalid-marker ticks (`peer-baseline.js:563-594`).
  - Below N = 30 non-excluded ticks the detector turns provisional (`session-baseline.js:432`), emits no candidate (`:661-662`) and reports no coverage (`:909-915`). So merely excluding alarmed ticks would let a sustained shift age the old data out and re-establish at the new level (re-review H2). §6.5 closes that.
- **Result.** This inverts the doctrine's "never adapts a model to unattested change" (`autonomy-doctrine.md:103`).

### 1.4 The outcome loop is broken (Astra audit rank 3)

- **The counting defect.** `fired_count` is `row.alerts.length` over the `alerts.json` snapshot (`calibration.js:245`). Alert identity is stable, so repeated fire/recover cycles collapse into a single record.
- **The effect.** Retuning needs at least 2 fires (`tuning-store.js:427`), so it can never trigger for a flapping constraint. The Astra audit verified that ten cycles yield `fired_count: 1` and no proposal.
- **No labels.** Acknowledgement records receipt only (`alert-store.js:366-376`). The only statuses are active, recovered, acknowledged and suppressed (`:200`; v2 cited `:198`); any other status is normalized to `active`. No label reaches any learner, and recall is `null` by design (`calibration.js:64`).

### 1.5 Data sources that are defective on `main` *(verified 2026-10-06; branch state verified v3)*

- **macOS VPN services.** On `main`, `parseScutilNcList` returns `[]` on this host's real `scutil --nc list` output (4 services, 1 connected), because the regex (`vpn-peer-status.js:324`) expects the name right after the UUID (Opus H5). **Fixed on `fix/collector-sources-2026-10`** (f315786, e408cbf, 150babc): `parseScutilNcListDetailed` (`vpn-peer-status.js:326-338` on the branch) parsed all 4 services on this host's real output, classified the two `PPP:Modem` entries as non-VPN, and flagged Tailscale *(verified v3)*.
- **Login origin.** `parseWhoOutput` turns `(:0)` into the remote host `":0"` (`vpn-peer-status.js:89-102`; Opus M3, Astra 12).
- **Binary lookup under launchd.** The daemon's launchd PATH is `/usr/bin:/bin:/usr/sbin:/sbin`, the installed plist carries no `EnvironmentVariables` (`daemon.js:1596`), and collectors `execFile` bare binary names (`tools/sessions.js:40-47`). So `tailscale` in /usr/local/bin and `tmux` in /opt/homebrew/bin resolve to ENOENT, which is reported as `absent` (Opus H6). **Fixed on the branch** (be09348, 2f7ab97, 44540d9): pinned absolute paths, a writer-set trust check on every ancestor, and `not_found_on_known_paths` / `untrusted_binary` statuses.
- **Census completeness after that fix (re-review M7).** On the branch, `censusStateFor` returns `complete` only if every multiplexer reports `ok` (`fact-translators.js:728-731` @ 3c18739), and `screen` reports `not_found_on_known_paths` when it is absent (`tools/sessions.js:179` @ 3c18739). A tmux-only host therefore records a `partial` session census on every tick: the incumbent `session.count_drop` never establishes and C5 starves. C0.1b fixes this before merge.
- **Sanitizer.** `isSafeEnumString` checks charset and length only (`diagnostics-sanitizer.js:30,44-46`). It does not validate against a schema (Astra 14).
- **Collection deadline.** Structural collectors run one after another (`daemon.js:395-403`) under one 45-second all-or-nothing deadline that discards every result on timeout (`daemon.js:984-993`; Opus M6).

### 1.6 Memory versus budgets (Opus H7)

- **Capacity-branch budgets.** On the capacity branch, the session budget is 4 MiB and the peer budget 16 MiB (`fact-families.js:244-245` @ 2dce005).
- **Worst-case horizon.** At worst-case ticks of 67 KB and 158 KB, those budgets hold only ~2.6 days and ~4.4 days of history.
- **No room for 30 days.** A raw 30-day horizon at worst case exceeds the 4× budget ceiling (`:358`).
- **One retention for every family.** The capacity branch applies a single 30-day retention to every family (`fact-store.js:31` @ 2dce005), so nothing can outlive the raw window without per-family retention (M5).
- **Volume attack.** An attacker who inflates volume can evict the long memory.

## 2. Design overview

| Part | What | Behaviour change |
|---|---|---|
| **C0 Prerequisites** (§3) | Source fixes, census universes, field schemas, per-collector sub-deadlines, boot identity and boundary verification, suspend grounding with a negative-result plan, F-cards | Removes existing fabrications. A failure now loses one collector's evidence, not the whole tick's. |
| **Outcome substrate** (§9) | Append-only transitions, labels, the `fired_count` fix, a `closed` status, the pending ledger | None on detection. Calibration counts become correct. |
| **Arbitrated adaptation** (§6.3–§6.6) | Alarmed observations go to an integrity-protected `pending` ledger; incumbents score open episodes against a persisted pre-episode snapshot; novelty stays pending until explained (D1) | Changes the existing detectors: they stop absorbing alarmed evidence, by folding or by aging out. Novelty alerts stay active until explained. |
| **L1 Context facts** (§4) | Lifecycle, network and session context as facts with event-time intervals; `created_vs_boot`; OS build at the boundary | Data only. No alert candidates. |
| **L1s Long memory** (§8) | `tick_summary` family with chaining, long-lived sufficient statistics, reference snapshots | Data only. |
| **L2 Context vector** (§5) | A pure, versioned function from `tick_summary` | None. Visible in `baseline inspect`. |
| **L3 Learners** (§7) | Transition models declared as EVENT or LEVEL streams; context dimensions as scored streams, counted once; soft structure; F1–F4 as OS-semantics constraints | Shadow only, default-on (D3), one vertical learner first. |
| **Coverage contract v3** (§6.1–§6.2) | Identity split into alert id, `incident_key` and `raise_ref`; recovery by stream kind; recovery, closure and admission kept separate | Applies from the first shadow record. |
| **Authority** (§11) | Additive promotion on the ladder; replacement by the per-host opt-in envelope (D2, DA1) | Per §11 |

## 3. C0: data-source prerequisites

| Id | Defect | Fix | Owner | Gate |
|---|---|---|---|---|
| C0.1 | ENOENT under launchd is read as "not installed" (Opus H6) | Resolve every collector binary from a pinned allowlist of absolute paths, which also closes PATH hijacking. Never emit `not_installed` from ENOENT. This plan adds the fact `collector.binary_state` ∈ {`resolved`, `operator_trusted`, `not_found_on_known_paths`, `untrusted_binary`, `unable`}. | Done on `fix/collector-sources-2026-10` (be09348, 2f7ab97, 44540d9; not merged). The fact family is this plan's. | daybreak (on that branch) |
| C0.1b | The branch's census rule makes every tmux-only or screen-only host permanently `partial` (re-review M7; `fact-translators.js:728-731`, `tools/sessions.js:153-183` @ 3c18739) | **Per-source census universes** keyed by the new `binary_availability` marker attribute (`fact-translators.js:751` @ 3c18739), following the peer availability-signature pattern (`peer-baseline.js:537-548`): a multiplexer that is stably `not_found_on_known_paths` is outside the session universe, so the census is complete over the rest; `untrusted_binary` and `unable` are always incomplete; a change in availability is a new regime (as for peers), and any transition interval that crosses it is `unknown`. The availability transition is itself a scored context event, so moving a binary aside to empty the universe is visible (I49). | `fix/collector-sources-2026-10` **before it merges**; otherwise this plan owns it as the first C0 item | daybreak |
| C0.2 | The scutil parser matches nothing on real output (Opus H5) | Real-output fixtures; classify by the bracket token (`VPN:`, `IPSec`, `PPP:L2TP` versus `PPP:Modem`); dedupe the Tailscale NE service against the tailnet. Linux: `nmcli -t connection show --active` plus tun/wg links, CI-gated. | Parser and classification done on `fix/collector-sources-2026-10` (verified v3 on real output, §1.5); the Linux source here | daybreak |
| C0.3 | The Tailscale envelope drops non-Running state (`tailscale-status.js:137,164` → `fact-translators.js:999`); the parser requires `Peer` even to observe backend state (`:81`) | Emit `net.tailnet_state` for every probe outcome. Parse `BackendState` without requiring `Peer`. Add `Self.Online`, exit-node-in-use, a health-issue count bucket and an HMAC of `CurrentTailnet`. | this plan | daybreak |
| C0.4 | Login-origin parsing (Opus M3, Astra 12): `(:0)`, `(:pts/3:S.0)` and `(mosh [pid])` all become remote; macOS local sessions are `console` and `ttysNNN`; `last` re-reads the same rows on every tick | Linux: `loginctl list-sessions` and `show-session` (Remote, RemoteHost, Service, Type, Class, IdleHint, LockedHint). macOS: `who` plus IOConsoleUsers. Explicit local-host patterns; keep the tty class; use the first-observed tick, never a parsed login time (decision kept from `fact-translators.js:882-886`). Dedupe `last` rows by row digest across ticks. | this plan | daybreak |
| C0.5 | The "location" fingerprint collides, is confounded with the tailnet, and is reversible (Opus M5, Astra 14) | Rename it `net.config_fingerprint`. Components: physical default-route interface kind; gateway MAC (`arp -n` / `ip neigh`); IPv6 router-advertisement prefix; DHCP domain; resolvers scoped to the physical interface only (not MagicDNS). Each component carries its own availability. HMAC with a per-install key stored outside fact history (state dir, 0600, never federated). Document it in the README data table. | this plan | daybreak |
| C0.6 | The sanitizer is not a schema validator (Astra 14) | A closed per-field schema for each new family: enum sets, hash/HMAC formats, integer ranges, and a **physical-object provenance tag** per field (used by I5). Validated at the translator. A rejected field yields `unable`, never a write. Hash at source. | this plan | daybreak |
| C0.7 | The all-or-nothing structural deadline (Opus M6) | Per-collector sub-deadlines inside the 45 s budget. Context collectors run after the session/peer census and record `unable` on timeout. They never cost the census. Cheap context reads bracket the census (§4.4). | this plan | daybreak |
| C0.8 | Reboot inferred from boot *time* (Astra 3, Opus M1) | One boot-identity primitive owned by the trusted-state B-ledger: macOS `kern.bootsessionuuid` (*verified 2026-10-06* readable unprivileged on Darwin 25.2, which answers trusted-state open question 2 for this OS version); Linux `/proc/sys/kernel/random/boot_id`, CI-gated. `todos/2026-09-08-clamp-boot-identity-guard.md` consumes the same primitive. **v3 adds** the boundary-verification conjunction (I41), the OS build at each boot (`kern.osversion`, *verified v3* readable unprivileged: `25C56`; Linux `/proc/sys/kernel/osrelease` plus the os-release build id), and conformance tests: a Linux CI VM reboot, kexec, and soft-reboot (`boot_id` must be unchanged); a macOS tart VM reboot; `launchctl reboot userspace` (`kern.willuserspacereboot` exists on this host, so the behaviour must be recorded, not assumed); a snapshot revert (the boot-id regression must be detected). | shared with trusted-state Phase 3 | daybreak |
| C0.9 | Suspend sources are ungrounded (Opus M2), and there is no plan for a negative result (re-review M9) | Measure on a real laptop and write up the result: the macOS sysctls (`kern.sleeptime`/`waketime`, `kern.sleep_abs_time`/`wake_abs_time`, `machdep.wake_abstime`/`wake_conttime`, and `kern.monotonicclock_usecs`, which is readable unprivileged here (*verified v3*) but unvalidated because this VM never sleeps); Linux `/proc/uptime` − `process.hrtime` (confirm libuv's clock sources) and `/sys/power/suspend_stats/success`; whether DarkWake is detectable cheaply. The A5 revert (`todos/2026-09-06-llm-budget-trusted-time.md`) is the cautionary precedent. **Go/no-go per platform, with a defined fallback:** *go* means F3 is verified there and `host.suspend` carries measured `[lower, upper]` bounds; *no-go* means `host.suspend` is `unknown`, the exposure interval is `[0, wall Δ]`, F3 stays inactive on that platform, and the exposure rule I46 applies (raise only if surprising at maximum exposure). The cost of a no-go is lower sensitivity, reported as `exposure_uncertain` in the abstention counts. It is never a false alert. | this plan | review |
| C0.10 | Inventory | Land the §0.5 rows as pending named tests | this plan | review |
| C0.11 | Horizons | Re-verify the capacity branch's real retention and every joined family's certified horizon (Astra 10) | this plan | review |
| C0.12 | No census at the boot boundary (F-class opinions, Opus §2). The daemon is a GUI LaunchAgent, so it starts only at GUI login, and the structural census runs only once a full interval has passed since the checkpoint (`daemon.js:972`). | A boundary-triggered census at +0 min when the daemon observes a new verified boot id or a wake, plus the existing +2/+10 samples (I15). The pre-shutdown and post-boot gaps are recorded with their durations (§7.8.3). | this plan | daybreak |
| C0.13 | The F class has no cards and no registry | Write one F-card each for F1–F4 (§7.8.5): statement, OS sources, platforms and versions, preconditions, consequences, tripwire, rejected broader wordings. Build the closed registry (I40) with a kill switch per fact. | this plan | daybreak + operator ratification, one per fact |

## 4. L1: context facts

New families in the `fact-families.js` registry. Each family gets its own budget (pinned worst-case bytes per tick × records per interval × horizon), its own ledger and trust gate, and a seen-set where useful.

### 4.1 `host_lifecycle`

| Fact | Source | Semantics (honest) |
|---|---|---|
| `host.boot` | Boot identity (C0.8), plus the reported boot time (`kern.boottime`, `/proc/stat btime`) and the OS build (`kern.osversion`, osrelease) as attributes | A reboot is a **verified boot-identity change** (I41), never a boot-time change. Boot time moves with wall-clock steps (Linux btime = realtime − boottime; macOS adjusts it when the calendar is set). Every `tick_summary` record carries the boot id and the seconds since boot, so `since_boot` never depends on a single event surviving retention (Astra 10). An OS build change across the boundary is recorded, as cause corroboration for the reboot stream (§7.8.3). |
| `host.boot_boundary` | The verification conjunction (I41) at the first observation in a new boot id | `verified`, `unverified` (with the failing conjunct) or `tripwire` (with the contradiction). Only `verified` lets F1 act on the interval. |
| `host.suspend` | Fast-tick (60 s) paired-clock deltas, aggregated into the next structural record | Aggregate suspended duration within (t_prev, t_now], as `[lower, upper]` bounds, and the number of suspends only where the OS exposes a counter. **No invented start or end instants** (Astra 3). On a C0.9 no-go platform, `unknown` with bounds `[0, wall Δ]`. Under F4, a suspend inside an interval is never an explanation for a departure in it. |
| `host.darkwake` | Only if C0.9 finds a cheap unprivileged signal | Its own context value; absent otherwise. Never guessed. |
| `host.clock` | Fast tick: wall-clock Δ versus boottime-clock Δ; timezone id (hashed) plus UTC offset | A `clock_step` event (magnitude bucket) when the gap exceeds measurement resolution (I24); timezone and DST change events. Local-time features are computed from the **stored** offset, never from the current timezone (Astra 10). Clock deltas are taken only within one boot (F2). |
| `host.daemon_gap` | The daemon checkpoint versus now, split using `host.suspend` | Cause ∈ {`suspended`, `daemon_not_running`, `unknown`}. **A fact only** (Opus M6). An integrity alert on unexplained gaps, if wanted, is a separate reviewed (S) rule outside this plan. |
| `host.lifecycle_record` | `last` reboot/shutdown rows, already fetched and dropped today (`vpn-peer-status.js:124,151`); `last -x` on Linux | Historical records with a time-confidence field, deduped by row digest. A missing shutdown row is `unknown`; it means neither "unclean" nor "clean". `pmset -g log` is not used: it is 1.4 MB and takes ~2.1 s. Reading `journalctl -b -1` needs group membership, so it is not used (Opus L2). |

### 4.2 `network_context`

| Fact | Source and notes |
|---|---|
| `net.tailnet_state` | `BackendState` (closed enum), `Self.Online`, exit node in use, health-issue count bucket, `CurrentTailnet` HMAC. Emitted for every probe outcome: `logged_out`, `not_found_on_known_paths`, `untrusted_binary` and `unable` are values (C0.3). `Online` means the node is connected to the control plane. It does not prove peer reachability (Astra 11). |
| `net.vpn_service_state` | Per-service state with HMAC'd uuid and typed kind (C0.2), at most 8 services per record (overflow is counted, L2). **Leaves the peer population for the learners**, because a connected VPN service is currently counted as a "peer" (`vpn-peer-status.js:420-427`), so using its state as context would restate the target (Astra 4). The incumbent detector is unchanged. |
| `net.config_fingerprint` | C0.5. Renamed from "location", because it is an observed configuration, not a place. |
| `collector.binary_state` | C0.1, C0.1b |
| `context.transition` | Old → new for any of the above, with the event-time interval (prev_obs_ts, obs_ts]. Never an instant. |

### 4.3 `session_context`

| Fact | Source and notes |
|---|---|
| `session.login_arrival` | The first-observed tick of a login record (C0.4). Origin class ∈ {`console`, `local_tty`, `local_display`, `remote`, `remote_mosh`, `unknown`}; remote host HMAC'd; tty class. Repeated sightings are not repeated logins (Astra 12). |
| `session.attachment` | `tmux list-clients -F '#{client_tty} #{session_name}'` joined to the login tty (Opus L1). This replaces v1's "creator lineage", which is infeasible: the tmux server daemonizes, and exited creators cannot be recovered (`tools/provenance.js:140`). |
| `session.created_vs_boot` | Per session, at collection time: `after_boot` if the creation second (tmux `#{session_created}`, `tools/sessions.js:38`) is at or after the boot time of the current verified boot, `before_boot` if earlier, `unknown` otherwise (screen exposes no creation time; an unverified boundary; a clock step recorded in the interval). It must be computed at collection, because the stored creation fingerprint is an opaque hash (`fact-translators.js:666-673`) (I51). A `before_boot` instance after a verified boundary is an F1 tripwire. |
| `user.presence` | Screen locked and idle bucket where readable unprivileged (IOConsoleUsers `CGSSessionScreenIsLocked`; logind `LockedHint`/`IdleHint`) (Opus L3) |
| Later candidate families (not C2) | `software_change` (package and update events, the doctrine's own corroboration example at `autonomy-doctrine.md:105`); power source and lid. The Descartes version and config hash ride in `tick_summary` from C2. |

### 4.4 Rules for all L1 facts (S)

- **Closed schemas** (C0.6); hash or HMAC at source; a physical-object provenance tag per field.
- **Degrade, never fabricate.** The states are `ok`, `partial`, `unable`, `not_applicable`, `not_found_on_known_paths` and `untrusted_binary`, and an unavailable value is recorded as such.
- **Event time is distinct from observation time.**
  - Today the daemon stamps every family with the same tick `ts` (`daemon.js:1017-1028`), even though collectors run one after another (`:395-403`). So a VPN can reconnect between the census read and the context read, producing a context/response pair that never coexisted (Astra 10).
  - Fix: each fact carries per-collector `obs_start` and `obs_end`.
  - Cheap context is read both before and after the session/peer census. If it changed in between, the tick's context is `unstable` (§6.2: it may raise, never recover).
- **Bounded** per-tick counts and bytes, with a T8 invariant per family.
- **No new privilege, and no alert candidates from L1.**

## 5. L2: context vector

`contextAt(tick_summary_record) → ContextVector` is pure and versioned, and it can be recomputed from the `tick_summary` family alone (§8.1).

| Dimension | Raw value retained | Default encoding | Notes |
|---|---|---|---|
| `since_boot` | Seconds since boot plus the boot id | Log-scale buckets (H, I6) | The edges can be re-derived from the raw value. Advances with time, so it never enters alert identity (§6.1). |
| `since_wake` | Interval bounds | Bucket, or `uncertain` when the interval straddles an edge | `uncertain` counts as unknown for recovery. Advances with time. |
| `tailnet` | Enum | Enum | Also a scored stream (§7.3) |
| `vpn` | Per-service HMAC state | Any / none, and per service | Also a scored stream |
| `net_config` | HMAC fingerprint | Frequency-ranked identity (K: S), `other`, `new` | `new` and `other` may raise, never recover |
| `hour_of_week` | Local time plus the stored UTC offset | 168 cells, partially pooled toward hour-of-day and day-of-week | Replaces weekday/weekend, so a Tuesday–Saturday schedule is learnable (Astra 6) |
| `presence` | Locked, idle or active | Enum | |
| Interval events | Boot (verified or not), suspend, transition or clock step inside the interval | Flags | Covariates for the transition models (§7.1) |

- **Removed.** `session_origin_mix` is removed because it was computed from live sessions, so a kill rewrites its own context (Opus H3).
- **Leakage rule (S, M6).** No dimension may be derived from the same physical object as a target it conditions. The check runs over the **field-provenance tags** of C0.6, not over families: targets and context can share a family (WireGuard peers come from `wg show <if> latest-handshakes`, `vpn-peer-status.js:203`, while C0.2 adds wg links to VPN context), so a family-level check would be vacuous. Banned pairs include a wg link and its peers, and the Tailscale network extension and the tailnet (I5).
- **Missing values.** `unable`, `unstable` and missing inputs give `unknown`. `new` (never seen) and `other` (rare) are values in their own right. None of them is ever silence.
- **Host vocabulary (H1).** A dimension never observed on this host (`presence` on a headless Linux host with no logind seat; `vpn` on Linux without NetworkManager; `since_wake` on a host that has never slept) is excluded from this host's vocabulary rather than encoded as `unknown` on every tick. Its first appearance is a structure-version change (§7.4). `not_applicable` and a stable `not_found_on_known_paths` are known values, not `unknown`.
- **Versioned mapping.** The vocabulary and top-K mapping are versioned. In evaluation they are fitted inside each fold from preceding data only (Astra 9, Astra 10).

## 6. Coverage contract v3 and arbitrated adaptation (security-critical)

### 6.0 Stream kinds, and three transitions that stay separate

**Today.**
- An alert's identity is `alertId(rule_id, fingerprint)` (`alert-store.js:27-30`).
- Any covered identity that is absent from this tick's candidates is recovered (`:313-321`; notify-once branch `:442-451`).
- The daemon checks only the owner and the identity (`daemon.js:834-850`).

**The risks.** A context-conditioned learner that reports an identity as evaluated after a context change fabricates a recovery (v1 Opus B1: a reboot, `tailscale down`, the unknown → parent fallback). v2's fix was written for levels. On an event stream it recovered a departure alert on the next quiet interval, with the departed sessions still gone (re-review B1).

**Stream kinds (I42).** Every learned stream is declared one of:

| Kind | Streams | What an alert asserts |
|---|---|---|
| **EVENT** | session departures, arrivals and churn; login arrivals; tailnet node-key novelty and inbound sessions; reboot events; context transitions (tailnet, VPN, `net_config`, presence, clock, binary availability); the incumbent novelty rules (service, lineage, scheduled job) | "These events happened in interval (t₀, t₁] of boot b." An event cannot un-happen. |
| **LEVEL** | session occupancy; tailnet online count; the incumbent `session.count_drop` and `peer.count_drop` / `peer.count_spike` | "The level observed now is surprising." A level can return. |

**Three transitions, never merged.** Keeping these apart is what lets learning proceed without waiting on a per-item label (the UAC concern in re-review H1(d)):

| Transition | Meaning | Who causes it | Notify-once effect | Pending-data effect |
|---|---|---|---|---|
| `recovered` | Positive evidence that the raised condition no longer holds (§6.2 CC3) | The producing detector, through coverage | Re-arms (`newEpisode`, notify-once `alert-store.js:383-385`) | **None.** Recovery never admits. |
| `closed` (reason) | The incident is closed: by a label (CC7), or for novelty by any D1 explanation (§6.6) | Label store; for novelty, the explanation sources of §6.3 | Re-arms. C1.1 adds `closed` to the status list, since today an unknown status silently becomes `active` (`alert-store.js:200`; branch `:220`), and notify-once's `newEpisode` must treat `closed` like `recovered`. | Admits only if the reason is an admission path (`expected`, `mine`, `benign`, or a D1 explanation). `suspicious` and `confirmed_incident` close without admitting. |
| `admitted` / `admitted_unexplained` | Pending data enters authority-bearing state | The admission paths of §6.3, charged to the drift budget | None | Folds into the baseline or the seen-set |

### 6.1 Identity (CC1; re-review H1, M1)

Verified on `feat/notify-once-2026-10` @ 25cf225 *(verified v3)*: an episode is `(alert id, incident_key ?? "default")` (README; `alertEpisodeKey`, `alert-store.js:77-79`); `newEpisode = !current || current.status === "recovered" || !current.episode_started_at` (`:383-385`); a key not yet in the episode is a `newIncident`, which makes a notification due (`:399`, `:430`); an episode holds at most 256 incident keys and overflow stays notify-safe (`:401`); diagnostics never create episodes, and the v2-era material-evidence digest is gone from the branch.

So each component of a learned alert goes in exactly one place:

| Component | Alert id (fingerprint) | `incident_key` | `raise_ref` |
|---|---|---|---|
| `rule_id` (which implies the stream kind) | ✔ | | |
| lineage | ✔ | | |
| `structure_id` (vocabulary mapping, model families, dimensions) | ✔ | | |
| EVENT streams: HMAC of boot id, interval (prev_obs_ts, obs_ts], and the event-set digest (entity keys plus instance fingerprints) | | ✔ | |
| LEVEL streams | | `default` | |
| `stratum_class`, the full raising cell (state, calendar and `since_*`), the evaluation level (leaf or backed-off), the parameter-snapshot digest, the exposure interval, the predictive p-value, the evidence summary (at-risk count, departed set) | | | ✔ |

- **Fingerprint** = `v3:<lineage>:<structure_id>`. No context enters it. Precedent: the scope-versioned `v2:vpn` / `v2:markerless` identities (`peer-baseline.js:50-61`).
- **Why no stratum in the alert id or the incident key.** A cell change (presence active → locked, a `since_*` bucket edge) would otherwise mint a new identity, or a new incident key and therefore a new notification (`:399`, `:430`), every time a persistent anomaly moved cell, while the old identity froze (re-review H1(b)).
- **Where `raise_ref` lives.** A display copy rides in `diagnostics`, which `normalizeAlertRecord` keeps (`alert-store.js:189-212`; a new top-level field would be dropped). The **authoritative** copy lives in the pending ledger (§6.4), because `alerts.json` has no integrity ledger (re-review H4).
- **Bounded identities.** Learned alert ids per rule ≤ live lineages × retained structure versions, which the snapshot cap (I3) bounds. Incident keys per episode ≤ 256, from the branch.

### 6.2 Recovery and closure (CC2–CC8; I17)

- **CC2 Raise.** Any trusted evaluation may raise, including a backed-off one (`unknown`, `new`, `other`, `unstable`, below support). It then uses the wider backed-off predictive and is never silent (Opus H3). It raises only if the observation is surprising at every admissible exposure (I46).
- **CC3 Recover, LEVEL streams.** All of the following must hold:
  - (a) a fresh, complete census in the same census universe (I49), and trusted fact history (the existing gates);
  - (b) the same lineage and the same `structure_id`;
  - (c) the current context is known and stable: no `unknown` or `unstable` dimension in the host vocabulary (§5);
  - (d) the current evaluation is at the raise's evaluation level or more specific, with support at or above the floor (I16), so a back-off raise can recover at the same back-off level once the context is known (H1(c));
  - (e) the evidence has changed, and the observation is unsurprising **both** under the current predictive in the current cell **and** under the raising parameter snapshot in the **raising cell** taken from `raise_ref`, at every admissible exposure (I46). The raising cell is the anchor: the host never has to return to it, and a refit, an hour change, a `since_*` advance or a slow walk can never clear an alert on unchanged evidence (Astra 5; replaces v2's "current cell equals `stratum_class`", re-review H1(a));
  - (f) the lineage is not in a drift-budget excursion (§11.3).
- **CC3-E Recover, EVENT streams (B1).** A quiet next interval is never evidence. The learner reports an event alert id as evaluated only when every open incident in its episode has positive evidence that the raised condition no longer holds:
  - **Departures.** Every entity key in the episode's cumulative departed set is present again in a fresh, trusted, complete census of the same universe, **within the same boot id** as the incident: any boot-id change, verified or not, blocks it. The cumulative deficit across the episode's open incidents is then empty.
    - A returning name with a new creation fingerprint is a recreation. It restores the departure, and it is scored as a churn event in the same learner (re-review B1 fix: fingerprints are compared only within one boot). The churn event is an EVENT incident that can never recover by evidence, so kill-and-replace stays visible.
    - **Across a verified boot boundary, a pre-boot departure never recovers** by restored names: under F1 a restored name is a new instance (F-class opinions, Opus §2 item 7; Astra §2). It stays frozen until a label closes it.
  - **Every other event kind** (arrivals, churn, login arrivals, node-key novelty, reboot events, context transitions): there is no evidence-based recovery, because what arrived, churned or transitioned did happen. These alerts stay frozen until closed (CC7).
- **CC4 Otherwise freeze.** The identity is not reported in `evaluatedAlertKeys`, and the alert keeps its status. Under notify-once a frozen alert is silent; a new incident under the same id still notifies.
- **CC5 Successors.** A successor version or replacement never reports a predecessor's identity as evaluated.
  - Predecessor parameter snapshots are retained, within bounds (§8.3), so the predecessor's own pure re-score can still recover its alerts under CC3.
  - If the snapshot is gone (history loss), the alert stays frozen until a label closes it.
- **CC6 Raise-only cells.** Transition and aftermath cells stay raise-only on a host until that host has a ratified replacement envelope for the family (D2, C7b).
- **CC7 Closure.** An operator label (§9) closes an alert, with a reason; labels are scoped to an alert id plus incident keys, and can be applied in bulk from the digest. For **novelty** only, the D1 explanations also close the alert (§6.6). Time, a quiet interval, a context change, a boot and a model change never close one. Whether bounded quiet should also close non-novelty EVENT alerts is **Q7**; until it is answered, it admits their pending data (§6.3) but does not close the alert.
- **CC8 F1 never touches alert state.** F1 scopes identity comparisons and removes boundary-crossing departures from the hazard likelihood. It never recovers, closes, admits or lowers severity (§7.8.2, A6).

**An open EVENT alert blocks nothing.** It notified once at activation. Learning proceeds through admission (§6.3), which does not wait for the label. Closing it is bookkeeping, done in bulk from the digest: notification, not confirmation (`autonomy-doctrine.md:46-50`).

**Stated consequence.** After a reboot, a pre-reboot departure alert **freezes** and stays frozen until the operator labels it (`descartes alerts label <id> expected|benign|mine|suspicious`, §9). A pre-reboot occupancy alert recovers only once the count is unsurprising under its raising snapshot, which the post-boot zero is not. This is the intended behaviour, not a bug.

**Named gate tests (C5 daybreak), split by kind:**

| Test | Setup | Expected |
|---|---|---|
| `cc_e_quiet_interval_after_kill_no_clear` | 4 of 5 sessions killed at t (D = 4 of 5 at risk), raise; at t+1, same cell, D = 0 of 1 | Frozen. The re-review B1 scenario. |
| `cc_e_departed_entities_return_recovers` (positive control) | Same as above; at t+3, within the same boot, the four entity keys are present again as the same instances | Recovered |
| `cc_e_recreated_same_name_scored_as_churn` | The four are recreated under the same names, new creation fingerprints, same boot | The departure recovers; a churn event is scored in the same learner and, if surprising, raises an EVENT alert that never recovers by evidence |
| `cc_e_partial_return_no_clear` | Two of the four return | Frozen: the cumulative deficit is not empty |
| `cc_e_reboot_restored_names_no_clear` | Departure alert raised; verified reboot; resurrect restores the same names | Frozen; a restored name is a new instance (F1) |
| `cc_e_reboot_freezes_nonvacuous` | Departure alert raised with `since_boot` = days; reboot; days later `since_boot` climbs back into the raising bucket with a quiet interval | Still frozen (re-review B1 reboot case) |
| `cc_e_arrival_never_recovers` | A surprising arrival raises; the arrived entity later departs | Frozen until a label |
| `cc_l_reboot_freezes` | Occupancy alert raised with `since_boot` = days. The boot id changes, and the first post-boot tick has 0 sessions, which is normal in the first `since_boot` bucket. | Frozen: 0 is surprising under the raising cell. A new alert appears only if the post-boot cell itself finds the tick surprising. |
| `cc_l_tailscale_down_freezes` | Tailnet online-count alert raised with `tailnet=Running`. Then `tailscale down`, and 0 peers online. | Frozen. The tailnet transition is scored as its own stream (§7.3). |
| `cc_l_unknown_context_freezes` | The tailnet probe fails (`unable`) → `tailnet=unknown`; the backed-off predictive accepts the current count | Frozen. May raise. |
| `cc_l_new_network_raises` | A never-seen `net_config`, then a session kill | Raises through the backed-off predictive; never silent |
| `cc_l_model_replacement_no_clear` | v1 alert active; structure v2 promoted; evidence unchanged | v2 does not recover it. The v1 alert recovers only through the v1 snapshot once the evidence is restored. |
| `cc_l_refit_no_clear` | A refit widens the predictive between raise and re-evaluation; evidence unchanged | Frozen (CC3e) |
| `cc_l_hour_change_no_clear` | Raised at 17:00; at 18:00 the same count is normal for 18:00 | Frozen: still surprising under the raising cell |
| `cc_l_since_boot_advance_recovers` | Raised at `since_boot` ∈ [1 h, 6 h); at 7 h the count is restored | Recovered without returning to the raising bucket (H1(a)) |
| `cc_l_backoff_raise_recovers_when_known` | Raised at a backed-off level; context becomes known; evidence restored | Recovered at the same level or more specific (H1(c)) |
| `cc_l_not_applicable_is_known` | Headless host: `presence` never observed | `presence` is not in the host vocabulary; alerts can recover |
| `cc_l_unstable_context_freezes` | Context changes between the bracketing reads | Frozen |
| `cc_l_evidence_restored_recovers` (positive control) | Same cell; the sessions return | Recovered |
| `id_cell_change_no_new_identity`, `id_cell_change_no_new_incident` | A persistent level anomaly crosses a `since_*` edge and presence active → locked | Same alert id, same incident key, no new notification (H1(b)) |
| `id_raise_ref_not_episode_state` | `raise_ref` changes on a refit while the alert is active | No new episode or incident (M1) |

### 6.3 Arbitrated adaptation (D1; audit §1g; Astra 5; Opus M10). Early and security-critical

**Rule (S).** An observation that raised an alert enters `pending`, in the pending ledger (§6.4). Pending observations are **retained**, never deleted. They are not folded into any authority-bearing baseline, and not counted as learned-normal, until an explanation source admits them. A hand-written "X explains Y" mapping is never an explanation (P1).

**Explanation sources (a closed set, I48):**
1. **`context_model`.** A context fact explains only through a model with the authority to explain: a promoted learner for that stream whose predictive, given the context, finds the observation unsurprising in the raising cell. Until a stream has such a learner (C7a for the first vertical, C8 for the rest), this source abstains for that stream. **An F fact is never an explanation** (D4; F-class opinions, Opus A6; Astra §5): F1 can remove boundary-crossing departures from a likelihood, but it cannot certify a pending observation as normal.
2. **`label`.** `expected`, `mine` or `benign` (§9), subject to the label-poisoning bound.
3. **`bounded_quiet`.** The pending item persists, with no further anomaly, for the bounded-quiet period. The mechanism is S, the period is O (I19), and on-host admission is the doctrine exception DA3.
   - For a sustained shift, "no further anomaly" is measured **on the stability of the new level**: the pending regime's own sufficient statistics show no further drift relative to themselves. Scored against the pre-episode level, every tick would be a further anomaly, so quiet would never come (re-review H2).
   - Admission consumes the cumulative drift budget anchored to the reference snapshot (§8.3).
   - Each admission is logged as `admitted_unexplained` and listed in a digest: notification, not confirmation (`autonomy-doctrine.md:46-50`).
   - When the budget is exhausted, admission needs a label.
4. **`federated_signature`** (reserved; §6.3.1).

Every admission is reversible: it is logged with its source and `evidence_ref` in the transition log, and the operator can revoke it, which re-opens the pending item and rebuilds the affected statistics from the retained pending record.

**Challengers still see everything.** Shadow challengers fit on all trusted data, pending included, with soft contamination weights from a mixture component (Opus M10). The incumbent therefore does not decide what a successor may learn, which resolves the deadlock in Astra 5 where every legitimate reboot fires the old detector and quarantines exactly the aftermath data the successor needs. Only authority-bearing state is restricted.

**Fixtures:** `arb_alarmed_tick_not_folded`, `arb_pending_retained_for_challenger`, `arb_quiet_admission_consumes_budget`, `arb_sustained_shift_quiet_on_new_level`, `arb_budget_exhausted_requires_label`, `arb_admission_revocable`, `label_burst_held_pending`, `explanation_f1_never_admits`, `explanation_context_abstains_without_promoted_learner`.

#### 6.3.1 Declared extension point: federated explanation sources (interfaces only)

The operator expects later federated layers to match known patterns or signatures, as a further explanation source (D1). v3 declares the interface and makes **no design commitment**.

- `ExplanationSource { id, kind, explains(pendingItem) → { verdict: explained | not_explained | abstain, evidence_ref, scope, authority_class } }`, with `kind` from the closed set above.
- `federated_signature` is reserved and inactive (`federated_source_reserved_inactive`).
- Whatever is designed later must at least: arrive through an attested, signed, off-host channel (`autonomy-doctrine.md:61-68,126-129`); carry provenance; be opt-in; have bounded influence, charged to the same drift budget; be logged like every other admission; and be revocable.

### 6.4 The pending ledger (H4; I44)

**Why.** v2 kept pending ticks "with the alert" in `alerts.json`. `normalizeAlertRecord` rebuilds each record from a fixed field list (`alert-store.js:189-212`); a malformed record is quarantined, which means dropped (`:229-237`); `alerts.json` has no integrity ledger; a corrupt session state store resets to fresh (`session-baseline.js:272-287`); and a seen-set re-seed rebuilds entries from certified candidates (capacity `novelty-seen-set.js:26-35`). One same-UID write could therefore launder pending observations into a baseline.

**Design.**
- **Home.** A trust-bearing store per family (`learned/pending/<family>/`), lineage-stamped to that family's fact ledger exactly as seen-sets are (capacity `novelty-seen-set.js:20-25`: ledger generation plus the committed pass id, validated against the same ledger the reader just read).
- **Content per open episode** `(alert id, incident_key)`: the authoritative `raise_ref`; the reference to the pre-episode snapshot (§6.5); the pending observations, as references to their tick summaries plus their sufficient-statistic contributions, so they outlive the raw window; bounded exemplars.
- **Two independent records must agree.** Pending membership is derived from the hash-chained transition log (§9: `activated` or `incident_opened` without a matching `recovered`, `closed` or `admitted`) **and** from the ledger-stamped store.
- **Discontinuity fails closed.** A missing, unreadable, mismatched or overflowed store, a broken transition-log chain, or a disagreement between the two records is a detected discontinuity:
  - every observation since the last certified pending state is treated as pending;
  - the affected detectors freeze adaptation at their last certified snapshot and keep scoring against it;
  - the `context_model` and `bounded_quiet` sources are disabled for the family until continuity is re-certified;
  - an integrity notice is raised.
  - Deleting or corrupting an `alerts.json` record therefore changes nothing about pending state (`pending_alert_record_deleted_no_fold`).
- **No eviction under a sustained shift.** Pending observations are kept as per-episode sufficient statistics plus bounded exemplars, so a month of pending ticks (~720) costs a fixed size. Exceeding the episode cap fails closed with a notice (`pending_overflow_fails_closed`).
- **Seen-sets.** A pending novel entity may still be folded into the seen-set: that memory "can only suppress a novelty claim" (capacity `novelty-seen-set.js:16-18`), which is what keeps it from re-alerting. Its pending status lives in the pending ledger, so a seen-set re-seed cannot drop it (`pending_seen_set_reseed_keeps_pending`).

The transition log is tamper-evident at the same UID, not tamper-proof. This design makes laundering detectable and fail closed. Preventing it outright needs off-host attestation, which is outside this plan.

### 6.5 Applied to the incumbents: anchors and pre-episode snapshots (step C1a; H2, H3; I45)

**Session and peer Welford folds.**
- An alarmed tick is no longer folded (today it is: `session-baseline.js:415-428`, `peer-baseline.js:589-594`). It goes to the pending ledger.
- **Anchor.** When C1a lands, each incumbent (session `count_drop`; peer `count_drop` / `count_spike` per availability regime) takes an anchor snapshot (count, mean, M2, EWMA) from its established window. The operator ratifies the anchors once per host, as part of the policy envelope, not item by item. Anchors are persisted, ledger-stamped and outlive the raw window. They are built here, decoupled from C7b, so the drift budget exists whether or not any learner is ever promoted (H3).
- **Pre-episode snapshot.** When an episode opens, the detector persists the snapshot of its window as of the last tick before the first alarmed tick. While the episode is open it scores every tick against that snapshot, not the sliding window. **Aging out of the raw window never makes it provisional during an open episode**, and re-warm-up ticks during an open episode are pending (re-review H2).
- **Recovery** follows CC3(e): the observation must be unsurprising under the pre-episode snapshot, with the evidence changed.
- **Exit from a sustained shift**: a label, or `admitted_unexplained` after bounded quiet measured on the stability of the new level (§6.3), within the drift budget.
- **Drift measure** (H, I20): |μ_admitted − μ_anchor| expressed in the incumbent's own z units, its own floor included (I35 unchanged), cumulative across admissions. Over budget: label-only admission plus a notice. Re-ratifying resets the anchor.
- **Admission paths available at C1a:** `label` and `bounded_quiet` (the latter only once DA3 is ratified; until then label-only). `context_model` abstains until C7a.

**Novelty seen-sets (service, lineage, scheduled job).** Covered by §6.6. Drift measure: admitted unexplained entities per family since the anchor.

**Fixtures:** `arb_sustained_shift_not_absorbed_by_ageout` (the re-review H2 scenario: kill 2 of 5 and keep them dead for 30 days; the detector stays established against its snapshot, never recovers and never folds), `arb_rewarmup_ticks_pending`, `arb_incumbent_recovery_needs_snapshot`, `drift_incumbent_anchor_measure`.

### 6.6 Novelty lifecycle (D1; supersedes the 2026-09-27 design)

- A novel entity raises its alert as today, and enters the pending ledger.
- **The alert stays active while the entity is pending.** The detector stops reporting a pending entity's alert id as evaluated, so the alert freezes as `active` instead of flipping to `recovered` on the next tick. This changes `computeCensusEvaluatedAlertKeys`, which today reports the whole historical union (`service-baseline.js:455-476`).
- **The alert closes when an explanation source admits the entity** (§6.3: `context_model` once a promoted learner exists for that stream; `label`; `bounded_quiet` within the per-family budget). The transition log records the source. Re-arming follows `closed` (§6.0).
- Under notify-once it notified once at activation and is silent while open. The incident key stays the producer's stable identity, as the branch already declares for novelty.
- Re-review L4 (the novelty half of C1a did nothing until Q4) is resolved by D1.
- **Fixtures:** `novelty_stays_active_until_explained`, `novelty_closed_by_label`, `novelty_closed_by_bounded_quiet_consumes_budget`, `novelty_budget_exhausted_requires_label`, `novelty_reseed_keeps_pending`.

## 7. L3: learners

### 7.1 Model transitions, not levels (Opus H1, Astra 8)

Sources: sessions, SSH logins, WireGuard peers with an active handshake, tailnet node keys. VPN services are context, not a source. Every stream below is declared EVENT or LEVEL (§6.0).

- **Departures** (EVENT) D_t = |S_{t−1} \ S_t|, taken from entity-key set differences between consecutive complete censuses of the same universe **within the same boot**. That restriction is F1 (process instances are boot-scoped), cited and tested, not an unreviewed hand rule (F-class opinions, Opus: "v2 already applies the fact silently"). While F1 is inactive (before its ratification, or after its kill switch), the learner uses the option-D fallback of §7.8.4: boundary-crossing intervals form their own unshrunk regime with a weak prior, scored in shadow, and their time-to-override is published. When F1 is active but a particular boundary fails verification (I41), that interval is scored as an ordinary within-boot interval and an integrity notice is raised (F-class opinions, Opus A4).
  - They are modelled as a hazard on the at-risk set: D_t ~ Binomial(|S_{t−1}|, 1 − exp(−λ(ctx)·e_t)).
  - The exposure e_t is the awake seconds in the interval: wall-clock Δ minus suspended time. Suspended time is an interval, so exposure is an interval [e_min, e_max], and I46 applies: raise only if surprising at every exposure in it (in practice at e_max for departures); recover only if unsurprising at every exposure in it (M9). That removes the bias toward alerting after a wake, which is the R9 false-positive class (`autonomy-doctrine.md:120`).
- **Arrivals** (EVENT) A_t ~ Poisson(μ(ctx)·e_t), with the same exposure rule.
- **Churn** (EVENT). Within one boot, churn is a name that reappears with a new creation fingerprint. **Across a boot, creation fingerprints are never compared** (F1; v2's "compared only if Q3 ratifies" was inverted). Post-boot identity continuity is learned separately (§7.8.3).
- **Reboot events** (EVENT), **in C5** (moved from C8): frequency given hour-of-week and presence; uptime at reboot; cause corroboration (whether a shutdown row exists; whether the OS build changed across the boundary; later, `software_change` events); drift in reboot frequency against the anchor (§7.8.3).
- **Interval events as covariates**: a boot, a suspend, or a transition inside the interval. Exposure adjusts every rate. Under F4, a suspend inside an interval never explains a departure in it.
- **Why transitions.** A level model is the wrong family for this data:
  - Under a level model, a host that has stably run 5 sessions gets Poisson(5), so P(Y ≤ 2) ≈ 0.125: a 60% kill is unremarkable.
  - Under the hazard model, with a learned per-session hazard of ~0.01 per hour, three departures in one hour have probability ≈ C(5,3)·0.01³ ≈ 1e-5.
  - A single departure at 18:00 stays quiet if this host's 18:00 hazard is high, with no stddev floor involved.
- **Levels (occupancy)** (LEVEL) become a secondary stream. Its model may be underdispersed: for example, a Dirichlet-smoothed categorical over the counts observed per cell.
- **Logins** are scored as arrival events (EVENT), per entity and per host. Presence hours become a separate, weaker stream (Opus M4).
- **Tailnet online count** (LEVEL) becomes a secondary stream, since it mostly measures the operator's own devices sleeping. Node-key novelty and inbound sessions (EVENT) are the primary tailnet streams (Opus L6).
- **Transitions across a census-universe change** (I49) are `unknown`, never zero.

### 7.2 Model-adequacy gate (S mechanism over the H family set; re-review M3)

**Gate.** Before a family is eligible for a stream, it must pass:
- a dispersion index;
- PIT calibration on held-out days;
- the mandatory fixtures below, each **flagged at the stream's allocated α_i** (§12);
- a verdict that is the same at ×0.1 and ×10 the fitted prior strength.

**Mandatory fixtures:** `adequacy_stable3_to0`, `adequacy_5_to_2`, `adequacy_excess_zeros`, `adequacy_regime_change`, `adequacy_prior_sensitivity_stable`.

**Why not the incumbent's z = −6.** v2 required the 3 → 0 drop to be "at least as surprising as the incumbent finds it" (z = −6). That made an S gate inherit a constant the code itself marks "PROVISIONAL … NOT tuned values" (`session-baseline.js:68-78`), and it compared a Gaussian z with a discrete probability. The re-review's arithmetic checks out *(verified v3)*: three sessions stable for three weeks (~1,512 session-hours, no departures) under a Gamma prior of shape 1 give P(all three depart within an hour) ≈ 6/1513³ ≈ 1.7e-9, while Φ(−6) ≈ 9.9e-10. So the preferred hazard family would fail its own fixture, and at shape 0.5 (≈ 5.4e-10) it would pass: the prior, not the data, would decide. The comparison with the incumbent moves to the evaluation, as an O tolerance (§10.5).

**On failure.** A family that fails is ineligible, and the stream stays on its incumbent.

### 7.3 Learn the joint, but count context once (Opus H3, Astra 4, re-review M2)

- **Context dimensions are scored too.** Context an attacker can influence (`tailnet`, `vpn`, `net_config`, `presence`, boot, suspend, clock, binary availability) is itself a scored stream: transition rates and dwell times, given the other context (`hour_of_week`, `since_boot`).
- **How a tick is scored.** A tick's joint log-surprise is the context-transition term plus the response-given-context term. **Each term is owned by one stream** (M2):
  - the context stream alerts on the transition term;
  - each response stream alerts on its conditional term only;
  - so "tailnet stopped at 03:00, then peers vanish" surfaces once, as a surprising context transition with the peer response attached as evidence, rather than four times.
- **Corroboration counts distinct evidence sources** (I29). An unusual-hour reboot that moves sessions, peers, logins and tailnet is one source, not four. On a single host, corroboration never grounds authority anyway (`autonomy-doctrine.md:61-68`); here it only feeds the O severity mapping.
- **`new`, `unknown` and `other`** back off for raising, never go silent, and never recover (CC2, CC3).
- **Novelty probability is learned with Good–Turing** (singletons / N, per dimension):
  - A host that joins new networks often finds a new network unremarkable.
  - A host that never does finds it surprising.
  - The novelty rate is itself scored for drift against the anchor, so an attacker who toggles a cheap dimension (on Linux, an nmcli resolver change from an active session) to inflate singletons raises a drift signal instead of buying silence (re-review L3, I21).

### 7.4 Soft structure, not hard selection (Opus H4, Astra 6, Astra 9)

- **The model.** A hierarchical log-linear model with shrinkage on every main effect and a bounded set of pairwise interactions. The alternative is Bayesian model averaging over the lattice (context-tree-weighting style).
  - There is no hard keep/drop decision and no hand back-off order.
  - Effect sizes, or model weights, are shown in `baseline inspect`.
- **The numbers did not disappear.** The pooling strength (hyperprior) is a P:
  - It is fitted by empirical Bayes inside each training fold.
  - It is sensitivity-checked at ×0.1 and ×10, and the evaluation report states the result.
- **When a new version is created.** A new structure version (`structure_id`) is created only when the representation changes, including when a dimension first appears in the host vocabulary (§5). Parameter refits stay inside one version and are bounded by the drift budget (§11.3).
- **What the learner can and cannot do.**
  - It weighs declared candidates at declared resolutions; it does not discover dimensions outside them.
  - Raw resolution is retained (§8.1), so alternative representations can be fitted later through the doctrine's compositional path (`model-ir` kernels).

### 7.5 Selection and evaluation kept apart (Astra 9)

- **Nested chronological evaluation.**
  - The outer loop uses rolling origins with day-blocked folds, and keeps episodes intact: a reboot aftermath is never split across a fold boundary.
  - The inner loop fits the vocabulary/top-K, priors and hyperparameters on preceding data only.
- **Exclude-latest scoring.** Each tick is scored against a model fitted on strictly earlier data. This follows the discipline at `peer-baseline.js:563`. The `model-ir` z-score is deliberately inclusive (`model-ir.js:335-341`), so it must not be reused as-is.
- **Objective.** Average likelihood is reported, but it is not the only objective, because it can trade away rare-attack sensitivity. Scenario detection is evaluated separately (§10).

### 7.6 Rare events (Opus H2, Astra 7)

- **Sample sizes, honestly.**
  - There are at most 720 hourly ticks in 30 days, and about 400 on a laptop that sleeps.
  - Hour-of-week therefore averages at most 4.3 ticks per cell.
  - Each reboot gives one aftermath episode, and this dev host had zero reboots in the window. Extra samples describe an aftermath; they are not additional independent reboot episodes (F-class opinions, Astra §3).
  - Ticks are autocorrelated, so episodes, not ticks, are the unit of evidence.
- **Eligibility** depends on predictive evidence and episode support, not on the current 30-tick warm-up (`session-baseline.js:83`).
- **Time-to-override (TTO)** is computed per stream and cell with the pinned definition of I23 (re-review L1): for a Gamma(a0, b0) rate, data outweighs the prior once accrued exposure ≥ b0 and observed events ≥ a0; for a Beta(α0, β0) probability, once trials ≥ α0 + β0. Both conditions are published in `baseline inspect` and in the evaluation report, with the wall time they imply at this host's observed accrual rate.
  - A cell whose TTO exceeds the horizon of available statistics is labelled `prior-governed`: it behaves like a rule and says so.
- **Long-lived per-episode statistics** (§8.2) let rare cells accumulate over months. TTO is then measured against long memory, not against the 30-day raw window.
- **Transition-triggered samples.**
  - Trigger: a verified boot-id change, a wake, or a tailnet, VPN, network or binary-availability transition.
  - Action: take cheap session and peer censuses at +0, +2 and +10 minutes (I15, C0.12).
  - Destination: `tick_summary`, chained (§8.1).
  - Why: the hourly cadence cannot see reconnects or a tmux-resurrect ramp (`daemon.js:66`), and after a quick reboot the first structural census can be up to an hour late (`daemon.js:972`).
- **Abstention (S).** Below the support floor, the model backs off for raising and never recovers (CC3d).
- **Boot boundaries (F1, D4).** Process instances are boot-scoped. Across a verified boundary, departures leave the hazard likelihood and creation fingerprints are not compared. Everything behavioural on either side stays learned: the reboot itself, every non-crossing interval with no grace period, the unobserved straddle as abstention, post-boot arrivals and restoration (§7.8.3). F1 has no time window and makes no claim about normal; that is what separates it from the rejected R6/R7 (Appendix A). Its kill switch reverts to option D (§7.8.4), whose boundary cell stays prior-governed for months, and the plan says so.

### 7.7 Runtime, substrate and default-on shadow (Opus M11, Astra 15, D3)

- **Cadence.** Fit on the structural cadence or daily, and score on the fast tick from cached parameters. The T9 read-cost model is respected, because learners read the small `tick_summary` family, not the 30-day raw stores (today's detectors re-read the whole window on every fast tick).
- **Kernels in `model-ir`.** The kernels are expressed as new `model-ir` ops, each with a runtime budget (fuel, memory, time), as the proactive-modeling plan requires for cardinality-sensitive group-bys:
  - a context group-by with a cardinality budget;
  - set-difference transitions;
  - conjugate hazard, Poisson and categorical models;
  - shrinkage.
  - If the C4a spike shows that the `model-ir` series contract cannot carry these, the divergence is written down and justified there.
- **Default-on shadow (D3, DA2; I47).**
  - Shadow learners run under `watch.json` (default-on). They are the plan's declared kernels, not agent-authored models; agent authoring and the existing AUTHOR-pipeline shadow constraints stay under `learned.json` exactly as today (`daemon.js:1061-1079`).
  - **No authority.** They emit no alert candidates and no `evaluatedAlertKeys`, write nothing to `alerts.json`, notifications, incumbent state or the pending ledger, and log only to their own shadow log and learned store.
  - **Isolation.** They run after the census and after the incumbents, in their own deadline slice; a throw or timeout is caught, recorded as `fit_aborted` or `score_aborted`, and never fails the tick.
  - **Bounds (S).** Maximum candidate dimensions, interactions and cells; CPU-ms, wall time and memory per fit and per score; durable, versioned parameter snapshots. An abort keeps the last version. Repeated aborts auto-disable the learner with a notice.
  - **Kill switch.** A `shadow_learning` flag in `watch.json` (operator), checked every tick, stops all shadow fitting and scoring.
  - **Proof of no effect.** `shadow_no_effect_on_incumbents`: on the same replay, the incumbents' candidates, coverage and `alerts.json` bytes are identical with shadow on and off.
- **Integration is new work.**
  - Today `model-ir.js` is imported only by `model-ladder.js`, and nothing imports `model-ladder.js` *(verified 2026-10-06)*.
  - C5 is therefore the first daemon integration of the model substrate, which is substantive lifecycle work. That is why one vertical learner comes first.

### 7.8 OS-semantics constraints: the F class (D4)

Adopted from `docs/reviews/2026-10-06-f-class-opinions.md` (Astra and Opus, both ALLOW WITH CONDITIONS). Learning decides how this machine behaves; verified semantics decide what its observations mean.

#### 7.8.1 The facts

| Id | Statement | Status | Notes |
|---|---|---|---|
| **F1** | Process instances are boot-scoped: given a verified ordinary kernel restart, processes from the previous kernel instance cannot continue as those same instances. | Adopt; card + ratification pending | A constraint on observation meaning, never an explanation. Cuts both ways: pids and logind session ids are per-boot counters, so equality across a boot is not continuity. Instances only: whether *names* come back is behaviour (resurrect), and stays learned. |
| **F2** | Clock domains are boot-scoped: boot-relative counters share an epoch only within one boot. | Adopt; card + ratification pending | Already relied on by trusted-state §5.3 (`2026-09-06-trusted-state-step-1.md:145`) and the clamp guard. |
| **F3** | Suspend clock semantics: the monotonic clock pauses across suspend; the boottime clock does not. | Adopt per platform; inactive where C0.9 has not verified it | The A5 lesson (`trusted-state:146`). |
| **F4** | Suspend and hibernate preserve process instances and boot identity. | Adopt; card + ratification pending | Rules an explanation out: a sleep never explains a departure. Hibernation's restore kernel is not a boot. |
| **F5** | Volatile kernel network state (sockets, WireGuard handshakes, interface instances) is boot-scoped. | **Deferred** | Kept narrow; drafted only when a learner needs it. |

#### 7.8.2 Admission criteria (every one must hold; I40)

- **A1.** It passes the four tests: *host-invariance* (no correctly working instance of the stated OS and version can violate it, under any configuration or habit); *a violation is a tripwire* (a contradiction means forgery, a snapshot restore or a collector bug, never "this host is different"); *no parameters* (no rate, duration, window, threshold, "usually", "expected" or "benign"); *evidence is conserved* (it only scopes identity comparisons and removes observations that are certain given an event from the likelihood of parameters they cannot inform, and that event is itself scored).
- **A2.** It cites the OS source or specification, scoped to platform and version. On an unknown platform or version it is inactive.
- **A3.** It is independent of configuration. If configuration can change it, the configuration is measured as a fact instead.
- **A4.** Its precondition is attested by the kernel and established independently of the consequences it covers. For F1 that is the conjunction of I41; any inconsistency makes the fact inactive and raises an integrity notice.
- **A5.** It has a tripwire.
- **A6.** Its effects come from a closed set: scope identity comparisons; exclude certain-given-the-event observations from the likelihood of parameters they cannot inform; fire its tripwire. It may never recover or close an alert; admit or fold pending observations; change severity or define normal; open any time window or act after the first post-boot census; or reset memory.
- **A7.** The event that absorbs the evidence is scored in the same learner, and is no cheaper for an attacker to produce than the evidence it absorbs.
- **A8.** Necessity: the learned alternative is shown to be degenerate (the value is known and the same on every host) or harmful.
- Astra's per-fact specification is required as well: a stable id and version; the authoritative OS contract; supported platforms; exact premises and conclusion; trusted evidence requirements; exclusions; permitted downstream uses. A statement that needs "usually", a time allowance or knowledge of normal workloads does not belong in F.

#### 7.8.3 What must stay scored before F1 may act in a learner

F1 activates in a learner only if all of the following are live **in that same learner** (F-class opinions, Opus §2). That is why the reboot-event stream moves into C5.

1. **The reboot itself** (EVENT): frequency given hour-of-week and presence; uptime at reboot; cause corroboration (a shutdown row present or `unknown`, §4.1; an OS build change across the boundary; later, `software_change`); drift in reboot frequency against the anchor. The reboot context is scored once, not once per response stream (§7.3).
2. **Every interval that does not cross the boundary**: ordinary hazard scoring up to the last pre-boot census and from the first post-boot census onward, with **no grace period**.
3. **The unobserved straddle**, reported as abstention with durations: pre-shutdown (last census → boot) and post-boot (boot → first census). These intervals are "unobserved", never "explained", and never recover anything. The +0 boundary census (C0.12) shrinks the post-boot gap.
4. **Post-boot arrivals and identity continuity**, learned per host and labelled prior-governed until data overrides: the restoration deficit (a pre-boot name that does not come back on a host that has learned to restore); foreign names arriving during the restore ramp; content changes in restored sessions (window-count bucket). Restored does not mean trusted.
5. **Tripwires** (integrity events): a pre-boot instance in a post-boot census (`created_vs_boot = before_boot`, I51); a boot-id change under a daemon process that never restarted; a boot id that regresses to an old value or is duplicated; a boot time outside (last observation, now]; uptime inconsistent with the gap.
6. **Unchanged streams**: logins, peer re-handshakes, tailnet transitions, and service and persistence novelty at boot.
7. **Pre-boot alerts.** F1 never recovers or closes them; across a boundary a restored name is a new instance (CC3-E).

**Long memory.** F never resets, partitions or ages statistics by boot; only instance identity is scoped. Otherwise a forced reboot would become a memory-wipe tool.

#### 7.8.4 The kill-switch fallback (option D)

Each fact's kill switch reverts to option D of the Opus opinion: the boundary interval is its own regime, not shrunk toward the within-boot hazard, with a weak prior (Beta(1,1)). It still needs the verified boundary and gains no tripwire, so it is a fallback, not the design. Option A (the boundary interval in the ordinary hazard with a shrunk boot covariate) is rejected: its prior asserts that reboots do not end processes, which is false on every machine, and boundary departures would inflate the post-boot hazard and hide post-boot kills. Option B (a strong overridable prior) is rejected because its "contrary data wins" fixture would need physically impossible data. Option C (a federated prior) is for behaviour (restoration rates, reboot rates per OS), later.

#### 7.8.5 Review process (per fact)

1. Write the F-card (C0.13): statement, spec references, platforms and versions, preconditions, consequences, tripwire, and the broader wordings that were rejected.
2. daybreak-blue adversarial review, on two questions: can the precondition be made true without the consequence, and does the fact absorb anything behavioural?
3. Operator ratification, once per fact. That sets the policy envelope; it is not per-item consent (`autonomy-doctrine.md:39-50`).
4. A registry entry as a fixed, audited primitive the agent can never author (`autonomy-doctrine.md:33-37`), plus its inventory row.
5. A kill switch per fact (§7.8.4).
6. Re-verification on every OS major version. Any tripwire that fires in the field triggers re-review.

**Rejected as F** (each smuggles behaviour or fails a criterion): "names, sessions or peers come back after boot or wake (within N)"; "a reboot, or an update reboot, is benign or expected"; any window ("the first tick after boot", "N minutes after boot"); "a boot-id change is a reboot" (that is a precondition to verify); "logout ends the user's processes" (depends on `KillUserProcesses` and the launchd session type); "a userspace reboot or soft-reboot is a boot" (the kernel survives; measure it as its own fact); "`/tmp` or `/run` is empty after boot" (measure the mounts); "utmp/wtmp is complete" (use a time-confidence field); "a clock step is benign"; "tmux server death explains all of its sessions' departures" (the death is a user-level, unattested event and is itself the mass-kill shape; it fails A4 and A7); "creation fingerprint bytes cannot survive reboot" (values can recur or be restored); "a reboot explains every departure since the previous census" (it invents causal timing); "VPN disconnection makes peer loss benign"; "matching names prove recovery".

#### 7.8.6 Tests

- **Real-OS conformance** (C0.8; the Linux side CI-gated): a Linux CI VM reboot (`boot_id` changes; no pre-boot pid/starttime survives; no process starts before btime); kexec; soft-reboot leaves `boot_id` unchanged; a macOS tart VM reboot (`bootsessionuuid` changes; no tmux session created before boot time); `launchctl reboot userspace` (record whether `bootsessionuuid` changes); snapshot revert (regression detected); laptop sleep and hibernate (C0.9).
- **Model fixtures:** `f1_boundary_excluded_from_hazard`; `f1_boot_event_scored` (a 03:00 reboot, screen locked, no update, raises in the reboot stream); `f1_restoration_deficit_raises`; `f1_foreign_arrival_raises`; `f1_no_cross_boot_fingerprint_compare` (unevaluated, frozen, never "clear"); `f1_recycled_id_not_continuity`; `f1_tripwire_preboot_instance` (`unknown` if a clock step was recorded); `f1_fail_closed_daemon_not_restarted`; `f1_boot_id_regression`; `f1_never_changes_alert_status_or_pending`; `f1_straddle_reported_unobserved`; `f1_no_grace_after_first_census`; `f1_kill_switch_reverts`.
- **Integration:** F1 neither clears unrelated alerts nor admits whole suspicious episodes into training; every application is logged with its evidence and scope; a contradictory observation disables applicability pending review (F-class opinions, Astra §4).

## 8. Long memory without the capacity conflict (Opus H7; both audits; re-review M5)

### 8.1 The `tick_summary` family

- **One record per structural tick and per transition-triggered sample**, holding:
  - per-source counts, arrivals, departures and churn;
  - per-source census states and census universe (I49);
  - **the departure basis**: a keyed digest of the census entity set (entity keys plus instance fingerprints) per source, and a link to the previous record, so departures for (r_{i−1}, r_i] are computed once, against the immediately preceding record, whether that was a structural tick or a sample (M5(a));
  - the raw-resolution context: boot id HMAC, seconds since boot, boundary verification, suspend bounds, tailnet/VPN states, `net_config` HMAC, local time plus UTC offset, presence, clock and timezone events;
  - collector states and observation times;
  - the Descartes version and config hash.
- **No entity keys.** Entity memory stays in the seen-sets. The previous entity set needed to chain the next interval is held in a small **census chain state** per source (one snapshot, bounded by the entity caps), ledger-stamped like a seen-set. If it is missing or invalid, the next interval's transitions are `unknown`, never zero (I50).
- **Size and caps (L2).**
  - A record is at most **1 KiB** at worst case, pinned by a T8-style test, with explicit caps: ≤ 8 VPN service states (overflow counted); a fixed, closed list of collectors for observation times; ≤ 8 interval events (overflow flagged).
  - The T8 floor gains a records-per-interval term: (H / interval) × records per interval (≤ 5 per hour: 1 structural plus at most 4 samples, I15) × worst-case record bytes × 1.25. That extends the capacity formula (`fact-families.js:343` @ 2dce005), which assumes one record per structural tick (M5(c)).
  - At worst-case cadence, 30 days takes ≈ 4.4 MiB including the 1.25 headroom; at the typical 1 record per hour it takes ≈ 0.9 MiB.
  - Record size is independent of entity count, so volume inflation cannot evict this memory.
- **Integrity (M5(b)).** A seen-set is one snapshot validated against its own family's latest pass (capacity `novelty-seen-set.js:20-25`); `tick_summary` is an append-only, cross-family history whose samples are primary data that cannot be re-derived. So it gets its own family ledger and a **multi-ledger validity rule**: each record carries the ledger passes of the families it was derived from; while those families are within their raw retention, the reader checks that each referenced pass is within the certified span; beyond it, the record's own hash chain and its family ledger's continuity certify it. A gap is a loss marker, never silence.
- **Horizon and retention.** A horizon of **at least 30 days is declared in `RULE_HORIZONS`** (S floor). Outliving the raw window needs **per-family retention**, which the capacity branch does not have (`fact-store.js:31` @ 2dce005); C2 adds it. The default beyond 30 days is an O resource choice (Q5).

### 8.2 Long-lived sufficient statistics

- **What is kept.** Per stream and cell, conjugate statistics (counts, exposure) plus per-episode records for rare events (boot, wake and network-change aftermaths).
- **Dated records.** Records are dated, so a forgetting rate can itself be learned later.
- **Bounds and integrity (M5(d)).** Capped (I3), and stored as a registered family with its own ledger and lineage stamp. A history loss cold-starts the affected statistics, raises an integrity notice and is recorded as `memory_lost`. While the loss stands, the affected streams can raise but never recover or admit. It never declares "everything normal". Wiping this store is therefore not cheaper for an attacker than the H7 volume attack.

### 8.3 Reference snapshots and drift

- **Snapshots kept.** Durable, versioned parameter snapshots: the incumbent anchors ratified at C1a (§6.5); learned snapshots at promotion and at ratification (the ratified one is the drift anchor); pre-episode snapshots for open episodes; a bounded number of periodic references.
- **Slow drift** is the cumulative divergence of the current predictive from the anchor's, on reference cells. It is not "recent versus rolling 30 days", which a slow poisoner walks along with (Astra 5; `autonomy-doctrine.md:110-116`). The `cusum` kernel (`model-ir.js:366`) is the candidate detector.
- **Measures per kind (H3, I20):** learned predictive divergence on reference cells; incumbent Welford |Δμ| in the incumbent's own z units; admitted unexplained entities per novelty family; the Good–Turing novelty rate per dimension (L3).

## 9. Labels and the outcome loop (both audits; Astra 13; Opus M10; re-review M1)

- **Append-only alert transitions** (`alert-transitions.jsonl`).
  - Records: `activated`, `incident_opened`, `escalated`, `frozen`, `recovered` (evidence), `closed` (label or D1 explanation, with reason), `admitted`, `admitted_unexplained`, `admission_revoked`, `pending_discontinuity`.
  - The log is hash-chained, so it is tamper-evident at the same UID, though not tamper-proof. It is one of the two records that define pending membership (§6.4).
  - **Re-grounded on the branch tip** (`feat/notify-once-2026-10` @ 25cf225, verified v3): the daemon is the sole alert-state writer and CLI mutations go through an append-only command queue (`alert-command-queue.js`), which is the natural single place to emit transitions. The episode is `(alert id, incident_key ?? "default")`. The branch has no transition log and no episode counter.
- **`activated` is a status transition** from a non-active state (absent, `recovered`, `closed`) to `active`. It is not a `newEpisode` and not a `newIncident`. Incidents are counted separately (`incident_opened`). Counting activations keeps a persistent EVENT episode with many incidents from inflating `fired_count` into `chronically_firing` (`calibration.js:293`), and from there into retire proposals (`tuning-store.js:413`, applied on approval at `tuning-authority.js:390`) (M1).
- **Fix the verified tuning-loop defect (C1.2).**
  - The fix: count `fired_count` from `activated` transitions, not from snapshot records (`calibration.js:245`, `tuning-store.js:427`).
  - For transition-backed rows, `fired_count_is_lower_bound` (`calibration.js:306`) then becomes false.
  - No standalone todo exists for this defect. This plan owns it as a prerequisite unless the operator splits it out.
- **Labels, separate from acknowledgement.**
  - Acknowledgement is receipt only (`alert-store.js:366-376`).
  - The labels are `benign`, `suspicious`, `expected` (an explained change), `mine` (the operator's own action), `confirmed_incident`, and `missed_incident` (for recall).
  - They are stored as append-only records with their source (CLI, uid) and scope: an alert id plus incident keys, or a pending window. They can be applied in bulk from the digest.
  - Neither an LLM `notify:false` nor a fast recovery is a label (Astra audit).
- **Label-poisoning bound** (mechanism S, label budget O). Labels are writes at the same UID, so a same-user attacker can forge them. Therefore:
  - (a) Labels never raise a model's authority above notify-only.
  - (b) Labels admit pending items only within the drift budget, which now exists from C1a on (§6.5).
  - (c) Label volume is itself a scored stream. A burst beyond the label budget leaves its items pending and raises an integrity notice.
  - (d) Promotion evidence counts only labels gathered under the calibration protocol (§10).
  - The doctrine requires that ground truth be fed, never minted (`autonomy-doctrine.md:126-129`). On-host labels are fed but forgeable, and are bounded accordingly.
- **Declaring a new normal** means labelling a pending window `expected`, within the drift budget. Going beyond the budget needs re-ratification of the anchor (§6.5, §11.3).
- **Reports separate four outcomes:** correct silence; abstention (including `exposure_uncertain` and the unobserved straddle); frozen; unsupported. The precedent is `model-ladder.js:150`, which already separates unsupported evaluation from a correct negative.

## 10. Evaluation protocol, written before model selection (Astra 13; Opus M7; re-review M8, M9)

All of this is pre-registered and frozen in step C3b, before the C4a spike runs.

1. **Corpus.**
   - Source: the 2026-10-05 calibration laptop's history, copied with identifiers HMAC'd.
   - **Observed context (M8).** On `main` nothing collects boot id, suspend, `net_config` or presence (`daemon.js:395-403`); a non-running tailnet leaves no fact (`tailscale-status.js:164` → `fact-translators.js:999`); `last` reboot rows are dropped; uptime is a 24-hour metric. So the go/no-go corpus is the calibration laptop's history **after at least four weeks of C2 collection** on it, with context as observed.
   - An earlier spike on today's history is allowed only as a declared **upper bound** with operator-reconstructed context. It cannot produce a "go" on its own, and the labels used to reconstruct context may not also serve as evaluation labels (no circularity).
   - Labels: operator-confirmed, covering its reboots, wakes, tailnet flaps and the events behind R4–R10. Reboots and wakes are *events*. They are not benign labels for whatever surrounds them.
   - This dev host is not a corpus: 0 reboots in the window (last boot 2026-09-04, verified); never slept (verified); its daemon is stale, and its stderr shows earlier ENOSPC errors (Opus M7).
2. **Scenarios**, written before any model exists:
   - Base set: mass session kill (the 2026-07-11 shape); kill and replace; an odd-hour unattributed login; drift over several days kept below threshold; a kill inside a reboot aftermath; **a sustained kill kept for 30 days** (re-review H2).
   - Adaptive set: toggle-then-act (`tailscale down` or `scutil --nc stop`, then kill); new-network-then-act; a sub-threshold drift chain across refits; volume eviction (Opus H7); context-switch recovery (the three v1 Opus B1 scenarios); **quiet-interval recovery after a kill** (re-review B1); a label burst; **pending-state laundering by deleting or corrupting `alerts.json`, the pending store or the seen-set** (re-review H4); **kill then force a reboot**; **kill just before an update reboot**; **a faked boot boundary** (clock step, stored-state tamper, snapshot revert); **reboot flooding**; **moving a multiplexer binary aside** (I49).
3. **Coherent chronological replay.** An injection changes the whole observation sequence consistently: census markers, entity keys, creation fingerprints, `created_vs_boot`, context facts, boot identity and the integrity ledgers. The result is replayed through the real translators and detectors. An impossible observation sequence counts as a test bug.
4. **Metrics.**
   - Predictive calibration (PIT).
   - Per-episode detection and delay. The delay floor is about one structural interval, lower with transition samples.
   - False alerts per week on labelled benign episodes, measured out of sample.
   - Rates of abstention, freezing and correct silence, reported separately.
   - Resource cost (shadow included) and uncertainty intervals.
   - Synthetic recall is scenario recall, never real-world recall.
5. **Promotion bar (numeric and classified).**
   - Minimum evidence (S): every pre-registered scenario has run; held-out days and labelled benign episodes per event type meet the protocol's minimum.
   - Operator tolerance (O): the maximum false alerts per week, and the minimum scenario detection relative to the incumbent. This is where the incumbent comparison lives now (§7.2).
   - Proposed values are written in C3b for the operator to ratify (Q5).
6. **Compare against the incumbent, knowing it is noisy.** Fewer alerts is a win only if scenario detection holds.
7. **Negative results (M9).**
   - A C0.9 no-go on a platform is a result, not a blocker: the learner runs there with the exposure interval `[0, wall Δ]`, and the report states the sensitivity cost.
   - Exposure bias is checked directly: on held-out wake episodes, the rate of raises attributable to exposure uncertainty must be zero under I46, and any non-zero rate is a test bug.
   - "Skip the full design" remains a valid C4a outcome.

## 11. Authority (Astra 1; Opus H8; D2)

### 11.1 Additive promotion

Shadow → notify-only on the existing ladder, whose ceiling is notify-only (`model-ladder.js:1-9`). A notify-only learner alerts alongside the incumbent and cannot suppress anything.

### 11.2 Replacement: the per-host opt-in envelope (D2, DA1)

**Why it needs an amendment.** Replacing a detector reduces what alerts. That is suppression plus sticky adaptation, which the doctrine places above the on-host ceiling (`autonomy-doctrine.md:61-68,126-129`; behavioral-modeling plan `:118-121`). The session and peer detectors are WATCH-tier and default-on, while the doctrine keeps learned models default-OFF (`autonomy-doctrine.md:134`). The operator decided (D2) to permit replacement through a per-host opt-in envelope; DA1 drafts the doctrine text.

**The envelope.**
- **Operator-ratified and recorded**, per host and per detector family. Example: "on this host, session-departure alerting routes to lineage L at ratified snapshot R." Set once per family per host, not item by item.
- **Reversible**: rollback is a routing flip.
- **Old detectors stay in code**, and routing is per host. No code is deleted, which honours roadmap §11 ("Fixed rules never weakened", `2026-07-09-self-learning-stratified-monitoring.md:224`).
- **New installs**, and any host without a ratified envelope, run the incumbents.
- **On a replaced host**, the incumbent keeps running in shadow with its alerts logged, so a regression is visible.
- **Refits** stay inside the drift budget anchored to the ratified snapshot (§11.3).

### 11.3 Post-promotion refits

Refits are bounded by a cumulative drift budget anchored to the ratified snapshot (§8.3); a rolling window is not an anchor. Exceeding the budget has three effects:
- The lineage drops back to notify-only, and the incumbent is re-routed.
- A notice is raised.
- Re-ratification is required.

### 11.4 Structure changes

A structure change creates a new version, which enters shadow.

### 11.5 Auto-demotion

The anomaly-of-anomaly guard applies (behavioral-modeling plan `:120`). Without it, an attacker who poisons a good detector's inputs could get that detector auto-quarantined.

## 12. Delivery (Opus M9; Astra 16; re-review M1, M2)

- **R3 notify-once** is built separately on `feat/notify-once-2026-10` (@ 25cf225, verified v3), with **producer-declared incident identity**:
  - the episode is `(alert id, incident_key ?? "default")`; diagnostic statistics, timestamps and stability counters never create episodes;
  - it notifies on activation, on a new incident key within the episode, and on escalation above the highest severity already notified;
  - it rearms after recovery (and, from C1.1, after `closed`);
  - acknowledgement does not block a later incident or escalation;
  - delivery is at-least-once, and the daemon is the single writer.

  It is O policy, independent of model truth and training eligibility. This plan's learned producers declare their keys per §6.1: event-set identity for EVENT streams, `default` for LEVEL streams.
- **Attention budget as a calibrated α allocation.**
  - A test notifies when its calibrated predictive p-value is ≤ α_i.
  - The α_i are allocated across streams so that the expected notifications per week ≈ N (O).
  - Calibration is checked by PIT on held-out data.
  - The budget is never a threshold that deletes detections: every detection is recorded and visible, and the budget governs only push delivery.
  - It is never re-derived from recent surprise history (which an attacker can game), and never raised during a flood; a flood produces a digest notice instead.
- **Severity** is a mapping from calibrated surprise and from corroboration across **distinct evidence sources** (O mapping, S counting rule, I29). A shared context event counts once (M2).
- **The digest** lists, per period: `admitted_unexplained` admissions, open frozen EVENT alerts awaiting a label (for bulk labelling), integrity notices, and abstention counts.

## 13. Tier (Astra 15; D3)

- **Watch tier.** L1 context collection, `tick_summary`, the pending ledger, the incumbent anchors and **default-on shadow learning** run under `watch.json`. Shadow learning has no authority and runs under the bounds and kill switch of §7.7 (D3, DA2). Data collection turns on once the C0 fixes land; shadow learning once DA2 is ratified.
- **Learned tier.** Agent authoring, the AUTHOR-pipeline shadow constraints (`daemon.js:1061-1079`) and any promotion stay under `learned.json`, default-OFF, as today (`autonomy-doctrine.md:134`).
- **Replacement** is an authority question (§11, D2), not a tier choice.

## 14. Sequencing and gates

| Step | Content | Gate | Needs |
|---|---|---|---|
| **C0** | Prerequisites (§3), including C0.1b census universes, C0.12 boundary census, C0.13 F-cards | daybreak (collectors, schemas, sanitization, sub-deadlines, boundary verification); review (inventory, C0.9 write-up); operator ratification per F-card | `fix/collector-sources-2026-10` merged with C0.1b |
| **CAP** | Merge `feat/fact-store-capacity-2026-10` (daybreak G3 READY). External to this plan. | that branch's gates | — |
| **DA** | Draft DA1–DA3 as one reviewed change to `docs/design/autonomy-doctrine.md` | review + operator ratification | D1–D3 |
| **C1** | Merge R3 from its branch. C1.1 append-only, hash-chained transitions, the `closed` status, and transitions emitted at the daemon's single writer. C1.2 `fired_count` from `activated`. C1.3 label store with the poisoning bound and bulk labels. C1.4 the pending ledger (§6.4). | daybreak (alert-store, pending ledger) | `feat/notify-once-2026-10`; CAP (C1.4 stamps to the family ledgers) |
| **C1a** | Arbitrated adaptation for the incumbents: (i) session/peer folds with ratified anchors, pre-episode snapshots and per-kind drift measures (§6.5); (ii) novelty pending lifecycle per D1 (§6.6). Admission by label from day one; by bounded quiet once DA3 is ratified. | **daybreak (security-critical)** | **CAP** (it rewrites the session, peer and service baselines that C1a changes, and the seen-sets exist only there), C1.1, C1.3, C1.4; DA3 for bounded quiet |
| **C2** | L1 facts, `tick_summary` with chaining and multi-ledger validity, per-family retention, long-lived statistics skeleton, transition samples including +0 | daybreak | C0, CAP; F2 and F3 ratified for the clock and suspend facts (else their facts are `unknown`) |
| **C3** | L2 vector and `baseline inspect` | review + property tests (recomputable; stable across timezone changes; no target-derived dimension by field provenance) | C2 |
| **C3b** | Pre-register the evaluation protocol; collect the calibration corpus and labels | review + operator | Q6 |
| **C4a** | **Time-boxed spike (≤ 1 week, written go/no-go).** Replay the corpus through (i) the incumbents, (ii) a minimal boot-id + tailnet-state transition model, and (iii) as much of the full design as the spike can build. Decide whether the `model-ir` fit holds or the divergence is justified. "Skip the full design" is a valid outcome. An earlier upper-bound run is allowed but cannot alone yield "go" (§10.1). | review | C3b corpus with ≥ 4 weeks of C2 context (M8) |
| **C4** | Estimator kernels in `model-ir` with runtime budgets; the adequacy gate (§7.2) | review + property tests | C4a go |
| **C5** | **One vertical shadow learner**: session departures and arrivals **plus the reboot-event stream** and the other §7.8.3 items, with the coverage contract enforced in the shadow log, default-on shadow isolation, daemon integration and runtime limits. F1 runs only if ratified and §7.8.3 is live; otherwise option D. | **daybreak** (the named `cc_*`, `id_*`, `f1_*` and `shadow_*` tests; poisoning; runtime) | C4; DA2 for default-on (until then under `learned.json`) |
| **C6** | Evaluation report per §10. Earliest at C2 landing + 30 days; for rare-event cells, months. | review + operator | C5 |
| **C7a** | Notify-only (additive) promotion. The promoted learner becomes a `context_model` explanation source for its stream. | ladder + daybreak re-gate | C6 |
| **C7b** | Per-host replacement envelope and the post-promotion drift budget (§11.2–11.3) | daybreak + operator ratification per host and family | DA1 ratified; C7a |
| **C8** | Repeat C5–C7 for peers per source, login arrivals and context streams | as above | C7a |

- **Linux sources are CI-gated**, because the dev host cannot run VMs.
- **C2 is the urgent data step.** The learners need weeks of context history, and C4a now waits on four weeks of it on the calibration laptop.
- **C1a is the urgent safety step**, and it waits on CAP. Splitting the fold half onto `main` ahead of CAP would be rewritten by the capacity merge (H3).

## 15. Non-goals

- No new hand-written behaviour rules, thresholds or suppressions. R4–R10 stay rejected.
- No shorter memory.
- No LLM in the detection path.
- No new privilege. The root helper remains optional.
- No change to the incumbents' constants. They are retired only by per-host routing under C7b.
- No F1 change to the incumbent `session.churn`, even though F1 would remove its cross-boot resurrect false positives (`session-baseline.js:456-644`; Opus audit `:33`). That changes an incumbent and overlaps R6's mechanism, so it is a separate operator decision (Q8).
- No design of federated explanation sources beyond the interface of §6.3.1.
- No change to the doctrine in this plan: DA1–DA3 are drafted as a separate reviewed change.
- Some audit findings are out of scope here and remain follow-ups that reuse this substrate:
  - the fixed resource reflexes (`alert-store.js:88-96`, `tools/findings.js`);
  - the provenance launch-path lists;
  - the credential path list;
  - the constraint miner.

## 16. Open questions and operator actions

**Resolved by the operator decisions:**
- ~~Q1 Tier for shadow learning~~: default-on shadow (D3; DA2; §7.7, §13).
- ~~Q2 Replacement authority~~: per-host opt-in envelope (D2; DA1; §11.2).
- ~~Q3 F class~~: allowed in the reviewers' narrowed form (D4; §7.8). Each fact still needs its own ratification (below).
- ~~Q4 Novelty lifecycle~~: pending until explained (D1; §6.3, §6.6).

**Still open:**
5. **Policy-envelope values (O).** The bounded-quiet period; the drift-budget sizes per kind; the label budget; N notifications per week; the promotion-bar tolerances; the shadow resource bounds; the `tick_summary` retention beyond 30 days. Accept the defaults C3b will propose, or set them yourself?
6. **Calibration corpus.** Copy the calibration laptop's history (HMAC'd), spend about an hour labelling its reboots, wakes and flaps, and **keep C2 running on that laptop for at least four weeks** before the C4a go/no-go (M8)?
7. **Bounded-quiet closure of non-novelty EVENT alerts (new).** D1 lets bounded quiet close novelty alerts. Should it also close departure, arrival, churn, reboot and context-transition alerts? Default in v3: **no**. Bounded quiet admits their pending data, the alert stays open until a label, and the digest offers bulk labelling (CC7).
8. **F1 on the incumbent `session.churn` (new).** Apply F1 to remove the incumbent's cross-boot resurrect false positives, with the verified boundary? Default in v3: **no**, per I35 and §15.

**Operator actions (not questions):**
- Record D1–D4 in `todos/2026-10-06-session-peer-tuning.md`, whose decision table this plan cannot edit.
- Ratify DA1–DA3 once drafted (step DA).
- Ratify F1, F2, F3 and F4 one at a time, after each F-card's daybreak review (§7.8.5).
- Ratify the incumbent anchors once per host when C1a lands (§6.5).

## 17. Key code refs

Refs on `main` were verified at daff6ed (v2) and still hold at 1ac41a2 (v3; the code is unchanged). Branch refs name their tip.

- **Global folds and scoring:** `welford-stats.js:20`; `session-baseline.js:68-83,272-287,407-438,432,661-662,897-915`; `peer-baseline.js:50-61,447-452,537-602`.
- **Recovery path:** `alert-store.js:27-30,189-212,200,229-237,263-323,366-376`; `daemon.js:834-850`; `service-baseline.js:455-476`.
- **Session identity:** `fact-translators.js:644-654` (entity key), `:666-673` (creation fingerprint); `tools/sessions.js:38` (`#{session_created}`), `:133` (screen pid in name).
- **Dropped context:** `tools/tailscale-status.js:81,137,164` → `fact-translators.js:998-1007`; `tools/network.js:81-261` → `fact-translators.js:532`; `vpn-peer-status.js:89-102,124,151,203,324,341,420-427`; `fact-translators.js:887,937`; `tools/system.js:65`, `daemon.js:307`.
- **Daemon:** cadence `daemon.js:64-67`; sequential collection `:395-403`; structural due check `:972`; all-or-nothing deadline `:984-993`; common tick ts `:1017-1028`; learned-nested AUTHOR shadow `:1061-1079`; plist `:1596`.
- **Outcome loop:** `calibration.js:57-64,245,293,306`; `tuning-store.js:413,427`; `tuning-authority.js:390`.
- **Model substrate:** `model-ir.js:262-455` (ops; inclusive z-score `:335-341`; cusum `:366`); `model-ladder.js:1-9,150`.
- **Notify-once branch @ 25cf225:** `alert-store.js:34-37` (`alertId`), `:64-79` (incident keys, `alertEpisodeKey`), `:220` (status list), `:345-358` (`notificationDue`), `:383-385` (`newEpisode`), `:399` (`newIncident`), `:401` (256-key overflow), `:442-451` (recovery); `alert-command-queue.js`; README "The producer declares incident identity".
- **Collector-sources branch @ 3c18739:** `fact-translators.js:728-731` (`censusStateFor`), `:733-738,751` (`binary_availability`); `peer-baseline.js:63-74` (incomplete VPN-services slot); `tools/sessions.js:153-183`; `tools/vpn-peer-status.js:326-338` (real-output parser); `tools/binary-resolver.js`.
- **Capacity branch @ 2dce005:** `fact-families.js:108-130` (`RULE_HORIZON_ENTRIES`), `:149` (`RULE_HORIZONS`), `:240-249` (budgets), `:258-273` (tick shapes), `:343` (T8 floor), `:358` (4× ceiling); `fact-store.js:31` (single retention); `novelty-seen-set.js:16-18` (memory only suppresses a claim), `:20-25` (lineage stamp), `:26-35` (re-seed).
- **Trusted state:** `2026-09-06-trusted-state-step-1.md:141-148` (§5.3 B-ledger; `:145` boot id; `:146` A5 lesson).
- **Doctrine:** `autonomy-doctrine.md:33-37,39-50,46-50,61-68,101-116,120,126-129,134`.

---

## Appendix A: Review disposition

Every finding is **Accepted** unless noted. "Where" points to the v3 section that addresses it.

### Operator decisions (2026-10-06)

| Id | Decision | Where |
|---|---|---|
| D1 | Novelty pending until explained; explanations: context, labels, bounded quiet; federated signatures later | §6.3, §6.3.1, §6.6, DA3, I19, I48 |
| D2 | Replacement by per-host opt-in envelope | §11.2–11.3, DA1, C7b |
| D3 | Default-on shadow learners | §7.7, §13, DA2, I47, C5 |
| D4 | F class adopted in the reviewers' narrowed form | §0.4, §7.1, §7.6, §7.8, I33, I36–I41, C0.12, C0.13 |

### v2 re-review (`2026-10-06-context-plan-v2-rereview-opus.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| B1 | No recovery rule for event streams; a departure alert recovers on the next quiet interval | Accepted. Streams declared EVENT or LEVEL; an event alert recovers only on positive evidence (departed keys present again in the same boot, cumulative deficit empty), otherwise frozen until a label; never across a boot by restored names; level streams keep level semantics; gate tests for both kinds. | §6.0, §6.2 CC3-E, `cc_e_*`, `cc_l_*`, I42 |
| H1 | Identity by stratum class makes alerts unrecoverable and multiplies notifications | Accepted. Alert id = rule, lineage, `structure_id` only; `incident_key` = event identity or `default`; stratum and raising cell in `raise_ref`; recovery re-scores the raising cell instead of requiring a return to it; never-observed dimensions excluded from the host vocabulary; `not_applicable` and stable not-found are known; back-off raises recover at the same level; identities bounded. | §6.1, §6.2 CC3, §5, I43, I22, I4 |
| H2 | C1a absorbs a sustained shift as old data ages out, then recovers on unchanged evidence | Accepted. Ratified anchors; persisted pre-episode snapshot scoring that outlives the raw window; re-warm-up ticks pending; incumbent recovery per CC3(e); exit by label or bounded quiet on the new level, within the drift budget. Aging out is never an explanation. | §6.5, §6.3, P3, I45, I19 |
| H3 | C1a cannot be built in the stated sequence | Accepted. Anchors built at C1a, decoupled from C7b; drift measures per incumbent kind; C1a (both halves) sequenced after the capacity merge; context path abstains until C7a; bounded quiet waits on DA3. | §6.5, §8.3, §14 (CAP, C1, C1a) |
| H4 | Pending state has no integrity-protected home | Accepted. Ledger-stamped pending store per family plus the hash-chained transition log; disagreement or loss fails closed; sufficient-statistic retention instead of eviction; overflow fails closed; seen-set re-seed cannot drop pending status. | §6.4, I44, I3 |
| M1 | Stale picture of notify-once; digest churn inflates `fired_count` | Accepted. Re-grounded on 25cf225 (producer-declared `incident_key`, no material digest); `raise_ref` is diagnostics only; `activated` is a status transition, incidents counted separately. | §6.1, §9, §12 |
| M2 | Joint scoring counts one context event in every stream | Accepted. Each term owned by one stream; corroboration counts distinct evidence sources. | §7.3, §12, I29 |
| M3 | The adequacy gate uses the incumbent's z = −6 constant | Accepted. Adequacy = PIT + flagged at α_i + prior-sensitivity stable; incumbent comparison moved to the O promotion tolerance. The re-review's arithmetic was verified. | §7.2, §10.5, I12, I35 |
| M4 | O class contradicts itself; bounded-quiet admission is an unflagged doctrine exception | Accepted. O redefined as parameters of S mechanisms; admission mechanisms are S; on-host admission recorded as DA3. The re-review's proposed question ("bounded-quiet admission into the incumbents, or label-only until attestation?"; not this plan's §16 Q7) is answered by D1 for novelty; for the statistical folds it is settled by DA3 ratification, label-only until then. | §0.4, Operator decisions, I19, I20, I27 |
| M5 | `tick_summary` cannot chain samples; its integrity model does not fit | Accepted. Departure basis plus previous-record link; ledger-stamped census chain state; multi-ledger validity rule; records-per-interval term in T8; per-family retention; long-lived store loss is an integrity notice and fails closed. | §8.1, §8.2, I2, I50 |
| M6 | The leakage check cannot enforce what it promises | Accepted. I5 checked over field-provenance tags by physical object; wg link and Tailscale NE pairs banned. | §5, C0.6, I5 |
| M7 | Census semantics of not-found binaries unspecified | Accepted. Per-source census universes keyed by `binary_availability`; `untrusted_binary`/`unable` incomplete; availability change = new regime, crossing intervals `unknown`; required of the collector-sources branch before merge. | §1.5, C0.1b, I49 |
| M8 | The C4a corpus lacks the context it evaluates | Accepted. Go/no-go on ≥ 4 weeks of C2 context on the calibration laptop; an earlier run is a declared upper bound only; no label circularity. | §10.1, §14 C4a, Q6 |
| M9 | C0.9 has no negative-result plan; exposure leans toward alerting | Accepted. Per-platform go/no-go with a defined fallback; exposure as an interval; raise only if surprising at every exposure, recover only if unsurprising at every exposure. | C0.9, §7.1, §10.7, I46 |
| L1 | The TTO formula is not a time | Accepted. Pinned exposure and event conditions; wall time derived from accrual rate. | §7.6, I23 |
| L2 | The 1 KiB bound has no caps behind it | Accepted. Explicit per-field caps with overflow counts. | §8.1, §4.2, I2 |
| L3 | Good–Turing novelty can be gamed | Accepted. Novelty rate scored for drift against the anchor. | §7.3, §8.3, I21 |
| L4 | The novelty half of C1a does nothing until Q4 | Resolved by D1. | §6.6 |

### F-class opinions (`2026-10-06-f-class-opinions.md`)

| Item | Disposition | Where |
|---|---|---|
| Both: ALLOW WITH CONDITIONS, narrowed to process-instance semantics, a constraint and not an explanation authority | Adopted as D4 | §7.8 |
| Astra: narrow §6.2's F admission path | Done: F removed as an admission path; `explanation_f1_never_admits` | §6.3 |
| Astra: reconcile §7.1 same-boot transitions with §7.6; separate instance identity from logical continuity | Done | §7.1, §7.6, §7.8.3 |
| Astra: fix event recovery before giving explanations operational effect | Done (B1) | §6.2 CC3-E |
| Astra: per-fact specification and adversarial fixtures; candidate judgments (admit F1/F2-shaped facts; reject "fingerprints cannot survive", "reboot explains every departure", windows, benign-reboot and matching-name claims); hibernation is not a boot | Adopted | §7.8.1, §7.8.2, §7.8.5, I38 |
| Opus edit 1: rename I33; rewrite §7.6 and Q3 around instances | Done | I33, §7.6, §16 |
| Opus edit 2: remove F as an admission path in §6.2 | Done | §6.3 |
| Opus edit 3: fix the inverted "compared only if Q3 ratifies" | Done: "never compared" | §7.1 |
| Opus edit 4: make the same-boot departure rule cite F1, with a published fallback if F1 is off | Done: cites F1; option D fallback with published TTO | §7.1, §7.8.4 |
| Opus edit 5: move the reboot-event stream into C5 | Done | §7.1, §7.8.3, §14 C5 |
| Opus edit 6: no recovery by restored names across a boundary | Done | §6.2 CC3-E |
| Opus edit 7: `created_vs_boot`, the OS build at the boundary, a +0 boundary census | Done | §4.1, §4.3, C0.8, C0.12, I15, I51 |
| Opus edit 8: incumbents unchanged; F1 on `session.churn` is a separate decision | Done | §15, Q8 |
| Admission criteria A1–A8; verified boundary by conjunction, fail closed | Adopted | §7.8.2, I40, I41 |
| Must-stay-scored list (reboot stream with frequency, cause and OS-build change; non-crossing intervals with no grace; straddle as abstention; restoration deficit and continuity learned; pre-boot alerts never recovered by restored names) | Adopted as a gate on F1 activation | §7.8.3 |
| Closed registry the agent can never author; per-fact F-card, daybreak review, operator ratification, kill switch, re-verification per OS major version | Adopted | §7.8.5, C0.13, I40 |
| Reject list | Adopted | §7.8.5 |
| Real-OS conformance and model fixtures | Adopted | §7.8.6, C0.8 |
| Options A–E (pure learner, strong prior, federated prior, feature only, F1 + D + C later) | E adopted; D is the kill-switch fallback; C reserved for behaviour, later | §7.8.4 |

### v1 Astra plan review (`2026-10-06-context-plan-review-astra.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| Astra 1 | BLOCKER: replacement and adaptation exceed authority | Accepted. Additive promotion on the ladder; replacement only via the per-host envelope (D2, DA1); refits drift-budgeted to the ratified snapshot. | §11, C7a/C7b |
| Astra 2 | BLOCKER: parent fallback fabricates recovery | Accepted. Fallback may raise but never recover; recovery re-scores the raising cell; event streams need positive evidence (re-review B1). | §6.1, §6.2 |
| Astra 3 | BLOCKER: lifecycle facts fabricate events and timestamps | Accepted. Verified boot identity; suspend as aggregate-duration intervals; clock and timezone facts. | §4.1, C0.8, C0.9 |
| Astra 4 | HIGH: conditioning explains the attack away; VPN target leakage | Accepted. Context dimensions are scored streams, counted once; leakage checked by field provenance; the evidence limit is stated. | §7.3, §5, §4.2, §0.3 |
| Astra 5 | HIGH: anomaly exclusion deadlocks and lets slow poisoning through | Accepted. Pending data retained in an integrity-protected ledger and visible to challengers; incumbents anchored (re-review H2); drift anchored to a snapshot. | §6.3–§6.5, §8.3, §11.3 |
| Astra 6 | HIGH: the S/P/O classification is not honest | Accepted. H and F classes; O redefined (M4); executable inventory; the daemon-downtime rule withdrawn. | §0.4, §0.5, §4.1 |
| Astra 7 | HIGH: sample size and temporal resolution | Accepted. Honest counts; episode support; pinned TTO; +0/+2/+10 samples; no 30-tick eligibility. | §7.6 |
| Astra 8 | HIGH: count families cannot represent underdispersion | Accepted. Transition and hazard models; underdispersed occupancy; adequacy gate without the incumbent constant. | §7.1, §7.2 |
| Astra 9 | HIGH: selection optimism; no separate evaluation | Accepted. Soft structure; nested chronological, day-blocked evaluation with in-fold vocabulary; exclude-latest scoring. | §7.4, §7.5, §10 |
| Astra 10 | HIGH: historical reconstruction contract | Accepted. Boot id on every record; stored UTC offset; per-collector observation time with bracketing reads; versioned top-K; chained summaries; horizons re-verified. | §4.4, §5, §8.1, C0.11 |
| Astra 11 | HIGH: per-source evidence contracts | Accepted. Census universes (I49); tailnet state for every outcome; `Online` semantics stated. R8 stays as the incumbent's scope fix (B) until C7b. | §4.2, §7.1, C0.1b, C0.3 |
| Astra 12 | HIGH: login learner learns occupancy | Accepted. Arrival events; `last` dedupe; tty is not taken to mean SSH; creator lineage dropped. | §4.3, §7.1, C0.4 |
| Astra 13 | HIGH: labels and evaluation certify the wrong thing | Accepted. Labels separate from acknowledgement; events are not labels; coherent replay; abstention reported separately. | §9, §10 |
| Astra 14 | MEDIUM: location identity; sanitizer is not a schema | Accepted. Network-configuration fingerprint with component availability; real field schemas with provenance tags. | C0.5, C0.6 |
| Astra 15 | MEDIUM: tier, runtime limits, integration | Accepted. Default-on shadow under strict bounds and a kill switch (D3); one vertical learner; daemon integration acknowledged as new work. | §13, §7.7, C5 |
| Astra 16 | MEDIUM: R3 needs episode state | Accepted and delegated: `feat/notify-once-2026-10` implements episodes, now with producer-declared incident keys. | §12, C1 |

### v1 Opus plan review (`2026-10-06-context-plan-review-opus.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| B1 | Context change fabricates recovery (reboot, tailnet, unknown) | Accepted, all three scenarios as gate tests, now split by stream kind | §6.2 |
| H1 | Level families miss partial kills | Accepted. Transitions (arrivals, departures, churn) with exposure intervals; levels secondary. | §7.1, §7.2 |
| H2 | Aftermaths are unlearnable at this cadence; the prior is the rule | Accepted. Pinned TTO; prior-governed labelling; long-lived statistics; transition samples; abstention (S); F1 adopted as a constraint (D4). | §7.6, §7.8, §8.2 |
| H3 | Attacker-steerable context; target leakage | Accepted. Joint scoring counted once; `session_origin_mix` removed; `new` and `unknown` raise-only; Good–Turing novelty with rate drift. | §5, §7.3 |
| H4 | Hard selection driven by a penalty | Accepted. Shrinkage or model averaging; no back-off order; pooling strength classified as P and sensitivity-checked. | §7.4, I9–I11 |
| H5 | macOS scutil parser broken (verified `[]`) | Accepted, delegated, **now fixed on `fix/collector-sources-2026-10`** (verified v3 on this host's real output; not merged). Linux nmcli here. | §1.5, C0.2 |
| H6 | ENOENT under launchd PATH | Accepted, delegated, **now fixed on the branch** (not merged); census completeness completed by C0.1b. | §1.5, C0.1, C0.1b |
| H7 | Long memory versus capacity budgets; volume eviction | Accepted. `tick_summary` at ≤ 1 KiB with field caps, ≥ 30 d in `RULE_HORIZONS`, chained, with per-family retention; long-lived statistics. | §8 |
| H8 | C7 is suppression plus sticky adaptation | Accepted. C7a/C7b split; per-host envelope (D2, DA1); drift budget. | §11 |
| M1 | Boot identity shared with trusted-state Phase 3 | Accepted. `bootsessionuuid` verified on this host; boundary verification by conjunction. | C0.8, I41 |
| M2 | Suspend sources, DarkWake, multiple sleeps | Accepted. Aggregate intervals; C0.9 go/no-go with a fallback. | §4.1, C0.9 |
| M3 | Session origin via `who`/`last` is wrong (verified `(:0)`) | Accepted. loginctl / IOConsoleUsers; first-observed tick. | C0.4 |
| M4 | Login-hour distribution is really presence hours | Accepted. Arrival events; presence hours a weaker stream. | §7.1 |
| M5 | Location fingerprint collides, is confounded and reversible | Accepted. Physical-interface components; HMAC with a per-install key; README table. | C0.5 |
| M6 | L1 is not behaviour-neutral | Accepted. Per-collector sub-deadlines; `daemon_gap` is a fact only. | C0.7, §4.1 |
| M7 | Evaluation not honest enough | Accepted. Pre-registered and adaptive scenarios (extended in v3); corpus with observed context; out of sample; numeric bars classified. | §10 |
| M8 | Unclassified numbers | Accepted. Every number is in the inventory, including v3's new ones. | §0.5 |
| M9 | Gameable attention budget; multiplicity | Accepted. Calibrated α allocation checked by PIT; never deletes a detection; not derived from recent history. | §12 |
| M10 | Contamination guard mechanics | Accepted. Soft weights for challengers; `benign` separate from acknowledgement; label-poisoning bound; declaring a new normal within the drift budget. | §6.3, §9 |
| M11 | Fit cadence, compute, second substrate | Accepted. Structural or daily fits with cached scoring; `model-ir` kernels with runtime budget, or a divergence justified at C4a. | §7.7 |
| L1 | Creator lineage is infeasible | Accepted. `tmux list-clients` joined to the login tty. | §4.3 |
| L2 | Shutdown-cause cost and privilege | Accepted. `pmset` log dropped; `last` rows and Linux `last -x` used; journal not used. | §4.1 |
| L3 | Missing context | Accepted. Presence/lock, DarkWake, clock and timezone, binary availability, Tailscale Self/Health and OS build in C2; software change and power deferred. | §4.1–4.3 |
| L4 | Two inaccurate statements | Accepted and corrected (the regime stratum exists; retention is 30 days). | §1.2, P3 |
| L5 | Sequencing | Accepted. C1a and C2 after the capacity merge; C4a spike; Linux sources CI-gated. | §14 |
| L6 | Tailnet online count has low security value | Accepted. Secondary LEVEL stream; node-key novelty and inbound sessions primary. | §7.1 |

### Principle audits (structural findings in scope)

| Finding | Disposition | Where |
|---|---|---|
| Adaptation without arbitration (Opus audit §1g, rank 4) | Accepted as an early security-critical step, now including novelty (D1) and aging-out (re-review H2) | §6.3–§6.6, C1a |
| Tuning loop counts repeated incidents as 1 (Astra audit rank 3, verified) | Accepted as prerequisite C1.2, counting `activated` transitions | §9, C1 |
| No independent labels (both audits) | Accepted | §9 |
| No durable behavioural memory or reference baselines (Astra rank 4; Opus §4 item 4) | Accepted for session/peer/context streams and the incumbent anchors | §6.5, §8 |
| Context collected then discarded (both audits, §3 tables) | Accepted for lifecycle, network and session context | §4 |
| Peer regime key is the right pattern to generalize (Opus audit 1a) | Accepted as the precedent for identity and census universes | §1.2, §6.1, C0.1b |
| Process rule: calibration findings become data work items | Accepted | P6 |
| Fixed resource reflexes, provenance lists, credential paths, constraint miner, metric retention | Out of scope; follow-ups reuse this substrate | §15 |

### R4–R10 non-reintroduction check

| Item | v3 status |
|---|---|
| R4 (floor 0.5 → 0.75) | Absent. No stddev floor exists in L3; the incumbent is unchanged; the incumbent's z is no longer an adequacy bar. |
| R5 (14-day window) | Absent. Memory grows (§8), and aging out is never an explanation (§6.5). |
| R6/R7 (reboot suppression or CRITICAL guard) | Absent. Reboots are facts, covariates and a scored EVENT stream. F1 is not R6: R6 detected a reboot by "uptime < gap" (forgeable by a clock step), then suppressed `session.churn` and made `count_drop` non-notifying, implicitly time-windowed and with no tripwire. F1 has no window and no parameters, needs a boundary verified by conjunction (I41), fails closed, has tripwires, never recovers, closes, admits or changes severity, and requires the reboot itself to be scored in the same learner. |
| R9 (wake grace) | Absent. Wake is an interval fact; under F4 a sleep never explains a departure; exposure uncertainty can lower sensitivity but never raise an alert (I46). |
| R10 (lone-churn rule) | Absent. Churn rate is learned per context. |
