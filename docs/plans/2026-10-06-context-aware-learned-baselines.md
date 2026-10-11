# Context-aware learned baselines

**Created:** 2026-10-06
**Status:** DRAFT v5. Designed to the operator decisions of 2026-10-06 as amended by the operator direction of 2026-10-09 (D5, below): no operator ratification or approval step anywhere; adaptation, promotion and per-host replacement are earned automatically from evidence the system gathers itself, bounded, reversible and notified; C1a is narrowed for the incumbents. One operator question remains, with a default (§16).
**Reviewed:** 2026-10-06 (gpt-6-astra xhigh + Opus 5.5 max; v1 NEEDS-REVISION 16 / 9)
**Reviewed:** 2026-10-06 (v2 re-review, Opus 5.5 max; NEEDS-REVISION 5: B1, H1–H4)
**Reviewed:** 2026-10-06 (F-class opinions, gpt-6-astra xhigh + Opus 5.5 max; both ALLOW WITH CONDITIONS)
**Reviewed:** 2026-10-07 (v3 re-review, Opus 5.5 max; NEEDS-REVISION 3: HIGH 1–3, plus MEDIUM 1–7 and LOW 1–5)
**Reviewed:** 2026-10-09 (v4 review, Opus 5.5 max; NEEDS-REVISION 2: HIGH 1–2, plus MEDIUM 1–5 and LOW 1–8)
**Reviewed:** 2026-10-09 (v4 review, gpt-6-astra xhigh; NEEDS-REVISION 5: HIGH 1–5, plus MEDIUM 6–9 and LOW 10)
**Revised:** 2026-10-06 (v2)
**Revised:** 2026-10-06 (v3 — operator decisions + v2 re-review + F-class opinions)
**Revised:** 2026-10-09 (v4 — §6 arbitration/pending redesign; v3 re-review folded; citations updated to merged main)
**Revised:** 2026-10-09 (v5 — no operator ratification; earned automatic adaptation; C1a narrowed; v4 Opus+Astra reviews folded)
**Addendum:** 2026-10-11 — C0 execution on `feat/context-facts-c2-2026-10`: the C0 rows C2 collects from (C0.3–C0.8, C0.12, and C0.9's raw capture only) are implemented; deviations and deferred items are listed in "Addendum: C0 execution (2026-10-11)" at the end of this plan. The C0.9 real-laptop measurement write-up is a separate, later task.
**Reviewed:** 2026-10-11 (C0 adversarial review, NEEDS-REWORK; every finding dispositioned in "C0 review fixes (2026-10-11)" at the end of this plan)
**Origin:** `todos/2026-10-06-session-peer-tuning.md` (operator reframe, 2026-10-06). This plan realizes Slice 12 of `docs/plans/2026-07-09-self-learning-stratified-monitoring.md:183` and generalizes it from time to all context.

**Inputs to v5:**
- The v4 reviews: `docs/reviews/2026-10-09-context-plan-v4-review-opus.md` (0 BLOCKER; HIGH 1–2; MEDIUM 1–5; LOW 1–8) and `docs/reviews/2026-10-09-context-plan-v4-review-astra.md` (HIGH 1–5; MEDIUM 6–9; LOW 10).
- The operator direction of 2026-10-09 (D5, next section). It overrides the ratification wording of D2, D4 and DA1, and every "ratify" step in v4.
- Operator decisions D1–D4, the F-class opinions (`docs/reviews/2026-10-06-f-class-opinions.md`) and `docs/design/autonomy-doctrine.md`.
- Code: `main` @ 66d3a2b (its code is 1169d40's plus b60efc8, which touched only `baseline.js`); `feat/notify-once-2026-10` @ 2e208df; `fix/collector-sources-2026-10` @ 1c2b412.
- Every finding since v1 is dispositioned in Appendix A.

**Inputs to v4 and v3** (kept for the record): the v3 re-review `docs/reviews/2026-10-07-context-plan-v3-rereview-opus.md`; the v2 re-review `docs/reviews/2026-10-06-context-plan-v2-rereview-opus.md` (B1, H1–H4, M1–M9, L1–L4); the F-class opinions; the v1 reviews `docs/reviews/2026-10-06-context-plan-review-astra.md` (Astra 1–16) and `docs/reviews/2026-10-06-context-plan-review-opus.md` (B1, H1–H8, M1–M11, L1–L6); the principle audits `docs/reviews/2026-10-06-learning-principle-audit-astra.md` and `docs/reviews/2026-10-06-learning-principle-audit-opus.md`.

**What v5 changes.**
1. **No ratification, anywhere** (D5). v4 asked the operator to ratify each F-card, a per-host replacement envelope and an anchor policy; to re-ratify after a drift excursion or an exhausted discontinuity budget; and to set the policy values. v5 removes every one of those steps:
   - F-cards are reviewed like code: code review plus daybreak (§7.8.5).
   - Learned adaptation, promotion and per-host replacement of an incumbent are **earned automatically** from shadow evidence, within a cumulative drift budget anchored to the last earned snapshot. Each is reversible and notified (§6.3.1, §11).
   - Anchors are taken automatically (§8.3). Policy values ship as reviewed defaults that the operator may override (§16.1).
   - Labels are optional input that accelerates or corrects learning. Nothing depends on them to work (§9).
2. **C1a is narrowed** (D5; this resolves Opus H1, Opus H2 and Astra 1 by scope). For the incumbents, C1a does two things: it never folds an alarmed tick, and it keeps novelty pending until explained (D1). An incumbent freezes on a sustained shift until a learned successor earns replacement, and that replacement is its exit. v4's held level, re-base, bounded-quiet LEVEL exit, incumbent anchors, incumbent drift measure and regime admission are removed (§6.5). One rule stays, so that a frozen LEVEL alert never mutes its detector: a tick beyond the episode's running extreme opens a new incident (I55).
3. **An earned promotion is the admission event** (Astra 5). Shadow learners train on everything, pending data included. A version earns serving authority only by passing the pre-registered shadow evaluation, adaptive attacks included, within its drift budget. Each version records its training membership, and its promotion admits exactly that membership. §6.3.2 states how poisoning is bounded.
4. **Contract gaps closed:**
   - a durable scored-through watermark, with ordered replay (Astra 2);
   - discontinuity recovery that keeps surviving terminal dispositions (Astra 3);
   - certification at derivation time, so intentional eviction is not loss (Astra 4);
   - bounded incident tombstones (Astra 9);
   - quarantined novelty re-alerts when the entity reappears (Opus M2);
   - a forged label never closes anything silently (Opus M5);
   - a digest step in C1, and reviewed defaults before C1 (Opus M4, Astra 8).
5. **Sequencing.** Start C0 and C2 now: they are the calendar-time long pole (§14).

**What v4 changed** (kept for the record). All three v3 HIGH findings sat in §6. v4 separated the observation lifecycle from alert status (HIGH 3), moved pending state into a daemon-written, hash-chained journal with a re-certification exit (HIGH 1), gave a LEVEL episode new incidents on a further anomaly (HIGH 2), and declared per stream kind which explanation sources apply (v3's Q7).

**Depends on / relates to** (code read for v5):
- **Capacity: merged.** `feat/fact-store-capacity-2026-10` merged into `main` at 1169d40 (daybreak G3 READY). It brought per-family stores and budgets (`fact-families.js`), `RULE_HORIZONS`, the sliding anchor, certified horizons, novelty seen-sets (`novelty-seen-set.js`) and S6 rule status. `main` is now 66d3a2b, and every `main` line this plan cites is unchanged since 1169d40 (§17). The CAP prerequisite of C1a and C2 is met (§14).
- **`feat/notify-once-2026-10` @ 2e208df** (worktree `.claude/worktrees/r3-notify-once`; not merged; **in rework**). R3 now keeps **first-class per-incident records under each alert id** *(verified v5)*:
  - each alert row persists an incident map, `incident_key → {first_seen, last_seen, severity_max, notified_severity, confirmed_at, …, status}`, so incidents are due, delivered, confirmed and retried independently (`alert-store.js:300-330`);
  - the live-incident count excludes acknowledged, recovered and suppressed incidents (`:629`), but a storm still resets only on a new episode (`:617-620`), and there is no `closed` status (`:282`, `:325`);
  - the daemon singleton and the CLI command queue are removed (5f92e46), and `alerts ack` writes directly (`:924`);
  - the alert store's read-modify-write race has its own todo on the branch (`todos/2026-10-09-alert-store-concurrent-writers.md`).

  This plan references the branch and states requirements on it (§6.1, §12, C1). It does not duplicate it.
- **`fix/collector-sources-2026-10` @ 1c2b412** (worktree `.claude/worktrees/collector-sources`; not merged; it now contains `main` @ 1169d40). It pins binaries to absolute paths with writer-set trust (Opus H6), parses real scutil output (Opus H5), and treats `not_found_on_known_paths` and `untrusted_binary` as incomplete. **Usable-multiplexer census universes are now implemented on it** *(verified v5)*:
  - `censusStateFor` (`fact-translators.js:732-738`) reports `complete` when at least one multiplexer is usable and none is incomplete;
  - 6ba7d80 gives session alerts per-universe ids;
  - 25aeb89 filters the session fold by the current universe, with an honest re-warm-up.

  What it lacks is the `census.universe_changed` notice. That notice is now its merge gate (C0.1b; Opus M3).
- The trusted-state Phase 3 boot-identity primitive (`docs/plans/2026-09-06-trusted-state-step-1.md` §5.3, :141-148, open question 2 at :301) and `todos/2026-09-08-clamp-boot-identity-guard.md`. The primitive is built once and shared. It already relies on what this plan names F2 (§7.8).

**Verification note.**
- Claims marked *(verified v5)* were checked on 2026-10-09 against `main` @ 66d3a2b, `feat/notify-once-2026-10` @ 2e208df and `fix/collector-sources-2026-10` @ 1c2b412.
- Claims marked *(verified v4)*, *(verified v3)* or *(verified 2026-10-06)* were checked earlier. Every `main` line they cite is unchanged at 66d3a2b, because b60efc8 touched only `baseline.js`. Branch lines are cited at the v5 tips wherever v5 relies on them (§17).
- The dev host is a Darwin 25.2 VM and is **not a corpus**:
  - Its last boot was 2026-09-04 (`kern.boottime`), which is outside the 30-day retention.
  - It has never slept (`kern.sleeptime` = `kern.waketime` = 0).
  - Opus M7 found its structural checkpoint stale since 2026-10-05.

---

## Operator decisions (2026-10-06; amended 2026-10-09)

**Provenance.** The operator gave D1–D4 during the 2026-10-06 planning session, and D5, emphatically, on 2026-10-09. All five were relayed to this revision. They are not yet recorded in `todos/2026-10-06-session-peer-tuning.md`, whose decision table stops at R3–R10. Recording them there is a follow-up edit for the next agent session; the operator has nothing to do.

| # | Decision | Answers | Design consequence | Doctrine amendment to draft |
|---|---|---|---|---|
| **D1** | **Novelty is pending until explained.** This reverses the 2026-09-27 one-tick-recovery design (HANDOFF 2026-09-27; `service-baseline.js:447-464`). An explanation is one of: a context fact, an operator label, or bounded quiet. **Later**, federated layers may match known patterns or signatures as a further explanation source. | v2 Q4 | §6.3 admission paths; §6.6 novelty lifecycle; the closed set of explanation sources, with `federated_signature` reserved as an interface only (§6.3.3) | **DA3**: bounded on-host admission |
| **D2** | **Replacement authority, per host and per detector family.** The old detector stays in code. Refits after promotion are bounded by a cumulative drift budget. *As amended by D5:* replacement is **earned automatically** and notified, not ratified by the operator per host; the drift budget is anchored to the last earned snapshot. | v2 Q2 | §11.2, §11.3, C7b | **DA1**: earned replacement |
| **D3** | **Shadow learners are default-on.** They raise no alerts of their own until promoted. This needs a policy amendment; strict compute, time, memory and disk bounds; a kill switch; and no effect on the incumbent detectors. | v2 Q1 | §7.7, §13, C5 | **DA2**: default-on shadow, and (D5) a default-on earned promotion path |
| **D4** | **The F class is delegated to the reviewers.** Both said ALLOW WITH CONDITIONS, so this plan adopts exactly their narrowed form: F1 process instances are boot-scoped, as a *constraint* on what an observation means, never as an explanation or arbitration authority; F2 clock domains are boot-scoped; F3 suspend clock semantics; F4 suspend and hibernate preserve instances and boot identity, so a sleep never explains a departure; F5 is deferred. Every admission criterion, rejection, must-stay-scored item and test in the opinions is adopted. | v2 Q3 | §0.4, §7.1, §7.6, §7.8, I33, I36–I41 | None. *As amended by D5:* each fact needs its own F-card, reviewed like code (code review plus daybreak), with no operator ratification (§7.8.5). |
| **D5** (2026-10-09) | **No per-item, per-version, per-host or per-anchor operator ratification or approval step, and no routine configuration or labelling chore.** In the operator's words: "Is the job simplifying people's lives, or creating bullshit work for them?" The doctrine already says that the human is **on** the loop (notified, able to audit, veto and roll back) and never **in** it; that autonomy scales with reversibility × corroboration; and that trust is earned from evidence the system gathers itself. Therefore: learner adaptation and promotion, including the replacement of an incumbent detector on a host, are **earned automatically** from shadow evidence, within a cumulative drift budget anchored to the last earned snapshot, reversibly, and with a notification (notification, not confirmation). F facts are reviewed like any code. Anchors are taken automatically. Labels are an **optional** input that accelerates or corrects learning, never a required path. C1a is narrowed for the incumbents to two things: never fold an alarmed tick, and keep novelty pending until explained (D1). | v4's ratification steps; v4 reviews Opus H1, H2; Astra 1, 5 | §0.2 P5, P7; §6.3, §6.5, §7.8.5, §8.3, §9, §11, §14, §16 | Rewords DA1 and DA3; widens DA2 |

**The doctrine amendments are drafted, not enacted, by this plan.** DA1–DA3 are written as one change to `docs/design/autonomy-doctrine.md` (step DA, §14), recording D1–D5. The operator has already given the direction; DA writes it down. It is reviewed once, like any change, and it gates no individual item. Steps whose behaviour goes beyond the current doctrine text wait for DA to merge, and say so. Until then their items simply stay pending, which needs nothing from anyone.
- **DA1** (D2, D5): **earned replacement.** Replacing a detector reduces what alerts, which the doctrine places above the on-host ceiling (`autonomy-doctrine.md:61-68,126-129`). The amendment permits it when it is earned:
  - a learned lineage that has served notify-only on a host, and that passes the pre-registered evaluation against the incumbent on that host's own replay within its drift budget, takes over alerting for one detector family on that host;
  - the takeover is notified;
  - the incumbent stays in code and in shadow;
  - rollback is a routing flip: automatic on a regression (§11.5) or a budget breach, and available to the operator at any time.
- **DA2** (D3, D5): **default-on shadow.** "Default-OFF behind the `learned.json` kill switch" (`:134`) is narrowed. It keeps covering agent authoring. Two things may run default-on under `watch`, within S resource bounds and behind their own kill switch: the declared shadow learners, and the earned promotion path of their lineages (§11).
- **DA3** (D1, D5; v2 re-review M4; v3 re-review MEDIUM 2 and 3; v4 Astra 5): **bounded on-host admission.** Admitting unattested observations into authority-bearing state is sticky adaptation, which the doctrine gates on attestation (`:103`, `:126-129`). The amendment permits on-host admission that is earned, bounded, reversible and notified. Its scope, by stream kind (§6.3):
  - `earned_promotion`, for every kind: a promoted version's recorded training membership, within the drift budget, minus the items vetoed under §6.3.2;
  - `bounded_quiet`, for NOVELTY entities only (D1);
  - `context_model`, for a promoted learner over its mapped incumbent NOVELTY items only;
  - `label`, which is optional, for every kind, bounded by the label budget and notified;
  - EVENT and LEVEL data are never admitted by bounded quiet.
  - **What bounds the exception** (S mechanisms, recorded in the amendment): the drift budgets, the label budget, the discontinuity budget, the vetoes of §6.3.2, the admission log and digest, and reversibility of every admission.
  - **What it does not change.** The attestation gate stays for acting on the host and for recommendations. A forged on-host signal can buy at most bounded, notified and reversible adaptation (§0.3, §6.3.2).

---

## 0. Core principle

### 0.1 The test every section must pass

Descartes is a system that **learns and adapts**. It needs **data**, **context awareness** and **the ability to learn**. It must not become an expert system, meaning a growing set of hand-written rules and magic thresholds that encode a human's (or an AI assistant's) guesses about what is normal on this machine. Real attacks unfold over days, so memory must be long.

### 0.2 What that means here

- **P1. Data, not behaviour rules.** This plan adds data and the ability to use it. It adds no "suppress X after reboot", no "ignore peers after wake", no "critical only if ≥ N". The rejected R4–R10 stay rejected. Appendix A checks that this plan reintroduces none of them. A hand-written "X explains Y" mapping is a behaviour rule and is never an explanation (§6.3).
- **P2. The machine weighs context, within a declared hypothesis space.** The plan offers candidate context and the learner decides how much each candidate matters. The plan states plainly what the learner *cannot* learn: the representation is a declared hypothesis space (class H, §0.4). Raw resolution is retained so that alternative representations can be learned later.
- **P3. Long memory stays and grows.**
  - Raw facts are kept for 30 days (`fact-store.js:31`). The 31-day constant at `welford-stats.js:20` is a read window, not retention (Opus L4).
  - On top of that come a compact per-tick summary family, long-lived sufficient statistics, durable reference snapshots and the pending journal, all of which outlive the raw window (§6.4, §8).
  - Aging out of the raw window is never an explanation (H2). A boot never resets or partitions memory (F-class opinions, Opus §2).
- **P4. Safety invariants stay**: never fabricate; completeness, freshness, coverage and integrity gates; resource bounds; privilege hardening. The doctrine's authority ceiling also stays: on-host, the ceiling is additive alerting (`autonomy-doctrine.md:61-68`). Anything that reduces what alerts is governed by §11 (earned, bounded, reversible and notified), DA1 and DA3.
- **P5. Adaptation is arbitrated and earned, never unconditional** (`autonomy-doctrine.md:101-116`). Today the default tier adapts with no gate at all (§1.3).
  - Under this plan nothing adapts merely because time passed, data aged out or an alert recovered.
  - Adaptation happens only when evidence the system gathers itself earns it: a version passing the pre-registered evaluation within its drift budget (§6.3.1), or certified quiet for a novel entity (§6.6).
  - Every adaptation is bounded, reversible and notified.
  - The incumbents never fold an alarmed tick (C1a, §6.5).
- **P6. Process rule.** A calibration finding becomes a missing-data or missing-context work item. It never becomes a new threshold or suppression (Opus audit §4 item 5).
- **P7. No chores** (D5). No part of the design depends on the operator labelling, ratifying, configuring or approving anything. Operator input (labels, overrides, vetoes, rollbacks) is optional: it accelerates or corrects. Its absence leaves the system conservative, never stuck.

### 0.3 Evidence limit (stated, not hidden)

No statistical method can tell a benign event from a malicious one when both produce identical observed evidence (Astra 4). Context-aware scoring raises the attacker's cost: they must reproduce a familiar transition, at a familiar time, with the familiar response. It does not make attacks impossible. Attacks that are indistinguishable from benign behaviour are an accepted evidence limit, not a defect to be patched with a rule.

The same limit applies at a boot: "sessions alive at 12:00, reboot at 12:30, absent at 13:00" cannot distinguish a 12:15 kill from termination by the reboot. Neither F1 nor a pure learner can recover information that was never observed (F-class opinions, Astra §2). This plan shrinks the unobserved gap with data (a +0 boundary census) and reports the remainder as abstention, never as "explained" (§7.8.3).

### 0.4 Classes

Every choice in the design is classified as one of the following. Anything unclassified is a defect.

| Class | Meaning | Obligation |
|---|---|---|
| **S** | Safety, integrity or authority invariant, a resource bound, or an admission **mechanism** | Never learned away. Exhaustion is visible. |
| **P** | A bootstrap prior that data overrides | Publish its strength and its time-to-override (§7.6). Provide a fixture showing contrary data wins. |
| **O** | Operator attention or authority policy: a **parameter** of an S mechanism. It ships as a reviewed default (§16.1); the operator may override it, and it never needs an operator action to take effect (D5). | It is never a claim about the machine. It may *size* an S admission mechanism (the bounded-quiet period, the drift-budget size, the label budget), but it never *defines* admission, recovery, or what counts as a benign label (re-review M4). |
| **H** | Declared hypothesis space: the vocabulary, model families and resolutions | Stated as a limit of what can be learned. Raw resolution is retained so the space can be widened later through `model-ir` composition (doctrine :33). |
| **F** | An OS-semantics constraint, admitted per fact under §7.8 (D4) | It fixes what an identifier can mean and which observations can inform which parameter. It never says what is usual, expected or benign. It never recovers, closes or admits anything. A contradiction fires an integrity tripwire. It is inactive until its own F-card has passed review (code review plus daybreak) and is in the registry. |

**Amended from v2 (M4).** v2 said O "never controls training admission" while classing the bounded-quiet period, drift-budget size and label budget as O. v3 made each admission mechanism S (I19, I20, I27) and kept only its size as O. On-host admission itself is the doctrine exception DA3.

**Amended in v5 (D5).** O values are reviewed defaults, not ratified values. F-cards are reviewed like code.

**New numbers in v4 (v3 re-review MEDIUM 7).** Every number v4 introduces, and the four v3 left unclassified, has a row: the abort count (I65), the boundary-verification tolerance (I66), "stably not found" (I67), the bounded-quiet stability statistic (I55, I19), the discontinuity budget (I54), the provisional label budget (I58), regime memory (I59) and the pending and quarantine caps (I3).

**New numbers in v5.** Every value v5 introduces has a row and a default: the C1 and C1a defaults (§16.1), the tombstone cap (I73), the cumulative drift horizon H (I72) and the digest period (I75). The running-extreme rule (I55) adds no number. v4's provisional label budget (I58) and regime memory (I59) are withdrawn.

### 0.5 Executable inventory

Each row becomes a named test in C0. Tests start pending, and the step that implements a row turns its test green. "Data can override" asks whether this host's own data can change the outcome. Rows I1–I51 keep their v3 numbers (some are amended); I52–I68 are new in v4; I69–I75 are new in v5. I58 and I61 are withdrawn in v5, and keep their numbers so that citations stay stable.

| # | Choice | Class | Data can override? | Counterexample fixture |
|---|---|---|---|---|
| I1 | 30-day raw retention (`fact-store.js:31`), per-family budgets and entity caps (`fact-families.js:240-273`) | S | No, by design. Exhaustion surfaces as `horizon_short`. | `inv_retention_exhaustion_visible` |
| I2 | `tick_summary` record ≤ 1 KiB with explicit per-field caps; T8 floor with a records-per-interval term; horizon ≥ 30 d registered in `RULE_HORIZONS` (`fact-families.js:108-149`); per-family retention | S | No | `t8_tick_summary_worst_case`, `t8_records_per_interval`, `inv_summary_horizon_registered`, `inv_summary_field_caps` |
| I3 | Caps on long-lived statistics, earned and serving snapshots, the pending journal and checkpoint (open items, exemplars per item, tick marks), the quarantine archive and incident tombstones (I73). **At a cap, pending items compact into `excluded` and quarantined items merge into an aggregate: never folded, and never a freeze** (v3 re-review HIGH 3(c)). Defaults in §16.1. | S | No | `inv_longlived_cap_evicts_visibly`, `pending_cap_compacts_to_excluded`, `quarantine_compaction_never_folds` (v3's `pending_overflow_fails_closed` is withdrawn) |
| I4 | Candidate context vocabulary (§5) | H | Partly. Any dimension can shrink to ~0; a dimension outside the vocabulary can never be added. Dimensions never observed on this host are excluded from the host's vocabulary; their appearance is a structure-version change (H1). | `inv_irrelevant_dim_shrinks`, `inv_outside_vocab_documented`, `inv_never_observed_dim_excluded` |
| I5 | No dimension derived from the same **physical object** as a target it conditions, checked by field provenance, not by family (M6). `session_origin_mix` is removed; VPN-service state leaves the peer population; a WireGuard link is not context for its own peers; the Tailscale network-extension service is not context for the tailnet. | S | No | `inv_no_target_derived_dim` (static check over field-provenance tags), `inv_wg_link_not_context_for_wg_peers` |
| I6 | `since_*` bucket edges | H | Not within one structure version. A new version can re-bin from the retained raw seconds. | `inv_rebin_from_summary` |
| I7 | `net_config` top-K. K is S and part of `structure_id`. **Membership** (the frequency ranking) is a parameter inside a version: refit in-fold and within the drift budget, with values outside it encoded `other` or `new`; it never changes `structure_id` (v3 re-review MEDIUM 6). Pooling rare values into `other` is H. | Ranking yes, pooling no | `inv_topk_fitted_in_fold`, `cc_l_new_network_raises`, `id_topk_reorder_same_structure_id` |
| I8 | Hour-of-week (168 cells) partially pooled toward hour and day-of-week. This replaces weekday/weekend. | H | Yes: pooling merges days the host treats alike | `inv_tue_sat_schedule_learned` |
| I9 | Lattice back-off order | Eliminated by soft structure (§7.4) | n/a | `inv_dim_order_invariant` |
| I10 | Pooling strength (hyperprior) | P | Yes in dense cells. TTO is published, and prior-governed cells are labelled as such. | `inv_prior_overridden_dense_cell`, `inv_tto_reported` |
| I11 | Complexity penalty for hard selection | Removed (no hard keep/drop) | n/a | none |
| I12 | Model families (hazard, Poisson, smoothed categorical), plus an adequacy gate: PIT calibration; the mandatory scenario drops flagged at the stream's α_i; the verdict stable under ×0.1 / ×10 prior sensitivity. **No incumbent constant is the bar** (M3). | Families H; gate S; α_i O | A family that fails adequacy is ineligible | `adequacy_stable3_to0`, `adequacy_5_to_2`, `adequacy_excess_zeros`, `adequacy_regime_change`, `adequacy_prior_sensitivity_stable` |
| I13 | Aftermath shape | Learned. No shape is placed in initialisation, fixtures or admission rules. | Yes | `inv_inverse_aftermath_learned` (a host whose sessions *rise* after boot learns that) |
| I14 | Interval-event covariates (boot, suspend or transition inside the interval) | H | Their effects are learned and may be ~0 | `inv_boot_flag_effect_learned` |
| I15 | Transition-triggered census samples at **+0**, +2 and +10 min. The +0 sample is the boundary census (F-class opinions, Opus §2). | Offsets H; cost cap S (≤ 3 per transition, ≤ 4 extra per hour) | No | `inv_extra_samples_capped`, `inv_boundary_census_at_plus0` |
| I16 | Support floor before a cell counts as "evaluated" for recovery | S | No | `cc_l_*` (§6.2) |
| I17 | Coverage contract v5: stream kinds (EVENT, LEVEL, NOVELTY), CC1–CC8 | S | No | `cc_l_*`, `cc_e_*`, `level_*` (§6.2) |
| I18 | Pending state under arbitrated adaptation. It is an **observation** state, separate from alert status (I52). It restricts authority; it is not a claim that the data is malicious. | S | No | `arb_alarmed_tick_not_folded`, `arb_pending_retained_for_shadow`, `recovered_episode_ticks_not_folded` |
| I19 | Bounded-quiet admission. The mechanism is S; the period Q is O (default §16.1). **v5: NOVELTY entities only** (D1). v4's held-LEVEL exit is removed with the held level (D5); learned LEVEL streams adapt by earned promotion (I71). For EVENT data it is undefined, so never applied (I56). Charged to the family's novelty budget and notified in the digest. On-host admission is DA3. | Mechanism S; period O | No (policy) | `novelty_closed_by_bounded_quiet_consumes_budget`, `event_bounded_quiet_never_admits`, `level_bounded_quiet_never_admits` |
| I20 | Drift budget for **learned lineages**: mechanism, measure and size. The anchor is the last earned snapshot (I71). The measure is the **sensitivity-reducing displacement of every authority-relevant decision boundary** (each severity tier's α boundary) on reference cells, in the anchor's predictive scale, so a mean shift, a variance widening and a severity-boundary move are all charged, and a change that only raises sensitivity is not (v4 Astra 7, Opus LOW 5). For novelty families, every admitted entity, by any source (v4 Opus M5); the Good–Turing novelty rate. Per-promotion and cumulative over the horizon H (I72). A loss never zeroes it. **v5: no incumbent drift measure** (C1a narrowed). | Mechanism S; measure H; size and H O | No | `drift_chain_exhausts_budget`, `drift_severity_boundary_charged`, `drift_sensitivity_increase_not_charged`, `drift_seen_set_admissions_counted`, `anchor_store_corrupt_no_fresh_budget` |
| I21 | Novelty probability. Its own rate is scored for drift against the anchor, so toggling cheap dimensions cannot make novelty unremarkable (L3). | Learned (Good–Turing) | Yes | `inv_novelty_rate_learned`, `inv_novelty_rate_drift_scored` |
| I22 | Handling of `new`, `unknown`, `other` and `unstable`. `not_applicable` and a stable not-found are known values (H1). | S: they back off for raising, never go silent, and never recover | No | `cc_l_unknown_context_freezes`, `cc_l_new_network_raises`, `cc_l_not_applicable_is_known` |
| I23 | TTO definition, pinned (L1): for a Gamma(a0, b0) rate, data outweighs the prior once accrued exposure ≥ b0 **and** observed events ≥ a0; for a Beta(α0, β0) probability, once trials ≥ α0 + β0. Wall time is reported by dividing by the host's observed accrual rate. | S (an honesty-reporting rule) | No | `inv_tto_reported`, `inv_tto_units` |
| I24 | Clock-step detection resolution | S (measurement resolution, not a claim about normal) | No | `l1_clock_step_detected`, `l1_no_false_step_on_suspend` |
| I25 | Per-collector sub-deadlines | S | No | `c0_context_timeout_keeps_census` |
| I26 | Components of the network-configuration fingerprint | H | No | `c0_fingerprint_component_availability` |
| I27 | Label-poisoning bound (v4 Opus M5): **every** label, closing and quarantining ones included, is charged to the label budget; every ingested label is notified; a closure never cancels an undelivered incident; a quarantining label never ends a LEVEL episode or a present NOVELTY alert. Labels are optional (D5). | Mechanism S; label budget O (default §16.1) | No | `label_burst_held_pending`, `label_notified_on_ingest`, `label_closure_never_cancels_undelivered`, `label_quarantine_keeps_present_condition_active` |
| I28 | Surprise → notification (α allocation, N per week) | O. It never deletes a detection. | No | `budget_does_not_delete_detection`, `budget_not_raised_by_flood` |
| I29 | Surprise → severity mapping. Corroboration counts **distinct evidence sources**; a shared context event counts once (M2). | Mapping O; counting rule S | No | `severity_mapping_declared`, `corroboration_shared_context_counted_once` |
| I30 | Promotion bars. They gate every earned authority change (I71). | Minimum evidence S; operator tolerance O (reviewed default, §16.1) | No | `ladder_rejects_without_preregistered_evidence`, `promotion_without_evaluation_refused` |
| I31 | Fit cadence and runtime limits | S | No | `fit_abort_keeps_last_version`, `t9_read_cost` |
| I32 | `host.daemon_gap` | A fact only, never an alert from L1 | n/a | `l1_no_alert_candidates` |
| I33 | **F1: process instances are boot-scoped** (renamed from v2's "a boot ends all processes"). A constraint on observation meaning: across a verified boot boundary, instance identity is never compared and boundary-crossing departures leave the hazard likelihood. It never recovers, closes or admits. | F (F-card review pending) | No: a contradiction is an integrity tripwire, not a learning signal | `f1_*` (§7.8.6). While F1 is inactive: `f1_kill_switch_reverts` (option D fallback) |
| I34 | R3 notify-once, with **producer-declared `incident_key`** and **first-class per-incident records** (`feat/notify-once-2026-10` @ 2e208df, in rework), plus the requirements of I63 and I73 | O | No | Tests on `feat/notify-once-2026-10`; `storm_*` (I63) |
| I35 | Incumbent constants: σ 3/5, floor 0.5, N 30, `CORRELATION_ODD_HOURS`, R8 | Unchanged by this plan (the audits class them A/C). They are not an adequacy bar (M3). The running-extreme rule (I55) decides when a frozen incumbent episode notifies again; it adds no number and changes nothing about what raises (v4 Opus M1 corrected v4's wording). | No | None. They are retired only by earned per-host replacement under C7b. |
| I36 | **F2: clock domains are boot-scoped.** Boot-relative counters (uptime, boottime, monotonic) are subtracted only within one boot identity. Already relied on by trusted-state §5.3 (`2026-09-06-trusted-state-step-1.md:145`). | F (F-card review pending) | No: a contradiction is a tripwire | `f2_no_cross_boot_subtraction`, `f2_boot_id_regression_tripwire` |
| I37 | **F3: suspend clock semantics, named per platform** (v3 re-review LOW 1). Linux: `CLOCK_MONOTONIC` pauses across suspend and `CLOCK_BOOTTIME` does not. macOS: `CLOCK_UPTIME_RAW` (`mach_absolute_time`) pauses, while `CLOCK_MONOTONIC` and `mach_continuous_time` do not (this host's `clock_gettime(3)`: `CLOCK_MONOTONIC` "will continue to increment while the system is asleep"). v3's "the monotonic clock pauses" was false on macOS. Verified per platform by C0.9 (the A5 lesson, `trusted-state:146`). | F (F-card review pending; inactive on any platform C0.9 has not verified) | No | `f3_paired_clock_delta_bounds_suspend`, `f3_inactive_on_unverified_platform`, `f3_clock_ids_named_per_platform` |
| I38 | **F4: suspend and hibernate preserve process instances and boot identity.** It rules an explanation *out*: a sleep never explains a departure. Linux hibernation boots a restore kernel and then restores the old kernel and userspace; that is not a boot (F-class opinions, Astra §4). | F (F-card review pending) | No | `f4_sleep_never_explains_departure`, `f4_hibernate_not_a_boot` |
| I39 | F5: volatile kernel network state (sockets, WireGuard handshakes, interface instances) is boot-scoped | F, **deferred**: inactive until a learner needs it and its F-card has passed review | n/a | none until drafted |
| I40 | The F registry is closed. Each fact must meet admission criteria A1–A8 and carry an F-card, reviewed like code (code review plus daybreak; no operator ratification, D5). The agent can never author an entry (doctrine :33-37). Each fact has a kill switch. | S | No | `f_registry_closed_to_agent`, `f_card_required` |
| I41 | A boot boundary is **verified by conjunction** and fails closed: a never-seen boot id, a daemon restart, kernel boot time inside (last observation, now], uptime consistent with the gap (both within the I66 tolerance), and no pre-boot instance after the boundary. Any inconsistency makes F1 inactive for that interval (departures are scored as ordinary) and raises an integrity notice. | S | No | `f1_fail_closed_daemon_not_restarted`, `f1_boot_id_regression`, `f1_tripwire_preboot_instance` |
| I42 | Every stream is declared **EVENT**, **LEVEL** or **NOVELTY**, and its kind fixes its recovery contract and which explanation sources apply (B1; I56). **Named exception** (v3 re-review LOW 2): the incumbent edge-triggered rules `session.churn` and `service.disappeared` fold nothing and hold no pending data. Their next-tick `recovered` is logged as `recovered(edge_rearm)`, never as evidence that an event un-happened. | S | No | `cc_e_quiet_interval_after_kill_no_clear`, `cc_e_departed_entities_return_recovers`, `incumbent_edge_rearm_logged_not_evidence` |
| I43 | Alert identity components: what enters the alert id; the `incident_key` (EVENT: the event set; NOVELTY: the entity; LEVEL: `lvl:<regime>:<extreme>`, never `default`); and `raise_ref` (§6.1) | S | No | `id_cell_change_no_new_identity`, `id_cell_change_no_new_incident`, `id_raise_ref_not_episode_state`, `id_level_incident_key_not_default` |
| I44 | The pending journal is integrity-protected: hash-chained, written by the daemon only, each entry citing the pass it scored, with a durable scored-through watermark (I69). A contradiction or loss is a detected discontinuity, with a defined exit (I53, I54). Pending stays pending and is never laundered into a baseline (H4). | S | No | `pending_alert_record_deleted_no_fold`, `pending_journal_corrupt_fails_closed`, `pending_seen_set_reseed_keeps_pending` |
| I45 | **Incumbent frozen serving snapshot** (v5; replaces v4's incumbent anchors and pre-episode snapshots). The snapshot an incumbent served at the last tick before an episode opened, computed from the clean ticks before `first_seen` and carried in the journal. An open episode is scored against it, and every tick of an open episode joins its pending item. No anchor, no drift budget, no new-normal exit for the incumbents (D5). | S | No | `arb_sustained_shift_not_absorbed_by_ageout`, `arb_rewarmup_ticks_pending`, `arb_incumbent_recovery_needs_snapshot`, `incumbent_label_never_folds` |
| I46 | Exposure interval rule: raise only if surprising under every admissible exposure; recover only if unsurprising under every admissible exposure (M9) | S | No | `exposure_raise_uses_max`, `exposure_recover_uses_worst_case` |
| I47 | Shadow isolation and resource bounds: no candidates, no coverage, no writes to incumbent state; CPU, wall-time, memory **and disk** caps (I64); auto-disable after repeated aborts (I65); kill switch. Default-on (D3), as is the earned promotion path (D5, DA2). | Isolation and bounds S; default-on O | No | `shadow_no_effect_on_incumbents`, `shadow_emits_no_candidates`, `shadow_budget_abort_keeps_last`, `shadow_kill_switch_stops_all`, `shadow_failure_isolated` |
| I48 | Explanation sources form a closed set: `earned_promotion`, `bounded_quiet`, `context_model`, `label` (optional), and the reserved `federated_signature` (inactive) | S | No | `explanation_source_closed_set`, `federated_source_reserved_inactive` |
| I49 | Census universes keyed by binary availability: a source whose binary is `not_found_on_known_paths` is outside the universe; `untrusted_binary` and `unable` are always incomplete; a change in availability is a regime change (no hysteresis, I67), arbitrated under §6.5.3 (I59), and intervals that cross it are `unknown` for transitions (M7) | S | No | `census_tmux_only_host_complete`, `census_untrusted_is_incomplete`, `census_availability_change_unknown_interval` |
| I50 | `tick_summary` chaining: every record carries its departure basis and a link to the previous record; the census chain state is ledger-stamped; a broken chain yields `unknown` transitions, never zero (M5) | S | No | `summary_chain_no_double_count`, `summary_chain_broken_unknown` |
| I51 | `created_vs_boot` ∈ {`after_boot`, `before_boot`, `unknown`}, computed at collection time (the creation fingerprint is an opaque hash and cannot be compared later) | S (data) | No | `l1_created_vs_boot_computed_at_collection` |
| I52 | **Observation lifecycle** (v3 re-review HIGH 3): `pending` → `admitted(source)`, `quarantined(reason)` or `excluded(reason)`. Recovery never changes it. `suspicious` and `confirmed_incident` quarantine permanently. Admission into authority-bearing state happens only by an earned promotion within the drift budget, or, for NOVELTY, by bounded quiet, mapped context or a label. The incumbents never fold an alarmed tick, admitted or not (C1a). Membership is read from the journal alone (§6.0, §6.4). | S | No | `recovered_episode_ticks_not_folded`, `confirmed_incident_ticks_quarantined`, `earned_promotion_admits_training_membership`, `pending_membership_from_journal_only` |
| I53 | **Pending journal: writer, stamp and write order** (v3 HIGH 1). The daemon's detection stage is the only writer. An entry is certified when written (I70): same generation, pass id ≤ last committed, inside the certified span at that time. The checkpoint is re-stamped by every family retention pass; a stale or missing checkpoint is rebuilt, and only a contradicting one is a discontinuity. Write order: journal, then alerts and transitions, then the watermark (I69); after a crash, step 2 is completed from the journal payload, never by re-running a detector. A failed append still raises and opens a discontinuity. At C1a landing, already-open incidents are journaled before the first detection run. | S | No | `pending_restamped_each_pass`, `pending_stale_checkpoint_rebuilt`, `pending_crash_between_writes_rebuilt`, `pending_fast_tick_no_discontinuity`, `pending_failed_append_raises_and_opens_epoch`, `pending_c1a_migration_journals_open_incidents` |
| I54 | **Discontinuity exit** (v3 HIGH 1; v4 Astra 3). Surviving terminal dispositions keep their provenance; where sources disagree, the most restrictive wins, and an unverifiable admission is never honoured; only genuinely uncertain membership becomes one `unexplained_discontinuity` item. Re-certification is automatic at the first clean family pass with a complete, trusted census. Detection never stops. Unattended admission is suspended for the epoch. Beyond the per-family discontinuity budget it stays suspended until the trailing 30-day count is back within budget, with a notice; no re-ratification (D5). | Mechanism S; budget size O (default §16.1) | No | `pending_recertifies_after_clean_pass`, `pending_discontinuity_keeps_unexplained`, `pending_discontinuity_keeps_quarantine`, `pending_discontinuity_unverified_admission_not_honoured`, `pending_truncation_never_stops_detection`, `pending_discontinuity_budget_exhausted_suspends_unattended` |
| I55 | **LEVEL running-extreme rule** (v5; replaces v4's held-level test, which absorbed further deterioration: v4 Astra 1, Opus M1). During an open LEVEL episode, a tick beyond the episode's running extreme in the raising direction is a new incident `lvl:<regime>:<extreme>`, and the superseded incident closes `closed(superseded)`. Nothing re-bases, and a partial return never moves the extreme. The extreme is re-derivable from the alert's incident keys, so a journal truncation cannot reset it (v4 Opus H2(a)). | S; no new number | No | `level_open_alert_new_drop_notifies`, `level_gradual_deterioration_notifies`, `level_oscillation_bounded_notifications`, `level_partial_return_holds`, `level_journal_truncated_new_drop_notifies`, `level_regime_freeze_new_regime_drop_notifies` |
| I56 | **Explanation sources by stream kind** (v3 MEDIUM 2; v3's Q7). `earned_promotion` applies to every kind. `label` applies to every kind, and is optional. `bounded_quiet` applies to NOVELTY entities only. `context_model` applies to mapped incumbent NOVELTY items only. | S | No | `event_bounded_quiet_never_admits`, `level_bounded_quiet_never_admits`, `earned_promotion_admits_training_membership`, `novelty_closed_by_bounded_quiet_consumes_budget` |
| I57 | **`context_model` authority** (v3 MEDIUM 3): DA merged; a lineage that has earned notify-only promotion (C7a); an explicit stream-map entry (same kind, same target quantity, same census universe), reviewed with the learner; a daybreak re-gate of the map. It applies to mapped incumbent NOVELTY items only, and never to its own lineage, which adapts by earned promotion (I71). | S | No | `context_model_requires_earned_promotion`, `context_model_unmapped_abstains`, `context_model_never_explains_own_lineage` |
| I58 | **Withdrawn in v5.** v4's provisional and ratified incumbent anchors are removed with C1a's narrowing (D5). A learned lineage's anchor is its last earned snapshot (I71, §8.3). | n/a | n/a | none |
| I59 | **Regime and universe changes for the incumbents** (v3 MEDIUM 5; narrowed in v5). Recovery only in the raising regime (CC3(a)). An open episode freezes across a change. A new regime re-warms honestly, as today, and its incidents carry its own regime in the key. v4's raise-only-until-admitted state and regime memory are removed (D5). A `census.universe_changed` integrity notice on every availability change is a merge gate of C0.1b (v4 Opus M3). | S | No | `level_regime_change_freezes_open_episode`, `level_regime_freeze_new_regime_drop_notifies`, `cc_l_incumbent_other_universe_no_recover`, `census_universe_changed_notice` |
| I60 | **Incumbent serving state.** While exclusions leave fewer than N folded ticks, an established detector serves its frozen serving snapshot (I45). It never turns provisional through exclusion or aging out. If the snapshot is lost and cannot be rebuilt from the clean ticks before `first_seen`, the episode stays frozen, with the running extreme live (v4 Opus H2(c)). | S | No | `arb_post_recovery_thin_window_uses_snapshot`, `serving_snapshot_deleted_no_absorb`, `incumbent_snapshot_lost_episode_stays_frozen` |
| I61 | **Withdrawn in v5** (the incumbent drift excursion). The incumbents carry no drift budget under C1a's narrowing (D5). Learned lineages: I20, I72. | n/a | n/a | none |
| I62 | **Label ingestion.** The CLI writes labels to an append-only label log. The daemon, the single writer of the chained transition log and pending journal, ingests each label once, by id, and notifies the ingested batch (I27). | S | No | `label_ingested_once_by_daemon`, `label_log_tamper_bounded_by_label_budget`, `label_notified_on_ingest` |
| I63 | **Storm requirements on R3** (C1 merge gate): a closed incident stops counting toward the live cap, while its tombstone is kept so that a re-emitted closed key never re-notifies (I73); the storm exits once live incidents fall below the cap; a storm never swallows a severity escalation; the digest lists every storm with its count. **A learned EVENT incident closes `closed(event_delivered)` once delivered**, so no label is needed to keep the live count down (D5). On 2e208df the live count already excludes acknowledged, recovered and suppressed incidents (`alert-store.js:629-631`), but the storm resets only on a new episode (`:617-620`). | O policy; S requirement | No | `storm_exits_below_cap`, `storm_escalation_notifies`, `storm_listed_in_digest`, `event_incident_closes_on_delivery` |
| I64 | **Shadow disk bound** (LOW 4): the shadow log and the learned store are registered families with budgets and a T8-style invariant | S | No | `t8_shadow_store_budget` |
| I65 | **Shadow auto-disable** after k consecutive aborts (v3 MEDIUM 7) | Mechanism S; k O (default 3, §16.1) | No | `shadow_repeated_aborts_disable` |
| I66 | **Boundary-verification tolerance** (MEDIUM 7): I41's "uptime consistent with the gap" and "boot time inside (last observation, now]" are checked to within the I24 measurement resolution. There is no separate constant. | S | No | `f1_uptime_gap_tolerance_is_resolution` |
| I67 | **Census-universe key hysteresis: none** (MEDIUM 7). The key is evaluated per census. A one-census flip (a symlink swap during `brew upgrade`) is two regime changes bracketed by `unknown` intervals, each raising `census.universe_changed`. The return resumes from the raw window, which still holds the known universe's ticks, because the fold filters by universe (25aeb89); v4's regime memory beyond the raw window is removed (I59). | H | No | `census_one_census_flip_resumes_regime` |
| I68 | **Raw clock readings retained** (v3 LOW 3). Every `tick_summary` record keeps the raw paired clock readings (wall clock, plus the pausing and non-pausing clocks of I37) and the boot id, so suspend bounds can be recomputed once the F2 and F3 cards land. | S (data) | No | `summary_suspend_bounds_recomputable` |
| I69 | **Scored-through watermark** (v4 Astra 2). Each family's journal carries a durable `scored_through` pass id, advanced only after every verdict for that pass is journaled. Detection consumes committed passes in order from it, scoring each as at its time; a pass that cannot be scored is `excluded(unadjudicated)`: never folded, and listed in the digest. | S | No | `watermark_crash_after_commit_replays_kill`, `watermark_unscorable_pass_excluded`, `watermark_restart_no_duplicate_incident` |
| I70 | **Certification at derivation** (v4 Astra 4; Opus LOW 4). A pending-journal entry, a checkpoint and a `tick_summary` record are certified once, when written: their source passes must be inside the certified span then, and they record the pass time and the span. From then on they are valid while their own chain and ledger are continuous. Intentional age or byte eviction of the source facts is not loss; a break in their own chain is. | S | No | `summary_valid_after_source_byte_eviction`, `pending_entry_valid_after_source_age_eviction`, `summary_own_chain_break_is_loss` |
| I71 | **Earned promotion** (D5; v4 Astra 5). Every authority change (notify-only promotion, a new serving version, per-host replacement) needs the pre-registered evaluation passed on this host's coherent replay, adaptive scenarios included, within the drift budget. Each candidate records its normal-component training membership; its promotion is the admission event for exactly that membership. Every promotion is notified and reversible: demotion restores the previous earned snapshot and returns its admitted items to pending. | Mechanism S; bars O (I30) | No | `earned_promotion_admits_training_membership`, `earned_promotion_vetoed_items_not_admitted`, `earned_promotion_notified`, `earned_promotion_demotion_returns_items_to_pending`, `replacement_earned_per_host_notified`, `replacement_rollback_reroutes` |
| I72 | **Poisoning bounds on earned adaptation** (D5; §6.3.2): (a) the drift budget, per promotion and cumulative over H from the last earned snapshot, never reset by a loss (a lost anchor demotes the lineage to shadow and returns the host to its incumbent); (b) the cross-stream veto: a pending item whose interval overlaps the raising interval of an unadmitted incident from a distinct evidence source (I29; counted by physical evidence, so an incumbent never vetoes its own successor) stays out of the normal component; (c) the anomalous-context veto: an item whose context was itself surprising and unadmitted, `unknown`, `unstable` or `new` stays out until that context is admitted; (d) quarantined data never enters a normal component; (e) the adaptive scenarios must still be detected. | Mechanism S; H and budget sizes O | No | `poison_cross_stream_veto`, `poison_anomalous_context_veto`, `poison_drift_chain_rate_limited`, `poison_anchor_loss_reverts_to_incumbent`, `quarantined_never_in_normal_component` |
| I73 | **Incident tombstones** (v4 Astra 9). A closed incident keeps a tombstone so that a re-emitted key never re-notifies. Bounded: an EVENT tombstone is dropped once its interval ends before the scored-through watermark (I69); LEVEL keys live within one episode; a per-alert cap (default §16.1) drops the oldest, with a notice. | S | No | `tombstone_event_dropped_behind_watermark`, `tombstone_cap_visible`, `closed_key_reemitted_no_renotify` |
| I74 | **Quarantined novelty re-alerts** (v4 Opus M2). A quarantined entity leaves both novelty suppression sets (window history and seen-set) as a reappearance watch: its alert stays active while it is present, recovers once a complete census shows it absent, and a later appearance is novel and notifies. | S | No | `novelty_quarantined_entity_reappears_alerts` |
| I75 | **The digest** (v4 Opus M4(a)). Built in C1.5; pushed once per period, only when not empty; **not** counted against the N-per-week attention budget. It lists every admission, closure, label, promotion, demotion, replacement, rollback, storm, discontinuity, unadjudicated pass, open EVENT alert and open LEVEL episode. | Existence and content S; period O (default daily) | No | `digest_pushed_not_throttled`, `digest_lists_every_closure_and_label` |

## 1. Problem (corrected from v1)

### 1.1 Symptom

The real-host calibration on 2026-10-05 showed the session and peer detectors alerting on ordinary events:
- reboots (sessions 3 → 0, then tmux-resurrect churn);
- wake from sleep (the tailnet not yet reconnected);
- tailnet devices coming and going.

The cause is missing context and missing learning machinery. Wrong thresholds are not the cause.

### 1.2 What exists today (with v1's inaccuracies corrected) *(lines verified v4)*

- **Session counts: one global fold.** Session counts use a single Welford fold over every complete tick (`session-baseline.js:385-416`), scored at fixed σ 3/5 with floor 0.5 (`:76-78`).
- **Peer counts: already one context stratum.** v1's claim of "no context dimension" was wrong (Opus L4, Astra 11):
  - Peer counts are already stratified by the regime of collector-availability signatures (`peer-baseline.js:523-534`).
  - Identities are already versioned per scope (`:50-61`).
  - That regime pattern is this plan's precedent, for alert identity and for census universes (I49).
- **Context that is collected and then thrown away**:
  - Uptime is read (`tools/system.js:65`) and stored as a 24-hour metric (`daemon.js:338`, `history-store.js:4`). No model reads it.
  - `last` reboot/shutdown rows are fetched and then dropped (`vpn-peer-status.js:127,154`).
  - Tailscale's non-Running states are parsed (`tools/tailscale-status.js:139`, `logged_out`) but the envelope becomes `unable` (`:166`) and the translator skips it (`fact-translators.js:999`). As a result, "tailnet stopped" leaves no fact.
  - Interfaces, routes and DNS are collected (`tools/network.js:81-261`), but only listeners are persisted (`fact-translators.js:532`).
  - `login_hour_bucket` is the hour of the *tick*, not of the login (`fact-translators.js:887,937`).
- **Retention.** Raw facts are kept 30 days (`fact-store.js:31`) while the read window is 31 days (`welford-stats.js:20`). Before the capacity merge, the 5 MB shared store held about one day at measured volume (Opus audit §1d). `main` now has per-family budgets (§1.6), and the 5 MB constant survives only as a deprecated default (`fact-store.js:32-36`).

### 1.3 Adaptation without arbitration (both audits; Opus audit §1g)

- **Novelty detectors.** They report every entity in the historical union as evaluated (`service-baseline.js:447-464`; `service.appeared` uses it at `:1043-1052`). A new service or lineage edge therefore fires once, and its alert flips to `recovered` on the next tick. HANDOFF 2026-09-27 adjudicated this as "edge-triggered transition notices": it is safe against fabrication, but it absorbs an installed persistence as normal one hour later with no arbitration. **D1 reverses this** (§6.6).
- **Statistical detectors.**
  - Sessions score the latest tick against the window without it, and then fold it on the next call even when it alarmed (`session-baseline.js:394-408`).
  - Peers exclude only overflow, invalid-marker and other-regime ticks (`peer-baseline.js:523-588`, drop direction `:612-647`).
  - Below N = 30 non-excluded ticks the detector turns provisional (`session-baseline.js:410`), emits no candidate (`:653-654`) and reports no coverage (`:913-927`). So merely excluding alarmed ticks would let a sustained shift age the old data out and re-establish at the new level (v2 re-review H2). §6.5 closes that.
- **Result.** This inverts the doctrine's "never adapts a model to unattested change" (`autonomy-doctrine.md:103`).

### 1.4 The outcome loop is broken (Astra audit rank 3)

- **The counting defect.** `fired_count` is `row.alerts.length` over the `alerts.json` snapshot (`calibration.js:245`). Alert identity is stable, so repeated fire/recover cycles collapse into a single record.
- **The effect.** Retuning needs at least 2 fires (`tuning-store.js:428`), so it can never trigger for a flapping constraint. The Astra audit verified that ten cycles yield `fired_count: 1` and no proposal.
- **No labels.** Acknowledgement records receipt only (`alert-store.js:440-451`). The only statuses are active, recovered, acknowledged and suppressed (`:260`; v3 cited `:200`, before the capacity merge); any other status is normalized to `active`. No label reaches any learner, and recall is `null` by design (`calibration.js:64`).

### 1.5 Data sources that are defective on `main` *(lines verified v4, unchanged at 66d3a2b; branch state verified v5 at 1c2b412)*

- **macOS VPN services.** On `main`, `parseScutilNcList` returns `[]` on this host's real `scutil --nc list` output (4 services, 1 connected), because the regex (`vpn-peer-status.js:327`) expects the name right after the UUID (Opus H5). **Fixed on `fix/collector-sources-2026-10`** (f315786, e408cbf, 150babc): `parseScutilNcListDetailed` (`vpn-peer-status.js:326-338` @ 3c18739) parsed all 4 services on this host's real output, classified the **three** `PPP:Modem` entries (`com.redhat.spice.0`, `tart-version-2.30.1`, `tart-version-2.30.6`) as non-VPN, and flagged Tailscale (v3 said two `PPP:Modem` entries; v3 re-review LOW 5).
- **Login origin.** `parseWhoOutput` turns `(:0)` into the remote host `":0"` (`vpn-peer-status.js:94-105`; Opus M3, Astra 12).
- **Binary lookup under launchd.** The daemon's launchd PATH is `/usr/bin:/bin:/usr/sbin:/sbin`, the installed plist carries no `EnvironmentVariables` (`daemon.js:1947`), and collectors `execFile` bare binary names (`tools/sessions.js:44-50,155`). So `tailscale` in /usr/local/bin and `tmux` in /opt/homebrew/bin resolve to ENOENT, which is reported as `absent` (Opus H6). **Fixed on the branch** (be09348, 2f7ab97, 44540d9): pinned absolute paths, a writer-set trust check on every ancestor, and `not_found_on_known_paths` / `untrusted_binary` statuses.
- **Census completeness after that fix (v2 re-review M7; ownership per v3 re-review §4; v4 Opus LOW 8, Astra 10).** At 3c18739 the branch's `censusStateFor` returned `complete` only if every multiplexer reported `ok`, so a tmux-only host was `partial` on every tick. **That is fixed at 1c2b412** *(verified v5)*, which also contains merged `main`:
  - `censusStateFor` (`fact-translators.js:732-738`) is `complete` when at least one multiplexer is usable and none is incomplete, and a `not_found_on_known_paths` source (`tools/sessions.js:182,208`) is outside the universe;
  - 6ba7d80 gives session alerts per-universe ids;
  - 25aeb89 filters the fold by the current universe, with an honest re-warm-up.

  What remains is the `census.universe_changed` notice. Without it, moving tmux aside while screen is present re-warms a new universe blind for about 30 hours, and nothing is raised (Opus M3). The notice is C0.1b's merge gate (§3).
- **Sanitizer.** `isSafeEnumString` checks charset and length only (`diagnostics-sanitizer.js:30,44-46`). It does not validate against a schema (Astra 14).
- **Collection deadline.** Structural collectors run one after another (`daemon.js:425-435`) under one 45-second all-or-nothing deadline that discards every result on timeout (`daemon.js:1055-1066`; Opus M6).

### 1.6 Memory versus budgets (Opus H7) *(verified v4: capacity merged)*

- **Budgets on `main`.** Since the capacity merge (1169d40), the session budget is 4 MiB and the peer budget 16 MiB (`fact-families.js:244-245`).
- **Worst-case horizon.** At worst-case ticks of 67 KB and 158 KB, those budgets hold only ~2.6 days and ~4.4 days of history.
- **No room for 30 days.** A raw 30-day horizon at worst case exceeds the 4× budget ceiling (`fact-families.js:358`).
- **One retention for every family.** `main` applies a single 30-day retention to every family (`fact-store.js:31`), so nothing can outlive the raw window without per-family retention (v2 re-review M5).
- **Volume attack.** An attacker who inflates volume can evict the long memory.

## 2. Design overview

| Part | What | Behaviour change |
|---|---|---|
| **C0 Prerequisites** (§3) | Source fixes, census universes, field schemas, per-collector sub-deadlines, boot identity and boundary verification, suspend grounding with a negative-result plan, F-cards | Removes existing fabrications. A failure now loses one collector's evidence, not the whole tick's. |
| **Outcome substrate** (§9, §12) | Append-only transitions, an optional label log ingested and notified by the daemon, the `fired_count` fix, a `closed` status, the pending journal with its scored-through watermark, the digest | None on detection. Calibration counts become correct. Every admission, closure and label is visible. |
| **Arbitrated adaptation** (§6.3–§6.6) | Alarmed observations get their own lifecycle (pending → admitted, quarantined or excluded) in a daemon-written, hash-chained pending journal with a re-certification exit. The incumbents never fold an alarmed tick, and freeze on a sustained shift until replaced (C1a narrowed). Novelty stays pending until explained (D1). Learned lineages adapt only by earned promotion. | Changes the existing detectors: they stop absorbing alarmed evidence, by folding, by aging out or by recovering. Novelty alerts stay active until explained. A frozen LEVEL alert still notifies a further extreme. A recurring benign dip re-notifies until its successor earns replacement (§6.5.2). |
| **L1 Context facts** (§4) | Lifecycle, network and session context as facts with event-time intervals; `created_vs_boot`; OS build at the boundary | Data only. No alert candidates. |
| **L1s Long memory** (§8) | `tick_summary` family with chaining and raw clock readings, long-lived sufficient statistics, reference snapshots | Data only. |
| **L2 Context vector** (§5) | A pure, versioned function from `tick_summary` | None. Visible in `baseline inspect`. |
| **L3 Learners** (§7) | Transition models declared as EVENT, LEVEL or NOVELTY streams; context dimensions as scored streams, counted once; soft structure; F1–F4 as OS-semantics constraints | Shadow only, default-on (D3), one vertical learner first. |
| **Coverage contract v5** (§6.0–§6.2) | Stream kinds; identity split into alert id, `incident_key` and `raise_ref`; recovery by stream kind; alert status and observation state kept separate | Applies from the first shadow record. |
| **Authority** (§11) | Promotion, serving versions and per-host replacement, all earned from the pre-registered evaluation within the drift budget; notified and reversible; no ratification (D2 as amended by D5, DA1) | Per §11 |

## 3. C0: data-source prerequisites

| Id | Defect | Fix | Owner | Gate |
|---|---|---|---|---|
| C0.1 | ENOENT under launchd is read as "not installed" (Opus H6) | Resolve every collector binary from a pinned allowlist of absolute paths, which also closes PATH hijacking. Never emit `not_installed` from ENOENT. This plan adds the fact `collector.binary_state` ∈ {`resolved`, `operator_trusted`, `not_found_on_known_paths`, `untrusted_binary`, `unable`}. | Done on `fix/collector-sources-2026-10` (be09348, 2f7ab97, 44540d9; not merged; at 1c2b412 it already contains `main` @ 1169d40). The fact family is this plan's. | daybreak (on that branch) |
| C0.1b | The branch's census rule made every tmux-only or screen-only host permanently `partial` (v2 re-review M7; at 3c18739). A binary moved aside re-warms a new universe blind, with nothing raised (v4 Opus M3). | **Per-source census universes** keyed by the `binary_availability` marker attribute, following the peer availability-signature pattern (`peer-baseline.js:523-534`). A multiplexer that is `not_found_on_known_paths` is outside the session universe, so the census is complete over the rest. `untrusted_binary` and `unable` are always incomplete. The key is evaluated per census, with no hysteresis (I67). A change in availability is a new regime, as for peers, and any transition interval that crosses it is `unknown`. **Implemented at 1c2b412** *(verified v5)*: `censusStateFor` (`fact-translators.js:732-738`), `binary_availability` (`:767`), per-universe session ids (6ba7d80), a universe-filtered fold (25aeb89). **Still missing, and now the merge gate:** the `census.universe_changed` integrity notice, a fixed, additive EVENT notice on every availability change, one incident per transition. It needs no pending journal, so moving a binary aside is visible from the day the branch merges. The incumbents' regime rules (§6.5.3, I59) land at C1a. | **`fix/collector-sources-2026-10`**: (1) add the notice; (2) daybreak; (3) merge. The branch already contains `main` @ 1169d40. This plan owns C0.1b only if that branch is abandoned. | daybreak |
| C0.2 | The scutil parser matches nothing on real output (Opus H5) | Real-output fixtures; classify by the bracket token (`VPN:`, `IPSec`, `PPP:L2TP` versus `PPP:Modem`); dedupe the Tailscale NE service against the tailnet. Linux: `nmcli -t connection show --active` plus tun/wg links, CI-gated. | Parser and classification done on `fix/collector-sources-2026-10` (verified v3 on real output, §1.5); the Linux source here | daybreak |
| C0.3 | The Tailscale envelope drops non-Running state (`tailscale-status.js:139,166` → `fact-translators.js:999`); the parser requires `Peer` even to observe backend state (`:83-84`) | Emit `net.tailnet_state` for every probe outcome. Parse `BackendState` without requiring `Peer`. Add `Self.Online`, exit-node-in-use, a health-issue count bucket and an HMAC of `CurrentTailnet`. | this plan | daybreak |
| C0.4 | Login-origin parsing (Opus M3, Astra 12): `(:0)`, `(:pts/3:S.0)` and `(mosh [pid])` all become remote; macOS local sessions are `console` and `ttysNNN`; `last` re-reads the same rows on every tick | Linux: `loginctl list-sessions` and `show-session` (Remote, RemoteHost, Service, Type, Class, IdleHint, LockedHint). macOS: `who` plus IOConsoleUsers. Explicit local-host patterns; keep the tty class; use the first-observed tick, never a parsed login time (decision kept from `fact-translators.js:882-886`). Dedupe `last` rows by row digest across ticks. | this plan | daybreak |
| C0.5 | The "location" fingerprint collides, is confounded with the tailnet, and is reversible (Opus M5, Astra 14) | Rename it `net.config_fingerprint`. Components: physical default-route interface kind; gateway MAC (`arp -n` / `ip neigh`); IPv6 router-advertisement prefix; DHCP domain; resolvers scoped to the physical interface only (not MagicDNS). Each component carries its own availability. HMAC with a per-install key stored outside fact history (state dir, 0600, never federated). Document it in the README data table. | this plan | daybreak |
| C0.6 | The sanitizer is not a schema validator (Astra 14) | A closed per-field schema for each new family: enum sets, hash/HMAC formats, integer ranges, and a **physical-object provenance tag** per field (used by I5). Validated at the translator. A rejected field yields `unable`, never a write. Hash at source. | this plan | daybreak |
| C0.7 | The all-or-nothing structural deadline (Opus M6) | Per-collector sub-deadlines inside the 45 s budget. Context collectors run after the session/peer census and record `unable` on timeout. They never cost the census. Cheap context reads bracket the census (§4.4). | this plan | daybreak |
| C0.8 | Reboot inferred from boot *time* (Astra 3, Opus M1) | One boot-identity primitive owned by the trusted-state B-ledger: macOS `kern.bootsessionuuid` (*verified 2026-10-06* readable unprivileged on Darwin 25.2, which answers trusted-state open question 2 for this OS version); Linux `/proc/sys/kernel/random/boot_id`, CI-gated. `todos/2026-09-08-clamp-boot-identity-guard.md` consumes the same primitive. It adds the boundary-verification conjunction (I41), checked to within the I24 resolution (I66); the OS build at each boot (`kern.osversion`, *verified v3* readable unprivileged: `25C56`; Linux `/proc/sys/kernel/osrelease` plus the os-release build id); and conformance tests: a Linux CI VM reboot, kexec, and soft-reboot (`boot_id` must be unchanged); a macOS tart VM reboot; `launchctl reboot userspace` (`kern.willuserspacereboot` exists on this host, so the behaviour must be recorded, not assumed); a snapshot revert (the boot-id regression must be detected). | shared with trusted-state Phase 3 | daybreak |
| C0.9 | Suspend sources are ungrounded (Opus M2); there is no plan for a negative result (v2 re-review M9); v3 named the wrong pausing clock on macOS (v3 re-review LOW 1) | Measure on a real laptop and write up the result, **naming the clock ids per platform**: Linux `CLOCK_MONOTONIC` (pauses across suspend) against `CLOCK_BOOTTIME` (does not); macOS `CLOCK_UPTIME_RAW` / `mach_absolute_time` (pauses) against `CLOCK_MONOTONIC` / `mach_continuous_time` (do not). Also measure the macOS sysctls (`kern.sleeptime`/`waketime`, `kern.sleep_abs_time`/`wake_abs_time`, `machdep.wake_abstime`/`wake_conttime`, and `kern.monotonicclock_usecs`, which is readable unprivileged here (*verified v3*) but unvalidated because this VM never sleeps); confirm which clock libuv's `hrtime` uses on each platform; read Linux `/sys/power/suspend_stats/success`; and find out whether DarkWake is detectable cheaply. The A5 revert (`todos/2026-09-06-llm-budget-trusted-time.md`) is the cautionary precedent. **Go/no-go per platform, with a defined fallback:** *go* means F3 is verified there and `host.suspend` carries measured `[lower, upper]` bounds; *no-go* means `host.suspend` is `unknown`, the exposure interval is `[0, wall Δ]`, F3 stays inactive on that platform, and the exposure rule I46 applies (raise only if surprising at maximum exposure). The cost of a no-go is lower sensitivity, reported as `exposure_uncertain` in the abstention counts. It is never a false alert. The raw readings are kept in `tick_summary` either way (I68). | this plan | review |
| C0.10 | Inventory | Land the §0.5 rows as pending named tests | this plan | review |
| C0.11 | Horizons | Re-verify retention and every joined family's certified horizon on merged `main` (Astra 10) | this plan | review |
| C0.12 | No census at the boot boundary (F-class opinions, Opus §2). The daemon is a GUI LaunchAgent, so it starts only at GUI login, and the structural census runs only once a full interval has passed since the checkpoint (`daemon.js:1043`). | A boundary-triggered census at +0 min when the daemon observes a new verified boot id or a wake, plus the existing +2/+10 samples (I15). The pre-shutdown and post-boot gaps are recorded with their durations (§7.8.3). | this plan | daybreak |
| C0.13 | The F class has no cards and no registry | Write one F-card each for F1–F4 (§7.8.5): statement, OS sources, platforms and versions, preconditions, consequences, tripwire, rejected broader wordings. Build the closed registry (I40) with a kill switch per fact. | this plan | code review + daybreak, per fact; no operator ratification (D5) |

## 4. L1: context facts

New families in the `fact-families.js` registry. Each family gets its own budget (pinned worst-case bytes per tick × records per interval × horizon), its own ledger and trust gate, and a seen-set where useful.

### 4.1 `host_lifecycle`

| Fact | Source | Semantics (honest) |
|---|---|---|
| `host.boot` | Boot identity (C0.8), plus the reported boot time (`kern.boottime`, `/proc/stat btime`) and the OS build (`kern.osversion`, osrelease) as attributes | A reboot is a **verified boot-identity change** (I41), never a boot-time change. Boot time moves with wall-clock steps (Linux btime = realtime − boottime; macOS adjusts it when the calendar is set). Every `tick_summary` record carries the boot id and the seconds since boot, so `since_boot` never depends on a single event surviving retention (Astra 10). An OS build change across the boundary is recorded, as cause corroboration for the reboot stream (§7.8.3). |
| `host.boot_boundary` | The verification conjunction (I41) at the first observation in a new boot id | `verified`, `unverified` (with the failing conjunct) or `tripwire` (with the contradiction). Only `verified` lets F1 act on the interval. |
| `host.suspend` | Fast-tick (60 s) deltas between a clock that pauses across suspend and one that does not, named per platform by C0.9 (I37), aggregated into the next structural record; the raw readings are kept (I68) | Aggregate suspended duration within (t_prev, t_now], as `[lower, upper]` bounds, and the number of suspends only where the OS exposes a counter. **No invented start or end instants** (Astra 3). On a C0.9 no-go platform, `unknown` with bounds `[0, wall Δ]`. Under F4, a suspend inside an interval is never an explanation for a departure in it. |
| `host.darkwake` | Only if C0.9 finds a cheap unprivileged signal | Its own context value; absent otherwise. Never guessed. |
| `host.clock` | Fast tick: wall-clock Δ versus the non-pausing clock's Δ; timezone id (hashed) plus UTC offset | A `clock_step` event (magnitude bucket) when the gap exceeds measurement resolution (I24); timezone and DST change events. Local-time features are computed from the **stored** offset, never from the current timezone (Astra 10). Clock deltas are taken only within one boot (F2). |
| `host.daemon_gap` | The daemon checkpoint versus now, split using `host.suspend` | Cause ∈ {`suspended`, `daemon_not_running`, `unknown`}. **A fact only** (Opus M6). An integrity alert on unexplained gaps, if wanted, is a separate reviewed (S) rule outside this plan. |
| `host.lifecycle_record` | `last` reboot/shutdown rows, already fetched and dropped today (`vpn-peer-status.js:127,154`); `last -x` on Linux | Historical records with a time-confidence field, deduped by row digest. A missing shutdown row is `unknown`; it means neither "unclean" nor "clean". `pmset -g log` is not used: it is 1.4 MB and takes ~2.1 s. Reading `journalctl -b -1` needs group membership, so it is not used (Opus L2). |

### 4.2 `network_context`

| Fact | Source and notes |
|---|---|
| `net.tailnet_state` | `BackendState` (closed enum), `Self.Online`, exit node in use, health-issue count bucket, `CurrentTailnet` HMAC. Emitted for every probe outcome: `logged_out`, `not_found_on_known_paths`, `untrusted_binary` and `unable` are values (C0.3). `Online` means the node is connected to the control plane. It does not prove peer reachability (Astra 11). |
| `net.vpn_service_state` | Per-service state with HMAC'd uuid and typed kind (C0.2), at most 8 services per record (overflow is counted, L2). **Leaves the peer population for the learners**, because a connected VPN service is currently counted as a "peer" (`vpn-peer-status.js:425-430`), so using its state as context would restate the target (Astra 4). The incumbent detector is unchanged. |
| `net.config_fingerprint` | C0.5. Renamed from "location", because it is an observed configuration, not a place. |
| `collector.binary_state` | C0.1, C0.1b |
| `context.transition` | Old → new for any of the above, with the event-time interval (prev_obs_ts, obs_ts]. Never an instant. |

### 4.3 `session_context`

| Fact | Source and notes |
|---|---|
| `session.login_arrival` | The first-observed tick of a login record (C0.4). Origin class ∈ {`console`, `local_tty`, `local_display`, `remote`, `remote_mosh`, `unknown`}; remote host HMAC'd; tty class. Repeated sightings are not repeated logins (Astra 12). |
| `session.attachment` | `tmux list-clients -F '#{client_tty} #{session_name}'` joined to the login tty (Opus L1). This replaces v1's "creator lineage", which is infeasible: the tmux server daemonizes, and exited creators cannot be recovered (`tools/provenance.js:140`). |
| `session.created_vs_boot` | Per session, at collection time: `after_boot` if the creation second (tmux `#{session_created}`, `tools/sessions.js:39-42`) is at or after the boot time of the current verified boot, `before_boot` if earlier, `unknown` otherwise (screen exposes no creation time; an unverified boundary; a clock step recorded in the interval). It must be computed at collection, because the stored creation fingerprint is an opaque hash (`fact-translators.js:666-673`) (I51). A `before_boot` instance after a verified boundary is an F1 tripwire. |
| `user.presence` | Screen locked and idle bucket where readable unprivileged (IOConsoleUsers `CGSSessionScreenIsLocked`; logind `LockedHint`/`IdleHint`) (Opus L3) |
| Later candidate families (not C2) | `software_change` (package and update events, the doctrine's own corroboration example at `autonomy-doctrine.md:105`); power source and lid. The Descartes version and config hash ride in `tick_summary` from C2. |

### 4.4 Rules for all L1 facts (S)

- **Closed schemas** (C0.6); hash or HMAC at source; a physical-object provenance tag per field.
- **Degrade, never fabricate.** The states are `ok`, `partial`, `unable`, `not_applicable`, `not_found_on_known_paths` and `untrusted_binary`, and an unavailable value is recorded as such.
- **Event time is distinct from observation time.**
  - Today the daemon stamps every family with the same tick `ts` (`daemon.js:1075-1106`), even though collectors run one after another (`:425-435`). So a VPN can reconnect between the census read and the context read, producing a context/response pair that never coexisted (Astra 10).
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
- **Leakage rule (S, M6).** No dimension may be derived from the same physical object as a target it conditions. The check runs over the **field-provenance tags** of C0.6, not over families: targets and context can share a family (WireGuard peers come from `wg show <if> latest-handshakes`, `vpn-peer-status.js:207`, while C0.2 adds wg links to VPN context), so a family-level check would be vacuous. Banned pairs include a wg link and its peers, and the Tailscale network extension and the tailnet (I5).
- **Missing values.** `unable`, `unstable` and missing inputs give `unknown`. `new` (never seen) and `other` (rare) are values in their own right. None of them is ever silence.
- **Host vocabulary (H1).** A dimension never observed on this host (`presence` on a headless Linux host with no logind seat; `vpn` on Linux without NetworkManager; `since_wake` on a host that has never slept) is excluded from this host's vocabulary rather than encoded as `unknown` on every tick. Its first appearance is a structure-version change (§7.4). `not_applicable` and a stable `not_found_on_known_paths` are known values, not `unknown`.
- **Versioned mapping, without volatile identity (v3 re-review MEDIUM 6).** The vocabulary, K and the bucket edges are versioned, and they make up `structure_id` with the model families (§6.1). **Top-K membership is not**: it is a parameter inside a version, refit within the drift budget, with values outside it encoded `other` or `new` (I7). Weeks of café visits, or an attacker toggling resolvers, can reorder the ranking without minting new alert ids or demoting a promoted lineage. In evaluation, the vocabulary and the ranking are fitted inside each fold from preceding data only (Astra 9, Astra 10).

## 6. Coverage contract v5 and arbitrated adaptation (security-critical)

**What changed from v4** (the v4 reviews; D5).
- **C1a is narrowed for the incumbents** (§6.5). v4's held level, re-base, bounded-quiet LEVEL exit, serving generations, incumbent anchors, incumbent drift measure and regime admission are gone. Both reviews found defects in exactly that machinery: Opus H1 (an admitted held level re-raises on the next tick, and a recurring dip is never admitted), Astra 1 (the held level absorbs further deterioration) and Opus M1 (re-base is undefined). A single non-adaptive rule keeps a frozen LEVEL alert from muting its detector: a tick beyond the episode's running extreme opens a new incident (I55).
- **Admission** (§6.3). `earned_promotion` joins the closed set, and an earned promotion is the admission event for the promoted version's training membership (Astra 5). Labels are optional. Bounded quiet applies to NOVELTY only.
- **The pending journal** (§6.4) gains a scored-through watermark (Astra 2). Its discontinuity recovery keeps surviving terminal dispositions (Astra 3). Its entries are certified when they are written (Astra 4). It carries the incumbents' frozen snapshots, so losing one is detected (Opus H2(c)).

**What changed from v3** (v3 re-review HIGH 1–3, MEDIUM 1–5; kept for the record).
- v3 derived pending membership from alert transitions, so the end of an alert ended the pending state of its data. A `recovered` episode, or one closed as `confirmed_incident`, released its alarmed ticks into the next recompute (HIGH 3).
- v3's integrity rule copied the seen-set stamp. Only the fact-store retention pass can meet that stamp, and only the detectors know verdicts (HIGH 1).
- A LEVEL alert had one incident key (`default`) and no exit but a label, so under notify-once it silenced its host-global detector (HIGH 2).

### 6.0 Stream kinds and two lifecycles

**Today** *(verified v5)*.
- An alert's identity is `alertId(rule_id, fingerprint)` (`alert-store.js:28-31`; `:37` @ 2e208df).
- Any covered identity that is absent from this tick's candidates is recovered (`:374-383`; notify-once `:694-704` @ 2e208df, which also marks every incident of the alert `recovered`).
- The daemon checks only the owner and the identity (`daemon.js:872-892`).

**The risks.**
- A context-conditioned learner that reports an identity as evaluated after a context change fabricates a recovery (v1 Opus B1: a reboot, `tailscale down`, the unknown → parent fallback).
- On an event stream, a quiet next interval is not evidence (v2 re-review B1).
- The end of an alert is not an admission of its data (v3 re-review HIGH 3).

**Stream kinds (I42).**

| Kind | Streams | What an alert asserts | Recovery by evidence | Bounded quiet |
|---|---|---|---|---|
| **EVENT** | session departures, arrivals and churn; login arrivals; tailnet inbound sessions; reboot events; context transitions (tailnet, VPN, `net_config`, presence, clock, binary availability) | "These events happened in interval (t₀, t₁] of boot b." An event cannot un-happen. | Departures only, when the same instances are present again within the same boot (CC3-E) | Never: undefined for a point event (I56) |
| **LEVEL** | session occupancy; tailnet online count; the incumbent `session.count_drop` and `peer.count_drop` / `peer.count_spike` | "The level observed now is surprising." A level can return. | Yes (CC3) | **No** (v5). A learned LEVEL stream adapts by earned promotion (§6.3.1); an incumbent freezes until it is replaced (§6.5). |
| **NOVELTY** | the incumbent `service.appeared`, `scheduled_job.appeared` and `process.lineage.novel_edge`; tailnet node-key novelty | "Entity e is present, and was never seen before." The appearance happened; the entity may persist. | Never; except that a quarantined entity's alert recovers when a complete census shows it absent (I74) | Yes (D1; §6.6) |

v3 listed novelty under EVENT. v4 gave it its own kind because its subject persists, and that is what makes bounded quiet definable for novelty and not for a point event.

**Named exception: the incumbent edge-triggered rules** (v3 re-review LOW 2).
- `session.churn` reports a fresh, unchanged entity as evaluated (`session-baseline.js:629-630`), and `service.disappeared` recovers through union coverage (`service-baseline.js:447-464`). Both therefore recover on the next tick.
- They are EVENT rules, but they fold nothing and hold no pending data. Notify-once keys each of their transitions as its own incident (notify-once README, "The producer declares incident identity"), so the wrong status costs no notification.
- They are recorded as an exception, not changed (I35, §15). Their `recovered` transition is logged as `recovered(edge_rearm)`, and calibration never counts it as evidence that an event un-happened (`incumbent_edge_rearm_logged_not_evidence`).

**Two lifecycles, never merged (v3 HIGH 3; I52).** An alert has a status. The observations that raised it have a state. They change for different reasons.
- **The alert lifecycle**, per alert id and per incident record (the notify-once rework's incident map). An alert goes `active` → `recovered` (positive evidence, CC3, alert-wide). Each incident can also go to `closed(reason)`, where the reason is one of `label`, `superseded`, `event_delivered`, `admitted_earned`, `admitted_unexplained`, `explained_context` or `replaced` (CC7). `recovered` and `closed` both re-arm.
- **The observation lifecycle**, per pending item in the pending journal (§6.4). An item goes `pending` → `admitted(source)`, `quarantined(reason)` or `excluded(reason)`. Only `admitted` data is ever folded into a learned lineage's authority-bearing state or closes a NOVELTY alert. **The incumbent statistical folds never fold an alarmed tick at all** (C1a, §6.5). Pending membership is read from the journal alone, never from alert status.

| Event | Alert / incident effect | Observation effect |
|---|---|---|
| A trusted evaluation raises (CC2) | A new incident (notify-once: due) | A new pending item; during an open LEVEL episode, the tick joins the episode's item |
| An open LEVEL episode sees a tick beyond its running extreme (I55) | A new incident `lvl:<regime>:<extreme>`, which is due; the incident it supersedes closes `closed(superseded)` | The tick joins the episode's item |
| A learned EVENT incident's notification is delivered (I63) | The incident closes `closed(event_delivered)`; the alert stays `active` | None |
| `recovered` (CC3, CC3-E) | The alert is recovered and re-arms | **None.** The items stay pending. |
| A version earns promotion (§6.3.1, I71) | Incidents whose items it admits close `closed(admitted_earned)`; a LEVEL episode whose items it admits closes and re-arms | Its recorded training membership, minus vetoed items, becomes `admitted(earned_promotion, version)`; drift-charged; notified |
| A lineage earns replacement of an incumbent on a host (§11.2) | The incumbent's open alerts on that host close `closed(replaced)`, each listed in the replacement notification | None: the items stay pending, and are admitted only through a training membership |
| `bounded_quiet` admits a NOVELTY entity (§6.6) | `closed(admitted_unexplained)`; re-arms | Admitted (`admitted_unexplained`), charged to the novelty budget, listed in the digest |
| `context_model` explains a mapped incumbent NOVELTY item (§6.3) | `closed(explained_context)` | Admitted, charged to the novelty budget |
| Label `expected`, `mine` or `benign` (optional) | EVENT and NOVELTY incidents close `closed(label)` once delivered. An incumbent LEVEL episode stays open (C1a). | Admissible to learned lineages, within the label budget; a NOVELTY entity is admitted. Notified on ingest (I27). |
| Label `suspicious` or `confirmed_incident` (optional) | EVENT incidents close `closed(label)` once delivered. A LEVEL episode, and a NOVELTY alert whose entity is still present, stay `active`, because the condition is real (I74). | **Quarantined, permanently** (§6.4.5). Notified on ingest. |
| A pending tick leaves the raw window | None | Its tick mark is dropped, since the tick no longer exists to fold. The item keeps its sufficient statistics and stays pending. |
| The family's pending cap is reached | None | The oldest unadmitted items compact into `excluded`: never folded, and listed in the digest |
| A committed pass cannot be scored in order (I69) | None | `excluded(unadjudicated)`: never folded, and listed in the digest |
| A discontinuity is detected (§6.4.4) | An integrity notice | Surviving terminal dispositions are kept; observations whose membership is uncertain are held in `unexplained_discontinuity` |
| An admission is revoked (an operator veto, or a demotion) | None: a closed incident stays closed | The item returns to pending and the affected statistics are rebuilt. The next tick re-scores, so a condition that still holds raises a new episode, which notifies. |

**There is no path on which an alarmed observation folds without an `admitted` record, and none on which an incumbent folds one at all.** Every `admitted` record names its source, its evidence, its budget charge and its digest line. None of these ever admits: recovery, a quarantining label, aging out of the raw window, compaction, a reboot, a model change, a discontinuity, an unadjudicated pass.

### 6.1 Identity (CC1; v2 re-review H1, M1; v3 re-review HIGH 2, MEDIUM 6; v4 Opus H2(a), M1, LOW 3; Astra 1, 9)

Verified on `feat/notify-once-2026-10` @ 2e208df *(verified v5; the branch is in rework, so these lines will move)*:
- The episode is `(alert id, incident_key ?? "default")` (`alertEpisodeKey`, `alert-store.js:80-82`).
- Each alert row persists an incident map. Each incident record carries its own severity, delivery state and status (`:300-330`; README, "Each alert row persists an incident map").
- A new incident key, or a severity escalation within an incident, makes that incident due. A confirmed incident at or below its notified severity is not due (`notificationDueForIncident`, `:567-573`, the check at `:571`).
- `newEpisode = !current || current.status === "recovered" || (!current.episode_started_at && …)` (`:605-606`). A new episode resets the incident map (`:617`). Neither status list has `closed` (`:282` for alerts, `:325` for incidents).
- An alert holds at most 256 live incident keys, and acknowledged, recovered and suppressed incidents do not count as live (`:10`, `:629-631`). The 257th puts the alert into `incident_storm`, which sends one storm notification and then no per-key notifications (`:676-690`). The storm resets only on a new episode (`:618-620`).
- A display copy of each candidate's `diagnostics` is kept per incident (`candidatePayload`, `:500`).

Each component of a learned alert goes in exactly one place:

| Component | Alert id (fingerprint) | `incident_key` | `raise_ref` |
|---|---|---|---|
| `rule_id` (which implies the stream kind) | ✔ | | |
| lineage | ✔ | | |
| `structure_id`: the dimension set, the model families, the bucket edges and K. **Not** top-K membership, which is a parameter inside a version (MEDIUM 6; I7, §5) | ✔ | | |
| EVENT streams: HMAC of the boot id, the interval (prev_obs_ts, obs_ts], and the event-set digest (entity keys plus instance fingerprints) | | ✔ | |
| NOVELTY streams: the producer's stable entity identity, as the branch already declares | | ✔ | |
| LEVEL streams: `lvl:<regime>:<extreme>`, where `<regime>` is the census regime or universe of the raise (where the alert id does not already carry it) and `<extreme>` is the episode's running extreme in the raising direction (I55). **Not** `default` (v3 HIGH 2). | | ✔ | |
| `stratum_class`, the full raising cell (state, calendar and `since_*`), the evaluation level (leaf or backed-off), the parameter-snapshot digest, the raising regime, the exposure interval, the predictive p-value, the evidence summary (at-risk count, departed set) | | | ✔ |

- **Fingerprint** = `v3:<lineage>:<structure_id>`. No context enters it. Precedent: the scope-versioned `v2:vpn` / `v2:markerless` identities (`peer-baseline.js:50-61`).
- **Why no stratum in the alert id or the incident key.** A cell change (presence active → locked, a `since_*` bucket edge) would otherwise mint a new identity, or a new incident key and therefore a new notification, every time a persistent anomaly moved cell, while the old identity froze (v2 re-review H1(b)).
- **Why the LEVEL key is `lvl:<regime>:<extreme>`.**
  - With `default`, once the incident is confirmed, every later raise on the same id is silent unless its severity exceeds the notified one (`:571`). Both peer rules are hard-capped at `warning` (`peer-baseline.js:688,730`), so a second drop could never notify (v3 HIGH 2).
  - The extreme is monotone within an episode, so a new key means a genuinely further anomaly, and a cell change, a partial return or an oscillation mints nothing (`id_cell_change_no_new_incident`, `level_oscillation_bounded_notifications`).
  - The key is **re-derivable from the alert's own incident keys**: it needs no generation or ordinal stored in the journal. Truncating the journal therefore cannot restart the numbering and collide with a confirmed key (Opus H2(a)).
  - The regime keeps a new regime's first raise from colliding with a frozen old-regime episode under the shared `v2:vpn` id (`peer-baseline.js:55-61`). Sessions already carry the universe in the alert id on the collector branch (6ba7d80).
  - For the incumbents, C1a moves the producer key from `default` to this form, rekeying open incidents in place with no new notification (§6.5.4; Opus LOW 3). The branch README's "session and peer baseline deviations use `default`" is superseded for them at C1a.
- **Where `raise_ref` lives.** A display copy rides in the incident's payload diagnostics (`:500`). The **authoritative** copy lives in the pending journal (§6.4), because `alerts.json` has no integrity ledger.
- **Bounded identities, storms and tombstones** (Astra 9).
  - Learned alert ids per rule ≤ live lineages × retained structure versions, which the snapshot cap (I3) bounds. Live incident keys per alert ≤ 256, from the branch.
  - **No label is needed to keep the live count down** (D5):
    - a learned EVENT incident closes `closed(event_delivered)` once its notification is confirmed, because an event has nothing further to track (I63);
    - a superseded LEVEL incident closes `closed(superseded)` (I55);
    - each NOVELTY entity has its own alert id.

    A storm therefore needs a genuine flood of undelivered incidents. An attacker who floods incidents buys one storm notification and a digest entry, not silence. A label may still drain one; nothing depends on that.
  - **Closed incidents leave tombstones**, so a re-emitted closed key never re-notifies. Tombstones are bounded (I73):
    - an EVENT key names its interval, so its tombstone is dropped once that interval ends before the scored-through watermark (I69), since that interval is never scored again;
    - LEVEL keys live within one episode, whose map resets on a new episode (`:617`);
    - a per-alert cap (S, §16.1) drops the oldest beyond it, with a notice.
  - **C1 merge requirements on R3 (I63):** a closed incident stops counting toward the live cap, while its tombstone is kept; the storm exits once live incidents fall below the cap; a storm never swallows a severity escalation; the digest lists every storm with its count.

### 6.2 Recovery and closure (CC2–CC8; I17)

- **CC2 Raise.** Any trusted evaluation may raise, including a backed-off one (`unknown`, `new`, `other`, `unstable`, below support). It then uses the wider backed-off predictive and is never silent (Opus H3). It raises only if the observation is surprising at every admissible exposure (I46).
- **CC3 Recover, LEVEL streams.** All of the following must hold:
  - (a) a fresh, complete census in **the same census universe and regime as the raise** (I49, I59), and trusted fact history (the existing gates). This applies to the incumbents too (v3 MEDIUM 5);
  - (b) the same lineage and the same `structure_id`;
  - (c) the current context is known and stable: no `unknown` or `unstable` dimension in the host vocabulary (§5);
  - (d) the current evaluation is at the raise's evaluation level or more specific, with support at or above the floor (I16), so a back-off raise can recover at the same back-off level once the context is known (H1(c));
  - (e) the evidence has changed, and the observation is unsurprising **both** under the current predictive in the current cell **and** under the raising parameter snapshot in the **raising cell** taken from `raise_ref`, at every admissible exposure (I46). For an incumbent, the raising snapshot is its frozen serving snapshot (§6.5.1). The raising cell is the anchor: the host never has to return to it, and a refit, an hour change, a `since_*` advance or a slow walk can never clear an alert on unchanged evidence (Astra 5; v2 re-review H1(a));
  - (f) for a learned lineage, the lineage is not over its drift budget (§11.3). The incumbents carry no drift budget (C1a narrowed, §6.5).
- **CC3-E Recover, EVENT streams.** A quiet next interval is never evidence. The learner reports an event alert id as evaluated only when every open incident in its episode has positive evidence that the raised condition no longer holds:
  - **Departures.** Every departed **instance** in the episode's cumulative departed set is present again, in a fresh, trusted, complete census of the same universe and **within the same boot id** as the incident. Instance identity is the same entity key, the same creation fingerprint, and a known `created_vs_boot` (I51), never the name alone (v3 MEDIUM 1). That is the case where an earlier census was wrong. Any boot-id change, verified or not, blocks it, and so does a `created_vs_boot` of `unknown` (for example after a recorded clock step), because the instance cannot then be verified.
    - **A same-name recreation does not recover.** A returning name with a new creation fingerprint is a new instance. The departure stays open until an earned promotion admits it or a label closes it, and the recreation is scored as a churn event in the same learner, as an EVENT incident of its own. v3 let a recreation "restore the departure". That keyed recovery on names, against §6.0, against the reject list ("matching names prove recovery", §7.8.5) and against Astra's F-class opinion ("returning names alone cannot authenticate restoration").
    - **No creation time, no instance identity.** Where a source exposes no creation time (screen: `tools/sessions.js:135-141`), an instance cannot be re-identified, so a return never recovers a departure.
    - **Across a verified boot boundary, a pre-boot departure never recovers.** Under F1 a restored name is a new instance (F-class opinions, Opus §2 item 7; Astra §2).
    - **Evidence limit** (Opus LOW 7). At the same UID, tmux restarted under a faked clock can reproduce old `#{session_created}` values (`tools/sessions.js:39-42`) and so fabricate this recovery. The data stays pending, so the effect is on alert status only (§16.2).
  - **Every other EVENT kind** (arrivals, churn, login arrivals, inbound sessions, reboot events, context transitions): there is no evidence-based recovery, because what arrived, churned or transitioned did happen. Such an alert stays `active` until an earned promotion admits its items, or a label closes it (CC7). Its incidents close once delivered, so it holds no live incident (I63).
- **CC3-N NOVELTY streams.** These never recover by evidence: the entity did appear. They close when an explanation source admits the entity (§6.6). The one exception is a quarantined entity: its alert recovers when a complete census shows the entity absent (I74).
- **CC4 Otherwise freeze.** The identity is not reported in `evaluatedAlertKeys`, and the alert keeps its status. Under notify-once a frozen alert is silent for its open incidents, and a new incident under the same id still notifies: a new event set (EVENT), or a new running extreme (LEVEL, I55). A new NOVELTY entity has its own alert id.
- **CC5 Successors.** A successor version or replacement never reports a predecessor's identity as evaluated.
  - Predecessor parameter snapshots are retained, within bounds (§8.3), so the predecessor's own pure re-score can still recover its alerts under CC3.
  - If the snapshot is gone (history loss), the alert stays frozen until a successor's earned promotion admits its items, or a label closes it.
- **CC6 Raise-only cells.** Transition and aftermath cells stay raise-only on a host until the lineage has earned replacement for that family on that host (§11.2, C7b).
- **CC7 Closure.** Nothing requires a label (D5).
  - **An earned promotion** closes, on every kind, the incidents whose items it admits (`closed(admitted_earned)`). A LEVEL episode closes and re-arms, because the admitted state is now the baseline the next change is measured against (§6.3.1).
  - **NOVELTY** also closes by `bounded_quiet` or a mapped `context_model` (§6.3, §6.6).
  - **An incumbent LEVEL episode** ends only by recovery or by replacement (C1a narrowed, §6.5). It has no admission exit.
  - **A learned EVENT incident** closes `closed(event_delivered)` once delivered, which is bookkeeping. The alert itself stays `active` until an earned promotion admits its items or a label closes it. An EVENT alert with no promoted successor stays open as one digest line: a visible cost, not a chore.
  - **An optional label** closes incidents, with a reason, on every kind except an open incumbent LEVEL episode, once the incident is delivered (Opus M5). Labels are scoped to an alert id plus incident keys, to a LEVEL episode, or to a pending window, and can be applied in bulk from the digest.
  - Time, a quiet interval, a context change, a boot and a model change never close an alert of any kind.
  - **v3's Q7 stays resolved, and dropped from §16.** Bounded quiet measures that a persisting state stayed stable. A point event has no persisting state, so the mechanism is undefined for it: it neither admits nor closes EVENT data (I56).
- **CC8 F1 never touches alert or observation state.** F1 scopes identity comparisons and removes boundary-crossing departures from the hazard likelihood. It never recovers, closes, admits, quarantines or lowers severity (§7.8.2, A6).

**An open alert blocks nothing.**
- It notified at activation, and a new incident still notifies (CC4). A storm is bounded and visible (§6.1).
- Learning proceeds without a label. Shadow learners fit on everything (§6.3), and pending data is admitted by an earned promotion.
- Closing alerts is bookkeeping: notification, not confirmation (`autonomy-doctrine.md:46-50`).

**Stated consequence.**
- After a reboot, a pre-reboot departure alert stays open until an earned promotion admits its items or a label closes it.
- A pre-reboot occupancy alert recovers only once the count is unsurprising under its raising snapshot, which the post-boot zero is not.
- If the post-boot level then holds, the episode stays frozen. A further drop beyond its running extreme is a new incident and notifies. The held level becomes normal only by an earned promotion (learned streams) or by the earned replacement of the incumbent (§6.5).
- Nothing about an open alert mutes its detector.

**Named gate tests (C5 and C1a daybreak), split by kind:**

| Test | Setup | Expected |
|---|---|---|
| `cc_e_quiet_interval_after_kill_no_clear` | 4 of 5 sessions killed at t (D = 4 of 5 at risk), raise; at t+1, same cell, D = 0 of 1 | Frozen. The v2 re-review B1 scenario. |
| `cc_e_departed_entities_return_recovers` (positive control) | Same as above; at t+3, within the same boot, the four entity keys are present again with the same creation fingerprints (a census miss) | Recovered |
| `cc_e_recreated_same_name_scored_as_churn` | The four are recreated under the same names, with new creation fingerprints, in the same boot | **Frozen**: the departure does not recover (v3 MEDIUM 1). A churn event is scored in the same learner and, if surprising, raises its own EVENT incident. |
| `cc_e_no_creation_time_return_frozen` | A screen session departs and a session with the same entity key returns | Frozen: there is no instance identity to verify |
| `cc_e_partial_return_no_clear` | Two of the four return | Frozen: the cumulative deficit is not empty |
| `cc_e_reboot_restored_names_no_clear` | Departure alert raised; verified reboot; resurrect restores the same names | Frozen; a restored name is a new instance (F1) |
| `cc_e_reboot_freezes_nonvacuous` | Departure alert raised with `since_boot` = days; reboot; days later `since_boot` climbs back into the raising bucket with a quiet interval | Still frozen (v2 re-review B1 reboot case) |
| `cc_e_arrival_never_recovers` | A surprising arrival raises; the arrived entity later departs | Frozen until an earned promotion admits it or a label closes it |
| `event_incident_closes_on_delivery` | A learned EVENT incident is delivered and confirmed | The incident closes `closed(event_delivered)` and stops counting as live; the alert stays `active`; a re-emitted key does not re-notify (tombstone) |
| `event_bounded_quiet_never_admits` | A kill raises; no further departures for many times Q; DA merged | The pending item stays pending; the alert stays open (CC7, I56) |
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
| `cc_l_incumbent_other_universe_no_recover` | `session.count_drop` raised with tmux and screen in the universe; screen is uninstalled; the tmux-only count matches the old mean | Frozen: a different universe never recovers (CC3(a), v3 MEDIUM 5) |
| `level_open_alert_new_drop_notifies` | The v3 HIGH 2 scenario, corrected per Opus LOW 1: two of six WireGuard peers are retired for good (one retired peer scores z = −2 and never raises); `peer.count_drop` raises at 4 and notifies; weeks later the remaining peers are cut | `lvl:<regime>:0` is a new incident, which notifies, although the rule is capped at `warning` |
| `level_gradual_deterioration_notifies` | Astra 1: an established peer count drops 8 → 5 and notifies; the next ticks read 4, 3, 2, 1, 0 | Each is a new running extreme and a new incident, which notifies; each superseded incident closes `closed(superseded)`. v4's held level scored these near z = −2 and stayed silent. |
| `level_oscillation_bounded_notifications` | Opus M1: 6 → 2 raises; the count then oscillates between 2 and 4 for days; later it drops to 0 | No incident during the oscillation; one new incident at 0 |
| `level_partial_return_holds` | 5 → 2 raises; then 3, still surprising under the frozen snapshot | No new incident; the extreme stays 2; the tick joins the episode's item |
| `level_journal_truncated_new_drop_notifies` | Opus H2(a): a confirmed `lvl:<regime>:4` peer incident; `learned/pending/peer/` is truncated; the remaining peers are cut | The extreme, re-derived from the alert's incident keys, is 4; 0 is a new incident and notifies |
| `level_regime_freeze_new_regime_drop_notifies` | A peer episode is frozen across a regime change; the new regime establishes, then drops | The new regime's incident carries its own regime in the key and notifies |
| `level_earned_promotion_closes_and_rearms` | A learned LEVEL episode; a successor version whose membership includes the episode's ticks earns promotion | The episode closes `closed(admitted_earned)` and re-arms; the next drop opens a new episode and notifies |
| `incumbent_sustained_shift_frozen_until_replacement` | A benign, permanent incumbent drop; no successor yet | The episode stays open, silent after its first notification; no tick folds; a further extreme notifies; replacement closes it `closed(replaced)` |
| `id_cell_change_no_new_identity`, `id_cell_change_no_new_incident` | A persistent level anomaly crosses a `since_*` edge and presence active → locked | Same alert id, same incident key, no new notification (H1(b)) |
| `id_raise_ref_not_episode_state` | `raise_ref` changes on a refit while the alert is active | No new episode or incident (v2 M1) |
| `id_level_incident_key_not_default` | Any LEVEL raise | The key is `lvl:<regime>:<extreme>` |
| `id_topk_reorder_same_structure_id` | The top-K network ranking reorders | Same `structure_id`, same alert ids (v3 MEDIUM 6) |

### 6.3 Arbitrated adaptation: explanation sources and admission (D1; D5; DA3; audit §1g; Astra 5 (v1 and v4); Opus M10; v3 re-review MEDIUM 2, MEDIUM 3). Early and security-critical

**Rule (S).** An observation that raised an alert enters `pending` in the pending journal (§6.4). It is retained, never deleted. It becomes learned-normal only through an `admitted` record, written by an explanation source with authority over that item. A hand-written "X explains Y" mapping is never an explanation (P1). **The incumbent statistical folds never fold an alarmed tick, admitted or not** (C1a narrowed, §6.5). For them, admission matters only to their learned successors.

**Explanation sources (a closed set, I48), and where each applies (I56):**

| Source | EVENT data | LEVEL data | NOVELTY data | Authority required |
|---|---|---|---|---|
| `earned_promotion` | ✔ | ✔ | ✔ | Applies to the recorded training membership of a version that has earned promotion: it passed the pre-registered evaluation within its drift budget, and vetoed items are excluded (§6.3.1, §6.3.2). Notified; reversible (I71, I72). |
| `bounded_quiet` | ✘ (undefined) | ✘ (removed in v5) | ✔ an entity (§6.6) | DA merged; the family's novelty budget; no open discontinuity epoch in the family (§6.4.4); notified in the digest |
| `context_model` | ✘ | ✘ | ✔ mapped incumbent items only | DA merged; a lineage that has earned notify-only promotion (C7a); a reviewed stream-map entry; a daybreak re-gate of the map (I57) |
| `label` (optional) | ✔ | ✔ for learned lineages; an open incumbent LEVEL episode stays frozen | ✔ | The label budget; notified on ingest (I27, I62) |
| `federated_signature` | reserved | reserved | reserved | §6.3.3 |

1. **`earned_promotion`** (D5; Astra v4 5). A learned lineage's own way to adapt, with provenance (§6.3.1).
2. **`bounded_quiet`** (NOVELTY only). This is Q of certified, complete family history since the incident opened, with: no further incident under the entity's alert id; the entity's producer identity unchanged, where the producer has one; and no discontinuity epoch in the family (§6.6). The mechanism is S and the period Q is O (I19; default §16.1).
   - It is undefined for EVENT data (I56).
   - v4 also applied it to held LEVEL shifts. v5 removes that with the held level: the incumbents freeze until they are replaced, and learned LEVEL streams adapt by earned promotion.
   - Each admission is logged as `admitted_unexplained`, charged to the family's novelty budget and listed in the digest: notification, not confirmation (`autonomy-doctrine.md:46-50`). Over budget, the entity stays pending and its alert stays active and silent.
3. **`context_model`** (v3 re-review MEDIUM 3). A learner explains a mapped incumbent NOVELTY item only when its predictive, given the context, finds the observation unsurprising.
   - **Example** (Opus LOW 6). A learned service-appearance stream conditioned on `software_change` maps to `service.appeared`: same kind, same target, same universe. A `software_change` model on its own maps to nothing.
   - **An explicit stream map** (S, reviewed with the learner). A learned stream L may explain items of rule R only if they share the same kind, the same target quantity and the same census universe.
   - **Never its own lineage.** A lineage adapts its own state by earned promotion, with membership provenance (§6.3.1). It never explains itself.
   - **Charged to the target family's novelty budget.** It abstains for unmapped items.
   - **An F fact is never an explanation** (D4; F-class opinions, Opus A6; Astra §5). F1 can remove boundary-crossing departures from a likelihood, but it cannot certify a pending observation as normal.
   - **Why only NOVELTY.** The incumbents never fold an alarmed tick, so explaining an incumbent LEVEL or EVENT item would change nothing but its alert status. Reducing what an incumbent alerts on is replacement's job (§11.2).
4. **`label`** (optional; §9).
   - `expected`, `mine` or `benign` make an item admissible to learned lineages without the vetoes of §6.3.2; it is still drift-charged at promotion. A labelled NOVELTY entity is admitted, and its alert closes.
   - `suspicious` and `confirmed_incident` quarantine (§6.4.5).
   - Every label is charged to the label budget and notified on ingest. A label never cancels an undelivered incident (Opus M5).
5. **`federated_signature`** (reserved; §6.3.3).

**Every admission is reversible.** It is logged, with its source, `evidence_ref` and budget charge, in the pending journal and in the transition log. The operator can revoke it, which returns the item to pending and rebuilds the affected statistics from the retained item (I52). Every earned promotion is reversible too: a demotion restores the previous earned snapshot and returns to pending the items that promotion admitted (I71).

**Shadow learners still see everything.** They fit on all trusted data, pending and excluded data included, with soft contamination weights from a mixture component (Opus M10). They carry no authority, so the incumbent does not decide what a successor may learn. That resolves the deadlock in Astra v1 5, where every legitimate reboot fires the old detector and quarantines exactly the aftermath data the successor needs. **Quarantined data is the exception**: it never enters a normal-behaviour component of any model, and the learners and the evaluation see it only as labelled incident evidence (§6.4.5, §10).

#### 6.3.1 Earned promotion is the admission event (D5; Astra v4 5)

**The problem** (Astra v4 HIGH 5). C5's departure learner keeps flagging a legitimate new workflow. Its successors may train on those pending events. But no version may explain its own lineage, bounded quiet is undefined for events, and nothing independent explains departures. v4 therefore left two bad options:
- promote the challenger's fitted parameters, which carries pending data into authority-bearing state with no admission; or
- rebuild it from admitted data only, which discards the adaptation that was evaluated.

The remaining option was labels, which made labels the only learning path.

**The contract:**
1. **Shadow may train on everything.** A shadow fit has no authority, so its inputs need no admission.
2. **A promotion candidate has an explicit membership.**
   - Its normal component is fitted on admitted items plus the pending items that pass the vetoes of §6.3.2.
   - Vetoed pending items enter only its contamination component, which carries no authority.
   - Quarantined items enter only as labelled incident evidence.
   - The membership (item ids, with weights) is recorded with the version. That is the training-membership provenance, bounded by the pending caps (I3).
3. **A version earns serving authority only by evidence.** It must pass the pre-registered shadow evaluation (§10) on this host's own coherent replay, adaptive-attack scenarios included. Its sensitivity-reducing displacement from the last earned snapshot must also fit the drift budget (I20, I72). The same bar applies to every change of authority:
   - shadow → notify-only (C7a);
   - a new serving version of a promoted lineage;
   - per-host replacement of an incumbent (C7b).
4. **The earned promotion is the admission event** for that version's membership.
   - Each pending item in it is written as `admitted(earned_promotion, version, evidence_ref)`.
   - Incidents whose items are all admitted close as `closed(admitted_earned)`; a LEVEL episode closes and re-arms.
   - What was evaluated is exactly what is admitted, so there is no laundering path and no rebuild that throws the adaptation away.
5. **Notified and reversible.**
   - Each promotion sends one notification: what changed, the drift charged, the cumulative displacement since the lineage's first earned snapshot, the items admitted, and the alerts closed.
   - Demotion restores the previous earned snapshot and returns the admitted items to pending; a condition that still holds then raises a new episode, which notifies. Three things demote: an operator veto at any time, auto-demotion on regression (§11.5), and a budget breach.
6. **The daemon writes it.** The detection stage, the journal's single writer (§6.4.2), writes the admission entries and routing changes. Shadow learners still write nothing outside their own log and store (§7.7).

No step asks anyone to approve anything. The operator is on the loop: notified of every promotion and able to veto or roll it back, but never asked first.

**Fixtures:** `earned_promotion_admits_training_membership`, `earned_promotion_vetoed_items_not_admitted`, `earned_promotion_notified`, `earned_promotion_demotion_returns_items_to_pending`, `promotion_without_evaluation_refused`, `promotion_over_drift_budget_refused`.

#### 6.3.2 How poisoning is bounded (D5)

An attacker wants their activity read as benign drift (`autonomy-doctrine.md:101-108`). Earned adaptation bounds that in five ways. None of them is a time window or a hand rule.
1. **The drift budget** (I20, I72).
   - Each promotion's sensitivity-reducing displacement from the last earned snapshot is bounded. So is the sum of the displacements earned over the trailing horizon H. A chain of individually plausible versions therefore cannot walk the baseline faster than budget / H.
   - **A loss never resets the budget.** A lineage whose anchor or drift ledger is lost (§8.3) is demoted to shadow and re-earns from scratch, and the host returns to its incumbent meanwhile (Opus H2(b)).
2. **Corroboration across independent streams.** A pending item is vetoed if its interval overlaps the raising interval of an unadmitted incident from a **distinct evidence source** (I29). A vetoed item stays out of every candidate's normal component. To be learned, an attacker's change must look normal on every independent stream at once. The test is on raising intervals, not on how long an alert stays open, so a long-open EVENT alert does not veto everything after it. **Sources are counted by the physical evidence they rest on** (the census or collector, as in I29 and §7.3), not by rule or stream. An incumbent and a learned stream over the same census are one source, so an incumbent's open incident never vetoes the learner that models its own target (otherwise Astra v1 5's deadlock would return).
3. **Never adapt to unattested change in context that is itself anomalous.** A response observation is vetoed while its context transition is surprising and unadmitted in its own context stream, or while its context is `unknown`, `unstable` or `new`. The veto lifts once that context has itself been admitted, by its own stream's earned promotion. For example, "`tailscale down` at 03:00, then the peers vanish" cannot be learned as a peer response while the 03:00 `tailscale down` is unexplained.
4. **Pre-registered adaptive scenarios.** A candidate that no longer detects a pre-registered adaptive scenario on this host's replay fails evaluation, however well it fits. The scenarios include a sub-threshold drift chain, toggle-then-act and a label burst (§10.2).
5. **Quarantine and labels.** Quarantined data never enters a normal component. Labels are budgeted and notified (§9).

**Evidence limit (stated).** On one host, the evaluation, the vetoes and the drift ledger are all computed and stored at the daemon's UID, so a same-UID attacker can forge their inputs.
- Earned on-host authority therefore stops at notify-only alerting, bounded admission and reversible per-host replacement, every step notified. Nothing earned on-host acts on the host (`autonomy-doctrine.md:61-68`).
- A patient poisoner can still walk a lineage at the budget rate. That walk is notified at every step, visible as cumulative displacement since the first earned snapshot, and reversible to any retained earned snapshot.
- Preventing it outright needs off-host attestation, which is outside this plan (§0.3, §16.2).

**Fixtures:** `poison_cross_stream_veto`, `poison_anomalous_context_veto`, `poison_drift_chain_rate_limited`, `poison_anchor_loss_reverts_to_incumbent`, `quarantined_never_in_normal_component`, `label_burst_held_pending`, `explanation_f1_never_admits`, `context_model_requires_earned_promotion`, `context_model_unmapped_abstains`, `context_model_never_explains_own_lineage`, `event_bounded_quiet_never_admits`, `level_bounded_quiet_never_admits`, `arb_alarmed_tick_not_folded`, `arb_pending_retained_for_shadow`, `arb_admission_revocable`.

#### 6.3.3 Declared extension point: federated explanation sources (interfaces only)

The operator expects later federated layers to match known patterns or signatures, as a further explanation source (D1). This plan declares the interface and makes **no design commitment**.

- `ExplanationSource { id, kind, explains(pendingItem) → { verdict: explained | not_explained | abstain, evidence_ref, scope, authority_class } }`, with `kind` from the closed set above.
- `federated_signature` is reserved and inactive (`federated_source_reserved_inactive`).
- Whatever is designed later must at least: arrive through an attested, signed, off-host channel (`autonomy-doctrine.md:61-68,126-129`); carry provenance; be opt-in; state which stream kinds it applies to (I56); have bounded influence, charged to the same drift budgets; be logged and notified like every other admission; and be revocable.

### 6.4 The pending journal (v2 re-review H4; v3 re-review HIGH 1, HIGH 3; v4 Astra 2–4, Opus H2(c), LOW 2, LOW 4; I44, I52–I54, I69, I70)

#### 6.4.1 Why the v2 and v3 designs could not hold

- **v2** kept pending ticks in `alerts.json`:
  - `normalizeAlertRecord` rebuilds each record from a fixed field list (`alert-store.js:249-272`);
  - a malformed record is quarantined, which means dropped (`:287-301`);
  - `alerts.json` has no integrity ledger;
  - a corrupt session state store resets to fresh (`session-baseline.js:244-264`);
  - a seen-set re-seed rebuilds entries from certified candidates (`novelty-seen-set.js:26-35`).
- **v3** moved pending state to a store "lineage-stamped exactly as seen-sets are". That stamp cannot fit the writer:
  - A seen-set is folded **by the family's retention pass, inside the pass** (`fact-store.js:455-476`), and a read is valid only if its stamp equals the ledger's last committed pass (`novelty-seen-set.js:371`).
  - Verdicts do not exist during the pass. The daemon persists the tick's facts, which runs each family's pass (`daemon.js:1122`), and only later evaluates the detectors (`:1743`).
  - A store written by the detectors would therefore read as a lineage mismatch on every structural tick, and its fail-closed state would never end (re-review HIGH 1(a)).
- **v3 also derived membership from alert transitions**, so the end of an alert released its data (HIGH 3).

#### 6.4.2 Records, the single writer and the scored-through watermark

- **Writer.** The daemon's detection stage, and nothing else.
  - Multiple daemons are unsupported (notify-once branch todo `2026-10-09-alert-store-concurrent-writers.md`).
  - The CLI never writes the journal. Labels go through the label log (§9, I62).
- **The journal.** `learned/pending/<family>/journal.jsonl`, append-only and hash-chained.
  - Each entry has `seq`, `prev_hash`, `family`, `ledger_generation`, `scored_pass_id`, the scored pass's time and the certified span at write time (§6.4.3), and the item id `(alert id, episode, incident key)`.
  - Its kind is one of `opened`, `added`, `admitted`, `quarantined`, `excluded`, `revoked`, `scored_through`, `discontinuity`, `recertified` or `compacted`.
  - Its payload holds the tick reference, the sufficient-statistic contribution, the authoritative `raise_ref`, the incumbent's frozen serving snapshot (once per episode, §6.5.1), and the source, `evidence_ref` and budget charge of any admission.
  - Learned lineages' earned snapshots and drift ledgers are chained the same way, in the learned store's own ledger (§8.3).
- **Membership derives from the journal alone** (v3 HIGH 3; I52). An observation is pending if it has an `opened` or `added` entry and no later terminal entry. The transition log (§9) is cross-referenced by item id, as an audit trail. It is not a membership source. A disagreement between the two is reported, and never used to release anything.
- **Write order, per scored pass.**
  1. The journal entries for every verdict, flushed.
  2. Then `alerts.json` and the transition log.
  3. Then a `scored_through(pass_id)` entry: the durable watermark.

  Entries are idempotent by `(item id, tick ref)`. After a crash, detection resumes from the watermark (below). It completes step 2 from the journal payload, never by re-running a detector, because evaluation mutates detector stores (`daemon.js:1575-1578`; Opus LOW 2).
- **A failed journal append** (ENOSPC has been seen on the dev host) never suppresses a raise. The alert is still written, and the family enters a discontinuity epoch, because the open incident has no journal entry (§6.4.4).
- **The fact-commit-to-verdict gap** (Astra 2; I69). Journal-first ordering covers a crash after a verdict exists. It does not cover a crash between the fact commit (`daemon.js:1124`) and detection (`:1743`). That leaves a committed pass with no verdict, and the next tick's census can hide it: the incumbent recompute would fold the earlier kill while scoring only the latest tick. The watermark closes the gap:
  - detection consumes every committed pass after `scored_through`, **in order**, and scores each as it would have been scored at its time. An incumbent scores that pass's tick against the clean window strictly before it. A learner scores from the parameters it was serving then.
  - verdicts are journaled before the watermark advances;
  - a pass that cannot be scored, because its facts were evicted or the detector cannot reconstruct its state, is journaled as `excluded(unadjudicated)`: never folded, never silently treated as normal, and listed in the digest.

  A late raise is still a raise: a kill seen only in a replayed pass alerts, and then recovers under CC3 if the next pass shows the sessions back (`watermark_crash_after_commit_replays_kill`).

#### 6.4.3 The stamp rule: certified when written (I53, I70; Astra 4; Opus LOW 4)

- **Entries cite the pass they scored; they do not have to equal it.** An entry is valid if, **when it was written**:
  - its `ledger_generation` equalled the family ledger's generation;
  - its `scored_pass_id` was ≤ the ledger's `last_committed_pass_id`; and
  - that pass lay inside the family's certified span.

  The entry records its pass time and the span at write time. From then on it is valid while the journal's chain is unbroken.
- **Intentional eviction is not loss.** A source pass that later leaves the certified span by age or byte eviction does not invalidate the entries that cited it. The ledger keeps only `last_committed_pass_id` (`fact-store-integrity.js:54`), and at worst-case session volume the raw history covers about 2.6 days (§1.6). Re-checking the source span later would make every long episode fail. Rebuilding a 30-day episode therefore never re-checks it.
- **Cadence.** The detection stage runs after its tick's pass commits. On a structural tick it cites the pass it just read. On a fast tick it cites the latest committed pass, and normally writes nothing.
- **A checkpoint, carried by the retention pass.** Each family's retention pass runs on every structural tick, before detection. It:
  - folds the journal entries written since the previous checkpoint into `learned/pending/<family>/checkpoint.json`, including the watermark and the incumbents' frozen serving snapshots;
  - drops the tick marks of ticks it has just evicted;
  - stamps the checkpoint with `(generation, pass id, journal seq, journal head hash)`.

  The pass carries pending state forward. It never decides it.
- **A checkpoint is an optimisation, not an authority.** A stale checkpoint (from an older pass), a missing one, or one whose write failed is rebuilt from the previous checkpoint and the journal suffix, with no loss. Only a checkpoint that **contradicts** the journal (a head-hash mismatch at its seq) is a discontinuity.
- **Compaction.** A pass may truncate the journal prefix that a checkpoint covers, leaving a header with the hash at the cut. After a cut, losing the checkpoint loses state, so it is a discontinuity.
- **Ordinary operation never trips the rule.** All of these are valid states: a pass on every structural tick; detection after the pass; fast ticks; a daemon restart; a crash between the writes; a failed checkpoint write; the source facts of an old entry evicted (`pending_restamped_each_pass`, `pending_stale_checkpoint_rebuilt`, `pending_fast_tick_no_discontinuity`, `pending_entry_valid_after_source_age_eviction`).

#### 6.4.4 Discontinuity and its exit (I54)

**A detected discontinuity** is any of:
- a missing, unreadable or chain-broken journal;
- a checkpoint that contradicts the journal, or one that is missing after a cut;
- a change of the family ledger's generation (a store migration or quarantine; a generation changes only on bootstrap, `fact-store-integrity.js:95-97,449`). Entries certified before the change stay valid (§6.4.3); the epoch covers the observations scored since;
- an **open** incident of a C1a producer with no journal entry (Opus LOW 4), including one left by a failed append.

Deleting or corrupting an `alerts.json` record is **not** a discontinuity, and changes nothing about pending state (`pending_alert_record_deleted_no_fold`).

**Landing migration, so the rule does not trip on day one.** When C1a lands, every alert of a C1a producer that is already open in `alerts.json` is an incident with no journal entry. Before the first detection run, C1a's migration therefore journals each such open incident as `opened`, citing the current pass (§6.5.4; `pending_c1a_migration_journals_open_incidents`).

**On detection**, epoch e opens for the family:
0. The daemon opens a new chain with a `discontinuity` entry that cites the old head hash (or `lost`), and journals on it from then on.
1. **Surviving terminal dispositions are kept, with their provenance** (Astra 3).
   - An item whose `quarantined`, `excluded` or `admitted` entry survives, in the journal's verified prefix or in the checkpoint, keeps that disposition.
   - Where surviving sources disagree, or only an unverifiable source records a disposition (the label log, `alerts.json`), the item takes the most restrictive disposition any source records: quarantined, then excluded, then pending. An unverifiable admission is never honoured.
   - Every other item recoverable from any surviving record is carried forward as pending. Nothing is admitted, and nothing quarantined is released.
2. **Only genuinely uncertain membership becomes pending.** Every tick from the last certified point to now whose membership cannot be recovered is held in one `unexplained_discontinuity` item. It stays pending, and it is admitted only by label or by an earned promotion whose membership names it. If no certified point survives, it covers the whole raw window.
3. **Detection continues.**
   - The detectors keep raising against their journal-carried serving snapshots (§6.5.1). A lost incumbent snapshot is rebuilt from the clean ticks before the open episode's `first_seen`. If that is impossible, the episode stays frozen and the running-extreme rule stays live (I60).
   - The running extreme is re-derived from the alert's incident keys (I55), so truncation cannot mute a frozen LEVEL alert (Opus H2(a)).
   - Recovery continues under CC3, because recovery never admits.
4. Unattended admission (`earned_promotion`, `bounded_quiet`, `context_model`) is suspended for the family. Labels still work, within the label budget.
5. An integrity notice, `integrity.pending_discontinuity`, is raised (fingerprint = the family; one incident per epoch).

**The exit: automatic re-certification.**
- It happens at the first family retention pass that commits cleanly after the break **and** carries a complete, trusted census for the family's detectors.
- The daemon then writes a `recertified` entry on the chain it opened at detection, carrying the epoch and the list of carried items, and writes a fresh checkpoint.
- Unattended admission resumes from the next tick.
- The `unexplained_discontinuity` item stays pending, and its ticks leave the raw window like any others.
- The integrity notice recovers, on the evidence that the chain verifies.
- An epoch therefore normally lasts one structural interval.

**The bound: a discontinuity budget** (mechanism S, size O, default §16.1; I54). Beyond a per-family number of epochs per 30 days, re-certification still restores continuity and scoring, but unattended admission stays suspended for that family until the trailing 30-day count is back within budget. The digest says so. No one re-ratifies anything (D5).

**What a same-UID attacker buys** by truncating `learned/pending/<family>/` (v3 HIGH 1(c)):
- once: one structural interval without unattended admission, and a notice;
- on every tick: a family that stops adapting, with its detection and alerts unaffected and a notice per epoch.

Never a laundered tick, never a released quarantine, and never a stopped or muted detector (`pending_truncation_never_stops_detection`, `pending_recertifies_after_clean_pass`, `pending_discontinuity_keeps_unexplained`, `pending_discontinuity_keeps_quarantine`, `pending_discontinuity_unverified_admission_not_honoured`, `pending_discontinuity_budget_exhausted_suspends_unattended`, `pending_failed_append_raises_and_opens_epoch`).

#### 6.4.5 Content, bounds and quarantine

- **Per item:**
  - the authoritative `raise_ref`;
  - for an incumbent LEVEL episode, its frozen serving snapshot reference (§6.5.1);
  - tick marks for its ticks still in the raw window;
  - its sufficient-statistic contributions, so it outlives the raw window;
  - at most E exemplars.
- **Caps (S, I3; defaults §16.1).** Open items per family, exemplars per item and checkpoint size are capped; tick marks are bounded by the raw window.
  - **At the item cap, the oldest unadmitted items compact into the family's `excluded` summary**: aggregate sufficient statistics, with each item's digest kept in a `compacted` journal entry.
  - Excluded data is never folded into authority-bearing state. Shadow learners see it with contamination weights. The digest lists the compaction.
  - Compaction never folds and never freezes. So pending items accumulating at one episode per reboot, or one per night, cannot trip a fail-closed state (v3 HIGH 3(c); `pending_cap_compacts_to_excluded`).
  - A label on a compacted item is recorded for evaluation, and admits nothing.
- **Quarantine is permanent.**
  - `suspicious` and `confirmed_incident` items keep their exemplars and evidence references.
  - They are never folded into any normal-behaviour fit: not the incumbent window, not long-lived statistics, not a learner's normal component. Evaluation and learners use them only as labelled incident evidence (§10).
  - A discontinuity never releases them (§6.4.4).
  - At the quarantine cap, the oldest items merge into a quarantine aggregate that keeps their sufficient statistics, their digests and the never-fold mark (`quarantine_compaction_never_folds`).
  - A later relabel by the operator is a label like any other. It returns the item to pending, within the label budget, and it is notified and logged.
- **Seen-sets.**
  - A pending novel entity may still be folded into the seen-set, because that memory "can only suppress a novelty claim" (`novelty-seen-set.js:16-18`), which is what stops it re-alerting. Its pending status lives in the journal, so a seen-set re-seed cannot drop it (`pending_seen_set_reseed_keeps_pending`).
  - **A quarantined entity is the exception** (Opus M2; I74). Today novelty is the latest census minus the union of window history and seen-before entries (`service-baseline.js:836-863`), and seen-set entries live 30 days past `last_seen` (`novelty-seen-set.js:6-8`). A re-installed malicious LaunchAgent would therefore never alert again. So a quarantined entity leaves both suppression sets and becomes a **reappearance watch**:
    - while it stays present, its alert stays active;
    - once a complete census shows it absent, the alert recovers;
    - a later appearance is novel again, and notifies (`novelty_quarantined_entity_reappears_alerts`).

The journal is tamper-evident at the same UID, not tamper-proof. This design makes laundering detectable and fail-closed, with a bounded exit. Preventing it outright needs off-host attestation, which is outside this plan.

### 6.5 Applied to the incumbents (step C1a, narrowed in v5; D5; v2 re-review H2, H3; v3 re-review HIGH 2, MEDIUM 5; v4 Opus H1, H2, M1, M3, LOW 3; Astra 1; I45, I55, I59, I60)

**Scope (D5).** C1a gives the window-based incumbents exactly two things:
- (a) **an alarmed tick is never folded** into their baseline;
- (b) **novelty is pending until explained** (D1; §6.6).

It adds only the minimum that keeps (a) from muting a detector or fabricating a recovery: a journal-carried serving snapshot, the running-extreme rule, and recovery only in the raising regime.

**No new-normal exit, no anchor and no drift budget is retrofitted onto the incumbents.** A sustained shift freezes an incumbent's episode until a learned successor earns replacement for that family on that host (§11.2), and that replacement is the exit.
- **Removed from v4:** the held level, re-base, the bounded-quiet LEVEL exit, serving generations, incumbent anchors (I58), the incumbent drift measure and excursion (I61), and regime admission and regime memory.
- **Why.** The v4 reviews found their defects in exactly this machinery: Opus H1 (an admitted held level re-raises on the next tick, and a recurring dip is never admitted), Astra 1 (the held level absorbs further deterioration) and Opus M1 (re-base is undefined).
- **What that leaves of Opus H2.** Its muting and budget-reset paths lose their object. Its snapshot-loss path is closed below.

#### 6.5.1 Exclusion and serving state (I45, I60)

- **One more exclusion predicate.** The incumbents already recompute from the raw window on every call, and already exclude ticks by predicate:
  - sessions exclude overflow and incomplete ticks (`tickGroupDisposition`, `session-baseline.js:367-373`; fold `:385-416`);
  - peers exclude overflow, invalid-marker and other-regime ticks (`peer-baseline.js:523-588`; drop direction `:612-647`).

  C1a adds one predicate: a tick that has a journal entry is not folded, whatever its disposition (pending, admitted, quarantined or excluded). **Under C1a an incumbent folds only ticks that never alarmed.** Admission matters to the learned successors, not to the incumbent.
- **The fold no longer absorbs an alarm.** Today the latest tick is scored, then folded on the next call even when it alarmed (`session-baseline.js:394-408`; peers `:572-580`). Under C1a the alarmed tick is journaled before that call, so it is excluded.
- **Every tick of an open episode joins its pending item**, alarmed or not, until the episode ends. Re-warm-up ticks and partial returns therefore never fold while an episode is open.
- **The frozen serving snapshot.**
  - When an episode opens, the detector records the snapshot it served at the last tick before the first alarmed tick. It is computed from the clean ticks before `first_seen`, never from a window that has already folded the alarm (Opus LOW 3).
  - The snapshot is carried in the pending journal and its checkpoint (§6.4.2), so losing it is a detected discontinuity, not a silent reset (Opus H2(c)).
  - The open episode is scored against this snapshot, not against the sliding window.
  - If exclusions leave fewer than N folded ticks, the established detector keeps serving the snapshot. Neither exclusion nor aging out ever makes an established detector provisional (v2 re-review H2; `arb_post_recovery_thin_window_uses_snapshot`).
- **Snapshot loss.** If the snapshot is lost and cannot be rebuilt from the clean ticks before `first_seen` (a 30-day episode can outlive them), the episode stays frozen: no recovery and no fold. The running-extreme rule needs no snapshot, so it stays live (§6.5.2). An integrity notice is raised (`serving_snapshot_deleted_no_absorb`, `incumbent_snapshot_lost_episode_stays_frozen`).
- **No anchor, no drift budget.** The incumbents keep today's exposure to sub-threshold drift through non-alarmed folds (§16.2). Their successors carry the anchored budget (§6.3.2).

#### 6.5.2 LEVEL episodes: frozen, never muted (I55)

**Each tick of an open episode is scored in this order:**
1. **Recovery** (CC3): in the raising regime, unsurprising under the frozen snapshot, with the evidence changed → `recovered`. The ticks stay pending (§6.0).
2. **A new running extreme**, beyond the episode's most extreme value so far in the rule's raising direction → a **new incident**, keyed `lvl:<regime>:<extreme>`.
   - Notify-once delivers it, because its key is new, even though the peer rules are capped at `warning`.
   - The incident it supersedes closes as `closed(superseded)` once the new one is recorded, so superseded incidents never pile up toward the storm cap (Opus M1).
3. Otherwise, a **frozen tick**: no incident. The tick joins the episode's item.

**Why this rule, and only this one.**
- v3 HIGH 2 showed that an open LEVEL alert keyed `default` mutes its host-global detector under notify-once.
- v4 closed that with an adaptive held level, and both reviews broke it:
  - Astra's peer count dropped 8 → 5 and then read 4, 3, 2, 1, 0. Against the accumulating held level each tick scored about z = −2, so nothing notified (Astra 1).
  - On an oscillating count, a re-base either notified every cycle or widened σ until a drop to 0 was silent (Opus M1).
- The running extreme does not have those failure modes:
  - It is **monotone and frozen**: it cannot absorb deterioration, a partial return never moves it, and it adds no number.
  - Every value beyond it is at least as surprising as the extreme that raised, under the same frozen snapshot, so **it needs no snapshot to apply**.
  - It is **re-derivable from the alert's own incident keys** (§6.1), so truncating the journal cannot reset it (Opus H2(a)).
- **Notifications are bounded.** Per drop episode, they are bounded by the count range. For a spike, they are bounded by the live cap (I63).

**Exits.** Recovery, always; or replacement by a successor that earned it (§11.2). **A label never ends an incumbent LEVEL episode.**
- An `expected` label is recorded for the successor, and makes the episode's ticks admissible to it.
- A quarantining label quarantines the episode's ticks, while the alert stays `active` because the condition is real.

**Stated consequence: the recurring dip** (Opus H1(b)).
- **The case.** Sessions drop 5 → 2 for ten hours every night. Each night is an episode: it raises, recovers in the morning, and its ticks stay pending.
- **Today** the alarmed ticks fold, and the alert habituates in about a week.
- **Under C1a** it notifies every night until the hour-of-week occupancy successor (C5) earns replacement. That habituation is the laundering path C1a exists to close, so the cost is accepted.
- **How it is bounded.** It is measured before C1a ships (the replay gate, §14), and the successor moves into C5. Labels are not the remedy.

**The v3 re-review's scenario, step by step** (`level_open_alert_new_drop_notifies`, corrected per Opus LOW 1):
1. The operator retires two of six WireGuard peers for good. (Retiring one scores z = −1/0.5 = −2 against the floor, `peer-baseline.js:68,74`, and never raises.)
2. `peer.count_drop` raises at z = −4 and notifies, keyed `lvl:<regime>:4`.
3. Weeks later, an attacker cuts the remaining four peers.
4. 0 is beyond the running extreme 4, so it is a new incident, `lvl:<regime>:0`, and it notifies, even though the rule is capped at `warning`.

#### 6.5.3 Regime and universe changes (narrowed; I49, I59; v3 MEDIUM 5; Opus M3)

- **Recovery only in the raising regime.** CC3(a) applies to the incumbents. The detector reports an open episode's alert id as evaluated only in the regime recorded in its `raise_ref` (`cc_l_incumbent_other_universe_no_recover`).
- **An open episode freezes across a change.** There is no scoring against the old regime's snapshot, no recovery and no incident from it, because the counts are not comparable. The episode resumes if the raising regime returns (`level_regime_change_freezes_open_episode`).
- **A new regime re-warms honestly, as today** (`peer-baseline.js:515-516`; sessions on the collector branch, 25aeb89). Once established, it may raise. Its incidents carry its own regime in the key, so they notify even while an old-regime episode on the same id is frozen (`level_regime_freeze_new_regime_drop_notifies`). v4's "raise-only until admitted" state and its regime memory are removed (D5).
- **Visible from day one.** Every availability change raises the S-class integrity notice `census.universe_changed`: an EVENT alert, one incident per transition, carrying the `collector.binary_state` transition.
  - It is a fixed, additive rule that needs no pending journal, so it is a **merge gate of C0.1b** on the collector branch (Opus M3). Moving a binary aside is then visible from the day that branch merges, not from C1a.
  - Until C8 scores binary availability as a context stream, the notice is the only signal (`census_universe_changed_notice`).
  - The rules above land at C1a.

#### 6.5.4 Landing migration (Opus LOW 3)

- Before the first detection run, C1a journals every already-open incident of a C1a producer as `opened`, citing the current pass (§6.4.4).
- An open `default` incident is **rekeyed in place** to `lvl:<regime>:<extreme so far>`, keeping its delivery state. The migration therefore sends no duplicate notification and leaves no live `default` key.
- Its frozen snapshot is taken from the clean ticks before its `first_seen`, not from the current window, which has already folded the alarmed ticks (`session-baseline.js:394-408`).

**Fixtures:**
- `arb_sustained_shift_not_absorbed_by_ageout` (the v2 re-review H2 scenario: kill 2 of 5 sessions and keep them dead for 30 days. The detector serves its snapshot, never recovers and never folds, and a further kill beyond the extreme still notifies.)
- `recovered_episode_ticks_not_folded` (v3 HIGH 3(a): kill 2 of 5 for 10 hours, then restart them. The 10 ticks stay pending, and the next recompute excludes them.)
- `confirmed_incident_ticks_quarantined` (v3 HIGH 3(b))
- `arb_rewarmup_ticks_pending`, `arb_incumbent_recovery_needs_snapshot`, `arb_post_recovery_thin_window_uses_snapshot`, `incumbent_label_never_folds`
- `serving_snapshot_deleted_no_absorb`, `incumbent_snapshot_lost_episode_stays_frozen`
- the `level_*` fixtures of §6.2, and `level_recurring_dip_notification_count` (it reports the count per night, and is the unit test behind the C1a replay gate)
- `c1a_migration_rekeys_in_place_no_duplicate`, `c1a_migration_snapshot_before_first_seen`, `pending_c1a_migration_journals_open_incidents`
- `census_universe_changed_notice`

### 6.6 Novelty lifecycle (D1; supersedes the 2026-09-27 design)

- A novel entity raises its alert as today, and opens a pending item.
- **The alert stays active while the entity is pending.** The detector stops reporting a pending entity's alert id as evaluated, so the alert freezes as `active` instead of recovering on the next tick. This changes `computeCensusEvaluatedAlertKeys`, which today reports the whole historical union (`service-baseline.js:447-464`; used for `service.appeared` at `:1043-1052`), and its scheduled-job and lineage counterparts.
- **The alert closes when an explanation source admits the entity** (§6.3):
  - **bounded quiet**, within the family's novelty budget, once DA has merged. That is Q of certified, complete family history since the incident opened, with no further incident under that alert id, the entity's producer identity unchanged where the producer has one, and no discontinuity epoch;
  - a **mapped `context_model`**: for example, a learned service-appearance stream conditioned on `software_change`, mapped to `service.appeared` (Opus LOW 6). That is the doctrine's own example of a package-manager event explaining a new binary (`autonomy-doctrine.md:105`);
  - the **earned promotion** of a learned successor whose membership includes the entity;
  - an optional **label**.

  Nothing waits on a label. An unexplained entity's alert stays active and silent (it notified once) until one of these admits it. Every admission, by any source, counts toward the family's novelty drift budget (Opus M5; I20).
- **A `suspicious` or `confirmed_incident` label** quarantines the item and turns the entity into a reappearance watch (I74; §6.4.5): its alert stays active while the entity is present, recovers once a complete census shows it absent, and a later re-install alerts again.
- The transition log records the source. `closed` re-arms (§6.0), and the seen-set keeps an admitted entity from re-alerting.
- Under notify-once, the alert notified once at activation and is silent while open. The incident key stays the producer's stable identity, as the branch already declares for novelty.
- v2 re-review L4 (the novelty half of C1a did nothing until Q4) is resolved by D1.
- **Fixtures:** `novelty_stays_active_until_explained`, `novelty_closed_by_label`, `novelty_closed_by_bounded_quiet_consumes_budget`, `novelty_bounded_quiet_needs_da_merged`, `novelty_budget_exhausted_stays_pending`, `novelty_reseed_keeps_pending`, `novelty_confirmed_incident_quarantined`, `novelty_quarantined_entity_reappears_alerts`, `novelty_every_admission_drift_counted`.

## 7. L3: learners

### 7.1 Model transitions, not levels (Opus H1, Astra 8)

Sources: sessions, SSH logins, WireGuard peers with an active handshake, tailnet node keys. VPN services are context, not a source. Every stream below is declared EVENT, LEVEL or NOVELTY (§6.0).

- **Departures** (EVENT) D_t = |S_{t−1} \ S_t|, taken from entity-key set differences between consecutive complete censuses of the same universe **within the same boot**. That restriction is F1 (process instances are boot-scoped), cited and tested, not an unreviewed hand rule (F-class opinions, Opus: "v2 already applies the fact silently"). While F1 is inactive (before its F-card lands, or after its kill switch), the learner uses the option-D fallback of §7.8.4: boundary-crossing intervals form their own unshrunk regime with a weak prior, scored in shadow, and their time-to-override is published. When F1 is active but a particular boundary fails verification (I41), that interval is scored as an ordinary within-boot interval and an integrity notice is raised (F-class opinions, Opus A4).
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
- **Tailnet online count** (LEVEL) becomes a secondary stream, since it mostly measures the operator's own devices sleeping. Node-key novelty (NOVELTY) and inbound sessions (EVENT) are the primary tailnet streams (Opus L6).
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
- **When a new version is created.** A new structure version (`structure_id`) is created only when the representation changes: the dimension set (including a dimension's first appearance in the host vocabulary, §5), the model families, the bucket edges or K. Top-K membership is a parameter, not representation (v3 re-review MEDIUM 6; I7). Parameter refits, membership included, stay inside one version and are bounded by the drift budget (§11.3).
- **What the learner can and cannot do.**
  - It weighs declared candidates at declared resolutions; it does not discover dimensions outside them.
  - Raw resolution is retained (§8.1), so alternative representations can be fitted later through the doctrine's compositional path (`model-ir` kernels).

### 7.5 Selection and evaluation kept apart (Astra 9)

- **Nested chronological evaluation.**
  - The outer loop uses rolling origins with day-blocked folds, and keeps episodes intact: a reboot aftermath is never split across a fold boundary.
  - The inner loop fits the vocabulary/top-K, priors and hyperparameters on preceding data only.
- **Exclude-latest scoring.** Each tick is scored against a model fitted on strictly earlier data. This follows the discipline at `peer-baseline.js:545-554`. The `model-ir` z-score is deliberately inclusive (`model-ir.js:335-341`), so it must not be reused as-is.
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
  - Why: the hourly cadence cannot see reconnects or a tmux-resurrect ramp (`daemon.js:81`), and after a quick reboot the first structural census can be up to an hour late (`daemon.js:1043`).
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
  - Shadow learners run under `watch.json` (default-on). They are the plan's declared kernels, not agent-authored models; agent authoring and the existing AUTHOR-pipeline shadow constraints stay under `learned.json` exactly as today (`daemon.js:1135-1156`).
  - **No authority.** They emit no alert candidates and no `evaluatedAlertKeys`, write nothing to `alerts.json`, notifications, incumbent state, the pending journal or the label log, and log only to their own shadow log and learned store. An earned promotion (§6.3.1) is written by the daemon's detection stage, not by the shadow learner.
  - **Isolation.** They run after the census and after the incumbents, in their own deadline slice; a throw or timeout is caught, recorded as `fit_aborted` or `score_aborted`, and never fails the tick.
  - **Bounds (S).** Maximum candidate dimensions, interactions and cells; CPU-ms, wall time and memory per fit and per score; durable, versioned parameter snapshots. **Disk**: the shadow log and the learned store are registered families with budgets and a T8-style invariant, because both run on every install (I64; v3 re-review LOW 4). An abort keeps the last version. k consecutive aborts (O, I65) auto-disable the learner with a notice.
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
| **F1** | Process instances are boot-scoped: given a verified ordinary kernel restart, processes from the previous kernel instance cannot continue as those same instances. | Adopt; card + review pending | A constraint on observation meaning, never an explanation. Cuts both ways: pids and logind session ids are per-boot counters, so equality across a boot is not continuity. Instances only: whether *names* come back is behaviour (resurrect), and stays learned. |
| **F2** | Clock domains are boot-scoped: boot-relative counters share an epoch only within one boot. | Adopt; card + review pending | Already relied on by trusted-state §5.3 (`2026-09-06-trusted-state-step-1.md:145`) and the clamp guard. |
| **F3** | Suspend clock semantics, named per platform: on Linux `CLOCK_MONOTONIC` pauses across suspend and `CLOCK_BOOTTIME` does not; on macOS `CLOCK_UPTIME_RAW` (`mach_absolute_time`) pauses, while `CLOCK_MONOTONIC` and `mach_continuous_time` do not. | Adopt per platform; inactive where C0.9 has not verified it | The A5 lesson (`trusted-state:146`). v3's wording ("the monotonic clock pauses") was false on macOS, whose `clock_gettime(3)` says `CLOCK_MONOTONIC` "will continue to increment while the system is asleep" (v3 re-review LOW 1; criterion A2 requires the clock ids). |
| **F4** | Suspend and hibernate preserve process instances and boot identity. | Adopt; card + review pending | Rules an explanation out: a sleep never explains a departure. Hibernation's restore kernel is not a boot. |
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
3. The fact lands like code (D5): the F-card, its registry entry and its tests merge after code review and the daybreak review of step 2. There is no separate operator ratification.
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
  - **the raw paired clock readings** the suspend bounds were derived from (wall clock, plus the pausing and non-pausing clocks of I37) with the boot id, so the bounds can be recomputed once the F2 and F3 cards land, and the C4a corpus keeps its wake context even if those cards land after C2 (I68; v3 re-review LOW 3);
  - collector states and observation times;
  - the Descartes version and config hash.
- **No entity keys.** Entity memory stays in the seen-sets. The previous entity set needed to chain the next interval is held in a small **census chain state** per source (one snapshot, bounded by the entity caps), ledger-stamped like a seen-set. If it is missing or invalid, the next interval's transitions are `unknown`, never zero (I50).
- **Size and caps (L2).**
  - A record is at most **1 KiB** at worst case, pinned by a T8-style test, with explicit caps: ≤ 8 VPN service states (overflow counted); a fixed, closed list of collectors for observation times; ≤ 8 interval events (overflow flagged).
  - The T8 floor gains a records-per-interval term: (H / interval) × records per interval (≤ 5 per hour: 1 structural plus at most 4 samples, I15) × worst-case record bytes × 1.25. That extends the capacity formula (`fact-families.js:343`, on `main` since the capacity merge), which assumes one record per structural tick (M5(c)).
  - At worst-case cadence, 30 days takes ≈ 4.4 MiB including the 1.25 headroom; at the typical 1 record per hour it takes ≈ 0.9 MiB.
  - Record size is independent of entity count, so volume inflation cannot evict this memory.
- **Integrity (M5(b)).** A seen-set is one snapshot validated against its own family's latest pass (`novelty-seen-set.js:20-25`); `tick_summary` is an append-only, cross-family history whose samples are primary data that cannot be re-derived. So it gets its own family ledger and is **certified at derivation** (I70; v4 Astra 4):
  - When a record is derived, each source pass it cites (generation, pass id, pass time) must lie inside its family's certified span at that moment. The record carries that certification, and its own hash chain commits to it.
  - From then on the record is valid while its own chain and family ledger are continuous. The reader never re-checks the source families' current span.
  - **Intentional age or byte eviction of the source facts is not loss.** At worst-case session volume the raw history covers about 2.6 days (§1.6), while summaries are kept for at least 30 days. v4's rule re-checked the source span on every read, so a seven-day-old record would have read as invalid, and volume eviction would have returned through validation.
  - A break in the summary's own chain, or a generation change of its own ledger, is loss. A gap is a loss marker, never silence (`summary_valid_after_source_byte_eviction`, `summary_own_chain_break_is_loss`).
- **Identity-dependent statistics are derived online** (v4 Astra 6). Several statistics need the census sets themselves: departures, restoration matches across a boundary (the pre-boot entity set is still in raw history when the +0/+2/+10 samples run), and same-name recreations. They are computed when each record is derived, while the raw census sets exist, and their per-episode results go to the long-lived per-episode records (§8.2). Nothing later needs the identities back. Summaries cannot support a coherent replay of identity-dependent scenarios beyond raw retention; that limit is an open item (§16.2).
- **Horizon and retention.** A horizon of **at least 30 days is declared in `RULE_HORIZONS`** (S floor). Outliving the raw window needs **per-family retention**, which `main` does not have yet (`fact-store.js:31`: one retention for every family); C2 adds it. The default beyond 30 days is an O resource choice (default 90 days, §16.1).

### 8.2 Long-lived sufficient statistics

- **What is kept.** Per stream and cell, conjugate statistics (counts, exposure) plus per-episode records for rare events (boot, wake and network-change aftermaths).
- **Dated records.** Records are dated, so a forgetting rate can itself be learned later.
- **Bounds and integrity (M5(d)).** Capped (I3), and stored as a registered family with its own ledger and lineage stamp. A history loss cold-starts the affected statistics, raises an integrity notice and is recorded as `memory_lost`. While the loss stands, the affected streams can raise but never recover or admit. It never declares "everything normal". Wiping this store is therefore not cheaper for an attacker than the H7 volume attack.

### 8.3 Reference snapshots and drift (I20, I72; Opus H2(b), LOW 5; Astra 7)

- **Snapshots kept.** Each is durable and versioned, and each is either journal-carried or chained in the learned store's own ledger, so its loss is detected, never silent (Opus H2):
  - each learned lineage's **earned snapshots**, the latest of which is its drift anchor;
  - its **drift ledger**: the displacement charged at each promotion, the sum over the trailing horizon H, and the total since its first earned snapshot;
  - the incumbents' frozen serving snapshots of open episodes (§6.5.1);
  - the serving snapshot of each serving version;
  - a bounded number of periodic references.
- **Anchors are taken automatically.** The anchor is whatever snapshot last earned promotion. Nobody states an anchor policy, and nobody re-anchors anything by hand (D5). v4's provisional and ratified incumbent anchors are withdrawn with C1a's narrowing.
- **Loss.** A lost anchor or drift ledger raises a `memory_lost` integrity notice.
  - The lineage is demoted to shadow and must re-earn from scratch. A host on which it had replaced the incumbent returns to the incumbent meanwhile.
  - The accumulated displacement is never zeroed by a loss, because nothing restarts from a fresh anchor until a new one has been earned against the full evaluation (`anchor_store_corrupt_no_fresh_budget`, `poison_anchor_loss_reverts_to_incumbent`).
- **Slow drift** is the cumulative divergence of the current predictive from the anchor's, on reference cells. It is not "recent versus rolling 30 days", which a slow poisoner walks along with (Astra 5; `autonomy-doctrine.md:110-116`). The `cusum` kernel (`model-ir.js:366`) is the candidate detector.
- **Measures (H3, I20).**
  - **Learned streams.** The sensitivity-reducing displacement of **every authority-relevant decision boundary** (each severity tier's α boundary) on reference cells, in the anchor's predictive scale. A mean shift, a variance widening and a severity-boundary move are all charged. A change that only increases sensitivity is not charged (Astra 7: a warning-only measure missed a critical-boundary move; Opus LOW 5: an unsigned measure charged a harmless rise).
  - **Novelty families.** Every admitted entity, by any source (Opus M5).
  - **Dimensions.** The Good–Turing novelty rate per dimension (L3).
  - **Not the incumbents.** v4's incumbent trigger measure is removed with C1a's narrowing.

## 9. Labels and the outcome loop (both audits; Astra 13; Opus M10; v2 re-review M1; v3 re-review HIGH 1, HIGH 3; v4 Opus M5; D5)

- **Append-only alert transitions** (`alert-transitions.jsonl`).
  - Records: `activated`, `incident_opened`, `escalated`, `frozen`, `recovered` (evidence; `recovered(edge_rearm)` for the incumbent exception of §6.0), `incident_closed` (with its reason: `label`, `superseded`, `event_delivered`, `admitted_earned`, `admitted_unexplained`, `explained_context`, `replaced`), `admitted`, `admitted_unexplained`, `quarantined`, `excluded`, `excluded_unadjudicated`, `admission_revoked`, `label_ingested`, `promotion_earned`, `promotion_demoted`, `replacement_earned`, `replacement_rolled_back`, `pending_discontinuity`, `recertified`.
  - The log is hash-chained, so it is tamper-evident at the same UID, though not tamper-proof.
  - **It is an audit trail, not the source of pending membership.** The pending journal is that source (§6.4.2). The two are cross-referenced by item id, and a disagreement is reported, never used to release anything.
  - **Re-grounded on the reworked branch** (`feat/notify-once-2026-10` @ 2e208df, *verified v5*). The daemon singleton and the CLI command queue are gone (5f92e46). `alerts ack` writes `alerts.json` directly (`alert-store.js:924`). Concurrent daemons are unsupported, and the store's read-modify-write race is its own todo. v3's "CLI mutations go through the command queue, the natural place to emit transitions" therefore no longer holds. Instead:
    - **the daemon is the only writer** of the transition log and of the pending journal;
    - **the CLI writes labels to an append-only label log** (`labels.jsonl`, re-read before append, as the branch's notification audit already does). The daemon ingests each label once, by id, on its next tick; emits `label_ingested` and the resulting `incident_closed`, `admitted` or `quarantined`; and notifies the ingested batch (I62, I27);
    - an acknowledgement that the CLI writes directly is observed on the daemon's next read, and logged.
  - The episode is `(alert id, incident_key ?? "default")`, with per-incident records. The branch has no transition log and no episode counter.
- **`activated` is a status transition** from a non-active state (absent, `recovered`, `closed`) to `active`. It is not a `newEpisode` and not a `newIncident`. Incidents are counted separately (`incident_opened`). Counting activations keeps a persistent EVENT episode with many incidents from inflating `fired_count` into `chronically_firing` (`calibration.js:293`), and from there into retire proposals (`tuning-store.js:416`, applied on approval at `tuning-authority.js:390`) (M1).
- **Fix the verified tuning-loop defect (C1.2).**
  - The fix: count `fired_count` from `activated` transitions, not from snapshot records (`calibration.js:245`, `tuning-store.js:428`).
  - For transition-backed rows, `fired_count_is_lower_bound` (`calibration.js:306`) then becomes false.
  - No standalone todo exists for this defect. This plan owns it as a prerequisite.
- **Labels are optional** (D5). They accelerate or correct learning. Nothing in the design depends on them: without labels, items stay pending, alerts stay active and silent after their one notification, and learning proceeds by earned promotion. The system is conservative, never stuck.
  - Acknowledgement is receipt only (`alert-store.js:440-451`).
  - The labels are `benign`, `suspicious`, `expected` (an explained change), `mine` (the operator's own action), `confirmed_incident`, and `missed_incident` (for recall).
  - They are stored as append-only records with their source (CLI, uid) and their scope: an alert id plus incident keys, a LEVEL episode, or a pending window. They can be applied in bulk from the digest.
  - **Their effect on data is fixed by §6.0 and §6.3.** `expected`, `mine` and `benign` make an item admissible to learned lineages without the §6.3.2 vetoes, still drift-charged at promotion, and admit a NOVELTY entity. They never make an incumbent fold an alarmed tick. `suspicious` and `confirmed_incident` quarantine permanently. `missed_incident` admits nothing and feeds recall.
  - Neither an LLM `notify:false` nor a fast recovery is a label (Astra audit).
- **Label-poisoning bound** (mechanism S, label budget O; Opus M5). Labels are writes at the same UID, so a same-user attacker can forge them, in the label log or before ingestion. Therefore:
  - (a) Labels never raise a model's authority above notify-only.
  - (b) **Every label is charged to the label budget**, quarantining and closing labels included, not only admitting ones. A burst beyond the budget is held, not applied, and raises an integrity notice. Label volume is itself a scored stream.
  - (c) **Every ingested label is notified**, and every closure lists its source in the digest. **A label never closes an undelivered incident**: the closure waits for delivery, so a forged label cannot cancel a notification or its retry (on 2e208df a recovered or suppressed incident is never retried, `alert-store.js:568`; C1.1 defines `closed` the same way, but only after delivery).
  - (d) A quarantining label never silences a condition that is still present: a LEVEL episode, or a NOVELTY entity that is still present, stays `active` (§6.0, I74).
  - (e) Promotion evidence counts only labels gathered under the calibration protocol (§10).
  - The doctrine requires that ground truth be fed, never minted (`autonomy-doctrine.md:126-129`). On-host labels are fed but forgeable, and are bounded and made visible accordingly.
- **There is no "declare a new normal" chore.** A learned lineage reaches a new normal by earned promotion (§6.3.1), and an incumbent by being replaced (§11.2). An optional `expected` label on an episode speeds that up: it makes the episode's items admissible and counts it as a benign episode in the evaluation.
- **Reports separate four outcomes:** correct silence; abstention (including `exposure_uncertain` and the unobserved straddle); frozen; unsupported. The precedent is `model-ladder.js:150`, which already separates unsupported evaluation from a correct negative.

## 10. Evaluation protocol, written before model selection (Astra 13; Opus M7; re-review M8, M9; D5)

All of this is pre-registered and frozen in step C3b, before the C4a spike runs. **The same protocol is also the runtime gate** (D5): run on each host's own coherent replay, it is what a version must pass to earn promotion or replacement (§6.3.1).

1. **Corpus.**
   - Source: the 2026-10-05 calibration laptop's history, copied with identifiers HMAC'd.
   - **Observed context (M8).** On `main` nothing collects boot id, suspend, `net_config` or presence (`daemon.js:425-435`); a non-running tailnet leaves no fact (`tailscale-status.js:166` → `fact-translators.js:999`); `last` reboot rows are dropped; uptime is a 24-hour metric. So the go/no-go corpus is the calibration laptop's history **after at least four weeks of C2 collection** on it, with context as observed.
   - An earlier spike on today's history is allowed only as a declared **upper bound**, with context reconstructed from what today's history holds (the uptime metric, `last` rows). It cannot produce a "go" on its own.
   - **Labels are optional** (D5). C2 records boot ids, suspends, and tailnet and network transitions as facts, so reboots, wakes and flaps are self-recording *events*. The corpus is treated as presumed benign, apart from its integrity notices and any operator labels, and scenario recall comes from coherent injection (item 3). Reboots and wakes are events. They are not benign labels for whatever surrounds them. The presumed-benign assumption is an evaluation risk, stated in §16.2.
   - This dev host is not a corpus: 0 reboots in the window (last boot 2026-09-04, verified); never slept (verified); its daemon is stale, and its stderr shows earlier ENOSPC errors (Opus M7).
2. **Scenarios**, written before any model exists:
   - Base set: mass session kill (the 2026-07-11 shape); kill and replace; an odd-hour unattributed login; drift over several days kept below threshold; a kill inside a reboot aftermath; **a sustained kill kept for 30 days** (re-review H2).
   - Adaptive set:
     - toggle-then-act (`tailscale down` or `scutil --nc stop`, then kill); new-network-then-act; a sub-threshold drift chain across refits **and across promotions**; volume eviction (Opus H7); context-switch recovery (the three v1 Opus B1 scenarios); **quiet-interval recovery after a kill** (re-review B1); a label burst; **forged labels**, both closing and quarantining (v4 Opus M5);
     - **pending-state laundering**: deleting or corrupting `alerts.json`, the pending journal, its checkpoint or the seen-set (v2 re-review H4); **truncating the pending journal on every tick** (v3 HIGH 1(c)); **journal corruption after a `confirmed_incident` label** (v4 Astra 3); **a crash between the fact commit and detection** (v4 Astra 2); **deleting the incumbent's serving snapshot** (v4 Opus H2(c)); **corrupting a lineage's anchor store** (v4 Opus H2(b));
     - **recover-then-fold**: kill 2 of 5 for 10 hours, then restart them (v3 HIGH 3(a)); **a `confirmed_incident` close followed by a recompute** (v3 HIGH 3(b)); **a persistent shift, then a second drop under notify-once** (v3 HIGH 2); **a gradual peer deterioration 8 → 5 → 0** (v4 Astra 1);
     - **same-name recreation within a boot** (v3 MEDIUM 1); **a universe change during an open episode** (v3 MEDIUM 5); **an incident flood to reach `incident_storm`** (I63); **a quarantined persistence re-installed** (v4 Opus M2);
     - **a poisoning chain that rides a context toggle into a promotion** (§6.3.2);
     - **kill then force a reboot**; **kill just before an update reboot**; **a faked boot boundary** (clock step, stored-state tamper, snapshot revert); **reboot flooding**; **moving a multiplexer binary aside** (I49).
3. **Coherent chronological replay.** An injection changes the whole observation sequence consistently: census markers, entity keys, creation fingerprints, `created_vs_boot`, context facts, boot identity and the integrity ledgers. The result is replayed through the real translators and detectors. An impossible observation sequence counts as a test bug.
4. **Metrics.**
   - Predictive calibration (PIT).
   - Per-episode detection and delay. The delay floor is about one structural interval, lower with transition samples.
   - False alerts per week on benign episodes (presumed benign, or labelled), measured out of sample.
   - Rates of abstention, freezing and correct silence, reported separately.
   - Resource cost (shadow included) and uncertainty intervals.
   - Synthetic recall is scenario recall, never real-world recall.
   - Quarantined (`suspicious`, `confirmed_incident`) data is labelled incident evidence for scenario recall. It is never a negative example and never enters a normal-behaviour fit (§6.4.5).
5. **Promotion bar (numeric and classified).**
   - Minimum evidence (S): every pre-registered scenario has run; held-out days and benign episodes per event type meet the protocol's minimum.
   - Operator tolerance (O): the maximum false alerts per week, and the minimum scenario detection relative to the incumbent. This is where the incumbent comparison lives now (§7.2).
   - The values are written in C3b as reviewed defaults (§16.1). The operator may override them, and never has to (D5).
6. **Compare against the incumbent, knowing it is noisy.** Fewer alerts is a win only if scenario detection holds.
7. **Negative results (M9).**
   - A C0.9 no-go on a platform is a result, not a blocker: the learner runs there with the exposure interval `[0, wall Δ]`, and the report states the sensitivity cost.
   - Exposure bias is checked directly: on held-out wake episodes, the rate of raises attributable to exposure uncertainty must be zero under I46, and any non-zero rate is a test bug.
   - "Skip the full design" remains a valid C4a outcome.

## 11. Authority: earned, bounded, reversible, notified (Astra 1; Opus H8; D2 as amended by D5; DA1)

### 11.1 Additive promotion (C7a)

Shadow → notify-only on the existing ladder, whose ceiling is notify-only (`model-ladder.js:1-9`).
- **Earned automatically** (§6.3.1). The pre-registered evaluation must pass on this host's replay, within the drift budget. The promotion is notified and reversible.
- **Additive.** A notify-only learner alerts alongside the incumbent and suppresses no alert.
- **Its only further power** is explanation authority over mapped incumbent NOVELTY items (`context_model`, I57). C5's vertical maps to no incumbent NOVELTY rule.

### 11.2 Replacement: earned, per host (D2, D5, DA1)

**Why it needs an amendment.** Replacing a detector reduces what alerts. That is suppression plus sticky adaptation, which the doctrine places above the on-host ceiling (`autonomy-doctrine.md:61-68,126-129`; behavioral-modeling plan `:118-121`). The session and peer detectors are WATCH-tier and default-on, while the doctrine keeps learned models default-OFF (`autonomy-doctrine.md:134`). v4 made replacement a per-host envelope that the operator ratified. D5 replaces that with earned replacement, and DA1 drafts the doctrine text.

**The policy.**
- **Earned, per host and per detector family.** A lineage that has served notify-only on the host takes over that family's alerting there when three things hold, all measured on the host's own coherent replay and its live notify-only record:
  - it detects every pre-registered scenario the incumbent detects, at the minimum relative detection tolerance (O);
  - it raises fewer false alerts;
  - its displacement fits the drift budget.

  Example: "on this host, session alerting routes to lineage L at earned snapshot R."
- **Notified.** One notification per replacement, listing the incumbent's open alerts it closes (`closed(replaced)`) and their incident histories.
- **Reversible.** Rollback is a routing flip. It happens automatically on a regression (§11.5) or a budget breach, and the operator can trigger it at any time. On rollback the incumbent resumes from its own state, and a condition that still holds raises a new episode, which notifies (`replacement_rollback_reroutes`).
- **Old detectors stay in code**, and routing is per host. No code is deleted, which honours roadmap §11 ("Fixed rules never weakened", `2026-07-09-self-learning-stratified-monitoring.md:224`).
- **New installs, and any host where no lineage has earned replacement, run the incumbents.**
- **On a replaced host**, the incumbent keeps running in shadow with its alerts logged, so a regression is visible. **The place is named** (v3 re-review §2): the incumbent-in-shadow's would-be alerts go to the shadow log; the digest lists divergences (the incumbent would have fired, the routed learner stayed silent); and `baseline inspect` shows them per family. C7b's gate requires this surface.
- **Which successor.** Coverage is judged by the pre-registered scenarios, not by matching target names. For `session.count_drop` (occupancy), C5 adds the hour-of-week occupancy LEVEL stream, so the successor models the incumbent's own target, including the recurring dip of §6.5.2 (Opus H1).

### 11.3 Post-promotion refits

- **Every refit is a new version.** It serves only once it has earned promotion (§6.3.1), within the cumulative budget anchored to the last earned snapshot (I20, I72). A rolling window is not an anchor.
- **Over the budget**, three things happen:
  - the lineage keeps serving its current version and adapts no further;
  - a notice is raised;
  - the budget recovers only as earned steps leave the horizon H.
- **A breach found after the fact** (the serving version's live predictive drifts past the budget, §8.3) demotes the lineage to its previous earned snapshot. On a replaced host, it also re-routes to the incumbent. Both are notified.
- No re-ratification (D5).

### 11.4 Structure changes

A structure change (the dimension set, the model families, the bucket edges or K; not top-K membership, v3 re-review MEDIUM 6) creates a new version, which enters shadow. The serving version keeps serving until its successor has earned promotion.

### 11.5 Auto-demotion

The anomaly-of-anomaly guard applies (behavioral-modeling plan `:120`). Without it, an attacker who poisons a good detector's inputs could get that detector auto-quarantined. A demotion is notified and reversible, like a promotion.

## 12. Delivery (Opus M9; Astra 16; v2 re-review M1, M2; v3 re-review HIGH 2; v4 Opus M4, Astra 9)

- **R3 notify-once** is built separately on `feat/notify-once-2026-10` (@ 2e208df, in rework, *verified v5*), with **producer-declared incident identity and first-class per-incident records**:
  - the episode is `(alert id, incident_key ?? "default")`; each incident is due, delivered, confirmed and retried on its own; diagnostic statistics, timestamps and stability counters never create episodes;
  - it notifies on activation, on a new incident key within the episode, and when an incident escalates above its notified severity;
  - it rearms after recovery (and, from C1.1, after `closed`);
  - acknowledgement does not block a later incident or escalation;
  - delivery is at-least-once: a lost confirmation can cause a duplicate, never silence;
  - more than 256 live incidents put the alert into `incident_storm`, subject to the C1 requirements of I63, with tombstones bounded by I73.

  It is O policy, independent of model truth and training eligibility. This plan's producers declare their keys per §6.1: the event set for EVENT streams, the entity for NOVELTY streams, and `lvl:<regime>:<extreme>` for LEVEL streams, the incumbents included from C1a.
- **Attention budget as a calibrated α allocation.**
  - A test notifies when its calibrated predictive p-value is ≤ α_i.
  - The α_i are allocated across streams so that the expected notifications per week ≈ N (O).
  - Calibration is checked by PIT on held-out data.
  - The budget is never a threshold that deletes detections: every detection is recorded and visible, and the budget governs only push delivery.
  - It is never re-derived from recent surprise history (which an attacker can game), and never raised during a flood; a flood produces a digest notice instead.
- **Severity** is a mapping from calibrated surprise and from corroboration across **distinct evidence sources** (O mapping, S counting rule, I29). A shared context event counts once (M2).
- **The digest** (built in step C1.5; I75; Opus M4(a)).
  - **Delivery.** It is pushed through the existing notification channel once per period (O, default daily, §16.1), only when it is not empty.
  - **Not throttled.** It does **not** count against the N-per-week attention budget. It is the "notification" in "notification, not confirmation", so throttling it would hide the audit trail.
  - **Contents, per period:**
    - every admission, by source, and the admissions refused for budget;
    - every closure, with its source (label, promotion, replacement, supersession, delivery);
    - every ingested label;
    - earned promotions, demotions, replacements and rollbacks, each with the drift charged and the cumulative displacement since the lineage's first earned snapshot;
    - open EVENT alerts (one line each; a label is optional);
    - **open LEVEL episodes**, with their running extreme, duration and incidents (v3 HIGH 2);
    - incident storms, with their counts (I63);
    - discontinuity epochs, `excluded(unadjudicated)` passes, drift-budget exhaustion and compactions to `excluded`;
    - integrity notices (`census.universe_changed` included) and abstention counts;
    - on a replaced host, the incumbent-in-shadow's divergences (§11.2).

## 13. Tier (Astra 15; D3; D5)

- **Watch tier.** These run under `watch.json`: L1 context collection, `tick_summary`, the pending journal, the label log, the digest, **default-on shadow learning**, and the **earned promotion path** of the plan's declared kernels (§11). Shadow learning has no authority, and runs under the bounds and kill switch of §7.7 (D3, DA2). Data collection turns on once the C0 rows it needs have landed. Shadow learning and the earned path turn on once DA has merged.
- **Learned tier.** Agent authoring and the AUTHOR-pipeline shadow constraints (`daemon.js:1135-1156`) stay under `learned.json`, default-OFF, as today (`autonomy-doctrine.md:134`).
- **Replacement** is an authority question (§11, D2, D5), not a tier choice.

## 14. Sequencing and gates

**Start C0 and C2 now. They are the calendar-time long pole.** Every learned step waits on context history that only accrues in real time:
- C4a's go/no-go needs at least four weeks of C2 context on the calibration laptop (M8);
- rare-event cells take months (§7.6);
- every week C2 is late is a week longer that the incumbents' interim costs last (§6.5.2), because their successors cannot earn replacement sooner.

C2 needs only the C0 rows it collects from: C0.1b, C0.3–C0.9 and C0.12. It does not need the F-cards (the raw clock readings are kept regardless, I68), and it does not need C1. Land those rows first and turn collection on.

| Step | Content | Gate | Needs |
|---|---|---|---|
| **C0** | Prerequisites (§3), including C0.1b census universes and the `census.universe_changed` notice, C0.12 boundary census, C0.13 F-cards | daybreak (collectors, schemas, sanitization, sub-deadlines, boundary verification); review (inventory, C0.9 write-up); per F-card, code review + daybreak (D5) | `fix/collector-sources-2026-10` (1c2b412, already containing `main` @ 1169d40) with the notice added as its merge gate, daybreak-gated and merged (§3; Opus M3) |
| **CAP** | `feat/fact-store-capacity-2026-10`. External to this plan. | **Done**: merged at 1169d40 (daybreak G3 READY) | — |
| **DA** | Draft DA1–DA3 as one change to `docs/design/autonomy-doctrine.md`, recording D1–D5, with the per-kind scope of §6.3 | review, like any change; no separate ratification (D5) | D1–D5 |
| **C1** | Merge R3 after its rework, rebased onto merged `main`, meeting I63 (EVENT incidents close on delivery; bounded tombstones, I73). **C1.1** hash-chained transitions written by the daemon; `closed(reason)` in the alert and incident status lists (absent on 2e208df, `alert-store.js:282,325`) and in `newEpisode`; a closure never cancels an undelivered incident. **C1.2** `fired_count` from `activated`. **C1.3** the label log, daemon ingestion and notification, the label budget (I27, I62). **C1.4** the pending journal, its checkpoint and scored-through watermark (I69), certification at write (I70), discontinuity with surviving dispositions (§6.4). **C1.5** the digest (I75). | daybreak (alert-store, pending journal) | `feat/notify-once-2026-10` (rework); the C1 defaults of §16.1, reviewed with the code |
| **C1a** | Arbitrated adaptation for the incumbents, **narrowed** (§6.5): (i) the exclusion predicate, the journal-carried frozen serving snapshot, the running-extreme rule and LEVEL keys, recovery only in the raising regime (§6.5.1–§6.5.3); (ii) the novelty pending lifecycle per D1, with the quarantine reappearance watch (§6.6); (iii) the landing migration (§6.5.4). Bounded quiet for novelty runs once DA has merged; until then, novelty items stay pending and their alerts active and silent. | **daybreak (security-critical)**, re-verifying every citation on the merged result. **Replay gate** (Opus H1): replay the 2026-10-05 calibration history through C1a and publish, per rule, the change in notification count, recurring dips included, before C1a ships | C1.1, C1.3, C1.4, C1.5 (CAP is met); the C1a defaults of §16.1 |
| **C2** | L1 facts, `tick_summary` with chaining, certification at derivation and raw clock readings, per-family retention, long-lived statistics skeleton with online per-episode identity statistics, transition samples including +0 | daybreak | The C0 rows it collects from. The F2 and F3 cards for the clock and suspend facts; until they land, those facts are `unknown`, and the raw readings let them be recomputed later (I68). |
| **C3** | L2 vector and `baseline inspect` | review + property tests (recomputable; stable across timezone changes; no target-derived dimension by field provenance; top-K reorder keeps `structure_id`) | C2 |
| **C3b** | Pre-register the evaluation protocol, which is also the runtime promotion gate (§10, §6.3.1); collect the calibration corpus (labels optional); write the refined O defaults and S caps as reviewed code (§16.1) | review | C2 running on the calibration laptop |
| **C4a** | **Time-boxed spike (≤ 1 week, written go/no-go).** Replay the corpus through (i) the incumbents, (ii) a minimal boot-id + tailnet-state transition model, and (iii) as much of the full design as the spike can build. Decide whether the `model-ir` fit holds or the divergence is justified. "Skip the full design" is a valid outcome. An earlier upper-bound run is allowed but cannot alone yield "go" (§10.1). | review | C3b corpus with ≥ 4 weeks of C2 context (M8) |
| **C4** | Estimator kernels in `model-ir` with runtime budgets; the adequacy gate (§7.2) | review + property tests | C4a go |
| **C5** | **One vertical shadow learner**: session departures and arrivals, **plus the reboot-event stream** and the other §7.8.3 items, **plus the hour-of-week session-occupancy LEVEL stream**, which is the same-target successor for `session.count_drop` (§11.2; Opus H1). The coverage contract is enforced in the shadow log, with default-on shadow isolation (disk bound included), daemon integration and runtime limits. F1 runs only if its card has landed and §7.8.3 is live; otherwise option D. | **daybreak** (the named `cc_*`, `id_*`, `f1_*` and `shadow_*` tests; poisoning; runtime) | C4; DA merged for default-on (until then under `learned.json`) |
| **C6** | Evaluation report per §10. Earliest at C2 landing + 30 days; for rare-event cells, months. | review | C5 |
| **C7a** | Earned notify-only promotion (§6.3.1, §11.1), automatic and notified; `earned_promotion` admission; `context_model` for mapped incumbent NOVELTY items (I57) | ladder + daybreak re-gate of the code | C6; DA merged |
| **C7b** | Earned per-host replacement and post-promotion refits (§11.2–11.3), with the incumbent-in-shadow's divergences surfaced (§11.2). Automatic, notified and reversible; no per-host ratification (D5). | daybreak (the code) | DA merged; C7a |
| **C8** | Repeat C5–C7 for peers per source, login arrivals and context streams (binary availability included, which then supersedes the `census.universe_changed` notice as the only signal) | as above | C7a |

- **Linux sources are CI-gated**, because the dev host cannot run VMs.
- **C2 is the urgent data step** (above).
- **C1a is the urgent safety step.** CAP has merged, so it now waits only on C1: the R3 rework, transitions, the label log, the pending journal and the digest. Its replay gate makes its interim cost on recurring benign patterns visible before it ships (§6.5.2).
- **Merge order on the shared files** (v3 re-review §4). The branches overlap on `alert-store.js`, `daemon.js`, `peer-baseline.js` and `session-baseline.js`:
  1. capacity (done, 1169d40);
  2. in either order: `fix/collector-sources-2026-10` (add the notice, daybreak, merge; it already contains 1169d40) and `feat/notify-once-2026-10` (finish the rework, rebase, daybreak, merge);
  3. C1;
  4. C1a.

  Each rebase moves this plan's branch citations, and C1a's daybreak gate re-verifies them on the merged result.

## 15. Non-goals

- No new hand-written behaviour rules, thresholds or suppressions. R4–R10 stay rejected.
- No shorter memory.
- No LLM in the detection path.
- No new privilege. The root helper remains optional.
- **No operator ratification, approval, configuration or labelling step that anything depends on** (D5). Operator input is optional, and its absence leaves the system conservative, never stuck.
- No change to the incumbents' constants. They are retired only by earned per-host replacement (C7b).
- **No new-normal exit, anchor or drift budget for the window-based incumbents** (D5). They freeze on a sustained shift until they are replaced.
- No F1 change to the incumbent `session.churn`, even though F1 would remove its cross-boot resurrect false positives (`session-baseline.js:417-651`; Opus audit `:33`). That changes an incumbent and overlaps R6's mechanism, so it is a separate operator decision (Q8).
- No change to the incumbent edge-triggered rules `session.churn` and `service.disappeared` beyond logging their next-tick recovery as `recovered(edge_rearm)` (§6.0, I42).
- No design of federated explanation sources beyond the interface of §6.3.3.
- No change to the doctrine in this plan: DA1–DA3 are drafted as a separate reviewed change.
- Some audit findings are out of scope here and remain follow-ups that reuse this substrate:
  - the fixed resource reflexes (`alert-store.js:89-99`, `tools/findings.js`);
  - the provenance launch-path lists;
  - the credential path list;
  - the constraint miner.

## 16. Open questions, defaults and open items

**Resolved by the operator decisions:**
- ~~Q1 Tier for shadow learning~~: default-on shadow (D3; DA2; §7.7, §13).
- ~~Q2 Replacement authority~~: earned per-host replacement (D2 as amended by D5; DA1; §11.2).
- ~~Q3 F class~~: allowed in the reviewers' narrowed form (D4). F-cards are reviewed like code (D5; §7.8.5).
- ~~Q4 Novelty lifecycle~~: pending until explained (D1; §6.3, §6.6).
- ~~Q5 Policy-envelope values~~: they ship as reviewed defaults (§16.1), which C3b refines from evidence. The operator may override any value, and never has to (D5).
- ~~Q6 Calibration corpus~~: C2 makes reboots, wakes and flaps self-recording events, so no labelling hour is needed (§10.1). The corpus is the calibration laptop's history after at least four weeks of C2 running there, which is just Descartes running.

**Resolved by the design:**
- ~~Q7 Bounded-quiet closure of non-novelty EVENT alerts~~. Bounded quiet is defined only for NOVELTY entities in v5 (§6.3, I56). EVENT and LEVEL data adapt by earned promotion.

**Still open (one question, with a default):**
8. **F1 on the incumbent `session.churn`.** Apply F1, with the verified boundary, to remove the incumbent's cross-boot resurrect false positives? Default: **no**, per I35 and §15. The earned successor (C5) removes them instead, without changing an incumbent.

**Operator actions: none required.** Optional at any time: labels, overrides of any default, vetoes and rollbacks. Recording D1–D5 in `todos/2026-10-06-session-peer-tuning.md` and confirming the merge order are agent work for the next session.

### 16.1 Reviewed defaults (O and S values; D5; Opus M4(b); Astra 8)

Each value ships with the code that needs it, and is reviewed like that code. Each is an attention or resource policy, not a claim about the machine (§0.4). C3b refines them from the corpus. The operator may override any of them.

| Value | Needed by | Default | Class |
|---|---|---|---|
| Open pending items per family (I3) | C1.4 | 1,024, then compaction to `excluded` | S |
| Exemplars per item (I3) | C1.4 | 8 | S |
| Quarantined items per family before aggregation (I3) | C1.4 | 256 | S |
| Incident tombstones per alert (I73) | C1 | 4,096 | S |
| Label budget (I27) | C1.3 | 50 labels per host per 7 days; a burst beyond it is held, with a notice | O |
| Discontinuity budget (I54) | C1.4 | 3 epochs per family per 30 days | O |
| Digest period (I75) | C1.5 | daily, sent only when not empty | O |
| Novelty bounded-quiet period Q (I19) | C1a | 14 days of certified, complete family history | O |
| Novelty admission budget (I20) | C1a | 8 unattended admissions per family per 30 days | O |
| `tick_summary` retention beyond 30 days (§8.1) | C2 | 90 days | O |
| Shadow abort count k (I65) | C5 | 3 | O |
| Shadow resource bounds, disk included (I47, I64) | C5 | set in C5 against the T8 and T9 models | S |
| Drift budgets per learned kind, and horizon H (I20, I72) | C7a | written in C3b from the corpus | O |
| Promotion-bar tolerances (I30) | C7a | written in C3b | O |
| N notifications per week (α allocation, §12) | C7a | written in C3b | O |

### 16.2 Open items (addendum, v5)

These are not closed by more machinery, by design. Each is stated, bounded and visible.
1. **Interim noise on the incumbents** (Opus H1(b)). A recurring benign pattern that alarms re-notifies at every occurrence until a successor earns replacement. The C1a replay gate measures it. C5's occupancy successor bounds it for sessions; peers wait for C8.
2. **Incumbent sub-threshold drift.** C1a adds no anchor or budget to the incumbents (D5), so a slow walk through non-alarmed folds is as possible as it is today. The successors carry the anchored budget.
3. **Incumbent tamper resistance at the same UID is today's, plus notices.** Suppose an attacker wipes the journal, its checkpoint and `alerts.json` together while no episode is open. The incumbent then re-establishes from post-break ticks after N clean ticks, exactly as a corrupt detector store does today (`session-baseline.js:244-264`), and `integrity.pending_discontinuity` is raised.
4. **Replay beyond raw retention** (Astra 6; partly closed). Identity-dependent statistics are derived online, while the raw census sets exist (§8.1). Coherent replay of identity-dependent scenarios, however, needs raw census sets, and at worst-case session volume those cover about 2.6 days (§1.6). C3b chooses between a periodic HMAC'd corpus export from the calibration laptop and restricting those scenarios to the retained window.
5. **Presumed-benign corpus.** Without required labels, an undetected incident in the corpus would be scored as benign. This is an evaluation risk. Integrity notices and optional labels reduce it.
6. **Same-UID forgery limits** (stated evidence limits):
   - the journal is tamper-evident, not tamper-proof;
   - CC3-E instance identity can be forged by restarting tmux under a faked clock, which can fabricate a `recovered` status but never admits data (Opus LOW 7);
   - labels can be forged, but they are budgeted and notified;
   - on-host evaluation inputs can be forged (§6.3.2).
7. **Patient poisoning** of a learned lineage at the drift-budget rate (§6.3.2). It is notified and reversible, but cannot be prevented without off-host attestation.

**Addendum (2026-10-09, after the v5 reviews).** Opus v5 (0 BLOCKER, 3 HIGH; `docs/reviews/2026-10-09-context-plan-v5-review-opus.md`) and Astra v5 (0 BLOCKER, 4 HIGH; `docs/reviews/2026-10-09-context-plan-v5-review-astra.md`). As agreed after v4, the plan is **not revised again for these**. None affects C0 or C2 (context data collection), which start now. Each item names the step that must close it before that step lands; that step's daybreak gate checks it.

| # | Item (sources) | Must be closed before |
|---|---|---|
| 8 | **Pending-directory loss mutes then re-baselines an established incumbent** when no episode is open; ticks never adjudicated fold (Opus H1, Astra 1). Direction: losing the pending store must never re-base an incumbent from post-break ticks; keep a durable per-incumbent serving snapshot outside the pending directory, or freeze until N trusted ticks are journaled. | C1.4 / C1a |
| 9 | **Quarantine does not revoke versions that learned from the quarantined data** (Opus H2, Astra 2). Direction: training-membership provenance is live; a later quarantine of any member marks every version that trained on it as tainted, and those versions are demoted (automatic, notified, reversible) and re-fit without it. | C7a |
| 10 | **Peer regimes share one recovery unit** — fabricated recovery or indefinite muting across regimes (Opus H3, Astra 3). Direction: per-regime incident keys (or alert identities) for peer LEVEL/EVENT incidents, consistent with notify-once per-incident records; recovery only within the raising regime. | C1a (peers) |
| 11 | **Reciprocal corroboration vetoes make correlated legitimate changes label-only** (Astra 4, NEW) — the UAC ditch again. Direction: a veto must be satisfiable by evidence other than a label (independent context facts such as a software-change event, bounded quiet within the drift budget); no path where only a label can admit. | C7a |
| 12 | Drift-budget continuity/bootstrap (anchor for the first promotion, total vs rate, doctrine :110-116 alignment) (Opus M1, Astra 6). | DA + C7a |
| 13 | Running extreme is a raw count, wrong for context-conditioned learned LEVEL streams (Opus M3, Astra 5). Direction: extreme in surprise units for learned streams; raw counts stay for incumbents only. | C5 |
| 14 | `earned_promotion` admission scope (which lineage's items) and the incumbent explanation boundary (Opus M5, Astra 7). | C7a |
| 15 | Label budget counts labels not coverage; bulk forged label bypasses vetoes (Opus M6, Astra 8). | C1.3 |
| 16 | Watermark needs a durable observation→pass mapping (Astra 9). | C1.4 |
| 17 | Retained evidence vs the runtime promotion protocol (Astra 10); interim-noise "bound" is a measurement (Opus M2, Astra 12). | C3b / C1a replay gate |
| 18 | Pending novelty can grow alert storage without bound (Opus M7, Astra 11). Direction: bounded pending set with storm semantics (one notification), never silent eviction. | C1a |
| 19 | CC3-E "every open incident" vacuous after delivered EVENT incidents close (Opus M4, Astra 14). | C1.1 |
| 20 | Exposure assumes wall-clock elapsed time is valid (Astra 13, NEW). Direction: exposure from the monotonic/boottime clock readings already kept (I68), wall time only as a cross-check. | C2 (data) / C4 |

## 17. Key code refs

Refs on `main` are verified at 66d3a2b (v5). Its code differs from 1169d40 only in `baseline.js` (b60efc8), so every `main` line below is unchanged since the capacity merge. Branch refs name their tip, and move when the branch is rebased.

- **Global folds and scoring:** `welford-stats.js:20`, `:84-89` (z-score with floor); `session-baseline.js:68-83` (constants), `:244-264` (corrupt-store reset), `:367-373` (tick disposition), `:385-416` (fold; score then fold `:394-408`; provisional `:410`), `:653-669` (count-drop candidate, `global` id), `:913-927` (coverage); `peer-baseline.js:50-61` (identities; `v2:vpn` `:55`), `:68,74` (σ and floor), `:446-448` (disposition), `:511-534` (regime filter), `:515-516` (honest re-warm-up), `:523-588` (spike fold), `:612-647` (drop fold), `:688,730` (warning caps).
- **Recovery path:** `alert-store.js:28-31` (`alertId`), `:249-272` (`normalizeAlertRecord`), `:260` (status list), `:287-301` (malformed-record quarantine), `:330-388` (`applyAlertCandidates`; recovery `:374-383`), `:440-451` (acknowledgement); `daemon.js:872-892` (coverage by owner and identity); `service-baseline.js:447-464` (union coverage), `:836-863` (novelty = latest minus history and seen-set), `:1043-1052` (`service.appeared` coverage).
- **Session churn (the edge-triggered exception):** `session-baseline.js:417-651` (evaluated keys `:629-630`).
- **Session identity:** `fact-translators.js:644-654` (entity key), `:666-673` (creation fingerprint); `tools/sessions.js:39-42` (`#{session_created}`), `:135-141` (screen: pid in the name, no creation time).
- **Dropped context:** `tools/tailscale-status.js:83-84,139,166` → `fact-translators.js:998-1007`; `tools/network.js:81-261` → `fact-translators.js:532`; `vpn-peer-status.js:94-105,127,154,207,327,348,425-430`; `fact-translators.js:887,937`; `tools/system.js:65`, `daemon.js:338`.
- **Daemon:** cadence `daemon.js:79-82`; sequential collection `:425-435`; `withDeadline` `:446`; structural due check `:1043`; all-or-nothing deadline `:1055-1066`; common tick ts `:1075-1106`; per-family persist and retention passes `:1122-1124`; learned-nested AUTHOR shadow `:1135-1156`; evaluation mutates detector stores `:1575-1578`; detector evaluation `:1743`; plist `:1947`.
- **Capacity and integrity (on `main` since 1169d40):** `fact-families.js:108-149` (`RULE_HORIZON_ENTRIES`, `RULE_HORIZONS`), `:240-249` (budgets), `:258-273` (tick shapes), `:343` (T8 floor), `:358` (4× ceiling); `fact-store.js:31` (single retention), `:32-36` (legacy 5 MB default), `:455-476` (seen-set fold inside the retention pass); `fact-store-integrity.js:54` (`last_committed_pass_id`), `:95-97,449` (generation changes only on bootstrap), `:690-705` (certified-span reporting); `novelty-seen-set.js:6-8` (entries kept 30 days past `last_seen`), `:10-18` (folded only by the retention pass; memory only suppresses a claim), `:20-25` (lineage stamp), `:26-35` (re-seed), `:371` (stamp equality on read).
- **Outcome loop:** `calibration.js:57-64,245,293,306`; `tuning-store.js:416,428`; `tuning-authority.js:390`.
- **Model substrate:** `model-ir.js:262-455` (ops; inclusive z-score `:335-341`; cusum `:366`); `model-ladder.js:1-9,150`.
- **Notify-once branch @ 2e208df (in rework):** `alert-store.js:10-11` (`MAX_LIVE_INCIDENTS`, storm key), `:37` (`alertId`), `:80-82` (`alertEpisodeKey`), `:282,325` (alert and incident status lists; no `closed`), `:300-330` (incident map), `:500` (`candidatePayload`), `:567-573` (`notificationDueForIncident`; confirmed-at-or-below not due `:571`), `:605-606` (`newEpisode`), `:617-620` (incident map and storm reset on a new episode), `:629-631` (live count excludes acknowledged, recovered and suppressed), `:676-690` (storm), `:694-704` (recovery), `:924` (acknowledgement); README "Ordinary alert delivery is episode-based" and "The producer declares incident identity"; `todos/2026-10-09-alert-store-concurrent-writers.md`; `notification-delivery.js` (re-read-before-append audit). Removed in 5f92e46: `alert-command-queue.js`, `daemon-singleton.js`.
- **Collector-sources branch @ 1c2b412 (contains `main` @ 1169d40):** `fact-translators.js:728-738` (usable-multiplexer `censusStateFor`), `:767` (`binary_availability`); `session-baseline.js:373-377` (binary availability per group); 6ba7d80 (per-universe session alert ids); 25aeb89 (universe-filtered fold); `tools/sessions.js:182,208` (`not_found_on_known_paths`); `tools/vpn-peer-status.js:334` (real-output parser); `tools/binary-resolver.js` (writer-set trust). No `census.universe_changed` yet.
- **Trusted state:** `2026-09-06-trusted-state-step-1.md:141-148` (§5.3 B-ledger; `:145` boot id; `:146` A5 lesson).
- **Doctrine:** `autonomy-doctrine.md:33-37,39-50,46-50,61-68,101-116,105,120,126-129,134`.

---

## Appendix A: Review disposition

Every finding is **Accepted** unless noted. "Where" points to the v5 section that addresses it. The tables for earlier reviews keep their dispositions as written. Where v5 replaced the mechanism, the v4 tables say so: v3 HIGH 2's held level became the running extreme (I55); v3 MEDIUM 4's incumbent anchors were withdrawn (I58); v3 MEDIUM 5's regime admission was narrowed (I59).

### v4 review, Opus 5.5 max (`2026-10-09-context-plan-v4-review-opus.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| HIGH 1 | The window-based incumbents have no working exit to a new normal: an admitted held level re-raises on the next tick, and a recurring dip that recovers is never admitted | **Resolved by scope (D5).** No new-normal exit is retrofitted onto the incumbents. They freeze on a sustained shift until a learned successor earns replacement, and that is the exit. The recurring-dip cost is stated, measured by a C1a replay gate before C1a ships, and bounded by an hour-of-week occupancy successor in C5. Opus's suggested drift-budgeted path for recurring recovered episodes was declined: it would be the new-normal machinery D5 removes. | §6.5, §6.5.2, §11.2, §14 C1a and C5, §16.2 item 1 |
| HIGH 2 | The discontinuity exit restores the journal but not detector state; one write mutes a LEVEL alert or resets the drift budget | Accepted, adapted to D5. (a) LEVEL keys are `lvl:<regime>:<extreme>`, re-derivable from `alerts.json`, so truncation cannot reset the numbering, and the regime is in the key. (b) The incumbents have no anchors. Learned anchors and drift ledgers are chained, and a loss demotes the lineage to shadow and returns the host to its incumbent; it never zeroes the accumulated displacement. Opus's "only the operator re-anchors" is replaced by automatic re-earning (D5). (c) The incumbent's frozen snapshot is journal-carried; if it is lost and cannot be rebuilt, the episode stays frozen with the running extreme live. | §6.1, §6.4.4, §6.5.1–§6.5.2, §6.3.2, §8.3, I55, I60, I72 |
| MEDIUM 1 | "Re-base" is undefined, and superseded LEVEL incidents stay live | Accepted. The held level and re-base are removed; the running extreme never widens or moves on a partial return; a superseded incident closes `closed(superseded)`. I35 corrected: the rule decides when a frozen episode notifies again. | §6.5.2, I35, I55, `level_oscillation_bounded_notifications` |
| MEDIUM 2 | Quarantined NOVELTY entities stay suppressed | Accepted. A quarantined entity leaves both suppression sets as a reappearance watch. | §6.4.5, §6.6, I74 |
| MEDIUM 3 | C0.1b cannot be built as written before C1a, and the branch already shipped the blind half | Accepted. `census.universe_changed` is a merge gate of C0.1b on the collector branch; the incumbents' regime rules land at C1a. | C0.1b, §6.5.3, §14, I59 |
| MEDIUM 4 | C1 and C1a depend on a digest no step builds and on values C3b proposes later | Accepted. C1.5 builds the digest: pushed, not counted against N. The values C1 and C1a need ship as reviewed defaults. | §12, §14, §16.1, I75 |
| MEDIUM 5 | A forged label closes an alert silently | Accepted. Every label is charged and notified on ingest; every closure lists its source in the digest; a closure never cancels an undelivered incident; a quarantining label never ends a LEVEL episode or a present NOVELTY alert; every novelty admission is drift-counted. | §6.0, §9, I20, I27 |
| LOW 1 | One retired peer gives z = −2, so the scenario never raises | Accepted: two of six peers. | §6.2, §6.5.2 |
| LOW 2 | Re-score on restart assumes idempotent detectors; journal append failure undefined | Accepted. The watermark plus completion from the journal payload; a failed append still raises and opens a discontinuity. | §6.4.2, I53, I69 |
| LOW 3 | The C1a migration double-notifies and snapshots a window that already folded the alarm | Accepted. Rekey in place; snapshot from the ticks before `first_seen`. | §6.5.4 |
| LOW 4 | "Inside the certified span" cannot be checked later; trigger too broad | Accepted. Certified once, at write time, with the pass time recorded; the trigger is limited to open incidents. | §6.4.3, §6.4.4, I70 |
| LOW 5 | Drift displacement is unsigned | Accepted for learned lineages (only sensitivity-reducing displacement is charged). The incumbent measure is removed. | I20, §8.3 |
| LOW 6 | The `software_change` example contradicts I57 | Accepted. Reworded as a service-appearance learner conditioned on `software_change`. | §6.3, §6.6 |
| LOW 7 | CC3-E instance identity can be forged at the same UID | Accepted as a stated evidence limit: status only, never data. | §6.2, §16.2 item 6 |
| LOW 8 | Stale branch tips | Accepted. Re-grounded on 2e208df and 1c2b412. | Header, §1.5, C0.1b, §6.1, §17 |

### v4 review, gpt-6-astra xhigh (`2026-10-09-context-plan-v4-review-astra.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| 1 HIGH | The held-level estimator absorbs further deterioration (8 → 5, then 4…0 at z ≈ −2) | Accepted. The held level is removed with C1a's narrowing (D5). The running extreme is monotone and frozen, so every further step notifies. | §6.5.2, I55, `level_gradual_deterioration_notifies` |
| 2 HIGH | Crash recovery omits the fact-commit-to-verdict gap | Accepted. A durable scored-through watermark; ordered replay of committed passes, or `excluded(unadjudicated)` where a pass cannot be scored. | §6.4.2, I69 |
| 3 HIGH | Discontinuity recovery downgrades quarantined observations to pending | Accepted. Surviving terminal dispositions are kept with their provenance; disagreement resolves to the most restrictive; an unverifiable admission is never honoured; only uncertain membership becomes `unexplained_discontinuity`. | §6.4.4, I54 |
| 4 HIGH | Long-memory certification depends on raw history that capacity retention removes | Accepted. Certification at derivation time; from then on, validity rests on the record's own chain. Intentional age or byte eviction is not loss; a break in the record's own chain is. | §6.4.3, §8.1, I70 |
| 5 HIGH | EVENT adaptation: laundering through promotion, or label-only learning | Accepted, resolved per D5. Shadow trains on everything; a promotion candidate's normal-component membership is explicit and recorded; serving authority is earned only by the pre-registered evaluation (adaptive scenarios included) within the drift budget; the earned promotion is the admission event for that membership; it is reversible and notified. The poisoning bounds are stated: drift budget, cross-stream corroboration veto, anomalous-context veto, adaptive scenarios, quarantine. | §6.3.1, §6.3.2, §11, I71, I72 |
| 6 MEDIUM | The retained summary cannot support identity-dependent learning and replay | Partly closed. Identity-dependent statistics are derived online into per-episode records. Coherent replay beyond raw retention is an open item for C3b. | §8.1, §16.2 item 4 |
| 7 MEDIUM | Warning-trigger displacement does not bound severity suppression | Accepted. The incumbent measure is removed (D5). The learned measure charges every authority-relevant decision boundary. | I20, §8.3 |
| 8 MEDIUM | Required early values are scheduled too late | Accepted. Reviewed defaults ship with C1 and C1a. | §16.1, §14 |
| 9 MEDIUM | Closing incidents removes the live cap without bounding retained records | Accepted. Tombstones are bounded by the watermark (EVENT), by the episode (LEVEL) and by a per-alert cap. | §6.1, I73 |
| 10 LOW | Dependency descriptions have drifted | Accepted. Refreshed: 1c2b412 already implements usable-multiplexer universes; 2e208df is the R3 tip. | Header, §1.5, C0.1b, §17 |

### Operator direction (2026-10-09)

| Id | Direction | Where |
|---|---|---|
| D5 | No per-item, per-version, per-host or per-anchor ratification; no routine configuration or labelling chores; earned, bounded, reversible, notified adaptation and replacement; labels optional; F facts reviewed like code; anchors automatic; C1a narrowed for the incumbents | Header; Operator decisions; §0.2 P5, P7; §0.4; §6.3, §6.5; §7.8.5; §8.3; §9; §10; §11; §13; §14; §15; §16 |

### v3 re-review (`2026-10-07-context-plan-v3-rereview-opus.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| HIGH 1 | The pending ledger's fail-closed state has no exit; its seen-set stamp rule trips on ordinary operation; a crash between writes freezes adaptation; one truncation is a learning denial of service | Accepted. A daemon-only, hash-chained journal whose entries cite the pass they scored. A checkpoint carried and re-stamped by every family retention pass; a stale or missing checkpoint is rebuilt, and only a contradiction is a discontinuity. Journal-first write order, with a re-score on restart. Automatic re-certification at the next clean pass with a complete, trusted census, carrying everything pending plus an `unexplained_discontinuity` item. Detection never stops. A discontinuity budget bounds repeats. | §6.4.2–§6.4.4, I44, I53, I54 |
| HIGH 2 | LEVEL alerts stay active indefinitely, and notify-once then mutes the host-global detector | Accepted. LEVEL incident key `lvl:<generation>:<ordinal>`. The held-level test mints a new incident on any further anomaly, so the warning caps do not matter. Recovery within the raising snapshot. A new normal only through label, bounded quiet (DA3) or a mapped context model, each closing and re-arming the episode; per-item consent is not the only path. Over budget, the episode stays open but is never muted. The digest lists open LEVEL episodes. Storm requirements on R3. | §6.1, §6.2 CC4 and CC7, §6.5.2, §12, I43, I55, I63 |
| HIGH 3 | What happens to pending data when an episode recovers or closes is contradictory, and the literal design launders it | Accepted. The observation lifecycle is separate from alert status. Recovery leaves items pending. Quarantining labels quarantine permanently, kept as evidence and never in a normal fit. Benign labels admit only through the drift-budgeted channel. Membership comes from the journal only. The item cap compacts to `excluded`, which never folds and never freezes. | §6.0, §6.4.5, I3, I52 |
| MEDIUM 1 | Within one boot, departure recovery is keyed on names | Accepted. Recovery needs the same instance (entity key, creation fingerprint and a known `created_vs_boot`) within one boot; a recreation stays frozen and is scored as churn; no creation time, no recovery. | §6.2 CC3-E, `cc_e_recreated_same_name_scored_as_churn`, `cc_e_no_creation_time_return_frozen` |
| MEDIUM 2 | The Q7 default admits event data under bounded quiet, beyond D1 and DA3 | Accepted. Bounded quiet is defined per kind and never applies to EVENT data, which admits by label or mapped context only. Q7 is resolved and dropped. DA3 states the scope. | §6.2 CC7, §6.3, I19, I56, DA3, §16 |
| MEDIUM 3 | Notify-only promotion at C7a grants admission authority without DA3 | Accepted. `context_model` needs DA3, C7a, an explicit stream map (same kind, target and universe) and a daybreak re-gate, and never explains its own lineage. C5's vertical maps to no incumbent. §11.1 narrowed. | §6.3, §11.1, §14 C7a, I57 |
| MEDIUM 4 | Incumbent anchors depend on a per-host ratification, and behaviour without one is undefined | Accepted. A provisional anchor is taken automatically at first establishment, with a notice. Ratification is one policy statement. Until then: no unattended admission, and labels within a provisional budget. Each new regime is anchored the same way. | §6.5.1, §16, I45, I58 |
| MEDIUM 5 | Regime and universe changes re-warm the incumbents with no arbitration | Accepted. CC3(a) for the incumbents. An open episode freezes across a change. A new regime is raise-only until its change is admitted. Regime memory. A `census.universe_changed` notice before C8. | §6.5.3, C0.1b, I49, I59 |
| MEDIUM 6 | `structure_id` includes the learned top-K mapping | Accepted. Top-K membership is a parameter inside a version; `structure_id` is the dimension set, families, bucket edges and K; the serving version is kept until its successor is evaluated. | §5, §6.1, §7.4, §11.4, I7 |
| MEDIUM 7 | New thresholds are unclassified | Accepted. Rows for "stably not found" (I67: no hysteresis), the bounded-quiet stability test (I55 and I19: the held-level test), the boundary tolerance (I66: the I24 resolution) and the abort count (I65: O), plus every number v4 adds. | §0.4, §0.5 |
| LOW 1 | F3's wording is false on macOS | Accepted. Clock ids are named per platform. | I37, §7.8.1, C0.9, §4.1 |
| LOW 2 | Two default-on incumbent EVENT rules still recover on a quiet interval | Accepted as a named exception: no fold, no pending data; `recovered(edge_rearm)` is never counted as evidence. | §6.0, I42, §15 |
| LOW 3 | C2 timing against the C4a corpus: no wake context if F2/F3 ratification lags | Accepted. Raw paired clock readings and the boot id in every `tick_summary` record. | §8.1, C0.9, I68 |
| LOW 4 | The default-on shadow log and learned store have no disk bound | Accepted. Registered families with budgets and a T8-style invariant. | §7.7, I47, I64 |
| LOW 5 | Three `PPP:Modem` services, not two | Accepted and corrected. | §1.5 |
| §2 | §11.2's "a regression is visible" names no place | Accepted. The shadow log, a digest divergence list and `baseline inspect`; C7b's gate requires them. | §11.2, §12, §14 C7b |
| §4 | C0.1b ownership and merge order against the capacity branch | Accepted. `fix/collector-sources-2026-10` rebases onto merged `main` (1169d40), implements C0.1b, passes daybreak, then merges. | §3 C0.1b, §14 |
| §4 | Overlapping branches move every citation; the C1a gate must re-verify | Accepted. Capacity is merged and every `main` citation was re-verified at 1169d40 (§17); the remaining rebases are named; C1a's daybreak gate re-verifies on the merged result. | §14, §17 |

**Closure of the v2 items the v3 re-review left partly open:** H1 (identity) through HIGH 2 and MEDIUM 6; H2 (absorption as data ages out) through HIGH 2, HIGH 3, MEDIUM 5 and I60; H4 (the pending state's home) through HIGH 1 and HIGH 3.

### Operator decisions (2026-10-06)

| Id | Decision | Where |
|---|---|---|
| D1 | Novelty pending until explained; explanations: context, labels, bounded quiet; federated signatures later | §6.3, §6.3.3, §6.6, DA3, I19, I48 |
| D2 | Replacement per host and detector family; v5: earned and notified, not ratified (D5) | §11.2–11.3, DA1, C7b |
| D3 | Default-on shadow learners | §7.7, §13, DA2, I47, C5 |
| D4 | F class adopted in the reviewers' narrowed form | §0.4, §7.1, §7.6, §7.8, I33, I36–I41, C0.12, C0.13 |

### v2 re-review (`2026-10-06-context-plan-v2-rereview-opus.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| B1 | No recovery rule for event streams; a departure alert recovers on the next quiet interval | Accepted. Streams declared EVENT or LEVEL (v4 adds NOVELTY); an event alert recovers only on positive evidence (departed keys present again in the same boot, cumulative deficit empty), otherwise frozen until a label; never across a boot by restored names; level streams keep level semantics; gate tests for both kinds. | §6.0, §6.2 CC3-E, `cc_e_*`, `cc_l_*`, I42 |
| H1 | Identity by stratum class makes alerts unrecoverable and multiplies notifications | Accepted. Alert id = rule, lineage, `structure_id` only; `incident_key` = event identity or `default` (v4: LEVEL keys are no longer `default`, v3 re-review HIGH 2); stratum and raising cell in `raise_ref`; recovery re-scores the raising cell instead of requiring a return to it; never-observed dimensions excluded from the host vocabulary; `not_applicable` and stable not-found are known; back-off raises recover at the same level; identities bounded. | §6.1, §6.2 CC3, §5, I43, I22, I4 |
| H2 | C1a absorbs a sustained shift as old data ages out, then recovers on unchanged evidence | Accepted. Ratified anchors (v4: provisional at establishment, I58); persisted pre-episode snapshot scoring that outlives the raw window; re-warm-up ticks pending; incumbent recovery per CC3(e); exit by label or bounded quiet on the new level, within the drift budget. Aging out is never an explanation. | §6.5, §6.3, P3, I45, I19 |
| H3 | C1a cannot be built in the stated sequence | Accepted. Anchors built at C1a, decoupled from C7b; drift measures per incumbent kind; C1a (both halves) sequenced after the capacity merge; context path abstains until C7a; bounded quiet waits on DA3. | §6.5, §8.3, §14 (CAP, C1, C1a) |
| H4 | Pending state has no integrity-protected home | Accepted. Ledger-stamped pending store per family plus the hash-chained transition log; disagreement or loss fails closed; sufficient-statistic retention instead of eviction; overflow fails closed; seen-set re-seed cannot drop pending status. v4 replaces the store with the pending journal, its re-certification exit and compaction instead of an overflow freeze (v3 re-review HIGH 1, HIGH 3). | §6.4, I44, I3 |
| M1 | Stale picture of notify-once; digest churn inflates `fired_count` | Accepted. Re-grounded on 25cf225 (producer-declared `incident_key`, no material digest), and in v4 on c461564's per-incident records; `raise_ref` is diagnostics only; `activated` is a status transition, incidents counted separately. | §6.1, §9, §12 |
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
| Closed registry the agent can never author; per-fact F-card, daybreak review, operator ratification, kill switch, re-verification per OS major version | Adopted; v5 replaces operator ratification with code review plus daybreak (D5) | §7.8.5, C0.13, I40 |
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
| M8 | Unclassified numbers | Accepted. Every number is in the inventory, including v3's and v4's new ones (v3 re-review MEDIUM 7). | §0.5 |
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

**v5 check.** v5 adds no threshold, suppression or window:
- The running-extreme rule (I55) reuses the stream's own raise, against a frozen snapshot, and adds no number. It only adds notifications.
- `census.universe_changed` is an integrity signal over the collector's evidence basis (S). It is additive.
- Earned promotion and replacement (I71) are gated by the pre-registered evaluation and the drift budget, both classified; the vetoes of §6.3.2 are evidence conditions, not windows or hand rules.
- Incident closure on delivery (I63) changes bookkeeping, not what raises or notifies.
- Every new value is classified, with a default (§0.5, §16.1).

(v4's check listed the held-level test and the anchor policy; both are removed in v5.)

| Item | v5 status |
|---|---|
| R4 (floor 0.5 → 0.75) | Absent. No stddev floor exists in L3; the incumbent is unchanged; the incumbent's z is no longer an adequacy bar. |
| R5 (14-day window) | Absent. Memory grows (§8), and aging out is never an explanation (§6.5). |
| R6/R7 (reboot suppression or CRITICAL guard) | Absent. Reboots are facts, covariates and a scored EVENT stream. F1 is not R6: R6 detected a reboot by "uptime < gap" (forgeable by a clock step), then suppressed `session.churn` and made `count_drop` non-notifying, implicitly time-windowed and with no tripwire. F1 has no window and no parameters, needs a boundary verified by conjunction (I41), fails closed, has tripwires, never recovers, closes, admits or changes severity, and requires the reboot itself to be scored in the same learner. |
| R9 (wake grace) | Absent. Wake is an interval fact; under F4 a sleep never explains a departure; exposure uncertainty can lower sensitivity but never raise an alert (I46). |
| R10 (lone-churn rule) | Absent. Churn rate is learned per context. |

---

## Addendum: C0 execution (2026-10-11)

Branch `feat/context-facts-c2-2026-10` (from `main` @ 414c6ef, which contains the merged `fix/collector-sources-2026-10`). Scope: the C0 rows C2 collects from (§14), all DATA only: no new alert candidate, rule or threshold. Not yet daybreak-gated; the boundary verification, the key handling, the schemas and the sub-deadline runner are the security-relevant parts for that gate.

**Done.**
- **C0.6** `context-schemas.js`: a closed schema per context fact (enum, 16-hex HMAC, bounded integer, bounded pattern, closed sentinels) with a physical-object provenance tag per field; every context point is validated at the translator, and a rejected field writes the schema's `unable` shape (offending field named from the closed list, an unknown key never echoed), never the value.
- **Families.** `host_lifecycle`, `network_context` and `session_context` are registered with a 30-day declared **data** horizon (`DATA_FAMILY_HORIZONS`, a resource floor, not a `RULE_HORIZONS` entry) and budgets sized like the capacity plan from the schema-derived worst-case record (pinned by test): 4, 2 and 11 MiB (total default budget 65 → 82 MiB). `MIN_STRUCTURAL_INTERVAL_MS` is unchanged.
- **C0.3** `net.tailnet_state` for every probe outcome; `Peer` no longer required to read `BackendState`; a Running daemon without a Peer map stays an unable peer census. Absent `Health` or `CurrentTailnet` is `unknown`, never zero or none.
- **C0.4** `tools/login-origin.js` (explicit local patterns: `(:0)`, `(:N.M)`, `(:pts/N:S.M)`, `(tmux(pid).%N)`; `(mosh [pid])` is `remote_mosh`) and `tools/login-sessions.js` (macOS `who` + IOConsoleUsers + bounded `last`; Linux `loginctl` list + one `show-session` + bounded `last`), first-observed-tick dedupe by row digest in a bounded 0600 seen-state (logind ids salted by the boot; the `last` identity ignores the logout suffix; a lost state re-emits as `reseeded`), per-tick caps 8 + 8 with overflow counts.
- **C0.5** `tools/net-config.js` and `net.config_fingerprint`: per-component state and keyed HMAC; the aggregate is `unknown` whenever any component failed. The per-install key is `stateDir/keys/context-hmac.key` (0700/0600, tmp+link creation, never federated); README data table updated.
- **C0.7** per-collector sub-deadlines (default 20 s census, 5 s context, both inside `deadline_ms`); census collectors first in their old order, context collectors strictly after; every envelope carries `observation.start_ms/end_ms`.
- **C0.8** `tools/host-lifecycle.js` (one fixed `sysctl` argv on macOS; `/proc` reads on Linux) and `boot-ledger.js`: digests of seen boot ids (ring of 64), a per-process daemon nonce, the I41 conjunction (never-seen id, daemon restart, boot time in the gap, uptime consistency, no pre-boot tmux instance in the census) checked to the one I24/I66 resolution constant (2 s: whole-second boot time plus non-atomic reads), failing closed to `unverified`, clock-independent contradictions as tripwires (see deviations 7 and 8); the OS build per boot; the bracket (boot id and wake marker before and after the census).
- **C0.9 (raw capture only)** `host.clock_reading` per structural tick: wall clock, libuv `hrtime` (labelled `uv_hrtime_clock_id: unverified`, never named as a pausing or non-pausing clock), `os.uptime()`, macOS `kern.monotonicclock_usecs`, `kern.sleeptime`/`waketime`, `kern.sleep_abs_time`/`wake_abs_time`, `machdep.wake_abstime`/`wake_conttime` (all readable unprivileged on Darwin 25.2), Linux `/proc/uptime` and `/sys/power/suspend_stats/success`. The no-go fallback is in force on every platform: `host.suspend` is `unknown` with exposure `[0, uptime Δ + resolution]` within one boot (`cross_boot` otherwise; `unknown` when either boot id or uptime is unreadable), F3 inactive. The bound uses the OS uptime delta, not the wall Δ the plan names (C0 review M2): a backward wall step makes the wall Δ smaller than the real elapsed time, so it is not an upper bound; uptime (Linux `CLOCK_BOOTTIME`, macOS now − `kern.boottime`, which the kernel moves with a calendar set) includes suspended time and does not move with a step. C0.9's measurement write-up should confirm the macOS half.
- **C0.12** a boundary probe every tick (~15 ms) folds the boot id and the OS wake marker into the ledger; a new boot id or wake makes a boundary census pending: at +0 when `boundary_census` is enabled (off by default, see deviation 1), otherwise at the next scheduled census, verified against that census, with `host.boundary_census` recording the pre/post gap durations (unknown, never clamped, when an input is missing or inconsistent).

**Deviations.**
1. **C0.12 ships OFF (`structural.boundary_census.enabled: false`, C0 review B1).** The +0 census writes into the session and peer families the incumbent detectors score and fold, so on by default it would change alerting (a census while the tailnet reconnects, or before tmux-resurrect has run, becomes the tick they score; boundary moments become over-represented in their folds). §7.6 sends the transition samples to `tick_summary` for the learners; until C1a/C2 can route them there, the boundary is still detected every tick, verified and recorded at the next *scheduled* census with its gap durations (`host.boundary_census.status: not_enabled`). Also from review L3: a change first seen by the after-census probe is recorded as `detected_after_census`. When it is enabled, the cost cap is: I15's "≤ 3 per transition, ≤ 4 extra per hour" is implemented as *borrow the next structural slot*: a boundary census advances the checkpoint by one interval instead of to now, and may borrow only when the checkpoint is not already ahead of now. Any horizon then holds at most H/interval + 2 structural runs, inside every family's T8 1.25 headroom, so the session and peer budgets did not have to grow; the census gap after a borrow is below two intervals. A boundary that cannot borrow waits for the slot and is recorded `deferred_cost_cap`. The +2/+10 samples are C2 (I15).
2. **C0.7 replaces the all-or-nothing deadline for every structural collector**, not only the context ones: an overrun now loses that collector's evidence only. Four daemon tests that pinned the whole-tick discard now pin per-collector loss. Shadow-constraint evaluation keeps its successful-tick-only discipline.
3. **C0.7 bracketing covers the cheap boot read only** (boot id + wake marker). Tailnet and VPN state are read once, after the census; bracketing them (and the `unstable` context value for them) is C2.
4. **C0.4 changes the incumbent peer census** (a fabrication removal): `who` rows with a local tag are no longer SSH peers, and a macOS `last` row with an empty host column no longer yields a peer named after its weekday ("Fri", observed on this host's real output). `(mosh [pid])` rows are unchanged in the peer census. Because this changes what counts as a peer, the peer availability signature is bumped to `v2` (C0 review M4): `v1` history stays a valid but different regime, so the count re-warms under `v2` instead of a parser change being scored as a sustained `peer.count_drop`. On Linux, session_context reads `loginctl`, not `who`; on macOS IOConsoleUsers feeds `user.presence` and the console source state (the console login itself comes from `who`). `last` now runs twice per structural tick (peer collector and login collector, ~0.35 s each here); sharing the read is a follow-up.
5. **C0.5 interface kind on macOS** comes from `ifconfig -v` (`type: Ethernet / Wi-Fi / ...`); `networksetup -listallhardwareports` was rejected (2.2 s per call). Linux DHCP domain is read only through `nmcli` (not_found where NetworkManager is absent; systemd-networkd leases are not read).
6. **C0.8 is not yet the trusted-state B-ledger.** `boot-ledger.js` is the shared primitive (one reader, one digest); wiring `boot_id` into `integrity.json` (§5.3 of the trusted-state plan) and the clamp guard (`todos/2026-09-08-clamp-boot-identity-guard.md`) remain their own steps.
7. **I41's uptime conjunct is not independent (C0 review H3), so no boundary is `verified` yet.** Both platforms derive the reported boot time from the uptime and the wall clock at read time (Linux `btime` = realtime − `CLOCK_BOOTTIME`; macOS libuv uptime = `time(NULL)` − `kern.boottime`). "(detection − boot time) agrees with uptime" is then an identity, and "uptime fits the gap" is algebraically `c_boot_time_in_gap`. The conjunct is recorded as `not_independent` (never `pass`), which keeps I41 intact and fail-closed: every boundary is `unverified` (`failing_conjunct: uptime_consistent` when nothing else fails). **Open item:** C0.9 names an independent clock (e.g. a validated `kern.monotonicclock_usecs`), or I41 is amended to four conjuncts. F1 is inactive either way.
8. **Clock-dependent contradictions are `unverified`, not tripwires (C0 review M3).** A boot time outside (last observation, now], a session apparently created before the boot, and a different daemon process apparently started before the boot all compare wall readings taken at different instants; a benign clock step (lagging RTC, then an NTP step) produces each of them, and there is no step detection until `host.clock` (C2). They fail their conjunct (named in `failing_conjunct`, a fail before an unknown before `not_independent`). The tripwires left are the clock-independent ones: a boot id seen before, and a boot-id change under the same daemon process (nonce). The other tripwire enum values stay in the schema for C2.

**Deferred.**
- **C0.9 measurement write-up** on a real laptop (separate later task): which clock libuv's `hrtime` uses per platform, the macOS sleep/wake sysctl semantics across real sleep and DarkWake, Linux `CLOCK_MONOTONIC` vs `CLOCK_BOOTTIME`, and the per-platform go/no-go. Reading the named clock ids needs native code (or a measured equivalent); until then the fallback above stands. The 60 s fast-tick clock deltas aggregated into the structural record (§4.1 `host.suspend` source) are also deferred: the boundary probe runs every tick but only the structural readings are persisted.
- **C0.8 conformance tests** (Linux VM reboot, kexec, soft-reboot, macOS tart reboot, `launchctl reboot userspace`, snapshot revert) are named as `todo` tests: they need a rebootable VM in CI. The Linux real-OS read test is platform-gated (CI).
- C2 items not started: `tick_summary` and chaining, per-family retention, `session.created_vs_boot`, `session.attachment`, `context.transition`, `host.clock` step/timezone events, `host.daemon_gap`, `host.lifecycle_record` (`last` reboot/shutdown rows), `net.vpn_service_state`, the `collector.binary_state` family, and the I5 static check over the provenance tags (C3).
- Out of this step's scope: C0.1b (`census.universe_changed`), C0.2's Linux VPN source, C0.10, C0.11, C0.13 (F-cards).

### C0 review fixes (2026-10-11)

Adversarial review of C0 at 9bd265d. Every finding was checked against the code; each accepted one has a failing test first and its own commit.

| Finding | Disposition |
|---|---|
| B1 +0 census feeds the session/peer detectors | Accepted. `boundary_census` ships disabled (deviation 1); boundaries are still recorded at the next scheduled census. |
| H1 raw tailnet name reaches the model | Accepted. The `collect_tailscale_status` tool strips it (`redactTailscaleEnvelopeForModel`, presence flag only). |
| H2 unread boot id written as `cross_boot` | Accepted. `interval_basis: unknown`. |
| H3 `c_uptime_consistent` cannot fail | Accepted. `not_independent` (deviation 7): fail-closed, no boundary `verified` until C0.9 or an I41 amendment. |
| M1 bracket `stable` with no wake marker | Accepted. `unknown`. |
| M2 wall delta is not an upper bound | Accepted. Uptime delta + resolution, within one boot. |
| M3 clock step produces a tripwire | Accepted, widened to the daemon start-time branch: clock-dependent contradictions are `unverified` (deviation 8). |
| M4 peer parser change without a regime bump | Accepted. Peer availability signature `v2`; `v1` stays a valid, different regime. |
| M5 empty boot salt for logind dedupe | Accepted. Salt falls back to the census's own boot read; with none, no dedupe that tick (census `unavailable`). |
| M6 fabricated/guessed fingerprint (a–d) | Accepted, all four. |
| M7 silent re-key | Accepted. `hmac_key_id` on every context fact; login seen-state keyed and discarded on key change. |
| M8 markerless peer tick after a VPN sub-deadline overrun | Accepted. No tailscale peer points when the VPN envelope is daemon-synthesized. |
| L1 ledger file trusted alone | Partly: the verdict needs the live after-read to confirm the boot (`live_boot_mismatch` / `live_boot_unread`). Ledger integrity itself stays B-ledger / daybreak scope. |
| L2 superseded pending boundary lost | Accepted. `superseded_count` on `host.boot_boundary` and `host.boundary_census`. |
| L3 `deferred_cost_cap` mislabel | Accepted. `not_enabled`, `detected_after_census`. |
| L4 unkeyed login digests | Accepted. HMAC under the per-install key (seen-state v2). |
| L5 truncated `who` count reported as definite | Accepted. Source `partial`, count `unknown`. |
| L6 `.unknown` entity-key collapse | Accepted. No key, no login row. |
| L7 unbounded every-tick probe, per-tick ledger write | Probe bounded by the context sub-deadline. The per-tick write is kept on purpose: it gives `last_observed_ms` tick precision for the gap conjunct. |
| L8 schema only in translators | Accepted. `normalizeFactPoint` enforces it at append and on read. |
| L9 `last` read twice, §0.5 ids, HANDOFF | Not changed here: the first two are already listed as known follow-ups (deviation 4, C0.10). Updating `docs/HANDOFF.md` is the parent agent's job. |
