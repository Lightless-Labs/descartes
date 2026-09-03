# Proactive Behavioral Modeling — Agent-Authored Models, an Earned-Trust Economy, and Divergence Arbitration

**Created:** 2026-09-03
**Reviewed:** 2026-09-03 (five-lens document-review gate — adversarial, security, feasibility, coherence, scope-guardian, run in parallel) — **NEEDS REWORK**. Five blockers (four on Plane B/C authorization + one on Slice-1 scoping), grounded in the existing code, recorded in the "Review outcome" section below and to be folded in the rework. **Plane A (the compositional DAG IR + static admissibility as the anti-Clippy mechanism) validated as sound; the recommend-only / no-host-mutation envelope confirmed intact.** Threat-model posture **decided 2026-09-03** (staged: attestation-gated above notify-only, additive-only below, with a labeled lab/VM toggle — see "Review outcome"); body rewrite is the next step.
**Status:** **NEEDS REWORK** (see "Review outcome"). The plan's *direction* holds; the trust-economy and arbitration planes overclaimed safety on evidence that is forgeable on-host and on a ground-truth currency the codebase does not have, and Slices 1–2 are mis-scoped. Not implementation-ready until reworked.
**Origin:** Interactive design session (Opus main-loop), extending the self-learning roadmap. The governing philosophy is `docs/design/autonomy-doctrine.md` (the "three ditches": Clippy / Vista UAC / Skynet).
**Supersedes / reconciles:** Slice 4 replaces *human-gated per-item promotion* (the single-use approval nonce in the roadmap's S7 and `docs/plans/2026-07-10-constraint-mining-pipeline.md` §8's "24h promotion nonce/expiry"; described as current behavior in `README.md`) with **evidence-driven auto-promotion** up to the recommend-only ceiling. This changes model **promotion** only. It does **not** touch AGENTS.md's *mutating-action* invariant: that ladder — `read-only → recommend-only → approval-required → policy-authorized low-risk → autonomous, narrowly-scoped, tested, reversible` (AGENTS.md, "Policy / Authority Plane") — stays intact and is in fact the direct anchor for this plan's authority tiers and its `reversibility × corroboration` principle. `approval-required` remains available as an operator *policy choice* for high-blast-radius actions; it stops being the mandatory per-item default. Until Slice 4 ships, the human promotion gate remains and the README's current description holds.
**Owner:** unassigned
**Todo:** tracked under [`todos/2026-07-09-self-learning-stratified-monitoring.md`](../../todos/2026-07-09-self-learning-stratified-monitoring.md) (this is a layer of that roadmap).

> Sequenced, locally-testable-first, read-only-first, additive-first. **NO code in this document.**

**Related plans / code:**
- `docs/design/autonomy-doctrine.md` — the doctrine this plan implements. Read it first.
- `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` — the parent roadmap ("learn the machine / self-monitor / self-audit / compile-down"). This plan is the concrete shape of its Layer-B/C ambition once agent authorship enters.
- `docs/plans/2026-07-10-constraint-mining-pipeline.md` — the deterministic mining + `draft→shadow→review-ready→active→retired` lifecycle this plan reinterprets as an evidence-driven trust economy.
- `docs/plans/2026-08-21-fact-store-completeness-hardening.md` (COMPLETED) — the completeness substrate that gates both *detection* and *adaptation*; the reason "never fabricate" holds.
- `docs/plans/2026-07-23-slice-7-authority-containment-plane.md` + `src/containment-recommend.js` — the recommend-only ceiling and the future authority gate the trust economy lifts models through.
- `docs/plans/2026-08-11-descartes-fleet-federated-topology.md` + `docs/plans/2026-08-21-tamper-evidence-attestation-design.md` — the cross-host corroboration/ratification source and the off-host reversibility/attestation the highest authority tier depends on.
- Code grounding: `src/constraint-eval.js` (the pure evaluator to generalize into a DAG interpreter), `src/constraint-store.js` (the flat IR record to widen), `src/constraint-miner.js`, `src/welford-stats.js` (mean/variance, z-score, EWMA) + `src/history-store.js` (percentiles) as the first registered *statistical* kernels, and `src/stat-diff.js` (the shared `lstat` metadata-diff behind the positive-evidence canary/credential detectors — a *set/attribute-diff* primitive, not a statistics kernel), `src/shadow-store.js` + `src/calibration.js` + `src/tuning-store.js` + `src/tuning-authority.js` (the evidence + auto-tuning machinery to repoint at automatic promotion), `src/fact-store-integrity.js` (completeness gating), the `*-baseline.js` detectors, `src/provenance-store.js`, `src/alert-intelligence.js` (the only existing LLM seam).

---

## Review outcome (2026-09-03 — five-lens adversarial gate, NEEDS REWORK)

Parallel document-review lenses (adversarial, security, feasibility, coherence, scope-guardian), each code-grounded. **Plane A holds** — the declarative DAG IR + "reject the inadmissible DAG before execution" is a sound, code-grounded anti-Clippy mechanism, and the recommend-only / no-host-mutation envelope is intact. Every blocker is on Planes B/C (authorization) or on the Slice 1–2 scoping.

**Blockers (grounded):**

- **B1 — No ground-truth currency.** Plane B climbs models on "corroborated true-positives at a low false-positive rate," but that quantity does not exist: `calibration.js` states outright (`:23`, `:64`, `:314-318`, verified) *"There is no ground-truth incident signal anywhere in this codebase,"* `recall_proxy` is always `null` by design, and the only real metric is a precision *proxy* — itself a documented lower bound whose numerator includes `llm_suppressed`. So the economy is **circular** (Plane C's "benign drift → suppress" verdict feeds the metric that demotes the model that fired) and **measures only down** (a silent/degenerate model climbs by never tripping a caught false-positive — the quietest models climb fastest). [adversarial 1/6; security 1c]
- **B2 — On-host evidence has no root-of-trust.** Single-host corroboration and the completeness proof are all files under the state dir, recomputable at daemon uid; `fact-store-integrity.js` is sha256 + counts + a locally-generated UUID with no external key/TPM/signature, so a same-uid rewrite of `facts.jsonl` + `integrity.json` is coherent and undetectable. "Corroboration replaces consent" and "never adapt to unattested change" both collapse against the primary threat (host compromise); the immune two-signal metaphor is a category error on one host (all signals share one failure mode). **§6.1 (independence) and §6.4 (federated ratification) are hard preconditions mis-filed as open questions.** [adversarial 2; security 1]
- **B3 — Static admissibility cannot bound the data-dependent operators the IR is built on** (`join` = O(N×M); `count_distinct`/`groupby` over high-cardinality fields = unbounded state; `window`/`quantile` are data- not shape-dependent) — yet the plan names static admissibility as Tier A's *whole* safety story. An admissible-*looking*, agent-authored (or prompt-injected) DAG can DoS/OOM the monitoring daemon, and a monitor that misses ticks is itself a defensive blind-spot attack. [feasibility 2; security 2; scope 5]
- **B4 — Slice 1 mis-scoped.** The comparator `switch` is the trivial scalar-in/bool-out half; `buildShadowFactLookup` collapses history to one latest-wins scalar per target, but the operators that justify the plan (`window`/`ewma`/`quantile`/`zscore`) need the *series* — a different input contract that lives in the *other* seam (`welford-stats.js` + the `*-baseline.js` detectors). The hard windowed / missing-input / dual-read-versioning contract is mislabeled design-sketch while the easy half is called "implementation-ready." [feasibility 1/4; scope 1]

**Must-fixes folded into the rework (each grounded in a finding above):**

1. **Restore a positive ground-truth oracle** for UP-promotion — operator labels + seeded/synthetic red-team fixtures + injected known-bad events — and break the arbitration↔demotion circularity; name the real currency (precision proxy, a lower bound) and its limits. *Labeling ≠ UAC consent*, so this preserves the no-per-item-approval decision while restoring the oracle the doctrine's "human on-the-loop" still needs.
2. **Off-host attestation / federated ratification as a HARD precondition** for any promotion above notify-only, for adaptation, and (later) for acting; **DEFINE "independence"** to exclude same-author and same-host-evidence lineage (definitional, not a tunable threshold). Add an anomaly-of-anomaly guard before auto-demoting an *established* detector, and specify the predecessor-supersession rule (what happens to a model when its adapted successor promotes).
3. **Pull the act tier out of this plan** — the execution primitive and its acting-governance (act-corroboration, action-rollback) belong in the Slice-7 authority-plane's own reviewed doc; today's recommend-only is the documented *absence* of an execution primitive (`containment-recommend.js`), and adding one gated by a computed trust score is a discontinuity, not a rung. This plan tops out at recommend (notify-only until attestation). The kill switch must be evaluated per-action on any future acting path.
4. **Runtime budget for cardinality / agent-authored DAGs** — per-model fuel + row + distinct-state ceilings; hard caps on `count_distinct`/`groupby` (reservoir/sketch); a max-window bound; a survivable mid-evaluation abort (no torn state, no missed tick beyond that model); and completeness-preserving degradation (a truncated count degrades to *silence*, never a wrong number). Split Tier A into structurally-bounded (hand-authored) vs runtime-budgeted (agent-authored/cardinality). Ship reference-resolution + arity/type validation in the first increment; co-design each kernel's cost contract *with* the kernel (a per-primitive contract required at Tier-C registration), not a monolithic analyzer that predicts a later slice.
5. **Confidentiality:** the feature algebra reads only hashed/bucketed fields (raw identity reachable *only* through a hashing primitive); agent-authored diagnostics constrained to a closed number/enum/hash schema, enforced before persistence or any boundary crossing — because `sanitizeDiagnostics` is only a charset gate (it passes a raw `host.example.com` / `10.0.0.1`), and the audit trail is federated.
6. **Anti-poisoning:** a per-lineage cumulative-drift *and* adaptation-rate budget anchored to an *attested* baseline (a Slice-7 prerequisite, not a knob — "re-earn from shadow" measures fit-to-recent-history, which the poisoner controls); a hard cap on candidate-DAG admission rate into soak; and the same charset/sanitization discipline on the authoring/arbitration LLM prompt as on the alert prompt (fact content is attacker-influenceable → prompt injection, and `model_pattern` sends it off-host).
7. **Re-scope Slices 1–2 into a thin VERTICAL spike** (thin IR generalization → ONE kernel → minimal auto-promote ladder → the authoring seam admitting ONE LLM-proposed DAG end-to-end) ending in a **written go/no-go**; decide the IR's real shape, the kernel vocabulary, the Node-vs-Rust boundary, and stateless-recompute vs incremental-state (which trades cost against a state-poisoning surface) *at that gate*. Force into the committed increment: the windowed/series input contract, missing-input (degrade-to-silence) semantics, dual-read versioning (v1 stays v1 on disk; v2 a byte-identical parallel proof; **never an in-place migration of active records**), and a baseline-detector byte-identical regression lock. Reclassify §6.7 (migration) from open-question to precondition, and give the recurring scoring/meta-monitoring work an explicit daemon cadence/home.
8. **Reconcile the two overlapping state machines** — the existing maturity lifecycle (`draft→shadow→review-ready→active→retired→quarantine`) vs the new *authority* axis (`shadow→notify-only→recommend`) on the same artifacts — into one state model with a single source of truth; extend migration to cover lifecycle states, not just IR fields. And **no kernel enters the registry without a live model that requires it** (the "dozen families" is a menu, not a build checklist).
9. **Tier-B hatch (deferred) hardening spec:** zero host imports / no WASI; compile-bomb + module-size limits; a pinned engine+version with FP/NaN determinism; a `memory.grow` cap; CEL and WASM treated as *separate* boundary specs; and stated plainly as runtime-enforced, not "statically analyzable."
10. **Coherence:** map or reclassify `notify-only` against the AGENTS.md ladder; define "signal" and "corroboration"; add a model version/lineage schema (`{id, parent_id, author, ts, lineage_depth}`); standardize "completeness-gated"; disambiguate primitive vs kernel; and lift "adaptation is authoring" up into the doctrine itself.

**Direction decision (2026-09-03, operator): the STAGED posture, with the attestation gate as a POLICY TOGGLE.**

- **Production default (gate on):** off-host attestation — the tamper-evidence + federated-ratification layer — is a HARD precondition for any authority above **notify-only**. Below the gate a model is **additive-only**: it may raise alerts, never suppress/whitelist, so a forged on-host model cannot *blind* the monitor or act (this closes security finding 1a at the tier that ships first).
- **Lab / adversarial-test posture (gate off, clearly labeled, never production):** relaxes the attestation requirement so the full economy runs on-host inside a VM, to red-team it and demonstrate value *now* without first building the entire off-host layer. This dev host has no Virtualization.framework, so the adversarial harness runs in the **tart CI VMs / remote hosts**, not locally.

**Design inspiration — AV/EDR self-defense (operator ask):** the AV world already solved the shape of B1/B2 and validates this posture. (a) Ground truth is never minted on the endpoint — signatures/labels are curated centrally, **code-signed**, distributed, and verified before load; so B1's positive oracle is an *attested external label feed* (operator-curated + seeded red-team fixtures now; shared/federated signatures later), and **YARA** (a bounded, declarative, no-arbitrary-code rule language shipped under a trust envelope) is a real-world precedent for the Plane-A rule IR. (b) Serious vendors *concede the on-host war against root* (a kernel rootkit/bootkit defeats an on-host agent) and move authority off-host: a cloud backend the attacker doesn't control + a **dead-man's-switch** (endpoint goes silent → the *backend* alarms) + a **hardware root-of-trust** (TPM / Secure Boot / measured boot). So B2's fix is tamper-*evident* on-host + authority *off-host* — exactly the tamper-evidence-attestation + federated-topology plans and the gate above. (c) ML detectors are retrained *centrally on attested data*, never on unattested endpoint-local data — the discipline behind "never adapt to unattested change." The lab toggle mirrors AV "tamper-protection / cloud-protection" switches that analysis sandboxes disable to detonate samples.

## 0. Scope, relationship to the roadmap, and commitment tiers

This plan turns the roadmap's north star — *Descartes builds its own monitoring models and earns the right to act* — into a buildable architecture, under the doctrine's hard constraint: **escape Clippy without falling into Vista UAC or Skynet.**

It is deliberately **not** a frozen spec for all slices. Per repo convention:

- **Committed / implementation-ready now:** Slices 1–2 (the model-IR generalization + static admissibility). These are pure, offline-testable, additive, and change no daemon behavior — they only re-express what exists on a more general substrate. They are the load-bearing, low-risk foundation everything else needs.
- **Design-sketch, dedicated plan required at pickup:** Slices 3–10. Schemas, kernel families, thresholds, and CLI surfaces named below are **provisional design intent to validate against real Slice 1–2 data**, not contracts. Each slice-group gets its own `docs/plans/` file when picked up.
- **HANDOFF / roadmap discipline:** `docs/HANDOFF.md` is updated at slice-group boundaries and before any compaction; this plan's header is updated at those boundaries, not per slice.

**Non-negotiable throughout:** the whole subsystem stays default-OFF behind `learned.json`; nothing here adds a mutating host action (the recommend-only ceiling holds until a separate authority plane, itself gated by this trust economy, exists); everything is additive to a clean, adversarially-reviewed baseline.

## 1. Problem statement

Today "self-learning" is a **deterministic miner producing a flat menu**: `constraint-miner.js` (explicitly *"no LLM"*) emits `{ family, target, expected }` records where `expected` is a single comparator (`gte|lte|eq`) or a string pattern, `constraint-eval.js` evaluates them, and a human approves promotion. The statistical machinery is real but narrow (`welford-stats.js`: streaming mean/variance, z-score, EWMA; `history-store.js`: p95; `calibration.js`/`tuning-*.js`: threshold auto-tuning) — roughly four of a dozen model families, all hand-coded, none agent-authored.

That architecture is in **two of the doctrine's ditches at once**:

- It is **Clippy**: the agent authors nothing; it can at best pick from hand-built detectors.
- Its promotion path is **Vista UAC**: every mined artifact waits on a human click.

The gap to close: let the agent **author its own behavioral models** — choosing metrics, transforms, model families, and hyperparameters — and let those models **earn the right to alert and eventually act by evidence the system gathers itself**, with the human on the loop (policy + audit + veto), never in it (per-item consent). And do this while the *acting* surface stays governed by `reversibility × corroboration`, never by attention.

## 2. Architecture — three planes

The three planes map one-to-one onto the three ditches' fixes.

### Plane A — a compositional behavioral-model IR (fix for Clippy)

A behavioral model is a **declarative DAG**, not a picked preset, with three composable layers:

- **Feature algebra** — primitive fact accessors plus bounded, composable transforms
  (`window`, `rate`, `delta`, `ratio`, `lag`, `log`, `ewma(α)`, `zscore`, `quantile(q)`,
  `count_distinct`, `groupby`, `join(stream_a, stream_b)`). This is the agent's *feature
  engineering* — "transformed metrics" and derived "additional metrics."
- **Model layer** — over those features, a family kernel with agent-chosen hyperparameters
  (a control chart, a Bayesian count model, a changepoint detector, a rule-list/tree, a
  random-cut forest).
- **Decision layer** — a rule-list/tree composing model outputs and features into
  fire / severity / suggested-authority.

The generativity is in **composition**: fixed, audited primitives; unbounded pipeline space. Three tiers of authoring power, added in order of need:

- **Tier A (workhorse):** the algebra above. Covers the large majority; cheap; statically bounded; no code.
- **Tier B (frontier, deferred):** a sandboxed, non-Turing-complete expression hatch (CEL-style, or a WASM module under a strict fuel + memory cap) for a novel transform the algebra cannot express — genuine agent-authored code, but caged and statically/dynamically bounded.
- **Tier C (grow the language):** a human-reviewed new *primitive kernel* joins the audited registry. The slow, deliberate path.

**Static admissibility** is what makes agent authorship safe *and* cheap, and it is only possible because the IR is declarative: before a model runs, its DAG is analyzed for a bounded **compute + memory budget**, valid **metric references** (every input resolves to something collected), and **bounded state** (no unbounded accumulation). An inadmissible DAG is rejected before it ever executes — impossible to do with arbitrary code.

**Evolution from what exists:** generalize `constraint-store.js`'s `target` (a fact field) into a *feature-DAG node*, and `expected` (a comparator) into a *model node*; turn `constraint-eval.js`'s comparator `switch` into a small **DAG interpreter** with a **primitive-kernel registry** (`welford-stats.js` and `history-store.js`'s percentile are the first *statistical* entries; `stat-diff.js`'s `lstat` metadata-diff is a *positive-evidence set-diff* primitive of a different family). Today's constraint families must re-express on the new IR with **byte-identical** evaluation (regression-locked), so the generalization ships behind existing behavior.

### Plane B — an earned-trust economy (fix for Vista UAC)

Promotion stops being a human click and becomes **a function of evidence, computed automatically.** The existing lifecycle states are reinterpreted as **authority tiers**, and a model's *power tracks its record*:

`shadow (observe only) → notify-only (may alert) → recommend (may propose containment) → act-on-recognition + notify (highest)`

These map directly onto AGENTS.md's Policy/Authority ladder: `shadow` ≈ read-only, `recommend` ≈ recommend-only, and `act-on-recognition + notify` ≈ AGENTS.md's *"autonomous action for narrowly scoped, tested, reversible cases only."* The economy is the *mechanism* that moves a model up that already-sanctioned ladder by evidence rather than by a toggle.

- **Earned:** a model climbs by *performing* — survives shadow-soak, backtests clean against history, then accumulates *corroborated* true-positives at a low false-positive rate.
- **Decaying + revocable:** trust decays; a model that regresses (rising FP-rate, disagreement with corroborators, firing in a known-good window) **auto-demotes** or is quarantined. Nothing is permanently blessed.
- **Corroboration replaces consent:** authority to *act* requires **N independent signals agreeing** (the immune two-signal / costimulation rule), not a human signature. Cross-host **ratification** from the federated topology is the strongest corroboration source.
- **Reversibility + circuit breakers + canarying** are the safety net instead of pre-approval: every active model is meta-monitored; new models canary on a slice; actions are reversible-by-default and auto-roll-back on regression.
- **The human is on the loop:** they set the **policy envelope** once (auto-promotion rules, corroboration thresholds per blast-radius, "always notify me on act") and **audit + veto + roll back** after the fact.

This repoints existing machinery rather than inventing it: `shadow-store.js` already records shadow/soak evidence; `calibration.js`/`tuning-*.js` already compute quality metrics and auto-tune. Those become the inputs to an **automatic** promotion function instead of a human review queue.

### Plane C — proactive behavioral modeling + divergence arbitration (fix for Skynet, and the agent's real job)

Each active model is continuously scored against ground truth, producing a **residual / divergence** stream. Divergence is not automatically an alarm; the agent **arbitrates** its cause — the doctrine's refine / adapt / alarm decision:

1. **model wrong/incomplete → refine**; 2. **benign concept drift → adapt**; 3. **the divergence *is* the threat → alarm (and, if earned, act)**.

This is the LLM agent's non-delegable role, and it is **adversarial**: an attacker wants case 3 misread as case 2 so the model adapts to accept them (boiling-frog poisoning). The governing rule: **never adapt to unattested change.** Adaptation is a *gated action* — allowed only when the change is corroborated by independent evidence (a package event explains a new binary; a maintenance window explains a load shift) and the underlying history is completeness-proven (`fact-store-integrity.js`). Adaptation is governed exactly as strictly as acting, because it is the same-sized attack surface.

**Adaptation is authoring.** The agent never mutates an active model in place. An "adapt" verdict *emits a new model version that enters at `shadow` and must earn its way back up* (Plane B's ladder, Slice 8's authoring path). This makes adaptation soak-gated by construction — no deterministic code has to trust the LLM's corroboration judgment, because the successor still has to survive the same evidence bar — and it bounds the boiling-frog attack structurally: a slow poisoner cannot walk an *active* model, only propose a chain of successors that each re-earn trust from `shadow`.

## 3. What we reuse (grounding)

| Need | Existing asset |
|---|---|
| Declarative IR seed | `constraint-store.js` record `{ family, target, expected }`; `constraint-eval.js` pure shared evaluator (already the seam between live tick and tuning backtest) |
| First primitive kernels | `welford-stats.js` (mean/variance, z-score, EWMA) + `history-store.js` (quantiles) as *statistical* kernels; `stat-diff.js` (`lstat` metadata-diff) as a *positive-evidence set-diff* primitive |
| Evidence + auto-tuning | `shadow-store.js` (soak), `calibration.js`, `tuning-store.js` / `tuning-authority.js` |
| Completeness gate (detect + adapt) | `fact-store-integrity.js`, `factHistoryTrustworthy` |
| Acting ceiling | `containment-recommend.js` (recommend-only), Slice-7 authority plane (future) |
| Corroboration at scale | federated topology + tamper-evidence attestation plans |
| The only LLM seam | `alert-intelligence.js` (rate-limited, audited, no-tools) — the pattern the offline authoring/arbitration seam mirrors |

## 4. Slice sequence (buildable, testable-first)

Each slice is additive, regression-locked against current behavior, and independently testable. Read-only / offline slices come before any hot-path change.

- **Slice 0 — doctrine + this plan.** Done (`docs/design/autonomy-doctrine.md`, this file).
- **Slice 1 — Model-IR v2 + DAG interpreter (pure, offline).** Generalize the record and the evaluator; stand up the primitive-kernel registry with the existing stats as its first members; re-express current constraint families with byte-identical evaluation under regression tests. No daemon behavior change.
- **Slice 2 — Static admissibility gate (pure).** Cost/memory/reference/bounded-state analysis of a DAG; reject inadmissible models before execution. Property-tested against adversarial DAGs (unbounded state, dangling references, budget blowups).
- **Slice 3 — First new kernels.** Bayesian counts (Beta-Bernoulli / Dirichlet / Poisson-Gamma surprise), changepoint (CUSUM / Page-Hinkley), and a rule-list/tree evaluator. Each pure, each backtested against recorded history. Upgrades the existing heuristic count-spike/drop and novelty detectors to rigorous families.
- **Slice 4 — Trust-economy state machine.** Reinterpret lifecycle states as authority tiers; make promotion an automatic function of shadow/soak/backtest evidence; add tier-scoped capability ceilings, trust decay, and auto-demote. Wired to `shadow-store`/`calibration`. Still recommend-only at the top.
- **Slice 5 — Meta-monitoring + circuit breakers.** Per-model FP-rate / corroboration / known-good-window monitors; auto-quarantine on regression; canary-slice rollout for new models.
- **Slice 6 — Corroboration engine.** The two-signal consensus gate; an "independence" model for signals; hook for federated ratification as the highest-corroboration source.
- **Slice 7 — Divergence arbitration (highest-stakes).** The residual stream; the refine/adapt/alarm decision surfaced to the agent with corroborating evidence; the **never-adapt-to-unattested-change** rule enforced via completeness + provenance + corroboration gating on *adaptation*; an "adapt" verdict emits a `shadow`-tier successor (Slice 8's path), never an in-place mutation. This is where the LLM enters, offline and audited, mirroring `alert-intelligence.js`'s budgeted no-tools pattern.
- **Slice 8 — Agent-authoring seam.** The LLM proposes model DAGs from its diagnosis; admissibility + soak + the trust economy admit them automatically at the `shadow` tier. Agent proposes; determinism + earned trust dispose.
- **Slice 9 — Policy envelope + audit/override surface.** The set-once operator policy (auto-promotion rules, corroboration thresholds by blast-radius, act-notification); the audit log + veto + rollback CLI/surface. This is the operator's entire ongoing touchpoint.
- **Slice 10 — Tier-B sandboxed expression hatch (deferred).** Only if Tier A provably pinches. Fuel/memory-bounded, deterministic, no I/O.

## 5. Safety invariants (preserved + extended)

- **Declarative-only in the hot path** — models are specifications, never code (until the caged, fuel-bounded Tier B, which is itself statically analyzable).
- **Autonomy scales with `reversibility × corroboration`, never attention** — the ceiling on *acting* lifts only by earned trust + corroboration + reversibility; never a consent prompt.
- **Never adapt to unattested change** — adaptation is completeness-, provenance-, and corroboration-gated, as strictly as acting.
- **Never fabricate; completeness-gated** — unchanged from the shipped substrate, now also covering adaptation.
- **Recommend-only until a governed authority plane exists** — this plan adds no host mutation.
- **Fully audited + reversible; default-OFF** behind `learned.json`.

## 6. Open questions / decisions needing sign-off

Named now so they are not silently resolved in code (mirrors the roadmap's flagged-defaults discipline):

1. **Corroboration thresholds and "independence."** What N, per blast-radius tier? What makes two signals *independent* enough to count as corroboration rather than one signal double-counted?
2. **Arbitration false-negative risk** — the core danger: an attacker successfully framing malice as benign drift. *Structurally answered in part:* adaptation is authoring (a `shadow`-entering successor that must re-earn trust), so no adaptation is ever an instant in-place mutation. The residual questions: what minimum corroboration + completeness proof is required before the agent may even *propose* an adaptation, and how to detect **slow multi-step poisoning** — a chain of individually-plausible successors that together drift the baseline onto an attacker (a rate-limit / cumulative-drift budget on successive adaptations of the same lineage).
3. **Where the LLM sits.** Offline authoring + arbitration only (proposed), never in the hot tick. Its rate/cost budget and audit trail (extend the `alert-intelligence.js` model).
4. **The auto-act tier.** Does reaching `act-on-recognition` require federated ratification (cross-host corroboration), or can single-host corroboration suffice for the most-reversible actions? This is the sharpest governance line and needs an explicit operator decision.
5. **Runtime / memory floor.** Kernels are KB; the Node daemon is tens of MB. If low-memory on-device is a hard requirement, this accelerates the Rust durable-core re-anchoring — independent of model families. Decide the Rust boundary before Slice 3+ kernel proliferation.
6. **Real-time dependency.** "Near-real-time" needs the deferred event-source path un-deferred; cheap kernels are necessary but not sufficient. Sequence that relative to this plan.
7. **IR versioning / migration** of already-active mined constraints onto Model-IR v2 (Slice 1 must not orphan or silently re-interpret live artifacts).

## 7. Success criteria

- The agent authors a novel, admissible behavioral model for *this* host (feature + family + hyperparameters it chose) that a human did not pre-build — and it is neither a menu pick (not Clippy) nor human-approved per-item (not UAC).
- That model climbs from `shadow` to `notify-only` **automatically on evidence**, and **auto-demotes** when deliberately regressed — no human click on either transition.
- A benign change is *adapted to* only with corroboration, and a simulated boiling-frog attack is *not* adapted to (it alarms) — the arbitration holds under adversarial pressure.
- Every promotion, adaptation, and (future) action is audited, reversible, and notified — the operator can reconstruct and undo any of it (not Skynet).
