# Proactive Behavioral Modeling — Agent-Authored Models, an Earned-Trust Economy, and Divergence Arbitration

**Created:** 2026-09-03
**Reviewed:** 2026-09-03 (five-lens document-review gate — adversarial, security, feasibility, coherence, scope-guardian, run in parallel) — **NEEDS REWORK**. Five blockers (four on Plane B/C authorization + one on Slice-1 scoping), grounded in the existing code, recorded in the "Review outcome" section below and to be folded in the rework. **Plane A (the compositional DAG IR + static admissibility as the anti-Clippy mechanism) validated as sound; the recommend-only / no-host-mutation envelope confirmed intact.** Threat-model posture **decided 2026-09-03** (staged: attestation-gated above notify-only, additive-only below, with a labeled lab/VM toggle — see "Review outcome"); the body was **reworked in place the same day** to fold every must-fix (§§2, 4, 5–7) and the doctrine updated to match.
**Status:** **REWORKED 2026-09-03** per the five-lens gate. Direction intact (Plane A sound); the trust-economy and arbitration planes were rebuilt around an *attested/fed* ground-truth oracle, the attestation gate (additive-only below, off-host root-of-trust above notify-only), and a runtime budget for agent-authored DAGs; the act tier was pulled to the Slice-7 authority-plane doc; the slices were re-sequenced spike-first. **Committed next step: the Slice-1 spike** (own dedicated plan at pickup). Anything above notify-only is blocked on the off-host attestation layer, by design.
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
6. **Anti-poisoning:** a per-lineage cumulative-drift *and* adaptation-rate budget anchored to an *attested* baseline (an arbitration-slice prerequisite, not a knob — "re-earn from shadow" measures fit-to-recent-history, which the poisoner controls); a hard cap on candidate-DAG admission rate into soak; and the same charset/sanitization discipline on the authoring/arbitration LLM prompt as on the alert prompt (fact content is attacker-influenceable → prompt injection, and `model_pattern` sends it off-host).
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

- **Committed next:** Slice 1 — **the spike** (a thin *vertical* slice through IR → one kernel → a minimal auto-promote-to-notify-only ladder → one agent-authored DAG, run in the lab/VM posture, ending in a **written go/no-go**). This gets its own dedicated plan at pickup; the review (scope-1 / feasibility-1) explicitly rejected committing a horizontal IR + analyzer foundation ahead of a proven consumer.
- **Gated on the spike's "go":** Slices 2+ (the horizontal build-out — fuller algebra + kernels, the runtime budget, the full attestation-gated trust economy, corroboration, arbitration, policy/audit). Schemas, kernel families, thresholds, and CLI surfaces named below are **provisional design intent to validate at the spike's go/no-go**, not contracts. Each slice-group gets its own `docs/plans/` file when picked up.
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

The generativity is in **composition**: fixed, audited primitives; unbounded pipeline space. Real-world precedent — **YARA** rules are a bounded, declarative, no-arbitrary-code pattern language that AV engines author, sign, ship, and evaluate cheaply on-host: the same shape this IR takes.

Three tiers of authoring power, added in order of need:

- **Tier A (workhorse):** the algebra above, **split by cost class (review B3):** *structurally-bounded* reductions (`window`/`rate`/`delta`/`ratio`/`lag`/`log`/`ewma`/`zscore`/`quantile` over a retention-bounded window — bounded by window length, cheap, statically checkable) vs *cardinality-sensitive* ops (`count_distinct`/`groupby`/`join` — memory scales with runtime cardinality, **not** a static property of the DAG). The latter are **not** admissible on static analysis alone.
- **Tier B (frontier, deferred):** a sandboxed hatch for a novel transform the algebra cannot express — two *distinct* boundary specs, not interchangeable: a non-Turing-complete expression language (CEL-style, comprehension/cost limits explicitly enabled) *or* a WASM module (pinned single engine+version, FP/NaN-deterministic, **zero host imports / no WASI**, compile-bomb + module-size limits, a `memory.grow` cap, strict fuel). Its safety is **runtime-enforced, not static** — the two must not be conflated.
- **Tier C (grow the language):** a human-reviewed new *primitive kernel* joins the audited registry, and **must carry a formal per-primitive cost/memory contract at registration** (so a future string/regex primitive cannot reintroduce the ReDoS that today's fixed `ends_with:` matcher cannot).

**Admissibility = static validation + a runtime budget.** For structurally-bounded, hand-authored DAGs, static analysis suffices — valid **metric references** (every input resolves to something collected) + **arity/type** + **bounded state**. For cardinality-sensitive *or* agent-authored DAGs it does **not**: because a Slice-1-authored DAG *executes* in the hot path, an admissible-*looking* one can DoS/OOM the daemon, and a monitor that misses ticks is itself a blind-spot attack (review B3). Those carry the **same runtime budget the plan reserves for Tier B** — per-model fuel + row + distinct-state ceilings, hard caps on `count_distinct`/`groupby` (reservoir/sketch), a max-window bound, and a **survivable mid-evaluation abort** (no torn state, no missed tick beyond that model). Any cap that truncates a result must **degrade to silence, never report a wrong number** (completeness-gated).

**Confidentiality (review, security-3):** the feature algebra reads **only hashed/bucketed fields** — raw identity (PIDs, ports, users, hosts, IPs, paths) is reachable *only* through a hashing primitive — and agent-authored diagnostics are constrained to a **closed number/enum/hash schema**, enforced *before* persistence or any boundary crossing. `sanitizeDiagnostics` today is only a charset gate (it passes a raw `host.example.com`), and the audit trail is federated, so raw identifiers must never be author-selectable into it.

**Evolution from what exists:** generalize `constraint-store.js`'s `target` (a fact field) into a *feature-DAG node*, and `expected` (a comparator) into a *model node*; turn `constraint-eval.js`'s comparator `switch` into a small **DAG interpreter** with a **primitive-kernel registry** (`welford-stats.js` and `history-store.js`'s percentile are the first *statistical* entries; `stat-diff.js`'s `lstat` metadata-diff is a *positive-evidence set-diff* primitive of a different family). Today's constraint families must re-express on the new IR with **byte-identical** evaluation (regression-locked), so the generalization ships behind existing behavior.

### Plane B — an earned-trust economy (fix for Vista UAC)

Promotion stops being a human click and becomes **a function of evidence the system gathers or is fed — never per-item consent** (the UAC fix). The authority tiers:

`shadow (observe only) → notify-only (additive alerts only) → [ATTESTATION GATE] → recommend`

- **The currency is not what the plan first claimed (review B1).** `calibration.js` is explicit and verified: *there is no ground-truth incident signal in the codebase*; `recall_proxy` is always `null` by design. The only on-host metric is a **precision proxy** (a documented lower bound whose numerator includes `llm_suppressed`) — usable to detect *regression* (measure DOWN), never to prove *competence* (measure UP), and circular with Plane C if used to promote.
- **UP-promotion needs a positive ground-truth oracle, and it is *fed*, not minted** (the AV lesson): **operator-supplied labels + seeded/synthetic red-team fixtures + injected known-bad events.** A model earns a tier by *catching seeded bad and staying quiet on seeded good* — demonstrated competence, not survivorship (which is all "no caught FP" proves — review, adversarial-6). This is **labeling, not consent**: it keeps the human as the ground-truth source "human on-the-loop" always needed, without a Cancel-or-Allow prompt.
- **The attestation gate (operator decision, 2026-09-03).** `shadow → notify-only` runs on-host, and a notify-only model is **additive-only** — it may raise alerts, never suppress/whitelist — so a forged on-host model cannot *blind* the monitor. **Everything above notify-only** (recommend, sticky adaptation, any future acting) is a **hard precondition on off-host attestation** (the tamper-evidence + federated-ratification layer), because on one host every "independent" signal *and* the completeness proof share a single failure mode (host compromise) and are forgeable at daemon uid (review B2). The lab/VM posture may relax this gate for red-teaming; production may not.
- **"Independence" is definitional, not a tunable threshold (review B2):** two signals corroborate only if they do **not** share author, host-evidence lineage, or derivation. On a single host that set is essentially empty — which is *why* real corroboration is cross-host ratification.
- **Decaying + revocable, with a guard:** trust decays and a regressing model auto-demotes/quarantines — but auto-demoting an *established, legitimate* detector needs its own **anomaly-of-anomaly guard**, or an attacker who poisons a good detector's inputs gets it auto-quarantined and disables the defense (review, security-1b).
- **Predecessor-supersession is load-bearing and must be specified:** when an adapted successor promotes, does its predecessor retire or coexist? Retire ⇒ a recommend-only *blinding* path; never-retire ⇒ adaptation never changes what fires. Resolved in the rework, not left implicit.
- **The human is on the loop:** sets the **policy envelope** once (oracle/label sources, tier thresholds, the attestation requirement, "always notify on the acting path") and **audits + vetoes + rolls back** after the fact.

The **act tier is deliberately not in this ladder (review, adversarial-4 / scope-4).** Today's recommend-only is the documented *absence* of an execution primitive (`containment-recommend.js` — no `child_process`, no capability token, enforced by boundary tests); adding one gated by a computed score is a discontinuity, not a rung. The execution primitive and its acting-governance belong to the **Slice-7 authority-plane's own reviewed doc**; this plan tops out at recommend, and the kill switch must be checked **per-action** on any future acting path.

This repoints some machinery — `shadow-store.js` records soak evidence, `calibration.js`/`tuning-*.js` compute the precision proxy — but the evidence-scored auto-promotion decision function **plus** the decay/demote/quarantine machine are **net-new safety-critical scope** that *coexists* with the retained human-nonce path (`promotion-store.js`/`tuning-authority.js`, kept as an operator policy option), not a free "repointing" (review, scope-2).

### Plane C — proactive behavioral modeling + divergence arbitration (fix for Skynet, and the agent's real job)

Each active model is continuously scored against ground truth, producing a **residual / divergence** stream. Divergence is not automatically an alarm; the agent **arbitrates** its cause — the doctrine's refine / adapt / alarm decision:

1. **model wrong/incomplete → refine**; 2. **benign concept drift → adapt**; 3. **the divergence *is* the threat → alarm (and, if earned, act)**.

This is the LLM agent's non-delegable role, and it is **adversarial**: an attacker wants case 3 misread as case 2 so the model adapts to accept them (boiling-frog poisoning). The governing rule: **never adapt to unattested change.** Adaptation is a *gated action* — allowed only when the change is corroborated by independent evidence (a package event explains a new binary; a maintenance window explains a load shift) and the underlying history is completeness-proven (`fact-store-integrity.js`). Adaptation is governed exactly as strictly as acting, because it is the same-sized attack surface.

**Adaptation is authoring — but that alone does not stop the boiling frog (review, adversarial-3).** The agent never mutates an active model in place; an "adapt" verdict *emits a new model version that enters at `shadow`*. But shadow-soak measures *fit to recent history*, and recent history is exactly what a slow poisoner controls — so a chain of individually-plausible successors can walk the baseline onto the attacker while every hop passes the same fit bar. The defenses that actually bound this:

- a **per-lineage cumulative-drift AND adaptation-rate budget**, anchored to an **attested baseline** (not to rolling recent history) — a prerequisite for the arbitration slice, not a tuning knob;
- a **hard cap on candidate-DAG admission rate into soak** — the LLM must not be able to flood the pipeline searching for an adversarial-but-admissible model;
- the **same charset/sanitization discipline on the authoring/arbitration prompt** as on the alert prompt — the residual/divergence stream is attacker-influenceable fact content (process names, paths, peer data), so prompt injection can bias arbitration toward "adapt," and `model_pattern` sends that input **off-host**, so it is sanitized before it leaves.

And per Plane B, *any* adaptation that changes what a model suppresses/whitelists sits **above the attestation gate** — so on-host, in production, adaptation is bounded to additive-only until attested.

## 3. What we reuse (grounding)

| Need | Existing asset |
|---|---|
| Declarative IR seed | `constraint-store.js` record `{ family, target, expected }`; `constraint-eval.js` pure shared evaluator (already the seam between live tick and tuning backtest) |
| First primitive kernels | `welford-stats.js` (mean/variance, z-score, EWMA) + `history-store.js` (quantiles) as *statistical* kernels; `stat-diff.js` (`lstat` metadata-diff) as a *positive-evidence set-diff* primitive |
| Evidence + auto-tuning | `shadow-store.js` (soak), `calibration.js`, `tuning-store.js` / `tuning-authority.js` |
| Completeness gate (detect + adapt) | `fact-store-integrity.js`, `factHistoryTrustworthy` |
| Acting ceiling | `containment-recommend.js` (recommend-only), Slice-7 authority plane (future, own doc) |
| Off-host root-of-trust (the hard gate above notify-only) | `docs/plans/2026-08-21-tamper-evidence-attestation-design.md` + the federated-topology plan — the AV/EDR cloud-backend + dead-man's-switch + TPM analog |
| Positive ground-truth oracle (net-new) | operator labels + seeded/synthetic red-team fixtures + injected known-bad — *because there is no on-host incident signal* (`calibration.js`) |
| Rule-IR precedent | **YARA** — a bounded, declarative, no-code rule language, curated + signed + shipped |
| The only LLM seam | `alert-intelligence.js` (rate-limited, audited, no-tools) — the pattern the offline authoring/arbitration seam mirrors (with prompt sanitization added) |

## 4. Slice sequence (buildable, testable-first)

**Re-sequenced to spike-first (review, scope-1 / feasibility-1).** The prior sequence built the horizontal framework (an IR + an admissibility analyzer) before any consumer proved its shape — and put the *hard* half (the windowed/series contract) in the design-sketch tier while calling the *easy* half (the scalar comparator) the foundation. Instead, a thin **vertical** slice proves the thesis and decides the framework's real shape at a go/no-go; the horizontal build-out is gated on that.

- **Slice 0 — doctrine + this plan + this review.** Done.
- **Slice 1 — the SPIKE (thin vertical slice → written go/no-go).** One end-to-end path, no framework:
  - a *thin* IR generalization carrying the **windowed/series input contract** (not just the scalar comparator seam — the real work, review B4) with explicit **missing-input → silence** semantics; **dual-read versioning** (v1 records stay v1 on disk and evaluate on the v1 path; v2 is a byte-identical parallel proof; **never an in-place migration of active records** — review feasibility-4); and a **baseline-detector byte-identical regression lock** (e.g. `peer.count_spike` z-score) *in addition to* a scalar-constraint lock;
  - **one** new kernel — the single family the demo model needs; no registry build-out (no kernel without a live consumer);
  - a **minimal auto-promote-to-notify-only ladder** (additive-only, on-host) driven by the **seeded-fixture oracle**: a model earns notify-only by catching seeded-bad / staying quiet on seeded-good, and auto-demotes when regressed (a minimal FP-monitor from `shadow-store` pulled in so promote + demote are one loop — review feasibility-3);
  - the **authoring seam** admitting **one** LLM-proposed DAG end-to-end (admissibility here = reference + arity validation, not the full budget analyzer — review scope-5), diagnostics constrained to the closed schema;
  - run under the **lab/VM posture in the tart CI VMs** (this host cannot virtualize), including a **red-team boiling-frog fixture** the model must alarm on rather than adapt to.
  - **Go/no-go output:** the IR's real shape, the kernel vocabulary actually needed, the **Node-vs-Rust boundary**, and **stateless-recompute vs incremental-state** (cost vs a state-poisoning surface) are decided *here*, on measured evidence — not predicted up front.
- **Slices 2+ (GATED on the spike's "go") — the horizontal build-out**, each its own dedicated plan at pickup: the fuller feature algebra + kernels (each only when a live model needs it); the **runtime budget + survivable abort** for cardinality/agent-authored DAGs; the full trust economy (attestation-gated tiers, decay/demote/quarantine with the anomaly-of-anomaly guard, meta-monitoring); the **corroboration engine** (independence *defined*, cross-host ratification); **divergence arbitration** with the per-lineage drift budget; the recurring scoring/meta-monitoring work given an explicit **daemon cadence/home** (review feasibility-5); and the **policy + audit/override** surface (the operator's whole ongoing touchpoint).
- **The attestation layer is a hard upstream dependency** for anything above notify-only (`docs/plans/2026-08-21-tamper-evidence-attestation-design.md` + the federated-topology plan). Build-out above the gate is blocked on it, by design.
- **The act tier is out of this plan** → the Slice-7 authority-plane's own reviewed doc.
- **Tier-B hatch — deferred**, specified per §2 Plane A's hardening list when picked up.

**One state model (review, scope-6 / coherence).** The existing maturity lifecycle (`draft→shadow→review-ready→active→retired→quarantine`) and the new *authority* axis (`shadow→notify-only→recommend`) must be reconciled into a single source of truth *before* Slice 1 wires promotion; migration covers lifecycle states, not just IR fields.

## 5. Safety invariants (preserved + extended)

- **Declarative-only in the hot path** — models are specifications; the only code path is the caged, fuel-bounded Tier-B hatch, which is **runtime-enforced, not "statically analyzable."**
- **Admissibility = static validation + a runtime budget** — structurally-bounded hand-authored DAGs pass on static checks; cardinality-sensitive *or* agent-authored DAGs also carry a runtime fuel/row/state budget with a survivable abort; any truncation degrades to silence, never a wrong number.
- **Hashed-fields-only algebra + closed diagnostics schema** — raw identity only via a hashing primitive; agent-authored output cannot carry raw identifiers into notifications, the audit trail, or federation.
- **Attestation-gated authority** — on-host tops out at notify-only (additive-only; cannot suppress/whitelist or act); recommend, sticky adaptation, and acting hard-depend on off-host attestation. "Independence" excludes same-host / same-author lineage *by definition*.
- **UP-promotion on demonstrated competence, not survivorship** — an attested/seeded positive oracle, never absence-of-caught-FP; the precision proxy measures *regression* only.
- **Never adapt to unattested change** — adaptation is authoring + completeness/provenance/corroboration-gated + bounded by a per-lineage cumulative-drift budget anchored to an attested baseline.
- **Autonomy scales with `reversibility × corroboration`, never attention.**
- **Recommend-only** — this plan adds no execution primitive; the kill switch is checked **per-action** on any future acting path.
- **Never fabricate; completeness-gated; fully audited + reversible; default-OFF** behind `learned.json`.

## 6. Open questions / decisions needing sign-off

The 2026-09-03 review reclassified several prior "open questions" (see Review outcome). **Now decided or hard-preconditions:** the threat-model posture (staged, attestation-gated — *decided*); "independence" (definitional, not a tunable N); federated ratification above notify-only (*hard precondition*, not optional); IR migration (a Slice-1 *precondition* — dual-read, never in-place). **Genuinely open, to settle with spike data or an explicit operator call:**

1. **Oracle mechanics** — the concrete form of operator labels + seeded red-team fixtures + injected known-bad, and the competence bar per tier.
2. **Drift-budget parameters** — the per-lineage cumulative-drift and adaptation-rate ceilings, and the attested baseline they anchor to.
3. **Predecessor-supersession** — retire vs coexist when a successor promotes (load-bearing; decide before the arbitration slice).
4. **Node-vs-Rust boundary and stateless-vs-incremental** — decided *at the spike's go/no-go*, on measured recompute×model cost, not predicted.
5. **Real-time dependency** — the deferred event-source path; cheap kernels are necessary, not sufficient, for near-real-time. Sequence relative to this plan.
6. **LLM seat + budget** — offline authoring/arbitration only, never the hot tick; rate/cost budget + sanitized prompt + audit, extending `alert-intelligence.js`.

## 7. Success criteria

**Spike (Slice 1) go/no-go bar:**

- The agent authors **one** novel, admissible behavioral model for *this* host (feature + family + hyperparameters it chose) that a human did not pre-build — neither a menu pick (not Clippy) nor human-approved per-item (not UAC).
- It climbs `shadow → notify-only` **automatically**, driven by the **seeded oracle** (catches seeded-bad, quiet on seeded-good — competence, not silence), and **auto-demotes** when deliberately regressed — no human click on either transition.
- Under the **lab/VM red-team**: a **boiling-frog fixture is alarmed on, not adapted to**; a **forged on-host "known-good" cannot blind the monitor** (additive-only holds); and an **admissible-looking DoS DAG is refused or survivably aborted** with no missed tick beyond itself.
- Every promotion, adaptation, and refusal is **audited and reversible**, carries **no raw identifiers**, and the run yields the written decisions (IR shape, kernel vocabulary, Rust boundary, stateless-vs-incremental).

**Whole-subsystem (post-go):** the above holds at fleet scale with cross-host ratification as the corroboration source, and **nothing above notify-only runs without the off-host attestation layer**.
