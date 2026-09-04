# Slice 1 — Behavioral-Model Spike (thin vertical slice → written go/no-go)

**Created:** 2026-09-03
**Status:** In progress — **spike** (time-boxed decision aid; "skip it / pivot" is a valid outcome).
**Progress:** 2026-09-03 — **§8 steps 1–2 landed** (`80031d4`): `src/model-ir.js` — the thin v2 IR + pure DAG interpreter (feature ops `fact`/`latest`/`window`/`zscore`, model op `threshold`), missing-input→silence, dual-read routing, and the **two byte-identical regression locks** (`threshold` reuses `evaluateExpected`; `zscore`/`window` reuse the welford primitives — identical *by construction*). Pure/offline, additive (no existing file touched), 24 new tests, suite 1621/1587-pass/0-fail. Two IR-shape questions surfaced for §6 (below). **§8 step 3 (CUSUM kernel) landed** (`f1d8d28`): a new `cusum` feature op (two-sided tabular; `target: number|"mean"`, reusing `foldWelford`), golden-locked against an independent reference + injected-changepoint-fires/stable-quiet + full silence coverage; additive, suite 1633/1599-pass.

**Decision for step 4 (from step 3, flag #1):** author bounded-statistic detectors (CUSUM etc.) as `threshold {comparator:"lte", value:h}` invariants — *"the statistic should stay ≤ h"* — so a crossing (statistic > h) is a **violation → `fired:true`**, consistent with v1's alarm=violation semantics (`evaluateModelNode` sets `fired:!satisfied`; a naive `gte h` framing inverts `fired`). (Corrected from an earlier "lt|lte": `evaluateNumericComparator` implements only `gte`/`lte`/`eq` — there is no `lt` comparator.) Minor step-3 flags for §6: `k` accepts negatives; `Number([])→0` coercion accepts `target:[]`; `rate` transform not built (counter metrics only).

**§8 step 4a (pure seeded-oracle ladder) landed** (`802d774`): `src/model-ladder.js` — `runOracle` (competence, **not** survivorship: promotion needs ≥1 caught seeded-bad **and** ≥1 quiet seeded-good; empty / one-sided / never-fires oracles all fail closed), `decideModelPromotion` (`shadow → notify-only`), `decideModelDemotion` (notify-only → shadow on a caught false-positive). 22 tests, additive, suite 1658/1624-pass. Three items for the §6 go/no-go: **(a)** the `now`-footgun — the promotion-decision clock must not leak into each historical fixture's window evaluation (fixed here; the VM daemon step must not reintroduce it); **(b)** the **`observations` seam gap** — `shadow-store.js` records don't tag which soak observations were seeded-good vs seeded-bad, so the VM step must add that tag or the demote loop has no real input; **(c)** the **false-*negative* demote trigger is unimplemented** — a notify-only model that goes *quiet on seeded-bad* (the boiling-frog shape, plan §5) is not currently a demote trigger; decide whether the VM step needs it.

**Runway note:** steps 1–3 + 4a were all pure/offline and are **done**. Everything remaining — **4b** (wire the ladder into the daemon under the lab posture), **5** (authoring seam), **6** (red-team) — needs the **tart CI VMs**, so the spike is now genuinely gated on that infra.

**§8 step 4a HARDENED — 3 daybreak-blue adversarial rounds, verdict READY (`787d31a`).** `gpt-daybreak-blue-latest` (frontier defensive-cyber model via codex — see [[daybreak-blue-security-reviewer]]) reviewed the trust-economy core across three TDD rounds and found a **blocker + ~20 real issues** the Sonnet-author / advisor / Opus-review chain all passed: a getter-TOCTOU (grade one object, promote another), forge-your-own-oracle, `SharedArrayBuffer`/`Date` aliasing surviving `structuredClone`, prototype-lookup + `minSamples`-crash + overflow fabrications, competence-vs-survivorship holes, and more — all now **closed and regression-locked**. Root-cause fix: fixtures are a caller-supplied trusted arg (not read off the model), and every untrusted input is **JSON-round-trip canonicalized once, in a safe order**, so the graded object == the promoted object == the persisted form. Final verdict: **READY for schema-valid plain-JSON inputs from a trusted ingestion boundary**; Lock A byte-identical; suite 1723 / 1689-pass. **daybreak-blue is the designated security reviewer for the step-6 red-team.**

**Security go/no-go items for the attestation-gated build-out (daybreak-CONFIRMED not blockers; deferred by contract):**
- **(a)** Full observation **authentication** — provenance, replay-once consumption, observation↔fixture identity, binding to the evaluated model-content digest. The pure layer requires `supported:true` + a valid unique string id; *where observations come from* is the daemon/shadow-store + attestation seam.
- **(b)** The full runtime **budget analyzer** — unbounded model count, nested-unary re-processing of a capped series, DAG width. The pure layer has only the minimal count caps (`MAX_ORACLE_FIXTURES` / `MAX_SERIES_POINTS`).
- **(c)** A trusted / monotonic decision **clock** (audit stamps + future-timestamp-skew bounds on live series).
- **(d)** The **plain-JSON ingestion contract**: 4 residual LOWs require a hostile in-process *live-object* caller (getters / Proxies / `toJSON` / non-JSON numbers), precluded when records are JSON-deserialized off disk. **Slice 4b (daemon wiring) MUST feed these functions plain-JSON data only** — that is the contract the hardening is verified against.
**Origin:** Slice 1 of `docs/plans/2026-09-03-proactive-behavioral-modeling.md` (reworked spike-first by the 2026-09-03 five-lens gate). Governed by `docs/design/autonomy-doctrine.md`.
**Owner:** unassigned
**Todo:** tracked under [`todos/2026-07-09-self-learning-stratified-monitoring.md`](../../todos/2026-07-09-self-learning-stratified-monitoring.md).

> Thin, additive, regression-locked, offline-testable-first. Runs only in the **lab/VM posture** (attestation gate OFF, clearly labeled non-production). **NO code in this document.**

**Related / code:**
- Parent plan: `docs/plans/2026-09-03-proactive-behavioral-modeling.md` (§4 Slice 1, the "Review outcome" must-fixes, the staged/attestation-gated decision).
- Grounding: `src/constraint-eval.js` + `src/constraint-store.js` (the flat IR to generalize *thinly*), `src/welford-stats.js` + `src/peer-baseline.js` (the *windowed/series* seam the spike must unify with the scalar one), `src/shadow-store.js` (soak evidence + the minimal FP-monitor), `src/fact-store.js` (`facts.jsonl`, `readFactPoints`), `src/fact-store-integrity.js` (completeness gate), `src/alert-intelligence.js` (the budgeted no-tools LLM-seam pattern the authoring seam mirrors).

---

## 0. Purpose, discipline, and time-box

Prove — or disprove — the plan's central thesis on **one** end-to-end example, cheaply, before committing the horizontal framework. This is a **decision aid**, not a foundation: its deliverable is a **written go/no-go** plus four decisions the framework's shape depends on. If the thesis does not hold (authorship too brittle, the cost model bad, the red-team wins), **the correct outcome is to say so and stop or pivot** — not to harden the spike.

- **Time-box:** a small, bounded effort. If it is sprawling into a framework, that is the NO-GO signal, not a reason to keep going.
- **Non-negotiable throughout:** default-OFF behind `learned.json`; **lab/VM posture only** (this is where the attestation gate is legitimately relaxed — the spike must refuse to run its economy outside a posture explicitly flagged non-production); **additive-only** (a spike model may raise alerts, never suppress/whitelist); **no host mutation**; runs in **disposable tart CI VMs** (this dev host has no Virtualization.framework — see [[descartes-dev-machine-no-virtualization]]).

## 1. The thesis to prove (the go/no-go bar)

All of these, on one host, in the lab posture:

1. **Authorship (not Clippy).** The agent authors **one** novel, admissible behavioral model for *this* host — a feature it engineered + a family + hyperparameters it chose — that a human did not pre-build. It is neither a menu pick nor human-approved per-item.
2. **Earned promotion (not UAC).** That model climbs `shadow → notify-only` **automatically**, driven by a **seeded-fixture oracle** (it catches seeded-bad and stays quiet on seeded-good — *competence, not silence*), and **auto-demotes** when deliberately regressed. No human click on either transition.
3. **Survives the red-team.** A **boiling-frog** fixture is alarmed on, not adapted to; a **forged on-host "known-good"** cannot blind the monitor (additive-only holds); an **admissible-looking DoS DAG** is refused or survivably aborted with no missed tick beyond itself.
4. **Accountable.** Every promotion, adaptation, and refusal is **audited and reversible** and carries **no raw identifiers** (closed diagnostics schema; hashed fields only).

## 2. In scope — the thin vertical slice

Exactly enough to carry one model end-to-end; no more.

1. **A thin IR generalization** — *not* the full algebra. Enough to express the demo model, and it must carry the **windowed/series input contract** (the real work — the scalar `evaluateExpected` seam is the trivial half; the operators that matter need the *series*, which today lives only in `welford-stats.js`/`peer-baseline.js`). Define **missing-input → silence** semantics explicitly (a windowed feature with too few / degraded points emits nothing, never a fabricated value). **Dual-read versioning:** v1 records stay v1 on disk and evaluate on the v1 path; the v2 DAG is a **byte-identical parallel proof** — **never an in-place migration of active records**.
2. **One new kernel** — the single family the demo needs; no registry build-out (no kernel without a live consumer).
3. **A minimal auto-promote ladder** — `shadow → notify-only` only, **additive-only**, driven by the seeded oracle; **auto-demote on regression** wired in the same loop (a minimal FP-monitor read from `shadow-store.js`), so promote and demote are one control loop, not two slices.
4. **The authoring seam** — the LLM proposes **one** DAG from a triage-style diagnosis; **admissibility here = reference-resolution + arity/type validation only** (not the full runtime budget analyzer); the prompt is **sanitized** like the alert prompt (fact content is attacker-influenceable); diagnostics constrained to a **closed number/enum/hash schema**.
5. **Two regression locks** — one scalar constraint family *and* one baseline detector (proposed: `peer.count_spike` z-score) re-expressed **byte-identically** on the v2 IR, so the generalization ships behind proven behavior.

## 3. Explicitly OUT of scope (deferred to the post-go build-out)

Naming these keeps the spike thin: the full feature algebra; multiple/other kernels; the **runtime budget analyzer** (beyond ref/arity validation — the DoS red-team is met with a *simple* per-model fuel/row cap + abort, not the full analyzer); the **real** attestation gate and cross-host corroboration (the spike runs gate-off in the lab); the `recommend` tier and any execution primitive; the policy/audit *surface* (a raw audit log is enough); Rust (spike stays Node unless the go/no-go says otherwise); the Tier-B hatch; the two-lifecycle reconciliation as a finished model (the spike may stub it, but must not entrench a second state machine).

## 4. The demo model (concrete, so the spike is real)

Proposed default (decide at spike start): the agent authors a **CUSUM changepoint** kernel over a **windowed rate** of one resource metric already in `facts.jsonl` (e.g. memory-pressure or load — chosen for clean, seedable dynamics), i.e. `cusum( rate( window(w, metric) ) )` with agent-chosen `w` and CUSUM threshold/drift. This proves **composition** (windowed feature) **+ a genuinely new family** (changepoint, beyond today's z-score/EWMA) **+ authorship** in one model, and it is trivially seedable (inject a known regime change = known-bad; normal variation = known-good). If a security-flavored metric (peer-login or scheduled-job count) proves as seedable, prefer it — but do not let metric choice expand scope.

## 5. Test & red-team plan

TDD throughout; offline/pure tests before any daemon wiring.

- **Regression locks (pure):** the scalar family and the `peer.count_spike` z-score evaluate byte-identically on the v2 IR (golden fixtures).
- **Missing-input semantics (pure):** degraded/short windows → silence, asserted directly.
- **Oracle (pure→VM):** seeded known-bad ⇒ the model fires and earns `notify-only`; seeded known-good ⇒ it stays quiet; a deliberately degenerate (never-fires) model does **not** climb (competence, not survivorship).
- **Red-team (VM):**
  - *Boiling-frog* — a slow multi-step drift fixture: the model must **alarm**, and any "adapt" must emit a `shadow`-tier successor that the drift-budget refuses to promote — not silently move the baseline.
  - *Blinding* — a forged clean soak/"known-good" for a model that never fires on the injected bad: additive-only must mean it **cannot suppress** the real detector's alert.
  - *DoS DAG* — an admissible-*looking* high-cardinality/large-window DAG: the simple fuel/row cap **refuses or survivably aborts** it with no missed tick beyond that model.
- **Environment:** all daemon-wired + red-team tests run in **disposable tart CI VMs**; Linux-only paths gated per [[descartes-dev-machine-no-virtualization]] (cross-target `cargo check` locally + CI execution).

## 6. Go/no-go — the written decisions the spike produces

The spike is not "done" until it writes these down (they are what the horizontal build-out needs):

1. **IR shape** — did the thin windowed/series contract generalize cleanly, or did it fight the flat evaluator? What does v2 actually need to be? *Surfaced by step 1:* (a) does `zscore` score the latest point **inclusive** of the window (step-1 default; byte-identical to a direct welford fold) or **exclusive** (peer-baseline's self-dampening convention)? (b) on a non-finite point, silence the **whole window** (step-1 default; conservative never-fabricate) or **drop just that point**?
2. **Kernel vocabulary** — which families are actually pulled by real authored models (vs the aspirational "dozen")?
3. **Node-vs-Rust boundary** — measured recompute×model cost and memory floor: does the durable core need to move to Rust before build-out, or not yet?
4. **Stateless-recompute vs incremental-state** — the measured cost vs the state-poisoning surface each opens.
5. **Proceed / pivot / skip** — does the thesis hold well enough to commit Slices 2+? **A NO-GO is a legitimate, valuable result.**

## 7. Safety during the spike

- Default-OFF behind `learned.json`; the economy **refuses to run** outside a posture explicitly flagged **lab/non-production**.
- **Additive-only**; **no host mutation**; **recommend/act tiers absent**.
- Completeness-gated inputs (`fact-store-integrity.js`); missing/degraded → silence.
- Hashed fields only; closed diagnostics schema; sanitized authoring prompt; raw audit log carries no raw identifiers.
- Disposable VMs; nothing the spike learns is promoted to a real host.

## 8. Internal sequencing (small steps, testable-first)

1. Thin v2 IR + DAG interpreter + the two byte-identical regression locks (pure, offline).
2. Missing-input → silence semantics + dual-read v1/v2 (pure).
3. The one CUSUM kernel + windowed feature (pure, backtested against recorded history).
4. Minimal `shadow → notify-only` ladder + seeded oracle + auto-demote loop (VM). *(Author the demo CUSUM model as a `lte h` invariant so `fired` = a changepoint crossing — see the Progress note's step-4 decision; the ladder keys on `fired`. Pure core done in 4a; this is the VM-wired 4b.)*
5. The authoring seam (one LLM-proposed DAG; ref/arity admissibility; sanitized prompt; closed diagnostics) (VM).
6. The three red-team fixtures (VM).
7. Write the §6 go/no-go.
