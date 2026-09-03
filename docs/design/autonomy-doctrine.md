# Autonomy Doctrine — The Three Ditches

**Kind:** living design doctrine (not a point-in-time plan).
**Established:** 2026-09-03 (interactive design session).
**Governs:** the whole self-authoring / self-monitoring / self-acting stack.
**Referenced by:** `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` (roadmap),
`docs/plans/2026-09-03-proactive-behavioral-modeling.md` (the buildable plan).

---

## North star

Descartes should **author and run its own behavioral models** of the machine it lives on,
and **earn the right to act** on what they find — without a human hand-building every
detector, without nagging the operator for consent, and without acting invisibly and
unaccountably.

"Learn the machine, monitor it, defend it" is the goal. This doctrine is about *how* to get
there without falling into one of three well-known ditches. Any design in this stack must be
checkable against all three.

## The three ditches

Each is a real product that failed in a real, memorable way. We name them so a proposal can
be tested against them in one sentence.

### 1. Clippy — fake intelligence over a canned menu

- **Failure:** the "agent" only toggles detectors a human pre-built and tunes a threshold.
  Intelligence is a costume over a fixed menu; users see through it and resent it.
- **Why it is tempting:** a fixed set of hand-written detectors is easy to reason about and
  easy to make safe.
- **Structural fix:** a **compositional model language, not a menu.** Fixed, audited
  *primitives* — feature accessors, bounded transforms, model kernels, decision combinators —
  which the agent *composes* into pipelines. Finite grammar, unbounded program space, like
  SQL, an ONNX graph, or a stream-processing DAG. The models are emergent and open-ended;
  only the primitives are fixed. Genuine authorship, still fully analyzable.

### 2. Vista UAC — consent fatigue

- **Failure:** "agent proposes, human approves" on every item. The operator gets a
  Cancel-or-Allow popup per model, cannot meaningfully judge them, and clicks Allow on
  reflex. The gate becomes theater, and an insult.
- **Why it is tempting:** a human approval gate feels safe and satisfies "a human is in
  control."
- **Structural fix:** **human on the loop, not in it.** The operator sets a *policy envelope
  once* and audits after the fact; the system promotes models by *evidence it gathers itself*
  (soak, backtest, corroboration, track record), not by a click. Authority is **earned,
  decaying, and revocable** — a model climbs authority tiers by performing and auto-demotes
  when it regresses. Notification, not confirmation.

### 3. Skynet — unaccountable autonomy

- **Failure:** the system acts on its own with no audit trail, no notification, and no undo.
  Powerful, and nobody can trust it or stop it.
- **Why it is tempting:** it is what you get if you "fix" ditch 2 by simply deleting the gate.
- **Structural fix:** **corroboration + notification + reversible, audited action.** Authority
  to act comes from *multiple independent signals agreeing* (the immune system's two-signal
  rule), every action is *notified* and *reversible*, and everything is *audited*. The human
  can always see, veto, and roll back.
- **The single-host caveat (the load-bearing one):** on one machine, every "independent"
  signal — and the completeness proof itself — shares a single failure mode (host compromise)
  and is forgeable at the daemon's own privilege. One host agreeing with itself is **not**
  corroboration. So corroboration that grounds *authority* (anything above raising an alert)
  must be **cross-host / off-host** — a federated or hardware root of trust — exactly as
  antivirus/EDR concede the on-host war against root and move the authority to a signed,
  off-host backend. On-host, the ceiling is additive alerting; everything above it waits on
  attestation.

## The unifying principle

> **Autonomy scales with `reversibility × corroboration`, never with human attention.**

Where an action is cheap to undo and weakly corroborated, act freely — a stray alert is
noise, auto-demote the model that raised it. Where an action is irreversible, demand strong
corroboration and always notify — but still never a per-event consent prompt. The knob that
opens is *earned structural capability*; the knob that never opens is *acting without
accountability*.

Two knobs stay independent, forever:

- **What the agent may propose** — widen this aggressively. That is how you escape Clippy.
- **What may act without a human** — widen this only by earned trust + corroboration +
  reversibility (that keeps you out of Skynet), and never by a consent prompt (that keeps you
  out of UAC).

## The agent's non-delegable job: proactive behavioral modeling + arbitration

The agent builds **behavioral models** — what is normal for *this* machine — and continuously
checks them against ground truth (actual system behavior). Every model yields a residual:
the model expected X, the machine did Y. When they diverge, the agent must arbitrate between
three causes. This judgment is the thing a purely deterministic system cannot do robustly,
and it is where the LLM agent genuinely earns its place:

1. **The model is wrong or incomplete** → refine the model.
2. **The world legitimately changed** (benign concept drift — a new workload, an upgrade, a
   new-but-fine peer) → adapt the model to the new normal.
3. **The divergence *is* the threat** (anomalous / harmful / malicious) → do **not** adapt;
   alarm, and if the authority is earned, act.

**Arbitration is adversarial.** An attacker *wants* their activity read as benign drift, so
the model adapts to accept them — the boiling-frog / poisoning attack on any adaptive
detector. Therefore the agent **never adapts a model to unattested change.** Adaptation is
itself a gated action, permitted only when the change is corroborated by independent evidence
(a package-manager event explains the new binary; a maintenance window explains the load
shift) *and* the underlying history is proven complete (the fact-store completeness
substrate). "Adapt to the new normal" is the primary attack surface, and it is governed as
strictly as acting on the host.

**Adaptation is authoring.** When the agent adapts a model to a benign change, it does *not*
mutate an active model in place — it proposes a *new model version* that enters the shadow
tier and must re-earn promotion on evidence. But "re-earn from shadow" measures fit to recent
history, and recent history is what a slow poisoner controls; so authoring-as-adaptation must
additionally be bounded by a per-lineage cumulative-drift budget anchored to an *attested*
baseline, or a chain of individually-plausible successors walks the baseline onto the
attacker. Adaptation is authoring, and authoring above additive alerting is attestation-gated.

## Invariants this doctrine preserves

- **Never fabricate** a security or health signal; degrade to silence under uncertainty.
- **Completeness-gated** — never reason, and never *adapt*, over history not proven complete.
- **Declarative-only in the hot path** — the agent authors model *specifications*, never
  executable code, in the evaluation loop. A future sandboxed, fuel-bounded expression hatch
  is the only exception, and it is **runtime-bounded (fuel + memory), not statically
  analyzable** — do not conflate the two.
- **Attestation-gated authority** — on-host, the ceiling is additive alerting; recommend,
  sticky adaptation, and acting hard-depend on an off-host / hardware root of trust.
  Ground truth for promotion is *fed* (operator labels, seeded fixtures, signed feeds),
  never minted on the endpoint.
- **Recommend-only until earned** — the capability to act is a ceiling that lifts by
  evidence, never a toggle.
- **Fully audited and reversible** — every promotion, adaptation, and action leaves a trail
  and can be undone.
- **Default-OFF** behind the `learned.json` kill switch.
