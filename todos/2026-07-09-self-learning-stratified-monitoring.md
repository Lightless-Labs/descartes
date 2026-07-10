# Self-Learning Stratified Monitoring

Tracking todo for `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` — making Descartes
learn the machine, build its own monitoring/alerting layers that wake the agent, and
audit/verify/maintain those layers (Absolution-Gap layered nervous system).

Plan produced + adversarially reviewed via an ultracode multi-agent design workflow
(Constraint Kernel spine, grafted with provenance/signature + statistical-baseline layers).

## Commitment tiers (see plan §0)

- Slices 1–3: committed / implementation-ready now.
- Layers B (provenance/signatures) & C (statistics): design-sketch — dedicated plan required at pickup.
- Node/JSONL is the durable substrate through ≥ Slice 16; Rust re-anchoring is checkpointed at the Layer A→B boundary.

## Layer A — Constraint Kernel

Dedicated mining-pipeline plan (S6a–S7): `docs/plans/2026-07-10-constraint-mining-pipeline.md` (code-grounded, two-lens reviewed). Flagged defaults awaiting sign-off (plan §8): `MIN_FIXTURE_COUNT=2`, `soakDays=7`, 24h promotion nonce/expiry, `DEFAULT_STRUCTURAL_TICK_DEADLINE_MS=45s`. Port-binding-identity mining is effectively macOS-only for v1 (Linux socket collector resolves no owner/pid).


- [x] **S1** Learned-artifact (constraint) store scaffolding + seed constraints (pure data layer; no daemon/collector/alert coupling). — `constraint-store.js` + 16 tests; suite 210 green (commit).
- [x] **S2** `evaluateConstraints()` + `extraCandidates` pipeline seam + code-enforced `sanitizeDiagnostics()` gate (explicit reviewed change to `evaluateAndPersistAlerts`; byte-identical fixed-rule regression test). — 3 new modules + adversarial verify (all 5 safety invariants CONFIRMED); the no-cross-recovery test caught a real self-recovery hazard (candidates missing `id`), hardened at the merge point; suite 229 green.
  - **Hard gate before S6c mining:** the sanitizer gate covers only candidate `diagnostics`. `evaluateConstraints` interpolates `id`/`family`/`target` verbatim into `title`/`summary`/`fingerprint`. Safe today (trusted `SEED_CONSTRAINTS` only), but once mining derives `target` from raw facts, bound/sanitize those key fields (or canonicalize targets at mine time) so a raw path can't reach a persisted alert title/notification/LLM prompt.
- [ ] **S6a** Multi-cadence collector scheduling in `daemon.js` (prerequisite for mining).
- [ ] **S6b** Categorical fact-history schema + translators (distinct from numeric metric-point schema).
- [ ] **S6c** Deterministic constraint miner (service-presence + port-binding).
- [ ] **S7** Shadow soak + deterministic promotion gate + human approve.

## Layer B — Provenance / Signature Reflex (defers milestone numbering to the witr plan)

- [ ] **S3** Provenance L0 collector (`tools/provenance.js`, native Node, on-demand).
- [ ] **S4** Immediate provenance-warning fixed rules (zero learning).
- [ ] **S5** Identity baseline + deterministic deviation warnings (identity_signature inputs pinned by fixtures first).

## Self-audit

- [ ] **S8** Artifact self-monitoring (chronically-firing / staleness / contradiction).
- [ ] **S9** Deterministic self-audit: fixture regression + coverage/staleness.

## Layer C — Statistical Baselines

- [ ] **S10** Welford/EWMA per-metric baseline + z-score deviation (system/disk).
- [ ] **S11** Per-identity behavioral baseline (top-N, cardinality-bounded).
- [ ] **S12** Time-of-day / day-type bucketing.

## L2 reuse + compile-down

- [ ] **S13** Reuse `alert-intelligence.js` for learned-artifact wakeups (per-namespace opt-in; critical-severity budget reservation). Only slice that reaches the LLM.
- [ ] **S14** Outcome-informed compile-down: reviewable tuning proposals (never auto-applied).
- [ ] **S15** Calibration report (read-only precision/recall proxy).
- [ ] **S16** Optional bounded `witr` binary cross-check.

## Decisions needed from operator before Layer B

- Rule-engine tech: hand-written per-family JS now, defer a general Datalog/DSL engine? (plan assumes yes.)
- Provenance privilege path: accept degraded unprivileged cross-UID coverage, or add an elevated read path (setgid helper / CAP_SYS_PTRACE / root-only mode)?
- `identity_signature` hashing inputs (pin with fixtures before S5).

## Carried-forward external (codex) priorities — not blocked by the above

- [ ] macOS release validation: fresh-Mac first-run Notification Center/TCC (`scripts/validate-macos-notifier-helper.sh --reset-tcc`); needs a physical fresh Mac.
- [ ] First live Homebrew tap auto-bump on next `vX.Y.Z` tag; run `scripts/check-homebrew-tap-token.sh` before tagging (needs token-bearing env).
- witr provenance + approval-notifications plan (`docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md`).
- rcodesign spike: deferred.
