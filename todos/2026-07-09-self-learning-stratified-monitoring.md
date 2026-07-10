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
  - **Sanitization gate — status (closed at mine-time in S6c):** `evaluateConstraints`/`buildViolationCandidate` interpolate `id`/`family`/`target` into `title`/`summary`/`fingerprint` unsanitized. S6c's miner now **bounds mined `id`/`family`/`target` at mine time** (`sanitizeIdentityString` + hash-digest id), so a mined→active constraint carries only safe-charset key fields into an alert title. Residual (low, defense-in-depth for S7): a *hand-authored* active constraint with a raw-path `target` would still interpolate verbatim (`validateConstraint` doesn't charset-bound `target`); optionally sanitize `buildViolationCandidate`'s `title`/`summary` in S7.
- [x] **S6a** Multi-cadence collector scheduling in `daemon.js` (prerequisite for mining). — additive hourly structural cadence (services/network/scheduled-jobs), 45s wall-time deadline (Symbol sentinel), atomic corrupt-tolerant checkpoint, kill-switch gated on `learned.json`; fast path byte-identical (adversarially verified — all 6 invariants CONFIRMED); suite 244 green.
- [x] **S6b** Categorical fact-history schema + translators (distinct from numeric metric-point schema). — `fact-store.js` (no finite-value gate, 30d/5MB retention, atomic, corrupt-tolerant) + `fact-translators.js` (systemd/launchd-branching service translator; port-binding grounded on real `network.js` shape, Linux owner degrades to `owner_known:false`, never fabricates) + shared `sanitizeIdentityString`; gated daemon wiring persists facts only on a successful enabled tick. Adversarially verified (all invariants CONFIRMED, zero issues); suite 277 green. (scheduled-jobs translator deferred to when S6c consumes it.)
- [x] **S6c** Deterministic constraint miner (service-presence + port-binding). — pure `mineConstraintCandidates` + idempotent `mergeMinedConstraints` (only touches its own `constraint.mined.*` drafts) + `descartes learned mine` CLI. Three-layer sanitization gate bounds mined `id`/`family`/`target` (adversarially verified against a raw-path fact); output is inert `status:"draft"` (never reaches `evaluateConstraints`); deterministic hash ids. All invariants CONFIRMED; suite 301 green. (Fixed a stray raw NUL byte in source so `ast-grep`/`rg` read it as text.)
- [x] **S7a** Shadow soak (daemon-wired, gated) → `shadow-violations.jsonl` → deterministic `learned soak` promoting shadow→review-ready. Shadow NEVER alerts and nothing reaches `active` (both adversarially verified, all 7 invariants CONFIRMED); active path + disabled path byte-identical; append-only/atomic/retention/corrupt-tolerant shadow log. Fixed a latent fractional-`soakDays` off-by-one in the promotion gate (+lock test). Suite 344 green. (Impl workflow errored on report serialization only; code was complete + green, verified via standalone pass.)
- [ ] **S7b** Human authority gate: `learned approve/reject` → `authority/promotions.json` (deny-by-default, nonce, expiry, audit) → review-ready→`active`. The only path from a learned artifact to live monitoring.

**Make it all live (phase 3) — gaps surfaced during Layer A:**
- Wire the *active* `evaluateConstraints` output into the daemon's `evaluateAndPersistAlerts` via the `extraCandidates` seam — the daemon's call site does NOT pass `extraCandidates` today, so even an activated constraint won't fire real alerts until this wiring lands.
- S13 LLM-wakeup reuse (per-namespace opt-in) + S14/S15 compile-down/calibration.
- Optional defense-in-depth: sanitize `buildViolationCandidate` `title`/`summary` (mined targets are already bounded; this covers hand-authored active constraints).

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
