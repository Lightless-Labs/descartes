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
- [x] **S7b** Human authority gate: `learned review/approve/reject` → `authority/promotions.json` (deny-by-default, single-use nonce, expiry, audit) → review-ready→`active`. `promoteReviewReadyToActive` is the SOLE `active`-writer; the gate is the only path to live monitoring. Adversarially verified (empirical probes): sole activation path, fail-closed at every denial, nonce single-use (two independent layers), strict expiry — all CONFIRMED, `OVERALL_SAFE: yes`. Fixed the flagged audit-misattribution (spot B: `logDenial` no longer attaches a denial to an already-decided record; +lock test). Suite 384 green.
  - **Deferred (minor, spot C):** non-transactional cross-file write (constraints.json then promotions.json) can leave an orphaned `pending` promotion record after a crash mid-write — no safety bypass (the constraint's own `promotion_history` records the approval; replay denies), but a `learned review` reconciliation/purge of orphaned pendings whose constraint is already active would close the gap.

**Make it live — operator pulled the constraint-firing wiring forward (2026-07-10), BEFORE Layer B:**
- [x] **S-live-1** Wire the *active* `evaluateConstraints` output into the daemon's `evaluateAndPersistAlerts` via the `extraCandidates` seam, gated by the learned kill-switch, byte-identical when disabled — so an approved/active constraint actually fires a real alert. Reuses the now-exported `buildShadowFactLookup` so active + shadow evaluation stay consistent (same degraded-exclusion, latest-wins). Two `[]` short-circuits (disabled; no-active) keep the alert output byte-identical when off; `alert-store.js` untouched (S2 merge intact). 8 new tests (byte-identical ×2, fires-when-violated, no-spurious ×3, no-cross-recovery); suite 392 green. **An approved constraint now produces a real alert end-to-end.**
- S13 LLM-wakeup reuse (per-namespace opt-in) + S14/S15 compile-down/calibration.
- Optional defense-in-depth: sanitize `buildViolationCandidate` `title`/`summary` (mined targets are already bounded; this covers hand-authored active constraints).

## Layer B — Provenance / Signature Reflex (defers milestone numbering to the witr plan)

Dedicated plan: `docs/plans/2026-07-10-layer-b-provenance.md` (code-grounded, two-lens reviewed incl. a security/doors-and-corners lens that substantially hardened the elevated path). Sequencing: **S3 first (no privilege deps)** → S3-priv (Linux may proceed after S3; macOS gated on a §6(f) real-fixture spike + fresh doors-and-corners pass) → S4 → S5.

- [x] **S3** Unprivileged provenance collector `tools/provenance.js` (`inspect_runtime_provenance`): target-first pid|port|container resolution, deterministic source classification (pure `classifySourceFromAncestry`), warnings-as-facts (pure `detectWarnings`), degrade-not-fabricate; registered via the atomic tool-policy/pi-harness edit + set-equality assertion. Adversarially verified OVERALL_SAFE (no shell/sudo/setcap, single fixed-argv `execFile`, registration set-equality tested). Fixed 3 minor verify findings: unresolvable-pid now degrades to `pid:undefined` (not echoed), container ref charset-guarded + `--` end-of-options (argument-injection guard), `executable_path` bounded in the emitted record. 35 new tests; suite 427 green.
  - Deferred (cosmetic, verify #4): Linux port fallthrough conflates race/beyond-scan with EACCES in the `reason` text — `pid` stays undefined either way (no fabrication), only the operator-facing reason attribution is imprecise.
- [ ] **S3-priv** Opt-in elevated read path — **APPROVED 2026-07-10, validate in Linux CI.** Install-time privilege only, daemon **never** self-escalates; a tiny fixed-purpose `root_helper` (Rust) confines root/CAP_SYS_PTRACE, hardened with seccomp-bpf/PR_SET_NO_NEW_PRIVS/cap-drop in its own build pipeline; two-condition AND opt-in (OS grant present + config enabled, default off); OS-level audience-scoping (0750 `root:descartes-provenance` group / macOS XPC `csreq`); config/helper-path trust-boundary check; echo-back scope-verification on untrusted helper output; graceful degrade. `mechanism:"auto"` never targets `root_helper`.
  - **Sequencing (operator deferred to agent, 2026-07-10):** build the **Linux `root_helper` first** (its cross-UID gap is confirmed real + un-gated per plan §6(f); validate in Linux CI — this dev host is macOS, no `tart`). The **macOS go/no-go spike** runs separately and does NOT block Linux: a *read-only investigation* (not a build) using the shipped S3 collector to measure how much of macOS cross-UID provenance is actually blocked (unprivileged `lsof` already resolves cross-UID pid+command, so the residual gap — codesign/spctl on other-UID exes, SIP/root daemons, container helpers — may be too narrow to justify a privileged macOS component; the spike's decision: full `SMAppService`/XPC helper vs. smaller `libproc` root_helper vs. defer macOS elevated entirely). **Keep it time-boxed — a handful of real captures + a written go/no-go, NOT a battle-hardened POC; "skip, gap too narrow" is a valid successful outcome (operator guardrail 2026-07-10).**
  - **Distinct workstream:** a separate Rust helper crate (hardening tested in its OWN build pipeline, not `npm test`) + Node-side elevated-path plumbing in `provenance.js` + Linux-CI validation + a fresh build-time doors-and-corners pass. Gets its own dedicated implementation plan at pickup (after S4/S5).
- [x] **S4** Immediate provenance-warning fixed rules (zero learning) → sanitized candidates through the now-live `extraCandidates` merge. — `provenance-warnings.js`: structural sub-collector (hourly, bounded-I/O — expensive deleted-exe check only on the narrowed public-bind set) → persisted facts → `computeProvenanceWarningCandidates` reads facts every tick (mirrors the constraint path) → `provenance.process.deleted_exe_running` / `provenance.socket.public_bind_no_supervisor`. Exe paths sha256-hashed (16 hex) before any warning/fact/candidate; diagnostics sanitized. Adversarially verified OVERALL_SAFE (byte-identical-when-disabled, sanitization, bounded I/O, 3-source no-cross-recovery, S3 refactor behavior-preserving). 27 new tests; suite 454 green. Plan §4 reconciled (S4 needs no codesign/spctl; ≤3h deleted-exe staleness self-heals — both addended).
- [ ] **S5** Identity baseline + deterministic deviation warnings (`identity_signature` hashing inputs pinned by fixtures FIRST; provisional→known_good grace window; unknown_identity/identity_drift/new_public_bind).

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
- Provenance privilege path: **DECIDED 2026-07-10 — build an opt-in elevated read path** (setgid helper / CAP_SYS_PTRACE on Linux; documented root-only mode) so cross-UID port→process ownership resolves, explicitly opt-in, still deny-by-default + never-fabricate. Build it as part of Layer B (after the live-wiring below).
- `identity_signature` hashing inputs (pin with fixtures before S5).

## Carried-forward external (codex) priorities — not blocked by the above

- [ ] macOS release validation: fresh-Mac first-run Notification Center/TCC (`scripts/validate-macos-notifier-helper.sh --reset-tcc`); needs a physical fresh Mac.
- [ ] First live Homebrew tap auto-bump on next `vX.Y.Z` tag; run `scripts/check-homebrew-tap-token.sh` before tagging (needs token-bearing env).
- witr provenance + approval-notifications plan (`docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md`).
- rcodesign spike: deferred.
