---
title: Codex project audit follow-up — trustworthy Observe → Notify
created: 2026-09-04
status: mostly-resolved
priority: p1
area: operational-reliability
kind: todo
owner: unassigned
source: "Codex (OpenAI assistant), user-requested repository-wide audit in this conversation on 2026-09-04"
audited_commit: cdb5256
tags: [audit, monitoring, reliability, evidence, documentation]
dependencies: []
---

# TODO: Codex project audit follow-up — trustworthy Observe → Notify

## Problem Statement

Descartes has strong read-only and authority boundaries, but its observation, alert-state,
and notification paths do not yet provide dependable unattended monitoring. Silence can
mean a healthy machine, unavailable evidence, a detector that cannot establish a baseline,
or a delivery failure. Those states must be distinguishable.

**Origin:** Codex, the OpenAI assistant conducting the user's repository-wide goals and
implementation audit in this conversation on 2026-09-04. This todo preserves that audit;
it is **not** the separate daybreak-blue security sweep. The reviewed tree ended at
`cdb5256`. Findings are source-level conclusions, not claims of observed production
incidents or a security certification. Revalidate them against the implementation before
making changes.

**Status:** Pending triage and implementation planning. The user requested recording the
work, not implementing fixes or replacing the existing active initiative.

## Findings

### P1 — address before relying on unattended monitoring

1. **Alert viewing mutates alert state.** `alerts list/watch` calls
   `evaluateAndPersistAlerts` without the learned/security candidates. Its recovery logic
   treats their absence as recovery. Evaluation also advances notification cooldowns
   before successful delivery. Make viewing read-only and separate evaluation, delivery
   attempts, delivery success, and acknowledgement.
   Sources: [alerts.js](../tools/descartes-cli/src/alerts.js),
   [alert-store.js](../tools/descartes-cli/src/alert-store.js).
2. **Routine byte-cap eviction can keep novelty detectors disabled indefinitely.** The
   default fact-store cap is 5 MiB; evictions mark history degraded. Baseline readers use
   approximately 31 days of history and reject degraded history. Repeated normal evictions
   prevent the loss from aging out. Preserve the completeness safety invariant while
   designing a bounded, trustworthy recovery path and visible coverage-loss reporting.
   Sources: [fact-store.js](../tools/descartes-cli/src/fact-store.js),
   [fact-store-integrity.js](../tools/descartes-cli/src/fact-store-integrity.js),
   [fact-store-completeness.js](../tools/descartes-cli/src/fact-store-completeness.js),
   [welford-stats.js](../tools/descartes-cli/src/welford-stats.js).
3. **Service baselines cannot establish on consistently truncated inventories.** The
   daemon uses the collector's default 80-service limit. Truncation produces a partial
   census, while appearance/disappearance baselines require complete censuses. Separate
   presentation limits from authoritative inventory rather than merely raising the cap.
   Sources: [services.js](../tools/descartes-cli/src/tools/services.js),
   [fact-translators.js](../tools/descartes-cli/src/fact-translators.js),
   [service-baseline.js](../tools/descartes-cli/src/service-baseline.js).
4. **Persistence failure can stop monitoring before alerts are evaluated.** Metric writes
   precede alert evaluation, so an uncaught storage failure can terminate the iteration,
   including during disk pressure. Metric retention and daemon-status writes also
   directly overwrite files that other commands read. Add degraded-storage behavior,
   atomic persistence, and a bounded fallback notification path.
   Sources: [daemon.js](../tools/descartes-cli/src/daemon.js),
   [history-store.js](../tools/descartes-cli/src/history-store.js).
5. **Model latency blocks subsequent observations.** Alert adjudication awaits session
   creation and `session.prompt()` inside the serial daemon iteration without a
   daemon-level deadline. Decouple model work from collection with bounded execution,
   cancellation, and backpressure.
   Sources: [alert-intelligence.js](../tools/descartes-cli/src/alert-intelligence.js),
   [daemon.js](../tools/descartes-cli/src/daemon.js).

### P2 — correctness, goal alignment, and release assurance

6. **Core resource notifications depend on the model route.** Memory, load, disk, and
   daemon alerts are not in the deterministic delivery allowlist. Enabling notifications
   alone does not deliver these alerts. L1 should notify deterministically, with optional
   model enrichment rather than model-dependent delivery.
   Source: [alert-intelligence.js](../tools/descartes-cli/src/alert-intelligence.js).
7. **Evidence grounding is weaker than the stated contract.** A nonempty array satisfies
   the evidence guard even when its observations are unsuccessful. Diagnosis JSON lacks
   schema/reference validation; `derive_findings` accepts model-supplied envelopes rather
   than references to collector-owned results. Validate usable evidence and references,
   and represent insufficient evidence explicitly without pretending to mechanically
   verify every natural-language claim.
   Sources: [triage-guard.js](../tools/descartes-cli/src/triage-guard.js),
   [triage.js](../tools/descartes-cli/src/triage.js),
   [pi-harness.js](../tools/descartes-cli/src/pi-harness.js).
8. **CI does not enforce the advertised release/platform guarantee.** Linux x86_64 is
   Tier 1 in the README, while configured Linux jobs are ARM64. Tests exclude tags; the
   tag release job has no configured dependency on passing tests for that commit. Add
   the supported architecture and an exact-commit release gate.
   Source: [pipeline.yml](../.buildkite/pipeline.yml).

### Documentation and broader gaps

- Correct the README's absolute no-false-alarm guarantee. Completeness checks prevent
  specific failure mechanisms, not all false positives or false negatives.
- Describe credential monitoring as metadata-change detection: configured watches use
  mtime/inode changes and do not detect ordinary reads. See
  [credential-access.js](../tools/descartes-cli/src/tools/credential-access.js).
- Replace the universal identity-hashing claim with an accurate field-level contract:
  metric dimensions retain process commands and filesystem paths; triage can send
  hostnames, PIDs, and process arguments to the selected model provider. Distinguish
  local storage, operator-requested diagnosis, and background model disclosure.
- Scope follow-ups for detector readiness/freshness/coverage reporting and independent
  watchdog behavior. An unavailable or failed evaluation must not imply a healthy host.
- Separately prioritize maintenance gaps: backup verification, storage hardware health,
  package/reboot state, service-failure playbooks, and continuous certificate/time-sync
  monitoring rather than only on-demand collectors.
- Keep roadmap claims honest: current constraint mining covers two families; the new
  model interpreter/ladder is an offline foundation, and calibration has no incident
  ground truth for recall. Persistent incident reasoning and auditable action plans are
  still future work. The narrow Rust core is an acknowledged migration stage, not a
  reason to defer reliability fixes for a rewrite.

## Proposed Solutions

### Option A — staged Observe → Notify reliability milestone (audit recommendation)

Plan small, test-first slices: read-only alert views and delivery bookkeeping; trustworthy
retention/inventory coverage; storage and model failure isolation; then evidence validation,
documentation, and release gates. Coordinate with existing recovery and locking todos.

Benefits: addresses the shared failure paths before adding more detectors. Cost/risk:
multi-slice work with sensitive changes to baseline recovery and alert lifecycle; requires
regression tests that preserve existing completeness and authority guarantees.

### Option B — triage into existing workstreams

Assign each finding to an existing or newly scoped child todo, retaining this file as the
audit checklist. Benefits: fits current work allocation. Cost/risk: shared alert/store
contracts can fall between owners unless an explicit integration milestone is retained.

## Recommended Action

Pending triage. Codex recommends Option A; this is not an operator-approved reprioritization.
Before implementation, produce a scoped plan under `docs/plans/`, reconcile overlap with
the linked backlog, and define cross-component acceptance tests. Broader maintenance and
learning gaps may become separately tracked follow-ups rather than expanding this fix set.

Preserve what works: read-only model tools, no general remediation capability, isolated
private harness configuration, narrowly confined privileged reads, explicit authority
gates, completeness-aware evidence, and honest uncertainty. Do not weaken trust checks
just to make disabled detectors emit alerts.

## Acceptance Criteria

- [ ] Findings are revalidated and each has a recorded disposition and owner/scoped plan.
- [ ] Listing/watching alerts leaves persisted state and delivery eligibility unchanged.
- [ ] Failed or unevaluated detector results cannot mark an incident recovered.
- [ ] Delivery success, failure, retry, and cooldown behavior are separately tested;
      enabled core operational notifications work with alert intelligence disabled.
- [ ] Normal retention churn has a tested, bounded trustworthy recovery path without
      removing completeness protections; unavailable coverage is visible.
- [ ] Inventories above 80 services remain usable for monitoring, or an explicitly
      bounded monitoring scope provides provable completeness and disclosed limitations.
- [ ] Storage failures and stalled model work do not silently stop local monitoring;
      persistence/read concurrency and bounded retry behavior have integration coverage.
- [ ] Triage distinguishes unsuccessful evidence from grounded diagnosis, validates its
      output/reference contract, and derives findings from collector-owned results.
- [ ] README detection/privacy guarantees match actual behavior and disclosure boundaries.
- [ ] Supported Linux x86_64 behavior is tested and releases require passing checks for
      the exact released commit, or support claims are explicitly revised by the operator.
- [ ] Broader coverage, maintenance, and learning gaps have explicit scoped dispositions.
- [ ] Relevant tests and review pass; this todo and HANDOFF are updated with actual results.

## Resources

- [Project goals and safety invariants](../AGENTS.md)
- [Project handoff](../docs/HANDOFF.md)
- [Completeness recovery optimization](2026-08-27-completeness-recovery-optimization.md)
  — same recovery substrate; this audit additionally highlights repeated normal eviction.
- [Fact-store concurrent-writer locking](2026-08-23-fact-store-concurrent-writer-locking.md)
  — related storage work, not a substitute for atomic reads or failure isolation.
- [Original evidence guard](2026-05-19-no-evidence-no-diagnosis-guard.md)
  — completed earlier; finding 7 is follow-up hardening, not a claim it was never built.
- [Monitoring and alerting](2026-05-28-monitoring-alerting.md)
- [Self-learning initiative](2026-07-09-self-learning-stratified-monitoring.md)
- [Separate daybreak-blue sweep](../docs/reviews/2026-09-04-daybreak-security-sweep.md)
  — adjacent review; do not attribute these Codex audit findings to it.

## Work Log

### 2026-09-04 — audit recorded at the user's request

**By:** Codex (OpenAI assistant).

- Compared stated goals with CLI/daemon, collectors, stores, detectors, model harness,
  Rust helper, notifier, and release configuration through `cdb5256`.
- Audit verification: Node suite 1,788 passed / 34 skipped / 0 failed; Rust workspace
  36 tests passed on macOS; CLI smoke check passed. These are results from the preceding
  audit, not tests rerun for this documentation-only change.
- Linux-specific privileged behavior, live provider behavior, and actual desktop
  delivery were not validated. No implementation fixes were made by this audit.
- Created this pending umbrella todo alongside the existing dated `todos/` backlog,
  as requested, and added a source-attributed link to `docs/HANDOFF.md`.

### 2026-09-04 (later) — findings driven to resolution via ultracode workflows (Opus-orchestrated)

At the operator's request, all 8 findings + the docs cluster were re-verified against the code
(9-agent read-only workflow — every finding CONFIRMED, none refuted) and then fixed TDD, each
adversarially verified, and the fabrication-class fixes (F4/F5) re-gated by `gpt-daybreak-blue-latest`.
The daybreak re-gate earned its place: it caught **three real fabrication BLOCKERs** in the F4/F5
fixes that the Sonnet implement→verify pipeline passed (hardcoded `state:"ok"`; a retention failure
reporting `written_count:0`; a microtask/macrotask race trusting a late model response), then two
further subtle edges (empty-error-message dropped by `filter(Boolean)`; a non-monotonic `Date.now()`
deadline) — three rounds to READY. Dispositions:

- **F1 — FIXED** `531394a` — `alerts list/watch` read-only + rule-scoped recovery (a view can no longer
  falsely recover a learned/canary/credential alert or consume its cooldown).
- **F2 — Tier 1 FIXED** `3dc307f` (configurable `fact_store_max_bytes` + `continuity_oldest_ts`
  coverage reporting); **Tier 2 DEFERRED** — the sliding-anchor / scoped-claim recovery genuinely
  narrows detection strength and needs its own plan + a minimum-span floor + daybreak review. NOT
  bolted onto Tier 1.
- **F3 — FIXED** `30c56c9` — authoritative `services_census` separated from the 80-item presentation
  cap (a >80-service host can now establish a service baseline); fail-closed census gate untouched.
- **F4 — FIXED** `a147d3f` + `03b4f66` + `d7feab2` (3 daybreak rounds) — storage-fault isolation that
  degrades-not-aborts AND never fabricates health: `state` derived from real collector/persistence
  health, honest `written_count` + surfaced `retention_error`.
- **F5 — FIXED** `8be50bc` + `31e88db` + `d7feab2` (3 daybreak rounds) — model deadline via
  `Promise.race` + real `session.abort()` + a MONOTONIC `performance.now()` elapsed belt; a
  timed-out/partial/late response is never trusted, recorded, or delivered.
- **F6 — FIXED** `ca28f79` — core-resource alerts (memory/load/disk/daemon) deliver deterministically
  when notifications are enabled, independent of the opt-in LLM route; LLM gating untouched.
- **F7 — FIXED** `787afd3` — the evidence guard counts only USABLE evidence (a failed "unable"
  observation no longer satisfies "no evidence, no diagnosis"); + the on-demand `collect_services` LLM
  tool strips the unbounded census.
- **F8 — DEFERRED → operator** — CI x86_64 coverage + exact-commit release gate is a release-semantics
  change; silently fail-closing a currently-flaky gate risks a release freeze (HANDOFF notes past macOS
  VM-pairing flakiness). Needs an operator CI-stability review before turning the gate on.
- **DOCS — FIXED** `0afb0e9` — README detection/privacy overclaims corrected (credential = metadata
  change not read and not a permission/ctime change; scoped no-false-alarm; field-level identity-
  disclosure contract). The doc-fix verifier caught a fresh overclaim the fix-spec itself introduced.

Full suite after all fixes: **1867 pass / 34 skipped / 0 fail.** Remaining open: F2-Tier2 (deferred
plan), F8 (operator sign-off). This todo stays open to track those two + the "Documentation and broader
gaps" list not yet individually dispositioned.
