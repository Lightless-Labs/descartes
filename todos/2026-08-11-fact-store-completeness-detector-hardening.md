---
title: Fact-store completeness — cross-detector history-loss hardening
created: 2026-08-11
status: pending
priority: medium
area: detection
kind: todo
owner: unassigned
related:
  - docs/plans/2026-08-11-agent-intrusion-detection-gaps-impl.md
  - todos/2026-08-11-tamper-evidence-attestation-design.md
  - todos/2026-07-09-self-learning-stratified-monitoring.md
---

# TODO: Fact-store completeness — cross-detector history-loss hardening

**Origin:** surfaced by gpt-5.6-sol while adversarially reviewing the process-lineage
anomaly detector (2026-08-11). It is NOT process-lineage-specific — it affects EVERY
baseline/novelty detector that defines "novel"/"anomaly" relative to fact-history.

## The problem

A detector that fires on "an edge/entity/value not seen in history" implicitly TRUSTS
that its fact-history is COMPLETE. It isn't, silently:
- `fact-store.js`'s `enforceFactRetention` / `appendFactPoints` drop corrupt/unparseable
  JSONL lines during retention **before** a detector's `readFactPoints` runs, so the
  detector sees `corrupt_count: 0` and trusts a silently-shortened history.
- `readFactPoints` (fact-store.js ~:169) drops schema-invalid-but-parseable records with
  ZERO count/signal.
- Result: a normal edge/value can read as "never seen" and **fabricate** a novel-edge /
  anomaly alert whenever history was truncated by corruption or retention. Each detector
  (session / service / peer / canary / process-lineage) closes this *one layer up* in its
  own store (persistent cold-start on store loss), but the underlying fact-history loss
  is a shared, unsignalled exposure.

Related inherent host-local limit (same class): a root-capable local attacker who WRITES
a crafted, schema-valid per-detector store or manifest can suppress cold-start or seed
state — the store is the attacker's own file. Detection, not prevention, is the fleet's
job (dead-man's-switch, see [[descartes-tamper-evidence-attestation-design]] /
todos/2026-08-11-tamper-evidence-attestation-design.md).

## Design direction (DESIGN-ONLY when picked up — its own plan + review)

- A **durable completeness signal**: a detector must be able to tell its history was
  truncated by corruption/retention — e.g. a `corrupt_dropped_count` / `retention_dropped`
  marker that SURVIVES to future `readFactPoints` callers, or a fact-count/continuity
  check, so the detector can **fail closed** (cold-start / no novelty claim) instead of
  fabricating.
- Decide the semantics once, centrally, so all detectors inherit it rather than each
  re-implementing per-store cold-start.
- Ties to the fleet/attestation layer (off-host observation of a host's silence /
  tamper) for the attacker-writes-a-valid-store case.

## Discipline

Cross-cutting fact-store change — tight plan → gated review → TDD, and re-check every
detector that consumes `readFactPoints`.
