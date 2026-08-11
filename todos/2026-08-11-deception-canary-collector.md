---
title: Deception / canary collector (Slice 7.1 — defend/repel tier below containment)
created: 2026-08-11
status: pending
priority: high
area: detection
kind: todo
owner: unassigned
related:
  - docs/research/2026-08-11-agentic-intrusion-defense.md
  - docs/plans/2026-07-23-slice-7-authority-containment-plane.md
  - docs/plans/2026-08-11-descartes-fleet-federated-topology.md
  - todos/2026-08-11-agent-intrusion-detection-gaps.md
  - todos/2026-08-11-recommend-only-containment-surface.md
  - todos/2026-07-09-self-learning-stratified-monitoring.md
---

# TODO: Deception / canary collector (Slice 7.1)

**Origin:** the agentic-intrusion defense research (`docs/research/2026-08-11-agentic-intrusion-defense.md`) + Slice 7 §(e) 7.1. The Black Hat talk named deception/honey-tokens as a top defensive lever (inject *uncertainty* into the attacker agent). Operator agreed it's the shippable near-term "defend/repel" rung BELOW containment.

## Why this is the highest-leverage next build

- **Mutates nothing on the host** (inert canary files / decoy credentials / decoy listeners + a tamper/access signal) → ships WITHOUT the Slice-7 authority plane / capability-token crypto.
- Closes the **credential-access** + **persistence** detection gaps most cheaply (poll-based atime/mtime/sentinel diff — no deferred event stream needed).
- A tripped canary is the **clean, narrow, high-confidence signal** that becomes the first federated-ratifiable signature (fleet plan) AND the first target for `throttle`/containment. Keystone of the whole ladder.

## Scope (reuse shipped shapes — v0 sketch is in the research doc §3)

- New L0-ish `canary` collector: place inert bait on Descartes' OWN systems only (legal "defend-own-perimeter" boundary, Slice 7 §(a)); emit an `evidenceEnvelope` (degrade-not-fabricate).
- A `canary.census` fact mirroring `SERVICE_CENSUS_FACT_NAME`; a stateless set/stat-diff like `detectServiceDisappearances`; an `extraCandidates` object matching `buildDisappearedCandidates`. Severity `critical` (near-zero legit cause), cleartext `canary_id` + hashed fingerprint (the scoped 2026-07-24 service.disappeared exception). **fs-only, no execFile.**
- Gated default-off behind `learned.json`; fail-closed namespace (never LLM-adjudicated).

## Open items to verify at implementation

- `atime` honesty: `relatime`/`noatime` blunt the read signal → detection is best-effort; the DECEPTION value (slowing the agent via uncertainty) holds regardless — claim deception unconditionally, detection where mount semantics allow.
- Decoy-placement footprint (files in system locations, any listening decoy socket) needs its own doors-and-corners pass per the Slice 7 §(e) 7.1 review note.

## Discipline

Its own tight plan → gated review → TDD + adversarial verify, like every collector slice.
