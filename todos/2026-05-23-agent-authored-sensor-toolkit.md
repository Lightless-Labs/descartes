---
title: Agent-Authored Sensor Toolkit / Reflex Workbench
created: 2026-05-23
status: open
priority: high
area: architecture
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-23-agent-authored-sensor-toolkit.md
  - docs/ROADMAP.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
---

# TODO: Agent-Authored Sensor Toolkit / Reflex Workbench

## Summary

Build the substrate that lets background LLM agents create their own deterministic sensors, rules, triggers, alarms, and statistical models from Descartes evidence. Do not hand-author a giant library of process/failure signatures.

The core is:

- evidence envelopes -> typed facts
- persisted facts/metrics over time
- safe Prolog/Datalog/Casbin-like rule evaluation
- constrained statistical model artifacts
- fixtures/evaluation harness
- promotion gates from draft to shadow to active

## Initial Milestone

Start with the smallest substrate slice from `docs/plans/2026-05-23-agent-authored-sensor-toolkit.md`:

1. Define a minimal fact schema for existing system/process/disk/service/cert/time evidence.
2. Convert existing evidence envelopes into facts with provenance.
3. Add a tiny safe rule-runner prototype with fixtures.
4. Add local metric/history storage design for sampled/event-driven metrics, rollups, retention, cardinality caps, missing-data semantics, and sensitivity/provenance labels.
5. Seed only 2-3 example rules to prove the machinery; do not build a hand-authored rule library.

## Acceptance Criteria

- A background agent can inspect available fact schemas and example facts.
- Candidate rules/models are artifacts, not arbitrary host-mutating code.
- Candidate artifacts have tests/fixtures before promotion.
- Runtime evaluation is bounded, deterministic, and read-only.
- Local metric/history storage is Descartes-owned and bounded.
- Promotion is explicit; no auto-activation without policy approval.
