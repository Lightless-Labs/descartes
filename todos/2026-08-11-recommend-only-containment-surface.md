---
title: Recommend-only containment surface (Slice 7.2 — first buildable Slice-7 rung, mutates nothing)
created: 2026-08-11
status: pending
priority: medium
area: containment
kind: todo
owner: unassigned
related:
  - docs/plans/2026-07-23-slice-7-authority-containment-plane.md
  - docs/plans/2026-08-11-descartes-fleet-federated-topology.md
  - docs/research/2026-08-11-agentic-intrusion-defense.md
  - todos/2026-08-11-deception-canary-collector.md
---

# TODO: Recommend-only containment surface (Slice 7.2)

**Origin:** Slice 7 §(e) 7.2 — the FIRST buildable rung of the authority/containment plane after operator sign-off (2026-08-11, all 9 §(d) decisions resolved).

## Why it's the safe first containment step

- **Mutates nothing.** It surfaces a containment RECOMMENDATION ("consider `<verb> <target>` — e.g. kill PID X / block peer Y") as a notification/alert; it executes NOTHING. No authority plane, no capability token, no privileged helper needed.
- It exercises the *proposal* half of the deterministic gate (the model may PROPOSE; only a future gate + off-machine token authorizes execution — §(c)) without any of the execution risk.
- Natural consumer for the fleet MVP's later remote-device notification relay (F2a).

## Scope

- A new deterministic (no-LLM) containment-recommendation alert/notification type, reusing the shipped alert + notification machinery (evidence-envelope, `extraCandidates`, the delivery path). Recommendation text is bounded/sanitised (numbers/closed-enums/hashes + the scoped cleartext exceptions).
- Deterministic gate is CODE, never a model prompt (§(c): AGENTS.md can't enforce).
- Default-off, fail-closed namespace; NEVER auto-executes.

## Discipline

Its own tight plan → gated review → TDD, per Slice 7's iron rule (dedicated plan + fresh doors-and-corners before any containment code, even recommend-only). Sequencing: after this, remote-device notification (7.4), then `throttle` as the reversible first EXECUTION primitive (7.5).
