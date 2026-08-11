---
title: Agent-intrusion host-detection gaps (process-lineage anomaly, persistence baseline, credential-file access)
created: 2026-08-11
status: pending
priority: high
area: detection
kind: todo
owner: unassigned
related:
  - docs/research/2026-08-11-agentic-intrusion-defense.md
  - todos/2026-05-19-process-identity-lineage-tools.md
  - todos/2026-08-11-deception-canary-collector.md
  - todos/2026-07-09-self-learning-stratified-monitoring.md
---

# TODO: Agent-intrusion host-detection gaps

**Origin:** the TTP → detectability map in `docs/research/2026-08-11-agentic-intrusion-defense.md`. Descartes' honest reach is the host EDGE; the research named **three structural gaps** this adversary class exploits that a single-host monitor CAN see and does not yet. All are read-only L0/L1 (no authority plane, zero mutation risk).

## The three gaps (prioritised)

1. **Process-lineage / child-spawn anomaly detector** (highest value). The incident's RCE (#7 deserialize-then-exec), command-injection (#13/#15), and privesc chains all reduce to *"an unexpected process spawned an unexpected child."* The shipped `inspect_process`/`inspect_parent_tree` collector (`todos/2026-05-19-process-identity-lineage-tools.md`, COMPLETED) gives the snapshot; this gap is the **behavioral baseline/signature on top** — a Layer-1 detector over exec-chains, not a new snapshot tool.
2. **Persistence baseline** — no "a new service / scheduled-job appeared" detector. `scheduled-jobs.js` has zero baseline wiring today. Mirror the session/service/peer census+baseline pattern (Slices 1/3/4/service.disappeared) for cron/systemd-timers/launchd + services.
3. **Credential-file-access signal** — no signal when sensitive credential files (`~/.ssh`, cloud creds, `/proc/self/environ`-class reads) are touched. Overlaps with the canary tier (`todos/2026-08-11-deception-canary-collector.md`) but for REAL credential paths, best-effort per mount atime semantics.

## Discipline

Each is its own collector/baseline slice: tight plan → gated review → TDD + adversarial verify, mirroring the observed-incident collectors. Read-only, default-off, fail-closed namespaces, degrade-not-fabricate. Honest scope: these harden the host EDGE; the cloud/cluster half of the incident stays out-of-scope for a single-host agent (see the research doc's scope box).
