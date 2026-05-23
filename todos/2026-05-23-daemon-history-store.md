---
title: Daemon and Local History Store
created: 2026-05-23
status: open
priority: high
area: architecture
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-23-daemon-history-store.md
  - docs/plans/2026-05-23-agent-authored-sensor-toolkit.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
---

# TODO: Daemon and Local History Store

## Summary

Build the local background substrate before implementing agent-authored sensors. Descartes needs a daemon/background agent that runs a conservative default set of read-only collectors, persists bounded local history/metrics, rotates/cleans up after itself, and exposes recent history to CLI commands and optional history-aware triage.

## Initial Scope

- `descartes daemon run --foreground` development loop.
- Daemon config and default collector profile.
- Descartes-owned history store under XDG state/cache paths.
- Bounded metric points and rollups.
- Retention/rotation/max-size enforcement.
- `descartes history summary` read path.
- Later: launchd/systemd user service install/start/status/stop/uninstall.
- Later: `descartes triage --use-history` with bounded history summaries.

## Safety Boundaries

- No background LLM calls.
- No telemetry/upload/federation.
- No mutating host actions.
- Read-only collectors only.
- No arbitrary shell/coding tools.
- No unbounded raw log/process capture.
- No silent privilege escalation.

## Acceptance Criteria

- Default daemon loop can collect system/process/disk history over time.
- History is persisted under Descartes-owned XDG paths.
- Rotation/retention prevents unbounded disk growth.
- CLI can summarize recent history without invoking an LLM.
- Tests cover daemon loop scheduling, storage writes, rollups, retention, and corrupt/partial store handling.
