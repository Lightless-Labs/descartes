---
title: Expand Descartes Local Read-Only Investigation Tools
created: 2026-05-19
status: open
priority: high
area: collectors
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-llm-driven-investigation-tools.md
  - todos/2026-05-19-process-identity-lineage-tools.md
  - todos/2026-05-19-temporal-sampling-investigation-tools.md
---

# TODO: Expand Descartes Local Read-Only Investigation Tools

## Summary

Descartes needs more local deterministic evidence tools so the LLM can investigate beyond the first resource-pressure slice.

This todo is about adding local read-only collectors. It is separate from re-enabling the LLM tool loop and separate from web/search tools.

## Current Tool Set

Already implemented:

- `collect_system`
- `collect_processes`
- `collect_disks`
- `collect_triage_evidence`
- `derive_findings`

## Current Next Priority

The immediate next capability slice is tracked in `todos/2026-05-19-process-identity-lineage-tools.md`:

1. add a shared redacted/bounded process argument representation
2. add `inspect_process`
3. add `inspect_parent_tree`

This is the best next bridge from snapshot resource triage toward behavior-aware operations/defense investigation.

## Candidate Next Tools

Prioritize tools that answer common first-triage questions without privileged mutation:

1. `inspect_process`
   - input: PID or process name
   - output: parent PID, executable, redacted/bounded command line, CPU/memory snapshot, start time where available
2. `inspect_parent_tree`
   - process ancestry and child processes
   - useful for identifying who launched a busy process
3. `sample_dimension`
   - bounded temporal sampling over an LLM-requested dimension, duration, and interval
   - see `todos/2026-05-19-temporal-sampling-investigation-tools.md`
4. `collect_network_basics`
   - interfaces, routes, DNS reachability, listening sockets where safe/available
5. `collect_services`
   - `launchd` on macOS
   - `systemd` on Linux
   - failed/restarting service summary
6. `collect_recent_logs`
   - strict bounded recent error/warning excerpts
   - explicit privacy notes
   - platform-specific backends (`log`, journal, syslog)
7. `collect_containers`
   - Docker / Colima / Lima / Podman where available
   - read-only container/resource summary
8. `collect_scheduled_jobs`
   - cron, launchd timers, systemd timers where available
9. `collect_certificates`
   - expiring certs in common local stores/paths, later
10. `collect_time_sync`
   - clock skew/time sync state

## Requirements

- Return evidence envelopes, not prose.
- Be read-only.
- Represent unsupported/missing permission as `unknown`/`unable`, not panics.
- Capture source, command/API used, latency, timestamp, and target.
- Avoid arbitrary shell. If shelling out is necessary, use fixed commands and argument arrays only.
- Keep output bounded and testable.
- Add fixtures/tests for parsing.

## Acceptance Criteria

This todo is complete when at least the next prioritized collector set is implemented, tested, and exposed as Descartes read-only tools for the triage agent.
