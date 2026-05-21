---
title: Expand Descartes Local Read-Only Investigation Tools
created: 2026-05-19
status: completed
priority: high
area: collectors
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-llm-driven-investigation-tools.md
  - todos/2026-05-19-process-identity-lineage-tools.md
  - todos/2026-05-19-temporal-sampling-investigation-tools.md
  - todos/2026-05-19-vm-inventory-collector.md
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
- `inspect_process`
- `inspect_parent_tree`
- `sample_dimension`
- `read_sampling_artifact`
- `collect_network_basics`
- `collect_services`
- `collect_recent_logs`
- `collect_containers`
- `collect_vms`
- `collect_scheduled_jobs`
- `collect_time_sync`
- `collect_certificates`
- `collect_triage_evidence`
- `derive_findings`

## Completion Update

The process identity/lineage slice in `todos/2026-05-19-process-identity-lineage-tools.md`, disk evidence noise reduction in `todos/2026-05-19-macos-disk-evidence-classification.md`, bounded temporal sampling in `todos/2026-05-19-temporal-sampling-investigation-tools.md`, network basics, service manager basics, bounded recent logs, container basics, VM basics, scheduled job basics, time sync basics, and certificate basics are complete. Scheduled jobs and time sync were hardened after review for bounded cron file reads, fair scheduler-source selection, safe NTP server validation, and unknown-state handling. Certificates now cover bounded local validity evidence for common certificate stores/paths and skip private keys.

## Candidate Future Tools

Additional collector candidates should be opened as dedicated todos when identified.

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
