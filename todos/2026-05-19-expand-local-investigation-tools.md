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
- `collect_triage_evidence`
- `derive_findings`

## Current Next Priority

The process identity/lineage slice in `todos/2026-05-19-process-identity-lineage-tools.md`, disk evidence noise reduction in `todos/2026-05-19-macos-disk-evidence-classification.md`, bounded temporal sampling in `todos/2026-05-19-temporal-sampling-investigation-tools.md`, network basics, service manager basics, bounded recent logs, and container basics are complete. The next collector-oriented priorities are VMs and scheduled jobs.

## Candidate Next Tools

Prioritize tools that answer common first-triage questions without privileged mutation:

1. `collect_vms`
   - parity-oriented normalized VM inventory across macOS and Linux
   - macOS: Tart / Lima VMs / UTM / Multipass / VMware / VirtualBox / Parallels where available
   - Linux: libvirt/KVM/QEMU, direct QEMU processes, VirtualBox, VMware, Multipass, Lima, Incus/LXD VMs, Podman machine, Proxmox `qm`, Xen where available
   - read-only VM inventory, state, resource summary, and owning runtime/source
   - distinguish VM runtime discovery from active VM inventory; do not start/stop/create/delete anything
   - dedicated plan: `todos/2026-05-19-vm-inventory-collector.md`
2. `collect_scheduled_jobs`
   - cron, launchd timers, systemd timers where available
3. `collect_certificates`
   - expiring certs in common local stores/paths, later
4. `collect_time_sync`
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
