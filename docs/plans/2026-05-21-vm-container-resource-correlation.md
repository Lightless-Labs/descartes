# VM / Container Resource Correlation Plan

**Created:** 2026-05-21  
**Status:** In progress  
**Addendum:** 2026-05-21 — first VM-side correlation landed: direct QEMU/VMware/UTM process hints are matched back into runtime VM inventory entries by compatible runtime/name/path signals, attaching resource snapshots without double-counting matched VMs.
**Addendum:** 2026-05-21 — container-host correlation metadata landed for Colima, Lima, and Podman machine. `collect_vms` now includes Colima VM inventory, and both VM/container host entries carry explicit runtime/name correlation hints plus summary counts.
**Addendum:** 2026-05-21 — deterministic process-resource attachment landed for container hosts where QEMU process names/paths match Colima, Lima, or Podman machine host identities. `collect_containers` now attaches bounded `resource_snapshot` and `process_correlation` to matched host entries.
**Addendum:** 2026-05-22 — Apple Virtualization/VZ process attribution landed for non-QEMU Colima, Lima, Podman machine, and Tart-style inventory. `collect_vms` and `collect_containers` now recognize bounded `VirtualizationService` / `com.apple.Virtualization.VirtualMachine` process hints and correlate them by deterministic runtime/name/path signals.

## Goal

Improve Descartes' ability to answer questions such as “which VM/container is eating resources?” by connecting runtime inventories to local process resource evidence while preserving read-only, bounded evidence collection.

## Scope

- Correlate VM runtime inventory with VM-like process hints and resource snapshots.
- Correlate container host runtimes such as Colima/Lima/Podman machine with VM inventory where possible.
- Keep container runtime stats and process evidence separate unless a deterministic mapping exists.
- Represent correlation confidence and missing/ambiguous matches explicitly.

## First Slice Implemented

`collect_vms` now correlates process-backed QEMU/VMware/UTM hints into matching runtime inventory entries when names/runtimes/path hints match. Matched process hints attach `resource_snapshot` and `process_correlation` to the runtime VM entry and are not counted as separate VMs. Unmatched process hints remain visible as low-confidence process-backed VM entries.

## Next Steps

1. Validate correlation metadata/resource attachment on macOS with real QEMU and VZ/Apple Virtualization Colima/Lima/Podman machine hosts, and on Linux with Podman machine/libvirt where available.
2. Consider a combined diagnostic helper only if targeted `collect_containers` + `collect_vms` evidence remains hard for the model to synthesize.
3. Keep improving confidence scoring for ambiguous runtime/process/name matches.
4. If real-host validation shows unnamed Apple Virtualization helper processes with no path/name hints, document the process shape and add a conservative attribution rule only when ambiguity can be bounded.

## Safety

- Read-only only.
- Fixed command arrays only.
- No container or VM lifecycle actions.
- No expansion of `collect_triage_evidence`; correlation stays inside targeted VM/container collectors unless a future plan says otherwise.
