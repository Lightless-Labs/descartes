# VM / Container Resource Correlation Plan

**Created:** 2026-05-21  
**Status:** In progress  
**Addendum:** 2026-05-21 — first VM-side correlation landed: direct QEMU/VMware/UTM process hints are matched back into runtime VM inventory entries by compatible runtime/name/path signals, attaching resource snapshots without double-counting matched VMs.

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

1. Add container-host to VM correlation for Colima, Lima, and Podman machine names.
2. Add summary counts for correlated container hosts once cross-runtime matches exist.
3. Consider a combined diagnostic helper only if targeted `collect_containers` + `collect_vms` evidence remains hard for the model to synthesize.
4. Validate on macOS with UTM/Colima/Lima and Linux with Podman machine/libvirt where available.

## Safety

- Read-only only.
- Fixed command arrays only.
- No container or VM lifecycle actions.
- No expansion of `collect_triage_evidence`; correlation stays inside targeted VM/container collectors unless a future plan says otherwise.
