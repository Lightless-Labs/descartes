# Descartes VM Inventory Collector Plan

**Created:** 2026-05-20  
**Status:** Completed  
**Completed:** 2026-05-20 — implemented `collect_vms`, parser tests, guarded triage exposure, docs updates, and v0.0.21 metadata bump.

## Goal

Add a guarded read-only `collect_vms` tool so questions about “containers or VMs” do not rely on container evidence plus process heuristics. The immediate field gap is Tart: if Tart is installed but has no running VMs, Descartes should still report the runtime as installed/available.

## Scope

- macOS-oriented runtimes: Tart, Lima, Multipass, VirtualBox.
- Linux/common runtimes: libvirt/virsh, Lima, Multipass, VirtualBox.
- Normalize runtime availability, VM inventory, state, resource-ish fields where exposed, probe metadata, and missing/unsupported runtime entries.
- Keep Docker/Colima container-host context in `collect_containers`; `collect_vms` may include Lima as VM inventory because Lima instances are VM-backed environments.

## Safety

- Read-only fixed command argv arrays only.
- No start/stop/create/delete/snapshot/clone operations.
- Strict VM/runtime bounds.
- Missing commands, stopped services, and permission-limited sockets must not fail the whole collector.
- VM names, paths, IPs, and runtime metadata are sensitive diagnostic artifacts.

## Acceptance Criteria

- Parser tests cover Tart, Lima, Multipass, VirtualBox, libvirt/virsh, bounds, and missing/permission command classification.
- `collect_vms` is exposed in the guarded triage tool surface.
- The triage prompt tells the model to use `collect_vms` for Tart/UTM/Parallels/VMware/VirtualBox/Multipass/Lima/libvirt/QEMU/VM questions.
- README/handoff/todo document the collector and package metadata is bumped.
- `npm test` passes.
