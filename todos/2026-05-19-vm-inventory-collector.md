---
title: VM Inventory Collector
created: 2026-05-19
status: completed
priority: high
area: collectors
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-expand-local-investigation-tools.md
  - docs/ROADMAP.md
---

# TODO: VM Inventory Collector

**Completed:** 2026-05-20 — implemented first VM inventory slice as `collect_vms` for Tart, Lima, Multipass, VirtualBox, and libvirt/virsh with bounded read-only probes and parser tests.  
**Enhanced:** 2026-05-20 — expanded VM parity to Parallels, VMware, UTM app/process detection, Podman machine, Incus/LXD VM mode, Proxmox `qm`, Xen `xl`, and direct QEMU/VMware/UTM process hints. Future expansion can add richer UTM inventory, richer VMware/Parallels details, Firecracker, Cloud Hypervisor, Kata Containers, and better deduplication/correlation.

## Summary

Add a parity-oriented, read-only `collect_vms` tool that discovers local VM runtimes and returns a normalized VM inventory across macOS and Linux. The tool should be runtime-agnostic at the evidence-envelope boundary, with platform/runtime-specific adapters underneath.

The goal is feature parity in shape and operator usefulness, not identical runtime availability on every host.

## Why This Matters

Descartes' future intent-based operations flow needs to answer questions like:

- What VM runtimes are installed?
- What VMs exist?
- Which VMs are running now?
- Are any VMs consuming resources?
- Which runtime owns a VM-like process?
- Could this machine satisfy a request such as “I need a quick Linux environment with npm”?

This also helps current triage: VM runtimes are common hidden CPU, memory, disk, and network consumers.

## Normalized Output Shape

Return an evidence envelope with a normalized result shape like:

```json
{
  "runtimes": [
    {
      "runtime": "libvirt | qemu | tart | lima | utm | multipass | virtualbox | vmware | parallels | incus | lxd | podman_machine | proxmox | xen",
      "installed": true,
      "available": true,
      "version": "optional",
      "support_status": "ok | missing | permission_limited | unsupported | unable",
      "source": { "command": ["virsh", "list", "--all"], "read_only": true }
    }
  ],
  "vms": [
    {
      "runtime": "libvirt",
      "id": "optional-runtime-id",
      "name": "vm-name",
      "state": "running | stopped | paused | suspended | unknown",
      "backend": "kvm | qemu | hvf | apple_virtualization | hyperkit | unknown",
      "cpus": 2,
      "memory_bytes": 4294967296,
      "disk_bytes": 21474836480,
      "ips": ["optional-safe-local-ip"],
      "owner_hint": "optional-runtime-or-process-hint",
      "resource_snapshot": {
        "pid": 1234,
        "cpu_percent": 12.3,
        "memory_percent": 4.5,
        "rss_bytes": 123456789
      },
      "source_runtime": "libvirt",
      "confidence": 1.0
    }
  ],
  "unsupported_or_missing": []
}
```

Keep fields optional where unavailable. Do not fail the whole collector because one runtime is absent, unsupported, or permission-limited.

## Platform / Runtime Coverage Targets

### macOS

Prioritize:

1. Tart
   - `tart list --format json` if available
   - Apple Virtualization / QEMU backend hints where exposed
2. Lima
   - `limactl list --json` or equivalent
3. UTM
   - command/API availability is less consistent; start with installed/running process detection if no stable CLI is available
4. Multipass
   - `multipass list --format json`
5. VirtualBox
   - `VBoxManage list vms`, `VBoxManage list runningvms`
6. VMware Fusion
   - `vmrun list` where available
   - `vmware-vmx` process correlation
7. Parallels
   - `prlctl list --all --json` where available
8. Docker Desktop / Colima backing VMs
   - treat as VM-adjacent runtime evidence, but keep container inventory separate in `collect_containers`

### Linux

Prioritize:

1. libvirt / KVM / QEMU
   - `virsh list --all`
   - `virsh dominfo <name>` for bounded per-VM details if cheap and safe
   - `/dev/kvm` presence and `kvm`, `kvm_intel`, `kvm_amd` module hints where available
2. Direct QEMU/KVM processes
   - `qemu-system-*` process detection and redacted/bounded args
   - correlate with libvirt when possible to avoid duplicates
3. VirtualBox
   - `VBoxManage list vms`, `VBoxManage list runningvms`
4. VMware Workstation / Player
   - `vmrun list`
   - `vmware-vmx` process correlation
5. Multipass
   - `multipass list --format json`
6. Lima
   - `limactl list --json` where available
7. Incus / LXD
   - `incus list --format json`, `lxc list --format json`
   - distinguish system containers from VM instances when exposed by the runtime
8. Podman machine
   - `podman machine list --format json`
9. Proxmox VE
   - `qm list` for VMs
   - note `pct list` as container inventory, not VM inventory
10. Xen
   - `xl list` where available

Firecracker, Cloud Hypervisor, and Kata Containers can be later best-effort process/runtime detection, especially on servers and platform hosts.

## Safety / Privacy

- Read-only only.
- No start/stop/create/delete/snapshot operations.
- No arbitrary shell; use fixed command argv arrays or platform APIs.
- Capture command argv, exit status/permission errors, stdout/stderr boundaries where practical.
- Bound output.
- Redact/bound process args using the shared process arg helper.
- Treat VM names, paths, IPs, and runtime metadata as sensitive diagnostic data.

## Deduplication / Correlation

A single VM may appear through multiple signals: runtime CLI, QEMU process, VM helper process, and container-adjacent tooling. The collector should prefer authoritative runtime inventory and attach process/resource hints when confidence is high.

Suggested confidence levels:

- `1.0`: authoritative runtime CLI/API inventory.
- `0.7`: process-correlated VM where runtime ownership is likely.
- `0.4`: VM-like process with insufficient owner/runtime evidence.

## Acceptance Criteria

- `collect_vms` returns one evidence envelope with normalized `runtimes`, `vms`, and `unsupported_or_missing` arrays.
- Missing runtimes are represented without failing the whole collector.
- At least one macOS adapter and one Linux adapter are implemented or explicitly represented as unsupported in tests.
- Tests cover parsing for at least libvirt, VirtualBox, Multipass, and one macOS-oriented runtime (Tart or Lima).
- Tests cover permission/missing-command handling.
- Tool is exposed through the guarded triage surface only after tests pass.
- `npm test` passes.
