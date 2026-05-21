# Descartes Collector Reference

**Updated:** 2026-05-21

This is the reference catalog for Descartes' current read-only evidence collectors and model-visible investigation tools. The source-adjacent developer guide lives at `tools/descartes-cli/src/tools/README.md`.

Normal `descartes triage` is model-led: the model chooses among these guarded tools, and each tool returns structured local evidence. `collect_triage_evidence` is intentionally still only the compact resource-pressure bundle, not an all-collectors bundle.

## Safety and privacy notes

- Collectors are read-only and must not mutate host state.
- No arbitrary shell/coding tools are exposed to the triage agent.
- Local evidence may include sensitive operational facts such as hostnames, usernames where relevant, process names, redacted command lines, service names, log excerpts, container/VM names, network listeners, mount paths, scheduled commands, NTP peers, and local paths.
- Redaction is best effort and does not make reports safe for broad sharing.
- Evidence may be sent to the selected LLM provider only for an explicit user-requested triage flow.

## Model-visible tools

| Tool | Envelope ID / output | Platforms | Parameters |
|---|---|---|---|
| `collect_system` | `system-overview` | macOS, Linux | none |
| `collect_processes` | `top-processes` | macOS, Linux | `limit?: 1..25` |
| `collect_disks` | `disk-usage` | macOS, Linux | none |
| `collect_network_basics` | `network-basics` | macOS, Linux | `check_dns_reachability?: boolean`, `socket_limit?: 1..200` |
| `collect_services` | `services` | macOS launchd, Linux systemd | `service_limit?: 1..200` |
| `collect_recent_logs` | `recent-logs` | macOS unified log, Linux journal/log files | `window_minutes?: 1..360`, `event_limit?: 1..200`, `include_security?: boolean` |
| `collect_containers` | `containers` | macOS, Linux | `container_limit?: 1..200`, `host_limit?: 1..100`, `include_stopped?: boolean`, `collect_stats?: boolean` |
| `collect_vms` | `vms` | macOS, Linux | `vm_limit?: 1..200` |
| `collect_scheduled_jobs` | `scheduled-jobs` | macOS, Linux | `job_limit?: 1..200`, `include_system?: boolean`, `include_user?: boolean` |
| `collect_time_sync` | `time-sync` | macOS, Linux | `check_offset?: boolean`, `server?: string` |
| `inspect_process` | `process-<pid>` | macOS, Linux | `pid: number` |
| `inspect_parent_tree` | `parent-tree-<pid>` | macOS, Linux | `pid: number`, `max_depth?: 1..64` |
| `sample_dimension` | `sample-<dimension>` | macOS, Linux | `dimension`, `duration_seconds?: 1..60`, `interval_seconds?: 1..60`, `top_n?: 1..20`, `aggregation?: ...` |
| `read_sampling_artifact` | `sampling-artifact-<id>` | macOS, Linux | `artifact_id: string`, `max_samples?: 1..25` |
| `collect_triage_evidence` | bundle: `evidence[]`, `findings[]`, `actions_taken: []` | macOS, Linux | none |
| `derive_findings` | `findings[]` | platform-independent | `evidence: any[]` |

## Collector details

### `collect_system`

Collects OS and resource overview facts: hostname, platform, OS release, architecture, uptime, CPU count, load averages, memory, and swap.

Sources:

- Node.js `os` APIs.
- Linux swap: `/proc/meminfo`.
- macOS swap: fixed `sysctl vm.swapusage`.

Privacy: may include hostname and machine shape.

### `collect_processes`

Collects top CPU and memory processes with bounded/redacted command lines.

Sources:

- Linux: fixed `ps -eo pid,ppid,pcpu,pmem,rss,comm,args`.
- macOS: fixed BSD-style `ps` process table snapshot.

Privacy: process names and command lines can be sensitive. Obvious secrets and high-entropy tokens are redacted best effort.

### `inspect_process`

Inspects one PID with process identity, bounded/redacted command line, parent summary, and child summaries.

Sources:

- Fixed `ps` snapshots.
- Linux `/proc` metadata where available.

Privacy: same sensitivity as `collect_processes`, but focused on one PID and lineage context.

### `inspect_parent_tree`

Inspects a bounded parent/ancestry chain for one PID.

Sources:

- Fixed `ps` snapshots.
- Linux `/proc` metadata where available.

Privacy: can reveal parent command lines and user/session context; command lines are bounded/redacted best effort.

### `collect_disks`

Collects filesystem space and inode usage, with pressure relevance classification to reduce noise from pseudo filesystems and developer runtime images.

Sources:

- Fixed `df -kP`.
- Fixed `df -iP` where supported.

Privacy: mount points and filesystem names may reveal local paths, volumes, and project/tooling names.

### `collect_network_basics`

Collects network interface facts, default route, DNS resolver/reachability, and listening socket inventory.

Sources:

- Node.js `os.networkInterfaces()`; MAC addresses are intentionally omitted.
- Linux: fixed `ip route show default`, `/etc/resolv.conf`, `ss -H -ltnu`.
- macOS: fixed `route -n get default`, `scutil --dns`, `lsof -nP -iTCP -sTCP:LISTEN`.
- Optional DNS reachability: Node.js DNS lookup of `example.com` unless disabled.

Privacy: may include local IP addresses, resolver addresses, default gateway/interface, listening ports, and process names for listeners where available.

### `collect_services`

Collects service manager state and summaries of failed/restarting/nonzero-exit jobs.

Sources:

- Linux: fixed `systemctl list-units --type=service --all --no-pager --no-legend`.
- macOS: fixed `launchctl list`.

Privacy: service names and labels can reveal installed software and local operational role.

### `collect_recent_logs`

Collects bounded warning/error log excerpts and fail2ban/firewall-oriented signals.

Sources:

- Linux: fixed `journalctl` queries for warnings/errors, fail2ban, firewall units, and kernel firewall messages; fixed `tail` probes for `/var/log/fail2ban.log` and `/var/log/ufw.log` where available.
- macOS: fixed `log show --style ndjson` predicates for recent errors/faults and firewall/security-oriented messages.

Privacy: log excerpts are sensitive diagnostic artifacts. Messages are bounded and obvious secrets are redacted best effort, but logs are not safe for broad sharing.

### `collect_containers`

Collects bounded container runtime evidence and container-host context.

Sources:

- Docker: fixed version/list/stats probes.
- Podman: fixed version/list/stats probes.
- Colima and Lima: fixed host/runtime context probes.

Behavior: missing commands, stopped daemons, and permission-limited sockets are represented per runtime. No container mutating commands are exposed.

Privacy: may include container names, images, commands, ports, mounts, networks, and resource snapshots.

### `collect_vms`

Collects bounded local VM runtime inventory and VM-like process hints.

Sources:

- macOS/common: Tart, Lima, Multipass, VirtualBox, Parallels, VMware, UTM app/process detection, Podman machine.
- Linux/common: libvirt/virsh, Lima, Multipass, VirtualBox, VMware, Podman machine, Incus/LXD VM mode, Proxmox `qm`, Xen `xl`, direct QEMU/VMware process hints.
- Fixed process snapshots for direct VM-like process hints.

Behavior: missing commands, unsupported runtimes, daemon failures, and permission limitations are represented per runtime/probe. No VM mutating commands are exposed.

Privacy: may include VM names, local paths, runtime metadata, IP addresses where reported by runtime tools, and bounded/redacted process hints.

### `collect_scheduled_jobs`

Collects bounded scheduled job evidence.

Sources:

- User cron: fixed `crontab -l`.
- System cron: regular-file-checked, byte-capped reads of `/etc/crontab`, `/etc/cron.d`, cron/periodic directories where present.
- Linux timers: fixed `systemctl list-timers --all --no-pager --no-legend` and `systemctl --user list-timers --all --no-pager --no-legend`.
- macOS scheduled launchd jobs: bounded reads of launchd plist paths through fixed `plutil -convert json -o - <plist>`.

Behavior: absent user crontabs, non-regular cron paths, oversized cron files, and missing/permission-limited scheduler sources are represented per probe. Returned jobs are selected fairly across scheduler sources so one source cannot hide all others. No scheduled jobs are modified.

Privacy: scheduled job labels, paths, schedules, users, and commands can be sensitive. Commands are bounded/redacted for obvious secrets best effort.

### `collect_time_sync`

Collects local clock and time synchronization state. It does not adjust the system clock.

Sources:

- Linux: fixed `timedatectl show`, `timedatectl status --no-pager`, optional `chronyc tracking`, optional `ntpq -pn`.
- macOS: fixed `launchctl print system/com.apple.timed`, best-effort `/usr/sbin/systemsetup -getusingnetworktime`, and `/usr/sbin/systemsetup -getnetworktimeserver`.
- Optional direct offset check: fixed `sntp -t 2 <server>` only when `check_offset: true` is requested. Server values are validated as host/IP-like values and rejected if they could be interpreted as options or paths.

Network: only `check_offset: true` contacts the requested/default NTP server. The collector rejects server values such as `-s`/`-S` before invoking `sntp` and never uses clock-setting actions.

Privacy: may include timezone, local RTC setting, NTP synchronization state, NTP server names/peers, and offset estimates.

### `sample_dimension`

Collects bounded temporal samples for one dimension.

Supported dimensions:

- `cpu_processes`
- `memory_processes`
- `load_memory_swap`

Policy bounds:

- maximum duration: 60 seconds
- minimum interval: 1 second
- maximum samples: 120
- maximum top processes: 20
- optional Descartes-owned sampling artifact when requested by aggregation mode

Privacy: process samples include bounded/redacted command lines; artifacts are sensitive diagnostic artifacts stored only under Descartes-owned cache paths.

### `read_sampling_artifact`

Reads a bounded excerpt from a Descartes-owned sampling artifact previously returned by `sample_dimension`.

This is not a general file reader. Artifact IDs must match the Descartes sampling artifact pattern and resolve under Descartes-owned cache paths.

### `collect_triage_evidence`

Collects the compact first-pass resource-pressure bundle:

- `collect_system`
- `collect_processes`
- `collect_disks`
- deterministic `derive_findings`
- `actions_taken: []`

Policy: do not expand this into every new collector. New collectors should remain targeted tools so the model chooses them intentionally.

### `derive_findings`

Computes deterministic findings from evidence envelopes for grounding and fallback behavior.

Current finding families include load pressure, memory pressure, swap pressure, disk pressure, dominant resource consumers, multiple resource consumers, runtime-image notices, and insufficient evidence.

This tool does not collect new local facts.

## Adding or changing collectors

When a collector is added or changed, update:

- source code under `tools/descartes-cli/src/tools/`
- tests under `tools/descartes-cli/test/`
- `tools/descartes-cli/src/pi-harness.js`
- `tools/descartes-cli/src/tool-policy.js`
- this reference doc
- `tools/descartes-cli/src/tools/README.md` if the collector structure/process changes
- `README.md`, `docs/HANDOFF.md`, and relevant plans/todos
