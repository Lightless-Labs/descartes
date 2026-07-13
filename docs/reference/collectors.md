# Descartes Collector Reference

**Updated:** 2026-05-22

This is the reference catalog for Descartes' current read-only evidence collectors and model-visible investigation tools. The source-adjacent developer guide lives at `tools/descartes-cli/src/tools/README.md`.

Normal `descartes triage` is model-led: the model chooses among these guarded tools, and each tool returns structured local evidence. `collect_triage_evidence` is intentionally still only the compact resource-pressure bundle, not an all-collectors bundle.

`descartes incident freeze` reuses this same registered collector set (the broad `collect_*` tools) to persist a Descartes-owned forensic snapshot on demand, without adding any new evidence-collection surface. It is documented separately at `docs/reference/incident-freeze.md` since it is an action, not a collector.

## Safety and privacy notes

- Collectors are read-only and must not mutate host state.
- No arbitrary shell/coding tools are exposed to the triage agent.
- Local evidence may include sensitive operational facts such as hostnames, usernames where relevant, process names, redacted command lines, service names, log excerpts, container/VM names, network listeners, mount paths, scheduled commands, NTP peers, certificate subjects/issuers/fingerprints, and local paths.
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
| `collect_certificates` | `certificates` | macOS, Linux | `warning_days?: 1..3650`, `certificate_limit?: 1..500` |
| `collect_sessions` | `sessions` | macOS, Linux | `session_limit?: 1..500` |
| `inspect_process` | `process-<pid>` | macOS, Linux | `pid: number` |
| `inspect_parent_tree` | `process-parent-tree-<pid>` | macOS, Linux | `pid: number`, `max_depth?: 1..64` |
| `inspect_runtime_provenance` | `provenance-<pid\|port\|container>-<value>` | macOS, Linux | exactly one of `pid: number`, `port: 1..65535`, `container: string` |
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

### `inspect_runtime_provenance`

Target-first provenance lookup: resolves exactly one of `pid`, `port`, or `container` (rejecting zero or multiple targets deterministically rather than guessing) into one provenance record: process/executable identity, a deterministic source classification (`launchd`/`systemd`/`cron`/`shell`/`ssh`/`supervisor`/`container`/`init`/`unknown`), listening socket context for port lookups, and fact-only warnings (not yet alerts).

Sources:

- Linux `pid`: `/proc/<pid>/exe` readlink (also the deleted-executable signal: a kernel-asserted `(deleted)` suffix), `/proc/<pid>/status` uid, fixed `ps -eo pid,ppid,uid,pcpu,pmem,rss,ucomm,args` for identity/ancestry.
- macOS `pid`: fixed `ps -axo pid,ppid,uid,pcpu,pmem,rss,ucomm,args` for identity/ancestry, fixed `lsof -a -p <pid> -d txt` plus a targeted `fs.stat` for the executable path (a `stat` `ENOENT` while lsof still shows the FD open is the inferred, reduced-confidence deleted-executable signal — macOS has no kernel-provided suffix), fixed `codesign -dv` for signature identity, and fixed `spctl --assess -t execute` surfaced only as a low-confidence operator-facing signal (never a hard rule input).
- Linux `port`: `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` for the matching local port and owning uid/inode (a confident fact even when pid resolution fails), then an own-uid `/proc/<pid>/fd` inode walk to resolve the pid. Other-UID sockets return the owning uid as a fact and degrade the pid to unresolved rather than guessing.
- macOS `port`: fixed `lsof -nP -iTCP:<port> -sTCP:LISTEN`, then delegates to the `pid` mechanics above.
- `container`: fixed `docker inspect -f '{{.State.Pid}}' <id>` / `podman inspect -f '{{.State.Pid}}' <id>` to resolve the container's top pid, then delegates to the `pid` mechanics above.
- uid→username: fixed `id -un <uid>`; a non-zero exit, timeout, or non-bare-token stdout yields `username_unavailable: true`, never a guessed username.

Behavior: unprivileged only — never escalates privilege, never shells out (every command is a fixed argv with a timeout and bounded buffer). Cross-UID, unresolvable, or permission-limited facts degrade explicitly (`status: "unable"` or `"partial"`, `confidence: 0` or `0.4`, `review_hint: "missing_permission"`) and never fabricate a pid, owner, or identity. Warnings surfaced are facts only in this collector (`deleted_exe_running`, `public_bind_no_supervisor`, `unexpected_parent`); a public bind is recognized via the address literals `0.0.0.0`, `[::]`, and the bare `*` form.

Privacy: process identity, executable paths, redacted/bounded command lines, usernames, and code-signing identities can be sensitive. Command/args fields reuse `processes.js`'s redaction helper verbatim.

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
- Podman machine: fixed `podman machine list --format json` host-context probe when available.

Behavior: missing commands, stopped daemons, and permission-limited sockets are represented per runtime. Docker and Podman container commands are bounded/redacted for obvious secrets and include command redaction metadata. Colima, Lima, and Podman machine host entries include VM-correlation metadata so matching VM inventory can be connected by name/runtime when both collectors are called. When deterministic QEMU or Apple Virtualization process matches are available, host entries also get bounded process resource snapshots from a fixed read-only `ps` scan. No container mutating commands are exposed.

Privacy: may include container names, images, bounded/redacted commands, ports, mounts, networks, container-host names/addresses, and resource snapshots.

### `collect_vms`

Collects bounded local VM runtime inventory and VM-like process hints.

Sources:

- macOS/common: Tart, Colima, Lima, Multipass, VirtualBox, Parallels, VMware, UTM app/process detection, Apple Virtualization process hints, Podman machine.
- Linux/common: Colima where installed, libvirt/virsh, Lima, Multipass, VirtualBox, VMware, Podman machine, Incus/LXD VM mode, Proxmox `qm`, Xen `xl`, direct QEMU/VMware process hints.
- Fixed process snapshots for direct VM-like process hints.

Behavior: missing commands, unsupported runtimes, daemon failures, and permission limitations are represented per runtime/probe. Direct QEMU/VMware/UTM/Apple Virtualization process hints are correlated back into matching runtime inventory entries when names/runtimes/paths match, so resource snapshots can be attached without double-counting the VM. QEMU and Apple Virtualization path/name matching includes common Colima, Lima, and Podman machine identifiers. Colima, Lima, and Podman machine VM entries include container-host correlation metadata so container-host inventory can be connected by name/runtime when both collectors are called. No VM mutating commands are exposed.

Privacy: may include VM names, local paths, runtime metadata, IP addresses where reported by runtime tools, resource snapshots, and bounded/redacted process hints.

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

### `collect_certificates`

Collects bounded local certificate validity evidence. It is intended for TLS/certificate expiry, local trust-store, Let's Encrypt, and common web-server certificate questions. It does not read private keys.

Sources:

- Linux/common paths: `/etc/ssl/certs`, `/etc/ssl/cert.pem`, `/usr/local/share/ca-certificates`, `/etc/pki/tls/certs`, `/etc/letsencrypt/live`, and common nginx/apache/httpd SSL directories when present.
- macOS/common paths: `/etc/ssl/certs`, `/etc/ssl/cert.pem`, Homebrew certificate stores, and fixed read-only `security find-certificate -a -p` probes for system root/system keychains.

Behavior: file reads are regular-file checked, byte bounded, count bounded, and selected results prioritize expired/soon-expiring certificates. Missing common paths are represented per source. Private-key filenames such as `privkey.pem` are intentionally skipped.

Privacy: certificate subjects, issuers, serial/fingerprint prefixes, keychain names, and local certificate paths can reveal domains, organizations, host roles, and internal infrastructure names.

### `collect_sessions`

Collects a read-only census of resident tmux/screen sessions for the invoking user: session name, attached/detached state, window count, and creation time where the multiplexer exposes it. Same-UID only — v0 does not attempt to enumerate other users' sessions.

Sources:

- Fixed `tmux list-sessions -F '#{session_name}\t#{session_windows}\t#{session_attached}\t#{session_created}'`.
- Fixed `screen -ls`. `screen -ls` is known to exit non-zero on some versions even when it succeeds and sessions exist; the collector inspects stdout/stderr for screen's own recognizable session-listing content before treating a non-zero exit as a real failure, rather than misclassifying a healthy listing as unavailable.

Behavior: degrade-not-fabricate — when neither `tmux` nor `screen` is present on the host, the envelope reports `status: "unable"`, `confidence: 0`; this is never conflated with "0 sessions". A multiplexer that IS present and genuinely reports zero sessions (tmux with no server running, screen's "No Sockets found") is a real, distinguishable fact: `status: "ok"`, an empty session list. Per-tick session entities are bounded at `DEFAULT_SESSION_ENTITY_LIMIT` (200); a count above the cap is truncated with an explicit `truncated: true` marker and the real `total_count` preserved, rather than silently dropping entities.

Fact-history: on the daemon's hourly structural tick (gated behind the `learned.json` kill switch, like every other structural sub-collector), `factPointsFromSessionEvidence` (`fact-translators.js`) translates this census into `session.presence` fact-points. The persisted `entity_key` is a fixed-length (16-char) hex SHA-256 hash of a domain-separated preimage (`descartes.fact.session.v1:<multiplexer>:<session_name>`) — never the raw or charset-substituted session name. Persisted `attributes` are closed-enum/bucketed only: `attached` (`"true"`/`"false"`), `window_count_bucket` (`"0"`/`"1"`/`"2-4"`/`"5-9"`/`"10+"`/`"unknown"`), and `created_at_bucket` (an opaque 10-minute epoch-bucket index, or `"unknown"` for screen sessions, whose `-ls` output does not reliably expose a creation time) — never a raw session name or raw timestamp. A truncated tick additionally emits one `confidence: 0` overflow-marker fact so a session flood is visible as "truncation happened" rather than silently dropped. This collector emits fact-history only — no alert candidates; alerting on session-count deviation/churn is a separate, later slice.

Privacy: the raw, un-hashed session name IS visible in this tool's on-demand `descartes triage` response (matching the existing consent posture of every other `TRIAGE_TOOL_NAMES` collector — triage is operator-invoked and already sees raw process/service data). Only the *persisted* fact-history is hashed/bucketed.

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
