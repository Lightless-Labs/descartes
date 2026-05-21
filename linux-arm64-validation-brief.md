# Linux ARM64 Validation Brief

## Goal

Validate Descartes VM/container/runtime collectors, scheduled-job evidence, and time-sync evidence on **Linux ARM64 only** for now, across representative distributions. Focus on graceful behavior, parser/runtime compatibility, and no mutating actions.

## Target Distributions

Prioritize:

1. **Ubuntu 24.04 ARM64**
   - Main baseline; common procps/systemd/journalctl/libvirt packaging.
2. **Debian 12 ARM64**
   - Conservative package versions.
3. **Fedora 40/41 ARM64**
   - Newer Podman/libvirt/systemd ecosystem.
4. Optional if easy: **Arch Linux ARM**
   - Rolling/latest output formats.

## Environment Prerequisites

- Node.js **22.19.0+**.
- Writable npm prefix, for example `--prefix "$HOME/.local"`.
- Fresh install from GitHub after latest push:

```bash
npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes
export PATH="$HOME/.local/bin:$PATH"
descartes --version
```

- Do not use privileged or destructive commands unless setup requires package install.
- No `descartes` mutating actions exist/should occur.

## Checks To Run Everywhere

### 1. Basic install/help/version

```bash
descartes --version
descartes --help
```

Expected:

- Version should be latest, currently `0.0.25` or newer.
- Help works from npm symlink.

### 2. Built-in test suite if repo checkout exists

```bash
npm test
```

Expected:

- All tests pass.
- Current expected count is around **111** tests, but do not fail solely on count drift if pass/fail is clean.

### 3. Direct collector smoke: scheduled job evidence

From repo checkout:

```bash
node --input-type=module -e '
import { collectScheduledJobsEvidence } from "./tools/descartes-cli/src/tools/scheduled-jobs.js";
const e = await collectScheduledJobsEvidence({ jobLimit: 20 });
console.log(JSON.stringify({
  id: e.id,
  status: e.status,
  summary: e.result.summary,
  job_count: e.result.jobs.length,
  jobs: e.result.jobs.slice(0, 10).map(j => ({
    kind: j.kind,
    source: j.source,
    scope: j.scope,
    schedule: j.schedule,
    unit: j.unit,
    activates: j.activates,
    path: j.path,
    command: j.command,
    command_redaction: j.command_redaction
  })),
  probes: e.result.probes.map(p => ({
    source: p.source,
    status: p.status,
    path: p.path,
    command: p.command,
    job_count: p.job_count,
    error: p.error,
    stderr: p.stderr
  }))
}, null, 2));
'
```

Expected:

- Returns a single `scheduled-jobs` envelope.
- No crash if `crontab` or `systemctl --user` are missing/unavailable.
- Cron/systemd timer probe failures are represented per source.
- Scheduled command lines are bounded and redact obvious secrets.
- Linux `systemctl list-timers --all --no-pager --no-legend` parsing works where systemd is present.

### 4. Direct collector smoke: time sync evidence

From repo checkout:

```bash
node --input-type=module -e '
import { collectTimeSyncEvidence } from "./tools/descartes-cli/src/tools/time-sync.js";
const e = await collectTimeSyncEvidence({ checkOffset: false });
console.log(JSON.stringify({
  id: e.id,
  status: e.status,
  summary: e.result.summary,
  probes: e.result.probes.map(p => ({
    source: p.source,
    status: p.status,
    optional: p.optional,
    command: p.command,
    error: p.error,
    stderr: p.stderr,
    parsed: p.parsed
  }))
}, null, 2));
'
```

Expected:

- Returns a single `time-sync` envelope.
- No crash if `chronyc`, `ntpq`, or `sntp` are missing.
- Linux `timedatectl show/status` failures are represented as unavailable sources, not panics.
- Optional chrony/ntpq failures do not make the whole envelope fail if timedatectl works.
- No external NTP server is contacted unless `checkOffset: true` is explicitly requested.

### 5. Direct collector smoke: VM evidence

From repo checkout:

```bash
node --input-type=module -e '
import { collectVmEvidence } from "./tools/descartes-cli/src/tools/vms.js";
const e = await collectVmEvidence({ vmLimit: 20 });
console.log(JSON.stringify({
  id: e.id,
  status: e.status,
  summary: e.result.summary,
  runtimes: e.result.runtimes.map(r => ({
    runtime: r.runtime,
    installed: r.installed,
    available: r.available,
    support_status: r.support_status,
    version: r.version
  })),
  vm_count: e.result.vms.length,
  probes: e.result.probes.map(p => ({
    name: p.name,
    status: p.status,
    support_status: p.support_status,
    result_count: p.result_count
  }))
}, null, 2));
'
```

Expected:

- Returns a single `vms` envelope.
- No crash if tools are missing.
- Missing runtimes appear as `support_status: "missing"`.
- Permission/daemon failures are represented, not fatal.
- `ps` process scan probe should work on Linux ARM64.

### 6. Direct collector smoke: container evidence

```bash
node --input-type=module -e '
import { collectContainerEvidence } from "./tools/descartes-cli/src/tools/containers.js";
const e = await collectContainerEvidence({ containerLimit: 20, hostLimit: 20, collectStats: false });
console.log(JSON.stringify({
  id: e.id,
  status: e.status,
  summary: e.result.summary,
  runtimes: e.result.runtimes.map(r => ({
    runtime: r.runtime,
    installed: r.installed,
    available: r.available,
    support_status: r.support_status,
    version: r.version
  })),
  containers: e.result.containers.length,
  hosts: e.result.container_hosts.length
}, null, 2));
'
```

Expected:

- Same graceful missing/permission behavior.
- Docker/Podman installed-but-daemon-down should not crash.

## Runtime-Specific Validation Matrix

Run what is feasible per distribution. It is okay if not all runtimes are installable.

### A. Empty/minimal host

No Docker/Podman/libvirt/etc installed. Cron/systemd tools may or may not be present depending image type.

Expected:

- `collect_vms` returns `unknown` or similar non-crash status.
- Runtimes listed with `missing`.
- `summary.vm_count: 0`.
- `collect_containers` similarly reports missing runtimes.
- `collect_scheduled_jobs` returns `scheduled-jobs` without crashing; absent crontab/timer sources are represented as absent/unable per probe.
- `collect_time_sync` returns `time-sync` without crashing; missing optional chrony/ntpq tools are represented per probe.

### B. Podman installed, no machines/containers

Install Podman normally.

Commands to inspect externally:

```bash
podman --version
podman ps --all
podman machine list --format json || true
```

Then run collectors.

Expected:

- `collect_containers` sees Podman installed/available if rootless Podman works.
- Empty container list is accepted.
- `collect_vms` handles `podman machine list --format json`:
  - available with zero VMs, or
  - unsupported/daemon/unable depending distro support, but no crash.

### C. Docker CLI installed, daemon absent or inactive

Install Docker CLI only, or stop daemon if safe in a disposable VM.

Expected:

- Docker is `installed: true` if `docker version` or the CLI probe can run enough.
- If daemon unavailable, support status should be `daemon_unavailable` or `unable`, not crash.
- No container list required.

### D. libvirt/virsh installed

Install `libvirt-clients`/`virsh` equivalent. Do not require starting VMs.

```bash
virsh list --all || true
```

Expected:

- If permission denied or no daemon: represented as `permission_limited`, `daemon_unavailable`, or `unable`.
- If accessible: runtime `libvirt` available and VMs parsed.

### E. QEMU process hint

On a disposable host, if feasible, run a harmless long-lived QEMU command that does not boot a real VM, or use an existing QEMU VM if already present. Do **not** create complex mutable infrastructure just for this.

Expected:

- `collect_vms` detects `qemu` runtime/process hint.
- VM entry has:
  - `runtime: "qemu"`
  - `state: "running"`
  - `confidence: 0.4`
  - bounded/redacted `owner_hint`
  - resource snapshot with PID/CPU/memory/RSS.

### F. Incus/LXD if native on distro

On Ubuntu/Debian/Fedora where convenient:

```bash
incus list --format json || true
lxc list --format json || true
```

Expected:

- Missing command is fine.
- Permission/daemon issues are represented.
- If VM instances exist, only `type: "virtual-machine"` entries should become VMs; containers should be ignored by `collect_vms`.

### G. Cron and systemd timers

On systemd distributions, inspect externally with fixed read-only commands:

```bash
crontab -l || true
systemctl list-timers --all --no-pager --no-legend || true
systemctl --user list-timers --all --no-pager --no-legend || true
ls -la /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
```

Then run `collect_scheduled_jobs`.

Expected:

- User crontab absence is `absent`, not a fatal failure.
- Large cron files are size-checked and read with a byte cap before parsing; non-regular cron paths are represented as unavailable.
- Systemd timers are parsed into `kind: "systemd_timer"` jobs with `unit` and `activates` where present.
- Cron entries from `/etc/crontab` and `/etc/cron.d` preserve schedule/user fields and redact obvious secrets in command text.
- Permission-limited cron directories/files are represented as unavailable sources rather than panics.
- No mutating scheduler commands are run.

### H. Time sync state

On systemd distributions, inspect externally with fixed read-only commands:

```bash
timedatectl show --property=Timezone --property=LocalRTC --property=NTP --property=CanNTP --property=NTPSynchronized --property=TimeUSec --property=RTCTimeUSec || true
timedatectl status --no-pager || true
chronyc tracking || true
ntpq -pn || true
```

Then run `collect_time_sync`.

Expected:

- `timedatectl` fields parse into `summary.synchronized`, `summary.ntp_enabled`, `timezone`, and `local_rtc` where present.
- Missing `chronyc`/`ntpq` is optional and does not fail the whole envelope.
- If a selected `ntpq` peer or chrony offset exists, offset is represented in seconds.
- No clock-setting commands are run.
- Do not run the optional `checkOffset: true` mode unless you explicitly want an external NTP query.
- If `checkOffset: true` is tested, server values starting with `-` or containing whitespace/path separators should be rejected before any `sntp` command is run.

### I. Multipass / VirtualBox / Xen / Proxmox

Only if naturally available on the ARM64 target.

Expected:

- Missing is okay.
- If installed, fixed probes return structured runtime/probe state.
- No collector crash from unsupported architecture packages.

## Model-Led Triage Validation

With credentials available:

```bash
descartes triage "do I have any containers or VMs running?" --json
```

And, if credentials are available, scheduler/time-targeted prompts:

```bash
descartes triage "do I have any scheduled jobs or timers that could be causing recurring load?" --json
descartes triage "is my clock or NTP synchronization broken?" --json
```

Expected:

- `diagnostics.active_tools` includes guarded tool list, including `collect_containers`, `collect_vms`, `collect_scheduled_jobs`, and `collect_time_sync`.
- Model should call `collect_containers` and `collect_vms` for the containers/VMs prompt.
- Model should call `collect_scheduled_jobs` for the scheduler/timers prompt.
- Model should call `collect_time_sync` for the clock/NTP prompt.
- `fallback_used: false` if auth/model succeeds.
- `actions_taken: []`.
- Final diagnosis cites relevant envelope IDs such as `containers`, `vms`, `scheduled-jobs`, and/or `time-sync`.
- No arbitrary shell/coding tools appear.

If no credentials:

- Skip model-led triage and just run direct collectors.

## Report Back

For each distro, provide:

```bash
uname -a
cat /etc/os-release
node --version
descartes --version
```

Installed relevant tools:

```bash
command -v crontab systemctl timedatectl chronyc ntpq sntp docker podman virsh qemu-system-aarch64 qemu-system-x86_64 limactl multipass VBoxManage incus lxc qm xl || true
```

Include:

- Collector JSON summaries from scheduled-job, time-sync, VM, and container smoke commands.
- Any stderr/errors classified incorrectly.
- Whether any command hung or exceeded timeout.
- Whether any runtime output format failed to parse despite command success.
- Whether model-led triage called the expected tools, if tested.
