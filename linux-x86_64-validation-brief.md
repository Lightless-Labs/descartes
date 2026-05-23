# Linux x86_64 Validation Brief

**Prepared:** 2026-05-22
**Audience:** infrastructure-running agent
**Target:** Linux x86_64 Tier-1 validation for Descartes `v0.0.31+`

## Goal

Close the main remaining first-slice platform gap: true Linux x86_64 behavior. Validate public GitHub install, XDG isolation, package tests, and direct Linux collector behavior. If safe credentials are available, validate model-led guarded triage without exposing raw host diagnostics.

## Safety / Privacy

- Read-only validation only, except installing Node/npm dependencies into temporary work directories and a user-writable npm prefix.
- Do not stop/start host services, create/destroy containers, create VMs, edit cron, adjust time, or install system packages unless the host is explicitly disposable and already approved for that setup.
- Do not upload raw triage JSON, full process arguments, hostnames, usernames, logs, certificate subjects, or command lines unless separately scrubbed.
- Report sanitized summaries only: envelope IDs/statuses/sources, probe statuses, counts, selected model metadata, called tool names, fallback state, and `actions_taken`.

## Target Hosts

Required:

1. One Linux x86_64 host or VM (`uname -m` is `x86_64` or `amd64`).

Preferred matrix if easy:

1. Ubuntu 24.04 x86_64
2. Debian 13 x86_64
3. Fedora 42 x86_64

A container is acceptable for install/parser smoke coverage, but a VM or host with systemd/journal/procfs is better for service/log/timer/time validation.

## Prerequisites

- Node.js `22.19.0+`
- npm compatible with that Node release
- outbound GitHub/npm access
- writable temporary directory and writable npm prefix

Start every host with:

```bash
set -euo pipefail

case "$(uname -m)" in
  x86_64|amd64) ;;
  *) echo "wrong architecture: $(uname -m)" >&2; exit 2 ;;
esac

node --version
npm --version
uname -a
cat /etc/os-release
```

## 1. Public GitHub Install Smoke

```bash
work="$(mktemp -d)"
prefix="$work/npm-prefix"
npm install -g --prefix "$prefix" github:Lightless-Labs/descartes
export PATH="$prefix/bin:$PATH"

descartes --version | tee "$work/descartes-version.txt"
descartes --help > "$work/descartes-help.txt"
find "$prefix/lib/node_modules" -path '*/docs/reference/collectors.md' -print -quit | tee "$work/collector-doc-path.txt"
```

Expected:

- `descartes --version` is `0.0.31` or newer.
- `descartes --help` works through the npm-prefix symlink.
- `docs/reference/collectors.md` is included in the installed package.
- The known upstream `node-domexception` deprecation warning may appear; do not fail solely for that.

## 2. Isolated-XDG No-Auth Triage Failure

```bash
xdg="$work/xdg"
mkdir -p "$xdg/home" "$xdg/config" "$xdg/data" "$xdg/state" "$xdg/cache"

set +e
HOME="$xdg/home" \
XDG_CONFIG_HOME="$xdg/config" \
XDG_DATA_HOME="$xdg/data" \
XDG_STATE_HOME="$xdg/state" \
XDG_CACHE_HOME="$xdg/cache" \
descartes triage "my machine is slow" --json > "$work/no-auth.stdout" 2> "$work/no-auth.stderr"
status=$?
set -e

echo "status=$status" | tee "$work/no-auth.status"
find "$xdg" -maxdepth 5 -type f | sort | tee "$work/no-auth-files.txt"
```

Expected:

- Command exits non-zero.
- Output/stderr mentions missing configured model credentials.
- Created files, if any, are under the supplied Descartes XDG directories.
- No `.pi`, `~/.pi`, project Pi settings, shell/coding tools, or user Pi paths are touched.

## 3. Clone, Test Suite, and Pack Dry Run

```bash
cd "$work"
git clone --depth=1 https://github.com/Lightless-Labs/descartes.git repo
cd repo
npm ci
npm test | tee "$work/npm-test.txt"
npm run pack:dry-run | tee "$work/pack-dry-run.txt"
```

Expected:

- `npm test` passes.
- `npm run pack:dry-run` includes runtime source files and `docs/reference/collectors.md`, and excludes tests/local artifacts.

## 4. Direct Collector Smoke Suite

Run from the cloned repo. This intentionally prints sanitized summaries only.

```bash
cat > "$work/repo/collector-smoke.mjs" <<'NODE'
import os from "node:os";
import path from "node:path";
import { collectAllEvidence } from "./tools/descartes-cli/src/tools/collect.js";
import { collectSystemEvidence } from "./tools/descartes-cli/src/tools/system.js";
import { collectProcessEvidence, inspectProcessEvidence, inspectParentTreeEvidence } from "./tools/descartes-cli/src/tools/processes.js";
import { collectDiskEvidence } from "./tools/descartes-cli/src/tools/disks.js";
import { collectNetworkEvidence } from "./tools/descartes-cli/src/tools/network.js";
import { collectServiceEvidence } from "./tools/descartes-cli/src/tools/services.js";
import { collectRecentLogsEvidence } from "./tools/descartes-cli/src/tools/logs.js";
import { collectContainerEvidence } from "./tools/descartes-cli/src/tools/containers.js";
import { collectVmEvidence } from "./tools/descartes-cli/src/tools/vms.js";
import { collectScheduledJobsEvidence } from "./tools/descartes-cli/src/tools/scheduled-jobs.js";
import { collectTimeSyncEvidence } from "./tools/descartes-cli/src/tools/time-sync.js";
import { collectCertificateEvidence } from "./tools/descartes-cli/src/tools/certificates.js";
import { sampleDimensionEvidence } from "./tools/descartes-cli/src/tools/sampling.js";

function probeSummary(probe) {
  return {
    name: probe.name,
    source: probe.source,
    status: probe.status,
    support_status: probe.support_status,
    optional: probe.optional,
    result_count: probe.result_count,
    job_count: probe.job_count,
    certificate_count: probe.certificate_count,
    error: probe.error ? String(probe.error).slice(0, 180) : undefined,
  };
}

function envelopeSummary(name, envelope) {
  return {
    name,
    id: envelope.id,
    status: envelope.status,
    source: envelope.source,
    review_hint: envelope.review_hint,
    trace_tool: envelope.trace?.tool,
    summary: envelope.result?.summary,
    probes: (envelope.result?.probes ?? []).map(probeSummary),
    result_counts: {
      top_cpu: envelope.result?.top_cpu?.length,
      top_memory: envelope.result?.top_memory?.length,
      filesystems: envelope.result?.filesystems?.length,
      services: envelope.result?.services?.length,
      events: envelope.result?.events?.length,
      containers: envelope.result?.containers?.length,
      container_hosts: envelope.result?.container_hosts?.length,
      vms: envelope.result?.vms?.length,
      jobs: envelope.result?.jobs?.length,
      certificates: envelope.result?.certificates?.length,
    },
  };
}

const results = [];
const all = await collectAllEvidence();
results.push({
  name: "collect_all",
  evidence: all.evidence.map((e) => ({ id: e.id, status: e.status, source: e.source, review_hint: e.review_hint, tool: e.trace?.tool })),
  findings_count: all.findings.length,
  actions_taken: all.actions_taken,
});

const collectors = [
  ["system", () => collectSystemEvidence()],
  ["processes", () => collectProcessEvidence({ limit: 5 })],
  ["disks", () => collectDiskEvidence()],
  ["network", () => collectNetworkEvidence({ checkDnsReachability: false, socketLimit: 10 })],
  ["services", () => collectServiceEvidence({ serviceLimit: 10 })],
  ["recent_logs", () => collectRecentLogsEvidence({ windowMinutes: 5, eventLimit: 5, includeSecurity: true })],
  ["containers", () => collectContainerEvidence({ collectStats: false, containerLimit: 10, hostLimit: 10 })],
  ["vms", () => collectVmEvidence({ vmLimit: 10 })],
  ["scheduled_jobs", () => collectScheduledJobsEvidence({ jobLimit: 10 })],
  ["time_sync", () => collectTimeSyncEvidence({ checkOffset: false })],
  ["certificates", () => collectCertificateEvidence({ certificateLimit: 10 })],
  ["inspect_process_self", () => inspectProcessEvidence({ pid: process.pid })],
  ["inspect_parent_tree_self", () => inspectParentTreeEvidence({ pid: process.pid, maxDepth: 8 })],
  ["sample_load_memory_swap", () => sampleDimensionEvidence({ dimension: "load_memory_swap", duration_seconds: 1, interval_seconds: 1, aggregation: "summary" }, { cacheDir: path.join(os.tmpdir(), "descartes-x86-smoke-cache") })],
];

for (const [name, run] of collectors) {
  try {
    results.push(envelopeSummary(name, await run()));
  } catch (error) {
    results.push({ name, thrown: String(error?.stack ?? error).slice(0, 800) });
  }
}

console.log(JSON.stringify({ platform: process.platform, arch: process.arch, node: process.version, results }, null, 2));
NODE

node "$work/repo/collector-smoke.mjs" | tee "$work/collector-smoke.json"
```

Expected:

- No collector throws.
- Each collector returns a structured evidence envelope with `ok`, `warning`, `unknown`, or graceful `unable` status as appropriate.
- Linux process collection uses procps-compatible `ps -eo ...` behavior and redacted/bounded args internally.
- Disk collection parses Linux `df -kP` and `df -iP`; pseudo/runtime filesystems are not misreported as pressure-relevant.
- systemd service/timer and journal probes parse where available and degrade cleanly in containers.
- Missing Docker/Podman/Lima/Colima/libvirt/etc. are represented per runtime/probe, not as whole-envelope crashes.
- Time sync and certificate collectors avoid mutating commands and skip private keys.

## 5. x86_64 Runtime/Platform Snapshot

```bash
{
  echo "arch=$(uname -m)"
  command -v crontab systemctl timedatectl journalctl chronyc ntpq sntp docker podman virsh qemu-system-x86_64 qemu-kvm limactl multipass VBoxManage vmrun prlctl incus lxc qm xl || true
  timedatectl show --property=Timezone --property=LocalRTC --property=NTP --property=CanNTP --property=NTPSynchronized --property=TimeUSec --property=RTCTimeUSec || true
  systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | awk '{state[$4]++} END {for (s in state) print "system_service_state", s, state[s]}' || true
  systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | wc -l | awk '{print "failed_system_service_count", $1}' || true
  systemctl list-timers --all --no-pager --no-legend 2>/dev/null | wc -l | awk '{print "system_timer_row_count", $1}' || true
  systemctl --user list-timers --all --no-pager --no-legend 2>/dev/null | wc -l | awk '{print "user_timer_row_count", $1}' || true
  journalctl -p warning --since "15 minutes ago" --no-pager -q 2>/dev/null | wc -l | awk '{print "recent_warning_or_worse_journal_line_count", $1}' || true
  podman --version || true
  podman ps --all --format '{{.State}}' 2>/dev/null | sort | uniq -c | sed 's/^/podman_container_state /' || true
  podman machine list --format '{{.Running}} {{.VMType}}' 2>/dev/null | sort | uniq -c | sed 's/^/podman_machine_state /' || true
  docker --version || true
  docker ps --all --format '{{.State}}' 2>/dev/null | sort | uniq -c | sed 's/^/docker_container_state /' || true
  virsh list --all --name 2>/dev/null | sed '/^$/d' | wc -l | awk '{print "virsh_vm_count", $1}' || true
  virsh list --state-running --name 2>/dev/null | sed '/^$/d' | wc -l | awk '{print "virsh_running_vm_count", $1}' || true
  ps -eo comm= 2>/dev/null | sort | uniq -c | sort -nr | head -20 | sed 's/^/process_comm_count /' || true
} | tee "$work/external-capabilities.txt"
```

Expected: read-only commands complete or fail gracefully while capturing counts/states, not raw logs, process args, container names/images, VM names, or command lines. Do not make service/package/container changes to improve these results.

## 6. Optional x86_64 Runtime Coverage, Only If Already Available

If these runtimes naturally exist on the host, verify the direct collector summaries reflect them:

- Docker installed with daemon unavailable, permission-limited, or available.
- Podman installed with zero or more containers.
- Podman machine installed with zero or more machines.
- libvirt/virsh installed with daemon unavailable, permission-limited, or available.
- QEMU/KVM process hints already running.
- VirtualBox, VMware, Multipass, Incus/LXD, Proxmox, or Xen if naturally present.

Do not create workloads just for this brief unless the infrastructure owner explicitly asked for disposable-runtime setup.

## 7. Optional Credentialed Model-Led Triage

Only run if a dedicated validation credential or pre-seeded Descartes auth is available. Prefer a revocable validation account/key, not a personal token. Do not upload full JSON.

```bash
auth_xdg="$work/xdg-auth"
mkdir -p "$auth_xdg/home" "$auth_xdg/config" "$auth_xdg/data" "$auth_xdg/state" "$auth_xdg/cache"
descartes_env=(env \
  HOME="$auth_xdg/home" \
  XDG_CONFIG_HOME="$auth_xdg/config" \
  XDG_DATA_HOME="$auth_xdg/data" \
  XDG_STATE_HOME="$auth_xdg/state" \
  XDG_CACHE_HOME="$auth_xdg/cache")

# If auth is not already seeded into "$auth_xdg/config/descartes/auth.json",
# run the supported login flow in the isolated XDG environment.
# Interactive/headless OAuth fallback:
#   "${descartes_env[@]}" descartes login --no-open

for prompt in \
  "my machine is slow" \
  "do I have any containers or VMs running?" \
  "do I have any scheduled jobs or timers that could be causing recurring load?" \
  "is my clock or NTP synchronization broken?" \
  "are any local certificates expiring soon?"
do
  safe_name="$(printf '%s' "$prompt" | tr -cs '[:alnum:]' '-' | tr '[:upper:]' '[:lower:]' | sed 's/^-//;s/-$//')"
  "${descartes_env[@]}" descartes triage "$prompt" --json > "$work/triage-$safe_name.raw.json"
  node -e '
    const fs = require("fs");
    const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    console.log(JSON.stringify({
      prompt: process.argv[2],
      selected_model: j.diagnostics?.selected_model,
      fallback_used: j.diagnostics?.fallback_used,
      active_tools: j.diagnostics?.active_tools,
      tool_calls: (j.diagnostics?.tool_calls ?? []).map(c => c.tool_name),
      evidence: (j.evidence ?? []).map(e => ({ id: e.id, status: e.status, source: e.source })),
      actions_taken: j.actions_taken,
      llm_error: j.diagnostics?.llm_error
    }, null, 2));
  ' "$work/triage-$safe_name.raw.json" "$prompt" | tee "$work/triage-$safe_name.summary.json"
done
```

Expected:

- `fallback_used: false` when auth/model succeeds.
- `actions_taken: []`.
- Active tools are only guarded Descartes evidence tools.
- At least one Descartes evidence tool is called for each prompt.
- Prompt-specific tool calls should include relevant collectors: `collect_triage_evidence`, `collect_containers`, `collect_vms`, `collect_scheduled_jobs`, `collect_time_sync`, and/or `collect_certificates`.

## Acceptance Criteria

This brief is complete when the returned report shows:

- Public GitHub install, `--help`, and `--version` work on Linux x86_64.
- Isolated-XDG no-auth failure is clean and does not touch Pi-owned paths.
- `npm test` passes from a clone.
- Direct collector smoke suite returns structured summaries with no thrown collector.
- Linux x86_64 parser/runtime issues are either absent or clearly captured with sanitized errors.
- Optional credentialed validation, if run, shows guarded tool use, `fallback_used: false`, and `actions_taken: []`.

## Report Back

Return a concise host summary:

- Distro, kernel, architecture, Node/npm versions.
- `descartes --version` and installed collector-doc presence.
- `npm test` pass/fail and any failing test names.
- No-auth status and XDG file list summary.
- Sanitized `collector-smoke.json`.
- Any collector that threw, hung, returned malformed JSON, or misclassified a normal missing-permission/missing-daemon condition.
- Optional credentialed triage summaries only; do not return raw reports.
