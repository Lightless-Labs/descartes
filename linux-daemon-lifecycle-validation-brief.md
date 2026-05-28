# Linux Daemon Lifecycle Validation Brief

**Prepared:** 2026-05-24
**Audience:** infrastructure-running agent
**Target:** Linux systemd-user daemon lifecycle validation for Descartes `v0.0.39+`

## Goal

Validate the new Descartes local history daemon lifecycle on Linux:

```bash
descartes daemon install
descartes daemon start
descartes daemon status
descartes history summary
descartes daemon stop
descartes daemon uninstall
```

This brief complements the broader Linux collector/package briefs (`linux-x86_64-validation-brief.md` and `linux-arm64-validation-brief.md`). It focuses on the systemd user service lifecycle and history accumulation.

## Safety / Privacy

- Run on a disposable VM/host or a dedicated validation user.
- No `sudo` is required or allowed for the daemon lifecycle itself.
- Mutating scope is limited to the current user's Descartes systemd unit and Descartes-owned XDG state/config paths.
- Do not run this on a personal workstation if `descartes daemon status` already shows an installed service unless the owner explicitly approves replacing/removing it.
- Always run cleanup (`descartes daemon stop`, then `descartes daemon uninstall`) before returning the host unless the owner explicitly wants the daemon left running.
- Do not upload raw daemon logs, raw process arguments, hostnames, usernames, full home paths, or full history JSON unless separately scrubbed.
- Report sanitized summaries: status values, service manager, running/enabled booleans, point counts, metric names, log file sizes/counts, and errors with sensitive paths redacted.

## Target Hosts

Required:

1. One Linux x86_64 host/VM with systemd user services available.

Preferred matrix if easy:

1. Ubuntu 24.04 x86_64
2. Debian 13 x86_64
3. Fedora 42 x86_64

Optional best-effort:

1. Ubuntu 24.04 ARM64
2. Debian 13 ARM64
3. Fedora 42 ARM64

Containers usually do **not** have a working systemd user manager and are acceptable only for install/status rendering smoke, not full start/stop validation.

## Prerequisites

- Node.js `22.19.0+`
- npm compatible with that Node release
- outbound GitHub/npm access
- writable temporary directory and user-writable npm prefix
- systemd user manager available for full lifecycle validation

Start every host with:

```bash
set -euo pipefail

node --version
npm --version
uname -a
cat /etc/os-release

echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}"
systemctl --user status >/dev/null 2>&1 && echo "systemd_user=available" || echo "systemd_user=unavailable"
```

If `systemd_user=unavailable`, skip the full start/stop lifecycle and report why. Still run the install-only isolated-XDG smoke below.

## 1. Public GitHub Install Smoke

```bash
work="$(mktemp -d)"
prefix="$work/npm-prefix"
npm install -g --prefix "$prefix" github:Lightless-Labs/descartes
export PATH="$prefix/bin:$PATH"

descartes --version | tee "$work/descartes-version.txt"
descartes --help > "$work/descartes-help.txt"
```

Expected:

- `descartes --version` is `0.0.39` or newer.
- Help includes `daemon install|start|status|stop|uninstall [--json]`.
- The known upstream `node-domexception` deprecation warning may appear; do not fail solely for that.

## 2. Isolated-XDG Install Rendering Smoke (No Start)

This verifies install/status output and generated-unit handling without touching the real user service manager.

```bash
iso="$work/isolated"
mkdir -p "$iso/home" "$iso/config" "$iso/data" "$iso/state" "$iso/cache"

isolated_env=(env \
  HOME="$iso/home" \
  XDG_CONFIG_HOME="$iso/config" \
  XDG_DATA_HOME="$iso/data" \
  XDG_STATE_HOME="$iso/state" \
  XDG_CACHE_HOME="$iso/cache")

"${isolated_env[@]}" descartes daemon install | tee "$work/isolated-install-human.txt"
"${isolated_env[@]}" descartes daemon install --json | tee "$work/isolated-install-json.txt"
"${isolated_env[@]}" descartes daemon status --json | tee "$work/isolated-status-json.txt"
"${isolated_env[@]}" descartes daemon uninstall --json | tee "$work/isolated-uninstall-json.txt"

node - <<'NODE' "$work/isolated-install-json.txt" "$work/isolated-status-json.txt"
const fs = require('fs');
for (const file of process.argv.slice(2)) {
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (parsed.content !== undefined) throw new Error(`${file} leaked generated service content`);
}
NODE

if grep -q '<plist\|\[Service\]' "$work/isolated-install-human.txt"; then
  echo "human install output leaked service file content" >&2
  exit 1
fi
```

Expected:

- Human output is concise and does not dump the systemd unit body.
- JSON output does not include a `content` field.
- Files are created only under the isolated XDG/HOME tree.
- Do **not** run `daemon start` under this isolated env; systemd user managers may not honor temporary XDG paths consistently.

## 3. Full systemd-user Lifecycle (Default Validation User Paths)

Run only if the host has a working systemd user manager and the current user is a disposable validation user or explicitly approved.

First check for an existing service:

```bash
set +e
descartes daemon status --json > "$work/pre-status.json" 2> "$work/pre-status.stderr"
pre_status=$?
set -e
cat "$work/pre-status.json" || true

echo "pre_status_exit=$pre_status" | tee "$work/pre-status.exit"
node - <<'NODE' "$work/pre-status.json"
const fs = require('fs');
let parsed;
try { parsed = JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); } catch { process.exit(0); }
if (parsed.installed) {
  console.error('Descartes daemon already installed for this user. Abort unless this is a disposable validation user and cleanup is approved.');
  process.exit(3);
}
NODE
```

Then run the lifecycle:

```bash
# Install should be idempotent.
descartes daemon install --json | tee "$work/install-1.json"
descartes daemon install --json | tee "$work/install-2.json"

# Start should be idempotent.
descartes daemon start --json | tee "$work/start-1.json"
descartes daemon start --json | tee "$work/start-2.json"

descartes daemon status --json | tee "$work/status-after-start.json"

# Let at least two daemon intervals elapse.
sleep 130

descartes history summary --window 10m | tee "$work/history-after-130s-human.txt"
descartes history summary --verbose --window 10m | tee "$work/history-after-130s-verbose.txt"
descartes history summary --json --window 10m | tee "$work/history-after-130s.raw.json"

# Stop and uninstall should be idempotent.
descartes daemon stop --json | tee "$work/stop-1.json"
descartes daemon stop --json | tee "$work/stop-2.json"
descartes daemon uninstall --json | tee "$work/uninstall-1.json"
descartes daemon uninstall --json | tee "$work/uninstall-2.json"
descartes daemon status --json | tee "$work/status-after-uninstall.json"
```

Expected:

- `install-1.status` is `installed` or `updated`.
- `install-2.status` is `unchanged`.
- `start-1.status` is `started` or `already_running`.
- `start-2.status` is `started` or `already_running`; it must not fail solely because the unit is already active/loaded.
- `status-after-start.installed` is `true` and should report `running: true` when systemd status commands work.
- Compact human `history summary` includes last sample age/cadence and highlights without dumping the full metric table.
- Verbose human `history summary --verbose` includes the full per-metric table.
- `history-after-130s` JSON has `history.point_count > 0` and includes system/process/disk metric names.
- `stop-1.status` is `stopped` or `not_running`.
- `stop-2.status` is `stopped` or `not_running`; it must not fail solely because the unit is already stopped.
- `uninstall-1.status` is `removed` or `not_installed`.
- `uninstall-2.status` is `not_installed`.
- `status-after-uninstall.status` is `not_installed`.

## 4. Sanitized Lifecycle Summary

Generate a sanitized report without raw paths/logs:

```bash
node - <<'NODE' "$work" | tee "$work/daemon-lifecycle-summary.json"
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
function readJson(name) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); }
  catch (error) { return { missing_or_invalid: true, error: String(error.message ?? error) }; }
}
function compactLifecycle(name) {
  const j = readJson(name);
  return {
    file: name,
    status: j.status,
    installed: j.installed,
    running: j.running,
    enabled: j.enabled,
    service_manager: j.service_manager,
    content_leaked: j.content !== undefined,
    runtime_status: j.runtime_status,
    enablement_status: j.enablement_status,
    error: j.error,
  };
}
const history = readJson('history-after-130s.raw.json');
console.log(JSON.stringify({
  lifecycle: [
    'install-1.json', 'install-2.json',
    'start-1.json', 'start-2.json',
    'status-after-start.json',
    'stop-1.json', 'stop-2.json',
    'uninstall-1.json', 'uninstall-2.json',
    'status-after-uninstall.json',
  ].map(compactLifecycle),
  history: {
    point_count: history.history?.point_count,
    metric_names: (history.history?.metrics ?? []).map(m => m.metric_name).sort(),
    daemon_status_state: history.daemon_status?.state,
    corrupt_count: history.history?.corrupt_count,
  },
}, null, 2));
NODE
```

Expected:

- `content_leaked` is false for every lifecycle JSON result.
- History metric names include at least:
  - `system.load.1m`
  - `system.memory.used_fraction`
  - `process.cpu_percent`
  - `disk.used_fraction`

## 5. Optional Log Inspection

Only report sizes/counts and sanitized error snippets.

```bash
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/descartes/daemon"
if [ -d "$state_dir" ]; then
  find "$state_dir" -maxdepth 1 -type f -name '*.log' -printf '%f %s bytes\n' 2>/dev/null | tee "$work/log-sizes.txt" || true
  for file in stdout.log stderr.log; do
    if [ -f "$state_dir/$file" ]; then
      # Do not return full logs by default. Count non-empty lines and show only bounded generic errors.
      awk 'NF {count++} END {print FILENAME, "non_empty_lines", count+0}' "$state_dir/$file" | tee -a "$work/log-line-counts.txt"
      grep -Ei 'error|exception|failed|denied' "$state_dir/$file" | tail -20 | sed -E 's#/home/[^ /]+#/home/[USER]#g; s#/Users/[^ /]+#/Users/[USER]#g' | tee -a "$work/log-error-snippets.txt" || true
    fi
  done
fi
```

Expected:

- No crash-loop stack traces.
- `stderr.log` should be empty or contain only known benign platform messages.
- Do not return raw logs unless explicitly requested and scrubbed.

## Acceptance Criteria

This brief is complete when the returned report shows:

- Public GitHub install works and version is `0.0.39+`.
- Isolated install human output is concise and does not leak generated unit content.
- Isolated install JSON does not include generated unit content.
- Full systemd-user lifecycle works on at least one Linux host/VM:
  - install idempotent
  - start idempotent
  - status reports installed/running where available
  - history accumulates over at least two daemon intervals
  - stop idempotent
  - uninstall idempotent
- Cleanup completed, or the report explicitly states the owner asked to leave the daemon installed/running.

## Report Back

Return:

- Distro, kernel, architecture, Node/npm versions.
- `descartes --version`.
- Whether `systemctl --user` was available.
- Sanitized `daemon-lifecycle-summary.json`.
- Log size/line-count summary and sanitized error snippets if any.
- Any lifecycle command that failed, hung, returned malformed JSON, leaked service content, or left the daemon installed unintentionally.
