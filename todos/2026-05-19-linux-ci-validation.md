---
title: Linux x86_64 VM/Container and CI Validation
created: 2026-05-19
status: open
priority: high
area: release
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-first-external-slice-validation.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
---

# TODO: Linux x86_64 VM/Container and CI Validation

## Summary

A physical Linux x86_64 host is not currently available, but a Linux VM or container can provide useful first-slice validation. Treat VM/container validation as best-effort coverage for the current resource-pressure CLI, and later promote it into Buildkite CI.

Container/VM validation is enough to check install/package behavior, path isolation, Linux command/parsing behavior, and graceful collector envelopes. It is not a complete substitute for a real Linux host with representative systemd services, disks, pressure signals, and host process table.

## Manual VM/Container Validation

Run in a Linux x86_64 VM/container with Node.js 22.19.0+:

```bash
node --version
npm --version
prefix="$(mktemp -d)/npm-prefix"
npm install -g --prefix "$prefix" github:Lightless-Labs/descartes
export PATH="$prefix/bin:$PATH"
descartes --version
descartes --help

tmp="$(mktemp -d)"
HOME="$tmp/home" \
XDG_CONFIG_HOME="$tmp/config" \
XDG_DATA_HOME="$tmp/data" \
XDG_STATE_HOME="$tmp/state" \
XDG_CACHE_HOME="$tmp/cache" \
descartes triage "my machine is slow" --json
status=$?
echo "status=$status"
find "$tmp" -maxdepth 4 -type f | sort
```

Expected no-auth result:

- exits non-zero
- prints `No configured model credentials found...`
- creates only Descartes-owned XDG config/auth files
- does not read/write Pi-owned paths

For collector validation from a clone:

```bash
node --input-type=module - <<'NODE'
import { collectAllEvidence } from './tools/descartes-cli/src/tools/collect.js';
const bundle = await collectAllEvidence();
console.log(JSON.stringify({
  platform: process.platform,
  arch: process.arch,
  evidence: bundle.evidence.map((e) => ({
    id: e.id,
    status: e.status,
    source: e.source,
    tool: e.trace?.tool,
    review_hint: e.review_hint,
  })),
  findings_count: bundle.findings.length,
  actions_taken: bundle.actions_taken,
}, null, 2));
NODE
```

For expanded targeted collector validation from a current clone, also run small direct smokes with bounded output:

```bash
node --input-type=module - <<'NODE'
import { collectContainerEvidence } from './tools/descartes-cli/src/tools/containers.js';
import { collectVmEvidence } from './tools/descartes-cli/src/tools/vms.js';
import { collectScheduledJobsEvidence } from './tools/descartes-cli/src/tools/scheduled-jobs.js';
import { collectTimeSyncEvidence } from './tools/descartes-cli/src/tools/time-sync.js';
import { collectCertificateEvidence } from './tools/descartes-cli/src/tools/certificates.js';
const collectors = [
  ['containers', await collectContainerEvidence({ collectStats: false, containerLimit: 5, hostLimit: 5 })],
  ['vms', await collectVmEvidence({ vmLimit: 5 })],
  ['scheduled_jobs', await collectScheduledJobsEvidence({ jobLimit: 5 })],
  ['time_sync', await collectTimeSyncEvidence()],
  ['certificates', await collectCertificateEvidence({ certificateLimit: 5 })],
];
for (const [name, envelope] of collectors) {
  console.log(JSON.stringify({ name, id: envelope.id, status: envelope.status, summary: envelope.result?.summary }, null, 2));
}
NODE
```

If safe credentials are available, also run:

```bash
descartes login
descartes triage "my machine is slow" --json
```

Report/scrub these fields only:

- `diagnostics.selected_model`
- `diagnostics.fallback_used`
- `diagnostics.active_tools`
- `diagnostics.tool_calls[].tool_name`
- evidence IDs/statuses/sources
- `actions_taken`
- any `llm_error`

Do not paste full process args or raw host identifiers unless intentionally reviewed.

## Tool / Feature Parity Matrix

Track Linux parity against macOS for the first-slice tool surface.

| Capability / Tool | macOS status | Linux VM/container target | Notes |
|---|---:|---:|---|
| GitHub npm install | validated | validated on Linux arm64 with prefix | User prefix installed public v0.0.11 successfully. |
| `descartes --help` / `--version` | validated | validated on Linux arm64 | v0.0.11 returned the expected version and help through the npm prefix symlink. |
| XDG path isolation | validated | partially validated on Linux arm64 | login stored credentials at `/home/admin/.config/descartes/auth.json`; still need isolated-XDG file listing. |
| no-auth triage failure | validated | validated on Linux arm64 | expected credentials error, no panic. |
| subscription/API-key login path | validated on macOS | validated on Linux arm64 | ChatGPT/Codex `--no-open` manual redirect flow succeeded. |
| model-led guarded tool use | validated | validated on Linux arm64 | credentialed JSON triage called `collect_triage_evidence`, `fallback_used: false`, `actions_taken: []`. |
| `collect_system` | validated | validated on Linux arm64 | Linux swap from `/proc/meminfo`; host reported Linux arm64. |
| `collect_processes` | validated | validated on Linux arm64 | v0.0.11 used Linux `ps -eo ...`, returned `top-processes.status: ok`, and sorted top CPU/memory in-process. |
| `collect_disks` | validated with classification | validated on Linux arm64 before classification | Linux `df -kP` and `df -iP` returned structured filesystem/inode evidence; rerun should confirm pseudo filesystems are classified not pressure-relevant. |
| `collect_triage_evidence` | validated | validated on Linux arm64 | combined evidence + findings returned through model-requested tool call. |
| `derive_findings` | validated | validate | deterministic, should be platform-independent |
| `inspect_process` | implemented / local macOS smoke checked | validate on Linux x86_64 | read-only PID identity envelope with redacted/bounded args. |
| `inspect_parent_tree` | implemented / local macOS smoke checked | validate on Linux x86_64 | read-only bounded ancestry envelope with redacted/bounded args. |
| temporal sampling | implemented / local macOS smoke checked | validate on Linux x86_64 | `sample_dimension` supports CPU processes, memory processes, and load/memory/swap plus Descartes-owned artifacts. |
| `collect_network_basics` | implemented / local macOS smoke checked | validate on Linux x86_64 | Linux uses fixed `ip route show default`, `/etc/resolv.conf`, DNS lookup, and `ss -H -ltnu`. |
| `collect_services` | implemented / local macOS smoke checked | validate on Linux x86_64 | Linux uses fixed `systemctl list-units --type=service --all --no-pager --no-legend`. |
| `collect_recent_logs` | implemented / local macOS smoke checked | validate on Linux x86_64 | Linux uses bounded fixed `journalctl` and fixed log-file tail probes. |
| `collect_containers` | implemented / local macOS smoke checked | validated on Linux ARM64 / validate x86_64 | v0.0.22 ARM64 archive passed direct container collector smokes on Ubuntu/Debian/Fedora with Podman available and missing Docker/Lima represented per runtime. Docker/Podman/Lima/Colima plus Podman machine host-context coverage; missing daemons/permissions should be represented per runtime/probe. |
| `collect_vms` | implemented / local macOS smoke checked | validated on Linux ARM64 / validate x86_64 | v0.0.22 ARM64 archive passed direct VM collector smokes on Ubuntu/Debian/Fedora with libvirt/podman-machine/LXD states represented without envelope failure. Linux targets include Colima where installed, libvirt/virsh, QEMU process hints, VirtualBox, VMware, Podman machine, Incus/LXD VMs, Proxmox, Xen, and others where available. |
| `collect_scheduled_jobs` | implemented / local macOS smoke checked | validate on Linux x86_64 | External Linux ARM64 scheduler command checks passed in the v0.0.22 validation archive, but the collector file did not exist in that version. Linux uses cron file probes plus system/user systemd timers; v0.0.25 bounds cron file reads and fairly selects returned jobs across sources. |
| `collect_time_sync` | implemented / local macOS smoke checked | validate on Linux x86_64 | External Linux ARM64 `timedatectl`/chrony command checks passed in the v0.0.22 validation archive, but the collector file did not exist in that version. Linux uses `timedatectl`, optional chrony/ntpq, and explicit optional SNTP offset checks; v0.0.25 rejects option/path-like NTP server values and preserves unknown sync state. |
| `collect_certificates` | implemented / local macOS smoke checked | validate on Linux x86_64 | Linux targets common trust/service certificate paths and skips private keys; added in v0.0.26. |
| collector reference docs | validated | validate package install includes docs | `docs/reference/collectors.md` is included in the package as of v0.0.24+. |

## Observed Linux Attempts

2026-05-19 local packaging update for v0.0.12:

- Descartes now depends on `@earendil-works/pi-coding-agent` 0.75.3 instead of deprecated `@mariozechner/*` Pi packages.
- Runtime requirement is now Node.js 22.19.0+.
- Fresh local tarball install no longer emits the `@mariozechner/*` deprecation warnings.
- One upstream `node-domexception` deprecation warning remains through `@google/genai`/Google auth transitive dependencies in Pi AI.
- Linux ARM64 validation should be rerun after v0.0.12 is pushed.

2026-05-21 local validation/doc update for v0.0.29:

- Current local package exposes additional guarded tools after the last credentialed public Linux ARM64 validation: network, services, recent logs, containers, VMs, scheduled jobs, time sync, and certificates.
- `collect_scheduled_jobs` was hardened after review: regular-file checks, byte-capped cron reads before parsing, discovered vs returned counts, and fair returned-job selection across scheduler sources.
- `collect_time_sync` was hardened after review: validates NTP server values before `sntp`, rejects option/path/whitespace values, and keeps unknown synchronization state unknown.
- `collect_certificates` was added: bounded local certificate validity evidence for common Linux/macOS stores and service-certificate paths, with private keys skipped.
- Updated Linux ARM64 validation brief includes scheduled-job, time-sync, and certificate direct collector smoke checks plus model-led prompts for scheduler/time/certificate questions.
- v0.0.28 adds Colima VM inventory, Podman machine container-host context, and Colima/Lima/Podman machine VM/container-host correlation metadata.
- v0.0.29 adds QEMU-backed process-resource attachment for Colima/Lima/Podman machine host entries when process names/paths deterministically match.
- Linux ARM64/x86_64 validation should now use v0.0.29+.

2026-05-21 Linux ARM64 multi-distro validation archive in ignored `materials/descartes-linux-arm64-validation.zip` validated public v0.0.22-era packaging/runtime on Ubuntu 24.04, Debian 13, and Fedora 42 ARM64:

- All three hosts used Node v22.21.1 and npm 10.9.4.
- Git clone, repo install, global install with a writable prefix, `descartes --help`, `descartes --version`, and `npm test` passed on all three distros; `descartes --version` returned `0.0.22`.
- Direct `collect_containers` and `collect_vms` runtime smokes passed on all three distros. Podman was detected as available in container evidence; VM evidence represented libvirt/podman-machine/LXD availability or daemon limitations without failing the envelope.
- External scheduler/time command checks passed: Ubuntu/Debian had synchronized `timedatectl` state, Fedora had active NTP but not synchronized through chrony at capture time, and systemd timer listings were available.
- The scheduled-job and time-sync direct collector smokes failed with `ERR_MODULE_NOT_FOUND` because v0.0.22 predated `scheduled-jobs.js` and `time-sync.js`; this is expected for the archive and does not validate v0.0.25 hardening.
- Model-led triage was skipped because the validation VMs had no model credentials.
- npm still emitted the known upstream `node-domexception` deprecation warning via transitive dependencies.

2026-05-19 third Ubuntu validation on Linux arm64 with `$HOME/.local` prefix validated the current public v0.0.11 package:

- `npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes` installed public v0.0.11 successfully
- `descartes --version` returned `0.0.11`; `descartes --help` worked through the npm prefix symlink
- `descartes login --no-open` completed ChatGPT/Codex OAuth by pasted redirect URL and stored auth in `/home/admin/.config/descartes/auth.json`
- credentialed human and JSON triage were non-fallback, selected `openai-codex/gpt-5.5`, exposed only guarded tools, called `collect_triage_evidence`, and left `actions_taken: []`
- `collect_system`, `collect_processes`, and `collect_disks` returned ok envelopes
- process collection used Linux `ps -eo pid,ppid,pcpu,pmem,rss,comm,args`; top CPU showed the Descartes triage process itself, confirming the procps fix
- JSON output still included full process command lines in public v0.0.11; current local work now redacts/bounds process args by default and should be revalidated on Linux

2026-05-19 second Ubuntu validation on Linux arm64 with `$HOME/.local` prefix reached runtime and credentialed triage on public v0.0.8:

- `npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes` installed public v0.0.8 successfully
- `descartes --version` returned `0.0.8`; `descartes --help` worked
- no-auth triage failed cleanly with the expected credentials message
- `descartes login --no-open` completed ChatGPT/Codex OAuth by pasted redirect URL and stored auth in `/home/admin/.config/descartes/auth.json`
- credentialed human and JSON triage were non-fallback, selected `openai-codex/gpt-5.5`, exposed only guarded tools, called `collect_triage_evidence`, and left `actions_taken: []`
- `collect_system` and `collect_disks` returned ok envelopes
- `collect_processes` returned unable because Linux procps rejected the v0.0.8 `ps -axo ... -m` invocation with `must set personality to get -x option`; v0.0.10 changed Linux collection to `ps -eo pid,ppid,pcpu,pmem,rss,comm,args` and sorts top CPU/memory in JavaScript

2026-05-19 first Ubuntu validation attempt did not reach Descartes runtime or collectors:

- host had Node v18.19.1/npm 9.2.0, below the supported runtime
- npm emitted `EBADENGINE` warnings for Descartes, Pi, Undici, AWS SDK, and related dependencies
- install then failed with `EACCES: permission denied, mkdir '/usr/local/lib/node_modules'`
- next validation should use Node 22.19.0+ and a user-writable npm prefix, for example `npm install -g --prefix "$prefix" ...`

## CI Goals

Promote the manual validation into Buildkite:

- Linux x86_64 agent or container image
- Node.js 22.19.0+
- package install/help/version check
- isolated-XDG no-auth triage failure check
- local collector smoke test
- optional credentialed triage job gated by secrets

## CI Credential Notes

Prefer CI secrets scoped to Descartes validation only. Avoid committing or printing credentials. If using provider credentials:

- prefer a revocable API key or dedicated test account over a personal subscription OAuth token
- store secrets in Buildkite secret management / agent environment hooks
- ensure JSON logs are scrubbed before artifact upload
- do not upload full process args, hostnames, usernames, or raw diagnostic reports unless redacted

## Acceptance Criteria

- Manual Linux x86_64 VM/container validation has been run and recorded, or Buildkite job provides equivalent coverage.
- Package install/help/version works on Linux x86_64.
- Isolated XDG paths and no-auth failure behavior are verified.
- Local collectors return structured envelopes or graceful `unable` evidence.
- Tool/feature parity matrix is updated with results and gaps.
- If credentialed validation is enabled, job confirms `fallback_used: false`, guarded active tools, at least one Descartes tool call, and `actions_taken: []`.
