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

Run in a Linux x86_64 VM/container with Node.js 20.18.1+ on Node 20 LTS, or Node.js 22.9.0+:

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
| `collect_disks` | validated | validated on Linux arm64 | Linux `df -kP` and `df -iP` returned structured filesystem/inode evidence. |
| `collect_triage_evidence` | validated | validated on Linux arm64 | combined evidence + findings returned through model-requested tool call. |
| `derive_findings` | validated | validate | deterministic, should be platform-independent |
| `inspect_process` | not implemented | future parity | tracked in process identity/lineage todo |
| `inspect_parent_tree` | not implemented | future parity | tracked in process identity/lineage todo |
| temporal sampling | not implemented | future parity | tracked separately |
| service manager checks | not implemented | future parity | Linux/systemd likely first real host requirement |

## Observed Linux Attempts

2026-05-19 third Ubuntu validation on Linux arm64 with `$HOME/.local` prefix validated the current public v0.0.11 package:

- `npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes` installed public v0.0.11 successfully
- `descartes --version` returned `0.0.11`; `descartes --help` worked through the npm prefix symlink
- `descartes login --no-open` completed ChatGPT/Codex OAuth by pasted redirect URL and stored auth in `/home/admin/.config/descartes/auth.json`
- credentialed human and JSON triage were non-fallback, selected `openai-codex/gpt-5.5`, exposed only guarded tools, called `collect_triage_evidence`, and left `actions_taken: []`
- `collect_system`, `collect_processes`, and `collect_disks` returned ok envelopes
- process collection used Linux `ps -eo pid,ppid,pcpu,pmem,rss,comm,args`; top CPU showed the Descartes triage process itself, confirming the procps fix
- JSON output still includes full process command lines, reinforcing the next process-args redaction/bounding task

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
- next validation should use Node 20.18.1+ LTS or Node 22.9.0+ and a user-writable npm prefix, for example `npm install -g --prefix "$prefix" ...`

## CI Goals

Promote the manual validation into Buildkite:

- Linux x86_64 agent or container image
- Node.js 20.18.1+ LTS or Node 22.9.0+
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
