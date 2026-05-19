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

Run in a Linux x86_64 VM/container with Node.js/npm 20.6+:

```bash
npm install -g github:Lightless-Labs/descartes
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
| GitHub npm install | validated | validate | `npm install -g github:Lightless-Labs/descartes` |
| `descartes --help` / `--version` | validated | validate | version should match package metadata |
| XDG path isolation | validated | validate | no `~/.pi`, no project `.pi` |
| no-auth triage failure | validated | validate | expected credentials error, no panic |
| subscription/API-key login path | validated on macOS | optional | use scoped/dedicated credentials if possible |
| model-led guarded tool use | validated | optional | requires credentials |
| `collect_system` | validated | validate | Linux swap from `/proc/meminfo` |
| `collect_processes` | validated | validate | Linux `ps -axo pid,ppid,pcpu,pmem,rss,comm,args -r/-m` behavior may differ by procps/BusyBox |
| `collect_disks` | validated | validate | Linux `df -kP`; `df -iP` may vary but should return envelope or graceful unable |
| `collect_triage_evidence` | validated | validate | combined evidence + findings |
| `derive_findings` | validated | validate | deterministic, should be platform-independent |
| `inspect_process` | not implemented | future parity | tracked in process identity/lineage todo |
| `inspect_parent_tree` | not implemented | future parity | tracked in process identity/lineage todo |
| temporal sampling | not implemented | future parity | tracked separately |
| service manager checks | not implemented | future parity | Linux/systemd likely first real host requirement |

## CI Goals

Promote the manual validation into Buildkite:

- Linux x86_64 agent or container image
- Node.js/npm 20.6+
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
