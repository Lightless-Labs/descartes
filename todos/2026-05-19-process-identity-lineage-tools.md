---
title: Process Identity and Lineage Investigation Tools
created: 2026-05-19
status: open
priority: immediate
area: collectors
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-expand-local-investigation-tools.md
  - todos/2026-05-19-macos-disk-evidence-classification.md
  - todos/2026-05-19-temporal-sampling-investigation-tools.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
---

# TODO: Process Identity and Lineage Investigation Tools

## Summary

The next high-impact, low-hanging capability after the v0.0.8 triage validation is process identity and lineage. This moves Descartes from snapshot resource triage toward behavior-aware operations/defense investigation while staying read-only and bounded.

Before adding richer process tools, add a shared process argument redaction/bounding helper so JSON output and future tools do not casually expose long command lines, high-entropy tokens, env-like blobs, or app-specific secrets.

## Why This Is Next

Descartes' long-term defense direction depends on understanding process behavior and provenance:

- what process is consuming resources?
- who launched it?
- what parent/child chain does it belong to?
- is it an expected app helper, a shell-spawned process, or something odd?
- is it long-running or newly spawned?
- does it have suspicious arguments or an unusual executable location?

This is directly useful for current triage and lays groundwork for later detection of trojan/ransomware-like behavior, persistence, and anomalous process trees.

## Proposed Scope

### 1. Shared process argument redaction/bounding

Add a utility used by `collect_processes`, compact prompt summaries, JSON output, and future process inspection tools.

Initial behavior:

- cap argument strings to a bounded length
- preserve executable/first useful tokens where possible
- redact high-entropy long values
- redact obvious `key=value` secrets/tokens (`token`, `secret`, `password`, `key`, `auth`, etc.)
- annotate whether args were truncated/redacted
- keep behavior deterministic and covered by tests

Avoid adding a raw/unredacted mode until there is an explicit local-only report policy.

### 2. `inspect_process`

Input:

```json
{ "pid": 1234 }
```

Return an evidence envelope with read-only facts where available:

- pid / ppid
- command/name
- redacted/bounded command line
- executable path where available
- user/uid where available
- CPU/memory snapshot
- start time or age where available
- parent process summary
- child count / top child summaries where available
- platform support status for unavailable fields
- trace with fixed commands/APIs used

### 3. `inspect_parent_tree`

Input:

```json
{ "pid": 1234, "max_depth": 16 }
```

Return an evidence envelope with:

- ancestry chain from target process to launchd/systemd/init
- redacted command line snippets for each ancestor
- missing/permission-limited nodes represented explicitly
- bounded child/sibling summary if cheap and safe

## Tool Exposure

Expose both tools to the guarded triage tool surface only after tests pass:

- `inspect_process`
- `inspect_parent_tree`

Update `TRIAGE_TOOL_NAMES` and tool-policy tests accordingly.

## Acceptance Criteria

- Process arg redaction utility has focused tests.
- `collect_processes` uses redacted/bounded args in default JSON evidence.
- `inspect_process` returns structured evidence envelope and handles missing/ended PIDs gracefully.
- `inspect_parent_tree` returns structured evidence envelope and handles missing/permission-limited parents gracefully.
- Tools are read-only and use fixed command argv arrays or platform APIs only.
- Triage harness exposes the new tools and rejects any unexpected/shell/coding tools.
- `npm test` passes.
