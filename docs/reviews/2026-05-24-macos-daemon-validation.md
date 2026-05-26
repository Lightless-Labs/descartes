# macOS daemon lifecycle field validation

**Date:** 2026-05-24
**Platform:** macOS, Apple Silicon laptop field report
**Package/branch:** public `main` after daemon lifecycle work, v0.0.34-era behavior

## Summary

A real macOS user-level launchd daemon validation succeeded for the initial Descartes history daemon lifecycle.

Validated commands:

```bash
descartes daemon install
descartes daemon start
descartes history summary
```

Observed behavior:

- `descartes daemon install` wrote the user launchd service file and printed concise human-readable output.
- `descartes daemon start` loaded/started the launchd service and reported `Running: yes`.
- `descartes history summary` showed metric history accumulating over time.
- Daemon status records stayed `ok` while the daemon continued running.
- Point counts advanced on the expected one-minute cadence:
  - first summary: 52 points, daemon status at `2026-05-24T23:53:29.875Z`
  - later summary: 260 points, daemon status at `2026-05-24T23:57:30.723Z`
  - later summary: 312 points, daemon status at `2026-05-24T23:58:30.951Z`

This closes the first macOS smoke for install/start/history accumulation. Stop/uninstall and idempotent reruns still need explicit real-host validation.

## Evidence shape observed

The daemon currently writes compact metric points for:

- `system.load.1m`, `system.load.5m`, `system.load.15m`
- `system.memory.free_bytes`, `system.memory.used_fraction`
- `system.swap.used_bytes`
- `system.uptime_seconds`
- `process.cpu_percent`, `process.memory_percent`, `process.rss_bytes`
- `disk.used_fraction`, `disk.available_bytes`, `disk.inode_used_fraction`

The point count growth is consistent with one sample per minute over the default profile:

- 13 system scalar metrics per interval plus multiple process/disk dimension points.
- Disk metrics currently include multiple pressure-relevant filesystems/mount dimensions.
- Process metrics record top-N command dimensions, not raw process arguments.

## UX findings

The default `history summary` output is too verbose for repeated human use. It is technically useful, but reads like a metric dump rather than an operator summary.

Recommended follow-up:

- Make default `descartes history summary` compact and opinionated.
- Move full metric tables behind `--verbose` or keep them primarily in `--json`.
- Show daemon freshness/cadence explicitly, for example:
  - last daemon sample age
  - expected next sample time or cadence
  - whether history is stale
- Group metrics into operator sections:
  - System pressure
  - Top process pressure
  - Disk pressure
- Highlight notable changes instead of every rollup line.
- Format bytes as GiB/MiB and fractions as percentages in human output.

Repeated summaries run within the same daemon interval naturally showed no new points. The CLI should make that unsurprising by showing last sample time and cadence.

## Safety notes

- This validation did not show background LLM calls.
- No remediation actions were taken.
- The only host mutation was the explicit user-level launchd service lifecycle.

## 2026-05-25 follow-up: launchd idempotency failure and local fix validation

A later real macOS field report against public v0.0.37 showed an idempotent-start failure:

- `npm install -g github:Lightless-Labs/descartes` installed v0.0.37.
- `descartes daemon install` returned `unchanged`.
- `descartes daemon start` failed with launchd's generic `Bootstrap failed: 5: Input/output error`.
- `descartes daemon stop` then returned `stopped`, proving launchd had service state to unload despite the failed `start` report.
- Immediate retries of `start` continued to hit the generic bootstrap error.

Local investigation on a macOS development host found two launchd behaviors that the CLI needed to handle:

1. Bootstrapping an already-loaded user agent can return only `Bootstrap failed: 5: Input/output error`, without an explicit “already loaded” string.
2. Immediately starting after `bootout` can see a transient loaded-but-not-running state such as `SIGTERMed`; another bootstrap during that state also returns the generic I/O error.

The v0.0.38 fix parses `launchctl print` state, treats `state = running` as idempotent before or after a generic bootstrap error, clears stale non-running launchd state with `bootout`, waits for it to disappear, and then bootstraps again.

Local validation after the fix, with cleanup, passed:

```bash
descartes daemon install
descartes daemon start
descartes daemon start      # now reports already running
descartes daemon status --json  # runtime_status: running
descartes history summary --window 5m
descartes daemon stop
descartes daemon start      # immediate restart after stop now works
descartes daemon uninstall
```

The test host's service was stopped/uninstalled after validation.

## Remaining validation

- macOS:
  - Re-run the failing field-user sequence with public v0.0.38+.
  - log file inspection for noise/crash loops
- Linux:
  - systemd user install/start/status/stop/uninstall
  - history accumulation under systemd user service
