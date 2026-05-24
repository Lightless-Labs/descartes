# Descartes Daemon and Local History Store

**Created:** 2026-05-23
**Status:** In Progress
**Addendum:** 2026-05-24 — Started the first Node.js implementation slice with a foreground-only daemon loop and JSONL metric store. SQLite remains a likely later durable store, but JSONL is sufficient for the initial bounded system/process/disk history summary path and avoids adding runtime dependencies while the CLI remains a temporary harness layer.

## Purpose

Before agent-authored sensors, rules, or background LLM agents can be useful, Descartes needs a local background substrate that collects deterministic evidence over time and exposes bounded history to the CLI.

This plan creates a read-only daemon/background agent that runs a default collector schedule, persists compact history/metrics under Descartes-owned paths, rotates/cleans up data, and lets `descartes triage` use recent history when explicitly requested or configured.

## User-Facing Shape

Initial commands should be explicit and reversible:

```bash
descartes daemon install
descartes daemon start
descartes daemon status
descartes daemon stop
descartes daemon uninstall

descartes history summary
descartes history inspect --window 1h
descartes triage "my machine is slow" --use-history
```

Names may change, but the concepts should remain: install/start/status/stop/uninstall, inspect bounded history, and opt into history-aware triage.

## Safety Boundaries

- Read-only collectors only.
- No background LLM calls in the first daemon milestone.
- No telemetry, upload, federation, or notifications.
- No mutating host actions.
- No arbitrary shell/coding tools.
- No silent privilege escalation.
- All state lives under Descartes-owned XDG paths.
- Retention, rotation, and max disk usage must be enforced by default.

## Default Collection Profile

Keep the first profile conservative:

| Collector | Suggested cadence | Notes |
|---|---:|---|
| system overview | 30-60s | load, memory, swap, uptime |
| processes | 30-60s | top CPU/memory only, redacted/bounded args |
| disks | 5-15m | filesystem pressure changes slowly |
| services | 5-15m | service failures/restarts |
| network basics | 5-15m | no DNS reachability by default unless policy says yes |
| scheduled jobs | 30-60m | low cadence |
| time sync | 30-60m | no external offset check by default |
| certificates | 6-24h | low cadence |
| logs | optional / low cadence | sensitive; bounded warning/error counts before excerpts |
| containers/VMs | 1-5m where tools exist | runtime inventory/resource attribution |

The default should collect enough to answer “what changed recently?” without filling disk or surprising users.

## Storage Model

Start with an implementation that can evolve toward Rust/Bazel-friendly storage. SQLite is likely the best practical first store; append-only JSONL with rotation is acceptable only if query needs stay trivial.

Data classes:

- raw or compact evidence snapshots, bounded and optionally sampled
- metric points with dimensions
- rollups over time windows
- provenance back to envelope IDs/traces
- sensitivity labels
- daemon run/status records

Minimum metric fields:

```text
ts
metric_name
dimensions
value
unit
source_envelope_id
source_tool
sensitivity
```

Minimum rollups:

- count
- min
- max
- mean
- last
- rate/delta where meaningful
- p95 where enough samples exist
- missing-data markers

Retention defaults:

- short high-resolution window, e.g. 24h
- longer rollup window, e.g. 7d
- hard maximum bytes per store
- rotation/compaction on daemon startup and periodically

## CLI Integration

`descartes history summary` should return operator-friendly summaries such as:

- load/memory/swap trends over 15m/1h/24h
- repeated top CPU/memory process names over time
- disk pressure changes
- service failure/restart count changes
- container/VM runtime/resource changes
- certificate/time-sync warning counts

`descartes triage --use-history` should provide bounded summarized history to the model, not raw unbounded logs/process data.

JSON triage should expose:

- `history_used: true|false`
- selected windows
- history summary envelope IDs
- history store diagnostics

## Platform Installation

Initial targets:

- macOS launchd user agent
- Linux systemd user service where available

Open questions:

- Whether to support system service install later.
- Whether npm-installed Node wrapper is acceptable for daemon install, or whether this should wait for a Rust-native daemon.
- How to handle machines without systemd/launchd.

## Relationship To Agent-Authored Sensor Toolkit

This plan comes first. The agent-authored sensor toolkit consumes the fact/metric history created here.

The daemon/history store is the substrate for:

- fact bridge over current and historical evidence
- metric catalog
- statistical baselines
- shadow-mode sensors
- later background LLM agent workbench

## Milestones

### Milestone 1: Daemon design and storage schema

- Decide storage engine for first implementation. **Initial decision:** bounded JSONL metric points under XDG state for the Node.js prototype; revisit SQLite when query needs outgrow simple summaries or when the durable Rust substrate begins.
- Define daemon config schema, collection profile schema, and metric schema. **Initial slice:** built-in conservative profile for system/process/disk and compact metric points with `ts`, `metric_name`, `dimensions`, `value`, `unit`, source envelope/tool, and sensitivity.
- Define retention/rotation policy. **Initial slice:** retention window plus max-byte enforcement on metric append / daemon iteration paths.
- Define service install/status lifecycle.

### Milestone 2: Local daemon loop prototype

- Run a foreground `descartes daemon run --foreground` loop for development. **Initial slice:** `descartes daemon run --foreground [--once] [--interval <duration>]`.
- Execute a small default collector set at bounded intervals. **Initial slice:** system/process/disk only.
- Persist compact metric points and daemon status records. **Initial slice:** `metrics.jsonl` and `daemon-status.json` under XDG state history dir.
- Enforce rotation/retention.

### Milestone 3: CLI history read path

- Add `descartes history summary` over persisted metrics. **Initial slice:** implemented deterministic summary renderer.
- Add JSON output for history summaries. **Initial slice:** `descartes history summary --json [--window <duration>]`.
- Add tests for retention, rollups, and corrupt/partial store handling. **Initial slice:** added Node tests for rollups, retention, corrupt records, max bytes, metric extraction, and daemon status writes.

### Milestone 4: Platform install/start/stop

- Add launchd user agent install/uninstall on macOS.
- Add systemd user service install/uninstall on Linux.
- Add status diagnostics.

### Milestone 5: Triage history integration

- Add `descartes triage --use-history`.
- Feed bounded summaries to the model as evidence envelopes.
- Include history diagnostics in JSON output.

## Non-Goals

- No background LLM calls.
- No notifications/alarms yet.
- No policy-authorized actions.
- No agent-authored rule/model promotion yet.
- No unbounded raw log/process capture.

## Acceptance Criteria

- User can install/start/status/stop/uninstall the background service.
- Daemon collects a default read-only profile without touching Pi paths.
- History is persisted under Descartes-owned XDG paths.
- Rotation/retention prevents unbounded disk growth.
- CLI can summarize recent history.
- Triage can optionally use bounded history summaries.
- All daemon behavior is testable without requiring platform service managers.
