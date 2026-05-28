---
title: Daemon and Local History Store
created: 2026-05-23
status: in_progress
priority: high
area: architecture
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-23-daemon-history-store.md
  - docs/plans/2026-05-23-agent-authored-sensor-toolkit.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
  - docs/reviews/2026-05-24-macos-daemon-validation.md
  - linux-daemon-lifecycle-validation-brief.md
---

# TODO: Daemon and Local History Store

## Summary

Build the local background substrate before implementing agent-authored sensors. Descartes needs a daemon/background agent that runs a conservative default set of read-only collectors, persists bounded local history/metrics, rotates/cleans up after itself, and exposes recent history to CLI commands and optional history-aware triage.

## Initial Scope

- `descartes daemon run --foreground` development loop.
- Daemon config and default collector profile.
- Descartes-owned history store under XDG state/cache paths.
- Bounded metric points and rollups.
- Retention/rotation/max-size enforcement.
- `descartes history summary` read path.
- User-level launchd/systemd service install/start/status/stop/uninstall.
- Later: `descartes triage --use-history` with bounded history summaries.

## Safety Boundaries

- No background LLM calls.
- No telemetry/upload/federation.
- No remediation/mutating host actions outside explicit daemon lifecycle commands.
- Read-only collectors only.
- No arbitrary shell/coding tools.
- No unbounded raw log/process capture.
- No silent privilege escalation.

## Acceptance Criteria

- [x] Default foreground daemon loop can collect system/process/disk history over time.
- [x] History is persisted under Descartes-owned XDG paths.
- [x] Rotation/retention prevents unbounded disk growth for the initial JSONL metric store.
- [x] CLI can summarize recent history without invoking an LLM.
- [x] Tests cover storage writes, rollups, retention, corrupt/partial store handling, metric extraction, and daemon status writes.
- [x] Tests cover repeated loop scheduling without waiting on real time.
- [x] Idempotent user-level service-file install/status/uninstall exists for launchd/systemd.
- [x] Idempotent platform daemon load/start/stop/enable/disable command construction exists for launchd/systemd.
- [x] macOS real-host install/start/history accumulation validated; see `docs/reviews/2026-05-24-macos-daemon-validation.md`.
- [ ] macOS field-user retry on v0.0.38+ remains follow-on after launchd generic bootstrap I/O/stale-state hardening.
- [ ] macOS real-host log inspection remains follow-on validation.
- [ ] Linux systemd-user lifecycle validation remains follow-on work; use `linux-daemon-lifecycle-validation-brief.md`.
- [x] `history summary` default human output should become compact; keep full metric tables behind `--verbose`/`--json`.
- [x] Initial `triage --use-history [--history-window <duration>]` exists and injects a bounded `history-summary` evidence envelope.
- [x] Triage auto-includes fresh daemon-backed history by default, with `--no-history` opt-out and `--use-history` force mode.
- [x] Default history window is 24h after field feedback that 1h was too short.
- [x] History summaries expose point-limit/truncation diagnostics (`matched_point_count`, `point_limit`, `truncated`).
- [x] Current retention is documented in handoff: 24h high-resolution JSONL, capped at 5 MiB.
- [ ] Richer history-aware triage prompting/evaluation remains follow-on work.
- [ ] Configurable retention and longer rollups remain follow-on work.

## Next: Monitoring and Alerting Direction

After the daemon/history substrate, move into actual monitoring/alerting before broader agent-authored sensors. Keep it deterministic first: periodic rule evaluation over recent metric summaries, explicit alert state, dedupe/cooldown, acknowledgements, and notification delivery adapters.

Candidate notification surfaces by system:

- macOS desktop: user notification via `osascript`/Notification Center where permissioned; fallback to menu-bar/CLI status later.
- Linux desktop: `notify-send`/D-Bus desktop notifications when a graphical session is available.
- Headless Linux/server: stdout/syslog/journald entries, optional email/webhook adapters only after explicit configuration.
- CLI-only MVP: `descartes alerts list`, `descartes alerts watch`, nonzero exit/status for scripts, and concise summaries in `descartes history summary`.
- Future integrations: Slack/Discord/webhook/mobile push only with explicit opt-in, redaction, routing policy, and rate limits.

Initial alerts should be local/read-only and conservative: stale daemon/no samples, sustained high memory/load, disk pressure, repeated service failures where service collection exists, certificate expiry, and time-sync warnings. No remediation actions without separate policy/authority work.
