---
title: Monitoring and Alerting
created: 2026-05-28
status: proposed
priority: high
area: monitoring
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-28-monitoring-alerting.md
  - docs/plans/2026-05-23-daemon-history-store.md
  - todos/2026-05-23-daemon-history-store.md
---

# TODO: Monitoring and Alerting

## Summary

Build the first deterministic monitoring and alerting layer on top of the daemon/history substrate. This should be the next major product step before broader agent-authored sensors.

## Initial Scope

- Periodic rule evaluation over recent bounded history summaries.
- Alert state persisted under Descartes-owned XDG state.
- CLI commands such as `descartes alerts list`, `descartes alerts watch`, and `descartes alerts ack`.
- Dedupe/cooldown and acknowledgement/suppression state.
- Optional notification adapters after explicit configuration.

## Candidate First Rules

- Daemon stale / no recent samples.
- Sustained high memory pressure.
- Sustained high load relative to CPU count.
- Disk pressure.
- Repeated service failures once service history is collected.
- Certificate expiry once certificate history is collected.
- Time-sync warnings once time-sync history is collected.

## Notification Surfaces

- macOS desktop: Notification Center via `osascript` or another permissioned local mechanism.
- Linux desktop: `notify-send` / D-Bus notifications when a graphical session is available.
- Headless Linux/server: syslog/journald first; optional email/webhook only after explicit opt-in.
- CLI-only MVP: `alerts list`, `alerts watch`, nonzero status for scripts, and concise alert summaries in `history summary`.
- Future integrations: Slack/Discord/webhook/mobile push only with explicit opt-in, redaction, routing policy, and rate limits.

## Safety Boundaries

- No background LLM calls.
- No remediation actions.
- No telemetry/upload/federation.
- No arbitrary shell/coding tools.
- No host mutation outside Descartes-owned alert state and explicit notification delivery.
- Notification payloads must be bounded/redacted summaries, not raw logs/process dumps.

## Acceptance Criteria

- [ ] Create first alert store schema and read/write tests.
- [ ] Add deterministic rule evaluator with tests and no real-time sleeps.
- [ ] Add CLI alert list/watch/ack read paths.
- [ ] Add daemon integration that evaluates rules after history collection.
- [ ] Add dedupe/cooldown behavior.
- [ ] Add a CLI-only notification/status MVP.
- [ ] Design macOS/Linux/headless delivery adapter config before enabling desktop/server notifications.
