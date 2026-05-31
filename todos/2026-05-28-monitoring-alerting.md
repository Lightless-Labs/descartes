---
title: Monitoring and Alerting
created: 2026-05-28
status: completed
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

Build the first monitoring and alerting layer on top of the daemon/history substrate. Deterministic local alerts are the wake trigger; with explicit opt-in, an LLM alert adjudicator should be woken by alerts to decide whether/how to notify and what notification text to send.

## Initial Scope

- Periodic rule evaluation over recent bounded history summaries.
- Alert state persisted under Descartes-owned XDG state.
- CLI commands such as `descartes alerts list`, `descartes alerts watch`, and `descartes alerts ack`.
- Dedupe/cooldown and acknowledgement/suppression state.
- Optional LLM alert adjudicator after explicit configuration.
- Optional notification adapters after explicit configuration.

## Candidate First Rules

- Daemon stale / no recent samples.
- Sustained high memory pressure.
- Sustained high load relative to CPU count.
- Disk pressure.
- Repeated service failures once service history is collected.
- Certificate expiry once certificate history is collected.
- Time-sync warnings once time-sync history is collected.

## LLM Alert Adjudication

The desired product direction is not “threshold crosses, daemon directly sends a fixed notification.” Instead:

- deterministic rules create/update local alert records;
- eligible alert transitions wake an LLM only after explicit user opt-in;
- the LLM receives bounded alert/history summaries, not raw dumps by default;
- the LLM decides `notify: true|false`, severity, title, body, reason, evidence refs, and next-check hint;
- that decision is persisted locally for audit and then handed to configured notification delivery.

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

## Implementation Update

2026-05-29: Implemented opt-in notification delivery config and setup/test UX. `descartes alerts notifications status|setup|test|disable` now manages delivery under Descartes XDG config. Delivery adapters are bounded and explicit: macOS desktop via `osascript`, Linux desktop via `notify-send`, headless/local syslog via `logger`, and CLI-only audit mode. Delivery attempts are locally audited and only LLM-authored alert-intelligence decisions are delivered automatically.

## Acceptance Criteria

- [x] Create first alert store schema and read/write tests.
- [x] Add deterministic rule evaluator with tests and no real-time sleeps.
- [x] Add CLI alert list/watch/ack read paths.
- [x] Add daemon integration that evaluates rules after history collection.
- [x] Add dedupe/cooldown behavior.
- [x] Add a CLI-only notification/status MVP.
- [x] Design explicit alert-intelligence config for opt-in background LLM wakeups.
- [x] Add structured LLM notification decision schema and local audit record.
- [x] Add rate limits/budget controls for LLM alert wakeups.
- [x] Design macOS/Linux/headless delivery adapter config before enabling desktop/server notifications.
- [x] Add notification permission/test UX for CLI users where the platform supports it.
