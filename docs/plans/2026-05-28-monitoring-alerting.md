# Descartes Monitoring and Alerting

**Created:** 2026-05-28
**Status:** Proposed

## Purpose

Move from on-demand history summaries into actual local monitoring and alerting, while preserving Descartes safety boundaries: deterministic local evidence first, no background LLM calls, no telemetry, no remediation actions, and explicit user control over notification delivery.

This layer should sit on top of the daemon/history substrate and run cheap deterministic rule evaluations over recent metrics and daemon status.

## Initial Scope

- Periodic rule evaluation in the daemon over recent bounded history summaries.
- Alert records persisted under Descartes-owned XDG state.
- CLI inspection commands, likely:
  - `descartes alerts list [--json]`
  - `descartes alerts watch [--json]`
  - `descartes alerts ack <alert-id>`
- Dedupe/cooldown so repeated threshold crossings do not spam users.
- Acknowledgement/suppression state.
- Conservative first rules:
  - daemon stale / no recent samples
  - sustained high memory pressure
  - sustained high load relative to CPU count
  - disk pressure
  - service failures once service history exists
  - certificate expiry once certificate history exists
  - time sync warnings once time-sync history exists

## Notification Surfaces

Start with CLI/status surfaces. Add desktop/headless delivery behind explicit configuration.

Candidate surfaces:

- macOS desktop: Notification Center via `osascript` or another permissioned local mechanism; fallback to CLI/status only.
- Linux desktop: `notify-send` / D-Bus notifications when a graphical session is available.
- Headless Linux/server: syslog/journald entries first; optional email/webhook only after explicit configuration.
- CLI-only MVP: `alerts list`, `alerts watch`, nonzero status for script checks, and concise alert summaries in `history summary`.
- Future integrations: Slack, Discord, webhook, mobile push only with opt-in, redaction, routing policy, and rate limits.

## Safety Boundaries

- No background LLM calls.
- No host mutation except explicit alert state writes under Descartes-owned paths.
- No remediation actions.
- No telemetry/upload/federation.
- No arbitrary shell/coding tools.
- Notifications must use bounded, redacted alert summaries, not raw logs/process dumps.
- Delivery adapters should fail closed: missed notification delivery must not crash the daemon or spam retries.

## Storage Shape

Alert records should be structured and auditable:

```json
{
  "id": "alert_...",
  "rule_id": "system.memory.sustained_high",
  "status": "active | recovered | acknowledged | suppressed",
  "severity": "info | warning | critical",
  "title": "Sustained high memory pressure",
  "summary": "Memory used stayed above 90% for 15m",
  "evidence_refs": ["history-summary"],
  "first_seen": "...",
  "last_seen": "...",
  "last_notified": "...",
  "cooldown_until": "...",
  "acknowledged_at": null,
  "diagnostics": {}
}
```

## Acceptance Criteria

- Rules can be tested without real time sleeps.
- Alerts are persisted under Descartes-owned XDG state.
- CLI can list active/recent alerts without invoking an LLM.
- Dedupe/cooldown prevents repeated alert spam.
- Notification delivery is optional and explicitly configured.
- All outputs preserve current read-only/no-telemetry/no-remediation boundaries.
