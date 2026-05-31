# Descartes Monitoring and Alerting

**Created:** 2026-05-28
**Status:** Completed
**Completed:** 2026-05-29 — first Node.js monitoring/alerting slice now has deterministic alerts, opt-in LLM adjudication, and opt-in notification setup/test/delivery audit.
**Updated:** 2026-05-28 — initial CLI-only alert store/rule evaluator slice implemented.
**Addendum:** 2026-05-28 — product direction changed: deterministic alerts should wake an opt-in LLM adjudicator, which decides whether/how to notify and writes the notification text.
**Updated:** 2026-05-28 — alert-intelligence config, LLM decision schema, local audit log, and rate-limit controls implemented.
**Updated:** 2026-05-29 — notification delivery config, setup/test UX, bounded delivery adapters, and local delivery audit implemented.

## Purpose

Move from on-demand history summaries into actual local monitoring and alerting, while preserving Descartes safety boundaries: deterministic local evidence first, no unconfigured background LLM calls, no telemetry, no remediation actions, and explicit user control over notification delivery.

This layer should sit on top of the daemon/history substrate and run cheap deterministic rule evaluations over recent metrics and daemon status. Deterministic rules are the wake trigger, not the final notification brain: once the user explicitly enables alert intelligence, alerts wake an LLM adjudicator that decides whether to notify, what severity/channel to use, and what bounded notification text to send.

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

## Alert Intelligence / LLM Wake Path

Product direction: the LLM should be woken by deterministic alert triggers and should decide whether/how to notify.

Design constraints for that path:

- Disabled by default until explicitly configured by the user.
- Wake only on deterministic alert state transitions or cooldown expiry, not continuously.
- Send only bounded alert records, recent history summary, daemon status, and selected sanitized evidence summaries; do not send raw logs/process dumps by default.
- No action/remediation tools in the alert adjudicator session.
- The LLM returns a structured decision, for example:

```json
{
  "notify": true,
  "severity": "info | warning | critical",
  "title": "Short notification title",
  "body": "Bounded user-facing notification text",
  "reason": "Why notification should or should not be sent",
  "evidence_refs": ["history-summary", "alert:alert_..."],
  "next_check_hint": "Optional short next check"
}
```

- Persist the LLM decision and prompt metadata as local alert audit state.
- Rate-limit and budget background model calls; repeated noisy alerts must not cause repeated model wakeups.
- If no credentials/model are configured, keep CLI-only deterministic alerts and do not fail the daemon.

## Notification Surfaces

Start with CLI/status surfaces. Add desktop/headless delivery behind explicit configuration. For LLM-enabled alerting, delivery adapters should receive the LLM's bounded notification decision, not raw alert/evidence blobs.

Candidate surfaces:

- macOS desktop: Notification Center via `osascript` or another permissioned local mechanism; fallback to CLI/status only.
- Linux desktop: `notify-send` / D-Bus notifications when a graphical session is available.
- Headless Linux/server: syslog/journald entries first; optional email/webhook only after explicit configuration.
- CLI-only MVP: `alerts list`, `alerts watch`, nonzero status for script checks, and concise alert summaries in `history summary`.
- Future integrations: Slack, Discord, webhook, mobile push only with opt-in, redaction, routing policy, and rate limits.

## Safety Boundaries

- No unconfigured background LLM calls; alert-intelligence model wakeups require explicit opt-in and configured credentials.
- No host mutation except explicit alert state writes under Descartes-owned paths and explicit notification delivery.
- No remediation actions.
- No telemetry/upload/federation beyond the configured provider call for opted-in alert intelligence.
- No arbitrary shell/coding tools.
- LLM wake prompts and notifications must use bounded, redacted alert/evidence summaries, not raw logs/process dumps.
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

## Implementation Notes

Initial Node.js prototype slice implemented in v0.0.41:

- `alert-store.js` persists structured alert records under Descartes-owned XDG state.
- Deterministic rules cover missing/stale daemon samples, sustained high memory pressure, sustained high load relative to CPU count, and disk pressure.
- `descartes alerts list/watch/ack` provides CLI-only alert inspection and acknowledgement without invoking an LLM.
- Daemon iterations evaluate and persist alerts after metric collection.
- Dedupe/cooldown and acknowledged/recovered states are covered by tests.

The v0.0.42 slice adds explicit alert-intelligence opt-in config, LLM adjudicator decision schema/audit, and max wakeups/hour rate limits. The v0.0.43 slice adds separately opt-in notification delivery config plus `descartes alerts notifications status|setup|test|disable`, bounded macOS desktop (`osascript`), Linux desktop (`notify-send`), syslog, and CLI-only delivery modes, local JSONL delivery audit, and daemon integration that delivers only LLM-authored notification decisions when both alert intelligence and notification delivery are enabled.

## Acceptance Criteria

- [x] Rules can be tested without real time sleeps.
- [x] Alerts are persisted under Descartes-owned XDG state.
- [x] CLI can list active/recent alerts without invoking an LLM.
- [x] Dedupe/cooldown prevents repeated alert spam.
- [x] Alert-intelligence LLM wakeups are optional, explicitly configured, rate-limited, and audited.
- [x] Notification delivery is optional and explicitly configured.
- [x] All outputs preserve current read-only/no-telemetry/no-remediation boundaries.
