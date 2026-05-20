# Descartes Recent Logs Collector Plan

**Created:** 2026-05-20  
**Status:** Completed  
**Completed:** 2026-05-20 — implemented `collect_recent_logs`, parser tests, guarded triage exposure, docs updates, and v0.0.19 metadata bump.

## Goal

Add a bounded read-only `collect_recent_logs` tool for local operational/security triage, including general warnings/errors plus fail2ban/firewall-oriented signals where available.

## Scope

- Linux: `journalctl`-based recent warnings/errors, fail2ban unit logs, firewall-related units, and kernel firewall/drop-style messages.
- macOS: unified log recent errors/faults plus firewall/security-oriented predicates where available.
- Return one structured evidence envelope with bounded entries, command metadata, privacy notes, and graceful `unable`/`unsupported` probe statuses.
- Expose through the guarded triage tool surface only after tests pass.

## Safety

- Read-only fixed command argv arrays only.
- Strict time/event/message bounds.
- Redact obvious secret tokens/passwords/API keys from excerpts.
- Treat log excerpts as sensitive diagnostic artifacts; no background upload or telemetry.
- Missing commands/permissions must not fail the whole collector.

## Acceptance Criteria

- Parser tests cover journal JSON, macOS unified-log JSON, syslog-style fail2ban/firewall lines, bounding, categorization, and redaction.
- `collect_recent_logs` is in `TRIAGE_TOOL_NAMES` and created by the private harness.
- Prompt tells the model to use logs for crashes/restarts/auth/firewall/fail2ban questions rather than guessing.
- README/handoff/todo document the new collector.
- `npm test` passes.
