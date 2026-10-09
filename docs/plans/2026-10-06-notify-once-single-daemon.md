# Notify-once incident records

**Status:** complete locally, 2026-10-09 — final architecture update after daybreak-blue review

## Objective

Persist notification state as first-class records for each incident identity under its alert id.
Each tick evaluates every persisted active incident for due-ness, independently confirms or retries
delivery, and retains confirmed incidents until recovery. A bounded live-incident set enters an
explicit storm state that has one notification target and suppresses per-incident adjudication.

## Decisions

- Alert state is represented by per-incident records, not a singleton episode or command queue.
  New incident keys and severity escalations bypass retry backoff; a failed unconfirmed incident is
  retried when its persisted backoff expires even if that key is absent from the current tick.
- Legacy records without episode metadata are suppressed only during their upgrade episode; recovery
  clears that compatibility marker so a later fresh incident can notify.
- At the live-incident bound, `incident_storm` is one persisted notification target. It retries after
  failure without requiring another overflow and does not send per-incident LLM adjudications.
- Delivery is at-least-once across a crash after external delivery and before confirmation.
- Notification audit rotation atomically renames the current file to an archive before offline
  compaction, preserving appenders holding the old inode and appending the compacted result to the
  fresh path.
- A future writer-boundary design is still TODO: concurrent alert-store read-modify-write writers
  are unsupported and remain tracked separately in `todos/2026-10-09-alert-store-concurrent-writers.md`.

## Verification

- Focused notify-once/containment/notification-delivery suites: 59 passing.
- Fresh-XDG `npm test`: 2,318 passing, 22 environment failures, 34 skipped, 2,374 total. The
  failures are 17 sandbox notifier-reuse loopback `listen EPERM` tests, 3 sandbox tap-bump loopback
  `listen EPERM` tests, and 2 live-host macOS provenance checks returning `unknown` instead of `ok`.
- Fresh-XDG `npm test`: 2,115 passing, 22 environment failures, 34 skipped, 2,171 total.
  The failures are the existing sandbox loopback `listen EPERM` tests (20) and two live-host
  macOS provenance checks returning `unknown` instead of `ok`.
