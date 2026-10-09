# Notify-once incident records

**Status:** complete locally, 2026-10-09 — final batched-delivery design recorded

## Objective

Persist notification state as first-class records for each incident identity under its alert id.
Each tick evaluates every persisted active incident for due-ness, independently confirms or retries
delivery, and retains confirmed incidents until recovery. A bounded live-incident set enters an
explicit storm state that has one notification target and suppresses per-incident adjudication.
There is no per-tick delivery-attempt cap: every route-qualified due item is visited in global
severity-descending order. Each route has its own circuit breaker, so one unavailable route cannot
monopolize the daemon or block another route.

## Decisions

- Alert state is represented by per-incident records, not a singleton episode or command queue.
  New incident keys and severity escalations bypass retry backoff; a failed unconfirmed incident is
  retried when its persisted backoff expires even if that key is absent from the current tick.
- Legacy records without episode metadata are suppressed only during their upgrade episode; recovery
  clears that compatibility marker so a later fresh incident can notify.
- Every tick scans every persisted active alert for expired failed-incident and failed-storm retries,
  including alerts with no current candidates or excluded recovery coverage. Delivery visits all
  route-qualified due entries, ordered by severity descending, new/escalated-before-retry, and
  oldest unconfirmed work; deferred due entries remain persisted for later ticks. Delivery outcomes
  (successes, failures, and route-breaker skips) are collected in memory and committed in one
  alert-store transaction per tick.
- At the live-incident bound, `incident_storm` is one persisted notification target. It retries after
  failure without requiring another overflow and does not send per-incident LLM adjudications.
- Delivery is at-least-once across a crash after external delivery and before confirmation.
- Notification delivery audit is dated UTC append-only JSONL segments. Writers open the segment for
  each append; readers consume the legacy file first, then orphan archives, then dated segments in
  order. Retention counts every audit segment, including the legacy file, and removes whole
  segments oldest-first while over the byte cap. It never removes the segment written by the
  current process in that tick, and never rewrites, renames, or compacts an append target.
- A future writer-boundary design is still TODO: concurrent alert-store read-modify-write writers
  are unsupported and remain tracked separately in `todos/2026-10-09-alert-store-concurrent-writers.md`.

## Verification

- Focused alert-intelligence suite: 148/148. The combined alert-store,
  alert-intelligence, notification-delivery, containment, and fact-store suites pass 243/243.
- Fresh-XDG `npm test`: 2,386 total, 2,330 passing, 22 environment failures, 34 skipped, 0 todo.
  The failures are 17 sandbox notifier-reuse loopback `listen EPERM` tests, 3 sandbox tap-bump
  loopback `listen EPERM` tests, and 2 live-host macOS provenance checks returning `unknown` instead
  of `ok`; no product-behavior failures remain.
