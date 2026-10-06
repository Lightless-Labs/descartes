# Notify-once single-daemon simplification

**Status:** complete locally, 2026-10-06

## Objective

Remove per-delivery locking, claiming, and takeover so notification state has one writer and
episodes can represent every live incident identity under an alert id.

## Decisions

- The daemon owns the singleton and all alert-state writes. CLI mutations use an append-only
  command queue while it is running, or acquire the same singleton for direct application when it
  is stopped.
- Singleton stale ownership is reclaimed only when the owner is provably gone. macOS without a
  process-start identity refuses to guess. Wait deadlines use a monotonic clock.
- Episodes retain bounded observed and notified incident-key sets. New keys and severity
  escalations bypass retry backoff; rollback makes a future last-attempt timestamp immediately
  eligible.
- Delivery is at-least-once across a crash after external delivery and before confirmation.
- All notification audit result types rotate with a retained summary.

## Verification

- Focused notify-once/daemon/producer suites: 207 passing.
- Fresh-XDG `npm test`: 2,115 passing, 22 environment failures, 34 skipped, 2,171 total.
  The failures are the existing sandbox loopback `listen EPERM` tests (20) and two live-host
  macOS provenance checks returning `unknown` instead of `ok`.
