# C1 alert evidence-boundary rework

**Status:** in progress  
**Last updated:** 2026-10-12 — daybreak rework

## Scope

Close the daybreak findings on the C1 alert foundations branch without making same-UID
tampering preventable. Same-UID edits remain `unprotected_same_uid`, but every edit that
changes alert, label, journal, or notification state must be detected, chained, and visible.

## Atomic slices

1. Closure attribution and restoration from the transition witness (B1, M2).
2. Witness-derived label budget and transactional label application (B2, B3).
3. Pending-journal fail-closed recovery, bounded state, and bounded reads (B4, HIGH 2/3).
4. Pending notification outbox and CLI visibility (B5).
5. Overflow severity memory (HIGH 1).
6. Incremental transition verification and durable digest closure attribution (MEDIUM 1/2).

Each slice adds a regression first, runs its focused tests, and is committed independently.
