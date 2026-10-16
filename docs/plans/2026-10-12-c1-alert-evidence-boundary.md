# C1 alert evidence-boundary rework

**Status:** complete
**Last updated:** 2026-10-16 — gate 3–4 follow-ups (addendum below)

## Scope

Close the daybreak findings on the C1 alert foundations branch without making same-UID
tampering preventable. Same-UID edits remain `unprotected_same_uid`, but every edit that
changes alert, label, journal, or notification state must be detected, chained, and visible.

## C1 addendum: same-UID evidence boundary (2026-10-12)

The C1 security scope deliberately does not attempt to defend against a deliberate attacker
running as the daemon's UID. That principal can rewrite `alerts.json`, `labels.state.json`, the
notification outbox, and the hash-chained logs themselves; every key needed to edit those files is
readable at the same UID. Therefore neither prevention nor reliable on-host proof of same-UID
forgery is achievable here. In particular, C1 does not add defenses for forged `storm_covered_at`,
`confirmed_at`, or closure records that reuse old authorizations, nor for pre-populated label-state
entries. The existing cheap consistency checks remain because they catch accidental or non-attacker
failures, but they are not presented as an attacker boundary.

The missing-authority remedy is off-host attestation, a separate initiative tracked by the autonomy
doctrine and this plan's §16.2 item 6. C1 instead fixes failures that require no attacker: unreadable
closure witnesses fail closed and re-notify, label journal-open failures abort the transaction,
required notices are queued before optional configuration is read, audit records precede delivery,
outbox overflow/corruption stays visible, discarded storm keys above the delivered storm severity
escalate, and closure reconciliation reuses the verified transition head.

## Addendum: daybreak gates 3–4 follow-ups (2026-10-16)

**Addendum:** 2026-10-16 — gate 3 (BLOCKER: structurally malformed outbox entries bypassed
corruption handling; MEDIUM: incremental transition verification fell back to `full_recovery` on
every tick after compaction) and gate 4 (BLOCKER: recovery compare-then-rename could quarantine a
valid concurrently written outbox; MEDIUM: `seen.resolution` unvalidated) are closed:

- `0e61a19` — every pending/seen/resolved entry is shape-validated; any malformed entry makes the
  outbox corrupt (quarantined, fresh valid outbox with a pending integrity notice). Alert list, JSON,
  digest build/render render only well-formed notices and count the rest; queue normalizes inputs so
  the module never writes what its validator rejects.
- `7905d16` — the incremental verifier accepts a compacted log: the cut header's recorded
  predecessor head (`through_seq`/`through_hash`) must be cited by the first kept record, and the
  header (carried witness, coverage, projection digest) is returned. The whole-file content digest in
  the state file still binds the unverified prefix, header included.
- `0936f47`, `5b09bf9`, and the round-5 lock rewrite — **outbox lock contract:** one lock file
  `<pendingFile>.lock`, JSON `{pid, token, at}`, created complete (temp file + `link()`, which fails
  if a lock exists — never empty); every outbox read-modify-write (queue, settle, view, attempt
  bookkeeping, corruption recovery) runs under it; recovery re-reads under the lock before
  quarantining. A lock is stale when the holder pid in the *observed* content is dead or the lock is
  older than 30 s (never because a waiter waited). Every lock removal — a holder's release (own
  token) or a stale break (exact observed content) — runs under a second `<lockFile>.break` lock and
  re-reads first, so nobody removes a lock other than the one they checked. Residual: the break lock's
  own stale break is unserialized (needs a crashed/30 s-paused break-lock holder plus a three-way
  race). `alerts list`/`digest` mark seen only the notice ids they rendered.

The lock is **cooperative**: a same-UID writer that ignores it can still race or rewrite the outbox.
That is the same deliberate same-UID forgery already out of scope above, not a new boundary.

## Atomic slices

1. Closure attribution and restoration from the transition witness (B1, M2).
2. Witness-derived label budget and transactional label application (B2, B3).
3. Pending-journal fail-closed recovery, bounded state, and bounded reads (B4, HIGH 2/3).
4. Pending notification outbox and CLI visibility (B5).
5. Overflow severity memory (HIGH 1).
6. Incremental transition verification and durable digest closure attribution (MEDIUM 1/2).

Each slice adds a regression first, runs its focused tests, and is committed independently.

## Completion

All six slices are implemented and committed locally. The final full-suite run used fresh
`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, and `XDG_CACHE_HOME` directories. It reported
2,789 tests: 2,726 passed, 22 environment-only failures, 35 skipped, and 6 todo. The failures are
the sandbox's localhost bind restriction (17 notifier-reuse and 3 tap-bump tests) plus restricted
live-process introspection (2 provenance tests); no changed-area product test failed.
