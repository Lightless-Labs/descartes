# Provenance-identity recovery coverage (deferred safe-frozen)

**Created:** 2026-10-05
**Status:** DEFERRED — safe-frozen; no positive-clear coverage is emitted.
**Branch:** `fix/provenance-identity-coverage-2026-10` (local only)
**Related plan:** `docs/plans/2026-09-20-detector-reported-recovery-coverage.md`

## Current posture

The provenance-identity producer keeps the `{ candidates, evaluatedAlertKeys }` shape for
`unknown_identity`, `identity_drift`, and `new_public_bind`, but `evaluatedAlertKeys` is always
`[]` on every path. Alerts freeze until acknowledged. This is intentional: detection continues,
but a disappearing candidate is never treated as proof that the condition cleared.

## Why deferred

An ordinary unprivileged macOS `lsof` census cannot prove that another UID has no public listener.
Linux `/proc/net` and fd attribution likewise cannot prove absence across other network namespaces.
Therefore even a successful-looking unprivileged census cannot establish the claimed global fact
“nobody on the machine holds this transport/port.” The fourth daybreak round made this the blocker
for restoring positive recovery coverage.

## Re-key/sibling/stat-skip edges from rounds 1–4

- macOS `[::]` and `::` wildcard spellings previously split public-bind detection.
- Linux `tcp6`/`udp6` keys previously split v4/v6 transport fingerprints.
- A cross-UID or cross-netns holder can be absent from an otherwise successful unprivileged census.
- A same-key identity with a transient stat-skipped sibling can be mistaken for a verified clear.
- Re-keyed identities, provisional holders, and sibling holders must not transfer absence authority.
- Bounded five-entry historical/current port lists cannot establish global absence; union overflow
  must be marked truncated.

The first two are detection-correctness fixes and are shipped independently of coverage. The latter
edges remain fail-closed; no coverage key is emitted for any of them.

## Revisit trigger

Revisit when `harden/root-helper-2026-10` provides an elevated root-helper census that is complete
machine-wide across UIDs and network namespaces.

## Required future design

Positive global absence may be reconsidered only over that complete privileged socket inventory.
The design must fold same-key observations and skipped siblings, include provisional/re-keyed/all-
holder records, normalize address/protocol keys before comparison, and make any incomplete or
truncated census produce no coverage. Until those conditions are met, keep the producer frozen.
