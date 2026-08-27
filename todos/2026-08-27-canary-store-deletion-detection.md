# Canary baseline-store deletion detection (durable provisioning marker)

**Created:** 2026-08-27
**Source:** `gpt-5.6-sol` review of Slice 7 (canary completeness adoption) — findings round 2, the missing-store→tamper revert. Deferred with an in-code note; this todo makes it trackable.
**Status:** OPEN — deferred. LOW/MED severity.

## The gap

`canary.tripped` fires on positive two-snapshot evidence regardless of the canary-baseline store's state (correct — a deleted store no longer *disables* the tripwire). But a **bare deletion of `canary-baseline.json`** (provisioned-then-removed by an adversary) currently raises **no signal of its own**: a cleanly-absent store is deliberately NOT treated as `canary.tampered(baseline_store_error)`, because that would false-alert legitimate first-run (never-provisioned) and post-decommission (store cleaned up) states. See the in-code note at `tools/descartes-cli/src/canary-baseline.js` (~L757, "Bare baseline-store deletion (provisioned-then-removed) is deferred").

So: corrupt / unreadable / write-failed stores DO raise `canary.tampered(baseline_store_error)`; a cleanly-deleted one does not. The tripwire still works either way (positive trips are store-independent), so this is a *defense-in-depth* gap, not a tripwire-evasion.

## Why it needs a marker (not just "missing => tamper")

To distinguish an adversarial deletion from a benign never-provisioned / decommissioned absence you need a **durable provisioning-state marker**: something set once at canary setup/enablement and cleared at decommission. Then: store absent + provisioning-marker present => tamper; absent + no marker => benign (first-run/decommission). The marker must itself live outside the deletable store (or be part of a signed/attested state) or the same adversary just deletes it too — which ties into the off-host / tamper-evidence attestation work (`todos/2026-08-11-tamper-evidence-attestation-design.md`).

## Fix sketch

- Add a provisioning marker written at canary enablement (`descartes canary` setup path) and cleared on explicit decommission.
- Missing store + marker-present => `canary.tampered(baseline_store_error)` (or a distinct `canary.tampered(baseline_store_deleted)` reason); missing store + no marker => no tamper (current behavior).
- Add tests: adversarial delete-after-provision => tamper; first-run => no tamper; decommission-then-absent => no tamper.
- Consider anchoring the marker in the tamper-evidence/off-host layer so a root adversary can't forge/delete it silently.

## Related
- `tools/descartes-cli/src/canary-baseline.js` (in-code note).
- `todos/2026-08-11-deception-canary-collector.md` (the canary collector itself).
- `todos/2026-08-11-tamper-evidence-attestation-design.md` (durable/off-host state — the marker's real home against local root).
