# Retention-clamp boot-identity guard (Phase 3)

**Created:** 2026-09-08
**Status:** deferred — depends on the Phase-3 boot-identity / continuity-ledger primitive
**Area:** fact-store retention clamp (introduced in trusted-state step-① Phase 1)
**Decision:** operator accepted (2026-09-08) shipping the Phase-1 clamp without this guard; this
item closes the known, accepted residual once the enabling primitive exists.

## Work

Add a boot-identity-aware guard to the fact-store retention clamp so the clamp applies only under a
monotonic, same-boot-consistent sequence. This closes the residual the Phase-1 clamp knowingly
leaves.

## Why deferred

A sound guard needs an out-of-band signal (boot identity) that a wall-clock-only check cannot
provide. That primitive lands with the Phase-3 continuity-ledger work
(`docs/plans/2026-09-06-trusted-state-step-1.md` §5.3). Building the guard before it exists would be
security theatre — it could not actually distinguish the case it needs to.

## Depends on / relates to

- Phase-3 continuity ledger (boot identity) — same plan, §5.3.
- The Phase-1 clamp — same plan, the "Revision" section, fix 1.

## Note (public repo)

The threat mechanics are intentionally **not** restated in this file. This item exists so the
accepted Phase-1 residual is tracked and closed once the enabling primitive exists — see the
operator on where the detailed rationale should live.
