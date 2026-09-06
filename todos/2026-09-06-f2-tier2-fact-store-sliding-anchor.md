# F2-Tier2: sliding-anchor / scoped-claim fact-store recovery

**Created:** 2026-09-06 (Astra audit finding F2, Tier-2 remainder)
**Status:** deferred — needs its own plan + a daybreak review before implementing
**Area:** `tools/descartes-cli/src/fact-store.js` (integrity/completeness recovery path)
**Tracking:** `todos/2026-09-04-codex-project-audit-follow-up.md` (F2 disposition: Tier-1 shipped)

## Context

Astra's F2 had two tiers. **Tier-1 shipped** (`continuity_oldest_ts` reporting in
fact-store-integrity — the store now reports the oldest timestamp it can still vouch for). **Tier-2
is the harder, deferred half:** after a detected continuity break, recovery currently re-anchors in
a way that can *narrow* the span the store claims to cover, which genuinely narrows detection
strength (a monitor keyed off that store sees a shorter history than really exists on disk).

## Why it is deferred (not a quick fix)

The fix is a *sliding anchor* with a **minimum-span floor** — recovery must never re-anchor to a
window shorter than a floor, so a break cannot silently shrink coverage. Getting the floor and the
re-anchor arithmetic right is a design task with its own failure modes (too-tight a floor wedges
recovery; too-loose re-admits the very corruption the break flagged). It is a detection-strength
change to a security-sensitive primitive, so:

## Plan

1. Write a dedicated plan under `docs/plans/` (sliding-anchor recovery + minimum-span floor;
   enumerate the re-anchor cases and their invariants).
2. Implement TDD.
3. **daybreak review** before landing — this narrows/widens detection on the fact store, exactly the
   class where the frontier reviewer earns its keep.

## Acceptance

- A continuity break never re-anchors below the minimum-span floor.
- The store's claimed coverage span is never silently narrower than the on-disk facts justify.
- daybreak re-gate of the recovery path is clean.
