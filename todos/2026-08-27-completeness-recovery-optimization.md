# Completeness recovery optimization — post-anchor-history rebuild

**Created:** 2026-08-27
**Source:** `gpt-5.6-sol` reviews of the fact-store completeness hardening (the Finding-1 tension) + the intrusion-detector sweep (Finding-1 re-flagged as a latch, intentionally deferred). This todo makes the deferred optimization trackable.
**Status:** OPEN — deferred OPTIMIZATION (not a correctness bug — current behavior is the safe, conservative choice).

## Current behavior (deliberate, safe)

After a real fact-history loss (corruption / schema-invalid / byte-cap eviction / continuity break), a novelty detector re-establishes trust only when the loss **ages out of the read window** — i.e. `factHistoryTrustworthy` requires `completeness.status === "intact"` even for an anchored caller. This is a deliberate shift from the plan's original **tick-count** recovery (N clean ticks after the anchor).

Why require intact rather than tick-count: sol's completeness-hardening review proved that anchored tick-count recovery FABRICATES — a loss *at/before the anchor but still inside the read window* leaves the window shortened, so an edge whose establishing ticks were scrubbed reads as "novel". Requiring `intact` (loss aged out) is provably non-fabricating. Documented as the design decision in `docs/plans/2026-08-21-fact-store-completeness-hardening.md` (Status line / §2a).

## The cost being optimized

Recovery is now bounded by the **retention window** (up to ~31 days by default) after a real loss, not by a handful of ticks. This is safe (never fabricates, self-heals, operator-visible via `descartes learned status`) but slow: a single byte-cap eviction can suppress a detector's novelty for the whole window.

## The optimization (the real fix)

Have the detector, during recovery, **rebuild its baseline from ONLY post-anchor history** rather than the full (still-shortened) window. Then a handful of clean post-anchor ticks give a trustworthy baseline AND the shortened pre-anchor region is ignored — resolving both the fabrication (hardening Finding 1) and the latch (sweep Finding 1) without the window-long wait.

This is a per-detector change to how the windowed baseline is computed during/after a cold-start recovery (session/peer/service/canary/process-lineage), NOT a helper change. Non-trivial: must be proven not to reintroduce the pre-anchor fabrication. Add integration tests using real `buildCompleteness` (not hand-authored `"intact"` fixtures — a lesson from the sweep).

## Related
- `docs/plans/2026-08-21-fact-store-completeness-hardening.md` (§2a, the Finding-1 fix + the window-aging design decision).
- `src/fact-store-completeness.js` `factHistoryTrustworthy` / `hasLossEventAfter`; the detector baseline computations.
