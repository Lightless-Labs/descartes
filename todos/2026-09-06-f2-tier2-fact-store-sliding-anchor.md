# F2-Tier2: sliding-anchor / scoped-claim fact-store recovery

**Created:** 2026-09-06 (Astra audit finding F2, Tier-2 remainder)
**Status:** deferred — needs its own plan + a daybreak review before implementing
**Area:** `tools/descartes-cli/src/fact-store.js` (integrity/completeness recovery path)
**Tracking:** `todos/2026-09-04-codex-project-audit-follow-up.md` (F2 disposition: Tier-1 shipped)
**Grounded review:** `docs/reviews/2026-09-06-trusted-state-step1-grounded-review.md` (F2-Tier2 section)

## Grounded-review corrections (2026-09-06) — the framing below was reshaped

Two code-grounded reviewers (gpt-6-astra + Fable 5.1) reshaped this item. Supersede the original
"sliding anchor + minimum-span floor" framing with:

- **The shape is a coverage *contract*, not a floor.** Detector-declared **evidence horizon** +
  store **certified-coverage** reporting; the minimum-span floor gates **detector eligibility only**
  — it must NEVER extend store-claimed coverage (requiring the store to keep claiming a span it lost
  violates never-fabricate; a literal "never re-anchor below the floor" either wedges or fabricates).
- **F2-Tier1 as shipped OVER-CLAIMS — fix this first, as the small standalone carve-out.**
  `continuity_oldest_ts` mirrors `ledger.continuity.oldest_ts`, which only moves *older*
  (`fact-store-integrity.js:313-316`) and can **predate retained facts** (test asserts only
  `typeof==="string"`, `constraint-store.test.js:569`). It is NOT a coverage boundary. Fix
  `oldest_ts` semantics and add `certified_from_ts = max(oldest retained, in-window loss markers)`.
- **Byte-cap eviction is today a *loss* channel** (`fact-store-integrity.js:472`); eviction from the
  *old* end is coverage-narrowing, not an interior gap — it should move `certified_from_ts`, not
  break trust. This is the biggest detection-strength win and **widens what detectors trust →
  daybreak review** before landing.
- **Verdict split:** Astra — GO standalone as a coverage-contract change; Fable — carve out the
  reporting fix now and FOLD horizon-declaration + byte-cap-reclassification into the critique-§6
  claim change / transactional-store move. Both **reject an anchor-arithmetic-only fix.**
- **Must-cover failure modes** (see the review doc): too-tight floor → fail-stuck; too-loose /
  backward-extended → fabricated coverage; interior gap never bridged; future-dated facts must not
  count as coverage; ordinary eviction must not perpetually rearm cold-start. Required test: a
  **coverage oracle** (generated retention/loss/recovery sequences → claimed coverage always ⊆
  justified coverage) + a real-path (non-mocked) recovery-liveness test.

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
