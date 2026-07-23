# FIX-SPEC — `reduceLatestProvenanceWarnings` same-tick ambiguity (second `>=` latest-wins copy)

**Created:** 2026-07-23
**Reviewed:** 2026-07-23 (via review gate) — GO_WITH_CHANGES, must-fixes folded in
**Status:** DRAFT — ready to implement
**Scope:** single function, single file (+ its test file). No wiring changes.
**Source:** `docs/plans/2026-07-16-codex-findings-hardening.md` ("Second copy exists — explicitly
DEFERRED", lines 104–109) and `docs/HANDOFF.md` option #2.
**Mirrors:** `shadow-store.js`'s `buildShadowFactLookup` Slice A fix, commit `accbc49`.

## Collision risk (from recon seam-map)

Severity: low. Only files touched are `provenance-warnings.js` and its test file
(`test/provenance-warnings.test.js`). Shared files `alert-store.js`, `alert-intelligence.js`, and
`daemon.js` are untouched by this slice. The only realistic overlap with a parallel task is another
task editing neighboring regions of `provenance-warnings.js` in the same time window — implementers
running this slice alongside others should check for concurrent edits to that file before merging.

## Bug

`tools/descartes-cli/src/tools/provenance-warnings.js:199–211`, `reduceLatestProvenanceWarnings`,
keeps a `Map<entity_key, {tsMs, point}>` and on a tie (`tsMs >= existing.tsMs`) silently overwrites
with whichever point was processed last — even when two same-`ts` points for the same `entity_key`
carry **different** `attributes` (a within-tick contradiction, e.g. two owners of one
socket/pid entity racing in one collector tick).

Unlike `buildShadowFactLookup`'s shadow-only copy of this bug, this one feeds a **real**
alert-candidate path: `buildProvenanceWarningCandidates(reduceLatestProvenanceWarnings(points))` is
called every daemon tick from `computeProvenanceWarningCandidates`, wired into `daemon.js`'s
`extraCandidates` concat (line 528). A silently-picked-last observation can directly become a
fired provenance alert.

## Fix

Replace the `>=` latest-wins reduction with the ambiguous-on-same-ts-different-value tracking
pattern from `shadow-store.js:buildShadowFactLookup` (lines ~211–265), adapted to this function's
shape (`Map<entity_key, {tsMs, point}>` → per-entity_key, not per-target; whole-`attributes`
equality, not a single `value` field — there is no single scalar attribute here, only a full
`attributes` object per observation):

```js
export function reduceLatestProvenanceWarnings(factPoints = []) {
  const latestByEntity = new Map();
  for (const point of factPoints ?? []) {
    if (!point || point.fact_name !== PROVENANCE_WARNING_FACT_NAME) continue;
    const entityKey = point.entity_key;
    if (!entityKey) continue;
    const tsMs = new Date(point.ts).getTime();
    if (!Number.isFinite(tsMs)) continue;
    const existing = latestByEntity.get(entityKey);
    if (!existing || tsMs > existing.tsMs) {
      // First observation, or a strictly-NEWER tick: legitimately supersedes anything older,
      // clearing any prior same-ts ambiguity (ambiguity is per-latest-ts, never sticky).
      latestByEntity.set(entityKey, { tsMs, point, ambiguous: false });
    } else if (tsMs === existing.tsMs && JSON.stringify(point.attributes) !== JSON.stringify(existing.point.attributes)) {
      // Same bug class as shadow-store.js's Slice A (commit accbc49): two DIFFERENT observations
      // at the SAME latest ts is a within-tick contradiction (one collector tick shares one ts).
      // Pre-fix this silently collapsed to last-processed-wins; now mark ambiguous and withhold —
      // fail to skip, never silently pick one. Identical duplicates are NOT ambiguous.
      existing.ambiguous = true;
    }
    // tsMs < existing.tsMs: an older observation; the newer one already won — ignore.
  }
  const ambiguousEntityKeys = [];
  const result = [];
  for (const [entityKey, entry] of latestByEntity) {
    if (entry.ambiguous) { ambiguousEntityKeys.push(entityKey); continue; }
    result.push(entry.point);
  }
  result.ambiguousEntityKeys = ambiguousEntityKeys;
  return result;
}
```

Notes:
- Equality check is `JSON.stringify(point.attributes)` (whole-observation equality), not a
  narrower field, since there is no single "value" per point here. `provenanceWarningFactPoints`
  (lines 126–137) builds `attributes` in a fixed key order (`rule_id`, `active`, then optional
  `source_type`/`confidence`/`severity`, then rule-specific fields), so this is deterministic for
  points produced by that function. Hand-built test fixtures must use that same key order to avoid
  a false-negative (same content, different insertion order); this is documented inline exactly
  like Slice A's own "same-ts = same-tick is a PROXY, not a guarantee" caveat — no key-sorting is
  added, to stay a minimal mirror of the accbc49 fix.
- Observability: suppressed entity_keys are exposed as `reduced.ambiguousEntityKeys` on the
  returned array (mirrors `lookup.ambiguousTargets`), decorating the plain array rather than
  wrapping it in `{ points, ambiguousEntityKeys }` — `buildProvenanceWarningCandidates` only does a
  plain `for...of` over the return value, so either shape works there; array-decoration is the less
  invasive option and matches Slice A's own choice.
- Update the function's doc comment (current lines 191–198) to drop the stale "mirrors
  `buildShadowFactLookup`'s own latest wins semantics" framing (that function no longer has
  latest-wins-on-ties semantics as of `accbc49`) and instead describe the ambiguity-aware behavior,
  parallel to `buildShadowFactLookup`'s updated doc comment.

**Zero changes** required to `buildProvenanceWarningCandidates` (lines 228–236) or
`computeProvenanceWarningCandidates` (lines 247–258): both consume the return value as a plain
array; an ambiguous entity_key is simply absent from it (equivalent to `lookup(target) ===
undefined`), and the extra `ambiguousEntityKeys` property is ignored by both. `daemon.js:528` and
`session-baseline.js:303` are read-only references, unaffected.

## Regression tests

Add to `tools/descartes-cli/test/provenance-warnings.test.js`, directly after the existing
`reduceLatestProvenanceWarnings` block (current lines 250–266), mirroring
`shadow-store.test.js`'s Slice A block (lines 256–321) 1:1 in intent:

1. **Same-ts, differing `attributes` → excluded, entity_key listed in `ambiguousEntityKeys`.**
   Two points, same `entity_key`, same `ts`, different `attributes` (e.g. differing
   `source_type`/`confidence` or differing rule-specific fields) → `reduceLatestProvenanceWarnings`
   returns `[]` for that entity, and `reduced.ambiguousEntityKeys` contains the entity_key.
2. **Same-ts, identical `attributes` → NOT ambiguous, kept.** Two points, same `entity_key`, same
   `ts`, byte-identical `attributes` (built in canonical key order) → one point returned,
   `ambiguousEntityKeys` is `[]`.
3. **Strictly-newer single value clears a prior same-ts ambiguity**, order-independent (two array
   orderings: ambiguous-pair-then-newer, and newer-then-ambiguous-pair) → the newer point wins,
   `ambiguousEntityKeys` is `[]`.
4. **Different entity_keys never cross-contaminate ambiguity.** A same-ts ambiguous pair for
   entity A and a clean single point for entity B in the same call → only A is excluded /
   listed in `ambiguousEntityKeys`; B is returned normally.

## Fail-safe confirmation

Ambiguous ⇒ **no alert claim, never a fabricated warning.** An ambiguous entity_key is dropped
from `reduceLatestProvenanceWarnings`'s return value entirely, so
`buildProvenanceWarningCandidates`'s `for...of` never sees it and never builds a candidate for it —
the "no fact, no claim → skip" path, identical in effect to `buildShadowFactLookup(...)(target) ===
undefined`. This can only ever **withhold** a provenance-warning candidate on conflicting evidence;
it can never invent, merge, or guess one. Degrade-not-fabricate preserved; no new alert namespace,
no execFile/shell surface, no LLM involvement, no new daemon wiring.

## Out of scope

- Any change to `buildProvenanceWarningCandidates`, `computeProvenanceWarningCandidates`,
  `daemon.js`, or `alert-store.js`'s `extraCandidates` merge.
- A shared `ambiguity` utility factored out of both copies (YAGNI per the Slice A note; the two
  functions have different Map value shapes — `value` vs whole-`attributes` — and different
  degraded-point exclusion rules, so a shared helper is not a small change).
- Sorting `attributes` keys before `JSON.stringify` (documented caveat instead, matching Slice A's
  own choice not to over-engineer the proxy check).
