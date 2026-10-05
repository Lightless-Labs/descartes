// THE single list of fact-store loss channels (fact-store capacity plan, 2026-10-05, §4.1 item 7 /
// step S1). Every trust consumer reads it from here: buildCompleteness's degraded evaluation
// (fact-store-integrity.js, which imports it as its LOSS_CHANNEL_FIELDS), factHistoryTrustworthy's
// anchor-relative check below, and the six detectors' own cold-start re-arm check
// (hasCompletenessLossAfterAnchor below -- previously six hand-maintained copies in the session,
// peer, service, process-lineage, persistence and canary detectors). A loss-channel change is now
// ONE edit, so no detector can silently keep (or drop) a channel the others changed.
//
// Order is significant ONLY for buildCompleteness's degraded_reason attribution (first match
// wins): last_future_fact_ts first, so a future-fact-only incident reports as such rather than
// being absorbed into a same-tick continuity-break attribution. The `.some` checks are
// order-independent.
//
// BLOCKER 2 (daybreak re-gate): last_future_fact_ts is a first-class anchor-relative channel. Fix 0
// added it to buildCompleteness's degraded array so a THIS-WINDOW future-fact loss degrades status
// -- but the anchor-relative check is a SEPARATE trust decision, keyed off the raw marker regardless
// of whether it has aged out of the current read window. Safe to include unconditionally (no
// R3-style DoS): last_future_fact_ts is always stamped with the pass's real nowIso when the future
// fact was dropped, never the record's own claimed future ts -- so it is a genuine past/current
// timestamp that ages out of the upper-bound clause exactly like every other loss channel, never a
// permanent lockout.
//
// R0b reclassification (fact-store capacity plan 2026-10-05, §4.1 item 4): last_bytecap_evict_ts is
// NOT a loss channel. The store's own byte-cap eviction is suffix-preserving and tick-aligned (it
// removes an oldest-end prefix, asserted in fact-store.js), so it NARROWS coverage -- recorded as
// the ledger's exclusive bytecap_floor_ts, enforced by readFactPoints, reported as
// certified_after_ts/coverage -- rather than breaking it. Treating it as a loss made every host
// whose per-tick volume filled the store read `degraded` for 31 days and re-armed every detector's
// cold-start anchor on every structural tick (the watch-tier lockout). Truncation by anything else
// is still a continuity break (prefix-digest check), and the corrupt, schema-invalid, continuity
// and future-fact channels keep their trust semantics (I4). last_bytecap_evict_ts and
// bytecap_evicted_total stay as informational fields.
export const COMPLETENESS_LOSS_TIMESTAMP_FIELDS = Object.freeze([
  "last_future_fact_ts",
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_continuity_break_ts",
]);

const LOSS_TIMESTAMP_FIELDS = COMPLETENESS_LOSS_TIMESTAMP_FIELDS;

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isValidCount(value) {
  return Number.isInteger(value) && value >= 0;
}

function isValidTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

/**
 * Returns true when a recorded loss event is strictly newer than anchorTs.
 * This is deliberately the only timestamp comparison used by the trust decision.
 * Missing/null event timestamps mean that channel has no recorded event. A malformed
 * timestamp is treated as a loss so the caller fails closed.
 */
function hasLossEventAfter(completeness, anchorTs, nowMs) {
  const anchorMs = anchorTs === undefined ? Number.NEGATIVE_INFINITY : Date.parse(anchorTs);
  if (!Number.isFinite(anchorMs) && anchorMs !== Number.NEGATIVE_INFINITY) return true;
  const upperBoundMs = Number.isFinite(nowMs) ? nowMs : Number.POSITIVE_INFINITY;

  return LOSS_TIMESTAMP_FIELDS.some((field) => {
    const timestamp = completeness[field];
    if (timestamp === undefined || timestamp === null) return false;
    if (!isValidTimestamp(timestamp)) return true;
    const lossMs = Date.parse(timestamp);
    return lossMs > anchorMs && lossMs <= upperBoundMs;
  });
}

/**
 * The detectors' cold-start re-arm check (moved here verbatim from the six detector copies; S1 of
 * the fact-store capacity plan, no behavior change): true when any loss channel recorded a loss
 * strictly after `anchorTs` and at or before `nowMs`. Deliberately NOT the same function as
 * hasLossEventAfter above -- the detectors' semantics differ in two pinned ways:
 *   - a missing/non-object completeness is "no loss" here (the caller's factHistoryTrustworthy
 *     call already fails closed on it, so re-arming on it too would double-count);
 *   - a missing/invalid anchor is treated as -Infinity (every recorded loss counts), where
 *     factHistoryTrustworthy instead fails closed with history_unknown.
 * A malformed (unparseable) loss timestamp counts as a loss (fail closed).
 */
export function hasCompletenessLossAfterAnchor(readResult, anchorTs, nowMs) {
  const completeness = readResult?.completeness;
  if (!completeness || typeof completeness !== "object" || Array.isArray(completeness)) return false;
  const anchorMs = typeof anchorTs === "string" && anchorTs.length > 0 && Number.isFinite(new Date(anchorTs).getTime())
    ? new Date(anchorTs).getTime()
    : -Infinity;
  const upperBoundMs = Number.isFinite(nowMs) ? nowMs : Infinity;
  return COMPLETENESS_LOSS_TIMESTAMP_FIELDS.some((field) => {
    const timestamp = completeness[field];
    if (timestamp === undefined || timestamp === null) return false;
    const timestampMs = new Date(timestamp).getTime();
    return !Number.isFinite(timestampMs) || (timestampMs > anchorMs && timestampMs <= upperBoundMs);
  });
}

/**
 * Makes the one central, fail-closed trust decision for fact-history consumers.
 * Pure: it performs no I/O and never mutates either input.
 *
 * MEDIUM-1 interim guard (fact-store capacity plan review fold, 2026-10-05): R0b reclassified
 * byte-cap eviction from a loss to coverage narrowing (fact-store-integrity.js), so a narrowed
 * store now reaches this function as plain `status: "intact"` -- correct for the daemon's
 * per-family history veto (daemon.js:1153, called with NO opts at all) and the six watch-tier
 * detectors behind it: they rely on their own retained-union / S3 per-rule horizon semantics, and
 * must keep trusting a narrowed store exactly as before. It is NOT correct for a reader with no
 * horizon of its own that mines or evaluates against the FULL accumulated window: the constraint
 * miner (`constraint-miner.js` -- "a truncated or otherwise untrustworthy history can hide
 * counterexamples and mint an over-strong draft"), the shadow evaluator (`shadow-store.js` --
 * "missing historical exercises can make a shadow candidate look falsely safe"), and correlation
 * (`incident-correlation.js` -- stateless, recomputed from the full read on every call). Those
 * three pass `opts.requireFullCoverage: true` to opt into a blunter, INTERIM fail-closed gate with
 * no anchor-relative carve-out, until S3 gives each its own per-reader horizon (fact-families.js).
 * Every other caller (the daemon veto, the detectors) omits it and is byte-for-byte unaffected.
 */
export function factHistoryTrustworthy(readResult, opts = {}) {
  try {
    if (!isObject(readResult) || !Object.prototype.hasOwnProperty.call(readResult, "completeness")) {
      return { trust: false, reason: "history_unknown" };
    }

    const completeness = readResult.completeness;
    if (!isObject(completeness)) return { trust: false, reason: "history_unknown" };

    if (!isValidCount(readResult.corrupt_count) || !isValidCount(readResult.schema_invalid_count)) {
      return { trust: false, reason: "history_unknown" };
    }
    if (readResult.corrupt_count > 0) return { trust: false, reason: "corrupt_facts_this_tick" };
    if (readResult.schema_invalid_count > 0) return { trust: false, reason: "schema_invalid_this_tick" };

    if (!["intact", "degraded", "unknown"].includes(completeness.status)) {
      return { trust: false, reason: "history_unknown" };
    }
    if (completeness.status === "unknown") return { trust: false, reason: "history_unknown" };

    // `!== "full"` (not `=== "narrowed"`) so any unexpected/malformed coverage value also fails
    // closed, matching this function's existing posture everywhere else. Only consulted when
    // opted in: coverage is ignored entirely for every other (bare) caller.
    const requireFullCoverage = isObject(opts) && opts.requireFullCoverage === true;
    const coverageOk = !requireFullCoverage || completeness.coverage === "full";

    const hasAnchor = isObject(opts) && Object.prototype.hasOwnProperty.call(opts, "anchorTs");
    if (!hasAnchor) {
      if (completeness.status === "degraded") return { trust: false, reason: "history_degraded" };
      return coverageOk ? { trust: true, reason: "ok" } : { trust: false, reason: "coverage_narrowed" };
    }

    const anchorTs = opts.anchorTs;
    if (anchorTs !== undefined && !isValidTimestamp(anchorTs)) return { trust: false, reason: "history_unknown" };
    if (completeness.status === "degraded") return { trust: false, reason: "history_degraded" };
    if (hasLossEventAfter(completeness, anchorTs, opts.nowMs)) {
      return { trust: false, reason: "history_degraded" };
    }

    return coverageOk ? { trust: true, reason: "ok" } : { trust: false, reason: "coverage_narrowed" };
  } catch {
    return { trust: false, reason: "history_unknown" };
  }
}
