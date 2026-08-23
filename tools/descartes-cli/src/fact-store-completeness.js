const LOSS_TIMESTAMP_FIELDS = [
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
];

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
 * Makes the one central, fail-closed trust decision for fact-history consumers.
 * Pure: it performs no I/O and never mutates either input.
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

    const hasAnchor = isObject(opts) && Object.prototype.hasOwnProperty.call(opts, "anchorTs");
    if (!hasAnchor) {
      return completeness.status === "degraded"
        ? { trust: false, reason: "history_degraded" }
        : { trust: true, reason: "ok" };
    }

    const anchorTs = opts.anchorTs;
    if (anchorTs !== undefined && !isValidTimestamp(anchorTs)) return { trust: false, reason: "history_unknown" };
    if (completeness.status === "degraded") return { trust: false, reason: "history_degraded" };
    if (hasLossEventAfter(completeness, anchorTs, opts.nowMs)) {
      return { trust: false, reason: "history_degraded" };
    }

    return { trust: true, reason: "ok" };
  } catch {
    return { trust: false, reason: "history_unknown" };
  }
}
