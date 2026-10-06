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
import { RULE_HORIZONS, noveltyFamilyForRule, ruleHorizonMs } from "./fact-families.js";

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
 * S4 (fact-store capacity plan §4.3): a multi-family readFactPoints result carries each family's own
 * read under `family_reads`, and every predicate below ANDs over them -- trust, horizon and
 * read-window coverage hold only if they hold for EVERY family read. A combined floor is never used to
 * gate (one family's newer age floor could mask another family's byte-cap floor). Returns the list
 * of reads to evaluate: [readResult] for a single-family read, the per-family reads otherwise, or null
 * when `family_reads` is present but malformed (callers fail closed).
 */
//
// A family store that was NEVER CREATED (`store_exists === false`: no facts.jsonl and no ledger)
// contributes no points and is left out of the AND: it holds no history that could hide a
// counterexample or a prior sighting, and requiring it would silence a multi-family reader (the
// miner, shadow) on every host where one of its families simply has nothing to observe (e.g. no
// listening ports). A single-family read of such a store still reads `unknown` (untrusted), so the
// daemon's per-family veto still freezes that family's rules. If EVERY family read is absent, there
// is nothing to vouch for: fail closed.
function perFamilyReads(readResult) {
  if (!isObject(readResult) || !Object.prototype.hasOwnProperty.call(readResult, "family_reads")) return [readResult];
  const familyReads = readResult.family_reads;
  if (!isObject(familyReads)) return null;
  const entries = Object.values(familyReads);
  if (entries.length === 0) return null;
  if (entries.some((entry) => !isObject(entry) || Object.prototype.hasOwnProperty.call(entry, "family_reads"))) return null;
  const present = entries.filter((entry) => entry.store_exists !== false);
  return present.length > 0 ? present : null;
}

function everyFamilyRead(readResult, predicate) {
  const reads = perFamilyReads(readResult);
  if (!reads) return false;
  return reads.every((read) => predicate(read));
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

// A completeness object carries a VALID ledger's coverage report only when coverage is exactly
// "full" or "narrowed" (LOW-2, review fold: buildCompleteness reports "unknown" when there is no
// ledger at all, whose null floor would otherwise read as "never narrowed"). A floor field that is
// absent reads as null (a real store always reports both; hand-built "full" fixtures omit them),
// but a "narrowed" report with no floor at all is self-contradictory and fails closed, as does any
// floor that is present but not a valid timestamp.
function validLedgerFloors(readResult) {
  const completeness = readResult?.completeness;
  if (!isObject(completeness)) return undefined;
  if (completeness.coverage !== "full" && completeness.coverage !== "narrowed") return undefined;
  const floors = {};
  for (const field of ["bytecap_floor_ts", "age_floor_ts"]) {
    const value = completeness[field];
    if (value === null || value === undefined) {
      floors[field] = null;
      continue;
    }
    if (!isValidTimestamp(value)) return undefined;
    floors[field] = Date.parse(value);
  }
  if (completeness.coverage === "narrowed" && floors.bytecap_floor_ts === null && floors.age_floor_ts === null) return undefined;
  return floors;
}

/**
 * The per-rule eligibility horizon (fact-store capacity plan §4.2, step S3). Pure and fail-closed.
 * True when the read's certified span is at least `horizonMs` long: no floor at all (nothing was
 * ever narrowed in this lineage -- the existing per-detector minimum-history gates govern, so day-1
 * behavior is unchanged), or `nowMs - floor >= horizonMs`.
 *
 * The floor is max(bytecap_floor_ts, age_floor_ts): the same boundary readFactPoints excludes
 * points at or below, so the predicate is never looser than what the store itself certifies. In
 * normal operation the age floor sits ~30 days back and never binds; after a wall-clock rollback it
 * can, and then it must.
 *
 * False on: no valid ledger (coverage not "full"/"narrowed" -- LOW-2), a missing/malformed
 * completeness or floor field, a floor in the future, or non-finite inputs.
 *
 * I5: this only ever REMOVES an evaluation. It is never an input to the cold-start re-arm, never
 * extends certified_after_ts, never adds points.
 */
export function certifiedHorizonOk(readResult, options = {}) {
  return everyFamilyRead(readResult, (read) => singleFamilyCertifiedHorizonOk(read, options));
}

function singleFamilyCertifiedHorizonOk(readResult, { nowMs, horizonMs } = {}) {
  try {
    if (!Number.isFinite(nowMs) || !Number.isFinite(horizonMs) || horizonMs < 0) return false;
    const floors = validLedgerFloors(readResult);
    if (!floors) return false;
    const floorMs = Math.max(floors.bytecap_floor_ts ?? Number.NEGATIVE_INFINITY, floors.age_floor_ts ?? Number.NEGATIVE_INFINITY);
    if (floorMs === Number.NEGATIVE_INFINITY) return true;
    if (floorMs > nowMs) return false;
    return nowMs - floorMs >= horizonMs;
  } catch {
    return false;
  }
}

/**
 * certifiedHorizonOk with the rule's registered horizon (fact-families.js RULE_HORIZONS). An
 * unregistered rule fails closed. The per-detector gate (§4.2): a rule is evaluable only when it is
 * not cold-start pending AND this holds; when it does not, the detector emits no candidate and
 * reports no evaluatedAlertKeys for that rule -- and nothing else changes (no re-arm, the fold and
 * store write proceed), so the rule resumes on the very tick its horizon recovers.
 */
export function ruleHorizonOk(readResult, ruleId, nowMs) {
  const horizonMs = ruleHorizonMs(ruleId);
  if (horizonMs === undefined) return false;
  return certifiedHorizonOk(readResult, { nowMs, horizonMs });
}

/**
 * S3b (§17): the read's seen-set for a novelty rule's family, when (and only when) it is valid --
 * validated by readFactPoints against the same ledger it read. undefined otherwise.
 */
export function validNoveltySeenSet(readResult, ruleId) {
  const family = noveltyFamilyForRule(ruleId);
  if (family === undefined) return undefined;
  const set = readResult?.seen_sets?.[family];
  return isObject(set) && set.status === "valid" && set.entries instanceof Map ? set : undefined;
}

// A migration marker transition is different from an ordinary missing/invalid seen-set. The
// latter may still fall back to an intact, full fact-store window; the former means the marker has
// invalidated the set's history and that window cannot authorize a novelty claim until the next
// fold re-certifies the set. This predicate is shared by detector gates, status rule evaluations,
// and the daemon's ruleEligible veto through noveltyRuleEligible.
export function noveltySeenSetMigrationInvalid(readResult, ruleId) {
  const family = noveltyFamilyForRule(ruleId);
  if (family === undefined) return false;
  const status = readResult?.seen_sets?.[family]?.status;
  return status === "quarantine_epoch_mismatch"
    || status === "quarantine_marker_unreadable"
    || status === "quarantine_migration_pending"
    || status === "quarantine_marker_future";
}

/**
 * The horizon referent for a NOVELTY rule (S3b, plan §18): with a valid seen-set the rule decides
 * novelty against the set, so its minimum-memory horizon (Q2: 48 h / 48 h / 6 d) is measured against
 * the set's certified_since_ts -- null (memory complete since the lineage began) is eligible, exactly
 * like a store that never narrowed. Without a valid set it falls back to the fact store's floor
 * (ruleHorizonOk); the caller ALSO keeps the interim full-coverage gate in that case.
 */
export function noveltyHorizonOk(readResult, ruleId, nowMs) {
  if (noveltySeenSetMigrationInvalid(readResult, ruleId)) return false;
  const set = validNoveltySeenSet(readResult, ruleId);
  if (!set) return ruleHorizonOk(readResult, ruleId, nowMs);
  const horizonMs = ruleHorizonMs(ruleId);
  if (horizonMs === undefined || !Number.isFinite(nowMs)) return false;
  if (set.certified_since_ts === null) return true;
  if (!isValidTimestamp(set.certified_since_ts)) return false;
  const sinceMs = Date.parse(set.certified_since_ts);
  if (sinceMs > nowMs) return false;
  return nowMs - sinceMs >= horizonMs;
}

/**
 * The full eligibility decision for a novelty rule, shared by the detectors' gate and the daemon's
 * independent veto so the two can never disagree on the referent: a valid seen-set and its horizon;
 * or, without one, the interim S2 rule -- full (un-narrowed) coverage AND the fact-floor horizon.
 */
export function noveltyRuleEligible(readResult, ruleId, nowMs) {
  if (noveltySeenSetMigrationInvalid(readResult, ruleId)) return false;
  if (validNoveltySeenSet(readResult, ruleId)) return noveltyHorizonOk(readResult, ruleId, nowMs);
  return readResult?.completeness?.coverage === "full" && ruleHorizonOk(readResult, ruleId, nowMs);
}

/**
 * THE per-rule eligibility decision for a read (S3b review MEDIUM-2), shared by the detectors' own
 * gates and the daemon's independent veto + horizon-short signal (I12), dispatching on the rule's
 * registered kind so the two can never disagree on the referent:
 *   - "novelty": noveltyRuleEligible (seen-set horizon, or full coverage + the fact-floor horizon);
 *   - "correlation": its registered 3 d horizon AND certifiedReadWindowOk over the detector's whole
 *     read window (`readWindowMs`, required -- fails closed without it). The detector's "unattributed-
 *     looking" test is a novelty proxy over that whole window, so a byte-cap floor anywhere inside
 *     it silences correlation even when the 3 d horizon is met; the signal must see that silence;
 *   - every other kind: ruleHorizonOk.
 * An unregistered rule fails closed. Status/loss trust is NOT decided here (factHistoryTrustworthy).
 */
export function ruleEligible(readResult, ruleId, nowMs, { readWindowMs } = {}) {
  const rule = RULE_HORIZONS.get(ruleId);
  if (!rule) return false;
  if (rule.kind === "novelty") return noveltyRuleEligible(readResult, ruleId, nowMs);
  if (rule.kind === "correlation") {
    if (!Number.isFinite(readWindowMs)) return false;
    return ruleHorizonOk(readResult, ruleId, nowMs) && certifiedReadWindowOk(readResult, { nowMs, windowMs: readWindowMs });
  }
  return ruleHorizonOk(readResult, ruleId, nowMs);
}

/**
 * S6 (fact-store capacity plan §7 S6, I11): one rule's "would evaluate" report, built by each
 * watch-tier detector from the values its own evaluation already computed, so `baseline status`
 * (which runs the detectors read-only) reports exactly what the detector does on the same state --
 * never a re-derivation. The gates are checked in the detector's own order, and the FIRST one that
 * stops the rule is reported:
 *   1. "history_untrusted"     -- factHistoryTrustworthy(...).trust is false (reason attached);
 *   2. "cold_start_pending"    -- the persistent lockout is pending, or (re)arms this tick;
 *   3. "history_horizon_short" -- the rule's eligibility horizon (ruleHorizonOk / noveltyHorizonOk);
 *   4. the detector's readiness gate (`readinessGate`), e.g. too few complete census ticks, a stale
 *      latest complete census, or a statistical baseline still warming up; "ok" when ready.
 * `evaluable` is true exactly when no gate stopped the rule. A rule can be evaluable with ZERO
 * evaluated keys (no sessions, no jobs): that still evaluates, and still reads "watching" (I11).
 * `evaluatedAlertKeys` are the keys the detector reported for THIS rule, copied verbatim. Display
 * and status only: no trust decision reads this.
 */
export function buildRuleEvaluation({ historyTrust, coldStartPendingThisTick, horizonOk, readinessGate = "ok", evaluatedAlertKeys = [] } = {}) {
  let gate;
  if (historyTrust?.trust !== true) gate = "history_untrusted";
  else if (coldStartPendingThisTick) gate = "cold_start_pending";
  else if (horizonOk !== true) gate = "history_horizon_short";
  else gate = typeof readinessGate === "string" && readinessGate.length > 0 ? readinessGate : "ok";
  return {
    evaluable: gate === "ok",
    gate,
    ...(gate === "history_untrusted" ? { history_reason: typeof historyTrust?.reason === "string" ? historyTrust.reason : "history_unknown" } : {}),
    evaluatedAlertKeys: [...evaluatedAlertKeys],
  };
}

/**
 * The scope of a novelty claim decided against this read's retained window (§4.2, §5 point 4): the
 * certified boundary when the store is narrowed, else the oldest point the read returned (the store
 * has held everything since then). undefined when neither is known. Display only.
 */
export function noveltyHistoryScopeTs(readResult, ruleId) {
  // S3b: decided against a valid seen-set -> its scope (max(certified_since, now - retention)).
  const set = ruleId === undefined ? undefined : validNoveltySeenSet(readResult, ruleId);
  if (set && isValidTimestamp(set.scope_ts)) return set.scope_ts;
  const completeness = readResult?.completeness;
  if (!isObject(completeness)) return undefined;
  if (isValidTimestamp(completeness.certified_after_ts)) return completeness.certified_after_ts;
  if (isValidTimestamp(completeness.oldest_certified_ts)) return completeness.oldest_certified_ts;
  return undefined;
}

/**
 * The non-detector readers' narrowing gate (fact-families.js READER_COVERAGE "read_window"; replaces
 * the interim requireFullCoverage gate of review-fold MEDIUM-1). True exactly when byte-cap eviction
 * is INVISIBLE to a read of `windowMs` ending at `nowMs` (windowMs undefined = an unbounded read):
 *   - no byte-cap floor; or
 *   - the floor is strictly before the window start (the floor is exclusive, the window inclusive,
 *     so a point at exactly the start would otherwise be hidden); or
 *   - the floor is at or below the age floor: every record it removed has ts <= the age floor, and
 *     the same retention passes would have age-evicted all of those from a store that never
 *     byte-evicted, so that store holds none of them either. This is the only way an UNBOUNDED read
 *     can qualify.
 * Referent (stated, not assumed): "a store that never byte-evicted under the same age retention".
 * Under that referent the read returns byte-identical points (fact-families.test.js proves it on
 * two real stores), so the gate is provably no weaker than "no byte-cap narrowing" for the reader's
 * inputs. An age floor alone never refuses: age retention narrowed every reader on `main` too.
 * Fails closed on no valid ledger, malformed completeness/floors, or bad inputs. Status/loss trust
 * is NOT decided here -- callers still require factHistoryTrustworthy(...).trust.
 */
export function certifiedReadWindowOk(readResult, options = {}) {
  return everyFamilyRead(readResult, (read) => singleFamilyCertifiedReadWindowOk(read, options));
}

function singleFamilyCertifiedReadWindowOk(readResult, { nowMs, windowMs } = {}) {
  try {
    if (!Number.isFinite(nowMs)) return false;
    if (windowMs !== undefined && (!Number.isFinite(windowMs) || windowMs < 0)) return false;
    const floors = validLedgerFloors(readResult);
    if (!floors) return false;
    const bytecapFloorMs = floors.bytecap_floor_ts;
    if (bytecapFloorMs === null) return true;
    if (floors.age_floor_ts !== null && bytecapFloorMs <= floors.age_floor_ts) return true;
    if (windowMs === undefined) return false;
    return bytecapFloorMs < nowMs - windowMs;
  } catch {
    return false;
  }
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
  // S4: a multi-family read is trusted only if EVERY family's own read is (§4.3: "Trust holds only
  // if every family is trusted"); the first failing family's reason is returned. A malformed
  // family_reads fails closed.
  const reads = perFamilyReads(readResult);
  if (!reads) return { trust: false, reason: "history_unknown" };
  for (const read of reads) {
    const result = singleFamilyFactHistoryTrustworthy(read, opts);
    if (!result.trust) return result;
  }
  return { trust: true, reason: "ok" };
}

function singleFamilyFactHistoryTrustworthy(readResult, opts = {}) {
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
