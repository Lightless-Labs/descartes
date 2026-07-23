// Slice 6 (observed-incident collectors plan, docs/plans/2026-07-13-observed-incident-
// collectors.md, Slice 6) -- L2 incident-correlation: a DETERMINISTIC cross-stream timeline join
// between Slice 4's session-drop/churn alert-history (the "kill side") and Slice 3's peer-login
// fact-history (the "login side"). This module performs NO host execFile/I/O of its own -- it
// only reads already-persisted alert-history (alert-store.js) and fact-history (fact-store.js),
// exactly mirroring session-baseline.js's/provenance-identity.js's own "pure recompute over
// persisted stores" shape.
//
// v0 ships exactly ONE pattern: `correlation.login_kill_proximity`. The join, candidate, and
// ranking below are 100% deterministic and run regardless of LLM consent (Decision 4) -- the
// ONLY place this milestone reaches the LLM is through the already-shipped, unmodified S13 gate
// (alert-intelligence.js's classifyAlertNamespace/PROMPT_TEMPLATES/adjudicateAlertNotifications),
// via a new, real, default-off "correlation" namespace this module knows nothing about.
//
// Safety invariants this module upholds by construction (see the plan's Decision 5):
//   - Gated by configDir/learned.json BEFORE any I/O (computeCorrelationCandidates' own
//     loadLearnedConfig(...).enabled short-circuit-to-[]), mirroring every sibling extraCandidates
//     source exactly.
//   - Anchors are read from alert-HISTORY (readAlertRecords, ANY status), never from the current
//     tick's in-memory candidate array -- a session.count_drop/session.churn alert that already
//     recovered is just as valid an anchor as one still active.
//   - Bounded lookback (DEFAULT_CORRELATION_LOOKBACK_MS, 24h) on the anchor's own first_seen --
//     the very first tick after this slice ships cannot replay weeks of pre-existing history as a
//     correlation storm.
//   - Every diagnostics value is a finite number, closed-enum string, or fixed-length hex hash --
//     enforced by sanitizeDiagnostics() here, and again, defense-in-depth, by alert-intelligence.js's
//     compactAlert re-run (Decision 3).
//   - title/summary are CLOSED-FORM templates interpolating only counts/hashes/closed-enums --
//     no raw session name/peer host/IP/free-text ever reaches either field (must-fix 2).
//   - Stored severity is capped at "warning" unconditionally in v0 (must-fix 7) -- the anchor's
//     real severity is preserved only as the anchor_severity diagnostic, never inherited directly.
import { alertId, readAlertRecords } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { PEER_CENSUS_MARKER_ENTITY_KEY, PEER_OVERFLOW_ENTITY_KEY } from "./fact-translators.js";
import { DEFAULT_PEER_PRESENCE_WINDOW_MS } from "./peer-signature-store.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS, SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID } from "./session-baseline.js";

export const CORRELATION_RULE_ID = "correlation.login_kill_proximity";

// PROVISIONAL (implementer-set, per the plan's Decision 6) -- not yet tuned against real data.

// Reuses peer-signature-store.js's own already-established presence-window value for consistency
// (plan Decision 1) rather than inventing a new arbitrary number.
export const DEFAULT_CORRELATION_WINDOW_MS = DEFAULT_PEER_PRESENCE_WINDOW_MS; // 3h

// Bounds the kill-side anchor scan so an unbounded alerts.json (which has no retention/pruning
// mechanism of its own, a pre-existing characteristic -- plan §5 open question 10) cannot replay
// months of old history as a correlation storm on any given tick.
export const DEFAULT_CORRELATION_LOOKBACK_MS = 24 * 60 * 60 * 1000; // 24h

// Closed-enum local hour-of-day strings, matching fact-translators.js's bucketLoginHour output
// shape exactly ("00".."23"). "unknown" is deliberately NOT a member -- a peer point whose ts
// failed to parse never qualifies as odd-hour (must-fix 6, stated explicitly rather than left as
// an implicit consequence of set non-membership).
export const CORRELATION_ODD_HOURS = new Set(["00", "01", "02", "03", "04", "05"]);

// A peer entity_key qualifies as "unattributed-looking" only when it has this many or fewer
// DISTINCT prior tick-groups (strictly before the qualifying observation's own ts) in the read
// window -- a novelty PROXY, explicitly weaker than real attribution (see this file's header).
export const CORRELATION_NOVELTY_MAX_PRIOR_TICKS = 1;

// Must-fix 4 cold-start gate: the peer.presence fact-STREAM as a whole (every entity_key
// combined, within the read window) must have at least this many distinct tick-groups...
export const CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS = 4;
// ...spanning at least this many days, before ANY peer may qualify as "unattributed-looking" at
// all. See findQualifyingPeerObservations' doc comment for why this is deliberately a
// stream-wide gate, not a per-entity one.
export const CORRELATION_MIN_PEER_HISTORY_DAYS = 3;

const PEER_FACT_NAME = "peer.presence";
const DAY_MS = 24 * 60 * 60 * 1000;

const KILL_SIDE_RULE_IDS = new Set([SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]);
const KNOWN_SEVERITIES = new Set(["info", "warning", "critical"]);

function tsMs(value) {
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : undefined;
}

/**
 * Kill-side anchors (Decision 1): every alert-history row (ANY status -- active, recovered,
 * acknowledged, suppressed) whose rule_id is session.count_drop/session.churn (Slice 4) and whose
 * first_seen falls within lookbackMs of now. Reads alert-HISTORY only -- callers pass the output
 * of readAlertRecords(descartesPaths), never a tick's own in-memory candidate array.
 */
export function findKillSideAnchors(alertRecords = [], { now, lookbackMs = DEFAULT_CORRELATION_LOOKBACK_MS } = {}) {
  const nowMs = tsMs(now);
  if (nowMs === undefined) return [];

  const anchors = [];
  for (const alert of alertRecords ?? []) {
    if (!KILL_SIDE_RULE_IDS.has(alert?.rule_id)) continue;
    const firstSeenMs = tsMs(alert.first_seen);
    if (firstSeenMs === undefined) continue;
    const ageMs = nowMs - firstSeenMs;
    if (ageMs < 0 || ageMs > lookbackMs) continue;
    anchors.push({
      alert_id: alert.id,
      rule_id: alert.rule_id,
      fingerprint: alert.fingerprint ?? "global",
      first_seen: alert.first_seen,
      first_seen_ms: firstSeenMs,
      severity: KNOWN_SEVERITIES.has(alert.severity) ? alert.severity : "warning",
    });
  }
  return anchors;
}

/**
 * Login-side qualification (Decision 1) for a single anchor. `peerPoints` is the FULL
 * peer.presence fact-history window already read once by the caller (covers both this proximity
 * join and the novelty count below -- one I/O class, per Decision 1's "no second read" note).
 *
 * MUST-FIX 4 cold-start gate -- deliberately a STREAM-WIDE bar, not a per-entity one: gating
 * "does THIS peer individually have >= N historical tick-groups" would be self-contradictory with
 * the novelty check right below it (a peer that has been seen >= N times already typically also
 * has more than CORRELATION_NOVELTY_MAX_PRIOR_TICKS prior ticks, so it could almost never satisfy
 * both at once -- exactly backwards for a proxy whose entire purpose is to flag RARELY-seen
 * peers). Instead this gate asks a narrower, coherent question: has the peer.presence
 * fact-collection STREAM ITSELF (any entity, combined) been running long enough for a low
 * per-peer prior-tick count to be a meaningful signal, rather than a week-1 deployment artifact
 * where every peer trivially has 0-1 prior ticks simply because few structural ticks have
 * happened yet at all. A fresh install fails this bar uniformly, for every peer, exactly matching
 * the week-1 cold-start fixture; a peer that is itself genuinely rare (seen once in months) can
 * still qualify once the collector overall has enough combined depth.
 *
 * MUST-FIX 5 overflow gate: if the read window contains so much as one peer.presence tick whose
 * entity_key is the overflow marker (the peer census collector hit its own per-tick cap at least
 * once), every peer's prior-tick count in that window is a potential undercount -- no peer may
 * qualify from this window at all. Mirrors session-baseline.js's own overflow fold-skip exactly.
 *
 * Regression fix (post-Slice-4c): the unconditional PEER_CENSUS_MARKER_ENTITY_KEY point (emitted
 * on every successful vpn-peer-status tick, including zero-peer ticks, so peer-baseline.js always
 * has a tick-group to fold) carries no real peer identity/observation either -- exactly like
 * PEER_OVERFLOW_ENTITY_KEY, it must be excluded from `realPoints` below, or marker-only ticks
 * would inflate the stream-wide cold-start tick-group/day-span counts (must-fix 4) and let a
 * peer's genuine first-ever appearance qualify during what should still be a cold-start window.
 * Unlike the overflow marker, the census marker carries no truncation signal, so it is
 * deliberately NOT added to `hasOverflowTick` below -- only to the real-peer exclusion.
 *
 * MUST-FIX 6: odd-hour membership is checked against the CLOSED CORRELATION_ODD_HOURS set, which
 * does not contain "unknown" -- a peer point whose observation-tick hour failed to parse never
 * qualifies, stated here explicitly rather than left as an implicit set-membership consequence.
 */
export function findQualifyingPeerObservations(peerPoints = [], anchor, options = {}) {
  const windowMs = options.windowMs ?? DEFAULT_CORRELATION_WINDOW_MS;
  const oddHours = options.oddHours ?? CORRELATION_ODD_HOURS;
  const noveltyMaxPriorTicks = options.noveltyMaxPriorTicks ?? CORRELATION_NOVELTY_MAX_PRIOR_TICKS;
  const minPeerHistoryTickGroups = options.minPeerHistoryTickGroups ?? CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS;
  const minPeerHistoryDays = options.minPeerHistoryDays ?? CORRELATION_MIN_PEER_HISTORY_DAYS;
  if (!anchor || !Number.isFinite(anchor.first_seen_ms)) return [];

  // MUST-FIX 5: any overflow-marker tick anywhere in the read window undercounts every peer's
  // prior-tick history -- fail closed to "no qualifying observations" for this whole window.
  const hasOverflowTick = (peerPoints ?? []).some((point) => point?.entity_key === PEER_OVERFLOW_ENTITY_KEY);
  if (hasOverflowTick) return [];

  const realPoints = (peerPoints ?? []).filter(
    (point) =>
      point?.entity_key !== PEER_OVERFLOW_ENTITY_KEY &&
      point?.entity_key !== PEER_CENSUS_MARKER_ENTITY_KEY &&
      point?.fact_name === PEER_FACT_NAME,
  );

  // MUST-FIX 4: stream-wide cold-start gate (see doc comment above) -- computed once over the
  // WHOLE read window, independent of which specific peer/anchor is being evaluated.
  const distinctTicksOverall = [...new Set(realPoints.map((point) => point.ts))]
    .map((ts) => ({ ts, ms: tsMs(ts) }))
    .filter((entry) => entry.ms !== undefined)
    .sort((a, b) => a.ms - b.ms);
  const tickGroupCount = distinctTicksOverall.length;
  const spanDays = tickGroupCount > 1 ? (distinctTicksOverall[tickGroupCount - 1].ms - distinctTicksOverall[0].ms) / DAY_MS : 0;
  if (tickGroupCount < minPeerHistoryTickGroups || spanDays < minPeerHistoryDays) return [];

  // Per-entity tick-group inventory (for the novelty/prior-tick-count check below).
  const ticksByEntity = new Map();
  for (const point of realPoints) {
    const ms = tsMs(point.ts);
    if (ms === undefined) continue;
    const list = ticksByEntity.get(point.entity_key) ?? [];
    list.push(ms);
    ticksByEntity.set(point.entity_key, list);
  }

  const qualifying = [];
  for (const point of realPoints) {
    const pointMs = tsMs(point.ts);
    if (pointMs === undefined) continue;
    if (Math.abs(pointMs - anchor.first_seen_ms) > windowMs) continue; // proximity

    const hourBucket = point.attributes?.login_hour_bucket;
    if (!oddHours.has(hourBucket)) continue; // odd-hour ("unknown" never qualifies, must-fix 6)

    const entityTicks = ticksByEntity.get(point.entity_key) ?? [];
    const priorTickCount = entityTicks.filter((ms) => ms < pointMs).length;
    if (priorTickCount > noveltyMaxPriorTicks) continue; // not "unattributed-looking" enough

    qualifying.push({
      point,
      delta_ms: Math.abs(pointMs - anchor.first_seen_ms),
      prior_tick_count: priorTickCount,
    });
  }
  return qualifying;
}

/**
 * Ranking + candidate cap (Decision 1, no-storm discipline): at most one candidate is ever
 * emitted per anchor, even when several peer observations qualify -- the qualifying observation
 * with the smallest delta wins, ties broken by lexicographically-smaller entity_key for
 * determinism. The full qualifying count is preserved as candidate_pool_size.
 */
export function rankAndSelectBestPeer(qualifying = []) {
  if (!Array.isArray(qualifying) || qualifying.length === 0) return undefined;
  const sorted = [...qualifying].sort((a, b) => {
    if (a.delta_ms !== b.delta_ms) return a.delta_ms - b.delta_ms;
    return String(a.point.entity_key).localeCompare(String(b.point.entity_key));
  });
  return { best: sorted[0], poolSize: qualifying.length };
}

// Closed-form templates (must-fix 2, hard requirement): every interpolated value below is a
// finite number, a closed-enum string, or an already-hashed identifier -- never a raw session
// name, peer host/IP, or other free text. Neither title nor summary is covered by
// sanitizeDiagnostics (that gate only ever sees `diagnostics`), so these two fields are built from
// a fixed, closed-form template rather than from any free-text interpolation.
function buildCorrelationTitle(anchor) {
  return `Correlated peer login near ${anchor.rule_id}`;
}

function buildCorrelationSummary(anchor, peerSourceType, peerObservedHourBucket, proximitySeconds, poolSize) {
  return `A ${peerSourceType} peer observed at hour ${peerObservedHourBucket} fell within ${proximitySeconds}s of a ${anchor.rule_id} anchor (anchor severity ${anchor.severity}); ${poolSize} peer observation(s) matched this window.`;
}

/**
 * Builds the correlation.login_kill_proximity candidate (Decision 1). Candidate shape matches the
 * existing extraCandidates sources exactly: id, rule_id, fingerprint, severity, title, summary,
 * diagnostics, evidence_refs.
 *
 * MUST-FIX 7 (hard requirement): stored severity is capped at "warning" UNCONDITIONALLY in v0 --
 * never inherited from the anchor, even when the anchor is itself critical. The anchor's real
 * severity is preserved only as the anchor_severity diagnostic field.
 */
export function buildCorrelationCandidate(anchor, bestPeer, poolSize) {
  const point = bestPeer.point;
  const peerEntityKey = String(point.entity_key);
  const peerSourceType = point.attributes?.source_type ?? "unknown";
  const peerObservedHourBucket = point.attributes?.login_hour_bucket ?? "unknown";
  const proximitySeconds = Math.round(bestPeer.delta_ms / 1000);
  const fingerprint = `${anchor.fingerprint}__${peerEntityKey}`;

  const diagnostics = sanitizeDiagnostics({
    kill_rule_id: anchor.rule_id,
    anchor_fingerprint: anchor.fingerprint,
    peer_entity_key: peerEntityKey,
    peer_source_type: peerSourceType,
    // MUST-FIX 6: named peer_observed_hour_bucket, not peer_login_hour_bucket -- this is the
    // OBSERVATION TICK's hour, not the peer's actual login instant.
    peer_observed_hour_bucket: peerObservedHourBucket,
    proximity_seconds: proximitySeconds,
    peer_novelty_prior_tick_count: bestPeer.prior_tick_count,
    candidate_pool_size: poolSize,
    anchor_severity: anchor.severity,
  });

  return {
    id: alertId(CORRELATION_RULE_ID, fingerprint),
    rule_id: CORRELATION_RULE_ID,
    fingerprint,
    severity: "warning", // must-fix 7: capped unconditionally, never anchor.severity.
    title: buildCorrelationTitle(anchor),
    summary: buildCorrelationSummary(anchor, peerSourceType, peerObservedHourBucket, proximitySeconds, poolSize),
    diagnostics,
    evidence_refs: ["session-baseline", "peer-presence"],
  };
}

/**
 * The daemon.js extraCandidates entry (Decision 6). Matches computeSessionBaselineCandidates'
 * exact signature/short-circuit shape: gated by loadLearnedConfig(...).enabled BEFORE any I/O.
 * No state file of its own (Decision 1's "re-derives fresh every tick, no new store" note) -- a
 * pure function over already-persisted alert-history/fact-history, recomputed fresh on every call
 * exactly like session-baseline.js's detectSessionChurn.
 */
export async function computeCorrelationCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const now = options.now ?? new Date().toISOString();
  const lookbackMs = options.lookbackMs ?? DEFAULT_CORRELATION_LOOKBACK_MS;
  const windowMs = options.correlationWindowMs ?? DEFAULT_CORRELATION_WINDOW_MS;
  const oddHours = options.oddHours ?? CORRELATION_ODD_HOURS;
  const noveltyMaxPriorTicks = options.noveltyMaxPriorTicks ?? CORRELATION_NOVELTY_MAX_PRIOR_TICKS;
  const minPeerHistoryTickGroups = options.minPeerHistoryTickGroups ?? CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS;
  const minPeerHistoryDays = options.minPeerHistoryDays ?? CORRELATION_MIN_PEER_HISTORY_DAYS;
  const factWindowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;

  const readAlerts = options.readAlertRecords ?? readAlertRecords;
  const readFacts = options.readFactPoints ?? readFactPoints;

  const [alertRecords, factResult] = await Promise.all([
    readAlerts(descartesPaths),
    readFacts(descartesPaths, { now, windowMs: factWindowMs }),
  ]);

  const anchors = findKillSideAnchors(alertRecords, { now, lookbackMs });
  if (anchors.length === 0) return [];

  // Regression fix (post-Slice-4c): strip the census marker here too, mirroring the realPoints
  // exclusion inside findQualifyingPeerObservations -- the overflow marker is deliberately KEPT
  // in this array (unlike the census marker) because findQualifyingPeerObservations' own
  // hasOverflowTick check (must-fix 5) needs to see it in the peerPoints it receives.
  const peerPoints = (factResult?.points ?? []).filter(
    (point) => point?.fact_name === PEER_FACT_NAME && point?.entity_key !== PEER_CENSUS_MARKER_ENTITY_KEY,
  );

  const candidates = [];
  for (const anchor of anchors) {
    const qualifying = findQualifyingPeerObservations(peerPoints, anchor, {
      windowMs,
      oddHours,
      noveltyMaxPriorTicks,
      minPeerHistoryTickGroups,
      minPeerHistoryDays,
    });
    if (qualifying.length === 0) continue;
    const ranked = rankAndSelectBestPeer(qualifying);
    if (!ranked) continue;
    candidates.push(buildCorrelationCandidate(anchor, ranked.best, ranked.poolSize));
  }
  return candidates;
}
