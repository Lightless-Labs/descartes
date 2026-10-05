// Fact-family and rule-horizon registry (fact-store capacity plan 2026-10-05, §4.2/§4.3, step S3).
//
// LEAF MODULE: it imports nothing. Every detector, the daemon, the fact store and the seen-set
// module import it; any import from here back into a detector or daemon.js would create an ESM
// cycle (service-baseline.js:64-69 documents why detectors cannot import daemon.js). That is also
// why the rule IDs below are STRING LITERALS rather than the detectors' exported constants: the
// daemon checks at its own module init that these literals match its HISTORY_DEPENDENT_ALERT_RULE_IDS
// (built from the detector constants), so a literal that drifts from its constant fails loudly.
//
// What lives here:
//   - FACT_FAMILY_BY_NAME: the closed fact_name -> family map (S4 routes appends/reads by it).
//   - RULE_HORIZONS: per history-dependent rule, the families it reads and its eligibility horizon
//     (operator Q2, §12: service.appeared/scheduled_job.appeared 48 h, process.lineage.novel_edge
//     6 d; the rest per the §4.2 table). A horizon only ever REMOVES an evaluation (I5): it never
//     adds points, never extends what the store certifies, never re-arms or clears cold start.
//   - READER_COVERAGE: the non-detector readers' narrowing policy (miner, shadow, tuning; §4.2).
//   - NOVELTY_FAMILIES: the per-family census shape the S3b first/last-seen set folds (§17).
//   - The horizon-short signal's fixed rule id and its N (§4.2, I12).
//
// Module init throws (mirroring daemon.js's duplicate-owner throw) on: a fact_name mapped twice, a
// rule or reader referencing an unknown family, a non-positive/non-finite horizon, or a novelty
// family whose census shape disagrees with the fact-name map or the rule table.

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

export const FACT_FAMILY_IDS = Object.freeze([
  "service",
  "process_lineage",
  "scheduled_job",
  "session",
  "peer",
  "canary",
  "network",
  "provenance",
]);

const KNOWN_FAMILIES = new Set(FACT_FAMILY_IDS);

// [fact_name, family] pairs, as an array (not an object literal) so a duplicate fact_name is a
// detectable init error instead of a silent last-write-wins.
const FACT_NAME_FAMILY_PAIRS = [
  ["service.presence", "service"],
  ["service.census", "service"],
  ["process.lineage_edge", "process_lineage"],
  ["process.lineage_edge.census", "process_lineage"],
  ["scheduled_job.presence", "scheduled_job"],
  ["scheduled_job.census", "scheduled_job"],
  ["session.presence", "session"],
  ["peer.presence", "peer"],
  ["canary.presence", "canary"],
  ["canary.census", "canary"],
  ["network.listening_port.owner", "network"],
  ["provenance.warning", "provenance"],
];

function buildFactFamilyByName(pairs) {
  const map = new Map();
  for (const [factName, family] of pairs) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: fact_name ${factName} maps to unknown family ${family}`);
    if (map.has(factName)) throw new Error(`fact-families: fact_name ${factName} is mapped twice`);
    map.set(factName, family);
  }
  return map;
}

export const FACT_FAMILY_BY_NAME = buildFactFamilyByName(FACT_NAME_FAMILY_PAIRS);

export function factFamilyForName(factName) {
  return FACT_FAMILY_BY_NAME.get(factName);
}

// kind selects the eligibility predicate (fact-store-completeness.js ruleEligible, shared by the
// detectors and the daemon's veto/horizon-short signal): the fact-floor horizon for every kind,
// except that "novelty" rules measure their horizon against the S3b seen-set's certified span
// rather than the fact store's floor (see novelty-seen-set.js), and "correlation" additionally
// requires its whole read window to be certified (S3b review MEDIUM-2).
const RULE_HORIZON_ENTRIES = [
  // Set-diff over the retained window: established >= 3 sightings plus the 6-tick lockout
  // (DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT, service-baseline.js).
  ["service.disappeared", { families: ["service"], horizonMs: 6 * HOUR_MS, kind: "set_diff" }],
  // Novelty (operator Q2): the MINIMUM certified memory before a rule may claim "new".
  ["service.appeared", { families: ["service"], horizonMs: 48 * HOUR_MS, kind: "novelty" }],
  ["scheduled_job.appeared", { families: ["scheduled_job"], horizonMs: 48 * HOUR_MS, kind: "novelty" }],
  ["process.lineage.novel_edge", { families: ["process_lineage"], horizonMs: 6 * DAY_MS, kind: "novelty" }],
  // Fingerprint diff: >= 2 complete observations plus the 6-tick lockout.
  ["session.churn", { families: ["session"], horizonMs: 6 * HOUR_MS, kind: "set_diff" }],
  // Statistical: MIN_SAMPLE_COUNT 30 at hourly ticks.
  ["session.count_drop", { families: ["session"], horizonMs: 30 * HOUR_MS, kind: "statistical" }],
  ["peer.count_spike", { families: ["peer"], horizonMs: 30 * HOUR_MS, kind: "statistical" }],
  ["peer.count_drop", { families: ["peer"], horizonMs: 30 * HOUR_MS, kind: "statistical" }],
  // CORRELATION_MIN_PEER_HISTORY_DAYS = 3 (incident-correlation.js). The detector itself is gated
  // STRICTER than this (its whole read window must be unaffected by byte-cap narrowing; see
  // READER_COVERAGE's rationale) -- this entry is the budget invariant's H_max(peer) and the daemon's
  // independent veto.
  ["correlation.login_kill_proximity", { families: ["peer"], horizonMs: 3 * DAY_MS, kind: "correlation" }],
  // canary_vanished needs >= 2 complete observations plus the 6-tick lockout.
  ["canary.tampered", { families: ["canary"], horizonMs: 6 * HOUR_MS, kind: "set_diff" }],
];

function validateFamilies(owner, families) {
  if (!Array.isArray(families) || families.length === 0) throw new Error(`fact-families: ${owner} must list at least one family`);
  for (const family of families) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: ${owner} references unknown family ${family}`);
  }
}

function buildRuleHorizons(entries) {
  const map = new Map();
  for (const [ruleId, entry] of entries) {
    if (map.has(ruleId)) throw new Error(`fact-families: rule ${ruleId} is registered twice`);
    validateFamilies(`rule ${ruleId}`, entry.families);
    if (!Number.isFinite(entry.horizonMs) || entry.horizonMs <= 0) throw new Error(`fact-families: rule ${ruleId} has an invalid horizon`);
    map.set(ruleId, Object.freeze({ ...entry, families: Object.freeze([...entry.families]) }));
  }
  return map;
}

export const RULE_HORIZONS = buildRuleHorizons(RULE_HORIZON_ENTRIES);

export function ruleHorizonMs(ruleId) {
  return RULE_HORIZONS.get(ruleId)?.horizonMs;
}

// Non-detector readers (§4.2, review fold MEDIUM-5). coverage:
//   - "read_window": the reader may run only when byte-cap narrowing is INVISIBLE to its read --
//     every point an otherwise identical store that never byte-evicted would return for the same
//     read is still returned (certifiedReadWindowOk, fact-store-completeness.js). This is provably
//     no weaker than "no byte-cap narrowing at all" for that reader's inputs, and replaces the
//     interim requireFullCoverage gate (§16 MEDIUM-1), which additionally refused on an AGE floor
//     inside the read window and on a byte-cap floor far older than the window.
//   - "report_only": no correctness gate (makes no absence or novelty claim); reports the
//     certified boundary alongside its output.
const READER_COVERAGE_ENTRIES = [
  // constraint-miner.js: DEFAULT_MIN_OBSERVATION_DAYS = 7 is its mining span; the read-window
  // criterion is stricter than a 7-day horizon (S3 deviation, plan §18).
  ["constraint_miner", { families: ["service", "network"], coverage: "read_window" }],
  ["shadow_evaluator", { families: ["service", "network"], coverage: "read_window" }],
  ["correlation", { families: ["peer"], coverage: "read_window" }],
  ["tuning_miner", { families: ["service", "network"], coverage: "report_only" }],
];

function buildReaderCoverage(entries) {
  const map = new Map();
  for (const [reader, entry] of entries) {
    if (map.has(reader)) throw new Error(`fact-families: reader ${reader} is registered twice`);
    validateFamilies(`reader ${reader}`, entry.families);
    if (!["read_window", "report_only"].includes(entry.coverage)) throw new Error(`fact-families: reader ${reader} has an unknown coverage policy`);
    map.set(reader, Object.freeze({ ...entry, families: Object.freeze([...entry.families]) }));
  }
  return map;
}

export const READER_COVERAGE = buildReaderCoverage(READER_COVERAGE_ENTRIES);

// S3b (§17): the three novelty families whose first/last-seen set the fact-store pass folds. The
// census shape (presence fact_name + census fact_name carrying attributes.census_state) mirrors the
// detectors' own groupers exactly; novelty-seen-set.test.js pins the parity.
const NOVELTY_FAMILY_ENTRIES = [
  ["service", { ruleId: "service.appeared", presenceFactName: "service.presence", censusFactName: "service.census" }],
  ["scheduled_job", { ruleId: "scheduled_job.appeared", presenceFactName: "scheduled_job.presence", censusFactName: "scheduled_job.census" }],
  ["process_lineage", { ruleId: "process.lineage.novel_edge", presenceFactName: "process.lineage_edge", censusFactName: "process.lineage_edge.census" }],
];

function buildNoveltyFamilies(entries) {
  const map = new Map();
  for (const [family, entry] of entries) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: novelty family ${family} is unknown`);
    if (FACT_FAMILY_BY_NAME.get(entry.presenceFactName) !== family || FACT_FAMILY_BY_NAME.get(entry.censusFactName) !== family) {
      throw new Error(`fact-families: novelty family ${family}'s fact names do not map to it`);
    }
    const rule = RULE_HORIZONS.get(entry.ruleId);
    if (!rule || rule.kind !== "novelty" || rule.families.length !== 1 || rule.families[0] !== family) {
      throw new Error(`fact-families: novelty family ${family}'s rule ${entry.ruleId} is not a single-family novelty rule`);
    }
    map.set(family, Object.freeze({ ...entry }));
  }
  for (const [ruleId, rule] of RULE_HORIZONS) {
    if (rule.kind === "novelty" && !map.has(rule.families[0])) throw new Error(`fact-families: novelty rule ${ruleId} has no seen-set family`);
  }
  return map;
}

export const NOVELTY_FAMILIES = buildNoveltyFamilies(NOVELTY_FAMILY_ENTRIES);

export function noveltyFamilyForRule(ruleId) {
  for (const [family, entry] of NOVELTY_FAMILIES) if (entry.ruleId === ruleId) return family;
  return undefined;
}

// The horizon-short signal (§4.2, §4.4, I12): a rule horizon-ineligible for more than
// HISTORY_HORIZON_SHORT_ALERT_TICKS consecutive structural intervals raises this FIXED daemon alert
// (alert-store.js FIXED_ALERT_RULE_IDS), driven by the daemon status record's history_horizon_short.
export const HISTORY_HORIZON_SHORT_RULE_ID = "daemon.fact_history.horizon_short";
export const HISTORY_HORIZON_SHORT_ALERT_TICKS = 24;
