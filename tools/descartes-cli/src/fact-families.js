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
  // Context families (docs/plans/2026-10-06-context-aware-learned-baselines.md §4, C0). DATA ONLY:
  // no detector rule reads them yet, so they carry a declared memory horizon (DATA_FAMILY_HORIZONS
  // below), not a RULE_HORIZONS entry.
  "host_lifecycle",
  "network_context",
  "session_context",
  // Context plan C2 (§3 C0.1, §4.2): per-binary availability/trust verdicts. DATA ONLY.
  "collector_state",
  // Context plan C2 (§8.2): the long-lived statistics skeleton (derived; DATA ONLY).
  "context_stats",
  // Context plan C2 (§8.1): one summary record per structural tick (derived; DATA ONLY).
  "tick_summary",
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
  // Context facts (C0.3-C0.12). Closed per-field schemas live in context-schemas.js; a test pins
  // that every schema's family equals its registry family here.
  ["host.boot", "host_lifecycle"],
  ["host.boot_boundary", "host_lifecycle"],
  ["host.clock_reading", "host_lifecycle"],
  ["host.suspend", "host_lifecycle"],
  ["host.boundary_census", "host_lifecycle"],
  ["host.lifecycle_record", "host_lifecycle"],
  ["net.tailnet_state", "network_context"],
  ["net.config_fingerprint", "network_context"],
  ["net.vpn_service_census", "network_context"],
  ["net.vpn_service_state", "network_context"],
  ["session.login_record", "session_context"],
  ["session.login_history_row", "session_context"],
  ["session.login_census", "session_context"],
  ["user.presence", "session_context"],
  ["session.attachment_census", "session_context"],
  ["session.attachment", "session_context"],
  ["collector.binary_state", "collector_state"],
  ["host.daemon_gap", "host_lifecycle"],
  ["context.transition", "network_context"],
  ["session.created_vs_boot", "session_context"],
  ["tick.summary", "tick_summary"],
  ["stats.episode", "context_stats"],
  ["stats.daily", "context_stats"],
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

/**
 * S4 (fact-store capacity plan §4.3, I7): the ONLY way a family id reaches a store path. Throws on a
 * missing or unknown family, so a store call that forgot its family fails loudly instead of
 * silently reading an empty (or a legacy) store, and a family id can never carry a path segment
 * (the registry is closed; there is no path-traversal surface).
 */
export function requireFactFamily(family) {
  if (family === undefined || family === null || family === "") throw new Error("fact-store: a fact family is required (no legacy single-store default)");
  if (typeof family !== "string" || !KNOWN_FAMILIES.has(family)) throw new Error(`fact-store: unknown fact family ${typeof family === "string" ? family : typeof family}`);
  return family;
}

/**
 * S4 routing (§4.3 write path, I7): groups fact points by their family. An unregistered fact_name
 * THROWS before anything is returned -- so before any family file is written -- rather than being
 * misrouted or silently dropped. Returns a Map<family, points[]> holding only non-empty groups, in
 * registry order.
 */
export function groupFactPointsByFamily(points) {
  const byFamily = new Map();
  for (const point of points ?? []) {
    const factName = typeof point?.fact_name === "string" ? point.fact_name.trim() : point?.fact_name;
    const family = FACT_FAMILY_BY_NAME.get(factName);
    if (family === undefined) throw new Error("fact-store: unregistered fact_name (no fact family); refusing the whole batch before any write");
    if (!byFamily.has(family)) byFamily.set(family, []);
    byFamily.get(family).push(point);
  }
  return new Map(FACT_FAMILY_IDS.filter((family) => byFamily.has(family)).map((family) => [family, byFamily.get(family)]));
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
//   - "present_only" (S4): no narrowing gate at all -- the reader only ever acts on facts that are
//     PRESENT ("no fact, no claim"), so a narrowed window can only remove a claim. Registered so its
//     families come from the registry like every other reader's.
const READER_COVERAGE_ENTRIES = [
  // constraint-miner.js: DEFAULT_MIN_OBSERVATION_DAYS = 7 is its mining span; the read-window
  // criterion is stricter than a 7-day horizon (S3 deviation, plan §18).
  ["constraint_miner", { families: ["service", "network"], coverage: "read_window" }],
  ["shadow_evaluator", { families: ["service", "network"], coverage: "read_window" }],
  ["correlation", { families: ["peer"], coverage: "read_window" }],
  ["tuning_miner", { families: ["service", "network"], coverage: "report_only" }],
  // S4 (§4.3 reader list): the daemon's live active-constraint evaluation reads the constraint-target
  // families; provenance-warning reads only its own family (deleted_exe_running /
  // public_bind_no_supervisor, every fast tick when learned is on).
  ["active_constraint", { families: ["service", "network"], coverage: "present_only" }],
  ["provenance_warning", { families: ["provenance"], coverage: "present_only" }],
];

function buildReaderCoverage(entries) {
  const map = new Map();
  for (const [reader, entry] of entries) {
    if (map.has(reader)) throw new Error(`fact-families: reader ${reader} is registered twice`);
    validateFamilies(`reader ${reader}`, entry.families);
    if (!["read_window", "report_only", "present_only"].includes(entry.coverage)) throw new Error(`fact-families: reader ${reader} has an unknown coverage policy`);
    map.set(reader, Object.freeze({ ...entry, families: Object.freeze([...entry.families]) }));
  }
  return map;
}

export const READER_COVERAGE = buildReaderCoverage(READER_COVERAGE_ENTRIES);

// The families a registered non-detector reader reads (S4). Throws on an unregistered reader.
export function readerFamilies(reader) {
  const entry = READER_COVERAGE.get(reader);
  if (!entry) throw new Error(`fact-families: unregistered reader ${reader}`);
  return [...entry.families];
}

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

// S4 per-family budgets (fact-store capacity plan §4.5, S0-revised table; operator Q1 as superseded by
// §15.4): service 18, process_lineage 10, scheduled_job 5, peer 16 MiB; session, canary, network and
// provenance 4 MiB -- 65 MiB in total.
const MIB = 1024 * 1024;
const FAMILY_BUDGET_ENTRIES = [
  ["service", 18 * MIB],
  ["process_lineage", 10 * MIB],
  ["scheduled_job", 5 * MIB],
  ["session", 4 * MIB],
  ["peer", 16 * MIB],
  ["canary", 4 * MIB],
  ["network", 4 * MIB],
  ["provenance", 4 * MIB],
  // Context families (C0): sized like the capacity plan, (horizon / interval) x worst-case tick x 1.25,
  // against the 30-day declared data horizon (DATA_FAMILY_HORIZON_ENTRIES), with the 4x ceiling still
  // admitting a 15-minute interval and not raising MIN_STRUCTURAL_INTERVAL_MS. Floors (1 h interval):
  // host_lifecycle 3,570,300 B; network_context 1,467,000 B; session_context 10,415,700 B.
  // C2: + host.daemon_gap and at most 4 host.lifecycle_record per tick.
  ["host_lifecycle", 7 * MIB],
  // C2: + the VPN service census marker, at most 8 net.vpn_service_state and at most 8
  // context.transition (one per dimension) records per tick.
  ["network_context", 13 * MIB],
  // C2: + the attachment census marker, at most 8 session.attachment and at most 8
  // session.created_vs_boot records per tick.
  ["session_context", 21 * MIB],
  // C2: at most MAX_BINARY_STATES_PER_TICK (12) collector.binary_state records per tick. Floor (1 h
  // interval, 30 days): 720 x 12 x 668 B x 1.25 = 7,214,400 B.
  ["collector_state", 8 * MIB],
  // C2 derived families. tick_summary: one record of at most 1,013 B per structural tick; 3 MiB holds the
  // 90-day retention at a 1 h interval (the 30-day floor is 911,700 B). context_stats: at most one
  // episode and one daily record per tick (899 B); 2 MiB holds the 30-day floor (809,100 B) and, at
  // typical volume (rare episodes, one daily record per day), the 365-day retention.
  ["context_stats", 2 * MIB],
  ["tick_summary", 3 * MIB],
];

// The pinned worst-case tick shape per family (§15.3): the maximum normalized record size the REAL
// translators produce on maximum-length inputs, the bytes of the per-tick markers (census, overflow),
// and the per-tick entity cap the DAEMON PATH actually passes (the collectors' defaults, which are now
// also hard upper clamps for session and peer -- §2: they used to be unclamped). worst = cap x record
// + markers. T8 (fact-families.test.js) asserts each entityCap equals the live exported collector
// constant, so raising a collector cap without revisiting the budget fails the suite. network and
// provenance are not pinned (they carry no history-dependent rule, so no horizon invariant applies).
const FAMILY_TICK_SHAPE_ENTRIES = [
  // DEFAULT_SERVICE_CENSUS_CEILING (tools/services.js); the hard clamp 5000 is an operator choice
  // (Q7: fixed budget, accept history_horizon_short).
  ["service", { maxRecordBytes: 291, markerBytes: 251, entityCap: 1000 }],
  // MAX_LINEAGE_EDGES_PER_TICK (tools/processes.js).
  ["process_lineage", { maxRecordBytes: 251, markerBytes: 297, entityCap: 200 }],
  // MAX_JOB_LIMIT (tools/scheduled-jobs.js clamp).
  ["scheduled_job", { maxRecordBytes: 354, markerBytes: 275, entityCap: 200 }],
  // MAX_SESSION_ENTITY_LIMIT (tools/sessions.js clamp); markers = census + overflow.
  ["session", { maxRecordBytes: 333, markerBytes: 530, entityCap: 200 }],
  // MAX_PEER_ENTITY_LIMIT (vpn-peer-status.js) + MAX_TAILSCALE_PEER_ENTITY_LIMIT (tailscale-status.js);
  // markers = VPN census + VPN overflow + Tailscale overflow.
  ["peer", { maxRecordBytes: 392, markerBytes: 933, entityCap: 400 }],
  // MAX_CANARIES (tools/canary.js).
  ["canary", { maxRecordBytes: 501, markerBytes: 247, entityCap: 200 }],
  // Context families: the worst-case NORMALIZED record of each fact, computed from its closed schema
  // (every field at its longest valid value; fact-families.test.js "C0 data-family T8" recomputes and
  // pins these numbers). Each per-tick fact counts as a marker; host_lifecycle: boot 698 +
  // boot_boundary 928 + clock_reading 1147 + suspend 581 + boundary_census 613; network_context:
  // tailnet_state 601 + config_fingerprint 1029; session_context: login_census 777 + user.presence 508
  // as markers, plus at most MAX_LOGIN_ARRIVALS_PER_TICK + MAX_LOGIN_HISTORY_ROWS_PER_TICK (8 + 8)
  // records of at most 643 B.
  // A boundary census (C0.12) borrows the next structural slot, so a horizon holds at most two extra
  // ticks, inside the 1.25 headroom.
  // C2: + host.daemon_gap 679 as a marker; records: MAX_LIFECYCLE_RECORDS_PER_TICK x host.lifecycle_record 721.
  ["host_lifecycle", { maxRecordBytes: 721, markerBytes: 4646, entityCap: 4 }],
  // C2: markers + vpn_service_census 614; records: MAX_VPN_SERVICE_STATES_PER_TICK (8) x vpn_service_state
  // 528 and MAX_TRANSITIONS_PER_TICK (8) x context.transition 699, counted at 699.
  ["network_context", { maxRecordBytes: 699, markerBytes: 2244, entityCap: 16 }],
  // C2: + session.attachment_census 608 as a marker; + MAX_SESSION_ATTACHMENTS_PER_TICK (8) records of
  // at most 573 B, counted at the family's 643 B record maximum.
  // + MAX_CREATED_VS_BOOT_PER_TICK (8) session.created_vs_boot records of at most 623 B.
  ["session_context", { maxRecordBytes: 643, markerBytes: 1893, entityCap: 32 }],
  // C2: at most MAX_BINARY_STATES_PER_TICK (context-translators.js) records of at most 668 B.
  ["collector_state", { maxRecordBytes: 668, markerBytes: 0, entityCap: 12 }],
  // C2: the exact worst cases (no envelope source, fixed entity key; pinned in context-c2-summary.test.js).
  ["context_stats", { maxRecordBytes: 0, markerBytes: 899, entityCap: 0 }],
  ["tick_summary", { maxRecordBytes: 0, markerBytes: 1013, entityCap: 0 }],
];

export const BUDGET_INVARIANT_HEADROOM = 1.25;
export const BUDGET_STRUCTURAL_INTERVAL_MS = HOUR_MS;

function buildFamilyBudgets() {
  const budgets = new Map();
  for (const [family, bytes] of FAMILY_BUDGET_ENTRIES) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: budget for unknown family ${family}`);
    if (budgets.has(family)) throw new Error(`fact-families: family ${family} has two budgets`);
    if (!Number.isSafeInteger(bytes) || bytes <= 0) throw new Error(`fact-families: family ${family} has an invalid budget`);
    budgets.set(family, bytes);
  }
  for (const family of FACT_FAMILY_IDS) if (!budgets.has(family)) throw new Error(`fact-families: family ${family} has no default budget`);
  return budgets;
}

export const FAMILY_DEFAULT_BUDGET_BYTES = buildFamilyBudgets();

function buildTickShapes() {
  const shapes = new Map();
  for (const [family, shape] of FAMILY_TICK_SHAPE_ENTRIES) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: tick shape for unknown family ${family}`);
    for (const key of ["maxRecordBytes", "markerBytes", "entityCap"]) {
      if (!Number.isSafeInteger(shape[key]) || shape[key] < 0) throw new Error(`fact-families: family ${family} has an invalid ${key}`);
    }
    shapes.set(family, Object.freeze({ ...shape, worstTickBytes: shape.entityCap * shape.maxRecordBytes + shape.markerBytes }));
  }
  return shapes;
}

export const FAMILY_TICK_SHAPES = buildTickShapes();

// Context-plan C0/§4: families that no rule reads yet but whose history is kept as DATA for later
// learners. Their declared horizon is the memory the budget must hold at worst-case volume (the 30-day
// raw retention, fact-store.js DEFAULT_FACT_RETENTION_MS); it is a resource floor (class S), never an
// eligibility gate, and never a RULE_HORIZONS entry (daemon.js pins RULE_HORIZONS to its
// history-dependent rule set in both directions).
const DATA_FAMILY_HORIZON_ENTRIES = [
  ["host_lifecycle", 30 * DAY_MS],
  ["network_context", 30 * DAY_MS],
  ["session_context", 30 * DAY_MS],
  ["collector_state", 30 * DAY_MS],
  // §8.1: the S floor of tick_summary's memory (at least 30 days, held at worst-case volume by the
  // budget); retention beyond it (90 days, FAMILY_RETENTION_MS) is an O choice held at typical volume.
  // Declared here, not in RULE_HORIZONS (C2 deviation): RULE_HORIZONS is the alert-rule registry.
  ["tick_summary", 30 * DAY_MS],
  ["context_stats", 30 * DAY_MS],
];

function buildDataFamilyHorizons(entries) {
  const map = new Map();
  for (const [family, horizonMs] of entries) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: data horizon for unknown family ${family}`);
    if (map.has(family)) throw new Error(`fact-families: family ${family} has two data horizons`);
    if (!Number.isFinite(horizonMs) || horizonMs <= 0) throw new Error(`fact-families: family ${family} has an invalid data horizon`);
    for (const rule of RULE_HORIZONS.values()) {
      if (rule.families.includes(family)) throw new Error(`fact-families: data family ${family} is read by rule-horizon rules; use RULE_HORIZONS`);
    }
    map.set(family, horizonMs);
  }
  return map;
}

export const DATA_FAMILY_HORIZONS = buildDataFamilyHorizons(DATA_FAMILY_HORIZON_ENTRIES);

// Context plan C2 / §8.1 ("Horizon and retention"): per-family retention. Before C2 every family
// shared fact-store.js's 30-day DEFAULT_FACT_RETENTION_MS (`fact-store.js:31`); long-memory families
// must outlive the raw window, so the age cutoff is resolved per family here. A family with no entry
// keeps the 30-day default. Each value is an O resource choice (§16.1), and must be at least the
// family's declared horizon (rule or data): retention shorter than the memory a family promises would
// make that promise unkeepable by construction (checked at module init).
export const DEFAULT_FAMILY_RETENTION_MS = 30 * DAY_MS;
const FAMILY_RETENTION_ENTRIES = [
  // §8.1 / §16.1: tick_summary is kept beyond the raw window; default 90 days (O).
  ["tick_summary", 90 * DAY_MS],
  // §8.2: the long-lived statistics outlive tick_summary; default 365 days (O).
  ["context_stats", 365 * DAY_MS],
];

function buildFamilyRetention(entries) {
  const map = new Map();
  for (const [family, retentionMs] of entries) {
    if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: retention for unknown family ${family}`);
    if (map.has(family)) throw new Error(`fact-families: family ${family} has two retentions`);
    if (!Number.isFinite(retentionMs) || retentionMs <= 0) throw new Error(`fact-families: family ${family} has an invalid retention`);
    map.set(family, retentionMs);
  }
  for (const family of FACT_FAMILY_IDS) if (!map.has(family)) map.set(family, DEFAULT_FAMILY_RETENTION_MS);
  return map;
}

export const FAMILY_RETENTION_MS = buildFamilyRetention(FAMILY_RETENTION_ENTRIES);

/** The age-retention of one family's store (§8.1, C2). Throws on an unknown family. */
export function familyRetentionMs(family) {
  requireFactFamily(family);
  return FAMILY_RETENTION_MS.get(family);
}

// Derived families (context plan C2, §8.1-§8.2): their records are DERIVED from the other families'
// committed passes (tick_summary is certified at derivation, I70), and each carries a lineage stamp
// that names its own family's last committed pass. They are therefore appended ONLY by their own
// derivation step: the daemon's generic per-tick write (appendFactPointsByFamily) neither appends to
// them nor runs a retention sweep over them -- a sweep would advance the very pass id the stamp names,
// and the stamp would never validate (the record's own pass runs retention anyway).
const DERIVED_FAMILY_ENTRIES = ["tick_summary", "context_stats"];
export const DERIVED_FAMILIES = Object.freeze(new Set(DERIVED_FAMILY_ENTRIES.map((family) => {
  if (!KNOWN_FAMILIES.has(family)) throw new Error(`fact-families: derived family ${family} is unknown`);
  return family;
})));

// H_max(f): the longest eligibility horizon of any history-dependent rule reading family f (§4.5),
// or, for a data family, its declared data horizon.
function buildFamilyHorizonMax() {
  const max = new Map();
  for (const rule of RULE_HORIZONS.values()) {
    for (const family of rule.families) max.set(family, Math.max(max.get(family) ?? 0, rule.horizonMs));
  }
  for (const [family, horizonMs] of DATA_FAMILY_HORIZONS) max.set(family, Math.max(max.get(family) ?? 0, horizonMs));
  for (const family of max.keys()) {
    if (!FAMILY_TICK_SHAPES.has(family)) throw new Error(`fact-families: family ${family} carries a rule horizon but no pinned worst-case tick`);
  }
  return max;
}

export const FAMILY_HORIZON_MAX_MS = buildFamilyHorizonMax();

for (const [family, horizonMs] of FAMILY_HORIZON_MAX_MS) {
  if (FAMILY_RETENTION_MS.get(family) < horizonMs) throw new Error(`fact-families: family ${family}'s retention is shorter than its horizon`);
}

/**
 * The T8 budget invariant / config floor (§4.5): (H_max / interval) x worst-case tick bytes x 1.25.
 * With a budget at or above it, inflating per-tick volume up to the collector caps can NARROW the
 * family's certified span, but never below its longest eligibility horizon (§5 N4). Families with no
 * history-dependent rule (network, provenance) have no horizon to protect: their floor is their
 * default budget, so an operator value can only RAISE it (S4 deviation, G2 question).
 *
 * G2 L3: the invariant counts structural TICKS, and the structural interval is operator-settable
 * (profile.structural.interval_ms, any positive number). `structuralIntervalMs` computes it at that
 * interval: below 1 h more ticks fall inside a horizon, so the floor scales up; at or above 1 h (or
 * for a missing/invalid value) it is the 1 h figure -- a slower interval never loosens it. The
 * defaults scale to the interval floor up to the ceiling; an explicit budget below the interval's
 * floor is rejected and reported as `budget_below_horizon_floor`. The daemon reports any effective
 * budget below the interval's floor as `horizon_invariant_unmet` rather than silently going horizon-short.
 */
export function familyBudgetFloorBytes(family, { structuralIntervalMs } = {}) {
  requireFactFamily(family);
  const horizonMs = FAMILY_HORIZON_MAX_MS.get(family);
  const shape = FAMILY_TICK_SHAPES.get(family);
  if (horizonMs === undefined || shape === undefined) return FAMILY_DEFAULT_BUDGET_BYTES.get(family);
  const intervalMs = typeof structuralIntervalMs === "number" && Number.isFinite(structuralIntervalMs) && structuralIntervalMs > 0
    ? Math.min(structuralIntervalMs, BUDGET_STRUCTURAL_INTERVAL_MS)
    : BUDGET_STRUCTURAL_INTERVAL_MS;
  return Math.ceil((horizonMs / intervalMs) * shape.worstTickBytes * BUDGET_INVARIANT_HEADROOM);
}

for (const family of FACT_FAMILY_IDS) {
  if (FAMILY_DEFAULT_BUDGET_BYTES.get(family) < familyBudgetFloorBytes(family)) {
    throw new Error(`fact-families: family ${family}'s default budget is below its horizon invariant`);
  }
}

// G2 L4: the upper bound on a configured budget. Every whole-file read of a family's store costs in
// proportion to its size, every fast tick (service is read four times per tick with learned on), and
// T9's read-cost bound is modelled at the DEFAULTS -- so an unbounded same-UID watch.json value would
// leave both the file and the per-tick read cost unbounded, and make the oversize check (relative to
// the budget) meaningless. 4x the default bounds read cost at 4x the T9 model, and is exactly enough
// to restore the T8 invariant down to a 15-minute structural interval (G2 L3) for every family.
export const BUDGET_CEILING_MULTIPLIER = 4;

export function familyBudgetCeilingBytes(family) {
  requireFactFamily(family);
  return BUDGET_CEILING_MULTIPLIER * FAMILY_DEFAULT_BUDGET_BYTES.get(family);
}

// The shortest structural interval for which every horizon-bearing family can fit its required
// floor under the fixed 4x ceiling. Profiles below this boundary are rejected by daemon validation;
// they cannot be made safe by silently selecting any bounded budget.
export const MIN_STRUCTURAL_INTERVAL_MS = Math.max(...[...FAMILY_HORIZON_MAX_MS].map(([family, horizonMs]) => (
  Math.ceil((horizonMs * FAMILY_TICK_SHAPES.get(family).worstTickBytes * BUDGET_INVARIANT_HEADROOM) / familyBudgetCeilingBytes(family))
)));

/**
 * Effective per-family budgets from watch.json's `fact_store_budgets` map (§4.5 Config). A missing,
 * non-finite, non-integer, or too-small value falls back to the family default; "too small" means
 * below the T8 invariant (familyBudgetFloorBytes), never merely below one tick, because a budget
 * between one tick and the invariant would leave the family permanently horizon-short (a
 * novelty-absorbing window, §4.2). A missing default scales to the interval floor when needed,
 * bounded by the 4x ceiling. Rejected values are reported (status reason
 * `budget_below_horizon_floor` / `invalid`), never silently applied. A value above the ceiling
 * (familyBudgetCeilingBytes, G2 L4) is clamped to it and reported (`budget_above_ceiling`). Keys that are not registry
 * families are ignored (and reported). Pure.
 */
export function resolveFactStoreBudgets(configured, { structuralIntervalMs } = {}) {
  const budgets = {};
  const rejected = {};
  const clamped = {};
  const source = {};
  const map = configured && typeof configured === "object" && !Array.isArray(configured) ? configured : {};
  for (const family of FACT_FAMILY_IDS) {
    const intervalFloor = familyBudgetFloorBytes(family, { structuralIntervalMs });
    const fallback = Math.min(familyBudgetCeilingBytes(family), Math.max(FAMILY_DEFAULT_BUDGET_BYTES.get(family), intervalFloor));
    if (!Object.prototype.hasOwnProperty.call(map, family)) {
      budgets[family] = fallback;
      source[family] = "default";
      continue;
    }
    const value = map[family];
    const floor = intervalFloor;
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
      budgets[family] = fallback;
      source[family] = "default";
      rejected[family] = { reason: "invalid", floor_bytes: floor };
    } else if (value < floor) {
      budgets[family] = fallback;
      source[family] = "default";
      rejected[family] = { reason: "budget_below_horizon_floor", configured_bytes: value, floor_bytes: floor };
    } else if (value > familyBudgetCeilingBytes(family)) {
      // G2 L4: clamped (not refused -- the operator asked for MORE than the ceiling, so the ceiling is
      // the closest bounded value) and reported.
      const ceiling = familyBudgetCeilingBytes(family);
      budgets[family] = ceiling;
      source[family] = "configured";
      clamped[family] = { reason: "budget_above_ceiling", configured_bytes: value, ceiling_bytes: ceiling };
    } else {
      budgets[family] = value;
      source[family] = "configured";
    }
  }
  const unknownKeys = Object.keys(map).filter((key) => !KNOWN_FAMILIES.has(key)).sort();
  return { budgets, source, rejected, clamped, ...(unknownKeys.length > 0 ? { unknown_families: unknownKeys } : {}) };
}

// The horizon-short signal (§4.2, §4.4, I12): a rule horizon-ineligible for more than
// HISTORY_HORIZON_SHORT_ALERT_TICKS consecutive structural intervals raises this FIXED daemon alert
// (alert-store.js FIXED_ALERT_RULE_IDS), driven by the daemon status record's history_horizon_short.
export const HISTORY_HORIZON_SHORT_RULE_ID = "daemon.fact_history.horizon_short";
export const HISTORY_HORIZON_SHORT_ALERT_TICKS = 24;
