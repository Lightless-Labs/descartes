import { readFactPoints } from "./fact-store.js";
import { readDaemonStatus } from "./history-store.js";
import {
  DEFAULT_BASELINE_FACT_WINDOW_MS,
} from "./welford-stats.js";
import {
  familyBudgetFloorBytes,
  NOVELTY_FAMILIES,
  resolveFactStoreBudgets,
  MIN_STRUCTURAL_INTERVAL_MS,
  RULE_HORIZONS,
} from "./fact-families.js";
import { ACTIVE_FRESHNESS_MULTIPLE, DEFAULT_STRUCTURAL_INTERVAL_MS } from "./daemon.js";
import {
  computeServiceAppearanceCandidates,
  computeServiceBaselineCandidates,
  DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT,
  DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT,
  groupServiceFactsByTick,
  loadServiceAppearanceBaselineStore,
  loadServiceBaselineStore,
  SERVICE_APPEARED_RULE_ID,
  SERVICE_DISAPPEARED_RULE_ID,
} from "./service-baseline.js";
import {
  computeSessionBaselineCandidates,
  computeWindowedSessionStats,
  DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT,
  groupSessionFactsByTick,
  loadSessionBaselineStore,
  SESSION_CHURN_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  tickGroupDisposition as sessionTickGroupDisposition,
} from "./session-baseline.js";
import {
  computePeerBaselineCandidates,
  computeWindowedPeerDropStats,
  computeWindowedPeerStats,
  DEFAULT_PEER_MIN_HISTORY_TICK_COUNT,
  groupPeerFactsByTick,
  loadPeerBaselineStore,
  PEER_COUNT_DROP_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  tickGroupDisposition as peerTickGroupDisposition,
} from "./peer-baseline.js";
import {
  computeScheduledJobBaselineCandidates,
  DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT,
  groupScheduledJobFactsByTick,
  loadPersistenceBaselineStore,
  SCHEDULED_JOB_APPEARED_RULE_ID,
} from "./persistence-baseline.js";
import {
  computeProcessLineageBaselineCandidates,
  DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT,
  groupProcessLineageFactsByTick,
  loadProcessLineageBaselineStore,
  PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
} from "./process-lineage-baseline.js";
import {
  loadWatchConfig,
  resolveWatchStorePaths,
  writeWatchConfig,
} from "./watch-store.js";
import { coldStartEntryReason } from "./cold-start-reason.js";

// S6 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §7 S6, §8 T11, I11): `baseline
// status` reports, PER RULE, whether that rule WOULD EVALUATE on the current state -- and it does so by
// running the watch-tier detectors themselves, read-only, on the same state the daemon's next fast
// tick would see: the same family reads, the same persisted detector stores, the same `now`, the same
// watch config, and the same options the daemon passes (activeFreshnessMs = ACTIVE_FRESHNESS_MULTIPLE x
// the structural interval to the four census detectors, nothing to session/peer). Every write seam is a
// no-op, so status never mutates anything. Each detector reports its own per-rule gates
// (`ruleEvaluations`, fact-store-completeness.js buildRuleEvaluation): history trust, the persistent
// cold-start lockout, the eligibility horizon (ruleHorizonOk / noveltyHorizonOk -- the same predicates
// the daemon's veto uses through ruleEligible), and its own readiness (complete census count, a fresh
// latest complete census, an established statistical baseline). Nothing about those gates is
// re-derived here, so status cannot drift from the detector (Leg E, §3: the old status counted complete
// groups after the anchor and never consulted history trust or the horizon).
//
// Scope: the eight watch-tier rules of the five baseline domains. canary.tampered and the correlation
// rule are learned-tier (`descartes learned status`), not watch-tier.

const STATUS_TICK_COUNT = 6;
const LIVE_RECOMPUTE_NOTE = "Answers are recomputed live from the fact-history window; they can differ slightly from the daemon's last tick.";
const DAEMON_RECORD_NOTE = "cap_below_tick, retention_failing and the horizon-short since time (shown only while the rule is horizon-short now) come from the daemon's last status record.";

function usage() {
  return `Usage:
  descartes baseline status [--json]
  descartes baseline inspect [--domain <name>] [--json]
  descartes baseline enable [--json]
  descartes baseline disable [--json]

Domains: service, session, peer, scheduled-job, process-lineage.

Status is reported per rule: "watching" means the rule's detector would evaluate it on the current
state (history trusted, cold start cleared, eligibility horizon met, detector ready). Other phases name
the gate that stops it. A family store that was never created reads "not observed (no store)".`;
}

function parseArgs(args, command) {
  const options = { json: false, domain: undefined, help: false };
  const values = [...(args ?? [])];
  for (let index = 0; index < values.length; index += 1) {
    const arg = values[index];
    if (arg === "--json") options.json = true;
    else if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--domain") {
      const domain = values[++index];
      if (!domain || domain.startsWith("--")) throw new Error(`baseline ${command} requires a value for --domain\n\n${usage()}`);
      options.domain = domain;
    } else {
      throw new Error(`Unexpected baseline ${command} argument: ${arg}\n\n${usage()}`);
    }
  }
  if (command !== "inspect" && options.domain !== undefined) {
    throw new Error(`baseline ${command} does not accept --domain\n\n${usage()}`);
  }
  return options;
}

function nowMsOf(options) {
  const nowMs = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(nowMs)) throw new Error("baseline commands require a valid --now value");
  return nowMs;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isValidTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function currentGroups(group, points, nowMs) {
  return group(points).filter((item) => {
    const timestamp = new Date(item.ts).getTime();
    return Number.isFinite(timestamp) && timestamp <= nowMs;
  });
}

// Display only: a tick-group is "complete" by the disposition each domain's cold-start lockout counts
// (the detectors' own functions for peer and session; censusState for the four census detectors), so
// "still learning — n of 6" tracks the lockout's re-accumulation. For peer that is the BASE
// overflow-vs-complete disposition: an invalid-signature tick clears the shared lockout (only
// count_drop's stricter disposition excludes it).
function isComplete(domain, group) {
  if (domain === "peer") return peerTickGroupDisposition(group) === "complete";
  if (domain === "session") return sessionTickGroupDisposition(group) === "complete";
  return group.censusState === "complete";
}

function completeGroups(domain, groups) {
  return groups.filter((group) => isComplete(domain, group));
}

function hasIncompleteLatest(domain, groups) {
  return groups.length > 0 && !isComplete(domain, groups[groups.length - 1]);
}

// H1 (S6 review; I11 "a fresh complete latest group"): no complete census within the daemon's
// freshness window (ACTIVE_FRESHNESS_MULTIPLE x the structural interval -- the same activeFreshnessMs
// the four census detectors gate on), including a window with no complete census left at all. The
// census rules stop on this (their latest_census_stale gate); the session and peer detectors apply no
// freshness gate and keep evaluating on the last census for up to the fact window (31 days), so for
// them this is the only signal that the collector is dead. Annotation only: it never changes a phase.
function latestCompleteCensusStale(domain, groups, nowMs, activeFreshnessMs) {
  if (groups.length === 0) return false;
  const complete = completeGroups(domain, groups);
  if (complete.length === 0) return true;
  const latestMs = new Date(complete[complete.length - 1].ts).getTime();
  return !(nowMs - latestMs <= activeFreshnessMs);
}

function stateReason(entry, groups) {
  return coldStartEntryReason({
    storeLossThisTick: Boolean(entry.missing || entry.corrupt),
    persistedReason: entry.state?.cold_start_reason,
    currentGroups: groups,
  });
}

// Display only: complete ticks observed strictly after the persisted cold-start anchor (the count the
// detector's re-accumulation branch uses). It does NOT decide the phase; the detector's own gate does.
function progressForState(entry, groups, nowMs) {
  if (!entry?.state?.cold_start_pending) return STATUS_TICK_COUNT;
  const anchor = entry.state.cold_start_since_ts ? new Date(entry.state.cold_start_since_ts).getTime() : undefined;
  if (!Number.isFinite(anchor)) return 0;
  return Math.min(STATUS_TICK_COUNT, completeGroups(entry.domain, groups)
    .filter((group) => new Date(group.ts).getTime() > anchor && new Date(group.ts).getTime() <= nowMs)
    .length);
}

function serviceEstablished(groups) {
  const counts = new Map();
  for (const group of completeGroups("service", groups)) {
    for (const entityKey of group.entityKeys) counts.set(entityKey, (counts.get(entityKey) ?? 0) + 1);
  }
  return [...counts.entries()]
    .filter(([, count]) => count >= DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT)
    .map(([entityKey]) => entityKey)
    .sort();
}

function entitySetFromGroups(groups) {
  const entities = new Set();
  for (const group of groups) for (const entityKey of group.entityKeys ?? []) entities.add(entityKey);
  return [...entities].sort();
}

function sessionEntities(groups) {
  const entities = new Set();
  for (const group of completeGroups("session", groups)) {
    for (const point of group.points ?? []) entities.add(point.entity_key);
  }
  return [...entities].sort();
}

function peerEntities(points, groups) {
  const completeTimestamps = new Set(completeGroups("peer", groups).map((group) => group.ts));
  return [...new Set(points
    .filter((point) => point?.fact_name === "peer.presence" && completeTimestamps.has(point.ts))
    .filter((point) => !String(point.entity_key).includes("census-marker") && !String(point.entity_key).includes("overflow-marker"))
    .map((point) => point.entity_key))].sort();
}

function statisticalBaseline(domain, groups) {
  if (domain === "session") return computeWindowedSessionStats(groups);
  return {
    spike: computeWindowedPeerStats(groups),
    drop: computeWindowedPeerDropStats(groups),
  };
}

function establishedForDomain(domain, points, groups) {
  if (domain === "service") return serviceEstablished(groups);
  if (domain === "session") {
    const baseline = statisticalBaseline(domain, groups);
    return baseline.confidence_state === "established" ? sessionEntities(groups) : [];
  }
  if (domain === "peer") {
    const baseline = statisticalBaseline(domain, groups);
    return baseline.spike.confidence_state === "established" ? peerEntities(points, groups) : [];
  }
  const required = domain === "scheduled-job" ? DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT : DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT;
  return completeGroups(domain, groups).length >= required + 1
    ? entitySetFromGroups(completeGroups(domain, groups))
    : [];
}

// Each domain's detectors, with exactly the DI seams the daemon's call uses (daemon.js
// runDaemonIteration: `detectorOptionsFor({ activeFreshnessMs })` for the four census detectors,
// `detectorOptionsFor()` for session and peer). `freshness` mirrors which ones get activeFreshnessMs.
const DOMAIN_DEFINITIONS = [
  {
    domain: "service",
    family: "service",
    group: groupServiceFactsByTick,
    required: DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT,
    producers: [
      { label: "service", compute: computeServiceBaselineCandidates, loadKey: "loadServiceBaselineStore", load: loadServiceBaselineStore, writeKey: "writeServiceBaselineStore", freshness: true, rules: [SERVICE_DISAPPEARED_RULE_ID] },
      { label: "service-appearance", compute: computeServiceAppearanceCandidates, loadKey: "loadServiceAppearanceBaselineStore", load: loadServiceAppearanceBaselineStore, writeKey: "writeServiceAppearanceBaselineStore", freshness: true, rules: [SERVICE_APPEARED_RULE_ID] },
    ],
  },
  {
    domain: "session",
    family: "session",
    group: groupSessionFactsByTick,
    required: DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT,
    producers: [
      { label: "session", compute: computeSessionBaselineCandidates, loadKey: "loadSessionBaselineStore", load: loadSessionBaselineStore, writeKey: "writeSessionBaselineStore", freshness: false, rules: [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID] },
    ],
  },
  {
    domain: "peer",
    family: "peer",
    group: groupPeerFactsByTick,
    required: DEFAULT_PEER_MIN_HISTORY_TICK_COUNT,
    producers: [
      { label: "peer", compute: computePeerBaselineCandidates, loadKey: "loadPeerBaselineStore", load: loadPeerBaselineStore, writeKey: "writePeerBaselineStore", freshness: false, rules: [PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID] },
    ],
  },
  {
    domain: "scheduled-job",
    family: "scheduled_job",
    group: groupScheduledJobFactsByTick,
    required: DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT,
    producers: [
      { label: "scheduled-job", compute: computeScheduledJobBaselineCandidates, loadKey: "loadPersistenceBaselineStore", load: loadPersistenceBaselineStore, writeKey: "writePersistenceBaselineStore", freshness: true, rules: [SCHEDULED_JOB_APPEARED_RULE_ID] },
    ],
  },
  {
    domain: "process-lineage",
    family: "process_lineage",
    group: groupProcessLineageFactsByTick,
    required: DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT,
    producers: [
      { label: "process-lineage", compute: computeProcessLineageBaselineCandidates, loadKey: "loadProcessLineageBaselineStore", load: loadProcessLineageBaselineStore, writeKey: "writeProcessLineageBaselineStore", freshness: true, rules: [PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID] },
    ],
  },
];

export const BASELINE_STATUS_RULE_IDS = Object.freeze(DOMAIN_DEFINITIONS.flatMap((definition) => definition.producers.flatMap((producer) => producer.rules)));

function normalizeDomainName(value) {
  return value === "scheduled_job" ? "scheduled-job" : value;
}

async function readDaemonRecord(descartesPaths, options) {
  try {
    const record = await (options.readDaemonStatus ?? readDaemonStatus)(descartesPaths);
    return record === undefined ? { status: "absent" } : isObject(record) ? { status: "present", record } : { status: "unreadable" };
  } catch {
    return { status: "unreadable" };
  }
}

// The daemon derives its structural interval from its resolved profile (profile.structural.interval_ms,
// default DEFAULT_STRUCTURAL_INTERVAL_MS). The CLI has no profile of its own, so it takes the one the
// daemon last recorded; without a usable record it uses the daemon's default.
//
// NOT display-only (S6 review M3): the interval sets activeFreshnessMs, which decides
// latest_census_stale vs watching for the four census rules. A recorded value is accepted only within
// the bounds validateDaemonProfile enforces before a daemon will run (a finite number >=
// MIN_STRUCTURAL_INTERVAL_MS; the daemon has no upper bound, so neither does this). A value outside
// them was not written by a running daemon, so status uses the default and says which source it used.
// Residual (disclosed): a same-UID forged in-bounds value, or a missing record on a non-default
// profile, makes status's freshness differ from the daemon's.
function structuralIntervalOf(daemonRecord) {
  if (daemonRecord.status !== "present") return { intervalMs: DEFAULT_STRUCTURAL_INTERVAL_MS, source: "default_no_record" };
  const value = daemonRecord.record?.profile?.structural?.interval_ms;
  if (value === undefined) return { intervalMs: DEFAULT_STRUCTURAL_INTERVAL_MS, source: "default_no_recorded_interval" };
  return typeof value === "number" && Number.isFinite(value) && value >= MIN_STRUCTURAL_INTERVAL_MS
    ? { intervalMs: value, source: "daemon_record" }
    : { intervalMs: DEFAULT_STRUCTURAL_INTERVAL_MS, source: "default_recorded_interval_invalid" };
}

async function runProducerReadOnly(descartesPaths, producer, { config, nowIso, activeFreshnessMs, options }) {
  const reads = [];
  const entries = [];
  const read = options.readFactPoints ?? readFactPoints;
  const load = options[producer.loadKey] ?? producer.load;
  const producerOptions = {
    now: nowIso,
    loadWatchConfig: async () => config,
    readFactPoints: async (paths, readOptions) => {
      const result = await read(paths, readOptions);
      reads.push({ options: readOptions, result });
      return result;
    },
    [producer.loadKey]: async (paths) => {
      const entry = await load(paths);
      entries.push(entry);
      return entry;
    },
    // Read-only: status never writes a detector store (or anything else).
    [producer.writeKey]: async () => {},
    ...(producer.freshness ? { activeFreshnessMs } : {}),
    ...(options.windowMs !== undefined ? { baselineFactWindowMs: options.windowMs } : {}),
  };
  try {
    const result = await producer.compute(descartesPaths, producerOptions);
    return { producer, result, reads, entry: entries[0] };
  } catch (error) {
    return { producer, error: error instanceof Error ? error.message : String(error), reads, entry: entries[0] };
  }
}

async function readBaselineInputs(descartesPaths, options) {
  const nowMs = nowMsOf(options);
  const nowIso = new Date(nowMs).toISOString();
  const config = await (options.loadWatchConfig ?? loadWatchConfig)(descartesPaths);
  // A disabled watch tier is reported as such with NO fact or store I/O (mirrors the detectors' own
  // kill-switch short-circuit, checked before any read).
  if (!config.enabled) return { config, nowMs, disabled: true, domains: DOMAIN_DEFINITIONS.map((definition) => ({ definition, runs: [], groups: [], points: [] })) };
  const daemonRecord = await readDaemonRecord(descartesPaths, options);
  const { intervalMs: structuralIntervalMs, source: structuralIntervalSource } = structuralIntervalOf(daemonRecord);
  const activeFreshnessMs = ACTIVE_FRESHNESS_MULTIPLE * structuralIntervalMs;
  const domains = [];
  for (const definition of DOMAIN_DEFINITIONS) {
    const runs = [];
    for (const producer of definition.producers) {
      runs.push(await runProducerReadOnly(descartesPaths, producer, { config, nowIso, activeFreshnessMs, options }));
    }
    // The family read this domain's detectors made (the one that carries the seen-set when one was
    // requested, so the family block can show the novelty memory's certified span).
    const familyRead = runs.flatMap((run) => run.reads).find((entry) => Array.isArray(entry.options?.seenSetFamilies) && entry.options.seenSetFamilies.length > 0)?.result
      ?? runs.flatMap((run) => run.reads)[0]?.result;
    const points = Array.isArray(familyRead?.points) ? familyRead.points : [];
    const groups = currentGroups(definition.group, points, nowMs);
    domains.push({ definition, runs, familyRead, points, groups });
  }
  return { config, nowMs, daemonRecord, structuralIntervalMs, structuralIntervalSource, activeFreshnessMs, domains };
}

function configPayload(config, descartesPaths) {
  return { ...config, config_path: resolveWatchStorePaths(descartesPaths).configFile };
}

const GATE_PHASES = {
  insufficient_complete_history: "still learning — not enough complete census ticks yet",
  latest_census_stale: "cannot evaluate — latest complete census is stale",
  baseline_warming_up: "still learning — statistical baseline warming up",
  drop_history_not_ready: "still learning — drop history re-accumulating since cold start",
  no_complete_census: "cannot establish — no complete census yet",
};

function storeAbsent(familyRead) {
  return familyRead?.store_exists === false;
}

function rulePhase({ gate, historyReason, horizonShortSince, progress, absent, error }) {
  if (absent) return "not observed (no store)";
  if (error !== undefined) return "cannot evaluate — detector error";
  if (gate === "ok") return "watching";
  if (gate === "history_untrusted") return `cannot establish — history untrusted (${historyReason ?? "history_unknown"})`;
  if (gate === "cold_start_pending") return `still learning — ${progress} of ${STATUS_TICK_COUNT}`;
  if (gate === "history_horizon_short") return `history horizon below minimum${horizonShortSince ? ` (since ${horizonShortSince})` : ""}`;
  return GATE_PHASES[gate] ?? `cannot evaluate — ${gate}`;
}

function budgetBlock(config, structuralIntervalMs) {
  return resolveFactStoreBudgets(config.fact_store_budgets, { structuralIntervalMs });
}

function familyStatusBlock({ family, familyRead, nowMs, budgets, structuralIntervalMs, daemonRecord }) {
  const completeness = isObject(familyRead?.completeness) ? familyRead.completeness : {};
  const floors = ["bytecap_floor_ts", "age_floor_ts"].map((field) => completeness[field]).filter(isValidTimestamp).map((value) => Date.parse(value));
  const floorMs = floors.length > 0 ? Math.max(...floors) : undefined;
  const block = {
    store: storeAbsent(familyRead) ? "absent" : "present",
    status: typeof completeness.status === "string" ? completeness.status : "unknown",
    coverage: typeof completeness.coverage === "string" ? completeness.coverage : "unknown",
    certified_after_ts: isValidTimestamp(completeness.certified_after_ts) ? completeness.certified_after_ts : null,
    bytecap_floor_ts: isValidTimestamp(completeness.bytecap_floor_ts) ? completeness.bytecap_floor_ts : null,
    oldest_certified_ts: isValidTimestamp(completeness.oldest_certified_ts) ? completeness.oldest_certified_ts : null,
    // The certified span the eligibility horizon is measured against: now - max(byte-cap floor, age
    // floor). null when the lineage was never narrowed (certified since it began). Display only.
    certified_horizon_ms: floorMs === undefined ? null : Math.max(0, nowMs - floorMs),
    budget_bytes: budgets.budgets[family],
    budget_source: budgets.source[family],
    floor_bytes: familyBudgetFloorBytes(family, { structuralIntervalMs }),
  };
  if (Number.isSafeInteger(familyRead?.bytes)) block.bytes = familyRead.bytes;
  if (budgets.rejected[family]) block.budget_rejected = budgets.rejected[family];
  const seenSet = familyRead?.seen_sets?.[family];
  if (NOVELTY_FAMILIES.has(family) && isObject(seenSet)) {
    block.seen_set = {
      status: seenSet.status,
      certified_since_ts: isValidTimestamp(seenSet.certified_since_ts) ? seenSet.certified_since_ts : null,
      scope_ts: isValidTimestamp(seenSet.scope_ts) ? seenSet.scope_ts : null,
    };
  }
  const recorded = daemonRecord.record?.fact_store_budgets?.families?.[family];
  if (isObject(recorded)) {
    if (recorded.cap_below_tick === true) block.cap_below_tick = true;
    if (recorded.retention_failing === true) block.retention_failing = true;
    if (typeof recorded.retention_error === "string" && recorded.retention_error) block.retention_error = recorded.retention_error;
    if (isObject(recorded.horizon_invariant_unmet)) block.horizon_invariant_unmet = recorded.horizon_invariant_unmet;
  }
  return block;
}

function horizonShortSinceOf(daemonRecord, ruleId, nowMs) {
  const since = daemonRecord.record?.history_horizon_short?.rules?.[ruleId]?.since_ts;
  return isValidTimestamp(since) && Date.parse(since) <= nowMs ? since : undefined;
}

// The status reasons for one rule (fact-store capacity plan §4.4/§7 S6). Annotations only: the phase
// comes from the detector's own gate; a reason never makes a rule "watching" or stops it.
function ruleReasons({ ruleEvaluation, absent, familyBlock, horizonShortSince, censusStale }) {
  const reasons = [];
  if (absent) reasons.push("not_observed_no_store");
  if (!absent && (censusStale || ruleEvaluation?.gate === "latest_census_stale")) reasons.push("latest_census_stale");
  if (ruleEvaluation?.gate === "history_horizon_short") reasons.push("history_horizon_short");
  if (familyBlock.cap_below_tick) reasons.push("cap_below_tick");
  if (familyBlock.budget_rejected?.reason === "budget_below_horizon_floor") reasons.push("budget_below_horizon_floor");
  if (familyBlock.horizon_invariant_unmet) reasons.push("horizon_invariant_unmet");
  if (familyBlock.retention_failing) reasons.push("retention_failing");
  return reasons;
}

function buildDomainReports(inputs) {
  if (inputs.disabled) {
    return {
      families: {},
      domains: inputs.domains.map(({ definition }) => ({
        domain: definition.domain,
        phase: "disabled",
        cold_start_pending: false,
        cold_start_reason: undefined,
        complete_ticks: 0,
        required_ticks: STATUS_TICK_COUNT,
        established_count: 0,
        rules: definition.producers.flatMap((producer) => producer.rules.map((ruleId) => ({
          rule_id: ruleId, phase: "disabled", watching: false, gate: "watch_disabled", evaluated_alert_keys: [], evaluated_count: 0, reasons: [],
        }))),
      })),
    };
  }
  const budgets = budgetBlock(inputs.config, inputs.structuralIntervalMs);
  const families = {};
  const domains = inputs.domains.map(({ definition, runs, familyRead, points, groups }) => {
    const familyBlock = familyStatusBlock({ family: definition.family, familyRead, nowMs: inputs.nowMs, budgets, structuralIntervalMs: inputs.structuralIntervalMs, daemonRecord: inputs.daemonRecord });
    families[definition.family] = familyBlock;
    const absent = storeAbsent(familyRead);
    const censusStale = !absent && latestCompleteCensusStale(definition.domain, groups, inputs.nowMs, inputs.activeFreshnessMs);
    const rules = [];
    for (const run of runs) {
      const entry = run.entry ? { ...run.entry, domain: definition.domain } : undefined;
      const progress = progressForState(entry, groups, inputs.nowMs);
      for (const ruleId of run.producer.rules) {
        const ruleEvaluation = run.result?.ruleEvaluations?.[ruleId];
        const error = run.error ?? (ruleEvaluation ? undefined : "no rule evaluation reported");
        // M2: the daemon record's since clock is attached only when the LIVE gate is horizon-short; a
        // record left over from an earlier horizon-short spell never annotates a rule that evaluates.
        const horizonShortSince = ruleEvaluation?.gate === "history_horizon_short" && !absent && run.error === undefined
          ? horizonShortSinceOf(inputs.daemonRecord, ruleId, inputs.nowMs)
          : undefined;
        const watching = !absent && error === undefined && ruleEvaluation.evaluable === true;
        const keys = watching ? [...ruleEvaluation.evaluatedAlertKeys] : [];
        rules.push({
          rule_id: ruleId,
          phase: rulePhase({ gate: ruleEvaluation?.gate, historyReason: ruleEvaluation?.history_reason, horizonShortSince, progress, absent, error }),
          watching,
          gate: absent ? "no_store" : error !== undefined ? "detector_error" : ruleEvaluation.gate,
          ...(ruleEvaluation?.history_reason ? { history_reason: ruleEvaluation.history_reason } : {}),
          ...(error !== undefined && !absent ? { error } : {}),
          evaluated_alert_keys: keys,
          evaluated_count: keys.length,
          horizon_ms: RULE_HORIZONS.get(ruleId)?.horizonMs,
          ...(horizonShortSince ? { horizon_short_since_ts: horizonShortSince } : {}),
          reasons: ruleReasons({ ruleEvaluation, absent, familyBlock, horizonShortSince, censusStale }),
        });
      }
    }
    const pendingEntries = runs.map((run) => run.entry).filter((entry) => entry?.state?.cold_start_pending);
    const watchingCount = rules.filter((rule) => rule.watching).length;
    const phases = [...new Set(rules.map((rule) => rule.phase))];
    const phase = phases.length === 1
      ? phases[0]
      : watchingCount > 0 ? `partially watching — ${watchingCount} of ${rules.length} rules` : rules[0].phase;
    return {
      domain: definition.domain,
      family: definition.family,
      phase,
      cold_start_pending: pendingEntries.length > 0,
      cold_start_reason: pendingEntries.length > 0 ? stateReason(pendingEntries[0], groups) : undefined,
      complete_ticks: Math.min(...runs.map((run) => progressForState(run.entry ? { ...run.entry, domain: definition.domain } : undefined, groups, inputs.nowMs))),
      required_ticks: STATUS_TICK_COUNT,
      established_count: establishedForDomain(definition.domain, points, groups).length,
      ...(hasIncompleteLatest(definition.domain, groups) ? { latest_census_incomplete: true } : {}),
      rules,
    };
  });
  return { families, domains };
}

function daemonRecordPayload(inputs) {
  if (inputs.disabled) return undefined;
  const { daemonRecord } = inputs;
  return {
    status: daemonRecord.status,
    ...(isValidTimestamp(daemonRecord.record?.ts) ? { ts: daemonRecord.record.ts } : {}),
    structural_interval_ms: inputs.structuralIntervalMs,
    structural_interval_source: inputs.structuralIntervalSource,
    ...(daemonRecord.record?.fact_store_legacy ? { fact_store_legacy: daemonRecord.record.fact_store_legacy } : {}),
    ...(Array.isArray(daemonRecord.record?.fact_store_deprecations) ? { fact_store_deprecations: daemonRecord.record.fact_store_deprecations } : {}),
    note: DAEMON_RECORD_NOTE,
  };
}

export async function buildBaselineStatus(descartesPaths, options = {}) {
  const inputs = await readBaselineInputs(descartesPaths, options);
  const { families, domains } = buildDomainReports(inputs);
  const daemon = daemonRecordPayload(inputs);
  return {
    watch_config: configPayload(inputs.config, descartesPaths),
    domains,
    families,
    ...(daemon ? { daemon_record: daemon } : {}),
    fact_history_window_ms: options.windowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS,
    note: LIVE_RECOMPUTE_NOTE,
  };
}

export async function buildBaselineInspect(descartesPaths, options = {}) {
  const requested = options.domain ? normalizeDomainName(options.domain) : undefined;
  if (requested && !DOMAIN_DEFINITIONS.some((definition) => definition.domain === requested)) {
    throw new Error(`Unknown baseline domain: ${options.domain}\n\n${usage()}`);
  }
  const inputs = await readBaselineInputs(descartesPaths, options);
  const { families, domains: statusDomains } = buildDomainReports(inputs);
  const selected = inputs.domains.filter(({ definition }) => !requested || definition.domain === requested);
  const domains = selected.map(({ definition, groups, points }) => {
    const status = statusDomains.find((domain) => domain.domain === definition.domain);
    const established = inputs.disabled ? [] : establishedForDomain(definition.domain, points, groups);
    const report = {
      domain: definition.domain,
      phase: status.phase,
      rules: status.rules,
      established,
      established_count: established.length,
      complete_ticks: completeGroups(definition.domain, groups).length,
      ...(families[definition.family] ? { history: families[definition.family] } : {}),
    };
    if (definition.domain === "session" || definition.domain === "peer") {
      report.baseline = statisticalBaseline(definition.domain, groups);
    }
    return report;
  });
  return {
    watch_config: configPayload(inputs.config, descartesPaths),
    domains,
    recomputed_live: true,
    fact_history_window_ms: options.windowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS,
    note: LIVE_RECOMPUTE_NOTE,
  };
}

function renderFamilyLine(family) {
  if (!family) return undefined;
  if (family.store === "absent") return "  history: not observed (no store)";
  const parts = [`history: ${family.status}, coverage ${family.coverage}`];
  if (family.certified_after_ts) parts.push(`certified after ${family.certified_after_ts}`);
  if (family.seen_set) {
    parts.push(family.seen_set.status === "valid"
      ? `novelty memory certified ${family.seen_set.certified_since_ts ? `since ${family.seen_set.certified_since_ts}` : "since the store began"}`
      : `novelty memory ${family.seen_set.status}`);
  }
  for (const flag of ["cap_below_tick", "retention_failing"]) if (family[flag]) parts.push(flag);
  if (family.budget_rejected) parts.push(`budget rejected (${family.budget_rejected.reason})`);
  return `  ${parts.join("; ")}`;
}

function renderStatus(report) {
  const lines = [`Structural watching: ${report.watch_config.enabled ? "enabled" : "disabled"}`];
  for (const domain of report.domains) {
    const reason = domain.cold_start_reason ? ` (${domain.cold_start_reason})` : "";
    lines.push(`- ${domain.domain}: ${domain.phase}${reason}`);
    if (report.watch_config.enabled) {
      for (const rule of domain.rules) {
        const extra = rule.reasons.length > 0 ? ` [${rule.reasons.join(", ")}]` : "";
        const count = rule.watching ? ` (${rule.evaluated_count} evaluated)` : "";
        lines.push(`    ${rule.rule_id}: ${rule.phase}${count}${extra}`);
      }
      const familyLine = renderFamilyLine(report.families?.[domain.family]);
      if (familyLine) lines.push(`    ${familyLine.trimStart()}`);
    }
  }
  if (report.daemon_record) {
    lines.push(report.daemon_record.status === "present"
      ? `Daemon status record: ${report.daemon_record.ts ?? "undated"}`
      : `Daemon status record: ${report.daemon_record.status}`);
    if (report.daemon_record.structural_interval_source !== "daemon_record") {
      lines.push(`  structural interval ${report.daemon_record.structural_interval_ms} ms (${report.daemon_record.structural_interval_source}); census freshness may differ from the daemon's`);
    }
    for (const deprecation of report.daemon_record.fact_store_deprecations ?? []) {
      lines.push(`  ${deprecation.source} ${deprecation.key}: ${deprecation.status}`);
    }
    if (report.daemon_record.fact_store_legacy?.status) lines.push(`  legacy fact store: ${report.daemon_record.fact_store_legacy.status}`);
  }
  lines.push(`Config path: ${report.watch_config.config_path}`);
  lines.push(report.note);
  return lines.join("\n");
}

function renderInspect(report) {
  const lines = ["Baseline inspect (recomputed live)"];
  for (const domain of report.domains) {
    const items = domain.established.length > 0 ? domain.established.join(", ") : "none";
    lines.push(`- ${domain.domain}: ${domain.phase}`);
    for (const rule of domain.rules ?? []) lines.push(`    ${rule.rule_id}: ${rule.phase}`);
    lines.push(`  Established (${domain.established.length}): ${items}`);
  }
  lines.push(report.note);
  return lines.join("\n");
}

export async function runBaseline(descartesPaths, args, runtime = {}) {
  const [subcommand = "status", ...rest] = args ?? [];
  const output = runtime.output ?? console.log;
  if (subcommand === "--help" || subcommand === "-h") {
    output(usage());
    return undefined;
  }
  if (!["status", "inspect", "enable", "disable"].includes(subcommand)) {
    throw new Error(`Unsupported baseline command: ${subcommand}\n\n${usage()}`);
  }
  const options = parseArgs(rest, subcommand);
  if (options.help) {
    output(usage());
    return undefined;
  }
  if (subcommand === "enable" || subcommand === "disable") {
    const existing = await loadWatchConfig(descartesPaths);
    const config = await writeWatchConfig(descartesPaths, { ...existing, enabled: subcommand === "enable" }, { now: runtime.now });
    const result = { watch_config: configPayload(config, descartesPaths) };
    output(options.json ? JSON.stringify(result, null, 2) : `Structural watching: ${config.enabled ? "enabled" : "disabled"}\nConfig path: ${result.watch_config.config_path}`);
    return result;
  }
  const report = subcommand === "status"
    ? await buildBaselineStatus(descartesPaths, { ...runtime, ...options })
    : await buildBaselineInspect(descartesPaths, { ...runtime, ...options });
  output(options.json ? JSON.stringify(report, null, 2) : subcommand === "status" ? renderStatus(report) : renderInspect(report));
  return report;
}
