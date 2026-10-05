import { readFactPoints } from "./fact-store.js";
import { alertId } from "./alert-store.js";
import {
  DEFAULT_BASELINE_FACT_WINDOW_MS,
} from "./welford-stats.js";
import {
  DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT,
  DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT,
  groupServiceFactsByTick,
  loadServiceAppearanceBaselineStore,
  loadServiceBaselineStore,
} from "./service-baseline.js";
import { factHistoryTrustworthy } from "./fact-store-completeness.js";
import {
  DEFAULT_MIN_SAMPLE_COUNT,
  DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT,
  computeWindowedSessionStats,
  evaluateSessionChurn,
  groupSessionFactsByTick,
  isSessionChurnObservationGroup,
  SESSION_CHURN_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  loadSessionBaselineStore,
} from "./session-baseline.js";
import {
  DEFAULT_PEER_MIN_HISTORY_TICK_COUNT,
  DEFAULT_PEER_MIN_SAMPLE_COUNT,
  PEER_SIGNATURE_INVALID,
  computeWindowedPeerDropStats,
  computeWindowedPeerStats,
  groupPeerFactsByTick,
  PEER_COUNT_DROP_RULE_ID,
  peerCountFingerprintForAvailabilitySignature,
  PEER_COUNT_SPIKE_RULE_ID,
  loadPeerBaselineStore,
} from "./peer-baseline.js";
import {
  DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT,
  groupScheduledJobFactsByTick,
  loadPersistenceBaselineStore,
} from "./persistence-baseline.js";
import {
  DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT,
  groupProcessLineageFactsByTick,
  loadProcessLineageBaselineStore,
} from "./process-lineage-baseline.js";
import {
  loadWatchConfig,
  resolveWatchStorePaths,
  writeWatchConfig,
} from "./watch-store.js";
import { coldStartEntryReason } from "./cold-start-reason.js";
import { readDaemonStatus } from "./history-store.js";

const STATUS_TICK_COUNT = 6;
const LIVE_RECOMPUTE_NOTE = "Answers are recomputed live from the fact-history window; they can differ slightly from the daemon's last tick.";

function usage() {
  return `Usage:
  descartes baseline status [--json]
  descartes baseline inspect [--domain <name>] [--json]
  descartes baseline enable [--json]
  descartes baseline disable [--json]

Domains: service, session, peer, scheduled-job, process-lineage.`;
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

function currentGroups(group, points, nowMs) {
  return group(points).filter((item) => {
    const timestamp = new Date(item.ts).getTime();
    return Number.isFinite(timestamp) && timestamp <= nowMs;
  });
}

function isComplete(domain, group) {
  if (domain === "peer") return !group.hasOverflow && group.availabilitySignature !== PEER_SIGNATURE_INVALID;
  if (domain === "session") return group.censusState === "complete" && !group.hasOverflow;
  return group.censusState === "complete";
}

function completeGroups(domain, groups) {
  return groups.filter((group) => isComplete(domain, group));
}

function hasIncompleteLatest(domain, groups) {
  return groups.length > 0 && !isComplete(domain, groups[groups.length - 1]);
}

function stateReason(entry, groups) {
  const storeLossThisTick = Boolean(entry.missing || entry.corrupt);
  // A1: a genuinely-read pending store carries its OWN recorded reason -- coldStartEntryReason is
  // the label chosen when a NEW entry is armed, and for a non-store-loss arming it always answers
  // "corrupt_facts", which would misreport e.g. a persisted "history_lost" lockout.
  if (!storeLossThisTick && typeof entry.state?.cold_start_reason === "string") return entry.state.cold_start_reason;
  return coldStartEntryReason({
    storeLossThisTick,
    persistedReason: entry.state?.cold_start_reason,
    currentGroups: groups,
  });
}

// A1 (2026-10 calibration review): `baseline status` used to report "watching" by counting
// post-anchor ticks alone, ignoring the gates the detectors actually apply -- e.g. session
// phase:"watching" with cold_start_pending:true while the detector reported evaluatedAlertKeys=[].
// The helpers below MIRROR (never alter) each detector's own gates, from the same fact-history
// window, stores and clock, so a domain says "watching" only when its detector would genuinely
// evaluate this tick: persisted lockout cleared, no lockout (re-)arming term, trustworthy history,
// fresh evidence, and the detector's own per-rule readiness.

// Mirrors the detectors' DEFAULT_*_FRESHNESS_FALLBACK_MS (3x the default 1h structural interval)
// when no daemon status record exists. A live daemon's persisted profile overrides this below.
export const DEFAULT_STATUS_FRESHNESS_MS = 3 * 60 * 60 * 1000;

const COMPLETENESS_LOSS_TIMESTAMP_FIELDS = [
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
  "last_future_fact_ts",
];

function isValidIsoTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(new Date(value).getTime());
}

// Same predicate every detector carries as hasCompletenessLossAfterAnchor.
function hasCompletenessLossAfterAnchor(readResult, anchorTs, nowMs) {
  const completeness = readResult?.completeness;
  if (!completeness || typeof completeness !== "object" || Array.isArray(completeness)) return false;
  const anchorMs = isValidIsoTimestamp(anchorTs) ? new Date(anchorTs).getTime() : -Infinity;
  const upperBoundMs = Number.isFinite(nowMs) ? nowMs : Infinity;
  return COMPLETENESS_LOSS_TIMESTAMP_FIELDS.some((field) => {
    const timestamp = completeness[field];
    if (timestamp === undefined || timestamp === null) return false;
    const timestampMs = new Date(timestamp).getTime();
    return !Number.isFinite(timestampMs) || (timestampMs > anchorMs && timestampMs <= upperBoundMs);
  });
}

// Mirrors the detectors' enteringColdStart / coldStartPendingThisTick terms for one store entry.
function detectorGate(entry, readResult, nowMs) {
  const state = entry.state ?? {};
  const pending = state.cold_start_pending !== false;
  const trust = factHistoryTrustworthy(readResult, { anchorTs: state.cold_start_since_ts, nowMs });
  const anchorMissingOrFuture = (pending && !isValidIsoTimestamp(state.cold_start_since_ts))
    || (isValidIsoTimestamp(state.cold_start_since_ts) && new Date(state.cold_start_since_ts).getTime() > nowMs);
  const lastFoldedWasFuture = isValidIsoTimestamp(state.last_folded_ts) && new Date(state.last_folded_ts).getTime() > nowMs;
  const factsCorrupt = Boolean(readResult?.corrupt_count);
  const storeLoss = entry.missing === true || entry.corrupt === true;
  const lossAfterAnchor = hasCompletenessLossAfterAnchor(readResult, state.cold_start_since_ts, nowMs);
  const wouldArm = factsCorrupt || storeLoss || anchorMissingOrFuture || lossAfterAnchor || lastFoldedWasFuture
    || (!pending && !trust.trust);
  let blockedReason;
  if (factsCorrupt) blockedReason = "corrupt_facts_this_tick";
  else if (lastFoldedWasFuture || (isValidIsoTimestamp(state.cold_start_since_ts) && new Date(state.cold_start_since_ts).getTime() > nowMs)) blockedReason = "clock_rollback";
  else if (!trust.trust) blockedReason = trust.reason;
  else if (lossAfterAnchor) blockedReason = "history_degraded";
  return { pending, wouldArm, trust, blockedReason };
}

// Live re-accumulation progress of a pending lockout: complete ticks strictly after its anchor
// (what the detector itself counts). A lockout the detector would re-arm this tick restarts at 0.
function lockoutProgress(entry, gate, domain, groups, nowMs) {
  if (gate.wouldArm) return 0;
  const anchor = new Date(entry.state.cold_start_since_ts).getTime();
  return completeGroups(domain, groups)
    .filter((group) => new Date(group.ts).getTime() > anchor && new Date(group.ts).getTime() <= nowMs)
    .length;
}

// The detector's own post-lockout readiness requirement, as { progress, required }.
function isFiniteFreshObservation(observation, nowMs, freshnessMs) {
  return Boolean(observation)
    && Number.isFinite(observation.z_score)
    && Number.isFinite(observation.mean_before)
    && isValidIsoTimestamp(observation.ts)
    && nowMs - new Date(observation.ts).getTime() <= freshnessMs;
}

function sessionRuleReadiness(groups, points, nowMs, freshnessMs) {
  const baseline = computeWindowedSessionStats(groups);
  const countReady = baseline.confidence_state === "established"
    && isFiniteFreshObservation(baseline.last_observation, nowMs, freshnessMs);
  const completeGroupsForChurn = groups.filter((group) => group.censusState === "complete");
  const latestChurnGroup = completeGroupsForChurn.at(-1);
  const churnFresh = completeGroupsForChurn.length >= 2
    && latestChurnGroup
    && nowMs - new Date(latestChurnGroup.ts).getTime() <= freshnessMs;
  const churnObservationTimestamps = new Set(groups.filter(isSessionChurnObservationGroup).map((group) => group.ts));
  const churnPoints = points.filter((point) => churnObservationTimestamps.has(point.ts));
  const churn = churnFresh
    ? evaluateSessionChurn(churnPoints, { structuralIntervalMs: freshnessMs / 3, activeFreshnessMs: freshnessMs })
    : { evaluatedEntityKeys: [] };
  const evaluatedAlertKeys = [];
  if (countReady) evaluatedAlertKeys.push(alertId(SESSION_COUNT_DROP_RULE_ID, "global"));
  for (const entityKey of churn.evaluatedEntityKeys) evaluatedAlertKeys.push(alertId(SESSION_CHURN_RULE_ID, entityKey));
  return {
    progress: baseline.stats.count,
    required: DEFAULT_MIN_SAMPLE_COUNT,
    established: baseline.confidence_state === "established",
    watchingRules: [
      ...(countReady ? [SESSION_COUNT_DROP_RULE_ID] : []),
      ...(churn.evaluatedEntityKeys.length > 0 ? [SESSION_CHURN_RULE_ID] : []),
    ],
    evaluatedAlertKeys,
  };
}

function peerRuleReadiness(groups, entries, nowMs, freshnessMs) {
  const spike = computeWindowedPeerStats(groups);
  const drop = computeWindowedPeerDropStats(groups);
  const currentFingerprint = peerCountFingerprintForAvailabilitySignature(groups.at(-1)?.availabilitySignature);
  const spikeReady = spike.confidence_state === "established" && isFiniteFreshObservation(spike.last_observation, nowMs, freshnessMs);
  const dropObservation = drop.last_observation;
  const anchorTs = entries[0]?.state?.cold_start_since_ts;
  const dropRecoveryReady = !isValidIsoTimestamp(anchorTs)
    || (isValidIsoTimestamp(dropObservation?.ts) && completeGroups("peer", groups).filter((group) => {
      const groupMs = new Date(group.ts).getTime();
      return dropTickGroupIsComplete(group)
        && groupMs > new Date(anchorTs).getTime()
        && groupMs < new Date(dropObservation.ts).getTime();
    }).length >= DEFAULT_PEER_MIN_HISTORY_TICK_COUNT);
  const dropReady = drop.confidence_state === "established"
    && dropRecoveryReady
    && isFiniteFreshObservation(dropObservation, nowMs, freshnessMs);
  return {
    progress: spike.stats.count,
    required: DEFAULT_PEER_MIN_SAMPLE_COUNT,
    established: spike.confidence_state === "established",
    watchingRules: [
      ...(spikeReady ? [PEER_COUNT_SPIKE_RULE_ID] : []),
      ...(dropReady ? [PEER_COUNT_DROP_RULE_ID] : []),
    ],
    evaluatedAlertKeys: [
      ...(spikeReady ? [alertId(PEER_COUNT_SPIKE_RULE_ID, currentFingerprint)] : []),
      ...(dropReady ? [alertId(PEER_COUNT_DROP_RULE_ID, currentFingerprint)] : []),
    ],
  };
}

function dropTickGroupIsComplete(group) {
  return !group.hasOverflow && group.availabilitySignature !== undefined && group.availabilitySignature !== PEER_SIGNATURE_INVALID;
}

function readinessFor(domain, groups, points = [], entries = [], nowMs = Date.now(), freshnessMs = DEFAULT_STATUS_FRESHNESS_MS) {
  if (domain === "session") {
    return sessionRuleReadiness(groups, points, nowMs, freshnessMs);
  }
  if (domain === "peer") {
    return peerRuleReadiness(groups, entries, nowMs, freshnessMs);
  }
  const required = domain === "service"
    ? DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT + 1 // the stricter of disappearance (2) and appearance (3 + 1)
    : domain === "scheduled-job"
      ? DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT + 1
      : DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT + 1;
  const progress = completeGroups(domain, groups).length;
  return { progress, required, established: progress >= required };
}

function phaseForRuleReadiness(domain, readiness) {
  if (readiness.watchingRules?.length > 0) {
    if (readiness.watchingRules.length === (domain === "session" ? 2 : 2)) return "watching";
    if (domain === "session" && readiness.watchingRules.includes(SESSION_CHURN_RULE_ID)) {
      return `watching (churn); count baseline still learning — ${readiness.progress} of ${readiness.required}`;
    }
    if (domain === "session") return `watching (count); churn has no fresh evaluable pair`;
    if (readiness.watchingRules.includes(PEER_COUNT_SPIKE_RULE_ID)) return "watching (spike); drop baseline is not evaluable";
    return "watching (drop); spike baseline is not evaluable";
  }
  return undefined;
}

function domainPhase({ enabled, entries, domain, groups, points = [], nowMs, readResult, freshnessMs = DEFAULT_STATUS_FRESHNESS_MS }) {
  if (!enabled) return { phase: "disabled", progress: 0, required: STATUS_TICK_COUNT, coldStartPending: false, coldStartReason: undefined, watchingRules: [], evaluatedAlertKeys: [] };
  const gated = entries.map((entry) => ({ entry, gate: detectorGate(entry, readResult, nowMs) }));
  const pendingEntries = gated.filter(({ gate }) => gate.pending);
  const coldStartPending = pendingEntries.length > 0;
  const blocked = gated.find(({ gate }) => gate.blockedReason !== undefined);
  const historyTrust = blocked ? blocked.gate.blockedReason : "ok";
  const base = {
    coldStartPending,
    coldStartReason: coldStartPending ? stateReason(pendingEntries[0].entry, groups) : undefined,
    historyTrust,
  };

  if (coldStartPending) {
    const progress = Math.min(...pendingEntries.map(({ entry, gate }) => lockoutProgress(entry, gate, domain, groups, nowMs)));
    // R2 (2026-10 calibration review): for the count rules (session/peer) the 30-sample count
    // baseline can be the BINDING requirement, not the 6-tick lockout. Each new complete tick
    // advances both, so show whichever has more ticks remaining (ties go to the lockout).
    if (domain === "session" || domain === "peer") {
      const readiness = readinessFor(domain, groups, points, entries, nowMs, freshnessMs);
      const countRemaining = readiness.required - readiness.progress;
      const lockoutRemaining = Math.max(0, STATUS_TICK_COUNT - progress);
      if (!readiness.established && countRemaining > lockoutRemaining) {
        return { ...base, phase: `still learning — ${readiness.progress} of ${readiness.required}`, progress: readiness.progress, required: readiness.required };
      }
    }
    if (progress < STATUS_TICK_COUNT) {
      return { ...base, phase: `still learning — ${progress} of ${STATUS_TICK_COUNT}`, progress, required: STATUS_TICK_COUNT };
    }
    // Enough post-anchor ticks, but the detector gates on the PRE-update store: the lockout clears
    // on its next tick and only the tick after that evaluates. Never "watching" while pending.
    const phase = historyTrust === "ok"
      ? `still learning — ${STATUS_TICK_COUNT} of ${STATUS_TICK_COUNT}, lockout clears on the next daemon tick`
      : `still learning — ${STATUS_TICK_COUNT} of ${STATUS_TICK_COUNT}, waiting for trustworthy fact history (${historyTrust})`;
    return { ...base, phase, progress: STATUS_TICK_COUNT, required: STATUS_TICK_COUNT };
  }

  if (gated.some(({ gate }) => gate.wouldArm)) {
    return { ...base, phase: `locked out — fact history untrustworthy (${historyTrust})`, progress: 0, required: STATUS_TICK_COUNT };
  }

  if (domain !== "session" && domain !== "peer" && hasIncompleteLatest(domain, groups)) {
    return { ...base, phase: "cannot establish — census incomplete", progress: 0, required: STATUS_TICK_COUNT };
  }

  const complete = completeGroups(domain, groups);
  const latest = complete[complete.length - 1];
  const readiness = readinessFor(domain, groups, points, entries, nowMs, freshnessMs);
  const rulePhase = phaseForRuleReadiness(domain, readiness);
  if (!rulePhase && (!latest || !(nowMs - new Date(latest.ts).getTime() <= freshnessMs))) {
    const phase = latest
      ? `stale — latest complete census ${latest.ts} is older than the freshness window`
      : "stale — no complete census in the fact-history window";
    return { ...base, phase, progress: 0, required: STATUS_TICK_COUNT };
  }

  if (rulePhase) {
    return { ...base, phase: rulePhase, progress: readiness.progress, required: readiness.required, watchingRules: readiness.watchingRules, evaluatedAlertKeys: readiness.evaluatedAlertKeys };
  }
  if (!readiness.established) {
    return { ...base, phase: `still learning — ${readiness.progress} of ${readiness.required}`, progress: readiness.progress, required: readiness.required };
  }
  return { ...base, phase: "watching", progress: readiness.required, required: readiness.required, watchingRules: readiness.watchingRules ?? [], evaluatedAlertKeys: readiness.evaluatedAlertKeys ?? [] };
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
  const completeByTimestamp = new Map(completeGroups("peer", groups).map((group) => [group.ts, group]));
  return [...new Set(points
    .filter((point) => point?.fact_name === "peer.presence" && completeByTimestamp.has(point.ts))
    .filter((point) => !String(point.entity_key).includes("census-marker") && !String(point.entity_key).includes("overflow-marker"))
    // R8: Tailscale is excluded only when the tick carries the VPN census marker that cannot vouch
    // for it. Markerless Tailscale-only hosts are part of the legacy peer-count baseline.
    .filter((point) => point.attributes?.source_type !== "tailscale" || completeByTimestamp.get(point.ts).availabilitySignature === undefined)
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

const DOMAIN_DEFINITIONS = [
  {
    domain: "service",
    group: groupServiceFactsByTick,
    stores: [loadServiceBaselineStore, loadServiceAppearanceBaselineStore],
    required: DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT,
  },
  {
    domain: "session",
    group: groupSessionFactsByTick,
    stores: [loadSessionBaselineStore],
    required: DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT,
  },
  {
    domain: "peer",
    group: groupPeerFactsByTick,
    stores: [loadPeerBaselineStore],
    required: DEFAULT_PEER_MIN_HISTORY_TICK_COUNT,
  },
  {
    domain: "scheduled-job",
    group: groupScheduledJobFactsByTick,
    stores: [loadPersistenceBaselineStore],
    required: DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT,
  },
  {
    domain: "process-lineage",
    group: groupProcessLineageFactsByTick,
    stores: [loadProcessLineageBaselineStore],
    required: DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT,
  },
];

function normalizeDomainName(value) {
  return value === "scheduled_job" ? "scheduled-job" : value;
}

async function readBaselineInputs(descartesPaths, options) {
  const nowMs = nowMsOf(options);
  const read = options.readFactPoints ?? readFactPoints;
  const readResult = await read(descartesPaths, {
    windowMs: options.windowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS,
    now: options.now,
  });
  const points = readResult?.points ?? [];
  const config = await (options.loadWatchConfig ?? loadWatchConfig)(descartesPaths);
  const domains = await Promise.all(DOMAIN_DEFINITIONS.map(async (definition) => {
    const groups = currentGroups(definition.group, points, nowMs);
    const entries = await Promise.all(definition.stores.map(async (loadStore) => ({
      ...(await loadStore(descartesPaths)),
      domain: definition.domain,
    })));
    return { definition, groups, entries };
  }));
  return { config, points, readResult, domains, nowMs };
}

function domainPhaseFor(inputs, { definition, groups, entries }, options) {
  return domainPhase({
    enabled: inputs.config.enabled,
    entries,
    domain: definition.domain,
    groups,
    points: inputs.points,
    nowMs: inputs.nowMs,
    readResult: inputs.readResult,
    freshnessMs: options.activeFreshnessMs ?? DEFAULT_STATUS_FRESHNESS_MS,
  });
}

async function resolveStatusFreshnessMs(descartesPaths, options) {
  if (options.activeFreshnessMs !== undefined) return options.activeFreshnessMs;
  const status = await (options.readDaemonStatus ?? readDaemonStatus)(descartesPaths);
  const structuralIntervalMs = status?.profile?.structural?.interval_ms;
  return Number.isFinite(structuralIntervalMs) && structuralIntervalMs > 0
    ? 3 * structuralIntervalMs
    : DEFAULT_STATUS_FRESHNESS_MS;
}

function configPayload(config, descartesPaths) {
  return { ...config, config_path: resolveWatchStorePaths(descartesPaths).configFile };
}

export async function buildBaselineStatus(descartesPaths, options = {}) {
  const freshnessMs = await resolveStatusFreshnessMs(descartesPaths, options);
  const inputs = await readBaselineInputs(descartesPaths, { ...options, activeFreshnessMs: freshnessMs });
  return {
    watch_config: configPayload(inputs.config, descartesPaths),
    domains: inputs.domains.map(({ definition, groups, entries }) => {
      const phase = domainPhaseFor(inputs, { definition, groups, entries }, { ...options, activeFreshnessMs: freshnessMs });
      return {
        domain: definition.domain,
        phase: phase.phase,
        cold_start_pending: phase.coldStartPending,
        cold_start_reason: phase.coldStartReason,
        history_trust: phase.historyTrust,
        complete_ticks: phase.progress,
        required_ticks: phase.required,
        established_count: establishedForDomain(definition.domain, inputs.points, groups).length,
        watching_rules: phase.watchingRules ?? [],
        evaluated_alert_keys: phase.evaluatedAlertKeys ?? [],
      };
    }),
    fact_history_window_ms: options.windowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS,
    note: LIVE_RECOMPUTE_NOTE,
  };
}

export async function buildBaselineInspect(descartesPaths, options = {}) {
  const freshnessMs = await resolveStatusFreshnessMs(descartesPaths, options);
  const inputs = await readBaselineInputs(descartesPaths, { ...options, activeFreshnessMs: freshnessMs });
  const requested = options.domain ? normalizeDomainName(options.domain) : undefined;
  if (requested && !DOMAIN_DEFINITIONS.some((definition) => definition.domain === requested)) {
    throw new Error(`Unknown baseline domain: ${options.domain}\n\n${usage()}`);
  }
  const selected = inputs.domains.filter(({ definition }) => !requested || definition.domain === requested);
  const domains = selected.map(({ definition, groups, entries }) => {
    const phase = domainPhaseFor(inputs, { definition, groups, entries }, { ...options, activeFreshnessMs: freshnessMs });
    const report = {
      domain: definition.domain,
      phase: phase.phase,
      established: inputs.config.enabled ? establishedForDomain(definition.domain, inputs.points, groups) : [],
      established_count: inputs.config.enabled ? establishedForDomain(definition.domain, inputs.points, groups).length : 0,
      complete_ticks: completeGroups(definition.domain, groups).length,
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

function renderStatus(report) {
  const lines = [`Structural watching: ${report.watch_config.enabled ? "enabled" : "disabled"}`];
  for (const domain of report.domains) {
    const reason = domain.cold_start_reason && !domain.phase.includes(`(${domain.cold_start_reason})`) ? ` (${domain.cold_start_reason})` : "";
    lines.push(`- ${domain.domain}: ${domain.phase}${reason}`);
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
