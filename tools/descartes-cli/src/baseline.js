import { readFactPoints } from "./fact-store.js";
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
import {
  DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT,
  computeWindowedSessionStats,
  groupSessionFactsByTick,
  loadSessionBaselineStore,
} from "./session-baseline.js";
import {
  DEFAULT_PEER_MIN_HISTORY_TICK_COUNT,
  PEER_SIGNATURE_INVALID,
  computeWindowedPeerDropStats,
  computeWindowedPeerStats,
  groupPeerFactsByTick,
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
  return coldStartEntryReason({
    storeLossThisTick: Boolean(entry.missing || entry.corrupt),
    persistedReason: entry.state?.cold_start_reason,
    currentGroups: groups,
  });
}

function progressForState(entry, groups, nowMs) {
  if (!entry.state?.cold_start_pending) return STATUS_TICK_COUNT;
  const anchor = entry.state.cold_start_since_ts ? new Date(entry.state.cold_start_since_ts).getTime() : undefined;
  if (!Number.isFinite(anchor)) return 0;
  return Math.min(STATUS_TICK_COUNT, completeGroups(entry.domain, groups)
    .filter((group) => new Date(group.ts).getTime() > anchor && new Date(group.ts).getTime() <= nowMs)
    .length);
}

function domainPhase({ enabled, entries, domain, groups, nowMs }) {
  if (!enabled) return { phase: "disabled", progress: 0, coldStartPending: false, coldStartReason: undefined };
  const pendingEntries = entries.filter((entry) => entry.state?.cold_start_pending);
  const primary = pendingEntries[0] ?? entries[0];
  const progress = pendingEntries.length === 0
    ? STATUS_TICK_COUNT
    : Math.min(...pendingEntries.map((entry) => progressForState({ ...entry, domain }, groups, nowMs)));
  const incomplete = hasIncompleteLatest(domain, groups);
  const phase = incomplete
    ? "cannot establish — census incomplete"
    : progress >= STATUS_TICK_COUNT
      ? "watching"
      : `still learning — ${progress} of ${STATUS_TICK_COUNT}`;
  return {
    phase,
    progress,
    coldStartPending: pendingEntries.length > 0,
    coldStartReason: pendingEntries.length > 0 ? stateReason(primary, groups) : undefined,
  };
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
    // R8: tailscale peers are not part of the peer-count baseline (groupPeerFactsByTick excludes
    // them), so they must not be listed as established for it either.
    .filter((point) => point.attributes?.source_type !== "tailscale")
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

function configPayload(config, descartesPaths) {
  return { ...config, config_path: resolveWatchStorePaths(descartesPaths).configFile };
}

export async function buildBaselineStatus(descartesPaths, options = {}) {
  const inputs = await readBaselineInputs(descartesPaths, options);
  return {
    watch_config: configPayload(inputs.config, descartesPaths),
    domains: inputs.domains.map(({ definition, groups, entries }) => {
      const phase = domainPhase({ enabled: inputs.config.enabled, entries, domain: definition.domain, groups, nowMs: inputs.nowMs });
      return {
        domain: definition.domain,
        phase: phase.phase,
        cold_start_pending: phase.coldStartPending,
        cold_start_reason: phase.coldStartReason,
        complete_ticks: phase.progress,
        required_ticks: STATUS_TICK_COUNT,
        established_count: establishedForDomain(definition.domain, inputs.points, groups).length,
      };
    }),
    fact_history_window_ms: options.windowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS,
    note: LIVE_RECOMPUTE_NOTE,
  };
}

export async function buildBaselineInspect(descartesPaths, options = {}) {
  const inputs = await readBaselineInputs(descartesPaths, options);
  const requested = options.domain ? normalizeDomainName(options.domain) : undefined;
  if (requested && !DOMAIN_DEFINITIONS.some((definition) => definition.domain === requested)) {
    throw new Error(`Unknown baseline domain: ${options.domain}\n\n${usage()}`);
  }
  const selected = inputs.domains.filter(({ definition }) => !requested || definition.domain === requested);
  const domains = selected.map(({ definition, groups, entries }) => {
    const phase = domainPhase({ enabled: inputs.config.enabled, entries, domain: definition.domain, groups, nowMs: inputs.nowMs });
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
    const reason = domain.cold_start_reason ? ` (${domain.cold_start_reason})` : "";
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
