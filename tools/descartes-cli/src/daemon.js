import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { promisify } from "node:util";
import { adjudicateAlertNotifications, deliverDueAlertNotifications, emitMetricAlertFallbackSignals, emitSessionAlertSignals, readAlertIntelligenceConfig } from "./alert-intelligence.js";
import { alertId, evaluateAndPersistAlerts, fixedAlertIds, FIXED_ALERT_RULE_IDS, readAlertRecords, RETENTION_FAILURE_RULE_ID } from "./alert-store.js";
import { evaluateConstraints } from "./constraint-eval.js";
import { loadConstraints, loadLearnedConfig, selectFamilyFactStoreCompleteness } from "./constraint-store.js";
import { loadWatchConfig } from "./watch-store.js";
import { appendFactPointsByFamily, factStoreFileBytes, readFactPoints } from "./fact-store.js";
import { factHistoryTrustworthy, ruleEligible } from "./fact-store-completeness.js";
import { combineFamilyCompleteness } from "./fact-store-integrity.js";
import { migrateLegacyFactStore } from "./fact-store-migration.js";
import {
  FACT_FAMILY_IDS,
  FAMILY_DEFAULT_BUDGET_BYTES,
  FAMILY_TICK_SHAPES,
  familyBudgetCeilingBytes,
  familyBudgetFloorBytes,
  MIN_STRUCTURAL_INTERVAL_MS,
  HISTORY_HORIZON_SHORT_ALERT_TICKS,
  NOVELTY_FAMILIES,
  readerFamilies,
  resolveFactStoreBudgets,
  RULE_HORIZONS,
} from "./fact-families.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";
import {
  factPointsFromNetworkEvidence,
  factPointsFromCanaryEvidence,
  factPointsFromProcessLineageEvidence,
  factPointsFromScheduledJobsEvidence,
  factPointsFromServiceEvidence,
  factPointsFromSessionEvidence,
  factPointsFromTailscaleStatusEvidence,
  factPointsFromVpnPeerEvidence,
} from "./fact-translators.js";
import { computeCorrelationCandidates, CORRELATION_RULE_ID } from "./incident-correlation.js";
import { computePeerBaselineCandidates, PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "./peer-baseline.js";
import {
  computeServiceAppearanceCandidates,
  computeServiceBaselineCandidates,
  SERVICE_APPEARED_RULE_ID,
  SERVICE_DISAPPEARED_RULE_ID,
} from "./service-baseline.js";
import { computeProcessLineageBaselineCandidates, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID } from "./process-lineage-baseline.js";
import { computeSessionBaselineCandidates, SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID } from "./session-baseline.js";
import { computeCanaryBaselineCandidates, CANARY_TAMPERED_RULE_ID, CANARY_TRIPPED_RULE_ID } from "./canary-baseline.js";
import { loadCanaryManifest } from "./canary-manifest.js";
import { computeScheduledJobBaselineCandidates, SCHEDULED_JOB_APPEARED_RULE_ID } from "./persistence-baseline.js";
import { computeCredentialAccessCandidates, CREDENTIAL_ACCESS_RULE_ID } from "./credential-access-baseline.js";
import { computeContainmentRecommendationCandidates, containmentRecommendationRuleIds } from "./containment-recommend.js";
import { buildShadowFactLookup, evaluateAndLogShadowConstraints } from "./shadow-store.js";
import { appendMetricPoints, parseDurationMs, readDaemonStatus, writeDaemonStatus } from "./history-store.js";
import { collectDiskEvidence } from "./tools/disks.js";
import { collectNetworkEvidence } from "./tools/network.js";
import { collectProcessEvidence, collectProcessLineageEvidence } from "./tools/processes.js";
import { computeProvenanceIdentityCandidates } from "./tools/provenance-identity.js";
import { IDENTITY_DRIFT_RULE_ID, NEW_PUBLIC_BIND_RULE_ID, UNKNOWN_IDENTITY_RULE_ID } from "./provenance-store.js";
import {
  collectProvenanceWarningsEvidence,
  computeProvenanceWarningCandidates,
  DELETED_EXE_RULE_ID,
  provenanceWarningFactPoints,
  PUBLIC_BIND_RULE_ID,
} from "./tools/provenance-warnings.js";
import { collectScheduledJobsEvidence } from "./tools/scheduled-jobs.js";
import { collectServiceEvidence } from "./tools/services.js";
import { collectSessionEvidence } from "./tools/sessions.js";
import { collectSystemEvidence } from "./tools/system.js";
import { collectTailscaleStatusEvidence } from "./tools/tailscale-status.js";
import { collectVpnPeerStatusEvidence } from "./tools/vpn-peer-status.js";
import { collectCanaryEvidence } from "./tools/canary.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_DAEMON_INTERVAL_MS = 60 * 1000;
export const DEFAULT_DAEMON_PROCESS_LIMIT = 5;
export const DEFAULT_STRUCTURAL_INTERVAL_MS = 60 * 60 * 1000;
export const DEFAULT_STRUCTURAL_TICK_DEADLINE_MS = 45 * 1000;
const LEGACY_CONTENT_PIN_FILE = "binary-content-pins.json";
// Slice B (Codex-hardening): a structural fact (service.presence / network.listening_port.owner)
// unobserved for more than this many STRUCTURAL cycles is treated as stale ("no live claim") by the
// active + shadow-soak constraint eval, instead of reading its last value as current for up to the
// 30-day fact-retention window. 3× the structural interval (default 3h) tolerates a couple of
// missed/slow structural ticks before a constraint stops evaluating. Pinned to the STRUCTURAL
// interval, NEVER the fast tick — those facts only refresh on the structural cadence.
export const ACTIVE_FRESHNESS_MULTIPLE = 3;

// Fix 3 (trusted-state step-1 revision, "R1 made signable"): the rule_ids of every alert family
// whose EMISSION is gated on factHistoryTrustworthy (i.e. would fall silent -- not merely stay
// quiet on genuinely-clean evidence -- whenever this tick's fact-history is untrustworthy).
// Verified by direct read of each source file, not grep alone (see the revision's own doc):
// canary-baseline.js's non-trip paths only (coldStartPendingThisTick, driven by
// !historyTrust.trust) -- R4/A1 exempts genuine canary.tripped trips from this lockout, so
// CANARY_TRIPPED_RULE_ID is deliberately NOT in this set; incident-correlation.js;
// peer-baseline.js; persistence-baseline.js; process-lineage-baseline.js; service-baseline.js
// (both disappearance and appearance); session-baseline.js.
//
// CANARY_TAMPERED_RULE_ID is included WHOLESALE (operator-accepted decision, plan's
// open_decisions): it is shared between one history-gated reason (canary_vanished) and two
// non-history-gated tamper reasons (manifest_unreadable, isolated entity). Including it wholesale
// freezes those two legitimate reasons too during a history-degraded tick (fail-stuck, bounded,
// acceptable per doctrine) rather than leaving canary_vanished's own fabricated-recovery gap open.
//
// constraint.violation.* (per-constraint, dynamic rule_ids from constraint-eval.js) is
// deliberately NOT enumerated here -- active-constraint evaluation does not gate on
// factHistoryTrustworthy at all (computeActiveConstraintCandidates's own doc comment: "no
// completeness gate needed... already follows 'no fact, no claim'"), so it must stay eligible
// for recovery regardless of this tick's fact-history trust. Under detector-reported coverage
// (§8) the covered set (computeCoveredAlerts below) is identity-keyed, and constraint.violation.*
// is a dynamic, NON-coverage-subject family (it has no owner in SECURITY_RULE_OWNERSHIP): it keeps
// its existing recovery semantics (subject only to the §7.7 vetoes), precisely so a dynamic
// non-history-gated rule_id like this is never wrongly frozen.
export const HISTORY_DEPENDENT_ALERT_RULE_IDS = new Set([
  SERVICE_DISAPPEARED_RULE_ID,
  SERVICE_APPEARED_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  SESSION_CHURN_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  PEER_COUNT_DROP_RULE_ID,
  PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
  SCHEDULED_JOB_APPEARED_RULE_ID,
  CORRELATION_RULE_ID,
  CANARY_TAMPERED_RULE_ID,
]);

// Fact-store capacity plan §4.3 / I7 (step S3): every history-dependent rule must have a
// fact-families.js registry entry (families + eligibility horizon), and the registry must name no
// rule this set does not. The registry is a leaf module and can only hold string literals, so this
// check -- against the set built from the detectors' own exported constants -- is also what catches
// a registry literal that has drifted from its constant. Throws at module init, like the
// duplicate-owner throw in SECURITY_RULE_OWNERSHIP below.
for (const ruleId of HISTORY_DEPENDENT_ALERT_RULE_IDS) {
  if (!RULE_HORIZONS.has(ruleId)) throw new Error(`fact-families registry has no horizon entry for history-dependent rule ${ruleId}`);
}
for (const ruleId of RULE_HORIZONS.keys()) {
  if (!HISTORY_DEPENDENT_ALERT_RULE_IDS.has(ruleId)) throw new Error(`fact-families registry names ${ruleId}, which is not a history-dependent rule`);
}

// BLOCKER-3 (daybreak-blue re-gate round 2, the root of the class -- subsumes BLOCKER-1/BLOCKER-2):
// global `historyTrust` alone is not enough to authorize recovery. A detector can short-circuit to
// [] for a reason ORTHOGONAL to history trust: its OWNING tier (watch.json or learned.json) is
// disabled this tick. Two real reproductions, BOTH with INTACT (trustworthy) history:
//   - watch:true, learned:false (the DEFAULT population): correlation/canary.tampered's detectors
//     are learned-gated and short-circuit; the watch-enabled history read is trustworthy, so
//     (pre-§8, when computeCoveredRuleIds early-returned undefined = unrestricted) their absent
//     candidates got fabricated-"recovered", even though those detectors never actually evaluated
//     this tick. (Post-§8 detector-reported coverage also freezes these by default; this
//     tier-ownership veto is now the §7.7 defense-in-depth layer, not the sole protection.)
//   - watch:false, learned:true: the six watch-gated detectors short-circuit; learned-on makes the
//     shared read trustworthy and (via containment) defeats the early return, but the resulting
//     exclusion set only ever covered containment.recommend.* -- none of the six watch-owned
//     families -- so they stay "covered" and get fabricated-"recovered" too.
// The fix: partition HISTORY_DEPENDENT_ALERT_RULE_IDS by which tier's detector actually owns each
// rule_id, and ALWAYS exclude a tier's families from recovery whenever that tier is disabled --
// independent of global history trust. A family is recovery-eligible only if its owning tier's
// detector genuinely ran this tick (never fabricate: silence from a disabled tier is not a clear).
//
// BLOCKER-1 (daybreak-blue re-gate, this slice) — the tier veto is now derived DIRECTLY from the
// COMPLETE SECURITY_RULE_OWNERSHIP registry (via tierVetoedRuleIds() at both persistence passes),
// NOT from these two history-dependent-only sets. These two sets remain the SOURCE OF TRUTH for the
// registry's `tier` column (WATCH_OWNED here -> "watch", everything else -> "author"), but the veto
// itself now spans EVERY registry-owned rule, including the positive-evidence AUTHOR rules
// (canary.tripped, credential.access) and provenance families these sets never named. See
// tierVetoedRuleIds()'s own doc comment for how it subsumes these sets. WATCH_OWNED_ is still the
// canonical membership test a future watch-gated rule must be added to (or it defaults to AUTHOR and
// over-freezes when learned is off). AUTHOR_OWNED_ is retained (still exported; daemon.test.js pins
// it) as the documented history-dependent AUTHOR pair, though the registry no longer consults it
// directly (its members resolve to "author" via the not-watch default).
export const WATCH_OWNED_HISTORY_DEPENDENT_RULE_IDS = new Set([
  SERVICE_DISAPPEARED_RULE_ID,
  SERVICE_APPEARED_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  SESSION_CHURN_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  PEER_COUNT_DROP_RULE_ID,
  PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
  SCHEDULED_JOB_APPEARED_RULE_ID,
]);
export const AUTHOR_OWNED_HISTORY_DEPENDENT_RULE_IDS = new Set([
  CORRELATION_RULE_ID,
  CANARY_TAMPERED_RULE_ID,
]);

// Component D (trusted-state step-1, §7): an honest, truthful integrity-mode LABEL, not a trust
// decision. "unprotected_same_uid" means Descartes provides no independent protection against
// modification of its own state (facts.jsonl, integrity.json, daemon-status.json, constraints,
// canary manifest, ...) by any process running under the same UID as Descartes itself -- same-UID
// write access is, today, unconditionally trusted. It LOWERS the implied assurance (states the
// mode is unprotected); it can never over-claim. Future rungs this enum is expected to grow into
// as later phases land real protection (none implemented yet, none implied by this value):
// "protected_local" (privilege-separated service UID / minimal daemon, threat-model step 2),
// "witnessed" (authenticated ledger / witness, threat-model steps 3-4), and beyond that
// interactive-hardware-approval and full attestation (threat-model steps 5-6, out of scope --
// see plan §12). Consulted by NO trust-decision code path anywhere in this codebase -- it is
// display/disclosure only, exactly like the completeness coverage fields (fact-store-integrity.js). Do not
// add a branch (`=== INTEGRITY_LEVEL_UNPROTECTED_SAME_UID` or any other comparison) that gates
// trust, suppression, recovery, promotion, or alerting on this value; the only permitted use is
// unconditionally including it verbatim on an operator-visible status surface.
export const INTEGRITY_LEVEL_UNPROTECTED_SAME_UID = "unprotected_same_uid";

export function defaultDaemonProfile() {
  return {
    interval_ms: DEFAULT_DAEMON_INTERVAL_MS,
    collectors: {
      system: { enabled: true },
      processes: { enabled: true, limit: DEFAULT_DAEMON_PROCESS_LIMIT },
      disks: { enabled: true },
    },
    structural: {
      interval_ms: DEFAULT_STRUCTURAL_INTERVAL_MS,
      collectors: {
        services: { enabled: true },
        network: { enabled: true },
        "scheduled-jobs": { enabled: true },
        // Slice S4: default true, matching its siblings exactly. Watch-by-default slice 1
        // (§3.2/§12): the outer gate for this whole structural tick is now configDir/watch.json's
        // WATCH flag, which itself defaults enabled:true -- so this sub-collector runs by default
        // on a fresh install too (that is the point of this slice), not merely "byte-identical
        // because the gate was off". configDir/learned.json (AUTHOR) is unaffected. See plan
        // section 4 and docs/plans/2026-09-10-watch-by-default-slice-1.md.
        provenance: { enabled: true },
        // Slice 1 (observed-incident collectors plan): default true, matching its siblings
        // exactly. Runs under the same default-ON watch.json gate as the rest of the structural
        // tick (watch-by-default slice 1, §3.2/§12). Pure read-only L0 fact source (tmux/screen
        // census) — this slice emits NO alert candidates (no extraCandidates addition below; see
        // docs/plans/2026-07-13-observed-incident-collectors.md Slice 1). Alerting on
        // session-count deviation/churn is Slice 4's job (and, per watch-by-default slice 1 §11
        // #1, that alerting itself now also runs under the default-ON watch.json gate).
        sessions: { enabled: true },
        // Slice 3 (observed-incident collectors plan): default true, matching its siblings
        // exactly — same outer watch.json gate (watch-by-default slice 1, §3.2/§12), same
        // structural-tick deadline/discard discipline. Pure read-only L0 fact source (SSH/VPN peer
        // census) — this slice ALSO emits NO alert candidates (no extraCandidates addition below;
        // see docs/plans/2026-07-13-observed-incident-collectors.md Slice 3's Alert-emission scope
        // decision, RESOLVED option 1). Alerting on unattributed/odd-hour peer logins is Slice
        // 4/6's job (also now watch-gated, §11 #1).
        "vpn-peer-status": { enabled: true },
        // Pure read-only Tailscale/tailnet L0 fact source, default true under the same watch.json
        // gate and with no extraCandidates addition.
        "tailscale-status": { enabled: true },
        // Canary collection is default-enabled like the other read-only structural collectors,
        // but remains byte-identical for existing installations because an absent/empty manifest
        // produces no canary facts, regardless of watch.json's now-default-ON gate.
        canary: { enabled: true },
        "process-lineage": { enabled: true },
      },
    },
    safety: {
      read_only: true,
      background_llm_calls: false,
      telemetry: false,
      host_mutation: false,
    },
  };
}

function isPositiveFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Throws a descriptive Error on the first invalid/missing required field, mirroring
 * validateConstraint's throw-fast style. A profile that omits `structural` entirely is
 * valid (structural cadence disabled) — every existing bare {interval_ms, collectors}
 * profile literal remains accepted.
 */
export function validateDaemonProfile(profile) {
  if (!isPlainObject(profile)) throw new Error("Daemon profile must be an object");

  if (!isPositiveFiniteNumber(profile.interval_ms)) {
    throw new Error(`Daemon profile interval_ms must be a positive finite number, got: ${JSON.stringify(profile.interval_ms)}`);
  }
  if (!isPlainObject(profile.collectors)) {
    throw new Error("Daemon profile collectors must be an object");
  }

  if (profile.structural !== undefined) {
    const structural = profile.structural;
    if (!isPlainObject(structural)) {
      throw new Error("Daemon profile structural must be an object when present");
    }
    if (!isPositiveFiniteNumber(structural.interval_ms)) {
      throw new Error(`Daemon profile structural.interval_ms must be a positive finite number, got: ${JSON.stringify(structural.interval_ms)}`);
    }
    if (structural.interval_ms < MIN_STRUCTURAL_INTERVAL_MS) {
      throw new Error(`Daemon profile structural.interval_ms ${structural.interval_ms}ms is below ${MIN_STRUCTURAL_INTERVAL_MS}ms; required family budget floor exceeds the 4x budget ceiling`);
    }
    if (!isPlainObject(structural.collectors)) {
      throw new Error("Daemon profile structural.collectors must be an object when present");
    }
    if (structural.deadline_ms !== undefined && !isPositiveFiniteNumber(structural.deadline_ms)) {
      throw new Error(`Daemon profile structural.deadline_ms must be a positive finite number, got: ${JSON.stringify(structural.deadline_ms)}`);
    }
  }

  return true;
}

function metric({ ts, metric_name, dimensions = {}, value, unit, envelope, sensitivity = "operational" }) {
  return {
    ts,
    metric_name,
    dimensions,
    value,
    unit,
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity,
  };
}

function pushFinite(points, point) {
  if (Number.isFinite(Number(point.value))) points.push(point);
}

export function metricPointsFromEvidence(evidence, options = {}) {
  const ts = options.ts ?? new Date().toISOString();
  const points = [];

  const system = evidence.find((envelope) => envelope.id === "system-overview" && envelope.status === "ok");
  if (system) {
    const result = system.result ?? {};
    const [load1, load5, load15] = result.load_average ?? [];
    pushFinite(points, metric({ ts, metric_name: "system.load.1m", value: load1, unit: "load_average", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.load.5m", value: load5, unit: "load_average", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.load.15m", value: load15, unit: "load_average", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.cpu.count", value: result.cpu_count, unit: "count", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.memory.used_fraction", value: result.memory?.used_fraction, unit: "fraction", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.memory.free_bytes", value: result.memory?.free_bytes, unit: "bytes", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.swap.used_bytes", value: result.swap?.used_bytes, unit: "bytes", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.uptime_seconds", value: result.uptime_seconds, unit: "seconds", envelope: system }));
  }

  const processes = evidence.find((envelope) => envelope.id === "top-processes" && envelope.status === "ok");
  if (processes) {
    const topCpu = processes.result?.top_cpu ?? [];
    topCpu.forEach((process, index) => {
      const dimensions = { rank: index + 1, command: process.command ?? "unknown" };
      pushFinite(points, metric({ ts, metric_name: "process.cpu_percent", dimensions, value: process.cpu_percent, unit: "percent", envelope: processes, sensitivity: "process_identity" }));
    });
    const topMemory = processes.result?.top_memory ?? [];
    topMemory.forEach((process, index) => {
      const dimensions = { rank: index + 1, command: process.command ?? "unknown" };
      pushFinite(points, metric({ ts, metric_name: "process.memory_percent", dimensions, value: process.memory_percent, unit: "percent", envelope: processes, sensitivity: "process_identity" }));
      pushFinite(points, metric({ ts, metric_name: "process.rss_bytes", dimensions, value: process.rss_bytes, unit: "bytes", envelope: processes, sensitivity: "process_identity" }));
    });
  }

  const disks = evidence.find((envelope) => envelope.id === "disk-usage" && envelope.status === "ok");
  if (disks) {
    for (const filesystem of disks.result?.filesystems ?? []) {
      if (filesystem.pressure_relevant === false) continue;
      const dimensions = {
        mount_point: filesystem.mount_point,
        filesystem: filesystem.filesystem,
        classification: filesystem.classification,
      };
      pushFinite(points, metric({ ts, metric_name: "disk.used_fraction", dimensions, value: filesystem.used_fraction, unit: "fraction", envelope: disks, sensitivity: "path" }));
      pushFinite(points, metric({ ts, metric_name: "disk.available_bytes", dimensions, value: filesystem.available_bytes, unit: "bytes", envelope: disks, sensitivity: "path" }));
    }
    if (Array.isArray(disks.result?.inodes)) {
      for (const filesystem of disks.result.inodes) {
        if (filesystem.pressure_relevant === false) continue;
        const dimensions = {
          mount_point: filesystem.mount_point,
          filesystem: filesystem.filesystem,
          classification: filesystem.classification,
        };
        pushFinite(points, metric({ ts, metric_name: "disk.inode_used_fraction", dimensions, value: filesystem.used_fraction, unit: "fraction", envelope: disks, sensitivity: "path" }));
      }
    }
  }

  return points;
}

export async function collectDaemonEvidence(profile = defaultDaemonProfile(), collectors = {}, options = {}) {
  const activeCollectors = {
    system: collectors.system ?? collectSystemEvidence,
    processes: collectors.processes ?? collectProcessEvidence,
    disks: collectors.disks ?? collectDiskEvidence,
  };
  const collectorOptions = {
    ...options,
    trustedBinaryPaths: options.trustedBinaryPaths ?? [],
  };
  const evidence = [];
  if (profile.collectors.system?.enabled) evidence.push(await activeCollectors.system(collectorOptions));
  if (profile.collectors.processes?.enabled) evidence.push(await activeCollectors.processes({ limit: profile.collectors.processes.limit ?? DEFAULT_DAEMON_PROCESS_LIMIT, ...collectorOptions }));
  if (profile.collectors.disks?.enabled) evidence.push(await activeCollectors.disks(collectorOptions));
  return evidence;
}

/**
 * Sibling to collectDaemonEvidence for the slower structural (services/network/scheduled-jobs)
 * cadence — identical enabled-flag/injectable-collectors pattern, stable evidence ordering.
 */
export async function collectStructuralEvidence(structuralProfile = {}, collectors = {}, options = {}) {
  const activeCollectors = {
    services: collectors.services ?? collectServiceEvidence,
    network: collectors.network ?? collectNetworkEvidence,
    "scheduled-jobs": collectors["scheduled-jobs"] ?? collectScheduledJobsEvidence,
    // Slice S4, additive fourth structural sub-collector: gated identically to its siblings
    // (structuralProfile.collectors.provenance.enabled), on the same slow cadence, subject to
    // the same structural-tick deadline/discard discipline below. See plan section 4.
    provenance: collectors.provenance ?? collectProvenanceWarningsEvidence,
    // Slice 1 (observed-incident collectors plan), additive fifth structural sub-collector:
    // gated identically to its siblings (structuralProfile.collectors.sessions.enabled), on the
    // same slow cadence, subject to the same structural-tick deadline/discard discipline below.
    // Read-only tmux/screen census; NO alert candidates emitted by this slice.
    sessions: collectors.sessions ?? collectSessionEvidence,
    // Slice 3 (observed-incident collectors plan), additive sixth structural sub-collector:
    // gated identically to its siblings (structuralProfile.collectors["vpn-peer-status"].enabled),
    // on the same slow cadence, subject to the same structural-tick deadline/discard discipline
    // below. Read-only SSH/VPN peer census; NO alert candidates emitted by this slice either.
    "vpn-peer-status": collectors["vpn-peer-status"] ?? collectVpnPeerStatusEvidence,
    // Tailscale/tailnet sibling: pure read-only L0 fact source, no alert candidates.
    "tailscale-status": collectors["tailscale-status"] ?? collectTailscaleStatusEvidence,
    canary: collectors.canary ?? (() => collectCanaryEvidence([])),
    "process-lineage": collectors["process-lineage"] ?? collectProcessLineageEvidence,
  };
  const collectorOptions = {
    ...options,
    trustedBinaryPaths: options.trustedBinaryPaths ?? [],
  };
  const evidence = [];
  if (structuralProfile.collectors?.services?.enabled) evidence.push(await activeCollectors.services(collectorOptions));
  if (structuralProfile.collectors?.network?.enabled) evidence.push(await activeCollectors.network(collectorOptions));
  if (structuralProfile.collectors?.["scheduled-jobs"]?.enabled) evidence.push(await activeCollectors["scheduled-jobs"](collectorOptions));
  if (structuralProfile.collectors?.provenance?.enabled) evidence.push(await activeCollectors.provenance(collectorOptions));
  if (structuralProfile.collectors?.sessions?.enabled) evidence.push(await activeCollectors.sessions(collectorOptions));
  if (structuralProfile.collectors?.["vpn-peer-status"]?.enabled) evidence.push(await activeCollectors["vpn-peer-status"](collectorOptions));
  if (structuralProfile.collectors?.["tailscale-status"]?.enabled) evidence.push(await activeCollectors["tailscale-status"](collectorOptions));
  if (structuralProfile.collectors?.canary?.enabled) evidence.push(await activeCollectors.canary(collectorOptions));
  if (structuralProfile.collectors?.["process-lineage"]?.enabled) evidence.push(await activeCollectors["process-lineage"](collectorOptions));
  return evidence;
}

const STRUCTURAL_TICK_TIMED_OUT = Symbol("structural-tick-timed-out");

/**
 * Races `promise` against a `deadlineMs` timer. On timeout, resolves to `onTimeout()`'s result
 * instead — the original promise is left to settle on its own (never awaited further here); its
 * result, if any, is discarded by the caller. Always clears the timer so the timeout branch never
 * outlives the race.
 */
async function withDeadline(promise, deadlineMs, onTimeout) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), deadlineMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function structuralCheckpointDir(descartesPaths) {
  return daemonLogDir(descartesPaths);
}

/**
 * Daemon-loop-internal state, not a "learned" artifact — deliberately not folded into
 * daemon-status.json (that would grow every consumer of readDaemonStatus's round-trip).
 */
export function resolveStructuralCheckpointPath(descartesPaths) {
  return path.join(structuralCheckpointDir(descartesPaths), "structural-checkpoint.json");
}

/**
 * ENOENT-tolerant and corrupt-tolerant (mirrors history-store.js's corrupt-tolerance philosophy
 * even though this file is written atomically) — both cases are treated as "never run".
 */
export async function readStructuralCheckpoint(descartesPaths) {
  const file = resolveStructuralCheckpointPath(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { last_structural_run_ms: undefined };
    throw error;
  }
  try {
    const parsed = JSON.parse(contents);
    const value = Number(parsed?.last_structural_run_ms);
    return { last_structural_run_ms: Number.isFinite(value) ? value : undefined };
  } catch {
    return { last_structural_run_ms: undefined };
  }
}

/**
 * Atomic tmp+rename write (0o600 file / 0o700 dir), mirroring constraint-store.js's writers —
 * a torn checkpoint write could cause structural collection to run every tick forever. (Finding
 * F4: history-store.js's writeDaemonStatus now uses the same tmp+rename idiom too, closing what
 * used to be the one non-atomic write in this file's persistence path.)
 */
export async function writeStructuralCheckpoint(descartesPaths, checkpoint = {}) {
  const dir = structuralCheckpointDir(descartesPaths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = resolveStructuralCheckpointPath(descartesPaths);
  const record = {
    last_structural_run_ms: Number(checkpoint.last_structural_run_ms),
    updated_at: checkpoint.now ? new Date(checkpoint.now).toISOString() : new Date().toISOString(),
  };
  const tmpFile = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(record, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, file);
  return record;
}

/**
 * Slice S-live-1, additive: evaluates any `status:"active"` constraint against the latest
 * fact-history and returns alert-store candidate objects for evaluateAndPersistAlerts'
 * `extraCandidates` option (Slice 2). Gated by the same learned.json kill switch the S6a
 * structural tick uses (loadLearnedConfig(...).enabled) — checked independently here (rather
 * than reusing the structural block's own read) because this must run on every daemon tick,
 * not just on a structural-due tick: an already-collected fact must be able to fire an alert
 * without waiting for the next hourly structural collection.
 *
 * Two cheap short-circuits, both returning `[]` without further I/O, guarantee this tick's
 * alert output stays byte-identical to the pre-S-live-1 baseline:
 *   - learned is disabled (the default) -> `[]` immediately, no loadConstraints/readFactPoints.
 *   - learned is enabled but there is no `status:"active"` constraint -> `[]`, no readFactPoints.
 *
 * Reuses shadow-store.js's exported `buildShadowFactLookup` (not duplicated) so ACTIVE and
 * SHADOW evaluation reconstruct constraint targets identically, including excluding degraded
 * (owner_known:"false"/confidence:0) observations. `evaluateConstraints` itself already skips
 * any target whose lookup returns `undefined` ("no fact, no claim") and routes candidate
 * `diagnostics` through `sanitizeDiagnostics` — nothing further is needed here.
 */
async function computeActiveConstraintCandidates(descartesPaths, options) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const loadConstraintsFn = options.loadConstraints ?? loadConstraints;
  const { constraints } = await loadConstraintsFn(descartesPaths);
  const activeConstraints = constraints.filter((constraint) => constraint?.status === "active");
  if (activeConstraints.length === 0) return [];

  // Slice B (Codex-hardening): `activeFreshnessMs` is threaded in by runDaemonIteration (3× the
  // STRUCTURAL interval — never the fast tick — since service.presence/network facts only refresh
  // on the structural cadence). It bounds both the fact read and the lookup's staleness horizon, so
  // a service/port unobserved for >3 structural cycles stops reading "satisfied" and skips. Absent
  // (direct unit calls) → staleness off, read window unbounded, behaviour unchanged.
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const freshnessMs = options.activeFreshnessMs;
  const readFacts = options.readFactPoints ?? readFactPoints;
  // Slice 9 audit — no completeness gate needed: active evaluation uses present facts and
  // already follows "no fact, no claim"; daemon append/retention wiring only persists facts.
  // Pass the SAME resolved nowMs snapshot to the read window AND the lookup staleness — never a bare
  // options.now (undefined in the live loop), which would let readFactPoints take its own, strictly
  // later, Date.now() and exclude a fact that is fresh per this snapshot at the horizon edge.
  const { points } = await readFacts(descartesPaths, { families: readerFamilies("active_constraint"), windowMs: options.factWindowMs ?? freshnessMs, now: nowMs });
  const factLookup = buildShadowFactLookup(points, { now: nowMs, freshnessMs });
  return evaluateConstraints(activeConstraints, factLookup);
}

// S13 I/O hardening, residual crash path 5b (defense-in-depth): adjudicateAlertNotifications is
// now fail-closed at every internal I/O point (config read, budget-seed audit read, per-alert
// append + in-process latch, the pi-harness.js/notification-delivery.js dynamic imports -- see
// alert-intelligence.js's own documentation comment above that function), but this call site had
// NO try/catch up the stack at all: an unhandled rejection here would kill the daemon process
// (launchd/systemd would then restart it, crash-looping). This catch cannot itself break the
// total<=max_calls_per_hour budget invariant -- by the time anything could reach it, any admitted
// LLM call's audit write has already succeeded or already been handled by the mechanisms above.
async function safeAdjudicateAlertNotifications(adjudicate, descartesPaths, alerts, options) {
  try {
    return await adjudicate(descartesPaths, alerts, options);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`descartes: adjudicateAlertNotifications failed unexpectedly (${message}); skipping alert intelligence this tick`);
    return { status: "error", decisions: [], error: message };
  }
}

// docs/reviews/2026-09-04-daybreak-security-sweep.md, cross-cutting SURVIVABILITY finding: each
// detector/producer below is independent evidence about the host. Before this helper, the
// `mainExtraCandidates` build below (and, via the identical exposure, the separate
// computeContainmentRecommendationCandidates call and the emitSessionAlertSignals call site)
// awaited each producer in one array/expression -- so ANY one of them throwing (a bad fact-store
// read, a store file that slipped past its own module's corrupt-file tolerance, etc.) aborted the
// WHOLE build, blinding every OTHER detector for the entire tick. safeCandidates() isolates that:
// a thrown error degrades to `fallback` (logged, never silent) for THIS detector THIS tick only --
// every other producer still runs and still reaches evaluateAndPersistAlerts. `fallback` is always
// passed explicitly by every call site below (never defaulted): `[]` for the candidate-array
// producers, `undefined` for the emitSessionAlertSignals call site, matching its existing "no
// delivery this tick" shape. (Deliberately NOT a `fallback = []` default parameter -- a caller
// passing `undefined` explicitly, which the emitSessionAlertSignals site legitimately needs to do,
// would silently fall through to the default instead of getting `undefined` back.)
//
// Finding F4, additive: extended one layer earlier (persistence-before-evaluation) with a bare
// `undefined` fallback for writeStructuralCheckpoint (a checkpoint that doesn't advance this tick
// just retries next tick, already-tolerated). writeDaemonStatus is NOT wrapped with safeCandidates
// -- see its own handling below, which must preserve genuine collector-derived `state` rather than
// substitute a fallback record disconnected from what this tick actually observed.
//
// Finding F4-B1/F4-B2 (daybreak-blue CONFIRMED BLOCKER re-gate): the metric-persist
// (appendMetricPoints) and structural fact-persist (appendFactPoints) calls below are ALSO
// deliberately NOT wrapped with safeCandidates, for the same reason writeDaemonStatus isn't --
// safeCandidates logs a warning but DISCARDS the thrown error, so a genuine append failure could
// never reach this tick's own status.state/storage_write_error, and daemon.status.not_ok could
// never fire from it (the fabrication F4-B1 closes). Both persist calls use their own inline
// try/catch instead, degrading to the same honest `{ written_count: 0, retention: undefined }`
// shape on an append failure while preserving the error message for the status record built
// below.
//
// BLOCKER 1 re-gate (daybreak-blue CONFIRMED BLOCKER, fabricated alert recovery on detector
// FAILURE): degrading a throw to `fallback` (above) is correct for THIS tick's candidate build,
// but it also made a genuine exception indistinguishable from a genuine "nothing to report" clear
// downstream, at the coveredAlertIds/recovery boundary -- an exception is not evidence of absence.
// The optional `failedLabels` Set (passed by every call site whose family must be withheld from
// recovery on its own failure, never defaulted) records `label` here, at the exact moment the
// exception is caught, so the caller can exclude that family's rule_ids from coveredAlertIds
// afterwards. A caller that omits `failedLabels` (none currently do, but the parameter stays
// optional rather than required) simply does not participate in that exclusion.
//
// Detector-reported recovery coverage (§8.B): the optional 5th arg `evaluatedByLabel` (a
// Map<label, Set<alertId>>, passed only by the twelve fast-tick detector call sites that
// participate in coverage -- NOT by the structural-checkpoint / containment / delivery sites,
// which keep the 4-arg form and are unaffected) turns on shape-validation + coverage collection:
//   - a converted producer returns `{ candidates: [...], evaluatedAlertKeys: [...] }` -> the
//     candidates array is returned (spread as before) and its evaluatedAlertKeys are unioned into
//     this label's reported set (owner-scoped: only ever consulted for persisted alerts whose
//     rule_id this label owns, so a foreign key can never authorize another family's recovery);
//   - a BARE array (an unconverted producer's old shape) -> returned as-is, NO coverage reported
//     (its coverage-subject families therefore freeze -- fail-safe, never fabricate). A bare array
//     from a coverage-subject label warns (a not-yet-converted detector, flagged for the follow-up
//     slice); a bare array from a non-coverage-subject label (active-constraint) is that producer's
//     PERMANENT contract and does NOT warn;
//   - a PARTIAL object (a valid `candidates` array but a missing/non-array `evaluatedAlertKeys`) ->
//     the candidates array is SURFACED regardless (§7.4: coverage never suppresses a PRESENT
//     positive candidate) while NO coverage is reported (its coverage-subject families freeze) + a
//     warn (partial shape -- a producer whose coverage field is malformed but whose signal is real);
//   - any OTHER shape (candidates itself absent/not-an-array -- a bare non-array object, null, ...)
//     -> treated as the fallback (no candidates) + NO coverage + a warn (fail-safe on a producer
//     that surfaced nothing).
// A throw is unchanged: warn, record in failedLabels, return fallback (no coverage reported).
async function safeCandidates(label, produce, fallback, failedLabels, evaluatedByLabel) {
  let produced;
  try {
    produced = await produce();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[daemon] detector '${label}' failed this tick, degrading to no candidates: ${message}`);
    failedLabels?.add(label);
    return fallback;
  }
  // Call sites not participating in coverage keep today's exact behavior (return the produced value
  // verbatim), so the structural-checkpoint / containment / delivery sites are untouched.
  if (!evaluatedByLabel) return produced;
  if (Array.isArray(produced)) {
    if (isCoverageSubjectLabel(label)) {
      console.warn(`[daemon] detector '${label}' returned a bare candidate array (no coverage report); freezing its family's recovery this tick (fail-safe, pending producer conversion)`);
    }
    return produced;
  }
  // §7.4: coverage NEVER suppresses a PRESENT positive candidate. If `produced` is an object
  // carrying a valid `candidates` array, SURFACE that array regardless of the coverage field, and
  // collect coverage ONLY when `evaluatedAlertKeys` is ALSO a valid array. A partial shape
  // (candidates present but evaluatedAlertKeys missing/non-array) still surfaces the candidates
  // (never dropped) while reporting NO coverage (fail-safe freeze of that family's recovery) + warns.
  if (produced && typeof produced === "object" && Array.isArray(produced.candidates)) {
    if (Array.isArray(produced.evaluatedAlertKeys)) {
      const reported = evaluatedByLabel.get(label) ?? new Set();
      for (const key of produced.evaluatedAlertKeys) reported.add(String(key));
      evaluatedByLabel.set(label, reported);
    } else {
      console.warn(`[daemon] detector '${label}' returned candidates with a missing/invalid evaluatedAlertKeys (partial shape); surfacing its candidates but reporting no coverage this tick (fail-safe freeze)`);
    }
    return produced.candidates;
  }
  // Only reached when there is genuinely nothing to surface (candidates itself absent/not-an-array,
  // null, a bare non-array object): treat as the fallback (no candidates) + NO coverage + warn.
  console.warn(`[daemon] detector '${label}' returned a malformed result shape (expected an array or { candidates, evaluatedAlertKeys }); treating as no candidates + no coverage (fail-safe)`);
  return fallback;
}

// BLOCKER 1 re-gate: the rule_ids each fast-tick detector (keyed by the exact `label` string
// passed to its own safeCandidates call site below) can ever emit -- consulted ONLY to compute
// which rule_ids must be excluded from coveredAlertIds when that detector's label appears in
// `failedLabels` (i.e. it genuinely threw this tick), never to make any other decision. Two
// detectors are deliberately ABSENT here because their rule_id sets are not fixed/static; each is
// handled by ruleIdsForFailedLabel below instead:
//   - "active-constraint": constraint.violation.<family> is dynamic (family is an
//     operator/mined constraint field, not a fixed enum) -- matched by prefix against this
//     tick's persisted rule_ids instead of a hardcoded list.
//   - "containment-recommendation": containment-recommend.js already exports the exact closed
//     set its own RECOMMEND_MAP can ever produce (containmentRecommendationRuleIds()) -- reused
//     verbatim, never hand-duplicated here.
const DETECTOR_FAILURE_RULE_IDS = {
  "provenance-warning": [DELETED_EXE_RULE_ID, PUBLIC_BIND_RULE_ID],
  "provenance-identity": [UNKNOWN_IDENTITY_RULE_ID, IDENTITY_DRIFT_RULE_ID, NEW_PUBLIC_BIND_RULE_ID],
  session: [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID],
  correlation: [CORRELATION_RULE_ID],
  peer: [PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID],
  service: [SERVICE_DISAPPEARED_RULE_ID],
  canary: [CANARY_TRIPPED_RULE_ID, CANARY_TAMPERED_RULE_ID],
  "process-lineage": [PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID],
  "scheduled-job": [SCHEDULED_JOB_APPEARED_RULE_ID],
  "service-appearance": [SERVICE_APPEARED_RULE_ID],
  "credential-access": [CREDENTIAL_ACCESS_RULE_ID],
};

const CONSTRAINT_VIOLATION_RULE_ID_PREFIX = "constraint.violation.";

// Detector-reported recovery coverage (§8.B) — the canonical ownership registry. Derived from
// DETECTOR_FAILURE_RULE_IDS above (the SAME "ground truth" map, extended per §7.6, never
// hand-duplicated), keyed by security rule_id, each row carrying the owning producer LABEL and the
// owning TIER (§8.B's "owning-tier column"). It answers ONE question for the covered-set
// construction: which producer owns a given security rule_id. A persisted alert whose rule_id is
// owned here is "coverage-subject" -- it recovers this tick ONLY if its OWNING producer reported
// its exact identity in evaluatedAlertKeys (owner-scoped: another producer's report can never
// authorize it, because the lookup only ever consults the owning label's reported set). A rule_id
// with NO owner here is deliberately NOT coverage-subject: containment.recommend.* is intentionally
// absent from DETECTOR_FAILURE_RULE_IDS (see its own doc comment) and keeps its deliberate existing
// recovery semantics. constraint.violation.* is also dynamic and absent from the registry, but its
// deferred active-constraint producer has no per-identity coverage report, so it is safe-frozen by
// computeCoveredAlerts below. Any OTHER unknown rule_id fails closed (frozen). Duplicate
// ownership is a build-time bug and throws here at module init (fail closed on the ambiguity rather
// than silently letting either label authorize the rule).
//
// The `tier` column assigns EVERY owned rule an EXPLICIT owning tier (BLOCKER-1, daybreak-blue
// re-gate this slice -- no `undefined` tier any more): WATCH for the eight watch-tier
// structural/novelty detectors (WATCH_OWNED_HISTORY_DEPENDENT_RULE_IDS --
// service.disappeared/appeared, session.count_drop/churn, peer.count_spike/drop,
// scheduled_job.appeared, process.lineage.novel_edge), AUTHOR for EVERYTHING ELSE (correlation and
// canary.tampered as before, PLUS the positive-evidence rules canary.tripped and credential.access
// and the provenance families that used to be `undefined`). AUTHOR is correct for all of them
// because every non-watch-owned producer here is learned-gated -- canary-baseline.js:483,
// credential-access-baseline.js:285, provenance-warnings.js:327, provenance-identity.js:193 all
// short-circuit on `!learnedConfig.enabled` BEFORE evaluating -- so their silence while learned is
// off is never a genuine clear. This complete tier column is the SOLE source tierVetoedRuleIds()
// derives the §7.7 tier veto from at BOTH persistence passes (it SUBSUMES the old
// history-dependent-only WATCH_OWNED/AUTHOR_OWNED spreads, which never named the positive-evidence
// rules -- the BLOCKER-1 gap). A FUTURE watch-gated rule MUST be added to
// WATCH_OWNED_HISTORY_DEPENDENT_RULE_IDS, or it defaults to AUTHOR here and over-freezes when learned
// is off (the SAFE direction -- an over-freeze is never a fabrication -- but still wrong, so it must
// be classified explicitly rather than left to the default).
const SECURITY_RULE_OWNERSHIP = (() => {
  const registry = new Map();
  for (const [label, ruleIds] of Object.entries(DETECTOR_FAILURE_RULE_IDS)) {
    for (const ruleId of ruleIds) {
      if (registry.has(ruleId)) {
        throw new Error(`ownership registry: rule_id '${ruleId}' is owned by both '${registry.get(ruleId).label}' and '${label}' (duplicate ownership)`);
      }
      const tier = WATCH_OWNED_HISTORY_DEPENDENT_RULE_IDS.has(ruleId) ? "watch" : "author";
      registry.set(ruleId, { label, tier });
    }
  }
  return registry;
})();

// §7.7 tier veto, derived DIRECTLY from the complete ownership registry (BLOCKER-1 fix, daybreak
// re-gate): a registry-owned security rule is tier-vetoed (frozen, never recoverable this tick)
// whenever its OWNING tier is disabled -- WATCH-owned while !watch.enabled, or AUTHOR-owned while
// !learned.enabled. Silence from a disabled tier is not a genuine clear (its detector short-circuits
// before evaluating), regardless of how trustworthy the OTHER tier's fact-history happens to be.
// This SUBSUMES the old history-dependent-only spreads (WATCH_OWNED_HISTORY_DEPENDENT_RULE_IDS ∪
// AUTHOR_OWNED_HISTORY_DEPENDENT_RULE_IDS): the eight history-dependent WATCH families and the two
// history-dependent AUTHOR families are in the registry with the same tiers, so they stay vetoed
// exactly as before -- while ALSO covering the positive-evidence AUTHOR rules (canary.tripped,
// credential.access) and the provenance families the old sets never named. Absent this, once those
// producers convert (next slice) an owner reporting an identity evaluated while its tier was off
// would fabricate a recovery (daybreak's repro: watch:true/learned:false + persisted canary.tripped
// + canary reports the identity evaluated -> covered -> recovered with no observation). Applied
// unconditionally at BOTH persistence passes via alwaysExcludedRuleIds. Fails CLOSED (freezes) on any
// tier value that is neither "watch" nor "author" -- unreachable today (the registry assigns exactly
// one of the two) but matching the registry's own throw-on-duplicate fail-closed posture.
function tierVetoedRuleIds({ watchEnabled, learnedEnabled }) {
  const vetoed = [];
  for (const [ruleId, { tier }] of SECURITY_RULE_OWNERSHIP) {
    if (tier === "watch") { if (!watchEnabled) vetoed.push(ruleId); }
    else if (tier === "author") { if (!learnedEnabled) vetoed.push(ruleId); }
    else vetoed.push(ruleId); // fail closed: an unclassified owned rule stays frozen until classified
  }
  return vetoed;
}

// The closed set of dynamic containment.recommend.<verb> rule_ids (from the same source of truth
// used by ruleIdsForFailedLabel), pre-computed once: these are NOT coverage-subject (no owner in
// SECURITY_RULE_OWNERSHIP) and keep their existing recovery semantics in computeCoveredAlerts.
const CONTAINMENT_RECOMMEND_RULE_IDS = new Set(containmentRecommendationRuleIds());

// True iff a safeCandidates `label` is a coverage-subject detector (present in the ownership
// registry's ground-truth map). A bare-array return from such a label is a not-yet-converted
// producer whose family therefore freezes (fail-safe) and warrants a warn; a bare array from a
// non-registry label (active-constraint / containment-recommendation) is that producer's PERMANENT
// contract, not an un-adopted shape, and must not warn.
function isCoverageSubjectLabel(label) {
  return Object.hasOwn(DETECTOR_FAILURE_RULE_IDS, label);
}

// Returns the rule_ids a single failed detector label must have excluded from coveredAlertIds.
// `persistedRuleIds` (this tick's currently-persisted alert rule_ids) is needed only for
// "active-constraint"'s dynamic prefix match -- every other label resolves from the static table
// above and ignores it.
function ruleIdsForFailedLabel(label, persistedRuleIds) {
  if (label === "active-constraint") {
    return persistedRuleIds.filter((ruleId) => ruleId.startsWith(CONSTRAINT_VIOLATION_RULE_ID_PREFIX));
  }
  if (label === "containment-recommendation") {
    return containmentRecommendationRuleIds();
  }
  return DETECTOR_FAILURE_RULE_IDS[label] ?? [];
}

// Detector-reported recovery coverage (§8.A) — the covered set is now keyed on alert IDENTITY
// (alertId(rule_id, fingerprint)), not rule_id, and recovery is authorized POSITIVELY (freeze by
// default) for every coverage-subject detector family, folding in FOUR restriction sources:
//
//   1. Coverage (NEW, the root fix): a persisted alert whose rule_id is owned in
//      SECURITY_RULE_OWNERSHIP recovers ONLY if its OWNING producer reported its exact identity in
//      evaluatedAlertKeys this tick. An unreported (or bare-array / thrown / not-yet-converted)
//      producer reports nothing -> its family freezes. Owner-scoped by construction: each persisted
//      alert consults ONLY its owning label's reported set, so a foreign producer's report can never
//      authorize another family. This is the "empty ⇒ genuine clear" fabrication closed at its root.
//   2. History-untrusted (existing, §7.7): HISTORY_DEPENDENT_ALERT_RULE_IDS freeze when
//      `!historyTrust.trust` — an independent daemon-side veto that still fires even if a detector's
//      coverage-reporting were buggy (kept per §7.7 as the intersection, not removed).
//   3. Failed-detector (existing, §7.7): a genuinely-thrown detector's rule_ids freeze
//      unconditionally (ruleIdsForFailedLabel over failedLabels).
//   4. alwaysExcludedRuleIds (existing, §7.7): the caller-supplied tier-ownership + containment
//      exclusions, applied unconditionally.
//
// Final eligibility is the INTERSECTION (§7.7): a family recovers only if reported-covered AND not
// history-vetoed AND not failed AND not always-excluded. FIXED_ALERT_RULE_IDS are EXEMPT from the
// coverage requirement (they always evaluate from current metrics) — their identities are seeded
// into the covered set and only the §7.7 vetoes (which never name a fixed rule) can drop them. The
// containment.recommend.* is NOT coverage-subject and keeps its deliberate existing recovery
// semantics (subject only to the §7.7 vetoes). constraint.violation.* is deferred under §8 and
// therefore remains frozen because the active-constraint producer reports no per-identity coverage.
// Any OTHER unowned rule_id fails closed (frozen).
//
// Always returns a Set of alert IDs (never `undefined`): freeze-by-default requires the full covered
// set every tick, and the persisted-alert read this needs is the same cheap local alert-record read
// the pre-fix code already did whenever any restriction applied. Only called when
// options.evaluateAlerts !== false, so the "no I/O when disabled" invariant (no detector/alert I/O
// on a disabled tick) is preserved by the caller, unchanged.
async function computeCoveredAlerts(descartesPaths, options, { historyVetoedRuleIds, failedLabels, alwaysExcludedRuleIds = [], evaluatedByLabel, horizonVetoedRuleIds = new Set(), successfulRetentionFamilies = new Set() }) {
  // S4 (§4.4, I6): the per-family history veto. Fail closed: a caller that passes no set vetoes every
  // history-dependent rule.
  const historyVetoed = historyVetoedRuleIds instanceof Set ? historyVetoedRuleIds : HISTORY_DEPENDENT_ALERT_RULE_IDS;

  const readAlerts = options.readAlertRecords ?? readAlertRecords;
  let persistedAlerts = [];
  try {
    persistedAlerts = await readAlerts(descartesPaths);
  } catch {
    persistedAlerts = [];
  }
  const persistedRuleIds = persistedAlerts.map((alert) => alert.rule_id);

  // §7.7 rule-id-level vetoes (history-untrusted ∪ failed-detector ∪ always-excluded): a rule_id in
  // this set freezes regardless of any coverage report.
  const vetoedRuleIds = new Set([
    // S4 (§4.4): a history-dependent rule freezes when ANY family it reads is untrusted (or was not
    // read) -- per family, so a loss in one family never freezes another family's recovery.
    ...historyVetoed,
    // Fact-store capacity plan §4.4 / I6 (step S3): the per-rule eligibility-horizon veto -- the
    // daemon's own, independent check (from its own per-family reads, against the same
    // fact-families.js registry the detectors use), so a detector that forgot its horizon gate still
    // cannot authorize a recovery off a window too short to evaluate the rule.
    ...horizonVetoedRuleIds,
    ...alwaysExcludedRuleIds,
  ]);
  for (const label of failedLabels) {
    for (const ruleId of ruleIdsForFailedLabel(label, persistedRuleIds)) vetoedRuleIds.add(ruleId);
  }

  // Seed with the fixed rules' identities (always covered, subject only to the §7.7 vetoes below,
  // which never name a fixed rule), then decide each persisted alert by identity.
  const covered = fixedAlertIds();
  for (const alert of persistedAlerts) {
    if (vetoedRuleIds.has(alert.rule_id)) continue; // §7.7 veto -> frozen
    if (alert.rule_id === RETENTION_FAILURE_RULE_ID) {
      if (successfulRetentionFamilies.has(alert.fingerprint)) covered.add(alert.id);
      continue; // a fast tick, failed pass, or unreadable status never authorizes recovery
    }
    if (FIXED_ALERT_RULE_IDS.has(alert.rule_id)) { covered.add(alert.id); continue; } // exempt
    const owner = SECURITY_RULE_OWNERSHIP.get(alert.rule_id);
    if (owner) {
      // Coverage-subject: recover ONLY if its owning producer reported this exact identity.
      if (evaluatedByLabel?.get(owner.label)?.has(alert.id)) covered.add(alert.id);
      continue; // else frozen (never fabricate)
    }
    if (CONTAINMENT_RECOMMEND_RULE_IDS.has(alert.rule_id)) {
      covered.add(alert.id); // containment's deliberate non-coverage-subject semantics (past vetoes)
      continue;
    }
    // Unknown/unowned rule_id: fail closed (frozen) — a future producer must register its rule.
  }
  return covered;
}

// Finding F4-B1/F4-B2: joins zero or more possibly-undefined error messages into one honestly-
// complete string (rather than one silently overwriting/discarding another on the rare tick where
// more than one persistence step fails), or `undefined` if none are present -- used to fold the
// metric-persist / structural-fact-persist / writeDaemonStatus failure messages into statusRecord.
function combineErrors(...messages) {
  const present = messages.filter(Boolean);
  return present.length > 0 ? present.join("; ") : undefined;
}

// Detector-reported recovery coverage (§8.D / BLOCKER-2): recursively freeze a value in place so a
// nested object cannot be mutated. Used on the per-tick config snapshot's `watch`/`learned` (after a
// structuredClone that severs any shared reference) so neither a producer handed the snapshot nor the
// daemon's own later tier check can mutate it mid-tick. Plain config objects only (booleans/strings/
// numbers), so a shallow recursion over own object/array properties is sufficient and terminates.
function deepFreeze(value) {
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

export async function runDaemonIteration(descartesPaths, options = {}) {
  const profile = options.profile ?? defaultDaemonProfile();
  validateDaemonProfile(profile);
  const ts = options.ts ?? new Date().toISOString();
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  try {
    await fs.unlink(path.join(descartesPaths.stateDir, "daemon", LEGACY_CONTENT_PIN_FILE));
  } catch (error) {
    if (error?.code !== "ENOENT") {
      console.warn(`[daemon] legacy binary content-pin cleanup failed (${error instanceof Error ? error.message : String(error)})`);
    }
  }
  // Slice B (Codex-hardening): one freshness horizon, derived from the RESOLVED profile's structural
  // interval (not options.profile, which may be undefined when defaulted), threaded into BOTH the
  // live-active and shadow-soak constraint evals so they apply the identical staleness bound.
  const structuralIntervalMs = profile.structural?.interval_ms ?? DEFAULT_STRUCTURAL_INTERVAL_MS;
  const activeFreshnessMs = ACTIVE_FRESHNESS_MULTIPLE * structuralIntervalMs;

  // Detector-reported recovery coverage (§8.D): an immutable per-tick config snapshot. watch.json
  // and learned.json are loaded ONCE here (via the same options.load*Config ?? load*Config DI seams
  // every call site already used) and DEEPLY frozen, so the daemon's own tier gates (the structural
  // block, the shadow-soak block, the fact-history-trust read below, the tier veto) AND the producers
  // all read the SAME immutable view of "which tier is on" within a tick. This closes the mid-tick
  // enablement-flip desync (daybreak R3's second note / §3 Config snapshot): a flip landing between
  // two loads within one tick could otherwise make the daemon's ownership view disagree with a
  // detector's own gate.
  //
  // BLOCKER-2 (daybreak-blue re-gate, this slice): the snapshot must be DEEPLY immutable and be what
  // the PRODUCERS consume. (a) Each nested config is structuredClone'd (severing any reference the
  // loader might share elsewhere) then deepFreeze'd, so a producer handed the snapshot CANNOT mutate
  // configSnapshot.learned.enabled (or watch's) to flip the daemon's OWN later tier check -- the old
  // outer-only Object.freeze left the nested objects mutable and shared by reference with
  // learnedConfigForHistory/watchConfigForHistory below. (b) The producer loader seam is wired to
  // this snapshot (via the `snapshotLoaders` const below) at BOTH the detectorOptions site (the
  // twelve fast-tick detectors) AND the second-pass containment-recommendation call, so an unconverted
  // producer doing `options.loadWatchConfig ?? loadWatchConfig` consumes the single frozen snapshot
  // rather than re-reading disk (which could observe a mid-tick flip). Both configs are loaded on
  // every tick already (the fact-history read below is unconditional), so this consolidates redundant
  // loads rather than adding any; the "no fact I/O when disabled" invariant (guarded separately
  // below) is untouched — these are cheap config reads, not fact-store reads.
  const loadWatchForTick = options.loadWatchConfig ?? loadWatchConfig;
  const loadLearnedForTick = options.loadLearnedConfig ?? loadLearnedConfig;
  const configSnapshot = Object.freeze({
    watch: deepFreeze(structuredClone(await loadWatchForTick(descartesPaths))),
    learned: deepFreeze(structuredClone(await loadLearnedForTick(descartesPaths))),
  });
  // BLOCKER-2 (b): the loader seam wired to the frozen snapshot, spread into EVERY producer call site
  // (the twelve fast-tick detectors via detectorOptions AND the second-pass containment-recommendation
  // producer below) so no producer re-reads watch.json/learned.json off disk this tick -- a second
  // read could observe a mid-tick enablement flip and desync the producer's own gate from the daemon's
  // tier veto. Each loader returns the single frozen value the snapshot captured above. Shared as one
  // const so the two call sites can never drift apart.
  const snapshotLoaders = {
    loadWatchConfig: async () => configSnapshot.watch,
    loadLearnedConfig: async () => configSnapshot.learned,
  };

  const collectorOptions = {
    trustedBinaryPaths: configSnapshot.watch.trusted_binary_paths,
  };
  // S5 (fact-store capacity plan §4.6 M2/M3, Q3/Q4): quarantine the legacy single store (and the
  // pre-S4 seen-sets) out of the facts tree, idempotently, before any per-family write this tick, and
  // delete quarantines older than 31 days. Fact I/O only when a tier is on (no I/O when disabled).
  // Never fatal: a failure is reported on the status record and the move resumes next tick (into the
  // same directory). The per-family stores themselves start fresh by construction (M2, I8).
  let factStoreLegacy;
  if (configSnapshot.watch.enabled || configSnapshot.learned.enabled) {
    const migrate = options.migrateLegacyFactStore ?? migrateLegacyFactStore;
    try {
      const migration = await migrate(descartesPaths, { now: nowMs });
      if (migration && (migration.status !== "none" || migration.deleted?.length > 0 || migration.pending?.length > 0 || migration.marker)) {
        factStoreLegacy = migration;
      }
    } catch (error) {
      const message = (error instanceof Error ? error.message : String(error)) || "unknown legacy fact-store migration error";
      console.warn(`[daemon] legacy fact-store quarantine failed this tick (${message}); it is never read, and the move resumes next tick`);
      factStoreLegacy = { status: "error", error: message };
    }
  }

  const evidence = await collectDaemonEvidence(profile, options.collectors, collectorOptions);
  const points = metricPointsFromEvidence(evidence, { ts });
  // Finding F4: isolated so a storage fault (ENOSPC/EACCES/EROFS) on this tick's metric persist
  // degrades this tick's write result to an honest zero rather than aborting the entire tick
  // before evaluateAndPersistAlerts ever runs. Finding F4-B1/F4-B2 re-gate: inline try/catch, not
  // safeCandidates (see that helper's own doc comment above) -- the failure message must survive
  // to feed this tick's own status.state/storage_write_error below, not merely be logged and
  // discarded. appendMetricPoints itself now treats a RETENTION-only failure as non-fatal (see
  // history-store.js) and returns it as `write.retention_error` instead of throwing, so this catch
  // is reached only on a genuine append failure (records never reached disk).
  const appendMetrics = options.appendMetricPoints ?? appendMetricPoints;
  let write;
  let metricPersistError;
  try {
    write = await appendMetrics(descartesPaths, points, {
      ts,
      retentionMs: options.retentionMs,
      maxBytes: options.maxBytes,
      now: options.now ?? ts,
    });
  } catch (error) {
    metricPersistError = (error instanceof Error ? error.message : String(error)) || "unknown metric-persist error";
    console.warn(`[daemon] metric-persist failed this tick (${metricPersistError}); degrading to written_count: 0, not fabricating a write`);
    write = { written_count: 0, retention: undefined };
  }

  // Independent, slower structural (services/network/scheduled-jobs) cadence. Gated behind
  // configDir/watch.json's WATCH-layer kill switch (watch-by-default slice 1, plan
  // docs/plans/2026-09-10-watch-by-default-slice-1.md §3.2/§12 -- moved off configDir/
  // learned.json, which now gates only the AUTHOR layer below; watch.json defaults ON, unlike
  // learned's default-off), checked before any work is attempted (convention #4) — when
  // disabled, this block reads nothing else and writes nothing.
  // S4 (fact-store capacity plan §4.5 Config): the per-family budgets for this tick, from the frozen
  // watch.json snapshot, each validated against its T8 horizon floor (a rejected value falls back to
  // the default and is reported as `budget_below_horizon_floor`). `options.factStoreBudgets` is a
  // TEST-ONLY seam (T1 forces routine eviction at real volume) that bypasses that floor -- exactly
  // why it is not a config path.
  const budgetResolution = resolveFactStoreBudgets(configSnapshot.watch.fact_store_budgets, { structuralIntervalMs });
  const effectiveBudgets = options.factStoreBudgets ?? budgetResolution.budgets;
  let structuralEvidence;
  let structuralCollectorStatuses;
  let structuralFacts;
  // Finding F4-B1/F4-B2: captured alongside structuralFacts (rather than discarded by
  // safeCandidates -- see its doc comment above) so a genuine structural-fact append failure can
  // feed this tick's own status.state/storage_write_error below.
  let structuralFactPersistError;
  let shadowEvaluation;
  const structuralProfile = profile.structural;
  if (structuralProfile?.interval_ms) {
    const watchConfig = configSnapshot.watch; // §8.D: per-tick snapshot (loaded once above)
    if (watchConfig.enabled) {
      const readCheckpoint = options.readStructuralCheckpoint ?? readStructuralCheckpoint;
      const checkpoint = await readCheckpoint(descartesPaths);
      const lastRunMs = Number.isFinite(checkpoint?.last_structural_run_ms) ? checkpoint.last_structural_run_ms : -Infinity;
      const structuralDue = nowMs - lastRunMs >= structuralProfile.interval_ms;
      if (structuralDue) {
        const deadlineMs = structuralProfile.deadline_ms ?? DEFAULT_STRUCTURAL_TICK_DEADLINE_MS;
        let structuralCollectors = options.structuralCollectors;
        if (structuralProfile.collectors?.canary?.enabled) {
          const loadManifest = options.loadCanaryManifest ?? loadCanaryManifest;
          const { canaries } = await loadManifest(descartesPaths);
          structuralCollectors = {
            ...structuralCollectors,
            canary: structuralCollectors?.canary ?? (() => collectCanaryEvidence(canaries)),
          };
        }
        const outcome = await withDeadline(
          collectStructuralEvidence(structuralProfile, structuralCollectors, collectorOptions),
          deadlineMs,
          () => STRUCTURAL_TICK_TIMED_OUT,
        );
        if (outcome === STRUCTURAL_TICK_TIMED_OUT) {
          // Partial results (if any) are discarded, not partially persisted, to avoid an
          // inconsistent fact snapshot. The checkpoint still advances below so a repeatedly-slow
          // host retries at the next full structural interval, not on every fast tick.
          structuralCollectorStatuses = [{ status: "unable", error: "structural_tick_deadline_exceeded" }];
        } else {
          structuralEvidence = outcome;
          structuralCollectorStatuses = structuralEvidence.map((envelope) => ({ id: envelope.id, status: envelope.status, tool: envelope.trace?.tool }));

          // Slice S6b, additive follow-up to S6a: translate this tick's structural evidence
          // into categorical fact-points and persist them. Only reachable here — i.e. only
          // when structural collection actually completed this tick (not timed out) and the
          // watch kill switch is enabled (already gated by the enclosing `if
          // (watchConfig.enabled)` block above) — never on a timed-out/partial tick, which
          // discards its evidence entirely rather than persisting a partial fact snapshot.
          const factPoints = [
            ...factPointsFromCanaryEvidence(structuralEvidence, { ts }),
            ...factPointsFromServiceEvidence(structuralEvidence, { ts }),
            ...factPointsFromNetworkEvidence(structuralEvidence, { ts }),
            // Slice S4, additive: structural provenance-warning evidence -> fact-points, same
            // discipline as its siblings above — only reachable on a successful (non-timed-out)
            // structural tick, never for a partial/timed-out one (plan section 4).
            ...provenanceWarningFactPoints(structuralEvidence, { ts }),
            // Slice 1 (observed-incident collectors plan), additive: session-census structural
            // evidence -> fact-points, same discipline as its siblings above — only reachable on
            // a successful (non-timed-out) structural tick. Pure L0 fact source: deliberately NOT
            // paired with any extraCandidates addition below — this slice emits NO alert
            // candidates (alerting on session-count deviation/churn is Slice 4's job).
            ...factPointsFromSessionEvidence(structuralEvidence, { ts }),
            // Slice 3 (observed-incident collectors plan), additive: VPN/SSH peer-status
            // structural evidence -> fact-points, same discipline as its siblings above — only
            // reachable on a successful (non-timed-out) structural tick. Pure L0 fact source:
            // deliberately NOT paired with any extraCandidates addition below — this slice emits
            // NO alert candidates either (RESOLVED option 1, plan Slice 3's Alert-emission scope
            // decision). Alerting on unattributed/odd-hour peer logins is Slice 4/6's job.
            ...factPointsFromVpnPeerEvidence(structuralEvidence, { ts }),
            // Tailscale/tailnet is another pure L0 peer.presence source. It deliberately emits no
            // extraCandidates and no census marker; vpn-peer-status remains the sole shared
            // availability/regime anchor, avoiding same-tick marker collision.
            ...factPointsFromTailscaleStatusEvidence(structuralEvidence, { ts }),
            ...factPointsFromProcessLineageEvidence(structuralEvidence, { ts }),
            // Persistence baseline, Slice A (docs/plans/2026-08-21-agent-intrusion-detection-
            // gaps.md): scheduled-jobs structural evidence -> fact-points, same discipline as its
            // siblings above — only reachable on a successful (non-timed-out) structural tick.
            // Pure L0 fact source: deliberately NOT paired with any extraCandidates addition here
            // — alerting on a novel scheduled job (scheduled_job.appeared) is Slice B's job.
            ...factPointsFromScheduledJobsEvidence(structuralEvidence, { ts }),
          ];
          // Finding F4: same isolation as the metric-persist call above -- a storage fault here must
          // not abort the tick before evaluateAndPersistAlerts, and must not fabricate a retention
          // outcome that did not happen. Finding F4-B1/F4-B2 re-gate: inline try/catch, not
          // safeCandidates -- the error message must survive to feed status.state/
          // storage_write_error below.
          //
          // S4 (fact-store capacity plan §4.3): the tick's points are routed to their family stores
          // (an unregistered fact_name throws before ANY family is written), each appended with its
          // own budget (watch.json fact_store_budgets, validated against the T8 floor by
          // resolveFactStoreBudgets; the legacy single fact_store_max_bytes is ignored, Q5), and every
          // other existing family store gets a retention pass too -- so this runs on every completed
          // structural tick, even one that produced no points. One family's append/retention failure
          // is reported (combined into storage_write_error/retention_error below) and never stops
          // another family from persisting. The DI seam keeps its historical name.
          const persistFacts = options.appendFactPoints ?? appendFactPointsByFamily;
          try {
            structuralFacts = await persistFacts(descartesPaths, factPoints, { ts, now: options.now ?? ts, budgets: effectiveBudgets });
            if (structuralFacts?.append_error) {
              structuralFactPersistError = structuralFacts.append_error;
              console.warn(`[daemon] structural-fact-persist failed for some families this tick (${structuralFactPersistError}); the others persisted`);
            }
          } catch (error) {
            structuralFactPersistError = (error instanceof Error ? error.message : String(error)) || "unknown structural-fact-persist error";
            console.warn(`[daemon] structural-fact-persist failed this tick (${structuralFactPersistError}); degrading to written_count: 0, not fabricating a write`);
            structuralFacts = { written_count: 0, retention: undefined };
          }

          // Slice S7a, additive, RE-GATED (watch-by-default slice 1, plan §3.2): shadow-constraint
          // evaluation stays on the AUTHOR flag, nested INSIDE the WATCH block, as a genuine
          // two-flag AND — not a rename. It only means anything once the AUTHOR pipeline has
          // produced status:"shadow" constraints, so it must not start running the moment WATCH
          // (default-on) turns on by itself; loaded independently from watchConfig here, on
          // purpose, so the two flags can never be conflated. Evaluate any status:"shadow"
          // constraints against the accumulated fact-history and log the results (fired and
          // non-fired) to shadow-violations.jsonl. Reuses this same structural-tick gate
          // (structuralDue + watchConfig.enabled, both already checked above) plus this nested
          // learnedConfig.enabled check, and the same wall-clock cadence/checkpoint — no new
          // timer, no new checkpoint. Only reached on a successful (non-timed-out) structural
          // tick, matching the "partial results discarded, not partially persisted" discipline
          // the timeout branch already follows. A cheap no-op whenever no constraint is
          // status:"shadow" (true for the entire lifetime of this plan until S7a's own
          // promoteDraftsToShadow first runs). Writes only to shadow-violations.jsonl — never
          // constraints.json, never alerts.json/notifications (evaluateAndLogShadowConstraints
          // never imports alert-store.js).
          const learnedConfig = configSnapshot.learned; // §8.D: per-tick snapshot (loaded once above)
          if (learnedConfig.enabled) {
            const evaluateShadow = options.evaluateAndLogShadowConstraints ?? evaluateAndLogShadowConstraints;
            shadowEvaluation = await evaluateShadow(descartesPaths, { ts, now: options.now ?? ts, freshnessMs: activeFreshnessMs });
          }
        }
        // Finding F4: a throw here (e.g. a disk fault) must not abort the tick. Safe by the file's
        // own existing reasoning (checkpoint doc comment above): a checkpoint that doesn't advance
        // just means structural work retries next tick, already-tolerated for the timeout case.
        const writeCheckpoint = options.writeStructuralCheckpoint ?? writeStructuralCheckpoint;
        await safeCandidates(
          "structural-checkpoint-persist",
          () => writeCheckpoint(descartesPaths, { last_structural_run_ms: nowMs, now: ts }),
          undefined,
        );
      }
    }
  }

  // Fix 2/Fix 3 (trusted-state step-1 revision, "R1 made signable"): ONE shared fact-history
  // read this tick, sourced identically for (a) the statusRecord's fact_store_completeness line
  // below and (b) scoping coveredAlertIds away from HISTORY_DEPENDENT_ALERT_RULE_IDS at BOTH
  // evaluateAndPersistAlerts call sites below whenever this tick's fact-history is untrustworthy
  // (no fabricated recovery -- alert-store.js's applyAlertCandidates would otherwise mark a
  // suppressed history-dependent family's persisted alert "recovered" just because its absent
  // candidate is indistinguishable from a genuine clear).
  //
  // Watch-by-default slice 1 BLOCKER fix (Fable interim adversarial pass, post-Step-3): gated on
  // watchConfig.enabled **OR** learnedConfig.enabled, NOT watch alone. HISTORY_DEPENDENT_ALERT_
  // RULE_IDS (above) covers all six watch-tier detector families (service.appeared/disappeared,
  // session.churn/count_drop, peer.count_spike/drop, process.lineage.novel_edge,
  // scheduled_job.appeared) -- those six genuinely did all move to WATCH -- PLUS correlation and
  // canary.tampered, which did NOT move: computeCorrelationCandidates (incident-correlation.js)
  // and computeCanaryBaselineCandidates (canary-baseline.js) are still gated on learnedConfig
  // ONLY. A watch-only gate here left a real gap: with watch:false + learned:true, this read
  // never ran (historyTrust stayed undefined), yet correlation/canary genuinely ran (learned on)
  // and genuinely went silent on degraded history -- their absent candidates then read as a
  // genuine clear and got fabricated-"recovered", exactly the hole Fix 3 exists to close.
  // Regression-tested: daemon.test.js's "watch-by-default BLOCKER regression" test, a real
  // red->green against this exact finding (mirrors the earlier "watch-by-default Fix-3
  // regression" test, which covers the inverse watch:true/learned:false population -- together
  // the two tests cover both halves of the OR). When BOTH flags are disabled there is no fact
  // store to protect, and this stays a true no-op (byte-identical to the pre-revision fast path;
  // this file's repeated "no I/O when disabled" tests pin exactly this). Both configs are loaded
  // via their OWN independent options.load*Config ?? load*Config calls (not folded into the
  // structural-tick block's watchConfig above, and the learnedConfig loaded here is reused below
  // at the containment-exclusion call site rather than loaded a third time): this read sits
  // OUTSIDE the `if (structuralProfile?.interval_ms)` guard and runs on EVERY fast tick, not just
  // a structural-due one, so it must not depend on that block having run this tick.
  //
  // BLOCKER 1 re-gate: only `historyTrust` itself (the TRUST DECISION) is computed here, at the
  // same point as before -- the actual coveredAlertIds Set is now built LATER, via
  // computeCoveredAlerts, after the twelve fast-tick detectors below have run and
  // `failedDetectorLabels` is known. A detector's genuine exception is exactly as disqualifying
  // for recovery as untrustworthy history, and that can only be known once the detectors have
  // actually been attempted this tick.
  // §8.D: the per-tick config snapshot (loaded once at tick start), NOT a fresh read here — the
  // daemon's tier view can no longer drift between the structural block above and this trust read.
  const watchConfigForHistory = configSnapshot.watch;
  const learnedConfigForHistory = configSnapshot.learned;
  let factStoreCompleteness;
  // Fact-store capacity plan §4.2/§4.4 (step S3): the rules whose eligibility horizon is not met on
  // the daemon's own read (vetoed from recovery at both persistence passes below), and the subset of
  // those that are horizon-SHORT on a valid ledger report (the operator signal, I12). Every rule is
  // vetoed when nothing was read -- already true via historyTrust, restated here so the veto is
  // self-contained.
  let horizonVetoedRuleIds = new Set(RULE_HORIZONS.keys());
  // S4 (§4.4): the per-family history veto -- every history-dependent rule when nothing was read.
  let historyVetoedRuleIds = new Set(HISTORY_DEPENDENT_ALERT_RULE_IDS);
  const familyHistoryReads = new Map();
  const horizonShortRuleIds = new Set();
  // S3b review LOW-2 (S4: per rule): rules whose tier is on but whose family read could not report
  // coverage (missing/invalid ledger, or the read threw) -- their horizon-short entry is carried forward.
  const horizonUnknownRuleIds = new Set();
  let noveltySeenSets;
  if (watchConfigForHistory.enabled || learnedConfigForHistory.enabled) {
    const readFactsForHistory = options.readFactPoints ?? readFactPoints;
    const tierOff = new Set(tierVetoedRuleIds({ watchEnabled: watchConfigForHistory.enabled, learnedEnabled: learnedConfigForHistory.enabled }));
    // S4 (fact-store capacity plan §4.3/§4.4, I6, I9): ONE independent read PER FAMILY, and only of
    // the family stores some history-dependent rule of an ENABLED tier reads (no I/O for a family
    // whose every dependent rule's tier is off). Each read is that family's own ledger, floors and
    // (for a novelty family) seen-set -- a loss in one family can no longer freeze another family's
    // recovery, and a veto can no longer authorize a recovery off a store it never checked.
    const historyFamilies = [...new Set([...RULE_HORIZONS].filter(([ruleId]) => !tierOff.has(ruleId)).flatMap(([, rule]) => rule.families))];
    for (const family of historyFamilies) {
      try {
        // S3b: the novelty seen-set too, validated against this same family read's ledger, so the
        // daemon's novelty-rule veto uses the same referent as the detectors (noveltyRuleEligible).
        familyHistoryReads.set(family, await readFactsForHistory(descartesPaths, {
          family,
          windowMs: DEFAULT_BASELINE_FACT_WINDOW_MS,
          now: nowMs,
          ...(NOVELTY_FAMILIES.has(family) ? { seenSetFamilies: [family] } : {}),
        }));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn(`[daemon] ${family} fact-history read failed this tick (${message}); degrading that family to unknown completeness, not fabricating trust`);
        familyHistoryReads.set(family, undefined);
      }
    }
    const familyTrust = new Map(historyFamilies.map((family) => [family, factHistoryTrustworthy(familyHistoryReads.get(family) ?? {})]));
    factStoreCompleteness = selectFamilyFactStoreCompleteness({
      // Combined summary over the family stores that EXIST (a never-created store is reported per
      // family as absent, "not observed (no store)", not folded in as "unknown").
      completeness: combineFamilyCompleteness((historyFamilies.some((family) => familyHistoryReads.get(family)?.store_exists !== false)
        ? historyFamilies.filter((family) => familyHistoryReads.get(family)?.store_exists !== false)
        : historyFamilies).map((family) => familyHistoryReads.get(family)?.completeness ?? { status: "unknown", coverage: "unknown" })),
      family_reads: Object.fromEntries(historyFamilies.map((family) => [family, familyHistoryReads.get(family) ?? { family }])),
    });
    // The per-family history veto (§4.4): a rule is vetoed when ANY family it reads is untrusted --
    // and a family that was not read (its tier is off, or the read threw) counts as untrusted.
    historyVetoedRuleIds = new Set([...HISTORY_DEPENDENT_ALERT_RULE_IDS].filter((ruleId) => (RULE_HORIZONS.get(ruleId)?.families ?? [undefined])
      .some((family) => familyTrust.get(family)?.trust !== true)));
    // Novelty rules (S3b): the SAME predicate the detectors use -- a valid current-epoch seen-set and
    // its horizon, nothing else (G3: no full-store fallback). Every other rule: the fact floor.
    // S3b review MEDIUM-2: correlation's referent is its whole 31 d read window (the same window and
    // predicate the detector uses -- ruleEligible), not only its 3 d horizon, so a correlation the
    // detector silenced is vetoed AND reported horizon-short here. S4: evaluated against each of the
    // rule's OWN family reads (an unread family is ineligible).
    const ruleEligibleOnFamilies = (ruleId) => RULE_HORIZONS.get(ruleId).families
      .every((family) => familyHistoryReads.get(family) !== undefined && ruleEligible(familyHistoryReads.get(family), ruleId, nowMs, { readWindowMs: DEFAULT_BASELINE_FACT_WINDOW_MS }));
    horizonVetoedRuleIds = new Set([...RULE_HORIZONS.keys()].filter((ruleId) => !ruleEligibleOnFamilies(ruleId)));
    // Display-only per-family seen-set state (the overflow / lineage-mismatch "status reason").
    const seenSetEntries = historyFamilies.flatMap((family) => Object.entries(familyHistoryReads.get(family)?.seen_sets ?? {}));
    if (seenSetEntries.length > 0) {
      noveltySeenSets = Object.fromEntries(seenSetEntries.map(([family, set]) => [family, {
        status: typeof set?.status === "string" ? set.status : "unknown",
        entry_count: Number.isSafeInteger(set?.entry_count) ? set.entry_count : 0,
        certified_since_ts: typeof set?.certified_since_ts === "string" ? set.certified_since_ts : null,
      }]));
    }
    // Horizon-SHORT is reported only over a valid ledger's coverage report: a missing/invalid ledger
    // or failed read is an untrusted-history condition (reported as such), not a short horizon. S4:
    // decided PER RULE on the rule's own family reads -- a rule whose family read reports no valid
    // coverage has UNKNOWN horizon state (its prior entry is carried forward; S3b review LOW-2),
    // without affecting any other family's rules.
    // S3b review LOW-3: only rules whose owning tier is running -- a detector that is not evaluating
    // because its tier is off is not "horizon-short", and must not raise the fixed alert. (The
    // recovery veto above is unchanged; the tier veto freezes those rules at both passes anyway.)
    const validCoverage = (family) => ["full", "narrowed"].includes(familyHistoryReads.get(family)?.completeness?.coverage);
    for (const ruleId of RULE_HORIZONS.keys()) {
      if (tierOff.has(ruleId)) continue;
      if (!RULE_HORIZONS.get(ruleId).families.every(validCoverage)) horizonUnknownRuleIds.add(ruleId);
      else if (horizonVetoedRuleIds.has(ruleId)) horizonShortRuleIds.add(ruleId);
    }
  } else {
    // BLOCKER-2 (daybreak-blue re-gate, found after the OR fix in 1e9ddaf): when NEITHER tier is
    // enabled, we cannot vouch for fact-history without a fact read we must not do when disabled
    // (the "no I/O when disabled" invariant) -- but leaving `historyTrust` simply `undefined` is
    // NOT the same as "nothing to protect": computeCoveredAlerts's `historyTrust?.trust ===
    // false` check treats `undefined` as trustworthy-by-omission, so a persisted active
    // history-dependent alert whose detector genuinely (and correctly) returns [] this tick
    // because its own gate is off would get flipped to "recovered" -- a fabricated all-clear with
    // NO fact read at all. Explicitly conservative UNTRUSTED instead, so HISTORY_DEPENDENT_ALERT_
    // RULE_IDS families freeze (never fabricate) rather than silently recover; this self-heals the
    // moment either tier is re-enabled and a real read resumes. `factStoreCompleteness` stays
    // `undefined` -- there is genuinely nothing to display when disabled, this is not itself a
    // fact-store read result. BLOCKER-3 (daybreak-blue round 2) ADDITIONALLY covers this same
    // both-off case via tier-ownership exclusion (WATCH_OWNED_HISTORY_DEPENDENT_RULE_IDS ∪
    // AUTHOR_OWNED_HISTORY_DEPENDENT_RULE_IDS, both non-empty when both tiers are off) at both
    // computeCoveredAlerts call sites below -- this `{trust:false}` branch is now defense-in-depth
    // for the both-off case specifically, not the only thing protecting it; it remains load-bearing
    // on its own for a genuinely-degraded read when at least one tier IS enabled.
    historyVetoedRuleIds = new Set(HISTORY_DEPENDENT_ALERT_RULE_IDS);
  }

  // Finding F4, THE FABRICATION TRAP: `statusRecord` is built here, BEFORE attempting the disk
  // write, entirely from real data already computed this tick (genuine collector evidence, the
  // genuine metric-write result above) -- so it is honest regardless of whether the write below
  // succeeds.
  //
  // Finding F4-B1 re-gate (daybreak-blue CONFIRMED BLOCKER): `state` used to be HARDCODED to "ok"
  // here, unconditionally -- so neither a genuine collector error NOR a genuine persistence
  // failure this tick could ever be reflected in it, and alert-store.js's daemon.status.not_ok
  // rule (which fires whenever state is not "ok"/"stopped") could never fire from either. `state`
  // is now DERIVED from real evidence already computed this tick: "error" when a collector
  // genuinely reported status:"error" (an "unable" collector -- e.g. a platform-inapplicable one
  // -- is deliberately NOT treated as a failure; over-firing daemon.status.not_ok on a benign
  // "unable" every tick would be its own fabrication in the other direction), OR when this tick's
  // own metric/structural-fact persist genuinely failed (an append error, or a non-fatal
  // retention_error surfaced by appendMetricPoints/appendFactPoints -- Finding F4-B2, see
  // history-store.js/fact-store.js). Otherwise "ok". On a write failure below we must NOT fall
  // back to some other hardcoded/default record -- doing so would fabricate daemon health in the
  // exact tick where persistence just demonstrably failed. Instead: on failure, log it and fold
  // the failure into the SAME genuine record (adding `storage_write_error` and forcing
  // `state: "error"`, since the write itself is a persistence failure this tick regardless of what
  // collectors reported), and use that in-memory record for the rest of the tick regardless of
  // whether the disk write succeeded -- so evaluateAndPersistAlerts (and everything downstream) is
  // still reached, unconditionally, with real data.
  // Fact-store capacity plan §4.2/§4.4, I12 (step S3): the horizon-short signal. Each short rule's
  // since_ts is carried forward from the previous status record while it stays short (reset the tick
  // it recovers), so the FIXED daemon.fact_history.horizon_short alert (alert-store.js) can fire once a
  // rule has been short for HISTORY_HORIZON_SHORT_ALERT_TICKS structural intervals. Time-based, not a
  // tick counter (S3 deviation): a fast tick re-reads the same history, so wall time since the rule
  // first went short is the faithful measure of "N consecutive structural ticks". The clock carries
  // ONLY from a prior status written at most one structural interval ago (S3b review LOW-1): wall
  // time is a faithful measure only while the daemon was actually ticking, so after downtime (or a
  // status that cannot be dated) the gap is unobserved and the clock restarts. A prior status that is
  // missing/unreadable/undated/stale/future-dated, or a since_ts in the future (clock rollback),
  // restarts the clock at now -- that only DELAYS the signal, and never suppresses the status entry.
  // Bounded imprecision, stated: a single not-short tick whose own status write failed (and no other
  // gap) is not seen, so a <= one-interval recovery inside a short run can be bridged.
  // Read lazily (and at most once): only a tick that actually reports horizon state touches the prior
  // status, so the tiers-off "no I/O when disabled" path is unchanged.
  let priorStatusPromise;
  const readPriorStatusOnce = () => {
    priorStatusPromise ??= (async () => {
      try {
        const readPriorStatus = options.readDaemonStatus ?? readDaemonStatus;
        return await readPriorStatus(descartesPaths);
      } catch {
        return undefined;
      }
    })();
    return priorStatusPromise;
  };
  let historyHorizonShort;
  if (horizonShortRuleIds.size > 0 || horizonUnknownRuleIds.size > 0) {
    const priorStatus = await readPriorStatusOnce();
    const priorStatusMs = typeof priorStatus?.ts === "string" ? Date.parse(priorStatus.ts) : Number.NaN;
    const priorContinuous = Number.isFinite(priorStatusMs) && priorStatusMs <= nowMs && nowMs - priorStatusMs <= structuralIntervalMs;
    const priorBlockRules = priorStatus?.history_horizon_short?.rules;
    const priorAnyRules = priorBlockRules && typeof priorBlockRules === "object" && !Array.isArray(priorBlockRules) ? priorBlockRules : undefined;
    const priorRules = priorContinuous ? priorAnyRules : undefined;
    const nowIsoForHorizon = new Date(nowMs).toISOString();
    const rules = {};
    for (const ruleId of [...horizonShortRuleIds].sort()) {
      const priorSince = priorRules ? priorRules[ruleId]?.since_ts : undefined;
      const priorSinceMs = typeof priorSince === "string" ? Date.parse(priorSince) : Number.NaN;
      rules[ruleId] = { since_ts: Number.isFinite(priorSinceMs) && priorSinceMs <= nowMs ? new Date(priorSinceMs).toISOString() : nowIsoForHorizon };
    }
    // S3b review LOW-2, per rule since S4: a rule whose family read is untrusted is WORSE than short,
    // not a clear. Dropping its entry would let the always-covered fixed alert "recover" and restart
    // its since clock, so its prior entry is carried forward unchanged (whatever its age -- the rule
    // is vetoed this tick, so it is not evaluating; LOW-1's continuity gate applies to EXTENDING a
    // short run, not to holding state through an unknown one). No prior entry stays none: never
    // fabricated. Only that family's rules are carried; every other family is decided on its own read.
    for (const ruleId of [...horizonUnknownRuleIds].sort()) {
      const priorEntry = priorAnyRules?.[ruleId];
      if (priorEntry && typeof priorEntry === "object" && !Array.isArray(priorEntry)) rules[ruleId] = priorEntry;
    }
    if (Object.keys(rules).length > 0) {
      historyHorizonShort = { threshold_ms: HISTORY_HORIZON_SHORT_ALERT_TICKS * structuralIntervalMs, rules: Object.fromEntries(Object.entries(rules).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) };
    }
  }

  // S4 (fact-store capacity plan §4.3-§4.5): the per-family budget/retention status block, for EVERY
  // registry family (display only; consulted by no trust decision). Computed only when a tier is on
  // (no I/O otherwise). Per family:
  //   - budget_bytes / source / floor_bytes / ceiling_bytes, `rejected` ({reason:
  //     budget_below_horizon_floor | invalid}) when watch.json's value was refused, and `clamped`
  //     ({reason: budget_above_ceiling}) when it was above the ceiling (G2 L4);
  //   - `horizon_invariant_unmet` ({required_bytes, structural_interval_ms}) when the effective budget is
  //     below the T8 invariant at this tick's structural interval (G2 L3: below 1 h it scales up);
  //   - last_tick_bytes and `cap_below_tick` (live per-tick volume above the effective budget: the
  //     family is fully evicted every tick), from this structural tick, carried across fast ticks;
  //   - retention_error with retention_error_since_ts (carried while it keeps failing, cleared by a
  //     clean structural pass), and `retention_failing` once it has failed for
  //     HISTORY_HORIZON_SHORT_ALERT_TICKS structural intervals, or once the store (as this tick's read
  //     saw it, or a stat of its file for a family with no history read) exceeds its budget by more
  //     than one worst-case tick (network/provenance: none pinned) -- a retention pass that keeps
  //     failing lets the file, and the read cost, grow without bound (appendFactPoints treats a
  //     retention throw as non-fatal).
  // Q5 (fact-store capacity plan §4.5 Config, §12): the legacy single-store cap is IGNORED; a
  // deliberate operator value (normalization already dropped the written-in 5 MB default and invalid
  // values) is named here so the operator's decision is never silently discarded.
  const factStoreDeprecations = [["watch.json", watchConfigForHistory], ["learned.json", learnedConfigForHistory]]
    .filter(([, config]) => typeof config?.fact_store_max_bytes === "number")
    .map(([source, config]) => ({
      key: "fact_store_max_bytes",
      source,
      configured_bytes: config.fact_store_max_bytes,
      status: "ignored",
      note: "the single fact-store cap is replaced by per-family budgets (watch.json fact_store_budgets, each at or above its horizon floor); this value no longer sizes any store",
    }));
  let factStoreBudgetsStatus;
  let carriedRetentionFailure = false;
  if (watchConfigForHistory.enabled || learnedConfigForHistory.enabled) {
    const priorFamilies = (await readPriorStatusOnce())?.fact_store_budgets?.families;
    const priorOf = (family) => {
      const entry = priorFamilies && typeof priorFamilies === "object" && !Array.isArray(priorFamilies) ? priorFamilies[family] : undefined;
      return entry && typeof entry === "object" && !Array.isArray(entry) ? entry : {};
    };
    const structuralFamilies = structuralFacts?.families && typeof structuralFacts.families === "object" ? structuralFacts.families : undefined;
    const families = {};
    for (const family of FACT_FAMILY_IDS) {
      const budgetBytes = effectiveBudgets[family] ?? FAMILY_DEFAULT_BUDGET_BYTES.get(family);
      const entry = {
        budget_bytes: budgetBytes,
        source: options.factStoreBudgets ? "override" : budgetResolution.source[family],
        floor_bytes: familyBudgetFloorBytes(family, { structuralIntervalMs }),
        ceiling_bytes: familyBudgetCeilingBytes(family),
        ...(budgetResolution.rejected[family] ? { rejected: budgetResolution.rejected[family] } : {}),
        ...(budgetResolution.clamped?.[family] ? { clamped: budgetResolution.clamped[family] } : {}),
      };
      // G2 L3: the T8 invariant at THIS tick's structural interval (operator-settable). Below 1 h the
      // same bytes hold fewer hours, so a budget sized at 1 h can leave the family permanently
      // horizon-short; say so here instead of leaving the horizon-short signal as the only sign.
      const intervalFloorBytes = familyBudgetFloorBytes(family, { structuralIntervalMs });
      if (budgetBytes < intervalFloorBytes) entry.horizon_invariant_unmet = { required_bytes: intervalFloorBytes, structural_interval_ms: structuralIntervalMs };
      const prior = priorOf(family);
      let lastTickBytes;
      let retentionError;
      let retentionSince;
      let retentionFailing = false;
      if (structuralFamilies) {
        const result = structuralFamilies[family];
        const retentionPassSucceeded = result && typeof result === "object" && !Array.isArray(result)
          && Object.prototype.hasOwnProperty.call(result, "retention")
          && result.append_error === undefined;
        if (Number.isSafeInteger(result?.appended_bytes) && result.written_count > 0) lastTickBytes = result.appended_bytes;
        if (typeof result?.retention_error === "string" && result.retention_error) {
          retentionError = result.retention_error;
          const priorSinceMs = typeof prior.retention_error_since_ts === "string" && prior.retention_error ? Date.parse(prior.retention_error_since_ts) : Number.NaN;
          retentionSince = Number.isFinite(priorSinceMs) && priorSinceMs <= nowMs ? new Date(priorSinceMs).toISOString() : new Date(nowMs).toISOString();
        } else if (!retentionPassSucceeded) {
          // A structural tick that did not return this family's successful retention result (for
          // example an append error or an injected whole-pass failure) has no authority to clear a
          // carried failure. Recovery is granted only by a genuinely completed family pass.
          if (typeof prior.retention_error === "string" && prior.retention_error && typeof prior.retention_error_since_ts === "string") {
            retentionError = prior.retention_error;
            retentionSince = prior.retention_error_since_ts;
          }
          retentionFailing = prior.retention_failing === true;
        }
      } else {
        if (Number.isSafeInteger(prior.last_tick_bytes)) lastTickBytes = prior.last_tick_bytes;
        if (typeof prior.retention_error === "string" && prior.retention_error && typeof prior.retention_error_since_ts === "string" && Number.isFinite(Date.parse(prior.retention_error_since_ts))) {
          retentionError = prior.retention_error;
          retentionSince = prior.retention_error_since_ts;
        }
        retentionFailing = prior.retention_failing === true;
      }
      if (lastTickBytes !== undefined) {
        entry.last_tick_bytes = lastTickBytes;
        if (lastTickBytes > budgetBytes) entry.cap_below_tick = true;
      }
      // G2 L1: a family the daemon made no history read of this tick (network and provenance carry no
      // history-dependent rule, so they are never read here) is sized by a stat of its file instead,
      // so the oversize check below runs for every family, not only the history-read ones.
      let readBytes = familyHistoryReads.get(family)?.bytes;
      if (!Number.isSafeInteger(readBytes)) readBytes = await factStoreFileBytes(descartesPaths, family);
      if (Number.isSafeInteger(readBytes)) entry.bytes = readBytes;
      if (retentionError !== undefined) {
        entry.retention_error = retentionError;
        entry.retention_error_since_ts = retentionSince;
      }
      const failingFor = retentionSince !== undefined && nowMs - Date.parse(retentionSince) >= HISTORY_HORIZON_SHORT_ALERT_TICKS * structuralIntervalMs;
      const oversize = Number.isSafeInteger(readBytes) && readBytes > budgetBytes + (FAMILY_TICK_SHAPES.get(family)?.worstTickBytes ?? 0);
      if (failingFor || oversize || retentionFailing) entry.retention_failing = true;
      if (entry.retention_error || entry.retention_failing === true) carriedRetentionFailure = true;
      families[family] = entry;
    }
    factStoreBudgetsStatus = { families, ...(budgetResolution.unknown_families ? { unknown_families: budgetResolution.unknown_families } : {}) };
    // The per-family completeness entries (families the daemon read) carry the same budget state,
    // plus the earliest horizon-short since_ts among that family's rules.
    if (factStoreCompleteness?.families) {
      for (const [family, entry] of Object.entries(factStoreCompleteness.families)) {
        const budget = families[family];
        if (!budget) continue;
        entry.budget_bytes = budget.budget_bytes;
        if (budget.cap_below_tick) entry.cap_below_tick = true;
        if (budget.horizon_invariant_unmet) entry.horizon_invariant_unmet = true;
        if (budget.retention_error) entry.retention_error = budget.retention_error;
        if (budget.retention_failing) entry.retention_failing = true;
        const shortSince = Object.entries(historyHorizonShort?.rules ?? {})
          .filter(([ruleId]) => RULE_HORIZONS.get(ruleId)?.families.includes(family))
          .map(([, rule]) => rule?.since_ts)
          .filter((since) => typeof since === "string" && Number.isFinite(Date.parse(since)))
          .sort()[0];
        // I11: a never-created store reads "not observed (no store)", never "horizon short since X"
        // (its rules' carried-forward entries stay on history_horizon_short itself).
        if (shortSince && entry.store !== "absent") entry.horizon_short_since = shortSince;
      }
    }
  }

  const collectorHasError = evidence.some((envelope) => envelope.status === "error")
    || (structuralCollectorStatuses ?? []).some((entry) => entry.status === "error");
  const storageWriteError = combineErrors(metricPersistError, structuralFactPersistError);
  const retentionError = combineErrors(write.retention_error, structuralFacts?.retention_error);
  const statusRecord = {
    ts,
    state: collectorHasError || storageWriteError || retentionError || carriedRetentionFailure ? "error" : "ok",
    mode: options.mode ?? "foreground",
    profile,
    collector_statuses: evidence.map((envelope) => ({ id: envelope.id, status: envelope.status, tool: envelope.trace?.tool })),
    points_written: write.written_count,
    retention: write.retention,
    ...(structuralCollectorStatuses ? { structural_collector_statuses: structuralCollectorStatuses } : {}),
    ...(storageWriteError ? { storage_write_error: storageWriteError } : {}),
    ...(retentionError ? { retention_error: retentionError } : {}),
    ...(factStoreCompleteness ? { fact_store_completeness: factStoreCompleteness } : {}),
    ...(factStoreBudgetsStatus ? { fact_store_budgets: factStoreBudgetsStatus } : {}),
    ...(factStoreLegacy ? { fact_store_legacy: factStoreLegacy } : {}),
    ...(factStoreDeprecations.length > 0 ? { fact_store_deprecations: factStoreDeprecations } : {}),
    ...(historyHorizonShort ? { history_horizon_short: historyHorizonShort } : {}),
    ...(noveltySeenSets ? { novelty_seen_sets: noveltySeenSets } : {}),
    // Component D (trusted-state step-1, §7): an installation MODE, not a per-tick/per-read
    // property, so it is unconditional here (unlike the ...(x ? {...} : {}) spreads above, which
    // are conditional on genuinely-computed-this-tick evidence). Display/disclosure only -- see
    // INTEGRITY_LEVEL_UNPROTECTED_SAME_UID's doc comment for the never-consulted-by-trust-logic
    // invariant.
    integrity_level: INTEGRITY_LEVEL_UNPROTECTED_SAME_UID,
  };
  const persistStatus = options.writeDaemonStatus ?? writeDaemonStatus;
  let status;
  try {
    status = await persistStatus(descartesPaths, statusRecord);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[daemon] writeDaemonStatus failed this tick (${message}); continuing with the in-memory status, not fabricating health`);
    // Finding F4-B1: a writeDaemonStatus failure IS itself a genuine persistence failure this
    // tick, so `state` must become "error" here too -- never left as whatever statusRecord.state
    // happened to already be (which could still be "ok" if collectors and the earlier persist
    // steps were all healthy). combineErrors preserves an earlier same-tick storageWriteError
    // (e.g. metric-persist also failed) rather than one overwriting the other.
    status = {
      ...statusRecord,
      state: "error",
      storage_write_error: combineErrors(statusRecord.storage_write_error, message),
    };
  }
  // Regression fix (sol re-review of the 7.2 re-phasing): computing the detector candidates
  // MUTATES detector stores (baseline folds, credential/lineage advances), so it must NOT run
  // when evaluateAlerts is false — otherwise the next enabled tick treats the changed state as
  // baseline and misses the signal, violating the option's prior no-detector-I/O contract.
  // Declared at this scope (not inside the branch) because the containment phase below re-merges
  // mainExtraCandidates; that block only runs when mainAlerts is truthy, i.e. when the branch ran.
  let mainExtraCandidates;
  let mainAlerts;
  let coveredAlertIds;
  let alertPersistenceError;
  // Detector-reported recovery coverage (§8.B): the per-tick, owner-scoped map of the alert
  // identities each producer LABEL reported it genuinely evaluated this tick (Map<label,
  // Set<alertId>>). Populated by safeCandidates at the twelve detector call sites below and consumed
  // by computeCoveredAlerts to authorize recovery per identity. Shared across BOTH persistence
  // passes (the containment pass re-persists the same detector alerts, so their coverage must carry
  // over). In this slice NO producer is converted, so it stays empty and every coverage-subject
  // family freezes — the intended, safe intermediate state until the per-producer conversion slice.
  const evaluatedByLabel = new Map();
  // BLOCKER 1 re-gate: every safeCandidates call below that produces alert candidates (the twelve
  // fast-tick detectors AND, further down, the containment-recommendation phase) shares this ONE
  // Set, so a label recorded here reflects a genuine exception this tick regardless of which call
  // site caught it. Read at two different points in time deliberately (see coveredAlertIds and
  // containmentCoveredAlertIds below) -- the main call's coveredAlertIds is computed once the twelve
  // detectors have run but strictly BEFORE containment-recommendation is even attempted, which is
  // exactly the phase-appropriate boundary: containment's own failure cannot retroactively affect
  // a persistence pass that already happened.
  const failedDetectorLabels = new Set();
  const successfulRetentionFamilies = new Set(
    Object.entries(structuralFacts?.families ?? {})
      .filter(([, result]) => result && typeof result === "object" && !Array.isArray(result)
        && Object.prototype.hasOwnProperty.call(result, "retention")
        && result.append_error === undefined)
      .map(([family]) => family),
  );
  if (options.evaluateAlerts !== false) {
    // Per-detector DI seams (mirrors the file's existing options.<fn> ?? <fn> pattern, e.g.
    // loadLearnedConfig/readFactPoints/adjudicateAlertNotifications above) so a single detector
    // can be overridden in isolation -- both for tests injecting a throwing detector, and for any
    // future caller needing to substitute one producer without touching the other eleven.
    const computeActiveConstraint = options.computeActiveConstraintCandidates ?? computeActiveConstraintCandidates;
    const computeProvenanceWarning = options.computeProvenanceWarningCandidates ?? computeProvenanceWarningCandidates;
    const computeProvenanceIdentity = options.computeProvenanceIdentityCandidates ?? computeProvenanceIdentityCandidates;
    const computeSessionBaseline = options.computeSessionBaselineCandidates ?? computeSessionBaselineCandidates;
    const computeCorrelation = options.computeCorrelationCandidates ?? computeCorrelationCandidates;
    const computePeerBaseline = options.computePeerBaselineCandidates ?? computePeerBaselineCandidates;
    const computeServiceBaseline = options.computeServiceBaselineCandidates ?? computeServiceBaselineCandidates;
    const computeCanaryBaseline = options.computeCanaryBaselineCandidates ?? computeCanaryBaselineCandidates;
    const computeProcessLineageBaseline = options.computeProcessLineageBaselineCandidates ?? computeProcessLineageBaselineCandidates;
    const computeScheduledJobBaseline = options.computeScheduledJobBaselineCandidates ?? computeScheduledJobBaselineCandidates;
    const computeServiceAppearance = options.computeServiceAppearanceCandidates ?? computeServiceAppearanceCandidates;
    const computeCredentialAccess = options.computeCredentialAccessCandidates ?? computeCredentialAccessCandidates;
    // §8.D / BLOCKER-2 (b): the immutable per-tick config snapshot is threaded into every producer's
    // options, AND the loadWatchConfig/loadLearnedConfig loader seams are OVERRIDDEN (via
    // snapshotLoaders, above) to resolve to the frozen snapshot values. Every producer reads its tier
    // gate through `options.loadWatchConfig ?? loadWatchConfig` (session-baseline.js:625) or
    // `options.loadLearnedConfig ?? loadLearnedConfig` (canary/credential/provenance), so overriding
    // them here makes even an UNCONVERTED producer consume the single frozen snapshot this tick
    // instead of re-reading watch.json/learned.json off disk -- a second disk read could observe a
    // mid-tick enablement flip and desync the producer's own gate from the daemon's tier veto. These
    // override any loader the test/caller injected (options.load*Config), which is correct: that
    // injected loader was already consumed ONCE, above, to BUILD the snapshot; the producers must see
    // that same first value, not a fresh read. The SAME snapshotLoaders are spread into the
    // second-pass containment-recommendation producer below. Each fast-tick producer receives
    // a fresh shallow copy of this base object below, so a producer can neither reassign a loader
    // nor mutate another producer's top-level options. (This is the seam the per-producer
    // conversion slice will build coverage reporting on; wiring it to the snapshot now is the
    // BLOCKER-2 fix, not the conversion.)
    const detectorOptions = { ...options, configSnapshot, ...snapshotLoaders };
    const detectorOptionsFor = (extra = {}) => ({ ...detectorOptions, ...extra });
    // Cross-cutting SURVIVABILITY fix: each entry is now individually fail-soft via
    // safeCandidates() -- a throw from any one detector degrades to [] (+ a warning) for that
    // detector THIS tick only, instead of aborting the whole array build and silently dropping
    // every OTHER detector's candidates for the tick. Order/arguments unchanged from before.
    // BLOCKER 1 re-gate: `failedDetectorLabels` is now threaded as safeCandidates' 4th argument at
    // every one of these twelve call sites, so a genuine exception here is ALSO recorded (not just
    // degraded to `[]`) for the coveredAlertIds computation below.
    mainExtraCandidates = [
          ...await safeCandidates("active-constraint", () => computeActiveConstraint(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("provenance-warning", () => computeProvenanceWarning(descartesPaths, detectorOptionsFor()), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("provenance-identity", () => computeProvenanceIdentity(descartesPaths, detectorOptionsFor()), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("session", () => computeSessionBaseline(descartesPaths, detectorOptionsFor({ activeFreshnessMs, structuralIntervalMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("correlation", () => computeCorrelation(descartesPaths, detectorOptionsFor()), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("peer", () => computePeerBaseline(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("service", () => computeServiceBaseline(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("canary", () => computeCanaryBaseline(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("process-lineage", () => computeProcessLineageBaseline(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("scheduled-job", () => computeScheduledJobBaseline(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("service-appearance", () => computeServiceAppearance(descartesPaths, detectorOptionsFor({ activeFreshnessMs })), [], failedDetectorLabels, evaluatedByLabel),
          ...await safeCandidates("credential-access", () => computeCredentialAccess(descartesPaths, detectorOptionsFor()), [], failedDetectorLabels, evaluatedByLabel),
        ];
    // BLOCKER 1 re-gate: computed HERE, after the twelve detectors above have actually run (so
    // failedDetectorLabels reflects this tick's real outcome) and BEFORE the main persistence
    // call below -- authorizes recovery only for rule_ids that are neither history-dependent
    // (while history is untrustworthy, unchanged from Fix 3) NOR owned by a detector that
    // genuinely threw this tick (new). `undefined` (fully unrestricted) whenever none of the
    // restrictions below apply -- byte-identical to the pre-fix default for the common,
    // nothing-wrong tick.
    //
    // alwaysExcludedRuleIds: containmentRecommendationRuleIds() -- containment.recommend.* is
    // EXCLUSIVELY evaluated by the second (containment) persistence pass below, which
    // structurally cannot run before this main call: computeContainmentRecommendationCandidates
    // consumes THIS call's own `mainAlerts` result as its input (see its own doc comment in
    // containment-recommend.js). This main call can therefore never know, at this point, whether
    // containment will succeed or throw this tick -- so it must NEVER authorize recovery for
    // containment.recommend.* itself (unconditionally, every tick), leaving that authority
    // exclusively with the containment call, which DOES know its own outcome by the time it runs.
    // Absent this, an unrestricted main call would mark a still-active containment.recommend.*
    // record "recovered" here whenever it is simply absent from mainExtraCandidates (which is
    // ALWAYS, every tick, success or failure -- containment candidates are never part of
    // mainExtraCandidates) -- ordinarily self-healed the same tick when the containment call
    // re-derives and reactivates the same candidate, but NOT when containment itself throws,
    // which is exactly BLOCKER 1's phase-appropriate-coverage requirement.
    // NOT gated on any kill switch: the 12 detectors above run regardless, so a detector EXCEPTION
    // must exclude its family from recovery ALWAYS. Gating the whole computation on a kill
    // switch's enabled flag (an earlier attempt did exactly this on learned.enabled) reopened
    // BLOCKER 1: a throwing detector still fabricated a "recovered" whenever that flag was off,
    // REGARDLESS of whether the throwing detector has its own gate (a "no gate of its own"
    // detector like canary-baseline was the sharpest illustration of the bug, not a description of
    // canary itself -- canary-baseline.js IS learned-gated, same as correlation; see the
    // fact-history-read comment above for the two-flag-OR fix to the sibling gap this created).
    // The same whole-computation-gated regression is reachable via either watchConfigForHistory.
    // enabled or learnedConfigForHistory.enabled now that both exist -- watch defaults ON, so
    // watch-disabled isn't the common case today, but an operator running `baseline disable` (or
    // a fresh ENOENT-disabled watch.json) reaches it exactly the same way learned-disabled did
    // before this slice (regression-tested: daemon.test.js's "BLOCKER 1 re-gate" test drives BOTH
    // flags disabled). So the call stays unconditional. Post-§8, computeCoveredAlerts no longer
    // has an early-return/unrestricted path (it always returns an identity-keyed Set, freezing
    // every coverage-subject family that wasn't reported evaluated); it performs one cheap local
    // alert-record read per pass. The fact-store's own "no I/O when disabled" invariant is
    // untouched (historyTrust is {trust:false} when BOTH watch and learned are disabled -> no fact
    // read; see that branch below).
    // The containment exclusion (first spread below) stays scoped to the AUTHOR flag (plan
    // §3.2/§12.3 fact 2: containment stays opt-in, unmoved by this slice) -- reuses
    // learnedConfigForHistory (loaded once, above, for the fact-history-read OR) rather than
    // loading learnedConfig a third time. Passed ONLY when learned is enabled: containment is
    // inert when learned is off (Slice 7.2 -> zero recommendations, and a stale recommendation
    // SHOULD then recover), so there is nothing to withhold.
    //
    // BLOCKER-3 re-gate (daybreak-blue round 2, the root of the class) + BLOCKER-1 (this slice): the
    // second spread below is the tier-ownership exclusion, independent of global historyTrust. It is
    // now derived DIRECTLY from the COMPLETE SECURITY_RULE_OWNERSHIP registry via tierVetoedRuleIds()
    // -- every WATCH-owned rule whenever watch is off, every AUTHOR-owned rule whenever learned is off
    // -- rather than from the old history-dependent-only WATCH_OWNED/AUTHOR_OWNED spreads it used to
    // build inline. This closes BLOCKER-1: the old spreads never named the positive-evidence AUTHOR
    // rules (canary.tripped, credential.access) or the provenance families, so once those producers
    // convert an owner reporting an identity evaluated while its tier was off would have fabricated a
    // recovery (see tierVetoedRuleIds()'s doc comment for the reproduction). This is NOT redundant
    // with history-untrusted exclusion: a tier can be disabled while the OTHER tier's history read is
    // perfectly trustworthy (e.g. the DEFAULT watch:true/learned:false population), in which case
    // historyUntrusted is false but the disabled tier's own detectors still never ran this tick --
    // silence from a disabled tier is not a genuine clear, regardless of how trustworthy the
    // fact-history happens to be. This DOES mean alwaysExcludedRuleIds.length === 0 (hence the
    // early-return "zero I/O" fast path) is no longer reachable on a tick where either tier is
    // off -- true for the default population itself (learned off by default) -- but that I/O is
    // one cheap local alert-record read, not a fact-store read; the fact store's own "no I/O when
    // disabled" invariant is untouched by this (cc21f35's else-branch still holds: no fact read
    // happens when both tiers are off). A genuine detector failure still forces its family's
    // exclusion via failedLabels on top of all sources, on either call site.
    coveredAlertIds = await computeCoveredAlerts(descartesPaths, options, {
      historyVetoedRuleIds,
      failedLabels: failedDetectorLabels,
      evaluatedByLabel,
      horizonVetoedRuleIds,
      successfulRetentionFamilies,
      alwaysExcludedRuleIds: [
        ...(learnedConfigForHistory.enabled ? containmentRecommendationRuleIds() : []),
        ...tierVetoedRuleIds({ watchEnabled: watchConfigForHistory.enabled, learnedEnabled: learnedConfigForHistory.enabled }),
      ],
    });
    mainAlerts = await evaluateAndPersistAlerts(descartesPaths, {
        now: ts,
        daemonStatus: status,
        windowMs: options.alertWindowMs,
        // Slice S4, additive: both sources land in the same concatenation before the one
        // evaluateAndPersistAlerts/applyAlertCandidates call, in the same commit as the
        // constraint candidates — matching applyAlertCandidates' recovery semantics (plan
        // section 4 / S-live-1 grounding).
        extraCandidates: mainExtraCandidates,
        successfulRetentionFamilies,
        // Detector-reported recovery coverage (§8.A): identity-keyed covered set. Freeze-by-default
        // for every coverage-subject family (recover only what a producer reported evaluated this
        // tick), intersected with the §7.7 vetoes (history-untrusted, failed-detector, and this
        // call's ADDITIONAL always-excluded containment.recommend.* — withheld here because
        // containment is the only phase that legitimately evaluates it) and tier-ownership.
        coveredAlertIds,
        lockTimeoutMs: options.lockTimeoutMs,
        lockRetryMs: options.lockRetryMs,
      });
    if (mainAlerts?.persistence_status === "lock_unavailable") {
      alertPersistenceError = mainAlerts.persistence_error;
      const failedStatus = {
        ...status,
        state: "error",
        storage_write_error: combineErrors(status.storage_write_error, `alert-store: ${alertPersistenceError}`),
      };
      try {
        status = await persistStatus(descartesPaths, failedStatus);
      } catch {
        status = failedStatus;
      }
    }
  }
  let alerts = mainAlerts;
  if (mainAlerts && !alertPersistenceError) {
    // Containment is a second phase: it consumes only the main evaluation's current active alerts
    // and notification-due IDs. Re-merge the first phase's candidates so shared recovery semantics
    // do not recover sibling alert families during the containment persistence pass.
    // Same DI-seam + safeCandidates discipline as the twelve detectors above: a throw here must
    // not blind the main evaluation's alerts, which are already computed and only being re-merged.
    // BLOCKER 1 re-gate: this call also threads `failedDetectorLabels` -- a genuine
    // computeContainmentRecommendationCandidates exception must withhold ITS OWN
    // containment.recommend.* rule_ids from recovery too (phase-appropriate: only for this,
    // second, persistence pass -- the main call above already ran without knowing whether
    // containment would fail).
    const computeContainmentRecommendation = options.computeContainmentRecommendationCandidates ?? computeContainmentRecommendationCandidates;
    // BLOCKER-2 (b): the second-pass containment-recommendation producer reads its own tier gate via
    // `options.loadLearnedConfig ?? loadLearnedConfig` (containment-recommend.js:331), so it too must
    // consume the frozen per-tick snapshot rather than re-reading learned.json off disk -- spread the
    // SAME snapshotLoaders the twelve fast-tick detectors get, so this pass cannot desync from the
    // snapshot the daemon's tier veto used.
    const containmentCandidates = await safeCandidates("containment-recommendation", () => computeContainmentRecommendation(descartesPaths, {
      ...options,
      ...snapshotLoaders,
      evaluation: mainAlerts,
    }), [], failedDetectorLabels);
    // BLOCKER 1 re-gate, phase-appropriate coverage: computed SEPARATELY from the main call's
    // coveredAlertIds -- this is the ONE call site where containment.recommend.* is ever
    // legitimately evaluated, so (unlike the main call above) it does NOT add
    // containmentRecommendationRuleIds() to alwaysExcludedRuleIds: containment.recommend.* stays
    // eligible for recovery whenever containment-recommendation genuinely ran this tick (whether
    // it found something or genuinely found nothing -- both are real evaluations, matching this
    // module's own documented "load-bearing fail-closed transition" for a genuine opt-in-off/
    // trigger-cleared recovery). When containment-recommendation itself just threw,
    // "containment-recommendation" is already in failedDetectorLabels (recorded by safeCandidates
    // above) and ruleIdsForFailedLabel excludes its closed rule_id set exactly like any other
    // failed detector -- so a genuine exception still cannot fabricate a recovery of its own
    // family, matching every other detector's protection.
    // BLOCKER-3 re-gate (daybreak-blue round 2) + BLOCKER-1 (this slice): the SAME registry-derived
    // tier-ownership exclusion as the main call above IS added here though (tierVetoedRuleIds() over
    // the complete SECURITY_RULE_OWNERSHIP registry) -- this second persistence pass re-derives its
    // own coveredAlertIds independently (BLOCKER 1's phase-appropriate-coverage requirement), so a
    // tier-disabled family (including the positive-evidence AUTHOR rules the old sets missed) must be
    // protected at THIS call site too, not just the main one, or a fix scoped to only the main call
    // would leave this pass fabricating the exact same recovery (mirrors Fix 3's own "BOTH
    // evaluateAndPersistAlerts call sites are patched" precedent).
    // Same history-untrusted and failed-main-detector restrictions as the main call otherwise
    // (shared base, applied identically at both sites); `undefined` (fully unrestricted, no extra
    // I/O) only when both tiers are enabled AND containment succeeds AND nothing else this tick
    // warrants a restriction.
    const containmentCoveredAlertIds = await computeCoveredAlerts(descartesPaths, options, {
      historyVetoedRuleIds,
      failedLabels: failedDetectorLabels,
      evaluatedByLabel,
      horizonVetoedRuleIds,
      successfulRetentionFamilies,
      alwaysExcludedRuleIds: tierVetoedRuleIds({ watchEnabled: watchConfigForHistory.enabled, learnedEnabled: learnedConfigForHistory.enabled }),
    });
    const containmentAlerts = await evaluateAndPersistAlerts(descartesPaths, {
      now: ts,
      daemonStatus: status,
      historySummary: mainAlerts.history_summary,
      windowMs: options.alertWindowMs,
      extraCandidates: [...mainAlerts.candidates, ...mainExtraCandidates, ...containmentCandidates],
      successfulRetentionFamilies,
      // Detector-reported recovery coverage (§8.A), containment pass: same identity-keyed
      // freeze-by-default covered set as the main call, sharing the SAME evaluatedByLabel report (so
      // the detector families re-persisted here keep their coverage), but WITHOUT the main call's
      // always-excluded containment.recommend.* — this is the one phase that legitimately evaluates
      // it, so it recovers whenever containment genuinely ran (unless containment-recommendation
      // itself threw, in which case failedLabels excludes its rule_ids just like any other
      // detector). §7.7 vetoes (history-untrusted, failed-detector, tier-ownership) apply identically.
      coveredAlertIds: containmentCoveredAlertIds,
      lockTimeoutMs: options.lockTimeoutMs,
      lockRetryMs: options.lockRetryMs,
    });
    const finalAlertsById = new Map((containmentAlerts.alerts ?? []).map((alert) => [alert.id, alert]));
    const dueEntryStillApplies = (entry) => {
      const finalAlert = finalAlertsById.get(entry.alert_id);
      if (!finalAlert || ["recovered", "suppressed"].includes(finalAlert.status)) return false;
      if (entry.storm) return finalAlert.incident_state === "incident_storm";
      const incident = finalAlert.incidents?.[entry.incident_key];
      return Boolean(incident && !["recovered", "suppressed"].includes(incident.status));
    };
    alerts = {
      ...containmentAlerts,
      // The second persistence pass must not hide ordinary alerts that were due in the first
      // phase; containment adds to the same delivery set rather than replacing it. Filter against
      // the second pass's final persisted state so an entry from the first pass cannot resurrect a
      // recommendation that the containment pass recovered in the same tick.
      notification_due_ids: [...new Set([
        ...(mainAlerts.notification_due_ids ?? []),
        ...(containmentAlerts.notification_due_ids ?? []),
      ].filter((id) => [...(mainAlerts.notification_due_incidents ?? []), ...(containmentAlerts.notification_due_incidents ?? [])]
        .some((entry) => entry.alert_id === id && dueEntryStillApplies(entry))))],
      notification_due_incidents: [...new Map([
        ...(mainAlerts.notification_due_incidents ?? []),
        ...(containmentAlerts.notification_due_incidents ?? []),
      ].filter(dueEntryStillApplies).map((entry) => [`${entry.alert_id}\0${entry.incident_key}`, entry])).values()],
      adjudication_due_incidents: [...new Map([
        ...(mainAlerts.adjudication_due_incidents ?? []),
        ...(containmentAlerts.adjudication_due_incidents ?? []),
      ].map((entry) => [`${entry.alert_id}\0${entry.incident_key}`, entry])).values()],
      adjudication_due_ids: [...new Set([
        ...(mainAlerts.adjudication_due_ids ?? []),
        ...(containmentAlerts.adjudication_due_ids ?? []),
      ])],
    };
    if (alerts?.persistence_status === "lock_unavailable") {
      alertPersistenceError = alerts.persistence_error;
      const failedStatus = {
        ...status,
        state: "error",
        storage_write_error: combineErrors(status.storage_write_error, `alert-store: ${alertPersistenceError}`),
      };
      try {
        status = await persistStatus(descartesPaths, failedStatus);
      } catch {
        status = failedStatus;
      }
    }
  }
  // Finding F6: read alert-intelligence config ONCE and share it with every delivery route.
  const alertIntelligenceConfig = alerts ? (options.alertIntelligenceConfig ?? await readAlertIntelligenceConfig(descartesPaths)) : undefined;
  const delivered = alerts && !alertPersistenceError
    ? await safeCandidates(
        "alert-delivery",
        () => deliverDueAlertNotifications(descartesPaths, alerts, {
          now: ts,
          config: alertIntelligenceConfig,
          deliverNotification: options.deliverNotification,
          emitSessionAlertSignals: options.emitSessionAlertSignals ?? emitSessionAlertSignals,
          emitMetricAlertFallbackSignals: options.emitMetricAlertFallbackSignals ?? emitMetricAlertFallbackSignals,
          adjudicateAlertNotifications: options.adjudicateAlertNotifications ?? adjudicateAlertNotifications,
          createSession: options.createSession,
          appendAuditRecord: options.appendAuditRecord,
          deliverSessionAlerts: options.deliverSessionAlerts,
          deliverMetricAlertFallback: options.deliverMetricAlertFallback,
          adjudicateAlerts: options.adjudicateAlerts,
        }),
        undefined,
      )
    : undefined;
  const sessionAlertDelivery = delivered?.sessionAlertDelivery?.route_failed ? undefined : delivered?.sessionAlertDelivery;
  const metricAlertFallback = delivered?.metricAlertFallback?.route_failed ? undefined
    : delivered?.metricAlertFallback
      ?? (alertIntelligenceConfig?.enabled && options.deliverMetricAlertFallback !== false ? { fired: [], skipped: "intelligence_enabled" } : undefined);
  const alertIntelligence = delivered?.alertIntelligence;
  return { evidence, points, write, status, alerts, alertIntelligence, sessionAlertDelivery, metricAlertFallback, alertPersistenceError, structuralEvidence, structuralFacts, shadowEvaluation };
}

export const DAEMON_LABEL = "com.lightless-labs.descartes.daemon";

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function systemdEscape(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function xmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function homeDir(env = process.env) {
  return env.HOME || os.homedir();
}

function daemonLogDir(descartesPaths) {
  return path.join(descartesPaths.stateDir, "daemon");
}

function xdgEnvLines(env = process.env) {
  return ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"]
    .filter((name) => env[name] && String(env[name]).trim())
    .map((name) => `Environment="${name}=${systemdEscape(env[name])}"`);
}

export function resolveDaemonServiceSpec(descartesPaths, options = {}) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const nodePath = options.nodePath ?? process.execPath;
  const cliPath = options.cliPath ?? process.argv[1];
  if (!cliPath) throw new Error("Cannot determine Descartes CLI path for daemon service installation");

  const logDir = daemonLogDir(descartesPaths);
  if (platform === "darwin") {
    const installPath = path.join(homeDir(env), "Library", "LaunchAgents", `${DAEMON_LABEL}.plist`);
    const programArguments = [nodePath, cliPath, "daemon", "run", "--foreground"];
    const argumentXml = programArguments.map((argument) => `\t\t<string>${xmlEscape(argument)}</string>`).join("\n");
    return {
      service_manager: "launchd-user",
      label: DAEMON_LABEL,
      install_path: installPath,
      log_dir: logDir,
      content: `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n\t<key>Label</key>\n\t<string>${DAEMON_LABEL}</string>\n\t<key>ProgramArguments</key>\n\t<array>\n${argumentXml}\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n\t<key>StandardOutPath</key>\n\t<string>${xmlEscape(path.join(logDir, "stdout.log"))}</string>\n\t<key>StandardErrorPath</key>\n\t<string>${xmlEscape(path.join(logDir, "stderr.log"))}</string>\n</dict>\n</plist>\n`,
    };
  }

  if (platform === "linux") {
    const configBase = path.dirname(descartesPaths.configDir);
    const installPath = path.join(configBase, "systemd", "user", "descartes.service");
    const execStart = [nodePath, cliPath, "daemon", "run", "--foreground"].map(shellQuote).join(" ");
    const envLines = xdgEnvLines(env).join("\n");
    return {
      service_manager: "systemd-user",
      label: "descartes.service",
      install_path: installPath,
      log_dir: logDir,
      content: `[Unit]\nDescription=Descartes local history daemon\nDocumentation=https://github.com/Lightless-Labs/descartes\n\n[Service]\nType=simple\nExecStart=${execStart}\nRestart=on-failure\nRestartSec=10\n${envLines ? `${envLines}\n` : ""}\n[Install]\nWantedBy=default.target\n`,
    };
  }

  throw new Error(`Daemon install is not supported on ${platform}. Use 'descartes daemon run --foreground' instead.`);
}

async function readFileIfPresent(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

function publicServiceSpec(spec) {
  return {
    service_manager: spec.service_manager,
    label: spec.label,
    install_path: spec.install_path,
    log_dir: spec.log_dir,
  };
}

export async function installDaemonService(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  await fs.mkdir(path.dirname(spec.install_path), { recursive: true, mode: 0o700 });
  await fs.mkdir(spec.log_dir, { recursive: true, mode: 0o700 });
  const existing = await readFileIfPresent(spec.install_path);
  if (existing === spec.content) {
    return { status: "unchanged", installed: true, ...publicServiceSpec(spec) };
  }
  await fs.writeFile(spec.install_path, spec.content, { mode: 0o600 });
  return { status: existing === undefined ? "installed" : "updated", installed: true, ...publicServiceSpec(spec) };
}

async function runServiceCommand(command, args, options = {}) {
  const runner = options.runner ?? execFileAsync;
  try {
    const result = await runner(command, args, { timeout: 10000, maxBuffer: 1024 * 256 });
    return { ok: true, command: [command, ...args], stdout: result?.stdout ?? "", stderr: result?.stderr ?? "", exit_code: 0 };
  } catch (error) {
    return {
      ok: false,
      command: [command, ...args],
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? error?.message ?? String(error),
      exit_code: error?.code ?? 1,
    };
  }
}

function commandText(result) {
  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`.toLowerCase();
}

function isAlreadyLoaded(result) {
  const text = commandText(result);
  return text.includes("already bootstrapped") || text.includes("service is already loaded") || text.includes("already loaded") || text.includes("eexist");
}

function isNotLoaded(result) {
  const text = commandText(result);
  return text.includes("could not find service") || text.includes("no such process") || text.includes("not bootstrapped") || text.includes("not loaded") || text.includes("enoent");
}

function launchdDomain(options = {}) {
  return `gui/${options.uid ?? process.getuid?.() ?? os.userInfo().uid}`;
}

export function parseLaunchdPrintState(output) {
  const match = String(output ?? "").match(/^\s*state\s*=\s*([^\n]+)\s*$/m);
  return match ? match[1].trim() : undefined;
}

function launchdServiceName(spec, options = {}) {
  return `${launchdDomain(options)}/${spec.label}`;
}

async function launchdRuntimeStatus(spec, options = {}) {
  const service = launchdServiceName(spec, options);
  const result = await runServiceCommand("launchctl", ["print", service], options);
  const state = result.ok ? parseLaunchdPrintState(result.stdout) : undefined;
  return {
    runtime_checked: true,
    running: state === "running",
    loaded: result.ok,
    runtime_status: result.ok ? state ?? "loaded" : isNotLoaded(result) ? "not_loaded" : "unknown",
    runtime_command: result.command,
    runtime_error: result.ok ? undefined : result.stderr,
  };
}

async function waitForLaunchdUnloaded(spec, options = {}) {
  const attempts = options.unloadWaitAttempts ?? 20;
  const intervalMs = options.unloadWaitIntervalMs ?? 250;
  const sleeper = options.sleep ?? sleep;
  let status;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    status = await launchdRuntimeStatus(spec, options);
    if (!status.loaded) return status;
    await sleeper(intervalMs, undefined, { ref: true });
  }
  return status;
}

async function runtimeStatusForSpec(spec, options = {}) {
  if (options.runtime === false) return { runtime_checked: false };
  if (spec.service_manager === "launchd-user") {
    return launchdRuntimeStatus(spec, options);
  }
  if (spec.service_manager === "systemd-user") {
    const active = await runServiceCommand("systemctl", ["--user", "is-active", spec.label], options);
    const enabled = await runServiceCommand("systemctl", ["--user", "is-enabled", spec.label], options);
    return {
      runtime_checked: true,
      running: active.ok && String(active.stdout).trim() === "active",
      enabled: enabled.ok && ["enabled", "static"].includes(String(enabled.stdout).trim()),
      runtime_status: String(active.stdout || active.stderr || "unknown").trim(),
      enablement_status: String(enabled.stdout || enabled.stderr || "unknown").trim(),
      runtime_commands: [active.command, enabled.command],
    };
  }
  return { runtime_checked: false };
}

export async function daemonServiceStatus(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  const existing = await readFileIfPresent(spec.install_path);
  return {
    status: existing === undefined ? "not_installed" : existing === spec.content ? "installed" : "drifted",
    installed: existing !== undefined,
    content_matches: existing === spec.content,
    service_manager: spec.service_manager,
    label: spec.label,
    install_path: spec.install_path,
    log_dir: spec.log_dir,
    ...(await runtimeStatusForSpec(spec, options)),
    // Component D, Fix-2-correction surface (trusted-state step-1 §7 / "R1 made signable" Fix 2):
    // daemonServiceStatus (not daemon-status.json) is what `descartes daemon status --json`
    // actually shows -- it never reads daemon-status.json (only spec.install_path via
    // readFileIfPresent, see above), so the label is added here directly, independent of the
    // daemon-status.json record's own copy (statusRecord, above). Same installation-mode
    // constant, display/disclosure only.
    integrity_level: INTEGRITY_LEVEL_UNPROTECTED_SAME_UID,
  };
}

export async function startDaemonService(descartesPaths, options = {}) {
  const install = await installDaemonService(descartesPaths, options);
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  if (spec.service_manager === "launchd-user") {
    const commands = [];
    const preStatus = await launchdRuntimeStatus(spec, options);
    commands.push(preStatus.runtime_command);
    if (preStatus.loaded && preStatus.running) {
      return { status: "already_running", running: true, installed: true, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, runtime_status: preStatus.runtime_status, commands };
    }
    if (preStatus.loaded && !preStatus.running) {
      const staleBootout = await runServiceCommand("launchctl", ["bootout", launchdServiceName(spec, options)], options);
      commands.push(staleBootout.command);
      if (!staleBootout.ok && !isNotLoaded(staleBootout)) {
        throw new Error(`Failed to clear stale launchd service state ${preStatus.runtime_status}: ${staleBootout.stderr || staleBootout.stdout}`);
      }
      const unloaded = await waitForLaunchdUnloaded(spec, options);
      commands.push(unloaded.runtime_command);
      if (unloaded.loaded) {
        throw new Error(`Failed to clear stale launchd service state ${unloaded.runtime_status}; try \`descartes daemon stop\` and retry in a few seconds.`);
      }
    }

    const domain = launchdDomain(options);
    const result = await runServiceCommand("launchctl", ["bootstrap", domain, spec.install_path], options);
    commands.push(result.command);
    if (result.ok) return { status: "started", install_status: install.status, running: true, installed: true, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, commands };

    const postStatus = await launchdRuntimeStatus(spec, options);
    commands.push(postStatus.runtime_command);
    if ((isAlreadyLoaded(result) || postStatus.loaded) && postStatus.running) {
      return { status: "already_running", running: true, installed: true, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, runtime_status: postStatus.runtime_status, commands };
    }

    const detail = postStatus.loaded
      ? `launchd reports service state ${postStatus.runtime_status}; run \`descartes daemon status --json\` and inspect ${spec.log_dir}/stderr.log`
      : `launchd reports service state ${postStatus.runtime_status}; inspect ${spec.log_dir}/stderr.log if it exists`;
    throw new Error(`Failed to start launchd service: ${result.stderr || result.stdout}\n${detail}`);
  }

  if (spec.service_manager === "systemd-user") {
    const daemonReload = await runServiceCommand("systemctl", ["--user", "daemon-reload"], options);
    if (!daemonReload.ok) throw new Error(`Failed to reload systemd user units: ${daemonReload.stderr || daemonReload.stdout}`);
    const enableNow = await runServiceCommand("systemctl", ["--user", "enable", "--now", spec.label], options);
    if (!enableNow.ok) throw new Error(`Failed to start systemd user service: ${enableNow.stderr || enableNow.stdout}`);
    return { status: "started", install_status: install.status, running: true, enabled: true, installed: true, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, commands: [daemonReload.command, enableNow.command] };
  }

  throw new Error(`Unsupported service manager: ${spec.service_manager}`);
}

export async function stopDaemonService(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  if (spec.service_manager === "launchd-user") {
    const service = `${launchdDomain(options)}/${spec.label}`;
    const result = await runServiceCommand("launchctl", ["bootout", service], options);
    if (result.ok) return { status: "stopped", running: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, commands: [result.command] };
    if (isNotLoaded(result)) return { status: "not_running", running: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, commands: [result.command] };
    throw new Error(`Failed to stop launchd service: ${result.stderr || result.stdout}`);
  }

  if (spec.service_manager === "systemd-user") {
    const disableNow = await runServiceCommand("systemctl", ["--user", "disable", "--now", spec.label], options);
    if (disableNow.ok) return { status: "stopped", running: false, enabled: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, commands: [disableNow.command] };
    if (isNotLoaded(disableNow) || commandText(disableNow).includes("not loaded")) return { status: "not_running", running: false, enabled: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, commands: [disableNow.command] };
    throw new Error(`Failed to stop systemd user service: ${disableNow.stderr || disableNow.stdout}`);
  }

  throw new Error(`Unsupported service manager: ${spec.service_manager}`);
}

export async function uninstallDaemonService(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  const existing = await readFileIfPresent(spec.install_path);
  if (existing === undefined) {
    return { status: "not_installed", installed: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path };
  }

  let stop;
  if (options.stopFirst !== false) {
    stop = await stopDaemonService(descartesPaths, options);
  }
  await fs.unlink(spec.install_path);
  return { status: "removed", installed: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path, stop };
}

function daemonUsage() {
  return `Usage:
  descartes daemon install [--json]
  descartes daemon start [--json]
  descartes daemon status [--json]
  descartes daemon stop [--json]
  descartes daemon uninstall [--json]
  descartes daemon run --foreground [--once] [--interval <duration>]

Install writes an idempotent user-level launchd/systemd service file. Start/stop load and unload it through the user service manager.
The foreground daemon loop is read-only, performs background LLM calls only if alert intelligence is explicitly enabled, and takes no remediation actions.
'status' reports integrity_level: "unprotected_same_uid" -- Descartes provides no independent protection against modification of its own state by a process running under the same UID. This is an honest disclosure of the current installation mode, not a trust decision.`;
}

function parseRunArgs(rest) {
  const options = { foreground: false, once: false, intervalMs: DEFAULT_DAEMON_INTERVAL_MS };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--foreground") options.foreground = true;
    else if (arg === "--once") options.once = true;
    else if (arg === "--interval" || arg === "--interval-seconds") {
      const value = rest[index + 1];
      if (!value) throw new Error(`${arg} requires a value`);
      options.intervalMs = arg === "--interval-seconds" ? Number(value) * 1000 : parseDurationMs(value, DEFAULT_DAEMON_INTERVAL_MS);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`Unknown daemon option: ${arg}\n\n${daemonUsage()}`);
    }
  }
  if (options.help) return options;
  if (!options.foreground) throw new Error(`Only foreground daemon runs are implemented in this milestone.\n\n${daemonUsage()}`);
  if (!Number.isFinite(options.intervalMs) || options.intervalMs < 1000) throw new Error("Daemon interval must be at least 1s");
  return options;
}

function parseLifecycleArgs(subcommand, rest) {
  const options = { subcommand, json: false };
  for (const arg of rest) {
    if (arg === "--json") options.json = true;
    else if (arg === "--help" || arg === "-h") options.help = true;
    else throw new Error(`Unexpected daemon ${subcommand} argument: ${arg}\n\n${daemonUsage()}`);
  }
  return options;
}

function parseDaemonArgs(args) {
  const [subcommand, ...rest] = args;
  if (!subcommand || subcommand === "--help" || subcommand === "-h") return { subcommand: "help" };
  if (!["install", "start", "status", "stop", "uninstall", "run"].includes(subcommand)) {
    throw new Error(`Unsupported daemon command: ${subcommand}\n\n${daemonUsage()}`);
  }
  return subcommand === "run" ? { subcommand, ...parseRunArgs(rest) } : parseLifecycleArgs(subcommand, rest);
}

function statusDescription(result) {
  const descriptions = {
    installed: "installed",
    updated: "updated",
    unchanged: "already installed and up to date",
    started: "started",
    already_running: "already running",
    stopped: "stopped",
    not_running: "not running",
    removed: "removed",
    not_installed: "not installed",
    drifted: "installed but differs from the expected Descartes service file",
  };
  return descriptions[result.status] ?? result.status;
}

export function renderDaemonResult(command, result) {
  const lines = [`Descartes daemon ${statusDescription(result)}.`];
  if (result.service_manager) lines.push(`Service manager: ${result.service_manager}`);
  if (result.label) lines.push(`Service: ${result.label}`);
  if (result.install_path) lines.push(`Service file: ${result.install_path}`);
  if (result.log_dir) lines.push(`Logs: ${result.log_dir}`);
  if (result.running !== undefined) lines.push(`Running: ${result.running ? "yes" : "no"}`);
  if (result.enabled !== undefined) lines.push(`Enabled: ${result.enabled ? "yes" : "no"}`);
  if (result.runtime_status) lines.push(`Runtime status: ${result.runtime_status}`);
  if (result.enablement_status) lines.push(`Enablement: ${result.enablement_status}`);
  if (result.content_matches === false) lines.push("Service file drift: yes");
  // Component D: display/disclosure only, guarded on presence like every other optional line
  // here -- install/start/stop/uninstall results never carry integrity_level, so their renders
  // stay unchanged.
  if (result.integrity_level) lines.push(`Integrity: ${result.integrity_level} (no independent protection against modification of Descartes state by a same-UID process)`);

  if (command === "install" && ["installed", "updated", "unchanged"].includes(result.status)) {
    lines.push("Next: run `descartes daemon start` to load/start the user service.");
  } else if (command === "start" && result.running) {
    lines.push("Next: run `descartes history summary` after a minute or two to inspect collected metrics.");
  } else if (command === "stop") {
    lines.push("The service file remains installed. Run `descartes daemon uninstall` to remove it.");
  }
  return lines.join("\n");
}

function printDaemonResult(command, result, options) {
  if (options.json) console.log(JSON.stringify(result, null, 2));
  else console.log(renderDaemonResult(command, result));
}

export async function runForegroundDaemonLoop(descartesPaths, options = {}) {
  const iterate = options.iterate ?? runDaemonIteration;
  const sleeper = options.sleep ?? sleep;
  const output = options.output ?? console.log;
  const shouldStop = options.shouldStop ?? (() => false);

  do {
    const result = await iterate(descartesPaths, { mode: "foreground" });
    output(JSON.stringify({ status: "ok", points_written: result.points.length, ts: result.status.ts }));
    if (options.once || shouldStop()) break;
    await sleeper(options.intervalMs, undefined, { ref: true });
  } while (!shouldStop());
}

export async function runDaemon(descartesPaths, args) {
  const options = parseDaemonArgs(args);
  if (options.subcommand === "help" || options.help) {
    console.log(daemonUsage());
    return;
  }
  if (options.subcommand === "install") {
    printDaemonResult("install", await installDaemonService(descartesPaths), options);
    return;
  }
  if (options.subcommand === "start") {
    printDaemonResult("start", await startDaemonService(descartesPaths), options);
    return;
  }
  if (options.subcommand === "status") {
    printDaemonResult("status", await daemonServiceStatus(descartesPaths), options);
    return;
  }
  if (options.subcommand === "stop") {
    printDaemonResult("stop", await stopDaemonService(descartesPaths), options);
    return;
  }
  if (options.subcommand === "uninstall") {
    printDaemonResult("uninstall", await uninstallDaemonService(descartesPaths), options);
    return;
  }

  let stopping = false;
  const stop = () => {
    stopping = true;
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    await runForegroundDaemonLoop(descartesPaths, {
      intervalMs: options.intervalMs,
      once: options.once,
      shouldStop: () => stopping,
    });
  } finally {
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    if (stopping) await writeDaemonStatus(descartesPaths, { state: "stopped", mode: "foreground" });
  }
}
