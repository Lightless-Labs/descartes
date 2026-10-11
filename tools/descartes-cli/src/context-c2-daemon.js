// Context plan C2 daemon glue (docs/plans/2026-10-06-context-aware-learned-baselines.md §4, §8.1-§8.2):
// sequences the C2 derivations around the structural tick's fact-store passes. DATA ONLY.
//
// The order on a completed structural tick (daemon.js runDaemonIteration):
//   1. prepareContextC2 -- AFTER the incumbent census and the C0 context facts are built: reads the
//      tick_summary chain state and the context_stats state (each validated against its own family's
//      ledger as it stands before this tick), builds the C2 facts that go into the context families
//      (binary states, VPN service states, lifecycle records, tmux attachments, created_vs_boot, the
//      daemon gap, context transitions). The daemon appends them with every other family (pass 1).
//   2. finalizeContextC2 -- AFTER pass 1: certifies the cited source passes (I70), derives the
//      tick_summary record and appends it to its own (derived) family, then commits the chain state
//      stamped with THAT pass; then the statistics records and their stamped state.
//
// Isolation: nothing here reads or writes an incumbent family's store, changes an incumbent fact
// point, or touches an alert. Every failure is caught by the caller and reported on the status record
// (`context_c2`); it never stops the incumbent facts from persisting and never changes the daemon's
// health state.

import { contextKeyId } from "./context-key.js";
import {
  factPointsFromBinaryStateEvidence,
  factPointsFromLifecycleRecordEvidence,
  factPointsFromSessionAttachmentEvidence,
  factPointsFromVpnServiceEvidence,
  observationInterval,
} from "./context-translators.js";
import {
  certifySourcePasses,
  configHash,
  deriveContextTransitions,
  deriveCreatedVsBoot,
  deriveStats,
  deriveTickSummary,
  descartesVersion,
  extractTickSnapshot,
  factPointsFromDaemonGap,
  factPointsFromTransitions,
  intervalChurn,
  readStatsState,
  readSummaryGapState,
  readSummaryChainState,
  SUMMARY_SOURCE_FAMILIES,
  writeStatsState,
  writeSummaryGapState,
  clearSummaryGapState,
  writeSummaryChainState,
} from "./context-summary.js";
import { appendFactPoints, factStoreExists, normalizeFactPoint, readFactPoints } from "./fact-store.js";
import { readFactIntegrityLedger } from "./fact-store-integrity.js";
import { factFamilyForName } from "./fact-families.js";

const VERDICTS = new Set(["verified", "unverified", "tripwire"]);
// The only families a C2 point may join the tick's shared pass in: the context families. Never an
// incumbent family, never a derived family (those are appended by finalizeContextC2 alone).
export const CONTEXT_C2_PASS_FAMILIES = Object.freeze(new Set(["host_lifecycle", "network_context", "session_context", "collector_state"]));

export async function recordContextC2Gap(descartesPaths, { ts, reason = "failed" } = {}) {
  const prior = await readSummaryGapState(descartesPaths);
  const priorCount = prior.status === "valid" ? prior.state.missing_count : 0;
  await writeSummaryGapState(descartesPaths, {
    schema_version: 1,
    missing_count: Math.min(priorCount + 1, 2 ** 32),
    first_ts: prior.status === "valid" ? prior.state.first_ts : ts,
    reason,
  });
}

/**
 * Isolation guard for the shared pass: the tick's fact batch is refused WHOLE (incumbents included)
 * on an unregistered fact_name, and a family's append fails on a point its store rejects. So every C2
 * point is checked here, before it joins the batch: a registered name, a context family, and a point
 * the store accepts (closed schema included). Throws on the first offender (the caller then drops
 * every C2 point and reports it); returns the points unchanged otherwise.
 */
export function admitContextC2Points(points) {
  for (const point of points ?? []) {
    const family = factFamilyForName(point?.fact_name);
    if (!CONTEXT_C2_PASS_FAMILIES.has(family)) throw new Error("context C2 point outside the context families; no C2 point joins this tick");
    normalizeFactPoint(point);
  }
  return points ?? [];
}

/**
 * Pass-1 half. Returns { points, context } where `points` are the C2 facts for the context families
 * and `context` carries what finalizeContextC2 needs. Pure apart from the two state/ledger reads.
 */
export async function prepareContextC2({ descartesPaths, evidence, basePoints, hostFacts, loginDedupe, ts, hmacKey, daemonIntervalMs, deps = {} }) {
  const readLedger = deps.readFactIntegrityLedger ?? readFactIntegrityLedger;
  const stateless = [
    ...factPointsFromBinaryStateEvidence(evidence, { ts, hmacKey }),
    ...factPointsFromVpnServiceEvidence(evidence, { ts, hmacKey }),
    ...factPointsFromLifecycleRecordEvidence(evidence, { ts, hmacKey, dedupe: loginDedupe }),
    ...factPointsFromSessionAttachmentEvidence(evidence, { ts, hmacKey }),
  ];
  const summaryLedger = await readLedger(descartesPaths, "tick_summary");
  const statsLedger = await readLedger(descartesPaths, "context_stats");
  const keyId = contextKeyId(hmacKey);
  const chainRead = await (deps.readSummaryChainState ?? readSummaryChainState)(descartesPaths, { ledger: summaryLedger.ledger ?? undefined, hmacKeyId: keyId });
  const statsRead = await (deps.readStatsState ?? readStatsState)(descartesPaths, { ledger: statsLedger.ledger ?? undefined });
  const gapRead = await readSummaryGapState(descartesPaths);
  const gapCount = gapRead.status === "valid" ? gapRead.state.missing_count : gapRead.status === "invalid" ? 1 : 0;
  const prevChain = chainRead.status === "valid" && gapCount === 0 ? chainRead.state : undefined;
  const snapshot = extractTickSnapshot({ evidence, points: [...(basePoints ?? []), ...stateless], hostFacts, ts, hmacKey, interval: daemonIntervalMs });
  const transitions = deriveContextTransitions(prevChain, snapshot);
  const sessionChurn = intervalChurn(prevChain?.session, snapshot.session);
  const rawVerdict = hostFacts?.currentBootVerdict;
  const created = deriveCreatedVsBoot({
    evidence,
    snapshot,
    arrivedKeys: sessionChurn.arrivedKeys,
    bootVerdict: VERDICTS.has(rawVerdict) ? rawVerdict : undefined,
    // Tri-state (C2 review M4): a step, a cross-check that saw none, or unknown (no previous reading).
    clockStep: transitions.transitions.some((t) => t.dimension === "clock_step") ? true : transitions.cross?.code === "c" ? false : undefined,
    ts,
    hmacKey,
  });
  const hostEnvelope = (evidence ?? []).find((e) => e?.id === "host-lifecycle");
  const hostObs = observationInterval(hostEnvelope ?? {});
  const gap = hostFacts ? factPointsFromDaemonGap(hostFacts.daemonGap, { ts, hmacKey, intervalMs: daemonIntervalMs, obsStartMs: hostObs.obsStartMs, obsEndMs: hostObs.obsEndMs }) : [];
  const points = [...stateless, ...created, ...gap, ...factPointsFromTransitions(transitions.transitions, { ts, hmacKey })];
  return {
    points,
    context: { snapshot, transitions, chainRead, statsRead, prevChain, gapCount, summaryLedgerReason: summaryLedger.reason, statsLedgerReason: statsLedger.reason },
  };
}

async function lastSummarySeq(descartesPaths, now) {
  try {
    const read = await readFactPoints(descartesPaths, { family: "tick_summary", now });
    let last;
    for (const point of read.points) {
      if (point.fact_name !== "tick.summary") continue;
      const seq = Number(point.attributes?.seq);
      if (Number.isSafeInteger(seq) && (last === undefined || seq > last)) last = seq;
    }
    return last;
  } catch {
    return undefined;
  }
}

function maxDefined(...values) {
  const known = values.filter(Number.isSafeInteger);
  return known.length > 0 ? Math.max(...known) : undefined;
}

// The last seq the (valid) statistics state saw, so a wiped tick_summary never reuses a seq (an
// episode id) the long-lived statistics already hold.
function statsLastSeq(statsRead) {
  if (statsRead?.status !== "valid") return undefined;
  return maxDefined(statsRead.state?.daily?.last_seq, statsRead.state?.episode?.eseq);
}

/**
 * Pass-2 half. Certifies, derives and appends the tick_summary record and the statistics, and
 * commits their stamped states only after their own append committed. Returns the status entry.
 */
export async function finalizeContextC2({ descartesPaths, prepared, factPoints, structuralFacts, ts, hmacKey, configForHash, budgets, deps = {} }) {
  const readLedger = deps.readFactIntegrityLedger ?? readFactIntegrityLedger;
  const append = deps.appendFactPoints ?? appendFactPoints;
  const { snapshot, transitions, chainRead, statsRead, prevChain, gapCount = 0 } = prepared.context;
  const contributed = new Set((factPoints ?? []).map((point) => factFamilyForName(point?.fact_name)).filter((family) => SUMMARY_SOURCE_FAMILIES.includes(family)));
  const ledgers = {};
  for (const family of SUMMARY_SOURCE_FAMILIES) {
    if (!contributed.has(family)) continue;
    ledgers[family] = (await readLedger(descartesPaths, family)).ledger ?? undefined;
  }
  const certification = certifySourcePasses({ familyResults: structuralFacts?.families, ledgers, contributed, tsMs: snapshot.tsMs });
  // C2 review M7: the two derived families vouch for each other. One family's whole directory wiped
  // while the other survives is LOSS (a restarted chain, a memory-lost cold start), never a first
  // run. (Both wiped together is not detectable from here; the trusted-state ledger is the B-ledger's.)
  const summaryExisted = prepared.context.summaryLedgerReason !== "missing" || await factStoreExists(descartesPaths, "tick_summary");
  const statsExisted = prepared.context.statsLedgerReason !== "missing" || await factStoreExists(descartesPaths, "context_stats");
  const storeHadSummaries = summaryExisted || statsExisted;
  const lastSeq = chainRead.status === "valid" && gapCount === 0 || !storeHadSummaries ? undefined : maxDefined(await lastSummarySeq(descartesPaths, ts), statsLastSeq(statsRead));
  const summary = deriveTickSummary({
    snapshot,
    prior: gapCount > 0 ? { status: "lost" } : chainRead,
    storeHadSummaries,
    lastSeq,
    certification,
    transitions,
    hmacKey,
    version: descartesVersion(),
    cfg: configHash(hmacKey, configForHash),
    gapCount,
  });
  const status = {
    chain: summary.chain,
    chain_state: chainRead.status,
    cert: certification.cert,
    seq: summary.seq,
    transitions: transitions.transitions.length,
  };
  const summaryPoints = [summary.point, summary.certificatePoint].filter(Boolean);
  const summaryWrite = await append(descartesPaths, summaryPoints, { family: "tick_summary", ts, now: ts, ...(budgets?.tick_summary ? { maxBytes: budgets.tick_summary } : {}) });
  if (!summaryWrite?.retention || summaryWrite.retention_error) {
    // The record reached disk but its pass did not commit: the chain state is NOT advanced, so the
    // next tick restarts the chain (unknown transitions), never continues it over an unstamped pass.
    return { ...status, summary: "appended_unstamped", error: summaryWrite?.retention_error ?? "tick_summary_retention_missing" };
  }
  await (deps.writeSummaryChainState ?? writeSummaryChainState)(descartesPaths, summary.nextState(summaryWrite.retention.ledger_generation, summaryWrite.retention.pass_id));
  const statsStoreExisted = statsExisted || summaryExisted;
  const stats = deriveStats({ prior: statsRead, storeExisted: statsStoreExisted, prevChain, snapshot, transitions, summary, nowIso: ts });
  const statsWrite = await append(descartesPaths, stats.points, { family: "context_stats", ts, now: ts, ...(budgets?.context_stats ? { maxBytes: budgets.context_stats } : {}) });
  const statsStatus = { state: statsRead.status, memory_lost: stats.memoryLost, points: stats.points.length };
  if (!statsWrite?.retention || statsWrite.retention_error) {
    return { ...status, summary: "committed", stats: { ...statsStatus, error: statsWrite?.retention_error ?? "context_stats_retention_missing" } };
  }
  const nextStats = stats.nextState(statsWrite.retention.ledger_generation, statsWrite.retention.pass_id);
  await (deps.writeStatsState ?? writeStatsState)(descartesPaths, nextStats);
  await clearSummaryGapState(descartesPaths);
  return { ...status, summary: "committed", stats: { ...statsStatus, memory_lost_count: nextStats.memory_lost_count } };
}
