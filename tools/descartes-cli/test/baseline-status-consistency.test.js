// T11 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §8 T11, §7 S6, I11): `baseline
// status` agrees with the detectors, PER RULE. For every watch-tier rule, at every checkpoint of every
// scenario, status reads "watching" exactly when the rule's detector evaluates it on the same state,
// and status's evaluated keys are exactly the detector's.
//
// The oracle is the REAL daemon path, not baseline.js's own detector runs: at each checkpoint status
// runs FIRST (it is read-only), then a daemon fast tick at the same `now` (structural not due) runs the
// producers with the daemon's own options (activeFreshnessMs from its profile, its config snapshot, its
// reads), and the producers' results are observed. Status before the daemon tick matters: the daemon's
// detectors write their stores, so the reverse order would compare two different states.
//
// Those comparisons mostly prove status and the daemon ran the same detector on the same inputs, so
// independent oracles are checked too (S6 review M1):
//   - the shared predicate, both directions: a rule status reports "watching" has trusted history
//     since its detector's anchor (factHistoryTrustworthy), a clear lockout, and passes the daemon's
//     own per-rule eligibility predicate (ruleEligible) on a fresh read; and each not-watching gate
//     (history_untrusted, cold_start_pending, history_horizon_short) is independently true;
//   - freshness from the test's own record of the newest complete census it wrote: a watching census
//     rule has a fresh one, the census-stale gate fires only on a stale one, and EVERY rule carries
//     the latest_census_stale reason exactly when it is stale (the session/peer detectors have no
//     freshness gate, H1);
//   - the per-rule keys partition each producer's top-level evaluatedAlertKeys (the daemon's coverage).
//
// Scenarios (seeded real-volume generator, small scale): a never-created store (fresh install, and a
// host with no peer/session collectors), clean accumulation through count-rule establishment, a stale
// latest census (4 h and 10 days), a 2 h interval, narrowed + horizon-short family stores (30 h count
// rules, and the 6 h set-diff rules), a partial-census tail (incomplete latest census, no complete
// census left), an untrusted (corrupt) store, and an already-locked-out install after the S5 upgrade.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildBaselineStatus, BASELINE_STATUS_RULE_IDS } from "../src/baseline.js";
import { runDaemonIteration } from "../src/daemon.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { appendFactPoints, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { MIN_STRUCTURAL_INTERVAL_MS, RULE_HORIZONS } from "../src/fact-families.js";
import { factHistoryTrustworthy, ruleEligible, validNoveltySeenSet } from "../src/fact-store-completeness.js";
import { resolveLegacyFactStorePaths } from "../src/fact-store-migration.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { writeWatchConfig } from "../src/watch-store.js";
import {
  computeServiceAppearanceCandidates,
  computeServiceBaselineCandidates,
  loadServiceAppearanceBaselineStore,
  loadServiceBaselineStore,
  resolveServiceBaselineStorePaths,
  SERVICE_APPEARED_RULE_ID,
  SERVICE_DISAPPEARED_RULE_ID,
  writeServiceAppearanceBaselineStore,
  writeServiceBaselineStore,
} from "../src/service-baseline.js";
import { computeProcessLineageBaselineCandidates, loadProcessLineageBaselineStore, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, writeProcessLineageBaselineStore } from "../src/process-lineage-baseline.js";
import { computeScheduledJobBaselineCandidates, loadPersistenceBaselineStore, SCHEDULED_JOB_APPEARED_RULE_ID, writePersistenceBaselineStore } from "../src/persistence-baseline.js";
import { computeSessionBaselineCandidates, loadSessionBaselineStore, SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID, writeSessionBaselineStore } from "../src/session-baseline.js";
import { computePeerBaselineCandidates, loadPeerBaselineStore, PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID, writePeerBaselineStore } from "../src/peer-baseline.js";
import { realVolumeStructuralCollectors } from "./fixtures/real-volume-tick.js";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const BASE_MS = Date.parse("2026-10-06T00:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();

// rule -> [observer label, the producer's persisted-store loader (for the anchor), family]
const RULES = new Map([
  [SERVICE_DISAPPEARED_RULE_ID, { label: "service", load: loadServiceBaselineStore, family: "service" }],
  [SERVICE_APPEARED_RULE_ID, { label: "service-appearance", load: loadServiceAppearanceBaselineStore, family: "service" }],
  [PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, { label: "process-lineage", load: loadProcessLineageBaselineStore, family: "process_lineage" }],
  [SCHEDULED_JOB_APPEARED_RULE_ID, { label: "scheduled-job", load: loadPersistenceBaselineStore, family: "scheduled_job" }],
  [SESSION_COUNT_DROP_RULE_ID, { label: "session", load: loadSessionBaselineStore, family: "session" }],
  [SESSION_CHURN_RULE_ID, { label: "session", load: loadSessionBaselineStore, family: "session" }],
  [PEER_COUNT_SPIKE_RULE_ID, { label: "peer", load: loadPeerBaselineStore, family: "peer" }],
  [PEER_COUNT_DROP_RULE_ID, { label: "peer", load: loadPeerBaselineStore, family: "peer" }],
]);
const COLLECTOR_OF_FAMILY = { service: "services", session: "sessions", peer: "vpn-peer-status", scheduled_job: "scheduled-jobs", process_lineage: "process-lineage" };
const CENSUS_RULES = new Set([SERVICE_DISAPPEARED_RULE_ID, SERVICE_APPEARED_RULE_ID, SCHEDULED_JOB_APPEARED_RULE_ID, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID]);
const PRODUCERS = {
  computeServiceBaselineCandidates: ["service", computeServiceBaselineCandidates],
  computeServiceAppearanceCandidates: ["service-appearance", computeServiceAppearanceCandidates],
  computeProcessLineageBaselineCandidates: ["process-lineage", computeProcessLineageBaselineCandidates],
  computeScheduledJobBaselineCandidates: ["scheduled-job", computeScheduledJobBaselineCandidates],
  computeSessionBaselineCandidates: ["session", computeSessionBaselineCandidates],
  computePeerBaselineCandidates: ["peer", computePeerBaselineCandidates],
};

async function tempPaths(label) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `descartes-t11-${label}-`));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function fastCollectorFakes() {
  const env = (id, tool, result) => ({ id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: iso(BASE_MS) } });
  return {
    system: async () => env("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => env("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => env("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

// Collector wrappers that make one family's census PARTIAL on a tick (the real translators: a
// truncated service enumeration, an "unable" session multiplexer).
const PARTIAL_COLLECTORS = {
  service: ["services", (envelope) => ({ ...envelope, result: { ...envelope.result, truncated: true } })],
  session: ["sessions", (envelope) => ({ ...envelope, result: { ...envelope.result, multiplexers: [{ multiplexer: "tmux", status: "unable" }, { multiplexer: "screen", status: "absent" }] } })],
};

function scenarioRig({ scale = 0.05, disabledCollectors = [], factStoreBudgets, structuralIntervalMs = HOUR_MS } = {}) {
  const { collectors: baseCollectors, structuralCollectorToggles } = realVolumeStructuralCollectors({ scale });
  // The test's own record of the newest COMPLETE census it wrote per family: the independent
  // freshness oracle (it never consults baseline.js or the detectors).
  const lastCompleteMs = {};
  let partialThisTick = new Set();
  const collectors = Object.fromEntries(Object.entries(baseCollectors).map(([id, collect]) => [id, async (...args) => {
    const envelope = await collect(...args);
    const partial = Object.entries(PARTIAL_COLLECTORS).find(([family, [collectorId]]) => collectorId === id && partialThisTick.has(family));
    return partial ? partial[1][1](envelope) : envelope;
  }]));
  const toggles = Object.fromEntries(Object.entries(structuralCollectorToggles).map(([id, toggle]) => [id, disabledCollectors.includes(id) ? { enabled: false } : toggle]));
  const profile = {
    interval_ms: 60_000,
    collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
    structural: { interval_ms: structuralIntervalMs, collectors: toggles },
  };
  const extra = factStoreBudgets ? { factStoreBudgets } : {};
  return {
    profile,
    activeFreshnessMs: 3 * structuralIntervalMs,
    lastCompleteMs,
    async structural(paths, hour, { partial = [] } = {}) {
      const ts = iso(BASE_MS + hour * HOUR_MS);
      partialThisTick = new Set(partial);
      let result;
      try {
        result = await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), structuralCollectors: collectors, ts, now: ts, ...extra });
      } finally {
        partialThisTick = new Set();
      }
      assert.ok(result.structuralFacts, `hour ${hour} is a structural tick`);
      for (const family of ["service", "session", "peer", "scheduled_job", "process_lineage"]) {
        if (!partial.includes(family) && !disabledCollectors.includes(COLLECTOR_OF_FAMILY[family])) lastCompleteMs[family] = Date.parse(ts);
      }
      return result;
    },
    // A daemon fast tick at `nowIso` with structural forced not-due, observing every watch-tier
    // producer's raw result.
    async fastTick(paths, nowIso) {
      const observed = new Map();
      const observers = Object.fromEntries(Object.entries(PRODUCERS).map(([key, [label, compute]]) => [key, async (...args) => {
        const result = await compute(...args);
        observed.set(label, result);
        return result;
      }]));
      const result = await runDaemonIteration(paths, {
        profile,
        collectors: fastCollectorFakes(),
        structuralCollectors: collectors,
        ts: nowIso,
        now: nowIso,
        readStructuralCheckpoint: async () => ({ last_structural_run_ms: Date.parse(nowIso) }),
        ...extra,
        ...observers,
      });
      assert.equal(result.structuralFacts, undefined, "the oracle tick is a fast tick");
      return observed;
    },
  };
}

const coverage = { gates: new Map(), zeroKeyWatching: new Set(), staleReason: new Set(), checkpoints: 0, incompleteLatest: 0 };

function record(ruleId, gate) {
  if (!coverage.gates.has(ruleId)) coverage.gates.set(ruleId, new Set());
  coverage.gates.get(ruleId).add(gate);
}

// The property: status first (read-only), then the daemon's fast tick at the same instant.
async function checkpoint(paths, rig, nowIso, label) {
  const status = await buildBaselineStatus(paths, { now: nowIso });
  const observed = await rig.fastTick(paths, nowIso);
  const nowMs = Date.parse(nowIso);
  coverage.checkpoints += 1;
  const statusRules = new Map(status.domains.flatMap((domain) => domain.rules).map((rule) => [rule.rule_id, rule]));
  assert.deepEqual([...statusRules.keys()].sort(), [...RULES.keys()].sort(), `${label}: status reports every watch-tier rule`);
  for (const [ruleId, { label: producer, load, family }] of RULES) {
    const statusRule = statusRules.get(ruleId);
    const detector = observed.get(producer)?.ruleEvaluations?.[ruleId];
    assert.ok(detector, `${label}: the daemon's ${producer} producer reported ${ruleId}`);
    const where = `${label} @ ${nowIso}: ${ruleId} (status: ${statusRule.phase}; detector gate: ${detector.gate})`;
    assert.equal(statusRule.watching, detector.evaluable, `${where}: watching <=> the detector evaluates`);
    assert.equal(statusRule.phase === "watching", detector.evaluable, `${where}: the phase says watching exactly when it evaluates`);
    assert.deepEqual([...statusRule.evaluated_alert_keys].sort(), [...detector.evaluatedAlertKeys].sort(), `${where}: status's evaluated keys == the detector's`);
    if (status.families[family]?.store === "absent") {
      assert.equal(statusRule.phase, "not observed (no store)", `${where}: a never-created store reads not observed`);
      assert.equal(detector.evaluable, false, `${where}: a never-created store never evaluates`);
      record(ruleId, "no_store");
    } else {
      record(ruleId, detector.gate);
    }
    if (statusRule.watching && statusRule.evaluated_alert_keys.length === 0) coverage.zeroKeyWatching.add(ruleId);
    if (status.families[family]?.store === "absent") continue;
    // Independent freshness oracle (I11 "a fresh complete latest group"): the age of the newest
    // complete census THIS TEST wrote for the family, against the daemon's 3 x structural interval.
    const lastComplete = rig.lastCompleteMs[family];
    const independentlyStale = lastComplete === undefined || !(nowMs - lastComplete <= rig.activeFreshnessMs);
    // Every rule, census or not, carries latest_census_stale exactly when the census is stale (H1:
    // the session/peer detectors have no freshness gate, so status must disclose it).
    assert.equal(statusRule.reasons.includes("latest_census_stale"), independentlyStale, `${where}: latest_census_stale reason <=> the latest complete census is older than ${rig.activeFreshnessMs} ms (reasons ${statusRule.reasons})`);
    if (independentlyStale) coverage.staleReason.add(ruleId);
    if (CENSUS_RULES.has(ruleId)) {
      if (statusRule.watching) assert.equal(independentlyStale, false, `${where}: a watching census rule has a fresh latest complete census`);
      if (detector.gate === "latest_census_stale") assert.equal(independentlyStale, true, `${where}: the census-stale gate fires only on a stale census`);
    }
    // The shared-predicate oracle (I11), both directions, on a fresh read of the same store and the
    // persisted detector state: "watching" => trusted since the anchor, lockout clear and the
    // daemon's own ruleEligible; and each not-watching gate is independently true.
    const novelty = RULE_HORIZONS.get(ruleId).kind === "novelty";
    const read = await readFactPoints(paths, { family, now: nowIso, ...(novelty ? { seenSetFamilies: [family] } : {}) });
    const entry = await load(paths);
    const { state } = entry;
    const trust = factHistoryTrustworthy(read, { anchorTs: state.cold_start_since_ts, nowMs, requireFullCoverage: novelty && !validNoveltySeenSet(read, ruleId) });
    const eligible = ruleEligible(read, ruleId, nowMs);
    if (statusRule.watching) {
      assert.equal(trust.trust, true, `${where}: watching implies trusted history (${trust.reason})`);
      assert.equal(state.cold_start_pending, false, `${where}: watching implies the lockout is clear`);
      assert.equal(eligible, true, `${where}: watching implies the daemon's ruleEligible`);
    } else if (detector.gate === "history_untrusted") {
      assert.equal(trust.trust, false, `${where}: history_untrusted implies factHistoryTrustworthy is false`);
    } else if (detector.gate === "cold_start_pending") {
      assert.ok(state.cold_start_pending === true || entry.missing === true || entry.corrupt === true, `${where}: cold_start_pending implies a persisted lockout or a lost store`);
    } else if (detector.gate === "history_horizon_short") {
      assert.equal(eligible, false, `${where}: history_horizon_short implies the daemon's ruleEligible is false`);
    }
  }
  // The daemon's coverage is each producer's TOP-LEVEL evaluatedAlertKeys; the per-rule keys status
  // reports partition it exactly (pairwise disjoint, union equal), in every state.
  for (const producer of new Set([...RULES.values()].map((value) => value.label))) {
    const result = observed.get(producer);
    const ruleIds = [...RULES].filter(([, value]) => value.label === producer).map(([ruleId]) => ruleId);
    const perRule = ruleIds.flatMap((ruleId) => result.ruleEvaluations[ruleId].evaluatedAlertKeys);
    assert.equal(new Set(perRule).size, perRule.length, `${label} @ ${nowIso}: ${producer}'s per-rule keys are disjoint`);
    assert.deepEqual([...perRule].sort(), [...(result.evaluatedAlertKeys ?? [])].sort(), `${label} @ ${nowIso}: ${producer}'s per-rule keys partition its evaluatedAlertKeys`);
  }
  for (const domain of status.domains) if (domain.latest_census_incomplete) coverage.incompleteLatest += 1;
  return status;
}

async function seedLockedOutLegacyStore(paths) {
  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(path.join(factsRootDir, "seen-sets"), { recursive: true });
  const legacyFacts = Array.from({ length: 4 }, (_, index) => JSON.stringify({
    ts: iso(BASE_MS - (4 - index) * HOUR_MS), fact_name: "service.presence", entity_key: `legacy-${index}`, attributes: { running: "true" }, sensitivity: "operational",
  })).join("\n");
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${legacyFacts}\n`);
  const evictTs = iso(BASE_MS - 2 * HOUR_MS);
  await fs.writeFile(path.join(factsRootDir, "integrity.json"), JSON.stringify({
    generation: "legacy-generation",
    schema_version: 1,
    corrupt_dropped_total: 0,
    schema_invalid_dropped_total: 0,
    bytecap_evicted_total: 12_345,
    age_evicted_total: 0,
    last_corrupt_ts: null,
    last_schema_invalid_ts: null,
    last_bytecap_evict_ts: evictTs,
    last_continuity_break_ts: null,
    first_degraded_ts: evictTs,
    continuity: { record_count_hwm: 20_000, oldest_ts: iso(BASE_MS - 30 * DAY_MS), last_rewrite_record_count: 4, last_rewrite_newest_ts: iso(BASE_MS - HOUR_MS), last_rewrite_bytes: legacyFacts.length + 1, output_digest: null, last_committed_pass_id: 9_999, continuity_ok: true, pending_pass: null },
    future_fact_dropped_total: 0,
    last_future_fact_ts: null,
  }, null, 2));
  await fs.writeFile(path.join(factsRootDir, "seen-sets", "service.json"), "{\"legacy\":true}\n");
  const pending = { cold_start_pending: true, cold_start_since_ts: iso(BASE_MS - 20 * DAY_MS) };
  await writeServiceBaselineStore(paths, pending);
  await writeServiceAppearanceBaselineStore(paths, pending);
  await writeProcessLineageBaselineStore(paths, pending);
  await writePersistenceBaselineStore(paths, pending);
  await writeSessionBaselineStore(paths, pending);
  await writePeerBaselineStore(paths, pending);
}

test("T11: per rule, baseline status reads watching exactly when the daemon's detector evaluates, with the same evaluated keys, over every scenario", { timeout: 300_000 }, async (t) => {
  await t.test("fresh install: every family store is never created -> not observed (no store)", async () => {
    const paths = await tempPaths("fresh");
    const rig = scenarioRig();
    const status = await checkpoint(paths, rig, iso(BASE_MS), "fresh");
    for (const domain of status.domains) assert.equal(domain.phase, "not observed (no store)", domain.domain);
  });

  await t.test("clean accumulation: cold start -> watching per rule, count rules warm up for 30 samples, then a stale latest census", async () => {
    const paths = await tempPaths("clean");
    const rig = scenarioRig();
    const checkpoints = new Set([0, 1, 3, 6, 7, 10, 20, 30, 31, 33, 35]);
    for (let hour = 0; hour <= 35; hour += 1) {
      await rig.structural(paths, hour);
      if (checkpoints.has(hour)) await checkpoint(paths, rig, iso(BASE_MS + (hour + 0.5) * HOUR_MS), `clean h${hour}`);
    }
    // No structural tick for 4 h, then for 10 days: the latest complete census is older than 3 x the
    // interval. The four census rules stop (latest_census_stale gate); session/peer have no freshness
    // gate in their detectors and keep evaluating (disclosed, §22.3/§22.4) -- status says "watching",
    // as the detector does, and every rule carries the latest_census_stale reason.
    for (const [hours, name] of [[39.5, "clean stale 4h"], [35 + 240, "clean stale 240h"]]) {
      const stale = await checkpoint(paths, rig, iso(BASE_MS + hours * HOUR_MS), name);
      const rules = stale.domains.flatMap((domain) => domain.rules);
      for (const rule of rules) assert.ok(rule.reasons.includes("latest_census_stale"), `${name}: ${rule.rule_id} carries latest_census_stale (${rule.reasons})`);
      for (const ruleId of CENSUS_RULES) assert.equal(rules.find((rule) => rule.rule_id === ruleId).gate, "latest_census_stale", `${name}: ${ruleId}`);
      for (const ruleId of [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID, PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID]) {
        assert.equal(rules.find((rule) => rule.rule_id === ruleId).phase, "watching", `${name}: ${ruleId} still evaluates in its detector (no freshness gate)`);
      }
    }
  });

  await t.test("a non-default structural interval (2 h): status uses the daemon's freshness (3 x interval), so a 4 h-old census still evaluates", async () => {
    const paths = await tempPaths("interval");
    const rig = scenarioRig({ structuralIntervalMs: 2 * HOUR_MS });
    for (let hour = 0; hour <= 18; hour += 2) await rig.structural(paths, hour);
    const status = await checkpoint(paths, rig, iso(BASE_MS + 22 * HOUR_MS), "interval 2h, census 4 h old");
    assert.equal(status.daemon_record.structural_interval_ms, 2 * HOUR_MS);
    assert.equal(status.domains.find((domain) => domain.domain === "service").rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).phase, "watching");
    const stale = await checkpoint(paths, rig, iso(BASE_MS + 24.5 * HOUR_MS), "interval 2h, census 6.5 h old");
    assert.equal(stale.domains.find((domain) => domain.domain === "service").rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).gate, "latest_census_stale");
  });

  await t.test("no peer or session collectors: those stores are never created while the others watch", async () => {
    const paths = await tempPaths("no-peer");
    const rig = scenarioRig({ disabledCollectors: ["vpn-peer-status", "sessions"] });
    for (let hour = 0; hour <= 8; hour += 1) await rig.structural(paths, hour);
    const status = await checkpoint(paths, rig, iso(BASE_MS + 8.5 * HOUR_MS), "no-peer");
    assert.equal(status.families.peer.store, "absent");
    assert.equal(status.families.session.store, "absent");
    for (const rule of status.domains.find((domain) => domain.domain === "peer").rules) assert.equal(rule.phase, "not observed (no store)");
    assert.equal(status.domains.find((domain) => domain.domain === "service").rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).phase, "watching");
  });

  await t.test("narrowed and horizon-short stores: novelty keeps evaluating on its seen-set, the 30 h count rules read horizon-short", async () => {
    // Size the forced budgets from one probe tick's real per-family bytes, so the test does not
    // depend on the generator's exact record sizes.
    const probe = await tempPaths("probe");
    const probeRig = scenarioRig();
    const first = await probeRig.structural(probe, 0);
    const tickBytes = (family) => first.status.fact_store_budgets.families[family].last_tick_bytes;
    const budgets = Object.fromEntries(Object.entries(first.status.fact_store_budgets.families).map(([family, entry]) => [family, entry.budget_bytes]));
    budgets.service = Math.floor(tickBytes("service") * 10.5); // ~10 ticks: narrowed, still >= the 6 h horizon
    budgets.session = Math.floor(tickBytes("session") * 8.5); // ~8 ticks: below the 30 h count horizon
    budgets.peer = Math.floor(tickBytes("peer") * 8.5);
    const paths = await tempPaths("narrowed");
    const rig = scenarioRig({ factStoreBudgets: budgets });
    for (let hour = 0; hour <= 40; hour += 1) {
      await rig.structural(paths, hour);
      if (hour === 12 || hour === 33 || hour === 40) {
        const status = await checkpoint(paths, rig, iso(BASE_MS + (hour + 0.5) * HOUR_MS), `narrowed h${hour}`);
        if (hour === 40) {
          assert.equal(status.families.service.coverage, "narrowed");
          assert.equal(status.families.service.seen_set.status, "valid");
          assert.ok(Number.isFinite(status.families.service.certified_horizon_ms));
          assert.ok(status.families.service.certified_after_ts, "the certified boundary is shown");
          const session = status.domains.find((domain) => domain.domain === "session").rules.find((rule) => rule.rule_id === SESSION_COUNT_DROP_RULE_ID);
          assert.equal(session.gate, "history_horizon_short");
          assert.match(session.phase, /^history horizon below minimum/);
          assert.ok(session.reasons.includes("history_horizon_short"));
        }
      }
    }
  });

  await t.test("set-diff horizon short: service and session stores narrowed below 6 h", async () => {
    const probe = await tempPaths("probe-short");
    const first = await scenarioRig().structural(probe, 0);
    const tickBytes = (family) => first.status.fact_store_budgets.families[family].last_tick_bytes;
    const budgets = Object.fromEntries(Object.entries(first.status.fact_store_budgets.families).map(([family, entry]) => [family, entry.budget_bytes]));
    budgets.service = Math.floor(tickBytes("service") * 4.5); // ~4 ticks: below the 6 h set-diff horizon
    budgets.session = Math.floor(tickBytes("session") * 4.5);
    const paths = await tempPaths("short");
    // Clear the lockouts at the default budgets first (a store narrowed below 6 ticks from the start
    // never re-accumulates 6 complete ticks), then shrink the budgets.
    const wide = scenarioRig();
    for (let hour = 0; hour <= 8; hour += 1) await wide.structural(paths, hour);
    const rig = scenarioRig({ factStoreBudgets: budgets });
    Object.assign(rig.lastCompleteMs, wide.lastCompleteMs);
    for (let hour = 9; hour <= 14; hour += 1) {
      await rig.structural(paths, hour);
      if (hour === 9 || hour === 14) await checkpoint(paths, rig, iso(BASE_MS + (hour + 0.5) * HOUR_MS), `short h${hour}`);
    }
    const status = await buildBaselineStatus(paths, { now: iso(BASE_MS + 14.5 * HOUR_MS) });
    const rules = status.domains.flatMap((domain) => domain.rules);
    assert.equal(rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).gate, "history_horizon_short");
    assert.equal(rules.find((rule) => rule.rule_id === SESSION_CHURN_RULE_ID).gate, "history_horizon_short");
  });

  await t.test("a partial-census tail: incomplete latest census, no complete census left in a narrowed window", async () => {
    const probe = await tempPaths("probe-partial");
    const first = await scenarioRig().structural(probe, 0);
    const tickBytes = (family) => first.status.fact_store_budgets.families[family].last_tick_bytes;
    const budgets = Object.fromEntries(Object.entries(first.status.fact_store_budgets.families).map(([family, entry]) => [family, entry.budget_bytes]));
    budgets.service = Math.floor(tickBytes("service") * 8.5); // ~8 ticks: still >= the 6 h set-diff horizon
    budgets.session = Math.floor(tickBytes("session") * 8.5);
    const paths = await tempPaths("partial");
    const rig = scenarioRig({ factStoreBudgets: budgets });
    for (let hour = 0; hour <= 9; hour += 1) await rig.structural(paths, hour);
    await checkpoint(paths, rig, iso(BASE_MS + 9.5 * HOUR_MS), "partial before");
    let status;
    for (let hour = 10; hour <= 20; hour += 1) {
      await rig.structural(paths, hour, { partial: ["service", "session"] });
      if (hour === 10 || hour === 13 || hour === 20) status = await checkpoint(paths, rig, iso(BASE_MS + (hour + 0.5) * HOUR_MS), `partial h${hour}`);
    }
    const service = status.domains.find((domain) => domain.domain === "service");
    const session = status.domains.find((domain) => domain.domain === "session");
    assert.equal(service.latest_census_incomplete, true);
    assert.equal(session.latest_census_incomplete, true);
    assert.equal(service.rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).gate, "insufficient_complete_history");
    assert.equal(session.rules.find((rule) => rule.rule_id === SESSION_CHURN_RULE_ID).gate, "no_complete_census");
  });

  await t.test("an untrusted store (a corrupt line): history untrusted, never watching", async () => {
    const paths = await tempPaths("corrupt");
    const rig = scenarioRig();
    for (let hour = 0; hour <= 8; hour += 1) await rig.structural(paths, hour);
    await checkpoint(paths, rig, iso(BASE_MS + 8.25 * HOUR_MS), "corrupt before");
    await fs.appendFile(resolveFactStorePaths(paths, "service").factsFile, "{not json\n");
    const status = await checkpoint(paths, rig, iso(BASE_MS + 8.5 * HOUR_MS), "corrupt after");
    const service = status.domains.find((domain) => domain.domain === "service");
    for (const rule of service.rules) {
      assert.equal(rule.gate, "history_untrusted");
      assert.match(rule.phase, /^cannot establish — history untrusted/);
    }
  });

  await t.test("an already-locked-out install after the upgrade: novelty horizon-short from the upgrade tick, the rest re-establish", async () => {
    const paths = await tempPaths("upgrade");
    await writeLearnedConfig(paths, { enabled: true });
    await seedLockedOutLegacyStore(paths);
    const rig = scenarioRig();
    for (let hour = 0; hour <= 9; hour += 1) {
      await rig.structural(paths, hour);
      if (hour === 0 || hour === 4 || hour === 9) await checkpoint(paths, rig, iso(BASE_MS + (hour + 0.5) * HOUR_MS), `upgrade h${hour}`);
    }
    const status = await buildBaselineStatus(paths, { now: iso(BASE_MS + 9.75 * HOUR_MS) });
    const appeared = status.domains.find((domain) => domain.domain === "service").rules.find((rule) => rule.rule_id === SERVICE_APPEARED_RULE_ID);
    assert.equal(appeared.gate, "history_horizon_short");
    assert.equal(appeared.horizon_short_since_ts, iso(BASE_MS), "the since clock is the daemon's, from the upgrade tick");
    assert.equal(status.families.service.seen_set.certified_since_ts, iso(BASE_MS), "the novelty memory is certified from the upgrade, not over the quarantined history");
    assert.equal(status.domains.find((domain) => domain.domain === "service").rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).phase, "watching");
    assert.equal(status.daemon_record.fact_store_legacy?.status !== undefined, true, "the legacy quarantine block is surfaced");
  });

  // The matrix the plan names (I11 / T11) was actually exercised.
  const expected = {
    [SERVICE_DISAPPEARED_RULE_ID]: ["no_store", "history_untrusted", "cold_start_pending", "ok", "latest_census_stale", "history_horizon_short", "insufficient_complete_history"],
    [SERVICE_APPEARED_RULE_ID]: ["no_store", "history_untrusted", "ok", "history_horizon_short", "latest_census_stale"],
    [SESSION_COUNT_DROP_RULE_ID]: ["no_store", "baseline_warming_up", "ok", "history_horizon_short"],
    [SESSION_CHURN_RULE_ID]: ["no_store", "ok", "history_horizon_short", "no_complete_census"],
    [PEER_COUNT_SPIKE_RULE_ID]: ["no_store", "baseline_warming_up", "ok", "history_horizon_short"],
    [PEER_COUNT_DROP_RULE_ID]: ["no_store", "baseline_warming_up", "ok", "history_horizon_short"],
    [SCHEDULED_JOB_APPEARED_RULE_ID]: ["no_store", "ok", "history_horizon_short", "latest_census_stale"],
    [PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID]: ["no_store", "ok", "history_horizon_short", "latest_census_stale"],
  };
  for (const [ruleId, gates] of Object.entries(expected)) {
    for (const gate of gates) assert.ok(coverage.gates.get(ruleId)?.has(gate), `${ruleId} exercised gate ${gate}; saw ${[...(coverage.gates.get(ruleId) ?? [])]}`);
  }
  // Not reached at this level: peer.count_drop's drop_history_not_ready (needs lockout-complete but
  // marker-incomplete peer ticks after a re-armed anchor over an established drop baseline).
  // The stale-census reason was seen on every rule, and an incomplete latest census was exercised.
  for (const ruleId of RULES.keys()) assert.ok(coverage.staleReason.has(ruleId), `${ruleId} carried the latest_census_stale reason on a stale census`);
  assert.ok(coverage.incompleteLatest > 0, "an incomplete latest census was exercised");
  // Zero entities still evaluate and still read watching (I11): this generator's session census is
  // always empty.
  assert.ok(coverage.zeroKeyWatching.has(SESSION_CHURN_RULE_ID), "session.churn watches an empty session census");
  assert.ok(coverage.checkpoints >= 20, `checkpoints: ${coverage.checkpoints}`);
  assert.deepEqual([...BASELINE_STATUS_RULE_IDS].sort(), [...RULES.keys()].sort(), "status covers exactly the watch-tier rules");
});

test("Leg E regression: a domain whose lockout cleared but whose count rule is still warming up is not reported as watching", { timeout: 120_000 }, async () => {
  const paths = await tempPaths("leg-e");
  const rig = scenarioRig();
  for (let hour = 0; hour <= 10; hour += 1) await rig.structural(paths, hour);
  const status = await buildBaselineStatus(paths, { now: iso(BASE_MS + 10.5 * HOUR_MS) });
  const session = status.domains.find((domain) => domain.domain === "session");
  assert.equal((await loadSessionBaselineStore(paths)).state.cold_start_pending, false, "precondition: the session lockout has cleared");
  assert.notEqual(session.phase, "watching", "count_drop cannot evaluate before 30 samples, so the domain is not watching");
  assert.equal(session.rules.find((rule) => rule.rule_id === SESSION_COUNT_DROP_RULE_ID).gate, "baseline_warming_up");
  assert.equal(session.rules.find((rule) => rule.rule_id === SESSION_CHURN_RULE_ID).phase, "watching");
  assert.match(session.phase, /^partially watching — 1 of 2 rules$/);
});

test("L1: peer re-accumulation progress counts what the peer lockout counts (an invalid-signature tick is lockout-complete)", { timeout: 120_000 }, async () => {
  const paths = await tempPaths("peer-progress");
  const rig = scenarioRig();
  for (let hour = 0; hour <= 2; hour += 1) await rig.structural(paths, hour);
  // Peer ticks whose census marker carries a garbled availability signature: the peer lockout's base
  // tickGroupDisposition (overflow-vs-complete) counts them; only count_drop's stricter disposition
  // excludes them.
  for (let hour = 3; hour <= 6; hour += 1) {
    const ts = iso(BASE_MS + hour * HOUR_MS);
    await appendFactPoints(paths, [
      { ts, fact_name: "peer.presence", entity_key: "peer.ssh.401c192722ae6bd2", attributes: { source_type: "ssh", presence_state: "observed_active", login_hour_bucket: "00", handshake_age_bucket: "n/a", exit_node_role: "n/a" }, source_envelope_id: "vpn-peer-status", source_tool: "collect_vpn_peer_status", sensitivity: "operational" },
      { ts, fact_name: "peer.presence", entity_key: "peer.census-marker.v1", attributes: { availability_signature: "garbled" }, source_envelope_id: "vpn-peer-status", source_tool: "collect_vpn_peer_status", sensitivity: "operational", confidence: 0 },
    ], { family: "peer", ts, now: ts });
  }
  const nowIso = iso(BASE_MS + 6.5 * HOUR_MS);
  assert.equal((await loadPeerBaselineStore(paths)).state.cold_start_pending, true, "precondition: the peer lockout is still persisted pending");
  const status = await buildBaselineStatus(paths, { now: nowIso });
  const peer = status.domains.find((domain) => domain.domain === "peer");
  // h1..h6 are strictly after the h0 anchor: six lockout-complete ticks, so the detector clears on its
  // next tick (deviation 5: "6 of 6" until the clear is persisted).
  assert.equal(peer.complete_ticks, 6);
  for (const rule of peer.rules) assert.equal(rule.phase, "still learning — 6 of 6", rule.rule_id);
  const observed = await rig.fastTick(paths, nowIso);
  assert.ok(observed.get("peer"), "the daemon ran the peer producer");
  assert.equal((await loadPeerBaselineStore(paths)).state.cold_start_pending, false, "the detector cleared the lockout on those six ticks");
});

test("status reasons: budget_below_horizon_floor from watch.json; cap_below_tick and retention_failing from the daemon record; a stale record's horizon-short since is ignored on a watching rule; status never writes", async () => {
  const paths = await tempPaths("reasons");
  const rig = scenarioRig();
  for (let hour = 0; hour <= 7; hour += 1) await rig.structural(paths, hour);
  await writeWatchConfig(paths, { enabled: true, fact_store_budgets: { service: 1024 } });
  const nowIso = iso(BASE_MS + 7.5 * HOUR_MS);
  const record = {
    ts: iso(BASE_MS + 7 * HOUR_MS),
    profile: rig.profile,
    fact_store_budgets: { families: { service: { cap_below_tick: true, retention_failing: true, retention_error: "boom" } } },
    history_horizon_short: { threshold_ms: 24 * HOUR_MS, rules: { [SERVICE_APPEARED_RULE_ID]: { since_ts: iso(BASE_MS + 2 * HOUR_MS) } } },
    fact_store_deprecations: [{ key: "fact_store_max_bytes", source: "watch.json", configured_bytes: 9_999_999, status: "ignored" }],
  };
  // A lost detector store is a state where the detector WOULD write (it re-arms its lockout), so the
  // read-only check below is not vacuous.
  await fs.rm(resolveServiceBaselineStorePaths(paths).storeFile);
  const before = await snapshotTree(path.dirname(path.dirname(paths.stateDir)));
  const status = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: async () => record });
  const after = await snapshotTree(path.dirname(path.dirname(paths.stateDir)));
  assert.deepEqual(after, before, "baseline status is read-only");
  const service = status.domains.find((domain) => domain.domain === "service");
  for (const rule of service.rules) {
    for (const reason of ["budget_below_horizon_floor", "cap_below_tick", "retention_failing"]) assert.ok(rule.reasons.includes(reason), `${rule.rule_id}: ${reason} in ${rule.reasons}`);
  }
  // M2: the record's horizon-short since clock is shown only when the LIVE gate is horizon-short; a
  // stale record never attaches a horizon-short reason to a rule that is watching. (The since clock
  // on a live horizon-short gate is covered by T11's upgrade scenario.)
  const appeared = service.rules.find((rule) => rule.rule_id === SERVICE_APPEARED_RULE_ID);
  assert.equal(appeared.gate, "ok");
  assert.equal(appeared.phase, "watching");
  assert.equal(appeared.horizon_short_since_ts, undefined);
  assert.ok(!appeared.reasons.includes("history_horizon_short"), `${appeared.reasons}`);
  assert.equal(status.families.service.budget_rejected.reason, "budget_below_horizon_floor");
  assert.deepEqual(status.daemon_record.fact_store_deprecations, record.fact_store_deprecations);
  // Reasons annotate; they never change what the detector decides: the appearance rule (its store
  // intact) still watches, the disappearance rule re-arms because its store was lost.
  assert.equal(service.rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).gate, "cold_start_pending");
  assert.equal(status.domains.find((domain) => domain.domain === "process-lineage").rules[0].phase, "watching");
  // An absent or unreadable record contributes nothing (never fabricated).
  const absent = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: async () => undefined });
  assert.equal(absent.daemon_record.status, "absent");
  assert.deepEqual(absent.domains.find((domain) => domain.domain === "process-lineage").rules[0].reasons, []);
  assert.deepEqual(absent.domains.find((domain) => domain.domain === "service").rules.find((rule) => rule.rule_id === SERVICE_DISAPPEARED_RULE_ID).reasons, ["budget_below_horizon_floor"]);
  const unreadable = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: async () => { throw new Error("garbled"); } });
  assert.equal(unreadable.daemon_record.status, "unreadable");
});

test("M3: the recorded structural interval is used only within the daemon's own profile bounds, and its source is shown", async () => {
  const paths = await tempPaths("interval-bounds");
  const rig = scenarioRig();
  for (let hour = 0; hour <= 7; hour += 1) await rig.structural(paths, hour);
  // The census is 2.5 h old: fresh at the 1 h default (3 h), so the phase does not depend on which
  // valid interval is used; the point is which value status accepts.
  const nowIso = iso(BASE_MS + 9.5 * HOUR_MS);
  const withInterval = (intervalMs) => async () => ({ ts: iso(BASE_MS + 7 * HOUR_MS), profile: { ...rig.profile, structural: { ...rig.profile.structural, interval_ms: intervalMs } } });
  const valid = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: withInterval(2 * HOUR_MS) });
  assert.equal(valid.daemon_record.structural_interval_ms, 2 * HOUR_MS);
  assert.equal(valid.daemon_record.structural_interval_source, "daemon_record");
  // Below MIN_STRUCTURAL_INTERVAL_MS the daemon refuses to start (validateDaemonProfile), so no
  // running daemon recorded it: status falls back to the default and says so.
  for (const bad of [MIN_STRUCTURAL_INTERVAL_MS - 1, 0, -5, Number.NaN, "3600000"]) {
    const rejected = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: withInterval(bad) });
    assert.equal(rejected.daemon_record.structural_interval_ms, HOUR_MS, `${bad}`);
    assert.equal(rejected.daemon_record.structural_interval_source, "default_recorded_interval_invalid", `${bad}`);
  }
  const absent = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: async () => undefined });
  assert.equal(absent.daemon_record.structural_interval_ms, HOUR_MS);
  assert.equal(absent.daemon_record.structural_interval_source, "default_no_record");
  const noStructural = await buildBaselineStatus(paths, { now: nowIso, readDaemonStatus: async () => ({ ts: nowIso, profile: { interval_ms: 60_000, collectors: {} } }) });
  assert.equal(noStructural.daemon_record.structural_interval_source, "default_no_recorded_interval");
});

async function snapshotTree(root) {
  const entries = {};
  async function walk(dir) {
    let names;
    try {
      names = await fs.readdir(dir, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    for (const entry of names) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else {
        const stat = await fs.stat(full);
        entries[path.relative(root, full)] = `${stat.size}:${stat.mtimeMs}`;
      }
    }
  }
  await walk(root);
  return entries;
}
