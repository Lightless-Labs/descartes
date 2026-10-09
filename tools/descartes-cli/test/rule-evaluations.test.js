// S6 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §7 S6, I11): every watch-tier
// producer returns an additive per-rule `ruleEvaluations` report built from its own gates. These
// tests pin the report's self-consistency against the producer's own evaluatedAlertKeys on the real
// daemon path: the per-rule keys partition evaluatedAlertKeys exactly, a rule that reported a key is
// evaluable, and an evaluable rule's gate is "ok". `baseline status` (S6) reads this report, so a
// report that drifted from the keys would make status disagree with the detector.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { buildRuleEvaluation } from "../src/fact-store-completeness.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { computeServiceAppearanceCandidates, computeServiceBaselineCandidates, SERVICE_APPEARED_RULE_ID, SERVICE_DISAPPEARED_RULE_ID } from "../src/service-baseline.js";
import { computeProcessLineageBaselineCandidates, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID } from "../src/process-lineage-baseline.js";
import { computeScheduledJobBaselineCandidates, SCHEDULED_JOB_APPEARED_RULE_ID } from "../src/persistence-baseline.js";
import { computeSessionBaselineCandidates, SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID } from "../src/session-baseline.js";
import { computePeerBaselineCandidates, PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "../src/peer-baseline.js";
import { realVolumeStructuralCollectors } from "./fixtures/real-volume-tick.js";

const HOUR_MS = 60 * 60 * 1000;
const BASE_MS = Date.parse("2026-10-06T00:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();

const PRODUCERS = [
  ["service", "computeServiceBaselineCandidates", computeServiceBaselineCandidates, [SERVICE_DISAPPEARED_RULE_ID]],
  ["service-appearance", "computeServiceAppearanceCandidates", computeServiceAppearanceCandidates, [SERVICE_APPEARED_RULE_ID]],
  ["process-lineage", "computeProcessLineageBaselineCandidates", computeProcessLineageBaselineCandidates, [PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID]],
  ["scheduled-job", "computeScheduledJobBaselineCandidates", computeScheduledJobBaselineCandidates, [SCHEDULED_JOB_APPEARED_RULE_ID]],
  ["session", "computeSessionBaselineCandidates", computeSessionBaselineCandidates, [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]],
  ["peer", "computePeerBaselineCandidates", computePeerBaselineCandidates, [PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID]],
];

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-rule-evaluations-"));
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

test("buildRuleEvaluation reports the first gate in the detector's own order", () => {
  const trusted = { trust: true, reason: "ok" };
  assert.deepEqual(buildRuleEvaluation({ historyTrust: { trust: false, reason: "history_degraded" }, coldStartPendingThisTick: true }), {
    evaluable: false, gate: "history_untrusted", history_reason: "history_degraded", evaluatedAlertKeys: [],
  });
  assert.equal(buildRuleEvaluation({ historyTrust: trusted, coldStartPendingThisTick: true, horizonOk: false }).gate, "cold_start_pending");
  assert.equal(buildRuleEvaluation({ historyTrust: trusted, coldStartPendingThisTick: false, horizonOk: false, readinessGate: "latest_census_stale" }).gate, "history_horizon_short");
  assert.equal(buildRuleEvaluation({ historyTrust: trusted, coldStartPendingThisTick: false, horizonOk: true, readinessGate: "latest_census_stale" }).gate, "latest_census_stale");
  const ok = buildRuleEvaluation({ historyTrust: trusted, coldStartPendingThisTick: false, horizonOk: true, evaluatedAlertKeys: ["k"] });
  assert.deepEqual(ok, { evaluable: true, gate: "ok", evaluatedAlertKeys: ["k"] });
  // A missing trust object or horizon fails closed (never evaluable).
  assert.equal(buildRuleEvaluation({}).evaluable, false);
  assert.equal(buildRuleEvaluation({ historyTrust: trusted, coldStartPendingThisTick: false }).gate, "history_horizon_short");
});

test("every watch-tier producer's ruleEvaluations partition its evaluatedAlertKeys exactly, on the real daemon path from day 1 through re-establishment", { timeout: 300_000 }, async () => {
  const paths = await tempPaths();
  const { collectors, structuralCollectorToggles } = realVolumeStructuralCollectors({ scale: 0.05 });
  const profile = {
    interval_ms: 60_000,
    collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
    structural: { interval_ms: HOUR_MS, collectors: structuralCollectorToggles },
  };
  const results = new Map();
  const observers = Object.fromEntries(PRODUCERS.map(([label, key, compute]) => [key, async (...args) => {
    const result = await compute(...args);
    results.set(label, result);
    return result;
  }]));
  const seenGates = new Map();
  for (let index = 0; index < 10; index += 1) {
    for (const offset of [0, 0.5]) {
      const ts = iso(BASE_MS + (index + offset) * HOUR_MS);
      results.clear();
      await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), structuralCollectors: collectors, ts, now: ts, ...observers });
      for (const [label, , , ruleIds] of PRODUCERS) {
        const result = results.get(label);
        assert.ok(result, `${label} ran at ${ts}`);
        assert.ok(result.ruleEvaluations && typeof result.ruleEvaluations === "object", `${label} reports ruleEvaluations at ${ts}`);
        assert.deepEqual(Object.keys(result.ruleEvaluations).sort(), [...ruleIds].sort(), `${label} reports exactly its own rules`);
        const partition = ruleIds.flatMap((ruleId) => result.ruleEvaluations[ruleId].evaluatedAlertKeys);
        assert.deepEqual([...partition].sort(), [...result.evaluatedAlertKeys].sort(), `${label}: per-rule keys == evaluatedAlertKeys at ${ts}`);
        for (const ruleId of ruleIds) {
          const evaluation = result.ruleEvaluations[ruleId];
          assert.equal(evaluation.evaluable, evaluation.gate === "ok", `${ruleId}: evaluable <=> gate ok`);
          if (evaluation.evaluatedAlertKeys.length > 0) assert.equal(evaluation.evaluable, true, `${ruleId}: a reported key implies evaluable at ${ts}`);
          if (!seenGates.has(ruleId)) seenGates.set(ruleId, new Set());
          seenGates.get(ruleId).add(evaluation.gate);
        }
      }
    }
  }
  // Day 1 is a cold start for every rule; the set_diff and novelty rules re-establish within the run
  // (6 complete ticks; no narrowing, so no horizon applies), while the 30-sample statistical rules
  // are still warming up.
  for (const ruleId of [SERVICE_DISAPPEARED_RULE_ID, SERVICE_APPEARED_RULE_ID, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, SCHEDULED_JOB_APPEARED_RULE_ID, SESSION_CHURN_RULE_ID]) {
    assert.ok(seenGates.get(ruleId).has("history_untrusted") || seenGates.get(ruleId).has("cold_start_pending"), `${ruleId} starts gated`);
    assert.ok(seenGates.get(ruleId).has("ok"), `${ruleId} becomes evaluable: ${[...seenGates.get(ruleId)]}`);
  }
  for (const ruleId of [SESSION_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID]) {
    assert.ok(seenGates.get(ruleId).has("baseline_warming_up"), `${ruleId} reports its warm-up gate: ${[...seenGates.get(ruleId)]}`);
    assert.equal(seenGates.get(ruleId).has("ok"), false, `${ruleId} cannot establish within 10 ticks`);
  }
});

test("a watch-disabled producer returns no ruleEvaluations (the disabled shape is unchanged)", async () => {
  const paths = await tempPaths();
  const loadWatchConfig = async () => ({ enabled: false });
  for (const [label, , compute] of PRODUCERS) {
    assert.deepEqual(await compute(paths, { loadWatchConfig }), { candidates: [], evaluatedAlertKeys: [] }, label);
  }
});
