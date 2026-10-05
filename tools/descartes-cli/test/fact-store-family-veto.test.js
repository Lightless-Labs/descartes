// T7 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §8, §4.4, I6): the daemon's
// history veto is PER FAMILY. Each family store is read independently; a history-dependent rule is
// frozen exactly when a family IT reads is untrusted (lost, never created, or unread) or its
// eligibility horizon is short there -- never because some OTHER family's store is. Every producer
// here reports coverage for its own alerts (the "buggy producer" shape), so the only thing that can
// freeze an alert is the daemon's own independent per-family check (§7.7).
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { alertId, writeAlertRecords } from "../src/alert-store.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { writeWatchConfig } from "../src/watch-store.js";
import { appendFactPointsByFamily, normalizeFactPoint, resolveFactStorePaths } from "../src/fact-store.js";
import { RULE_HORIZONS } from "../src/fact-families.js";
import { resolveDescartesPaths } from "../src/paths.js";

const NOW = "2026-05-24T00:00:00.000Z";
const HOUR_MS = 60 * 60 * 1000;

const BENIGN_FACT_NAME_BY_FAMILY = {
  service: "service.presence",
  process_lineage: "process.lineage_edge",
  scheduled_job: "scheduled_job.presence",
  session: "session.presence",
  peer: "peer.presence",
  canary: "canary.presence",
};
const RULE_FAMILIES = Object.keys(BENIGN_FACT_NAME_BY_FAMILY);

// Producer label -> the history-dependent rules it owns (SECURITY_RULE_OWNERSHIP in daemon.js).
const PRODUCERS = {
  computeSessionBaselineCandidates: ["session.count_drop", "session.churn"],
  computeCorrelationCandidates: ["correlation.login_kill_proximity"],
  computePeerBaselineCandidates: ["peer.count_spike", "peer.count_drop"],
  computeServiceBaselineCandidates: ["service.disappeared"],
  computeCanaryBaselineCandidates: ["canary.tampered"],
  computeProcessLineageBaselineCandidates: ["process.lineage.novel_edge"],
  computeScheduledJobBaselineCandidates: ["scheduled_job.appeared"],
  computeServiceAppearanceCandidates: ["service.appeared"],
};
const ALL_RULES = Object.values(PRODUCERS).flat();
const FINGERPRINT = "t7";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-family-veto-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function envelope(id, tool, result) {
  return { id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: NOW } };
}

function fastCollectorFakes() {
  return {
    system: async () => envelope("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

const PROFILE = { interval_ms: 60_000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } } };

function benign(family, ts, key = "control") {
  return { ts, fact_name: BENIGN_FACT_NAME_BY_FAMILY[family], entity_key: key, attributes: {} };
}

// Every rule family's store exists and reads intact (one tick at NOW, committed by a second pass);
// `skip` families are left uncreated, `narrow` maps family -> hours of certified span.
// Narrowed families are seeded FIRST: every routed append also sweeps the other existing stores at
// its own `now`, and a sweep at an earlier clock would future-drop (a real loss) a store already
// holding facts at NOW.
async function seedStores(paths, { skip = [], narrow = {} } = {}) {
  const ordered = [...RULE_FAMILIES].sort((left, right) => Number(narrow[right] !== undefined) - Number(narrow[left] !== undefined));
  for (const family of ordered) {
    if (skip.includes(family)) continue;
    if (narrow[family] !== undefined) {
      const earlier = new Date(Date.parse(NOW) - narrow[family] * HOUR_MS).toISOString();
      await appendFactPointsByFamily(paths, [benign(family, earlier, "old")], { now: earlier });
      const later = benign(family, NOW, "new");
      // Room for exactly the later record: the earlier tick is byte-evicted, the floor is `earlier`.
      await appendFactPointsByFamily(paths, [later], { now: NOW, budgets: { [family]: Buffer.byteLength(`${JSON.stringify(normalizeFactPoint(later))}\n`) } });
    } else {
      await appendFactPointsByFamily(paths, [benign(family, NOW)], { now: NOW });
    }
  }
  await appendFactPointsByFamily(paths, [], { now: NOW });
}

async function degrade(paths, family) {
  await fs.appendFile(resolveFactStorePaths(paths, family).factsFile, "not-json\n");
  await appendFactPointsByFamily(paths, [], { now: NOW });
  await appendFactPointsByFamily(paths, [], { now: NOW });
}

async function runTick(paths) {
  await writeAlertRecords(paths, ALL_RULES.map((ruleId) => ({
    rule_id: ruleId, fingerprint: FINGERPRINT, status: "active", severity: "warning",
    title: "t7", summary: "t7 fixture", first_seen: NOW, last_seen: NOW, diagnostics: {},
  })));
  const producers = Object.fromEntries(Object.entries(PRODUCERS).map(([name, rules]) => [
    name,
    async () => ({ candidates: [], evaluatedAlertKeys: rules.map((ruleId) => alertId(ruleId, FINGERPRINT)) }),
  ]));
  const result = await runDaemonIteration(paths, { profile: PROFILE, collectors: fastCollectorFakes(), ts: NOW, now: NOW, ...producers });
  return Object.fromEntries(ALL_RULES.map((ruleId) => [ruleId, result.alerts.alerts.find((alert) => alert.rule_id === ruleId)?.status]));
}

async function enabledPaths() {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeLearnedConfig(paths, { enabled: true });
  return paths;
}

function rulesOf(family) {
  return ALL_RULES.filter((ruleId) => RULE_HORIZONS.get(ruleId).families.includes(family));
}

test("T7 control: every family store intact and every producer reporting coverage -> every history-dependent alert recovers", async () => {
  const paths = await enabledPaths();
  await seedStores(paths);
  const statuses = await runTick(paths);
  for (const ruleId of ALL_RULES) assert.equal(statuses[ruleId], "recovered", ruleId);
});

for (const family of RULE_FAMILIES) {
  test(`T7: the ${family} store untrusted (in-window corrupt line) freezes ONLY the ${family} rules -- even though their producer reports coverage -- and every other family still recovers`, async () => {
    const paths = await enabledPaths();
    await seedStores(paths);
    await degrade(paths, family);
    const statuses = await runTick(paths);
    const frozen = rulesOf(family);
    assert.ok(frozen.length > 0);
    for (const ruleId of ALL_RULES) {
      assert.equal(statuses[ruleId], frozen.includes(ruleId) ? "active" : "recovered", `${ruleId} with ${family} degraded`);
    }
  });
}

for (const family of RULE_FAMILIES) {
  test(`T7: a ${family} store that was never created counts as untrusted for the ${family} rules only`, async () => {
    const paths = await enabledPaths();
    await seedStores(paths, { skip: [family] });
    const statuses = await runTick(paths);
    for (const ruleId of ALL_RULES) {
      assert.equal(statuses[ruleId], rulesOf(family).includes(ruleId) ? "active" : "recovered", `${ruleId} with ${family} absent`);
    }
  });
}

test("T7: a family whose tier is off is not read and its rules stay frozen; the other tier's families recover (I9: no read for a family with no enabled dependent rule)", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeLearnedConfig(paths, { enabled: false });
  await seedStores(paths);
  const reads = [];
  await writeAlertRecords(paths, ALL_RULES.map((ruleId) => ({
    rule_id: ruleId, fingerprint: FINGERPRINT, status: "active", severity: "warning",
    title: "t7", summary: "t7 fixture", first_seen: NOW, last_seen: NOW, diagnostics: {},
  })));
  const { readFactPoints } = await import("../src/fact-store.js");
  const producers = Object.fromEntries(Object.entries(PRODUCERS).map(([name, rules]) => [
    name,
    async () => ({ candidates: [], evaluatedAlertKeys: rules.map((ruleId) => alertId(ruleId, FINGERPRINT)) }),
  ]));
  const result = await runDaemonIteration(paths, {
    profile: PROFILE,
    collectors: fastCollectorFakes(),
    ts: NOW,
    now: NOW,
    ...producers,
    readFactPoints: async (descartesPaths, options) => {
      reads.push(options.family ?? options.families);
      return readFactPoints(descartesPaths, options);
    },
  });
  // The daemon's own history reads (window = the 31 d baseline window, now = a number).
  assert.equal(reads.includes("canary"), false, "canary's only dependent rule is learned-tier: no canary read with learned off");
  const status = (ruleId) => result.alerts.alerts.find((alert) => alert.rule_id === ruleId)?.status;
  assert.equal(status("canary.tampered"), "active");
  assert.equal(status("correlation.login_kill_proximity"), "active");
  for (const ruleId of ["service.disappeared", "session.count_drop", "peer.count_drop", "process.lineage.novel_edge", "scheduled_job.appeared"]) {
    assert.equal(status(ruleId), "recovered", ruleId);
  }
});

test("T7: a family's horizon short freezes only that family's horizon-short rules; the other families recover on the same tick", async () => {
  const paths = await enabledPaths();
  // session narrowed to a 10 h certified span: churn (6 h) OK, count_drop (30 h) short.
  await seedStores(paths, { narrow: { session: 10 } });
  const statuses = await runTick(paths);
  assert.equal(statuses["session.count_drop"], "active", "horizon-short: frozen despite the producer's coverage report");
  for (const ruleId of ALL_RULES.filter((ruleId) => ruleId !== "session.count_drop")) {
    assert.equal(statuses[ruleId], "recovered", ruleId);
  }
});

test("T7 regression for the single-file veto: a peer-store loss plus a buggy peer producer reporting coverage stays frozen while a perfectly healthy service store recovers", async () => {
  const paths = await enabledPaths();
  await seedStores(paths);
  await degrade(paths, "peer");
  const statuses = await runTick(paths);
  assert.equal(statuses["peer.count_drop"], "active");
  assert.equal(statuses["peer.count_spike"], "active");
  assert.equal(statuses["correlation.login_kill_proximity"], "active", "correlation reads the peer store too");
  assert.equal(statuses["service.disappeared"], "recovered");
});
