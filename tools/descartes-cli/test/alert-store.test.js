import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  acknowledgeAlert,
  applyAlertCandidates,
  evaluateAlertRules,
  evaluateAndPersistAlerts,
  readAlertRecords,
  resolveAlertStorePaths,
  writeAlertRecords,
} from "../src/alert-store.js";
import { appendMetricPoints, writeDaemonStatus } from "../src/history-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alerts-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function historySummary(metrics, overrides = {}) {
  return {
    window_ms: 15 * 60 * 1000,
    since: "2026-05-28T00:00:00.000Z",
    until: "2026-05-28T00:15:00.000Z",
    point_count: metrics.reduce((sum, metric) => sum + metric.count, 0),
    matched_point_count: metrics.reduce((sum, metric) => sum + metric.count, 0),
    point_limit: 10000,
    truncated: false,
    corrupt_count: 0,
    metrics,
    ...overrides,
  };
}

function metric(metric_name, values, extra = {}) {
  return {
    metric_name,
    unit: extra.unit ?? "count",
    count: values.length,
    min: Math.min(...values),
    max: Math.max(...values),
    mean: values.reduce((sum, value) => sum + value, 0) / values.length,
    last: values.at(-1),
    p95: Math.max(...values),
    first_ts: "2026-05-28T00:00:00.000Z",
    last_ts: "2026-05-28T00:14:00.000Z",
    dimensions_seen: extra.dimensions_seen ?? 1,
    sensitivity: extra.sensitivity ?? "operational",
  };
}

test("alert store persists normalized alert records under Descartes state", async () => {
  const paths = await tempPaths();
  const written = await writeAlertRecords(paths, [{
    rule_id: "system.memory.sustained_high",
    severity: "critical",
    title: "Sustained high memory pressure",
    summary: "Memory high",
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T00:01:00.000Z",
  }]);

  assert.equal(written.length, 1);
  assert.match(written[0].id, /^alert_/);
  assert.equal(written[0].status, "active");
  const storePaths = resolveAlertStorePaths(paths);
  assert.equal(path.dirname(storePaths.alertsFile), path.join(paths.stateDir, "alerts"));
  const readBack = await readAlertRecords(paths);
  assert.deepEqual(readBack, written);
});

test("alert rules detect daemon freshness, sustained pressure, high load, and disk pressure", () => {
  const summary = historySummary([
    metric("system.memory.used_fraction", [0.92, 0.93], { unit: "fraction" }),
    metric("system.cpu.count", [4, 4]),
    metric("system.load.1m", [6.2, 6.4], { unit: "load_average" }),
    metric("disk.used_fraction", [0.96], { unit: "fraction", dimensions_seen: 2 }),
  ]);
  const candidates = evaluateAlertRules(summary, {
    ts: "2026-05-28T00:14:30.000Z",
    state: "ok",
    profile: { interval_ms: 60_000 },
  }, { now: "2026-05-28T00:15:00.000Z" });

  assert.deepEqual(candidates.map((candidate) => candidate.rule_id).sort(), [
    "disk.space.high_used_fraction",
    "system.load.sustained_high",
    "system.memory.sustained_high",
  ]);
  assert.equal(candidates.find((candidate) => candidate.rule_id === "disk.space.high_used_fraction").severity, "critical");
});

test("alert rules report missing and stale daemon samples", () => {
  const missing = evaluateAlertRules(historySummary([], { point_count: 0 }), undefined, { now: "2026-05-28T00:15:00.000Z" });
  assert(missing.some((candidate) => candidate.rule_id === "daemon.status.missing"));
  assert(missing.some((candidate) => candidate.rule_id === "daemon.samples.missing"));

  const stale = evaluateAlertRules(historySummary([
    metric("system.memory.used_fraction", [0.2], { unit: "fraction" }),
  ]), { ts: "2026-05-28T00:14:30.000Z", state: "ok", profile: { interval_ms: 60_000 } }, { now: "2026-05-28T00:25:00.000Z" });
  assert(stale.some((candidate) => candidate.rule_id === "daemon.samples.stale"));
});

test("candidate application dedupes alerts, enforces cooldown, and recovers absent candidates", () => {
  const first = applyAlertCandidates([], [{
    id: "alert_memory",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "warning",
    title: "Memory high",
    summary: "High",
    evidence_refs: ["history-summary"],
    diagnostics: {},
  }], { now: "2026-05-28T00:00:00.000Z", cooldownMs: 60_000 });
  assert.equal(first.alerts.length, 1);
  assert.deepEqual(first.notification_due_ids, ["alert_memory"]);
  assert.equal(first.alerts[0].last_notified, "2026-05-28T00:00:00.000Z");

  const second = applyAlertCandidates(first.alerts, [{
    ...first.alerts[0],
    summary: "Still high",
  }], { now: "2026-05-28T00:00:30.000Z", cooldownMs: 60_000 });
  assert.equal(second.alerts.length, 1);
  assert.deepEqual(second.notification_due_ids, []);
  assert.equal(second.alerts[0].first_seen, "2026-05-28T00:00:00.000Z");
  assert.equal(second.alerts[0].summary, "Still high");

  const recovered = applyAlertCandidates(second.alerts, [], { now: "2026-05-28T00:02:00.000Z", cooldownMs: 60_000 });
  assert.equal(recovered.alerts[0].status, "recovered");
});

test("acknowledgement persists and suppresses re-notification while condition remains", async () => {
  const paths = await tempPaths();
  const [alert] = await writeAlertRecords(paths, [{
    rule_id: "disk.space.high_used_fraction",
    title: "High disk pressure",
    summary: "Disk high",
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T00:00:00.000Z",
  }]);

  const acknowledged = await acknowledgeAlert(paths, alert.id, { now: "2026-05-28T00:01:00.000Z" });
  assert.equal(acknowledged.status, "acknowledged");
  assert.equal(acknowledged.acknowledged_at, "2026-05-28T00:01:00.000Z");

  const applied = applyAlertCandidates(await readAlertRecords(paths), [{ ...alert, summary: "Still high" }], {
    now: "2026-05-28T00:20:00.000Z",
    cooldownMs: 60_000,
  });
  assert.equal(applied.alerts[0].status, "acknowledged");
  assert.deepEqual(applied.notification_due_ids, []);
});

test("evaluate and persist alerts uses local history and daemon status without an LLM", async () => {
  const paths = await tempPaths();
  await appendMetricPoints(paths, [
    { ts: "2026-05-28T00:00:00.000Z", metric_name: "system.memory.used_fraction", value: 0.92, unit: "fraction" },
    { ts: "2026-05-28T00:01:00.000Z", metric_name: "system.memory.used_fraction", value: 0.91, unit: "fraction" },
  ], { now: "2026-05-28T00:01:00.000Z" });
  await writeDaemonStatus(paths, { ts: "2026-05-28T00:01:00.000Z", state: "ok", profile: { interval_ms: 60_000 } });

  const result = await evaluateAndPersistAlerts(paths, { now: "2026-05-28T00:02:00.000Z", windowMs: 15 * 60 * 1000 });
  assert(result.alerts.some((alert) => alert.rule_id === "system.memory.sustained_high"));
  assert(result.notification_due_ids.length > 0);
});
