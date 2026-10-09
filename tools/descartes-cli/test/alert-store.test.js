import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  acknowledgeAlert,
  alertId,
  applyAlertCandidates,
  confirmAlertDelivery,
  evaluateAlertRules,
  evaluateAlerts,
  evaluateAndPersistAlerts,
  FIXED_ALERT_RULE_IDS,
  readAlertRecords,
  recordAlertDeliveryFailure,
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

test("candidate application reports due work and rearms after recovery", () => {
  const first = applyAlertCandidates([], [{
    id: "alert_memory",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "warning",
    title: "Memory high",
    summary: "High",
    evidence_refs: ["history-summary"],
    diagnostics: {},
  }], { now: "2026-05-28T00:00:00.000Z" });
  assert.equal(first.alerts.length, 1);
  assert.deepEqual(first.notification_due_ids, ["alert_memory"]);
  assert.equal(first.alerts[0].last_notified, null);
  assert.equal(first.alerts[0].episode_started_at, "2026-05-28T00:00:00.000Z");
  assert.equal(first.alerts[0].episode_notified_at, null);
  assert.equal(first.alerts[0].notified_severity_max, null);

  const delivered = { ...first.alerts[0], last_notified: "2026-05-28T00:00:00.000Z", episode_notified_at: "2026-05-28T00:00:00.000Z", notified_severity_max: "warning" };
  const second = applyAlertCandidates([delivered], [{
    ...first.alerts[0],
    summary: "Still high",
  }], { now: "2026-05-28T05:00:00.000Z" });
  assert.equal(second.alerts.length, 1);
  assert.deepEqual(second.notification_due_ids, []);
  assert.equal(second.alerts[0].first_seen, "2026-05-28T00:00:00.000Z");
  assert.equal(second.alerts[0].summary, "Still high");

  const escalated = applyAlertCandidates(second.alerts, [{
    ...second.alerts[0],
    severity: "critical",
    title: "Critical memory pressure",
  }], { now: "2026-05-28T05:01:00.000Z" });
  assert.deepEqual(escalated.notification_due_ids, ["alert_memory"]);
  assert.equal(escalated.alerts[0].notified_severity_max, "warning");
  assert.equal(escalated.alerts[0].episode_notified_at, "2026-05-28T00:00:00.000Z");

  const escalatedDelivered = { ...escalated.alerts[0], last_notified: "2026-05-28T05:01:00.000Z", episode_notified_at: "2026-05-28T05:01:00.000Z", notified_severity_max: "critical" };
  const deescalated = applyAlertCandidates([escalatedDelivered], [{
    ...escalated.alerts[0],
    severity: "warning",
  }], { now: "2026-05-28T05:02:00.000Z" });
  assert.deepEqual(deescalated.notification_due_ids, []);
  assert.equal(deescalated.alerts[0].notified_severity_max, "critical");

  const recovered = applyAlertCandidates(deescalated.alerts, [], { now: "2026-05-28T05:03:00.000Z" });
  assert.equal(recovered.alerts[0].status, "recovered");

  const reactivated = applyAlertCandidates(recovered.alerts, [{
    ...recovered.alerts[0],
    severity: "warning",
  }], { now: "2026-05-28T05:04:00.000Z" });
  assert.deepEqual(reactivated.notification_due_ids, ["alert_memory"]);
  assert.equal(reactivated.alerts[0].episode_started_at, "2026-05-28T05:04:00.000Z");
  assert.equal(reactivated.alerts[0].notified_severity_max, null);
});

test("episode notification state is committed only by a confirmed delivery", async () => {
  const paths = await tempPaths();
  const candidate = {
    id: "alert_delivery_contract",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "critical",
    title: "Memory high",
    summary: "High",
    diagnostics: { min: 0.97, threshold: 0.9 },
  };

  // The injected candidate is outside the fixed-rule evaluator, so use the pure result to pin
  // the delivery contract without depending on host history.
  const applied = applyAlertCandidates([], [candidate], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, applied.alerts);
  assert.deepEqual(applied.notification_due_ids, [candidate.id]);
  assert.equal(applied.alerts[0].episode_notified_at, null);
  assert.equal(applied.alerts[0].notified_severity_max, null);

  const failed = applyAlertCandidates(applied.alerts, [candidate], { now: "2026-10-06T00:01:00.000Z" });
  assert.deepEqual(failed.notification_due_ids, [candidate.id], "a failed/unavailable delivery remains due");
  assert.equal(failed.alerts[0].episode_notified_at, null);

  const confirmed = await confirmAlertDelivery(paths, candidate.id, {
    now: "2026-10-06T00:02:00.000Z",
    severity: candidate.severity,
    episodeKey: "default",
  });
  assert.equal(confirmed.confirmed, true);
  const persisted = await readAlertRecords(paths);
  assert.equal(persisted[0].episode_notified_at, "2026-10-06T00:02:00.000Z");
  assert.equal(persisted[0].notified_severity_max, "critical");
  const quiet = applyAlertCandidates(persisted, [candidate], { now: "2026-10-06T00:03:00.000Z" });
  assert.deepEqual(quiet.notification_due_ids, []);
  assert.equal(persisted.some((alert) => alert.id === candidate.id), true);
});

test("delivery failures remain visible without consuming the episode", async () => {
  const paths = await tempPaths();
  const candidate = {
    id: "alert_failure_visible",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "warning",
    title: "Memory high",
    summary: "High",
    diagnostics: { min: 0.92 },
  };
  const applied = applyAlertCandidates([], [candidate], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, applied.alerts);
  const failure = await recordAlertDeliveryFailure(paths, candidate.id, {
    now: "2026-10-06T00:01:00.000Z",
    reason: "unavailable",
    episodeKey: "default",
  });
  assert.equal(failure.recorded, true);
  const stored = (await readAlertRecords(paths))[0];
  assert.equal(stored.delivery_failure_count, 1);
  assert.equal(stored.delivery_failure_reason, "unavailable");
  assert.equal(stored.episode_notified_at, null);
});

test("ordinary memory statistics do not create a second episode", () => {
  const candidate = {
    id: alertId("system.memory.sustained_high", "global"),
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "warning",
    title: "Memory high",
    summary: "Memory remains high",
    diagnostics: { mean: 0.92, max: 0.94, count: 10, observed_at: "2026-10-06T00:00:00.000Z" },
  };
  const first = applyAlertCandidates([], [candidate], { now: "2026-10-06T00:00:00.000Z" });
  const delivered = { ...first.alerts[0], episode_notified_at: "2026-10-06T00:00:00.000Z", notified_severity_max: "warning" };
  const drifted = applyAlertCandidates([delivered], [{
    ...candidate,
    diagnostics: { mean: 0.97, max: 0.99, count: 11, observed_at: "2026-10-06T00:01:00.000Z" },
  }], { now: "2026-10-06T00:01:00.000Z" });
  assert.deepEqual(drifted.notification_due_ids, []);
});

test("producer-declared incident keys re-arm without diagnostic digests or ignore lists", () => {
  const delivered = (result) => ({
    ...result.alerts[0],
    last_notified: "2026-10-06T00:00:00.000Z",
    episode_notified_at: "2026-10-06T00:00:00.000Z",
    notified_severity_max: result.alerts[0].severity,
  });
  const base = {
    id: alertId("provenance.port.new_public_bind", "port.tcp.443"),
    rule_id: "provenance.port.new_public_bind",
    fingerprint: "port.tcp.443",
    incident_key: "identity-a",
    severity: "warning",
    title: "New public bind",
    summary: "A new identity owns 443.",
    diagnostics: { identity_hash: "identity-a", protocol: "tcp", local_port: 443, observed_at: "2026-10-06T00:00:00.000Z" },
  };
  let first = applyAlertCandidates([], [base], { now: "2026-10-06T00:00:00.000Z" });
  assert.deepEqual(first.notification_due_ids, [base.id]);
  let state = [delivered(first)];
  const unchanged = applyAlertCandidates(state, [{ ...base, diagnostics: { ...base.diagnostics, observed_at: "2026-10-06T00:01:00.000Z" } }], { now: "2026-10-06T00:01:00.000Z" });
  assert.deepEqual(unchanged.notification_due_ids, [], "unchanged material evidence is silent");

  const identityB = { ...base, incident_key: "identity-b", diagnostics: { ...base.diagnostics, identity_hash: "identity-b", observed_at: "2026-10-06T00:02:00.000Z" } };
  const changed = applyAlertCandidates(state, [identityB], { now: "2026-10-06T00:02:00.000Z" });
  assert.deepEqual(changed.notification_due_ids, [base.id], "identity A -> B on the same port is a new episode");

  const canary = {
    ...base,
    id: alertId("canary.tripped", "canary-hash"),
    rule_id: "canary.tripped",
    fingerprint: "canary-hash",
    incident_key: "trip-a",
    diagnostics: { canary_id_hash: "canary-hash", trip_reason: "changed", last_seen_ts: "2026-10-06T00:00:00.000Z" },
  };
  const canaryFirst = applyAlertCandidates([], [canary], { now: "2026-10-06T00:00:00.000Z" });
  const canarySecond = applyAlertCandidates([delivered(canaryFirst)], [{ ...canary, incident_key: "trip-b", diagnostics: { ...canary.diagnostics, last_seen_ts: "2026-10-06T00:01:00.000Z" } }], { now: "2026-10-06T00:01:00.000Z" });
  assert.deepEqual(canarySecond.notification_due_ids, [canary.id], "a second canary trip remains material even with a stable canary identity");

  const correlation = {
    ...base,
    id: alertId("correlation.login_kill_proximity", "anchor-a__peer-a"),
    rule_id: "correlation.login_kill_proximity",
    fingerprint: "anchor-a__peer-a",
    incident_key: "anchor-tick-a",
    diagnostics: { anchor_fingerprint: "anchor-a", peer_entity_key: "peer-a", observed_at: "2026-10-06T00:00:00.000Z", proximity_seconds: 5 },
  };
  const correlationFirst = applyAlertCandidates([], [correlation], { now: "2026-10-06T00:00:00.000Z" });
  const correlationChanged = applyAlertCandidates([delivered(correlationFirst)], [{ ...correlation, incident_key: "anchor-tick-b", diagnostics: { ...correlation.diagnostics, anchor_fingerprint: "anchor-b", observed_at: "2026-10-06T00:01:00.000Z" } }], { now: "2026-10-06T00:01:00.000Z" });
  assert.deepEqual(correlationChanged.notification_due_ids, [correlation.id], "a frozen correlation with a new anchor is a new episode");
});

test("acknowledgement suppresses persistence but not a later severity escalation", () => {
  const acknowledged = {
    id: "alert_ack",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    status: "acknowledged",
    severity: "warning",
    title: "Memory high",
    summary: "Still high",
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T01:00:00.000Z",
    last_notified: "2026-05-28T00:00:00.000Z",
    episode_notified_at: "2026-05-28T00:00:00.000Z",
    notified_severity_max: "warning",
    episode_started_at: "2026-05-28T00:00:00.000Z",
    acknowledged_at: "2026-05-28T00:01:00.000Z",
  };

  const persistent = applyAlertCandidates([acknowledged], [{ ...acknowledged }], { now: "2026-05-28T05:00:00.000Z" });
  assert.equal(persistent.alerts[0].status, "acknowledged");
  assert.deepEqual(persistent.notification_due_ids, []);

  const escalated = applyAlertCandidates(persistent.alerts, [{ ...persistent.alerts[0], severity: "critical" }], { now: "2026-05-28T05:01:00.000Z" });
  assert.equal(escalated.alerts[0].status, "acknowledged");
  assert.deepEqual(escalated.notification_due_ids, ["alert_ack"]);
  assert.equal(escalated.alerts[0].notified_severity_max, "warning");
});

test("legacy active records without episode metadata remain silent", () => {
  const legacy = {
    id: "alert_legacy",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    status: "active",
    severity: "warning",
    title: "Memory high",
    summary: "Still high",
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T01:00:00.000Z",
    last_notified: "2026-05-28T00:00:00.000Z",
  };

  const persistent = applyAlertCandidates([legacy], [{ ...legacy }], { now: "2026-05-28T05:00:00.000Z" });
  assert.deepEqual(persistent.notification_due_ids, []);
  assert.equal(persistent.alerts[0].episode_started_at, "2026-05-28T05:00:00.000Z");
  assert.equal(persistent.alerts[0].episode_notified_at, null);
  assert.equal(persistent.alerts[0].notified_severity_max, null);

  const escalated = applyAlertCandidates(persistent.alerts, [{ ...persistent.alerts[0], severity: "critical" }], { now: "2026-05-28T05:01:00.000Z" });
  assert.deepEqual(escalated.notification_due_ids, []);
});

test("legacy Oct-1 delivery cannot prove Oct-3 current activation", async () => {
  const paths = await tempPaths();
  const store = resolveAlertStorePaths(paths);
  await fs.mkdir(store.dir, { recursive: true });
  const legacy = {
    id: "alert_legacy_audit",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    status: "active",
    severity: "warning",
    title: "Memory high",
    summary: "Still high",
    first_seen: "2026-10-01T00:00:00.000Z",
    last_seen: "2026-10-03T00:05:00.000Z",
    last_notified: "2026-10-01T00:01:00.000Z",
    diagnostics: { min: 0.92 },
  };
  await fs.writeFile(store.alertsFile, JSON.stringify({ version: 1, alerts: [legacy] }));
  const [migrated] = await readAlertRecords(paths);
  assert.equal(migrated.episode_started_at, null);
  const upgraded = applyAlertCandidates([migrated], [{ ...migrated }], { now: "2026-10-03T00:06:00.000Z" });
  assert.deepEqual(upgraded.notification_due_ids, []);
  assert.equal(upgraded.alerts[0].episode_started_at, "2026-10-03T00:06:00.000Z");
  assert.equal(migrated.last_notified, "2026-10-01T00:01:00.000Z", "legacy field is retained as history, never used as proof");
});

test("a fixed alert active for five simulated days produces one notification", () => {
  let alerts = [];
  let notificationCount = 0;
  for (let hour = 0; hour <= 5 * 24; hour += 1) {
    const now = new Date(Date.UTC(2026, 4, 28, hour)).toISOString();
    const result = applyAlertCandidates(alerts, [{
      id: "alert_horizon_short",
      rule_id: "daemon.fact_history.horizon_short",
      fingerprint: "global",
      severity: "warning",
      title: "Fact history horizon is short",
      summary: "The fact history is shorter than expected.",
      diagnostics: {},
    }], { now });
    notificationCount += result.notification_due_ids.length;
    alerts = result.alerts.map((alert) => result.notification_due_ids.includes(alert.id)
      ? { ...alert, last_notified: now, episode_notified_at: now, notified_severity_max: alert.severity }
      : alert);
  }
  assert.equal(notificationCount, 1);
  assert.equal(alerts[0].status, "active");
});

test("acknowledgement persists and suppresses re-notification while condition remains", async () => {
  const paths = await tempPaths();
  const [alert] = await writeAlertRecords(paths, [{
    rule_id: "disk.space.high_used_fraction",
    title: "High disk pressure",
    summary: "Disk high",
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T00:00:00.000Z",
    episode_started_at: "2026-05-28T00:00:00.000Z",
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

async function seededScenario(paths) {
  await appendMetricPoints(paths, [
    { ts: "2026-05-28T00:00:00.000Z", metric_name: "system.memory.used_fraction", value: 0.92, unit: "fraction" },
    { ts: "2026-05-28T00:01:00.000Z", metric_name: "system.memory.used_fraction", value: 0.91, unit: "fraction" },
  ], { now: "2026-05-28T00:01:00.000Z" });
  await writeDaemonStatus(paths, { ts: "2026-05-28T00:01:00.000Z", state: "ok", profile: { interval_ms: 60_000 } });
}

test("evaluateAndPersistAlerts produces byte-identical alert records with extraCandidates omitted or empty", async () => {
  const baselinePaths = await tempPaths();
  await seededScenario(baselinePaths);
  const baseline = await evaluateAndPersistAlerts(baselinePaths, { now: "2026-05-28T00:02:00.000Z", windowMs: 15 * 60 * 1000 });

  const omittedPaths = await tempPaths();
  await seededScenario(omittedPaths);
  const omitted = await evaluateAndPersistAlerts(omittedPaths, { now: "2026-05-28T00:02:00.000Z", windowMs: 15 * 60 * 1000 });

  const emptyPaths = await tempPaths();
  await seededScenario(emptyPaths);
  const empty = await evaluateAndPersistAlerts(emptyPaths, { now: "2026-05-28T00:02:00.000Z", windowMs: 15 * 60 * 1000, extraCandidates: [] });

  assert.deepEqual(omitted.alerts, baseline.alerts);
  assert.deepEqual(empty.alerts, baseline.alerts);
  assert.deepEqual(omitted.notification_due_ids, baseline.notification_due_ids);
  assert.deepEqual(empty.notification_due_ids, baseline.notification_due_ids);

  // Round-trip through the store itself is also byte-identical.
  const rereadBaseline = await readAlertRecords(baselinePaths);
  const rereadEmpty = await readAlertRecords(emptyPaths);
  assert.deepEqual(rereadEmpty, rereadBaseline);
});

test("a fixed-rule alert and an extraCandidates alert do not spuriously recover each other", async () => {
  const paths = await tempPaths();
  await seededScenario(paths); // drives the fixed system.memory.sustained_high rule active

  const extraCandidate = {
    rule_id: "constraint.violation.test-family",
    fingerprint: "constraint.test.example",
    severity: "warning",
    title: "Constraint violated",
    summary: "Test constraint violated",
    diagnostics: { actual: 5 },
    evidence_refs: ["constraint-store"],
  };

  const first = await evaluateAndPersistAlerts(paths, {
    now: "2026-05-28T00:02:00.000Z",
    windowMs: 15 * 60 * 1000,
    extraCandidates: [extraCandidate],
  });
  const fixedAlert = first.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const extraAlert = first.alerts.find((alert) => alert.rule_id === "constraint.violation.test-family");
  assert.ok(fixedAlert, "expected the fixed-rule alert to be active");
  assert.ok(extraAlert, "expected the extraCandidates alert to be active");
  assert.equal(fixedAlert.status, "active");
  assert.equal(extraAlert.status, "active");

  // Next iteration: extraCandidates is now absent (constraint resolved / no longer supplied).
  // The fixed-rule alert must remain active, not spuriously recover.
  const second = await evaluateAndPersistAlerts(paths, {
    now: "2026-05-28T00:03:00.000Z",
    windowMs: 15 * 60 * 1000,
    extraCandidates: [],
  });
  const fixedAfter = second.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const extraAfter = second.alerts.find((alert) => alert.rule_id === "constraint.violation.test-family");
  assert.equal(fixedAfter.status, "active");
  assert.equal(extraAfter.status, "recovered");

  // Symmetric case: fixed-rule condition clears (memory no longer sustained-high via a
  // fresh window with no samples in range) while extraCandidates stays active — the
  // extraCandidates alert must not be spuriously recovered by the fixed-rule source.
  const thirdPaths = await tempPaths();
  await seededScenario(thirdPaths);
  const symmetricFirst = await evaluateAndPersistAlerts(thirdPaths, {
    now: "2026-05-28T00:02:00.000Z",
    windowMs: 15 * 60 * 1000,
    extraCandidates: [extraCandidate],
  });
  assert.ok(symmetricFirst.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high" && alert.status === "active"));
  assert.ok(symmetricFirst.alerts.find((alert) => alert.rule_id === "constraint.violation.test-family" && alert.status === "active"));

  const symmetricSecond = await evaluateAndPersistAlerts(thirdPaths, {
    now: "2026-05-28T00:20:00.000Z", // well past the metric window; fixed rule candidate drops out
    windowMs: 60 * 1000,
    extraCandidates: [extraCandidate],
  });
  const fixedSymmetric = symmetricSecond.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const extraSymmetric = symmetricSecond.alerts.find((alert) => alert.rule_id === "constraint.violation.test-family");
  assert.equal(extraSymmetric.status, "active");
  assert.equal(fixedSymmetric.status, "recovered");
});

test("applyAlertCandidates scoped by coveredAlertIds only recovers alert identities it has full visibility into", () => {
  const existing = [
    {
      id: "alert_disk",
      rule_id: "disk.space.high_used_fraction",
      fingerprint: "global",
      status: "active",
      severity: "warning",
      title: "High disk pressure",
      summary: "Disk high",
      evidence_refs: ["history-summary"],
      first_seen: "2026-05-28T00:00:00.000Z",
      last_seen: "2026-05-28T00:00:00.000Z",
      last_notified: null,
      cooldown_until: null,
      acknowledged_at: null,
      diagnostics: {},
    },
    {
      id: "alert_canary",
      rule_id: "canary.tripped",
      fingerprint: "global",
      status: "active",
      severity: "critical",
      title: "Canary tripped",
      summary: "Canary tripped",
      evidence_refs: ["canary-baseline"],
      first_seen: "2026-05-28T00:00:00.000Z",
      last_seen: "2026-05-28T00:00:00.000Z",
      last_notified: null,
      cooldown_until: null,
      acknowledged_at: null,
      diagnostics: {},
    },
  ];

  // No candidates supplied this round (as if only the fixed rules were re-evaluated and both
  // fixed-rule and detector-only alerts came up empty this call), but scoped by alert IDENTITY
  // (§8.A) to only the fixed-rule alert's id — the covered set is keyed on alert.id now, not
  // rule_id, so the detector alert's identity being absent freezes it.
  const result = applyAlertCandidates(existing, [], {
    now: "2026-05-28T00:05:00.000Z",
    coveredAlertIds: new Set(["alert_disk"]),
  });

  const diskAfter = result.alerts.find((alert) => alert.id === "alert_disk");
  const canaryAfter = result.alerts.find((alert) => alert.id === "alert_canary");
  assert.equal(diskAfter.status, "recovered", "fixed-rule alert identity present in the covered set must recover");
  assert.equal(canaryAfter.status, "active", "an alert identity absent from the covered set must never be touched by a scoped recovery pass");
});

test("applyAlertCandidates coveredAlertIds discriminates by FINGERPRINT: two alerts under the SAME rule_id recover independently (per-fingerprint headline, §8 C1)", () => {
  const ruleId = "session.count_drop";
  const idA = alertId(ruleId, "entity-A");
  const idB = alertId(ruleId, "entity-B");
  const existing = [
    {
      id: idA, rule_id: ruleId, fingerprint: "entity-A", status: "active", severity: "critical",
      title: "Session count deviation (A)", summary: "A", evidence_refs: ["history-summary"],
      first_seen: "2026-05-28T00:00:00.000Z", last_seen: "2026-05-28T00:00:00.000Z",
      last_notified: null, cooldown_until: null, acknowledged_at: null, diagnostics: {},
    },
    {
      id: idB, rule_id: ruleId, fingerprint: "entity-B", status: "active", severity: "critical",
      title: "Session count deviation (B)", summary: "B", evidence_refs: ["history-summary"],
      first_seen: "2026-05-28T00:00:00.000Z", last_seen: "2026-05-28T00:00:00.000Z",
      last_notified: null, cooldown_until: null, acknowledged_at: null, diagnostics: {},
    },
  ];

  // No candidates this round; coverage authorizes ONLY fingerprint A's identity. Because coverage is
  // keyed on alert IDENTITY (rule_id + fingerprint), A must recover while B -- SAME rule_id, absent
  // from the covered set -- stays frozen. Rule-id-level coverage would recover BOTH; this pins that
  // per-fingerprint discrimination, which today's suite only exercises across DIFFERENT rule_ids.
  const result = applyAlertCandidates(existing, [], {
    now: "2026-05-28T00:05:00.000Z",
    coveredAlertIds: new Set([idA]),
  });

  const afterA = result.alerts.find((alert) => alert.id === idA);
  const afterB = result.alerts.find((alert) => alert.id === idB);
  assert.equal(afterA.status, "recovered", "the covered fingerprint (A) recovers");
  assert.equal(afterB.status, "active", "the uncovered fingerprint (B) under the SAME rule_id stays frozen -- coverage discriminates per fingerprint, not per rule_id");
});

test("readAlertRecords quarantines a single malformed persisted record instead of aborting the whole read", async () => {
  const paths = await tempPaths();
  const storePaths = resolveAlertStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true, mode: 0o700 });
  const good = {
    id: "alert_good",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "warning",
    title: "Sustained high memory pressure",
    summary: "Memory high",
    evidence_refs: ["history-summary"],
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T00:01:00.000Z",
    last_notified: null,
    cooldown_until: null,
    acknowledged_at: null,
    diagnostics: {},
  };
  const bad = { id: "bad", rule_id: "x", first_seen: "not-a-date" };
  await fs.writeFile(storePaths.alertsFile, JSON.stringify({ version: 1, alerts: [good, bad] }, null, 2), { mode: 0o600 });

  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  let records;
  try {
    records = await readAlertRecords(paths);
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(records.length, 1, "the valid record must survive; only the malformed one is quarantined");
  assert.equal(records[0].id, "alert_good");
  assert(warnings.length > 0, "a quarantined record must be surfaced via console.warn");
  assert(warnings.some((line) => line.includes("bad")), "the warning should identify the quarantined record");
});

test("readAlertRecords still rejects on whole-file JSON corruption (distinct, more severe case)", async () => {
  const paths = await tempPaths();
  const storePaths = resolveAlertStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storePaths.alertsFile, "{not json", { mode: 0o600 });

  await assert.rejects(() => readAlertRecords(paths));
});

test("evaluateAlerts never writes; evaluateAndPersistAlerts does", async () => {
  const paths = await tempPaths();
  await appendMetricPoints(paths, [
    { ts: "2026-05-28T00:00:00.000Z", metric_name: "system.memory.used_fraction", value: 0.92, unit: "fraction" },
    { ts: "2026-05-28T00:01:00.000Z", metric_name: "system.memory.used_fraction", value: 0.91, unit: "fraction" },
  ], { now: "2026-05-28T00:01:00.000Z" });
  await writeDaemonStatus(paths, { ts: "2026-05-28T00:01:00.000Z", state: "ok", profile: { interval_ms: 60_000 } });

  const before = await readAlertRecords(paths);
  assert.deepEqual(before, []);

  const evaluated = await evaluateAlerts(paths, { now: "2026-05-28T00:02:00.000Z", windowMs: 15 * 60 * 1000 });
  assert(evaluated.alerts.some((alert) => alert.rule_id === "system.memory.sustained_high"));

  const afterReadOnly = await readAlertRecords(paths);
  assert.deepEqual(afterReadOnly, [], "evaluateAlerts must never persist to disk");

  const persisted = await evaluateAndPersistAlerts(paths, { now: "2026-05-28T00:02:00.000Z", windowMs: 15 * 60 * 1000 });
  assert(persisted.alerts.some((alert) => alert.rule_id === "system.memory.sustained_high"));

  const afterWrite = await readAlertRecords(paths);
  assert(afterWrite.some((alert) => alert.rule_id === "system.memory.sustained_high"), "evaluateAndPersistAlerts must persist to disk");
});

test("delivery failure backoff delays retries and a future last attempt never suppresses forever", async () => {
  const paths = await tempPaths();
  const candidate = { id: "alert_backoff", rule_id: "system.memory.sustained_high", fingerprint: "global", severity: "warning", title: "Memory", summary: "High" };
  const applied = applyAlertCandidates([], [candidate], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, applied.alerts);
  await recordAlertDeliveryFailure(paths, candidate.id, { now: "2026-10-06T00:00:00.000Z", reason: "unavailable", episodeKey: "default" });
  let stored = (await readAlertRecords(paths))[0];
  assert.equal(stored.next_attempt_at, "2026-10-06T00:01:00.000Z");
  assert.equal(stored.delivery_failing_since, "2026-10-06T00:00:00.000Z");
  assert.deepEqual(applyAlertCandidates([stored], [{ ...candidate }], { now: "2026-10-06T00:00:30.000Z" }).notification_due_ids, []);
  assert.deepEqual(applyAlertCandidates([stored], [{ ...candidate }], { now: "2026-10-06T00:01:00.000Z" }).notification_due_ids, [candidate.id]);
  await recordAlertDeliveryFailure(paths, candidate.id, { now: "2026-10-06T00:01:00.000Z", reason: "unavailable", episodeKey: "default" });
  stored = (await readAlertRecords(paths))[0];
  assert.equal(stored.next_attempt_at, "2026-10-06T00:03:00.000Z");
  await writeAlertRecords(paths, [{ ...stored, next_attempt_at: "2099-01-01T00:00:00.000Z" }]);
  await recordAlertDeliveryFailure(paths, candidate.id, { now: "2026-10-06T00:02:00.000Z", reason: "unavailable", episodeKey: "default" });
  stored = (await readAlertRecords(paths))[0];
  assert.equal(stored.next_attempt_at, "2026-10-06T00:06:00.000Z");
  assert.deepEqual(applyAlertCandidates([{ ...stored, last_attempt_at: "2099-01-01T00:00:00.000Z", backoff_delay_ms: 60_000 }], [{ ...candidate }], { now: "2026-10-06T00:02:00.000Z" }).notification_due_ids, [candidate.id]);
});

test("unknown severities rank above critical and are never coerced down", () => {
  const candidate = {
    id: "alert_unknown_severity",
    rule_id: "foreign.future_rule",
    fingerprint: "global",
    severity: "emergency",
    title: "Foreign severity",
    summary: "Unknown severity must fail loud.",
    diagnostics: { incident: "same" },
  };
  const existing = {
    ...candidate,
    severity: "critical",
    last_notified: "2026-10-06T00:00:00.000Z",
    episode_notified_at: "2026-10-06T00:00:00.000Z",
    notified_severity_max: "critical",
    first_seen: "2026-10-06T00:00:00.000Z",
    last_seen: "2026-10-06T00:00:00.000Z",
  };
  const result = applyAlertCandidates([existing], [candidate], { now: "2026-10-06T00:01:00.000Z" });
  assert.equal(result.alerts[0].severity, "emergency");
  assert.deepEqual(result.notification_due_ids, [candidate.id]);
});

// Fact-store capacity plan §4.2/I12 (step S3): the horizon-short fixed rule.
test("S3: daemon.fact_history.horizon_short is a FIXED rule matching fact-families.js, driven only by the status record's history_horizon_short block", async () => {
  const { HISTORY_HORIZON_SHORT_RULE_ID } = await import("../src/fact-families.js");
  const { FIXED_ALERT_RULE_IDS: fixed, evaluateAlertRules: evaluate } = await import("../src/alert-store.js");
  assert.ok(fixed.has(HISTORY_HORIZON_SHORT_RULE_ID));
  const now = "2026-10-05T12:00:00.000Z";
  const threshold = 24 * 60 * 60 * 1000;
  const status = (rules, thresholdMs = threshold) => ({ ts: now, state: "ok", history_horizon_short: { threshold_ms: thresholdMs, rules } });
  const fired = (daemonStatus) => evaluate({ point_count: 1, metrics: [] }, daemonStatus, { now }).filter((c) => c.rule_id === HISTORY_HORIZON_SHORT_RULE_ID);
  const atThreshold = new Date(Date.parse(now) - threshold).toISOString();
  const justUnder = new Date(Date.parse(now) - threshold + 1).toISOString();
  assert.equal(fired(status({ "service.appeared": { since_ts: justUnder } })).length, 0);
  const signal = fired(status({ "service.appeared": { since_ts: atThreshold }, "session.churn": { since_ts: justUnder } }));
  assert.equal(signal.length, 1);
  assert.equal(signal[0].diagnostics.rule_ids, "service.appeared", "only the overdue rule is named");
  assert.equal(fired(undefined).length, 0);
  assert.equal(fired({ ts: now, state: "ok" }).length, 0);
  assert.equal(fired(status({ "service.appeared": { since_ts: "garbage" } })).length, 0);
  assert.equal(fired(status({ "service.appeared": { since_ts: atThreshold } }, "nope")).length, 0, "a malformed block vouches for nothing");
});
