// Context plan C1.1 (§9): the hash-chained, daemon-written alert transition log.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  acknowledgeAlert,
  applyAlertCandidates,
  confirmAlertDelivery,
  MAX_LIVE_INCIDENTS,
  readAlertRecords,
  requestAlertClosure,
  writeAlertRecords,
} from "../src/alert-store.js";
import {
  deriveAlertTransitions,
  projectAlerts,
  readAlertTransitions,
  recordAlertTransitions,
  resolveAlertTransitionPaths,
} from "../src/alert-transitions.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alert-transitions-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const ID = "alert_transitions0001";
function candidate(key = "k", severity = "warning", ruleId = "constraint.violation.service") {
  return { id: ID, rule_id: ruleId, fingerprint: "c-1", incident_key: key, severity, title: "t", summary: "s", diagnostics: {} };
}
function t(minute) {
  return new Date(Date.UTC(2026, 9, 12, 0, minute)).toISOString();
}

async function tick(paths, candidates, minute, options = {}) {
  const applied = applyAlertCandidates(await readAlertRecords(paths), candidates, { now: t(minute), ...options });
  await writeAlertRecords(paths, applied.alerts);
  return recordAlertTransitions(paths, { now: t(minute) });
}

function kinds(records) {
  return records.map((record) => record.kind);
}

test("first run over an existing store writes genesis and invents no activation", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [candidate()], { now: t(0) });
  await writeAlertRecords(paths, applied.alerts);
  const report = await recordAlertTransitions(paths, { now: t(1) });
  assert.equal(report.status, "ok");
  const log = await readAlertTransitions(paths);
  assert.equal(log.status, "valid");
  assert.deepEqual(kinds(log.records), ["genesis"]);
  assert.equal(log.records[0].active_alerts, 1);
  assert.equal(log.coverage_from_ts, t(1));
});

test("repeated fire/recover cycles each log one activation, with incidents and recoveries", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: t(0) });
  for (let cycle = 0; cycle < 3; cycle += 1) {
    await tick(paths, [candidate()], 10 * cycle + 1);
    await tick(paths, [], 10 * cycle + 2);
  }
  const log = await readAlertTransitions(paths);
  assert.equal(log.status, "valid");
  assert.equal(log.records.filter((record) => record.kind === "activated").length, 3);
  assert.equal(log.records.filter((record) => record.kind === "recovered").length, 3);
  assert.equal(log.records.filter((record) => record.kind === "incident_opened").length, 3);
  // Re-running with no change appends nothing.
  const quiet = await recordAlertTransitions(paths, { now: t(40) });
  assert.equal(quiet.appended, 0);
});

test("escalation, closure, CLI acknowledgement and storms are logged", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: t(0) });
  await tick(paths, [candidate("a"), candidate("b")], 1);
  await tick(paths, [candidate("a", "critical"), candidate("b")], 2);
  await confirmAlertDelivery(paths, ID, { now: t(3), incidentKey: "b" });
  const [alert] = await readAlertRecords(paths);
  await writeAlertRecords(paths, [requestAlertClosure(alert, { incidentKeys: ["b"], reason: "label", now: t(3) }).alert]);
  await recordAlertTransitions(paths, { now: t(3) });
  await acknowledgeAlert(paths, ID, { now: t(4) });
  await recordAlertTransitions(paths, { now: t(5) });
  const flood = Array.from({ length: MAX_LIVE_INCIDENTS + 2 }, (_, index) => candidate(`f-${index}`));
  await tick(paths, flood, 6);
  const log = await readAlertTransitions(paths);
  const byKind = (kind) => log.records.filter((record) => record.kind === kind);
  assert.equal(byKind("escalated").length, 1);
  assert.equal(byKind("escalated")[0].incident_key, "a");
  assert.equal(byKind("incident_closed").length, 1);
  assert.equal(byKind("incident_closed")[0].reason, "label");
  assert.equal(byKind("acknowledged").length, 1, "a CLI acknowledgement is observed and logged on the daemon's next read");
  assert.equal(byKind("incident_storm").length, 1);
});

test("incumbent_edge_rearm_logged_not_evidence: an edge-triggered rule's recovery is recovered(edge_rearm)", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: t(0) });
  await tick(paths, [candidate("x", "warning", "session.churn")], 1);
  await tick(paths, [], 2);
  const log = await readAlertTransitions(paths);
  const recovered = log.records.find((record) => record.kind === "recovered");
  assert.equal(recovered.reason, "edge_rearm");
});

test("a tampered log restarts the chain, keeps the broken file aside, and marks a coverage gap", async () => {
  const paths = await tempPaths();
  const { logFile, brokenFile } = resolveAlertTransitionPaths(paths);
  await recordAlertTransitions(paths, { now: t(0) });
  await tick(paths, [candidate()], 1);
  const raw = (await fs.readFile(logFile, "utf8")).split("\n");
  const second = JSON.parse(raw[1]);
  second.severity = "critical";
  raw[1] = JSON.stringify(second);
  await fs.writeFile(logFile, raw.join("\n"));
  assert.equal((await readAlertTransitions(paths)).status, "broken");
  const report = await tick(paths, [], 2);
  assert.equal(report.restarted, "hash_mismatch");
  await fs.access(brokenFile);
  const log = await readAlertTransitions(paths);
  assert.equal(log.status, "valid");
  assert.equal(log.records[0].kind, "chain_restart");
  assert.equal(log.coverage_from_ts, t(2));
  assert.ok(log.records.some((record) => record.kind === "recovered"), "the projection survives the restart via the state file");
});

test("a deleted log with a surviving state is a restart, never a fresh genesis", async () => {
  const paths = await tempPaths();
  const { logFile } = resolveAlertTransitionPaths(paths);
  await recordAlertTransitions(paths, { now: t(0) });
  await tick(paths, [candidate()], 1);
  await fs.rm(logFile);
  const report = await recordAlertTransitions(paths, { now: t(2) });
  assert.equal(report.restarted, "log_missing");
  assert.equal((await readAlertTransitions(paths)).records[0].kind, "chain_restart");
});

test("a crash between the log append and the state write folds the suffix: no duplicate activation", async () => {
  const paths = await tempPaths();
  const { stateFile } = resolveAlertTransitionPaths(paths);
  await recordAlertTransitions(paths, { now: t(0) });
  const staleState = await fs.readFile(stateFile, "utf8");
  await tick(paths, [candidate()], 1);
  await fs.writeFile(stateFile, staleState);
  const report = await recordAlertTransitions(paths, { now: t(2) });
  assert.equal(report.appended, 0);
  assert.equal(report.rebaselined, null);
  const log = await readAlertTransitions(paths);
  assert.equal(log.records.filter((record) => record.kind === "activated").length, 1);
});

test("a missing state over an existing log rebaselines visibly", async () => {
  const paths = await tempPaths();
  const { stateFile } = resolveAlertTransitionPaths(paths);
  await recordAlertTransitions(paths, { now: t(0) });
  await tick(paths, [candidate()], 1);
  await fs.rm(stateFile);
  const report = await recordAlertTransitions(paths, { now: t(2) });
  assert.equal(report.rebaselined, "state_missing");
  const log = await readAlertTransitions(paths);
  assert.equal(log.records.at(-1).kind, "rebaselined");
  assert.equal(log.coverage_from_ts, t(2));
});

test("compaction keeps a verifiable cut header and the chain continues", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: t(0) });
  for (let index = 0; index < 30; index += 1) {
    const applied = applyAlertCandidates(await readAlertRecords(paths), index % 2 === 0 ? [candidate()] : [], { now: t(index + 1) });
    await writeAlertRecords(paths, applied.alerts);
    await recordAlertTransitions(paths, { now: t(index + 1), maxBytes: 4096 });
  }
  const log = await readAlertTransitions(paths);
  assert.equal(log.status, "valid");
  assert.equal(log.header?.kind, "compacted");
  assert.ok(log.coverage_from_ts >= log.header.through_ts);
  await tick(paths, [candidate()], 50);
  assert.equal((await readAlertTransitions(paths)).status, "valid");
});

test("deriveAlertTransitions is pure and ignores carried tombstones on a closed re-arm", () => {
  const first = applyAlertCandidates([], [candidate("a")], { now: t(0) });
  const delivered = { ...first.alerts[0], incidents: { a: { ...first.alerts[0].incidents.a, confirmed_at: t(1), notified_severity: "warning" } } };
  const closed = requestAlertClosure(delivered, { reason: "label", now: t(2), closeAlert: true }).alert;
  const projection = projectAlerts([closed]);
  const rearmed = applyAlertCandidates([closed], [candidate("a"), candidate("b")], { now: t(3) });
  const records = deriveAlertTransitions(projection, rearmed.alerts, { now: t(3) });
  assert.deepEqual(kinds(records), ["activated", "incident_opened"]);
  assert.equal(records[1].incident_key, "b");
  assert.equal(records[0].from, "closed");
});
