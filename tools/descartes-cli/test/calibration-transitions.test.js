// Context plan C1.2 (§9): fired_count from `activated` transitions. Reproduces the verified
// tuning-loop defect (docs/reviews/2026-10-06-learning-principle-audit-astra.md finding 3): a stable
// alert identity collapsed ten fire/recover cycles into fired_count 1, so no tuning proposal was ever
// mined. With the daemon's transition log the ten episodes are counted.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { applyAlertCandidates, readAlertRecords, writeAlertRecords } from "../src/alert-store.js";
import { readAlertTransitions, recordAlertTransitions } from "../src/alert-transitions.js";
import { computeCalibrationReport } from "../src/calibration.js";
import { mineTuningCandidates } from "../src/tuning-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-calibration-transitions-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const CONSTRAINT_ID = "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa";
const RULE_ID = "constraint.violation.daemon-config";

function violation() {
  return { id: "alert_cal_tr_0000001", rule_id: RULE_ID, fingerprint: CONSTRAINT_ID, severity: "warning", title: "violation", summary: "s", diagnostics: { constraint_id: CONSTRAINT_ID } };
}

function at(hour, minute = 0) {
  return new Date(Date.UTC(2026, 9, 1, hour, minute)).toISOString();
}

async function cycle(paths, cycles, { recordEvery = true } = {}) {
  await recordAlertTransitions(paths, { now: at(0) });
  for (let index = 0; index < cycles; index += 1) {
    for (const [candidates, minute] of [[[violation()], 0], [[], 5]]) {
      const now = at(index + 1, minute);
      const applied = applyAlertCandidates(await readAlertRecords(paths), candidates, { now });
      await writeAlertRecords(paths, applied.alerts);
      if (recordEvery) await recordAlertTransitions(paths, { now });
    }
  }
}

const constraint = {
  id: CONSTRAINT_ID,
  kind: "constraint",
  family: "daemon-config",
  target: "daemon.profile.interval_ms",
  expected: { comparator: "gte", value: 1000 },
  status: "active",
  confidence: 1,
  provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: "2026-07-01T00:00:00.000Z" },
  fixtures: [],
  promotion_history: [],
  first_observed: "2026-07-01T00:00:00.000Z",
  last_verified: "2026-07-01T00:00:00.000Z",
  sensitivity: "operational",
  schema_version: 1,
};

test("ten fire/recover cycles under one stable identity: snapshot says 1, transitions say 10", async () => {
  const paths = await tempPaths();
  await cycle(paths, 10);
  const alerts = await readAlertRecords(paths);
  assert.equal(alerts.length, 1, "one stable alert record");

  const legacy = computeCalibrationReport(alerts, [], [], [], { now: at(20) });
  assert.equal(legacy.artifacts[0].fired_count, 1, "the verified defect: the snapshot collapses ten episodes");
  assert.equal(legacy.artifacts[0].fired_count_is_lower_bound, true);
  assert.deepEqual(mineTuningCandidates([constraint], legacy, new Map(), { now: at(20) }), [], "and nothing is ever mined");

  const transitions = await readAlertTransitions(paths);
  const report = computeCalibrationReport(alerts, [], [], [], { now: at(20), transitions });
  const row = report.artifacts[0];
  assert.equal(row.fired_count, 10);
  assert.equal(row.fired_count_source, "transitions");
  assert.equal(row.fired_count_is_lower_bound, false, "the log covers every episode of this alert");
  assert.equal(row.auto_recovered_fast_count, 10);
  assert.equal(row.chronically_firing, true);
  const mined = mineTuningCandidates([constraint], report, new Map(), { now: at(20) });
  assert.equal(mined.length, 1);
  assert.equal(mined[0].kind, "retire");
});

test("a window inside the log's coverage counts only its activations, exactly", async () => {
  const paths = await tempPaths();
  await cycle(paths, 10);
  const transitions = await readAlertTransitions(paths);
  const report = computeCalibrationReport(await readAlertRecords(paths), [], [], [], { now: at(20), since: at(6), transitions });
  assert.equal(report.artifacts[0].fired_count, 5);
  assert.equal(report.artifacts[0].fired_count_is_lower_bound, false);
});

test("episodes before the log's coverage keep the count a lower bound", async () => {
  const paths = await tempPaths();
  // The alert fires before the log exists, so the genesis record cannot vouch for its history.
  const applied = applyAlertCandidates([], [violation()], { now: at(-1) });
  await writeAlertRecords(paths, applied.alerts);
  await cycle(paths, 3);
  const transitions = await readAlertTransitions(paths);
  const report = computeCalibrationReport(await readAlertRecords(paths), [], [], [], { now: at(20), transitions });
  assert.equal(report.artifacts[0].fired_count_is_lower_bound, true);
  assert.ok(report.artifacts[0].fired_count >= 2);
  const windowed = computeCalibrationReport(await readAlertRecords(paths), [], [], [], { now: at(20), since: at(-2), transitions });
  assert.equal(windowed.artifacts[0].fired_count_is_lower_bound, true, "a window that starts before coverage is a lower bound");
});

test("a persistent episode with many incidents is one activation (incidents never inflate fired_count)", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: at(0) });
  for (let index = 0; index < 6; index += 1) {
    const now = at(1, index);
    const applied = applyAlertCandidates(await readAlertRecords(paths), [{ ...violation(), incident_key: `k-${index}` }], { now });
    await writeAlertRecords(paths, applied.alerts);
    await recordAlertTransitions(paths, { now });
  }
  const transitions = await readAlertTransitions(paths);
  const report = computeCalibrationReport(await readAlertRecords(paths), [], [], [], { now: at(5), transitions });
  assert.equal(report.artifacts[0].fired_count, 1);
});
