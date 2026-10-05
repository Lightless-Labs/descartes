import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { runLearnedConfigCommand } from "../src/constraint-store.js";
import {
  buildBaselineInspect,
  buildBaselineStatus,
  runBaseline,
} from "../src/baseline.js";
import { loadWatchConfig, resolveWatchStorePaths, writeWatchConfig } from "../src/watch-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-baseline-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function capture() {
  const values = [];
  return { values, output: (value) => values.push(value) };
}

// S6 (fact-store capacity plan §4.4, I11): rewritten. A fresh install has never created any family
// store, so every domain (and every rule in it) reads "not observed (no store)", not "still learning
// -- 0 of 6": nothing has been observed for it to learn from, and its detectors evaluate nothing. The
// cold-start reason is still reported from the (fresh, pending) detector stores.
test("baseline status on a fresh install is watch-on and reports every domain not observed (no store)", async () => {
  const paths = await tempPaths();
  const result = await buildBaselineStatus(paths, { now: "2026-09-27T12:00:00.000Z" });

  assert.equal(result.watch_config.enabled, true);
  assert.deepEqual(result.domains.map((domain) => domain.domain), [
    "service",
    "session",
    "peer",
    "scheduled-job",
    "process-lineage",
  ]);
  for (const domain of result.domains) {
    assert.equal(domain.phase, "not observed (no store)");
    assert.equal(domain.cold_start_reason, "initial_baseline");
    for (const rule of domain.rules) {
      assert.equal(rule.phase, "not observed (no store)");
      assert.equal(rule.watching, false);
      assert.ok(rule.reasons.includes("not_observed_no_store"));
    }
  }
  assert.deepEqual(Object.keys(result.families).sort(), ["peer", "process_lineage", "scheduled_job", "service", "session"]);
  for (const family of Object.values(result.families)) assert.equal(family.store, "absent");
});

test("baseline status renders human and JSON forms", async () => {
  const paths = await tempPaths();
  const human = capture();
  await runBaseline(paths, ["status"], { output: human.output, now: "2026-09-27T12:00:00.000Z" });
  assert.match(human.values[0], /Structural watching: enabled/);
  assert.match(human.values[0], /service: not observed \(no store\)/);
  assert.match(human.values[0], /service\.disappeared: not observed \(no store\)/);
  assert.match(human.values[0], /process-lineage: not observed \(no store\)/);

  const json = capture();
  await runBaseline(paths, ["status", "--json"], { output: json.output, now: "2026-09-27T12:00:00.000Z" });
  const parsed = JSON.parse(json.values[0]);
  assert.equal(parsed.watch_config.enabled, true);
  assert.equal(parsed.domains[0].phase, "not observed (no store)");
});

test("baseline inspect is live, supports a domain filter, and exposes the recomputation note", async () => {
  const paths = await tempPaths();
  const point = (ts, entity_key) => ({
    ts,
    fact_name: "service.presence",
    entity_key,
    attributes: {},
  });
  const census = (ts) => ({
    ts,
    fact_name: "service.census",
    entity_key: "service.census-marker.v1",
    attributes: { census_state: "complete" },
  });
  const points = [];
  for (let index = 0; index < 4; index += 1) {
    const ts = `2026-09-27T0${index}:00:00.000Z`;
    points.push(census(ts), point(ts, "service.example"));
  }

  const readFactPoints = async () => ({
    points,
    corrupt_count: 0,
    completeness: { status: "intact" },
  });
  const result = await buildBaselineInspect(paths, {
    now: "2026-09-27T12:00:00.000Z",
    readFactPoints,
    domain: "service",
  });
  assert.equal(result.domains.length, 1);
  assert.deepEqual(result.domains[0].established, ["service.example"]);
  assert.equal(result.recomputed_live, true);
  assert.match(result.note, /recomputed live/i);

  const human = capture();
  await runBaseline(paths, ["inspect", "--domain", "service"], { output: human.output, now: "2026-09-27T12:00:00.000Z", readFactPoints });
  assert.match(human.values[0], /Established \(1\): service\.example/);

  const json = capture();
  await runBaseline(paths, ["inspect", "--domain", "service", "--json"], { output: json.output, now: "2026-09-27T12:00:00.000Z", readFactPoints });
  assert.deepEqual(JSON.parse(json.values[0]).domains[0].established, ["service.example"]);
});

test("baseline enable and disable write only watch.json", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true, fact_store_max_bytes: 2048 }, { now: "2026-09-27T11:00:00.000Z" });
  const disabled = capture();
  await runBaseline(paths, ["disable"], { output: disabled.output, now: "2026-09-27T12:00:00.000Z" });
  assert.match(disabled.values[0], /Structural watching: disabled/);
  assert.equal((await loadWatchConfig(paths)).enabled, false);
  assert.equal((await loadWatchConfig(paths)).fact_store_max_bytes, 2048);

  const enabled = capture();
  await runBaseline(paths, ["enable", "--json"], { output: enabled.output, now: "2026-09-27T12:00:00.000Z" });
  assert.equal(JSON.parse(enabled.values[0]).watch_config.enabled, true);
  assert.equal((await loadWatchConfig(paths)).enabled, true);
  assert.equal((await fs.stat(resolveWatchStorePaths(paths).configFile)).isFile(), true);
});

test("an explicit learned disable does not disable default-on watch", async () => {
  const paths = await tempPaths();
  const output = capture();
  await runLearnedConfigCommand(paths, "disable", ["--json"], { output: output.output, now: "2026-09-27T12:00:00.000Z" });
  assert.equal(JSON.parse(output.values[0]).learned_config.enabled, false);
  assert.equal((await loadWatchConfig(paths)).enabled, true);

  const status = await buildBaselineStatus(paths, { now: "2026-09-27T12:00:00.000Z" });
  assert.equal(status.watch_config.enabled, true);
  // S6: no store exists yet (nothing was observed), but the domain is NOT "disabled".
  assert.equal(status.domains[0].phase, "not observed (no store)");
});

test("baseline status with watch disabled reports every rule disabled and reads no fact store", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: false }, { now: "2026-09-27T11:00:00.000Z" });
  const status = await buildBaselineStatus(paths, {
    now: "2026-09-27T12:00:00.000Z",
    readFactPoints: async () => { throw new Error("a disabled watch tier must not read fact history"); },
  });
  for (const domain of status.domains) {
    assert.equal(domain.phase, "disabled");
    for (const rule of domain.rules) assert.equal(rule.phase, "disabled");
  }
});
