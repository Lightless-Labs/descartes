// S4 status surfaces (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §4.3-§4.5,
// T12): watch.json `fact_store_budgets`, and the daemon status record's per-family
// `fact_store_budgets` block (budget, source, rejected values as `budget_below_horizon_floor`,
// `cap_below_tick`, retention failure with a since-timestamp and `retention_failing`) plus the
// per-family entries of `fact_store_completeness`.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { loadWatchConfig, normalizeWatchConfig, writeWatchConfig } from "../src/watch-store.js";
import { appendFactPointsByFamily, readFactPoints } from "../src/fact-store.js";
import { FACT_FAMILY_IDS, FAMILY_DEFAULT_BUDGET_BYTES, FAMILY_TICK_SHAPES, familyBudgetFloorBytes } from "../src/fact-families.js";
import { resolveDescartesPaths } from "../src/paths.js";

const HOUR_MS = 60 * 60 * 1000;
const T0 = Date.parse("2026-05-24T00:00:00.000Z");
const at = (hours) => new Date(T0 + hours * HOUR_MS).toISOString();

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-store-status-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function envelope(id, tool, result) {
  return { id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: at(0) } };
}

function fastCollectorFakes() {
  return {
    system: async () => envelope("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

// A structural profile whose only collector is the services census (one service, census marker).
function structuralProfile() {
  return {
    interval_ms: 60_000,
    collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
    structural: { interval_ms: HOUR_MS, collectors: { services: { enabled: true } } },
  };
}

function serviceCollector() {
  return {
    services: async () => envelope("services", "collect_services", {
      manager: "systemd",
      services: [{ name: "nginx.service", running: true }],
    }),
  };
}

async function tick(paths, hours, extra = {}) {
  return runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: serviceCollector(),
    ts: at(hours),
    now: at(hours),
    ...extra,
  });
}

test("watch.json: fact_store_budgets round-trips (absent stays absent; a non-object is dropped)", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  assert.equal(Object.prototype.hasOwnProperty.call(await loadWatchConfig(paths), "fact_store_budgets"), false);
  await writeWatchConfig(paths, { enabled: true, fact_store_budgets: { peer: 32 * 1024 * 1024, service: 1024 } });
  assert.deepEqual((await loadWatchConfig(paths)).fact_store_budgets, { peer: 32 * 1024 * 1024, service: 1024 });
  for (const junk of ["x", 5, [], null]) assert.equal(normalizeWatchConfig({ fact_store_budgets: junk }).fact_store_budgets, undefined);
});

test("status: fact_store_budgets reports every registry family's effective budget and source; a value below the horizon floor is reported as budget_below_horizon_floor and the default applies", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true, fact_store_budgets: { peer: 32 * 1024 * 1024, service: 1024, bogus: 1 } });
  const result = await tick(paths, 0);
  const budgets = result.status.fact_store_budgets;
  assert.deepEqual(Object.keys(budgets.families).sort(), [...FACT_FAMILY_IDS].sort());
  assert.equal(budgets.families.peer.budget_bytes, 32 * 1024 * 1024);
  assert.equal(budgets.families.peer.source, "configured");
  assert.equal(budgets.families.service.budget_bytes, FAMILY_DEFAULT_BUDGET_BYTES.get("service"));
  assert.equal(budgets.families.service.source, "default");
  assert.deepEqual(budgets.families.service.rejected, { reason: "budget_below_horizon_floor", configured_bytes: 1024, floor_bytes: familyBudgetFloorBytes("service") });
  assert.deepEqual(budgets.unknown_families, ["bogus"]);
  // The per-family completeness entry of a family the daemon read carries its budget too.
  assert.equal(result.status.fact_store_completeness.families.service.budget_bytes, FAMILY_DEFAULT_BUDGET_BYTES.get("service"));
});

test("status: cap_below_tick when a family's live per-tick volume exceeds its effective budget; carried on the fast ticks in between, cleared when it fits again", async () => {
  const paths = await tempPaths();
  const tiny = { ...Object.fromEntries(FAMILY_DEFAULT_BUDGET_BYTES), service: 64 };
  const structural = await tick(paths, 0, { factStoreBudgets: tiny });
  assert.equal(structural.status.fact_store_budgets.families.service.cap_below_tick, true);
  assert.ok(structural.status.fact_store_budgets.families.service.last_tick_bytes > 64);
  const fast = await tick(paths, 0.5, { factStoreBudgets: tiny });
  assert.equal(fast.structuralFacts, undefined, "not a structural tick");
  assert.equal(fast.status.fact_store_budgets.families.service.cap_below_tick, true, "carried from the last structural tick");
  const fits = await tick(paths, 1);
  assert.equal(fits.status.fact_store_budgets.families.service.cap_below_tick, undefined);
});

test("T12: a persistently failing retention pass surfaces retention_error with a since-timestamp, then retention_failing after N structural intervals", async () => {
  const paths = await tempPaths();
  const failingPersist = async (descartesPaths, points, options) => {
    const result = await appendFactPointsByFamily(descartesPaths, points, options);
    return { ...result, families: { ...result.families, service: { ...result.families.service, retention_error: "simulated retention failure" } }, retention_error: "service: simulated retention failure" };
  };
  const first = await tick(paths, 0, { appendFactPoints: failingPersist });
  const service = first.status.fact_store_budgets.families.service;
  assert.equal(service.retention_error, "simulated retention failure");
  assert.equal(service.retention_error_since_ts, at(0));
  assert.equal(service.retention_failing, undefined, "one failed pass is not yet 'failing'");
  assert.equal(first.status.state, "error", "a retention failure is still a not-ok daemon state");
  let last;
  for (let hours = 1; hours <= 24; hours += 1) {
    last = await tick(paths, hours, { appendFactPoints: failingPersist });
    assert.equal(last.status.fact_store_budgets.families.service.retention_error_since_ts, at(0), "since_ts carried while it keeps failing");
  }
  assert.equal(last.status.fact_store_budgets.families.service.retention_failing, true);
  const healed = await tick(paths, 25);
  assert.equal(healed.status.fact_store_budgets.families.service.retention_error, undefined);
  assert.equal(healed.status.fact_store_budgets.families.service.retention_failing, undefined);
});

test("T12: a store larger than its budget by more than one worst-case tick reads retention_failing at once", async () => {
  const paths = await tempPaths();
  await tick(paths, 0);
  const budget = FAMILY_DEFAULT_BUDGET_BYTES.get("service");
  const result = await tick(paths, 0.5, {
    readFactPoints: async (descartesPaths, options) => {
      const read = await readFactPoints(descartesPaths, options);
      return options.family === "service" ? { ...read, bytes: budget + FAMILY_TICK_SHAPES.get("service").worstTickBytes + 1 } : read;
    },
  });
  assert.equal(result.status.fact_store_budgets.families.service.retention_failing, true);
  assert.equal(result.status.fact_store_completeness.families.service.retention_failing, true);
});

test("status: a family store that was never created is `absent` (not observed), never 'unknown'", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: false });
  const result = await tick(paths, 0);
  const families = result.status.fact_store_completeness.families;
  assert.equal(families.service.store, "present");
  assert.equal(families.peer.store, "absent");
  assert.equal(families.session.store, "absent");
  assert.equal(result.status.fact_store_completeness.status, families.service.status, "the combined status is over the stores that exist");
});
