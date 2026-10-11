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
import { FACT_FAMILY_IDS, FAMILY_DEFAULT_BUDGET_BYTES, FAMILY_TICK_SHAPES, familyBudgetCeilingBytes, familyBudgetFloorBytes } from "../src/fact-families.js";
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

test("G2 HIGH-2: carried retention failure stays fixed-alert-active across fast ticks and recovers only after a successful structural pass", async () => {
  const paths = await tempPaths();
  const failingPersist = async (descartesPaths, points, options) => {
    const result = await appendFactPointsByFamily(descartesPaths, points, options);
    return {
      ...result,
      families: { ...result.families, service: { ...result.families.service, retention_error: "simulated persistent retention failure" } },
      retention_error: "service: simulated persistent retention failure",
    };
  };

  const structuralFailure = await tick(paths, 0, { appendFactPoints: failingPersist });
  const alertId = "daemon.fact_store.retention_failing";
  const firstAlert = structuralFailure.alerts.alerts.find((alert) => alert.rule_id === alertId);
  assert.ok(firstAlert, "the structural retention failure must raise a fixed alert");
  assert.equal(firstAlert.fingerprint, "service");
  assert.equal(firstAlert.status, "active");
  assert.equal(structuralFailure.status.state, "error");

  const fast = await tick(paths, 0.5);
  const carriedAlert = fast.alerts.alerts.find((alert) => alert.rule_id === alertId && alert.fingerprint === "service");
  assert.ok(carriedAlert, "the carried persisted retention failure must remain visible on a fast tick");
  assert.equal(carriedAlert.status, "active");
  assert.equal(fast.status.state, "error", "carried retention failure must not fabricate daemon health ok");

  const unreadableStatusFast = await tick(paths, 0.75, {
    readDaemonStatus: async () => { throw new Error("status unreadable"); },
  });
  const unreadableAlert = unreadableStatusFast.alerts.alerts.find((alert) => alert.rule_id === alertId && alert.fingerprint === "service");
  assert.equal(unreadableAlert?.status, "active", "an unreadable prior status cannot authorize recovery");
  assert.equal(unreadableStatusFast.alerts.candidates.some((candidate) => candidate.rule_id === alertId && candidate.fingerprint === "service"), false, "an unresolved alert is frozen rather than re-emitted without successful evidence");

  await writeWatchConfig(paths, { enabled: false });
  await writeLearnedConfig(paths, { enabled: false });
  const bothOff = await tick(paths, 0.9);
  const bothOffAlert = bothOff.alerts.alerts.find((alert) => alert.rule_id === alertId && alert.fingerprint === "service");
  assert.equal(bothOffAlert?.status, "active", "both tiers off provides no successful retention pass");

  await writeWatchConfig(paths, { enabled: true });
  const recovered = await tick(paths, 1);
  const recoveredAlert = recovered.alerts.alerts.find((alert) => alert.rule_id === alertId && alert.fingerprint === "service");
  assert.equal(recoveredAlert?.status, "recovered", "only a successful structural retention pass may recover the fixed alert");
  assert.equal(recovered.status.fact_store_budgets.families.service.retention_error, undefined);
  assert.equal(recovered.status.state, "ok");
});

test("G2 MEDIUM re-gate: an unresolved retention alert freezes while failed delivery retries with both tiers disabled", async () => {
  const paths = await tempPaths();
  const failingPersist = async (descartesPaths, points, options) => {
    const result = await appendFactPointsByFamily(descartesPaths, points, options);
    return {
      ...result,
      families: { ...result.families, service: { ...result.families.service, retention_error: "simulated persistent retention failure" } },
      retention_error: "service: simulated persistent retention failure",
    };
  };

  const failed = await tick(paths, 0, { appendFactPoints: failingPersist });
  const alertId = "daemon.fact_store.retention_failing";
  const initial = failed.alerts.alerts.find((alert) => alert.rule_id === alertId && alert.fingerprint === "service");
  assert.ok(initial);
  const frozenFields = { last_seen: initial.last_seen, last_notified: initial.last_notified, cooldown_until: initial.cooldown_until };

  await writeWatchConfig(paths, { enabled: false });
  await writeLearnedConfig(paths, { enabled: false });
  for (const hour of [1, 2]) {
    const result = await tick(paths, hour);
    const current = result.alerts.alerts.find((alert) => alert.rule_id === alertId && alert.fingerprint === "service");
    assert.deepEqual({ last_seen: current.last_seen, last_notified: current.last_notified, cooldown_until: current.cooldown_until }, frozenFields);
    assert.equal(result.alerts.notification_due_ids.includes(current.id), true, "the persisted failed delivery remains due even when detector coverage is excluded");
    assert.equal(result.alerts.candidates.some((candidate) => candidate.rule_id === alertId && candidate.fingerprint === "service"), false);
    assert.equal(current.status, "active");
  }
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

// G2 L1: network and provenance carry no history-dependent rule, so the daemon never makes a history
// read of them and had no `bytes` to compare with the budget -- the oversize path of deviation 8 never
// ran for them. Their size now comes from a stat of the store file (no parse, tier-on only).
test("G2 L1: a network or provenance store above its budget reads retention_failing at once and reports its bytes, though the daemon makes no history read of it", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: false });
  const { resolveFactStorePaths } = await import("../src/fact-store.js");
  const sizes = { network: FAMILY_DEFAULT_BUDGET_BYTES.get("network") + 1, provenance: 1234 };
  await tick(paths, 0);
  // Grown between structural ticks (as a retention pass that keeps failing would leave them).
  for (const [family, size] of Object.entries(sizes)) {
    const file = resolveFactStorePaths(paths, family).factsFile;
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, "");
    await fs.truncate(file, size);
  }
  const fast = await tick(paths, 0.5);
  assert.equal(fast.structuralFacts, undefined, "a fast tick: no retention pass ran");
  const { families } = fast.status.fact_store_budgets;
  assert.equal(families.network.bytes, sizes.network);
  assert.equal(families.network.retention_failing, true, "above budget (network has no pinned worst tick)");
  assert.equal(families.provenance.bytes, sizes.provenance);
  assert.equal(families.provenance.retention_failing, undefined, "within budget");
  assert.equal(families.canary.bytes, undefined, "a never-created store the daemon does not read (canary: learned off) reports no size");
});

// G2 MEDIUM: supported structural intervals auto-scale missing family budgets. A profile below the
// ceiling boundary is rejected by validateDaemonProfile before this status path can run.
test("G2 MEDIUM: a supported 15-minute interval auto-scales defaults and accepts an explicitly raised family budget", async () => {
  const MIN = 60 * 1000;
  const fastProfile = { ...structuralProfile(), structural: { interval_ms: 15 * MIN, collectors: { services: { enabled: true } } } };
  const hourly = await tick(await tempPaths(), 0);
  for (const family of FACT_FAMILY_IDS) assert.equal(hourly.status.fact_store_budgets.families[family].horizon_invariant_unmet, undefined, `${family} at 1 h`);

  const paths = await tempPaths();
  const peerFloor = familyBudgetFloorBytes("peer", { structuralIntervalMs: 15 * MIN });
  await writeWatchConfig(paths, { enabled: true, fact_store_budgets: { peer: peerFloor } });
  const result = await tick(paths, 0, { profile: fastProfile });
  const { families } = result.status.fact_store_budgets;
  assert.equal(families.session.horizon_invariant_unmet, undefined, "the default session budget is auto-scaled at 15 minutes");
  assert.equal(families.service.horizon_invariant_unmet, undefined, "the default service budget is auto-scaled at 15 minutes");
  assert.equal(families.peer.budget_bytes, peerFloor);
  assert.equal(families.peer.horizon_invariant_unmet, undefined, "raised to the 15-minute floor: met");
  assert.equal(families.network.horizon_invariant_unmet, undefined, "no horizon, no invariant");
  assert.equal(result.status.fact_store_completeness.families.service.horizon_invariant_unmet, undefined);
});

// G2 L4: a same-UID watch.json cannot size a store (and its whole-file reads every fast tick) without
// bound; the oversize check is relative to the budget, so it needs the bound too.
test("G2 L4: a configured budget above the ceiling is clamped and reported; the store's oversize check uses the clamped budget", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true, fact_store_budgets: { service: 1e12 } });
  const result = await tick(paths, 0);
  const service = result.status.fact_store_budgets.families.service;
  assert.equal(service.budget_bytes, familyBudgetCeilingBytes("service"));
  assert.equal(service.source, "configured");
  assert.equal(service.ceiling_bytes, familyBudgetCeilingBytes("service"));
  assert.deepEqual(service.clamped, { reason: "budget_above_ceiling", configured_bytes: 1e12, ceiling_bytes: familyBudgetCeilingBytes("service") });
  const oversize = await tick(paths, 0.5, {
    readFactPoints: async (descartesPaths, options) => {
      const read = await readFactPoints(descartesPaths, options);
      return options.family === "service" ? { ...read, bytes: familyBudgetCeilingBytes("service") + FAMILY_TICK_SHAPES.get("service").worstTickBytes + 1 } : read;
    },
  });
  assert.equal(oversize.status.fact_store_budgets.families.service.retention_failing, true);
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

// Q5 (fact-store capacity plan §4.5 Config, §12): the legacy single-store cap is IGNORED by the
// per-family stores, and a deliberate operator value is named in status (never silently dropped);
// the written-in 5 MB default is not an operator choice and reports nothing.
test("Q5: a deliberate legacy fact_store_max_bytes (watch.json or learned.json) is reported as deprecated and ignored; the written-in default reports nothing", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true, fact_store_max_bytes: 64 * 1024 * 1024 });
  await writeLearnedConfig(paths, { enabled: true, fact_store_max_bytes: 1024 });
  const result = await tick(paths, 0);
  assert.deepEqual(result.status.fact_store_deprecations.map(({ key, source, configured_bytes: bytes, status }) => [key, source, bytes, status]), [
    ["fact_store_max_bytes", "watch.json", 64 * 1024 * 1024, "ignored"],
    ["fact_store_max_bytes", "learned.json", 1024, "ignored"],
  ]);
  assert.match(result.status.fact_store_deprecations[0].note, /fact_store_budgets/);
  // Ignored: the service store still gets its per-family default budget, not 1 KiB or 64 MiB.
  assert.equal(result.status.fact_store_budgets.families.service.budget_bytes, FAMILY_DEFAULT_BUDGET_BYTES.get("service"));

  const defaults = await tempPaths();
  // A pre-S4 watch.json with the written-in default, exactly as every old write left it.
  const { resolveWatchStorePaths } = await import("../src/watch-store.js");
  await fs.mkdir(path.dirname(resolveWatchStorePaths(defaults).configFile), { recursive: true });
  await fs.writeFile(resolveWatchStorePaths(defaults).configFile, JSON.stringify({ enabled: true, fact_store_max_bytes: 5 * 1024 * 1024 }));
  const quiet = await tick(defaults, 0);
  assert.equal(quiet.status.fact_store_deprecations, undefined);
});

test("T12 (daemon): one family's append failure is reported as storage_write_error (state error) while the other families persist this tick", async () => {
  const paths = await tempPaths();
  const { resolveFactStorePaths } = await import("../src/fact-store.js");
  // The network store's facts.jsonl is a directory: its append fails; the service store's does not.
  const networkFile = resolveFactStorePaths(paths, "network").factsFile;
  await fs.mkdir(path.join(networkFile, "blocker"), { recursive: true });
  const result = await runDaemonIteration(paths, {
    profile: { ...structuralProfile(), structural: { interval_ms: HOUR_MS, collectors: { services: { enabled: true }, network: { enabled: true } } } },
    collectors: fastCollectorFakes(),
    structuralCollectors: {
      ...serviceCollector(),
      network: async () => envelope("network-basics", "collect_network", { listening_sockets: [{ protocol: "tcp", state: "LISTEN", local_address: "0.0.0.0", local_port: 8080 }] }),
    },
    ts: at(0),
    now: at(0),
  });
  assert.match(result.status.storage_write_error, /network: /);
  assert.equal(result.status.state, "error");
  assert.equal(result.structuralFacts.families.network.written_count, 0);
  assert.ok(result.structuralFacts.families.service.written_count > 0);
  assert.ok((await readFactPoints(paths, { family: "service", now: at(0) })).points.length > 0, "the service family still persisted");
});

test("status shape: the top-level keys of a clean watch-tier tick's status record are pinned (a new block must be added here deliberately)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: false });
  const result = await tick(paths, 0);
  assert.deepEqual(Object.keys(result.status).sort(), [
    "collector_statuses",
    // Context plan C2: the tick_summary / statistics outcome (data only; never part of `state`).
    "context_c2",
    "context_key_status",
    "fact_store_budgets",
    "fact_store_completeness",
    "integrity_level",
    "mode",
    "novelty_seen_sets",
    "points_written",
    "profile",
    "retention",
    "state",
    "structural_collector_statuses",
    "ts",
  ]);
});

test("status: a never-created family store never shows horizon_short_since, even while a carried-forward horizon-short entry names one of its rules (I11: absent is 'not observed', not 'short')", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: false });
  const result = await tick(paths, 0, {
    readDaemonStatus: async () => ({ ts: at(-0.5), history_horizon_short: { threshold_ms: 24 * HOUR_MS, rules: { "session.count_drop": { since_ts: at(-10) } } } }),
  });
  assert.equal(result.status.history_horizon_short.rules["session.count_drop"].since_ts, at(-10), "the unknown rule's entry is carried (S3b LOW-2)");
  assert.equal(result.status.fact_store_completeness.families.session.store, "absent");
  assert.equal(result.status.fact_store_completeness.families.session.horizon_short_since, undefined);
});
