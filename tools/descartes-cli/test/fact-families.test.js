import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { appendFactPoints, enforceFactRetention, readFactPoints } from "../src/fact-store.js";
import {
  FACT_FAMILY_BY_NAME,
  FACT_FAMILY_IDS,
  FAMILY_DEFAULT_BUDGET_BYTES,
  FAMILY_HORIZON_MAX_MS,
  FAMILY_TICK_SHAPES,
  familyBudgetCeilingBytes,
  familyBudgetFloorBytes,
  groupFactPointsByFamily,
  requireFactFamily,
  resolveFactStoreBudgets,
  NOVELTY_FAMILIES,
  READER_COVERAGE,
  RULE_HORIZONS,
  ruleHorizonMs,
} from "../src/fact-families.js";
import { certifiedHorizonOk, certifiedReadWindowOk, ruleEligible, ruleHorizonOk } from "../src/fact-store-completeness.js";
import { HISTORY_DEPENDENT_ALERT_RULE_IDS } from "../src/daemon.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-families-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function completeness(overrides = {}) {
  return {
    completeness: {
      status: "intact",
      bytecap_floor_ts: null,
      age_floor_ts: null,
      coverage: "full",
      ...overrides,
    },
    corrupt_count: 0,
    schema_invalid_count: 0,
  };
}

const NOW_MS = Date.parse("2026-10-05T12:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();

test("registry: every fact_name maps to exactly one known family, and the family list is closed", () => {
  for (const [factName, family] of FACT_FAMILY_BY_NAME) {
    assert.ok(FACT_FAMILY_IDS.includes(family), `${factName} -> ${family} must be a known family`);
  }
  assert.equal(FACT_FAMILY_BY_NAME.get("service.census"), "service");
  assert.equal(FACT_FAMILY_BY_NAME.get("process.lineage_edge.census"), "process_lineage");
  assert.equal(FACT_FAMILY_BY_NAME.get("provenance.warning"), "provenance");
});

test("registry: the rule-horizon literals match the daemon's HISTORY_DEPENDENT_ALERT_RULE_IDS exactly (both directions)", () => {
  assert.deepEqual([...RULE_HORIZONS.keys()].sort(), [...HISTORY_DEPENDENT_ALERT_RULE_IDS].sort());
});

test("registry: operator Q2 horizons (§12) and the §4.2 table", () => {
  assert.equal(ruleHorizonMs("service.appeared"), 48 * HOUR);
  assert.equal(ruleHorizonMs("scheduled_job.appeared"), 48 * HOUR);
  assert.equal(ruleHorizonMs("process.lineage.novel_edge"), 6 * DAY);
  assert.equal(ruleHorizonMs("service.disappeared"), 6 * HOUR);
  assert.equal(ruleHorizonMs("session.churn"), 6 * HOUR);
  assert.equal(ruleHorizonMs("canary.tampered"), 6 * HOUR);
  assert.equal(ruleHorizonMs("session.count_drop"), 30 * HOUR);
  assert.equal(ruleHorizonMs("peer.count_spike"), 30 * HOUR);
  assert.equal(ruleHorizonMs("peer.count_drop"), 30 * HOUR);
  assert.equal(ruleHorizonMs("correlation.login_kill_proximity"), 3 * DAY);
  assert.equal(ruleHorizonMs("not.a.rule"), undefined);
});

test("registry: non-detector readers carry an explicit narrowing policy; novelty families map 1:1 to the novelty rules", () => {
  assert.equal(READER_COVERAGE.get("constraint_miner").coverage, "read_window");
  assert.equal(READER_COVERAGE.get("shadow_evaluator").coverage, "read_window");
  assert.equal(READER_COVERAGE.get("correlation").coverage, "read_window");
  assert.equal(READER_COVERAGE.get("tuning_miner").coverage, "report_only");
  assert.deepEqual([...NOVELTY_FAMILIES.keys()].sort(), ["process_lineage", "scheduled_job", "service"]);
  for (const [family, entry] of NOVELTY_FAMILIES) {
    assert.equal(RULE_HORIZONS.get(entry.ruleId).kind, "novelty");
    assert.deepEqual(RULE_HORIZONS.get(entry.ruleId).families, [family]);
  }
});

test("certifiedHorizonOk: no floor at all -> eligible (day-1 behavior unchanged; existing per-detector gates govern)", () => {
  assert.equal(certifiedHorizonOk(completeness(), { nowMs: NOW_MS, horizonMs: 48 * HOUR }), true);
});

test("certifiedHorizonOk: requires now - floor >= horizon on the raw byte-cap floor", () => {
  const read = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 10 * HOUR) });
  assert.equal(certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 6 * HOUR }), true);
  assert.equal(certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 10 * HOUR }), true, "exactly the horizon is enough");
  assert.equal(certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 10 * HOUR + 1 }), false);
  assert.equal(certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 48 * HOUR }), false);
});

test("certifiedHorizonOk: the age floor counts too -- never looser than what readFactPoints itself excludes (max of both floors)", () => {
  const read = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 40 * HOUR), age_floor_ts: iso(NOW_MS - 2 * HOUR) });
  assert.equal(certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 6 * HOUR }), false);
  assert.equal(certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 2 * HOUR }), true);
});

test("certifiedHorizonOk: fails closed on no valid ledger (coverage unknown, LOW-2), malformed or missing completeness, a future floor, or bad inputs", () => {
  assert.equal(certifiedHorizonOk(completeness({ coverage: "unknown" }), { nowMs: NOW_MS, horizonMs: HOUR }), false, "LOW-2: a null floor with no ledger is NOT day-1-eligible");
  assert.equal(certifiedHorizonOk(completeness({ coverage: undefined }), { nowMs: NOW_MS, horizonMs: HOUR }), false);
  assert.equal(certifiedHorizonOk({}, { nowMs: NOW_MS, horizonMs: HOUR }), false);
  assert.equal(certifiedHorizonOk(undefined, { nowMs: NOW_MS, horizonMs: HOUR }), false);
  assert.equal(certifiedHorizonOk(completeness({ bytecap_floor_ts: "garbage", coverage: "narrowed" }), { nowMs: NOW_MS, horizonMs: HOUR }), false);
  assert.equal(certifiedHorizonOk(completeness({ bytecap_floor_ts: iso(NOW_MS + 1), coverage: "narrowed" }), { nowMs: NOW_MS, horizonMs: 0 }), false, "a floor in the future is never eligible");
  assert.equal(certifiedHorizonOk(completeness(), { nowMs: Number.NaN, horizonMs: HOUR }), false);
  assert.equal(certifiedHorizonOk(completeness(), { nowMs: NOW_MS, horizonMs: Number.NaN }), false);
  const narrowedWithoutFloor = completeness({ coverage: "narrowed" });
  delete narrowedWithoutFloor.completeness.bytecap_floor_ts;
  delete narrowedWithoutFloor.completeness.age_floor_ts;
  assert.equal(certifiedHorizonOk(narrowedWithoutFloor, { nowMs: NOW_MS, horizonMs: HOUR }), false, "'narrowed' with no floor at all is self-contradictory");
  assert.equal(certifiedHorizonOk({ completeness: { status: "intact", coverage: "full" } }, { nowMs: NOW_MS, horizonMs: HOUR }), true, "an absent floor field on a 'full' report reads as null");
});

test("certifiedHorizonOk is pure: it never mutates its input", () => {
  const read = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - HOUR) });
  const before = structuredClone(read);
  certifiedHorizonOk(read, { nowMs: NOW_MS, horizonMs: 6 * HOUR });
  assert.deepEqual(read, before);
});

test("certifiedReadWindowOk: a byte-cap floor strictly before the read window start is invisible to that read; at or inside it is not", () => {
  const windowMs = 3 * HOUR;
  const startMs = NOW_MS - windowMs;
  assert.equal(certifiedReadWindowOk(completeness(), { nowMs: NOW_MS, windowMs }), true);
  assert.equal(certifiedReadWindowOk(completeness({ coverage: "narrowed", bytecap_floor_ts: iso(startMs - 1) }), { nowMs: NOW_MS, windowMs }), true);
  assert.equal(certifiedReadWindowOk(completeness({ coverage: "narrowed", bytecap_floor_ts: iso(startMs) }), { nowMs: NOW_MS, windowMs }), false, "the floor is exclusive and the window inclusive: a point at exactly the start would be hidden");
  assert.equal(certifiedReadWindowOk(completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - HOUR) }), { nowMs: NOW_MS, windowMs }), false);
});

test("certifiedReadWindowOk: a byte-cap floor at or below the age floor is invisible to ANY read (the range it evicted was age-evicted too); an unbounded read needs exactly that", () => {
  const read = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 31 * DAY), age_floor_ts: iso(NOW_MS - 30 * DAY) });
  assert.equal(certifiedReadWindowOk(read, { nowMs: NOW_MS, windowMs: undefined }), true);
  assert.equal(certifiedReadWindowOk(read, { nowMs: NOW_MS, windowMs: 31 * DAY }), true);
  const recent = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 2 * DAY), age_floor_ts: iso(NOW_MS - 30 * DAY) });
  assert.equal(certifiedReadWindowOk(recent, { nowMs: NOW_MS, windowMs: undefined }), false);
  assert.equal(certifiedReadWindowOk(completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 2 * DAY) }), { nowMs: NOW_MS, windowMs: undefined }), false, "no age floor: an unbounded read sees the byte-cap narrowing");
  // An age floor alone never refuses (main always age-evicted; the referent is a store that never
  // BYTE-evicted under the same retention).
  assert.equal(certifiedReadWindowOk(completeness({ coverage: "narrowed", age_floor_ts: iso(NOW_MS - 30 * DAY) }), { nowMs: NOW_MS, windowMs: 31 * DAY }), true);
});

test("certifiedReadWindowOk: fails closed with no valid ledger, malformed completeness, or bad inputs", () => {
  assert.equal(certifiedReadWindowOk(completeness({ coverage: "unknown" }), { nowMs: NOW_MS, windowMs: HOUR }), false);
  assert.equal(certifiedReadWindowOk({}, { nowMs: NOW_MS, windowMs: HOUR }), false);
  assert.equal(certifiedReadWindowOk(completeness({ bytecap_floor_ts: "garbage", coverage: "narrowed" }), { nowMs: NOW_MS, windowMs: HOUR }), false);
  assert.equal(certifiedReadWindowOk(completeness(), { nowMs: Number.NaN, windowMs: HOUR }), false);
  assert.equal(certifiedReadWindowOk(completeness(), { nowMs: NOW_MS, windowMs: -1 }), false);
});

test("ruleEligible (S3b review MEDIUM-2): correlation is eligible only when its whole read window is certified, not merely its 3 d horizon -- the daemon signal/veto and the detector share this one predicate", () => {
  const CORRELATION = "correlation.login_kill_proximity";
  const tenDaysBack = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 10 * DAY) });
  assert.equal(ruleHorizonOk(tenDaysBack, CORRELATION, NOW_MS), true, "discriminating fixture: the 3 d horizon alone is met");
  assert.equal(certifiedReadWindowOk(tenDaysBack, { nowMs: NOW_MS, windowMs: 31 * DAY }), false, "but the 31 d read window sees the narrowing");
  assert.equal(ruleEligible(tenDaysBack, CORRELATION, NOW_MS, { readWindowMs: 31 * DAY }), false);
  assert.equal(ruleEligible(tenDaysBack, CORRELATION, NOW_MS), false, "fails closed without a read window");
  const fortyDaysBack = completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 40 * DAY) });
  assert.equal(ruleEligible(fortyDaysBack, CORRELATION, NOW_MS, { readWindowMs: 31 * DAY }), true, "a floor older than the read window is invisible to it");
  // Non-correlation rules keep their registered horizon; an unknown rule fails closed.
  assert.equal(ruleEligible(tenDaysBack, "session.count_drop", NOW_MS), true);
  assert.equal(ruleEligible(completeness({ coverage: "narrowed", bytecap_floor_ts: iso(NOW_MS - 2 * HOUR) }), "session.count_drop", NOW_MS), false);
  assert.equal(ruleEligible(tenDaysBack, "not.a.rule", NOW_MS, { readWindowMs: 31 * DAY }), false);
});

function servicePoint(ts, name) {
  return { ts, fact_name: "service.presence", entity_key: name, attributes: { running: "true" }, source_tool: "test" };
}

test("certifiedReadWindowOk is PROVABLY no weaker than 'no byte-cap narrowing': whenever it passes, the read returns exactly the points a never-byte-evicted store returns", async () => {
  const evicted = await tempPaths();
  const reference = await tempPaths();
  const start = Date.parse("2026-10-01T00:00:00.000Z");
  let nowMs = start;
  for (let tick = 0; tick < 12; tick += 1) {
    nowMs = start + tick * HOUR;
    const ts = iso(nowMs);
    const points = [servicePoint(ts, `svc-a-${tick % 3}`), servicePoint(ts, `svc-b-${tick}`)];
    // A small cap forces routine byte-cap eviction on one store; the reference never evicts.
    await appendFactPoints(evicted, points, { family: "service", now: ts, maxBytes: 1200 });
    await appendFactPoints(reference, points, { family: "service", now: ts, maxBytes: 10 * 1024 * 1024 });
  }
  let passes = 0;
  for (const windowMs of [HOUR, 2 * HOUR, 3 * HOUR, 5 * HOUR, 8 * HOUR, 11 * HOUR, 30 * DAY]) {
    const readOptions = { windowMs, now: iso(nowMs) };
    const narrowed = await readFactPoints(evicted, { family: "service", ...(readOptions) });
    const full = await readFactPoints(reference, { family: "service", ...(readOptions) });
    assert.equal(narrowed.completeness.coverage, "narrowed", "the evicting store really was narrowed");
    if (certifiedReadWindowOk(narrowed, { nowMs, windowMs })) {
      passes += 1;
      assert.deepEqual(narrowed.points, full.points, `window ${windowMs}: certified => identical input`);
    } else {
      assert.notDeepEqual(narrowed.points, full.points, `window ${windowMs}: refused only when the narrowing is actually visible`);
    }
  }
  assert.ok(passes > 0 && passes < 7, "the oracle exercised both outcomes");
});

test("T5 (deferred from S2): maxBytes 0 and a single tick over the cap leave an empty store whose horizon is ineligible", async () => {
  for (const maxBytes of [0, 50]) {
    const paths = await tempPaths();
    const ts = "2026-10-05T00:00:00.000Z";
    await appendFactPoints(paths, [servicePoint(ts, "svc-a"), servicePoint(ts, "svc-b")], { family: "service", now: ts, maxBytes });
    await enforceFactRetention(paths, { family: "service", now: ts, maxBytes });
    const read = await readFactPoints(paths, { family: "service", windowMs: 31 * DAY, now: ts });
    assert.deepEqual(read.points, []);
    assert.equal(read.completeness.coverage, "narrowed");
    assert.equal(certifiedHorizonOk(read, { nowMs: Date.parse(ts), horizonMs: HOUR }), false);
  }
});

// --- S4 (fact-store capacity plan §4.3/§4.5): budgets, the T8 invariant, routing ---

test("T8: every family's default budget meets (H_max / interval) x worst-case tick x 1.25, against the LIVE collector caps the daemon path passes", async () => {
  const { DEFAULT_SERVICE_CENSUS_CEILING } = await import("../src/tools/services.js");
  const { MAX_LINEAGE_EDGES_PER_TICK } = await import("../src/tools/processes.js");
  const { MAX_JOB_LIMIT } = await import("../src/tools/scheduled-jobs.js");
  const { MAX_SESSION_ENTITY_LIMIT, DEFAULT_SESSION_ENTITY_LIMIT } = await import("../src/tools/sessions.js");
  const { MAX_PEER_ENTITY_LIMIT, DEFAULT_PEER_ENTITY_LIMIT } = await import("../src/tools/vpn-peer-status.js");
  const { MAX_TAILSCALE_PEER_ENTITY_LIMIT, DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT } = await import("../src/tools/tailscale-status.js");
  const { MAX_CANARIES } = await import("../src/tools/canary.js");
  // The pinned entity cap per family must equal the live collector constant: raising a collector
  // cap without revisiting the family budget fails HERE, not on a real host.
  const liveCaps = {
    service: DEFAULT_SERVICE_CENSUS_CEILING,
    process_lineage: MAX_LINEAGE_EDGES_PER_TICK,
    scheduled_job: MAX_JOB_LIMIT,
    session: MAX_SESSION_ENTITY_LIMIT,
    peer: MAX_PEER_ENTITY_LIMIT + MAX_TAILSCALE_PEER_ENTITY_LIMIT,
    canary: MAX_CANARIES,
  };
  // §2: the session/peer defaults are now also their clamps (no unbounded operator limit).
  assert.ok(DEFAULT_SESSION_ENTITY_LIMIT <= MAX_SESSION_ENTITY_LIMIT);
  assert.ok(DEFAULT_PEER_ENTITY_LIMIT <= MAX_PEER_ENTITY_LIMIT);
  assert.ok(DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT <= MAX_TAILSCALE_PEER_ENTITY_LIMIT);
  const pinnedWorst = { service: 291_251, process_lineage: 50_497, scheduled_job: 71_075, session: 67_130, peer: 157_733, canary: 100_447 };
  for (const [family, cap] of Object.entries(liveCaps)) {
    const shape = FAMILY_TICK_SHAPES.get(family);
    assert.equal(shape.entityCap, cap, `${family}: pinned entity cap must equal the live collector cap`);
    assert.equal(shape.worstTickBytes, cap * shape.maxRecordBytes + shape.markerBytes);
    assert.equal(shape.worstTickBytes, pinnedWorst[family], `${family}: worst-case tick must match §15.3`);
    const hMax = FAMILY_HORIZON_MAX_MS.get(family);
    assert.ok(hMax > 0, `${family} must carry a horizon`);
    const required = (hMax / HOUR) * shape.worstTickBytes * 1.25;
    assert.ok(FAMILY_DEFAULT_BUDGET_BYTES.get(family) >= required, `${family}: ${FAMILY_DEFAULT_BUDGET_BYTES.get(family)} < ${required}`);
    assert.equal(familyBudgetFloorBytes(family), Math.ceil(required));
  }
  // The accepted H_max per family (§15.4, Q2).
  assert.equal(FAMILY_HORIZON_MAX_MS.get("service"), 48 * HOUR);
  assert.equal(FAMILY_HORIZON_MAX_MS.get("process_lineage"), 6 * DAY);
  assert.equal(FAMILY_HORIZON_MAX_MS.get("scheduled_job"), 48 * HOUR);
  assert.equal(FAMILY_HORIZON_MAX_MS.get("session"), 30 * HOUR);
  assert.equal(FAMILY_HORIZON_MAX_MS.get("peer"), 72 * HOUR);
  assert.equal(FAMILY_HORIZON_MAX_MS.get("canary"), 6 * HOUR);
  // The S0-revised defaults (65 MiB in total).
  const MIB = 1024 * 1024;
  assert.deepEqual(Object.fromEntries(FAMILY_DEFAULT_BUDGET_BYTES), {
    service: 18 * MIB, process_lineage: 10 * MIB, scheduled_job: 5 * MIB, session: 4 * MIB,
    peer: 16 * MIB, canary: 4 * MIB, network: 4 * MIB, provenance: 4 * MIB,
    // Context families (C0; context plan §4): 17 MiB, sized by the data-family T8 test below.
    host_lifecycle: 7 * MIB, network_context: 13 * MIB, session_context: 21 * MIB,
    // Context plan C2 families, sized by their own T8 tests (context-c2-*.test.js).
    collector_state: 8 * MIB, context_stats: 2 * MIB, tick_summary: 3 * MIB,
  });
  assert.equal([...FAMILY_DEFAULT_BUDGET_BYTES.values()].reduce((a, b) => a + b, 0), 119 * MIB);
});

test("T8 config floor: resolveFactStoreBudgets rejects a value below the horizon invariant (budget_below_horizon_floor) and falls back to the default; accepts one at or above it", () => {
  const floor = familyBudgetFloorBytes("service");
  const below = resolveFactStoreBudgets({ service: floor - 1 });
  assert.equal(below.budgets.service, FAMILY_DEFAULT_BUDGET_BYTES.get("service"));
  assert.deepEqual(below.rejected.service, { reason: "budget_below_horizon_floor", configured_bytes: floor - 1, floor_bytes: floor });
  const at = resolveFactStoreBudgets({ service: floor });
  assert.equal(at.budgets.service, floor);
  assert.equal(at.source.service, "configured");
  assert.equal(at.rejected.service, undefined);
  const raised = resolveFactStoreBudgets({ peer: 64 * 1024 * 1024 });
  assert.equal(raised.budgets.peer, 64 * 1024 * 1024);
  // One worst-case tick is NOT enough (the pre-review rule): it would leave the family horizon-short.
  const oneTick = resolveFactStoreBudgets({ session: FAMILY_TICK_SHAPES.get("session").worstTickBytes * 2 });
  assert.equal(oneTick.rejected.session.reason, "budget_below_horizon_floor");
  for (const bad of [Number.NaN, Infinity, -1, 0, 1.5, "20000000", null]) {
    const result = resolveFactStoreBudgets({ canary: bad });
    assert.equal(result.budgets.canary, FAMILY_DEFAULT_BUDGET_BYTES.get("canary"));
    assert.equal(result.rejected.canary.reason, "invalid");
  }
  // network/provenance carry no rule horizon: their floor is the default, so only raising is accepted.
  assert.equal(familyBudgetFloorBytes("network"), FAMILY_DEFAULT_BUDGET_BYTES.get("network"));
  assert.equal(resolveFactStoreBudgets({ network: 1024 }).rejected.network.reason, "budget_below_horizon_floor");
  // Unknown keys are ignored and reported, never turned into a family.
  const unknown = resolveFactStoreBudgets({ "../etc": 99 * 1024 * 1024 });
  assert.deepEqual(unknown.unknown_families, ["../etc"]);
  assert.deepEqual(Object.keys(unknown.budgets).sort(), [...FACT_FAMILY_IDS].sort());
  // Missing/garbage map -> every default.
  for (const value of [undefined, null, [], "x"]) assert.deepEqual(resolveFactStoreBudgets(value).budgets, Object.fromEntries(FAMILY_DEFAULT_BUDGET_BYTES));
});

// G2 L3: the T8 invariant counts TICKS, so it depends on the structural interval, which is
// operator-settable. Below 1 h more ticks fit in a horizon and the floor scales up; above 1 h it is
// held at the 1 h figure (never loosened).
test("G2 L3: the T8 floor is computed at the structural interval -- scaled up below 1 h, never below the 1 h figure", () => {
  const MIN = 60 * 1000;
  for (const family of FAMILY_HORIZON_MAX_MS.keys()) {
    const hourly = familyBudgetFloorBytes(family);
    assert.equal(familyBudgetFloorBytes(family, { structuralIntervalMs: HOUR }), hourly);
    assert.equal(familyBudgetFloorBytes(family, { structuralIntervalMs: 15 * MIN }), Math.ceil((FAMILY_HORIZON_MAX_MS.get(family) / (15 * MIN)) * FAMILY_TICK_SHAPES.get(family).worstTickBytes * 1.25));
    assert.ok(familyBudgetFloorBytes(family, { structuralIntervalMs: 15 * MIN }) > hourly);
    assert.equal(familyBudgetFloorBytes(family, { structuralIntervalMs: 2 * HOUR }), hourly, "a slower interval never lowers the floor");
    for (const bad of [0, -1, Number.NaN, Infinity, "60000"]) assert.equal(familyBudgetFloorBytes(family, { structuralIntervalMs: bad }), hourly);
  }
  // The reviewer's case: a 15-minute interval leaves the default peer budget below the invariant
  // (~106 worst-case ticks, ~26 h, under the 30 h count-rule horizon and the 72 h correlation one).
  assert.ok(FAMILY_DEFAULT_BUDGET_BYTES.get("peer") < familyBudgetFloorBytes("peer", { structuralIntervalMs: 15 * MIN }));
  // network/provenance have no horizon: their floor stays the default at any interval.
  assert.equal(familyBudgetFloorBytes("network", { structuralIntervalMs: MIN }), FAMILY_DEFAULT_BUDGET_BYTES.get("network"));
});

test("G2 MEDIUM: default budgets auto-scale to a supported structural interval, while the 4x ceiling remains a hard bound", () => {
  const interval = 15 * 60 * 1000;
  const resolved = resolveFactStoreBudgets(undefined, { structuralIntervalMs: interval });
  for (const family of FAMILY_HORIZON_MAX_MS.keys()) {
    const expected = Math.min(
      familyBudgetCeilingBytes(family),
      Math.max(FAMILY_DEFAULT_BUDGET_BYTES.get(family), familyBudgetFloorBytes(family, { structuralIntervalMs: interval })),
    );
    assert.equal(resolved.budgets[family], expected, `${family} default scales to its 15-minute floor when needed`);
    assert.ok(resolved.budgets[family] <= familyBudgetCeilingBytes(family), `${family} stays below its ceiling`);
    assert.equal(resolved.rejected[family], undefined);
  }
  assert.equal(resolved.budgets.network, FAMILY_DEFAULT_BUDGET_BYTES.get("network"));
  assert.equal(resolved.budgets.provenance, FAMILY_DEFAULT_BUDGET_BYTES.get("provenance"));
});

// G2 L4: a configured budget has an upper bound -- the file, and its whole-file reads every fast tick,
// stay bounded (T9 is modelled at the defaults; read cost scales linearly up to this ceiling).
test("G2 L4: a configured budget above the per-family ceiling (4x the default) is clamped to it and reported as budget_above_ceiling", () => {
  for (const family of FACT_FAMILY_IDS) {
    const ceiling = familyBudgetCeilingBytes(family);
    assert.equal(ceiling, 4 * FAMILY_DEFAULT_BUDGET_BYTES.get(family));
    const huge = resolveFactStoreBudgets({ [family]: 1e12 });
    assert.equal(huge.budgets[family], ceiling);
    assert.equal(huge.source[family], "configured");
    assert.deepEqual(huge.clamped[family], { reason: "budget_above_ceiling", configured_bytes: 1e12, ceiling_bytes: ceiling });
    assert.equal(huge.rejected[family], undefined);
    const atCeiling = resolveFactStoreBudgets({ [family]: ceiling });
    assert.equal(atCeiling.budgets[family], ceiling);
    assert.equal(atCeiling.clamped[family], undefined);
  }
  // Coherence with L3: the ceiling admits a budget that restores the invariant down to a 15-minute
  // structural interval for every family with a horizon.
  for (const family of FAMILY_HORIZON_MAX_MS.keys()) {
    assert.ok(familyBudgetCeilingBytes(family) >= familyBudgetFloorBytes(family, { structuralIntervalMs: 15 * 60 * 1000 }), family);
  }
  assert.deepEqual(resolveFactStoreBudgets(undefined).clamped, {});
});

test("T12 routing: groupFactPointsByFamily routes by fact_name and THROWS on an unregistered name (whole batch, before anything is returned)", () => {
  const grouped = groupFactPointsByFamily([
    { fact_name: "service.presence", entity_key: "a" },
    { fact_name: "network.listening_port.owner", entity_key: "b" },
    { fact_name: "service.census", entity_key: "c" },
  ]);
  assert.deepEqual([...grouped.keys()], ["service", "network"]);
  assert.equal(grouped.get("service").length, 2);
  assert.throws(() => groupFactPointsByFamily([{ fact_name: "service.presence", entity_key: "a" }, { fact_name: "peer.seen", entity_key: "b" }]), /unregistered fact_name/);
  assert.throws(() => groupFactPointsByFamily([{ entity_key: "b" }]), /unregistered fact_name/);
  assert.equal(groupFactPointsByFamily([]).size, 0);
});

test("T12 routing: requireFactFamily throws on a missing or unknown family", () => {
  assert.equal(requireFactFamily("peer"), "peer");
  for (const bad of [undefined, null, "", "facts", "../service", "seen-sets", 7]) assert.throws(() => requireFactFamily(bad), /fact family/);
});

test("T12 routing: every fact_name each translator can emit is registered (source scan of the translators + the real-volume tick)", async () => {
  const { readFile } = await import("node:fs/promises");
  const here = path.dirname(new URL(import.meta.url).pathname);
  const emitted = new Set();
  for (const file of ["../src/fact-translators.js", "../src/tools/provenance-warnings.js"]) {
    const source = await readFile(path.join(here, file), "latin1");
    const constants = new Map([...source.matchAll(/const\s+([A-Z_][A-Z0-9_]*)\s*=\s*"([^"]+)"/g)].map((m) => [m[1], m[2]]));
    for (const match of source.matchAll(/fact_name:\s*(?:"([^"]+)"|([A-Z_][A-Z0-9_]*))/g)) {
      const name = match[1] ?? constants.get(match[2]);
      assert.ok(name, `unresolved fact_name expression ${match[0]} in ${file}`);
      emitted.add(name);
    }
  }
  assert.ok(emitted.size >= 12, `expected every translator fact_name, scanned ${[...emitted]}`);
  for (const name of emitted) assert.ok(FACT_FAMILY_BY_NAME.has(name), `translator fact_name ${name} is not registered`);
  // And by running the real translators over a generated real-volume tick.
  const { realVolumeStructuralCollectors } = await import("./fixtures/real-volume-tick.js");
  const translators = await import("../src/fact-translators.js");
  const { collectors } = realVolumeStructuralCollectors({ scale: 0.05 });
  const evidence = await Promise.all(Object.values(collectors).map((collect) => collect()));
  const ts = "2026-10-05T00:00:00.000Z";
  const points = [
    ...translators.factPointsFromServiceEvidence(evidence, { ts }),
    ...translators.factPointsFromNetworkEvidence(evidence, { ts }),
    ...translators.factPointsFromSessionEvidence(evidence, { ts }),
    ...translators.factPointsFromVpnPeerEvidence(evidence, { ts }),
    ...translators.factPointsFromTailscaleStatusEvidence(evidence, { ts }),
    ...translators.factPointsFromProcessLineageEvidence(evidence, { ts }),
    ...translators.factPointsFromScheduledJobsEvidence(evidence, { ts }),
    ...translators.factPointsFromCanaryEvidence(evidence, { ts }),
  ];
  assert.ok(points.length > 0);
  assert.doesNotThrow(() => groupFactPointsByFamily(points));
});

// --- Context plan C0 (docs/plans/2026-10-06-context-aware-learned-baselines.md §4): data families ---

test("C0 data-family T8: each context family's budget holds its 30-day data horizon at the schema-derived worst-case tick x 1.25, without raising the minimum structural interval", async () => {
  const { DATA_FAMILY_HORIZONS, MIN_STRUCTURAL_INTERVAL_MS } = await import("../src/fact-families.js");
  const { CONTEXT_FACT_SCHEMAS } = await import("../src/context-schemas.js");
  const { normalizeFactPoint } = await import("../src/fact-store.js");
  const { MAX_LOGIN_ARRIVALS_PER_TICK, MAX_LOGIN_HISTORY_ROWS_PER_TICK, MAX_VPN_SERVICE_STATES_PER_TICK, MAX_LIFECYCLE_RECORDS_PER_TICK, MAX_SESSION_ATTACHMENTS_PER_TICK, CONTEXT_ENVELOPE_SOURCES } = await import("../src/context-translators.js");
  const { MAX_TRANSITIONS_PER_TICK, MAX_CREATED_VS_BOOT_PER_TICK } = await import("../src/context-summary.js");
  // Worst-case normalized record per context fact, from its closed schema: every field at its longest
  // valid value, the longest envelope id/tool, a digest-suffixed entity key, confidence 0.
  const longestSource = Object.values(CONTEXT_ENVELOPE_SOURCES).reduce((a, b) => (a.id.length + a.tool.length >= b.id.length + b.tool.length ? a : b));
  const worst = {};
  for (const [factName, schema] of CONTEXT_FACT_SCHEMAS) {
    const attributes = {};
    for (const [field, spec] of Object.entries(schema.fields)) {
      const candidates = spec.kind === "enum" ? [...spec.values] : [...spec.sentinels];
      if (spec.kind === "hmac") candidates.push("f".repeat(16));
      if (spec.kind === "int") candidates.push(String(spec.max));
      if (spec.kind === "pattern") candidates.push("9".repeat(spec.maxLength));
      attributes[field] = candidates.sort((a, b) => b.length - a.length)[0];
    }
    // The per-field maxima are an UPPER BOUND, not necessarily one valid record (e.g. a pattern
    // field at its max length), and the store now enforces the context schema (C0 review L8): the
    // shape is normalized under a same-length placeholder name, then the real name is put back.
    const record = normalizeFactPoint({
      ts: "2026-10-11T00:00:00.000Z", fact_name: "x".repeat(factName.length), entity_key: `${factName}.${"f".repeat(16)}`, attributes,
      source_envelope_id: longestSource.id, source_tool: longestSource.tool, sensitivity: "operational", confidence: 0,
    });
    record.fact_name = factName;
    worst[factName] = Buffer.byteLength(`${JSON.stringify(record)}\n`);
  }
  assert.deepEqual(worst, {
    "host.boot": 698, "host.boot_boundary": 928, "host.clock_reading": 1147, "host.suspend": 581, "host.boundary_census": 613,
    "net.tailnet_state": 601, "net.config_fingerprint": 1029,
    "session.login_record": 643, "session.login_history_row": 597, "session.login_census": 777, "user.presence": 508,
    // C2 facts (their families' T8 are pinned in context-c2-*.test.js).
    "collector.binary_state": 668, "net.vpn_service_census": 614, "net.vpn_service_state": 528,
    "host.lifecycle_record": 721, "session.attachment_census": 608, "session.attachment": 573,
    "host.daemon_gap": 679, "context.transition": 699, "session.created_vs_boot": 623,
    // Derived records: an upper bound under this generic shape (a longest envelope source, a suffixed
    // entity key, confidence, rejected_field); their exact worst cases are pinned in
    // context-c2-summary.test.js (tick.summary 1,024 B <= 1 KiB plus its certificate sibling).
    "tick.summary": 1170, "tick.summary_certificate": 1109, "stats.episode": 669, "stats.daily": 684,
  }, "a schema change must revisit the pinned context tick shapes");
  assert.equal(FAMILY_TICK_SHAPES.get("collector_state").maxRecordBytes, worst["collector.binary_state"]);
  const tick = {
    host_lifecycle: worst["host.boot"] + worst["host.boot_boundary"] + worst["host.clock_reading"] + worst["host.suspend"] + worst["host.boundary_census"]
      + worst["host.daemon_gap"] + MAX_LIFECYCLE_RECORDS_PER_TICK * worst["host.lifecycle_record"],
    network_context: worst["net.tailnet_state"] + worst["net.config_fingerprint"] + worst["net.vpn_service_census"]
      + MAX_VPN_SERVICE_STATES_PER_TICK * worst["net.vpn_service_state"] + MAX_TRANSITIONS_PER_TICK * worst["context.transition"],
    session_context: worst["session.login_census"] + worst["user.presence"] + worst["session.attachment_census"]
      + (MAX_LOGIN_ARRIVALS_PER_TICK + MAX_LOGIN_HISTORY_ROWS_PER_TICK) * Math.max(worst["session.login_record"], worst["session.login_history_row"])
      + MAX_SESSION_ATTACHMENTS_PER_TICK * worst["session.attachment"] + MAX_CREATED_VS_BOOT_PER_TICK * worst["session.created_vs_boot"],
  };
  for (const family of ["host_lifecycle", "network_context", "session_context"]) {
    assert.equal(DATA_FAMILY_HORIZONS.get(family), 30 * DAY, `${family} declares the 30-day raw retention as its data horizon`);
    assert.equal(FAMILY_HORIZON_MAX_MS.get(family), 30 * DAY);
    assert.ok(FAMILY_TICK_SHAPES.get(family).worstTickBytes >= tick[family], `${family}: pinned ${FAMILY_TICK_SHAPES.get(family).worstTickBytes} < schema worst ${tick[family]}`);
    const required = (30 * 24) * FAMILY_TICK_SHAPES.get(family).worstTickBytes * 1.25;
    assert.ok(FAMILY_DEFAULT_BUDGET_BYTES.get(family) >= required, `${family}: ${FAMILY_DEFAULT_BUDGET_BYTES.get(family)} < ${required}`);
    assert.equal(familyBudgetFloorBytes(family), Math.ceil(required));
    assert.ok(familyBudgetCeilingBytes(family) >= familyBudgetFloorBytes(family, { structuralIntervalMs: 15 * 60 * 1000 }));
  }
  // The context families must not tighten the shortest supported structural interval (service sets it).
  assert.equal(MIN_STRUCTURAL_INTERVAL_MS, 833_276);
  assert.ok(!RULE_HORIZONS.has("host.boot") && [...RULE_HORIZONS.values()].every((rule) => rule.families.every((f) => !DATA_FAMILY_HORIZONS.has(f))));
});

test("C0.6: every context schema's family is the registry family of its fact_name, and every context fact is registered", async () => {
  const { CONTEXT_FACT_SCHEMAS } = await import("../src/context-schemas.js");
  for (const [factName, schema] of CONTEXT_FACT_SCHEMAS) assert.equal(FACT_FAMILY_BY_NAME.get(factName), schema.family, factName);
  for (const [factName, family] of FACT_FAMILY_BY_NAME) {
    if (["host_lifecycle", "network_context", "session_context"].includes(family)) assert.ok(CONTEXT_FACT_SCHEMAS.has(factName), `${factName} has no closed schema`);
  }
});
