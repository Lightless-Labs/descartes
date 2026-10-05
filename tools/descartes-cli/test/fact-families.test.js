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
    await appendFactPoints(evicted, points, { now: ts, maxBytes: 1200 });
    await appendFactPoints(reference, points, { now: ts, maxBytes: 10 * 1024 * 1024 });
  }
  let passes = 0;
  for (const windowMs of [HOUR, 2 * HOUR, 3 * HOUR, 5 * HOUR, 8 * HOUR, 11 * HOUR, 30 * DAY]) {
    const readOptions = { windowMs, now: iso(nowMs) };
    const narrowed = await readFactPoints(evicted, readOptions);
    const full = await readFactPoints(reference, readOptions);
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
    await appendFactPoints(paths, [servicePoint(ts, "svc-a"), servicePoint(ts, "svc-b")], { now: ts, maxBytes });
    await enforceFactRetention(paths, { now: ts, maxBytes });
    const read = await readFactPoints(paths, { windowMs: 31 * DAY, now: ts });
    assert.deepEqual(read.points, []);
    assert.equal(read.completeness.coverage, "narrowed");
    assert.equal(certifiedHorizonOk(read, { nowMs: Date.parse(ts), horizonMs: HOUR }), false);
  }
});
