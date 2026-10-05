// R0b: the fact-store coverage contract (docs/plans/2026-10-05-fact-store-capacity-and-sliding-
// anchor.md §4.1, §6 I1-I3/I8/I10, §8 T3-T6). Byte-cap eviction is suffix-preserving and
// tick-aligned, so it narrows coverage instead of breaking it; the ledger records an exclusive
// floor (`bytecap_floor_ts`), and readFactPoints never returns a point at or below it.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { appendFactPoints, enforceFactRetention, FUTURE_FACT_TOLERANCE_MS, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import {
  FACT_INTEGRITY_SCHEMA_VERSION,
  isValidFactIntegrityLedger,
  readFactIntegrityLedger,
  resolveFactIntegrityPaths,
} from "../src/fact-store-integrity.js";
import {
  factPointsFromServiceEvidence,
  factPointsFromSessionEvidence,
  factPointsFromTailscaleStatusEvidence,
  factPointsFromVpnPeerEvidence,
} from "../src/fact-translators.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-coverage-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const HOUR_MS = 60 * 60 * 1000;
const BASE_MS = Date.parse("2026-10-01T00:00:00.000Z");
const hour = (index) => new Date(BASE_MS + index * HOUR_MS).toISOString();
const lineBytes = (point) => Buffer.byteLength(`${JSON.stringify(point)}\n`);

function envelope(id, tool, result, status = "ok") {
  return { id, status, layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: hour(0) } };
}

// Real per-family record order, produced by the REAL translators (§4.1 "Why the boundary must be
// strict"): service = presence..., census LAST; session = presence..., census, overflow; peer = VPN
// presence..., VPN census, VPN overflow, then the Tailscale presence..., Tailscale overflow
// (concatenated in that order by daemon.js:1024-1028).
function serviceTick(ts) {
  return factPointsFromServiceEvidence([envelope("services", "collect_services", {
    manager: "systemd",
    services_census: ["alpha.service", "beta.service", "gamma.service", "delta.service"].map((name) => ({ name, running: true })),
    truncated: false,
  })], { ts });
}

function sessionTick(ts) {
  return factPointsFromSessionEvidence([envelope("sessions", "collect_sessions", {
    multiplexers: [{ multiplexer: "tmux", status: "ok" }],
    total_count: 205,
    sessions: ["one", "two", "three"].map((name, index) => ({ multiplexer: "tmux", session_name: name, attached: false, window_count: 1, created_at_epoch_seconds: 1_700_000_000 + index })),
    truncated: true,
    cap: 200,
  })], { ts });
}

function peerTick(ts) {
  const vpn = factPointsFromVpnPeerEvidence([envelope("vpn-peer-status", "collect_vpn_peer_status", {
    sources: { ssh_who: { status: "ok" }, ssh_last: { status: "ok" }, wireguard: { status: "ok" }, vpn_services: { status: "ok" }, established_inbound: { status: "ok" } },
    total_count: 205,
    peers: ["alice", "bob", "carol"].map((user) => ({ source_type: "ssh", presence_state: "observed_active", remote_user: user, remote_host: "203.0.113.5" })),
    truncated: true,
  })], { ts });
  const tailscale = factPointsFromTailscaleStatusEvidence([envelope("tailscale-status", "collect_tailscale_status", {
    total_count: 205,
    peers: ["k1", "k2"].map((key) => ({ source_type: "tailscale", presence_state: "observed_active", node_public_key: `${key}-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDE=`, latest_handshake_epoch_seconds: 0 })),
    truncated: true,
  })], { ts });
  return [...vpn, ...tailscale];
}

function groupByTs(points) {
  const groups = new Map();
  for (const point of points) {
    const key = new Date(point.ts).toISOString();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(`${point.fact_name}|${point.entity_key}`);
  }
  for (const list of groups.values()) list.sort();
  return groups;
}

// ---------------------------------------------------------------------------------------------
// T3: a split tick is never readable. For each real per-family order, size the cap so the PRE-R0b
// newest-first suffix loop keeps all of the newest tick plus the TAIL of the oldest tick (its
// census/overflow markers and some presence facts) while evicting the oldest tick's first presence
// facts -- a tick that would read "complete" but miss entities.
// ---------------------------------------------------------------------------------------------

for (const [family, buildTick] of [["service", serviceTick], ["session", sessionTick], ["peer", peerTick]]) {
  test(`T3 (${family}): byte-cap eviction is tick-aligned in the real record order -- no partial tick survives`, async () => {
    const paths = await tempPaths();
    const older = buildTick(hour(0));
    const newer = buildTick(hour(1));
    // Keep everything from the newer tick + all but the FIRST record of the older tick.
    const cap = [...newer, ...older.slice(1)].reduce((sum, point) => sum + lineBytes(point), 0) + 1;
    await appendFactPoints(paths, older, { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
    await appendFactPoints(paths, newer, { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
    const retention = await enforceFactRetention(paths, { now: hour(1), maxBytes: cap });

    // The whole older tick is evicted (tick alignment), not just its first record.
    assert.equal(retention.bytecap_evicted_count, older.length, "tick-aligned: the entire split tick is evicted");
    assert.equal(retention.kept_count, newer.length);
    const raw = (await fs.readFile(resolveFactStorePaths(paths).factsFile, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(raw.some((record) => record.ts === hour(0)), false, "no record of the split tick is physically kept");

    const read = await readFactPoints(paths, { now: hour(1) });
    const groups = groupByTs(read.points);
    assert.deepEqual([...groups.keys()], [hour(1)]);
    assert.deepEqual(groups.get(hour(1)), groupByTs(newer.map((point) => ({ ...point }))).get(hour(1)));
  });
}

// ---------------------------------------------------------------------------------------------
// T5: assertions and edge cases (eviction half; the ledger half lives with the v2 ledger tests).
// ---------------------------------------------------------------------------------------------

test("T5: a non-suffix eviction (forced through the candidate-order seam) throws before anything is written", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [...serviceTick(hour(0)), ...serviceTick(hour(1)), ...serviceTick(hour(2))], { now: hour(2), maxBytes: Number.MAX_SAFE_INTEGER });
  const before = await fs.readFile(resolveFactStorePaths(paths).factsFile);
  const oneTick = serviceTick(hour(2)).reduce((sum, point) => sum + lineBytes(point), 0);
  await assert.rejects(
    () => enforceFactRetention(paths, {
      now: hour(2),
      maxBytes: oneTick,
      // Stub the sort: newest-first, so the newest-first keep loop would keep the OLDEST tick.
      orderRetentionCandidates: (candidates) => [...candidates].reverse(),
    }),
    /suffix/,
  );
  const after = await fs.readFile(resolveFactStorePaths(paths).factsFile);
  assert.deepEqual(after, before, "a refused pass must not rewrite the store");
});

test("T5: the accounting sum holds with tick-aligned eviction counted as byte-cap", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2, 3].map((index) => serviceTick(hour(index)));
  await appendFactPoints(paths, ticks.flat(), { now: hour(3), maxBytes: Number.MAX_SAFE_INTEGER });
  // Room for 2.5 ticks: tick alignment must drop the half tick too.
  const tickBytes = ticks[0].reduce((sum, point) => sum + lineBytes(point), 0);
  const retention = await enforceFactRetention(paths, { now: hour(3), maxBytes: Math.floor(tickBytes * 2.5) });
  assert.equal(retention.kept_count, ticks[0].length * 2);
  assert.equal(retention.bytecap_evicted_count, ticks[0].length * 2);
  assert.equal(retention.kept_count + retention.age_evicted_count + retention.bytecap_evicted_count + retention.future_fact_dropped_count, ticks.flat().length);
});

// ---------------------------------------------------------------------------------------------
// Ledger v2: bytecap_floor_ts (§4.1 item 2, I2, I8, T5 ledger half, T6).
// ---------------------------------------------------------------------------------------------

const tickBytes = (tick) => tick.reduce((sum, point) => sum + lineBytes(point), 0);

async function readRawLedger(paths) {
  return JSON.parse(await fs.readFile(resolveFactIntegrityPaths(paths).integrityFile, "utf8"));
}

async function writeRawLedger(paths, ledger) {
  await fs.writeFile(resolveFactIntegrityPaths(paths).integrityFile, `${JSON.stringify(ledger, null, 2)}\n`);
}

// Appends `count` hourly service ticks (hour(0)..hour(count-1)), each through appendFactPoints
// with the given cap, as the daemon does.
async function appendHourlyTicks(paths, { from = 0, count, maxBytes }) {
  const results = [];
  for (let index = from; index < from + count; index += 1) {
    results.push(await appendFactPoints(paths, serviceTick(hour(index)), { now: hour(index), maxBytes }));
  }
  return results;
}

test("T5: a new ledger is schema v2 with bytecap_floor_ts null; total > 0 <=> floor !== null is validated", async () => {
  const paths = await tempPaths();
  await appendHourlyTicks(paths, { count: 2, maxBytes: Number.MAX_SAFE_INTEGER });
  const ledger = await readRawLedger(paths);
  assert.equal(FACT_INTEGRITY_SCHEMA_VERSION, 2);
  assert.equal(ledger.schema_version, 2);
  assert.equal(ledger.bytecap_floor_ts, null);
  assert.equal(isValidFactIntegrityLedger(ledger), true);
  assert.equal(isValidFactIntegrityLedger({ ...ledger, bytecap_floor_ts: hour(0) }), false, "floor set while nothing was ever byte-evicted");
  assert.equal(isValidFactIntegrityLedger({ ...ledger, bytecap_evicted_total: 3, last_bytecap_evict_ts: hour(1) }), false, "evictions recorded with no floor");
  const { bytecap_floor_ts: _omitted, ...withoutFloor } = ledger;
  assert.equal(isValidFactIntegrityLedger(withoutFloor), false, "the floor key is required in v2");
  assert.equal(isValidFactIntegrityLedger({ ...ledger, bytecap_floor_ts: "garbage" }), false);
});

test("T5: the floor is the newest evicted ts, is exclusive (every kept record is strictly newer), and never decreases across passes (I2)", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 3;
  await appendHourlyTicks(paths, { count: 3, maxBytes: cap });
  assert.equal((await readRawLedger(paths)).bytecap_floor_ts, null, "nothing evicted yet");
  let previousFloorMs = Number.NEGATIVE_INFINITY;
  for (let index = 3; index < 9; index += 1) {
    await appendFactPoints(paths, serviceTick(hour(index)), { now: hour(index), maxBytes: cap });
    const ledger = await readRawLedger(paths);
    assert.equal(ledger.bytecap_floor_ts, hour(index - 3), `after tick ${index} the floor is the newest evicted tick`);
    assert.ok(Date.parse(ledger.bytecap_floor_ts) >= previousFloorMs, "the floor never decreases");
    previousFloorMs = Date.parse(ledger.bytecap_floor_ts);
    const raw = (await fs.readFile(resolveFactStorePaths(paths).factsFile, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(raw.every((record) => Date.parse(record.ts) > previousFloorMs), "every kept record is strictly above the floor");
    assert.equal(isValidFactIntegrityLedger(ledger), true);
  }
  // A pass that evicts nothing (budget raised) keeps the floor.
  await enforceFactRetention(paths, { now: hour(9), maxBytes: Number.MAX_SAFE_INTEGER });
  assert.equal((await readRawLedger(paths)).bytecap_floor_ts, hour(5));
});

test("T5: maxBytes 0 and a single tick over the cap both leave an empty store with a set floor and a valid ledger", async () => {
  for (const maxBytes of [0, 50]) {
    const paths = await tempPaths();
    await appendFactPoints(paths, serviceTick(hour(0)), { now: hour(0), maxBytes: Number.MAX_SAFE_INTEGER });
    const retention = await enforceFactRetention(paths, { now: hour(0), maxBytes });
    assert.equal(retention.kept_count, 0, `maxBytes ${maxBytes}`);
    const ledger = await readRawLedger(paths);
    assert.equal(ledger.bytecap_floor_ts, hour(0), `maxBytes ${maxBytes}: floor = the evicted tick`);
    assert.equal(ledger.continuity.last_rewrite_record_count, 0);
    assert.equal(isValidFactIntegrityLedger(ledger), true);
  }
});

test("T5: floor plausibility -- a non-empty store's floor at or above last_rewrite_newest_ts makes the ledger invalid (forged floor rejected, not trusted)", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendHourlyTicks(paths, { count: 4, maxBytes: cap });
  const ledger = await readRawLedger(paths);
  assert.equal(ledger.continuity.last_rewrite_newest_ts, hour(3));
  assert.equal(isValidFactIntegrityLedger(ledger), true);
  assert.equal(isValidFactIntegrityLedger({ ...ledger, bytecap_floor_ts: hour(3) }), false, "floor equal to the newest kept record");
  assert.equal(isValidFactIntegrityLedger({ ...ledger, bytecap_floor_ts: "2027-01-01T00:00:00.000Z" }), false, "far-future forged floor");
  await writeRawLedger(paths, { ...ledger, bytecap_floor_ts: "2027-01-01T00:00:00.000Z" });
  assert.equal((await readFactIntegrityLedger(paths)).reason, "invalid");
  assert.notEqual((await readFactPoints(paths, { now: hour(3) })).completeness.status, "intact");
});

test("T5: crash between the ledger write and the rename, then retry, leaves the floor exactly where one clean pass would (idempotent)", async () => {
  for (const window of ["beforeFactsRename", "afterFactsRename"]) {
    const reference = await tempPaths();
    const crashed = await tempPaths();
    const cap = tickBytes(serviceTick(hour(0))) * 2;
    for (const paths of [reference, crashed]) await appendHourlyTicks(paths, { count: 3, maxBytes: Number.MAX_SAFE_INTEGER });
    await enforceFactRetention(reference, { now: hour(3), maxBytes: cap });
    await assert.rejects(() => enforceFactRetention(crashed, { now: hour(3), maxBytes: cap, [window]: async () => { throw new Error("simulated crash"); } }), /simulated crash/);
    await enforceFactRetention(crashed, { now: hour(3), maxBytes: cap });
    const [ref, got] = [await readRawLedger(reference), await readRawLedger(crashed)];
    assert.equal(got.bytecap_floor_ts, hour(0), window);
    assert.equal(got.bytecap_floor_ts, ref.bytecap_floor_ts, window);
    assert.equal(got.bytecap_evicted_total, ref.bytecap_evicted_total, `${window}: evictions counted once`);
  }
});

test("I2/MEDIUM-3: a floor more than FUTURE_FACT_TOLERANCE_MS ahead of the pass is clamped to the pass time AND an in-window loss is stamped in the same pass", async () => {
  // Clock N days fast, then corrected.
  const paths = await tempPaths();
  const fastMs = 5 * 24 * HOUR_MS;
  const fast = (index) => new Date(BASE_MS + fastMs + index * HOUR_MS).toISOString();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  for (let index = 0; index < 4; index += 1) {
    await appendFactPoints(paths, serviceTick(fast(index)), { now: fast(index), maxBytes: cap });
  }
  assert.equal((await readRawLedger(paths)).bytecap_floor_ts, fast(1));
  // Clock corrected: the real time is hour(4), five days before the floor.
  await appendFactPoints(paths, serviceTick(hour(4)), { now: hour(4), maxBytes: cap });
  const ledger = await readRawLedger(paths);
  assert.ok(Date.parse(ledger.bytecap_floor_ts) <= Date.parse(hour(4)) + FUTURE_FACT_TOLERANCE_MS, `floor ${ledger.bytecap_floor_ts} was not clamped`);
  assert.equal(ledger.last_continuity_break_ts, hour(4), "the backwards move of the floor must stamp a loss in the same pass");
  assert.equal(isValidFactIntegrityLedger(ledger), true);
  // The family reads degraded (never intact) while that loss is in the window...
  await enforceFactRetention(paths, { now: hour(5), maxBytes: cap });
  assert.equal((await readFactPoints(paths, { now: hour(5), windowMs: 31 * 24 * HOUR_MS })).completeness.status, "degraded");
  // ...and the blind is bounded: once the loss ages out of the 31-day window it reads intact again.
  const later = new Date(BASE_MS + 32 * 24 * HOUR_MS).toISOString();
  await appendFactPoints(paths, serviceTick(later), { now: later, maxBytes: cap });
  await enforceFactRetention(paths, { now: later, maxBytes: cap });
  assert.equal((await readFactPoints(paths, { now: later, windowMs: 31 * 24 * HOUR_MS })).completeness.status, "intact");
});

test("below-floor records (appended after a clock rollback) are evicted at the next pass instead of wedging the ledger's plausibility check", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendHourlyTicks(paths, { count: 4, maxBytes: cap });
  assert.equal((await readRawLedger(paths)).bytecap_floor_ts, hour(1));
  // Evict everything, then roll the clock back below the floor (within the future tolerance).
  await enforceFactRetention(paths, { now: hour(3), maxBytes: 0 });
  assert.equal((await readRawLedger(paths)).bytecap_floor_ts, hour(3));
  const rolledBack = new Date(BASE_MS + 2.5 * HOUR_MS).toISOString();
  const result = await appendFactPoints(paths, serviceTick(rolledBack), { now: rolledBack, maxBytes: cap });
  assert.equal(result.retention_error, undefined, "retention must not fail on a store whose records all sit below the floor");
  assert.equal(result.retention.kept_count, 0, "records at or below the floor are evicted");
  assert.equal(result.retention.bytecap_evicted_count, serviceTick(rolledBack).length);
  const ledger = await readRawLedger(paths);
  assert.equal(ledger.bytecap_floor_ts, hour(3), "the floor does not move backwards");
  assert.equal(isValidFactIntegrityLedger(ledger), true);
});

test("T6: a valid v1 ledger with no evictions upgrades to v2 (floor null) and reads intact -- never invalid, never a continuity break", async () => {
  const paths = await tempPaths();
  await appendHourlyTicks(paths, { count: 3, maxBytes: Number.MAX_SAFE_INTEGER });
  const v2 = await readRawLedger(paths);
  const { bytecap_floor_ts: _floor, ...v1 } = { ...v2, schema_version: 1 };
  await writeRawLedger(paths, v1);
  const read = await readFactIntegrityLedger(paths);
  assert.equal(read.reason, null);
  assert.equal(read.ledger.schema_version, 2);
  assert.equal(read.ledger.bytecap_floor_ts, null);
  assert.equal((await readFactPoints(paths, { now: hour(2) })).completeness.status, "intact");
  await appendFactPoints(paths, serviceTick(hour(3)), { now: hour(3), maxBytes: Number.MAX_SAFE_INTEGER });
  const after = await readRawLedger(paths);
  assert.equal(after.schema_version, 2);
  assert.equal(after.last_continuity_break_ts, null);
  assert.equal((await readFactPoints(paths, { now: hour(3) })).completeness.status, "intact");
});

test("T6 (Q3 = fresh per-family stores, so no M4 floor derivation): a v1 ledger that has byte-evicted is never certified -- it takes the continuity-break bootstrap, never a clean floor:null", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendHourlyTicks(paths, { count: 4, maxBytes: cap });
  const v2 = await readRawLedger(paths);
  assert.ok(v2.bytecap_evicted_total > 0);
  const { bytecap_floor_ts: _floor, ...v1 } = { ...v2, schema_version: 1 };
  await writeRawLedger(paths, v1);
  assert.equal((await readFactIntegrityLedger(paths)).reason, "invalid");
  assert.notEqual((await readFactPoints(paths, { now: hour(3) })).completeness.status, "intact");
  await appendFactPoints(paths, serviceTick(hour(4)), { now: hour(4), maxBytes: cap });
  await appendFactPoints(paths, serviceTick(hour(5)), { now: hour(5), maxBytes: cap });
  const ledger = await readRawLedger(paths);
  assert.equal(ledger.last_continuity_break_ts, hour(4), "lineage break stamped");
  assert.equal((await readFactPoints(paths, { now: hour(5) })).completeness.status, "degraded");
});

test("T6: an already-v2 ledger round-trips unchanged through read and a no-op-eviction pass", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendHourlyTicks(paths, { count: 4, maxBytes: cap });
  const before = await readRawLedger(paths);
  const read = await readFactIntegrityLedger(paths);
  assert.deepEqual(read.ledger, before);
});

test("T6/HIGH-1: a missing integrity.json over a surviving non-empty facts.jsonl stamps a continuity break and never reads intact", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendHourlyTicks(paths, { count: 4, maxBytes: cap });
  await fs.unlink(resolveFactIntegrityPaths(paths).integrityFile);
  await appendFactPoints(paths, serviceTick(hour(4)), { now: hour(4), maxBytes: cap });
  const ledger = await readRawLedger(paths);
  assert.equal(ledger.last_continuity_break_ts, hour(4));
  for (let index = 5; index < 8; index += 1) {
    await appendFactPoints(paths, serviceTick(hour(index)), { now: hour(index), maxBytes: cap });
    assert.notEqual((await readFactPoints(paths, { now: hour(index) })).completeness.status, "intact", `tick ${index}`);
  }
});

test("T6/HIGH-1: a missing ledger over an absent store (first run) bootstraps clean: unknown, then intact", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(hour(0)), { now: hour(0), maxBytes: Number.MAX_SAFE_INTEGER });
  assert.equal((await readRawLedger(paths)).last_continuity_break_ts, null);
  assert.equal((await readFactPoints(paths, { now: hour(0) })).completeness.status, "unknown");
  await appendFactPoints(paths, serviceTick(hour(1)), { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
  assert.equal((await readFactPoints(paths, { now: hour(1) })).completeness.status, "intact");
});

test("T6/HIGH-1: a missing ledger over an existing EMPTY store bootstraps clean", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, "");
  await appendFactPoints(paths, serviceTick(hour(0)), { now: hour(0), maxBytes: Number.MAX_SAFE_INTEGER });
  assert.equal((await readRawLedger(paths)).last_continuity_break_ts, null);
});

test("T6/HIGH-1: a crash between the very first append and the first retention pass reads as a lineage break, never a clean bootstrap", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  // The first append reached disk but its retention pass never ran (no ledger).
  await fs.writeFile(factsFile, serviceTick(hour(0)).map((point) => JSON.stringify(point)).join("\n") + "\n");
  await appendFactPoints(paths, serviceTick(hour(1)), { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
  assert.equal((await readRawLedger(paths)).last_continuity_break_ts, hour(1));
  // Direct retention over a ledger-less non-empty store is the same case.
  const direct = await tempPaths();
  await fs.mkdir(resolveFactStorePaths(direct).dir, { recursive: true });
  await fs.writeFile(resolveFactStorePaths(direct).factsFile, serviceTick(hour(0)).map((point) => JSON.stringify(point)).join("\n") + "\n");
  await enforceFactRetention(direct, { now: hour(0) });
  assert.equal((await readRawLedger(direct)).last_continuity_break_ts, hour(0));
});

// ---------------------------------------------------------------------------------------------
// Read side (§4.1 items 3, 5, 6; I1): the floor is enforced by the store, not by six detectors.
// ---------------------------------------------------------------------------------------------

const MONTH_WINDOW_MS = 31 * 24 * HOUR_MS;
const RETENTION_MS = 30 * 24 * HOUR_MS;

test("I1: readFactPoints never returns a point at or below bytecap_floor_ts, even one still physically present", async () => {
  const paths = await tempPaths();
  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendHourlyTicks(paths, { count: 4, maxBytes: cap });
  assert.equal((await readRawLedger(paths)).bytecap_floor_ts, hour(1));
  // A record below the floor appended WITHOUT a retention pass (rollback, before the next pass
  // evicts it physically): the read must still hide it.
  await fs.appendFile(resolveFactStorePaths(paths).factsFile, `${JSON.stringify(serviceTick(hour(1))[0])}\n${JSON.stringify(serviceTick(hour(0.5))[0])}\n`);
  const read = await readFactPoints(paths, { now: hour(3), windowMs: MONTH_WINDOW_MS });
  assert.ok(read.points.length > 0);
  assert.ok(read.points.every((point) => Date.parse(point.ts) > Date.parse(hour(1))), "no point at or below the floor");
  assert.deepEqual([...groupByTs(read.points).keys()], [hour(2), hour(3)]);
});

test("completeness reports the raw floor, certified_after_ts = max(floor, retention cutoff), oldest_certified_ts and coverage", async () => {
  const paths = await tempPaths();
  await appendHourlyTicks(paths, { count: 3, maxBytes: Number.MAX_SAFE_INTEGER });
  const full = (await readFactPoints(paths, { now: hour(2), windowMs: MONTH_WINDOW_MS })).completeness;
  assert.equal(full.bytecap_floor_ts, null);
  assert.equal(full.certified_after_ts, null);
  assert.equal(full.coverage, "full");
  assert.equal(full.oldest_certified_ts, hour(0));

  const cap = tickBytes(serviceTick(hour(0))) * 2;
  await appendFactPoints(paths, serviceTick(hour(3)), { now: hour(3), maxBytes: cap });
  const narrowed = (await readFactPoints(paths, { now: hour(3), windowMs: MONTH_WINDOW_MS })).completeness;
  assert.equal(narrowed.bytecap_floor_ts, hour(1));
  assert.equal(narrowed.certified_after_ts, hour(1));
  assert.equal(narrowed.coverage, "narrowed");
  assert.equal(narrowed.oldest_certified_ts, hour(2));

  // Once the floor is older than the retention cutoff, certified_after_ts reports the cutoff (the
  // range between the floor and now - 30 d has been age-evicted; reporting the floor would
  // over-claim). The raw floor is unchanged.
  const later = new Date(Date.parse(hour(1)) + RETENTION_MS + 5 * HOUR_MS).toISOString();
  const aged = (await readFactPoints(paths, { now: later, windowMs: MONTH_WINDOW_MS })).completeness;
  assert.equal(aged.bytecap_floor_ts, hour(1));
  assert.equal(aged.certified_after_ts, new Date(Date.parse(later) - RETENTION_MS).toISOString());
});

test("a zero-cap / all-evicted store reads intact with coverage narrowed and an empty certified span (G1 question: vs fail-closed unknown)", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(hour(0)), { now: hour(0), maxBytes: 0 });
  await appendFactPoints(paths, serviceTick(hour(1)), { now: hour(1), maxBytes: 0 });
  const read = await readFactPoints(paths, { now: hour(1), windowMs: MONTH_WINDOW_MS });
  assert.deepEqual(read.points, []);
  assert.equal(read.completeness.coverage, "narrowed");
  assert.equal(read.completeness.bytecap_floor_ts, hour(1));
  assert.equal(read.completeness.oldest_certified_ts, null);
});

test("a floor more than FUTURE_FACT_TOLERANCE_MS ahead of the read fails closed (status unknown, degraded_reason future_floor) -- the empty-store forged-floor bound", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(hour(0)), { now: hour(0), maxBytes: 0 });
  await enforceFactRetention(paths, { now: hour(0), maxBytes: 0 });
  const ledger = await readRawLedger(paths);
  assert.equal(ledger.continuity.last_rewrite_record_count, 0);
  const forged = { ...ledger, bytecap_floor_ts: "2030-01-01T00:00:00.000Z" };
  assert.equal(isValidFactIntegrityLedger(forged), true, "an empty store has no in-ledger plausibility referent");
  await writeRawLedger(paths, forged);
  const read = await readFactPoints(paths, { now: hour(1), windowMs: MONTH_WINDOW_MS });
  assert.equal(read.completeness.status, "unknown");
  assert.equal(read.completeness.degraded_reason, "future_floor");
  // ...and the next pass clamps it with a loss stamp (MEDIUM-3), never certifying anything.
  await appendFactPoints(paths, serviceTick(hour(1)), { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
  const after = await readRawLedger(paths);
  assert.equal(after.last_continuity_break_ts, hour(1));
  assert.ok(Date.parse(after.bytecap_floor_ts) <= Date.parse(hour(1)));
  assert.notEqual((await readFactPoints(paths, { now: hour(1), windowMs: MONTH_WINDOW_MS })).completeness.status, "intact");
});

test("F2-Tier1 fold-in: continuity.oldest_ts is not a coverage boundary -- completeness reports certified fields instead, and no trust path reads oldest_ts", async () => {
  const paths = await tempPaths();
  await appendHourlyTicks(paths, { count: 2, maxBytes: Number.MAX_SAFE_INTEGER });
  const read = await readFactPoints(paths, { now: hour(1), windowMs: MONTH_WINDOW_MS });
  assert.equal("continuity_oldest_ts" in read.completeness, false);
  for (const field of ["bytecap_floor_ts", "certified_after_ts", "oldest_certified_ts", "coverage"]) {
    assert.ok(field in read.completeness, `${field} missing`);
  }
  const srcDir = new URL("../src/", import.meta.url);
  const files = (await fs.readdir(srcDir, { recursive: true })).filter((name) => name.endsWith(".js"));
  for (const name of files) {
    const source = await fs.readFile(new URL(name, srcDir), "latin1");
    if (name === "fact-store-integrity.js") continue; // the writer of continuity.oldest_ts
    assert.equal(/continuity(?:\?)?\.oldest_ts|continuity_oldest_ts/.test(source.replace(/\/\/.*$/gm, "")), false, `${name} reads continuity.oldest_ts outside the ledger writer`);
  }
});

// ---------------------------------------------------------------------------------------------
// T4: coverage oracle. Seeded sequences of store operations against a reference model of what was
// appended per ts. After every operation:
//   - I1: every returned point is strictly above the reported floor;
//   - when status is intact: every returned ts group equals the full appended set for that ts (no
//     partial ticks), and every appended, not-future-dropped ts above the floor and inside the read
//     window IS returned (claimed is a subset of justified);
//   - the floor never decreases, OR the read is not intact (an in-window loss was stamped);
//   - certified_after_ts is never older than the floor.
// ---------------------------------------------------------------------------------------------

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function oracleTick(ts, count, salt) {
  return Array.from({ length: count }, (_, index) => ({
    ts,
    fact_name: "service.presence",
    entity_key: `svc-${salt}-${index}`,
    attributes: { running: "true", manager: "systemd" },
  })).concat([{ ts, fact_name: "service.census", entity_key: "service.census-marker.v1", attributes: { census_state: "complete" }, confidence: 0 }]);
}

const ORACLE_OPS = [
  ["append", 30], ["oversize", 3], ["budget", 6], ["corrupt", 1], ["schemaInvalid", 1], ["future", 3],
  ["rollback", 4], ["fastThenCorrected", 1], ["crash", 3], ["ledgerDelete", 1], ["forgeFloor", 1], ["truncate", 1], ["noopPass", 4],
];

function pickOp(random) {
  const total = ORACLE_OPS.reduce((sum, [, weight]) => sum + weight, 0);
  let roll = random() * total;
  for (const [name, weight] of ORACLE_OPS) {
    roll -= weight;
    if (roll < 0) return name;
  }
  return "append";
}

test("T4: coverage oracle over seeded operation sequences", { timeout: 120_000 }, async () => {
  const unitTick = tickBytes(oracleTick(hour(0), 4, "x"));
  let checkedIntactReads = 0;
  for (let seed = 1; seed <= 30; seed += 1) {
    const random = mulberry32(seed);
    const paths = await tempPaths();
    const { dir: factsDir, factsFile } = resolveFactStorePaths(paths);
    await fs.mkdir(factsDir, { recursive: true });
    const model = new Map(); // ts -> { keys: sorted string[], alive: boolean }
    let nowMs = BASE_MS;
    let budget = Math.floor(unitTick * (1 + random() * 4));
    let previousFloorMs = Number.NEGATIVE_INFINITY;
    let currentGeneration;
    let salt = 0;
    const log = [];
    const appendTick = async (tsMs, count, cap = budget) => {
      salt += 1;
      const ts = new Date(tsMs + Math.floor(random() * 900) + 1).toISOString();
      const tick = oracleTick(ts, count, `${seed}-${salt}`);
      model.set(ts, { keys: tick.map((point) => `${point.fact_name}|${point.entity_key}`).sort(), alive: true });
      await appendFactPoints(paths, tick, { now: new Date(nowMs).toISOString(), maxBytes: cap });
      markFutureDropped();
    };
    const markFutureDropped = () => {
      for (const [ts, entry] of model) if (Date.parse(ts) > nowMs + FUTURE_FACT_TOLERANCE_MS) entry.alive = false;
    };
    for (let step = 0; step < 30; step += 1) {
      const op = pickOp(random);
      log.push(op);
      switch (op) {
        case "append": nowMs += HOUR_MS; await appendTick(nowMs, 1 + Math.floor(random() * 6)); break;
        case "oversize": nowMs += HOUR_MS; await appendTick(nowMs, 40); break;
        case "budget": budget = random() < 0.15 ? 0 : Math.floor(unitTick * (0.5 + random() * 5)); break;
        case "corrupt": await fs.appendFile(factsFile, "not-json\n"); break;
        case "schemaInvalid": await fs.appendFile(factsFile, `${JSON.stringify({ ts: new Date(nowMs).toISOString(), fact_name: "service.presence", attributes: {} })}\n`); break;
        case "future": await appendTick(nowMs + FUTURE_FACT_TOLERANCE_MS + HOUR_MS, 3); break;
        case "rollback": nowMs -= Math.floor(1 + random() * 4) * HOUR_MS; await appendTick(nowMs, 1 + Math.floor(random() * 4)); break;
        case "fastThenCorrected": {
          const realMs = nowMs;
          nowMs += 3 * 24 * HOUR_MS;
          await appendTick(nowMs, 3);
          nowMs += HOUR_MS;
          await appendTick(nowMs, 3, 0);
          nowMs = realMs + HOUR_MS;
          await appendTick(nowMs, 2);
          break;
        }
        case "crash": {
          nowMs += HOUR_MS;
          const hook = random() < 0.5 ? "beforeFactsRename" : "afterFactsRename";
          await enforceFactRetention(paths, { now: new Date(nowMs).toISOString(), maxBytes: budget, [hook]: async () => { throw new Error("crash"); } }).catch(() => {});
          break;
        }
        case "ledgerDelete": await fs.unlink(resolveFactIntegrityPaths(paths).integrityFile).catch(() => {}); break;
        case "forgeFloor": {
          const raw = await fs.readFile(resolveFactIntegrityPaths(paths).integrityFile, "utf8").catch(() => undefined);
          if (raw) await fs.writeFile(resolveFactIntegrityPaths(paths).integrityFile, JSON.stringify({ ...JSON.parse(raw), bytecap_floor_ts: "2030-01-01T00:00:00.000Z", bytecap_evicted_total: 1, last_bytecap_evict_ts: new Date(nowMs).toISOString() }));
          break;
        }
        case "truncate": {
          const lines = (await fs.readFile(factsFile, "utf8").catch(() => "")).split("\n").filter(Boolean);
          await fs.writeFile(factsFile, lines.slice(0, Math.floor(lines.length / 2)).map((line) => `${line}\n`).join(""));
          break;
        }
        case "noopPass": await enforceFactRetention(paths, { now: new Date(nowMs).toISOString(), maxBytes: budget }); markFutureDropped(); break;
        default: break;
      }

      // A new ledger lineage (generation change: a re-bootstrap) never carries trust over (I8). A
      // re-bootstrap over a NON-empty store stamps a loss (HIGH-1, pinned by the T6 tests and by the
      // floor-backwards check below); one over an empty store is a fresh store. Either way, ticks
      // appended before the new lineage began are no longer part of what it can justify.
      const generation = await fs.readFile(resolveFactIntegrityPaths(paths).integrityFile, "utf8")
        .then((raw) => JSON.parse(raw).generation, () => undefined);
      if (generation !== undefined && currentGeneration !== undefined && generation !== currentGeneration) {
        for (const entry of model.values()) entry.alive = false;
      }
      if (generation !== undefined) currentGeneration = generation;
      const read = await readFactPoints(paths, { now: nowMs, windowMs: MONTH_WINDOW_MS });
      const { completeness } = read;
      const floorMs = completeness.bytecap_floor_ts === null ? Number.NEGATIVE_INFINITY : Date.parse(completeness.bytecap_floor_ts);
      const where = `seed ${seed} step ${step} (${log.join(",")})`;
      assert.ok(read.points.every((point) => Date.parse(point.ts) > floorMs), `I1 violated at ${where}`);
      if (completeness.certified_after_ts !== null) {
        assert.ok(Date.parse(completeness.certified_after_ts) >= floorMs, `certified_after_ts older than the floor at ${where}`);
      }
      if (floorMs < previousFloorMs) {
        assert.notEqual(completeness.status, "intact", `floor moved backwards with no loss stamped at ${where}`);
      }
      previousFloorMs = floorMs;
      if (completeness.status === "intact") {
        checkedIntactReads += 1;
        const groups = groupByTs(read.points);
        for (const [ts, keys] of groups) {
          const expected = model.get(ts);
          assert.ok(expected, `returned a ts the model never appended at ${where}`);
          assert.deepEqual(keys, expected.keys, `partial tick ${ts} returned at ${where}`);
        }
        const sinceMs = nowMs - MONTH_WINDOW_MS;
        for (const [ts, entry] of model) {
          const tsMs = Date.parse(ts);
          if (!entry.alive || tsMs <= floorMs || tsMs < sinceMs) continue;
          assert.ok(groups.has(ts), `appended tick ${ts} above the floor is missing from an intact read at ${where}`);
        }
      }
    }
  }
  // While byte-cap eviction is still a loss channel (until the S2 reclassification commit), almost
  // every read after the first eviction is degraded, so few intact reads are checked.
  assert.ok(checkedIntactReads > 20, `the oracle exercised too few intact reads (${checkedIntactReads})`);
});
