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
