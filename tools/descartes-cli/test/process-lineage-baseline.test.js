import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { appendFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { buildLineageEntityKey, PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME, PROCESS_LINEAGE_EDGE_CENSUS_MARKER_ENTITY_KEY, PROCESS_LINEAGE_EDGE_FACT_NAME } from "../src/fact-translators.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT,
  PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
  buildNovelEdgeCandidates,
  computeProcessLineageBaselineCandidates,
  detectNovelProcessLineageEdges,
  groupProcessLineageFactsByTick,
  isValidProcessLineageBaselineStoreShape,
  loadProcessLineageBaselineStore,
  normalizeProcessLineageBaselineState,
  resolveProcessLineageBaselineStorePaths,
  writeProcessLineageBaselineStore,
} from "../src/process-lineage-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-process-lineage-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

async function settleFactStore(paths, now) {
  await appendFactPoints(paths, [], { now });
}

const BASE_TS = Date.parse("2026-01-01T00:00:00.000Z");
const HOUR_MS = 60 * 60 * 1000;

function tickTs(hourOffset) {
  return new Date(BASE_TS + hourOffset * HOUR_MS).toISOString();
}

function lineagePoint(ts, parent = "shell", child = "node") {
  return {
    ts,
    fact_name: PROCESS_LINEAGE_EDGE_FACT_NAME,
    entity_key: buildLineageEntityKey(parent, child),
    attributes: {},
    source_envelope_id: "process-lineage-edges",
    source_tool: "collect_process_lineage",
    sensitivity: "operational",
  };
}

function censusMarkerPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME,
    entity_key: PROCESS_LINEAGE_EDGE_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "process-lineage-edges",
    source_tool: "collect_process_lineage",
    sensitivity: "operational",
    confidence: 0,
  };
}

function completeTick(ts, edges = [["shell", "node"]]) {
  return [...edges.map(([parent, child]) => lineagePoint(ts, parent, child)), censusMarkerPoint(ts)];
}

function partialTick(ts, edges = [["shell", "node"]]) {
  return [...edges.map(([parent, child]) => lineagePoint(ts, parent, child)), censusMarkerPoint(ts, "partial")];
}

function flatten(ticks) {
  return ticks.flat();
}

function intactReadResult(points, completeness = { status: "intact" }) {
  return {
    points,
    corrupt_count: 0,
    schema_invalid_count: 0,
    completeness,
  };
}

function degradedReadResult(points, lossTs = tickTs(2)) {
  return {
    points,
    corrupt_count: 0,
    schema_invalid_count: 0,
    completeness: { status: "degraded", last_bytecap_evict_ts: lossTs },
  };
}

function expectedHash(entityKey) {
  return createHash("sha256").update(`${PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID}:${entityKey}`).digest("hex").slice(0, 16);
}

test("load/write/normalize process-lineage baseline state is corrupt-tolerant and atomic", async () => {
  const paths = await tempPaths();
  assert.deepEqual(normalizeProcessLineageBaselineState(undefined), {
    version: 2, last_folded_ts: undefined, skipped_partial_tick_count: 0, novel_edge_event_count: 0,
    cold_start_pending: true, cold_start_reason: undefined, cold_start_since_ts: undefined,
  });
  const missing = await loadProcessLineageBaselineStore(paths);
  assert.equal(missing.corrupt, false);
  await writeProcessLineageBaselineStore(paths, {
    cold_start_pending: false,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: 2,
    novel_edge_event_count: 3,
  });
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  assert.equal((await fs.stat(storeFile)).mode & 0o777, 0o600);
  assert.equal((await fs.readdir(dir)).some((name) => name.endsWith(".tmp")), false);
  assert.equal((await loadProcessLineageBaselineStore(paths)).state.novel_edge_event_count, 3);
});

test("groupProcessLineageFactsByTick is fail-closed for partial, unknown, and markerless groups", () => {
  const groups = groupProcessLineageFactsByTick(flatten([
    completeTick(tickTs(2), [["shell", "node"]]),
    [lineagePoint(tickTs(1), "shell", "python")],
    [censusMarkerPoint(tickTs(3), "partial")],
    [censusMarkerPoint(tickTs(4), "garbled")],
  ]));
  assert.deepEqual(groups.map((group) => group.ts), [tickTs(1), tickTs(2), tickTs(3), tickTs(4)]);
  assert.equal(groups[0].censusState, undefined);
  assert.equal(groups[2].censusState, "partial");
  assert.equal(groups[3].censusState, "unknown");
});

test("detectNovelProcessLineageEdges requires prior complete history and fires only for first appearance", () => {
  const groups = groupProcessLineageFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    partialTick(tickTs(2), [["shell", "python"]]),
    [censusMarkerPoint(tickTs(3), "garbled"), lineagePoint(tickTs(3), "shell", "python")],
    [lineagePoint(tickTs(4), "shell", "python")],
    completeTick(tickTs(5), [["shell", "node"], ["shell", "python"]]),
  ]));
  const options = { nowMs: Date.parse(tickTs(5)), minHistoryTickCount: 2, freshnessMs: HOUR_MS };
  const novel = detectNovelProcessLineageEdges(groups, options);
  assert.deepEqual(novel, [{ entity_key: buildLineageEntityKey("shell", "python"), first_seen_ts: tickTs(5) }]);

  assert.deepEqual(detectNovelProcessLineageEdges(groups.slice(0, 5), { ...options, nowMs: Date.parse(tickTs(4)) }), []);
  const establishedLater = groupProcessLineageFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
    completeTick(tickTs(3), [["shell", "node"], ["shell", "python"]]),
  ]));
  assert.deepEqual(detectNovelProcessLineageEdges(establishedLater, { ...options, nowMs: Date.parse(tickTs(6)) }), []);
});

test("detectNovelProcessLineageEdges rejects cold-start and stale latest complete groups", () => {
  const groups = groupProcessLineageFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1), [["shell", "node"], ["shell", "python"]]),
  ]));
  assert.deepEqual(detectNovelProcessLineageEdges(groups, { nowMs: Date.parse(tickTs(1)), minHistoryTickCount: DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT }), []);
  assert.deepEqual(detectNovelProcessLineageEdges(groups, { nowMs: Date.parse(tickTs(1)) + 2 * HOUR_MS, minHistoryTickCount: 1, freshnessMs: HOUR_MS }), []);
});

test("buildNovelEdgeCandidates hashes identity, sanitizes diagnostics, and caps severity at warning", () => {
  const entityKey = buildLineageEntityKey("shell", "python");
  const candidate = buildNovelEdgeCandidates([{ entity_key: entityKey, first_seen_ts: tickTs(2) }])[0];
  assert.equal(candidate.rule_id, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID);
  assert.equal(candidate.severity, "warning");
  assert.equal(candidate.fingerprint, expectedHash(entityKey));
  assert.equal(candidate.id, buildNovelEdgeCandidates([{ entity_key: entityKey, first_seen_ts: tickTs(2) }])[0].id);
  assert.deepEqual(candidate.diagnostics, { entity_key_hash: expectedHash(entityKey), first_seen_ts: tickTs(2) });
  assert.equal(JSON.stringify(candidate).includes(entityKey), false);
});

test("computeProcessLineageBaselineCandidates checks learned.json before any fact/store I/O", async () => {
  const paths = await tempPaths();
  let readCalls = 0;
  let loadCalls = 0;
  const result = await computeProcessLineageBaselineCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { readCalls += 1; return { points: [] }; },
    loadProcessLineageBaselineStore: async () => { loadCalls += 1; return { state: normalizeProcessLineageBaselineState() }; },
  });
  assert.deepEqual(result, []);
  assert.equal(readCalls, 0);
  assert.equal(loadCalls, 0);
});

test("computeProcessLineageBaselineCandidates folds counters once and emits a novel edge end-to-end", async () => {
  const paths = await tempPaths();
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await writeLearnedConfig(paths, { enabled: true });
  // Prime the baseline store as already-established (past the persistent cold-start lockout
  // added below) -- this test is about the fold/counter bookkeeping, not the lockout itself,
  // which gets its own dedicated tests further down. A genuinely-established store must carry a
  // valid last_folded_ts (the exact-schema fix below rejects an established store without one),
  // so an arbitrary before-the-fixture anchor is supplied here.
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));
  const first = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(first.length, 1);
  assert.equal(first[0].diagnostics.entity_key_hash, expectedHash(buildLineageEntityKey("shell", "python")));
  const second = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(second.length, 1, "candidate re-emits from the same fact window");
  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.novel_edge_event_count, 1);
  assert.equal(state.skipped_partial_tick_count, 0);
});

// HIGH fix (deception/anomaly-detector review, the canary corrupt-store pattern): an absent or
// corrupt stored lineage baseline/history must never be treated as authoritative EMPTY history --
// that would make a perfectly normal, already-established edge read as "never seen" and fabricate
// a novel-edge alert. A corrupt/unreadable fact-history or baseline store must FAIL CLOSED
// (degrade to cold-start, emit zero novel-edge claims) instead.

test("computeProcessLineageBaselineCandidates fails closed end-to-end when facts.jsonl has a genuinely corrupt line, never fabricating the novel edge that same history would otherwise fire", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Prime as already-established so the "clean" sanity-control call below can actually fire --
  // proving the corrupted-facts case really would fabricate an alert absent the corrupt gate.
  // (A valid last_folded_ts is required for the store to actually count as established.)
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);

  // Sanity control: this exact fact-history, read WITHOUT corruption, fires the "shell->python"
  // novel edge (same shape as the "folds counters once..." end-to-end test above) -- proving the
  // corrupted case below really would have fabricated an alert had it not been gated.
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));
  const clean = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(clean.length, 1);

  // Now corrupt facts.jsonl with a genuinely unparsable line (a partial/torn write, disk
  // corruption, ...). readFactPoints is corrupt-tolerant per-line (drops the bad line, keeps the
  // rest) -- it does NOT throw -- so without an explicit fail-closed gate the surviving points
  // would be silently treated as the complete, authoritative history.
  const { factsFile } = resolveFactStorePaths(paths);
  await fs.appendFile(factsFile, "{this is not valid json\n");

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, []);
});

test("computeProcessLineageBaselineCandidates fails closed end-to-end when the persisted baseline-store file is corrupt", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, []);
});

test("computeProcessLineageBaselineCandidates: corrupt fact-history and genuine cold-start both fail closed to zero claims (fixture-driven)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);

  // Corrupt fact-history (even with plenty of ticks) fails closed via the explicit corrupt gate.
  const corrupt = await computeProcessLineageBaselineCandidates(paths, {
    now: tickTs(2),
    minHistoryTickCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => ({ ...intactReadResult(points), corrupt_count: 1 }),
    loadProcessLineageBaselineStore: async () => ({ state: normalizeProcessLineageBaselineState(), corrupt: false }),
    writeProcessLineageBaselineStore: async () => {},
  });
  assert.deepEqual(corrupt, []);

  // Genuine day-1 cold-start (too few complete ticks, no corruption at all) fails closed via the
  // pre-existing minHistoryTickCount gate -- same zero-claims outcome, distinct cause.
  const coldStart = await computeProcessLineageBaselineCandidates(paths, {
    now: tickTs(2),
    minHistoryTickCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => intactReadResult(points.filter((point) => point.ts === tickTs(2))),
    loadProcessLineageBaselineStore: async () => ({ state: normalizeProcessLineageBaselineState(), corrupt: false }),
    writeProcessLineageBaselineStore: async () => {},
  });
  assert.deepEqual(coldStart, []);
});

test("computeProcessLineageBaselineCandidates: degraded truncated history suppresses a fabricated established-edge alert", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const truncatedPoints = flatten([
    completeTick(tickTs(1)),
    completeTick(tickTs(2)),
    completeTick(tickTs(3), [["shell", "node"], ["shell", "python"]]),
  ]);
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(0) });

  const result = await computeProcessLineageBaselineCandidates(paths, {
    now: tickTs(3),
    minHistoryTickCount,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => degradedReadResult(truncatedPoints, tickTs(3)),
  });

  assert.deepEqual(result, [], "untrustworthy retained history must not authorize a novel-edge claim");
  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
});

test("computeProcessLineageBaselineCandidates: a future pending anchor re-arms at the injected now", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeProcessLineageBaselineStore(paths, {
    cold_start_pending: true,
    cold_start_since_ts: tickTs(10),
  });

  await computeProcessLineageBaselineCandidates(paths, {
    now: tickTs(0),
    readFactPoints: async () => intactReadResult([]),
  });

  const { state } = await loadProcessLineageBaselineStore(paths);
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_since_ts, tickTs(0));
});

test("computeProcessLineageBaselineCandidates: rollback repairs a future anchor and watermark, then persists re-established trust", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeProcessLineageBaselineStore(paths, {
    cold_start_pending: true,
    cold_start_since_ts: tickTs(10),
    last_folded_ts: tickTs(10),
  });

  let points = flatten([completeTick(tickTs(11), [["shell", "python"]])]);
  const options = {
    minHistoryTickCount: 6,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => intactReadResult(points, { status: "intact", last_corrupt_ts: tickTs(100) }),
  };
  await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(0) });
  assert.equal((await loadProcessLineageBaselineStore(paths)).state.last_folded_ts, undefined);

  points = flatten([
    ...Array.from({ length: 6 }, (_, index) => completeTick(tickTs(index + 1))),
    completeTick(tickTs(11), [["shell", "python"]]),
  ]);
  const recoveredTick = await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(6) });
  assert.deepEqual(recoveredTick, [], "the tick that re-establishes trust remains suppressed");
  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, false);
  assert.equal(state.last_folded_ts, tickTs(6), "future facts must not advance the folded watermark");

  points = [...points, ...completeTick(tickTs(7), [["shell", "python"]])];
  const resumed = await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(7) });
  assert.equal(resumed.length, 1, "novelty resumes after rollback recovery has been persisted");
});

test("computeProcessLineageBaselineCandidates: intact history control still detects a novel edge", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  const result = await computeProcessLineageBaselineCandidates(paths, {
    now: tickTs(2),
    minHistoryTickCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => intactReadResult(points),
  });

  assert.equal(result.length, 1, "an intact store must not be falsely suppressed");
  assert.equal(result[0].diagnostics.entity_key_hash, expectedHash(buildLineageEntityKey("shell", "python")));
});

test("computeProcessLineageBaselineCandidates: one transient fact-history loss recovers after clean ticks", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  let points = flatten([completeTick(tickTs(0)), completeTick(tickTs(1))]);
  let readResult = degradedReadResult([], tickTs(2));
  const options = {
    minHistoryTickCount,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => ({ ...readResult, points }),
  };

  points = [...points, ...completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]])];
  const lossTick = await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(2) });
  assert.deepEqual(lossTick, []);

  readResult = intactReadResult([]);
  points = [...points, ...completeTick(tickTs(3), [["shell", "node"], ["shell", "python"]])];
  assert.deepEqual(await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(3) }), []);

  points = [...points, ...completeTick(tickTs(4), [["shell", "node"], ["shell", "python"]])];
  assert.deepEqual(await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(4) }), []);
  assert.equal((await loadProcessLineageBaselineStore(paths)).state.cold_start_pending, false);

  points = [...points, ...completeTick(tickTs(5), [["shell", "node"], ["shell", "ruby"]])];
  const resumed = await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(5) });
  assert.equal(resumed.length, 1, "novelty resumes after genuinely-new clean ticks re-establish trust");
});

test("computeProcessLineageBaselineCandidates: a clean tick cannot self-heal and fire after fact-history loss", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  let points = flatten([completeTick(tickTs(1)), completeTick(tickTs(2)), completeTick(tickTs(3), [["shell", "node"], ["shell", "python"]])]);
  let readResult = degradedReadResult(points, tickTs(3));
  const options = {
    minHistoryTickCount: 1,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => ({ ...readResult, points }),
  };

  assert.deepEqual(await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(3) }), []);
  points = [...points, ...completeTick(tickTs(4), [["shell", "node"], ["shell", "python"]])];
  readResult = intactReadResult([]);
  assert.deepEqual(
    await computeProcessLineageBaselineCandidates(paths, { ...options, now: tickTs(4) }),
    [],
    "the first clean tick after loss may re-establish state but must not emit novelty",
  );
  assert.equal((await loadProcessLineageBaselineStore(paths)).state.cold_start_pending, false);
});

// BOUNDED fix (deception/anomaly-detector review -- corrupt/missing-store self-heal-and-
// immediately-fire pattern): a corrupt, missing, or otherwise reset/lost baseline store must
// put the detector into a PERSISTENT cold-start -- zero novel-edge claims not just for the tick
// where the loss is observed, but for every tick until minHistoryTickCount genuinely new
// complete ticks have re-accumulated since the reset. Self-healing the store file (the very next
// write producing a valid file again) must never be conflated with re-establishing the baseline.

test("computeProcessLineageBaselineCandidates: a corrupt baseline store forces a PERSISTENT cold-start -- corrupt tick then the self-healed tick right after both stay at zero (not 0-then-1)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;

  // Prime the store as already-established, so the failure below is attributable to the
  // corruption itself, not to an unrelated cold-start that was already in effect. (A valid
  // last_folded_ts is required for the store to actually count as established.)
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, flatten([completeTick(tickTs(0)), completeTick(tickTs(1))]), { now: tickTs(1) });
  const control = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(1), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(control, [], "not enough complete history yet -- unrelated to the corruption below");

  // Corrupt the persisted baseline store (disk error, partial write, ...).
  const { storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });

  // Tick N: a new complete census tick arrives carrying a genuinely novel "shell->python" edge,
  // while the store read is corrupt this round -> zero claims (fail-closed, pre-existing).
  await appendFactPoints(paths, completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]), { now: tickTs(2) });
  const corruptTick = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(corruptTick, [], "corrupt store this tick fails closed");

  // Tick N+1: the store has self-healed (the corrupt tick above wrote a valid file back) and
  // facts.jsonl is completely clean. This is exactly the scenario that used to fabricate:
  // pre-fix, the detector trusted the live fact window again immediately here and fired
  // "shell->python" as novel -- even though it already silently appeared, unclaimed, at tick N.
  // It must still be zero: self-healing the store file is not the same as re-establishing trust.
  await appendFactPoints(paths, completeTick(tickTs(3), [["shell", "node"], ["shell", "python"]]), { now: tickTs(3) });
  const nextTick = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(3), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(nextTick, [], "still zero right after self-heal -- not re-established yet, not 0-then-1");

  const midState = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(midState.cold_start_pending, true, "only 1 of 2 required fresh ticks has accumulated since the reset");
  assert.equal(midState.cold_start_reason, "corrupt_store");

  // Tick N+2: a second genuinely new complete tick since the reset satisfies
  // minHistoryTickCount -- re-established. This tick itself still emits zero (it cannot alert
  // in the same breath it regains trust), but the store now flips cold_start_pending off for
  // the tick after.
  await appendFactPoints(paths, completeTick(tickTs(4), [["shell", "node"], ["shell", "python"]]), { now: tickTs(4) });
  const reestablishingTick = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(4), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(reestablishingTick, []);
  const reestablishedState = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(reestablishedState.cold_start_pending, false);
});

test("computeProcessLineageBaselineCandidates: a missing baseline store with retained fact-history is cold-start, not trust -- it does not fire on the very first (or second) tick", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;

  // Retained fact-history: a full, clean, multi-tick window already sitting in facts.jsonl --
  // exactly as it would look if only the baseline-store file (a separate file) were lost while
  // facts.jsonl survived (state dir partially wiped, a disk error scoped to one file, ...).
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));

  // Sanity control: this exact fact-history, read against an already-established store, fires
  // immediately (mirrors the "folds counters once" end-to-end test) -- proving the missing-store
  // run below really would fabricate the "shell->python" alert had the missing store been
  // trusted immediately instead of gated.
  const controlPaths = await tempPaths();
  await writeLearnedConfig(controlPaths, { enabled: true });
  await writeProcessLineageBaselineStore(controlPaths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(controlPaths, points, { now: tickTs(2) });
  await settleFactStore(controlPaths, tickTs(2));
  const control = await computeProcessLineageBaselineCandidates(controlPaths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(control.length, 1);

  // No baseline-store file has ever been written for `paths` -- it is missing, not corrupt.
  const missing = await loadProcessLineageBaselineStore(paths);
  assert.equal(missing.corrupt, false);
  assert.equal(missing.state.cold_start_pending, true);

  const first = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(first, [], "missing store must cold-start, not trust the retained fact-history immediately");

  // A second call against the SAME unchanged fact window (no genuinely new ticks since the
  // reset) must also stay at zero -- re-establishment needs real new ticks, not repeated
  // queries of the same stale-relative-to-the-loss data.
  const second = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(second, []);

  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "missing_store");
});

// FABRICATION + FAIL-SAFE fix (deception/anomaly-detector review -- schema-invalid-store trust
// and Infinity-re-establishment-boundary patterns): a store that parses as valid JSON but does
// not match the persisted schema (wrong/missing fields, old-format, foreign) must never be
// trusted at face value just because it parsed -- and once it is correctly rejected into
// cold-start, it must get a REAL anchor (not undefined/Infinity) so it can genuinely
// re-establish instead of being permanently silenced.

test("computeProcessLineageBaselineCandidates: a parseable-but-schema-invalid baseline store (valid JSON, wrong shape) is treated as corrupt -- cold-start, zero novel-edge, and a real anchor is set", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  // Sanity control: this exact fact-history, read against a genuinely-established store, fires
  // immediately -- proving the schema-invalid store below really would fabricate the alert had it
  // been trusted at face value instead of being validated.
  const controlPaths = await tempPaths();
  await writeLearnedConfig(controlPaths, { enabled: true });
  await writeProcessLineageBaselineStore(controlPaths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(controlPaths, points, { now: tickTs(2) });
  await settleFactStore(controlPaths, tickTs(2));
  const control = await computeProcessLineageBaselineCandidates(controlPaths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(control.length, 1);

  // A parseable-but-schema-invalid store: valid JSON, but missing schema_version, counters, and
  // the cold-start anchor entirely -- exactly the shape a hand-edited or foreign file might have.
  assert.equal(isValidProcessLineageBaselineStoreShape({ cold_start_pending: false }), false);
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify({ cold_start_pending: false }), { mode: 0o600 });

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "schema-invalid store must not be trusted -- zero novel-edge claims, not fabricated ones");

  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "invalid_store_schema");
  assert.equal(typeof state.cold_start_since_ts, "string", "a real anchor must be set, not left undefined");
  assert.ok(Number.isFinite(new Date(state.cold_start_since_ts).getTime()), "anchor must be a valid ISO timestamp");
});

test("computeProcessLineageBaselineCandidates: an old-format/empty baseline store enters cold-start with a real anchor and ACTUALLY re-establishes after enough new complete ticks (not Infinity/never)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;

  // Old-format/empty store: valid JSON, but an empty object -- no schema_version, no fields at
  // all. Under the pre-fix normalizer this defaulted cold_start_pending to true (safe) but left
  // cold_start_since_ts undefined -- the re-accumulation gate falls back to `Infinity` for a
  // missing anchor, and no real tick timestamp can ever exceed Infinity, so it never
  // re-established. The fix must reject it into cold-start WITH a real anchor instead.
  assert.equal(isValidProcessLineageBaselineStoreShape({}), false);
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify({}), { mode: 0o600 });

  await appendFactPoints(paths, completeTick(tickTs(0)), { now: tickTs(0) });
  const tick0 = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(0), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(tick0, []);
  const afterTick0 = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(afterTick0.cold_start_pending, true);
  assert.equal(typeof afterTick0.cold_start_since_ts, "string", "anchor must be set on entering cold-start, not left undefined");
  assert.ok(Number.isFinite(new Date(afterTick0.cold_start_since_ts).getTime()));

  // First genuinely new complete tick strictly after the anchor: not enough yet.
  await appendFactPoints(paths, completeTick(tickTs(1)), { now: tickTs(1) });
  const tick1 = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(1), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(tick1, []);
  assert.equal((await loadProcessLineageBaselineStore(paths)).state.cold_start_pending, true, "only 1 of 2 required fresh ticks so far");

  // Second genuinely new complete tick since the reset satisfies minHistoryTickCount --
  // re-established. This tick itself still emits zero (cannot alert in the same breath it
  // regains trust), but the store flips cold_start_pending off for the tick after.
  await appendFactPoints(paths, completeTick(tickTs(2)), { now: tickTs(2) });
  const tick2 = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(tick2, []);
  assert.equal((await loadProcessLineageBaselineStore(paths)).state.cold_start_pending, false, "must ACTUALLY re-establish, not stay stuck forever (not Infinity/never)");

  // Sanity: with trust genuinely restored, a subsequent real novel edge fires normally -- the
  // detector is not permanently silenced.
  await appendFactPoints(paths, completeTick(tickTs(3), [["shell", "node"], ["shell", "python"]]), { now: tickTs(3) });
  const tick3 = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(3), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(tick3.length, 1, "trust genuinely restored after re-establishment -- detector works again");
});

test("computeProcessLineageBaselineCandidates: a fully schema-valid established store is trusted immediately -- no regression from the schema-validation fix", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));

  // A hand-constructed but FULLY schema-valid store -- every field correctly typed and present
  // (or validly absent where optional) -- must pass validation and be trusted at face value,
  // exactly as before the schema-validation fix.
  const validStore = {
    version: 2,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: 0,
    novel_edge_event_count: 0,
    cold_start_pending: false,
    cold_start_reason: undefined,
    cold_start_since_ts: undefined,
  };
  assert.equal(isValidProcessLineageBaselineStoreShape(validStore), true);
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify(validStore), { mode: 0o600 });

  const loaded = await loadProcessLineageBaselineStore(paths);
  assert.equal(loaded.corrupt, false);
  assert.equal(loaded.state.cold_start_pending, false);

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(result.length, 1, "fully-valid established store trusts immediately, same as before the fix");
});

// TERMINAL fix (gpt-5.6-sol review -- exact-schema pattern): the prior "full schema validation"
// was still too LENIENT -- it checked each field's TYPE "if present" instead of requiring the
// COMPLETE established-state schema. A minimal parseable store like
// {version:2, <both counters>, cold_start_pending:false} that is simply MISSING last_folded_ts
// passed and was trusted, fabricating a novel-edge claim from retained history the store never
// actually vouched for. Foreign/unknown top-level keys and invalid (negative/fractional) counters
// were also silently accepted. isValidProcessLineageBaselineStoreShape is now exact-schema: any
// store that is not an EXACT valid shape is routed to persistent cold-start with a real anchor
// (reason "invalid_store_schema"), identical to the corrupt-store path.

test("computeProcessLineageBaselineCandidates: gpt-5.6-sol TERMINAL fix -- an established store MISSING last_folded_ts is rejected into cold-start (zero novel-edge), while the identical store WITH last_folded_ts trusts and fires", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  // The minimal parseable store gpt-5.6-sol flagged: version, both counters, and
  // cold_start_pending:false are all present and individually well-typed -- but last_folded_ts is
  // missing entirely. The prior "check each field if present" validation let this through and
  // trusted it as genuinely established.
  const minimalStoreMissingLastFolded = {
    version: 2,
    skipped_partial_tick_count: 0,
    novel_edge_event_count: 0,
    cold_start_pending: false,
  };
  assert.equal(
    isValidProcessLineageBaselineStoreShape(minimalStoreMissingLastFolded),
    false,
    "an established store missing last_folded_ts must be rejected",
  );
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify(minimalStoreMissingLastFolded), { mode: 0o600 });

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "store missing last_folded_ts must not be trusted -- zero novel-edge claims, not fabricated ones");
  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "invalid_store_schema");
  assert.equal(typeof state.cold_start_since_ts, "string", "a real anchor must be set, not left undefined");
  assert.ok(Number.isFinite(new Date(state.cold_start_since_ts).getTime()), "anchor must be a valid ISO timestamp");

  // Sanity control: the exact same store, but WITH a valid last_folded_ts, is genuinely
  // established and trusts+fires immediately -- proving the rejection above is really about the
  // missing field, not some other accidental mismatch.
  const controlPaths = await tempPaths();
  await writeLearnedConfig(controlPaths, { enabled: true });
  await appendFactPoints(controlPaths, points, { now: tickTs(2) });
  await settleFactStore(controlPaths, tickTs(2));
  const controlStoreWithLastFolded = { ...minimalStoreMissingLastFolded, last_folded_ts: tickTs(-1) };
  assert.equal(isValidProcessLineageBaselineStoreShape(controlStoreWithLastFolded), true);
  const controlLocation = resolveProcessLineageBaselineStorePaths(controlPaths);
  await fs.mkdir(controlLocation.dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(controlLocation.storeFile, JSON.stringify(controlStoreWithLastFolded), { mode: 0o600 });
  const controlResult = await computeProcessLineageBaselineCandidates(controlPaths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(controlResult.length, 1, "the identical store WITH last_folded_ts trusts and fires the novel edge");
});

test("computeProcessLineageBaselineCandidates: gpt-5.6-sol fix -- a store with a foreign/unknown top-level key is rejected into cold-start", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  const foreignKeyStore = {
    version: 2,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: 0,
    novel_edge_event_count: 0,
    cold_start_pending: false,
    unexpected_field: "injected",
  };
  assert.equal(isValidProcessLineageBaselineStoreShape(foreignKeyStore), false, "an unknown top-level key must reject the whole store");
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify(foreignKeyStore), { mode: 0o600 });

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "store with a foreign top-level key must not be trusted");
  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "invalid_store_schema");
  assert.ok(Number.isFinite(new Date(state.cold_start_since_ts).getTime()), "anchor must be a valid ISO timestamp");
});

test("computeProcessLineageBaselineCandidates: gpt-5.6-sol fix -- a store with a negative or fractional counter is rejected into cold-start", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  const negativeCounterStore = {
    version: 2,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: -1,
    novel_edge_event_count: 0,
    cold_start_pending: false,
  };
  const fractionalCounterStore = {
    version: 2,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: 0,
    novel_edge_event_count: 1.5,
    cold_start_pending: false,
  };
  assert.equal(isValidProcessLineageBaselineStoreShape(negativeCounterStore), false, "a negative counter must reject the whole store");
  assert.equal(isValidProcessLineageBaselineStoreShape(fractionalCounterStore), false, "a fractional counter must reject the whole store");

  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify(negativeCounterStore), { mode: 0o600 });

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "store with a negative counter must not be trusted");
  const state = (await loadProcessLineageBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "invalid_store_schema");
});

test("computeProcessLineageBaselineCandidates: gpt-5.6-sol fix -- an exact-valid established store (every required field present and in range) still trusts and fires, no regression", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [["shell", "node"], ["shell", "python"]]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));

  const exactValidStore = {
    version: 2,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: 0,
    novel_edge_event_count: 0,
    cold_start_pending: false,
  };
  assert.equal(isValidProcessLineageBaselineStoreShape(exactValidStore), true);
  const { dir, storeFile } = resolveProcessLineageBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify(exactValidStore), { mode: 0o600 });

  const result = await computeProcessLineageBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(result.length, 1, "exact-valid established store trusts and fires -- no regression from the stricter schema check");
});
