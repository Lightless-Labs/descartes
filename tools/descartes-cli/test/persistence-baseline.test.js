import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { appendFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import {
  SCHEDULED_JOB_CENSUS_FACT_NAME,
  SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY,
  SCHEDULED_JOB_PRESENCE_FACT_NAME,
  buildScheduledJobEntityKey,
} from "../src/fact-translators.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT,
  SCHEDULED_JOB_APPEARED_RULE_ID,
  buildScheduledJobAppearedCandidates,
  computeScheduledJobBaselineCandidates,
  detectScheduledJobAppearances,
  groupScheduledJobFactsByTick,
  isValidPersistenceBaselineStoreShape,
  loadPersistenceBaselineStore,
  normalizePersistenceBaselineState,
  resolvePersistenceBaselineStorePaths,
  writePersistenceBaselineStore,
} from "../src/persistence-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-persistence-baseline-test-"));
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

const BASE_TS = Date.parse("2026-02-01T00:00:00.000Z");
const HOUR_MS = 60 * 60 * 1000;

function tickTs(hourOffset) {
  return new Date(BASE_TS + hourOffset * HOUR_MS).toISOString();
}

const KEY_CRON = buildScheduledJobEntityKey("cron", "cron_d", "digest-a");
const KEY_TIMER = buildScheduledJobEntityKey("systemd_timer", "systemd_timers", "backup.timer");

function presencePoint(ts, entityKey) {
  return {
    ts,
    fact_name: SCHEDULED_JOB_PRESENCE_FACT_NAME,
    entity_key: entityKey,
    attributes: { kind: "cron", source: "cron_d" },
    source_envelope_id: "scheduled-jobs",
    source_tool: "collect_scheduled_jobs",
    sensitivity: "operational",
  };
}

function censusMarkerPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: SCHEDULED_JOB_CENSUS_FACT_NAME,
    entity_key: SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "scheduled-jobs",
    source_tool: "collect_scheduled_jobs",
    sensitivity: "operational",
    confidence: 0,
  };
}

function completeTick(ts, keys = [KEY_TIMER]) {
  return [...keys.map((key) => presencePoint(ts, key)), censusMarkerPoint(ts)];
}

function partialTick(ts, keys = [KEY_TIMER]) {
  return [...keys.map((key) => presencePoint(ts, key)), censusMarkerPoint(ts, "partial")];
}

function flatten(ticks) {
  return ticks.flat();
}

function intactReadResult(points, completeness = { status: "intact" }) {
  return { points, corrupt_count: 0, schema_invalid_count: 0, completeness };
}

function degradedReadResult(points, lossTs) {
  return { points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "degraded", last_bytecap_evict_ts: lossTs } };
}

function expectedHash(entityKey) {
  return createHash("sha256").update(`${SCHEDULED_JOB_APPEARED_RULE_ID}:${entityKey}`).digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------------------------------
// Store I/O: exact-schema validation (mirrors process-lineage-baseline.js's own coverage)
// ---------------------------------------------------------------------------------------------

test("load/write/normalize persistence-baseline state is exact-schema and atomic", async () => {
  const paths = await tempPaths();
  assert.deepEqual(normalizePersistenceBaselineState(undefined), {
    version: 2, last_folded_ts: undefined, skipped_partial_tick_count: 0, appeared_event_count: 0,
    cold_start_pending: true, cold_start_reason: undefined, cold_start_since_ts: undefined,
  });
  const missing = await loadPersistenceBaselineStore(paths);
  assert.equal(missing.corrupt, false);
  assert.equal(missing.missing, true);
  await writePersistenceBaselineStore(paths, {
    cold_start_pending: false,
    last_folded_ts: tickTs(1),
    skipped_partial_tick_count: 2,
    appeared_event_count: 3,
  });
  const { dir, storeFile } = resolvePersistenceBaselineStorePaths(paths);
  assert.equal((await fs.stat(storeFile)).mode & 0o777, 0o600);
  assert.equal((await fs.readdir(dir)).some((name) => name.endsWith(".tmp")), false);
  assert.equal((await loadPersistenceBaselineStore(paths)).state.appeared_event_count, 3);
});

test("isValidPersistenceBaselineStoreShape rejects an unknown top-level key, a wrong-typed cold_start_pending, and a missing last_folded_ts on an established store", () => {
  assert.equal(isValidPersistenceBaselineStoreShape({
    version: 2, cold_start_pending: false, last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0, appeared_event_count: 0, unexpected_key: "x",
  }), false, "an unknown top-level key must reject the whole store");
  assert.equal(isValidPersistenceBaselineStoreShape({
    version: 2, cold_start_pending: "false", last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), false, "a wrong-typed cold_start_pending (string, not boolean) must reject the whole store");
  assert.equal(isValidPersistenceBaselineStoreShape({
    version: 2, cold_start_pending: false,
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), false, "an established store missing last_folded_ts must be rejected, not partially trusted");
  assert.equal(isValidPersistenceBaselineStoreShape({
    version: 2, cold_start_pending: true,
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), false, "a cold_start_pending:true store with no valid cold_start_since_ts anchor can never re-establish and must be rejected");
  assert.equal(isValidPersistenceBaselineStoreShape({
    version: 2, cold_start_pending: false, last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), true, "a fully-valid established store is accepted");
});

test("loadPersistenceBaselineStore treats a schema-invalid-but-parseable store identically to a missing/corrupt one (forces cold-start, never partially trusted)", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolvePersistenceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify({ cold_start_pending: false, unexpected: true }), { mode: 0o600 });
  const { state, corrupt } = await loadPersistenceBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "invalid_store_schema");
});

// ---------------------------------------------------------------------------------------------
// Pure detection
// ---------------------------------------------------------------------------------------------

test("groupScheduledJobFactsByTick is fail-closed for partial, unknown, and markerless groups", () => {
  const groups = groupScheduledJobFactsByTick(flatten([
    completeTick(tickTs(2), [KEY_TIMER]),
    [presencePoint(tickTs(1), KEY_CRON)],
    [censusMarkerPoint(tickTs(3), "partial")],
    [censusMarkerPoint(tickTs(4), "garbled")],
  ]));
  assert.deepEqual(groups.map((group) => group.ts), [tickTs(1), tickTs(2), tickTs(3), tickTs(4)]);
  assert.equal(groups[0].censusState, undefined);
  assert.equal(groups[2].censusState, "partial");
  assert.equal(groups[3].censusState, "unknown");
});

test("detectScheduledJobAppearances requires prior complete history and fires only for first appearance", () => {
  const groups = groupScheduledJobFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    partialTick(tickTs(2), [KEY_CRON]),
    [censusMarkerPoint(tickTs(3), "garbled"), presencePoint(tickTs(3), KEY_CRON)],
    [presencePoint(tickTs(4), KEY_CRON)],
    completeTick(tickTs(5), [KEY_TIMER, KEY_CRON]),
  ]));
  const options = { nowMs: Date.parse(tickTs(5)), minHistoryTickCount: 2, freshnessMs: HOUR_MS };
  const appearances = detectScheduledJobAppearances(groups, options);
  assert.deepEqual(appearances, [{ entity_key: KEY_CRON, first_seen_ts: tickTs(5) }]);
});

test("detectScheduledJobAppearances: an entity present in ANY prior complete group never re-fires, even several ticks back", () => {
  const groups = groupScheduledJobFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [KEY_TIMER, KEY_CRON]),
    completeTick(tickTs(3), [KEY_TIMER, KEY_CRON]),
  ]));
  assert.deepEqual(detectScheduledJobAppearances(groups, { nowMs: Date.parse(tickTs(6)), minHistoryTickCount: 2, freshnessMs: 5 * HOUR_MS }), []);
});

test("detectScheduledJobAppearances rejects cold-start (too few complete groups) and stale latest complete groups", () => {
  const groups = groupScheduledJobFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1), [KEY_TIMER, KEY_CRON]),
  ]));
  assert.deepEqual(detectScheduledJobAppearances(groups, { nowMs: Date.parse(tickTs(1)), minHistoryTickCount: DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT }), []);
  assert.deepEqual(detectScheduledJobAppearances(groups, { nowMs: Date.parse(tickTs(1)) + 2 * HOUR_MS, minHistoryTickCount: 1, freshnessMs: HOUR_MS }), []);
});

test("[P8 degrade, both directions] a job appearing only in a partial latest group does not fire; a job whose only prior sightings were partial is not treated as historical", () => {
  const latestPartial = groupScheduledJobFactsByTick(flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    partialTick(tickTs(2), [KEY_TIMER, KEY_CRON]),
  ]));
  assert.deepEqual(detectScheduledJobAppearances(latestPartial, { nowMs: Date.parse(tickTs(2)), minHistoryTickCount: 1, freshnessMs: HOUR_MS }), []);

  const priorPartialOnly = groupScheduledJobFactsByTick(flatten([
    completeTick(tickTs(0)),
    partialTick(tickTs(1), [KEY_CRON]),
    completeTick(tickTs(2), [KEY_TIMER]),
    completeTick(tickTs(3), [KEY_TIMER, KEY_CRON]),
  ]));
  // KEY_CRON's only prior sighting is in the partial tick(1) group, so it must NOT be treated as
  // historical -- it fires as a genuine appearance on tick(3).
  const appearances = detectScheduledJobAppearances(priorPartialOnly, { nowMs: Date.parse(tickTs(3)), minHistoryTickCount: 2, freshnessMs: HOUR_MS });
  assert.deepEqual(appearances, [{ entity_key: KEY_CRON, first_seen_ts: tickTs(3) }]);
});

test("buildScheduledJobAppearedCandidates hashes identity, sanitizes diagnostics, and caps severity at warning", () => {
  const candidate = buildScheduledJobAppearedCandidates([{ entity_key: KEY_CRON, first_seen_ts: tickTs(2) }])[0];
  assert.equal(candidate.rule_id, SCHEDULED_JOB_APPEARED_RULE_ID);
  assert.equal(candidate.severity, "warning");
  assert.equal(candidate.fingerprint, expectedHash(KEY_CRON));
  assert.deepEqual(candidate.diagnostics, { entity_key_hash: expectedHash(KEY_CRON), first_seen_ts: tickTs(2) });
  assert.equal(JSON.stringify(candidate).includes(KEY_CRON), false);
});

// ---------------------------------------------------------------------------------------------
// computeScheduledJobBaselineCandidates: kill-switch, fold-once counters, cold-start lockout
// ---------------------------------------------------------------------------------------------

test("computeScheduledJobBaselineCandidates checks learned.json before any fact/store I/O", async () => {
  const paths = await tempPaths();
  let readCalls = 0;
  let loadCalls = 0;
  const result = await computeScheduledJobBaselineCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { readCalls += 1; return { points: [] }; },
    loadPersistenceBaselineStore: async () => { loadCalls += 1; return { state: normalizePersistenceBaselineState() }; },
  });
  assert.deepEqual(result, []);
  assert.equal(readCalls, 0);
  assert.equal(loadCalls, 0);
});

test("computeScheduledJobBaselineCandidates folds counters once and emits an appearance end-to-end", async () => {
  const paths = await tempPaths();
  const points = flatten([
    completeTick(tickTs(0)),
    completeTick(tickTs(1)),
    completeTick(tickTs(2), [KEY_TIMER, KEY_CRON]),
  ]);
  await writeLearnedConfig(paths, { enabled: true });
  await writePersistenceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));
  const first = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(first.length, 1);
  assert.equal(first[0].diagnostics.entity_key_hash, expectedHash(KEY_CRON));
  const second = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(second.length, 1, "candidate re-emits from the same fact window");
  const state = (await loadPersistenceBaselineStore(paths)).state;
  assert.equal(state.appeared_event_count, 1);
  assert.equal(state.skipped_partial_tick_count, 0);
});

test("computeScheduledJobBaselineCandidates: fold-time-only counters increment exactly once per newly-observed tick-group, not per recompute", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writePersistenceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  const points = flatten([completeTick(tickTs(0)), completeTick(tickTs(1)), completeTick(tickTs(2), [KEY_TIMER, KEY_CRON])]);
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));
  await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  const state = (await loadPersistenceBaselineStore(paths)).state;
  assert.equal(state.appeared_event_count, 1, "three recomputes over the SAME unchanged window must not triple-count the fold");
});

// HIGH fix pattern (mirrors process-lineage-baseline.test.js): a corrupt/missing store must never
// self-heal-and-immediately-fire.

test("computeScheduledJobBaselineCandidates fails closed end-to-end when facts.jsonl has a genuinely corrupt line, never fabricating the appearance that same history would otherwise fire", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writePersistenceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  const points = flatten([completeTick(tickTs(0)), completeTick(tickTs(1)), completeTick(tickTs(2), [KEY_TIMER, KEY_CRON])]);

  await appendFactPoints(paths, points, { now: tickTs(2) });
  await settleFactStore(paths, tickTs(2));
  const clean = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(clean.length, 1, "sanity control: this history really would fire absent the corrupt gate");

  const { factsFile } = resolveFactStorePaths(paths);
  await fs.appendFile(factsFile, "{this is not valid json\n");

  const result = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, []);
});

test("computeScheduledJobBaselineCandidates fails closed end-to-end when the persisted baseline-store file is corrupt", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = flatten([completeTick(tickTs(0)), completeTick(tickTs(1)), completeTick(tickTs(2), [KEY_TIMER, KEY_CRON])]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  const { dir, storeFile } = resolvePersistenceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });

  const result = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, []);
});

test("computeScheduledJobBaselineCandidates: corrupt fact-history and genuine cold-start both fail closed to zero claims (fixture-driven)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = flatten([completeTick(tickTs(0)), completeTick(tickTs(1)), completeTick(tickTs(2), [KEY_TIMER, KEY_CRON])]);

  const corrupt = await computeScheduledJobBaselineCandidates(paths, {
    now: tickTs(2),
    minHistoryTickCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => ({ ...intactReadResult(points), corrupt_count: 1 }),
    loadPersistenceBaselineStore: async () => ({ state: normalizePersistenceBaselineState(), corrupt: false }),
    writePersistenceBaselineStore: async () => {},
  });
  assert.deepEqual(corrupt, []);

  const coldStart = await computeScheduledJobBaselineCandidates(paths, {
    now: tickTs(2),
    minHistoryTickCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => intactReadResult(points.filter((point) => point.ts === tickTs(2))),
    loadPersistenceBaselineStore: async () => ({ state: normalizePersistenceBaselineState(), corrupt: false }),
    writePersistenceBaselineStore: async () => {},
  });
  assert.deepEqual(coldStart, []);
});

test("computeScheduledJobBaselineCandidates: degraded/untrustworthy retained history suppresses a fabricated established-job alert", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const truncatedPoints = flatten([
    completeTick(tickTs(1)),
    completeTick(tickTs(2)),
    completeTick(tickTs(3), [KEY_TIMER, KEY_CRON]),
  ]);
  await writePersistenceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(0) });

  const result = await computeScheduledJobBaselineCandidates(paths, {
    now: tickTs(3),
    minHistoryTickCount,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => degradedReadResult(truncatedPoints, tickTs(3)),
  });

  assert.deepEqual(result, [], "untrustworthy retained history must not authorize an appearance claim");
  const state = (await loadPersistenceBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
});

test("computeScheduledJobBaselineCandidates: a corrupt baseline store forces a PERSISTENT cold-start -- corrupt tick then the self-healed tick right after both stay at zero (not 0-then-1); a second genuinely-new complete tick since the reset re-establishes, and the detector fires normally afterward (positive control)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;

  await writePersistenceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, flatten([completeTick(tickTs(0)), completeTick(tickTs(1))]), { now: tickTs(1) });
  const control = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(1), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(control, [], "not enough complete history yet -- unrelated to the corruption below");

  const { storeFile } = resolvePersistenceBaselineStorePaths(paths);
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });

  await appendFactPoints(paths, completeTick(tickTs(2), [KEY_TIMER, KEY_CRON]), { now: tickTs(2) });
  const corruptTick = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(2), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(corruptTick, [], "corrupt store this tick fails closed");

  await appendFactPoints(paths, completeTick(tickTs(3), [KEY_TIMER, KEY_CRON]), { now: tickTs(3) });
  const nextTick = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(3), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(nextTick, [], "still zero right after self-heal -- not re-established yet, not 0-then-1");

  const midState = (await loadPersistenceBaselineStore(paths)).state;
  assert.equal(midState.cold_start_pending, true, "only 1 of 2 required fresh ticks has accumulated since the reset");
  assert.equal(midState.cold_start_reason, "corrupt_store");

  await appendFactPoints(paths, completeTick(tickTs(4), [KEY_TIMER, KEY_CRON]), { now: tickTs(4) });
  const reestablishingTick = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(4), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(reestablishingTick, [], "cannot alert in the same breath it regains trust");
  const reestablishedState = (await loadPersistenceBaselineStore(paths)).state;
  assert.equal(reestablishedState.cold_start_pending, false);

  // Positive control: with trust genuinely restored, a real appearance now fires.
  await appendFactPoints(paths, completeTick(tickTs(5), [KEY_TIMER, KEY_CRON, "scheduled_job.9:new-entry.5:cron_d.16:0123456789abcdef"]), { now: tickTs(5) });
  const resumed = await computeScheduledJobBaselineCandidates(paths, { now: tickTs(5), minHistoryTickCount, activeFreshnessMs: HOUR_MS });
  assert.equal(resumed.length, 1, "novelty resumes after genuinely-new clean ticks re-establish trust");
});

test("computeScheduledJobBaselineCandidates with learned.json disabled makes ZERO calls into readFactPoints/loadPersistenceBaselineStore", async () => {
  const paths = await tempPaths();
  let readCalls = 0;
  let loadCalls = 0;
  const result = await computeScheduledJobBaselineCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { readCalls += 1; return { points: [] }; },
    loadPersistenceBaselineStore: async () => { loadCalls += 1; return { state: normalizePersistenceBaselineState() }; },
  });
  assert.deepEqual(result, []);
  assert.equal(readCalls, 0);
  assert.equal(loadCalls, 0);
});

// P9 fail-closed namespace pins (classifyAlertNamespace / deterministic-delivery allowlist /
// no_eligible_alerts even with full consent) live in test/alert-intelligence.test.js, mirroring
// SERVICE_DISAPPEARED_RULE_ID's/PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID's own coverage there exactly.
