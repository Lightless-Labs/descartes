import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { isFixedLengthHexHash, isSafeEnumString, sanitizeDiagnostics } from "../src/diagnostics-sanitizer.js";
import { appendFactPoints, readFactPoints } from "../src/fact-store.js";
import { SESSION_CENSUS_MARKER_ENTITY_KEY, SESSION_OVERFLOW_ENTITY_KEY } from "../src/fact-translators.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_BASELINE_FACT_WINDOW_MS,
  DEFAULT_CRITICAL_SIGMA,
  DEFAULT_DEVIATION_SIGMA,
  DEFAULT_MIN_SAMPLE_COUNT,
  DEFAULT_STDDEV_FLOOR,
  DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS,
  SESSION_CHURN_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  buildChurnCandidates,
  buildCountDropCandidate,
  computeSessionBaselineCandidates,
  computeWindowedSessionStats,
  computeZScore,
  detectSessionChurn,
  emptyWelfordStats,
  foldWelford,
  groupSessionFactsByTick,
  loadSessionBaselineStore,
  resolveSessionBaselineStorePaths,
  updateEwma,
  writeSessionBaselineStore,
} from "../src/session-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-session-baseline-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const BASE_TS = Date.parse("2026-01-01T00:00:00.000Z");
const HOUR_MS = 60 * 60 * 1000;

function tickTs(hourOffset) {
  return new Date(BASE_TS + hourOffset * HOUR_MS).toISOString();
}

function sessionPoint(ts, entityKey, fingerprint = "abababababababab") {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: entityKey,
    attributes: { multiplexer: "tmux", attached: "true", window_count_bucket: "1", created_at_fingerprint: fingerprint },
    source_envelope_id: "sessions",
    source_tool: "collect_sessions",
    sensitivity: "operational",
  };
}

function censusMarkerPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: SESSION_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "sessions",
    source_tool: "collect_sessions",
    sensitivity: "operational",
    confidence: 0,
  };
}

function overflowMarkerPoint(ts) {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: SESSION_OVERFLOW_ENTITY_KEY,
    attributes: { overflow: "true", total_count_bucket: "1000+" },
    source_envelope_id: "sessions",
    source_tool: "collect_sessions",
    sensitivity: "operational",
    confidence: 0,
  };
}

// A "complete" tick-group: `count` distinct session facts + a complete census marker.
function completeTick(ts, count, entityPrefix = "e") {
  const points = [];
  for (let i = 0; i < count; i += 1) points.push(sessionPoint(ts, `${entityPrefix}-${i}`));
  points.push(censusMarkerPoint(ts, "complete"));
  return points;
}

function partialTick(ts, count, entityPrefix = "e") {
  const points = [];
  for (let i = 0; i < count; i += 1) points.push(sessionPoint(ts, `${entityPrefix}-${i}`));
  points.push(censusMarkerPoint(ts, "partial"));
  return points;
}

function overflowTick(ts, count, entityPrefix = "e") {
  const points = completeTick(ts, count, entityPrefix);
  points.push(overflowMarkerPoint(ts));
  return points;
}

function flatten(groupsOfPoints) {
  return groupsOfPoints.flat();
}

async function seedAndCompute(paths, points, options = {}) {
  const lastTs = points.reduce((max, p) => Math.max(max, new Date(p.ts).getTime()), 0);
  const now = options.now ?? new Date(lastTs).toISOString();
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, points, { now });
  return computeSessionBaselineCandidates(paths, { now, ...options });
}

// ---------------------------------------------------------------------------------------------
// Welford / EWMA / z-score pure-function unit tests: MOVED to welford-stats.test.js (Slice 4b,
// Decision 4 / Fable review MUST-FIX 5 — the four primitives now live in welford-stats.js;
// session-baseline.js only re-exports them). The name-imports above (foldWelford, updateEwma,
// computeZScore, emptyWelfordStats) still resolve via that re-export and remain used below by
// computeWindowedSessionStats-adjacent fixtures/candidate tests in this file.
// ---------------------------------------------------------------------------------------------

test("DEVIATION_SIGMA/CRITICAL_SIGMA/STDDEV_FLOOR/MIN_SAMPLE_COUNT defaults are positive finite constants", () => {
  for (const value of [DEFAULT_DEVIATION_SIGMA, DEFAULT_CRITICAL_SIGMA, DEFAULT_STDDEV_FLOOR, DEFAULT_MIN_SAMPLE_COUNT, DEFAULT_BASELINE_FACT_WINDOW_MS]) {
    assert(Number.isFinite(value) && value > 0);
  }
  assert(DEFAULT_CRITICAL_SIGMA > DEFAULT_DEVIATION_SIGMA);
});

// ---------------------------------------------------------------------------------------------
// groupSessionFactsByTick / tick-group disposition.
// ---------------------------------------------------------------------------------------------

test("groupSessionFactsByTick: excludes both the census marker and the overflow marker from `count`, and reports censusState/hasOverflow per tick", () => {
  const points = flatten([overflowTick(tickTs(0), 3)]);
  const groups = groupSessionFactsByTick(points);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].count, 3);
  assert.equal(groups[0].hasOverflow, true);
  assert.equal(groups[0].censusState, "complete");
});

test("groupSessionFactsByTick: a markerless (legacy) tick-group has censusState undefined", () => {
  const ts = tickTs(0);
  const points = [sessionPoint(ts, "e-0")]; // no census marker at all
  const groups = groupSessionFactsByTick(points);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, undefined);
});

test("groupSessionFactsByTick: a garbled/unrecognized census_state marker value degrades to censusState 'unknown', NOT 'complete' (degrade-not-fabricate, never max-trust-by-default — mirrors groupServiceFactsByTick)", () => {
  const ts = tickTs(0);
  const points = [sessionPoint(ts, "e-0"), censusMarkerPoint(ts, "truncated-oops")];
  const groups = groupSessionFactsByTick(points);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, "unknown");
});

test("groupSessionFactsByTick: orders tick-groups ascending by ts regardless of input order", () => {
  const points = flatten([completeTick(tickTs(2), 1), completeTick(tickTs(0), 1), completeTick(tickTs(1), 1)]);
  const groups = groupSessionFactsByTick(points);
  assert.deepEqual(groups.map((g) => g.ts), [tickTs(0), tickTs(1), tickTs(2)]);
});

// ---------------------------------------------------------------------------------------------
// z-score-before-fold ordering (must-fix 5) + STDDEV_FLOOR guard, via computeWindowedSessionStats.
// ---------------------------------------------------------------------------------------------

test("computeWindowedSessionStats: z_score for the latest tick-group is computed against the window EXCLUDING it (self-dampening avoidance)", () => {
  const groups = groupSessionFactsByTick(flatten([completeTick(tickTs(0), 10), completeTick(tickTs(1), 10), completeTick(tickTs(2), 1)]));
  const windowed = computeWindowedSessionStats(groups, { minSampleCount: 3 });
  // mean_before/stddev_before must reflect ONLY the first two groups (10, 10) -> mean 10, stddev 0 -> floored.
  assert.equal(windowed.last_observation.mean_before, 10);
  assert.equal(windowed.last_observation.stddev_before, 0);
  assert.equal(windowed.last_observation.z_score, (1 - 10) / DEFAULT_STDDEV_FLOOR);
  // The FULL post-fold stats (including the deviant group) must differ from mean_before -- proving
  // the z-score was NOT computed against the already-updated (self-dampened) mean.
  assert.notEqual(windowed.stats.mean, windowed.last_observation.mean_before);
  assert.equal(windowed.stats.mean, (10 + 10 + 1) / 3);
});

test("computeWindowedSessionStats: STDDEV_FLOOR guard prevents a trivial +/-1 fluctuation on a zero-variance baseline from producing an extreme z", () => {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(30), 19)); // a trivial one-session fluctuation
  const groups = groupSessionFactsByTick(flatten(ticks));
  const windowed = computeWindowedSessionStats(groups, { minSampleCount: DEFAULT_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "established");
  assert.equal(windowed.last_observation.z_score, (19 - 20) / DEFAULT_STDDEV_FLOOR);
  assert.ok(windowed.last_observation.z_score > -DEFAULT_DEVIATION_SIGMA, "a trivial +/-1 fluctuation must not cross the deviation threshold");
  const candidate = buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined);
});

// ---------------------------------------------------------------------------------------------
// Overflow-tick handling (must-fix 5 + plan-text nice-to-have ii).
// ---------------------------------------------------------------------------------------------

test("computeWindowedSessionStats: an overflow tick-group is excluded from the windowed recompute entirely", () => {
  const ticks = [completeTick(tickTs(0), 10), completeTick(tickTs(1), 10), completeTick(tickTs(2), 10), overflowTick(tickTs(3), 500)];
  const groups = groupSessionFactsByTick(flatten(ticks));
  const windowed = computeWindowedSessionStats(groups, { minSampleCount: 3 });
  assert.equal(windowed.stats.count, 3, "the overflow tick-group must not be folded into the windowed stats");
  assert.equal(windowed.stats.mean, 10);
  assert.equal(windowed.last_observation.ts, tickTs(2), "last_observation stays pinned to the last REAL (complete) tick-group");
  assert.equal(windowed.last_observation.has_overflow, true, "has_overflow reflects the most recent tick of ANY disposition, purely for observability");
});

test("an overflow tick occurring during an already-active session.count_drop leaves the candidate's z_score/severity unchanged from the prior real observation", () => {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(30), 0)); // mass-drop tick, fires
  const beforeOverflow = groupSessionFactsByTick(flatten(ticks));
  const windowedBefore = computeWindowedSessionStats(beforeOverflow, { minSampleCount: DEFAULT_MIN_SAMPLE_COUNT });
  const candidateBefore = buildCountDropCandidate({ confidence_state: windowedBefore.confidence_state, last_observation: windowedBefore.last_observation });
  assert.ok(candidateBefore, "expected the mass-drop tick to fire session.count_drop");

  ticks.push(overflowTick(tickTs(31), 500)); // an overflow tick lands right after
  const afterOverflow = groupSessionFactsByTick(flatten(ticks));
  const windowedAfter = computeWindowedSessionStats(afterOverflow, { minSampleCount: DEFAULT_MIN_SAMPLE_COUNT });
  const candidateAfter = buildCountDropCandidate({ confidence_state: windowedAfter.confidence_state, last_observation: windowedAfter.last_observation });

  assert.ok(candidateAfter, "the candidate must keep re-firing, not disappear, across an intervening overflow tick");
  assert.equal(candidateAfter.diagnostics.z_score, candidateBefore.diagnostics.z_score);
  assert.equal(candidateAfter.severity, candidateBefore.severity);
  assert.equal(windowedBefore.last_observation.has_overflow, false);
  assert.equal(windowedAfter.last_observation.has_overflow, true, "has_overflow flips purely for observability");
});

// ---------------------------------------------------------------------------------------------
// Confidence-state gate + day-1/cold-start no-storm.
// ---------------------------------------------------------------------------------------------

test("buildCountDropCandidate: no candidate below min_sample_count regardless of how extreme the z-score would otherwise be", () => {
  const ticks = [];
  for (let i = 0; i < 10; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(10), 0)); // 11 total groups, well below the default 30
  const groups = groupSessionFactsByTick(flatten(ticks));
  const windowed = computeWindowedSessionStats(groups, { minSampleCount: DEFAULT_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.ok(windowed.last_observation.z_score < -10, "sanity: the underlying z-score IS extreme");
  const candidate = buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined);
});

test("day-1 no-storm: a single complete tick-group's own observation never fires (nothing to compare against yet)", () => {
  const groups = groupSessionFactsByTick(completeTick(tickTs(0), 5));
  const windowed = computeWindowedSessionStats(groups, { minSampleCount: DEFAULT_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.equal(buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation }), undefined);
  assert.deepEqual(detectSessionChurn(completeTick(tickTs(0), 5)), []);
});

// ---------------------------------------------------------------------------------------------
// Exact-zero fold (must-fix 1) + near-zero mass-drop + markerless-legacy skip (must-fix 1) +
// partial skip (must-fix 2), driven end-to-end through computeSessionBaselineCandidates.
// ---------------------------------------------------------------------------------------------

test("EXACT-ZERO fixture (must-fix 1): a complete tick-group with ZERO non-marker session facts folds as a real 0 and fires session.count_drop CRITICAL", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(30), 0)); // exact zero, not merely near-zero
  const candidates = await seedAndCompute(paths, flatten(ticks));
  const dropCandidates = candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.equal(dropCandidates.length, 1);
  const [candidate] = dropCandidates;
  assert.equal(candidate.severity, "critical");
  assert.equal(candidate.diagnostics.observed_count, 0);
  assert.equal(candidate.diagnostics.mean_before, 20);
  assert.equal(candidate.diagnostics.confidence_state, "established");
});

test("near-zero mass-drop fixture: a complete tick-group dropping to 1 (not exactly 0) also fires session.count_drop", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(30), 1));
  const candidates = await seedAndCompute(paths, flatten(ticks));
  const dropCandidates = candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.equal(dropCandidates.length, 1);
  assert.equal(dropCandidates[0].diagnostics.observed_count, 1);
});

test("a moderate drop crosses DEVIATION_SIGMA but not CRITICAL_SIGMA -> severity 'warning', not 'critical'", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(30), 18)); // z = (18-20)/0.5 = -4: <= -3 (fires) but > -5 (not critical)
  const candidates = await seedAndCompute(paths, flatten(ticks));
  const dropCandidates = candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.equal(dropCandidates.length, 1);
  assert.equal(dropCandidates[0].severity, "warning");
});

test("MARKERLESS-LEGACY-TICK skip test (must-fix 1): pre-addendum markerless history is skipped entirely, never folded, never treated as zero, and confidence_state cold-starts fresh from the first marked tick-group", async () => {
  const paths = await tempPaths();
  const legacyPoints = [];
  for (let i = 0; i < 10; i += 1) legacyPoints.push(sessionPoint(tickTs(i), "legacy-e", "fp-legacy")); // no census marker at all

  const markedTicks = [];
  for (let i = 10; i < 40; i += 1) markedTicks.push(completeTick(tickTs(i), 20));

  const points = [...legacyPoints, ...flatten(markedTicks)];
  await seedAndCompute(paths, points);

  const { state } = await loadSessionBaselineStore(paths);
  assert.equal(state.stats.count, 30, "only the 30 marked/complete tick-groups should be folded, not the 10 legacy ones");
  assert.equal(state.confidence_state, "established");
});

test("PARTIAL-CENSUS skip test (must-fix 2): a tick-group carrying a 'partial' marker is excluded from the fold, last_folded_ts still advances, skipped_partial_tick_count increments, and no candidate is derived from it", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 20; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(partialTick(tickTs(20), 2)); // tmux-ok/screen-errored: an undercounted, partial tick
  for (let i = 21; i < 31; i += 1) ticks.push(completeTick(tickTs(i), 20));

  const candidates = await seedAndCompute(paths, flatten(ticks));
  assert.equal(candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID).length, 0, "the partial tick's undercount must never derive a candidate");

  const { state } = await loadSessionBaselineStore(paths);
  assert.equal(state.stats.count, 30, "only the 30 complete tick-groups fold; the partial one is excluded entirely");
  assert.equal(state.skipped_partial_tick_count, 1);
  assert.equal(state.last_folded_ts, tickTs(30), "last_folded_ts advances past the partial tick even though it was skipped");
});

test("GARBLED-CENSUS skip test (adversarial-review regression, mirrors service-baseline's garbled-marker fix): a tick-group carrying a census marker whose census_state is neither 'complete' nor 'partial' is excluded from the fold exactly like 'partial', last_folded_ts still advances, skipped_partial_tick_count is untouched, and no session.count_drop candidate is derived from it even though the tick itself is a mass-drop (near-zero) tick", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  // A garbled/unrecognized census_state marker value on a tick that is ALSO a mass-drop in raw
  // entity count -- if this were silently upgraded to "complete" (the pre-fix ternary's behavior),
  // it would manufacture a false session.count_drop from an empty/garbled census.
  ticks.push([sessionPoint(tickTs(30), "e-0"), censusMarkerPoint(tickTs(30), "truncated-oops")]);

  const candidates = await seedAndCompute(paths, flatten(ticks));
  assert.equal(
    candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID).length,
    0,
    "a garbled census_state marker must never manufacture a fabricated session.count_drop",
  );

  const { state } = await loadSessionBaselineStore(paths);
  assert.equal(state.stats.count, 30, "only the 30 complete tick-groups fold; the garbled one is excluded entirely");
  assert.equal(state.skipped_partial_tick_count, 0, "a garbled census_state is a DISTINCT disposition from 'partial' -- it must not increment the partial counter");
  assert.equal(state.last_folded_ts, tickTs(30), "last_folded_ts advances past the garbled tick even though it was skipped");
});

test("OVERFLOW-tick skip, driven end-to-end (must-fix 5): skipped_overflow_tick_count increments and the tick is excluded from the persisted stats", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(overflowTick(tickTs(30), 500));

  await seedAndCompute(paths, flatten(ticks));
  const { state } = await loadSessionBaselineStore(paths);
  assert.equal(state.stats.count, 30);
  assert.equal(state.skipped_overflow_tick_count, 1);
  assert.equal(state.last_folded_ts, tickTs(30));
});

// ---------------------------------------------------------------------------------------------
// Gradual-drift (no false alarm) + regime-change (recovers without operator action) — must-fix 5.
// ---------------------------------------------------------------------------------------------

test("gradual-drift fixture, pinned to a stated realistic rate (~1 session/day over 15 days): no false alarm at any daily step", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const TICKS_PER_DAY = 24;
  const DAYS = 15; // "2-3 weeks" per the plan; 15 days sits at its lower bound, kept short for test runtime
  let hour = 0;
  for (let day = 0; day < DAYS; day += 1) {
    const count = 30 - day; // ~1 session/day decline, a plausible organic falloff
    const dayPoints = [];
    for (let h = 0; h < TICKS_PER_DAY; h += 1) {
      dayPoints.push(...completeTick(tickTs(hour), count));
      hour += 1;
    }
    const now = tickTs(hour - 1);
    await appendFactPoints(paths, dayPoints, { now });
    const candidates = await computeSessionBaselineCandidates(paths, { now });
    const dropCandidates = candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
    assert.equal(dropCandidates.length, 0, `unexpected session.count_drop candidate on day ${day} (count=${count}): ${JSON.stringify(dropCandidates)}`);
  }
});

test("regime-change fixture: a sustained, legitimate shift from N to M<N eventually RECOVERS (stops firing) without any operator action", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const N = 20;
  const M = 5;
  const baselineTicks = [];
  for (let i = 0; i < 40; i += 1) baselineTicks.push(...completeTick(tickTs(i), N));
  await appendFactPoints(paths, baselineTicks, { now: tickTs(39) });

  let hour = 40;
  let firedImmediatelyAfterShift = false;
  let recoveredAtHour;
  const MAX_ADDITIONAL_TICKS = 20; // hand-verified: this bimodal-variance mix recovers within ~6 ticks
  for (let i = 0; i < MAX_ADDITIONAL_TICKS; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, completeTick(ts, M), { now: ts });
    const candidates = await computeSessionBaselineCandidates(paths, { now: ts });
    const fired = candidates.some((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
    if (i === 0) firedImmediatelyAfterShift = fired;
    if (!fired && recoveredAtHour === undefined) recoveredAtHour = hour;
    hour += 1;
  }

  assert.equal(firedImmediatelyAfterShift, true, "the regime change itself must be detected as a deviation");
  assert.ok(recoveredAtHour !== undefined, "expected session.count_drop to eventually stop firing as the windowed mean/stddev adapt to the new regime");

  // Confirm the recovery is SUSTAINED, not a single flukey non-fire tick.
  for (let i = 0; i < 3; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, completeTick(ts, M), { now: ts });
    const candidates = await computeSessionBaselineCandidates(paths, { now: ts });
    assert.equal(candidates.some((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID), false, `expected sustained recovery, but session.count_drop re-fired at hour ${hour}`);
    hour += 1;
  }
});

// ---------------------------------------------------------------------------------------------
// Re-emission every tick (Decision 3, load-bearing).
// ---------------------------------------------------------------------------------------------

test("re-emission-every-tick: after a deviation candidate fires once, a subsequent call with NO new fact-history still re-emits the identical candidate id", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), 20));
  ticks.push(completeTick(tickTs(30), 0));
  const points = flatten(ticks);
  const now = tickTs(30);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, points, { now });

  const first = await computeSessionBaselineCandidates(paths, { now });
  const second = await computeSessionBaselineCandidates(paths, { now }); // no new fact-history written in between
  const firstDrop = first.find((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
  const secondDrop = second.find((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(firstDrop && secondDrop);
  assert.equal(firstDrop.id, secondDrop.id);
  assert.deepEqual(firstDrop, secondDrop);
});

// ---------------------------------------------------------------------------------------------
// Windowed-recompute idempotency (must-fix 5): repeated calls against unchanged fact-history
// write session-baseline.json AT MOST ONCE and produce byte-identical persisted stats.
// ---------------------------------------------------------------------------------------------

test("windowed-recompute idempotency: repeated calls against the SAME unchanged fact-history write session-baseline.json at most once and leave stats byte-identical", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 5; i += 1) ticks.push(completeTick(tickTs(i), 10));
  const now = tickTs(4);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, flatten(ticks), { now });

  let writeCount = 0;
  const countingWrite = async (descartesPaths, state) => {
    writeCount += 1;
    return writeSessionBaselineStore(descartesPaths, state);
  };

  await computeSessionBaselineCandidates(paths, { now, writeSessionBaselineStore: countingWrite });
  const { state: afterFirst } = await loadSessionBaselineStore(paths);
  await computeSessionBaselineCandidates(paths, { now, writeSessionBaselineStore: countingWrite });
  await computeSessionBaselineCandidates(paths, { now, writeSessionBaselineStore: countingWrite });
  const { state: afterThird } = await loadSessionBaselineStore(paths);

  assert.equal(writeCount, 1, "session-baseline.json must be written at most once across repeated calls with unchanged fact-history");
  assert.deepEqual(afterFirst, afterThird);
});

// ---------------------------------------------------------------------------------------------
// Churn detection (must-fix 4).
// ---------------------------------------------------------------------------------------------

test("session.churn fires on a fingerprint change on an entity in the LATEST tick-group", () => {
  const points = [
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "fp2"), censusMarkerPoint(tickTs(1), "complete"),
  ];
  const churn = detectSessionChurn(points);
  assert.equal(churn.length, 1);
  assert.deepEqual(churn[0], { entity_key: "e1", prior_fingerprint: "fp1", current_fingerprint: "fp2" });
});

test("session.churn non-fire: a single observation never churns (nothing to diff against)", () => {
  const points = [sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete")];
  assert.deepEqual(detectSessionChurn(points), []);
});

test("session.churn non-fire: an unchanged fingerprint across two observations never churns", () => {
  const points = [
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "fp1"), censusMarkerPoint(tickTs(1), "complete"),
  ];
  assert.deepEqual(detectSessionChurn(points), []);
});

test("session.churn non-fire: an 'unknown' fingerprint (the screen-session case) on either side of the pair never churns", () => {
  const olderUnknown = [
    sessionPoint(tickTs(0), "e1", "unknown"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "fp2"), censusMarkerPoint(tickTs(1), "complete"),
  ];
  assert.deepEqual(detectSessionChurn(olderUnknown), []);
  const newerUnknown = [
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "unknown"), censusMarkerPoint(tickTs(1), "complete"),
  ];
  assert.deepEqual(detectSessionChurn(newerUnknown), []);
});

test("session.churn non-fire: a STALE pair (entity churned, then absent from every tick through the latest) does not fire (must-fix 4 recency bound)", () => {
  const points = [
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "fp2"), censusMarkerPoint(tickTs(1), "complete"),
    censusMarkerPoint(tickTs(2), "complete"), // e1 absent from here on
    censusMarkerPoint(tickTs(3), "complete"),
    censusMarkerPoint(tickTs(4), "complete"), // latest complete tick-group
  ];
  assert.deepEqual(detectSessionChurn(points), []);
});

test("session.churn non-fire: pre-existing-history-at-first-run (upgrade-day storm guard, must-fix 4) — weeks of already-differing MARKERLESS fingerprints emit ZERO churn on the first post-deploy call", () => {
  const legacyPoints = [
    sessionPoint(tickTs(0), "e1", "fp-reboot-old"), // no census marker: pre-Slice-4-addendum history
    sessionPoint(tickTs(24), "e1", "fp-reboot-new"), // simulates a reboot recreating the session
  ];
  const firstPostDeployTick = [censusMarkerPoint(tickTs(48), "complete")]; // e1 absent this tick, but the marker exists now
  const churn = detectSessionChurn([...legacyPoints, ...firstPostDeployTick]);
  assert.deepEqual(churn, [], "no upgrade-day storm: legacy markerless history must never fire on first run");
});

test("session.churn: a partial tick-group's own point is excluded from the pool (must-fix 2), but flanking complete observations still churn-compare correctly", () => {
  const points = [
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "fp-partial-noise"), censusMarkerPoint(tickTs(1), "partial"),
    sessionPoint(tickTs(2), "e1", "fp2"), censusMarkerPoint(tickTs(2), "complete"),
  ];
  const churn = detectSessionChurn(points);
  assert.equal(churn.length, 1);
  assert.deepEqual(churn[0], { entity_key: "e1", prior_fingerprint: "fp1", current_fingerprint: "fp2" });
});

test("session.churn non-fire: a garbled/unrecognized census_state marker on the LATEST tick-group does NOT fire, even though the entity's fingerprint genuinely changed (adversarial-review regression, mirrors service-baseline's garbled-marker fix) -- a garbled census must never be treated as 'the latest complete tick-group' anchor", () => {
  const points = [
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "e1", "fp2"), censusMarkerPoint(tickTs(1), "truncated-oops"),
  ];
  assert.deepEqual(detectSessionChurn(points), [], "no other 'complete' tick-group exists in this pool, so the recency-bound anchor can never be satisfied");
});

test("session.churn: an 'unknown'-disposition tick-group's own point is excluded from the pool even when it is NOT the latest tick (adversarial-review regression) -- a garbled census on an OLDER tick must never supply the prior_fingerprint side of a churn pair", () => {
  const points = [
    // tick0's census marker is garbled/unrecognized -> censusState "unknown". Without excluding
    // it from the pool, its session.presence point would wrongly anchor the "prior_fingerprint"
    // side of a churn pair against tick1's genuinely complete, latest observation.
    sessionPoint(tickTs(0), "e1", "fp1"), censusMarkerPoint(tickTs(0), "truncated-garbled"),
    sessionPoint(tickTs(1), "e1", "fp2"), censusMarkerPoint(tickTs(1), "complete"),
  ];
  assert.deepEqual(detectSessionChurn(points), [], "an 'unknown' tick-group's point must never feed either side of a churn pair, including the older side");
});

test("session.churn, driven end-to-end through computeSessionBaselineCandidates", async () => {
  const paths = await tempPaths();
  const points = [
    sessionPoint(tickTs(0), "session.tmux.aaaaaaaaaaaaaaaa", "1111111111111111"),
    censusMarkerPoint(tickTs(0), "complete"),
    sessionPoint(tickTs(1), "session.tmux.aaaaaaaaaaaaaaaa", "2222222222222222"),
    censusMarkerPoint(tickTs(1), "complete"),
  ];
  const candidates = await seedAndCompute(paths, points);
  const churnCandidates = candidates.filter((c) => c.rule_id === SESSION_CHURN_RULE_ID);
  assert.equal(churnCandidates.length, 1);
  assert.equal(churnCandidates[0].diagnostics.entity_key, "session.tmux.aaaaaaaaaaaaaaaa");
  assert.equal(churnCandidates[0].diagnostics.prior_fingerprint, "1111111111111111");
  assert.equal(churnCandidates[0].diagnostics.current_fingerprint, "2222222222222222");
});

test("GARBLED-MARKER end-to-end (adversarial-review regression, mirrors service-baseline's garbled-marker fix): a garbled census_state on the latest tick fires NEITHER session.count_drop NOR session.churn, through computeSessionBaselineCandidates", async () => {
  const paths = await tempPaths();
  const points = [
    sessionPoint(tickTs(0), "session.tmux.aaaaaaaaaaaaaaaa", "1111111111111111"),
    censusMarkerPoint(tickTs(0), "complete"),
    // Latest tick: the same entity's fingerprint changed (would churn) AND the raw entity count
    // dropped to one lone point (would count_drop), but the census marker itself is garbled.
    sessionPoint(tickTs(1), "session.tmux.aaaaaaaaaaaaaaaa", "2222222222222222"),
    censusMarkerPoint(tickTs(1), "truncated-oops"),
  ];
  const candidates = await seedAndCompute(paths, points);
  assert.equal(candidates.filter((c) => c.rule_id === SESSION_CHURN_RULE_ID).length, 0, "a garbled census must never manufacture a fabricated session.churn");
  assert.equal(candidates.filter((c) => c.rule_id === SESSION_COUNT_DROP_RULE_ID).length, 0, "a garbled census must never manufacture a fabricated session.count_drop");
});

test("GARBLED-MARKER on an OLDER (non-latest) tick, end-to-end (adversarial-review regression): a garbled census_state on an EARLIER tick must not supply the prior_fingerprint side of a fabricated session.churn, through computeSessionBaselineCandidates", async () => {
  const paths = await tempPaths();
  const points = [
    // Older tick: census marker is garbled/unrecognized. Its session.presence point must be
    // excluded from the churn pool entirely, not merely disqualified as the "latest" anchor.
    sessionPoint(tickTs(0), "session.tmux.aaaaaaaaaaaaaaaa", "1111111111111111"),
    censusMarkerPoint(tickTs(0), "truncated-garbled"),
    // Latest tick: genuinely complete census, same entity, changed fingerprint.
    sessionPoint(tickTs(1), "session.tmux.aaaaaaaaaaaaaaaa", "2222222222222222"),
    censusMarkerPoint(tickTs(1), "complete"),
  ];
  const candidates = await seedAndCompute(paths, points);
  assert.equal(candidates.filter((c) => c.rule_id === SESSION_CHURN_RULE_ID).length, 0, "a garbled census on an older tick must never manufacture a fabricated session.churn using its point as the prior_fingerprint anchor");
});

// ---------------------------------------------------------------------------------------------
// Fail-closed namespace / candidate shape / sanitized diagnostics.
// ---------------------------------------------------------------------------------------------

test("candidate shape matches the existing extraCandidates sources (buildPublicBindCandidate/buildDeletedExeCandidate) exactly", () => {
  const dropCandidate = buildCountDropCandidate({
    confidence_state: "established",
    last_observation: { ts: tickTs(0), count: 0, z_score: -10, mean_before: 20, stddev_before: 0.5 },
  });
  const [churnCandidate] = buildChurnCandidates([{ entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" }]);
  for (const candidate of [dropCandidate, churnCandidate]) {
    assert.deepEqual(Object.keys(candidate).sort(), ["diagnostics", "evidence_refs", "fingerprint", "id", "rule_id", "severity", "summary", "title"]);
  }
});

test("sanitized-diagnostics assertion: every diagnostics field for both candidate types survives sanitizeDiagnostics() unchanged (numeric/closed-enum/hash only)", () => {
  const dropCandidate = buildCountDropCandidate({
    confidence_state: "established",
    last_observation: { ts: tickTs(0), count: 0, z_score: -10.5, mean_before: 20, stddev_before: 0.5 },
  });
  assert.deepEqual(sanitizeDiagnostics(dropCandidate.diagnostics), dropCandidate.diagnostics);
  assert.equal(JSON.stringify(dropCandidate.diagnostics).includes("redacted"), false);

  const [churnCandidate] = buildChurnCandidates([{ entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" }]);
  assert.deepEqual(sanitizeDiagnostics(churnCandidate.diagnostics), churnCandidate.diagnostics);
  assert(isSafeEnumString(churnCandidate.diagnostics.entity_key));
  assert(isFixedLengthHexHash(churnCandidate.diagnostics.prior_fingerprint));
  assert(isFixedLengthHexHash(churnCandidate.diagnostics.current_fingerprint));
  assert.equal(JSON.stringify(churnCandidate.diagnostics).includes("redacted"), false);
});

test("no raw session name is reachable from this module's candidate diagnostics — inputs are already-hashed by construction (must-fix 3)", () => {
  const [churnCandidate] = buildChurnCandidates([{ entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" }]);
  const serialized = JSON.stringify(churnCandidate);
  assert.equal(/deploy-worker|first-ever-session|worker/.test(serialized), false);
});

// ---------------------------------------------------------------------------------------------
// Store I/O: atomic write shape + corrupt-tolerance + byte-identical-when-disabled.
// ---------------------------------------------------------------------------------------------

test("resolveSessionBaselineStorePaths mirrors provenance-store.js's stateDir/learned convention", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveSessionBaselineStorePaths(paths);
  assert.equal(dir, path.join(paths.stateDir, "learned"));
  assert.equal(storeFile, path.join(paths.stateDir, "learned", "session-baseline.json"));
});

test("loadSessionBaselineStore: ENOENT -> fresh provisional state, no throw", async () => {
  const paths = await tempPaths();
  const { state, corrupt } = await loadSessionBaselineStore(paths);
  assert.equal(corrupt, false);
  assert.equal(state.confidence_state, "provisional");
  assert.equal(state.stats.count, 0);
});

test("loadSessionBaselineStore: corrupt JSON resets to a fresh baseline with corrupt:true, never throws out of a daemon tick", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveSessionBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(storeFile, "{not valid json", "utf8");
  const { state, corrupt } = await loadSessionBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(state.confidence_state, "provisional");

  // computeSessionBaselineCandidates must tolerate the corrupt store and keep working (honest
  // cold-start re-warm-up, not a crashed tick).
  const points = flatten([completeTick(tickTs(0), 5)]);
  const candidates = await seedAndCompute(paths, points);
  assert.deepEqual(candidates, []);
});

test("writeSessionBaselineStore writes 0o600 via atomic tmp+rename (no leftover .tmp file)", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveSessionBaselineStorePaths(paths);
  await writeSessionBaselineStore(paths, { last_folded_ts: tickTs(0) });
  const stat = await fs.stat(storeFile);
  assert.equal(stat.mode & 0o777, 0o600);
  const entries = await fs.readdir(dir);
  assert.equal(entries.some((entry) => entry.endsWith(".tmp")), false);
});

test("computeSessionBaselineCandidates short-circuits to [] before any I/O when learned.json is disabled", async () => {
  const paths = await tempPaths();
  let ioAttempted = false;
  const result = await computeSessionBaselineCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { ioAttempted = true; throw new Error("readFactPoints must not be called while learned.json is disabled"); },
    loadSessionBaselineStore: async () => { ioAttempted = true; throw new Error("loadSessionBaselineStore must not be called while learned.json is disabled"); },
  });
  assert.deepEqual(result, []);
  assert.equal(ioAttempted, false);
});

test("computeSessionBaselineCandidates calls the real (default) loadLearnedConfig when not injected, and returns [] on a fresh state dir (learned.json absent = disabled by default)", async () => {
  const paths = await tempPaths();
  const result = await computeSessionBaselineCandidates(paths, {});
  assert.deepEqual(result, []);
});

// ---------------------------------------------------------------------------------------------
// DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS allowlist (Decision 2b) matches the exported rule_ids.
// ---------------------------------------------------------------------------------------------

test("DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS is exactly [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]", () => {
  assert.deepEqual(DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]);
});
