import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { isSafeEnumString, sanitizeDiagnostics } from "../src/diagnostics-sanitizer.js";
import { appendFactPoints } from "../src/fact-store.js";
import { PEER_OVERFLOW_ENTITY_KEY } from "../src/fact-translators.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_PEER_CRITICAL_SIGMA,
  DEFAULT_PEER_DEVIATION_SIGMA,
  DEFAULT_PEER_MIN_SAMPLE_COUNT,
  DEFAULT_PEER_STDDEV_FLOOR,
  PEER_COUNT_SPIKE_RULE_ID,
  buildCountSpikeCandidate,
  computePeerBaselineCandidates,
  computeWindowedPeerStats,
  groupPeerFactsByTick,
  loadPeerBaselineStore,
  resolvePeerBaselineStorePaths,
  writePeerBaselineStore,
} from "../src/peer-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-peer-baseline-test-"));
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

function peerPoint(ts, entityKey, { presenceState = "observed_active", sourceType = "ssh" } = {}) {
  return {
    ts,
    fact_name: "peer.presence",
    entity_key: entityKey,
    attributes: {
      source_type: sourceType,
      presence_state: presenceState,
      login_hour_bucket: "12",
      handshake_age_bucket: sourceType === "wireguard" ? "lt_1h" : "n/a",
    },
    source_envelope_id: "vpn-peer-status",
    source_tool: "collect_vpn_peer_status",
    sensitivity: "operational",
  };
}

function overflowMarkerPoint(ts) {
  return {
    ts,
    fact_name: "peer.presence",
    entity_key: PEER_OVERFLOW_ENTITY_KEY,
    attributes: { overflow: "true", total_count_bucket: "1000+" },
    source_envelope_id: "vpn-peer-status",
    source_tool: "collect_vpn_peer_status",
    sensitivity: "operational",
    confidence: 0,
  };
}

// A tick-group with `count` currently-active (observed_active) peers, no overflow marker.
function activeTick(ts, count, entityPrefix = "peer.ssh.e") {
  const points = [];
  for (let i = 0; i < count; i += 1) points.push(peerPoint(ts, `${entityPrefix}-${i}`));
  return points;
}

function historicalTick(ts, count, entityPrefix = "peer.ssh.h") {
  const points = [];
  for (let i = 0; i < count; i += 1) points.push(peerPoint(ts, `${entityPrefix}-${i}`, { presenceState: "observed_historical" }));
  return points;
}

// An overflow tick-group: `activeCount` is the collector's own CAPPED observed_active count
// (the true count exceeded DEFAULT_PEER_ENTITY_LIMIT and was truncated before this translator
// ever ran) plus the overflow marker.
function overflowTick(ts, activeCount, entityPrefix = "peer.ssh.e") {
  const points = activeTick(ts, activeCount, entityPrefix);
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
  return computePeerBaselineCandidates(paths, { now, ...options });
}

// ---------------------------------------------------------------------------------------------
// Constants sanity.
// ---------------------------------------------------------------------------------------------

test("DEFAULT_PEER_DEVIATION_SIGMA/CRITICAL_SIGMA/STDDEV_FLOOR/MIN_SAMPLE_COUNT are positive finite constants", () => {
  for (const value of [DEFAULT_PEER_DEVIATION_SIGMA, DEFAULT_PEER_CRITICAL_SIGMA, DEFAULT_PEER_STDDEV_FLOOR, DEFAULT_PEER_MIN_SAMPLE_COUNT]) {
    assert(Number.isFinite(value) && value > 0);
  }
});

test("PEER_COUNT_SPIKE_RULE_ID is 'peer.count_spike'", () => {
  assert.equal(PEER_COUNT_SPIKE_RULE_ID, "peer.count_spike");
});

// ---------------------------------------------------------------------------------------------
// Tick-grouping: observed_active-only counting (Decision 1, hard requirement), overflow marker
// exclusion, and historical-only tick-groups folding as a real zero (Fable review MUST-FIX 2).
// ---------------------------------------------------------------------------------------------

test("groupPeerFactsByTick: count is the number of observed_active (non-overflow) points sharing one ts; observed_historical points are present but NOT counted", () => {
  const groups = groupPeerFactsByTick([...activeTick(tickTs(0), 3), ...historicalTick(tickTs(0), 5)]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].count, 3, "only the 3 observed_active points should count, not the 5 observed_historical ones");
  assert.equal(groups[0].hasOverflow, false);
});

test("groupPeerFactsByTick: an overflow-marked tick-group's hasOverflow is true, and the marker itself is never counted", () => {
  const groups = groupPeerFactsByTick(overflowTick(tickTs(0), 200));
  assert.equal(groups.length, 1);
  assert.equal(groups[0].count, 200);
  assert.equal(groups[0].hasOverflow, true);
});

test("groupPeerFactsByTick: a historical-only tick-group (zero observed_active points) still produces a tick-group with count 0 -- not absent (Fable review MUST-FIX 2, hard requirement)", () => {
  const groups = groupPeerFactsByTick([...activeTick(tickTs(0), 5), ...historicalTick(tickTs(1), 3)]);
  assert.equal(groups.length, 2, "the historical-only tick at hour 1 must still produce its own tick-group");
  assert.equal(groups[1].ts, tickTs(1));
  assert.equal(groups[1].count, 0, "a historical-only tick-group folds as a real, complete ZERO-count observation");
});

test("groupPeerFactsByTick: who-fails/last-succeeds companion fixture -- an SSH-only host whose currently-active count silently drops to zero (envelope still 'ok' because `last` resolved) still produces a tick-group with count 0, not a skip (same depression vector as MUST-FIX 1)", () => {
  const ticks = [];
  for (let i = 0; i < 5; i += 1) ticks.push(...activeTick(tickTs(i), 5));
  ticks.push(...historicalTick(tickTs(5), 5)); // `who` failed this tick; `last` alone still resolved
  const groups = groupPeerFactsByTick(ticks);
  assert.equal(groups.length, 6);
  assert.equal(groups[5].count, 0);
});

test("groupPeerFactsByTick: an unrecognized/missing presence_state defaults to counted (matches fact-translators.js's buildPeerFactPoint ternary default, nice-to-have (i))", () => {
  const point = { ts: tickTs(0), fact_name: "peer.presence", entity_key: "peer.ssh.x", attributes: { source_type: "ssh" } }; // no presence_state at all
  const groups = groupPeerFactsByTick([point]);
  assert.equal(groups[0].count, 1);
});

test("groupPeerFactsByTick: orders tick-groups ascending by ts regardless of input order", () => {
  const groups = groupPeerFactsByTick([...activeTick(tickTs(2), 1), ...activeTick(tickTs(0), 1), ...activeTick(tickTs(1), 1)]);
  assert.deepEqual(groups.map((g) => g.ts), [tickTs(0), tickTs(1), tickTs(2)]);
});

// ---------------------------------------------------------------------------------------------
// z-score-before-fold ordering + STDDEV_FLOOR guard, via computeWindowedPeerStats.
// ---------------------------------------------------------------------------------------------

test("computeWindowedPeerStats: z_score for the latest tick-group is computed against the window EXCLUDING it (self-dampening avoidance)", () => {
  const groups = groupPeerFactsByTick([...activeTick(tickTs(0), 2), ...activeTick(tickTs(1), 2), ...activeTick(tickTs(2), 20)]);
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: 3 });
  assert.equal(windowed.last_observation.mean_before, 2);
  assert.equal(windowed.last_observation.stddev_before, 0);
  assert.equal(windowed.last_observation.z_score, (20 - 2) / DEFAULT_PEER_STDDEV_FLOOR);
  assert.notEqual(windowed.stats.mean, windowed.last_observation.mean_before);
  assert.equal(windowed.stats.mean, (2 + 2 + 20) / 3);
});

test("computeWindowedPeerStats: STDDEV_FLOOR guard prevents a trivial +/-1 fluctuation on a stable low-count baseline from producing a spurious spike", () => {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 3)); // a trivial one-peer fluctuation
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "established");
  assert.equal(windowed.last_observation.z_score, (3 - 2) / DEFAULT_PEER_STDDEV_FLOOR);
  assert.ok(windowed.last_observation.z_score < DEFAULT_PEER_DEVIATION_SIGMA, "a trivial +1 fluctuation must not cross the deviation threshold");
  const candidate = buildCountSpikeCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined);
});

// ---------------------------------------------------------------------------------------------
// Overflow-tick handling: SCORE-BUT-NEVER-FOLD (Fable review MUST-FIX 3, hard requirement) --
// the deliberate divergence from session-baseline.js's session.count_drop (which excludes an
// overflow tick from scoring too).
// ---------------------------------------------------------------------------------------------

test("computeWindowedPeerStats: an overflow tick-group is excluded from the windowed mean/variance recompute (folding), mirrored verbatim from session-baseline.js", () => {
  const ticks = [...activeTick(tickTs(0), 2), ...activeTick(tickTs(1), 2), ...activeTick(tickTs(2), 2), ...overflowTick(tickTs(3), 200)];
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: 3 });
  assert.equal(windowed.stats.count, 3, "the overflow tick-group must not be folded into the windowed stats");
  assert.equal(windowed.stats.mean, 2);
});

test(">cap-burst-fires fixture (Fable review MUST-FIX 3, hard requirement): a burst beyond the peer entity cap STILL fires peer.count_spike, scored at the capped count against the PRE-overflow window stats, while the tick is excluded from the persisted mean/variance recompute", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  const burstTs = tickTs(30);
  const burstPoints = overflowTick(burstTs, 200); // the collector's own capped observed_active count
  const candidates = await seedAndCompute(paths, [...ticks, ...burstPoints], { now: burstTs });

  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(spike, "expected peer.count_spike to STILL fire on a >cap burst (score-but-never-fold)");
  assert.equal(spike.diagnostics.observed_count, 200);
  assert.equal(spike.diagnostics.mean_before, 2);
  assert.equal(spike.severity, "warning");

  const { state } = await loadPeerBaselineStore(paths);
  assert.equal(state.stats.count, 30, "the overflow tick must be excluded from the persisted mean/variance recompute");
  assert.equal(state.stats.mean, 2);
  assert.equal(state.skipped_overflow_tick_count, 1);
  assert.equal(state.last_folded_ts, burstTs, "last_folded_ts still advances past the overflow tick");
});

test("overflow-tick scoring-vs-folding interaction: an overflow tick occurring while peer.count_spike is already active updates z_score using the overflow tick's OWN capped count against the PRE-overflow window stats, while persisted stats/mean/variance/EWMA stay byte-identical (never folded)", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 10)); // z = (10-2)/0.5 = 16 -> already fires
  const beforeTs = tickTs(30);
  const before = await seedAndCompute(paths, ticks, { now: beforeTs });
  const spikeBefore = before.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(spikeBefore, "expected the sustained shift to fire peer.count_spike before the overflow tick");
  const { state: stateBefore } = await loadPeerBaselineStore(paths);

  const overflowTs = tickTs(31);
  await appendFactPoints(paths, overflowTick(overflowTs, 200), { now: overflowTs });
  const after = await computePeerBaselineCandidates(paths, { now: overflowTs });
  const spikeAfter = after.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(spikeAfter, "the candidate must keep re-firing, not disappear, across an intervening overflow tick");
  assert.equal(spikeAfter.diagnostics.observed_count, 200, "scored at the overflow tick's own capped count, not the prior real observation's");
  assert.notEqual(spikeAfter.diagnostics.z_score, spikeBefore.diagnostics.z_score);

  const { state: stateAfter } = await loadPeerBaselineStore(paths);
  assert.deepEqual(stateAfter.stats, stateBefore.stats, "persisted mean/variance/EWMA must be UNCHANGED across the overflow tick");
  assert.equal(stateAfter.skipped_overflow_tick_count, stateBefore.skipped_overflow_tick_count + 1);
});

// ---------------------------------------------------------------------------------------------
// Confidence-state gate + day-1/cold-start no-storm.
// ---------------------------------------------------------------------------------------------

test("buildCountSpikeCandidate: no candidate below min_sample_count regardless of how extreme the z-score would otherwise be (cold-start/day-1 no-storm)", () => {
  const ticks = [];
  for (let i = 0; i < 10; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(10), 200)); // 11 total groups, well below the default 30
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.ok(windowed.last_observation.z_score > 10, "sanity: the underlying z-score IS extreme");
  const candidate = buildCountSpikeCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined);
});

test("day-1 no-storm: a single complete tick-group's own observation never fires (nothing to compare against yet)", () => {
  const groups = groupPeerFactsByTick(activeTick(tickTs(0), 5));
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.equal(buildCountSpikeCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation }), undefined);
});

// ---------------------------------------------------------------------------------------------
// Synthetic spike fixture (core positive case) + severity cap (Fable review MUST-FIX 1, hard
// requirement) + observed_historical exclusion (Decision 1, hard requirement).
// ---------------------------------------------------------------------------------------------

test("synthetic spike fixture: a mass odd-hour peer-login burst fires peer.count_spike at 'warning' severity", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8)); // z = (8-2)/0.5 = 12 >= DEVIATION_SIGMA
  const candidates = await seedAndCompute(paths, ticks);
  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(spike, "expected peer.count_spike to fire on the synthetic burst");
  assert.equal(spike.severity, "warning");
  assert.equal(spike.diagnostics.observed_count, 8);
  assert.equal(spike.diagnostics.mean_before, 2);
  assert.equal(spike.diagnostics.confidence_state, "established");
});

test("MUST-FIX 1 (hard requirement): stored severity is capped at 'warning' UNCONDITIONALLY, even at an extreme z crossing CRITICAL_SIGMA-equivalent magnitude", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 100)); // z = (100-2)/0.5 = 196, wildly beyond CRITICAL_SIGMA=5
  const candidates = await seedAndCompute(paths, ticks);
  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(spike);
  assert.ok(spike.diagnostics.z_score > DEFAULT_PEER_CRITICAL_SIGMA * 10, "sanity: the z-score is extreme");
  assert.equal(spike.severity, "warning", "severity must stay 'warning' even at an extreme z -- never 'critical' in v0");
});

test("observed_historical points are EXCLUDED from the spike count (Decision 1, hard requirement): historical volume alone crossing the threshold must not fire when the active count stays flat", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  const burstTs = tickTs(30);
  const burstPoints = [...activeTick(burstTs, 2), ...historicalTick(burstTs, 50)]; // 50 historical would obviously cross the threshold if wrongly counted
  const candidates = await seedAndCompute(paths, [...ticks, ...burstPoints], { now: burstTs });
  assert.equal(candidates.filter((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID).length, 0, "observed_historical volume must never contribute to the spike count");
});

// ---------------------------------------------------------------------------------------------
// Gradual-drift (no false alarm) + regime-change (recovers without operator action).
// ---------------------------------------------------------------------------------------------

test("gradual-drift fixture, pinned to a stated realistic rate (~1 new peer/week over a month, legitimate onboarding): no false alarm at any weekly step", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const TICKS_PER_DAY = 24;
  const WEEKS = 4;
  let hour = 0;
  for (let week = 0; week < WEEKS; week += 1) {
    const count = 2 + week; // +1 peer/week, a plausible organic onboarding rate
    for (let day = 0; day < 7; day += 1) {
      const dayPoints = [];
      for (let h = 0; h < TICKS_PER_DAY; h += 1) {
        dayPoints.push(...activeTick(tickTs(hour), count));
        hour += 1;
      }
      const now = tickTs(hour - 1);
      await appendFactPoints(paths, dayPoints, { now });
      const candidates = await computePeerBaselineCandidates(paths, { now });
      const spikes = candidates.filter((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
      assert.equal(spikes.length, 0, `unexpected peer.count_spike on week ${week} day ${day} (count=${count}): ${JSON.stringify(spikes)}`);
    }
  }
});

test("regime-change fixture: a sustained, legitimate shift from N to M>N (e.g. 3 new authorized devices permanently added) eventually RECOVERS (stops firing) without any operator action", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const N = 2;
  const M = 5;
  const baselineTicks = [];
  for (let i = 0; i < 40; i += 1) baselineTicks.push(...activeTick(tickTs(i), N));
  await appendFactPoints(paths, baselineTicks, { now: tickTs(39) });

  let hour = 40;
  let firedImmediatelyAfterShift = false;
  let recoveredAtHour;
  const MAX_ADDITIONAL_TICKS = 20;
  for (let i = 0; i < MAX_ADDITIONAL_TICKS; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, activeTick(ts, M), { now: ts });
    const candidates = await computePeerBaselineCandidates(paths, { now: ts });
    const fired = candidates.some((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
    if (i === 0) firedImmediatelyAfterShift = fired;
    if (!fired && recoveredAtHour === undefined) recoveredAtHour = hour;
    hour += 1;
  }

  assert.equal(firedImmediatelyAfterShift, true, "the regime change itself must be detected as a deviation");
  assert.ok(recoveredAtHour !== undefined, "expected peer.count_spike to eventually stop firing as the windowed mean/stddev adapt to the new regime");

  for (let i = 0; i < 3; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, activeTick(ts, M), { now: ts });
    const candidates = await computePeerBaselineCandidates(paths, { now: ts });
    assert.equal(candidates.some((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID), false, `expected sustained recovery, but peer.count_spike re-fired at hour ${hour}`);
    hour += 1;
  }
});

// ---------------------------------------------------------------------------------------------
// Re-emission every tick + windowed-recompute idempotency.
// ---------------------------------------------------------------------------------------------

test("re-emission-every-tick: after a deviation candidate fires once, a subsequent call with NO new fact-history still re-emits the identical candidate id", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8));
  const now = tickTs(30);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, ticks, { now });

  const first = await computePeerBaselineCandidates(paths, { now });
  const second = await computePeerBaselineCandidates(paths, { now });
  const firstSpike = first.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  const secondSpike = second.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(firstSpike && secondSpike);
  assert.equal(firstSpike.id, secondSpike.id);
  assert.deepEqual(firstSpike, secondSpike);
});

test("windowed-recompute idempotency: repeated calls against the SAME unchanged fact-history write peer-baseline.json at most once and leave stats byte-identical", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 5; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  const now = tickTs(4);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, ticks, { now });

  let writeCount = 0;
  const countingWrite = async (descartesPaths, state) => {
    writeCount += 1;
    return writePeerBaselineStore(descartesPaths, state);
  };

  await computePeerBaselineCandidates(paths, { now, writePeerBaselineStore: countingWrite });
  const { state: afterFirst } = await loadPeerBaselineStore(paths);
  await computePeerBaselineCandidates(paths, { now, writePeerBaselineStore: countingWrite });
  await computePeerBaselineCandidates(paths, { now, writePeerBaselineStore: countingWrite });
  const { state: afterThird } = await loadPeerBaselineStore(paths);

  assert.equal(writeCount, 1, "peer-baseline.json must be written at most once across repeated calls with unchanged fact-history");
  assert.deepEqual(afterFirst, afterThird);
});

// ---------------------------------------------------------------------------------------------
// Candidate shape + sanitized diagnostics + no raw peer identifier reachable.
// ---------------------------------------------------------------------------------------------

test("candidate shape matches the existing extraCandidates sources (buildCountDropCandidate/buildChurnCandidates) exactly", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8));
  const candidates = await seedAndCompute(paths, ticks);
  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(spike);
  assert.equal(typeof spike.id, "string");
  assert.equal(spike.fingerprint, "global");
  assert.equal(typeof spike.title, "string");
  assert.equal(typeof spike.summary, "string");
  assert.equal(typeof spike.diagnostics, "object");
  assert.deepEqual(spike.evidence_refs, ["peer-baseline"]);
  assert.equal(JSON.stringify(spike.diagnostics).includes("redacted"), false);
});

test("sanitized-diagnostics assertion: every diagnostics field survives sanitizeDiagnostics() unchanged (numeric/closed-enum only)", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8));
  const candidates = await seedAndCompute(paths, ticks);
  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.deepEqual(sanitizeDiagnostics(spike.diagnostics), spike.diagnostics);
  assert(isSafeEnumString(spike.diagnostics.confidence_state));
  for (const key of ["observed_count", "mean_before", "stddev_before", "z_score"]) {
    assert.equal(typeof spike.diagnostics[key], "number");
    assert.ok(Number.isFinite(spike.diagnostics[key]));
  }
});

test("no raw peer host/IP/pubkey is reachable from this module's candidate diagnostics -- v0's global count-only signal never reads per-peer attributes at all", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8, "peer.ssh.definitely-not-a-hash"));
  const candidates = await seedAndCompute(paths, ticks);
  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  const serialized = JSON.stringify(spike);
  assert.equal(/definitely-not-a-hash|203\.0\.113|alice/.test(serialized), false);
});

// ---------------------------------------------------------------------------------------------
// Store I/O: atomic write shape + corrupt-tolerance + byte-identical-when-disabled.
// ---------------------------------------------------------------------------------------------

test("resolvePeerBaselineStorePaths mirrors session-baseline.js's stateDir/learned convention", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolvePeerBaselineStorePaths(paths);
  assert.equal(dir, path.join(paths.stateDir, "learned"));
  assert.equal(storeFile, path.join(paths.stateDir, "learned", "peer-baseline.json"));
});

test("loadPeerBaselineStore: ENOENT -> fresh provisional state, no throw", async () => {
  const paths = await tempPaths();
  const { state, corrupt } = await loadPeerBaselineStore(paths);
  assert.equal(corrupt, false);
  assert.equal(state.confidence_state, "provisional");
  assert.equal(state.stats.count, 0);
});

test("loadPeerBaselineStore: corrupt JSON resets to a fresh baseline with corrupt:true, never throws out of a daemon tick", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolvePeerBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(storeFile, "{not valid json", "utf8");
  const { state, corrupt } = await loadPeerBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(state.confidence_state, "provisional");

  const candidates = await seedAndCompute(paths, activeTick(tickTs(0), 2));
  assert.deepEqual(candidates, []);
});

test("writePeerBaselineStore writes 0o600 via atomic tmp+rename (no leftover .tmp file)", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolvePeerBaselineStorePaths(paths);
  await writePeerBaselineStore(paths, { last_folded_ts: tickTs(0) });
  const stat = await fs.stat(storeFile);
  assert.equal(stat.mode & 0o777, 0o600);
  const entries = await fs.readdir(dir);
  assert.equal(entries.some((entry) => entry.endsWith(".tmp")), false);
});

test("computePeerBaselineCandidates short-circuits to [] before any I/O when learned.json is disabled", async () => {
  const paths = await tempPaths();
  let ioAttempted = false;
  const result = await computePeerBaselineCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { ioAttempted = true; throw new Error("readFactPoints must not be called while learned.json is disabled"); },
    loadPeerBaselineStore: async () => { ioAttempted = true; throw new Error("loadPeerBaselineStore must not be called while learned.json is disabled"); },
  });
  assert.deepEqual(result, []);
  assert.equal(ioAttempted, false);
});

test("computePeerBaselineCandidates calls the real (default) loadLearnedConfig when not injected, and returns [] on a fresh state dir (learned.json absent = disabled by default)", async () => {
  const paths = await tempPaths();
  const result = await computePeerBaselineCandidates(paths, {});
  assert.deepEqual(result, []);
});
