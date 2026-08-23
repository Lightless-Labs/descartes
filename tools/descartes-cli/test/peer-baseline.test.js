import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { isSafeEnumString, sanitizeDiagnostics } from "../src/diagnostics-sanitizer.js";
import { appendFactPoints } from "../src/fact-store.js";
import { PEER_CENSUS_MARKER_ENTITY_KEY, PEER_OVERFLOW_ENTITY_KEY, factPointsFromTailscaleStatusEvidence } from "../src/fact-translators.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_PEER_CRITICAL_SIGMA,
  DEFAULT_PEER_DEVIATION_SIGMA,
  DEFAULT_PEER_MIN_SAMPLE_COUNT,
  DEFAULT_PEER_STDDEV_FLOOR,
  PEER_COUNT_DROP_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  buildCountDropCandidate,
  buildCountSpikeCandidate,
  computePeerBaselineCandidates,
  computeWindowedPeerDropStats,
  computeWindowedPeerStats,
  groupPeerFactsByTick,
  loadPeerBaselineStore,
  normalizePeerBaselineState,
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

// Slice 4c fixtures -------------------------------------------------------------------------

const DEFAULT_SIGNATURE = "v1:ok-ok-ok-ok-ok";

function censusMarkerPoint(ts, signature = DEFAULT_SIGNATURE) {
  return {
    ts,
    fact_name: "peer.presence",
    entity_key: PEER_CENSUS_MARKER_ENTITY_KEY,
    attributes: { availability_signature: signature },
    source_envelope_id: "vpn-peer-status",
    source_tool: "collect_vpn_peer_status",
    sensitivity: "operational",
    confidence: 0,
  };
}

// A tick-group with `count` currently-active peers PLUS a well-formed census marker (Slice 4c) --
// the shape peer.count_drop needs to ever consider a tick-group foldable ("complete", per
// dropTickGroupDisposition).
function activeTickWithMarker(ts, count, signature = DEFAULT_SIGNATURE, entityPrefix = "peer.ssh.e") {
  return [...activeTick(ts, count, entityPrefix), censusMarkerPoint(ts, signature)];
}

// An overflow tick-group that ALSO carries a census marker -- dropTickGroupDisposition checks
// hasOverflow FIRST, so this still classifies as "overflow" (excluded from drop's scoring AND
// folding, Decision 0.1) regardless of the marker's presence/signature.
function overflowTickWithMarker(ts, activeCount, signature = DEFAULT_SIGNATURE, entityPrefix = "peer.ssh.e") {
  return [...activeTick(ts, activeCount, entityPrefix), overflowMarkerPoint(ts), censusMarkerPoint(ts, signature)];
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

function tailscalePoints(ts, peers) {
  return factPointsFromTailscaleStatusEvidence([{
    id: "tailscale-status",
    status: "ok",
    result: { peers },
    trace: { tool: "collect_tailscale_status" },
  }], { ts });
}

function tailscalePeer(index, presenceState = "observed_active") {
  return {
    source_type: "tailscale",
    presence_state: presenceState,
    node_public_key: `tailscale-key-${index}`,
    is_exit_node_active: false,
    is_exit_node_option: false,
    latest_handshake_epoch_seconds: 0,
  };
}

function flatten(groupsOfPoints) {
  return groupsOfPoints.flat();
}

// Fact-store completeness hardening (Slice 5) fixtures, mirroring session-baseline.test.js's
// intactReadResult/degradedReadResult exactly -- injected via options.readFactPoints so the
// dedicated cold-start tests below don't need to fabricate real ledger corruption/eviction.
function intactReadResult(points) {
  return {
    points,
    corrupt_count: 0,
    schema_invalid_count: 0,
    completeness: { status: "intact" },
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

async function seedAndCompute(paths, points, options = {}) {
  const lastTs = points.reduce((max, p) => Math.max(max, new Date(p.ts).getTime()), 0);
  const now = options.now ?? new Date(lastTs).toISOString();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 5) gave peer-baseline.js its own persistent
  // cold-start lockout, mirroring process-lineage-baseline.js's/session-baseline.js's own: a
  // brand-new store starts cold_start_pending, and a single one-shot append+compute call (exactly
  // this helper's shape) can never itself satisfy re-establishment (all of `points`' history
  // necessarily predates the anchor a fresh lockout would set on its own first read). Every test
  // below this helper predates Slice 5 and is about peer-baseline's OTHER logic (Welford folding,
  // regime-keyed fold, tick-disposition skips, ...), not the lockout itself -- so, mirroring
  // session-baseline.test.js's own precedent, this helper pre-establishes the store (anchored
  // strictly before the fixture's own earliest point) and confirms the shared integrity ledger to
  // 'intact' (a fresh ledger's first retention pass is deliberately 'unknown' -- bootstrap
  // anti-laundering rule; a second clean pass confirms it) so callers keep exercising exactly what
  // they always tested. The lockout mechanism itself has its own dedicated coverage further down
  // in this file.
  const firstTs = points.reduce((min, p) => Math.min(min, new Date(p.ts).getTime()), Infinity);
  const establishedAnchor = Number.isFinite(firstTs) ? new Date(firstTs - 1).toISOString() : now;
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: establishedAnchor });
  await appendFactPoints(paths, points, { now });
  await appendFactPoints(paths, [], { now });
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

test("PEER_COUNT_DROP_RULE_ID is 'peer.count_drop'", () => {
  assert.equal(PEER_COUNT_DROP_RULE_ID, "peer.count_drop");
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

test("groupPeerFactsByTick: VPN and Tailscale peer points sharing one tick sum into one combined count", () => {
  const ts = tickTs(0);
  const groups = groupPeerFactsByTick([
    ...activeTickWithMarker(ts, 2),
    ...tailscalePoints(ts, [tailscalePeer(1), tailscalePeer(2)]),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].count, 4);
  assert.equal(groups[0].availabilitySignature, DEFAULT_SIGNATURE);
});

test("Tailscale-only markerless ticks stay provisional for drop detection while spike detection establishes", () => {
  const points = [];
  for (let i = 0; i < DEFAULT_PEER_MIN_SAMPLE_COUNT; i += 1) {
    points.push(...tailscalePoints(tickTs(i), [tailscalePeer(`${i}-a`), tailscalePeer(`${i}-b`)]));
  }
  // A historical-only point creates a truthful zero-count tick-group without fabricating a
  // census marker. A completely empty Tailscale Peer map creates no peer.presence tick-group.
  points.push(...tailscalePoints(tickTs(DEFAULT_PEER_MIN_SAMPLE_COUNT), [tailscalePeer("historical", "observed_historical")]));

  const groups = groupPeerFactsByTick(points);
  assert.equal(groups.length, DEFAULT_PEER_MIN_SAMPLE_COUNT + 1);
  assert.equal(groups.every((group) => group.availabilitySignature === undefined), true);
  assert.equal(groups.at(-1).count, 0);

  const drop = computeWindowedPeerDropStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(drop.confidence_state, "provisional");
  assert.equal(drop.last_observation, undefined);

  const spike = computeWindowedPeerStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(spike.confidence_state, "established");
  assert.equal(spike.last_observation.count, 0);
});

// ---------------------------------------------------------------------------------------------
// Census marker + availability signature (Slice 4c) -- groupPeerFactsByTick.
// ---------------------------------------------------------------------------------------------

test("groupPeerFactsByTick: a marker-bearing tick-group surfaces availabilitySignature, and the marker itself is never counted", () => {
  const groups = groupPeerFactsByTick(activeTickWithMarker(tickTs(0), 3, "v1:ok-ok-partial-ok-ok"));
  assert.equal(groups.length, 1);
  assert.equal(groups[0].count, 3, "the marker itself must not be counted as a peer");
  assert.equal(groups[0].availabilitySignature, "v1:ok-ok-partial-ok-ok");
});

test("groupPeerFactsByTick: a marker-less legacy tick-group still produces availabilitySignature: undefined (backward-compat pin)", () => {
  const groups = groupPeerFactsByTick(activeTick(tickTs(0), 3));
  assert.equal(groups.length, 1);
  assert.equal(groups[0].availabilitySignature, undefined);
});

test("groupPeerFactsByTick: a marker point with a non-string/missing availability_signature attribute coerces to undefined, indistinguishable from a marker-less group (Decision 6 sentinel unification)", () => {
  const malformedMarker = { ...censusMarkerPoint(tickTs(0)), attributes: { availability_signature: 12345 } };
  const groupsMalformed = groupPeerFactsByTick([...activeTick(tickTs(0), 3), malformedMarker]);
  assert.equal(groupsMalformed[0].availabilitySignature, undefined);

  const missingAttrMarker = { ...censusMarkerPoint(tickTs(1)), attributes: {} };
  const groupsMissing = groupPeerFactsByTick([...activeTick(tickTs(1), 2), missingAttrMarker]);
  assert.equal(groupsMissing[0].availabilitySignature, undefined);
});

test("groupPeerFactsByTick: a GARBLED-BUT-STRING-TYPED availability_signature (e.g. empty string, or a shape that does not match buildPeerAvailabilitySignature's 'v1:<5 closed-enum codes>' format) coerces to undefined -- a type-only guard is NOT enough (Stage 2 adversarial-review fix, 2026-07-23)", () => {
  for (const garbled of ["", "garbage", "v1:ok-ok-ok-ok", "v1:ok-ok-ok-ok-ok-ok", "v2:ok-ok-ok-ok-ok", "v1:ok-ok-injected-ok-ok", "not-even-versioned"]) {
    const marker = { ...censusMarkerPoint(tickTs(0)), attributes: { availability_signature: garbled } };
    const groups = groupPeerFactsByTick([...activeTick(tickTs(0), 3), marker]);
    assert.equal(groups[0].availabilitySignature, undefined, `expected garbled signature ${JSON.stringify(garbled)} to coerce to undefined`);
  }
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
  // Fact-store completeness hardening (Slice 5): this fixture only asserts the ABSENCE of a false
  // spike at every step, so a cold-start suppression (which also yields zero candidates) can never
  // invalidate that assertion -- left un-pre-seeded on purpose, mirroring
  // session-baseline.test.js's own identically-shaped gradual-drift fixture, which is likewise
  // left unmodified by the lockout slice for the same reason.
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
  // Fact-store completeness hardening (Slice 5): pre-establish the cold-start lockout (see
  // seedAndCompute's comment above) -- this fixture drives appendFactPoints/
  // computePeerBaselineCandidates directly rather than through seedAndCompute, so it needs the
  // same pre-seed + ledger-confirmation applied by hand.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  const N = 2;
  const M = 5;
  const baselineTicks = [];
  for (let i = 0; i < 40; i += 1) baselineTicks.push(...activeTick(tickTs(i), N));
  await appendFactPoints(paths, baselineTicks, { now: tickTs(39) });
  await appendFactPoints(paths, [], { now: tickTs(39) }); // confirm the integrity ledger to 'intact'

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
// Regime-keyed fold (Slice 4c, Decision 2(c)) -- computeWindowedPeerStats (spike), the retroactive
// fix for the accepted false-positive class named in the Slice 4b plan.
// ---------------------------------------------------------------------------------------------

test("computeWindowedPeerStats regime-keyed fold: a mixed-regime fixture (N ticks degraded, then ONE recovery tick at a new signature) does NOT false-fire peer.count_spike on the recovery tick", () => {
  const degradedSignature = "v1:ok-ok-missing_permission-ok-ok";
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 1, degradedSignature));
  ticks.push(...activeTickWithMarker(tickTs(30), 5, DEFAULT_SIGNATURE)); // recovery: true count was always 5
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });

  // The new regime has exactly ONE same-signature sample -- an honest re-warm-up, never
  // "established" off a single tick, regardless of how large the underlying jump looks.
  assert.equal(windowed.confidence_state, "provisional");
  const candidate = buildCountSpikeCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined, "the regime flip itself must never fire a false spike");
});

test("computeWindowedPeerStats regime-keyed fold: confidence_state resets to 'provisional' immediately on a regime flip, even though the OLD regime was already 'established'", () => {
  const degradedSignature = "v1:ok-ok-missing_permission-ok-ok";
  const preFlipTicks = [];
  for (let i = 0; i < 30; i += 1) preFlipTicks.push(...activeTickWithMarker(tickTs(i), 1, degradedSignature));
  const preFlipGroups = groupPeerFactsByTick(preFlipTicks);
  const preFlipWindowed = computeWindowedPeerStats(preFlipGroups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(preFlipWindowed.confidence_state, "established", "sanity: the OLD (degraded) regime was established before the flip");

  const postFlipTicks = [...preFlipTicks, ...activeTickWithMarker(tickTs(30), 5, DEFAULT_SIGNATURE)];
  const postFlipGroups = groupPeerFactsByTick(postFlipTicks);
  const postFlipWindowed = computeWindowedPeerStats(postFlipGroups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(postFlipWindowed.confidence_state, "provisional", "the new regime must re-warm-up from scratch, not inherit the old regime's established confidence");
});

test("computeWindowedPeerStats regime-keyed fold: fully marker-less fixtures are a true no-op (backward-compat) -- the existing gradual-drift/regime-change tests above already pin this unmodified", () => {
  // This test exists purely to document the claim explicitly (plan §6): every fixture in the
  // "gradual-drift" and "regime-change" test blocks above never emits a census marker, so every
  // tick-group's availabilitySignature is undefined throughout, `undefined === undefined` is
  // always true, and the regime predicate never excludes anything. Those tests passing unmodified
  // (see this file's own suite run) IS the regression pin for this claim.
  const ticks = [];
  for (let i = 0; i < 5; i += 1) ticks.push(...activeTick(tickTs(i), 2)); // no marker, matches legacy fact-history
  const groups = groupPeerFactsByTick(ticks);
  assert.ok(groups.every((g) => g.availabilitySignature === undefined));
  const windowed = computeWindowedPeerStats(groups, { minSampleCount: 3 });
  assert.equal(windowed.stats.count, 5, "every marker-less group folds normally when the regime predicate is a no-op");
});

test("computeWindowedPeerStats regime-keyed fold: TRANSITIONAL post-upgrade mixed-window test -- N marker-less legacy tick-groups (already >= min_sample_count on their own) followed by ONE marker-bearing tick-group resets confidence_state to 'provisional' (one-time, honest, accepted cost, §2c)", () => {
  const ticks = [];
  for (let i = 0; i < DEFAULT_PEER_MIN_SAMPLE_COUNT + 5; i += 1) ticks.push(...activeTick(tickTs(i), 2)); // legacy, no marker
  const upgradeTs = tickTs(DEFAULT_PEER_MIN_SAMPLE_COUNT + 5);
  ticks.push(...activeTickWithMarker(upgradeTs, 2, DEFAULT_SIGNATURE)); // first post-upgrade tick

  assert.doesNotThrow(() => {
    const groups = groupPeerFactsByTick(ticks);
    const windowed = computeWindowedPeerStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
    assert.equal(
      windowed.confidence_state,
      "provisional",
      "despite the marker-less legacy history alone being large enough to satisfy min_sample_count, the first marker-bearing tick starts its own regime from zero",
    );
    const candidate = buildCountSpikeCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
    assert.equal(candidate, undefined, "no spike candidate is built off the reset");
  });
});

// ---------------------------------------------------------------------------------------------
// peer.count_drop -- computeWindowedPeerDropStats (Slice 4c). Mirrors computeWindowedPeerStats'
// own test shapes above, sign-flipped, plus the exclude-from-BOTH overflow contrast (Decision 0.1)
// and the cold-start-forever-without-the-marker pin.
// ---------------------------------------------------------------------------------------------

test("computeWindowedPeerDropStats: z_score for the latest eligible tick-group is computed against the window EXCLUDING it (self-dampening avoidance)", () => {
  const groups = groupPeerFactsByTick([...activeTickWithMarker(tickTs(0), 2), ...activeTickWithMarker(tickTs(1), 2), ...activeTickWithMarker(tickTs(2), 0)]);
  const windowed = computeWindowedPeerDropStats(groups, { minSampleCount: 3 });
  assert.equal(windowed.last_observation.mean_before, 2);
  assert.equal(windowed.last_observation.stddev_before, 0);
  assert.equal(windowed.last_observation.z_score, (0 - 2) / DEFAULT_PEER_STDDEV_FLOOR);
  assert.notEqual(windowed.stats.mean, windowed.last_observation.mean_before);
});

test("computeWindowedPeerDropStats: STDDEV_FLOOR guard prevents a trivial -1 fluctuation on a stable low-count baseline from producing a spurious drop", () => {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 3));
  ticks.push(...activeTickWithMarker(tickTs(30), 2)); // a trivial one-peer fluctuation down
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerDropStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "established");
  assert.equal(windowed.last_observation.z_score, (2 - 3) / DEFAULT_PEER_STDDEV_FLOOR);
  assert.ok(windowed.last_observation.z_score > -DEFAULT_PEER_DEVIATION_SIGMA, "a trivial -1 fluctuation must not cross the deviation threshold");
  const candidate = buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined);
});

test("computeWindowedPeerDropStats: an overflow tick-group is EXCLUDED from BOTH scoring and folding -- contrast with peer.count_spike's own score-but-never-fold (Decision 0.1)", () => {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 5));
  const overflowTs = tickTs(30);
  ticks.push(...overflowTickWithMarker(overflowTs, 200));
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerDropStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.stats.count, 30, "the overflow tick-group must not be folded into the windowed stats");
  assert.notEqual(windowed.last_observation.ts, overflowTs, "the overflow tick must not even be SCORED -- last_observation stays pinned to the prior real tick");
  assert.notEqual(windowed.last_observation.count, 200);
});

test("computeWindowedPeerDropStats: a marker-less-only fixture (pre-Slice-4c fact-history) NEVER reaches 'established' -- cold-start-forever-without-the-marker pin", () => {
  const ticks = [];
  for (let i = 0; i < 50; i += 1) ticks.push(...activeTick(tickTs(i), 2)); // no marker at all
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerDropStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.equal(windowed.stats.count, 0, "a markerless tick-group can never be 'complete' for the drop direction, so nothing ever folds");
  assert.equal(buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation }), undefined);
});

test("computeWindowedPeerDropStats day-1 no-storm: a single complete (marker-bearing) tick-group's own observation never fires (nothing to compare against yet)", () => {
  const groups = groupPeerFactsByTick(activeTickWithMarker(tickTs(0), 5));
  const windowed = computeWindowedPeerDropStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.equal(buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation }), undefined);
});

// ---------------------------------------------------------------------------------------------
// buildCountDropCandidate -- confidence gate, sign/guard, hard-capped severity (Decision 0).
// ---------------------------------------------------------------------------------------------

test("buildCountDropCandidate: no candidate below min_sample_count regardless of how extreme the z-score would otherwise be (cold-start/day-1 no-storm)", () => {
  const ticks = [];
  for (let i = 0; i < 10; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 20));
  ticks.push(...activeTickWithMarker(tickTs(10), 0)); // 11 total groups, well below the default 30
  const groups = groupPeerFactsByTick(ticks);
  const windowed = computeWindowedPeerDropStats(groups, { minSampleCount: DEFAULT_PEER_MIN_SAMPLE_COUNT });
  assert.equal(windowed.confidence_state, "provisional");
  assert.ok(windowed.last_observation.z_score < -10, "sanity: the underlying z-score IS extreme");
  const candidate = buildCountDropCandidate({ confidence_state: windowed.confidence_state, last_observation: windowed.last_observation });
  assert.equal(candidate, undefined);
});

test("buildCountDropCandidate: fires at z <= -DEVIATION_SIGMA AND count < mean_before", () => {
  const state = { confidence_state: "established", last_observation: { ts: tickTs(0), count: 1, z_score: -6, mean_before: 10, stddev_before: 1.5 } };
  const candidate = buildCountDropCandidate(state);
  assert.ok(candidate);
  assert.equal(candidate.rule_id, PEER_COUNT_DROP_RULE_ID);
});

test("buildCountDropCandidate: does not fire when z <= -DEVIATION_SIGMA but count is NOT < mean_before (defense-in-depth guard, redundant given a negative z)", () => {
  const state = { confidence_state: "established", last_observation: { ts: tickTs(0), count: 10, z_score: -6, mean_before: 10, stddev_before: 1.5 } };
  const candidate = buildCountDropCandidate(state);
  assert.equal(candidate, undefined);
});

test("synthetic drop fixture: a mass peer-drop-to-near-zero fires peer.count_drop at 'warning' severity", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 10));
  ticks.push(...activeTickWithMarker(tickTs(30), 1)); // z = (1-10)/0.5 = -18 <= -DEVIATION_SIGMA
  const candidates = await seedAndCompute(paths, ticks);
  const drop = candidates.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  assert.ok(drop, "expected peer.count_drop to fire on the synthetic mass drop");
  assert.equal(drop.severity, "warning");
  assert.equal(drop.diagnostics.observed_count, 1);
  assert.equal(drop.diagnostics.mean_before, 10);
  assert.equal(drop.diagnostics.confidence_state, "established");
});

test("Stage 2 adversarial-review regression (hard requirement): a garbled-but-string-typed availability_signature (e.g. '') must NEVER establish a poolable regime or fire peer.count_drop/peer.count_spike -- PoC from the adversarial verify, exact repro (30 ticks at count 10 + 1 tick at count 1, all sharing the SAME garbled '' signature)", async () => {
  const paths = await tempPaths();
  const garbledSignature = ""; // never producible by buildPeerAvailabilitySignature, but was previously legal per the code's own type-only guard
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 10, garbledSignature));
  ticks.push(...activeTickWithMarker(tickTs(30), 1, garbledSignature)); // would have been z = (1-10)/0.5 = -18 pre-fix
  const candidates = await seedAndCompute(paths, ticks);
  const drop = candidates.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  const spike = candidates.find((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(drop, undefined, "a garbled signature must never establish a drop-direction regime baseline");
  assert.equal(spike, undefined, "a garbled signature must never establish a spike-direction regime baseline either");

  const windowedDrop = computeWindowedPeerDropStats(groupPeerFactsByTick(ticks));
  assert.equal(windowedDrop.confidence_state, "provisional", "every tick-group must classify as markerless (garbled signature), never 'complete'");
});

test("EXACT-ZERO drop fixture: a genuine zero-peer tick (the census marker's whole reason for existing) fires as a real, foldable zero, not a fabricated/skipped one", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 5));
  ticks.push(censusMarkerPoint(tickTs(30))); // genuinely zero peers this tick, marker still present
  const candidates = await seedAndCompute(paths, ticks);
  const drop = candidates.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  assert.ok(drop, "expected peer.count_drop to fire on a genuine drop to exact zero");
  assert.equal(drop.diagnostics.observed_count, 0);
});

test("MUST-FIX-1-equivalent (hard requirement): stored severity is capped at 'warning' UNCONDITIONALLY for peer.count_drop, even at an extreme z crossing CRITICAL_SIGMA-equivalent magnitude", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 100));
  ticks.push(...activeTickWithMarker(tickTs(30), 0)); // z = (0-100)/0.5 = -200, wildly beyond -CRITICAL_SIGMA
  const candidates = await seedAndCompute(paths, ticks);
  const drop = candidates.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  assert.ok(drop);
  assert.ok(drop.diagnostics.z_score < -DEFAULT_PEER_CRITICAL_SIGMA * 10, "sanity: the z-score is extreme");
  assert.equal(drop.severity, "warning", "severity must stay 'warning' even at an extreme z -- never 'critical' in v0");
});

test("chronic-degradation-then-recovery sequence: a signature flip from a degraded regime (spuriously low count) to a healthy regime (true count) does NOT false-fire peer.count_spike (the pre-Slice-4c accepted FP class) NOR peer.count_drop, and settles cleanly once the new regime accumulates its own baseline", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const degradedSignature = "v1:ok-ok-missing_permission-ok-ok";
  let hour = 0;
  for (let i = 0; i < 35; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, activeTickWithMarker(ts, 1, degradedSignature), { now: ts });
    hour += 1;
  }

  let anyFalseFire = false;
  for (let i = 0; i < 35; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, activeTickWithMarker(ts, 5, DEFAULT_SIGNATURE), { now: ts });
    const candidates = await computePeerBaselineCandidates(paths, { now: ts });
    if (candidates.length > 0) anyFalseFire = true;
    hour += 1;
  }
  assert.equal(anyFalseFire, false, "the regime flip itself, and the new regime's own re-warm-up, must never fire a false spike or drop");

  const finalTs = tickTs(hour);
  await appendFactPoints(paths, activeTickWithMarker(finalTs, 5, DEFAULT_SIGNATURE), { now: finalTs });
  const finalCandidates = await computePeerBaselineCandidates(paths, { now: finalTs });
  assert.equal(finalCandidates.length, 0, "the fully-established new regime must recover cleanly, firing neither direction on a steady count");
});

test("re-emission-every-tick (drop): after a peer.count_drop candidate fires once, a subsequent call with NO new fact-history still re-emits the identical candidate id", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 10));
  ticks.push(...activeTickWithMarker(tickTs(30), 1));
  const now = tickTs(30);
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 5): pre-establish the cold-start lockout (see
  // seedAndCompute's comment above) -- this fixture drives appendFactPoints/
  // computePeerBaselineCandidates directly.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, ticks, { now });
  await appendFactPoints(paths, [], { now }); // confirm the integrity ledger to 'intact'

  const first = await computePeerBaselineCandidates(paths, { now });
  const second = await computePeerBaselineCandidates(paths, { now });
  const firstDrop = first.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  const secondDrop = second.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  assert.ok(firstDrop && secondDrop);
  assert.equal(firstDrop.id, secondDrop.id);
  assert.deepEqual(firstDrop, secondDrop);
});

test("computePeerBaselineCandidates: returns [], [spike-only], or [drop-only] depending on which direction's conditions are independently met (array-return shape coverage)", async () => {
  const pathsNone = await tempPaths();
  const flatTicks = [];
  for (let i = 0; i < 30; i += 1) flatTicks.push(...activeTickWithMarker(tickTs(i), 5));
  flatTicks.push(...activeTickWithMarker(tickTs(30), 5));
  const noneCandidates = await seedAndCompute(pathsNone, flatTicks);
  assert.deepEqual(noneCandidates.map((c) => c.rule_id), []);

  const pathsSpike = await tempPaths();
  const spikeTicks = [];
  for (let i = 0; i < 30; i += 1) spikeTicks.push(...activeTickWithMarker(tickTs(i), 2));
  spikeTicks.push(...activeTickWithMarker(tickTs(30), 8));
  const spikeCandidates = await seedAndCompute(pathsSpike, spikeTicks);
  assert.deepEqual(spikeCandidates.map((c) => c.rule_id), [PEER_COUNT_SPIKE_RULE_ID]);

  const pathsDrop = await tempPaths();
  const dropTicks = [];
  for (let i = 0; i < 30; i += 1) dropTicks.push(...activeTickWithMarker(tickTs(i), 10));
  dropTicks.push(...activeTickWithMarker(tickTs(30), 1));
  const dropCandidates = await seedAndCompute(pathsDrop, dropTicks);
  assert.deepEqual(dropCandidates.map((c) => c.rule_id), [PEER_COUNT_DROP_RULE_ID]);
});

test("sanitized-diagnostics assertion (drop): every diagnostics field survives sanitizeDiagnostics() unchanged (numeric/closed-enum only)", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 10));
  ticks.push(...activeTickWithMarker(tickTs(30), 1));
  const candidates = await seedAndCompute(paths, ticks);
  const drop = candidates.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  assert.deepEqual(sanitizeDiagnostics(drop.diagnostics), drop.diagnostics);
  assert(isSafeEnumString(drop.diagnostics.confidence_state));
  for (const key of ["observed_count", "mean_before", "stddev_before", "z_score"]) {
    assert.equal(typeof drop.diagnostics[key], "number");
    assert.ok(Number.isFinite(drop.diagnostics[key]));
  }
});

test("no raw peer host/IP/pubkey is reachable from peer.count_drop's candidate diagnostics -- v0's global count-only signal never reads per-peer attributes at all", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 10));
  ticks.push(...activeTickWithMarker(tickTs(30), 1, DEFAULT_SIGNATURE, "peer.ssh.definitely-not-a-hash"));
  const candidates = await seedAndCompute(paths, ticks);
  const drop = candidates.find((c) => c.rule_id === PEER_COUNT_DROP_RULE_ID);
  const serialized = JSON.stringify(drop);
  assert.equal(/definitely-not-a-hash|203\.0\.113|alice/.test(serialized), false);
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
  // Fact-store completeness hardening (Slice 5): pre-establish the cold-start lockout (see
  // seedAndCompute's comment above) -- this fixture drives appendFactPoints/
  // computePeerBaselineCandidates directly.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, ticks, { now });
  await appendFactPoints(paths, [], { now }); // confirm the integrity ledger to 'intact'

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
  // Fact-store completeness hardening (Slice 5): confirm the integrity ledger to 'intact' before
  // the repeated-call phase below -- a fresh ledger's first retention pass reads 'unknown'
  // (bootstrap), which would otherwise keep factHistoryTrustworthy returning false and the
  // cold-start lockout re-arming (and rewriting the store) on every one of the "repeated calls
  // with unchanged fact-history" below, defeating the very idempotency this test checks. (The
  // store itself is left un-pre-seeded/day-1 on purpose: this test only asserts on write-count and
  // state equality, not on candidates, so day-1 suppression on the first call doesn't affect it.)
  await appendFactPoints(paths, [], { now });

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
// Fact-store completeness hardening (docs/plans/2026-08-21-fact-store-completeness-hardening.md,
// Slice 5): the persisted cold-start lockout that gates ALL peer.* novelty (peer.count_spike/
// peer.count_drop) whenever fact-history completeness cannot be trusted. Per the plan's "Required
// test in every one of Slices 3-7" + the per-detector migration test. Mirrors
// session-baseline.test.js's own dedicated cold-start coverage (Slice 4) and
// process-lineage-baseline.test.js's (Slice 3) exactly, adapted to peer-baseline's spike/drop
// shape. The suppressed direction below is peer.count_spike (Welford-based, markerless), which
// needs no census marker to establish -- peer.count_drop shares the exact same lockout (both
// directions are gated by the one `coldStartPendingThisTick` check) and is exercised by the
// truncated-history/intact-control pair below via the same mechanism.
// ---------------------------------------------------------------------------------------------

test("computePeerBaselineCandidates: degraded truncated history suppresses a fabricated peer.count_spike (an established pattern must not read as anomalous just because retention scrubbed the history that would have shown it as normal)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8)); // burst tick -- would fire peer.count_spike if trusted
  const points = ticks;
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  const result = await computePeerBaselineCandidates(paths, {
    now: tickTs(30),
    minHistoryTickCount,
    readFactPoints: async () => degradedReadResult(points, tickTs(30)),
  });

  assert.deepEqual(result, [], "untrustworthy retained history must not authorize a peer.count_spike claim");
  const { state } = await loadPeerBaselineStore(paths);
  assert.equal(state.cold_start_pending, true);
});

test("computePeerBaselineCandidates: intact history control still fires a real peer.count_spike (sanity check proving the degraded case above really would have fabricated an alert absent the gate)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  ticks.push(...activeTick(tickTs(30), 8));
  const points = ticks;
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  const result = await computePeerBaselineCandidates(paths, {
    now: tickTs(30),
    readFactPoints: async () => intactReadResult(points),
  });

  const spikeCandidates = result.filter((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(spikeCandidates.length, 1, "an intact store must not be falsely suppressed");
});

test("computePeerBaselineCandidates: one transient fact-history loss recovers after minHistoryTickCount genuinely-new clean ticks (recovery-latch fix, bounded not permanent)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const minSampleCount = 2;
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  let points = [...activeTick(tickTs(0), 2)];
  let readResult = degradedReadResult([], tickTs(1));
  const options = { minHistoryTickCount, minSampleCount, readFactPoints: async () => ({ ...readResult, points }) };

  // Loss tick: a burst (count 10 vs. an established mean of 2) that would fire peer.count_spike
  // if trusted.
  points = [...points, ...activeTick(tickTs(1), 10)];
  const lossTick = await computePeerBaselineCandidates(paths, { ...options, now: tickTs(1) });
  assert.deepEqual(lossTick, []);
  const afterLoss = (await loadPeerBaselineStore(paths)).state;
  assert.equal(afterLoss.cold_start_pending, true);

  readResult = intactReadResult([]);
  points = [...points, ...activeTick(tickTs(2), 2)]; // 1st re-accum tick
  assert.deepEqual(await computePeerBaselineCandidates(paths, { ...options, now: tickTs(2) }), []);

  points = [...points, ...activeTick(tickTs(3), 2)]; // 2nd re-accum tick
  assert.deepEqual(await computePeerBaselineCandidates(paths, { ...options, now: tickTs(3) }), []);
  assert.equal((await loadPeerBaselineStore(paths)).state.cold_start_pending, false);

  // A genuinely new burst after re-establishment must fire normally.
  points = [...points, ...activeTick(tickTs(4), 200)];
  const resumed = await computePeerBaselineCandidates(paths, { ...options, now: tickTs(4) });
  const spikeCandidates = resumed.filter((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(spikeCandidates.length, 1, "novelty resumes after genuinely-new clean ticks re-establish trust");
});

test("computePeerBaselineCandidates: a clean tick cannot self-heal and fire peer.* novelty in the same breath fact-history loss is first observed on the prior tick", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minSampleCount = 2;
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  let points = [
    ...activeTick(tickTs(1), 2),
    ...activeTick(tickTs(2), 2),
    ...activeTick(tickTs(3), 10), // would fire peer.count_spike if trusted
  ];
  let readResult = degradedReadResult(points, tickTs(3));
  const options = { minHistoryTickCount: 1, minSampleCount, readFactPoints: async () => ({ ...readResult, points }) };

  assert.deepEqual(await computePeerBaselineCandidates(paths, { ...options, now: tickTs(3) }), []);

  points = [...points, ...activeTick(tickTs(4), 200)]; // an even larger burst on the very next tick
  readResult = intactReadResult([]);
  assert.deepEqual(
    await computePeerBaselineCandidates(paths, { ...options, now: tickTs(4) }),
    [],
    "the first clean tick after loss may re-establish state but must not emit novelty in the same tick",
  );
  assert.equal((await loadPeerBaselineStore(paths)).state.cold_start_pending, false);
});

test("migration: a pre-Slice-5 store with no cold_start_* fields at all cold-starts once on first read, then recovers after minHistoryTickCount clean ticks (per-detector P8 analog)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const minSampleCount = 2;

  // Simulate a store written by a pre-Slice-5 daemon: no cold_start_pending/_reason/_since_ts at
  // all -- written directly to disk, bypassing writePeerBaselineStore's normalizer entirely.
  const { dir, storeFile } = resolvePeerBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const legacyState = {
    version: 1,
    last_folded_ts: tickTs(-1),
    confidence_state: "established",
    stats: { count: 5, mean: 2, m2: 0, variance: 0, stddev: 0, ewma: 2, ewma_variance: 0, min: 2, max: 2 },
    last_observation: undefined,
    skipped_overflow_tick_count: 0,
    availability_signature: undefined,
    drop: {
      confidence_state: "provisional",
      stats: { count: 0, mean: 0, m2: 0, variance: 0, stddev: 0, ewma: undefined, ewma_variance: undefined, min: undefined, max: undefined },
      last_observation: undefined,
    },
    skipped_markerless_tick_count: 0,
  };
  await fs.writeFile(storeFile, JSON.stringify(legacyState, null, 2), { mode: 0o600 });

  const ticks = [];
  for (let i = 0; i < 5; i += 1) ticks.push(...activeTick(tickTs(i), 2));
  await appendFactPoints(paths, ticks, { now: tickTs(4) });
  await appendFactPoints(paths, [], { now: tickTs(4) }); // confirm the shared integrity ledger to 'intact'

  // First read post-migration: even against a fully intact, loss-free fact-history ledger, the
  // missing cold_start_* fields default to pending (fail-closed) -- an established-looking store
  // must not be trusted just because it parses. A bounded, one-time cold-start is required.
  const firstRead = await computePeerBaselineCandidates(paths, { now: tickTs(4), minHistoryTickCount, minSampleCount });
  assert.deepEqual(firstRead, []);
  const afterFirst = (await loadPeerBaselineStore(paths)).state;
  assert.equal(afterFirst.cold_start_pending, true);
  assert.equal(
    typeof afterFirst.cold_start_since_ts,
    "string",
    "the migration must synthesize a real anchor, never leave it undefined (the Infinity re-establishment-boundary trap)",
  );
  assert.ok(Number.isFinite(new Date(afterFirst.cold_start_since_ts).getTime()));

  // minHistoryTickCount genuinely-new clean ticks after the migration anchor re-establish trust.
  let hour = 5;
  for (let i = 0; i < minHistoryTickCount; i += 1) {
    const ts = tickTs(hour);
    await appendFactPoints(paths, activeTick(ts, 2), { now: ts });
    await computePeerBaselineCandidates(paths, { now: ts, minHistoryTickCount, minSampleCount });
    hour += 1;
  }
  assert.equal(
    (await loadPeerBaselineStore(paths)).state.cold_start_pending,
    false,
    "the migration cold-start must be bounded -- it clears after minHistoryTickCount genuinely-new clean ticks, never latching forever",
  );

  // And peer.* novelty genuinely resumes afterward.
  const ts = tickTs(hour);
  await appendFactPoints(paths, activeTick(ts, 200), { now: ts });
  const resumed = await computePeerBaselineCandidates(paths, { now: ts, minHistoryTickCount, minSampleCount });
  assert.equal(resumed.filter((c) => c.rule_id === PEER_COUNT_SPIKE_RULE_ID).length, 1);
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

test("loadPeerBaselineStore: corrupt JSON reset also yields fresh, safe defaults for the Slice 4c additions (drop/availability_signature/skipped_markerless_tick_count)", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolvePeerBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(storeFile, "{not valid json", "utf8");
  const { state, corrupt } = await loadPeerBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(state.availability_signature, undefined);
  assert.equal(state.drop.confidence_state, "provisional");
  assert.equal(state.drop.stats.count, 0);
  assert.equal(state.drop.last_observation, undefined);
  assert.equal(state.skipped_markerless_tick_count, 0);
});

test("store round-trip: drop/availability_signature/skipped_markerless_tick_count fields persist and restore correctly through computePeerBaselineCandidates -> loadPeerBaselineStore", async () => {
  const paths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...activeTickWithMarker(tickTs(i), 10));
  ticks.push(...activeTickWithMarker(tickTs(30), 1));
  await seedAndCompute(paths, ticks);
  const { state } = await loadPeerBaselineStore(paths);
  assert.equal(state.availability_signature, DEFAULT_SIGNATURE);
  assert.equal(typeof state.drop, "object");
  assert.equal(state.drop.confidence_state, "established");
  assert.equal(state.drop.last_observation.count, 1);
  assert.equal(state.skipped_markerless_tick_count, 0);
});

test("normalizePeerBaselineState: missing/malformed Slice 4c fields degrade safely (fresh nested drop state, undefined signature, 0 counter)", () => {
  const normalized = normalizePeerBaselineState({ drop: "not-an-object", availability_signature: 12345, skipped_markerless_tick_count: "NaN" });
  assert.equal(normalized.drop.confidence_state, "provisional");
  assert.equal(normalized.drop.stats.count, 0);
  assert.equal(normalized.drop.last_observation, undefined);
  assert.equal(normalized.availability_signature, undefined);
  assert.equal(normalized.skipped_markerless_tick_count, 0);
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
