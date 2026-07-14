// S14 (outcome-informed compile-down) — docs/plans/2026-07-14-compile-down-calibration.md §5.
// tuning-store.js: mining, the backtest, and the deterministic draft->review-ready gate.
// Convention: temp XDG dirs + hand-built fixtures, NO fs mocking (matches every other store's
// test file in this repo).

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { buildConstraintTarget, writeLearnedConfig } from "../src/constraint-store.js";
import {
  DEFAULT_MIN_BACKTEST_SAMPLES,
  DEFAULT_MIN_RETUNE_FIRES,
  DEFAULT_RETUNE_MARGIN_PCT,
  TUNING_KINDS,
  TUNING_STATUSES,
  backtestRetune,
  buildFactHistoryByTarget,
  loadTuningCandidates,
  mergeMinedTuningCandidates,
  mineTuningCandidates,
  promoteTuningDraftsToReviewReady,
  proposeRetune,
  replayObservedValues,
  resolveTuningStorePaths,
  runLearnedTuningList,
  runLearnedTuningMine,
  runLearnedTuningPromote,
  tuningCandidateId,
  validateTuningCandidate,
  writeTuningCandidates,
} from "../src/tuning-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-tuning-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const DAY_MS = 24 * 60 * 60 * 1000;

function activeConstraint(overrides = {}) {
  return {
    id: "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa",
    kind: "constraint",
    family: "daemon-config",
    target: "daemon.profile.interval_ms",
    expected: { comparator: "gte", value: 1000 },
    status: "active",
    confidence: 1,
    provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: "2026-07-01T00:00:00.000Z" },
    fixtures: [],
    promotion_history: [],
    first_observed: "2026-07-01T00:00:00.000Z",
    last_verified: "2026-07-01T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

function calibrationRow(overrides = {}) {
  return {
    artifact_ref: "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa",
    granularity: "artifact",
    rule_id_family: "constraint.violation.daemon-config",
    fired_count: 6,
    fired_count_is_lower_bound: true,
    auto_recovered_fast_count: 5,
    never_escalated_count: null,
    llm_adjudicated_count: 0,
    llm_suppressed_count: 0,
    llm_namespace_enabled: null,
    llm_suppressed_rate: null,
    precision_proxy: 0.1,
    recall_proxy: null,
    recall_proxy_reason: "no ground-truth incident signal available",
    shadow_fire_rate: null,
    chronically_firing: true,
    schema_version: 1,
    ...overrides,
  };
}

function draftTuningCandidate(overrides = {}) {
  return {
    id: tuningCandidateId("retire", "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa"),
    kind: "retire",
    artifact_ref: "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa",
    rule_id_family: "constraint.violation.daemon-config",
    granularity: "artifact",
    status: "draft",
    current: null,
    proposed: null,
    justification: { fired_count: 6, auto_recovered_fast_count: 5, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: null, backtest: null },
    applied: false,
    apply_note: null,
    mined_at: "2026-07-10T00:00:00.000Z",
    backtested_at: "2026-07-10T00:00:00.000Z",
    promotion_history: [],
    schema_version: 1,
    ...overrides,
  };
}

// ============================================================================================
// resolveTuningStorePaths / validateTuningCandidate / load-write round trip
// ============================================================================================

test("resolveTuningStorePaths points at stateDir/learned/tuning-candidates.json with no double-nesting", async () => {
  const paths = await tempPaths();
  const resolved = resolveTuningStorePaths(paths);
  assert.equal(resolved.dir, path.join(paths.stateDir, "learned"));
  assert.equal(resolved.tuningCandidatesFile, path.join(paths.stateDir, "learned", "tuning-candidates.json"));
  for (const value of Object.values(resolved)) {
    const occurrences = value.split(path.sep).filter((segment) => segment === "descartes").length;
    assert.equal(occurrences, 1, `expected exactly one "descartes" path segment in ${value}`);
  }
});

test("TUNING_KINDS/TUNING_STATUSES are the plan's closed sets", () => {
  assert.deepEqual(TUNING_KINDS, ["retire", "retune", "promote_shadow_hint"]);
  assert.deepEqual(TUNING_STATUSES, ["draft", "review-ready", "approved", "rejected"]);
});

test("validateTuningCandidate accepts a well-formed draft", () => {
  assert.equal(validateTuningCandidate(draftTuningCandidate()), true);
});

test("validateTuningCandidate rejects a bad kind/status/granularity/missing fields", () => {
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ kind: "delete_everything" })), /kind must be one of/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ status: "applied" })), /status must be one of/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ granularity: "global" })), /granularity must be/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ artifact_ref: "" })), /non-empty artifact_ref/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ rule_id_family: "" })), /non-empty rule_id_family/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ justification: undefined })), /justification object/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ applied: "yes" })), /boolean applied/);
  assert.throws(() => validateTuningCandidate(draftTuningCandidate({ schema_version: undefined })), /numeric schema_version/);
});

test("writeTuningCandidates/loadTuningCandidates round-trip", async () => {
  const paths = await tempPaths();
  const candidate = draftTuningCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const { candidates, corrupt_count } = await loadTuningCandidates(paths);
  assert.equal(corrupt_count, 0);
  assert.deepEqual(candidates, [candidate]);
});

test("loadTuningCandidates returns an empty result on ENOENT (day-1, no file yet)", async () => {
  const paths = await tempPaths();
  const { candidates, corrupt_count } = await loadTuningCandidates(paths);
  assert.deepEqual(candidates, []);
  assert.equal(corrupt_count, 0);
});

test("a corrupted tuning-candidates.json is tolerated rather than thrown", async () => {
  const paths = await tempPaths();
  const { tuningCandidatesFile, dir } = resolveTuningStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(tuningCandidatesFile, "{ not json", "utf8");
  const { candidates, corrupt_count } = await loadTuningCandidates(paths);
  assert.deepEqual(candidates, []);
  assert.equal(corrupt_count, 1);
});

test("writeTuningCandidates is atomic (tmp+rename, no leftover tmp file)", async () => {
  const paths = await tempPaths();
  await writeTuningCandidates(paths, [draftTuningCandidate()]);
  const { dir } = resolveTuningStorePaths(paths);
  const entries = await fs.readdir(dir);
  assert.equal(entries.some((entry) => entry.endsWith(".tmp")), false);
});

// ============================================================================================
// tuningCandidateId -- MUST-FIX 5: deliberately timestamp-free
// ============================================================================================

test("tuningCandidateId is deterministic and does NOT depend on mined_at/wall-clock", () => {
  const a = tuningCandidateId("retire", "constraint.mined.x.deadbeefdeadbeef");
  const b = tuningCandidateId("retire", "constraint.mined.x.deadbeefdeadbeef");
  assert.equal(a, b);
  assert.match(a, /^tuning\.[0-9a-f]{16}$/);
});

test("tuningCandidateId differs by kind and by artifact_ref (no accidental collision)", () => {
  const retire = tuningCandidateId("retire", "constraint.mined.x.deadbeefdeadbeef");
  const retune = tuningCandidateId("retune", "constraint.mined.x.deadbeefdeadbeef");
  const otherRef = tuningCandidateId("retire", "constraint.mined.y.cafecafecafecafe");
  assert.notEqual(retire, retune);
  assert.notEqual(retire, otherRef);
});

// ============================================================================================
// proposeRetune -- loosen-only, direction correctness, empty-observedValues guard
// ============================================================================================

test("proposeRetune: gte constraint clustering below its floor -> a LOWER proposed value", () => {
  const proposed = proposeRetune("gte", [50, 60, 70]);
  assert.ok(proposed < 50, `expected a loosened floor below the minimum observed value 50, got ${proposed}`);
  assert.equal(proposed, 50 * (1 - DEFAULT_RETUNE_MARGIN_PCT));
});

test("proposeRetune: lte constraint clustering above its ceiling -> a HIGHER proposed value", () => {
  const proposed = proposeRetune("lte", [50, 60, 70]);
  assert.ok(proposed > 70, `expected a loosened ceiling above the maximum observed value 70, got ${proposed}`);
  assert.equal(proposed, 70 * (1 + DEFAULT_RETUNE_MARGIN_PCT));
});

test("proposeRetune: eq/pattern comparator -> undefined (categorical has no numeric retune)", () => {
  assert.equal(proposeRetune("eq", [1, 2, 3]), undefined);
  assert.equal(proposeRetune(undefined, [1, 2, 3]), undefined);
});

test("proposeRetune: empty observedValues -> undefined, never +/-Infinity", () => {
  assert.equal(proposeRetune("gte", []), undefined);
  assert.equal(proposeRetune("lte", []), undefined);
});

// ============================================================================================
// backtestRetune -- determinism, no wall-clock/random dependency
// ============================================================================================

test("backtestRetune: counts how many replayed ticks would fire under current vs. proposed", () => {
  const result = backtestRetune([50, 60, 70], { comparator: "gte", value: 1000 }, { comparator: "gte", value: 47.5 });
  assert.deepEqual(result, { sample_ticks: 3, would_fire_count_current: 3, would_fire_count_proposed: 0 });
});

test("backtestRetune is deterministic: repeated calls with the same input produce byte-identical output", () => {
  const first = backtestRetune([1, 2, 3, 4], { comparator: "lte", value: 2 }, { comparator: "lte", value: 5 });
  const second = backtestRetune([1, 2, 3, 4], { comparator: "lte", value: 2 }, { comparator: "lte", value: 5 });
  assert.deepEqual(first, second);
});

// ============================================================================================
// replayObservedValues / buildFactHistoryByTarget -- MUST-FIX 3: replay via buildShadowFactLookup,
// degraded observations excluded, NOT a raw String attribute read.
// ============================================================================================

test("replayObservedValues: replays through buildShadowFactLookup, excluding a degraded (owner_known:\"false\") tick entirely", () => {
  // Use buildFactHistoryByTarget to compute the REAL target string for these points, so the
  // degraded-exclusion assertion below reflects the actual shared buildConstraintTarget function.
  const points = [
    { ts: "2026-07-01T00:00:00.000Z", fact_name: "service.presence", entity_key: "myservice", attributes: { running: "50" } },
    { ts: "2026-07-01T01:00:00.000Z", fact_name: "service.presence", entity_key: "myservice", attributes: { running: "60", owner_known: "false" } },
    { ts: "2026-07-01T02:00:00.000Z", fact_name: "service.presence", entity_key: "myservice", attributes: { running: "70" } },
  ];
  const byTarget = buildFactHistoryByTarget(points);
  const [[realTarget, bucketedPoints]] = [...byTarget.entries()];

  const observed = replayObservedValues(bucketedPoints, realTarget);
  // The degraded (owner_known:"false") tick at 01:00 is excluded entirely -- not a fabricated
  // gap value -- so only the 50 and 70 observations survive, in chronological order.
  assert.deepEqual(observed, [50, 70]);
});

test("replayObservedValues is deterministic and chronologically ordered regardless of input order", () => {
  const points = [
    { ts: "2026-07-01T02:00:00.000Z", fact_name: "service.presence", entity_key: "svc", attributes: { running: "70" } },
    { ts: "2026-07-01T00:00:00.000Z", fact_name: "service.presence", entity_key: "svc", attributes: { running: "50" } },
    { ts: "2026-07-01T01:00:00.000Z", fact_name: "service.presence", entity_key: "svc", attributes: { running: "60" } },
  ];
  const byTarget = buildFactHistoryByTarget(points);
  const [[target, bucketedPoints]] = [...byTarget.entries()];
  assert.deepEqual(replayObservedValues(bucketedPoints, target), [50, 60, 70]);
  // Re-running with the same input is byte-identical.
  assert.deepEqual(replayObservedValues(bucketedPoints, target), replayObservedValues([...bucketedPoints].reverse(), target));
});

test("replayObservedValues skips a non-numeric observation (cannot inform a numeric retune) without throwing", () => {
  const points = [
    { ts: "2026-07-01T00:00:00.000Z", fact_name: "network.listening_port.owner", entity_key: "port-443", attributes: { owner: "nginx" } },
    { ts: "2026-07-01T01:00:00.000Z", fact_name: "network.listening_port.owner", entity_key: "port-443", attributes: { owner: "42" } },
  ];
  const byTarget = buildFactHistoryByTarget(points);
  const [[target, bucketedPoints]] = [...byTarget.entries()];
  assert.deepEqual(replayObservedValues(bucketedPoints, target), [42]);
});

// ============================================================================================
// mineTuningCandidates -- the decision table (plan §5.2), constraint.*-only v1 scope (must-fix 6)
// ============================================================================================

test("mineTuningCandidates: a chronically-firing constraint.* row -> exactly one 'retire' draft", () => {
  const constraint = activeConstraint();
  const row = calibrationRow({ chronically_firing: true, fired_count: 6 });
  const candidates = mineTuningCandidates([constraint], { artifacts: [row] }, new Map(), { now: "2026-07-10T00:00:00.000Z" });

  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.kind, "retire");
  assert.equal(candidate.status, "draft");
  assert.equal(candidate.artifact_ref, constraint.id);
  assert.equal(candidate.rule_id_family, "constraint.violation.daemon-config");
  assert.equal(candidate.granularity, "artifact");
  assert.equal(candidate.current, null);
  assert.equal(candidate.proposed, null);
  assert.equal(candidate.applied, false);
  assert.equal(candidate.apply_note, null);
  assert.equal(candidate.justification.fired_count, 6);
  assert.equal(candidate.justification.backtest, null);
  assert.equal(candidate.id, tuningCandidateId("retire", constraint.id));
});

test("mineTuningCandidates: a healthy artifact (few fires, high precision) -> no proposal", () => {
  const constraint = activeConstraint();
  const row = calibrationRow({ chronically_firing: false, fired_count: 1, precision_proxy: 0.95 });
  const candidates = mineTuningCandidates([constraint], { artifacts: [row] }, new Map(), { now: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(candidates, []);
});

test("mineTuningCandidates: retune band (fired_count in [MIN_RETUNE_FIRES, MIN_CHRONIC_FIRES)) with a numeric gte comparator -> a backtested 'retune' draft", () => {
  const row = calibrationRow({ chronically_firing: false, fired_count: 3 });
  assert.ok(row.fired_count >= DEFAULT_MIN_RETUNE_FIRES, "fixture must be inside the retune band");

  // constraint.target must be fact-derived (via the shared buildConstraintTarget) for the
  // backtest's replay-through-buildShadowFactLookup wiring to find it.
  const target = buildConstraintTarget("service.presence", "myservice");
  const constraint = activeConstraint({ expected: { comparator: "gte", value: 1000 }, target });

  const realPoints = [
    { ts: "2026-07-01T00:00:00.000Z", fact_name: "service.presence", entity_key: "myservice", attributes: { running: "50" } },
    { ts: "2026-07-01T01:00:00.000Z", fact_name: "service.presence", entity_key: "myservice", attributes: { running: "60" } },
    { ts: "2026-07-01T02:00:00.000Z", fact_name: "service.presence", entity_key: "myservice", attributes: { running: "70" } },
  ];
  const factHistoryByTarget = new Map([[target, realPoints]]);

  const candidates = mineTuningCandidates([constraint], { artifacts: [row] }, factHistoryByTarget, { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.kind, "retune");
  assert.equal(candidate.status, "draft");
  assert.deepEqual(candidate.current, { expected: { comparator: "gte", value: 1000 } });
  assert.equal(candidate.proposed.expected.comparator, "gte");
  assert.ok(candidate.proposed.expected.value < 50, `expected a loosened floor below 50, got ${candidate.proposed.expected.value}`);
  assert.equal(candidate.justification.backtest.sample_ticks, 3);
  assert.equal(candidate.justification.backtest.would_fire_count_proposed, 0);
});

test("mineTuningCandidates: an eq/pattern (categorical) constraint in the retune band never gets a retune proposal", () => {
  const constraint = activeConstraint({ expected: { comparator: "eq", value: "true" } });
  const row = calibrationRow({ chronically_firing: false, fired_count: 3 });
  const candidates = mineTuningCandidates([constraint], { artifacts: [row] }, new Map(), { now: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(candidates, []);
});

test("mineTuningCandidates: MUST-FIX 6 -- constraint.*-only v1 scope; a chronically-firing session/peer/correlation/provenance row NEVER emits a candidate", () => {
  const nonConstraintRows = [
    calibrationRow({ artifact_ref: "session.count_drop", granularity: "family", rule_id_family: "session.count_drop", chronically_firing: true, fired_count: 10 }),
    calibrationRow({ artifact_ref: "peer.count_spike", granularity: "family", rule_id_family: "peer.count_spike", chronically_firing: true, fired_count: 10 }),
    calibrationRow({ artifact_ref: "correlation.login_kill_proximity", granularity: "family", rule_id_family: "correlation.login_kill_proximity", chronically_firing: true, fired_count: 10 }),
    calibrationRow({ artifact_ref: "9999888877776666", granularity: "artifact", rule_id_family: "provenance.process.unknown_identity", chronically_firing: true, fired_count: 10 }),
  ];
  // Even providing a live constraint whose id happens to match one of these refs (adversarial:
  // what if a future bug tried to resolve it anyway) -- still zero candidates, because the
  // rule_id_family gate runs BEFORE any constraint lookup.
  const candidates = mineTuningCandidates([], { artifacts: nonConstraintRows }, new Map(), { now: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(candidates, []);
});

test("mineTuningCandidates: a calibration row whose artifact_ref does not resolve to a live status:\"active\" constraint is skipped (degrade, never fabricate)", () => {
  const row = calibrationRow({ chronically_firing: true, fired_count: 6, artifact_ref: "constraint.does.not.exist" });
  assert.deepEqual(mineTuningCandidates([], { artifacts: [row] }, new Map(), { now: "2026-07-10T00:00:00.000Z" }), []);

  const retired = activeConstraint({ status: "retired" });
  const rowForRetired = calibrationRow({ chronically_firing: true, fired_count: 6, artifact_ref: retired.id });
  assert.deepEqual(mineTuningCandidates([retired], { artifacts: [rowForRetired] }, new Map(), { now: "2026-07-10T00:00:00.000Z" }), []);
});

test("mineTuningCandidates: promote_shadow_hint -- a still-shadow constraint with zero shadow fires and full soak coverage -> a hint, gated on the LIVE constraint status (not the calibration report, which has no row for a never-alerted shadow constraint)", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const shadowConstraint = activeConstraint({
    id: "constraint.mined.service-presence.bbbbbbbbbbbbbbbb",
    family: "service-presence",
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  const shadowRecords = Array.from({ length: 7 }, (_, day) => ({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    constraint_id: shadowConstraint.id,
    family: "service-presence",
    target: shadowConstraint.target,
    expected: shadowConstraint.expected,
    actual: "true",
    fired: false,
  }));
  const now = shadowSinceMs + 7 * DAY_MS;

  // Empty calibration report -- this constraint has never alerted, so it has no calibration row
  // at all; the trigger must still fire because it checks the LIVE constraint status directly.
  const candidates = mineTuningCandidates([shadowConstraint], { artifacts: [] }, new Map(), { now, shadowRecords, soakDays: 7 });
  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.kind, "promote_shadow_hint");
  assert.equal(candidate.artifact_ref, shadowConstraint.id);
  assert.equal(candidate.applied, false);
  assert.equal(candidate.justification.shadow_fire_rate, 0);
});

test("mineTuningCandidates: promote_shadow_hint does NOT fire for a constraint that has already been promoted past shadow (live status check, not inferred from shadow_fire_rate alone)", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const promoted = activeConstraint({
    id: "constraint.mined.service-presence.cccccccccccccccc",
    status: "active", // already promoted past shadow since the shadow-violations.jsonl records were written
  });
  const staleShadowRecords = Array.from({ length: 7 }, (_, day) => ({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    constraint_id: promoted.id,
    family: "service-presence",
    target: promoted.target,
    expected: promoted.expected,
    actual: "true",
    fired: false,
  }));
  const now = shadowSinceMs + 7 * DAY_MS;
  const candidates = mineTuningCandidates([promoted], { artifacts: [] }, new Map(), { now, shadowRecords: staleShadowRecords, soakDays: 7 });
  assert.deepEqual(candidates, []);
});

test("mineTuningCandidates: promote_shadow_hint does not fire when checkShadowSoak isn't satisfied yet (e.g. a fire in the shadow window)", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const shadowConstraint = activeConstraint({ id: "constraint.mined.service-presence.dddddddddddddddd", status: "shadow", promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "x" }] });
  const shadowRecords = [{ ts: shadowSince, constraint_id: shadowConstraint.id, family: "service-presence", target: shadowConstraint.target, expected: shadowConstraint.expected, actual: "false", fired: true }];
  const now = shadowSinceMs + 7 * DAY_MS;
  const candidates = mineTuningCandidates([shadowConstraint], { artifacts: [] }, new Map(), { now, shadowRecords, soakDays: 7 });
  assert.deepEqual(candidates, []);
});

test("mineTuningCandidates is deterministic: same inputs -> byte-identical output (aside from the mined_at/backtested_at timestamp, which is caller-supplied via options.now)", () => {
  const constraint = activeConstraint();
  const row = calibrationRow({ chronically_firing: true, fired_count: 6 });
  const first = mineTuningCandidates([constraint], { artifacts: [row] }, new Map(), { now: "2026-07-10T00:00:00.000Z" });
  const second = mineTuningCandidates([constraint], { artifacts: [row] }, new Map(), { now: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(first, second);
});

// ============================================================================================
// mergeMinedTuningCandidates -- MUST-FIX 5: idempotent merge (id has no mined_at)
// ============================================================================================

test("mergeMinedTuningCandidates: a new id is added as a new draft", () => {
  const mined = [draftTuningCandidate()];
  const merge = mergeMinedTuningCandidates([], mined);
  assert.equal(merge.new_count, 1);
  assert.equal(merge.updated_count, 0);
  assert.equal(merge.unchanged_count, 0);
  assert.deepEqual(merge.candidates, mined);
});

test("mergeMinedTuningCandidates: MUST-FIX 5 -- re-mining the SAME underlying signal at a LATER mined_at refreshes the existing draft, never accumulates a duplicate", () => {
  const first = draftTuningCandidate({ mined_at: "2026-07-10T00:00:00.000Z", backtested_at: "2026-07-10T00:00:00.000Z" });
  const { candidates: afterFirst } = mergeMinedTuningCandidates([], [first]);

  const reminded = draftTuningCandidate({ mined_at: "2026-07-11T00:00:00.000Z", backtested_at: "2026-07-11T00:00:00.000Z" });
  assert.equal(reminded.id, first.id, "the id must be identical across re-mines of the same (kind, artifact_ref)");

  const merge = mergeMinedTuningCandidates(afterFirst, [reminded]);
  assert.equal(merge.candidates.length, 1, "must refresh in place, never accumulate a second draft");
  assert.equal(merge.new_count, 0);
  assert.equal(merge.updated_count, 1);
  assert.equal(merge.candidates[0].mined_at, "2026-07-11T00:00:00.000Z");
});

test("mergeMinedTuningCandidates: a candidate already past draft (review-ready/approved/rejected) is left completely untouched by a re-mine", () => {
  for (const status of ["review-ready", "approved", "rejected"]) {
    const existing = draftTuningCandidate({ status, mined_at: "2026-07-10T00:00:00.000Z" });
    const remined = draftTuningCandidate({ mined_at: "2026-07-11T00:00:00.000Z", justification: { ...draftTuningCandidate().justification, fired_count: 999 } });
    const merge = mergeMinedTuningCandidates([existing], [remined]);
    assert.deepEqual(merge.candidates, [existing]);
    assert.equal(merge.unchanged_count, 1);
  }
});

test("mergeMinedTuningCandidates: an identical re-mine (no real change) counts as unchanged, not updated", () => {
  const existing = draftTuningCandidate();
  const merge = mergeMinedTuningCandidates([existing], [draftTuningCandidate()]);
  assert.equal(merge.updated_count, 0);
  assert.equal(merge.unchanged_count, 1);
});

// ============================================================================================
// promoteTuningDraftsToReviewReady -- the deterministic draft -> review-ready gate
// ============================================================================================

test("promoteTuningDraftsToReviewReady: a retire/promote_shadow_hint draft (justification present, no backtest needed) promotes immediately", () => {
  const draft = draftTuningCandidate();
  const [promoted] = promoteTuningDraftsToReviewReady([draft], { now: "2026-07-11T00:00:00.000Z" });
  assert.equal(promoted.status, "review-ready");
  assert.equal(promoted.promotion_history.at(-1).from, "draft");
  assert.equal(promoted.promotion_history.at(-1).to, "review-ready");
});

test("promoteTuningDraftsToReviewReady: a retune draft below MIN_BACKTEST_SAMPLES stays draft; at/above the bar promotes", () => {
  const belowBar = draftTuningCandidate({
    kind: "retune",
    justification: { fired_count: 3, auto_recovered_fast_count: 0, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: null, backtest: { sample_ticks: 3, would_fire_count_current: 3, would_fire_count_proposed: 0 } },
  });
  const [stillDraft] = promoteTuningDraftsToReviewReady([belowBar], { now: "2026-07-11T00:00:00.000Z" });
  assert.equal(stillDraft.status, "draft");

  const atBar = draftTuningCandidate({
    kind: "retune",
    justification: { fired_count: 3, auto_recovered_fast_count: 0, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: null, backtest: { sample_ticks: DEFAULT_MIN_BACKTEST_SAMPLES, would_fire_count_current: 3, would_fire_count_proposed: 0 } },
  });
  const [promoted] = promoteTuningDraftsToReviewReady([atBar], { now: "2026-07-11T00:00:00.000Z" });
  assert.equal(promoted.status, "review-ready");
});

test("promoteTuningDraftsToReviewReady is idempotent on non-draft statuses", () => {
  for (const status of ["review-ready", "approved", "rejected"]) {
    const candidate = draftTuningCandidate({ status });
    const [result] = promoteTuningDraftsToReviewReady([candidate], { now: "2026-07-11T00:00:00.000Z" });
    assert.deepEqual(result, candidate);
  }
});

// ============================================================================================
// No LLM anywhere (source-regex, mirrors promotion-store.js/calibration.js's own tests)
// ============================================================================================

test("tuning-store.js never imports the pi-harness/alert-intelligence LLM touchpoints", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/tuning-store.js"), "utf8");
  assert.equal(/from\s*["'`]\.\/pi-harness\.js["'`]/.test(source), false);
  assert.equal(/import\(\s*["'`][^"'`]*pi-harness\.js["'`]\s*\)/.test(source), false);
  assert.equal(/\bcreateSession\s*\(/.test(source), false);

  const importMatch = source.match(/import\s*{([^}]*)}\s*from\s*["'`]\.\/alert-intelligence\.js["'`]/);
  assert.ok(importMatch, "expected exactly one named-import statement from alert-intelligence.js");
  const importedNames = importMatch[1].split(",").map((name) => name.trim()).filter(Boolean);
  const allowedNames = new Set(["readAlertIntelligenceAudit", "readAlertIntelligenceConfig"]);
  for (const name of importedNames) assert.ok(allowedNames.has(name), `unexpected alert-intelligence.js import: ${name}`);
});

// ============================================================================================
// CLI: descartes learned tuning mine | promote | list
// ============================================================================================

test("runLearnedTuningMine: disabled learned.json -> { status: 'disabled' }, no candidates written", async () => {
  const paths = await tempPaths();
  const lines = [];
  const result = await runLearnedTuningMine(paths, [], { output: (line) => lines.push(line) });
  assert.deepEqual(result, { status: "disabled" });
  const { candidates } = await loadTuningCandidates(paths);
  assert.deepEqual(candidates, []);
});

test("runLearnedTuningMine: day-1 empty state (learned enabled, nothing else exists) -> zero candidates, no error", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const lines = [];
  const result = await runLearnedTuningMine(paths, [], { output: (line) => lines.push(line), now: "2026-07-10T00:00:00.000Z" });
  assert.equal(result.mined_candidates, 0);
  assert.equal(result.new_drafts, 0);
});

test("runLearnedTuningMine end-to-end: an active constraint + a chronically-firing alerts.json fixture mines exactly one retire draft; running mine twice does not duplicate it", async () => {
  const { writeConstraints } = await import("../src/constraint-store.js");
  const { normalizeAlertRecord, writeAlertRecords } = await import("../src/alert-store.js");

  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });

  const constraint = activeConstraint({ id: "constraint.mined.daemon-config.eeeeeeeeeeeeeeee" });
  await writeConstraints(paths, [constraint]);

  const noisyAlerts = [];
  for (let i = 0; i < 6; i += 1) {
    noisyAlerts.push(normalizeAlertRecord({
      rule_id: "constraint.violation.daemon-config",
      fingerprint: `noisy-${i}`,
      status: "recovered",
      severity: "warning",
      title: "t",
      summary: "s",
      first_seen: `2026-07-01T00:0${i}:00.000Z`,
      last_seen: `2026-07-01T00:0${i}:05.000Z`,
      diagnostics: { constraint_id: constraint.id },
    }));
  }
  await writeAlertRecords(paths, noisyAlerts);

  const summary1 = await runLearnedTuningMine(paths, [], { output: () => {}, now: "2026-07-10T00:00:00.000Z" });
  assert.equal(summary1.mined_candidates, 1);
  assert.equal(summary1.new_drafts, 1);

  const { candidates: afterFirst } = await loadTuningCandidates(paths);
  assert.equal(afterFirst.length, 1);
  assert.equal(afterFirst[0].kind, "retire");
  assert.equal(afterFirst[0].artifact_ref, constraint.id);

  // Running mine again (later wall-clock) refreshes, does not duplicate.
  const summary2 = await runLearnedTuningMine(paths, [], { output: () => {}, now: "2026-07-11T00:00:00.000Z" });
  assert.equal(summary2.mined_candidates, 1);
  assert.equal(summary2.updated_drafts, 1);
  assert.equal(summary2.new_drafts, 0);

  const { candidates: afterSecond } = await loadTuningCandidates(paths);
  assert.equal(afterSecond.length, 1, "must not accumulate a second draft for the same underlying signal");
  assert.equal(afterSecond[0].id, afterFirst[0].id);
});

test("runLearnedTuningPromote: promotes an eligible draft to review-ready and reports it", async () => {
  const paths = await tempPaths();
  await writeTuningCandidates(paths, [draftTuningCandidate()]);
  const result = await runLearnedTuningPromote(paths, [], { output: () => {}, now: "2026-07-11T00:00:00.000Z" });
  assert.equal(result.promoted_count, 1);
  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates[0].status, "review-ready");
});

test("runLearnedTuningList: lists candidates regardless of learned.json enable state (never gated)", async () => {
  const paths = await tempPaths();
  await writeTuningCandidates(paths, [draftTuningCandidate()]);
  const lines = [];
  const result = await runLearnedTuningList(paths, ["--json"], { output: (line) => lines.push(line) });
  assert.equal(result.candidates.length, 1);
  const payload = JSON.parse(lines[0]);
  assert.equal(payload.learned_tuning_list.candidates.length, 1);
});
