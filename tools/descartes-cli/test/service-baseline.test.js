import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { isFixedLengthHexHash, sanitizeDiagnostics } from "../src/diagnostics-sanitizer.js";
import { appendFactPoints, readFactPoints } from "../src/fact-store.js";
import { SERVICE_CENSUS_FACT_NAME, SERVICE_CENSUS_MARKER_ENTITY_KEY } from "../src/fact-translators.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_BASELINE_FACT_WINDOW_MS,
  DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT,
  DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS,
  SERVICE_DISAPPEARED_RULE_ID,
  buildDisappearedCandidates,
  computeServiceBaselineCandidates,
  detectServiceDisappearances,
  groupServiceFactsByTick,
  loadServiceBaselineStore,
  normalizeServiceBaselineState,
  resolveServiceBaselineStorePaths,
  writeServiceBaselineStore,
} from "../src/service-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-service-baseline-test-"));
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

function servicePoint(ts, entityKey, { running = "true", manager = "launchd" } = {}) {
  return {
    ts,
    fact_name: "service.presence",
    entity_key: entityKey,
    attributes: { running, manager },
    source_envelope_id: "services",
    source_tool: "collect_services",
    sensitivity: "operational",
  };
}

function censusMarkerPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: SERVICE_CENSUS_FACT_NAME,
    entity_key: SERVICE_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "services",
    source_tool: "collect_services",
    sensitivity: "operational",
    confidence: 0,
  };
}

// A "complete" tick-group: the given entity_keys, each as a service.presence point, plus a
// complete census marker.
function completeTick(ts, entityKeys) {
  return [...entityKeys.map((key) => servicePoint(ts, key)), censusMarkerPoint(ts, "complete")];
}

function partialTick(ts, entityKeys) {
  return [...entityKeys.map((key) => servicePoint(ts, key)), censusMarkerPoint(ts, "partial")];
}

function flatten(groupsOfPoints) {
  return groupsOfPoints.flat();
}

// Builds N leading "established" complete tick-groups all carrying the same entityKeys (>=
// DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT by default), starting at hour 0.
function establishedTicks(entityKeys, count = DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT) {
  const ticks = [];
  for (let i = 0; i < count; i += 1) ticks.push(completeTick(tickTs(i), entityKeys));
  return ticks;
}

async function seedAndCompute(paths, points, options = {}) {
  const lastTs = points.reduce((max, p) => Math.max(max, new Date(p.ts).getTime()), 0);
  const now = options.now ?? new Date(lastTs).toISOString();
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, points, { now });
  return computeServiceBaselineCandidates(paths, { now, ...options });
}

function expectedHash(entityKey) {
  return createHash("sha256").update(`service.disappeared:${entityKey}`).digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------------------------------
// Store I/O.
// ---------------------------------------------------------------------------------------------

test("loadServiceBaselineStore: ENOENT yields fresh state with corrupt:false", async () => {
  const paths = await tempPaths();
  const { state, corrupt } = await loadServiceBaselineStore(paths);
  assert.equal(corrupt, false);
  assert.deepEqual(state, { version: 1, last_folded_ts: undefined, skipped_partial_tick_count: 0, disappearance_event_count: 0 });
});

test("loadServiceBaselineStore: corrupt JSON yields fresh state with corrupt:true, never throws", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveServiceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{not valid json", { mode: 0o600 });
  const { state, corrupt } = await loadServiceBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(state.disappearance_event_count, 0);
});

test("writeServiceBaselineStore: atomic write leaves no tmp file behind and the final file is 0o600", async () => {
  const paths = await tempPaths();
  await writeServiceBaselineStore(paths, { version: 1, last_folded_ts: tickTs(0), skipped_partial_tick_count: 0, disappearance_event_count: 1 });
  const { dir, storeFile } = resolveServiceBaselineStorePaths(paths);
  const entries = await fs.readdir(dir);
  assert.ok(!entries.some((name) => name.endsWith(".tmp")), "no tmp file should remain after a successful write");
  const stat = await fs.stat(storeFile);
  assert.equal(stat.mode & 0o777, 0o600);
});

test("normalizeServiceBaselineState: rejects malformed shapes field-by-field, falling back to safe defaults", () => {
  assert.deepEqual(normalizeServiceBaselineState(undefined), { version: 1, last_folded_ts: undefined, skipped_partial_tick_count: 0, disappearance_event_count: 0 });
  assert.deepEqual(normalizeServiceBaselineState(null), { version: 1, last_folded_ts: undefined, skipped_partial_tick_count: 0, disappearance_event_count: 0 });
  assert.deepEqual(normalizeServiceBaselineState([1, 2, 3]), { version: 1, last_folded_ts: undefined, skipped_partial_tick_count: 0, disappearance_event_count: 0 });
  const normalized = normalizeServiceBaselineState({
    version: 99,
    last_folded_ts: 12345, // wrong type -> undefined
    skipped_partial_tick_count: "not a number", // -> 0
    disappearance_event_count: Number.NaN, // -> 0
  });
  assert.deepEqual(normalized, { version: 1, last_folded_ts: undefined, skipped_partial_tick_count: 0, disappearance_event_count: 0 });
  const valid = normalizeServiceBaselineState({ last_folded_ts: tickTs(3), skipped_partial_tick_count: 2, disappearance_event_count: 5 });
  assert.deepEqual(valid, { version: 1, last_folded_ts: tickTs(3), skipped_partial_tick_count: 2, disappearance_event_count: 5 });
});

// ---------------------------------------------------------------------------------------------
// groupServiceFactsByTick.
// ---------------------------------------------------------------------------------------------

test("groupServiceFactsByTick: service.presence points + a complete census marker produce the correct entityKeys set and censusState, excluding the marker's own entity_key", () => {
  const ts = tickTs(0);
  const points = completeTick(ts, ["svc-a", "svc-b"]);
  const groups = groupServiceFactsByTick(points);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, "complete");
  assert.deepEqual([...groups[0].entityKeys].sort(), ["svc-a", "svc-b"]);
  assert.equal(groups[0].entityKeys.has(SERVICE_CENSUS_MARKER_ENTITY_KEY), false);
});

test("groupServiceFactsByTick: a partial census marker tick reports censusState 'partial'", () => {
  const ts = tickTs(0);
  const groups = groupServiceFactsByTick(partialTick(ts, ["svc-a"]));
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, "partial");
});

test("groupServiceFactsByTick: a garbled/unrecognized census_state marker value degrades to censusState 'unknown', NOT 'complete' (degrade-not-fabricate, never max-trust-by-default)", () => {
  const ts = tickTs(0);
  const groups = groupServiceFactsByTick([censusMarkerPoint(ts, "truncated-oops")]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, "unknown");
});

test("groupServiceFactsByTick: no marker at all for a tick -> censusState undefined (legacy/markerless)", () => {
  const ts = tickTs(0);
  const groups = groupServiceFactsByTick([servicePoint(ts, "svc-a")]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, undefined);
  assert.deepEqual([...groups[0].entityKeys], ["svc-a"]);
});

test("groupServiceFactsByTick: an all-marker, zero-presence tick still produces a tick-group with an empty entityKeys set (genuine zero-service census, never silently skipped)", () => {
  const ts = tickTs(0);
  const groups = groupServiceFactsByTick([censusMarkerPoint(ts, "complete")]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].censusState, "complete");
  assert.equal(groups[0].entityKeys.size, 0);
});

test("groupServiceFactsByTick: points from an unrelated fact_name sharing the read window are ignored entirely", () => {
  const ts = tickTs(0);
  const unrelated = { ts, fact_name: "session.presence", entity_key: "session.tmux.abcdef0123456789", attributes: {}, sensitivity: "operational" };
  const anotherUnrelated = { ts, fact_name: "network.listening_port.owner", entity_key: "tcp:0.0.0.0:8080", attributes: {}, sensitivity: "operational" };
  const points = [...completeTick(ts, ["svc-a"]), unrelated, anotherUnrelated];
  const groups = groupServiceFactsByTick(points);
  assert.equal(groups.length, 1);
  assert.deepEqual([...groups[0].entityKeys], ["svc-a"]);
});

test("groupServiceFactsByTick: orders tick-groups ascending by ts regardless of input order", () => {
  const points = flatten([completeTick(tickTs(2), ["a"]), completeTick(tickTs(0), ["a"]), completeTick(tickTs(1), ["a"])]);
  const groups = groupServiceFactsByTick(points);
  assert.deepEqual(groups.map((g) => g.ts), [tickTs(0), tickTs(1), tickTs(2)]);
});

// ---------------------------------------------------------------------------------------------
// detectServiceDisappearances.
// ---------------------------------------------------------------------------------------------

test("detectServiceDisappearances: fewer than 2 complete tick-groups in the window -> []", () => {
  const groups = groupServiceFactsByTick(completeTick(tickTs(0), ["svc-a"]));
  assert.deepEqual(detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(0)) }), []);
});

test("detectServiceDisappearances: an entity_key seen in fewer than the min-established-count complete censuses, then absent, does NOT fire (cold-start gate)", () => {
  const ticks = [completeTick(tickTs(0), ["svc-a"]), completeTick(tickTs(1), ["svc-a"]), completeTick(tickTs(2), [])];
  const groups = groupServiceFactsByTick(flatten(ticks));
  const result = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(2)), minEstablishedCount: DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT });
  assert.deepEqual(result, [], "svc-a was only seen in 2 complete censuses, below the default min of 3");
});

test("detectServiceDisappearances: an established entity_key present in the second-most-recent complete census, absent from the freshest complete census (which is itself fresh), FIRES", () => {
  const ticks = [...establishedTicks(["svc-a"], 3), completeTick(tickTs(3), [])];
  const groups = groupServiceFactsByTick(flatten(ticks));
  const result = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(3)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.equal(result.length, 1);
  assert.equal(result[0].entity_key, "svc-a");
  assert.equal(result[0].disappeared_at_ts, tickTs(3));
  assert.equal(result[0].last_seen_ts, tickTs(2));
  assert.equal(result[0].complete_census_seen_count, 3);
});

test("detectServiceDisappearances: an established entity_key absent from a 'partial' freshest-in-time tick-group does NOT fire off that partial tick -- only a genuinely complete tick-group counts as 'the freshest complete census'", () => {
  const ticks = [...establishedTicks(["svc-a"], 3), partialTick(tickTs(3), [])];
  const groups = groupServiceFactsByTick(flatten(ticks));
  const result = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(3)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "the partial tick must be skipped over, not treated as a disappearance observation");
});

test("detectServiceDisappearances: a garbled/unrecognized census_state marker value (neither 'complete' nor 'partial') does NOT fire -- it must degrade to 'unknown' and be excluded, never silently upgraded to a trusted complete census (adversarial-review regression)", () => {
  const ticks = [...establishedTicks(["svc-a"], 3), [censusMarkerPoint(tickTs(3), "truncated-oops")]];
  const groups = groupServiceFactsByTick(flatten(ticks));
  assert.equal(groups[groups.length - 1].censusState, "unknown");
  const result = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(3)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "a garbled census_state marker must never manufacture a fabricated mass-disappearance");
});

test("detectServiceDisappearances: a stale freshest-complete tick-group (beyond activeFreshnessMs relative to now) does NOT fire, even though the entity_key is genuinely absent from it", () => {
  const ticks = [...establishedTicks(["svc-a"], 3), completeTick(tickTs(3), [])];
  const groups = groupServiceFactsByTick(flatten(ticks));
  // now is far beyond the freshness horizon relative to the freshest complete tick-group (tickTs(3)).
  const nowMs = Date.parse(tickTs(3)) + 10 * HOUR_MS;
  const result = detectServiceDisappearances(groups, { nowMs, minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.deepEqual(result, [], "freshness gate must independently block firing on a stale complete census");
});

test("detectServiceDisappearances: edge-triggered, not sticky -- fires only on the transition tick, not on every subsequent tick the service stays absent", () => {
  const ticks = [...establishedTicks(["svc-a"], 3), completeTick(tickTs(3), []), completeTick(tickTs(4), [])];
  const groups = groupServiceFactsByTick(flatten(ticks));

  const atTransition = detectServiceDisappearances(groups.slice(0, 4), { nowMs: Date.parse(tickTs(3)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.equal(atTransition.length, 1, "expected the transition tick (tick 3) to fire");

  const afterTransition = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(4)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.deepEqual(afterTransition, [], "tick 4 compares tick 2 (absent) vs tick 3 (also absent) -- no straddling transition, so it must not re-fire");
});

test("detectServiceDisappearances: a service that reappears after a fired disappearance is eligible to fire again on a LATER genuine disappearance", () => {
  const ticks = [
    ...establishedTicks(["svc-a"], 3), // ticks 0-2: established
    completeTick(tickTs(3), []), // tick 3: disappears (fires)
    completeTick(tickTs(4), ["svc-a"]), // tick 4: reappears
    completeTick(tickTs(5), ["svc-a"]), // tick 5: still present
    completeTick(tickTs(6), []), // tick 6: disappears again
  ];
  const groups = groupServiceFactsByTick(flatten(ticks));

  const secondDisappearance = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(6)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.equal(secondDisappearance.length, 1, "a re-established service must be eligible to fire again on a later genuine disappearance");
  assert.equal(secondDisappearance[0].entity_key, "svc-a");
  assert.equal(secondDisappearance[0].disappeared_at_ts, tickTs(6));
});

test("detectServiceDisappearances: different entity_keys never interfere with each other", () => {
  const ticks = [
    completeTick(tickTs(0), ["svc-a", "svc-b"]),
    completeTick(tickTs(1), ["svc-a", "svc-b"]),
    completeTick(tickTs(2), ["svc-a", "svc-b"]),
    completeTick(tickTs(3), ["svc-b"]), // only svc-a disappears
  ];
  const groups = groupServiceFactsByTick(flatten(ticks));
  const result = detectServiceDisappearances(groups, { nowMs: Date.parse(tickTs(3)), minEstablishedCount: 3, freshnessMs: HOUR_MS });
  assert.equal(result.length, 1);
  assert.equal(result[0].entity_key, "svc-a");
});

// ---------------------------------------------------------------------------------------------
// buildDisappearedCandidates / computeServiceBaselineCandidates.
// ---------------------------------------------------------------------------------------------

test("computeServiceBaselineCandidates: learned.json disabled -> [], zero I/O (readFactPoints/loadServiceBaselineStore never called)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: false });
  let readCalled = false;
  let loadStoreCalled = false;
  const candidates = await computeServiceBaselineCandidates(paths, {
    readFactPoints: async () => { readCalled = true; return { points: [] }; },
    loadServiceBaselineStore: async () => { loadStoreCalled = true; return { state: {} }; },
  });
  assert.deepEqual(candidates, []);
  assert.equal(readCalled, false);
  assert.equal(loadStoreCalled, false);
});

test("buildDisappearedCandidates: severity is ALWAYS 'warning' -- no code path can produce 'critical' for this rule_id", () => {
  const candidates = buildDisappearedCandidates([
    { entity_key: "svc-a", disappeared_at_ts: tickTs(1), last_seen_ts: tickTs(0), complete_census_seen_count: 100 },
  ]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].severity, "warning");
  assert.equal(candidates[0].rule_id, SERVICE_DISAPPEARED_RULE_ID);
});

test("buildDisappearedCandidates: diagnostics passes through sanitizeDiagnostics (assert shape) and carries the SANITIZED service name in cleartext (2026-07-24 operator decision) alongside the entity_key_hash", () => {
  const entry = { entity_key: "com.example.raw-service-name", disappeared_at_ts: tickTs(1), last_seen_ts: tickTs(0), complete_census_seen_count: 5 };
  const [candidate] = buildDisappearedCandidates([entry]);
  const expectedShape = sanitizeDiagnostics({
    service_name: entry.entity_key, // already charset-sanitized at the fixture's own definition
    entity_key_hash: expectedHash(entry.entity_key),
    last_seen_ts: entry.last_seen_ts,
    complete_census_seen_count: entry.complete_census_seen_count,
  });
  assert.deepEqual(candidate.diagnostics, expectedShape);
  assert.ok(isFixedLengthHexHash(candidate.diagnostics.entity_key_hash));
  assert.equal(candidate.diagnostics.entity_key_hash, expectedHash(entry.entity_key));
  // 2026-07-24 operator decision: the sanitized service name IS shown in cleartext in diagnostics
  // (local notification to the machine's own operator; identity IS the signal for this rule_id).
  assert.equal(candidate.diagnostics.service_name, entry.entity_key);
  assert.equal(JSON.stringify(candidate.diagnostics).includes(entry.entity_key), true, "the sanitized service name is intentionally shown in diagnostics for this rule_id");
});

test("buildDisappearedCandidates: diagnostics.service_name is charset-sanitized (no newline/control-char/injection) even if entity_key somehow arrived unsanitized -- defense in depth beyond fact-translators.js's own sanitizeEntityKey", () => {
  const dirty = "svc\nname\x01with\tcontrol\x1bchars";
  const entry = { entity_key: dirty, disappeared_at_ts: tickTs(1), last_seen_ts: tickTs(0), complete_census_seen_count: 5 };
  const [candidate] = buildDisappearedCandidates([entry]);
  assert.notEqual(candidate.diagnostics.service_name, dirty);
  assert.equal(/[\x00-\x1f\x7f]/.test(String(candidate.diagnostics.service_name ?? "")), false, "sanitized service_name must contain no control characters");
  assert.equal(/[\r\n]/.test(String(candidate.diagnostics.service_name ?? "")), false, "sanitized service_name must contain no newlines");
});

test("buildDisappearedCandidates: `fingerprint` (and the derived `id`) stay HASHED, never the raw/sanitized entity_key, for stable dedup/edge-triggering -- UNCHANGED by the 2026-07-24 cleartext-diagnostics decision, which is scoped to the DISPLAYED diagnostics.service_name field only (adversarial-review regression + 2026-07-24 scoping regression)", () => {
  const entry = { entity_key: "com.example.raw-service-name", disappeared_at_ts: tickTs(1), last_seen_ts: tickTs(0), complete_census_seen_count: 5 };
  const [candidate] = buildDisappearedCandidates([entry]);
  assert.notEqual(candidate.fingerprint, entry.entity_key);
  assert.equal(candidate.fingerprint, expectedHash(entry.entity_key));
  assert.ok(isFixedLengthHexHash(candidate.fingerprint));
  assert.equal(candidate.fingerprint, candidate.diagnostics.entity_key_hash, "fingerprint and diagnostics.entity_key_hash must be derived from the same hash so dedup stays stable");
  assert.equal(String(candidate.id).includes(entry.entity_key), false, "`id` (derived from the hashed fingerprint) must never carry the raw/sanitized entity_key");
  // diagnostics.service_name is the ONE intentional exception (2026-07-24 operator decision) --
  // the sanitized service name IS expected to appear there. Everywhere else in the persisted
  // candidate (fingerprint/id in particular) must stay hash-derived.
  assert.equal(candidate.diagnostics.service_name, entry.entity_key);
});

test("computeServiceBaselineCandidates: store write is skipped on a tick with zero new tick-groups since last_folded_ts (at-most-one-write convention)", async () => {
  const paths = await tempPaths();
  const ticks = [...establishedTicks(["svc-a"], 3), completeTick(tickTs(3), [])];
  const now = tickTs(3);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, flatten(ticks), { now });

  let writeCount = 0;
  const countingWrite = async (descartesPaths, state) => {
    writeCount += 1;
    return writeServiceBaselineStore(descartesPaths, state);
  };
  const commonOptions = { now, freshnessMs: HOUR_MS, establishedMinCensusCount: 3, writeServiceBaselineStore: countingWrite };

  await computeServiceBaselineCandidates(paths, commonOptions);
  const { state: afterFirst } = await loadServiceBaselineStore(paths);
  await computeServiceBaselineCandidates(paths, commonOptions);
  await computeServiceBaselineCandidates(paths, commonOptions);
  const { state: afterThird } = await loadServiceBaselineStore(paths);

  assert.equal(writeCount, 1, "service-baseline.json must be written at most once across repeated calls with unchanged fact-history");
  assert.deepEqual(afterFirst, afterThird);
});

test("fold-time-only counter increment (Stage 1 review must-fix 3): disappearance_event_count increments by exactly 1 total across repeated calls against the SAME unchanged fact window, and does not increment again once a later new tick-group lands", async () => {
  const paths = await tempPaths();
  const ticks = [...establishedTicks(["svc-a"], 3), completeTick(tickTs(3), [])]; // svc-a disappears at tick 3
  const now = tickTs(3);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, flatten(ticks), { now });

  const commonOptions = { now, freshnessMs: HOUR_MS, establishedMinCensusCount: 3 };

  // N repeated calls against the SAME unchanged fact window (the fast-tick re-emission scenario:
  // last_folded_ts does not advance because no new tick-group has landed).
  for (let i = 0; i < 5; i += 1) {
    await computeServiceBaselineCandidates(paths, commonOptions);
  }
  const { state: afterRepeats } = await loadServiceBaselineStore(paths);
  assert.equal(afterRepeats.disappearance_event_count, 1, "must increment exactly once total, not once per call");

  // Advance the window by one new complete tick-group (svc-a stays absent) -- must NOT increment
  // again for the same already-counted event.
  const laterTs = tickTs(4);
  await appendFactPoints(paths, completeTick(laterTs, []), { now: laterTs });
  await computeServiceBaselineCandidates(paths, { ...commonOptions, now: laterTs });
  const { state: afterAdvance } = await loadServiceBaselineStore(paths);
  assert.equal(afterAdvance.disappearance_event_count, 1, "the already-counted event must not be recounted once last_folded_ts advances past it");
});

test("fold-time-only counter increment: skipped_partial_tick_count increments exactly once per newly-observed partial tick-group across repeated calls", async () => {
  const paths = await tempPaths();
  const ticks = [...establishedTicks(["svc-a"], 3), partialTick(tickTs(3), ["svc-a"])];
  const now = tickTs(3);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, flatten(ticks), { now });

  const commonOptions = { now, freshnessMs: HOUR_MS, establishedMinCensusCount: 3 };
  for (let i = 0; i < 4; i += 1) {
    await computeServiceBaselineCandidates(paths, commonOptions);
  }
  const { state } = await loadServiceBaselineStore(paths);
  assert.equal(state.skipped_partial_tick_count, 1, "must increment exactly once total across repeated calls, not once per call");
});

test("re-emission every call: candidate list is rebuilt fresh from the current window on every invocation, not dependent on whether a store write happened that tick", async () => {
  const paths = await tempPaths();
  const ticks = [...establishedTicks(["svc-a"], 3), completeTick(tickTs(3), [])];
  const now = tickTs(3);
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, flatten(ticks), { now });

  const commonOptions = { now, freshnessMs: HOUR_MS, establishedMinCensusCount: 3 };
  const first = await computeServiceBaselineCandidates(paths, commonOptions);
  const second = await computeServiceBaselineCandidates(paths, commonOptions); // no new fact-history in between
  assert.equal(first.length, 1);
  assert.equal(second.length, 1);
  assert.deepEqual(first, second);
});

test("computeServiceBaselineCandidates end-to-end: an established service disappearing in a fresh complete census fires exactly one service.disappeared candidate naming the sanitized service in diagnostics.service_name (2026-07-24), with fingerprint/id still hash-derived", async () => {
  const paths = await tempPaths();
  const ticks = [...establishedTicks(["svc-a", "svc-b"], 5), completeTick(tickTs(5), ["svc-b"])]; // svc-a disappears
  const candidates = await seedAndCompute(paths, flatten(ticks), { freshnessMs: HOUR_MS, establishedMinCensusCount: 3 });
  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.rule_id, SERVICE_DISAPPEARED_RULE_ID);
  assert.equal(candidate.severity, "warning");
  assert.equal(candidate.diagnostics.entity_key_hash, expectedHash("svc-a"));
  // 2026-07-24 operator decision: the sanitized service name is intentionally shown in diagnostics.
  assert.equal(candidate.diagnostics.service_name, "svc-a");
  assert.equal(JSON.stringify(candidate.diagnostics).includes("svc-a"), true, "the sanitized service name is intentionally shown in diagnostics for service.disappeared");
  // fingerprint/id must still be hash-derived, never the raw/sanitized entity_key, so dedup stays
  // stable -- this scoped exception applies to diagnostics.service_name only.
  assert.notEqual(candidate.fingerprint, "svc-a");
  assert.equal(String(candidate.id).includes("svc-a"), false);
});

test("computeServiceBaselineCandidates: readFactPoints window bound is threaded through (regression: fact points outside baselineFactWindowMs are excluded)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, completeTick(tickTs(0), ["svc-a"]), { now: tickTs(0) });
  // A direct readFactPoints call with a tiny window relative to `now` should see nothing.
  const now = tickTs(1000);
  const { points } = await readFactPoints(paths, { windowMs: HOUR_MS, now });
  assert.deepEqual(points, []);
});

test("DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT / DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS / DEFAULT_BASELINE_FACT_WINDOW_MS are positive finite constants", () => {
  for (const value of [DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT, DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS, DEFAULT_BASELINE_FACT_WINDOW_MS]) {
    assert(Number.isFinite(value) && value > 0);
  }
});
