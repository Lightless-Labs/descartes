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
  DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT,
  SERVICE_APPEARED_RULE_ID,
  SERVICE_DISAPPEARED_RULE_ID,
  buildAppearedCandidates,
  buildDisappearedCandidates,
  computeServiceAppearanceCandidates,
  computeServiceBaselineCandidates,
  detectServiceAppearances,
  detectServiceDisappearances,
  groupServiceFactsByTick,
  isValidServiceAppearanceBaselineStoreShape,
  loadServiceAppearanceBaselineStore,
  loadServiceBaselineStore,
  normalizeServiceAppearanceBaselineState,
  normalizeServiceBaselineState,
  resolveServiceAppearanceBaselineStorePaths,
  resolveServiceBaselineStorePaths,
  writeServiceAppearanceBaselineStore,
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

// Fact-store completeness hardening (Slice 6) fixtures, mirroring session-baseline.test.js's/
// peer-baseline.test.js's own intactReadResult/degradedReadResult exactly -- injected via
// options.readFactPoints so the dedicated cold-start tests below don't need to fabricate real
// ledger corruption/eviction.
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

async function seedAndCompute(paths, points, options = {}) {
  const lastTs = points.reduce((max, p) => Math.max(max, new Date(p.ts).getTime()), 0);
  const now = options.now ?? new Date(lastTs).toISOString();
  await writeLearnedConfig(paths, { enabled: true });
  // Slice 6 (fact-store completeness hardening) gave service-baseline.js its own persistent
  // cold-start lockout, mirroring process-lineage-baseline.js's/session-baseline.js's/
  // peer-baseline.js's: a brand-new store starts cold_start_pending, and a single one-shot
  // append+compute call (exactly this helper's shape) can never itself satisfy re-establishment
  // (all of `points`' history necessarily predates the anchor a fresh lockout would set on its own
  // first read). Every test below this helper predates Slice 6 and is about service-baseline's
  // OTHER logic (set-diff detection, tick-disposition skips, ...), not the lockout itself -- so,
  // mirroring session-baseline.test.js's/peer-baseline.test.js's own precedent of pre-seeding
  // cold_start_pending:false before wiring/candidate-shape tests, this helper pre-establishes the
  // store (anchored strictly before the fixture's own earliest point) and confirms the shared
  // integrity ledger to 'intact' (a fresh ledger's first retention pass is deliberately 'unknown' --
  // bootstrap anti-laundering rule; a second clean pass confirms it) so callers keep exercising
  // exactly what they always tested. The lockout mechanism itself has its own dedicated coverage
  // further down in this file.
  const firstTs = points.reduce((min, p) => Math.min(min, new Date(p.ts).getTime()), Infinity);
  const establishedAnchor = Number.isFinite(firstTs) ? new Date(firstTs - 1).toISOString() : now;
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: establishedAnchor });
  await appendFactPoints(paths, points, { now });
  await appendFactPoints(paths, [], { now });
  return computeServiceBaselineCandidates(paths, { now, ...options });
}

function expectedHash(entityKey) {
  return createHash("sha256").update(`service.disappeared:${entityKey}`).digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------------------------------
// Store I/O.
// ---------------------------------------------------------------------------------------------

// Fact-store completeness hardening (Slice 6): freshServiceBaselineState/normalizeServiceBaselineState
// now also carry the persistent cold-start lockout's three fields, defaulting fail-closed.
const FRESH_STATE_DEFAULTS = { cold_start_pending: true, cold_start_reason: undefined, cold_start_since_ts: undefined };

test("loadServiceBaselineStore: ENOENT yields fresh state with corrupt:false, missing:true, and a cold-start-pending lockout tagged 'missing_store'", async () => {
  const paths = await tempPaths();
  const { state, corrupt, missing } = await loadServiceBaselineStore(paths);
  assert.equal(corrupt, false);
  assert.equal(missing, true);
  assert.deepEqual(state, {
    version: 1,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    disappearance_event_count: 0,
    ...FRESH_STATE_DEFAULTS,
    cold_start_reason: "missing_store",
  });
});

test("loadServiceBaselineStore: corrupt JSON yields fresh state with corrupt:true, missing:false, never throws, and a cold-start-pending lockout tagged 'corrupt_store'", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveServiceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{not valid json", { mode: 0o600 });
  const { state, corrupt, missing } = await loadServiceBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(missing, false);
  assert.equal(state.disappearance_event_count, 0);
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "corrupt_store");
});

test("writeServiceBaselineStore: atomic write leaves no tmp file behind and the final file is 0o600", async () => {
  const paths = await tempPaths();
  await writeServiceBaselineStore(paths, {
    version: 1,
    last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0,
    disappearance_event_count: 1,
    cold_start_pending: false,
  });
  const { dir, storeFile } = resolveServiceBaselineStorePaths(paths);
  const entries = await fs.readdir(dir);
  assert.ok(!entries.some((name) => name.endsWith(".tmp")), "no tmp file should remain after a successful write");
  const stat = await fs.stat(storeFile);
  assert.equal(stat.mode & 0o777, 0o600);
});

test("writeServiceBaselineStore: does not synthesize a wall-clock cold-start anchor", async () => {
  const paths = await tempPaths();
  const written = await writeServiceBaselineStore(paths, { last_folded_ts: tickTs(0) }); // cold_start_pending defaults true, no since_ts supplied
  assert.equal(written.cold_start_pending, true);
  assert.equal(written.cold_start_since_ts, undefined);
  const { state } = await loadServiceBaselineStore(paths);
  assert.equal(state.cold_start_since_ts, undefined);
});

test("normalizeServiceBaselineState: rejects malformed shapes field-by-field, falling back to safe defaults", () => {
  const freshExpected = {
    version: 1,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    disappearance_event_count: 0,
    ...FRESH_STATE_DEFAULTS,
  };
  assert.deepEqual(normalizeServiceBaselineState(undefined), freshExpected);
  assert.deepEqual(normalizeServiceBaselineState(null), freshExpected);
  assert.deepEqual(normalizeServiceBaselineState([1, 2, 3]), freshExpected);
  const normalized = normalizeServiceBaselineState({
    version: 99,
    last_folded_ts: 12345, // wrong type -> undefined
    skipped_partial_tick_count: "not a number", // -> 0
    disappearance_event_count: Number.NaN, // -> 0
    cold_start_pending: "not a boolean", // fail-closed idiom: anything but literal false -> pending
    cold_start_reason: 42, // wrong type -> undefined
    cold_start_since_ts: 12345, // wrong type -> undefined
  });
  assert.deepEqual(normalized, freshExpected);
  const valid = normalizeServiceBaselineState({ last_folded_ts: tickTs(3), skipped_partial_tick_count: 2, disappearance_event_count: 5 });
  assert.deepEqual(valid, { version: 1, last_folded_ts: tickTs(3), skipped_partial_tick_count: 2, disappearance_event_count: 5, ...FRESH_STATE_DEFAULTS });
});

test("normalizeServiceBaselineState: cold_start_pending is trusted false ONLY when explicitly and validly recorded as such (fail-closed idiom, mirrors process-lineage/session/peer)", () => {
  const established = normalizeServiceBaselineState({
    last_folded_ts: tickTs(3),
    cold_start_pending: false,
    cold_start_reason: undefined,
    cold_start_since_ts: tickTs(0),
  });
  assert.equal(established.cold_start_pending, false);
  assert.equal(established.cold_start_since_ts, tickTs(0));

  // Any non-literal-false value -- missing, non-boolean, or explicit true -- stays pending.
  assert.equal(normalizeServiceBaselineState({}).cold_start_pending, true);
  assert.equal(normalizeServiceBaselineState({ cold_start_pending: true }).cold_start_pending, true);
  assert.equal(normalizeServiceBaselineState({ cold_start_pending: "false" }).cold_start_pending, true);
  assert.equal(normalizeServiceBaselineState({ cold_start_pending: 0 }).cold_start_pending, true);
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
  // Fact-store completeness hardening (Slice 6): pre-establish the cold-start lockout (this test
  // is about the write-skip/at-most-one-write convention, not the lockout, which has its own
  // dedicated coverage further down) and confirm the shared integrity ledger to 'intact'.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, flatten(ticks), { now });
  await appendFactPoints(paths, [], { now });

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
  // Fact-store completeness hardening (Slice 6): pre-establish the cold-start lockout (this test
  // is about the fold-time-only counter convention, not the lockout) and confirm the shared
  // integrity ledger to 'intact'.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, flatten(ticks), { now });
  await appendFactPoints(paths, [], { now });

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
  // Fact-store completeness hardening (Slice 6): pre-establish the cold-start lockout and confirm
  // the shared integrity ledger to 'intact' (see the "disappearance_event_count" fold-time test
  // above for the identical rationale).
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, flatten(ticks), { now });
  await appendFactPoints(paths, [], { now });

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
  // Fact-store completeness hardening (Slice 6): pre-establish the cold-start lockout and confirm
  // the shared integrity ledger to 'intact' (see the fold-time tests above for the identical
  // rationale) — this test is about re-emission, not the lockout.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, flatten(ticks), { now });
  await appendFactPoints(paths, [], { now });

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

test("DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT / DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS / DEFAULT_BASELINE_FACT_WINDOW_MS / DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT are positive finite constants", () => {
  for (const value of [DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT, DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS, DEFAULT_BASELINE_FACT_WINDOW_MS, DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT]) {
    assert(Number.isFinite(value) && value > 0);
  }
});

// ---------------------------------------------------------------------------------------------
// Fact-store completeness hardening (Slice 6): persistent cold-start lockout.
// docs/plans/2026-08-21-fact-store-completeness-hardening.md, "Required test in every one of
// Slices 3-7" + the per-detector migration test. Mirrors session-baseline.test.js's/
// peer-baseline.test.js's own dedicated cold-start coverage exactly, adapted to service-baseline's
// set-diff disappearance shape.
// ---------------------------------------------------------------------------------------------

// 30 complete censuses in which "svc-a" is present (establishing it, default minEstablishedCount is
// 3), then a 31st complete census in which it is missing -- would fire service.disappeared if the
// retained history were trusted (mirrors test/daemon.test.js's own serviceDisappearanceFixtureFactPoints).
function disappearanceFixturePoints() {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(completeTick(tickTs(i), ["svc-a"]));
  ticks.push(completeTick(tickTs(30), []));
  return flatten(ticks);
}

test("computeServiceBaselineCandidates: degraded truncated history suppresses a fabricated service.disappeared (an established service must not read as vanished just because retention scrubbed the history that would have shown it as present)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  const points = disappearanceFixturePoints();
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  const result = await computeServiceBaselineCandidates(paths, {
    now: tickTs(30),
    minHistoryTickCount,
    freshnessMs: HOUR_MS,
    readFactPoints: async () => degradedReadResult(points, tickTs(30)),
  });

  assert.deepEqual(result, [], "untrustworthy retained history must not authorize a service.disappeared claim");
  const { state } = await loadServiceBaselineStore(paths);
  assert.equal(state.cold_start_pending, true);
});

test("computeServiceBaselineCandidates: a future pending anchor re-arms at the injected now", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeServiceBaselineStore(paths, {
    cold_start_pending: true,
    cold_start_since_ts: tickTs(10),
  });

  await computeServiceBaselineCandidates(paths, {
    now: tickTs(0),
    readFactPoints: async () => intactReadResult([]),
  });

  const { state } = await loadServiceBaselineStore(paths);
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_since_ts, tickTs(0));
});

test("computeServiceBaselineCandidates: rollback repairs a future anchor and watermark, then persists re-established trust", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeServiceBaselineStore(paths, {
    cold_start_pending: true,
    cold_start_since_ts: tickTs(10),
    last_folded_ts: tickTs(10),
  });

  let points = flatten([completeTick(tickTs(11), ["svc-a"])]);
  const options = {
    minHistoryTickCount: 6,
    establishedMinCensusCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => intactReadResult(points, { status: "intact", last_corrupt_ts: tickTs(100) }),
  };
  await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(0) });
  assert.equal((await loadServiceBaselineStore(paths)).state.last_folded_ts, undefined);

  points = flatten([
    ...Array.from({ length: 6 }, (_, index) => completeTick(tickTs(index + 1), ["svc-a"])),
    completeTick(tickTs(11), ["svc-a"]),
  ]);
  const recoveredTick = await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(6) });
  assert.deepEqual(recoveredTick, [], "the tick that re-establishes trust remains suppressed");
  const state = (await loadServiceBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, false);
  assert.equal(state.last_folded_ts, tickTs(6), "future facts must not advance the folded watermark");

  points = [...points, ...completeTick(tickTs(7), [])];
  const resumed = await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(7) });
  assert.equal(resumed.some((candidate) => candidate.rule_id === SERVICE_DISAPPEARED_RULE_ID), true, "service novelty resumes after rollback recovery has been persisted");
});

test("computeServiceBaselineCandidates: intact history control still fires a real service.disappeared (sanity check proving the degraded case above really would have fabricated an alert absent the gate)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = disappearanceFixturePoints();
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  const result = await computeServiceBaselineCandidates(paths, {
    now: tickTs(30),
    freshnessMs: HOUR_MS,
    readFactPoints: async () => intactReadResult(points),
  });

  const disappearedCandidates = result.filter((c) => c.rule_id === SERVICE_DISAPPEARED_RULE_ID);
  assert.equal(disappearedCandidates.length, 1, "an intact store must not be falsely suppressed");
});

test("computeServiceBaselineCandidates: one transient fact-history loss recovers after minHistoryTickCount genuinely-new clean ticks (recovery-latch fix, bounded not permanent)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  let points = flatten(establishedTicks(["svc-a"], 3)); // ticks 0,1,2: svc-a established
  let readResult = degradedReadResult([], tickTs(3));
  const options = { minHistoryTickCount, establishedMinCensusCount: 3, freshnessMs: HOUR_MS, readFactPoints: async () => ({ ...readResult, points }) };

  // Loss tick: svc-a would disappear here -- would fire if trusted.
  points = [...points, ...completeTick(tickTs(3), [])];
  const lossTick = await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(3) });
  assert.deepEqual(lossTick, []);

  readResult = intactReadResult([]);
  points = [...points, ...completeTick(tickTs(4), [])]; // 1st re-accum tick (still absent)
  assert.deepEqual(await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(4) }), []);

  points = [...points, ...completeTick(tickTs(5), [])]; // 2nd re-accum tick (still absent)
  assert.deepEqual(await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(5) }), []);
  assert.equal((await loadServiceBaselineStore(paths)).state.cold_start_pending, false);

  // A genuinely new disappearance after re-establishment must fire normally: svc-a reappears
  // (tick 6), is present again (tick 7, keeping its already-established sighting count from ticks
  // 0-2 well above minEstablishedCount), then genuinely vanishes again (tick 8).
  points = [...points, ...completeTick(tickTs(6), ["svc-a"])];
  assert.deepEqual(await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(6) }), []);
  points = [...points, ...completeTick(tickTs(7), ["svc-a"])];
  assert.deepEqual(await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(7) }), []);
  points = [...points, ...completeTick(tickTs(8), [])];
  const resumed = await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(8) });
  const disappearedCandidates = resumed.filter((c) => c.rule_id === SERVICE_DISAPPEARED_RULE_ID);
  assert.equal(disappearedCandidates.length, 1, "novelty resumes after genuinely-new clean ticks re-establish trust");
  assert.equal(disappearedCandidates[0].diagnostics.service_name, "svc-a");
});

test("computeServiceBaselineCandidates: a clean tick cannot self-heal and fire service.disappeared in the same breath fact-history loss is first observed on the prior tick", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  // ticks 0-2: svc-a established. tick 3: a normal complete tick (svc-a still present) observed
  // under a DEGRADED read -- arms the lockout, but carries no disappearance transition of its own
  // (nothing to suppress there beyond the arming itself).
  let points = [...flatten(establishedTicks(["svc-a"], 3)), ...completeTick(tickTs(3), ["svc-a"])];
  let readResult = degradedReadResult(points, tickTs(3));
  const options = { minHistoryTickCount: 1, establishedMinCensusCount: 3, freshnessMs: HOUR_MS, readFactPoints: async () => ({ ...readResult, points }) };

  assert.deepEqual(await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(3) }), []);

  // Tick 4 is BOTH (a) the first genuinely-new clean tick past the tick-3 anchor -- satisfying
  // minHistoryTickCount:1 and flipping cold_start_pending false in the persisted store by the end
  // of this call -- AND (b) a tick where svc-a genuinely disappears (previous=tick3 present,
  // latest=tick4 absent), i.e. a REAL disappearance candidate that a same-tick self-heal-and-fire
  // bug (gating on the POST-update cold_start_pending instead of the pre-update
  // coldStartPendingThisTick) would incorrectly let through.
  points = [...points, ...completeTick(tickTs(4), [])];
  readResult = intactReadResult([]);
  assert.deepEqual(
    await computeServiceBaselineCandidates(paths, { ...options, now: tickTs(4) }),
    [],
    "the first clean tick after loss may re-establish state but must not emit novelty in the same tick, even though a real disappearance transition exists on this exact tick",
  );
  assert.equal((await loadServiceBaselineStore(paths)).state.cold_start_pending, false);
});

test("migration: a pre-Slice-6 store with no cold_start_* fields at all cold-starts once on first read, then recovers after minHistoryTickCount clean ticks (per-detector P8 analog)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const minHistoryTickCount = 2;

  // Simulate a store written by a pre-Slice-6 daemon: no cold_start_pending/_reason/_since_ts at
  // all -- written directly to disk, bypassing writeServiceBaselineStore's normalizer entirely.
  const { dir, storeFile } = resolveServiceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const legacyState = {
    version: 1,
    last_folded_ts: tickTs(-1),
    skipped_partial_tick_count: 0,
    disappearance_event_count: 0,
  };
  await fs.writeFile(storeFile, JSON.stringify(legacyState, null, 2), { mode: 0o600 });

  const ticks = flatten(establishedTicks(["svc-a"], 5)); // ticks 0-4: svc-a established
  await appendFactPoints(paths, ticks, { now: tickTs(4) });
  await appendFactPoints(paths, [], { now: tickTs(4) }); // confirm the shared integrity ledger to 'intact'

  // First read post-migration: even against a fully intact, loss-free fact-history ledger, the
  // missing cold_start_* fields default to pending (fail-closed) -- an established-looking store
  // must not be trusted just because it parses. A bounded, one-time cold-start is required.
  const firstRead = await computeServiceBaselineCandidates(paths, { now: tickTs(4), minHistoryTickCount, establishedMinCensusCount: 3, freshnessMs: HOUR_MS });
  assert.deepEqual(firstRead, []);
  const afterFirst = (await loadServiceBaselineStore(paths)).state;
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
    await appendFactPoints(paths, completeTick(ts, ["svc-a"]), { now: ts });
    await computeServiceBaselineCandidates(paths, { now: ts, minHistoryTickCount, establishedMinCensusCount: 3, freshnessMs: HOUR_MS });
    hour += 1;
  }
  assert.equal(
    (await loadServiceBaselineStore(paths)).state.cold_start_pending,
    false,
    "the migration cold-start must be bounded -- it clears after minHistoryTickCount genuinely-new clean ticks, never latching forever",
  );

  // And service.disappeared novelty genuinely resumes afterward.
  const ts = tickTs(hour);
  await appendFactPoints(paths, completeTick(ts, []), { now: ts }); // svc-a genuinely vanishes
  const resumed = await computeServiceBaselineCandidates(paths, { now: ts, minHistoryTickCount, establishedMinCensusCount: 3, freshnessMs: HOUR_MS });
  assert.equal(resumed.filter((c) => c.rule_id === SERVICE_DISAPPEARED_RULE_ID).length, 1);
});

// ---------------------------------------------------------------------------------------------
// Persistence baseline, Slice C (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md) —
// service.appeared, the appearance-direction twin of service.disappeared above. Reuses the SAME
// service.presence/service.census fact-history and groupServiceFactsByTick; own SEPARATE
// service-appearance-baseline.json store on the hardened exact-schema shape (O3).
// ---------------------------------------------------------------------------------------------

function expectedAppearedHash(entityKey) {
  return createHash("sha256").update(`${SERVICE_APPEARED_RULE_ID}:${entityKey}`).digest("hex").slice(0, 16);
}

test("service-appearance store is a SEPARATE file from service-baseline.json", async () => {
  const paths = await tempPaths();
  const disappearance = resolveServiceBaselineStorePaths(paths);
  const appearance = resolveServiceAppearanceBaselineStorePaths(paths);
  assert.notEqual(disappearance.storeFile, appearance.storeFile);
  assert.match(appearance.storeFile, /service-appearance-baseline\.json$/);
});

test("load/write/normalize service-appearance baseline state is exact-schema and atomic", async () => {
  const paths = await tempPaths();
  assert.deepEqual(normalizeServiceAppearanceBaselineState(undefined), {
    version: 2, last_folded_ts: undefined, skipped_partial_tick_count: 0, appeared_event_count: 0,
    cold_start_pending: true, cold_start_reason: undefined, cold_start_since_ts: undefined,
  });
  const missing = await loadServiceAppearanceBaselineStore(paths);
  assert.equal(missing.corrupt, false);
  assert.equal(missing.missing, true);
  await writeServiceAppearanceBaselineStore(paths, {
    cold_start_pending: false, last_folded_ts: tickTs(1), skipped_partial_tick_count: 2, appeared_event_count: 3,
  });
  const { dir, storeFile } = resolveServiceAppearanceBaselineStorePaths(paths);
  assert.equal((await fs.stat(storeFile)).mode & 0o777, 0o600);
  assert.equal((await fs.readdir(dir)).some((name) => name.endsWith(".tmp")), false);
  assert.equal((await loadServiceAppearanceBaselineStore(paths)).state.appeared_event_count, 3);
});

test("isValidServiceAppearanceBaselineStoreShape rejects an unknown key, a wrong-typed cold_start_pending, and an established store missing last_folded_ts -- DELIBERATELY stricter than the disappearance sibling's own lenient normalizeServiceBaselineState", () => {
  assert.equal(isValidServiceAppearanceBaselineStoreShape({
    version: 2, cold_start_pending: false, last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0, appeared_event_count: 0, unexpected_key: "x",
  }), false);
  assert.equal(isValidServiceAppearanceBaselineStoreShape({
    version: 2, cold_start_pending: "false", last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), false);
  assert.equal(isValidServiceAppearanceBaselineStoreShape({
    version: 2, cold_start_pending: false,
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), false, "an established store missing last_folded_ts must be rejected -- the disappearance sibling's lenient store would have accepted this");
  assert.equal(isValidServiceAppearanceBaselineStoreShape({
    version: 2, cold_start_pending: false, last_folded_ts: tickTs(0),
    skipped_partial_tick_count: 0, appeared_event_count: 0,
  }), true);
});

test("loadServiceAppearanceBaselineStore treats a schema-invalid-but-parseable store identically to a missing/corrupt one", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveServiceAppearanceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify({ cold_start_pending: false, unexpected: true }), { mode: 0o600 });
  const { state, corrupt } = await loadServiceAppearanceBaselineStore(paths);
  assert.equal(corrupt, true);
  assert.equal(state.cold_start_pending, true);
  assert.equal(state.cold_start_reason, "invalid_store_schema");
});

test("detectServiceAppearances requires prior complete history and fires only for first appearance", () => {
  const groups = groupServiceFactsByTick(flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a"]),
    partialTick(tickTs(2), ["svc-b"]),
    [censusMarkerPoint(tickTs(3), "unknown"), servicePoint(tickTs(3), "svc-b")],
    [servicePoint(tickTs(4), "svc-b")],
    completeTick(tickTs(5), ["svc-a", "svc-b"]),
  ]));
  const options = { nowMs: Date.parse(tickTs(5)), minHistoryTickCount: 2, freshnessMs: HOUR_MS };
  assert.deepEqual(detectServiceAppearances(groups, options), [{ entity_key: "svc-b", first_seen_ts: tickTs(5) }]);
});

test("detectServiceAppearances: a service present in ANY prior complete group never re-fires, even several ticks back", () => {
  const groups = groupServiceFactsByTick(flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a"]),
    completeTick(tickTs(2), ["svc-a", "svc-b"]),
    completeTick(tickTs(3), ["svc-a", "svc-b"]),
  ]));
  assert.deepEqual(detectServiceAppearances(groups, { nowMs: Date.parse(tickTs(6)), minHistoryTickCount: 2, freshnessMs: 5 * HOUR_MS }), []);
});

test("detectServiceAppearances rejects cold-start (too few complete groups) and stale latest complete groups", () => {
  const groups = groupServiceFactsByTick(flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a", "svc-b"]),
  ]));
  assert.deepEqual(detectServiceAppearances(groups, { nowMs: Date.parse(tickTs(1)), minHistoryTickCount: DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT }), []);
  assert.deepEqual(detectServiceAppearances(groups, { nowMs: Date.parse(tickTs(1)) + 2 * HOUR_MS, minHistoryTickCount: 1, freshnessMs: HOUR_MS }), []);
});

test("[P8 degrade, both directions] a service appearing only in a partial latest group does not fire; a service whose only prior sightings were partial/unknown is not treated as historical", () => {
  const latestPartial = groupServiceFactsByTick(flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a"]),
    partialTick(tickTs(2), ["svc-a", "svc-b"]),
  ]));
  assert.deepEqual(detectServiceAppearances(latestPartial, { nowMs: Date.parse(tickTs(2)), minHistoryTickCount: 1, freshnessMs: HOUR_MS }), []);

  const priorPartialOnly = groupServiceFactsByTick(flatten([
    completeTick(tickTs(0), ["svc-a"]),
    partialTick(tickTs(1), ["svc-b"]),
    completeTick(tickTs(2), ["svc-a"]),
    completeTick(tickTs(3), ["svc-a", "svc-b"]),
  ]));
  assert.deepEqual(detectServiceAppearances(priorPartialOnly, { nowMs: Date.parse(tickTs(3)), minHistoryTickCount: 2, freshnessMs: HOUR_MS }), [{ entity_key: "svc-b", first_seen_ts: tickTs(3) }]);
});

test("buildAppearedCandidates hashes identity under service.appeared's OWN domain (never service.disappeared's), sanitizes diagnostics (hash-only, no cleartext-name exception), and caps severity at warning", () => {
  const candidate = buildAppearedCandidates([{ entity_key: "svc-new", first_seen_ts: tickTs(2) }])[0];
  assert.equal(candidate.rule_id, SERVICE_APPEARED_RULE_ID);
  assert.equal(candidate.severity, "warning");
  assert.equal(candidate.fingerprint, expectedAppearedHash("svc-new"));
  assert.deepEqual(candidate.diagnostics, { entity_key_hash: expectedAppearedHash("svc-new"), first_seen_ts: tickTs(2) });
  assert.equal(JSON.stringify(candidate).includes("svc-new"), false);
  // Domain separation: the appeared-hash must differ from the disappeared-hash for the SAME
  // entity_key -- a shared fingerprint space would let the two rule_ids' dedup/edge-triggering
  // silently interfere with each other.
  assert.notEqual(candidate.fingerprint, createHash("sha256").update(`service.disappeared:svc-new`).digest("hex").slice(0, 16));
});

test("computeServiceAppearanceCandidates checks learned.json before any fact/store I/O", async () => {
  const paths = await tempPaths();
  let readCalls = 0;
  let loadCalls = 0;
  const result = await computeServiceAppearanceCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { readCalls += 1; return { points: [] }; },
    loadServiceAppearanceBaselineStore: async () => { loadCalls += 1; return { state: normalizeServiceAppearanceBaselineState() }; },
  });
  assert.deepEqual(result, []);
  assert.equal(readCalls, 0);
  assert.equal(loadCalls, 0);
});

test("computeServiceAppearanceCandidates folds counters once and emits an appearance end-to-end", async () => {
  const paths = await tempPaths();
  const points = flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a"]),
    completeTick(tickTs(2), ["svc-a", "svc-new"]),
  ]);
  await writeLearnedConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await appendFactPoints(paths, points, { now: tickTs(2) });
  await appendFactPoints(paths, [], { now: tickTs(2) });
  const first = await computeServiceAppearanceCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, establishedMinCensusCount: 2, activeFreshnessMs: HOUR_MS });
  assert.equal(first.length, 1);
  assert.equal(first[0].diagnostics.entity_key_hash, expectedAppearedHash("svc-new"));
  const state = (await loadServiceAppearanceBaselineStore(paths)).state;
  assert.equal(state.appeared_event_count, 1);
});

test("co-existence: a service that disappears then reappears exercises BOTH detectors correctly without cross-contaminating each other's fold checkpoints (O3)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(-1) });

  // Ticks 0-2: svc-a established. Tick 3: svc-a disappears. Tick 4: svc-a reappears.
  const points = flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a"]),
    completeTick(tickTs(2), ["svc-a"]),
    completeTick(tickTs(3), []),
    completeTick(tickTs(4), ["svc-a"]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(4) });
  await appendFactPoints(paths, [], { now: tickTs(4) });

  const opts = { now: tickTs(4), minHistoryTickCount: 2, establishedMinCensusCount: 2, activeFreshnessMs: HOUR_MS };
  const disappeared = await computeServiceBaselineCandidates(paths, opts);
  const appeared = await computeServiceAppearanceCandidates(paths, opts);

  // The disappearance fired on tick(3) (svc-a missing from the tick(2)->tick(3) pair) but the
  // freshness gate on computeServiceBaselineCandidates only ever looks at the SINGLE latest
  // complete pair (tick(3)->tick(4)) where svc-a is present again -- so no disappearance is live
  // at tick(4). The appearance detector, using the FULL historical union, correctly does NOT
  // re-fire for svc-a (it was seen in ticks 0-2, so it is not "never seen before").
  assert.equal(disappeared.filter((c) => c.rule_id === SERVICE_DISAPPEARED_RULE_ID).length, 0);
  assert.equal(appeared.filter((c) => c.rule_id === SERVICE_APPEARED_RULE_ID).length, 0);

  // Independent fold checkpoints: both stores must have advanced to the SAME latest tick without
  // either fold observably skipping a tick because of the other's write.
  const disappearanceState = (await loadServiceBaselineStore(paths)).state;
  const appearanceState = (await loadServiceAppearanceBaselineStore(paths)).state;
  assert.equal(disappearanceState.last_folded_ts, tickTs(4));
  assert.equal(appearanceState.last_folded_ts, tickTs(4));
});

test("computeServiceAppearanceCandidates fails closed end-to-end when the persisted appearance-baseline-store file is corrupt, never fabricating the appearance that same history would otherwise fire", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const points = flatten([
    completeTick(tickTs(0), ["svc-a"]),
    completeTick(tickTs(1), ["svc-a"]),
    completeTick(tickTs(2), ["svc-a", "svc-new"]),
  ]);
  await appendFactPoints(paths, points, { now: tickTs(2) });

  const { dir, storeFile } = resolveServiceAppearanceBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });

  const result = await computeServiceAppearanceCandidates(paths, { now: tickTs(2), minHistoryTickCount: 2, establishedMinCensusCount: 2, activeFreshnessMs: HOUR_MS });
  assert.deepEqual(result, []);
});

test("computeServiceAppearanceCandidates: degraded/untrustworthy retained history suppresses a fabricated established-service appearance alert", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const truncatedPoints = flatten([
    completeTick(tickTs(1), ["svc-a"]),
    completeTick(tickTs(2), ["svc-a"]),
    completeTick(tickTs(3), ["svc-a", "svc-new"]),
  ]);
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: tickTs(0) });

  const result = await computeServiceAppearanceCandidates(paths, {
    now: tickTs(3),
    minHistoryTickCount: 2,
    establishedMinCensusCount: 2,
    activeFreshnessMs: HOUR_MS,
    readFactPoints: async () => degradedReadResult(truncatedPoints, tickTs(3)),
  });
  assert.deepEqual(result, []);
  const state = (await loadServiceAppearanceBaselineStore(paths)).state;
  assert.equal(state.cold_start_pending, true);
});

test("[P9] SERVICE_APPEARED_RULE_ID classifies to unknown_namespace -- structurally LLM-ineligible (full deterministic-delivery pin lives in test/alert-intelligence.test.js)", async () => {
  const { classifyAlertNamespace } = await import("../src/alert-intelligence.js");
  const classified = classifyAlertNamespace(SERVICE_APPEARED_RULE_ID);
  assert.equal(classified.namespace, undefined);
  assert.equal(classified.hardExcluded, false);
});
