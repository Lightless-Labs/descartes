import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  buildCanaryTamperedCandidates,
  buildCanaryTrippedCandidates,
  computeCanaryBaselineCandidates,
  detectCanaryTrips,
  groupCanaryFactsByTick,
  loadCanaryBaselineStore,
  resolveCanaryBaselineStorePaths,
  writeCanaryBaselineStore,
} from "../src/canary-baseline.js";

const ts = (day) => `2026-08-${String(day).padStart(2, "0")}T00:00:00.000Z`;

const CANARY_IDENTITY_FINGERPRINT_DOMAIN = "descartes.canary.identity.v1";
const CANARY_IDENTITY_FINGERPRINT_SEPARATOR = "\u0000";
function identityFingerprint(canaryPath, sentinelPath) {
  return createHash("sha256")
    .update([CANARY_IDENTITY_FINGERPRINT_DOMAIN, canaryPath, sentinelPath ?? ""].join(CANARY_IDENTITY_FINGERPRINT_SEPARATOR))
    .digest("hex")
    .slice(0, 16);
}

const CURRENT_CANARY_PATH = "/fixture/credential";
const CURRENT_CANARY_IDENTITY = identityFingerprint(CURRENT_CANARY_PATH);

function manifestCanary(pathValue = CURRENT_CANARY_PATH) {
  return { id: "credential", kind: "credential-file", path: pathValue, watch: ["atime"] };
}

// identity_fingerprint defaults to a fixed, stable value across every tick (mirroring an
// unchanged canary's real behavior -- tools/canary.js's identity fingerprint only changes when
// the manifest's path/sentinel_path for this canary_id actually changes), so every EXISTING trip
// test below -- none of which is testing identity binding itself -- keeps behaving exactly as
// before FIX-A: (previousSnapshot.identityFingerprint === latestSnapshot.identityFingerprint)
// holds by default and detectCanaryTrips proceeds to compare attributes normally. The dedicated
// FIX-A tests further down override `identity_fingerprint` per-tick to simulate a manifest
// path/sentinel_path edit or a canary_id reused for a different underlying file.
function presence(day, id = "credential", attributes = {}) {
  return {
    ts: ts(day),
    fact_name: "canary.presence",
    entity_key: id,
    attributes: {
      atime: "100",
      mtime: "100",
      ino: "1",
      size: "2",
      executed: "false",
      kind: "credential-file",
      watch: "atime",
      identity_fingerprint: "fp-stable-v1",
      ...attributes,
    },
  };
}

function census(day, state = "complete") {
  return { ts: ts(day), fact_name: "canary.census", entity_key: "canary.census-marker.v1", attributes: { census_state: state } };
}

function threeTicks(latestAttributes = {}) {
  return groupCanaryFactsByTick([
    presence(1), census(1),
    presence(2), census(2),
    presence(3, "credential", latestAttributes), census(3),
  ]);
}

// Fact-store completeness hardening (Slice 7) fixtures, mirroring session-baseline.test.js's/
// service-baseline.test.js's own intactReadResult/degradedReadResult exactly -- injected via
// options.readFactPoints so the dedicated cold-start tests below don't need to fabricate real
// ledger corruption/eviction.
function intactReadResult(points, completeness = { status: "intact" }) {
  return { points, corrupt_count: 0, schema_invalid_count: 0, completeness };
}

function degradedReadResult(points, lossTs) {
  return { points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "degraded", last_bytecap_evict_ts: lossTs } };
}

// One millisecond before the given day's ts -- a convenient "anchored strictly before this
// fixture's earliest point" watermark for pre-seeding an established cold-start store.
function anchorBefore(day) {
  return new Date(Date.parse(ts(day)) - 1).toISOString();
}

// Slice 7 gave canary-baseline.js its own persistent cold-start lockout, mirroring
// session-baseline.js's/service-baseline.js's own. Every test ABOVE this point in the file
// predates Slice 7 and exercises canary-baseline's OTHER logic (trip detection, identity binding,
// manifest gating, tamper alerts, ...), not the lockout itself -- their readFactPoints/
// loadCanaryBaselineStore fixtures are updated (via this helper + intactReadResult above) to
// present an already-established, loss-free history wherever the test's own assertions require
// novelty output, exactly mirroring session-baseline.test.js's/service-baseline.test.js's own
// precedent. The lockout mechanism itself has its own dedicated coverage further down in this
// file.
function establishedCanaryState(overrides = {}) {
  return {
    version: 1,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    trip_event_count: 0,
    cold_start_pending: false,
    cold_start_reason: undefined,
    cold_start_since_ts: undefined,
    ...overrides,
  };
}

test("groups strict census states and carries executed/watch snapshots", () => {
  const groups = groupCanaryFactsByTick([
    presence(1, "one", { executed: "true", watch: "mtime,executed" }), census(1, "complete"),
    presence(2, "two"), census(2, "garbled"),
    presence(3, "three"),
  ]);
  assert.equal(groups[0].censusState, "complete");
  assert.equal(groups[1].censusState, "unknown");
  assert.equal(groups[2].censusState, undefined);
  assert.deepEqual(groups[0].canaries.get("one"), {
    atime: "100", mtime: "100", ino: "1", size: "2", executed: "true", kind: "credential-file", watch: "mtime,executed",
    identityFingerprint: "fp-stable-v1",
  });
});

test("detects atime, mtime, and executed transitions", () => {
  const nowMs = new Date(ts(3)).getTime();
  assert.equal(detectCanaryTrips(threeTicks({ atime: "101" }), { nowMs, minEstablishedCount: 3 })[0].trip_reason, "atime_advanced");
  assert.equal(detectCanaryTrips(threeTicks({ mtime: "101", watch: "mtime" }), { nowMs, minEstablishedCount: 3 })[0].trip_reason, "mtime_changed");
  assert.equal(detectCanaryTrips(threeTicks({ executed: "true", watch: "executed" }), { nowMs, minEstablishedCount: 3 })[0].trip_reason, "executed");
});

test("uses latest watch provenance and order, with freshness and cold-start gates", () => {
  const points = [
    presence(1, "credential", { atime: "100", mtime: "100", watch: "atime" }), census(1),
    presence(2, "credential", { atime: "101", mtime: "100", watch: "atime" }), census(2),
    presence(3, "credential", { atime: "102", mtime: "101", watch: "mtime,atime" }), census(3),
  ];
  const groups = groupCanaryFactsByTick(points);
  const nowMs = new Date(ts(3)).getTime();
  assert.equal(detectCanaryTrips(groups, { nowMs, minEstablishedCount: 3 })[0].trip_reason, "mtime_changed");
  assert.deepEqual(detectCanaryTrips(groups, { nowMs, minEstablishedCount: 4 }), []);
  assert.deepEqual(detectCanaryTrips(groups, { nowMs: nowMs + 10_000, freshnessMs: 1, minEstablishedCount: 3 }), []);

  const absentLatest = groupCanaryFactsByTick([presence(1), census(1), presence(2), census(2), census(3)]);
  assert.deepEqual(detectCanaryTrips(absentLatest, { nowMs, minEstablishedCount: 1 }), []);
});

test("a blackout tick (partial census, e.g. from an unreadable canary) is excluded, and the trip still fires across it", () => {
  const points = [
    presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1, "complete"),
    // Day 2: "credential" was unreadable this tick, so no presence fact was emitted for it and
    // the census marker correctly reports "partial" (fact-translators.js's HIGH fix) rather than
    // "complete" — this tick must be excluded from detectCanaryTrips's two-COMPLETE-group diff.
    census(2, "partial"),
    presence(3, "credential", { mtime: "999", watch: "mtime" }), census(3, "complete"),
  ];
  const groups = groupCanaryFactsByTick(points);
  const nowMs = new Date(ts(3)).getTime();
  const trips = detectCanaryTrips(groups, { nowMs, minEstablishedCount: 2 });
  assert.equal(trips.length, 1);
  assert.equal(trips[0].trip_reason, "mtime_changed");
  // The comparison spans the blackout tick straight back to day 1, proving the partial tick was
  // skipped rather than silently treated as a clean baseline.
  assert.equal(trips[0].last_seen_ts, ts(1));
});

test("P1 fix: a sentinel-EACCES blackout tick's census is partial, and a genuine false->unknown->true execution across it still fires", () => {
  const points = [
    presence(1, "credential", { executed: "false", watch: "executed" }), census(1, "complete"),
    // Day 2: the sentinel access() failed with EACCES this tick (fact-translators.js's P1 fix,
    // mirroring tools/canary.js's degrade-not-fabricate "unknown"). A presence fact IS still
    // emitted (lstat succeeded — the canary's `status` is "ok") but with executed:"unknown", and
    // the census marker must report "partial" here, not "complete".
    presence(2, "credential", { executed: "unknown", watch: "executed" }), census(2, "partial"),
    presence(3, "credential", { executed: "true", watch: "executed" }), census(3, "complete"),
  ];
  const groups = groupCanaryFactsByTick(points);
  assert.equal(groups[1].censusState, "partial");
  const nowMs = new Date(ts(3)).getTime();
  const trips = detectCanaryTrips(groups, { nowMs, minEstablishedCount: 2 });
  // Day 2 (partial) is excluded from the two-COMPLETE-group comparison, so the diff spans
  // straight from day 1's confirmed "false" to day 3's "true" and the trip fires.
  assert.equal(trips.length, 1);
  assert.equal(trips[0].trip_reason, "executed");
  assert.equal(trips[0].last_seen_ts, ts(1));
});

test("fails closed on a missing attribute: a hole on either side never trips (mtime and executed)", () => {
  const nowMs = new Date(ts(3)).getTime();
  // Latest mtime missing (e.g. dropped by a degraded translator run): must SKIP, not trip on
  // undefined !== previous.
  const latestMissingMtime = groupCanaryFactsByTick([
    presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1),
    presence(2, "credential", { mtime: "100", watch: "mtime" }), census(2),
    presence(3, "credential", { mtime: undefined, watch: "mtime" }), census(3),
  ]);
  assert.deepEqual(detectCanaryTrips(latestMissingMtime, { nowMs, minEstablishedCount: 3 }), []);

  // Previous (second-to-last complete) tick's mtime missing: must SKIP, not trip against a
  // fabricated "changed" baseline.
  const previousMissingMtime = groupCanaryFactsByTick([
    presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1),
    presence(2, "credential", { mtime: undefined, watch: "mtime" }), census(2),
    presence(3, "credential", { mtime: "101", watch: "mtime" }), census(3),
  ]);
  assert.deepEqual(detectCanaryTrips(previousMissingMtime, { nowMs, minEstablishedCount: 3 }), []);

  // Previous tick's executed missing/unknown (e.g. canary.js's degrade-not-fabricate "unknown"
  // for a non-ENOENT access() failure): must SKIP, not trip a critical "executed" candidate on a
  // hole rather than a confirmed prior "false".
  const previousMissingExecuted = groupCanaryFactsByTick([
    presence(1, "credential", { executed: "false", watch: "executed" }), census(1),
    presence(2, "credential", { executed: "unknown", watch: "executed" }), census(2),
    presence(3, "credential", { executed: "true", watch: "executed" }), census(3),
  ]);
  assert.deepEqual(detectCanaryTrips(previousMissingExecuted, { nowMs, minEstablishedCount: 3 }), []);
});

test("watch order chooses one deterministic reason when multiple attributes move", () => {
  const groups = threeTicks({ atime: "101", mtime: "101", watch: "mtime,atime" });
  const trips = detectCanaryTrips(groups, { nowMs: new Date(ts(3)).getTime(), minEstablishedCount: 3 });
  assert.equal(trips.length, 1);
  assert.equal(trips[0].trip_reason, "mtime_changed");
});

// IDENTITY BINDING (FIX-A, canary v0 finalization) --------------------------------------------
//
// Hard invariant under test: detectCanaryTrips must NEVER fabricate a trip by comparing an OLD
// identity's facts against a NEW identity's facts under the same canary_id (entity_key). See
// canary-baseline.js's own header comment above canarySightingKey for the full rationale.

test("FIX-A (i): a manifest path edit (same canary_id, new identity_fingerprint) produces NO fabricated trip", () => {
  // Day 1-2: the canary at its ORIGINAL path, established under identity_fingerprint "fp-old".
  // Day 3: the operator edits canaries.json to point this SAME canary_id at a different file --
  // the collector now reports a NEW identity_fingerprint ("fp-new") and, incidentally, a "later"
  // mtime for the new file -- exactly the shape that, uncorrected, would look like a genuine
  // mtime_changed trip against day 2's recorded mtime.
  const points = [
    presence(1, "credential", { mtime: "100", watch: "mtime", identity_fingerprint: "fp-old" }), census(1),
    presence(2, "credential", { mtime: "100", watch: "mtime", identity_fingerprint: "fp-old" }), census(2),
    presence(3, "credential", { mtime: "999", watch: "mtime", identity_fingerprint: "fp-new" }), census(3),
  ];
  const groups = groupCanaryFactsByTick(points);
  const nowMs = new Date(ts(3)).getTime();
  assert.deepEqual(detectCanaryTrips(groups, { nowMs, minEstablishedCount: 2 }), []);
});

test("FIX-A (ii): a canary_id reused for a different underlying file produces NO fabricated trip (including on the executed watch)", () => {
  // Day 1-2: "credential" established against file A (identity_fingerprint "fp-fileA"), sentinel
  // never observed executed.
  // Day 3: the manifest entry for "credential" is deleted and a brand-new entry reusing the SAME
  // id "credential" is added, pointing at an entirely different file B (identity_fingerprint
  // "fp-fileB") whose own sentinel already exists -- executed:"true" from the very first
  // observation of file B, purely because it's a different file, not because anything was
  // actually touched. Uncorrected, this is exactly the false->true shape detectCanaryTrips'
  // executed watch fires a CRITICAL trip on.
  const points = [
    presence(1, "credential", { executed: "false", watch: "executed", identity_fingerprint: "fp-fileA" }), census(1),
    presence(2, "credential", { executed: "false", watch: "executed", identity_fingerprint: "fp-fileA" }), census(2),
    presence(3, "credential", { executed: "true", watch: "executed", identity_fingerprint: "fp-fileB" }), census(3),
  ];
  const groups = groupCanaryFactsByTick(points);
  const nowMs = new Date(ts(3)).getTime();
  assert.deepEqual(detectCanaryTrips(groups, { nowMs, minEstablishedCount: 2 }), []);
});

test("FIX-A (iii): a genuine access to an UNCHANGED canary (stable identity_fingerprint) still trips", () => {
  // Same identity_fingerprint on every tick (the default the `presence()` fixture already uses,
  // matching a real canary whose manifest entry was never edited) -- the mtime change on day 3 is
  // a genuine observation of the SAME file and must still trip normally.
  const points = [
    presence(1, "credential", { mtime: "100", watch: "mtime", identity_fingerprint: "fp-stable" }), census(1),
    presence(2, "credential", { mtime: "100", watch: "mtime", identity_fingerprint: "fp-stable" }), census(2),
    presence(3, "credential", { mtime: "999", watch: "mtime", identity_fingerprint: "fp-stable" }), census(3),
  ];
  const groups = groupCanaryFactsByTick(points);
  const nowMs = new Date(ts(3)).getTime();
  const trips = detectCanaryTrips(groups, { nowMs, minEstablishedCount: 2 });
  assert.equal(trips.length, 1);
  assert.equal(trips[0].trip_reason, "mtime_changed");
  assert.equal(trips[0].canary_id, "credential");
});

test("FIX-A: a missing identity_fingerprint on either side (pre-migration fact history) fails CLOSED -- no trip, not a fabricated match against another missing value", () => {
  const nowMs = new Date(ts(3)).getTime();
  const bothMissing = groupCanaryFactsByTick([
    { ts: ts(1), fact_name: "canary.presence", entity_key: "credential", attributes: { mtime: "100", watch: "mtime", kind: "credential-file" } },
    census(1),
    { ts: ts(2), fact_name: "canary.presence", entity_key: "credential", attributes: { mtime: "100", watch: "mtime", kind: "credential-file" } },
    census(2),
    { ts: ts(3), fact_name: "canary.presence", entity_key: "credential", attributes: { mtime: "999", watch: "mtime", kind: "credential-file" } },
    census(3),
  ]);
  assert.deepEqual(detectCanaryTrips(bothMissing, { nowMs, minEstablishedCount: 2 }), []);
});

test("builds critical hash-keyed candidates with sanitized diagnostics", () => {
  const [candidate] = buildCanaryTrippedCandidates([{
    canary_id: "credential.bak",
    kind: "credential-file",
    trip_reason: "executed",
    last_seen_ts: ts(2),
  }]);
  assert.equal(candidate.severity, "critical");
  assert.equal(candidate.rule_id, "canary.tripped");
  assert.notEqual(candidate.fingerprint, "credential.bak");
  assert.match(candidate.id, /^alert_[0-9a-f]{16}$/);
  assert.equal(candidate.diagnostics.canary_id, "credential.bak");
  const [unsafe] = buildCanaryTrippedCandidates([{ canary_id: "!!!", kind: "credential-file", trip_reason: "executed" }]);
  assert.notEqual(unsafe.diagnostics.canary_id, "!!!");
});

test("disabled learned config short-circuits before fact or store I/O", async () => {
  let reads = 0;
  let stores = 0;
  const result = await computeCanaryBaselineCandidates({}, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => { reads += 1; return { points: [] }; },
    loadCanaryBaselineStore: async () => { stores += 1; return { state: {} }; },
  });
  assert.deepEqual(result, []);
  assert.equal(reads, 0);
  assert.equal(stores, 0);
});

test("compute folds counters once and rebuilds candidates on repeated calls", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  // Slice 7: pre-establish the cold-start lockout -- a single one-shot compute call can never
  // itself satisfy re-establishment (see establishedCanaryState's own comment above).
  let state = establishedCanaryState();
  let writes = 0;
  const options = {
    now: ts(3),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({ state }),
    writeCanaryBaselineStore: async (_paths, next) => { writes += 1; state = next; return next; },
    loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }] }),
  };
  try {
    const first = await computeCanaryBaselineCandidates(paths, options);
    const second = await computeCanaryBaselineCandidates(paths, options);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(writes, 1);
    assert.equal(state.trip_event_count, 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("manifest-gated: a canary removed from the current manifest produces no further trips", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  // Slice 7: pre-established (see establishedCanaryState's own comment above) so this test keeps
  // exercising the manifest gate itself, not the (separately-covered) cold-start lockout.
  const state = establishedCanaryState();
  try {
    const stillPresent = await computeCanaryBaselineCandidates(paths, {
      now: ts(3),
      establishedMinCensusCount: 3,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult(points),
      loadCanaryBaselineStore: async () => ({ state }),
      writeCanaryBaselineStore: async (_paths, next) => next,
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }] }),
    });
    assert.equal(stillPresent.length, 1);

    // Same stale trip-shaped facts, but the manifest no longer lists "credential" — simulating
    // canaries.json having the entry removed (also covers emptied/corrupted/unreadable, since
    // loadCanaryManifest degrades all of those to the identical `{ canaries: [] }` shape).
    const decommissioned = await computeCanaryBaselineCandidates(paths, {
      now: ts(3),
      establishedMinCensusCount: 3,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult(points),
      loadCanaryBaselineStore: async () => ({ state }),
      writeCanaryBaselineStore: async (_paths, next) => next,
      loadCanaryManifest: async () => ({ canaries: [] }),
    });
    assert.deepEqual(decommissioned, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("P1 fix: a corrupt/unreadable manifest (read_ok:false) does NOT suppress candidates for already-established canaries -- fails the gate OPEN", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  // Slice 7: pre-established (see establishedCanaryState's own comment above).
  const state = establishedCanaryState();
  try {
    // Mirrors the shape the real loadCanaryManifest now returns for a genuine read/parse
    // FAILURE (canary-manifest.js's P1 fix): canaries:[] with read_ok:false, NOT the
    // authoritative-empty-manifest shape ({ canaries: [] } alone / read_ok:true) a legitimate
    // decommission produces.
    const stillFires = await computeCanaryBaselineCandidates(paths, {
      now: ts(3),
      establishedMinCensusCount: 3,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult(points),
      loadCanaryBaselineStore: async () => ({ state }),
      writeCanaryBaselineStore: async (_paths, next) => next,
      loadCanaryManifest: async () => ({ canaries: [], unreadable: true, read_ok: false }),
    });
    // Tamper fix (canary v0 finalization): the gate still fails OPEN (the trip still fires) AND
    // the read_ok:false itself now ALSO raises a dedicated canary.tampered(manifest_unreadable)
    // alert -- a corrupt/unreadable manifest must never again go completely unnoticed.
    assert.equal(stillFires.length, 2);
    const trip = stillFires.find((candidate) => candidate.rule_id === "canary.tripped");
    const tamper = stillFires.find((candidate) => candidate.rule_id === "canary.tampered");
    assert.equal(trip.diagnostics.trip_reason, "atime_advanced");
    assert.equal(tamper.severity, "critical");
    assert.equal(tamper.diagnostics.tamper_reason, "manifest_unreadable");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("P1 fix, end-to-end with the real loadCanaryManifest: a corrupted canaries.json on disk does not silence an established canary's trip", async () => {
  const stateRoot = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const configRoot = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-manifest-"));
  const paths = { stateDir: stateRoot, configDir: configRoot };
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  try {
    // An attacker (or disk corruption) truncates/mangles canaries.json -- no fs mocking, the real
    // loadCanaryManifest reads this actual file and must report read_ok:false for it.
    await fs.writeFile(path.join(configRoot, "canaries.json"), "{not json");
    const candidates = await computeCanaryBaselineCandidates(paths, {
      now: ts(3),
      establishedMinCensusCount: 3,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult(points),
      // Slice 7: pre-established (see establishedCanaryState's own comment above) rather than a
      // real fresh (cold_start_pending:true) read off an empty stateRoot.
      loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
      writeCanaryBaselineStore: async (_paths, next) => next,
    });
    // Tamper fix (canary v0 finalization): now also raises canary.tampered(manifest_unreadable)
    // alongside the trip, end-to-end against the real loadCanaryManifest.
    assert.equal(candidates.length, 2);
    const trip = candidates.find((candidate) => candidate.rule_id === "canary.tripped");
    const tamper = candidates.find((candidate) => candidate.rule_id === "canary.tampered");
    assert.equal(trip.diagnostics.trip_reason, "atime_advanced");
    assert.equal(tamper.diagnostics.tamper_reason, "manifest_unreadable");
  } finally {
    await fs.rm(stateRoot, { recursive: true, force: true });
    await fs.rm(configRoot, { recursive: true, force: true });
  }
});

// CANARY VANISHED --------------------------------------------------------------------------

test("canary vanished: a canary still listed in the manifest that disappears from the latest complete census raises canary.tampered, not canary.tripped", async () => {
  const points = [
    presence(1, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(1),
    presence(2, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(2),
    // Day 3: "credential" is genuinely gone (ENOENT) -- collectOneCanary never emits a presence
    // fact for it, but that alone does not force the census to "partial" (a lone ENOENT is
    // ordinary evidence, not a this-tick read failure), so the tick is still "complete".
    census(3),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 2,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    // Slice 7: pre-established (see establishedCanaryState's own comment above) so this test keeps
    // exercising canary_vanished detection itself, not the (separately-covered) cold-start lockout.
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [manifestCanary()], read_ok: true }),
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, "canary.tampered");
  assert.equal(candidates[0].severity, "critical");
  assert.equal(candidates[0].diagnostics.tamper_reason, "canary_vanished");
  assert.equal(candidates[0].diagnostics.canary_id, "credential");
  assert.equal(candidates[0].diagnostics.last_seen_ts, ts(2));
});

test("legit decommission: a canary removed from the manifest AND gone produces NO tamper alert (indistinguishable from decommission -- inherent host-local limit)", async () => {
  const points = [
    presence(1, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(1),
    presence(2, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(2),
    census(3),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 2,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    // The operator has ALSO removed "credential" from the manifest -- the canary being both gone
    // AND absent from the manifest is a legitimate decommission, not tamper.
    loadCanaryManifest: async () => ({ canaries: [], read_ok: true }),
  });
  assert.deepEqual(candidates, []);
});

test("a canary that never reached the established sighting-count threshold does not raise canary_vanished on disappearance (avoids false positives on freshly-added canaries)", async () => {
  const points = [
    presence(1, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(1),
    census(2),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(2),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [manifestCanary()], read_ok: true }),
  });
  assert.deepEqual(candidates, []);
});

// FIX-A parity for CANARY VANISHED (identity binding, canary v0 finalization -- terminal fix) ---
//
// Hard invariant under test: detectCanaryVanished must NEVER fabricate a canary_vanished alert by
// letting a NEW identity under a reused/edited canary_id inherit an OLD identity's established
// sighting count. See canary-baseline.js's own FIX-A parity header comment above
// detectCanaryVanished for the full rationale.

test("FIX-A parity (i): an id-reuse / path-edit whose NEW identity never reached its own establishment threshold raises NO fabricated canary_vanished (previously inherited the OLD identity's sighting count)", async () => {
  const newIdentity = identityFingerprint("/fixture/credential-new");
  const points = [
    // Day 1-2: "credential" established against file A (identity_fingerprint "fp-old") -- reaches
    // the established threshold (2) purely under its own identity.
    presence(1, "credential", { identity_fingerprint: "fp-old" }), census(1),
    presence(2, "credential", { identity_fingerprint: "fp-old" }), census(2),
    // Day 3: the manifest entry for "credential" is edited (or its id reused) to point at a
    // different file B -- a NEW identity fingerprint -- sighted for the very first time.
    presence(3, "credential", { identity_fingerprint: newIdentity }), census(3),
    // Day 4: file B disappears (ENOENT) having been observed under its own identity only ONCE --
    // it never itself reached the established-sighting threshold. Uncorrected (counting by
    // canary_id alone), this canary_id's TOTAL appearances across days 1-3 (3) would clear the
    // threshold on borrowed history from "fp-old" and fabricate a canary_vanished alert about an
    // identity that was never actually established.
    census(4),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(4),
    establishedMinCensusCount: 2,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [manifestCanary("/fixture/credential-new")], read_ok: true }),
  });
  assert.deepEqual(candidates, []);
});

test("FIX-A parity (ii): a genuinely-established, UNCHANGED-identity canary that actually vanishes still raises canary.tampered(canary_vanished)", async () => {
  const points = [
    presence(1, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(1),
    presence(2, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(2),
    presence(3, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(3),
    // Day 4: the SAME identity that was genuinely established over days 1-3 is now genuinely gone.
    census(4),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(4),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    // Slice 7: pre-established (see establishedCanaryState's own comment above).
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [manifestCanary()], read_ok: true }),
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, "canary.tampered");
  assert.equal(candidates[0].diagnostics.tamper_reason, "canary_vanished");
  assert.equal(candidates[0].diagnostics.canary_id, "credential");
  assert.equal(candidates[0].diagnostics.last_seen_ts, ts(3));
});

test("FIX-A parity (iii): id reuse for an already-absent new path with zero observations raises no fabricated canary_vanished", async () => {
  const points = [
    presence(1, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(1),
    presence(2, "credential", { identity_fingerprint: CURRENT_CANARY_IDENTITY }), census(2),
    // The manifest now points at a different path, but that new identity was never observed.
    census(3),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 2,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [manifestCanary("/fixture/credential-never-observed")], read_ok: true }),
  });
  assert.deepEqual(candidates, []);
});

// MANIFEST TAMPER ---------------------------------------------------------------------------

test("manifest tamper: a successfully-read, genuinely empty manifest (legit decommission/never-configured) raises NO tamper alert", async () => {
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(1),
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => ({ points: [] }),
    loadCanaryBaselineStore: async () => ({ state: { version: 1, skipped_partial_tick_count: 0, trip_event_count: 0 } }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [], read_ok: true }),
  });
  assert.deepEqual(candidates, []);
});

test("manifest tamper: a schema-invalid manifest (read_ok:false) raises canary.tampered(manifest_unreadable)", async () => {
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(1),
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => ({ points: [] }),
    loadCanaryBaselineStore: async () => ({ state: { version: 1, skipped_partial_tick_count: 0, trip_event_count: 0 } }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [], schema_invalid: true, read_ok: false }),
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, "canary.tampered");
  assert.equal(candidates[0].diagnostics.tamper_reason, "manifest_unreadable");
  assert.equal(candidates[0].diagnostics.canary_id, undefined);
});

// BASELINE-STORE FAILURE --------------------------------------------------------------------

test("baseline-store failure: a throwing loadCanaryBaselineStore never aborts the tick, raises canary.tampered(baseline_store_error), and does not suppress canary.tripped", async () => {
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  let writeCalled = false;
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => { const error = new Error("denied"); error.code = "EACCES"; throw error; },
    writeCanaryBaselineStore: async () => { writeCalled = true; },
    loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
  });
  // The store failure arms the vanished-claim lockout and raises direct tamper evidence, but a
  // positive two-snapshot trip remains trustworthy and must not be silenced by that lockout.
  const trip = candidates.find((candidate) => candidate.rule_id === "canary.tripped");
  const tamper = candidates.find((candidate) => candidate.rule_id === "canary.tampered");
  assert.equal(trip.diagnostics.trip_reason, "atime_advanced");
  // ...and a dedicated tamper alert is raised for the broken store, without ever throwing out of
  // computeCanaryBaselineCandidates (a throw here would abort the ENTIRE daemon tick).
  assert.equal(tamper.diagnostics.tamper_reason, "baseline_store_error");
  // No fold-write is attempted against a load that failed -- nothing safe to fold onto.
  assert.equal(writeCalled, false);
});

test("baseline-store failure: a throwing writeCanaryBaselineStore never aborts the tick and raises canary.tampered(baseline_store_error) -- the LOAD succeeded, so canary.tripped still fires normally", async () => {
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    // Slice 7: pre-established (see establishedCanaryState's own comment above) -- the LOAD itself
    // succeeds here (only the write fails below), so the lockout is not implicated.
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState() }),
    writeCanaryBaselineStore: async () => { const error = new Error("read-only filesystem"); error.code = "EROFS"; throw error; },
    loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
  });
  const trip = candidates.find((candidate) => candidate.rule_id === "canary.tripped");
  const tamper = candidates.find((candidate) => candidate.rule_id === "canary.tampered");
  assert.equal(trip.diagnostics.trip_reason, "atime_advanced");
  assert.equal(tamper.diagnostics.tamper_reason, "baseline_store_error");
});

test("baseline-store failure: a corrupt-but-non-throwing store load (existing degrade-to-fresh-state behavior) now ALSO raises canary.tampered(baseline_store_error)", async () => {
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    // Mirrors the real loadCanaryBaselineStore's own corrupt-file shape (Slice 7): a corrupt store
    // degrades to a fresh, cold_start_pending:true state, not merely bare bookkeeping counters.
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState({ cold_start_pending: true, cold_start_reason: "corrupt_store" }), corrupt: true }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
  });
  const tamper = candidates.find((candidate) => candidate.rule_id === "canary.tampered");
  assert.equal(tamper.diagnostics.tamper_reason, "baseline_store_error");
});

test("baseline-store deletion does not raise a false tamper and does not disable a positive canary.tripped", async () => {
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(3),
    establishedMinCensusCount: 3,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({ state: establishedCanaryState({ cold_start_pending: true, cold_start_reason: "missing_store" }), missing: true }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
  });
  assert.equal(candidates.filter((candidate) => candidate.rule_id === "canary.tripped").length, 1);
  assert.equal(candidates.some((candidate) => candidate.rule_id === "canary.tampered"), false);
});

test("legit first run: configured canaries with a genuinely absent baseline store and no facts produce no alert", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  try {
    const candidates = await computeCanaryBaselineCandidates({ stateDir: root }, {
      now: ts(1),
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult([]),
      loadCanaryManifest: async () => ({ canaries: [manifestCanary()], read_ok: true }),
    });
    assert.deepEqual(candidates, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("legit decommission with retained facts: an absent baseline store and removed canary produce no alert", async () => {
  const points = [presence(1), census(1), presence(2), census(2)];
  const candidates = await computeCanaryBaselineCandidates({}, {
    now: ts(2),
    establishedMinCensusCount: 2,
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => intactReadResult(points),
    loadCanaryBaselineStore: async () => ({
      state: establishedCanaryState({ cold_start_pending: true, cold_start_reason: "missing_store" }),
      missing: true,
    }),
    writeCanaryBaselineStore: async (_paths, next) => next,
    loadCanaryManifest: async () => ({ canaries: [], read_ok: true }),
  });
  assert.deepEqual(candidates, []);
});

test("baseline-store failure, end-to-end with the real loadCanaryBaselineStore: an unreadable store on disk (EISDIR) does not abort the tick or suppress canary.tripped", async () => {
  const stateRoot = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: stateRoot };
  const points = [
    presence(1), census(1), presence(2), census(2), presence(3, "credential", { atime: "101" }), census(3),
  ];
  try {
    const { dir, storeFile } = resolveCanaryBaselineStorePaths(paths);
    await fs.mkdir(dir, { recursive: true });
    // Directory trick (mirrors canary-manifest.test.js's own pattern): making the store path
    // itself a directory forces a real, non-ENOENT fs.readFile failure regardless of uid.
    await fs.mkdir(storeFile, { recursive: true });
    const candidates = await computeCanaryBaselineCandidates(paths, {
      now: ts(3),
      establishedMinCensusCount: 3,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult(points),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    });
    const trip = candidates.find((candidate) => candidate.rule_id === "canary.tripped");
    const tamper = candidates.find((candidate) => candidate.rule_id === "canary.tampered");
    assert.equal(trip.diagnostics.trip_reason, "atime_advanced");
    assert.equal(tamper.diagnostics.tamper_reason, "baseline_store_error");
  } finally {
    await fs.rm(stateRoot, { recursive: true, force: true });
  }
});

test("builds canary.tampered candidates with sanitized diagnostics and stable per-reason fingerprints", () => {
  const [manifestTamper] = buildCanaryTamperedCandidates([{ reason: "manifest_unreadable" }]);
  assert.equal(manifestTamper.rule_id, "canary.tampered");
  assert.equal(manifestTamper.severity, "critical");
  assert.match(manifestTamper.id, /^alert_[0-9a-f]{16}$/);
  assert.equal(manifestTamper.diagnostics.tamper_reason, "manifest_unreadable");

  // Same reason, called twice -> identical fingerprint/id (stable cooldown/dedup for a
  // persistently-unreadable manifest, rather than a fresh alert id every tick).
  const [again] = buildCanaryTamperedCandidates([{ reason: "manifest_unreadable" }]);
  assert.equal(again.id, manifestTamper.id);
  assert.equal(again.fingerprint, manifestTamper.fingerprint);

  const [vanished] = buildCanaryTamperedCandidates([{ canary_id: "credential", kind: "credential-file", reason: "canary_vanished", last_seen_ts: ts(2) }]);
  assert.equal(vanished.diagnostics.canary_id, "credential");
  assert.equal(vanished.diagnostics.canary_kind, "credential-file");
  assert.notEqual(vanished.fingerprint, manifestTamper.fingerprint);
  const [unsafe] = buildCanaryTamperedCandidates([{ canary_id: "!!!", kind: "credential-file", reason: "canary_vanished" }]);
  assert.notEqual(unsafe.diagnostics.canary_id, "!!!");
});

test("baseline store round-trips normalized state", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-store-"));
  try {
    await writeCanaryBaselineStore({ stateDir: root }, { last_folded_ts: ts(3), skipped_partial_tick_count: 2, trip_event_count: 4 });
    const loaded = await loadCanaryBaselineStore({ stateDir: root });
    // Slice 7: round-tripping through normalizeCanaryBaselineState now also fail-closed-defaults
    // the three cold-start lockout fields (not supplied above) to pending:true (missing ⇒ still
    // pending, per the same idiom process-lineage/session/service/peer already use).
    assert.deepEqual(loaded.state, {
      version: 1,
      last_folded_ts: ts(3),
      skipped_partial_tick_count: 2,
      trip_event_count: 4,
      cold_start_pending: true,
      cold_start_reason: undefined,
      cold_start_since_ts: undefined,
    });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------------
// Fact-store completeness hardening (Slice 7): persistent cold-start lockout.
// docs/plans/2026-08-21-fact-store-completeness-hardening.md, "Required test in every one of
// Slices 3-7" + the per-detector migration test. Mirrors session-baseline.test.js's/
// service-baseline.test.js's own dedicated cold-start coverage, adapted to canary's
// tripped/vanished shape.
// ---------------------------------------------------------------------------------------------

test("computeCanaryBaselineCandidates: degraded truncated history does not suppress a positive canary.tripped transition", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  try {
    await writeCanaryBaselineStore(paths, { cold_start_pending: false, last_folded_ts: anchorBefore(1) });
    const points = [
      presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1),
      presence(2, "credential", { mtime: "999", watch: "mtime" }), census(2), // would trip if trusted
    ];

    const result = await computeCanaryBaselineCandidates(paths, {
      now: ts(2),
      establishedMinCensusCount: 2,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => degradedReadResult(points, ts(2)),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    });

    const trips = result.filter((candidate) => candidate.rule_id === "canary.tripped");
    assert.equal(trips.length, 1, "incomplete history must not suppress direct two-snapshot trip evidence");
    const { state } = await loadCanaryBaselineStore(paths);
    assert.equal(state.cold_start_pending, true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("computeCanaryBaselineCandidates: intact history control still fires a real canary.tripped", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  try {
    await writeCanaryBaselineStore(paths, { cold_start_pending: false, last_folded_ts: anchorBefore(1) });
    const points = [
      presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1),
      presence(2, "credential", { mtime: "999", watch: "mtime" }), census(2),
    ];

    const result = await computeCanaryBaselineCandidates(paths, {
      now: ts(2),
      establishedMinCensusCount: 2,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => intactReadResult(points),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    });

    const trips = result.filter((candidate) => candidate.rule_id === "canary.tripped");
    assert.equal(trips.length, 1, "an intact store must not be falsely suppressed");
    assert.equal(trips[0].diagnostics.trip_reason, "mtime_changed");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("computeCanaryBaselineCandidates: one transient fact-history loss recovers after minHistoryTickCount genuinely-new clean ticks (recovery-latch fix, bounded not permanent)", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  try {
    const minHistoryTickCount = 2;
    await writeCanaryBaselineStore(paths, { cold_start_pending: false, last_folded_ts: anchorBefore(1) });

    let points = [presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1)];
    let readResult = degradedReadResult([], ts(2));
    const options = {
      minHistoryTickCount,
      establishedMinCensusCount: 2,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => ({ ...readResult, points }),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    };

    // Loss tick: credential's mtime would change here (100 -> 999) -- would trip if trusted.
    points = [...points, presence(2, "credential", { mtime: "999", watch: "mtime" }), census(2)];
    const lossTick = await computeCanaryBaselineCandidates(paths, { ...options, now: ts(2) });
    assert.equal(lossTick.filter((candidate) => candidate.rule_id === "canary.tripped").length, 1);

    readResult = intactReadResult([]);
    points = [...points, presence(3, "credential", { mtime: "999", watch: "mtime" }), census(3)]; // 1st re-accum tick
    assert.deepEqual(await computeCanaryBaselineCandidates(paths, { ...options, now: ts(3) }), []);

    points = [...points, presence(4, "credential", { mtime: "999", watch: "mtime" }), census(4)]; // 2nd re-accum tick
    assert.deepEqual(await computeCanaryBaselineCandidates(paths, { ...options, now: ts(4) }), []);
    assert.equal((await loadCanaryBaselineStore(paths)).state.cold_start_pending, false);

    // A genuinely new mtime change after re-establishment must trip normally.
    points = [...points, presence(5, "credential", { mtime: "12345", watch: "mtime" }), census(5)];
    const resumed = await computeCanaryBaselineCandidates(paths, { ...options, now: ts(5) });
    const trips = resumed.filter((candidate) => candidate.rule_id === "canary.tripped");
    assert.equal(trips.length, 1, "novelty resumes after genuinely-new clean ticks re-establish trust");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("computeCanaryBaselineCandidates: positive trips remain observable while loss is first detected and while trust re-establishes", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  try {
    await writeCanaryBaselineStore(paths, { cold_start_pending: false, last_folded_ts: anchorBefore(1) });

    let points = [
      presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1),
      presence(2, "credential", { mtime: "100", watch: "mtime" }), census(2),
      presence(3, "credential", { mtime: "999", watch: "mtime" }), census(3), // would trip if trusted
    ];
    let readResult = degradedReadResult(points, ts(3));
    const options = {
      minHistoryTickCount: 1,
      establishedMinCensusCount: 2,
      loadLearnedConfig: async () => ({ enabled: true }),
      readFactPoints: async () => ({ ...readResult, points }),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    };

    const lossTick = await computeCanaryBaselineCandidates(paths, { ...options, now: ts(3) });
    assert.equal(lossTick.filter((candidate) => candidate.rule_id === "canary.tripped").length, 1);

    // Day 4: a GENUINE new mtime change (999 -> 1234) lands on the very tick that qualifies as the
    // first re-accumulation tick. Positive trip evidence is emitted even while that state changes.
    points = [...points, presence(4, "credential", { mtime: "1234", watch: "mtime" }), census(4)];
    readResult = intactReadResult([]);
    const recovered = await computeCanaryBaselineCandidates(paths, { ...options, now: ts(4) });
    assert.equal(recovered.filter((candidate) => candidate.rule_id === "canary.tripped").length, 1);
    assert.equal((await loadCanaryBaselineStore(paths)).state.cold_start_pending, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("migration: a pre-Slice-7 store with no cold_start_* fields at all cold-starts once on first read, then recovers after minHistoryTickCount clean ticks (per-detector P8 analog)", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  try {
    const minHistoryTickCount = 2;

    // Simulate a store written by a pre-Slice-7 daemon: no cold_start_pending/_reason/_since_ts at
    // all -- written directly to disk, bypassing writeCanaryBaselineStore's normalizer entirely.
    const { dir, storeFile } = resolveCanaryBaselineStorePaths(paths);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const legacyState = { version: 1, last_folded_ts: anchorBefore(1), skipped_partial_tick_count: 0, trip_event_count: 0 };
    await fs.writeFile(storeFile, JSON.stringify(legacyState, null, 2), { mode: 0o600 });

    let points = [presence(1, "credential", { mtime: "100", watch: "mtime" }), census(1)];
    const baseOptions = {
      minHistoryTickCount,
      establishedMinCensusCount: 2,
      loadLearnedConfig: async () => ({ enabled: true }),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    };

    // First read post-migration: even against a fully intact, loss-free fact-history, the missing
    // cold_start_* fields default to pending (fail-closed) -- an established-looking store must not
    // be trusted just because it parses. A bounded, one-time cold-start is required.
    const firstRead = await computeCanaryBaselineCandidates(paths, { ...baseOptions, now: ts(1), readFactPoints: async () => intactReadResult(points) });
    assert.deepEqual(firstRead, []);
    const afterFirst = (await loadCanaryBaselineStore(paths)).state;
    assert.equal(afterFirst.cold_start_pending, true);
    assert.equal(
      typeof afterFirst.cold_start_since_ts,
      "string",
      "the migration must synthesize a real anchor, never leave it undefined (the Infinity re-establishment-boundary trap)",
    );
    assert.ok(Number.isFinite(new Date(afterFirst.cold_start_since_ts).getTime()));

    // minHistoryTickCount genuinely-new clean ticks after the migration anchor re-establish trust.
    for (let day = 2; day <= 1 + minHistoryTickCount; day += 1) {
      points = [...points, presence(day, "credential", { mtime: "100", watch: "mtime" }), census(day)];
      await computeCanaryBaselineCandidates(paths, { ...baseOptions, now: ts(day), readFactPoints: async () => intactReadResult(points) });
    }
    assert.equal(
      (await loadCanaryBaselineStore(paths)).state.cold_start_pending,
      false,
      "the migration cold-start must be bounded -- it clears after minHistoryTickCount genuinely-new clean ticks, never latching forever",
    );

    // And canary.tripped genuinely resumes afterward.
    const resumeDay = 2 + minHistoryTickCount;
    points = [...points, presence(resumeDay, "credential", { mtime: "999", watch: "mtime" }), census(resumeDay)];
    const resumed = await computeCanaryBaselineCandidates(paths, { ...baseOptions, now: ts(resumeDay), readFactPoints: async () => intactReadResult(points) });
    assert.equal(resumed.filter((candidate) => candidate.rule_id === "canary.tripped").length, 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("computeCanaryBaselineCandidates: rollback repairs a future anchor, a future watermark, and a future ledger loss ts, then persists re-established trust without re-latching", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-baseline-"));
  const paths = { stateDir: root };
  try {
    await writeCanaryBaselineStore(paths, {
      cold_start_pending: true,
      cold_start_since_ts: ts(20),
      last_folded_ts: ts(20),
    });

    // A single tick, far in the future relative to the clock below -- must not fold, score, or
    // satisfy re-accumulation while the clock hasn't caught up to it.
    let points = [presence(21, "credential", { mtime: "100", watch: "mtime" }), census(21)];
    const options = {
      minHistoryTickCount: 6,
      establishedMinCensusCount: 2,
      loadLearnedConfig: async () => ({ enabled: true }),
      // "intact" status but with a FUTURE loss timestamp embedded (last_corrupt_ts far ahead of
      // nowMs) -- must never count against trust once nowMs is still behind it.
      readFactPoints: async () => intactReadResult(points, { status: "intact", last_corrupt_ts: ts(25) }),
      loadCanaryManifest: async () => ({ canaries: [{ id: "credential" }], read_ok: true }),
    };

    await computeCanaryBaselineCandidates(paths, { ...options, now: ts(1) });
    assert.equal((await loadCanaryBaselineStore(paths)).state.last_folded_ts, undefined, "a future watermark must be clamped, not trusted");

    // Day 1's own tick equals the anchor set by the first call above (ts(1)) and so does NOT count
    // toward re-accumulation (strictly-AFTER, not at-or-after) -- days 2-7 (6 ticks) are what
    // satisfy minHistoryTickCount:6 by the time `now` reaches day 7.
    points = [];
    for (let day = 1; day <= 7; day += 1) points.push(presence(day, "credential", { mtime: "100", watch: "mtime" }), census(day));
    points.push(presence(21, "credential", { mtime: "100", watch: "mtime" }), census(21));

    const recoveredTick = await computeCanaryBaselineCandidates(paths, { ...options, now: ts(7) });
    assert.deepEqual(recoveredTick, [], "the tick that re-establishes trust remains suppressed");
    const state = (await loadCanaryBaselineStore(paths)).state;
    assert.equal(state.cold_start_pending, false);
    assert.equal(state.last_folded_ts, ts(7), "future facts must not advance the folded watermark");

    points = [...points, presence(8, "credential", { mtime: "999", watch: "mtime" }), census(8)];
    const resumed = await computeCanaryBaselineCandidates(paths, { ...options, now: ts(8) });
    assert.equal(
      resumed.some((candidate) => candidate.rule_id === "canary.tripped"),
      true,
      "canary novelty resumes after rollback recovery has been persisted, and does not re-latch",
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
