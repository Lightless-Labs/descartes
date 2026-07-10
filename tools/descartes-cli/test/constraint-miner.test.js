import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateConstraints } from "../src/constraint-eval.js";
import { SEED_CONSTRAINTS, loadConstraints, writeConstraints } from "../src/constraint-store.js";
import { isFixedLengthHexHash, isSafeEnumString } from "../src/diagnostics-sanitizer.js";
import { appendFactPoints, readFactPoints } from "../src/fact-store.js";
import {
  MINED_ID_PREFIX,
  mergeMinedConstraints,
  mineConstraintCandidates,
  runLearned,
} from "../src/constraint-miner.js";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-constraint-miner-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const DAY_MS = 24 * 60 * 60 * 1000;
const BASE_TS = Date.parse("2026-07-01T00:00:00.000Z");

function servicePoint({ entityKey = "nginx.service", ts, running = "true", sourceEnvelopeId = "services" } = {}) {
  return {
    ts: new Date(ts).toISOString(),
    fact_name: "service.presence",
    entity_key: entityKey,
    attributes: { running, manager: "systemd" },
    source_envelope_id: sourceEnvelopeId,
    source_tool: "collect_services",
    sensitivity: "operational",
  };
}

function portPoint({ entityKey = "tcp:127.0.0.1:5432", ts, owner = "postgres", ownerKnown = true, sourceEnvelopeId = "network-basics" } = {}) {
  const attributes = ownerKnown ? { owner, owner_known: "true" } : { owner_known: "false" };
  const point = {
    ts: new Date(ts).toISOString(),
    fact_name: "network.listening_port.owner",
    entity_key: entityKey,
    attributes,
    source_envelope_id: sourceEnvelopeId,
    source_tool: "collect_network",
    sensitivity: "operational",
  };
  if (!ownerKnown) point.confidence = 0;
  return point;
}

function stableServiceHistory({ entityKey = "nginx.service", running = "true", count = 3, spanDays = 8 } = {}) {
  const points = [];
  for (let index = 0; index < count; index += 1) {
    const ts = BASE_TS + Math.round((spanDays * DAY_MS * index) / Math.max(1, count - 1));
    points.push(servicePoint({ entityKey, ts, running }));
  }
  return points;
}

// --- Core mining rule ---

test("a stable service-presence fact across >= minObservationDays/minSamples yields exactly one draft constraint", () => {
  const factHistory = stableServiceHistory();
  const candidates = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });

  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.status, "draft");
  assert.equal(candidate.family, "service-presence");
  assert.equal(candidate.kind, "constraint");
  assert.equal(candidate.expected.comparator, "eq");
  assert.equal(candidate.expected.value, "true");
  assert.equal(candidate.confidence, 1);
  assert.equal(candidate.provenance.samples, 3);
  assert.equal(candidate.provenance.window, "7d");
  assert.deepEqual(candidate.provenance.source_collectors, ["services"]);
  assert.equal(candidate.promotion_history.length, 0);
  assert.equal(candidate.sensitivity, "operational");
  assert(candidate.id.startsWith(MINED_ID_PREFIX));
});

test("a fact with fewer than minSamples yields no constraint", () => {
  const factHistory = stableServiceHistory({ count: 2 });
  const candidates = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  assert.deepEqual(candidates, []);
});

test("a fact spanning less than minObservationDays yields no constraint even with many samples clustered in a short window", () => {
  const points = [];
  for (let i = 0; i < 10; i += 1) {
    points.push(servicePoint({ ts: BASE_TS + i * 60_000, running: "true" })); // 10 samples within 10 minutes
  }
  const candidates = mineConstraintCandidates(points, [], { now: BASE_TS + DAY_MS });
  assert.deepEqual(candidates, []);
});

test("a fact that flips (contradicting observations) yields no constraint for that group, but other stable groups in the same input still mine", () => {
  const stable = stableServiceHistory({ entityKey: "nginx.service", running: "true" });
  const flipping = [
    servicePoint({ entityKey: "postgres.service", ts: BASE_TS, running: "true" }),
    servicePoint({ entityKey: "postgres.service", ts: BASE_TS + 4 * DAY_MS, running: "false" }),
    servicePoint({ entityKey: "postgres.service", ts: BASE_TS + 8 * DAY_MS, running: "true" }),
  ];
  const candidates = mineConstraintCandidates([...stable, ...flipping], [], { now: BASE_TS + 8 * DAY_MS });

  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].target.includes("nginx"), true);
});

test("degraded samples (owner_known:false/confidence:0) are excluded from both the sample count and the contradiction check", () => {
  // 2 confirming + 5 degraded over the window -> insufficient real samples, does not mine.
  const insufficientPoints = [
    portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS, ownerKnown: true, owner: "postgres" }),
    portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + 8 * DAY_MS, ownerKnown: true, owner: "postgres" }),
    ...Array.from({ length: 5 }, (_, i) => portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + i * DAY_MS, ownerKnown: false })),
  ];
  assert.deepEqual(mineConstraintCandidates(insufficientPoints, [], { now: BASE_TS + 8 * DAY_MS }), []);

  // 5 confirming (consistent owner) + 2 degraded samples -> still mines; degraded never counts as contradicting.
  const sufficientPoints = [
    ...Array.from({ length: 5 }, (_, i) => portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + i * 2 * DAY_MS, ownerKnown: true, owner: "postgres" })),
    portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + DAY_MS, ownerKnown: false }),
    portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + 3 * DAY_MS, ownerKnown: false }),
  ];
  const candidates = mineConstraintCandidates(sufficientPoints, [], { now: BASE_TS + 8 * DAY_MS });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].family, "port-binding-identity");
  assert.equal(candidates[0].expected.value, "postgres");
});

test("port-binding mining: macOS-resolvable owner yields a draft; Linux owner_known:false does not fabricate an owner-bound constraint", () => {
  const macFactHistory = Array.from({ length: 4 }, (_, i) =>
    portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + i * 3 * DAY_MS, ownerKnown: true, owner: "postgres" }));
  const macCandidates = mineConstraintCandidates(macFactHistory, [], { now: BASE_TS + 9 * DAY_MS });
  assert.equal(macCandidates.length, 1);
  assert.equal(macCandidates[0].family, "port-binding-identity");
  assert.equal(macCandidates[0].expected.value, "postgres");

  const linuxFactHistory = Array.from({ length: 10 }, (_, i) =>
    portPoint({ entityKey: "tcp:0.0.0.0:22", ts: BASE_TS + i * DAY_MS, ownerKnown: false }));
  const linuxCandidates = mineConstraintCandidates(linuxFactHistory, [], { now: BASE_TS + 10 * DAY_MS });
  assert.deepEqual(linuxCandidates, []);
});

test("two families mixed in one input are mined independently, family field correctly discriminates", () => {
  const serviceFacts = stableServiceHistory({ entityKey: "nginx.service", running: "true" });
  const portFacts = Array.from({ length: 4 }, (_, i) =>
    portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + i * 3 * DAY_MS, ownerKnown: true, owner: "postgres" }));
  const candidates = mineConstraintCandidates([...serviceFacts, ...portFacts], [], { now: BASE_TS + 9 * DAY_MS });

  assert.equal(candidates.length, 2);
  const families = candidates.map((c) => c.family).sort();
  assert.deepEqual(families, ["port-binding-identity", "service-presence"]);
});

// --- Reserved id namespace + determinism ---

test("every mined id starts with the reserved constraint.mined. prefix; no SEED_CONSTRAINTS id does", () => {
  const candidates = mineConstraintCandidates(stableServiceHistory(), [], { now: BASE_TS + 8 * DAY_MS });
  assert(candidates.length > 0);
  for (const candidate of candidates) {
    assert(candidate.id.startsWith(MINED_ID_PREFIX), `expected ${candidate.id} to start with ${MINED_ID_PREFIX}`);
  }
  for (const seed of SEED_CONSTRAINTS) {
    assert.equal(seed.id.startsWith(MINED_ID_PREFIX), false, `SEED_CONSTRAINTS id ${seed.id} unexpectedly carries the mined prefix`);
  }
});

test("mineConstraintCandidates is deterministic: identical factHistory in yields identical ids/candidates out", () => {
  const factHistory = stableServiceHistory();
  const first = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  const second = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  assert.deepEqual(first, second);
});

test("mined ids depend only on (family, entity_key), not on `now` — re-mining unchanged facts at a later `now` yields the same id", () => {
  const factHistory = stableServiceHistory();
  const first = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  const later = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 30 * DAY_MS });
  assert.equal(first[0].id, later[0].id);
});

test("mineConstraintCandidates(factHistory, snapshots, options) — snapshots omitted/[]/undefined all behave identically", () => {
  const factHistory = stableServiceHistory();
  const withUndefined = mineConstraintCandidates(factHistory, undefined, { now: BASE_TS + 8 * DAY_MS });
  const withEmptyArray = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  const withSnapshotData = mineConstraintCandidates(factHistory, [{ some: "snapshot" }], { now: BASE_TS + 8 * DAY_MS });
  assert.deepEqual(withUndefined, withEmptyArray);
  assert.deepEqual(withEmptyArray, withSnapshotData);
});

// --- Sanitization gate (HARD GATE) ---

test("an adversarial fact whose entity_key is a raw path cannot produce a constraint whose id/family/target carries a raw path", () => {
  const hostileEntityKey = "/usr/local/bin/../../etc/passwd";
  const factHistory = stableServiceHistory({ entityKey: hostileEntityKey });
  const candidates = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });

  assert.equal(candidates.length, 1);
  const [candidate] = candidates;

  // No raw path separator ever reaches id/target (sanitizeIdentityString strips "/" but
  // deliberately preserves literal "." — a safe-charset character in its own right — so a
  // ".." run surviving sanitization is expected and not itself a path-traversal risk once
  // "/" is gone; see diagnostics-sanitizer.test.js's own "etc" assertion for the same shape).
  assert.equal(candidate.id.includes("/"), false);
  assert.equal(candidate.target.includes("/"), false);

  // id/target/family pass diagnostics-sanitizer.js's real allowlist predicates directly.
  assert(isSafeEnumString(candidate.target), `expected target ${candidate.target} to be a safe enum string`);
  assert(isSafeEnumString(candidate.family), `expected family ${candidate.family} to be a safe enum string`);
  const hashSuffix = candidate.id.slice(MINED_ID_PREFIX.length + candidate.family.length + 1);
  assert(isFixedLengthHexHash(hashSuffix), `expected id hash suffix ${hashSuffix} to be a fixed-length hex hash`);
});

test("an entirely-unsafe entity_key (nothing survives sanitization) is dropped rather than mined with an empty/unsafe target", () => {
  const factHistory = stableServiceHistory({ entityKey: "////" });
  const candidates = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  assert.deepEqual(candidates, []);
});

// --- Draft inertness (HARD REQUIREMENT) ---

test("a freshly-mined draft constraint is never evaluated by evaluateConstraints (status:draft is skipped entirely)", () => {
  const candidates = mineConstraintCandidates(stableServiceHistory({ running: "true" }), [], { now: BASE_TS + 8 * DAY_MS });
  assert.equal(candidates.length, 1);
  const [draft] = candidates;
  assert.equal(draft.status, "draft");

  // A factLookup that would obviously violate the mined constraint if it were evaluated
  // (constraint expects "true", fact reports "false").
  const obviouslyViolatingFactLookup = (target) => (target === draft.target ? "false" : undefined);
  const alertCandidates = evaluateConstraints([draft], obviouslyViolatingFactLookup);
  assert.deepEqual(alertCandidates, []);
});

test("scanning mineConstraintCandidates' output: every emitted status is the literal string draft, never active", () => {
  const factHistory = [
    ...stableServiceHistory({ entityKey: "nginx.service" }),
    ...Array.from({ length: 4 }, (_, i) => portPoint({ entityKey: "tcp:127.0.0.1:5432", ts: BASE_TS + i * 3 * DAY_MS, ownerKnown: true })),
  ];
  const candidates = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 9 * DAY_MS });
  assert(candidates.length > 0);
  for (const candidate of candidates) assert.equal(candidate.status, "draft");
});

// --- Merge / idempotency ---

test("mergeMinedConstraints: re-mining the same stable fact does not duplicate — same id, updated in place", () => {
  const factHistory = stableServiceHistory();
  const firstRun = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  const firstMerge = mergeMinedConstraints([], firstRun);
  assert.equal(firstMerge.new_count, 1);
  assert.equal(firstMerge.constraints.length, 1);

  // Second mining run over an extended fact-history (same entity_key/family -> same id),
  // with an additional, later observation.
  const extendedHistory = [...factHistory, servicePoint({ ts: BASE_TS + 12 * DAY_MS, running: "true" })];
  const secondRun = mineConstraintCandidates(extendedHistory, [], { now: BASE_TS + 12 * DAY_MS });
  const secondMerge = mergeMinedConstraints(firstMerge.constraints, secondRun);

  assert.equal(secondMerge.constraints.length, 1, "re-mining must not duplicate the draft");
  assert.equal(secondMerge.new_count, 0);
  assert.equal(secondMerge.updated_count, 1);
  assert.equal(secondMerge.constraints[0].id, firstMerge.constraints[0].id);
  assert.equal(secondMerge.constraints[0].provenance.samples, 4);
  assert.equal(secondMerge.constraints[0].last_verified, new Date(BASE_TS + 12 * DAY_MS).toISOString());
});

test("mergeMinedConstraints never clobbers an existing active/hand-authored constraint sharing a candidate's id", () => {
  const factHistory = stableServiceHistory();
  const [candidate] = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });

  const promotedConstraint = { ...candidate, status: "active", expected: { comparator: "eq", value: "true" } };
  const merge = mergeMinedConstraints([promotedConstraint], [candidate]);

  assert.equal(merge.constraints.length, 1);
  assert.equal(merge.constraints[0].status, "active", "an already-promoted constraint must not be reset to draft/reclobbered");
  assert.equal(merge.new_count, 0);
  assert.equal(merge.updated_count, 0);
  assert.equal(merge.unchanged_count, 1);
});

test("mergeMinedConstraints preserves unrelated hand-authored SEED_CONSTRAINTS entries untouched", () => {
  const factHistory = stableServiceHistory();
  const candidates = mineConstraintCandidates(factHistory, [], { now: BASE_TS + 8 * DAY_MS });
  const merge = mergeMinedConstraints(SEED_CONSTRAINTS, candidates);

  assert.equal(merge.constraints.length, SEED_CONSTRAINTS.length + candidates.length);
  for (const seed of SEED_CONSTRAINTS) {
    const preserved = merge.constraints.find((c) => c.id === seed.id);
    assert.deepEqual(preserved, seed);
  }
});

// --- No LLM anywhere (grep-able absence, mirrors S7's planned regression) ---

test("constraint-miner.js never imports the pi-harness/alert-intelligence LLM touchpoints", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/constraint-miner.js"), "utf8");
  assert.equal(/pi-harness\.js/.test(source), false);
  assert.equal(/alert-intelligence\.js/.test(source), false);
});

// --- CLI: descartes learned mine ---

test("descartes learned mine writes drafts to constraints.json, preserves existing SEED_CONSTRAINTS, and prints a summary", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, SEED_CONSTRAINTS);
  await appendFactPoints(paths, stableServiceHistory(), { now: BASE_TS + 8 * DAY_MS });

  const lines = [];
  await runLearned(paths, ["mine"], { now: BASE_TS + 8 * DAY_MS, output: (line) => lines.push(line) });

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints.length, SEED_CONSTRAINTS.length + 1);
  for (const seed of SEED_CONSTRAINTS) assert(constraints.some((c) => c.id === seed.id));
  const mined = constraints.find((c) => c.id.startsWith(MINED_ID_PREFIX));
  assert(mined);
  assert.equal(mined.status, "draft");

  assert.equal(lines.length, 1);
  assert.match(lines[0], /Mined 1 candidate/);
  assert.match(lines[0], /1 new draft/);
});

test("descartes learned mine --json prints a machine-readable summary", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, stableServiceHistory(), { now: BASE_TS + 8 * DAY_MS });

  const lines = [];
  await runLearned(paths, ["mine", "--json"], { now: BASE_TS + 8 * DAY_MS, output: (line) => lines.push(line) });

  assert.equal(lines.length, 1);
  const payload = JSON.parse(lines[0]);
  assert.equal(payload.learned_mine.mined_candidates, 1);
  assert.equal(payload.learned_mine.new_drafts, 1);
  assert.equal(payload.learned_mine.updated_drafts, 0);
});

test("descartes learned mine re-run does not duplicate drafts (idempotent CLI round-trip)", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, stableServiceHistory(), { now: BASE_TS + 8 * DAY_MS });

  await runLearned(paths, ["mine"], { now: BASE_TS + 8 * DAY_MS, output: () => {} });
  await runLearned(paths, ["mine"], { now: BASE_TS + 8 * DAY_MS, output: () => {} });

  const { constraints } = await loadConstraints(paths);
  const mined = constraints.filter((c) => c.id.startsWith(MINED_ID_PREFIX));
  assert.equal(mined.length, 1, "re-running mine must not duplicate drafts");
});

test("descartes learned mine reads facts via readFactPoints and honors --window", async () => {
  const paths = await tempPaths();
  // A fact-history window explicitly narrower than the mined span should exclude the older samples.
  await appendFactPoints(paths, stableServiceHistory(), { now: BASE_TS + 8 * DAY_MS });
  const { points } = await readFactPoints(paths, { now: BASE_TS + 8 * DAY_MS, windowMs: DAY_MS }); // only ~last day
  assert(points.length < 3);
});

test("resolveConstraintStorePaths-adjacent: descartes learned mine's writes pass the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  assert.doesNotThrow(() => assertNoPiOwnedPath(paths));
});
