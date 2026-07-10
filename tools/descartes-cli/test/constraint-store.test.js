import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_SOAK_DAYS,
  MIN_FIXTURE_COUNT,
  SEED_CONSTRAINTS,
  checkShadowSoak,
  loadConstraints,
  loadLearnedConfig,
  promoteDraftsToShadow,
  promoteShadowToReviewReady,
  resolveConstraintStorePaths,
  validateConstraint,
  writeConstraints,
  writeLearnedConfig,
} from "../src/constraint-store.js";

const DAY_MS = 24 * 60 * 60 * 1000;

function draftConstraint(overrides = {}) {
  return {
    id: "constraint.mined.service-presence.deadbeefdeadbeef",
    kind: "constraint",
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    status: "draft",
    confidence: 1,
    provenance: { window: "7d", samples: 5, source_collectors: ["services"], mined_at: "2026-07-01T00:00:00.000Z" },
    fixtures: [
      { input: { "service.presence": "true" }, expect_match: true },
      { input: { "service.presence": "false" }, expect_match: false },
    ],
    promotion_history: [],
    first_observed: "2026-07-01T00:00:00.000Z",
    last_verified: "2026-07-01T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

function shadowRecord(overrides = {}) {
  return {
    ts: "2026-07-02T00:00:00.000Z",
    constraint_id: draftConstraint().id,
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    actual: "true",
    fired: false,
    ...overrides,
  };
}

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-constraint-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function wellFormedConstraint(overrides = {}) {
  return {
    id: "constraint.test.example",
    kind: "constraint",
    family: "service-presence",
    target: "service.example",
    expected: { present: true },
    status: "active",
    confidence: 0.9,
    provenance: {
      window: "static",
      samples: 1,
      source_collectors: ["hand-authored"],
      mined_at: "2026-07-09T00:00:00.000Z",
    },
    fixtures: [{ input: { present: true }, expect_match: true }],
    promotion_history: [{ ts: "2026-07-09T00:00:00.000Z", from: "draft", to: "active", actor: "human-cli", note: "seed" }],
    first_observed: "2026-07-09T00:00:00.000Z",
    last_verified: "2026-07-09T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

test("validateConstraint accepts a well-formed constraint record", () => {
  assert.doesNotThrow(() => validateConstraint(wellFormedConstraint()));
});

test("validateConstraint rejects missing id", () => {
  const record = wellFormedConstraint({ id: "" });
  assert.throws(() => validateConstraint(record), /id/);
});

test("validateConstraint rejects wrong kind", () => {
  const record = wellFormedConstraint({ kind: "signature" });
  assert.throws(() => validateConstraint(record), /kind/);
});

test("validateConstraint rejects missing family", () => {
  const record = wellFormedConstraint({ family: undefined });
  assert.throws(() => validateConstraint(record), /family/);
});

test("validateConstraint rejects missing target", () => {
  const record = wellFormedConstraint({ target: "" });
  assert.throws(() => validateConstraint(record), /target/);
});

test("validateConstraint rejects missing expected", () => {
  const record = wellFormedConstraint({ expected: undefined });
  assert.throws(() => validateConstraint(record), /expected/);
});

test("validateConstraint rejects an invalid status", () => {
  const record = wellFormedConstraint({ status: "bogus" });
  assert.throws(() => validateConstraint(record), /status/);
});

test("validateConstraint rejects non-numeric confidence", () => {
  const record = wellFormedConstraint({ confidence: "high" });
  assert.throws(() => validateConstraint(record), /confidence/);
});

test("validateConstraint rejects out-of-range confidence", () => {
  assert.throws(() => validateConstraint(wellFormedConstraint({ confidence: 1.5 })), /confidence/);
  assert.throws(() => validateConstraint(wellFormedConstraint({ confidence: -0.1 })), /confidence/);
});

test("validateConstraint rejects missing schema_version", () => {
  const record = wellFormedConstraint({ schema_version: undefined });
  assert.throws(() => validateConstraint(record), /schema_version/);
});

test("atomic write then read round-trips seed constraints", async () => {
  const paths = await tempPaths();
  assert(SEED_CONSTRAINTS.length >= 3 && SEED_CONSTRAINTS.length <= 5);
  for (const seed of SEED_CONSTRAINTS) {
    assert.equal(seed.status, "active");
    assert.doesNotThrow(() => validateConstraint(seed));
  }

  const written = await writeConstraints(paths, SEED_CONSTRAINTS);
  assert.equal(written.length, SEED_CONSTRAINTS.length);

  const { constraints, corrupt_count } = await loadConstraints(paths);
  assert.equal(corrupt_count, 0);
  assert.deepEqual(constraints.map((c) => c.id).sort(), SEED_CONSTRAINTS.map((c) => c.id).sort());
});

test("a corrupted constraints.json is tolerated rather than thrown", async () => {
  const paths = await tempPaths();
  const { dir, constraintsFile } = resolveConstraintStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(constraintsFile, "{ not json", { mode: 0o600 });

  const { constraints, corrupt_count } = await loadConstraints(paths);
  assert.deepEqual(constraints, []);
  assert(corrupt_count >= 1);
});

test("resolved constraint store paths have no doubled descartes segment", async () => {
  const paths = await tempPaths();
  const resolved = resolveConstraintStorePaths(paths);
  assert.equal(resolved.dir, path.join(paths.stateDir, "learned"));
  assert.equal(resolved.constraintsFile, path.join(paths.stateDir, "learned", "constraints.json"));
  assert.equal(resolved.configFile, path.join(paths.configDir, "learned.json"));

  for (const value of Object.values(resolved)) {
    if (typeof value !== "string") continue;
    const occurrences = value.split(path.sep).filter((segment) => segment === "descartes").length;
    assert.equal(occurrences, 1, `expected exactly one "descartes" path segment in ${value}`);
  }
});

test("resolved constraint store paths pass the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const resolved = resolveConstraintStorePaths(paths);
  assert.doesNotThrow(() => assertNoPiOwnedPath(resolved));
});

test("enablement switch defaults to disabled when learned.json is absent", async () => {
  const paths = await tempPaths();
  const config = await loadLearnedConfig(paths);
  assert.equal(config.enabled, false);
});

test("enablement switch reads back a present learned.json", async () => {
  const paths = await tempPaths();
  const written = await writeLearnedConfig(paths, { enabled: true });
  assert.equal(written.enabled, true);

  const reread = await loadLearnedConfig(paths);
  assert.equal(reread.enabled, true);
});

// --- S7a: additive draft->shadow / shadow->review-ready status-transition helpers (plan §5) ---

test("MIN_FIXTURE_COUNT/DEFAULT_SOAK_DAYS defaults match the plan's recommended values", () => {
  assert.equal(MIN_FIXTURE_COUNT, 2);
  assert.equal(DEFAULT_SOAK_DAYS, 7);
});

test("promoteDraftsToShadow promotes a draft with >= MIN_FIXTURE_COUNT fixtures and appends promotion_history", () => {
  const draft = draftConstraint();
  const [promoted] = promoteDraftsToShadow([draft], { now: "2026-07-01T12:00:00.000Z" });
  assert.equal(promoted.status, "shadow");
  assert.equal(promoted.promotion_history.length, 1);
  assert.deepEqual(promoted.promotion_history[0], {
    ts: "2026-07-01T12:00:00.000Z",
    from: "draft",
    to: "shadow",
    actor: "deterministic-gate",
    note: "minimum-fixture bar met",
  });
});

test("promoteDraftsToShadow does not promote a draft below the minimum-fixture bar", () => {
  const draft = draftConstraint({ fixtures: [{ input: { "service.presence": "true" }, expect_match: true }] });
  const [unchanged] = promoteDraftsToShadow([draft], { now: "2026-07-01T12:00:00.000Z" });
  assert.equal(unchanged.status, "draft");
  assert.deepEqual(unchanged.promotion_history, []);
});

test("promoteDraftsToShadow is an idempotent no-op on non-draft statuses", () => {
  for (const status of ["shadow", "review-ready", "active", "retired"]) {
    const constraint = draftConstraint({ status, promotion_history: [{ ts: "2026-07-01T00:00:00.000Z", from: "draft", to: status, actor: "x" }] });
    const [result] = promoteDraftsToShadow([constraint], { now: "2026-07-02T00:00:00.000Z" });
    assert.deepEqual(result, constraint);
  }
});

test("checkShadowSoak: eligible after a clean soak window with zero fires and full daily observation coverage", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const constraint = draftConstraint({
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  // One clean (non-fired) observation per day across the full 7-day soak window.
  const records = Array.from({ length: 7 }, (_, day) => shadowRecord({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: false,
  }));

  const now = shadowSinceMs + 7 * DAY_MS;
  assert.equal(checkShadowSoak(constraint, records, { soakDays: 7, now }), true);
});

test("checkShadowSoak: a fractional soakDays is floored (7.9 behaves like 7, not 8) — no promotion-window off-by-one", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const constraint = draftConstraint({
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  const records = Array.from({ length: 7 }, (_, day) => shadowRecord({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: false,
  }));
  const now = shadowSinceMs + 7 * DAY_MS;
  // 7.9 floors to 7: eligible, identical to soakDays:7 (window and daily coverage both use the floored value).
  assert.equal(checkShadowSoak(constraint, records, { soakDays: 7.9, now }), true);
  // 8 requires a full 8th day that has not elapsed yet: not eligible.
  assert.equal(checkShadowSoak(constraint, records, { soakDays: 8, now }), false);
});

test("checkShadowSoak: a single fired:true record anywhere in the window blocks promotion", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const constraint = draftConstraint({
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  const records = Array.from({ length: 7 }, (_, day) => shadowRecord({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: day === 2, // a single false-fire on day 3
  }));

  const now = shadowSinceMs + 7 * DAY_MS;
  assert.equal(checkShadowSoak(constraint, records, { soakDays: 7, now }), false);
});

test("checkShadowSoak: insufficient daily observation coverage (a gap) is not eligible even with zero fires", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const constraint = draftConstraint({
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  // Missing day 3 entirely — "nobody looked" that day.
  const records = [0, 1, 3, 4, 5, 6].map((day) => shadowRecord({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: false,
  }));

  const now = shadowSinceMs + 7 * DAY_MS;
  assert.equal(checkShadowSoak(constraint, records, { soakDays: 7, now }), false);
});

test("checkShadowSoak: not eligible before soakDays has elapsed, even with clean daily coverage so far", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const constraint = draftConstraint({
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  const records = Array.from({ length: 5 }, (_, day) => shadowRecord({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: false,
  }));

  const now = shadowSinceMs + 5 * DAY_MS; // only 5 of 7 required days have elapsed
  assert.equal(checkShadowSoak(constraint, records, { soakDays: 7, now }), false);
});

test("promoteShadowToReviewReady flips only eligible shadow constraints and appends promotion_history", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const eligible = draftConstraint({
    id: "constraint.mined.service-presence.eligible",
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  const stillSoaking = draftConstraint({
    id: "constraint.mined.service-presence.soaking",
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  const cleanRecords = Array.from({ length: 7 }, (_, day) => shadowRecord({
    constraint_id: eligible.id,
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: false,
  }));
  const firedOnDay3 = Array.from({ length: 7 }, (_, day) => shadowRecord({
    constraint_id: stillSoaking.id,
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: day === 2,
  }));

  const now = shadowSinceMs + 7 * DAY_MS;
  const promoted = promoteShadowToReviewReady([eligible, stillSoaking], [...cleanRecords, ...firedOnDay3], { soakDays: 7, now });

  const eligibleAfter = promoted.find((c) => c.id === eligible.id);
  assert.equal(eligibleAfter.status, "review-ready");
  assert.equal(eligibleAfter.promotion_history.length, 2);
  assert.equal(eligibleAfter.promotion_history.at(-1).from, "shadow");
  assert.equal(eligibleAfter.promotion_history.at(-1).to, "review-ready");

  // A constraint that has fired stays in "shadow" indefinitely — inspectable, not silently
  // reset/retried, and — critically — never skips straight to review-ready or active.
  const stillSoakingAfter = promoted.find((c) => c.id === stillSoaking.id);
  assert.equal(stillSoakingAfter.status, "shadow");
  assert.equal(stillSoakingAfter.promotion_history.length, 1);
});

test("no exported transition helper in constraint-store.js ever sets status to \"active\"", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/constraint-store.js"), "utf8");
  // Scoped, targeted check: neither promoteDraftsToShadow nor promoteShadowToReviewReady's
  // bodies contain a literal "active" status assignment. SEED_CONSTRAINTS legitimately
  // contains hand-authored status:"active" seeds (Slice 1) — this test only guards the two
  // new S7a transition functions, not the whole file.
  const promoteDraftsToShadowSrc = source.slice(source.indexOf("export function promoteDraftsToShadow"), source.indexOf("export function checkShadowSoak"));
  const promoteShadowToReviewReadySrc = source.slice(
    source.indexOf("export function promoteShadowToReviewReady"),
    source.indexOf("const SEED_TS"),
  );
  assert.equal(/["']active["']/.test(promoteDraftsToShadowSrc), false);
  assert.equal(/["']active["']/.test(promoteShadowToReviewReadySrc), false);
});
