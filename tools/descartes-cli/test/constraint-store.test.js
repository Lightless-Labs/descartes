import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { isSafeEnumString } from "../src/diagnostics-sanitizer.js";
import {
  DEFAULT_SOAK_DAYS,
  MIN_FIXTURE_COUNT,
  SEED_CONSTRAINTS,
  buildConstraintTarget,
  checkShadowSoak,
  loadConstraints,
  loadLearnedConfig,
  promoteDraftsToShadow,
  promoteReviewReadyToActive,
  promoteShadowToReviewReady,
  resolveConstraintStorePaths,
  runLearnedConfigCommand,
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

// --- buildConstraintTarget: shared target-builder (Codex review finding #8, target-truncation
// collision) — the ONE place (fact_name, entity_key) -> target is ever computed, used by both
// constraint-miner.js's buildMinedConstraint and shadow-store.js's buildShadowFactLookup so
// they can never diverge. ---

test("buildConstraintTarget: two entity_keys sharing an identical 64-char sanitized prefix but different tails produce DIFFERENT targets", () => {
  const sharedPrefix = "a".repeat(64);
  const entityKeyOne = `${sharedPrefix}-service-one`;
  const entityKeyTwo = `${sharedPrefix}-service-two`;

  const targetOne = buildConstraintTarget("service.presence", entityKeyOne);
  const targetTwo = buildConstraintTarget("service.presence", entityKeyTwo);

  assert.notEqual(targetOne, undefined);
  assert.notEqual(targetTwo, undefined);
  assert.notEqual(targetOne, targetTwo, "distinct entity_keys sharing a 64-char sanitized prefix must not collide onto the same target");
});

test("buildConstraintTarget produces a safe, bounded string (isSafeEnumString) even for a hostile/overlong entity_key", () => {
  const target = buildConstraintTarget("service.presence", `/usr/local/${"x".repeat(100)}/../../etc/passwd`);
  assert.notEqual(target, undefined);
  assert(target.length <= 64);
  assert.equal(target.includes("/"), false);
  assert(isSafeEnumString(target), `expected ${target} to be a safe enum string`);
});

test("buildConstraintTarget is deterministic: same (fact_name, entity_key) in yields the same target out", () => {
  const first = buildConstraintTarget("network.listening_port.owner", "tcp:0.0.0.0:5432");
  const second = buildConstraintTarget("network.listening_port.owner", "tcp:0.0.0.0:5432");
  assert.equal(first, second);
});

test("buildConstraintTarget returns undefined when nothing safe survives sanitization (degrade, never fabricate)", () => {
  assert.equal(buildConstraintTarget("service.presence", "////"), undefined);
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

test("loadLearnedConfig fails closed to disabled (does not throw) when learned.json contains malformed JSON", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveConstraintStorePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, "{ not json", { mode: 0o600 });

  const config = await loadLearnedConfig(paths);
  assert.equal(config.enabled, false);
});

// --- descartes learned enable | disable | status (CLI) — the kill switch is operationally
// load-bearing but had no command to flip it; users had to hand-edit learned.json. ---

test("descartes learned status reports disabled and the config path when learned.json is absent, without throwing", async () => {
  const paths = await tempPaths();
  const lines = [];
  const result = await runLearnedConfigCommand(paths, "status", [], { output: (line) => lines.push(line) });

  assert.equal(result.enabled, false);
  assert.equal(result.config_path, resolveConstraintStorePaths(paths).configFile);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /disabled/);
  assert.match(lines[0], new RegExp(resolveConstraintStorePaths(paths).configFile.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("descartes learned enable flips learned.json to enabled:true and prints confirmation", async () => {
  const paths = await tempPaths();
  const lines = [];
  const result = await runLearnedConfigCommand(paths, "enable", [], { now: "2026-07-11T00:00:00.000Z", output: (line) => lines.push(line) });

  assert.equal(result.enabled, true);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /enabled/);

  const reread = await loadLearnedConfig(paths);
  assert.equal(reread.enabled, true);
});

test("descartes learned disable flips learned.json to enabled:false and prints confirmation", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });

  const lines = [];
  const result = await runLearnedConfigCommand(paths, "disable", [], { now: "2026-07-11T00:00:00.000Z", output: (line) => lines.push(line) });

  assert.equal(result.enabled, false);
  assert.match(lines[0], /disabled/);

  const reread = await loadLearnedConfig(paths);
  assert.equal(reread.enabled, false);
});

test("descartes learned enable/disable are idempotent (repeated calls settle on the same state without throwing)", async () => {
  const paths = await tempPaths();
  await runLearnedConfigCommand(paths, "enable", [], { output: () => {} });
  const second = await runLearnedConfigCommand(paths, "enable", [], { output: () => {} });
  assert.equal(second.enabled, true);

  await runLearnedConfigCommand(paths, "disable", [], { output: () => {} });
  const fourth = await runLearnedConfigCommand(paths, "disable", [], { output: () => {} });
  assert.equal(fourth.enabled, false);
});

test("descartes learned enable/disable/status --json print machine-readable payloads", async () => {
  const paths = await tempPaths();
  const enableLines = [];
  await runLearnedConfigCommand(paths, "enable", ["--json"], { output: (line) => enableLines.push(line) });
  const enablePayload = JSON.parse(enableLines[0]);
  assert.equal(enablePayload.learned_config.enabled, true);
  assert.equal(typeof enablePayload.learned_config.config_path, "string");

  const statusLines = [];
  await runLearnedConfigCommand(paths, "status", ["--json"], { output: (line) => statusLines.push(line) });
  const statusPayload = JSON.parse(statusLines[0]);
  assert.equal(statusPayload.learned_config.enabled, true);
});

test("descartes learned status never mutates learned.json (read-only)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await runLearnedConfigCommand(paths, "status", [], { output: () => {} });

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

test("checkShadowSoak: a fire AFTER the first soak window (e.g. day 8, following a clean days 0-6) still blocks promotion when checked later (e.g. day 10) — a fire anywhere since shadow enrollment blocks promotion, not just within the fixed first-window", () => {
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const constraint = draftConstraint({
    status: "shadow",
    promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
  });
  // Clean, fully-covered days 0-6 (would satisfy the fixed first soak window on its own)...
  const cleanDays0to6 = Array.from({ length: 7 }, (_, day) => shadowRecord({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    fired: false,
  }));
  // ...but the constraint fires on day 8, AFTER that fixed window closes.
  const firedOnDay8 = shadowRecord({
    ts: new Date(shadowSinceMs + 8 * DAY_MS + 3600000).toISOString(),
    fired: true,
  });
  const records = [...cleanDays0to6, firedOnDay8];

  // `learned soak` is finally run on day 10 — well past the day-8 fire.
  const now = shadowSinceMs + 10 * DAY_MS;
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

// --- S7b: additive review-ready->active transition helper (plan §5, the human authority gate) ---
// This is the ONLY function in the codebase that writes status:"active" via a code path
// (SEED_CONSTRAINTS above is hand-authored static data, not a code path). It is reachable only
// through promotion-store.js's decideConstraintPromotion, itself only invoked by the
// human-gated `descartes learned approve` CLI command — see promotion-store.test.js for the
// end-to-end proof and the whole-src-tree "only one activation path" regression.

test("promoteReviewReadyToActive activates a matching review-ready constraint and appends promotion_history", () => {
  const constraint = draftConstraint({ status: "review-ready", promotion_history: [{ ts: "2026-07-08T00:00:00.000Z", from: "shadow", to: "review-ready", actor: "deterministic-gate" }] });
  const { constraints, activated } = promoteReviewReadyToActive([constraint], constraint.id, { now: "2026-07-10T00:00:00.000Z", note: "approved via test" });

  assert.equal(activated, true);
  assert.equal(constraints[0].status, "active");
  assert.equal(constraints[0].promotion_history.length, 2);
  assert.deepEqual(constraints[0].promotion_history.at(-1), {
    ts: "2026-07-10T00:00:00.000Z",
    from: "review-ready",
    to: "active",
    actor: "human-cli",
    note: "approved via test",
  });
});

test("promoteReviewReadyToActive fails closed (no-op) on every non-review-ready status", () => {
  for (const status of ["draft", "shadow", "active", "retired"]) {
    const constraint = draftConstraint({ status, promotion_history: [] });
    const { constraints, activated } = promoteReviewReadyToActive([constraint], constraint.id, { now: "2026-07-10T00:00:00.000Z" });
    assert.equal(activated, false, `must not activate from status "${status}"`);
    assert.deepEqual(constraints[0], constraint);
  }
});

test("promoteReviewReadyToActive fails closed (no-op) when the id does not match any constraint", () => {
  const constraint = draftConstraint({ status: "review-ready" });
  const { constraints, activated } = promoteReviewReadyToActive([constraint], "constraint.does.not.exist", { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(activated, false);
  assert.deepEqual(constraints[0], constraint);
});

test("promoteReviewReadyToActive only touches the named constraint, leaving every other constraint (even other review-ready ones) untouched", () => {
  const target = draftConstraint({ id: "constraint.target", status: "review-ready" });
  const other = draftConstraint({ id: "constraint.other", status: "review-ready" });
  const { constraints, activated } = promoteReviewReadyToActive([target, other], target.id, { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(activated, true);
  assert.equal(constraints.find((c) => c.id === "constraint.target").status, "active");
  assert.equal(constraints.find((c) => c.id === "constraint.other").status, "review-ready");
});

test("promoteReviewReadyToActive's function body contains exactly one status:\"active\" literal (source-level proof there is no second, stray writer inside it)", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/constraint-store.js"), "utf8");
  const helperStart = source.indexOf("export function promoteReviewReadyToActive");
  assert(helperStart >= 0, "constraint-store.js must define promoteReviewReadyToActive");
  // promoteReviewReadyToActive is the last export in the file (Slice S7b, appended after
  // SEED_CONSTRAINTS), so slicing to end-of-file captures exactly its body and nothing else —
  // no other code follows it. Doc comments ABOVE this marker (which legitimately describe the
  // function in prose, e.g. "the ONLY code path that ... status:\"active\"") are excluded by
  // construction, mirroring the existing S7a test's function-boundary-slicing technique above.
  const helperSrc = source.slice(helperStart);
  // Match the `status` key specifically (not the promotion_history entry's `to: "active"`,
  // which legitimately co-occurs as part of describing that same single transition).
  const matches = helperSrc.match(/status:\s*["']active["']/g) ?? [];
  assert.equal(matches.length, 1, `expected exactly one status:"active" assignment inside promoteReviewReadyToActive's body, found ${matches.length}`);
});
