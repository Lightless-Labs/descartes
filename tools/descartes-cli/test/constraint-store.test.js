import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import {
  SEED_CONSTRAINTS,
  loadConstraints,
  loadLearnedConfig,
  resolveConstraintStorePaths,
  validateConstraint,
  writeConstraints,
  writeLearnedConfig,
} from "../src/constraint-store.js";

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
