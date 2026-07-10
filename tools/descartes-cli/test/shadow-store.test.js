import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { appendFactPoints } from "../src/fact-store.js";
import { loadConstraints, writeConstraints } from "../src/constraint-store.js";
import {
  DEFAULT_SHADOW_MAX_BYTES,
  DEFAULT_SHADOW_RETENTION_MS,
  appendShadowRecords,
  buildShadowFactLookup,
  enforceShadowRetention,
  evaluateAndLogShadowConstraints,
  normalizeShadowRecord,
  readShadowRecords,
  resolveShadowStorePaths,
  runLearnedSoak,
} from "../src/shadow-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-shadow-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function shadowConstraint(overrides = {}) {
  return {
    id: "constraint.mined.service-presence.deadbeefdeadbeef",
    kind: "constraint",
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    status: "shadow",
    confidence: 1,
    provenance: { window: "7d", samples: 5, source_collectors: ["services"], mined_at: "2026-07-01T00:00:00.000Z" },
    fixtures: [
      { input: { "service.presence": "true" }, expect_match: true },
      { input: { "service.presence": "false" }, expect_match: false },
    ],
    promotion_history: [{ ts: "2026-07-01T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
    first_observed: "2026-07-01T00:00:00.000Z",
    last_verified: "2026-07-01T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

// --- resolveShadowStorePaths ---

test("resolveShadowStorePaths points at stateDir/learned/shadow-violations.jsonl with no double-nesting, passes the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const storePaths = resolveShadowStorePaths(paths);
  assert.equal(storePaths.dir, path.join(paths.stateDir, "learned"));
  assert.equal(storePaths.shadowViolationsFile, path.join(paths.stateDir, "learned", "shadow-violations.jsonl"));
  assert.doesNotThrow(() => assertNoPiOwnedPath({ shadowViolationsFile: storePaths.shadowViolationsFile }));
});

test("DEFAULT_SHADOW_RETENTION_MS/DEFAULT_SHADOW_MAX_BYTES are their own constants", () => {
  assert.equal(DEFAULT_SHADOW_RETENTION_MS, 30 * 24 * 60 * 60 * 1000);
  assert.equal(DEFAULT_SHADOW_MAX_BYTES, 5 * 1024 * 1024);
});

// --- normalizeShadowRecord ---

test("normalizeShadowRecord requires a non-empty constraint_id and a boolean fired", () => {
  assert.throws(() => normalizeShadowRecord({ fired: true }), /constraint_id/);
  assert.throws(() => normalizeShadowRecord({ constraint_id: "c1", fired: "yes" }), /fired/);
  assert.doesNotThrow(() => normalizeShadowRecord({ constraint_id: "c1", fired: true }));
});

// --- appendShadowRecords / readShadowRecords round-trip ---

test("appendShadowRecords/readShadowRecords round-trip, append-only, JSONL shaped", async () => {
  const paths = await tempPaths();
  const ts = "2026-07-10T00:00:00.000Z";
  await appendShadowRecords(paths, [
    { ts, constraint_id: "c1", family: "service-presence", target: "service.presence.nginx", expected: { comparator: "eq", value: "true" }, actual: "true", fired: false },
    { ts, constraint_id: "c2", family: "port-binding-identity", target: "network.listening_port.owner.tcp", expected: { comparator: "eq", value: "postgres" }, actual: "unknown", fired: true },
  ]);

  const { records, corrupt_count } = await readShadowRecords(paths);
  assert.equal(corrupt_count, 0);
  assert.equal(records.length, 2);
  assert.deepEqual(records.map((r) => r.constraint_id).sort(), ["c1", "c2"]);
  assert.equal(records.find((r) => r.constraint_id === "c2").fired, true);
});

test("readShadowRecords returns an empty result on ENOENT", async () => {
  const paths = await tempPaths();
  const { records, corrupt_count } = await readShadowRecords(paths);
  assert.deepEqual(records, []);
  assert.equal(corrupt_count, 0);
});

test("readShadowRecords skips corrupt lines (counted) and drops invalid-schema records (not counted as corrupt)", async () => {
  const paths = await tempPaths();
  const storePaths = resolveShadowStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.shadowViolationsFile, [
    JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", constraint_id: "c1", fired: false }),
    "not-json",
    JSON.stringify({ ts: "2026-07-10T00:00:01.000Z", fired: true }), // missing constraint_id -> invalid schema
    "",
  ].join("\n"));

  const { records, corrupt_count } = await readShadowRecords(paths);
  assert.equal(corrupt_count, 1);
  assert.equal(records.length, 1);
  assert.equal(records[0].constraint_id, "c1");
});

test("enforceShadowRetention drops records older than retentionMs and keeps the file under maxBytes (newest-first)", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-07-10T00:00:00.000Z");
  await appendShadowRecords(paths, [
    { ts: "2026-07-09T00:00:00.000Z", constraint_id: "old", fired: false },
    { ts: "2026-07-10T00:00:00.000Z", constraint_id: "fresh", fired: false },
  ], { now: base, retentionMs: 23 * 60 * 60 * 1000 });

  const retention = await enforceShadowRetention(paths, { now: base, retentionMs: 23 * 60 * 60 * 1000 });
  assert.equal(retention.kept_count, 1);

  const { records } = await readShadowRecords(paths);
  assert.deepEqual(records.map((r) => r.constraint_id), ["fresh"]);
});

test("appendShadowRecords rewrites are atomic (tmp+rename, no leftover tmp file)", async () => {
  const paths = await tempPaths();
  const storePaths = resolveShadowStorePaths(paths);
  await appendShadowRecords(paths, [{ ts: "2026-07-10T00:00:00.000Z", constraint_id: "c1", fired: false }], { now: "2026-07-10T00:00:00.000Z" });

  const dirEntries = await fs.readdir(storePaths.dir);
  assert(!dirEntries.some((entry) => entry.endsWith(".tmp")), "no leftover tmp file after a successful append+retention rewrite");
});

// --- evaluateAndLogShadowConstraints (I/O orchestrator, wired into daemon.js's structural tick) ---

test("evaluateAndLogShadowConstraints is a no-op (no facts read, no file written) when zero constraints are status:\"shadow\"", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, []);

  const result = await evaluateAndLogShadowConstraints(paths, { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(result.evaluated_count, 0);
  assert.equal(result.appended_count, 0);
  await assert.rejects(() => fs.access(resolveShadowStorePaths(paths).shadowViolationsFile));
});

test("evaluateAndLogShadowConstraints ignores non-shadow constraints (draft/active/review-ready/retired)", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [
    shadowConstraint({ id: "c.draft", status: "draft" }),
    shadowConstraint({ id: "c.active", status: "active" }),
    shadowConstraint({ id: "c.review-ready", status: "review-ready" }),
    shadowConstraint({ id: "c.retired", status: "retired" }),
  ]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: { running: "false" } },
  ], { now: "2026-07-10T00:00:00.000Z" });

  const result = await evaluateAndLogShadowConstraints(paths, { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(result.evaluated_count, 0);
  assert.equal(result.appended_count, 0);
});

test("evaluateAndLogShadowConstraints appends exactly one record per shadow constraint with matching facts, and never fabricates against a degraded fact", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  await writeConstraints(paths, [shadowConstraint()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: { running: "false" } },
  ], { now });

  const result = await evaluateAndLogShadowConstraints(paths, { now });
  assert.equal(result.evaluated_count, 1);
  assert.equal(result.fired_count, 1);
  assert.equal(result.appended_count, 1);

  const { records } = await readShadowRecords(paths);
  assert.equal(records.length, 1);
  assert.equal(records[0].constraint_id, "constraint.mined.service-presence.deadbeefdeadbeef");
  assert.equal(records[0].fired, true);
  assert.equal(records[0].actual, "false");
});

test("evaluateAndLogShadowConstraints excludes degraded facts (owner_known:\"false\"/confidence:0) — never confirming or contradicting", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  const portConstraint = shadowConstraint({
    id: "constraint.mined.port-binding-identity.cafebabecafebabe",
    family: "port-binding-identity",
    target: "network.listening_port.owner.tcp_0.0.0.0_5432",
    expected: { comparator: "eq", value: "postgres" },
  });
  await writeConstraints(paths, [portConstraint]);
  await appendFactPoints(paths, [
    {
      fact_name: "network.listening_port.owner",
      entity_key: "tcp:0.0.0.0:5432",
      attributes: { owner_known: "false" },
      confidence: 0,
    },
  ], { now });

  const result = await evaluateAndLogShadowConstraints(paths, { now });
  assert.equal(result.evaluated_count, 1);
  assert.equal(result.appended_count, 0, "a degraded/unresolvable fact must never produce a fired or non-fired shadow record");
});

test("evaluateAndLogShadowConstraints never writes to constraints.json (read-only of constraint status)", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  await writeConstraints(paths, [shadowConstraint()]);
  await appendFactPoints(paths, [{ fact_name: "service.presence", entity_key: "nginx", attributes: { running: "true" } }], { now });

  await evaluateAndLogShadowConstraints(paths, { now });

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints.length, 1);
  assert.equal(constraints[0].status, "shadow");
  assert.deepEqual(constraints[0].promotion_history, shadowConstraint().promotion_history);
});

// --- buildShadowFactLookup export (Slice S-live-1, additive: daemon.js reuses this for
// active-constraint evaluation so ACTIVE and SHADOW evaluation reconstruct targets identically) ---

test("buildShadowFactLookup is exported and behaves identically to its existing internal use: target reconstruction, latest-wins, and degraded-observation exclusion", () => {
  assert.equal(typeof buildShadowFactLookup, "function");

  const points = [
    { ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: { running: "false" } },
    { ts: "2026-07-10T00:05:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: { running: "true" } }, // latest wins
    {
      ts: "2026-07-10T00:00:00.000Z",
      fact_name: "network.listening_port.owner",
      entity_key: "tcp:0.0.0.0:5432",
      attributes: { owner_known: "false" },
      confidence: 0,
    }, // degraded -> excluded entirely
  ];

  const lookup = buildShadowFactLookup(points);
  assert.equal(lookup("service.presence.nginx"), "true");
  assert.equal(lookup("network.listening_port.owner.tcp:0.0.0.0:5432"), undefined);
  assert.equal(lookup("nonexistent.target"), undefined);
});

// --- No LLM anywhere (grep-able absence, mirrors S6c's/S7's planned regression) ---

test("shadow-store.js never imports the pi-harness/alert-intelligence LLM touchpoints", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/shadow-store.js"), "utf8");
  assert.equal(/pi-harness\.js/.test(source), false);
  assert.equal(/alert-intelligence\.js/.test(source), false);
});

test("shadow-store.js never sets status to \"active\" anywhere in its source (S7a hard invariant)", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/shadow-store.js"), "utf8");
  assert.equal(/status:\s*["']active["']/.test(source), false);
  assert.equal(/status\s*=\s*["']active["']/.test(source), false);
});

// --- CLI: descartes learned soak ---

test("descartes learned soak enrolls eligible drafts into shadow and prints a summary", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [
    {
      id: "constraint.mined.service-presence.eligible",
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
    },
  ]);

  const lines = [];
  const summary = await runLearnedSoak(paths, [], { now: "2026-07-08T00:00:00.000Z", output: (line) => lines.push(line) });

  assert.equal(summary.enrolled_to_shadow, 1);
  assert.equal(summary.promoted_to_review_ready, 0);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /1 draft/);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "shadow");
});

test("descartes learned soak --json prints a machine-readable summary", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, []);
  const lines = [];
  await runLearnedSoak(paths, ["--json"], { now: "2026-07-08T00:00:00.000Z", output: (line) => lines.push(line) });
  assert.equal(lines.length, 1);
  const payload = JSON.parse(lines[0]);
  assert.equal(payload.learned_soak.enrolled_to_shadow, 0);
  assert.equal(payload.learned_soak.promoted_to_review_ready, 0);
});

test("descartes learned soak promotes a shadow constraint with a clean soak window to review-ready, reading only already-logged shadow-violations.jsonl (never evaluating constraints itself)", async () => {
  const paths = await tempPaths();
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const DAY_MS = 24 * 60 * 60 * 1000;
  await writeConstraints(paths, [shadowConstraint({ promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }] })]);

  const cleanRecords = Array.from({ length: 7 }, (_, day) => ({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    constraint_id: shadowConstraint().id,
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    actual: "true",
    fired: false,
  }));
  await appendShadowRecords(paths, cleanRecords, { now: shadowSinceMs + 7 * DAY_MS });

  const now = shadowSinceMs + 7 * DAY_MS;
  const summary = await runLearnedSoak(paths, [], { now, output: () => {} });
  assert.equal(summary.promoted_to_review_ready, 1);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "review-ready");
});

test("descartes learned soak never sets any constraint to status:\"active\"", async () => {
  const paths = await tempPaths();
  const shadowSince = "2026-07-01T00:00:00.000Z";
  const shadowSinceMs = Date.parse(shadowSince);
  const DAY_MS = 24 * 60 * 60 * 1000;
  await writeConstraints(paths, [shadowConstraint({ promotion_history: [{ ts: shadowSince, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }] })]);
  const cleanRecords = Array.from({ length: 7 }, (_, day) => ({
    ts: new Date(shadowSinceMs + day * DAY_MS + 3600000).toISOString(),
    constraint_id: shadowConstraint().id,
    fired: false,
  }));
  await appendShadowRecords(paths, cleanRecords, { now: shadowSinceMs + 7 * DAY_MS });

  await runLearnedSoak(paths, [], { now: shadowSinceMs + 7 * DAY_MS, output: () => {} });

  const { constraints } = await loadConstraints(paths);
  assert(constraints.every((c) => c.status !== "active"), "S7a must never write status:\"active\"");
  assert.equal(constraints[0].status, "review-ready", "review-ready is the terminal state in S7a");
});
