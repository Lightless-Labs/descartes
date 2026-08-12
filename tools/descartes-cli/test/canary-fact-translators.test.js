import assert from "node:assert/strict";
import { test } from "node:test";
import { factPointsFromCanaryEvidence } from "../src/fact-translators.js";

const envelope = (status = "ok", result = {}) => ({ id: "canary", status, result, trace: { tool: "collect_canary_evidence" } });

test("translates ok canaries with executed/watch provenance and a census marker", () => {
  const points = factPointsFromCanaryEvidence([envelope("ok", {
    summary: { total_count: 1 },
    canaries: [{ id: "credential.bak", kind: "credential-file", status: "ok", atime: "a", mtime: "m", ino: "1", size: "2", executed: "true", watch: ["mtime", "executed"] }],
  })], { ts: "2026-08-11T00:00:00.000Z" });
  assert.equal(points.length, 2);
  assert.equal(points[0].fact_name, "canary.presence");
  assert.equal(points[0].entity_key, "credential.bak");
  assert.deepEqual(points[0].attributes, { atime: "a", mtime: "m", ino: "1", size: "2", executed: "true", kind: "credential-file", watch: "mtime,executed" });
  assert.equal(points[1].fact_name, "canary.census");
  assert.equal(points[1].confidence, 0);
});

test("census marker requires an attempted non-empty manifest", () => {
  assert.deepEqual(factPointsFromCanaryEvidence([envelope("ok", { summary: { total_count: 0 }, canaries: [] })]), []);
  assert.deepEqual(factPointsFromCanaryEvidence([envelope("unable", { summary: { total_count: 1 } })]), []);
  assert.equal(factPointsFromCanaryEvidence([envelope("warning", { summary: { total_count: 1 }, canaries: [] })]).length, 1);
});

test("one unreadable canary among ok ones marks the census partial, not complete", () => {
  const points = factPointsFromCanaryEvidence([envelope("warning", {
    summary: { total_count: 2, ok_count: 1, unreadable_count: 1 },
    canaries: [
      { id: "credential.bak", kind: "credential-file", status: "ok", atime: "a", mtime: "m", ino: "1", size: "2", watch: ["mtime"] },
      { id: "blocked", status: "unreadable" },
    ],
  })], { ts: "2026-08-11T00:00:00.000Z" });
  const census = points.find((point) => point.fact_name === "canary.census");
  assert.equal(census.attributes.census_state, "partial");
});

test("P1 fix: a sentinel-EACCES canary (executed:unknown) marks the census partial, not complete", () => {
  // Real shape: tools/canary.js already flips envelope.status to "warning" and populates
  // summary.execution_unknown_count whenever any canary degrades to executed:"unknown".
  const points = factPointsFromCanaryEvidence([envelope("warning", {
    summary: { total_count: 1, ok_count: 1, unreadable_count: 0, execution_unknown_count: 1 },
    canaries: [
      { id: "sentinel", kind: "scheduled-job", status: "ok", atime: "a", mtime: "m", ino: "1", size: "2", executed: "unknown", watch: ["executed"] },
    ],
  })], { ts: "2026-08-11T00:00:00.000Z" });
  const census = points.find((point) => point.fact_name === "canary.census");
  assert.equal(census.attributes.census_state, "partial");
});

test("P1 fix: census still degrades to partial even if envelope.status/summary don't reflect the execution-unknown canary (defensive scan)", () => {
  // Defensive-layer regression: even if a future/simplified fixture leaves envelope.status "ok"
  // and omits summary.execution_unknown_count, the direct per-canary scan must still catch it.
  const points = factPointsFromCanaryEvidence([envelope("ok", {
    summary: { total_count: 1, ok_count: 1 },
    canaries: [
      { id: "sentinel", kind: "scheduled-job", status: "ok", atime: "a", mtime: "m", ino: "1", size: "2", executed: "unknown", watch: ["executed"] },
    ],
  })], { ts: "2026-08-11T00:00:00.000Z" });
  const census = points.find((point) => point.fact_name === "canary.census");
  assert.equal(census.attributes.census_state, "partial");
});

test("absent/unreadable entries and unsafe ids produce no presence fact", () => {
  const points = factPointsFromCanaryEvidence([envelope("warning", {
    summary: { total_count: 3 },
    canaries: [
      { id: "absent", status: "absent" },
      { id: "blocked", status: "unreadable" },
      { id: "!!!", status: "ok", watch: ["atime"] },
    ],
  })]);
  assert.equal(points.length, 1);
  assert.equal(points[0].fact_name, "canary.census");
});
