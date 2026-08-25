import assert from "node:assert/strict";
import test from "node:test";
import { computeStatDiffTripReason, statSnapshotAttributes } from "../src/stat-diff.js";

// Canary regression pin (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md, Slice D): the
// three ALREADY-SHIPPED canary trip reasons must remain byte-identical after the extraction from
// canary-baseline.js's own inline loop -- see canary-baseline.test.js for the full end-to-end
// canary regression suite; this file pins the extracted primitive itself, directly.

test("atime_advanced fires only when the latest atime is strictly greater than the previous one, and only when 'atime' is in the watch list", () => {
  assert.equal(computeStatDiffTripReason({ atime: 100 }, { atime: 200 }, ["atime"]), "atime_advanced");
  assert.equal(computeStatDiffTripReason({ atime: 200 }, { atime: 100 }, ["atime"]), undefined, "a DECREASE never trips");
  assert.equal(computeStatDiffTripReason({ atime: 100 }, { atime: 100 }, ["atime"]), undefined, "unchanged never trips");
  assert.equal(computeStatDiffTripReason({ atime: 100 }, { atime: 200 }, ["mtime"]), undefined, "not in the watch list -> never checked");
});

test("atime_advanced accepts ISO-string timestamps too (coerced via Date.parse), not just numeric epoch values", () => {
  assert.equal(computeStatDiffTripReason(
    { atime: "2026-01-01T00:00:00.000Z" },
    { atime: "2026-01-02T00:00:00.000Z" },
    ["atime"],
  ), "atime_advanced");
});

test("mtime_changed fires on ANY finite difference (not just an increase), fail-closed on non-finite or missing values", () => {
  assert.equal(computeStatDiffTripReason({ mtime: 1 }, { mtime: 2 }, ["mtime"]), "mtime_changed");
  assert.equal(computeStatDiffTripReason({ mtime: 2 }, { mtime: 1 }, ["mtime"]), "mtime_changed", "any change, not just forward");
  assert.equal(computeStatDiffTripReason({ mtime: "a" }, { mtime: "a" }, ["mtime"]), undefined);
  assert.equal(computeStatDiffTripReason({ mtime: "a" }, { mtime: "b" }, ["mtime"]), undefined, "non-finite values are not evidence of change");
  assert.equal(computeStatDiffTripReason({ mtime: Number.NaN }, { mtime: 2 }, ["mtime"]), undefined, "NaN is not evidence of change");
  assert.equal(computeStatDiffTripReason({ mtime: null }, { mtime: 2 }, ["mtime"]), undefined, "null is not evidence of change");
  assert.equal(computeStatDiffTripReason({}, { mtime: "a" }, ["mtime"]), undefined, "missing previous mtime must SKIP, not trip");
  assert.equal(computeStatDiffTripReason({ mtime: "a" }, {}, ["mtime"]), undefined, "missing latest mtime must SKIP, not trip");
  assert.equal(computeStatDiffTripReason(
    { mtime: "2026-01-01T00:00:00.000Z" },
    { mtime: "2026-01-02T00:00:00.000Z" },
    ["mtime"],
  ), "mtime_changed", "finite ISO timestamps retain canary behavior");
});

test("executed fires ONLY on an explicit previously-observed 'false' flipping to 'true' -- never off an undefined/missing/'unknown' previous value", () => {
  assert.equal(computeStatDiffTripReason({ executed: "false" }, { executed: "true" }, ["executed"]), "executed");
  assert.equal(computeStatDiffTripReason({ executed: "unknown" }, { executed: "true" }, ["executed"]), undefined);
  assert.equal(computeStatDiffTripReason({}, { executed: "true" }, ["executed"]), undefined);
  assert.equal(computeStatDiffTripReason({ executed: "false" }, { executed: "false" }, ["executed"]), undefined);
});

test("[NEW, additive] ino_changed fires when the inode differs, fail-closed on a missing value on either side -- this is genuinely new logic, not a reuse of prior canary behavior", () => {
  assert.equal(computeStatDiffTripReason({ ino: "42" }, { ino: "99" }, ["ino"]), "ino_changed");
  assert.equal(computeStatDiffTripReason({ ino: "42" }, { ino: "42" }, ["ino"]), undefined);
  assert.equal(computeStatDiffTripReason({}, { ino: "99" }, ["ino"]), undefined, "missing previous ino must SKIP, not trip");
  assert.equal(computeStatDiffTripReason({ ino: 42 }, { ino: 99 }, ["ino"]), "ino_changed", "numeric inos compare correctly too");
  assert.equal(computeStatDiffTripReason({ ino: Number.NaN }, { ino: 99 }, ["ino"]), undefined, "NaN is not evidence of inode change");
});

test("first-match-wins across multiple watches, in the order given", () => {
  const reason = computeStatDiffTripReason(
    { atime: 100, mtime: "a", ino: 1 },
    { atime: 200, mtime: "b", ino: 2 },
    ["atime", "mtime", "ino"],
  );
  assert.equal(reason, "atime_advanced");
});

test("returns undefined for an empty or unrecognized watch list", () => {
  assert.equal(computeStatDiffTripReason({ mtime: "a" }, { mtime: "b" }, []), undefined);
  assert.equal(computeStatDiffTripReason({ mtime: "a" }, { mtime: "b" }, ["unknown_watch_kind"]), undefined);
});

test("statSnapshotAttributes mirrors tools/canary.js's own statAttribute convention: Date instances -> ISO string, everything else -> String(value)", () => {
  const snapshot = statSnapshotAttributes({ atime: new Date("2026-01-01T00:00:00.000Z"), mtime: new Date("2026-01-02T00:00:00.000Z"), ino: 42, size: 7 });
  assert.equal(snapshot.atime, "2026-01-01T00:00:00.000Z");
  assert.equal(snapshot.mtime, "2026-01-02T00:00:00.000Z");
  assert.equal(snapshot.ino, "42");
  assert.equal(snapshot.size, "7");
});
