import assert from "node:assert/strict";
import test from "node:test";
import {
  coldStartEntryReason,
  HISTORY_LOST_REASON,
  INITIAL_BASELINE_REASON,
} from "../src/cold-start-reason.js";

test("cold-start entry labels a genuinely first baseline distinctly", () => {
  assert.equal(coldStartEntryReason({
    storeLossThisTick: true,
    persistedReason: "missing_store",
    currentGroups: [],
  }), INITIAL_BASELINE_REASON);
});

test("cold-start entry labels a lost baseline after established history", () => {
  assert.equal(coldStartEntryReason({
    storeLossThisTick: true,
    persistedReason: "missing_store",
    currentGroups: [
      { censusState: "complete" },
      { censusState: "complete" },
    ],
  }), HISTORY_LOST_REASON);
});

test("cold-start reason labels do not alter the existing non-store-loss label", () => {
  assert.equal(coldStartEntryReason({
    storeLossThisTick: false,
    persistedReason: "anything",
  }), "corrupt_facts");
});
