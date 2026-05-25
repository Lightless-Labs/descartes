import assert from "node:assert/strict";
import test from "node:test";
import { parseTriageArgs } from "../src/triage.js";

test("triage parser accepts history options before the prompt", () => {
  const parsed = parseTriageArgs(["--use-history", "--history-window", "2h", "Hey there!", "How's my system doing?"]);
  assert.equal(parsed.useHistory, true);
  assert.equal(parsed.historyWindow, "2h");
  assert.equal(parsed.prompt, "Hey there! How's my system doing?");
});

test("triage parser accepts history options after the prompt", () => {
  const parsed = parseTriageArgs(["Hey there!", "--use-history", "--json"]);
  assert.equal(parsed.useHistory, true);
  assert.equal(parsed.json, true);
  assert.equal(parsed.historyWindow, "24h");
  assert.equal(parsed.prompt, "Hey there!");
});

test("triage parser rejects invalid history windows", () => {
  assert.throws(
    () => parseTriageArgs(["--use-history", "--history-window", "forever", "status?"]),
    /Invalid duration/
  );
});
