import assert from "node:assert/strict";
import test from "node:test";
import { evaluateHistorySelection, parseTriageArgs } from "../src/triage.js";

function historySummary(lastTs = "2026-05-28T12:00:00.000Z", pointCount = 1) {
  return {
    point_count: pointCount,
    metrics: pointCount > 0 ? [{ metric_name: "system.load.1m", last_ts: lastTs }] : [],
  };
}

const daemonStatus = { state: "ok", ts: "2026-05-28T12:00:00.000Z", profile: { interval_ms: 60_000 } };

test("triage parser defaults history mode to auto", () => {
  const parsed = parseTriageArgs(["How's my system doing?"]);
  assert.equal(parsed.historyMode, "auto");
  assert.equal(parsed.useHistory, false);
  assert.equal(parsed.historyWindow, "24h");
});

test("triage parser accepts history options before the prompt", () => {
  const parsed = parseTriageArgs(["--use-history", "--history-window", "2h", "Hey there!", "How's my system doing?"]);
  assert.equal(parsed.historyMode, "forced");
  assert.equal(parsed.useHistory, true);
  assert.equal(parsed.historyWindow, "2h");
  assert.equal(parsed.prompt, "Hey there! How's my system doing?");
});

test("triage parser accepts history options after the prompt", () => {
  const parsed = parseTriageArgs(["Hey there!", "--use-history", "--json"]);
  assert.equal(parsed.historyMode, "forced");
  assert.equal(parsed.useHistory, true);
  assert.equal(parsed.json, true);
  assert.equal(parsed.historyWindow, "24h");
  assert.equal(parsed.prompt, "Hey there!");
});

test("triage parser accepts explicit history opt-out", () => {
  const parsed = parseTriageArgs(["status?", "--no-history"]);
  assert.equal(parsed.historyMode, "disabled");
  assert.equal(parsed.useHistory, false);
});

test("triage parser rejects conflicting history flags", () => {
  assert.throws(
    () => parseTriageArgs(["--use-history", "--no-history", "status?"]),
    /either --use-history or --no-history/
  );
});

test("triage parser rejects invalid history windows", () => {
  assert.throws(
    () => parseTriageArgs(["--history-window", "forever", "status?"]),
    /Invalid duration/
  );
});

test("auto history selection uses fresh daemon-backed history", () => {
  const selected = evaluateHistorySelection({
    mode: "auto",
    summary: historySummary(),
    daemonStatus,
    now: "2026-05-28T12:02:00.000Z",
  });
  assert.equal(selected.used, true);
  assert.equal(selected.skip_reason, undefined);
  assert.equal(selected.max_age_ms, 5 * 60 * 1000);
});

test("auto history selection skips stale, empty, or unhealthy history", () => {
  assert.equal(evaluateHistorySelection({
    mode: "auto",
    summary: historySummary("2026-05-28T11:00:00.000Z"),
    daemonStatus,
    now: "2026-05-28T12:00:00.000Z",
  }).skip_reason, "stale");
  assert.equal(evaluateHistorySelection({
    mode: "auto",
    summary: historySummary("2026-05-28T12:00:00.000Z", 0),
    daemonStatus,
    now: "2026-05-28T12:00:00.000Z",
  }).skip_reason, "no_points");
  assert.equal(evaluateHistorySelection({
    mode: "auto",
    summary: historySummary(),
    daemonStatus: { state: "stopped", profile: { interval_ms: 60_000 } },
    now: "2026-05-28T12:00:00.000Z",
  }).skip_reason, "daemon_status_not_ok");
});

test("forced history selection uses available summary even when stale", () => {
  const selected = evaluateHistorySelection({
    mode: "forced",
    summary: historySummary("2026-05-28T11:00:00.000Z"),
    daemonStatus,
    now: "2026-05-28T12:00:00.000Z",
  });
  assert.equal(selected.used, true);
  assert.equal(selected.skip_reason, undefined);
});
