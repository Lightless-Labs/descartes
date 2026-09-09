import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateHistorySelection, parseTriageArgs, selectTriageHistory, unverifiedEvidenceRefs } from "../src/triage.js";
import { writeDaemonStatus } from "../src/history-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-triage-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

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

// Component D (trusted-state step-1, §7): a real-path test (real writeDaemonStatus +
// selectTriageHistory, no mock) proving the label survives triage's own
// sanitizeHistoryDaemonStatus allow-list selector (an internal, non-exported closed-key picker --
// see triage.js) rather than being silently stripped. evaluateHistorySelection's own
// state !== "ok" gate is a pre-existing decision path untouched by this change; this test asserts
// only that the label is disclosed on the diagnostics surface, never that it is consulted.
test("Component D: selectTriageHistory's sanitized daemon_status carries integrity_level through", async () => {
  const paths = await tempPaths();
  await writeDaemonStatus(paths, {
    state: "ok",
    mode: "foreground",
    profile: { interval_ms: 60_000 },
    integrity_level: "unprotected_same_uid",
  });

  const selection = await selectTriageHistory(paths, { historyMode: "auto" });
  assert.equal(selection.daemon_status.integrity_level, "unprotected_same_uid");
});

// F7 fix C: surfaces dangling evidence_refs citations as metadata without rejecting or rewriting
// the model's free-text diagnosis prose (honest-uncertainty, not mechanical verification).
test("unverifiedEvidenceRefs flags evidence_refs that do not resolve to real collected evidence ids", () => {
  const evidence = [{ id: "system-overview" }, { id: "top-processes" }];
  const diagnosis = { evidence_refs: ["system-overview", "fabricated-id", "top-processes"] };

  assert.deepEqual(unverifiedEvidenceRefs(diagnosis, evidence), ["fabricated-id"]);
});

test("unverifiedEvidenceRefs returns empty when every cited ref resolves", () => {
  const evidence = [{ id: "system-overview" }];
  const diagnosis = { evidence_refs: ["system-overview"] };

  assert.deepEqual(unverifiedEvidenceRefs(diagnosis, evidence), []);
});

test("unverifiedEvidenceRefs tolerates a diagnosis with no evidence_refs array (e.g. raw_text fallback)", () => {
  assert.deepEqual(unverifiedEvidenceRefs({ raw_text: "not json" }, []), []);
});
