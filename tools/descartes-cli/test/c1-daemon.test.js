// Context plan C1: daemon integration of the alert foundations (transition log; later the label
// ingestion, the pending journal and the digest). These steps are audit/foundation only: they never
// change which alerts fire or when they notify.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { readAlertRecords } from "../src/alert-store.js";
import { readAlertTransitions } from "../src/alert-transitions.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-c1-daemon-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

function envelope(id, tool, result) {
  return { id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: "2026-10-12T00:00:00.000Z" } };
}

function collectorsWithMemory(usedFraction) {
  return {
    system: async () => envelope("system-overview", "collect_system", { load_average: [0.1, 0.1, 0.1], uptime_seconds: 10, memory: { used_fraction: usedFraction, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

export async function runTicks(paths, fractions, { startMinute = 0, extra = {} } = {}) {
  const results = [];
  for (const [index, fraction] of fractions.entries()) {
    const ts = new Date(Date.UTC(2026, 9, 12, 0, startMinute + index)).toISOString();
    results.push(await runDaemonIteration(paths, { collectors: collectorsWithMemory(fraction), ts, now: ts, alertWindowMs: 90_000, deliverNotification: async () => ({ status: "cli_only" }), ...extra }));
  }
  return results;
}

test("the daemon appends activated and recovered transitions for a firing fixed rule", async () => {
  const paths = await tempPaths();
  const results = await runTicks(paths, [0.95, 0.95, 0.95, 0.2, 0.2, 0.2]);
  const memory = (await readAlertRecords(paths)).find((alert) => alert.rule_id === "system.memory.sustained_high");
  assert.ok(memory, "the memory alert fired");
  const log = await readAlertTransitions(paths);
  assert.equal(log.status, "valid");
  const forMemory = log.records.filter((record) => record.alert_id === memory.id).map((record) => record.kind);
  assert.ok(forMemory.includes("activated"));
  assert.ok(forMemory.includes("recovered"));
  assert.ok(results.every((result) => result.alertTransitions?.status === "ok"));
});

test("a transition-log failure never affects alerting", async () => {
  const paths = await tempPaths();
  const results = await runTicks(paths, [0.95, 0.95, 0.95], { extra: { recordAlertTransitions: async () => { throw new Error("ENOSPC: no space left"); } } });
  assert.equal(results.at(-1).alertTransitions.status, "error");
  assert.ok((await readAlertRecords(paths)).some((alert) => alert.rule_id === "system.memory.sustained_high" && alert.status === "active"));
});
