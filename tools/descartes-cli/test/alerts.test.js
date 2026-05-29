import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runAlerts, renderAlertList, visibleAlerts } from "../src/alerts.js";
import { appendMetricPoints, writeDaemonStatus } from "../src/history-store.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { writeAlertRecords } from "../src/alert-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alerts-cli-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("alert renderer lists active alerts and hides recovered records by default", () => {
  const alerts = [
    {
      id: "alert_active",
      rule_id: "system.memory.sustained_high",
      fingerprint: "global",
      status: "active",
      severity: "warning",
      title: "Sustained high memory pressure",
      summary: "Memory high",
      evidence_refs: ["history-summary"],
      first_seen: "2026-05-28T00:00:00.000Z",
      last_seen: "2026-05-28T00:01:00.000Z",
      last_notified: null,
      cooldown_until: null,
      acknowledged_at: null,
      diagnostics: {},
    },
    {
      id: "alert_old",
      rule_id: "disk.space.high_used_fraction",
      fingerprint: "global",
      status: "recovered",
      severity: "critical",
      title: "Recovered disk pressure",
      summary: "Recovered",
      evidence_refs: ["history-summary"],
      first_seen: "2026-05-27T00:00:00.000Z",
      last_seen: "2026-05-27T00:01:00.000Z",
      last_notified: null,
      cooldown_until: null,
      acknowledged_at: null,
      diagnostics: {},
    },
  ];

  assert.deepEqual(visibleAlerts(alerts).map((alert) => alert.id), ["alert_active"]);
  const output = renderAlertList(alerts);
  assert.match(output, /alert_active/);
  assert.doesNotMatch(output, /alert_old/);
  assert.match(renderAlertList(alerts, { all: true }), /alert_old/);
});

test("alerts list evaluates local history and prints active alerts", async () => {
  const paths = await tempPaths();
  const now = new Date().toISOString();
  await appendMetricPoints(paths, [
    { ts: now, metric_name: "disk.used_fraction", value: 0.96, unit: "fraction" },
  ], { now });
  await writeDaemonStatus(paths, { ts: now, state: "ok", profile: { interval_ms: 60_000 } });

  const outputs = [];
  await runAlerts(paths, ["list"], { output: (line) => outputs.push(line) });
  assert.equal(outputs.length, 1);
  assert.match(outputs[0], /Alerts/);
  assert.match(outputs[0], /disk/i);
});

test("alerts ack marks an alert acknowledged", async () => {
  const paths = await tempPaths();
  const [alert] = await writeAlertRecords(paths, [{
    rule_id: "daemon.samples.missing",
    title: "No recent metric samples",
    summary: "No samples",
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T00:00:00.000Z",
  }]);

  const outputs = [];
  await runAlerts(paths, ["ack", alert.id], { output: (line) => outputs.push(line) });
  assert.match(outputs[0], new RegExp(`Acknowledged ${alert.id}`));

  const jsonOutputs = [];
  await runAlerts(paths, ["list", "--json", "--all"], { output: (line) => jsonOutputs.push(JSON.parse(line)) });
  assert.equal(jsonOutputs[0].alerts.find((entry) => entry.id === alert.id).status, "acknowledged");
});

test("alerts watch can run once without real-time sleeps", async () => {
  const paths = await tempPaths();
  const outputs = [];
  await runAlerts(paths, ["watch", "--once"], {
    output: (line) => outputs.push(line),
    sleep: async () => {
      throw new Error("watch --once should not sleep");
    },
  });
  assert.equal(outputs.length, 1);
  assert.match(outputs[0], /Alerts|No active alerts/);
});

test("alerts intelligence status enable and disable are explicit", async () => {
  const paths = await tempPaths();
  const statusOutputs = [];
  await runAlerts(paths, ["intelligence", "status", "--json"], { output: (line) => statusOutputs.push(JSON.parse(line)) });
  assert.equal(statusOutputs[0].alert_intelligence.enabled, false);

  const enableOutputs = [];
  await runAlerts(paths, ["intelligence", "enable", "--json", "--model", "openai-codex/gpt-5.5", "--thinking", "high", "--max-per-hour", "2"], { output: (line) => enableOutputs.push(JSON.parse(line)) });
  assert.equal(enableOutputs[0].alert_intelligence.enabled, true);
  assert.equal(enableOutputs[0].alert_intelligence.model_pattern, "openai-codex/gpt-5.5");
  assert.equal(enableOutputs[0].alert_intelligence.max_calls_per_hour, 2);

  const disableOutputs = [];
  await runAlerts(paths, ["intelligence", "disable", "--json"], { output: (line) => disableOutputs.push(JSON.parse(line)) });
  assert.equal(disableOutputs[0].alert_intelligence.enabled, false);
});

test("alerts notification setup status test and disable are explicit", async () => {
  const paths = await tempPaths();
  const setupOutputs = [];
  await runAlerts(paths, ["notifications", "setup", "--json", "--channel", "linux"], {
    platform: "linux",
    env: { DISPLAY: ":0" },
    output: (line) => setupOutputs.push(JSON.parse(line)),
  });
  assert.equal(setupOutputs[0].notifications.enabled, true);
  assert.equal(setupOutputs[0].notifications.channel, "linux-desktop");

  const calls = [];
  const testOutputs = [];
  await runAlerts(paths, ["notifications", "test", "--json"], {
    platform: "linux",
    env: { DISPLAY: ":0" },
    runner: async (command, args) => calls.push([command, ...args]),
    output: (line) => testOutputs.push(JSON.parse(line)),
  });
  assert.equal(testOutputs[0].delivery.status, "delivered");
  assert.equal(calls[0][0], "notify-send");

  const disableOutputs = [];
  await runAlerts(paths, ["notifications", "disable", "--json"], { output: (line) => disableOutputs.push(JSON.parse(line)) });
  assert.equal(disableOutputs[0].notifications.enabled, false);
});
