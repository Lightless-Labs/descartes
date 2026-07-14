import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readAlertIntelligenceConfig, resolveAlertIntelligencePaths } from "../src/alert-intelligence.js";
import { runAlerts, renderAlertList, visibleAlerts } from "../src/alerts.js";
import { appendMetricPoints, writeDaemonStatus } from "../src/history-store.js";
import { readNotificationDeliveryConfig, writeNotificationDeliveryConfig } from "../src/notification-delivery.js";
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

test("alerts intelligence status renders enabled namespaces, critical reservation, and a corrupt marker", async () => {
  const paths = await tempPaths();
  const textOutputs = [];
  await runAlerts(paths, ["intelligence", "status"], { output: (line) => textOutputs.push(line) });
  assert.match(textOutputs[0], /Critical-severity reservation: 1/);
  assert.match(textOutputs[0], /Enabled namespaces: metric/);
  assert.doesNotMatch(textOutputs[0], /WARNING: alert-intelligence\.json was corrupt/);

  await fs.mkdir(paths.configDir, { recursive: true });
  await fs.writeFile(path.join(paths.configDir, "alert-intelligence.json"), "{not valid json", "utf8");
  const corruptOutputs = [];
  await runAlerts(paths, ["intelligence", "status"], { output: (line) => corruptOutputs.push(line) });
  assert.match(corruptOutputs[0], /WARNING: alert-intelligence\.json was corrupt/);
});

// S13 I/O hardening: `unavailable` (could not be READ) is distinct from `corrupt` (read fine,
// parsed as garbage) -- the status renderer surfaces its own, separate warning.
test("alerts intelligence status renders an 'unavailable' warning, distinct from 'corrupt', when the config path cannot be read (EISDIR)", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveAlertIntelligencePaths(paths);
  // Directory trick (no fs mocking / no chmod): the config path IS a directory, so fs.readFile
  // fails with EISDIR -- a real, non-ENOENT filesystem error.
  await fs.mkdir(configFile, { recursive: true });

  const outputs = [];
  await runAlerts(paths, ["intelligence", "status"], { output: (line) => outputs.push(line) });
  assert.match(outputs[0], /WARNING: alert-intelligence\.json could not be read/);
  assert.doesNotMatch(outputs[0], /WARNING: alert-intelligence\.json was corrupt/);
});

// S13 I/O hardening -- CLI consent-clobber guard: a config read that returned unavailable:true
// (the file could not be READ, e.g. EACCES/EIO/ENOSPC/EROFS) must not let a mutation subcommand
// silently replace a possibly-intact config with defaults via its tmp-write + rename (which only
// needs directory permissions, not read permission on the old file). A `corrupt:true` config
// (read fine, parsed as garbage) is NOT guarded -- overwriting it is recovery, not data loss.
test("S13 I/O hardening: enable-namespace/disable-namespace/enable/disable REFUSE to write (throw) when the config is unavailable, and never clobber it with defaults; a corrupt config still allows overwrite (recovery)", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveAlertIntelligencePaths(paths);
  await fs.mkdir(configFile, { recursive: true });

  await assert.rejects(
    () => runAlerts(paths, ["intelligence", "enable-namespace", "provenance"], { output: () => {} }),
    /alert-intelligence\.json could not be read.*refusing to write/s,
  );
  await assert.rejects(
    () => runAlerts(paths, ["intelligence", "disable-namespace", "metric"], { output: () => {} }),
    /alert-intelligence\.json could not be read.*refusing to write/s,
  );
  await assert.rejects(
    () => runAlerts(paths, ["intelligence", "enable"], { output: () => {} }),
    /alert-intelligence\.json could not be read.*refusing to write/s,
  );
  await assert.rejects(
    () => runAlerts(paths, ["intelligence", "disable"], { output: () => {} }),
    /alert-intelligence\.json could not be read.*refusing to write/s,
  );

  // The on-disk config was NEVER overwritten: the config path is still a directory (no tmp-write
  // + rename ever completed), so a fresh read still reports unavailable, never silently-defaulted
  // enabled_namespaces.
  const stillUnavailable = await readAlertIntelligenceConfig(paths);
  assert.equal(stillUnavailable.unavailable, true);

  // A corrupt (not unavailable) config remains overwritable.
  const corruptPaths = await tempPaths();
  await fs.mkdir(corruptPaths.configDir, { recursive: true });
  await fs.writeFile(path.join(corruptPaths.configDir, "alert-intelligence.json"), "{not valid json", "utf8");
  const enableOutputs = [];
  await runAlerts(corruptPaths, ["intelligence", "enable-namespace", "provenance", "--json"], { output: (line) => enableOutputs.push(JSON.parse(line)) });
  assert.deepEqual(enableOutputs[0].alert_intelligence.enabled_namespaces, ["metric", "provenance"]);
});

test("alerts intelligence enable-namespace validates the namespace, rejects learned, and round-trips via normalize", async () => {
  const paths = await tempPaths();

  await assert.rejects(
    () => runAlerts(paths, ["intelligence", "enable-namespace", "learned"], { output: () => {} }),
    /self-audit-only and can never be enabled/,
  );
  await assert.rejects(
    () => runAlerts(paths, ["intelligence", "enable-namespace", "provenence"], { output: () => {} }),
    /Unknown alert intelligence namespace: provenence/,
  );

  const enableOutputs = [];
  await runAlerts(paths, ["intelligence", "enable-namespace", "provenance", "--json"], { output: (line) => enableOutputs.push(JSON.parse(line)) });
  assert.deepEqual(enableOutputs[0].alert_intelligence.enabled_namespaces, ["metric", "provenance"]);

  const textOutputs = [];
  await runAlerts(paths, ["intelligence", "enable-namespace", "constraint"], { output: (line) => textOutputs.push(line) });
  assert.match(textOutputs[0], /Namespace 'constraint' enabled for alert intelligence/);
  assert.match(textOutputs[0], /mined structural constraint-violation diagnostics/);
  assert.match(textOutputs[0], /Enabled namespaces: metric, provenance, constraint/);

  // Round-trips through normalizeAlertIntelligenceConfig on read.
  assert.deepEqual((await readAlertIntelligenceConfig(paths)).enabled_namespaces, ["metric", "provenance", "constraint"]);

  const disableOutputs = [];
  await runAlerts(paths, ["intelligence", "disable-namespace", "provenance", "--json"], { output: (line) => disableOutputs.push(JSON.parse(line)) });
  assert.deepEqual(disableOutputs[0].alert_intelligence.enabled_namespaces, ["metric", "constraint"]);
});

// Slice 6 (observed-incident collectors plan) must-fix 3: without a NAMESPACE_DATA_CLASS_NOTES
// entry for "correlation", the enable-namespace disclosure prints the literal string "undefined"
// as the externalized data class — the first cross-stream namespace in this milestone, the one
// place informed consent matters most.
test("alerts intelligence enable-namespace correlation prints a real data-class disclosure, never the literal string 'undefined'", async () => {
  const paths = await tempPaths();

  const textOutputs = [];
  await runAlerts(paths, ["intelligence", "enable-namespace", "correlation"], { output: (line) => textOutputs.push(line) });
  assert.match(textOutputs[0], /Namespace 'correlation' enabled for alert intelligence/);
  assert.match(textOutputs[0], /correlated session-anomaly and peer-login events \(hashed\/bucketed, temporally joined\)/);
  assert.equal(textOutputs[0].includes("undefined"), false, "the disclosure must never print the literal string 'undefined' as the externalized data class");
  assert.match(textOutputs[0], /Enabled namespaces: metric, correlation/);

  const jsonOutputs = [];
  await runAlerts(paths, ["intelligence", "status", "--json"], { output: (line) => jsonOutputs.push(JSON.parse(line)) });
  assert.deepEqual(jsonOutputs[0].alert_intelligence.enabled_namespaces, ["metric", "correlation"]);
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

  const helperRoot = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alerts-native-helper-"));
  const srcDir = path.join(helperRoot, "src");
  const appHelper = path.join(helperRoot, "native", "macos", "DescartesNotifier.app", "Contents", "MacOS", "DescartesNotifier");
  await fs.mkdir(path.dirname(appHelper), { recursive: true });
  await fs.mkdir(srcDir, { recursive: true });
  await fs.writeFile(appHelper, "#!/bin/sh\n", { mode: 0o755 });
  const bundledNativeOutputs = [];
  await runAlerts(paths, ["notifications", "setup", "--json", "--channel", "native"], {
    platform: "darwin",
    nativeHelperBaseDir: srcDir,
    output: (line) => bundledNativeOutputs.push(JSON.parse(line)),
  });
  assert.equal(bundledNativeOutputs[0].notifications.channel, "macos-native");
  assert.equal(bundledNativeOutputs[0].resolution.resolved_macos_native_helper_path, appHelper);

  const nativeOutputs = [];
  await runAlerts(paths, ["notifications", "setup", "--json", "--channel", "native", "--helper", appHelper], {
    platform: "darwin",
    output: (line) => nativeOutputs.push(JSON.parse(line)),
  });
  assert.equal(nativeOutputs[0].notifications.channel, "macos-native");
  assert.equal(nativeOutputs[0].notifications.macos_native_helper_path, appHelper);

  const disableOutputs = [];
  await runAlerts(paths, ["notifications", "disable", "--json"], { output: (line) => disableOutputs.push(JSON.parse(line)) });
  assert.equal(disableOutputs[0].notifications.enabled, false);
});

test("native notification setup clears stale helper override in favor of bundled helper", async () => {
  const paths = await tempPaths();
  await writeNotificationDeliveryConfig(paths, {
    enabled: true,
    channel: "macos-native",
    macos_native_helper_path: path.join(paths.cacheDir, "stale-helper"),
  });
  const helperRoot = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alerts-native-helper-"));
  const srcDir = path.join(helperRoot, "src");
  const appHelper = path.join(helperRoot, "native", "macos", "DescartesNotifier.app", "Contents", "MacOS", "DescartesNotifier");
  await fs.mkdir(path.dirname(appHelper), { recursive: true });
  await fs.mkdir(srcDir, { recursive: true });
  await fs.writeFile(appHelper, "#!/bin/sh\n", { mode: 0o755 });

  const outputs = [];
  await runAlerts(paths, ["notifications", "setup", "--json", "--channel", "native"], {
    platform: "darwin",
    nativeHelperBaseDir: srcDir,
    output: (line) => outputs.push(JSON.parse(line)),
  });

  assert.equal(outputs[0].notifications.macos_native_helper_path, undefined);
  assert.equal(outputs[0].resolution.macos_native_helper_source, "bundled");
  assert.equal(outputs[0].resolution.resolved_macos_native_helper_path, appHelper);
  assert.equal((await readNotificationDeliveryConfig(paths)).macos_native_helper_path, undefined);
});

test("native notification setup rejects missing helper without persisting unusable config", async () => {
  const paths = await tempPaths();
  await assert.rejects(
    () => runAlerts(paths, ["notifications", "setup", "--json", "--channel", "native"], {
      platform: "darwin",
      nativeHelperBaseDir: paths.cacheDir,
      output: () => {},
    }),
    /Native macOS notification setup unavailable: Native macOS notification helper is not packaged or configured/,
  );
  assert.deepEqual(await readNotificationDeliveryConfig(paths), {
    enabled: false,
    channel: "cli",
    macos_native_helper_path: undefined,
    updated_at: undefined,
  });
});
