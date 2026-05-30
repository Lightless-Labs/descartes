import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  defaultNotificationChannel,
  deliverNotificationDecision,
  normalizeNotificationPayload,
  readNotificationDeliveryAudit,
  readNotificationDeliveryConfig,
  resolveNotificationDeliveryPaths,
  testNotificationDelivery,
  writeNotificationDeliveryConfig,
} from "../src/notification-delivery.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-notifications-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("notification delivery config is disabled by default and persists under Descartes config", async () => {
  const paths = await tempPaths();
  assert.deepEqual(await readNotificationDeliveryConfig(paths), { enabled: false, channel: "cli", macos_native_helper_path: undefined, updated_at: undefined });

  const written = await writeNotificationDeliveryConfig(paths, { enabled: true, channel: "syslog" }, { now: "2026-05-29T00:00:00.000Z" });
  assert.equal(written.enabled, true);
  assert.equal(written.channel, "syslog");
  assert.equal(written.updated_at, "2026-05-29T00:00:00.000Z");
  assert.equal(path.dirname(resolveNotificationDeliveryPaths(paths).configFile), paths.configDir);
});

test("notification payloads are bounded before adapter delivery", () => {
  const payload = normalizeNotificationPayload({
    severity: "critical",
    title: "x".repeat(200),
    body: "body ".repeat(100),
  }, { alertId: "alert_1", ruleId: "rule" });
  assert.equal(payload.severity, "critical");
  assert.equal(payload.alert_id, "alert_1");
  assert(payload.title.length <= 81);
  assert(payload.body.length <= 241);
});

test("default notification channel follows platform/session availability", () => {
  assert.equal(defaultNotificationChannel("darwin", {}), "macos-desktop");
  assert.equal(defaultNotificationChannel("linux", { DISPLAY: ":0" }), "linux-desktop");
  assert.equal(defaultNotificationChannel("linux", {}), "syslog");
  assert.equal(defaultNotificationChannel("freebsd", {}), "cli");
});

test("disabled delivery records a local audit without invoking adapters", async () => {
  const paths = await tempPaths();
  const record = await deliverNotificationDecision(paths, { notify: true, title: "Alert", body: "Body" }, {
    now: "2026-05-29T00:01:00.000Z",
    runner: async () => {
      throw new Error("runner should not be called while disabled");
    },
  });
  assert.equal(record.status, "disabled");
  assert.equal((await readNotificationDeliveryAudit(paths)).length, 1);
});

test("enabled linux desktop delivery uses fixed notify-send command with injected runner", async () => {
  const paths = await tempPaths();
  await writeNotificationDeliveryConfig(paths, { enabled: true, channel: "linux-desktop" }, { now: "2026-05-29T00:00:00.000Z" });
  const calls = [];
  const record = await deliverNotificationDecision(paths, {
    notify: true,
    severity: "warning",
    title: "Memory pressure is high",
    body: "Memory has stayed above the threshold.",
  }, {
    now: "2026-05-29T00:01:00.000Z",
    platform: "linux",
    env: { DISPLAY: ":0" },
    runner: async (command, args) => calls.push([command, ...args]),
  });
  assert.equal(record.status, "delivered");
  assert.equal(calls[0][0], "notify-send");
  assert(calls[0].includes("--app-name=Descartes"));
});

test("notification test helper delivers bounded configured test payload", async () => {
  const paths = await tempPaths();
  const calls = [];
  const record = await testNotificationDelivery(paths, {
    config: { enabled: true, channel: "syslog" },
    platform: "linux",
    runner: async (command, args) => calls.push([command, ...args]),
    now: "2026-05-29T00:02:00.000Z",
  });
  assert.equal(record.status, "delivered");
  assert.deepEqual(calls[0].slice(0, 3), ["logger", "-t", "descartes"]);
  assert.equal(record.payload.alert_id, "test");
});

test("native macOS delivery fails closed when helper is not configured", async () => {
  const paths = await tempPaths();
  const record = await deliverNotificationDecision(paths, { notify: true, title: "Alert", body: "Body" }, {
    config: { enabled: true, channel: "macos-native" },
    platform: "darwin",
    now: "2026-05-29T00:03:00.000Z",
  });
  assert.equal(record.status, "unavailable");
  assert.match(record.reason, /helper is not configured/);
});

test("native macOS delivery uses configured helper with fixed bounded arguments", async () => {
  const paths = await tempPaths();
  const calls = [];
  const record = await deliverNotificationDecision(paths, {
    notify: true,
    severity: "critical",
    title: "CPU alert",
    body: "Load is high.",
  }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: "/opt/descartes/DescartesNotifier" },
    alertId: "alert_cpu",
    ruleId: "system.load.sustained_high",
    platform: "darwin",
    now: "2026-05-29T00:04:00.000Z",
    runner: async (command, args) => calls.push([command, ...args]),
  });
  assert.equal(record.status, "delivered");
  assert.equal(calls[0][0], "/opt/descartes/DescartesNotifier");
  assert.deepEqual(calls[0].slice(1), [
    "--title", "CPU alert",
    "--body", "Load is high.",
    "--severity", "critical",
    "--alert-id", "alert_cpu",
    "--rule-id", "system.load.sustained_high",
  ]);
});
