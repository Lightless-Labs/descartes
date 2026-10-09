import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  defaultNotificationChannel,
  deliverNotificationDecision,
  normalizeNotificationPayload,
  notificationDeliveryResolution,
  readNotificationDeliveryAudit,
  readNotificationDeliveryConfig,
  resolveNotificationDeliveryPaths,
  testNotificationDelivery,
  resolveBundledMacosHelperPath,
  macosAppBundleFor,
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

test("repeated identical delivery failures append one immutable audit row per attempt", async () => {
  const paths = await tempPaths();
  const options = {
    now: "2026-05-29T00:01:00.000Z",
    episodeKey: "default",
    alertId: "alert_repeat",
    ruleId: "system.memory.sustained_high",
  };
  await deliverNotificationDecision(paths, { notify: true, title: "Alert", body: "Body" }, options);
  const second = await deliverNotificationDecision(paths, { notify: true, title: "Alert", body: "Body" }, { ...options, now: "2026-05-29T00:02:00.000Z" });
  assert.equal(second.status, "disabled");
  const audit = await readNotificationDeliveryAudit(paths);
  assert.equal(audit.length, 2);
  assert.equal(audit[0].ts, "2026-05-29T00:01:00.000Z");
  assert.equal(audit[1].ts, "2026-05-29T00:02:00.000Z");
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

test("native macOS delivery fails closed when helper is not packaged or configured", async () => {
  const paths = await tempPaths();
  const record = await deliverNotificationDecision(paths, { notify: true, title: "Alert", body: "Body" }, {
    config: { enabled: true, channel: "macos-native" },
    platform: "darwin",
    nativeHelperBaseDir: paths.cacheDir,
    now: "2026-05-29T00:03:00.000Z",
  });
  assert.equal(record.status, "unavailable");
  assert.match(record.reason, /helper is not packaged or configured/);
});

test("native macOS helper resolution prefers the bundled app executable", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-native-helper-test-"));
  const srcDir = path.join(root, "src");
  const appHelper = path.join(root, "native", "macos", "DescartesNotifier.app", "Contents", "MacOS", "DescartesNotifier");
  const legacyHelper = path.join(root, "native", "macos", "DescartesNotifier");
  await fs.mkdir(path.dirname(appHelper), { recursive: true });
  await fs.mkdir(path.dirname(legacyHelper), { recursive: true });
  await fs.mkdir(srcDir, { recursive: true });
  await fs.writeFile(appHelper, "#!/bin/sh\n", { mode: 0o755 });
  await fs.writeFile(legacyHelper, "#!/bin/sh\n", { mode: 0o755 });
  assert.equal(resolveBundledMacosHelperPath({ nativeHelperBaseDir: srcDir }), appHelper);
});

test("native macOS delivery uses configured helper with fixed bounded arguments", async () => {
  const paths = await tempPaths();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-configured-native-helper-"));
  const helper = path.join(root, "DescartesNotifier");
  await fs.writeFile(helper, "#!/bin/sh\n", { mode: 0o755 });
  const calls = [];
  const record = await deliverNotificationDecision(paths, {
    notify: true,
    severity: "critical",
    title: "CPU alert",
    body: "Load is high.",
  }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: helper },
    alertId: "alert_cpu",
    ruleId: "system.load.sustained_high",
    platform: "darwin",
    now: "2026-05-29T00:04:00.000Z",
    runner: async (command, args) => calls.push([command, ...args]),
  });
  assert.equal(record.status, "delivered");
  assert.equal(calls[0][0], helper);
  assert.deepEqual(calls[0].slice(1), [
    "--title", "CPU alert",
    "--body", "Load is high.",
    "--severity", "critical",
    "--alert-id", "alert_cpu",
    "--rule-id", "system.load.sustained_high",
  ]);
});

// --- macos-native: launch a .app helper via LaunchServices (`open`), not a direct exec ---
// (Bug: exec'ing …/DescartesNotifier.app/Contents/MacOS/DescartesNotifier directly makes macOS deny
//  notification authorization — "Notifications are not allowed for this application". `open` launches
//  the registered bundle so the permission grant applies. Real-host confirmed 2026-07.)

test("macosAppBundleFor extracts the .app from an inner Mach-O path, and returns undefined for a bare binary", () => {
  assert.equal(
    macosAppBundleFor("/opt/x/DescartesNotifier.app/Contents/MacOS/DescartesNotifier"),
    "/opt/x/DescartesNotifier.app",
  );
  assert.equal(macosAppBundleFor("/opt/x/DescartesNotifier"), undefined);
  assert.equal(macosAppBundleFor(undefined), undefined);
});

test("native macOS delivery launches a .app helper via `open -g -n <app> --args …`, NOT a direct exec of the inner binary", async () => {
  const paths = await tempPaths();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-app-helper-"));
  const appBundle = path.join(root, "DescartesNotifier.app");
  const inner = path.join(appBundle, "Contents", "MacOS", "DescartesNotifier");
  await fs.mkdir(path.dirname(inner), { recursive: true });
  await fs.writeFile(inner, "#!/bin/sh\n", { mode: 0o755 });

  const calls = [];
  const record = await deliverNotificationDecision(paths, {
    notify: true, severity: "info", title: "T", body: "B",
  }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: inner },
    alertId: "a1", ruleId: "r1", platform: "darwin",
    now: "2026-07-16T00:00:00.000Z",
    runner: async (command, args) => { calls.push([command, ...args]); },
  });

  assert.equal(record.status, "delivered");
  assert.equal(calls[0][0], "/usr/bin/open");
  assert.deepEqual(calls[0].slice(1), [
    "-g", "-n", appBundle, "--args",
    "--title", "T", "--body", "B", "--severity", "info", "--alert-id", "a1", "--rule-id", "r1",
  ]);
});

test("native macOS delivery treats `open`'s spurious nonzero exit (numeric code) as delivered/best_effort — never a false error", async () => {
  const paths = await tempPaths();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-app-helper-besteffort-"));
  const inner = path.join(root, "DescartesNotifier.app", "Contents", "MacOS", "DescartesNotifier");
  await fs.mkdir(path.dirname(inner), { recursive: true });
  await fs.writeFile(inner, "#!/bin/sh\n", { mode: 0o755 });

  const record = await deliverNotificationDecision(paths, { notify: true, title: "T", body: "B" }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: inner },
    platform: "darwin",
    now: "2026-07-16T00:01:00.000Z",
    // `open` delivered but returned exit 1 (the accessory notifier exits before open can observe it).
    runner: async () => { const e = new Error("Command failed"); e.code = 1; throw e; },
  });
  assert.equal(record.status, "delivered");
  assert.equal(record.delivery_confidence, "best_effort");
});

test("native macOS delivery still reports an ERROR when `open` itself cannot be spawned (string code) or on a bare-binary direct-exec failure", async () => {
  const paths = await tempPaths();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-app-helper-spawnfail-"));
  const inner = path.join(root, "DescartesNotifier.app", "Contents", "MacOS", "DescartesNotifier");
  await fs.mkdir(path.dirname(inner), { recursive: true });
  await fs.writeFile(inner, "#!/bin/sh\n", { mode: 0o755 });

  // .app path but `open` can't be spawned -> a string error.code is a genuine failure, not best-effort.
  const spawnFail = await deliverNotificationDecision(paths, { notify: true, title: "T", body: "B" }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: inner },
    platform: "darwin", now: "2026-07-16T00:02:00.000Z",
    runner: async () => { const e = new Error("spawn open ENOENT"); e.code = "ENOENT"; throw e; },
  });
  assert.equal(spawnFail.status, "error");

  // A bare-binary direct-exec failure keeps precise error status (best-effort leniency is open-only).
  const bare = path.join(root, "bare-notifier");
  await fs.writeFile(bare, "#!/bin/sh\n", { mode: 0o755 });
  const bareErr = await deliverNotificationDecision(paths, { notify: true, title: "T", body: "B" }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: bare },
    platform: "darwin", now: "2026-07-16T00:03:00.000Z",
    runner: async () => { const e = new Error("helper failed"); e.code = 1; throw e; },
  });
  assert.equal(bareErr.status, "error");
});

test("native macOS helper resolution reports invalid configured helpers as unavailable", async () => {
  const paths = await tempPaths();
  const missingHelper = path.join(paths.cacheDir, "missing-helper");
  const resolution = notificationDeliveryResolution({
    enabled: true,
    channel: "macos-native",
    macos_native_helper_path: missingHelper,
  }, { platform: "darwin", nativeHelperBaseDir: paths.cacheDir });
  assert.equal(resolution.resolved_macos_native_helper_path, undefined);
  assert.equal(resolution.macos_native_helper_path, missingHelper);
  assert.equal(resolution.macos_native_helper_source, "config");
  assert.equal(resolution.macos_native_helper_available, false);
  assert.match(resolution.macos_native_helper_reason, /not an executable file/);

  const record = await deliverNotificationDecision(paths, { notify: true, title: "Alert", body: "Body" }, {
    config: { enabled: true, channel: "macos-native", macos_native_helper_path: missingHelper },
    platform: "darwin",
    now: "2026-05-29T00:05:00.000Z",
  });
  assert.equal(record.status, "unavailable");
  assert.match(record.reason, /not an executable file/);
});

test("delivery audit writes dated UTC append-only segments and reads all records chronologically", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(auditFile), { recursive: true });
  await fs.writeFile(auditFile, `${JSON.stringify({ ts: "2026-10-01T00:00:00.000Z", status: "legacy", payload: { title: "legacy" } })}\n`);
  await fs.writeFile(path.join(path.dirname(auditFile), "notification-delivery.jsonl.migrated.archive"), `${JSON.stringify({ ts: "2026-10-02T00:00:00.000Z", status: "legacy", payload: { title: "legacy-archive" } })}\n`);
  await fs.writeFile(path.join(path.dirname(auditFile), "notification-delivery-2026-10-04.jsonl"), `${JSON.stringify({ ts: "2026-10-04T00:00:00.000Z", status: "dated", payload: { title: "dated-before-legacy" } })}\n`);
  await deliverNotificationDecision(paths, { notify: true, title: "Alert newest", body: "Body" }, {
    config: { enabled: true, channel: "cli" }, now: "2026-10-06T00:20:00.000Z",
  });
  await deliverNotificationDecision(paths, { notify: true, title: "Alert later", body: "Body" }, {
    config: { enabled: true, channel: "cli" }, now: "2026-10-07T00:20:00.000Z",
  });
  const audit = await readNotificationDeliveryAudit(paths);
  assert.deepEqual(audit.map((entry) => entry.payload?.title), ["legacy", "legacy-archive", "dated-before-legacy", "Alert newest", "Alert later"]);
  assert.equal((await fs.readFile(path.join(path.dirname(auditFile), "notification-delivery-2026-10-06.jsonl"), "utf8")).split("\n").filter(Boolean).length, 1);
  assert.equal((await fs.readFile(path.join(path.dirname(auditFile), "notification-delivery-2026-10-07.jsonl"), "utf8")).split("\n").filter(Boolean).length, 1);
  assert.deepEqual((await fs.readdir(path.dirname(auditFile))).filter((name) => name.endsWith(".archive")), ["notification-delivery.jsonl.migrated.archive"]);
});

test("retention deletes oldest-by-name segments until the total byte cap is satisfied", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveNotificationDeliveryPaths(paths);
  const dir = path.dirname(auditFile);
  await fs.mkdir(dir, { recursive: true });
  const row = (ts, title) => `${JSON.stringify({ ts, status: "delivered", channel: "cli", payload: { title, body: "Body" } })}\n`;
  const oldest = path.join(dir, "notification-delivery-2026-09-01.jsonl");
  const middle = path.join(dir, "notification-delivery-2026-09-02.jsonl");
  await fs.writeFile(oldest, row("2026-09-01T00:00:00.000Z", "oldest"));
  await fs.writeFile(middle, row("2026-09-02T00:00:00.000Z", "middle"));
  // The actual audit row includes bounded-delivery metadata, so leave a small margin above two
  // fixture-row sizes: enough for middle + current, but not enough for oldest + middle + current.
  const cap = (await fs.stat(middle)).size * 2 + 64;
  await deliverNotificationDecision(paths, { notify: true, title: "current-day", body: "Body" }, {
    config: { enabled: true, channel: "cli" }, now: "2026-10-09T00:02:00.000Z", maxBytes: cap,
  });
  const audit = await readNotificationDeliveryAudit(paths);
  assert.deepEqual(audit.map((entry) => entry.payload?.title), ["middle", "current-day"]);
  await assert.rejects(() => fs.access(oldest));
  await fs.access(middle);
  await fs.access(path.join(dir, "notification-delivery-2026-10-09.jsonl"));
});

test("retention counts and prunes the legacy audit file as the oldest segment", async () => {
  const paths = await tempPaths();
  const { auditDir, auditFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(auditDir, { recursive: true });
  await fs.writeFile(auditFile, "x".repeat(4096));

  await deliverNotificationDecision(paths, { notify: true, title: "current", body: "Body" }, {
    config: { enabled: true, channel: "cli" },
    now: "2026-10-09T00:03:00.000Z",
    maxBytes: 1,
  });

  await assert.rejects(() => fs.access(auditFile));
  await fs.access(path.join(auditDir, "notification-delivery-2026-10-09.jsonl"));
  const audit = await readNotificationDeliveryAudit(paths);
  assert.deepEqual(audit.map((entry) => entry.payload?.title), ["current"]);
});

test("concurrent append during retention is not lost and a post-append crash leaves the row readable", async () => {
  const paths = await tempPaths();
  let hookCalled = false;
  const external = { ts: "2026-10-09T00:04:59.000Z", status: "delivered", channel: "cli", payload: { title: "racing append", body: "Body" } };
  await assert.rejects(() => deliverNotificationDecision(paths, { notify: false, title: "crash row", body: "Body" }, {
    config: { enabled: true, channel: "cli" }, now: "2026-10-09T00:05:00.000Z",
    beforeAuditRetention: async ({ segmentFile }) => {
      hookCalled = true;
      await fs.appendFile(segmentFile, `${JSON.stringify(external)}\n`);
      throw new Error("simulated crash after append");
    },
  }));
  assert.equal(hookCalled, true, "the append must race during retention");
  const audit = await readNotificationDeliveryAudit(paths);
  assert.deepEqual(audit.map((entry) => entry.payload?.title), ["racing append", "crash row"]);
});

test("retention has no wall-clock expiry and removes a segment only for byte pressure", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveNotificationDeliveryPaths(paths);
  const dir = path.dirname(auditFile);
  const old = path.join(dir, "notification-delivery-2026-09-01.jsonl");
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(old, `${JSON.stringify({ ts: "2026-09-01T00:00:00.000Z", status: "delivered", payload: { title: "old-record" } })}\n`);
  await deliverNotificationDecision(paths, { notify: true, title: "current", body: "Body" }, {
    config: { enabled: true, channel: "cli" },
    now: "2026-10-09T00:00:00.000Z", maxBytes: 10_000,
  });
  await fs.access(old);
});

test("retention re-stats before unlink and skips a segment modified by a paused writer", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveNotificationDeliveryPaths(paths);
  const dir = path.dirname(auditFile);
  const old = path.join(dir, "notification-delivery-2026-09-01.jsonl");
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(old, `${JSON.stringify({ ts: "2026-09-01T00:00:00.000Z", status: "delivered", payload: { title: "old-record" } })}\n`);
  let pausedWriterRan = false;
  await deliverNotificationDecision(paths, { notify: true, title: "current", body: "Body" }, {
    config: { enabled: true, channel: "cli" },
    now: "2026-10-09T00:00:00.000Z",
    maxBytes: 1,
    beforeAuditRetention: async ({ auditDir }) => {
      if (pausedWriterRan) return;
      pausedWriterRan = true;
      await fs.appendFile(old, `${JSON.stringify({ ts: "2026-10-09T00:00:01.000Z", status: "delivered", payload: { title: "paused-writer" } })}\n`);
    },
  });
  assert.equal(pausedWriterRan, true);
  await fs.access(old);
  assert.equal((await readNotificationDeliveryAudit(paths)).some((entry) => entry.payload?.title === "paused-writer"), true);
});

test("retention never deletes the segment written by the current process tick", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveNotificationDeliveryPaths(paths);
  const dir = path.dirname(auditFile);
  const rollbackNamed = path.join(dir, "notification-delivery-2026-09-01.jsonl");
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(rollbackNamed, `${JSON.stringify({ ts: "2026-09-01T00:00:00.000Z", status: "delivered", payload: { title: "rollback-existing" } })}\n`);
  const existingSize = (await fs.stat(rollbackNamed)).size;
  await deliverNotificationDecision(paths, { notify: true, title: "rolled-back", body: "Body" }, {
    config: { enabled: true, channel: "cli" },
    now: "2026-09-01T00:00:00.000Z", maxBytes: existingSize,
  });
  await fs.access(rollbackNamed);
});
