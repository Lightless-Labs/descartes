import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  defaultNotificationChannel,
  deliverNotificationDecision,
  normalizeNotificationPayload,
  queuePendingNotification,
  notificationDeliveryResolution,
  readNotificationDeliveryAudit,
  readPendingNotifications,
  recoverNotificationOutbox,
  retainNotificationOutbox,
  selectNotificationNoticeWindow,
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

test("required_disabled_notice_stays_pending_until a later daemon retry", async () => {
  const paths = await tempPaths();
  const record = await deliverNotificationDecision(paths, { notify: true, title: "Integrity", body: "State changed." }, {
    now: "2026-05-29T00:01:00.000Z",
    required: true,
    requiredNoticeId: "unattributed:abc",
    ruleId: "integrity.unattributed_change",
  });
  assert.equal(record.status, "disabled");
  assert.equal((await readPendingNotifications(paths)).pending.length, 1);
  const state = await readPendingNotifications(paths);
  assert.equal(state.notices.length, 1);
  assert.equal(state.notices[0].last_status, "disabled");
});

test("required_unavailable_notice_stays_pending", async () => {
  const paths = await tempPaths();
  const record = await deliverNotificationDecision(paths, { notify: true, title: "Integrity", body: "State changed." }, {
    now: "2026-05-29T00:03:00.000Z",
    required: true,
    requiredNoticeId: "discontinuity:abc",
    ruleId: "integrity.pending_discontinuity",
    config: { enabled: true, channel: "macos-native" },
    platform: "darwin",
    nativeHelperBaseDir: paths.cacheDir,
  });
  assert.equal(record.status, "unavailable");
  assert.equal((await readPendingNotifications(paths)).pending[0].id, "discontinuity:abc");
});

test("required notices are queued before malformed notification config is read", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "{ malformed");
  await assert.rejects(() => deliverNotificationDecision(paths, { notify: true, title: "Integrity", body: "State changed." }, {
    now: "2026-05-29T00:03:30.000Z",
    required: true,
    requiredNoticeId: "integrity:malformed-config",
    ruleId: "integrity.unattributed_change",
  }));
  assert.equal((await readPendingNotifications(paths)).pending[0].id, "integrity:malformed-config");
});

test("notification outbox overflow keeps a counted summary instead of silently evicting unresolved notices", async () => {
  const paths = await tempPaths();
  for (let index = 0; index < 512; index += 1) {
    await queuePendingNotification(paths, { notify: true, title: `Notice ${index}`, body: "Pending" }, {
      now: "2026-05-29T00:00:00.000Z",
      required: true,
      requiredNoticeId: `notice:${index}`,
      ruleId: "integrity.test",
    });
  }
  await queuePendingNotification(paths, { notify: true, title: "Notice 512", body: "Pending" }, {
    now: "2026-05-29T00:00:00.000Z",
    required: true,
    requiredNoticeId: "notice:512",
    ruleId: "integrity.test",
  });
  const state = await readPendingNotifications(paths);
  const summary = state.pending.find((entry) => entry.rule_id === "integrity.notification_outbox");
  assert.equal(state.pending.length, 512);
  assert.equal(state.pending.some((entry) => entry.id === "notice:0"), true);
  assert.equal(summary.notices_overflowed, 2, "the displaced unresolved notice and the new one are both counted");
  assert.match(summary.body, /2/);
});

test("corrupt notification outbox is surfaced read-only; daemon recovery owns quarantine", async () => {
  const paths = await tempPaths();
  const { pendingFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(pendingFile), { recursive: true });
  await fs.writeFile(pendingFile, "not json");
  const rendered = await readPendingNotifications(paths);
  assert.equal(rendered.tamper.kind, "notification_outbox_corrupt");
  assert.equal((await fs.readdir(path.dirname(pendingFile))).some((name) => name.startsWith("notification-pending.json.corrupt-")), false);
  await recoverNotificationOutbox(paths);
  await queuePendingNotification(paths, { notify: true, title: "Alert", body: "Body" }, {
    now: "2026-05-29T00:04:00.000Z",
    required: true,
    requiredNoticeId: "notice:after-corruption",
    ruleId: "integrity.test",
  });
  const state = await readPendingNotifications(paths);
  assert.ok(state.pending.some((entry) => entry.rule_id === "integrity.notification_outbox"));
  assert.ok(state.pending.some((entry) => entry.id === "notice:after-corruption"));
  assert.ok((await fs.readdir(path.dirname(pendingFile))).some((name) => name.startsWith("notification-pending.json.corrupt-")));
});

function validEntry(overrides = {}) {
  return {
    id: "notice:valid",
    digest: "a".repeat(64),
    rule_id: "integrity.test",
    first_seen_at: "2026-05-29T00:00:00.000Z",
    severity: "warning",
    title: "Valid",
    body: "Body",
    attempts: 0,
    last_status: null,
    ...overrides,
  };
}

test("malformed notification entries are reported read-only and quarantined only by daemon recovery", async () => {
  const cases = [
    { notices: [null] },
    { notices: [validEntry(), 7] },
    { notices: [validEntry({ title: undefined })] },
    { notices: [validEntry({ attempts: -1 })] },
  ];
  for (const [index, body] of cases.entries()) {
    const paths = await tempPaths();
    const { pendingFile } = resolveNotificationDeliveryPaths(paths);
    await fs.mkdir(path.dirname(pendingFile), { recursive: true });
    await fs.writeFile(pendingFile, JSON.stringify({ v: 2, ...body }));

    const state = await readPendingNotifications(paths);
    assert.equal(state.tamper?.kind, "notification_outbox_corrupt", `case ${index}`);
    assert.equal(state.notices.length, 1, `case ${index}`);
    assert.equal(state.notices[0].rule_id, "integrity.notification_outbox", `case ${index}`);
    assert.equal((await fs.readdir(path.dirname(pendingFile))).some((name) => name.startsWith("notification-pending.json.corrupt-")), false, `case ${index}: CLI/read path must not quarantine`);
    await recoverNotificationOutbox(paths);
    const persisted = JSON.parse(await fs.readFile(pendingFile, "utf8"));
    assert.equal(persisted.notices.length, 1, `case ${index}: daemon recovery replaces the corrupt outbox`);
    assert.equal((await readPendingNotifications(paths)).tamper, undefined, `case ${index}: the recovered outbox reads clean`);
    assert.ok((await fs.readdir(path.dirname(pendingFile))).some((name) => name.startsWith("notification-pending.json.corrupt-")), `case ${index}`);
  }
});

test("daemon queueing still works after a structurally malformed outbox", async () => {
  const paths = await tempPaths();
  const { pendingFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(pendingFile), { recursive: true });
  await fs.writeFile(pendingFile, JSON.stringify({ v: 2, notices: [null] }));
  await recoverNotificationOutbox(paths);
  const record = await deliverNotificationDecision(paths, { notify: true, title: "Integrity", body: "State changed." }, {
    now: "2026-05-29T00:05:00.000Z",
    required: true,
    requiredNoticeId: "notice:after-malformed",
    ruleId: "integrity.test",
  });
  assert.equal(record.status, "disabled");
  const state = await readPendingNotifications(paths);
  assert.equal(state.tamper, undefined);
  assert.deepEqual(state.notices.map((entry) => entry.id).sort(), ["integrity.notification_outbox:corrupt", "notice:after-malformed"]);
  assert.equal(state.notices.find((entry) => entry.id === "notice:after-malformed").attempts, 1);
});

test("every outbox entry the module writes passes its own shape validation", async () => {
  const paths = await tempPaths();
  const options = (id, extra = {}) => ({ now: "2026-05-29T00:06:00.000Z", required: true, requiredNoticeId: id, ruleId: "integrity.test", ...extra });
  // failed attempt mutates attempts/last_status
  await deliverNotificationDecision(paths, { notify: true, title: "Failing", body: "Body" }, options("notice:failing", {
    config: { enabled: true, channel: "macos-native" }, platform: "darwin", nativeHelperBaseDir: paths.cacheDir,
  }));
  // delivered remains retained with its delivery outcome
  await deliverNotificationDecision(paths, { notify: true, title: "Delivered", body: "Body" }, options("notice:delivered", {
    config: { enabled: true, channel: "syslog" }, platform: "linux", runner: async () => ({ stdout: "", stderr: "" }),
  }));
  // a numeric rule id and a Date `now` are normalized, never self-corrupting
  await queuePendingNotification(paths, { notify: true, title: "Odd inputs", body: "Body" }, { now: new Date("2026-05-29T00:07:00.000Z"), requiredNoticeId: "notice:odd", ruleId: 42 });
  await queuePendingNotification(paths, { notify: true, title: "Still pending", body: "Body" }, options("notice:pending"));
  const state = await readPendingNotifications(paths);
  assert.equal(state.tamper, undefined);
  assert.ok(state.notices.some((entry) => entry.id === "notice:delivered" && entry.last_status === "delivered"));
  assert.ok(state.notices.some((entry) => entry.id === "notice:failing" && entry.attempts === 1));
  assert.ok(state.notices.some((entry) => entry.id === "notice:odd" && entry.rule_id === "42"));
  assert.deepEqual(state.pending.map((entry) => entry.id), ["notice:failing", "notice:odd", "notice:pending"]);
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

test("the old viewed/resolved outbox schema is corrupt and never drives a view mutation", async () => {
  for (const body of [
    { pending: [], seen: [validEntry()], resolved: [] },
    { pending: [], seen: [], resolved: [validEntry()] },
  ]) {
    const paths = await tempPaths();
    const { pendingFile } = resolveNotificationDeliveryPaths(paths);
    await fs.mkdir(path.dirname(pendingFile), { recursive: true });
    await fs.writeFile(pendingFile, JSON.stringify({ v: 1, ...body }));
    assert.equal((await readPendingNotifications(paths)).tamper?.kind, "notification_outbox_corrupt", JSON.stringify(body));
  }
});

/* removed: viewing must never mutate notification state
test("seen marks append to the CLI log and the daemon folds only rendered notices", async () => {
  const paths = await tempPaths();
  for (const id of ["notice:rendered", "notice:queued-after-render"]) {
    await queuePendingNotification(paths, { notify: true, title: id, body: "Body" }, { now: "2026-05-29T00:13:00.000Z", requiredNoticeId: id, ruleId: "integrity.test" });
  }
  await appendSeenNotification(paths, "notice:rendered", { now: "2026-05-29T00:14:00.000Z" });
  const folded = await foldNotificationSeenLog(paths, { now: "2026-05-29T00:14:00.000Z" });
  assert.equal(folded.seen, 1);
  const state = await readPendingNotifications(paths);
  assert.deepEqual(state.pending.map((entry) => entry.id), ["notice:queued-after-render"]);
  assert.deepEqual(state.seen.map((entry) => entry.id), ["notice:rendered"]);
});
*/

/* removed with viewing marks
test("48 CLI seen append processes plus a daemon fold lose neither notices nor seen marks", async () => {
  const paths = await tempPaths();
  const ids = Array.from({ length: 48 }, (_, index) => `notice:process:${index}`);
  for (const id of ids) await queuePendingNotification(paths, { notify: true, title: id, body: "Body" }, { now: "2026-05-29T00:15:00.000Z", requiredNoticeId: id, ruleId: "integrity.test" });
  const moduleUrl = new URL("../src/notification-delivery.js", import.meta.url).href;
  await Promise.all(ids.map((id) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", `import { appendSeenNotification } from ${JSON.stringify(moduleUrl)}; await appendSeenNotification(${JSON.stringify(paths)}, ${JSON.stringify(id)}, { now: "2026-05-29T00:16:00.000Z" });`], { stdio: "ignore" });
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`seen append exited ${code}`)));
  })));
  await foldNotificationSeenLog(paths, { now: "2026-05-29T00:17:00.000Z" });
  const state = await readPendingNotifications(paths);
  assert.deepEqual(state.pending, []);
  assert.deepEqual(state.seen.map((entry) => entry.id).sort(), ids.sort());
});
*/

/* removed with viewing marks
test("a crash after fold and offset record replays seen marks idempotently", async () => {
  const paths = await tempPaths();
  await queuePendingNotification(paths, { notify: true, title: "Replay", body: "Body" }, { now: "2026-05-29T00:18:00.000Z", requiredNoticeId: "notice:replay", ruleId: "integrity.test" });
  await appendSeenNotification(paths, "notice:replay", { now: "2026-05-29T00:19:00.000Z" });
  await assert.rejects(() => foldNotificationSeenLog(paths, { now: "2026-05-29T00:19:00.000Z", beforeRotate: async () => { throw new Error("simulated daemon crash"); } }), /simulated daemon crash/);
  const replay = await foldNotificationSeenLog(paths, { now: "2026-05-29T00:20:00.000Z" });
  assert.equal(replay.seen, 0, "the replay is idempotent after the outbox was already persisted");
  assert.deepEqual((await readPendingNotifications(paths)).seen.map((entry) => entry.id), ["notice:replay"]);
});
*/

/* removed with viewing marks
test("malformed seen-log lines are ignored and counted without blocking later valid marks", async () => {
  const paths = await tempPaths();
  await queuePendingNotification(paths, { notify: true, title: "Valid", body: "Body" }, { now: "2026-05-29T00:21:00.000Z", requiredNoticeId: "notice:valid-seen", ruleId: "integrity.test" });
  const { seenFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(seenFile), { recursive: true });
  await fs.writeFile(seenFile, "not json\n" + JSON.stringify({ v: 1, id: "notice:valid-seen", seen_at: "2026-05-29T00:22:00.000Z" }) + "\n");
  const folded = await foldNotificationSeenLog(paths, { now: "2026-05-29T00:22:00.000Z" });
  assert.equal(folded.malformed, 1);
  assert.deepEqual((await readPendingNotifications(paths)).seen.map((entry) => entry.id), ["notice:valid-seen"]);
});
*/

test("an overflow summary created with a non-ISO now still passes outbox validation", async () => {
  const paths = await tempPaths();
  for (let index = 0; index < 513; index += 1) {
    await queuePendingNotification(paths, { notify: true, title: `N ${index}`, body: "Body" }, { now: 0, requiredNoticeId: `notice:epoch:${index}`, ruleId: "integrity.test" });
  }
  const state = await readPendingNotifications(paths);
  assert.equal(state.tamper, undefined);
  assert.ok(state.pending.some((entry) => entry.rule_id === "integrity.notification_outbox" && entry.first_seen_at === "1970-01-01T00:00:00.000Z"));
});

test("non-ENOENT outbox read errors abort outbox work without quarantine or mutation", async () => {
  const paths = await tempPaths();
  const { pendingFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(pendingFile, { recursive: true });
  const before = await fs.readdir(path.dirname(pendingFile));
  const recovered = await recoverNotificationOutbox(paths);
  assert.equal(recovered.outbox_error.code, "EISDIR");
  assert.equal(recovered.recovered, undefined);
  assert.deepEqual(await fs.readdir(path.dirname(pendingFile)), before);
  await assert.rejects(() => queuePendingNotification(paths, { notify: true, title: "No write", body: "Body" }, {
    now: "2026-05-29T00:30:00.000Z", required: true, requiredNoticeId: "notice:eisdir", ruleId: "integrity.test",
  }), /EISDIR/);
  assert.deepEqual(await fs.readdir(path.dirname(pendingFile)), before);
});

test("malformed JSON is quarantined and valid embedded notices are salvaged", async () => {
  const paths = await tempPaths();
  const { pendingFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(pendingFile), { recursive: true });
  const entry = validEntry({ id: "notice:salvage" });
  await fs.writeFile(pendingFile, `{"v":2,"notices":[${JSON.stringify(entry)},`);
  const recovered = await recoverNotificationOutbox(paths);
  assert.equal(recovered.recovered, true);
  assert.ok(recovered.notices.some((notice) => notice.id === "notice:salvage"));
  assert.ok((await fs.readdir(path.dirname(pendingFile))).some((name) => name.startsWith("notification-pending.json.corrupt-")));
  const persisted = JSON.parse(await fs.readFile(pendingFile, "utf8"));
  assert.ok(persisted.notices.some((notice) => notice.id === "notice:salvage"));
});

test("daemon retention keeps the newest 50 notices in the 30-day window and aggregates older notices", async () => {
  const paths = await tempPaths();
  for (let index = 0; index < 55; index += 1) {
    await queuePendingNotification(paths, { notify: true, title: `N ${index}`, body: "Body" }, {
      now: new Date(Date.UTC(2026, 0, 1) + index * 60 * 60 * 1000).toISOString(), required: true, requiredNoticeId: `notice:retention:${index}`, ruleId: "integrity.test",
    });
  }
  const retained = await retainNotificationOutbox(paths, { now: "2026-01-04T00:00:00.000Z" });
  assert.equal(retained.status, "ok");
  const state = await readPendingNotifications(paths);
  const view = selectNotificationNoticeWindow(state, { now: "2026-01-04T00:00:00.000Z" });
  assert.equal(view.entries.filter((notice) => notice.rule_id === "integrity.test").length, 50);
  assert.equal(view.older_count, 5);
  assert.ok(view.entries.some((notice) => notice.rule_id === "integrity.notification_outbox"));
});
