import { execFile } from "node:child_process";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const NOTIFICATION_CHANNELS = new Set(["cli", "macos-desktop", "macos-native", "linux-desktop", "syslog"]);

export function resolveNotificationDeliveryPaths(descartesPaths) {
  const alertsDir = path.join(descartesPaths.stateDir, "alerts");
  return {
    configFile: path.join(descartesPaths.configDir, "notifications.json"),
    auditDir: alertsDir,
    auditFile: path.join(alertsDir, "notification-delivery.jsonl"),
  };
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid notification ${field}: ${ts}`);
  return date.toISOString();
}

function clampString(value, max) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function defaultNotificationChannel(platform = process.platform, env = process.env) {
  if (platform === "darwin") return "macos-desktop";
  if (platform === "linux" && (env.DISPLAY || env.WAYLAND_DISPLAY || env.DBUS_SESSION_BUS_ADDRESS)) return "linux-desktop";
  if (platform === "linux") return "syslog";
  return "cli";
}

export function normalizeNotificationDeliveryConfig(config = {}) {
  const channel = String(config.channel ?? "cli");
  const helperPath = config.macos_native_helper_path ? String(config.macos_native_helper_path).trim() : undefined;
  return {
    enabled: config.enabled === true,
    channel: NOTIFICATION_CHANNELS.has(channel) ? channel : "cli",
    macos_native_helper_path: helperPath || undefined,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
  };
}

export async function readNotificationDeliveryConfig(descartesPaths) {
  const { configFile } = resolveNotificationDeliveryPaths(descartesPaths);
  try {
    return normalizeNotificationDeliveryConfig(JSON.parse(await fs.readFile(configFile, "utf8")));
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeNotificationDeliveryConfig();
    throw error;
  }
}

export async function writeNotificationDeliveryConfig(descartesPaths, config, options = {}) {
  const { configFile } = resolveNotificationDeliveryPaths(descartesPaths);
  await ensureParent(configFile);
  const normalized = normalizeNotificationDeliveryConfig({ ...config, updated_at: options.now ?? new Date().toISOString() });
  const tmp = `${configFile}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmp, configFile);
  return normalized;
}

export function normalizeNotificationPayload(decision = {}, options = {}) {
  const severity = ["info", "warning", "critical"].includes(decision.severity) ? decision.severity : "info";
  return {
    alert_id: options.alertId ? String(options.alertId) : undefined,
    rule_id: options.ruleId ? String(options.ruleId) : undefined,
    episode_key: options.episodeKey ? String(options.episodeKey) : undefined,
    severity,
    title: clampString(decision.title, 80) || "Descartes alert",
    body: clampString(decision.body, 240) || "Descartes noticed a local system alert.",
  };
}

function appleScriptString(value) {
  return `"${String(value).replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function isExecutableFile(candidate) {
  try {
    fsSync.accessSync(candidate, fsSync.constants.X_OK);
    return fsSync.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function bundledMacosHelperCandidates(options = {}) {
  const baseDir = options.nativeHelperBaseDir ?? path.dirname(fileURLToPath(import.meta.url));
  return [
    path.resolve(baseDir, "../native/macos/DescartesNotifier.app/Contents/MacOS/DescartesNotifier"),
    path.resolve(baseDir, "../native/macos/DescartesNotifier"),
  ];
}

export function resolveBundledMacosHelperPath(options = {}) {
  return bundledMacosHelperCandidates(options).find(isExecutableFile);
}

// If `helperPath` is the inner Mach-O of a macOS `.app` bundle (`…/<Name>.app/Contents/MacOS/<exe>`),
// returns the enclosing `.app` path; otherwise undefined. A helper INSIDE a bundle must be launched
// via LaunchServices (`open`), never exec'd directly: macOS's UNUserNotificationCenter refuses
// authorization for a process it does not recognize as a launched, registered app — a direct exec of
// the inner binary fails with "Notifications are not allowed for this application"
// (UNErrorCodeNotificationsNotAllowed), regardless of code-signing. `open` launches the registered
// bundle so the permission grant (keyed to the signed bundle id) applies.
export function macosAppBundleFor(helperPath) {
  if (typeof helperPath !== "string") return undefined;
  const match = /^(.*\.app)\/Contents\/MacOS\/[^/]+$/.exec(helperPath);
  return match ? match[1] : undefined;
}

function macosNativeHelperResolution(options = {}) {
  const env = options.env ?? process.env;
  const explicitCandidates = [
    ["override", options.macosNativeHelperPath],
    ["config", options.config?.macos_native_helper_path],
    ["env", env.DESCARTES_MACOS_NOTIFICATION_HELPER],
  ];
  for (const [source, candidate] of explicitCandidates) {
    const helperPath = candidate ? String(candidate).trim() : "";
    if (!helperPath) continue;
    if (isExecutableFile(helperPath)) return { path: helperPath, source, available: true, reason: undefined };
    return {
      path: helperPath,
      source,
      available: false,
      reason: "Native macOS notification helper path is not an executable file",
    };
  }
  const bundled = resolveBundledMacosHelperPath(options);
  if (bundled) return { path: bundled, source: "bundled", available: true, reason: undefined };
  return {
    path: undefined,
    source: undefined,
    available: false,
    reason: "Native macOS notification helper is not packaged or configured",
  };
}

function nativeMacosHelperPath(options = {}) {
  const resolution = macosNativeHelperResolution(options);
  return resolution.available ? resolution.path : undefined;
}

export function resolveMacosNativeHelperPath(options = {}) {
  return nativeMacosHelperPath(options);
}

export function notificationDeliveryResolution(config = {}, options = {}) {
  const normalized = normalizeNotificationDeliveryConfig(config);
  if (normalized.channel !== "macos-native") return { resolved_macos_native_helper_path: undefined };
  const resolution = macosNativeHelperResolution({ ...options, config: normalized });
  return {
    resolved_macos_native_helper_path: resolution.available ? resolution.path : undefined,
    macos_native_helper_path: resolution.path,
    macos_native_helper_source: resolution.source,
    macos_native_helper_available: resolution.available,
    macos_native_helper_reason: resolution.reason,
  };
}

function commandForPayload(channel, payload, options = {}) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  if (channel === "cli") return undefined;
  if (channel === "macos-native") {
    if (platform !== "darwin" && !options.allowPlatformMismatch) {
      return { unavailable: "Native macOS notifications require macOS" };
    }
    const helperResolution = macosNativeHelperResolution(options);
    if (!helperResolution.available) {
      return { unavailable: helperResolution.reason };
    }
    const notifierArgs = [
      "--title", payload.title,
      "--body", payload.body,
      "--severity", payload.severity,
      "--alert-id", payload.alert_id ?? "",
      "--rule-id", payload.rule_id ?? "",
    ];
    // A helper resolved inside a `.app` bundle (the packaged/Homebrew default) MUST be launched via
    // LaunchServices, or macOS denies notification authorization (see macosAppBundleFor). `open`
    // reliably delivers but returns a nonzero exit even on success — the accessory notifier exits
    // before `open` can observe it (`-W` fails with a kevent "No such process") — so delivery status
    // from an `open` launch is best-effort ("launched"), flagged via `best_effort_status` for the
    // runner below. A bare-binary `--helper` override (not inside a `.app`) keeps the direct-exec
    // path, whose precise exit-code status is preserved.
    const appBundle = macosAppBundleFor(helperResolution.path);
    if (appBundle) {
      return {
        // -g: don't steal focus; -n: force a fresh instance so `--args` reaches THIS launch.
        command: "/usr/bin/open",
        args: ["-g", "-n", appBundle, "--args", ...notifierArgs],
        best_effort_status: true,
      };
    }
    return { command: helperResolution.path, args: notifierArgs };
  }
  if (channel === "macos-desktop") {
    if (platform !== "darwin" && !options.allowPlatformMismatch) {
      return { unavailable: "macOS desktop notifications require macOS" };
    }
    return {
      command: "osascript",
      args: ["-e", `display notification ${appleScriptString(payload.body)} with title ${appleScriptString(payload.title)} subtitle ${appleScriptString(`Descartes ${payload.severity}`)}`],
    };
  }
  if (channel === "linux-desktop") {
    if (platform !== "linux" && !options.allowPlatformMismatch) {
      return { unavailable: "Linux desktop notifications require Linux" };
    }
    if (!(env.DISPLAY || env.WAYLAND_DISPLAY || env.DBUS_SESSION_BUS_ADDRESS) && !options.allowHeadlessDesktop) {
      return { unavailable: "Linux desktop notifications require a graphical session D-Bus/display" };
    }
    return {
      command: "notify-send",
      args: ["--app-name=Descartes", "--urgency", payload.severity === "critical" ? "critical" : "normal", payload.title, payload.body],
    };
  }
  if (channel === "syslog") {
    if (platform !== "linux" && platform !== "darwin" && !options.allowPlatformMismatch) {
      return { unavailable: "syslog notification delivery is only enabled on Unix-like hosts" };
    }
    return {
      command: "logger",
      args: ["-t", "descartes", `${payload.severity}: ${payload.title} — ${payload.body}`],
    };
  }
  return { unavailable: `Unsupported notification channel: ${channel}` };
}

export const MAX_NOTIFICATION_DELIVERY_AUDIT_RECORDS = 1000;
// Operator policy (O): retain complete dated audit segments up to this total byte cap.
export const MAX_NOTIFICATION_DELIVERY_AUDIT_BYTES = 50 * 1024 * 1024;

function parseAuditRecords(contents) {
  return contents.split("\n").filter((line) => line.trim()).map((line) => {
    try { return JSON.parse(line); } catch { return undefined; }
  }).filter(Boolean);
}

function datedSegmentFile(auditDir, day) {
  return path.join(auditDir, `notification-delivery-${day}.jsonl`);
}

function isDatedSegment(name) {
  return /^notification-delivery-\d{4}-\d{2}-\d{2}\.jsonl$/.test(name);
}

function isOrphanArchive(name) {
  return /^notification-delivery\.jsonl\..+\.archive$/.test(name);
}

async function readAuditFile(file) {
  try {
    return parseAuditRecords(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

async function auditFilesInReadOrder(descartesPaths) {
  const { auditDir, auditFile } = resolveNotificationDeliveryPaths(descartesPaths);
  let entries;
  try {
    entries = await fs.readdir(auditDir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const names = new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name));
  const files = names.has(path.basename(auditFile)) ? [auditFile] : [];
  const archives = entries.filter((entry) => entry.isFile() && isOrphanArchive(entry.name)).map((entry) => entry.name).sort();
  files.push(...archives.map((name) => path.join(auditDir, name)));
  files.push(...entries.filter((entry) => entry.isFile() && isDatedSegment(entry.name)).map((entry) => entry.name).sort().map((name) => path.join(auditDir, name)));
  return files;
}

async function pruneNotificationDeliveryAudit(descartesPaths, now, options = {}) {
  const { auditDir, auditFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const maxBytes = Number.isFinite(options.maxBytes) && options.maxBytes >= 0
    ? options.maxBytes
    : MAX_NOTIFICATION_DELIVERY_AUDIT_BYTES;
  let entries;
  try {
    entries = await fs.readdir(auditDir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  const candidates = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const segmentMatch = /^notification-delivery-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(entry.name);
    const archive = isOrphanArchive(entry.name);
    const legacy = entry.name === path.basename(auditFile);
    if (!segmentMatch && !archive && !legacy) continue;
    const file = path.join(auditDir, entry.name);
    let initialStat;
    try {
      initialStat = await fs.stat(file);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    candidates.push({ file, name: entry.name, initialStat });
  }
  // The compatibility file predates dated segments and is therefore always the oldest retention
  // candidate, even though its filename would sort after a dated segment lexicographically.
  const legacyName = path.basename(auditFile);
  candidates.sort((left, right) => {
    const leftRank = left.name === legacyName ? 0 : isOrphanArchive(left.name) ? 1 : 2;
    const rightRank = right.name === legacyName ? 0 : isOrphanArchive(right.name) ? 1 : 2;
    return leftRank - rightRank || left.name.localeCompare(right.name);
  });
  let totalBytes = candidates.reduce((sum, candidate) => sum + candidate.initialStat.size, 0);

  // Snapshot all candidates before a paused writer can race the unlink phase. appendDeliveryAudit
  // passes this hook only for tests and diagnostics; production callers leave it undefined.
  await options.beforeAuditRetention?.({ auditDir, segmentFile: options.segmentFile, now });

  for (const { file, initialStat } of candidates) {
    if (totalBytes <= maxBytes) break;
    // Never remove the dated segment this process appended during this tick, even if a wall-clock
    // rollback made its name sort before older segments.
    if (file === options.segmentFile) continue;
    let latestStat;
    try {
      latestStat = await fs.stat(file);
    } catch (error) {
      if (error?.code === "ENOENT") {
        totalBytes -= initialStat.size;
        continue;
      }
      throw error;
    }
    if (latestStat.mtimeMs !== initialStat.mtimeMs || latestStat.size !== initialStat.size) continue;
    try {
      await fs.unlink(file);
      totalBytes -= latestStat.size;
    } catch (error) {
      if (error?.code === "ENOENT") totalBytes -= latestStat.size;
      else throw error;
    }
  }
}

async function appendDeliveryAudit(descartesPaths, record, options = {}) {
  const { auditDir } = resolveNotificationDeliveryPaths(descartesPaths);
  const segmentFile = datedSegmentFile(auditDir, normalizeIso(record.ts, "audit timestamp").slice(0, 10));
  await ensureParent(segmentFile);
  // fs.appendFile opens and closes this dated segment for every row. There is no shared descriptor,
  // inode rename, read/modify/write, compaction, or replacement window for a concurrent writer.
  await fs.appendFile(segmentFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  await pruneNotificationDeliveryAudit(descartesPaths, record.ts, { ...options, segmentFile });
  return record;
}

export async function readNotificationDeliveryAudit(descartesPaths) {
  const files = await auditFilesInReadOrder(descartesPaths);
  const records = [];
  for (const file of files) records.push(...await readAuditFile(file));
  return records.map((record, index) => ({ record, index, ts: Date.parse(record?.ts) }))
    .sort((left, right) => {
      const leftValid = Number.isFinite(left.ts);
      const rightValid = Number.isFinite(right.ts);
      if (leftValid && rightValid && left.ts !== right.ts) return left.ts - right.ts;
      if (leftValid !== rightValid) return leftValid ? -1 : 1;
      return left.index - right.index;
    })
    .map(({ record }) => record);
}

export async function deliverNotificationDecision(descartesPaths, decision, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const config = options.config ?? await readNotificationDeliveryConfig(descartesPaths);
  const payload = normalizeNotificationPayload(decision, options);
  const append = (record) => appendDeliveryAudit(descartesPaths, record, options);
  if (decision?.notify !== true) {
    return append({ ts: now, status: "skipped", reason: "notify_false", channel: config.channel, payload });
  }
  if (!config.enabled) {
    return append({ ts: now, status: "disabled", channel: config.channel, payload });
  }
  const commandSpec = commandForPayload(config.channel, payload, { ...options, config });
  if (!commandSpec) {
    return append({ ts: now, status: "cli_only", channel: config.channel, payload });
  }
  if (commandSpec.unavailable) {
    return append({ ts: now, status: "unavailable", channel: config.channel, reason: commandSpec.unavailable, payload });
  }

  const runner = options.runner ?? execFileAsync;
  try {
    await runner(commandSpec.command, commandSpec.args, { timeout: options.timeoutMs ?? 5000, maxBuffer: 1024 * 64 });
    return append({
      ts: now,
      status: "delivered",
      channel: config.channel,
      command: [commandSpec.command, ...commandSpec.args.slice(0, 3)],
      payload,
    });
  } catch (error) {
    // `open`-launched delivery (best_effort_status): `open` returns a nonzero exit code even on a
    // successful LaunchServices launch, so a NUMERIC-exit rejection is NOT a delivery failure — the
    // notification was launched, we just can't observe the accessory helper's own exit status
    // (accurate post-time status would need the helper to write a result file, a signed-release
    // follow-up). Only a spawn failure (`open` itself unrunnable — a string `error.code` like ENOENT)
    // or a timeout/kill is a real error.
    if (commandSpec.best_effort_status && typeof error?.code === "number") {
      return append({
        ts: now,
        status: "delivered",
        delivery_confidence: "best_effort",
        channel: config.channel,
        command: [commandSpec.command, ...commandSpec.args.slice(0, 3)],
        payload,
      });
    }
    return append({
      ts: now,
      status: "error",
      channel: config.channel,
      error: error instanceof Error ? error.message : String(error),
      payload,
    });
  }
}

export function notificationPlatformNotes(channel) {
  if (channel === "macos-native") return "Native macOS delivery uses a signed/notarized Descartes notification helper when installed by macOS-specific packaging; --helper is for development or advanced overrides only.";
  if (channel === "macos-desktop") return "macOS may attribute CLI notifications to Terminal, your shell, or osascript rather than a branded Descartes app.";
  if (channel === "linux-desktop") return "Linux desktop notifications require a graphical session notification service; headless systems should use syslog.";
  if (channel === "syslog") return "Syslog delivery writes a bounded local log entry through logger; configure external forwarding separately if desired.";
  return "CLI-only mode records delivery decisions locally but does not send desktop or server notifications.";
}

export async function testNotificationDelivery(descartesPaths, options = {}) {
  const config = options.config ?? await readNotificationDeliveryConfig(descartesPaths);
  return deliverNotificationDecision(descartesPaths, {
    notify: true,
    severity: "info",
    title: "Descartes notification test",
    body: "Descartes notifications are configured for this channel.",
  }, { ...options, config, alertId: "test", ruleId: "notifications.test" });
}
