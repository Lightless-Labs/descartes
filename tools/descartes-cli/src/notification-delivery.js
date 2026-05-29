import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const NOTIFICATION_CHANNELS = new Set(["cli", "macos-desktop", "linux-desktop", "syslog"]);

export function resolveNotificationDeliveryPaths(descartesPaths) {
  return {
    configFile: path.join(descartesPaths.configDir, "notifications.json"),
    auditFile: path.join(descartesPaths.stateDir, "alerts", "notification-delivery.jsonl"),
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
  return {
    enabled: config.enabled === true,
    channel: NOTIFICATION_CHANNELS.has(channel) ? channel : "cli",
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
    severity,
    title: clampString(decision.title, 80) || "Descartes alert",
    body: clampString(decision.body, 240) || "Descartes noticed a local system alert.",
  };
}

function appleScriptString(value) {
  return `"${String(value).replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function commandForPayload(channel, payload, options = {}) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  if (channel === "cli") return undefined;
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

async function appendDeliveryAudit(descartesPaths, record) {
  const { auditFile } = resolveNotificationDeliveryPaths(descartesPaths);
  await ensureParent(auditFile);
  await fs.appendFile(auditFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return record;
}

export async function readNotificationDeliveryAudit(descartesPaths) {
  const { auditFile } = resolveNotificationDeliveryPaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(auditFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const records = [];
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      // Ignore corrupt local audit lines rather than breaking alert delivery.
    }
  }
  return records;
}

export async function deliverNotificationDecision(descartesPaths, decision, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const config = options.config ?? await readNotificationDeliveryConfig(descartesPaths);
  const payload = normalizeNotificationPayload(decision, options);
  if (decision?.notify !== true) {
    return appendDeliveryAudit(descartesPaths, { ts: now, status: "skipped", reason: "notify_false", channel: config.channel, payload });
  }
  if (!config.enabled) {
    return appendDeliveryAudit(descartesPaths, { ts: now, status: "disabled", channel: config.channel, payload });
  }
  const commandSpec = commandForPayload(config.channel, payload, options);
  if (!commandSpec) {
    return appendDeliveryAudit(descartesPaths, { ts: now, status: "cli_only", channel: config.channel, payload });
  }
  if (commandSpec.unavailable) {
    return appendDeliveryAudit(descartesPaths, { ts: now, status: "unavailable", channel: config.channel, reason: commandSpec.unavailable, payload });
  }

  const runner = options.runner ?? execFileAsync;
  try {
    await runner(commandSpec.command, commandSpec.args, { timeout: options.timeoutMs ?? 5000, maxBuffer: 1024 * 64 });
    return appendDeliveryAudit(descartesPaths, {
      ts: now,
      status: "delivered",
      channel: config.channel,
      command: [commandSpec.command, ...commandSpec.args.slice(0, 3)],
      payload,
    });
  } catch (error) {
    return appendDeliveryAudit(descartesPaths, {
      ts: now,
      status: "error",
      channel: config.channel,
      error: error instanceof Error ? error.message : String(error),
      payload,
    });
  }
}

export function notificationPlatformNotes(channel) {
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
