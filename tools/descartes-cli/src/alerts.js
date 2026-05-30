import { setTimeout as sleep } from "node:timers/promises";
import {
  readAlertIntelligenceConfig,
  writeAlertIntelligenceConfig,
} from "./alert-intelligence.js";
import { acknowledgeAlert, evaluateAndPersistAlerts, readAlertRecords } from "./alert-store.js";
import { parseDurationMs } from "./history-store.js";
import {
  defaultNotificationChannel,
  notificationPlatformNotes,
  readNotificationDeliveryConfig,
  testNotificationDelivery,
  writeNotificationDeliveryConfig,
} from "./notification-delivery.js";

function alertsUsage() {
  return `Usage:
  descartes alerts list [--json] [--all]
  descartes alerts watch [--json] [--interval <duration>] [--once] [--all]
  descartes alerts ack <alert-id> [--json]
  descartes alerts intelligence status [--json]
  descartes alerts intelligence enable [--json] [--model <MODEL>] [--thinking <LEVEL>] [--max-per-hour <N>]
  descartes alerts intelligence disable [--json]
  descartes alerts notifications status [--json]
  descartes alerts notifications setup [--json] [--channel cli|desktop|macos|native|linux|syslog] [--helper <PATH>]
  descartes alerts notifications test [--json]
  descartes alerts notifications disable [--json]

Lists and acknowledges deterministic local alerts without invoking an LLM.
Alert intelligence is explicit opt-in; when enabled, deterministic alert transitions may wake an LLM to decide whether/how to notify.
Notification delivery is separately opt-in and only sends bounded LLM-authored notification text.`;
}

function parseAlertsArgs(args) {
  const [subcommand, ...rest] = args;
  if (!subcommand || subcommand === "--help" || subcommand === "-h") return { subcommand: "help" };
  if (!["list", "watch", "ack", "intelligence", "notifications"].includes(subcommand)) throw new Error(`Unsupported alerts command: ${subcommand}\n\n${alertsUsage()}`);
  const options = { subcommand, json: false, all: false, intervalMs: 5000, once: false };
  if (subcommand === "intelligence") {
    options.intelligenceCommand = rest.shift() ?? "status";
    if (!["status", "enable", "disable"].includes(options.intelligenceCommand)) throw new Error(`Unsupported alerts intelligence command: ${options.intelligenceCommand}\n\n${alertsUsage()}`);
  }
  if (subcommand === "notifications") {
    options.notificationsCommand = rest.shift() ?? "status";
    if (!["status", "setup", "test", "disable"].includes(options.notificationsCommand)) throw new Error(`Unsupported alerts notifications command: ${options.notificationsCommand}\n\n${alertsUsage()}`);
  }
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--json") options.json = true;
    else if (arg === "--all") options.all = true;
    else if (arg === "--once") options.once = true;
    else if (arg === "--model") {
      const value = rest[index + 1];
      if (!value) throw new Error("--model requires a value");
      options.modelPattern = value;
      index += 1;
    } else if (arg === "--thinking") {
      const value = rest[index + 1];
      if (!value) throw new Error("--thinking requires a value");
      options.thinkingLevel = value;
      index += 1;
    } else if (arg === "--max-per-hour") {
      const value = Number(rest[index + 1]);
      if (!Number.isFinite(value) || value < 0) throw new Error("--max-per-hour requires a non-negative number");
      options.maxCallsPerHour = Math.floor(value);
      index += 1;
    } else if (arg === "--interval") {
      const value = rest[index + 1];
      if (!value) throw new Error("--interval requires a value");
      options.intervalMs = parseDurationMs(value, options.intervalMs);
      index += 1;
    } else if (arg === "--channel") {
      const value = rest[index + 1];
      if (!value) throw new Error("--channel requires a value");
      options.notificationChannel = value;
      index += 1;
    } else if (arg === "--helper") {
      const value = rest[index + 1];
      if (!value) throw new Error("--helper requires a value");
      options.notificationHelper = value;
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (subcommand === "ack" && !options.alertId) {
      options.alertId = arg;
    } else {
      throw new Error(`Unexpected alerts ${subcommand} argument: ${arg}\n\n${alertsUsage()}`);
    }
  }
  if (subcommand === "ack" && !options.alertId && !options.help) throw new Error(`alerts ack requires an alert id\n\n${alertsUsage()}`);
  if (subcommand !== "watch" && options.once) throw new Error(`--once is only supported for alerts watch\n\n${alertsUsage()}`);
  if (subcommand !== "intelligence" && (options.modelPattern || options.thinkingLevel || options.maxCallsPerHour !== undefined)) throw new Error(`Alert intelligence options require 'descartes alerts intelligence enable'\n\n${alertsUsage()}`);
  if (subcommand === "intelligence" && options.intelligenceCommand !== "enable" && (options.modelPattern || options.thinkingLevel || options.maxCallsPerHour !== undefined)) throw new Error(`Alert intelligence model/rate options are only supported with enable\n\n${alertsUsage()}`);
  if (subcommand !== "notifications" && (options.notificationChannel || options.notificationHelper)) throw new Error(`Notification options require 'descartes alerts notifications setup'\n\n${alertsUsage()}`);
  if (subcommand === "notifications" && options.notificationsCommand !== "setup" && (options.notificationChannel || options.notificationHelper)) throw new Error(`Notification setup options are only supported with setup\n\n${alertsUsage()}`);
  if (!Number.isFinite(options.intervalMs) || options.intervalMs < 1000) throw new Error("Alert watch interval must be at least 1s");
  return options;
}

const severityRank = { critical: 0, warning: 1, info: 2 };
const activeStatuses = new Set(["active", "acknowledged", "suppressed"]);

function sortAlerts(alerts) {
  return [...alerts].sort((left, right) => {
    const statusLeft = activeStatuses.has(left.status) ? 0 : 1;
    const statusRight = activeStatuses.has(right.status) ? 0 : 1;
    if (statusLeft !== statusRight) return statusLeft - statusRight;
    if ((severityRank[left.severity] ?? 9) !== (severityRank[right.severity] ?? 9)) return (severityRank[left.severity] ?? 9) - (severityRank[right.severity] ?? 9);
    return right.last_seen.localeCompare(left.last_seen);
  });
}

export function visibleAlerts(alerts, options = {}) {
  return sortAlerts(alerts.filter((alert) => options.all || activeStatuses.has(alert.status)));
}

export function renderAlertList(alerts, options = {}) {
  const shown = visibleAlerts(alerts, options);
  if (shown.length === 0) return options.all ? "No alert records." : "No active alerts.";
  const lines = [`Alerts (${shown.length}${options.all ? " total" : " active"})`];
  for (const alert of shown) {
    lines.push(`- ${alert.id} [${alert.severity}/${alert.status}] ${alert.title}`);
    if (alert.summary) lines.push(`  ${alert.summary}`);
    lines.push(`  first_seen=${alert.first_seen} last_seen=${alert.last_seen}`);
    if (alert.acknowledged_at) lines.push(`  acknowledged_at=${alert.acknowledged_at}`);
  }
  return lines.join("\n");
}

function jsonAlertPayload(alerts, options = {}) {
  return { alerts: visibleAlerts(alerts, options) };
}

function renderAlertIntelligenceStatus(config) {
  const lines = [`Alert intelligence: ${config.enabled ? "enabled" : "disabled"}`];
  lines.push(`Max LLM wakeups/hour: ${config.max_calls_per_hour}`);
  if (config.model_pattern) lines.push(`Model override: ${config.model_pattern}`);
  if (config.thinking_level) lines.push(`Thinking override: ${config.thinking_level}`);
  lines.push("No remediation/action tools are available to alert intelligence sessions.");
  return lines.join("\n");
}

function expandNotificationChannel(channel, runtime = {}) {
  const normalized = String(channel ?? "desktop").toLowerCase();
  if (normalized === "desktop") return defaultNotificationChannel(runtime.platform, runtime.env);
  if (normalized === "macos") return "macos-desktop";
  if (normalized === "native") return "macos-native";
  if (normalized === "linux") return "linux-desktop";
  return normalized;
}

function renderNotificationDeliveryStatus(config) {
  const lines = [`Notification delivery: ${config.enabled ? "enabled" : "disabled"}`];
  lines.push(`Channel: ${config.channel}`);
  if (config.macos_native_helper_path) lines.push(`Native macOS helper: ${config.macos_native_helper_path}`);
  lines.push(notificationPlatformNotes(config.channel));
  if (config.enabled) lines.push("Notifications deliver bounded LLM alert decisions only; no raw alert dumps or remediation actions are sent.");
  else lines.push("Run `descartes alerts notifications setup` and then `descartes alerts notifications test` to opt in and trigger any platform permission prompt.");
  return lines.join("\n");
}

export async function runAlerts(descartesPaths, args, runtime = {}) {
  const options = parseAlertsArgs(args);
  const output = runtime.output ?? console.log;
  const sleeper = runtime.sleep ?? sleep;
  const shouldStop = runtime.shouldStop ?? (() => false);
  if (options.subcommand === "help" || options.help) {
    output(alertsUsage());
    return;
  }

  if (options.subcommand === "intelligence") {
    const existing = await readAlertIntelligenceConfig(descartesPaths);
    let config = existing;
    if (options.intelligenceCommand === "enable") {
      config = await writeAlertIntelligenceConfig(descartesPaths, {
        ...existing,
        enabled: true,
        model_pattern: options.modelPattern ?? existing.model_pattern,
        thinking_level: options.thinkingLevel ?? existing.thinking_level,
        max_calls_per_hour: options.maxCallsPerHour ?? existing.max_calls_per_hour,
      });
    } else if (options.intelligenceCommand === "disable") {
      config = await writeAlertIntelligenceConfig(descartesPaths, { ...existing, enabled: false });
    }
    if (options.json) output(JSON.stringify({ alert_intelligence: config }, null, 2));
    else output(renderAlertIntelligenceStatus(config));
    return;
  }

  if (options.subcommand === "notifications") {
    const existing = await readNotificationDeliveryConfig(descartesPaths);
    let config = existing;
    let delivery;
    if (options.notificationsCommand === "setup") {
      config = await writeNotificationDeliveryConfig(descartesPaths, {
        enabled: true,
        channel: expandNotificationChannel(options.notificationChannel, runtime),
        macos_native_helper_path: options.notificationHelper ?? existing.macos_native_helper_path,
      });
    } else if (options.notificationsCommand === "disable") {
      config = await writeNotificationDeliveryConfig(descartesPaths, { ...existing, enabled: false });
    } else if (options.notificationsCommand === "test") {
      delivery = await testNotificationDelivery(descartesPaths, { config, platform: runtime.platform, env: runtime.env, runner: runtime.runner });
    }
    if (options.json) output(JSON.stringify({ notifications: config, delivery }, null, 2));
    else {
      const lines = [renderNotificationDeliveryStatus(config)];
      if (delivery) lines.push(`Test delivery: ${delivery.status}${delivery.reason ? ` (${delivery.reason})` : ""}`);
      output(lines.join("\n"));
    }
    return;
  }

  if (options.subcommand === "ack") {
    const alert = await acknowledgeAlert(descartesPaths, options.alertId);
    if (options.json) output(JSON.stringify({ alert }, null, 2));
    else output(`Acknowledged ${alert.id}: ${alert.title}`);
    return;
  }

  const printList = async () => {
    const result = await evaluateAndPersistAlerts(descartesPaths);
    if (options.json) output(JSON.stringify({ ...jsonAlertPayload(result.alerts, options), notification_due_ids: result.notification_due_ids }, null, 2));
    else output(renderAlertList(result.alerts, options));
  };

  if (options.subcommand === "list") {
    await printList();
    return;
  }

  do {
    await printList();
    if (options.once || shouldStop()) break;
    await sleeper(options.intervalMs, undefined, { ref: true });
  } while (!shouldStop());
}

export { readAlertRecords };
