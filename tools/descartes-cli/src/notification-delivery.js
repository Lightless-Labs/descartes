import { execFile } from "node:child_process";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import crypto from "node:crypto";
import { atomicWrite, canonicalJson } from "./hash-chain.js";

const execFileAsync = promisify(execFile);

export const NOTIFICATION_CHANNELS = new Set(["cli", "macos-desktop", "macos-native", "linux-desktop", "syslog"]);
export const MAX_PENDING_NOTIFICATIONS = 512;
export const MAX_RETAINED_NOTIFICATION_NOTICES = 50;
export const NOTIFICATION_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
export const NOTIFICATION_RETRY_BASE_MS = 60_000;
export const NOTIFICATION_RETRY_CAP_MS = 60 * 60 * 1000;
export const NOTIFICATION_OUTBOX_INTEGRITY_RULE_ID = "integrity.notification_outbox";
const NOTIFICATION_OUTBOX_OVERFLOW_ID = `${NOTIFICATION_OUTBOX_INTEGRITY_RULE_ID}:overflow`;
const NOTIFICATION_OUTBOX_CORRUPT_ID = `${NOTIFICATION_OUTBOX_INTEGRITY_RULE_ID}:corrupt`;

export function resolveNotificationDeliveryPaths(descartesPaths) {
  const alertsDir = path.join(descartesPaths.stateDir, "alerts");
  return {
    configFile: path.join(descartesPaths.configDir, "notifications.json"),
    auditDir: alertsDir,
    auditFile: path.join(alertsDir, "notification-delivery.jsonl"),
    pendingFile: path.join(alertsDir, "notification-pending.json"),
  };
}

function isIsoString(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

/** Stored notices are retained delivery records, not arbitrary notification payloads. */
export function isNotificationEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  if (typeof entry.id !== "string" || entry.id.length === 0) return false;
  if (typeof entry.digest !== "string" || entry.digest.length === 0) return false;
  if (!(typeof entry.rule_id === "string" || entry.rule_id === null)) return false;
  if (!isIsoString(entry.first_seen_at)) return false;
  if (!(entry.severity === "info" || entry.severity === "warning" || entry.severity === "critical")) return false;
  if (typeof entry.title !== "string" || typeof entry.body !== "string") return false;
  if (!Number.isSafeInteger(entry.attempts) || entry.attempts < 0) return false;
  if (!(entry.last_status === null || typeof entry.last_status === "string")) return false;
  if (entry.notices_overflowed !== undefined && (!Number.isSafeInteger(entry.notices_overflowed) || entry.notices_overflowed < 0)) return false;
  if (entry.corruption !== undefined && typeof entry.corruption !== "string") return false;
  if (entry.delivered_at !== undefined && !isIsoString(entry.delivered_at)) return false;
  if (entry.last_attempt_at !== undefined && !isIsoString(entry.last_attempt_at)) return false;
  if (entry.next_attempt_at !== undefined && !isIsoString(entry.next_attempt_at)) return false;
  return true;
}

export function filterNotificationEntries(entries) {
  const valid = [];
  let skipped = 0;
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (isNotificationEntry(entry)) valid.push(entry);
    else skipped += 1;
  }
  return { entries: valid, skipped };
}

async function parseOutbox(pendingFile) {
  let text;
  try {
    text = await fs.readFile(pendingFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { state: { v: 2, notices: [] } };
    return { kind: "io", error };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { kind: "corrupt", error, salvaged: salvageNotificationEntries(text) };
  }
  const validShape = parsed?.v === 2 && Array.isArray(parsed.notices)
    && Object.keys(parsed).every((key) => ["v", "notices", "updated_at"].includes(key));
  const notices = Array.isArray(parsed?.notices) ? parsed.notices : [];
  const invalidIndex = notices.findIndex((entry) => !isNotificationEntry(entry));
  if (!validShape || invalidIndex >= 0) {
    const message = !validShape
      ? "notification outbox has an invalid schema"
      : `notification outbox has an invalid notice at index ${invalidIndex}`;
    return { kind: "corrupt", error: new Error(message), salvaged: notices.filter(isNotificationEntry) };
  }
  return { state: { v: 2, notices } };
}

function scanJsonValues(text) {
  const values = [];
  for (let start = 0; start < text.length; start += 1) {
    if (text[start] !== "{") continue;
    const stack = [];
    let inString = false;
    let escaped = false;
    for (let index = start; index < text.length; index += 1) {
      const character = text[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') {
        inString = true;
        continue;
      }
      if (character === "{" || character === "[") stack.push(character);
      else if (character === "}" || character === "]") {
        const expected = character === "}" ? "{" : "[";
        if (stack.at(-1) !== expected) break;
        stack.pop();
        if (stack.length === 0) {
          try { values.push(JSON.parse(text.slice(start, index + 1))); } catch { /* not a complete value */ }
          break;
        }
      }
    }
  }
  return values;
}

function salvageNotificationEntries(text) {
  const candidates = [];
  for (const value of scanJsonValues(text)) {
    if (isNotificationEntry(value)) candidates.push(value);
    for (const entry of value?.notices ?? []) if (isNotificationEntry(entry)) candidates.push(entry);
  }
  const unique = new Map();
  for (const entry of candidates) unique.set(entry.id, entry);
  return [...unique.values()];
}

function publicOutboxState(notices, extras = {}) {
  const valid = filterNotificationEntries(notices).entries;
  const pending = valid.filter((entry) => !["delivered", "cli_only", "skipped"].includes(entry.last_status));
  return { v: 2, notices: valid, pending, ...extras };
}

function outboxErrorState(error) {
  return publicOutboxState([], { outbox_error: { code: error?.code, message: error?.message ?? String(error) } });
}

/** The daemon re-reads, quarantines, and replaces a corrupt outbox. */
export async function recoverNotificationOutbox(descartesPaths) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const now = new Date().toISOString();
  const read = await parseOutbox(pendingFile);
  if (read.state) return publicOutboxState(read.state.notices);
  if (read.kind === "io") return outboxErrorState(read.error);
  let message = read.error?.message ?? String(read.error);
  try {
    try {
      await fs.rename(pendingFile, `${pendingFile}.corrupt-${Date.now()}-${crypto.randomUUID()}`);
    } catch (error) {
      // Keep the durable integrity signal even when the original file cannot be moved.
      if (error?.code !== "ENOENT") message = `${message}; quarantine failed: ${error?.message ?? String(error)}`;
    }
    const salvaged = filterNotificationEntries(read.salvaged).entries;
    const fresh = { v: 2, notices: [outboxIntegrityEntry("corrupt", message, now), ...salvaged.filter((entry) => entry.id !== NOTIFICATION_OUTBOX_CORRUPT_ID)] };
    await atomicWrite(pendingFile, JSON.stringify({ ...fresh, updated_at: now }));
    return publicOutboxState(fresh.notices, { tamper: { kind: "notification_outbox_corrupt", message }, recovered: true });
  } catch (recoveryError) {
    return publicOutboxState([outboxIntegrityEntry("corrupt", `${message}; recovery failed: ${recoveryError?.message ?? String(recoveryError)}`, now)], { tamper: { kind: "notification_outbox_corrupt", message } });
  }
}

/**
 * Reads the required-notice outbox. A parseable-but-malformed outbox is corruption; filesystem
 * failures are not. This function never writes, renames, or quarantines.
 */
export async function readPendingNotifications(descartesPaths) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const read = await parseOutbox(pendingFile);
  if (read.state) return publicOutboxState(read.state.notices);
  if (read.kind === "io") return outboxErrorState(read.error);
  const message = read.error?.message ?? String(read.error);
  return publicOutboxState([outboxIntegrityEntry("corrupt", message, new Date().toISOString())], { tamper: { kind: "notification_outbox_corrupt", message } });
}

function pendingNoticeDigest(decision, options = {}) {
  return crypto.createHash("sha256").update(canonicalJson({ id: options.requiredNoticeId, rule_id: options.ruleId, payload: normalizeNotificationPayload(decision, options) })).digest("hex");
}

function outboxIntegrityEntry(kind, message, now) {
  const decision = kind === "overflow"
    ? { notify: true, severity: "critical", title: "Descartes: required notification outbox overflowed", body: "Required notifications overflowed; unresolved notices are represented by this counted summary." }
    : { notify: true, severity: "critical", title: "Descartes: required notification outbox corrupt", body: `The required notification outbox was corrupt (${message}); its contents were quarantined and this integrity notice remains pending.` };
  return {
    id: kind === "overflow" ? NOTIFICATION_OUTBOX_OVERFLOW_ID : NOTIFICATION_OUTBOX_CORRUPT_ID,
    digest: pendingNoticeDigest(decision, { requiredNoticeId: kind === "overflow" ? NOTIFICATION_OUTBOX_OVERFLOW_ID : NOTIFICATION_OUTBOX_CORRUPT_ID, ruleId: NOTIFICATION_OUTBOX_INTEGRITY_RULE_ID }),
    rule_id: NOTIFICATION_OUTBOX_INTEGRITY_RULE_ID,
    first_seen_at: now,
    severity: decision.severity,
    title: decision.title,
    body: decision.body,
    attempts: 0,
    last_status: null,
    ...(kind === "overflow" ? { notices_overflowed: 0 } : { corruption: message }),
  };
}

function updateOverflowSummary(existing, count, now) {
  const summary = existing ?? outboxIntegrityEntry("overflow", "", now);
  const noticesOverflowed = (summary.notices_overflowed ?? 0) + count;
  return {
    ...summary,
    notices_overflowed: noticesOverflowed,
    body: `Required notification outbox overflowed; ${noticesOverflowed} unresolved notice${noticesOverflowed === 1 ? "" : "s"} are represented by this counted summary.`,
  };
}

async function writePendingState(pendingFile, state, now) {
  await atomicWrite(pendingFile, JSON.stringify({ v: 2, notices: state.notices, updated_at: now }));
}

export async function queuePendingNotification(descartesPaths, decision, options = {}) {
  if (!options.requiredNoticeId) throw new Error("required notification needs requiredNoticeId");
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  await ensureParent(pendingFile);
  const state = await recoverNotificationOutbox(descartesPaths);
  if (state.outbox_error) throw Object.assign(new Error(state.outbox_error.message), { code: state.outbox_error.code });
  const payload = normalizeNotificationPayload(decision, options);
  const id = String(options.requiredNoticeId);
  const existing = state.notices.find((entry) => entry.id === id);
  const entry = existing ?? {
    id,
    digest: pendingNoticeDigest(decision, options),
    rule_id: options.ruleId === undefined || options.ruleId === null ? null : String(options.ruleId),
    first_seen_at: now,
    severity: payload.severity,
    title: payload.title,
    body: payload.body,
    attempts: 0,
    last_status: null,
  };
  if (!existing) {
    const summary = state.notices.find((candidate) => candidate.id === NOTIFICATION_OUTBOX_OVERFLOW_ID);
    if (state.notices.length < MAX_PENDING_NOTIFICATIONS) {
      state.notices.push(entry);
    } else if (summary) {
      state.notices = state.notices.filter((candidate) => candidate.id !== summary.id).slice(0, MAX_PENDING_NOTIFICATIONS - 1);
      state.notices.push(updateOverflowSummary(summary, 1, now));
    } else {
      const displaced = Math.max(1, state.notices.length - (MAX_PENDING_NOTIFICATIONS - 1));
      state.notices = state.notices.slice(0, MAX_PENDING_NOTIFICATIONS - 1);
      state.notices.push(updateOverflowSummary(undefined, displaced + 1, now));
    }
  }
  await writePendingState(pendingFile, { notices: state.notices }, now);
  return existing ?? entry;
}

async function settlePendingNotification(descartesPaths, id, status, now) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const state = await recoverNotificationOutbox(descartesPaths);
  if (state.outbox_error) throw Object.assign(new Error(state.outbox_error.message), { code: state.outbox_error.code });
  const index = state.notices.findIndex((entry) => entry.id === id);
  if (index < 0) return;
  const entry = state.notices[index];
  const at = normalizeIso(now, "delivery timestamp");
  const delivered = status === "delivered" || status === "cli_only";
  state.notices[index] = {
    ...entry,
    last_status: String(status || "delivered"),
    ...(delivered ? { delivered_at: entry.delivered_at ?? at, next_attempt_at: undefined } : {}),
  };
  await writePendingState(pendingFile, { notices: state.notices }, at);
}

export async function resolvePendingNotification(descartesPaths, id, status, now = new Date().toISOString()) {
  return settlePendingNotification(descartesPaths, id, status, now);
}

async function recordNotificationFailure(descartesPaths, id, status, now) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const state = await recoverNotificationOutbox(descartesPaths);
  if (state.outbox_error) throw Object.assign(new Error(state.outbox_error.message), { code: state.outbox_error.code });
  const index = state.notices.findIndex((entry) => entry.id === id);
  if (index < 0) return;
  const entry = state.notices[index];
  const attempts = (entry.attempts ?? 0) + 1;
  const delay = Math.min(NOTIFICATION_RETRY_CAP_MS, NOTIFICATION_RETRY_BASE_MS * (2 ** Math.min(attempts - 1, 16)));
  const at = normalizeIso(now, "attempt timestamp");
  state.notices[index] = {
    ...entry,
    attempts,
    last_status: typeof status === "string" ? status : "error",
    last_attempt_at: at,
    next_attempt_at: new Date(Date.parse(at) + delay).toISOString(),
  };
  await writePendingState(pendingFile, { notices: state.notices }, at);
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

function noticeDelivered(entry) {
  return entry?.last_status === "delivered" || entry?.last_status === "cli_only";
}

function noticeAttemptDue(entry, nowMs) {
  if (noticeDelivered(entry)) return false;
  const nextAttemptMs = Date.parse(entry?.next_attempt_at ?? "");
  return !Number.isFinite(nextAttemptMs) || nextAttemptMs <= nowMs;
}

/**
 * Daemon-owned retry pass for every retained required notice that is due. Producers may enqueue
 * notices through the normal delivery path, but retry ownership stays here so a failed producer
 * cannot make an integrity or overflow notice disappear between ticks.
 */
export async function drainDueNotificationOutbox(descartesPaths, options = {}) {
  const { now: rawNow = new Date().toISOString(), deliverNotification, ...deliveryOptions } = options;
  const now = normalizeIso(rawNow, "now");
  const recovered = await recoverNotificationOutbox(descartesPaths);
  if (recovered.outbox_error) return { status: "warning", error: recovered.outbox_error, attempted: 0, delivered: 0, failed: 0 };
  const due = recovered.notices.filter((entry) => noticeAttemptDue(entry, Date.parse(now)));
  const delivery = deliverNotification ?? deliverNotificationDecision;
  const usesNormalPath = delivery === deliverNotificationDecision;
  let delivered = 0;
  let failed = 0;
  for (const entry of due) {
    const decision = { notify: true, severity: entry.severity, title: entry.title, body: entry.body };
    const attemptOptions = {
      ...deliveryOptions,
      now,
      required: true,
      requiredNoticeId: entry.id,
      ruleId: entry.rule_id,
    };
    let result;
    try {
      result = await delivery(descartesPaths, decision, attemptOptions);
    } catch (error) {
      result = { status: "error", error: error instanceof Error ? error.message : String(error) };
      try {
        await recordNotificationFailure(descartesPaths, entry.id, result.status, now);
      } catch {
        // Preserve the original drain failure; the next daemon tick will retry the retained entry.
      }
    }
    const reachedOperator = result?.status === "delivered" || result?.status === "cli_only";
    if (reachedOperator) delivered += 1;
    else failed += 1;
    // The production delivery function records its own result. Injected delivery seams do not,
    // so the daemon records their outcome here while keeping focused tests deterministic.
    if (!usesNormalPath) {
      try {
        if (reachedOperator) await settlePendingNotification(descartesPaths, entry.id, result.status, now);
        else await recordNotificationFailure(descartesPaths, entry.id, result?.status ?? "error", now);
      } catch {
        // A later tick can retry if the outbox itself became unavailable while recording this one.
      }
    }
  }
  return { status: failed > 0 ? "warning" : "ok", attempted: due.length, delivered, failed };
}

/** Selects the read-only operator view. It never changes the outbox. */
export function selectNotificationNoticeWindow(state, { now = new Date().toISOString() } = {}) {
  const nowMs = Date.parse(normalizeIso(now, "now"));
  const cutoffMs = nowMs - NOTIFICATION_RETENTION_MS;
  const source = filterNotificationEntries(state?.notices ?? state?.pending ?? state).entries;
  const overflowed = source.reduce((sum, entry) => sum + (entry.id === NOTIFICATION_OUTBOX_OVERFLOW_ID ? (entry.notices_overflowed ?? 0) : 0), 0);
  const summary = source.find((entry) => entry.id === NOTIFICATION_OUTBOX_OVERFLOW_ID);
  const recent = source
    .filter((entry) => entry.id !== NOTIFICATION_OUTBOX_OVERFLOW_ID)
    .filter((entry) => {
      const firstSeenMs = Date.parse(entry.first_seen_at);
      return entry.rule_id === NOTIFICATION_OUTBOX_INTEGRITY_RULE_ID
        || (Number.isFinite(firstSeenMs) && firstSeenMs >= cutoffMs && firstSeenMs <= nowMs);
    })
    .sort((left, right) => right.first_seen_at.localeCompare(left.first_seen_at) || right.id.localeCompare(left.id));
  const entries = [...recent.slice(0, MAX_RETAINED_NOTIFICATION_NOTICES), ...(summary ? [summary] : [])];
  const older_count = Math.max(0, recent.length - MAX_RETAINED_NOTIFICATION_NOTICES)
    + source.filter((entry) => entry.id !== NOTIFICATION_OUTBOX_OVERFLOW_ID && Date.parse(entry.first_seen_at) < cutoffMs).length
    + overflowed;
  return {
    entries,
    older_count,
    overflowed_count: overflowed,
    pending_count: entries.filter((entry) => !noticeDelivered(entry)).length,
  };
}

/** Daemon-only time/count retention. CLI reads never call this function. */
export async function retainNotificationOutbox(descartesPaths, { now = new Date().toISOString() } = {}) {
  const normalizedNow = normalizeIso(now, "now");
  const state = await recoverNotificationOutbox(descartesPaths);
  if (state.outbox_error) return { status: "warning", outbox_error: state.outbox_error };
  const nowMs = Date.parse(normalizedNow);
  const cutoffMs = nowMs - NOTIFICATION_RETENTION_MS;
  const summary = state.notices.find((entry) => entry.id === NOTIFICATION_OUTBOX_OVERFLOW_ID);
  const candidates = state.notices.filter((entry) => entry.id !== NOTIFICATION_OUTBOX_OVERFLOW_ID);
  const kept = candidates
    .filter((entry) => {
      const firstSeenMs = Date.parse(entry.first_seen_at);
      return firstSeenMs >= cutoffMs && firstSeenMs <= nowMs;
    })
    .sort((left, right) => right.first_seen_at.localeCompare(left.first_seen_at) || right.id.localeCompare(left.id))
    .slice(0, MAX_RETAINED_NOTIFICATION_NOTICES);
  const keptIds = new Set(kept.map((entry) => entry.id));
  const dropped = candidates.filter((entry) => !keptIds.has(entry.id));
  const droppedCount = dropped.length + dropped.reduce((sum, entry) => sum + (entry.notices_overflowed ?? 0), 0);
  const nextSummary = droppedCount > 0 ? updateOverflowSummary(summary, droppedCount, normalizedNow) : summary;
  const notices = [...kept, ...(nextSummary ? [nextSummary] : [])];
  const changed = notices.length !== state.notices.length || notices.some((entry, index) => entry.id !== state.notices[index]?.id || JSON.stringify(entry) !== JSON.stringify(state.notices[index]));
  if (changed) {
    const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
    await writePendingState(pendingFile, { notices }, normalizedNow);
  }
  return { status: "ok", retained: kept.length, dropped: droppedCount, overflowed: nextSummary?.notices_overflowed ?? 0 };
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
  let queued;
  if (options.required === true) {
    queued = await queuePendingNotification(descartesPaths, decision, options);
    if (!noticeAttemptDue(queued, Date.parse(now))) {
      return { status: noticeDelivered(queued) ? queued.last_status : "retry_pending", retry_after: queued.next_attempt_at };
    }
  }
  const config = options.config ?? await readNotificationDeliveryConfig(descartesPaths);
  const payload = normalizeNotificationPayload(decision, options);
  const append = (record) => appendDeliveryAudit(descartesPaths, record, options);
  const finish = async (record) => {
    if (options.required === true) {
      const delivered = record?.status === "delivered" || record?.status === "cli_only";
      if (delivered) await settlePendingNotification(descartesPaths, options.requiredNoticeId, record.status, now);
      else await recordNotificationFailure(descartesPaths, options.requiredNoticeId, record?.status, now);
    }
    return record;
  };
  if (decision?.notify !== true) {
    return finish(await append({ ts: now, status: "skipped", reason: "notify_false", channel: config.channel, payload }));
  }
  if (!config.enabled) {
    return finish(await append({ ts: now, status: "disabled", channel: config.channel, payload }));
  }
  const commandSpec = commandForPayload(config.channel, payload, { ...options, config });
  if (!commandSpec) {
    return finish(await append({ ts: now, status: "cli_only", channel: config.channel, payload }));
  }
  if (commandSpec.unavailable) {
    return finish(await append({ ts: now, status: "unavailable", channel: config.channel, reason: commandSpec.unavailable, payload }));
  }

  const runner = options.runner ?? execFileAsync;
  try {
    await runner(commandSpec.command, commandSpec.args, { timeout: options.timeoutMs ?? 5000, maxBuffer: 1024 * 64 });
    return finish(await append({
      ts: now,
      status: "delivered",
      channel: config.channel,
      command: [commandSpec.command, ...commandSpec.args.slice(0, 3)],
      payload,
    }));
  } catch (error) {
    // `open`-launched delivery (best_effort_status): `open` returns a nonzero exit code even on a
    // successful LaunchServices launch, so a NUMERIC-exit rejection is NOT a delivery failure — the
    // notification was launched, we just can't observe the accessory helper's own exit status
    // (accurate post-time status would need the helper to write a result file, a signed-release
    // follow-up). Only a spawn failure (`open` itself unrunnable — a string `error.code` like ENOENT)
    // or a timeout/kill is a real error.
    if (commandSpec.best_effort_status && typeof error?.code === "number") {
      return finish(await append({
        ts: now,
        status: "delivered",
        delivery_confidence: "best_effort",
        channel: config.channel,
        command: [commandSpec.command, ...commandSpec.args.slice(0, 3)],
        payload,
      }));
    }
    return finish(await append({
      ts: now,
      status: "error",
      channel: config.channel,
      error: error instanceof Error ? error.message : String(error),
      payload,
    }));
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
