import { execFile } from "node:child_process";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import crypto from "node:crypto";
import { atomicWrite, canonicalJson } from "./hash-chain.js";
import { throwIfCollectorAborted } from "./tools/collector-abort.js";

const execFileAsync = promisify(execFile);

export const NOTIFICATION_CHANNELS = new Set(["cli", "macos-desktop", "macos-native", "linux-desktop", "syslog"]);
export const MAX_PENDING_NOTIFICATIONS = 512;
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

/** Stored notices are an outbox record, not an arbitrary notification payload. */
export function isNotificationEntry(entry, section = "pending") {
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
  if (section === "seen" && (!isIsoString(entry.seen_at) || entry.resolution !== "viewed")) return false;
  if (section === "resolved" && (!isIsoString(entry.resolved_at) || typeof entry.resolution !== "string" || entry.resolution.length === 0)) return false;
  return true;
}

export function filterNotificationEntries(entries, section = "pending") {
  const valid = [];
  let skipped = 0;
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (isNotificationEntry(entry, section)) valid.push(entry);
    else skipped += 1;
  }
  return { entries: valid, skipped };
}

// Every outbox read-modify-write (queue, settle, view, attempt bookkeeping, corruption recovery)
// runs under one cooperative lock file, so a writer never acts on a stale read: recovery re-reads
// under the lock before quarantining, and concurrent queues/views never lose each other's notices.
// Cooperative only: a same-UID writer that ignores the lock is out of scope (evidence boundary).
//
// Lock files are created complete (content written to a temp file, then link()ed into place, which
// fails if the lock exists), so a lock is never empty. Liveness is judged from the content a waiter
// observed, never from a re-read. Removing a lock (a holder's release, or breaking a stale one)
// happens only under a second "break" lock and only after re-reading the exact content, so no one
// can remove a lock other than the one they checked: a fresh lock can only be created while none
// exists, and every removal is serialized and verified.
//
// A lock held by a LIVE process is never broken, however old (an unfenced lease would let a paused
// holder resume and overwrite a newer writer). It is stale only when its holder is dead, or when the
// live process at that pid started after the lock was taken (pid reuse; checked with `ps` only once
// a lock is old). A waiter blocked by a live holder fails loudly after a bounded wait instead.
const OUTBOX_LOCK_REUSE_CHECK_MS = 30_000;
const OUTBOX_LOCK_MAX_WAIT_MS = 120_000;
const OUTBOX_LOCK_REUSE_SLACK_MS = 5_000;

function lockHolder(content) {
  try {
    const holder = JSON.parse(content);
    return holder && typeof holder === "object" && !Array.isArray(holder) ? holder : null;
  } catch {
    return null;
  }
}

function lockPidAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

async function readLockContent(lockFile) {
  try {
    return await fs.readFile(lockFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

async function createLockFile(lockFile, content) {
  const tmp = `${lockFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(tmp, content, { mode: 0o600 });
  try {
    await fs.link(tmp, lockFile);
  } finally {
    await fs.unlink(tmp).catch(() => {});
  }
}

function parseElapsedMs(etime) {
  const match = /^\s*(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)\s*$/.exec(String(etime));
  if (!match) return null;
  const [, days = "0", hours = "0", minutes, seconds] = match;
  return (((Number(days) * 24 + Number(hours)) * 60 + Number(minutes)) * 60 + Number(seconds)) * 1000;
}

/** True when the live process now at `pid` started after `atIso` (so it cannot be the lock's holder). */
async function lockPidReused(pid, atIso, { signal } = {}) {
  const at = Date.parse(atIso);
  if (!Number.isFinite(at)) return false;
  try {
    throwIfCollectorAborted(signal);
    const { stdout } = await execFileAsync("ps", ["-o", "etime=", "-p", String(pid)], { timeout: 2000, maxBuffer: 1024 });
    const elapsedMs = parseElapsedMs(stdout);
    if (elapsedMs === null) return false;
    return Date.now() - elapsedMs > at + OUTBOX_LOCK_REUSE_SLACK_MS;
  } catch {
    return false;
  }
}

async function lockIsStale(observed, ageMs) {
  const holder = lockHolder(observed);
  const alive = lockPidAlive(holder?.pid);
  if (alive === false) return true;
  if (alive === true && ageMs > OUTBOX_LOCK_REUSE_CHECK_MS) return lockPidReused(holder.pid, holder.at);
  return false;
}

async function acquireLockFile(lockFile, token, breakStale, { maxWaitMs = OUTBOX_LOCK_MAX_WAIT_MS } = {}) {
  const content = JSON.stringify({ pid: process.pid, token, at: new Date().toISOString() });
  const started = Date.now();
  let delayMs = 2;
  let reuseChecked;
  for (;;) {
    try {
      await createLockFile(lockFile, content);
      return;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    const observed = await readLockContent(lockFile);
    if (observed === undefined) continue;
    let ageMs;
    try {
      ageMs = Date.now() - (await fs.stat(lockFile)).mtimeMs;
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    // The pid-reuse probe spawns `ps`; run it at most once per observed lock.
    const probeReuse = ageMs > OUTBOX_LOCK_REUSE_CHECK_MS && reuseChecked !== observed;
    if (probeReuse) reuseChecked = observed;
    if (lockPidAlive(lockHolder(observed)?.pid) === false || (probeReuse && await lockIsStale(observed, ageMs))) {
      await breakStale(observed);
      continue;
    }
    if (Date.now() - started > maxWaitMs) {
      const holder = lockHolder(observed);
      throw new Error(`notification outbox lock held by live pid ${holder?.pid ?? "unknown"} since ${holder?.at ?? "unknown"}; not breaking it (${lockFile})`);
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    delayMs = Math.min(delayMs * 2, 50);
  }
}

async function removeLockIf(lockFile, predicate) {
  const current = await readLockContent(lockFile);
  if (current !== undefined && predicate(current)) {
    await fs.unlink(lockFile).catch((error) => {
      if (error?.code !== "ENOENT") throw error;
    });
  }
}

// Serializes lock removal. Its own stale break is unserialized (residual: a break lock left by a
// crashed process can be removed concurrently by two breakers; this needs that crash plus a three-way
// race).
async function withOutboxBreakLock(lockFile, fn) {
  const breakFile = `${lockFile}.break`;
  const token = crypto.randomUUID();
  await acquireLockFile(breakFile, token, (observed) => removeLockIf(breakFile, (current) => current === observed));
  try {
    return await fn();
  } finally {
    await removeLockIf(breakFile, (current) => lockHolder(current)?.token === token);
  }
}

async function withOutboxLock(pendingFile, fn, { maxWaitMs } = {}) {
  const lockFile = `${pendingFile}.lock`;
  await ensureParent(lockFile);
  const token = crypto.randomUUID();
  await acquireLockFile(lockFile, token, (observed) => withOutboxBreakLock(lockFile, () => removeLockIf(lockFile, (current) => current === observed)), { maxWaitMs });
  try {
    return await fn();
  } finally {
    await withOutboxBreakLock(lockFile, () => removeLockIf(lockFile, (current) => lockHolder(current)?.token === token));
  }
}

async function parseOutbox(pendingFile) {
  let text;
  try {
    text = await fs.readFile(pendingFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { state: { v: 1, pending: [], seen: [], resolved: [] } };
    return { error };
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed?.v !== 1 || !Array.isArray(parsed.pending) || !Array.isArray(parsed.seen) || !Array.isArray(parsed.resolved)) {
      throw new Error("notification outbox has an invalid schema");
    }
    for (const [section, entries] of [["pending", parsed.pending], ["seen", parsed.seen], ["resolved", parsed.resolved]]) {
      const invalidIndex = entries.findIndex((entry) => !isNotificationEntry(entry, section));
      if (invalidIndex >= 0) throw new Error(`notification outbox has an invalid ${section} entry at index ${invalidIndex}`);
    }
    return { state: { v: 1, pending: parsed.pending, seen: parsed.seen, resolved: parsed.resolved } };
  } catch (error) {
    return { error };
  }
}

function unrecoveredOutbox(message, now) {
  // The integrity notice is surfaced in memory; a writer must quarantine before writing.
  return { v: 1, pending: [outboxIntegrityEntry("corrupt", message, now)], seen: [], resolved: [], tamper: { kind: "notification_outbox_corrupt", message } };
}

/** Must hold the outbox lock. Re-reads; a still-corrupt outbox is quarantined and replaced. */
async function loadOutboxLocked(pendingFile) {
  const now = new Date().toISOString();
  const read = await parseOutbox(pendingFile);
  if (read.state) return read.state;
  let message = read.error?.message ?? String(read.error);
  try {
    try {
      await fs.rename(pendingFile, `${pendingFile}.corrupt-${Date.now()}-${crypto.randomUUID()}`);
    } catch (error) {
      // Keep the durable integrity signal even when the original file cannot be moved.
      if (error?.code !== "ENOENT") message = `${message}; quarantine failed: ${error?.message ?? String(error)}`;
    }
    const fresh = { v: 1, pending: [outboxIntegrityEntry("corrupt", message, now)], seen: [], resolved: [] };
    await atomicWrite(pendingFile, JSON.stringify({ ...fresh, updated_at: now }));
    return { ...fresh, tamper: { kind: "notification_outbox_corrupt", message }, recovered: true };
  } catch (recoveryError) {
    return unrecoveredOutbox(`${message}; recovery failed: ${recoveryError?.message ?? String(recoveryError)}`, now);
  }
}

/**
 * Reads the required-notice outbox. Every entry in pending/seen/resolved must have the full outbox
 * record shape; a parseable-but-malformed outbox is as corrupt as invalid JSON. A corrupt outbox is
 * quarantined (renamed aside, under the outbox lock, after a re-read) and replaced by a fresh valid
 * outbox holding a pending integrity notice, so callers only ever see well-formed entries. This is
 * the one write a read may make.
 */
export async function readPendingNotifications(descartesPaths) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const read = await parseOutbox(pendingFile);
  if (read.state) return read.state;
  try {
    return await withOutboxLock(pendingFile, () => loadOutboxLocked(pendingFile));
  } catch (lockError) {
    return unrecoveredOutbox(`${read.error?.message ?? String(read.error)}; recovery failed: ${lockError?.message ?? String(lockError)}`, new Date().toISOString());
  }
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
  await atomicWrite(pendingFile, JSON.stringify({ v: 1, pending: state.pending, seen: state.seen.slice(-MAX_PENDING_NOTIFICATIONS), resolved: state.resolved.slice(-MAX_PENDING_NOTIFICATIONS), updated_at: now }));
}

export async function queuePendingNotification(descartesPaths, decision, options = {}) {
  if (!options.requiredNoticeId) throw new Error("required notification needs requiredNoticeId");
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return withOutboxLock(pendingFile, async () => {
    let state = await loadOutboxLocked(pendingFile);
    if (state.tamper && !state.recovered) {
      const quarantine = `${pendingFile}.corrupt-${Date.now()}-${crypto.randomUUID()}`;
      await fs.rename(pendingFile, quarantine).catch((error) => {
        if (error?.code !== "ENOENT") throw error;
      });
      state = { v: 1, pending: [outboxIntegrityEntry("corrupt", state.tamper.message, now)], seen: [], resolved: [] };
    }
    const payload = normalizeNotificationPayload(decision, options);
    const id = String(options.requiredNoticeId);
    const existing = state.pending.find((entry) => entry.id === id);
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
      const summary = state.pending.find((candidate) => candidate.id === NOTIFICATION_OUTBOX_OVERFLOW_ID);
      if (state.pending.length < MAX_PENDING_NOTIFICATIONS) {
        state.pending.push(entry);
      } else if (summary) {
        state.pending = state.pending.filter((candidate) => candidate.id !== summary.id).slice(0, MAX_PENDING_NOTIFICATIONS - 1);
        state.pending.push(updateOverflowSummary(summary, 1, now));
      } else {
        const displaced = Math.max(1, state.pending.length - (MAX_PENDING_NOTIFICATIONS - 1));
        state.pending = state.pending.slice(0, MAX_PENDING_NOTIFICATIONS - 1);
        state.pending.push(updateOverflowSummary(undefined, displaced + 1, now));
      }
    }
    await writePendingState(pendingFile, state, now);
    return existing ?? entry;
  }, { maxWaitMs: options.lockWaitMs });
}

async function settlePendingNotification(descartesPaths, id, status, now) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  return withOutboxLock(pendingFile, async () => {
    const state = await loadOutboxLocked(pendingFile);
    if (state.tamper && !state.recovered) throw new Error(`notification outbox corrupt: ${state.tamper.message}`);
    const index = state.pending.findIndex((entry) => entry.id === id);
    if (index < 0) return;
    const [entry] = state.pending.splice(index, 1);
    state.resolved.push({ ...entry, resolved_at: normalizeIso(now, "resolved_at"), resolution: String(status || "resolved") });
    await atomicWrite(pendingFile, JSON.stringify({ v: 1, pending: state.pending, seen: state.seen.slice(-512), resolved: state.resolved.slice(-512), updated_at: now }));
  });
}

export async function resolvePendingNotification(descartesPaths, id, status, now = new Date().toISOString()) {
  return settlePendingNotification(descartesPaths, id, status, now);
}

/** Marks pending notices seen. `ids`, when given, limits this to the notices the caller rendered, so a
 * notice queued after the render stays pending. */
export async function viewPendingNotifications(descartesPaths, { now = new Date().toISOString(), ids } = {}) {
  const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
  return withOutboxLock(pendingFile, async () => {
    const state = await loadOutboxLocked(pendingFile);
    // An unrecovered corrupt outbox is left in place for a writer to quarantine; never overwrite it here.
    if (state.tamper && !state.recovered) return [];
    const shown = ids === undefined ? null : new Set(ids);
    const pending = state.pending.filter((entry) => shown === null || shown.has(entry.id));
    if (pending.length === 0) return [];
    const remaining = state.pending.filter((entry) => !pending.includes(entry));
    const seenAt = normalizeIso(now, "seen_at");
    const viewed = pending.map((entry) => ({ ...entry, seen_at: seenAt, resolution: "viewed" }));
    await atomicWrite(pendingFile, JSON.stringify({ v: 1, pending: remaining, seen: [...state.seen, ...viewed].slice(-512), resolved: state.resolved.slice(-512), updated_at: now }));
    return viewed;
  });
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
  if (options.required === true) await queuePendingNotification(descartesPaths, decision, options);
  const config = options.config ?? await readNotificationDeliveryConfig(descartesPaths);
  const payload = normalizeNotificationPayload(decision, options);
  const append = (record) => appendDeliveryAudit(descartesPaths, record, options);
  const finish = async (record) => {
    if (options.required === true) {
      const delivered = record?.status === "delivered";
      const cliViewed = record?.status === "cli_only" && options.allowCliOnly === true;
      if (delivered || cliViewed) await settlePendingNotification(descartesPaths, options.requiredNoticeId, delivered ? "delivered" : "cli_only", now);
      else {
        const { pendingFile } = resolveNotificationDeliveryPaths(descartesPaths);
        await withOutboxLock(pendingFile, async () => {
          const state = await loadOutboxLocked(pendingFile);
          const entry = state.tamper && !state.recovered ? undefined : state.pending.find((candidate) => candidate.id === options.requiredNoticeId);
          if (!entry) return;
          entry.attempts = (entry.attempts ?? 0) + 1;
          entry.last_status = typeof record?.status === "string" ? record.status : "error";
          await atomicWrite(pendingFile, JSON.stringify({ v: 1, pending: state.pending, seen: state.seen.slice(-512), resolved: state.resolved.slice(-512), updated_at: now }));
        });
      }
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
