import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { buildHistorySummary, readDaemonStatus } from "./history-store.js";

export const DEFAULT_ALERT_COOLDOWN_MS = 15 * 60 * 1000;
export const DEFAULT_ALERT_WINDOW_MS = 15 * 60 * 1000;
export const DELIVERY_BACKOFF_BASE_MS = 60_000;
export const DELIVERY_BACKOFF_CAP_MS = 60 * 60 * 1000;

// Retained as a compatibility export for the historical alert-config constraint and callers that
// import the old symbol. Alert delivery no longer uses this value: episode state below is the only
// notification policy for ordinary alerts. The budget_exhausted meta-signal keeps its own one-hour
// delivery window in alert-intelligence.js.

export function resolveAlertStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "alerts");
  return {
    dir,
    alertsFile: path.join(dir, "alerts.json"),
  };
}

async function ensureAlertDir(descartesPaths) {
  await fs.mkdir(resolveAlertStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, fieldName = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid alert ${fieldName}: ${ts}`);
  return date.toISOString();
}

export function alertId(ruleId, fingerprint = "global") {
  const digest = crypto.createHash("sha256").update(`${ruleId}\0${fingerprint}`).digest("hex").slice(0, 16);
  return `alert_${digest}`;
}

function metricByName(summary) {
  return new Map((summary?.metrics ?? []).map((metric) => [metric.metric_name, metric]));
}

function newestMetricTimestamp(summary) {
  const timestamps = (summary?.metrics ?? [])
    .map((metric) => new Date(metric.last_ts).getTime())
    .filter(Number.isFinite);
  return timestamps.length > 0 ? Math.max(...timestamps) : undefined;
}

function formatPercent(value) {
  return `${(Number(value) * 100).toFixed(0)}%`;
}

function pushCandidate(candidates, candidate) {
  const fingerprint = candidate.fingerprint ?? "global";
  candidates.push({
    id: alertId(candidate.rule_id, fingerprint),
    fingerprint,
    evidence_refs: ["history-summary"],
    ...candidate,
  });
}

function normalizeIncidentKey(value) {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (!text) return null;
  if (/^[A-Za-z0-9._:-]{1,128}$/.test(text)) return text;
  return `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;
}

function normalizeIncidentKeyList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(normalizeIncidentKey).filter(Boolean))].slice(-256);
}

export function alertEpisodeKey(alertOrCandidate = {}) {
  return normalizeIncidentKey(alertOrCandidate.current_incident_key ?? alertOrCandidate.incident_key) ?? "default";
}

// The complete, static set of rule_ids evaluateAlertRules() can ever produce. Used to scope
// applyAlertCandidates' recovery eligibility (see coveredAlertIds below) for callers — like the
// CLI's read-only alerts list/watch view — that only ever compute THIS subset of candidates and
// must never be treated as authoritative over a detector family (canary.*, credential.access,
// session.*, peer.*, service.*, provenance.*, correlation.*, scheduled_job.*, service_appearance.*,
// containment.*, learned.*) they did not themselves evaluate this call. Keep in sync with the
// rule_id literals pushed inside evaluateAlertRules below.
export const FIXED_ALERT_RULE_IDS = new Set([
  "daemon.status.missing",
  "daemon.status.not_ok",
  "daemon.samples.missing",
  "daemon.samples.stale",
  "daemon.status.stale",
  "system.memory.sustained_high",
  "system.load.sustained_high",
  "disk.space.high_used_fraction",
]);

// Detector-reported recovery coverage (§8.A): coverage is now keyed on alert IDENTITY
// (alertId(rule_id, fingerprint)), not rule_id, so a caller can authorize recovery per persisted
// alert rather than per family. Every fixed rule pushes its candidate with the default "global"
// fingerprint (pushCandidate above), so its identity is alertId(ruleId) — this helper is the
// identity-keyed analog of "the fixed rules I have full visibility into", handed to
// coveredAlertIds by the CLI read-only path and folded into the daemon's per-tick covered set.
export function fixedAlertIds() {
  return new Set([...FIXED_ALERT_RULE_IDS].map((ruleId) => alertId(ruleId)));
}

export function evaluateAlertRules(historySummary, daemonStatus, options = {}) {
  const now = new Date(options.now ?? historySummary?.until ?? Date.now());
  const nowMs = now.getTime();
  const thresholds = {
    memoryUsedFraction: 0.9,
    loadPerCpu: 1.5,
    diskWarningFraction: 0.9,
    diskCriticalFraction: 0.95,
    minSustainedSamples: 2,
    daemonDefaultStaleMs: 5 * 60 * 1000,
    ...options.thresholds,
  };
  const candidates = [];
  const metrics = metricByName(historySummary);
  const intervalMs = Number(daemonStatus?.profile?.interval_ms);
  const staleMs = Math.max(thresholds.daemonDefaultStaleMs, Number.isFinite(intervalMs) ? intervalMs * 3 : 0);
  const newestMetricMs = newestMetricTimestamp(historySummary);
  const daemonStatusMs = daemonStatus?.ts ? new Date(daemonStatus.ts).getTime() : undefined;

  if (!daemonStatus) {
    pushCandidate(candidates, {
      rule_id: "daemon.status.missing",
      severity: "warning",
      title: "Daemon status is missing",
      summary: "No local history daemon status record is available.",
      diagnostics: { reason: "missing_daemon_status" },
    });
  } else if (daemonStatus.state && !["ok", "stopped"].includes(daemonStatus.state)) {
    pushCandidate(candidates, {
      rule_id: "daemon.status.not_ok",
      severity: "warning",
      title: "Daemon status is not ok",
      summary: `Local history daemon reported state ${daemonStatus.state}.`,
      diagnostics: { state: daemonStatus.state },
    });
  }

  if ((historySummary?.point_count ?? 0) === 0) {
    pushCandidate(candidates, {
      rule_id: "daemon.samples.missing",
      severity: "warning",
      title: "No recent metric samples",
      summary: "No local metric history points are available in the alert evaluation window.",
      diagnostics: { window_ms: historySummary?.window_ms, point_count: historySummary?.point_count ?? 0 },
    });
  } else if (Number.isFinite(newestMetricMs) && nowMs - newestMetricMs > staleMs) {
    pushCandidate(candidates, {
      rule_id: "daemon.samples.stale",
      severity: "warning",
      title: "Metric samples are stale",
      summary: `Newest local metric sample is older than ${Math.round(staleMs / 1000)}s.`,
      diagnostics: { newest_sample_ts: new Date(newestMetricMs).toISOString(), stale_ms: staleMs, age_ms: nowMs - newestMetricMs },
    });
  } else if (Number.isFinite(daemonStatusMs) && nowMs - daemonStatusMs > staleMs) {
    pushCandidate(candidates, {
      rule_id: "daemon.status.stale",
      severity: "warning",
      title: "Daemon status is stale",
      summary: `Local history daemon status is older than ${Math.round(staleMs / 1000)}s.`,
      diagnostics: { daemon_status_ts: new Date(daemonStatusMs).toISOString(), stale_ms: staleMs, age_ms: nowMs - daemonStatusMs },
    });
  }

  const memory = metrics.get("system.memory.used_fraction");
  if (memory?.count >= thresholds.minSustainedSamples && memory.min >= thresholds.memoryUsedFraction) {
    pushCandidate(candidates, {
      rule_id: "system.memory.sustained_high",
      severity: memory.min >= 0.95 ? "critical" : "warning",
      title: "Sustained high memory pressure",
      summary: `Memory used stayed at or above ${formatPercent(thresholds.memoryUsedFraction)} for ${memory.count} samples.`,
      diagnostics: { min: memory.min, mean: memory.mean, max: memory.max, count: memory.count, threshold: thresholds.memoryUsedFraction },
    });
  }

  const load = metrics.get("system.load.1m");
  const cpuCount = metrics.get("system.cpu.count")?.last;
  if (load?.count >= thresholds.minSustainedSamples && Number.isFinite(cpuCount) && cpuCount > 0) {
    const threshold = Number(cpuCount) * thresholds.loadPerCpu;
    if (load.min >= threshold) {
      pushCandidate(candidates, {
        rule_id: "system.load.sustained_high",
        severity: load.min >= threshold * 2 ? "critical" : "warning",
        title: "Sustained high system load",
        summary: `1m load stayed above ${threshold.toFixed(2)} (${thresholds.loadPerCpu}× CPU count) for ${load.count} samples.`,
        diagnostics: { min: load.min, mean: load.mean, max: load.max, count: load.count, cpu_count: cpuCount, threshold },
      });
    }
  }

  const disk = metrics.get("disk.used_fraction");
  if (disk?.max >= thresholds.diskWarningFraction) {
    const critical = disk.max >= thresholds.diskCriticalFraction;
    pushCandidate(candidates, {
      rule_id: "disk.space.high_used_fraction",
      severity: critical ? "critical" : "warning",
      title: critical ? "Critical disk pressure" : "High disk pressure",
      summary: `At least one pressure-relevant filesystem reached ${formatPercent(disk.max)} used.`,
      diagnostics: { max: disk.max, mean: disk.mean, dimensions_seen: disk.dimensions_seen, threshold: critical ? thresholds.diskCriticalFraction : thresholds.diskWarningFraction },
    });
  }

  return candidates;
}

export function normalizeAlertRecord(record) {
  if (!record || typeof record !== "object") throw new Error("Alert record must be an object");
  const ruleId = String(record.rule_id ?? "").trim();
  if (!ruleId) throw new Error("Alert record requires rule_id");
  const fingerprint = String(record.fingerprint ?? "global");
  const firstSeen = normalizeIso(record.first_seen ?? record.last_seen ?? new Date().toISOString(), "first_seen");
  const lastSeen = normalizeIso(record.last_seen ?? firstSeen, "last_seen");
  const status = ["active", "recovered", "acknowledged", "suppressed"].includes(record.status) ? record.status : "active";
  const lastNotified = record.last_notified ? normalizeIso(record.last_notified, "last_notified") : null;
  const episodeNotifiedAt = record.episode_notified_at ? normalizeIso(record.episode_notified_at, "episode_notified_at") : null;
  const normalizedCurrentIncidentKey = normalizeIncidentKey(record.current_incident_key ?? record.incident_key) ?? "default";
  const notifiedIncidentKeys = normalizeIncidentKeyList(record.notified_incident_keys);
  // Legacy records had one episode-level delivery timestamp but no incident-key set. Preserve the
  // old proof only when the episode itself has a confirmed timestamp; a legacy last_notified alone
  // remains untrusted and is intentionally still due on migration.
  if ((!Array.isArray(record.notified_incident_keys) || record.notified_incident_keys.length === 0) && episodeNotifiedAt) notifiedIncidentKeys.push(normalizedCurrentIncidentKey);
  const notifiedSeverityMax = record.notified_severity_max === undefined || record.notified_severity_max === null
    ? null
    : String(record.notified_severity_max);
  return {
    id: String(record.id ?? alertId(ruleId, fingerprint)),
    rule_id: ruleId,
    fingerprint,
    incident_key: normalizeIncidentKey(record.incident_key),
    current_incident_key: normalizeIncidentKey(record.current_incident_key ?? record.incident_key),
    episode_incident_keys: normalizeIncidentKeyList(record.episode_incident_keys),
    notified_incident_keys: [...new Set(notifiedIncidentKeys)].slice(-256),
    incident_key_overflow: record.incident_key_overflow === true,
    status,
    severity: record.severity === undefined || record.severity === null ? "warning" : String(record.severity),
    title: String(record.title ?? ruleId),
    summary: String(record.summary ?? ""),
    evidence_refs: Array.isArray(record.evidence_refs) ? record.evidence_refs.map(String).slice(0, 16) : [],
    first_seen: firstSeen,
    last_seen: lastSeen,
    last_notified: lastNotified,
    cooldown_until: record.cooldown_until ? normalizeIso(record.cooldown_until, "cooldown_until") : null,
    acknowledged_at: record.acknowledged_at ? normalizeIso(record.acknowledged_at, "acknowledged_at") : null,
    // A missing episode_started_at is meaningful legacy state: it cannot prove delivery after
    // the current activation and must remain missing until applyAlertCandidates starts the upgrade
    // episode. Never synthesize first_seen here.
    episode_started_at: record.episode_started_at ? normalizeIso(record.episode_started_at, "episode_started_at") : null,
    notified_severity_max: notifiedSeverityMax,
    episode_notified_at: episodeNotifiedAt,
    adjudicated_at: record.adjudicated_at ? normalizeIso(record.adjudicated_at, "adjudicated_at") : null,
    adjudicated_episode_key: normalizeIncidentKey(record.adjudicated_episode_key),
    adjudication: record.adjudication && typeof record.adjudication === "object" && !Array.isArray(record.adjudication)
      ? { notify: record.adjudication.notify === true, severity: record.adjudication.severity === undefined ? undefined : String(record.adjudication.severity) }
      : null,
    delivery_failure_count: Number.isInteger(record.delivery_failure_count) && record.delivery_failure_count > 0 ? record.delivery_failure_count : 0,
    last_delivery_failure_at: record.last_delivery_failure_at ? normalizeIso(record.last_delivery_failure_at, "last_delivery_failure_at") : null,
    delivery_failure_reason: record.delivery_failure_reason ? String(record.delivery_failure_reason) : null,
    delivery_failing_since: record.delivery_failing_since ? normalizeIso(record.delivery_failing_since, "delivery_failing_since") : null,
    next_attempt_at: record.next_attempt_at ? normalizeIso(record.next_attempt_at, "next_attempt_at") : null,
    last_attempt_at: record.last_attempt_at ? normalizeIso(record.last_attempt_at, "last_attempt_at") : null,
    backoff_delay_ms: Number.isFinite(record.backoff_delay_ms) && record.backoff_delay_ms > 0 ? Math.min(record.backoff_delay_ms, DELIVERY_BACKOFF_CAP_MS) : null,
    diagnostics: record.diagnostics && typeof record.diagnostics === "object" && !Array.isArray(record.diagnostics) ? record.diagnostics : {},
  };
}

export async function readAlertRecords(descartesPaths) {
  const { alertsFile } = resolveAlertStorePaths(descartesPaths);
  try {
    const parsed = JSON.parse(await fs.readFile(alertsFile, "utf8"));
    const rawAlerts = Array.isArray(parsed) ? parsed : parsed.alerts;
    // Tolerate a single malformed persisted record (bad rule_id, unparseable first_seen/
    // last_seen/last_notified/cooldown_until/acknowledged_at date) instead of letting
    // Array.prototype.map's implicit re-throw abort the entire read: one bad record must not
    // blind the whole alert pipeline for this tick. Quarantine per-record and surface a count
    // via console.warn; every OTHER field in normalizeAlertRecord already degrades to a safe
    // default rather than throwing. Whole-file corruption (unparseable JSON, non-ENOENT fs
    // errors) is a distinct, more severe case and must keep propagating unchanged — see the
    // catch block below, which this loop does not touch.
    const normalized = [];
    let quarantinedCount = 0;
    for (const rawAlert of rawAlerts ?? []) {
      try {
        normalized.push(normalizeAlertRecord(rawAlert));
      } catch (recordError) {
        quarantinedCount += 1;
        const identifier = rawAlert?.id ?? rawAlert?.rule_id ?? "<unknown>";
        console.warn(`descartes: quarantined malformed alert record (id/rule_id=${identifier}): ${recordError?.message ?? recordError}`);
      }
    }
    if (quarantinedCount > 0) {
      console.warn(`descartes: readAlertRecords quarantined ${quarantinedCount} malformed record(s) out of ${(rawAlerts ?? []).length}`);
    }
    return normalized;
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

async function writeAlertRecordsUnlocked(descartesPaths, alerts) {
  await ensureAlertDir(descartesPaths);
  const { alertsFile } = resolveAlertStorePaths(descartesPaths);
  const normalized = alerts.map(normalizeAlertRecord).sort((left, right) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    if ((severityOrder[left.severity] ?? 9) !== (severityOrder[right.severity] ?? 9)) return (severityOrder[left.severity] ?? 9) - (severityOrder[right.severity] ?? 9);
    return right.last_seen.localeCompare(left.last_seen);
  });
  const payload = JSON.stringify({ version: 1, alerts: normalized }, null, 2);
  const tmpFile = `${alertsFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, alertsFile);
  return normalized;
}

export async function writeAlertRecords(descartesPaths, alerts) {
  return writeAlertRecordsUnlocked(descartesPaths, alerts);
}

const ALERT_SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
export function alertSeverityRank(severity) {
  return Object.hasOwn(ALERT_SEVERITY_RANK, severity) ? ALERT_SEVERITY_RANK[severity] : 3;
}

function deliveryBackoffEligible(alert, nowMs) {
  if (!Number.isFinite(nowMs)) return true;
  const lastAttemptMs = alert.last_attempt_at ? new Date(alert.last_attempt_at).getTime() : NaN;
  const delayMs = Number.isFinite(alert.backoff_delay_ms) ? alert.backoff_delay_ms : undefined;
  if (!Number.isFinite(lastAttemptMs) || !Number.isFinite(delayMs)) {
    if (!alert.next_attempt_at) return true;
    const nextAttemptMs = new Date(alert.next_attempt_at).getTime();
    return !Number.isFinite(nextAttemptMs) || nextAttemptMs <= nowMs;
  }
  // A future last-attempt timestamp is a clock rollback artifact. It must never suppress a retry.
  if (lastAttemptMs > nowMs) return true;
  return nowMs >= lastAttemptMs + delayMs;
}

function notificationDue(alert, { newEpisode = false, newIncident = false, severityEscalated = false, previousAlert, nowMs } = {}) {
  if (["suppressed", "recovered"].includes(alert.status)) return false;
  if (newEpisode || newIncident || severityEscalated) return true;
  if (!deliveryBackoffEligible(alert, nowMs)) return false;

  const notifiedMax = alertSeverityRank(alert.notified_severity_max);
  if (alert.notified_incident_keys?.includes(alert.current_incident_key ?? "default")) {
    return alertSeverityRank(alert.severity) > notifiedMax;
  }

  // An operator acknowledgement suppresses ordinary persistence, including a legacy record that
  // has not yet acquired episode fields. A higher severity is still a new security-relevant change.
  if (!newIncident && !severityEscalated && (previousAlert?.status === "acknowledged" || alert.status === "acknowledged")) return false;
  if (previousAlert?.status === "acknowledged" || alert.status === "acknowledged") {
    return alertSeverityRank(alert.severity) > alertSeverityRank(previousAlert?.severity);
  }
  return true;
}

export function applyAlertCandidates(existingAlerts, candidates, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const byId = new Map(existingAlerts.map((alert) => [alert.id, normalizeAlertRecord(alert)]));
  const activeCandidateIds = new Set(candidates.map((candidate) => candidate.id));
  const notificationDueIds = new Set();
  const adjudicationDueIds = new Set();
  // Detector-reported recovery coverage (§8.A): the covered set is keyed on alert IDENTITY
  // (alert.id = alertId(rule_id, fingerprint)), not rule_id, so recovery is authorized per persisted
  // alert rather than per family. undefined means "unrestricted", i.e. today's exact behavior: any
  // persisted id absent from `candidates` this call is eligible for recovery — kept for callers that
  // evaluate the full candidate universe and pass nothing. A caller that only evaluates a PARTIAL
  // universe (the CLI's read-only view, restricted to the fixed rules) or that enforces
  // detector-reported coverage (the daemon) passes an explicit Set of alert IDs so it can only
  // recover the specific alert identities it actually has full visibility into this call.
  const coveredAlertIds = options.coveredAlertIds;

  for (const candidate of candidates) {
    const current = byId.get(candidate.id);
    const candidateEpisodeKey = alertEpisodeKey(candidate);
    const newEpisode = !current
      || current.status === "recovered"
      || !current.episode_started_at;
    const base = current ?? normalizeAlertRecord({
      ...candidate,
      incident_key: candidateEpisodeKey === "default" ? null : candidateEpisodeKey,
      current_incident_key: candidateEpisodeKey,
      episode_incident_keys: candidateEpisodeKey === "default" ? ["default"] : [candidateEpisodeKey],
      status: "active",
      first_seen: now,
      last_seen: now,
    });
    const nextStatus = base.status === "acknowledged" || base.status === "suppressed" ? base.status : "active";
    const priorIncidentKeys = new Set(newEpisode
      ? []
      : ((base.episode_incident_keys?.length ? base.episode_incident_keys : [alertEpisodeKey(base)]).map((key) => key || "default")));
    const newIncident = !priorIncidentKeys.has(candidateEpisodeKey);
    const episodeIncidentKeys = [...priorIncidentKeys, candidateEpisodeKey].filter(Boolean);
    const overflow = base.incident_key_overflow || episodeIncidentKeys.length > 256;
    let next = normalizeAlertRecord({
      ...base,
      ...candidate,
      status: nextStatus,
      first_seen: base.first_seen,
      last_seen: now,
      acknowledged_at: nextStatus === "acknowledged" ? base.acknowledged_at : null,
      last_notified: base.last_notified,
      cooldown_until: base.cooldown_until,
      episode_started_at: newEpisode ? now : base.episode_started_at,
      current_incident_key: candidateEpisodeKey,
      episode_incident_keys: episodeIncidentKeys.slice(-256),
      notified_incident_keys: newEpisode ? [] : base.notified_incident_keys,
      incident_key_overflow: overflow,
      notified_severity_max: newEpisode ? null : base.notified_severity_max,
      episode_notified_at: newEpisode ? null : base.episode_notified_at,
      adjudicated_at: newEpisode ? null : base.adjudicated_at,
      adjudicated_episode_key: newEpisode ? null : base.adjudicated_episode_key,
      adjudication: newEpisode ? null : base.adjudication,
      delivery_failure_count: newEpisode || newIncident ? 0 : base.delivery_failure_count,
      last_delivery_failure_at: newEpisode || newIncident ? null : base.last_delivery_failure_at,
      delivery_failure_reason: newEpisode || newIncident ? null : base.delivery_failure_reason,
      delivery_failing_since: newEpisode || newIncident ? null : base.delivery_failing_since,
      next_attempt_at: newEpisode || newIncident ? null : base.next_attempt_at,
      last_attempt_at: newEpisode || newIncident ? null : base.last_attempt_at,
      backoff_delay_ms: newEpisode || newIncident ? null : base.backoff_delay_ms,
    });
    const severityEscalated = current && alertSeverityRank(next.severity) > alertSeverityRank(current.severity);
    if (notificationDue(next, { newEpisode, newIncident, severityEscalated, previousAlert: current, nowMs: new Date(now).getTime() })) {
      notificationDueIds.add(next.id);
    }
    const sameNegativeAdjudication = next.adjudicated_episode_key === alertEpisodeKey(next)
      && next.adjudication?.notify === false
      && next.adjudication?.severity === next.severity;
    if (!sameNegativeAdjudication && (newEpisode || severityEscalated || notificationDueIds.has(next.id))) {
      adjudicationDueIds.add(next.id);
    }
    byId.set(next.id, next);
  }

  for (const [id, alert] of byId) {
    const isCovered = !coveredAlertIds || coveredAlertIds.has(alert.id);
    if (isCovered && !activeCandidateIds.has(id) && ["active", "acknowledged"].includes(alert.status)) {
      byId.set(id, normalizeAlertRecord({
        ...alert,
        status: "recovered",
        last_seen: now,
      }));
    }
  }

  return {
    alerts: [...byId.values()],
    notification_due_ids: [...notificationDueIds],
    adjudication_due_ids: [...adjudicationDueIds],
  };
}

// Non-persisting evaluation: computes candidates and merges them against the existing persisted
// alerts in memory, but never writes to disk. Used by evaluateAndPersistAlerts below (the daemon's
// authoritative write path) and directly by read-only callers (the CLI's alerts list/watch view)
// that must never mutate persisted state — see options.coveredAlertIds, threaded through to
// applyAlertCandidates to scope recovery eligibility (by alert identity) for a caller that only
// evaluates a partial candidate universe (e.g. fixedAlertIds()).
export async function evaluateAlerts(descartesPaths, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const [historySummary, daemonStatus, existing] = await Promise.all([
    options.historySummary ? Promise.resolve(options.historySummary) : buildHistorySummary(descartesPaths, { now, windowMs: options.windowMs ?? DEFAULT_ALERT_WINDOW_MS, limit: options.limit }),
    options.daemonStatus ? Promise.resolve(options.daemonStatus) : readDaemonStatus(descartesPaths),
    options.existingAlerts ? Promise.resolve(options.existingAlerts) : readAlertRecords(descartesPaths),
  ]);
  const candidates = evaluateAlertRules(historySummary, daemonStatus, { now, thresholds: options.thresholds });
  const extraCandidates = Array.isArray(options.extraCandidates) ? options.extraCandidates : [];
  // Both sources MUST be merged into one array before the single applyAlertCandidates call below:
  // applyAlertCandidates' recovery logic marks any active alert id absent from the current candidate
  // array as "recovered", so evaluating fixed rules and extra (e.g. constraint) candidates separately
  // would cause each source to spuriously recover the other's alerts every iteration. Every fixed-rule
  // candidate already carries an `id` (set by pushCandidate); defensively assign the same alertId()
  // to any extraCandidates entry missing one, so a source that forgets to set `id` cannot desync
  // applyAlertCandidates' recovery-detection set from the ids it actually persists under.
  const mergedCandidates = [...candidates, ...extraCandidates].map((candidate) =>
    candidate?.id ? candidate : { ...candidate, id: alertId(candidate.rule_id, candidate.fingerprint ?? "global") }
  );
  const applied = applyAlertCandidates(existing, mergedCandidates, { now, cooldownMs: options.cooldownMs, coveredAlertIds: options.coveredAlertIds });
  return { alerts: applied.alerts, candidates, history_summary: historySummary, daemon_status: daemonStatus ?? null, notification_due_ids: applied.notification_due_ids, adjudication_due_ids: applied.adjudication_due_ids };
}

export async function evaluateAndPersistAlerts(descartesPaths, options = {}) {
  // Candidate computation and history reads happen outside the lock. The locked section only
  // re-reads the latest alert snapshot, applies the already-computed candidates, and atomically
  // writes it. This bounds lock hold time without changing detector coverage or recovery semantics.
  const evaluated = await evaluateAlerts(descartesPaths, options);
    const candidates = [...(evaluated.candidates ?? []), ...(Array.isArray(options.extraCandidates) ? options.extraCandidates : [])]
    .map((candidate) => candidate?.id ? candidate : { ...candidate, id: alertId(candidate.rule_id, candidate.fingerprint ?? "global") });
  const latest = await readAlertRecords(descartesPaths);
  const applied = applyAlertCandidates(latest, candidates, { now: options.now ?? new Date().toISOString(), cooldownMs: options.cooldownMs, coveredAlertIds: options.coveredAlertIds });
  const alerts = await writeAlertRecordsUnlocked(descartesPaths, applied.alerts);
  return { ...evaluated, alerts, notification_due_ids: applied.notification_due_ids, adjudication_due_ids: applied.adjudication_due_ids };
}

export async function confirmAlertDelivery(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let confirmed = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
    if (options.episodeKey && alertEpisodeKey(alert) !== options.episodeKey) return alert;
    confirmed = true;
    const incidentKey = options.incidentKey ?? options.episodeKey ?? alertEpisodeKey(alert);
    const notifiedKeys = [...new Set([...(alert.notified_incident_keys ?? []), incidentKey].filter(Boolean))];
    const currentRank = alert.notified_severity_max === null ? -1 : alertSeverityRank(alert.notified_severity_max);
    const nextRank = alertSeverityRank(options.severity ?? alert.severity);
    return normalizeAlertRecord({
      ...alert,
      last_notified: now,
      episode_notified_at: now,
      notified_incident_keys: notifiedKeys.slice(-256),
      incident_key_overflow: alert.incident_key_overflow || notifiedKeys.length > 256,
      notified_severity_max: nextRank >= currentRank ? (options.severity ?? alert.severity) : alert.notified_severity_max,
      delivery_failure_count: 0,
      last_delivery_failure_at: null,
      delivery_failure_reason: null,
      delivery_failing_since: null,
      next_attempt_at: null,
      last_attempt_at: now,
      backoff_delay_ms: null,
    });
  });
  if (!confirmed) return { confirmed: false };
  const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
  return { confirmed: true, alert: written.find((alert) => alert.id === alertIdValue) };
}

export async function recordAlertDeliveryFailure(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let recorded = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
    if (options.episodeKey && alertEpisodeKey(alert) !== options.episodeKey) return alert;
    recorded = true;
    const count = alert.delivery_failure_count + 1;
    const delay = Math.min(DELIVERY_BACKOFF_CAP_MS, DELIVERY_BACKOFF_BASE_MS * (2 ** Math.min(count - 1, 16)));
    const nextAttemptMs = new Date(now).getTime() + delay;
    return normalizeAlertRecord({
      ...alert,
      delivery_failure_count: count,
      last_delivery_failure_at: now,
      last_attempt_at: now,
      backoff_delay_ms: delay,
      delivery_failure_reason: String(options.reason ?? "delivery_failed").slice(0, 240),
      delivery_failing_since: alert.delivery_failing_since ?? now,
      next_attempt_at: new Date(nextAttemptMs).toISOString(),
    });
  });
  if (!recorded) return { recorded: false };
  const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
  return { recorded: true, alert: written.find((alert) => alert.id === alertIdValue) };
}

export async function recordAlertAdjudication(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let recorded = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
    if (options.episodeKey && alertEpisodeKey(alert) !== options.episodeKey) return alert;
    recorded = true;
    return normalizeAlertRecord({
      ...alert,
      adjudicated_at: now,
      adjudicated_episode_key: options.episodeKey ?? alertEpisodeKey(alert),
      adjudication: { notify: options.notify === true, severity: options.severity ?? alert.severity },
    });
  });
  if (!recorded) return { recorded: false };
  const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
  return { recorded: true, alert: written.find((alert) => alert.id === alertIdValue) };
}

export async function acknowledgeAlert(descartesPaths, alertId, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let found = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertId) return alert;
    found = true;
    return normalizeAlertRecord({ ...alert, status: "acknowledged", acknowledged_at: now });
  });
  if (!found) throw new Error(`Alert not found: ${alertId}`);
  return (await writeAlertRecordsUnlocked(descartesPaths, updated)).find((alert) => alert.id === alertId);
}
