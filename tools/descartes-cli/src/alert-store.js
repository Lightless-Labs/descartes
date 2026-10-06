import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { buildHistorySummary, readDaemonStatus } from "./history-store.js";
import { readNotificationDeliveryAudit } from "./notification-delivery.js";

export const DEFAULT_ALERT_COOLDOWN_MS = 15 * 60 * 1000;
export const DEFAULT_ALERT_WINDOW_MS = 15 * 60 * 1000;
const ALERT_STORE_LOCK_STALE_MS = 30_000;

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

async function withAlertStoreLock(descartesPaths, operation) {
  const { dir } = resolveAlertStorePaths(descartesPaths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const lockFile = path.join(dir, "alerts.json.lock");
  const owner = `${process.pid}:${crypto.randomUUID()}`;
  for (;;) {
    try {
      const handle = await fs.open(lockFile, "wx", 0o600);
      try {
        await handle.writeFile(owner, "utf8");
      } finally {
        await handle.close();
      }
      try {
        return await operation();
      } finally {
        try {
          const currentOwner = await fs.readFile(lockFile, "utf8");
          if (currentOwner === owner) await fs.unlink(lockFile);
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
        }
      }
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      try {
        const stat = await fs.stat(lockFile);
        if (Date.now() - stat.mtimeMs > ALERT_STORE_LOCK_STALE_MS) {
          await fs.unlink(lockFile);
          continue;
        }
      } catch (statError) {
        if (statError?.code !== "ENOENT") throw statError;
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
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
  const notifiedSeverityMax = record.notified_severity_max === undefined || record.notified_severity_max === null
    ? null
    : String(record.notified_severity_max);
  return {
    id: String(record.id ?? alertId(ruleId, fingerprint)),
    rule_id: ruleId,
    fingerprint,
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
    episode_started_at: record.episode_started_at
      ? normalizeIso(record.episode_started_at, "episode_started_at")
      : status === "recovered" ? null : firstSeen,
    notified_severity_max: notifiedSeverityMax,
    episode_notified_at: episodeNotifiedAt,
    material_evidence_digest: String(record.material_evidence_digest ?? "").startsWith("v2:")
      ? String(record.material_evidence_digest)
      : materialEvidenceDigest(record),
    adjudicated_at: record.adjudicated_at ? normalizeIso(record.adjudicated_at, "adjudicated_at") : null,
    adjudicated_evidence_digest: record.adjudicated_evidence_digest ? String(record.adjudicated_evidence_digest) : null,
    adjudication: record.adjudication && typeof record.adjudication === "object" && !Array.isArray(record.adjudication)
      ? { notify: record.adjudication.notify === true, severity: record.adjudication.severity === undefined ? undefined : String(record.adjudication.severity) }
      : null,
    delivery_failure_count: Number.isInteger(record.delivery_failure_count) && record.delivery_failure_count > 0 ? record.delivery_failure_count : 0,
    last_delivery_failure_at: record.last_delivery_failure_at ? normalizeIso(record.last_delivery_failure_at, "last_delivery_failure_at") : null,
    delivery_failure_reason: record.delivery_failure_reason ? String(record.delivery_failure_reason) : null,
    diagnostics: record.diagnostics && typeof record.diagnostics === "object" && !Array.isArray(record.diagnostics) ? record.diagnostics : {},
  };
}

export const MATERIAL_EVIDENCE_VOLATILE_FIELDS = Object.freeze({
  "*": Object.freeze(["age_ms", "daemon_status_ts", "evaluation_ts", "newest_sample_ts", "now", "observation_ts", "observed_at", "timestamp", "ts", "window_ms"]),
  "canary.tripped": Object.freeze(["age_ms", "evaluation_ts", "observation_ts", "observed_at", "timestamp", "ts"]),
  "provenance.port.new_public_bind": Object.freeze(["age_ms", "evaluation_ts", "observation_ts", "observed_at", "stable_iteration_count", "stable_sample_count", "timestamp", "ts"]),
  "correlation.login_kill_proximity": Object.freeze(["age_ms", "candidate_pool_size", "evaluation_ts", "observation_ts", "observed_at", "peer_novelty_prior_tick_count", "proximity_seconds", "timestamp", "ts"]),
});

function canonicalEvidence(value, ignoredFields) {
  if (Array.isArray(value)) return value.map((entry) => canonicalEvidence(entry, ignoredFields));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort()
      .filter((key) => !ignoredFields.has(key))
      .map((key) => [key, canonicalEvidence(value[key], ignoredFields)]));
  }
  return value;
}

export function materialEvidenceDigest(candidateOrRecord = {}) {
  const diagnostics = candidateOrRecord?.diagnostics && typeof candidateOrRecord.diagnostics === "object"
    ? candidateOrRecord.diagnostics
    : {};
  const volatileFields = new Set([
    ...(MATERIAL_EVIDENCE_VOLATILE_FIELDS["*"] ?? []),
    ...(MATERIAL_EVIDENCE_VOLATILE_FIELDS[candidateOrRecord?.rule_id] ?? []),
  ]);
  return `v2:${crypto.createHash("sha256")
    .update(JSON.stringify(canonicalEvidence(diagnostics, volatileFields)))
    .digest("hex")}`;
}

async function deriveLegacyDeliveryState(descartesPaths, alerts, legacyAlertIds = new Set()) {
  if (alerts.length === 0) return alerts;
  let audit = [];
  try {
    audit = await readNotificationDeliveryAudit(descartesPaths);
  } catch (error) {
    console.warn(`descartes: notification delivery audit unavailable (${error?.message ?? error}); legacy alerts remain due`);
  }
  return alerts.map((alert) => {
    if (!legacyAlertIds.has(alert.id)) return alert;
    const activation = new Date(alert.episode_started_at ?? alert.first_seen).getTime();
    const successful = audit
      .filter((record) => record?.payload?.alert_id === alert.id && ["delivered", "cli_only"].includes(record.status))
      .filter((record) => Number.isFinite(new Date(record.ts).getTime()) && new Date(record.ts).getTime() >= activation)
      .sort((left, right) => String(right.ts).localeCompare(String(left.ts)))[0];
    if (!successful) {
      return normalizeAlertRecord({ ...alert, episode_notified_at: null, notified_severity_max: null });
    }
    return normalizeAlertRecord({
      ...alert,
      episode_notified_at: successful.ts,
      notified_severity_max: successful.payload?.severity ?? alert.severity,
    });
  });
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
    const legacyAlertIds = new Set();
    let quarantinedCount = 0;
    for (const rawAlert of rawAlerts ?? []) {
      try {
        normalized.push(normalizeAlertRecord(rawAlert));
        if (!Object.hasOwn(rawAlert ?? {}, "material_evidence_digest")) legacyAlertIds.add(String(rawAlert?.id ?? alertId(rawAlert?.rule_id, rawAlert?.fingerprint ?? "global")));
      } catch (recordError) {
        quarantinedCount += 1;
        const identifier = rawAlert?.id ?? rawAlert?.rule_id ?? "<unknown>";
        console.warn(`descartes: quarantined malformed alert record (id/rule_id=${identifier}): ${recordError?.message ?? recordError}`);
      }
    }
    if (quarantinedCount > 0) {
      console.warn(`descartes: readAlertRecords quarantined ${quarantinedCount} malformed record(s) out of ${(rawAlerts ?? []).length}`);
    }
    return deriveLegacyDeliveryState(descartesPaths, normalized, legacyAlertIds);
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
  return withAlertStoreLock(descartesPaths, () => writeAlertRecordsUnlocked(descartesPaths, alerts));
}

const ALERT_SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
export function alertSeverityRank(severity) {
  return Object.hasOwn(ALERT_SEVERITY_RANK, severity) ? ALERT_SEVERITY_RANK[severity] : 3;
}

function notificationDue(alert, { newEpisode = false, previousAlert } = {}) {
  if (["suppressed", "recovered"].includes(alert.status)) return false;
  if (newEpisode) return true;

  const notifiedMax = alertSeverityRank(alert.notified_severity_max);
  if (alert.notified_severity_max !== null && alert.notified_severity_max !== undefined) {
    return alertSeverityRank(alert.severity) > notifiedMax;
  }

  // An operator acknowledgement suppresses ordinary persistence, including a legacy record that
  // has not yet acquired episode fields. A higher severity is still a new security-relevant change.
  if (previousAlert?.status === "acknowledged" || alert.status === "acknowledged") {
    return alertSeverityRank(alert.severity) > alertSeverityRank(previousAlert?.severity);
  }
  return true;
}

export function applyAlertCandidates(existingAlerts, candidates, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const byId = new Map(existingAlerts.map((alert) => [alert.id, normalizeAlertRecord(alert)]));
  const activeCandidateIds = new Set(candidates.map((candidate) => candidate.id));
  const notificationDueIds = [];
  const adjudicationDueIds = [];
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
    const evidenceDigest = materialEvidenceDigest(candidate);
    const newEpisode = !current || current.status === "recovered" || current.material_evidence_digest !== evidenceDigest;
    const base = current ?? normalizeAlertRecord({
      ...candidate,
      status: "active",
      first_seen: now,
      last_seen: now,
    });
    const nextStatus = base.status === "acknowledged" || base.status === "suppressed" ? base.status : "active";
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
      notified_severity_max: newEpisode ? null : base.notified_severity_max,
      episode_notified_at: newEpisode ? null : base.episode_notified_at,
      material_evidence_digest: evidenceDigest,
      adjudicated_at: newEpisode ? null : base.adjudicated_at,
      adjudicated_evidence_digest: newEpisode ? null : base.adjudicated_evidence_digest,
      adjudication: newEpisode ? null : base.adjudication,
    });
    const severityChanged = current && current.severity !== next.severity;
    if (notificationDue(next, { newEpisode, previousAlert: current })) {
      notificationDueIds.push(next.id);
    }
    const sameNegativeAdjudication = next.adjudicated_evidence_digest === evidenceDigest
      && next.adjudication?.notify === false
      && next.adjudication?.severity === next.severity;
    if (!sameNegativeAdjudication && (newEpisode || severityChanged || notificationDueIds.includes(next.id))) {
      adjudicationDueIds.push(next.id);
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
    notification_due_ids: notificationDueIds,
    adjudication_due_ids: adjudicationDueIds,
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
    readAlertRecords(descartesPaths),
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
  return withAlertStoreLock(descartesPaths, async () => {
    const evaluated = await evaluateAlerts(descartesPaths, options);
    const alerts = await writeAlertRecordsUnlocked(descartesPaths, evaluated.alerts);
    return { ...evaluated, alerts };
  });
}

export async function confirmAlertDelivery(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return withAlertStoreLock(descartesPaths, async () => {
    const alerts = await readAlertRecords(descartesPaths);
    let confirmed = false;
    const updated = alerts.map((alert) => {
      if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
      if (options.evidenceDigest && alert.material_evidence_digest !== options.evidenceDigest) return alert;
      confirmed = true;
      const nextRank = alertSeverityRank(options.severity ?? alert.severity);
      const currentRank = alert.notified_severity_max === null ? -1 : alertSeverityRank(alert.notified_severity_max);
      return normalizeAlertRecord({
        ...alert,
        last_notified: now,
        episode_notified_at: now,
        notified_severity_max: nextRank >= currentRank ? (options.severity ?? alert.severity) : alert.notified_severity_max,
        delivery_failure_count: 0,
        last_delivery_failure_at: null,
        delivery_failure_reason: null,
      });
    });
    if (!confirmed) return { confirmed: false };
    const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
    return { confirmed: true, alert: written.find((alert) => alert.id === alertIdValue) };
  });
}

export async function recordAlertDeliveryFailure(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return withAlertStoreLock(descartesPaths, async () => {
    const alerts = await readAlertRecords(descartesPaths);
    let recorded = false;
    const updated = alerts.map((alert) => {
      if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
      if (options.evidenceDigest && alert.material_evidence_digest !== options.evidenceDigest) return alert;
      recorded = true;
      return normalizeAlertRecord({
        ...alert,
        delivery_failure_count: alert.delivery_failure_count + 1,
        last_delivery_failure_at: now,
        delivery_failure_reason: String(options.reason ?? "delivery_failed").slice(0, 240),
      });
    });
    if (!recorded) return { recorded: false };
    const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
    return { recorded: true, alert: written.find((alert) => alert.id === alertIdValue) };
  });
}

export async function recordAlertAdjudication(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return withAlertStoreLock(descartesPaths, async () => {
    const alerts = await readAlertRecords(descartesPaths);
    let recorded = false;
    const updated = alerts.map((alert) => {
      if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
      if (options.evidenceDigest && alert.material_evidence_digest !== options.evidenceDigest) return alert;
      recorded = true;
      return normalizeAlertRecord({
        ...alert,
        adjudicated_at: now,
        adjudicated_evidence_digest: options.evidenceDigest ?? alert.material_evidence_digest,
        adjudication: { notify: options.notify === true, severity: options.severity ?? alert.severity },
      });
    });
    if (!recorded) return { recorded: false };
    const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
    return { recorded: true, alert: written.find((alert) => alert.id === alertIdValue) };
  });
}

export async function acknowledgeAlert(descartesPaths, alertId, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return withAlertStoreLock(descartesPaths, async () => {
    const alerts = await readAlertRecords(descartesPaths);
    let found = false;
    const updated = alerts.map((alert) => {
      if (alert.id !== alertId) return alert;
      found = true;
      return normalizeAlertRecord({ ...alert, status: "acknowledged", acknowledged_at: now });
    });
    if (!found) throw new Error(`Alert not found: ${alertId}`);
    return (await writeAlertRecordsUnlocked(descartesPaths, updated)).find((alert) => alert.id === alertId);
  });
}
