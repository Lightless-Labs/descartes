// Context plan C1.5 (§12, I75; v4 Opus M4(a)): the digest -- the "notification" in "notification,
// not confirmation". Built from the daemon's own records (the transition log, the alert store, the
// pending journals and the label ingestion state), pushed once per period through the existing
// notification channel, ONLY when not empty, and never counted against any attention budget: the
// digest is the audit trail of everything that changed state without asking anyone.
//
// The push carries a counts line (the notification channel clamps bodies to 240 characters); the
// full digest is written to stateDir/alerts/digests/digest-<period end>.json and rendered by
// `descartes alerts digest`. Building a digest never mutates alert, journal or label state.
import fs from "node:fs/promises";
import path from "node:path";
import { readAlertRecords } from "./alert-store.js";
import { streamKindForRule } from "./alert-stream-kinds.js";
import { readAlertTransitions } from "./alert-transitions.js";
import { resolveAlertLabelPaths } from "./alert-labels.js";
import { atomicWrite } from "./hash-chain.js";
import { readFactIntegrityLedger } from "./fact-store-integrity.js";
import { inspectPendingJournal, PENDING_JOURNAL_FAMILIES, pendingAdmissionStatus } from "./pending-journal.js";
import { deliverNotificationDecision, queuePendingNotification, readPendingNotifications, resolvePendingNotification, selectNotificationNoticeWindow } from "./notification-delivery.js";

// §16.1 (O): the digest period. Default daily, sent only when not empty.
export const DIGEST_PERIOD_MS = 24 * 60 * 60 * 1000;
// C1 addendum (S): digest files retained.
export const MAX_RETAINED_DIGESTS = 30;
export const DIGEST_RULE_ID = "descartes.digest";
// C1 addendum (S): the retry interval after a failed digest push.
export const DIGEST_RETRY_MS = 60 * 60 * 1000;

export function resolveAlertDigestPaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "alerts");
  return { stateFile: path.join(dir, "digest.state.json"), digestsDir: path.join(dir, "digests") };
}

const OPEN_STATUSES = new Set(["active", "acknowledged"]);

// I55 keys are lvl:<regime>:<extreme>, and the newest such incident carries the running extreme
// (in the raising direction). Incumbents still key `default` until C1a, so it is null for them.
function levelExtreme(incidents) {
  const newest = Object.entries(incidents ?? {})
    .map(([key, incident]) => ({ match: /^lvl:[^:]*:(-?\d+(?:\.\d+)?)$/.exec(key), first_seen: incident?.first_seen ?? "" }))
    .filter((entry) => entry.match)
    .sort((left, right) => left.first_seen.localeCompare(right.first_seen))
    .at(-1);
  return newest ? Number(newest.match[1]) : null;
}

async function readJsonOrNull(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return null;
  }
}

/** Builds the digest for (since, now]. Read-only. */
export async function buildAlertDigest(descartesPaths, { now, since } = {}) {
  const nowIso = new Date(now ?? Date.now()).toISOString();
  const state = await readJsonOrNull(resolveAlertDigestPaths(descartesPaths).stateFile);
  const sinceIso = new Date(since ?? state?.last_period_end ?? (Date.parse(nowIso) - DIGEST_PERIOD_MS)).toISOString();
  const inPeriod = (ts) => ts > sinceIso && ts <= nowIso;
  const [alerts, transitions, pendingNotifications] = await Promise.all([readAlertRecords(descartesPaths), readAlertTransitions(descartesPaths), readPendingNotifications(descartesPaths)]);
  const notificationWindow = selectNotificationNoticeWindow(pendingNotifications, { now: nowIso });
  const pendingNoticeEntries = notificationWindow.entries.filter((entry) => !["delivered", "cli_only", "skipped"].includes(entry.last_status));
  const alertsById = new Map(alerts.map((alert) => [alert.id, alert]));
  const records = transitions.records.filter((record) => typeof record.ts === "string" && inPeriod(record.ts));
  const byKind = (...kinds) => records.filter((record) => kinds.includes(record.kind));

  const closures = byKind("incident_closed", "alert_closed").map((record) => {
    // Closure attribution is part of the chained transition record. The current alert store may
    // have re-armed, been compacted, or been edited since the closure; it is never a retrospective
    // source of provenance for a digest.
    return { ts: record.ts, kind: record.kind, alert_id: record.alert_id, rule_id: record.rule_id, incident_key: record.incident_key ?? null, reason: record.reason ?? null, source: record.source ?? null };
  });
  const labelState = await readJsonOrNull(resolveAlertLabelPaths(descartesPaths).stateFile);
  const journals = {};
  for (const family of PENDING_JOURNAL_FAMILIES) {
    try {
      const { ledger } = await readFactIntegrityLedger(descartesPaths, family);
      const inspected = await inspectPendingJournal(descartesPaths, family, { ledger });
      if (inspected.status === "missing") continue;
      const journalState = inspected.state;
      journals[family] = {
        status: inspected.status,
        ...(inspected.cause ? { cause: inspected.cause } : {}),
        open_epoch: journalState?.open_epoch ?? null,
        admission: journalState ? pendingAdmissionStatus(journalState, nowIso) : { suspended: true, reason: "unreadable" },
        excluded_ranges: (journalState?.ranges ?? []).filter((range) => inPeriod(range.ts)),
        compacted_total: journalState?.excluded_summary?.by_reason?.compacted ?? 0,
        admissions: Object.values(journalState?.items ?? {}).filter((item) => item.state === "admitted" && item.disposition?.ts && inPeriod(item.disposition.ts))
          .map((item) => ({ item: item.item, source: item.disposition.source, budget_charge: item.disposition.budget_charge ?? null })),
      };
    } catch (error) {
      journals[family] = { status: "error", error: error instanceof Error ? error.message : String(error) };
    }
  }

  const openEvent = [];
  const openLevel = [];
  const storms = [];
  const integrity = [];
  for (const alert of alerts) {
    const kind = streamKindForRule(alert.rule_id);
    if (OPEN_STATUSES.has(alert.status) && kind === "event") {
      openEvent.push({ alert_id: alert.id, rule_id: alert.rule_id, since: alert.episode_started_at ?? alert.first_seen });
    }
    if (OPEN_STATUSES.has(alert.status) && kind === "level") {
      const keys = Object.keys(alert.incidents ?? {});
      openLevel.push({
        alert_id: alert.id,
        rule_id: alert.rule_id,
        since: alert.episode_started_at ?? alert.first_seen,
        duration_ms: Math.max(0, Date.parse(nowIso) - Date.parse(alert.episode_started_at ?? alert.first_seen)),
        incidents: keys.length,
        running_extreme: levelExtreme(alert.incidents),
      });
    }
    if (alert.incident_state === "incident_storm") storms.push({ alert_id: alert.id, rule_id: alert.rule_id, incident_count: alert.incident_storm_count });
    if (OPEN_STATUSES.has(alert.status) && (alert.rule_id.startsWith("integrity.") || alert.rule_id === "census.universe_changed")) {
      integrity.push({ alert_id: alert.id, rule_id: alert.rule_id });
    }
  }

  const digest = {
    schema_version: 1,
    period: { since: sinceIso, until: nowIso },
    admissions: Object.entries(journals).flatMap(([family, journal]) => (journal.admissions ?? []).map((admission) => ({ family, ...admission }))),
    closures,
    labels: {
      ingested: byKind("label_ingested").map((record) => ({ ts: record.ts, label_id: record.label_id, label: record.label, charge: record.charge, effect: record.effect, alert_id: record.alert_id ?? null, family: record.family ?? null })),
      held: (labelState?.held ?? []).map((entry) => ({ label_id: entry.id, held_at: entry.held_at, charge: entry.charge })),
    },
    promotions: byKind("promotion_earned", "promotion_demoted", "replacement_earned", "replacement_rolled_back"),
    open_event_alerts: openEvent,
    open_level_episodes: openLevel,
    storms: { active: storms, entered: byKind("incident_storm").map((record) => ({ ts: record.ts, alert_id: record.alert_id, live_incidents: record.live_incidents })) },
    discontinuities: byKind("pending_discontinuity").map((record) => ({ ts: record.ts, family: record.family, epoch: record.epoch, cause: record.cause })),
    recertifications: byKind("recertified").map((record) => ({ ts: record.ts, family: record.family, epoch: record.epoch })),
    unadjudicated: Object.entries(journals).flatMap(([family, journal]) => (journal.excluded_ranges ?? []).map((range) => ({ family, ...range }))),
    admission_suspended: Object.entries(journals).filter(([, journal]) => journal.admission?.suspended).map(([family, journal]) => ({ family, reason: journal.admission.reason })),
    tombstones_dropped: byKind("tombstones_dropped").map((record) => ({ alert_id: record.alert_id, count: record.count })),
    integrity: {
      active_notices: integrity,
      transition_log: { status: transitions.status, gaps: byKind("chain_restart", "rebaselined").map((record) => ({ ts: record.ts, kind: record.kind, reason: record.reason ?? null })) },
      journals: Object.entries(journals).filter(([, journal]) => journal.status !== "valid").map(([family, journal]) => ({ family, status: journal.status, cause: journal.cause ?? null })),
    },
    notifications: {
      notices: notificationWindow.entries,
      pending: pendingNoticeEntries,
      older_count: notificationWindow.older_count,
      overflowed_count: notificationWindow.overflowed_count,
      ...(pendingNotifications.tamper ? { corrupt: true } : {}),
      ...(pendingNotifications.outbox_error ? { warning: pendingNotifications.outbox_error } : {}),
    },
  };
  digest.counts = {
    admissions: digest.admissions.length,
    closures: closures.length,
    labels: digest.labels.ingested.length,
    labels_held: digest.labels.held.length,
    promotions: digest.promotions.length,
    open_event_alerts: openEvent.length,
    open_level_episodes: openLevel.length,
    storms: storms.length + digest.storms.entered.length,
    discontinuities: digest.discontinuities.length,
    unadjudicated: digest.unadjudicated.length,
    integrity: integrity.length + digest.integrity.transition_log.gaps.length + digest.integrity.journals.length,
    notifications_pending: digest.notifications.pending.length,
    notifications_recent: digest.notifications.notices.length,
    notifications_older: digest.notifications.older_count,
  };
  digest.empty = Object.values(digest.counts).every((count) => count === 0) && digest.admission_suspended.length === 0 && digest.tombstones_dropped.length === 0;
  return digest;
}

export function digestSummaryLine(digest) {
  const c = digest.counts;
  const parts = [
    c.closures && `${c.closures} closure${c.closures === 1 ? "" : "s"}`,
    c.labels && `${c.labels} label${c.labels === 1 ? "" : "s"}`,
    c.labels_held && `${c.labels_held} held`,
    c.admissions && `${c.admissions} admission${c.admissions === 1 ? "" : "s"}`,
    c.open_event_alerts && `${c.open_event_alerts} open event alert${c.open_event_alerts === 1 ? "" : "s"}`,
    c.open_level_episodes && `${c.open_level_episodes} open level episode${c.open_level_episodes === 1 ? "" : "s"}`,
    c.storms && `${c.storms} storm${c.storms === 1 ? "" : "s"}`,
    c.discontinuities && `${c.discontinuities} discontinuit${c.discontinuities === 1 ? "y" : "ies"}`,
    c.unadjudicated && `${c.unadjudicated} unadjudicated range${c.unadjudicated === 1 ? "" : "s"}`,
    c.integrity && `${c.integrity} integrity item${c.integrity === 1 ? "" : "s"}`,
    c.notifications_pending && `${c.notifications_pending} required notice${c.notifications_pending === 1 ? "" : "s"} pending`,
  ].filter(Boolean);
  return `${parts.join(", ") || "no changes"}. Run 'descartes alerts digest' for details.`;
}

export function renderAlertDigest(digest) {
  const lines = [`Descartes digest ${digest.period.since} .. ${digest.period.until}`];
  if (digest.empty) {
    lines.push("Nothing changed state and nothing is open.");
    return lines.join("\n");
  }
  lines.push(digestSummaryLine(digest));
  if (digest.notifications?.corrupt) lines.push("- WARNING: notification outbox is corrupt; the daemon will quarantine and recover it on its next tick.");
  if (digest.notifications?.warning) lines.push(`- WARNING: notification outbox could not be read (${digest.notifications.warning.message}); the daemon left it unchanged and will retry.`);
  for (const closure of digest.closures) lines.push(`- closed ${closure.alert_id}${closure.incident_key ? `/${closure.incident_key}` : ""} (${closure.reason ?? "unknown"}${closure.source?.ref ? `, ${closure.source.kind} ${closure.source.ref}` : ""})`);
  for (const label of digest.labels.ingested) lines.push(`- label ${label.label} ${label.label_id} (charge ${label.charge}, ${label.effect})`);
  for (const held of digest.labels.held) lines.push(`- label ${held.label_id} held over budget since ${held.held_at} (charge ${held.charge})`);
  for (const alert of digest.open_event_alerts) lines.push(`- open event alert ${alert.alert_id} [${alert.rule_id}] since ${alert.since}`);
  for (const episode of digest.open_level_episodes) lines.push(`- open level episode ${episode.alert_id} [${episode.rule_id}] since ${episode.since}, ${episode.incidents} incident(s)${episode.running_extreme === null ? "" : `, running extreme ${episode.running_extreme}`}`);
  for (const storm of digest.storms.active) lines.push(`- incident storm on ${storm.alert_id} [${storm.rule_id}]: ${storm.incident_count} incidents`);
  for (const entry of digest.discontinuities) lines.push(`- pending journal discontinuity: ${entry.family} epoch ${entry.epoch} (${entry.cause})`);
  for (const range of digest.unadjudicated) lines.push(`- ${range.family}: passes ${range.pass_from}..${range.pass_to} excluded (${range.reason})`);
  for (const entry of digest.admission_suspended) lines.push(`- ${entry.family}: unattended admission suspended (${entry.reason})`);
  for (const gap of digest.integrity.transition_log.gaps) lines.push(`- transition log ${gap.kind}${gap.reason ? ` (${gap.reason})` : ""} at ${gap.ts}`);
  for (const notice of digest.integrity.active_notices) lines.push(`- integrity notice active: ${notice.rule_id}`);
  for (const notice of digest.notifications?.notices ?? []) lines.push(`- required notification ${notice.last_status ?? "pending"}: ${notice.title} [${notice.digest.slice(0, 16)}]`);
  if ((digest.notifications?.older_count ?? 0) > 0) lines.push(`- required notifications older/overflowed: ${digest.notifications.older_count}`);
  return lines.join("\n");
}

/**
 * The daemon's per-tick step: once a period has elapsed since the last one, build the digest for it,
 * write it, and push one summary notification if (and only if) it is not empty. The first run only
 * starts the clock. A failed push keeps the period open and retries hourly; it is never dropped.
 */
export async function maybeSendAlertDigest(descartesPaths, { now, deliverNotification, periodMs = DIGEST_PERIOD_MS } = {}) {
  const nowIso = new Date(now ?? Date.now()).toISOString();
  const { stateFile, digestsDir } = resolveAlertDigestPaths(descartesPaths);
  const state = await readJsonOrNull(stateFile);
  const last = typeof state?.last_period_end === "string" && Number.isFinite(Date.parse(state.last_period_end)) ? state.last_period_end : null;
  if (!last) {
    await atomicWrite(stateFile, JSON.stringify({ v: 1, last_period_end: nowIso }));
    return { status: "started" };
  }
  // A wall-clock rollback never stalls the digest: a last period end in the future restarts the clock.
  if (Date.parse(last) > Date.parse(nowIso)) {
    await atomicWrite(stateFile, JSON.stringify({ v: 1, last_period_end: nowIso, restarted_from: last }));
    return { status: "clock_rollback" };
  }
  if (Date.parse(nowIso) - Date.parse(last) < periodMs) return { status: "not_due" };
  if (typeof state?.retry_after === "string" && Date.parse(nowIso) < Date.parse(state.retry_after)) return { status: "retry_pending" };
  const digest = await buildAlertDigest(descartesPaths, { now: nowIso, since: last });
  const result = { status: digest.empty ? "empty" : "sent", counts: digest.counts };
  if (!digest.empty) {
    await fs.mkdir(digestsDir, { recursive: true, mode: 0o700 });
    await atomicWrite(path.join(digestsDir, `digest-${nowIso.replaceAll(":", "-")}.json`), JSON.stringify(digest, null, 2));
    const files = (await fs.readdir(digestsDir)).filter((name) => /^digest-.*\.json$/.test(name)).sort();
    for (const name of files.slice(0, Math.max(0, files.length - MAX_RETAINED_DIGESTS))) await fs.rm(path.join(digestsDir, name), { force: true });
    if (deliverNotification !== null) {
      try {
        const digestDecision = {
          notify: true,
          severity: "info",
          title: "Descartes digest",
          body: digestSummaryLine(digest),
        };
        const noticeOptions = { now: nowIso, ruleId: DIGEST_RULE_ID, required: true, requiredNoticeId: `${DIGEST_RULE_ID}:${last}`, allowCliOnly: true };
        if (deliverNotification) await queuePendingNotification(descartesPaths, digestDecision, noticeOptions);
        result.delivery = await (deliverNotification ?? deliverNotificationDecision)(descartesPaths, digestDecision, noticeOptions);
        if (deliverNotification && ["delivered", "cli_only"].includes(result.delivery?.status)) await resolvePendingNotification(descartesPaths, noticeOptions.requiredNoticeId, result.delivery.status, nowIso);
        if (["error", "disabled", "unavailable"].includes(result.delivery?.status)) result.delivery_error = result.delivery.error ?? result.delivery.reason ?? result.delivery.status;
      } catch (error) {
        result.delivery_error = error instanceof Error ? error.message : String(error);
      }
    }
  }
  if (result.delivery_error) {
    // A failed push is retried (hourly), never dropped: the period does not advance until it lands.
    result.status = result.delivery?.status === "disabled" || result.delivery?.status === "unavailable" ? "delivery_pending" : "delivery_failed";
    await atomicWrite(stateFile, JSON.stringify({ v: 1, last_period_end: last, last_status: result.status, retry_after: new Date(Date.parse(nowIso) + DIGEST_RETRY_MS).toISOString() }));
    return result;
  }
  await atomicWrite(stateFile, JSON.stringify({ v: 1, last_period_end: nowIso, last_status: result.status }));
  return result;
}
