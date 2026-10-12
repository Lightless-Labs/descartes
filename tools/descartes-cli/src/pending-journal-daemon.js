// Context plan C1.4: the daemon's side of the pending journal. Kept out of daemon.js so the tick
// only calls two seams: runPendingJournalPrePass (after the fact commit, before detection) and
// finishPendingJournalTick (after alerts.json and the transition log: the watermark and checkpoint).
//
// Every failure is contained per family and reported; nothing here can fail a tick, change which
// alerts fire, or delay a notification: the pre-pass, which runs before detection, never delivers
// anything; its discontinuity notices go out after detection (deliverPendingJournalNotices, review L2).
import { labelQuarantineScopes } from "./alert-labels.js";
import { readAlertTransitionWitness } from "./alert-transitions.js";
import { readFactIntegrityLedger } from "./fact-store-integrity.js";
import { deliverNotificationDecision } from "./notification-delivery.js";
import { journalCommittedPass, journalScoredThrough, pendingAdmissionStatus, PENDING_JOURNAL_FAMILIES } from "./pending-journal.js";

// The detector labels (daemon.js safeCandidates) that score each journaled family.
export const DETECTOR_LABELS_BY_FAMILY = Object.freeze({
  session: Object.freeze(["session"]),
  peer: Object.freeze(["peer"]),
  service: Object.freeze(["service", "service-appearance"]),
  process_lineage: Object.freeze(["process-lineage"]),
  scheduled_job: Object.freeze(["scheduled-job"]),
});

export const PENDING_DISCONTINUITY_NOTICE_ID = "integrity.pending_discontinuity";

function errorMessage(error) {
  return (error instanceof Error ? error.message : String(error)) || "unknown pending-journal error";
}

// The transition log's witness for a family's journal (review M3): its creation and the epochs it
// saw, from the log's records, its compaction header, any restart record and its state file.
export async function journalWitness(descartesPaths, family) {
  try {
    const entry = (await readAlertTransitionWitness(descartesPaths)).pending_journals[family];
    return { exists: entry?.created === true, epochs: entry?.epochs ?? [] };
  } catch {
    return { exists: false, epochs: [] };
  }
}

// One integrity notice per epoch (I54 step 5), outside any attention budget. Whoever opens the epoch
// (the pre-pass, or label ingestion opening a journal on its own) sends it.
// A delivery that returned a failure status was not notified (review L2). No per-notice retry is kept
// across ticks: the digest lists every open epoch and retries its own push until it is delivered.
const FAILED_DELIVERY_STATUSES = new Set(["error", "unavailable"]);

export function notificationOutcome(result) {
  const status = typeof result?.status === "string" ? result.status : null;
  if (status && FAILED_DELIVERY_STATUSES.has(status)) return { notified: false, notify_status: status, notify_error: typeof result.error === "string" ? result.error : (result.reason ?? status) };
  return { notified: true, notify_status: status };
}

export async function deliverPendingDiscontinuityNotice(descartesPaths, { family, cause, ts, deliverNotification } = {}) {
  try {
    const result = await (deliverNotification ?? deliverNotificationDecision)(descartesPaths, {
      notify: true,
      severity: "warning",
      title: "Descartes: pending journal discontinuity",
      body: `The ${family} pending journal lost continuity (${cause}); unattended admission is suspended for it until re-certification. Detection is unaffected.`,
    }, { now: ts, ruleId: PENDING_DISCONTINUITY_NOTICE_ID });
    return notificationOutcome(result);
  } catch (error) {
    return { notified: false, notify_status: "error", notify_error: errorMessage(error) };
  }
}

/** After detection: one notice per epoch the pre-pass opened. Returns the per-family outcomes. */
export async function deliverPendingJournalNotices(descartesPaths, prePass, { ts, deliverNotification } = {}) {
  const outcomes = [];
  for (const [family, result] of Object.entries(prePass?.families ?? {})) {
    const report = result?.report;
    if (!report?.discontinuity) continue;
    const outcome = await deliverPendingDiscontinuityNotice(descartesPaths, { family, cause: report.discontinuity.cause, ts, deliverNotification });
    Object.assign(report, outcome);
    outcomes.push({ family, ...outcome });
  }
  return outcomes;
}

export async function runPendingJournalPrePass(descartesPaths, { structuralFacts, ts, families = PENDING_JOURNAL_FAMILIES } = {}) {
  const results = {};
  for (const family of families) {
    const passResult = structuralFacts?.families?.[family];
    if (!passResult) continue;
    try {
      const { ledger } = await readFactIntegrityLedger(descartesPaths, family);
      const { handle, report } = await journalCommittedPass(descartesPaths, family, {
        passResult,
        ledger,
        ts,
        witnessExists: async () => (await journalWitness(descartesPaths, family)).exists,
        priorEpochs: async () => (await journalWitness(descartesPaths, family)).epochs,
        // Review L4: the label log's quarantines, re-applied at a chain-level loss.
        quarantineScopes: () => labelQuarantineScopes(descartesPaths),
        // The census completeness this exit needs is the family's own certified, non-empty commit;
        // C1a, which journals verdicts, tightens it to its detectors' census completeness.
        censusComplete: (passResult.written_count ?? 0) > 0,
      });
      results[family] = { handle, report, ledger, passId: passResult.retention?.pass_id ?? null };
    } catch (error) {
      // Fail closed for the family: no admission can happen from an unreadable/unwritable journal,
      // and detection carries on. The next tick re-reads; a missed mapping becomes an explicit range.
      results[family] = { error: errorMessage(error), report: { family, status: "error", error: errorMessage(error) } };
      console.warn(`descartes: pending journal (${family}) pre-pass failed (${errorMessage(error)}); detection is unaffected`);
    }
  }
  return { families: results };
}

/** Audit records for the transition log, from this tick's pre-pass reports. */
export function pendingJournalAuditRecords(prePass) {
  const records = [];
  for (const [family, result] of Object.entries(prePass?.families ?? {})) {
    const report = result.report ?? {};
    if (report.created) records.push({ kind: "pending_journal_created", family });
    if (report.discontinuity) records.push({ kind: "pending_discontinuity", family, epoch: report.discontinuity.epoch, cause: report.discontinuity.cause });
    if (report.recertified) records.push({ kind: "recertified", family, epoch: report.recertified });
    if (report.excluded_ranges > 0) records.push({ kind: "excluded_unadjudicated", family, ranges: report.excluded_ranges });
    if (report.status === "error") records.push({ kind: "pending_journal_error", family });
  }
  return records;
}

export async function finishPendingJournalTick(descartesPaths, prePass, { ts, alertsPersisted, failedDetectorLabels = new Set() } = {}) {
  const summary = {};
  for (const [family, result] of Object.entries(prePass?.families ?? {})) {
    if (!result.handle) {
      summary[family] = { status: "error", error: result.error };
      continue;
    }
    const failed = (DETECTOR_LABELS_BY_FAMILY[family] ?? []).some((label) => failedDetectorLabels.has(label));
    try {
      const outcome = await journalScoredThrough(descartesPaths, result.handle, {
        ledger: result.ledger,
        passId: result.passId,
        scored: alertsPersisted && !failed,
        ts,
      });
      summary[family] = {
        status: result.report.status === "discontinuity" ? "discontinuity" : "ok",
        watermark: outcome.watermark,
        admission: outcome.admission,
        open_epoch: result.handle.state.open_epoch,
        ...(result.report.discontinuity ? { discontinuity: result.report.discontinuity } : {}),
      };
    } catch (error) {
      summary[family] = { status: "error", error: errorMessage(error), admission: pendingAdmissionStatus(result.handle.state, ts) };
      console.warn(`descartes: pending journal (${family}) watermark/checkpoint failed (${errorMessage(error)}); detection is unaffected`);
    }
  }
  return summary;
}
