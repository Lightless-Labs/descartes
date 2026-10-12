// Context plan C1.4: the daemon's side of the pending journal. Kept out of daemon.js so the tick
// only calls two seams: runPendingJournalPrePass (after the fact commit, before detection) and
// finishPendingJournalTick (after alerts.json and the transition log: the watermark and checkpoint).
//
// Every failure is contained per family and reported; nothing here can fail a tick, change which
// alerts fire, or delay a notification.
import { readAlertTransitions } from "./alert-transitions.js";
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

async function journalWitness(descartesPaths, family) {
  try {
    const log = await readAlertTransitions(descartesPaths);
    return log.records.some((record) => record.kind === "pending_journal_created" && record.family === family);
  } catch {
    return false;
  }
}

// One integrity notice per epoch (I54 step 5), outside any attention budget. Whoever opens the epoch
// (the pre-pass, or label ingestion opening a journal on its own) sends it.
export async function deliverPendingDiscontinuityNotice(descartesPaths, { family, cause, ts, deliverNotification } = {}) {
  try {
    await (deliverNotification ?? deliverNotificationDecision)(descartesPaths, {
      notify: true,
      severity: "warning",
      title: "Descartes: pending journal discontinuity",
      body: `The ${family} pending journal lost continuity (${cause}); unattended admission is suspended for it until re-certification. Detection is unaffected.`,
    }, { now: ts, ruleId: PENDING_DISCONTINUITY_NOTICE_ID });
    return { notified: true };
  } catch (error) {
    return { notified: false, notify_error: errorMessage(error) };
  }
}

export async function runPendingJournalPrePass(descartesPaths, { structuralFacts, ts, deliverNotification, families = PENDING_JOURNAL_FAMILIES } = {}) {
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
        witnessExists: () => journalWitness(descartesPaths, family),
        // The census completeness this exit needs is the family's own certified, non-empty commit;
        // C1a, which journals verdicts, tightens it to its detectors' census completeness.
        censusComplete: (passResult.written_count ?? 0) > 0,
      });
      results[family] = { handle, report, ledger, passId: passResult.retention?.pass_id ?? null };
      if (report.discontinuity) {
        Object.assign(report, await deliverPendingDiscontinuityNotice(descartesPaths, { family, cause: report.discontinuity.cause, ts, deliverNotification }));
      }
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
