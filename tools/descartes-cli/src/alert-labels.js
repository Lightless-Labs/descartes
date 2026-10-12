// Context plan C1.3 (§9, I27, I62; open item 15): the OPTIONAL label log.
//
// Labels are optional input (D5): nothing in Descartes depends on them. Without labels, items stay
// pending, alerts stay open and silent after their one notification, and learning proceeds by
// earned promotion. A label only accelerates or corrects.
//
// Writers and readers:
//   - the CLI (`descartes alerts label ...`) appends to stateDir/alerts/labels.jsonl. It never writes
//     alerts.json, the transition log or the pending journal;
//   - the daemon ingests each label ONCE, by id, on its next tick (stateDir/alerts/labels.state.json
//     records what it ingested and what it holds), applies its effect, logs `label_ingested` /
//     `label_held` in the transition log and notifies the ingested batch.
//
// The label-poisoning bound (I27; item 15). Labels are same-UID writes, so they are forgeable:
//   - the budget charges COVERAGE, not label count: a label is charged the number of incidents (or
//     pending items) its scope resolves to at ingestion, at least 1. One bulk label over a window
//     costs what it covers;
//   - a label whose charge does not fit the trailing-window budget is HELD WHOLE, never partially
//     applied, and raises a notice. Held labels are retried every tick, oldest first, and a held
//     label is released as soon as its charge fits the trailing window (a label whose charge alone
//     exceeds the whole budget therefore stays held, visibly, and is listed by the digest);
//   - a label closure never cancels an undelivered incident: it waits for delivery (alert-store
//     requestAlertClosure);
//   - a quarantining label never silences a present condition: LEVEL episodes and NOVELTY alerts
//     stay open on suspicious/confirmed_incident;
//   - every ingested label is notified, and every closure lists its label id.
//   The second half of item 15 (labels bypassing the §6.3.2 vetoes) has no object before C7a, where
//   vetoes exist; C1 records that on-host labels must not lift them (plan C1 addendum).
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { isUndeliverableStatus, readAlertRecords, requestAlertClosure, writeAlertRecords } from "./alert-store.js";
import { streamKindForRule } from "./alert-stream-kinds.js";
import { readAlertTransitionWitness, WITNESS_LABEL_MEMORY_MS } from "./alert-transitions.js";
import { RULE_HORIZONS } from "./fact-families.js";
import { atomicWrite, readJsonlStrict } from "./hash-chain.js";
import { appendPendingEntries, openPendingJournal, PENDING_JOURNAL_FAMILIES, pendingItemId } from "./pending-journal.js";

export const ALERT_LABELS = Object.freeze(["benign", "suspicious", "expected", "mine", "confirmed_incident", "missed_incident"]);
const LABEL_SET = new Set(ALERT_LABELS);
const ADMISSIBLE_LABELS = new Set(["benign", "expected", "mine"]);
const QUARANTINE_LABELS = new Set(["suspicious", "confirmed_incident"]);
export const LABEL_SCHEMA_VERSION = 1;
export const LABEL_NOTICE_RULE_ID = "descartes.labels";

// §16.1 (O): the label budget, in coverage units per trailing window.
export const LABEL_BUDGET_UNITS = 50;
export const LABEL_BUDGET_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
// C1 addendum (S): how long ingested-label ids are remembered, and the label log's size bound
// (the CLI prunes ingested-age entries beyond it).
export const LABEL_MEMORY_MS = WITNESS_LABEL_MEMORY_MS;
export const MAX_LABEL_LOG_BYTES = 1024 * 1024;
export const MAX_LABEL_RETRIES = 3;
export const LABEL_RETRY_DELAY_MS = 60_000;

const ALERT_ID_RE = /^alert_[0-9a-f]{16}$/;
const INCIDENT_KEY_RE = /^(?:[A-Za-z0-9._:-]{1,128}|sha256:[0-9a-f]{64})$/;
const LABEL_ID_RE = /^[0-9a-f-]{36}$/;

export function resolveAlertLabelPaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "alerts");
  return { dir, logFile: path.join(dir, "labels.jsonl"), stateFile: path.join(dir, "labels.state.json") };
}

function isoOrNull(value) {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** Strict validation; returns the normalized label or null. No free text survives. */
export function normalizeLabelRecord(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (raw.v !== LABEL_SCHEMA_VERSION || !LABEL_ID_RE.test(String(raw.id ?? "")) || !LABEL_SET.has(raw.label)) return null;
  const ts = isoOrNull(raw.ts);
  if (!ts) return null;
  const scope = raw.scope;
  let normalizedScope = null;
  if (scope?.kind === "alert" && ALERT_ID_RE.test(String(scope.alert_id ?? ""))) {
    const keys = scope.incident_keys === undefined ? undefined : (Array.isArray(scope.incident_keys) ? scope.incident_keys : null);
    if (keys === null || (keys && (keys.length === 0 || keys.length > 256 || !keys.every((key) => typeof key === "string" && INCIDENT_KEY_RE.test(key))))) return null;
    normalizedScope = { kind: "alert", alert_id: scope.alert_id, ...(keys ? { incident_keys: [...new Set(keys)].sort() } : {}) };
  } else if (scope?.kind === "pending_window" && PENDING_JOURNAL_FAMILIES.includes(scope.family)) {
    const from = isoOrNull(scope.from_ts);
    const to = isoOrNull(scope.to_ts);
    if (!from || !to || Date.parse(from) > Date.parse(to)) return null;
    normalizedScope = { kind: "pending_window", family: scope.family, from_ts: from, to_ts: to };
  }
  if (!normalizedScope) return null;
  const uid = Number.isSafeInteger(raw.source?.uid) ? raw.source.uid : null;
  return { v: LABEL_SCHEMA_VERSION, id: raw.id, ts, label: raw.label, scope: normalizedScope, source: { kind: "cli", uid } };
}

export async function readAlertLabels(descartesPaths) {
  const { logFile } = resolveAlertLabelPaths(descartesPaths);
  const read = await readJsonlStrict(logFile, { maxBytes: MAX_LABEL_LOG_BYTES, maxLines: 20000 });
  if (!read.exists) return { labels: [], invalid: 0, tamper: null };
  const labels = [];
  let invalid = 0;
  const seen = new Set();
  for (const parsed of read.records) {
    const label = normalizeLabelRecord(parsed);
    if (!label || seen.has(label.id)) {
      invalid += 1;
      continue;
    }
    seen.add(label.id);
    labels.push(label);
  }
  const tamper = read.exceeded ? { kind: "label_log_read_cap", bytes: read.bytes } : (read.bad_line !== null ? { kind: "label_log_unparseable", line: read.bad_line } : null);
  if (tamper) invalid += 1;
  return { labels, invalid, tamper };
}

/** The quarantining labels in the log (review L4), as scopes a discontinuity re-applies. Never throws. */
export async function labelQuarantineScopes(descartesPaths, { now } = {}) {
  try {
    const nowMs = Date.parse(new Date(now ?? Date.now()).toISOString());
    const { labels } = await readAlertLabels(descartesPaths);
    // A future-dated label is not yet in force (review L5), here as at ingestion.
    return labels.filter((label) => QUARANTINE_LABELS.has(label.label) && Date.parse(label.ts) <= nowMs).map((label) => ({ label_id: label.id, ts: label.ts, scope: label.scope }));
  } catch {
    return [];
  }
}

/**
 * CLI append. Validates, re-reads the log before appending (pruning entries older than the label
 * memory once the log is past its size bound), and appends one line. Never touches alerts.json.
 */
export async function appendAlertLabel(descartesPaths, { label, scope, now, uid } = {}) {
  const ts = new Date(now ?? Date.now()).toISOString();
  const record = normalizeLabelRecord({
    v: LABEL_SCHEMA_VERSION,
    id: crypto.randomUUID(),
    ts,
    label,
    scope,
    source: { kind: "cli", uid: uid ?? (typeof process.getuid === "function" ? process.getuid() : null) },
  });
  if (!record) throw new Error("Invalid label: expected a known label and an alert id (alert_<16 hex>) with optional incident keys, or a pending window");
  const { dir, logFile } = resolveAlertLabelPaths(descartesPaths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    const stat = await fs.stat(logFile);
    if (stat.size > MAX_LABEL_LOG_BYTES) {
      const { labels } = await readAlertLabels(descartesPaths);
      const cutoff = Date.parse(ts) - LABEL_MEMORY_MS;
      await atomicWrite(logFile, labels.filter((entry) => Date.parse(entry.ts) >= cutoff).map((entry) => `${JSON.stringify(entry)}\n`).join(""));
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await fs.appendFile(logFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return record;
}

// ------------------------------------------------------------------------------------------------
// Daemon ingestion
// ------------------------------------------------------------------------------------------------

async function readIngestionState(stateFile) {
  try {
    const parsed = JSON.parse(await fs.readFile(stateFile, "utf8"));
    if (parsed?.v !== LABEL_SCHEMA_VERSION || typeof parsed.ingested !== "object" || !Array.isArray(parsed.held)) return { status: "invalid", state: { v: LABEL_SCHEMA_VERSION, ingested: {}, held: [], failed: [] } };
    return { status: "valid", state: { ...parsed, failed: Array.isArray(parsed.failed) ? parsed.failed : [] } };
  } catch (error) {
    return { status: error?.code === "ENOENT" ? "missing" : "invalid", state: { v: LABEL_SCHEMA_VERSION, ingested: {}, held: [], failed: [] } };
  }
}

function familiesForRule(ruleId) {
  return (RULE_HORIZONS.get(ruleId)?.families ?? []).filter((family) => PENDING_JOURNAL_FAMILIES.includes(family));
}

/** The incidents an alert-scoped label resolves to: the named keys that exist, else every incident. */
function scopedIncidentKeys(alert, scope) {
  const existing = Object.keys(alert?.incidents ?? {});
  return scope.incident_keys ? scope.incident_keys.filter((key) => existing.includes(key)) : existing;
}

// Review L5: a label speaks about what existed when it was written. It never reaches an alert episode
// or a pending item that started after its own timestamp.
function predatesEpisode(alert, label) {
  return Boolean(alert?.episode_started_at) && Date.parse(alert.episode_started_at) > Date.parse(label.ts);
}

function pendingItemsInScope(handles, label, alertsById) {
  const scope = label.scope;
  const matches = [];
  for (const [family, handle] of Object.entries(handles)) {
    for (const [id, item] of Object.entries(handle?.state?.items ?? {})) {
      if (!["pending", "admitted"].includes(item.state)) continue;
      if (Date.parse(item.opened_ts ?? "") > Date.parse(label.ts)) continue;
      if (scope.kind === "alert") {
        if (item.item?.alert_id !== scope.alert_id) continue;
        if (scope.incident_keys && !scope.incident_keys.includes(item.item?.incident_key)) continue;
        if (!familiesForRule(alertsById.get(scope.alert_id)?.rule_id).includes(family)) continue;
      } else {
        if (family !== scope.family) continue;
        const opened = Date.parse(item.opened_ts ?? "");
        if (!(opened >= Date.parse(scope.from_ts) && opened <= Date.parse(scope.to_ts))) continue;
      }
      matches.push({ family, id });
    }
  }
  return matches;
}

/**
 * Charge (item 15): the number of things the label's scope resolves to at ingestion -- incidents of
 * the alert, plus pending items it would mark -- never less than 1, so even a label that resolves to
 * nothing is not free.
 */
export function labelCharge(label, alertsById, handles) {
  const items = pendingItemsInScope(handles, label, alertsById).length;
  const alert = label.scope.kind === "alert" ? alertsById.get(label.scope.alert_id) : null;
  const incidents = alert && !predatesEpisode(alert, label) ? scopedIncidentKeys(alert, label.scope).length : 0;
  return Math.max(1, Math.max(incidents, items));
}

function consumedInWindow(state, nowMs) {
  return Object.values(state.ingested)
    .filter((entry) => nowMs - Date.parse(entry.ingested_at) <= LABEL_BUDGET_WINDOW_MS)
    .reduce((sum, entry) => sum + (entry.charge ?? 0), 0);
}

// The alert-side effect, fixed by §6.0 and the stream kind (I42, I56). Pure.
function applyLabelToAlert(alert, label, now) {
  const kind = streamKindForRule(alert.rule_id);
  const keys = scopedIncidentKeys(alert, label.scope);
  const none = { alert, closed: [], deferred: [], skipped: keys, effect: "none" };
  if (label.label === "missed_incident") return { ...none, effect: "recall_only" };
  if (predatesEpisode(alert, label)) return { ...none, effect: "predates_episode" };
  if (!kind) return { ...none, effect: "undeclared_kind" };
  // An incumbent LEVEL episode stays open under every label (C1a, §6.5); a NOVELTY alert stays
  // active under a quarantining label while its entity is present (I74).
  if (kind === "level") return { ...none, effect: "level_episode_stays_open" };
  if (kind === "novelty" && QUARANTINE_LABELS.has(label.label)) return { ...none, effect: "present_condition_stays_open" };
  if (isUndeliverableStatus(alert.status)) return { ...none, effect: "alert_not_open" };
  const result = requestAlertClosure(alert, {
    incidentKeys: keys,
    reason: "label",
    now,
    by: { kind: "label", ref: label.id },
    closeAlert: label.scope.incident_keys === undefined,
  });
  return { ...result, effect: "closure_requested" };
}

/**
 * The daemon's per-tick ingestion. `handles` are the pending-journal handles this tick already
 * opened (so label entries extend the same chain); missing families are opened here. Returns
 * { ingested: [...], held: [...], released: [...], audit (transition records), notice }.
 */
export async function ingestAlertLabels(descartesPaths, { now, handles = {}, ledgers = {}, deps = {} } = {}) {
  const ts = new Date(now ?? Date.now()).toISOString();
  const nowMs = Date.parse(ts);
  const { stateFile } = resolveAlertLabelPaths(descartesPaths);
  const labelRead = await readAlertLabels(descartesPaths);
  const { labels, invalid } = labelRead;
  const stateRead = await readIngestionState(stateFile);
  const state = stateRead.state;
  // Review M1: labels.state.json is unchained, so what was ingested (and charged) is rebuilt from the
  // transition log's witness of chained label_ingested records. A deleted or edited state can then
  // neither reset the label budget nor re-ingest a label.
  let rebuiltFromWitness = 0;
  let witness = null;
  if (labels.length > 0 || Object.keys(state.ingested).length > 0) {
    try {
      witness = await (deps.readAlertTransitionWitness ?? readAlertTransitionWitness)(descartesPaths);
    } catch {
      witness = null;
    }
    for (const [id, entry] of Object.entries(witness?.labels ?? {})) {
      const local = state.ingested[id];
      if (local && (local.ingested_at !== entry.ingested_at || local.charge !== entry.charge || local.label !== entry.label)) {
        state.__witnessConflicts ??= [];
        state.__witnessConflicts.push({ kind: "unattributed_change", label_id: id, field: local.charge !== entry.charge ? "charge" : (local.ingested_at !== entry.ingested_at ? "ingested_at" : "label"), digest: crypto.createHash("sha256").update(JSON.stringify(local)).digest("hex") });
      }
      if (!local || local.ingested_at !== entry.ingested_at || local.charge !== entry.charge || local.label !== entry.label) rebuiltFromWitness += 1;
      state.ingested[id] = { ingested_at: entry.ingested_at, charge: entry.charge ?? 0, label: entry.label ?? null, from_witness: true };
    }
  }
  const heldIds = new Set(state.held.map((entry) => entry.id));
  const failedById = new Map((state.failed ?? []).map((entry) => [entry.id, entry]));
  // A future-dated label waits for its own time (review L5: it could otherwise reach any later episode).
  const fresh = labels.filter((label) => !state.ingested[label.id] && !heldIds.has(label.id) && !failedById.get(label.id)?.exhausted && Date.parse(label.ts) <= nowMs && nowMs - Date.parse(label.ts) <= LABEL_MEMORY_MS);
  const retryable = labels.filter((label) => {
    const failed = failedById.get(label.id);
    return failed && !failed.exhausted && Date.parse(failed.retry_at ?? "") <= nowMs;
  });
  const labelById = new Map(labels.map((label) => [label.id, label]));
  const queue = [...state.held.map((entry) => labelById.get(entry.id)).filter(Boolean), ...retryable, ...fresh.sort((a, b) => a.ts.localeCompare(b.ts) || a.id.localeCompare(b.id))]
    .filter((label, index, all) => all.findIndex((candidate) => candidate.id === label.id) === index);
  const report = { ingested: [], held: [], released: [], invalid, state: stateRead.status, audit: [], discontinuities: [], tamper: labelRead.tamper };
  if (labelRead.tamper) report.audit.push({ ...labelRead.tamper, kind: "unattributed_change", source: "labels.jsonl" });
  for (const conflict of state.__witnessConflicts ?? []) report.audit.push(conflict);
  delete state.__witnessConflicts;
  // A missing state with nothing to rebuild is a first use; a state that is invalid, or missing while
  // the witness proves ingestions, was lost: audited and notified.
  const stateLost = labels.length > 0 && (stateRead.status === "invalid" || (stateRead.status === "missing" && rebuiltFromWitness > 0));
  if (stateLost) {
    report.audit.push({ kind: "label_state_rebuilt", state: stateRead.status, rebuilt_from_witness: rebuiltFromWitness });
  }
  if (labelRead.tamper) return report;
  if (queue.length === 0 && stateRead.status === "valid" && report.audit.length === 0) return report;

  let alerts = await (deps.readAlertRecords ?? readAlertRecords)(descartesPaths);
  const alertsById = () => new Map(alerts.map((alert) => [alert.id, alert]));
  let alertsChanged = false;
  const stillHeld = [];
  let blocked = false;
  for (const label of queue) {
    const wasHeld = heldIds.has(label.id);
    const byId = alertsById();
    // Families this label touches: open their journals now if this tick has not.
    const families = label.scope.kind === "alert" ? familiesForRule(byId.get(label.scope.alert_id)?.rule_id) : [label.scope.family];
    for (const family of families) {
      if (!handles[family]) {
        try {
          // The same double-wipe witness and epochs the pre-pass consults (review M3).
          const journalWitness = witness?.pending_journals?.[family];
          handles[family] = await (deps.openPendingJournal ?? openPendingJournal)(descartesPaths, family, { ledger: ledgers[family] ?? null, now: ts, witnessExists: journalWitness?.created === true, priorEpochs: journalWitness?.epochs ?? [],
            quarantineScopes: labels.filter((entry) => QUARANTINE_LABELS.has(entry.label) && Date.parse(entry.ts) <= nowMs).map((entry) => ({ label_id: entry.id, ts: entry.ts, scope: entry.scope })) });
          // A journal this ingestion creates is witnessed like one the pre-pass creates.
          if (handles[family]?.created) report.audit.push({ kind: "pending_journal_created", family, opened_by: "label_ingestion" });
          // Opening a journal can itself detect a discontinuity: it must be audited and notified
          // exactly like one the pre-pass finds (the epoch re-certifies at the next clean pass).
          if (handles[family]?.discontinuity) {
            const { epoch, cause } = handles[family].discontinuity;
            report.discontinuities.push({ family, epoch, cause });
            report.audit.push({ kind: "pending_discontinuity", family, epoch, cause, opened_by: "label_ingestion" });
          }
        } catch {
          handles[family] = null;
        }
      }
    }
    const charge = labelCharge(label, byId, handles);
    const remaining = LABEL_BUDGET_UNITS - consumedInWindow(state, nowMs);
    // Oldest first: once one label is held, every later one waits behind it (no reordering by size).
    if (blocked || charge > remaining) {
      blocked = true;
      const heldAt = state.held.find((entry) => entry.id === label.id)?.held_at ?? ts;
      stillHeld.push({ id: label.id, held_at: heldAt, charge });
      if (!wasHeld) {
        report.held.push({ id: label.id, label: label.label, charge, remaining });
        report.audit.push({ kind: "label_held", label_id: label.id, label: label.label, charge, budget_remaining: Math.max(0, remaining) });
      }
      continue;
    }
    // Apply the restrictive journal effect first. Alert closure and label ingestion are committed
    // only after every family append for this label succeeds. A journal write failure leaves the
    // label un-ingested and retryable, so it cannot close an alert without quarantine evidence.
    const pendingEffects = new Map();
    let journalFailed = null;
    for (const { family, id } of pendingItemsInScope(handles, label, byId)) {
      const handle = handles[family];
      if (!handle) continue;
      const entry = QUARANTINE_LABELS.has(label.label)
        ? { kind: "quarantined", item_id: id, reason: "label", label_id: label.id }
        : (ADMISSIBLE_LABELS.has(label.label) ? { kind: "label_marked", item_id: id, label_id: label.id, label: label.label } : null);
      if (!entry) continue;
      const effects = pendingEffects.get(family) ?? [];
      effects.push({ id, entry });
      pendingEffects.set(family, effects);
    }
    for (const [family, effects] of pendingEffects) {
      try {
        await (deps.appendPendingEntries ?? appendPendingEntries)(descartesPaths, handles[family], effects.map((effect) => effect.entry), { now: ts, restrictiveOnly: true });
      } catch (error) {
        journalFailed = error;
        break;
      }
    }
    if (journalFailed) {
      const previous = failedById.get(label.id);
      const attempts = (previous?.attempts ?? 0) + 1;
      const exhausted = attempts >= MAX_LABEL_RETRIES;
      const failure = { id: label.id, attempts, exhausted, retry_at: new Date(nowMs + LABEL_RETRY_DELAY_MS * Math.min(2 ** (attempts - 1), 60)).toISOString(), error: String(journalFailed?.message ?? journalFailed) };
      failedById.set(label.id, failure);
      report.audit.push({ kind: "label_retry_failed", label_id: label.id, attempts, exhausted, error: failure.error });
      continue;
    }

    // Only now apply the alert-side effect and mark the label ingested.
    let alertEffect = { closed: [], deferred: [], skipped: [], effect: "none" };
    if (label.scope.kind === "alert") {
      const alert = byId.get(label.scope.alert_id);
      if (alert) {
        alertEffect = applyLabelToAlert(alert, label, ts);
        if (alertEffect.alert !== alert) {
          alerts = alerts.map((entry) => (entry.id === alert.id ? alertEffect.alert : entry));
          alertsChanged = true;
        }
      } else {
        alertEffect = { closed: [], deferred: [], skipped: [], effect: "unknown_alert" };
      }
    }
    const journalEffects = [...pendingEffects.entries()].flatMap(([family, effects]) => effects.map(({ id, entry }) => ({ family, item_id: id, kind: entry.kind })));
    state.ingested[label.id] = { ingested_at: ts, charge, label: label.label };
    failedById.delete(label.id);
    const summary = {
      id: label.id,
      label: label.label,
      charge,
      effect: alertEffect.effect,
      closed: alertEffect.closed.length,
      deferred: alertEffect.deferred.length,
      journal: journalEffects.length,
    };
    report.ingested.push(summary);
    if (wasHeld) report.released.push(label.id);
    report.audit.push({
      kind: "label_ingested",
      label_id: label.id,
      label: label.label,
      scope_kind: label.scope.kind,
      ...(label.scope.kind === "alert" ? { alert_id: label.scope.alert_id } : { family: label.scope.family }),
      charge,
      effect: alertEffect.effect,
      closed_incidents: alertEffect.closed,
      deferred_incidents: alertEffect.deferred,
      journal_effects: journalEffects.length,
      ...(wasHeld ? { released_from_hold: true } : {}),
    });
    for (const incidentKey of alertEffect.closed) {
      report.audit.push({ kind: "closure_authorized", alert_id: label.scope.alert_id, incident_key: incidentKey, reason: "label", label_id: label.id });
    }
  }
  state.held = stillHeld;
  state.failed = [...failedById.values()].slice(-MAX_LABEL_RETRIES * 256);
  // Remember ingested ids for the label memory; the label log is what proves a label existed.
  for (const [id, entry] of Object.entries(state.ingested)) {
    if (nowMs - Date.parse(entry.ingested_at) > LABEL_MEMORY_MS) delete state.ingested[id];
  }
  if (alertsChanged) await (deps.writeAlertRecords ?? writeAlertRecords)(descartesPaths, alerts);
  await atomicWrite(stateFile, JSON.stringify({ ...state, updated_at: ts }));
  const retryFailures = report.audit.filter((record) => record.kind === "label_retry_failed");
  if (report.ingested.length > 0 || report.held.length > 0 || retryFailures.length > 0 || stateLost) {
    const closed = report.ingested.reduce((sum, entry) => sum + entry.closed, 0);
    const deferred = report.ingested.reduce((sum, entry) => sum + entry.deferred, 0);
    report.notice = {
      notify: true,
      severity: report.held.length > 0 || retryFailures.length > 0 || stateLost ? "warning" : "info",
      title: report.held.length > 0 ? "Descartes: label budget exceeded" : (retryFailures.length > 0 ? "Descartes: label quarantine retry pending" : (stateLost ? "Descartes: label state rebuilt" : "Descartes: labels ingested")),
      body: `${report.ingested.length} label${report.ingested.length === 1 ? "" : "s"} ingested (${closed} incident closure${closed === 1 ? "" : "s"}, ${deferred} waiting for delivery); ${report.held.length} held over the label budget; ${retryFailures.length} quarantine write retr${retryFailures.length === 1 ? "y" : "ies"} failed.${stateLost ? ` The label state was ${stateRead.status}; ${rebuiltFromWitness} ingestion${rebuiltFromWitness === 1 ? "" : "s"} rebuilt from the transition log.` : ""}`,
    };
  }
  return report;
}
