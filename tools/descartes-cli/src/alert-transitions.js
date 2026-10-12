// Context plan C1.1 (§9): the append-only, hash-chained alert transition log
// (stateDir/alerts/alert-transitions.jsonl). The daemon is its ONLY writer; the CLI never writes it.
//
// Each daemon tick diffs the persisted alert store against the projection the log last recorded
// (alert-transitions.state.json, stamped with the log head) and appends the transitions it finds:
// activated, incident_opened, escalated, incident_reopened, incident_closed(reason),
// alert_closed(reason), recovered (reason edge_rearm for the I42 exception), acknowledged (a CLI ack
// observed on the daemon's next read), incident_storm, incident_storm_exited, tombstones_dropped. The
// daemon also appends audit records here (label_ingested, label_held, pending_discontinuity, ...).
//
// It is an AUDIT TRAIL, never the source of pending membership (the pending journal is, §6.4.2).
// `activated` is one alert-level transition into an active state per episode (not a newEpisode
// record and not an incident), so calibration can count fired episodes exactly (C1.2, M1).
//
// Coverage is explicit: `genesis` (first run over an existing store: no activations are invented for
// alerts that were already active), `rebaselined` (the projection could not be continued) and
// `chain_restart` (a broken or deleted log; the broken file is kept aside) mark points before which
// counts are lower bounds. Compaction keeps a cut header at the head of the file.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { normalizeAlertRecord, readAlertRecords, writeAlertRecords } from "./alert-store.js";
import { EDGE_REARM_RULE_IDS } from "./alert-stream-kinds.js";
import { appendLines, atomicWrite, canonicalJson, GENESIS_PREV_HASH, readJsonlStrict, sealRecord, trimTornTail, verifyChain } from "./hash-chain.js";

export const ALERT_TRANSITION_DOMAIN = "descartes.alert_transition.v1";
export const ALERT_TRANSITIONS_SCHEMA_VERSION = 1;
// §16.1 addendum (S): the transition log's byte cap. Compaction keeps the newest half.
export const MAX_ALERT_TRANSITIONS_BYTES = 8 * 1024 * 1024;

export const COVERAGE_GAP_KINDS = Object.freeze(new Set(["genesis", "rebaselined", "chain_restart"]));
// The witness keeps, per pending-journal family, the epochs it saw (the newest few), and the label
// ingestions within the label memory (review M1/M3).
export const WITNESS_MAX_EPOCHS_PER_FAMILY = 64;
export const WITNESS_LABEL_MEMORY_MS = 30 * 24 * 60 * 60 * 1000;

export function resolveAlertTransitionPaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "alerts");
  return {
    dir,
    logFile: path.join(dir, "alert-transitions.jsonl"),
    stateFile: path.join(dir, "alert-transitions.state.json"),
    brokenFile: path.join(dir, "alert-transitions.broken.jsonl"),
  };
}

// ------------------------------------------------------------------------------------------------
// Projection and diff (pure)
// ------------------------------------------------------------------------------------------------

export function projectAlerts(alerts) {
  const projected = {};
  for (const raw of alerts ?? []) {
    const alert = normalizeAlertRecord(raw);
    projected[alert.id] = {
      rule_id: alert.rule_id,
      fingerprint: alert.fingerprint,
      status: alert.status,
      episode_started_at: alert.episode_started_at,
      incident_state: alert.incident_state,
      tombstones_dropped_total: alert.tombstones_dropped_total ?? 0,
      incidents: Object.fromEntries(Object.entries(alert.incidents ?? {}).map(([key, incident]) => [key, {
        status: incident.status,
        severity_max: incident.severity_max,
        confirmed_at: incident.confirmed_at,
        notified_severity: incident.notified_severity,
        close_on_delivery: incident.close_on_delivery === true,
      }])),
    };
  }
  return { v: ALERT_TRANSITIONS_SCHEMA_VERSION, alerts: projected };
}

const ACTIVE_STATES = new Set(["active", "acknowledged"]);
const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
function rank(severity) {
  return Object.hasOwn(SEVERITY_RANK, severity) ? SEVERITY_RANK[severity] : 3;
}

/**
 * Diffs the recorded projection against the current alert records. Returns unsealed record bodies in
 * a deterministic order (alert id, then kind order, then incident key). Pure.
 */
export function deriveAlertTransitions(projection, alerts, { now } = {}) {
  const ts = new Date(now ?? Date.now()).toISOString();
  const before = projection?.alerts ?? {};
  const after = projectAlerts(alerts).alerts;
  const normalizedById = new Map((alerts ?? []).map((raw) => normalizeAlertRecord(raw)).map((alert) => [alert.id, alert]));
  const records = [];
  for (const id of Object.keys(after).sort()) {
    const prev = before[id];
    const cur = after[id];
    const base = { ts, alert_id: id, rule_id: cur.rule_id, fingerprint: cur.fingerprint };
    const episodeChanged = !prev || prev.episode_started_at !== cur.episode_started_at;
    const newEpisode = Boolean(cur.episode_started_at) && episodeChanged;
    if (newEpisode && prev && ACTIVE_STATES.has(prev.status)) {
      // The previous episode ended between two reads without an observed recovery or closure.
      records.push({ ...base, kind: "episode_ended", inferred: true, episode_started_at: prev.episode_started_at });
    }
    if (ACTIVE_STATES.has(cur.status) && (newEpisode || (prev && !ACTIVE_STATES.has(prev.status)))) {
      records.push({ ...base, kind: "activated", status: cur.status, episode_started_at: cur.episode_started_at, from: prev?.status ?? "absent" });
    }
    const prevIncidents = newEpisode ? Object.fromEntries(Object.entries(prev?.incidents ?? {}).filter(([, incident]) => incident.status === "closed")) : (prev?.incidents ?? {});
    for (const key of Object.keys(cur.incidents).sort()) {
      const incident = cur.incidents[key];
      const old = prevIncidents[key];
      if (!old) {
        if (incident.status === "closed") continue; // carried tombstone never observed open
        records.push({ ...base, kind: "incident_opened", incident_key: key, severity: incident.severity_max, episode_started_at: cur.episode_started_at });
        continue;
      }
      if (old.status === "closed" && incident.status !== "closed") {
        records.push({ ...base, kind: "incident_reopened", incident_key: key, severity: incident.severity_max });
      } else if (rank(incident.severity_max) > rank(old.severity_max) && incident.status !== "closed") {
        records.push({ ...base, kind: "escalated", incident_key: key, severity: incident.severity_max, from_severity: old.severity_max });
      }
      if (incident.status === "closed" && old.status !== "closed") {
        const closedReason = normalizedById.get(id)?.incidents?.[key]?.closed_reason ?? null;
        records.push({ ...base, kind: "incident_closed", incident_key: key, reason: closedReason, source: normalizedById.get(id)?.incidents?.[key]?.closed_by ?? null });
      }
    }
    if (prev && !episodeChanged) {
      if (cur.status === "recovered" && prev.status !== "recovered") {
        records.push({ ...base, kind: "recovered", ...(EDGE_REARM_RULE_IDS.has(cur.rule_id) ? { reason: "edge_rearm" } : {}) });
      }
      if (cur.status === "closed" && prev.status !== "closed") {
        const closedReason = normalizedById.get(id)?.closed_reason ?? null;
        records.push({ ...base, kind: "alert_closed", reason: closedReason, source: normalizedById.get(id)?.closed_by ?? null });
      }
      if (cur.status === "acknowledged" && prev.status === "active") {
        records.push({ ...base, kind: "acknowledged" });
      }
    }
    const prevStorm = !newEpisode && prev?.incident_state === "incident_storm";
    if (cur.incident_state === "incident_storm" && !prevStorm) {
      records.push({ ...base, kind: "incident_storm", live_incidents: Object.values(cur.incidents).filter((incident) => !["acknowledged", "recovered", "suppressed", "closed"].includes(incident.status)).length });
    } else if (prevStorm && cur.incident_state !== "incident_storm") {
      records.push({ ...base, kind: "incident_storm_exited" });
    }
    if ((cur.tombstones_dropped_total ?? 0) > (prev?.tombstones_dropped_total ?? 0)) {
      records.push({ ...base, kind: "tombstones_dropped", count: cur.tombstones_dropped_total - (prev?.tombstones_dropped_total ?? 0) });
    }
  }
  return records;
}

function closureKey(alertId, incidentKey = null) {
  return `${alertId}\u0000${incidentKey ?? ""}`;
}

function closureWitnesses(records = [], extra = []) {
  const known = new Set();
  for (const record of [...records, ...extra]) {
    if (record?.kind !== "closure_authorized" || typeof record.alert_id !== "string") continue;
    known.add(closureKey(record.alert_id, record.incident_key));
  }
  return known;
}

async function priorProjectionForReconciliation(descartesPaths, log) {
  try {
    const { stateFile } = resolveAlertTransitionPaths(descartesPaths);
    const state = JSON.parse(await fs.readFile(stateFile, "utf8"));
    if (state?.projection?.alerts && Number.isSafeInteger(state.head_seq)) {
      return foldTransitionRecords(state.projection, (log.records ?? []).filter((record) => record.seq > state.head_seq));
    }
  } catch {
    // A missing/invalid projection cannot prove a prior closure. The next chain record remains a
    // visible rebaseline; never guess a closure witness from the mutable alert store.
  }
  return null;
}

/**
 * Repairs a closed alert/incident that was not authorized by a daemon closure record. The
 * transition projection is the only prior-state witness; current closed_by/reason fields are never
 * treated as proof. Returns an alert array and audit records for the caller's single daemon write.
 */
export async function reconcileAlertClosures(descartesPaths, { now, alerts, authorizedClosures = [] } = {}) {
  const current = alerts ?? await readAlertRecords(descartesPaths);
  const log = await readAlertTransitions(descartesPaths);
  const prior = await priorProjectionForReconciliation(descartesPaths, log);
  if (!prior) return { alerts: current, changes: [], audit: [], notices: [] };
  const authorized = closureWitnesses(log.records, authorizedClosures);
  const at = new Date(now ?? Date.now()).toISOString();
  const repaired = [];
  const next = current.map((raw) => {
    const alert = normalizeAlertRecord(raw);
    const before = prior.alerts?.[alert.id];
    if (!before) return alert;
    let changed = false;
    const incidents = { ...alert.incidents };
    for (const [key, incident] of Object.entries(incidents)) {
      if (incident.status !== "closed" || before.incidents?.[key]?.status === "closed") continue;
      if (authorized.has(closureKey(alert.id, key))) continue;
      const digest = crypto.createHash("sha256").update(canonicalJson({ alert_id: alert.id, incident_key: key, status: "closed", reason: incident.closed_reason, closed_at: incident.closed_at, closed_by: incident.closed_by })).digest("hex");
      const priorIncident = before.incidents?.[key];
      incidents[key] = {
        ...incident,
        ...(priorIncident ? {
          status: priorIncident.status === "closed" ? "active" : priorIncident.status,
          confirmed_at: priorIncident.confirmed_at ?? null,
          notified_severity: priorIncident.notified_severity ?? null,
          close_on_delivery: priorIncident.close_on_delivery === true,
        } : { status: "active", confirmed_at: null, notified_severity: null }),
        closed_reason: null,
        closed_at: null,
        closed_by: null,
        close_requested: null,
      };
      repaired.push({ alert_id: alert.id, incident_key: key, digest });
      changed = true;
    }
    const alertWasClosed = alert.status === "closed" && before.status !== "closed" && !authorized.has(closureKey(alert.id));
    if (alertWasClosed) {
      const digest = crypto.createHash("sha256").update(canonicalJson({ alert_id: alert.id, status: "closed", reason: alert.closed_reason, closed_at: alert.closed_at, closed_by: alert.closed_by })).digest("hex");
      repaired.push({ alert_id: alert.id, incident_key: null, digest });
      changed = true;
    }
    if (!changed) return alert;
    const repairedAlert = normalizeAlertRecord({ ...alert, ...before, status: before.status === "closed" ? "active" : before.status, closed_reason: null, closed_at: null, closed_by: null, close_requested: null, incidents, integrity_status: "unattributed_change", integrity_digest: repaired.at(-1).digest, integrity_at: at });
    return repairedAlert;
  });
  const audit = repaired.map((change) => ({ kind: "unattributed_change", alert_id: change.alert_id, incident_key: change.incident_key, digest: change.digest, status: "repaired" }));
  return {
    alerts: next,
    changes: repaired,
    audit,
    notices: repaired.map((change) => ({
      notify: true,
      severity: "critical",
      title: "Descartes: unattributed alert-state change",
      body: `Restored ${change.alert_id}${change.incident_key ? `/${change.incident_key}` : ""} from the transition witness; digest ${change.digest.slice(0, 16)}.`,
    })),
  };
}

// Folds already-logged records onto a projection (crash recovery: the log advanced but the state
// file did not). Covers every kind deriveAlertTransitions emits.
export function foldTransitionRecords(projection, records) {
  const alerts = structuredClone(projection?.alerts ?? {});
  for (const record of records) {
    const id = record.alert_id;
    if (!id) continue;
    const alert = alerts[id];
    switch (record.kind) {
      case "activated": {
        const carried = alert?.status === "closed"
          ? Object.fromEntries(Object.entries(alert.incidents ?? {}).filter(([, incident]) => incident.status === "closed"))
          : {};
        alerts[id] = { rule_id: record.rule_id, fingerprint: record.fingerprint, status: record.status ?? "active", episode_started_at: record.episode_started_at ?? null, incident_state: "normal", tombstones_dropped_total: alert?.tombstones_dropped_total ?? 0, incidents: carried };
        break;
      }
      case "incident_opened":
        if (alert) alert.incidents[record.incident_key] = { status: "active", severity_max: record.severity };
        break;
      case "escalated":
      case "incident_reopened":
        if (alert) alert.incidents[record.incident_key] = { status: "active", severity_max: record.severity };
        break;
      case "incident_closed":
        if (alert?.incidents?.[record.incident_key]) alert.incidents[record.incident_key].status = "closed";
        break;
      case "recovered":
        if (alert) {
          alert.status = "recovered";
          for (const incident of Object.values(alert.incidents)) if (incident.status !== "closed") incident.status = "recovered";
        }
        break;
      case "alert_closed":
        if (alert) alert.status = "closed";
        break;
      case "acknowledged":
        if (alert) {
          alert.status = "acknowledged";
          alert.incident_state = "normal";
          for (const incident of Object.values(alert.incidents)) if (!["recovered", "suppressed", "closed"].includes(incident.status)) incident.status = "acknowledged";
        }
        break;
      case "incident_storm":
        if (alert) alert.incident_state = "incident_storm";
        break;
      case "incident_storm_exited":
        if (alert) alert.incident_state = "normal";
        break;
      case "tombstones_dropped":
        if (alert) alert.tombstones_dropped_total = (alert.tombstones_dropped_total ?? 0) + (record.count ?? 0);
        break;
      default:
        break;
    }
  }
  return { v: ALERT_TRANSITIONS_SCHEMA_VERSION, alerts };
}

// Review L6: the projection the state file holds is bound to the chain. Whenever the recorded
// projection changes, the daemon appends a `projection` record carrying its digest; the projection
// is trusted only if it matches the last chained digest at its stamp (else: a visible rebaseline).
export function projectionDigest(projection) {
  return crypto.createHash("sha256").update(canonicalJson(JSON.parse(JSON.stringify(projection?.alerts ?? {})))).digest("hex");
}

function lastProjectionDigest(log, uptoSeq) {
  for (let index = (log.records ?? []).length - 1; index >= 0; index -= 1) {
    const record = log.records[index];
    if (record.seq <= uptoSeq && record.kind === "projection" && typeof record.digest === "string") return record.digest;
  }
  return typeof log.header?.projection_digest === "string" && log.header.through_seq <= uptoSeq ? log.header.projection_digest : null;
}

// ------------------------------------------------------------------------------------------------
// Witness (review M3, M1)
// ------------------------------------------------------------------------------------------------
//
// The log witnesses state other files hold: that a family's pending journal exists (so wiping the
// journal and its checkpoint is a discontinuity, not a first run), the discontinuity epochs it saw
// (so the budget survives a wipe), and the labels the daemon ingested (so deleting the label state
// neither resets the label budget nor re-ingests a label). Compaction and a chain restart drop the
// records themselves, so the witness is carried: in the compaction header, on the chain_restart
// record, and in alert-transitions.state.json. The header and state file are unchained (same-UID
// writable, like everything here); a witness can be ADDED to, which only ever holds something back.

export function emptyTransitionWitness() {
  return { pending_journals: {}, labels: {} };
}

export function mergeTransitionWitness(...witnesses) {
  const merged = emptyTransitionWitness();
  for (const witness of witnesses) {
    if (!witness || typeof witness !== "object") continue;
    for (const [family, entry] of Object.entries(witness.pending_journals ?? {})) {
      if (!entry || typeof entry !== "object") continue;
      const into = merged.pending_journals[family] ?? { created: false, epochs: [] };
      into.created = into.created || entry.created === true;
      for (const epoch of Array.isArray(entry.epochs) ? entry.epochs : []) {
        if (Number.isSafeInteger(epoch?.epoch) && !into.epochs.some((known) => known.epoch === epoch.epoch)) into.epochs.push({ epoch: epoch.epoch, opened_at: epoch.opened_at ?? null, cause: epoch.cause ?? null });
      }
      into.epochs.sort((left, right) => left.epoch - right.epoch);
      into.epochs = into.epochs.slice(-WITNESS_MAX_EPOCHS_PER_FAMILY);
      merged.pending_journals[family] = into;
    }
    for (const [labelId, entry] of Object.entries(witness.labels ?? {})) {
      if (!entry || typeof entry.ingested_at !== "string") continue;
      const known = merged.labels[labelId];
      if (!known || Date.parse(entry.ingested_at) < Date.parse(known.ingested_at)) merged.labels[labelId] = { ingested_at: entry.ingested_at, charge: Number.isFinite(entry.charge) ? entry.charge : 0, label: entry.label ?? null };
    }
  }
  return merged;
}

/** Folds log records into a witness (from a compaction header's carried witness, if any). Pure. */
export function foldTransitionWitness(base, records) {
  const fromRecords = emptyTransitionWitness();
  for (const record of records ?? []) {
    if (record?.carried_witness) Object.assign(fromRecords, mergeTransitionWitness(fromRecords, record.carried_witness));
    const family = typeof record?.family === "string" ? record.family : null;
    if (record?.kind === "pending_journal_created" && family) {
      fromRecords.pending_journals[family] = { created: true, epochs: fromRecords.pending_journals[family]?.epochs ?? [] };
    } else if (record?.kind === "pending_discontinuity" && family && Number.isSafeInteger(record.epoch)) {
      Object.assign(fromRecords, mergeTransitionWitness(fromRecords, { pending_journals: { [family]: { created: true, epochs: [{ epoch: record.epoch, opened_at: record.ts ?? null, cause: record.cause ?? null }] } } }));
    } else if (record?.kind === "label_ingested" && typeof record.label_id === "string" && typeof record.ts === "string") {
      Object.assign(fromRecords, mergeTransitionWitness(fromRecords, { labels: { [record.label_id]: { ingested_at: record.ts, charge: record.charge, label: record.label } } }));
    }
  }
  return mergeTransitionWitness(base, fromRecords);
}

function pruneTransitionWitness(witness, nowMs) {
  const pruned = mergeTransitionWitness(witness);
  for (const [labelId, entry] of Object.entries(pruned.labels)) {
    if (nowMs - Date.parse(entry.ingested_at) > WITNESS_LABEL_MEMORY_MS) delete pruned.labels[labelId];
  }
  return pruned;
}

// ------------------------------------------------------------------------------------------------
// Log I/O
// ------------------------------------------------------------------------------------------------

/**
 * Reads and verifies the log. status: "missing" | "valid" | "broken". `records` are the verified
 * records only. coverage_from_ts is the latest coverage gap (genesis, rebaseline, restart, or the
 * compaction cut): activations before it are not in the log.
 */
export async function readAlertTransitions(descartesPaths) {
  const { logFile } = resolveAlertTransitionPaths(descartesPaths);
  const read = await readJsonlStrict(logFile, { maxBytes: MAX_ALERT_TRANSITIONS_BYTES, maxLines: 200000 });
  if (!read.exists) return { status: "missing", records: [], head_seq: 0, head_hash: GENESIS_PREV_HASH, coverage_from_ts: null, torn_tail: false };
  if (read.exceeded) return { status: "broken", reason: "log_read_cap", records: [], head_seq: 0, head_hash: GENESIS_PREV_HASH, coverage_from_ts: null, torn_tail: false, witness: emptyTransitionWitness() };
  if (read.bad_line !== null) {
    const partial = verifyChain(ALERT_TRANSITION_DOMAIN, read.records);
    return { status: "broken", reason: "unparseable_line", records: partial.verified, head_seq: partial.head_seq, head_hash: partial.head_hash, coverage_from_ts: null, torn_tail: false, witness: foldTransitionWitness(partial.header?.carried_witness, partial.verified) };
  }
  const chain = verifyChain(ALERT_TRANSITION_DOMAIN, read.records);
  const records = chain.verified;
  const witness = foldTransitionWitness(chain.header?.carried_witness, records);
  let coverageFrom = chain.header?.through_ts ?? null;
  for (const record of records) if (COVERAGE_GAP_KINDS.has(record.kind)) coverageFrom = record.ts;
  if (!chain.ok) {
    return { status: "broken", reason: chain.reason, records, head_seq: chain.head_seq, head_hash: chain.head_hash, coverage_from_ts: coverageFrom, torn_tail: read.torn_tail, witness };
  }
  if (records.length === 0 && !chain.header) {
    return { status: "missing", records: [], head_seq: 0, head_hash: GENESIS_PREV_HASH, coverage_from_ts: null, torn_tail: read.torn_tail, witness };
  }
  return { status: "valid", records, head_seq: chain.head_seq, head_hash: chain.head_hash, coverage_from_ts: coverageFrom, torn_tail: read.torn_tail, bytes: read.bytes, header: chain.header, witness };
}

/**
 * The witness from every surviving source: the log (verified records, its compaction header and any
 * restart record's carried witness) and the state file. Never throws: an unreadable source adds
 * nothing.
 */
export async function readAlertTransitionWitness(descartesPaths) {
  const { stateFile } = resolveAlertTransitionPaths(descartesPaths);
  let fromLog = null;
  try {
    fromLog = (await readAlertTransitions(descartesPaths)).witness ?? null;
  } catch {
    fromLog = null;
  }
  const stateRead = await readState(stateFile);
  return mergeTransitionWitness(fromLog, stateRead.status === "valid" ? stateRead.state.witness : null);
}

async function readState(stateFile) {
  try {
    const parsed = JSON.parse(await fs.readFile(stateFile, "utf8"));
    if (!parsed || parsed.v !== ALERT_TRANSITIONS_SCHEMA_VERSION || !Number.isSafeInteger(parsed.head_seq) || typeof parsed.head_hash !== "string"
      || !parsed.projection || typeof parsed.projection.alerts !== "object") return { status: "invalid" };
    return { status: "valid", state: parsed };
  } catch (error) {
    if (error?.code === "ENOENT") return { status: "missing" };
    return { status: "invalid" };
  }
}

async function compactIfNeeded(logFile, maxBytes, nowMs) {
  const read = await readJsonlStrict(logFile, { maxBytes: MAX_ALERT_TRANSITIONS_BYTES, maxLines: 200000 });
  if (!read.exists || read.bytes <= maxBytes) return false;
  const chain = verifyChain(ALERT_TRANSITION_DOMAIN, read.records);
  if (!chain.ok) return false;
  const records = chain.verified;
  let kept = [];
  let keptBytes = 0;
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const size = Buffer.byteLength(JSON.stringify(records[index])) + 1;
    if (keptBytes + size > maxBytes / 2 && kept.length > 0) break;
    kept.unshift(records[index]);
    keptBytes += size;
  }
  const firstKeptIndex = records.length - kept.length;
  if (firstKeptIndex <= 0) return false;
  const cutRecord = records[firstKeptIndex - 1];
  // The dropped records' witness rides in the header (review M3).
  const carriedWitness = pruneTransitionWitness(foldTransitionWitness(chain.header?.carried_witness, records.slice(0, firstKeptIndex)), nowMs);
  const projectionAtCut = lastProjectionDigest({ records: records.slice(0, firstKeptIndex), header: chain.header }, cutRecord.seq);
  const header = { kind: "compacted", through_seq: cutRecord.seq, through_hash: cutRecord.hash, through_ts: cutRecord.ts, v: ALERT_TRANSITIONS_SCHEMA_VERSION, carried_witness: carriedWitness, ...(projectionAtCut ? { projection_digest: projectionAtCut } : {}) };
  await atomicWrite(logFile, [header, ...kept].map((record) => `${JSON.stringify(record)}\n`).join(""));
  return true;
}

/**
 * Appends sealed records after the current head. Assumes the caller verified the chain this tick.
 * Returns the new head.
 */
async function appendSealed(logFile, head, bodies) {
  let seq = head.head_seq;
  let prevHash = head.head_hash;
  const sealed = [];
  for (const body of bodies) {
    seq += 1;
    const record = sealRecord(ALERT_TRANSITION_DOMAIN, { prevHash, seq }, body);
    sealed.push(record);
    prevHash = record.hash;
  }
  await appendLines(logFile, sealed);
  return { head_seq: seq, head_hash: prevHash, sealed };
}

/**
 * The daemon's per-tick write. Reads the alert store (unless given), continues the recorded projection
 * (folding any logged-but-unstamped suffix after a crash), appends the derived transitions plus any
 * `extraRecords` (audit records from label ingestion, the pending journal, the digest), stamps the
 * state with the new head and compacts past the cap. Never throws for a broken or missing log: it
 * restarts the chain (keeping the broken file aside) and reports it.
 */
export async function recordAlertTransitions(descartesPaths, options = {}) {
  const now = new Date(options.now ?? Date.now()).toISOString();
  const { dir, logFile, stateFile, brokenFile } = resolveAlertTransitionPaths(descartesPaths);
  const alerts = options.alerts ?? await readAlertRecords(descartesPaths);
  let log = await readAlertTransitions(descartesPaths);
  const stateRead = await readState(stateFile);
  const report = { status: "ok", appended: 0, restarted: null, rebaselined: null };
  let projection;
  const leading = [];
  const nowMs = Date.parse(now);
  // Review M3: what the log and the state witness before this tick, carried across a restart.
  const priorWitness = mergeTransitionWitness(log.witness, stateRead.status === "valid" ? stateRead.state.witness : null);

  if (log.torn_tail) await trimTornTail(logFile);
  if (log.status === "broken") {
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    await fs.rename(logFile, brokenFile).catch(async () => fs.copyFile(logFile, brokenFile));
    leading.push({ ts: now, kind: "chain_restart", restart: true, reason: log.reason ?? "broken", lost_head_seq: log.head_seq, carried_witness: pruneTransitionWitness(priorWitness, nowMs) });
    report.restarted = log.reason ?? "broken";
    projection = stateRead.status === "valid" ? stateRead.state.projection : projectAlerts(alerts);
    log = { status: "missing", head_seq: 0, head_hash: `lost:${log.head_hash}`, records: [] };
  } else if (log.status === "missing") {
    if (stateRead.status === "valid") {
      // The state proves a log existed: its loss is a restart, never a silent genesis.
      leading.push({ ts: now, kind: "chain_restart", restart: true, reason: "log_missing", lost_head_seq: stateRead.state.head_seq, carried_witness: pruneTransitionWitness(priorWitness, nowMs) });
      report.restarted = "log_missing";
      projection = stateRead.state.projection;
      log = { status: "missing", head_seq: 0, head_hash: `lost:${stateRead.state.head_hash}`, records: [] };
    } else {
      leading.push({ ts: now, kind: "genesis", existing_alerts: alerts.length, active_alerts: alerts.filter((alert) => ["active", "acknowledged"].includes(alert.status)).length });
      projection = projectAlerts(alerts);
      log = { status: "missing", head_seq: 0, head_hash: GENESIS_PREV_HASH, records: [] };
    }
  } else {
    const stamped = stateRead.status === "valid" && (
      (stateRead.state.head_seq === log.head_seq && stateRead.state.head_hash === log.head_hash)
      || (stateRead.state.head_seq < log.head_seq && log.records.some((record) => record.seq === stateRead.state.head_seq && record.hash === stateRead.state.head_hash)));
    const chainedDigest = stamped ? lastProjectionDigest(log, stateRead.state.head_seq) : null;
    const projectionBound = stamped && (chainedDigest === null || chainedDigest === projectionDigest(stateRead.state.projection));
    if (projectionBound && stateRead.state.head_seq === log.head_seq) {
      projection = stateRead.state.projection;
    } else if (projectionBound) {
      projection = foldTransitionRecords(stateRead.state.projection, log.records.filter((record) => record.seq > stateRead.state.head_seq));
    } else {
      // Review L6: a state stamped past the log's head means the log lost its tail (a truncation); a
      // stamped state whose projection is not the chained one was edited.
      const reason = stateRead.status !== "valid" ? `state_${stateRead.status}`
        : (stamped ? "projection_mismatch" : (stateRead.state.head_seq > log.head_seq ? "log_truncated" : "state_mismatch"));
      leading.push({ ts: now, kind: "rebaselined", reason });
      report.rebaselined = reason;
      projection = projectAlerts(alerts);
    }
  }

  const derived = deriveAlertTransitions(projection, alerts, { now });
  const extra = (options.extraRecords ?? []).map((record) => ({ ts: now, ...record }));
  const bodies = [...leading, ...derived, ...extra];
  // Review L6: chain the digest of the projection this tick records whenever it changes.
  const nextProjectionDigest = projectionDigest(projectAlerts(alerts));
  const restarting = leading.some((record) => record.kind === "chain_restart" || record.kind === "genesis");
  const lastChained = restarting ? null : lastProjectionDigest(log, log.head_seq);
  if (nextProjectionDigest !== lastChained) bodies.push({ ts: now, kind: "projection", digest: nextProjectionDigest });
  let head = { head_seq: log.head_seq, head_hash: log.head_hash };
  if (bodies.length > 0) {
    // A restarted chain's first record cites the lost head; seal it with that marker.
    if (head.head_hash.startsWith("lost:")) {
      const first = sealRecord(ALERT_TRANSITION_DOMAIN, { prevHash: head.head_hash, seq: 1 }, bodies[0]);
      await appendLines(logFile, [first]);
      head = { head_seq: 1, head_hash: first.hash };
      const rest = await appendSealed(logFile, head, bodies.slice(1));
      head = { head_seq: rest.head_seq, head_hash: rest.head_hash };
    } else {
      const appended = await appendSealed(logFile, head, bodies);
      head = { head_seq: appended.head_seq, head_hash: appended.head_hash };
    }
  }
  report.appended = bodies.length;
  report.kinds = Object.fromEntries([...new Set(bodies.map((body) => body.kind))].sort().map((kind) => [kind, bodies.filter((body) => body.kind === kind).length]));
  const witness = pruneTransitionWitness(foldTransitionWitness(priorWitness, bodies), nowMs);
  await atomicWrite(stateFile, JSON.stringify({ v: ALERT_TRANSITIONS_SCHEMA_VERSION, head_seq: head.head_seq, head_hash: head.head_hash, projection: projectAlerts(alerts), witness, updated_at: now }));
  const maxBytes = options.maxBytes ?? MAX_ALERT_TRANSITIONS_BYTES;
  if (await compactIfNeeded(logFile, maxBytes, nowMs)) report.compacted = true;
  report.head_seq = head.head_seq;
  return report;
}
