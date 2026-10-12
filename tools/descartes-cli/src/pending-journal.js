// Context plan C1.4 (§6.4, I44, I52-I54, I69, I70, I3; open item 16): the pending journal.
//
// One append-only, hash-chained journal per fact family
// (stateDir/learned/pending/<family>/journal.jsonl) plus a checkpoint (checkpoint.json). The daemon is
// its ONLY writer; the CLI never writes it (labels reach it through the daemon's ingestion, I62).
//
// What it holds:
//   - the observation lifecycle of every pending item (opened/added -> admitted(source),
//     quarantined(reason), excluded(reason); revoked returns an admission to pending). Membership is
//     read from the journal alone, never from alert status (I52);
//   - the DURABLE observation-to-pass mapping (item 16): one `pass_committed` entry per committed
//     family pass the daemon saw, with the observation time it committed. A gap in the mapping (a
//     pass committed with no entry, e.g. a crash between the fact commit and the mapping) is
//     journaled explicitly as `excluded(unmapped_pass)` over the pass range and its observation span;
//   - the scored-through watermark (I69): `scored_through(pass_id)` once every verdict for that pass is
//     journaled. A mapped pass left behind the watermark (committed, never scored) is
//     `excluded(unadjudicated)`: never folded, listed in the digest. C1 journals and excludes such
//     passes; the ordered replay that would score them instead is C1a's (it changes detection);
//   - discontinuity epochs and their exit (I54), and the caps of I3.
//
// Certification at write (I70): an entry that could ever carry authority (opened, added, admitted,
// revoked, pass_committed, scored_through, recertified) is written only if, at that moment, its cited
// pass lies in the family ledger's certified span: same generation, pass id <= last committed, no
// pending pass, continuity not broken, pass time above the floors. It records the pass time and the
// span, and from then on stays valid while its own chain is continuous: intentional age or byte
// eviction of the source facts is not loss. Restrictive entries (quarantined, excluded, compacted,
// discontinuity, label_marked) never need certification: they can only withhold.
//
// Tamper-evident at the daemon's UID, not tamper-proof (§6.4.5).
import fs from "node:fs/promises";
import path from "node:path";
import { RULE_HORIZONS } from "./fact-families.js";
import { RULE_STREAM_KINDS } from "./alert-stream-kinds.js";
import { appendLines, atomicWrite, canonicalJson, GENESIS_PREV_HASH, readJsonlStrict, sealRecord, trimTornTail, verifyChain } from "./hash-chain.js";
import crypto from "node:crypto";

export const PENDING_JOURNAL_DOMAIN = "descartes.pending_journal.v1";
export const PENDING_JOURNAL_SCHEMA_VERSION = 1;

export const PENDING_ENTRY_KINDS = Object.freeze([
  "opened", "added", "admitted", "quarantined", "excluded", "revoked", "scored_through",
  "pass_committed", "discontinuity", "recertified", "compacted", "label_marked",
]);
const ENTRY_KIND_SET = new Set(PENDING_ENTRY_KINDS);
const RESTRICTIVE_KINDS = new Set(["quarantined", "excluded", "compacted", "discontinuity", "label_marked"]);

// I48: the closed set of explanation sources. federated_signature is reserved and inactive.
export const EXPLANATION_SOURCES = Object.freeze(["earned_promotion", "bounded_quiet", "context_model", "label"]);
export const RESERVED_EXPLANATION_SOURCES = Object.freeze(["federated_signature"]);
const UNATTENDED_SOURCES = new Set(["earned_promotion", "bounded_quiet", "context_model"]);

// §16.1 reviewed defaults (I3 caps are S; the discontinuity budget is O).
export const MAX_OPEN_PENDING_ITEMS = 1024;
export const MAX_EXEMPLARS_PER_ITEM = 8;
export const MAX_QUARANTINED_ITEMS = 256;
export const DISCONTINUITY_BUDGET_EPOCHS = 3;
export const DISCONTINUITY_BUDGET_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
// C1 addendum defaults (S): the retained pass-map entries behind the watermark, the retained
// unadjudicated-range and epoch records, and the journal size beyond which the prefix a checkpoint
// covers is cut.
export const MAX_RETAINED_SCORED_PASSES = 64;
export const MAX_RETAINED_RANGES = 256;
export const MAX_RETAINED_EPOCHS = 64;
export const MAX_JOURNAL_BYTES_BEFORE_CUT = 256 * 1024;
const MAX_PAYLOAD_BYTES = 4096;

// The families whose detectors are declared C1a producers (the incumbent EVENT/LEVEL/NOVELTY rules
// of alert-stream-kinds.js), derived from the rule-horizon registry rather than restated.
export const PENDING_JOURNAL_FAMILIES = Object.freeze([...new Set([...RULE_STREAM_KINDS.keys()]
  .flatMap((ruleId) => RULE_HORIZONS.get(ruleId)?.families ?? []))].sort());

export function resolvePendingJournalPaths(descartesPaths, family) {
  if (!PENDING_JOURNAL_FAMILIES.includes(family)) throw new Error(`pending-journal: ${family} is not a journaled family`);
  const dir = path.join(descartesPaths.stateDir, "learned", "pending", family);
  return {
    dir,
    journalFile: path.join(dir, "journal.jsonl"),
    checkpointFile: path.join(dir, "checkpoint.json"),
    brokenFile: path.join(dir, "journal.broken.jsonl"),
  };
}

export function pendingItemId({ alert_id: alertId, episode, incident_key: incidentKey }) {
  return [alertId, episode, incidentKey].map((part) => String(part ?? "")).join("|");
}

function boundedPayload(value) {
  if (value === undefined || value === null) return null;
  const text = canonicalJson(value);
  if (Buffer.byteLength(text) > MAX_PAYLOAD_BYTES) return { truncated: true, digest: crypto.createHash("sha256").update(text).digest("hex").slice(0, 32) };
  return JSON.parse(text);
}

// ------------------------------------------------------------------------------------------------
// State and fold (pure)
// ------------------------------------------------------------------------------------------------

export function emptyPendingState(family) {
  return {
    v: PENDING_JOURNAL_SCHEMA_VERSION,
    family,
    generation: null,
    last_mapped_pass_id: 0,
    last_observation_ts: null,
    watermark: 0,
    passes: {},
    items: {},
    excluded_summary: { count: 0, by_reason: {} },
    quarantine_aggregate: { count: 0, digests: [] },
    ranges: [],
    epochs: [],
    open_epoch: null,
    head_seq: 0,
    head_hash: GENESIS_PREV_HASH,
  };
}

const DISPOSITION_RANK = { admitted: 0, pending: 1, excluded: 2, quarantined: 3 };

function itemDigest(item) {
  return crypto.createHash("sha256").update(canonicalJson({ item: item.item, ticks: item.ticks, stats: item.stats })).digest("hex").slice(0, 16);
}

function boundState(state) {
  // Passes behind the watermark are only audit history: keep the newest few. Unscored passes are
  // kept in full (they are what a replay would need).
  const passIds = Object.keys(state.passes).map(Number).sort((a, b) => a - b);
  const scored = passIds.filter((id) => id <= state.watermark);
  for (const id of scored.slice(0, Math.max(0, scored.length - MAX_RETAINED_SCORED_PASSES))) delete state.passes[id];
  if (state.ranges.length > MAX_RETAINED_RANGES) state.ranges = state.ranges.slice(-MAX_RETAINED_RANGES);
  if (state.epochs.length > MAX_RETAINED_EPOCHS) state.epochs = state.epochs.slice(-MAX_RETAINED_EPOCHS);
  // I3: quarantined items beyond the cap merge into the aggregate (never folded, never released).
  const quarantined = Object.entries(state.items).filter(([, item]) => item.state === "quarantined")
    .sort(([, left], [, right]) => left.disposition_seq - right.disposition_seq);
  for (const [id, item] of quarantined.slice(0, Math.max(0, quarantined.length - MAX_QUARANTINED_ITEMS))) {
    state.quarantine_aggregate.count += 1;
    state.quarantine_aggregate.digests = [...state.quarantine_aggregate.digests, itemDigest(item)].slice(-MAX_QUARANTINED_ITEMS);
    delete state.items[id];
  }
  return state;
}

/** Applies verified entries to a state. Pure (returns a new state). */
export function foldPendingEntries(initial, entries) {
  let state = structuredClone(initial);
  for (const entry of entries) {
    state.head_seq = entry.seq ?? state.head_seq;
    state.head_hash = entry.hash ?? state.head_hash;
    if (typeof entry.ledger_generation === "string" && !RESTRICTIVE_KINDS.has(entry.kind)) state.generation = entry.ledger_generation;
    const id = entry.item_id;
    const item = id ? state.items[id] : undefined;
    switch (entry.kind) {
      case "opened": {
        if (!id || state.items[id]) break;
        state.items[id] = {
          item: entry.item,
          state: "pending",
          opened_seq: entry.seq,
          opened_ts: entry.ts,
          ticks: entry.tick ? [entry.tick] : [],
          stats: entry.stats ?? null,
          exemplars: entry.exemplar ? [entry.exemplar] : [],
          raise_ref: entry.raise_ref ?? null,
          serving_snapshot: entry.serving_snapshot ?? null,
          disposition: null,
          disposition_seq: entry.seq,
        };
        break;
      }
      case "added":
        if (item && item.state !== "quarantined") {
          if (entry.tick && !item.ticks.some((tick) => tick.ts === entry.tick.ts)) item.ticks.push(entry.tick);
          if (entry.exemplar && item.exemplars.length < MAX_EXEMPLARS_PER_ITEM) item.exemplars.push(entry.exemplar);
          if (entry.stats) item.stats = entry.stats;
        }
        break;
      case "admitted":
        // An admission never overrides a quarantine or an exclusion (most restrictive wins).
        if (item && item.state === "pending") {
          item.state = "admitted";
          item.disposition = { source: entry.source, evidence_ref: entry.evidence_ref ?? null, budget_charge: entry.budget_charge ?? null, seq: entry.seq, ts: entry.ts };
          item.disposition_seq = entry.seq;
        }
        break;
      case "revoked":
        if (item && item.state === "admitted") {
          item.state = "pending";
          item.disposition = { revoked: true, reason: entry.reason ?? null, seq: entry.seq, ts: entry.ts };
          item.disposition_seq = entry.seq;
        }
        break;
      case "quarantined":
        if (item) {
          item.state = "quarantined";
          item.disposition = { reason: entry.reason ?? null, label_id: entry.label_id ?? null, seq: entry.seq, ts: entry.ts };
          item.disposition_seq = entry.seq;
        }
        break;
      case "excluded":
        if (item && item.state !== "quarantined") {
          item.state = "excluded";
          item.disposition = { reason: entry.reason ?? null, seq: entry.seq, ts: entry.ts };
          item.disposition_seq = entry.seq;
        }
        if (!id) {
          state.ranges.push({ reason: entry.reason, pass_from: entry.pass_from ?? null, pass_to: entry.pass_to ?? null, observation_ts_from: entry.observation_ts_from ?? null, observation_ts_to: entry.observation_ts_to ?? null, seq: entry.seq, ts: entry.ts });
          if (Number.isSafeInteger(entry.pass_to)) {
            for (const [passId, pass] of Object.entries(state.passes)) if (Number(passId) <= entry.pass_to && Number(passId) >= (entry.pass_from ?? 0)) pass.excluded = entry.reason;
          }
        }
        state.excluded_summary.count += 1;
        state.excluded_summary.by_reason[entry.reason ?? "unknown"] = (state.excluded_summary.by_reason[entry.reason ?? "unknown"] ?? 0) + 1;
        break;
      case "compacted":
        for (const compactedId of entry.item_ids ?? []) {
          if (state.items[compactedId]?.state === "pending") {
            state.items[compactedId].state = "excluded";
            state.items[compactedId].disposition = { reason: "compacted", seq: entry.seq, ts: entry.ts };
            state.items[compactedId].disposition_seq = entry.seq;
            state.excluded_summary.count += 1;
            state.excluded_summary.by_reason.compacted = (state.excluded_summary.by_reason.compacted ?? 0) + 1;
          }
        }
        break;
      case "label_marked":
        if (item) item.labels = [...(item.labels ?? []), { label_id: entry.label_id, label: entry.label, seq: entry.seq }].slice(-MAX_EXEMPLARS_PER_ITEM);
        break;
      case "pass_committed":
        state.passes[entry.pass_id] = { observation_ts: entry.observation_ts ?? null, pass_time_ms: entry.pass_time_ms ?? null, generation: entry.ledger_generation ?? null, written_count: entry.written_count ?? 0 };
        state.last_mapped_pass_id = Math.max(state.last_mapped_pass_id, entry.pass_id);
        if (entry.observation_ts) state.last_observation_ts = entry.observation_ts;
        break;
      case "scored_through":
        state.watermark = Math.max(state.watermark, entry.pass_id);
        if (state.passes[entry.pass_id]) state.passes[entry.pass_id].scored = true;
        break;
      case "discontinuity":
        if (entry.carried_state) {
          const carried = entry.carried_state;
          state = { ...emptyPendingState(state.family), ...carried, head_seq: entry.seq, head_hash: entry.hash };
        }
        if (entry.cause === "generation_change") {
          // A new ledger generation restarts pass ids: the pass map and watermark restart with it.
          // Entries certified under the old generation stay valid (I70); only pass bookkeeping resets.
          state.passes = {};
          state.last_mapped_pass_id = 0;
          state.watermark = 0;
        }
        state.epochs = [...state.epochs, { epoch: entry.epoch, opened_at: entry.ts, cause: entry.cause, opened_pass_id: entry.pass_id ?? null, recertified_at: null }];
        state.open_epoch = entry.epoch;
        if (entry.ledger_generation) state.generation = entry.ledger_generation;
        break;
      case "recertified":
        state.epochs = state.epochs.map((epoch) => (epoch.epoch === entry.epoch ? { ...epoch, recertified_at: entry.ts } : epoch));
        if (state.open_epoch === entry.epoch) state.open_epoch = null;
        break;
      default:
        break;
    }
  }
  return boundState(state);
}

/**
 * I54: whether unattended admission (earned_promotion, bounded_quiet, context_model) is allowed for
 * the family. Suspended while an epoch is open, and beyond the discontinuity budget until the
 * trailing count is back within it. Labels are never suspended by this (they have their own budget).
 */
export function pendingAdmissionStatus(state, now) {
  if (state.open_epoch !== null) return { suspended: true, reason: "open_epoch" };
  const nowMs = new Date(now ?? Date.now()).getTime();
  const recent = state.epochs.filter((epoch) => nowMs - Date.parse(epoch.opened_at) <= DISCONTINUITY_BUDGET_WINDOW_MS);
  if (recent.length > DISCONTINUITY_BUDGET_EPOCHS) return { suspended: true, reason: "discontinuity_budget", epochs_in_window: recent.length };
  return { suspended: false, reason: null, epochs_in_window: recent.length };
}

export function isUnattendedSource(source) {
  return UNATTENDED_SOURCES.has(source);
}

/** Item ids whose membership is pending (opened/added with no terminal disposition). */
export function pendingMembership(state) {
  return Object.entries(state.items).filter(([, item]) => item.state === "pending").map(([id]) => id).sort();
}

/** Passes committed and mapped but not yet scored (behind no watermark), oldest first. */
export function unscoredPasses(state) {
  return Object.entries(state.passes)
    .map(([passId, pass]) => ({ pass_id: Number(passId), ...pass }))
    .filter((pass) => pass.pass_id > state.watermark && !pass.excluded)
    .sort((left, right) => left.pass_id - right.pass_id);
}

// ------------------------------------------------------------------------------------------------
// Certification at write (I70)
// ------------------------------------------------------------------------------------------------

export function certifyPendingWrite({ ledger, passId, passTimeMs }) {
  if (!ledger) return { ok: false, reason: "ledger_unavailable" };
  const continuity = ledger.continuity ?? {};
  if (continuity.pending_pass) return { ok: false, reason: "pass_pending" };
  if (continuity.continuity_ok === false) return { ok: false, reason: "continuity_lost" };
  if (!Number.isSafeInteger(passId) || passId < 1 || passId > continuity.last_committed_pass_id) return { ok: false, reason: "pass_not_committed" };
  const floors = [ledger.bytecap_floor_ts, ledger.age_floor_ts].filter((value) => typeof value === "string").map(Date.parse).filter(Number.isFinite);
  const spanStart = floors.length > 0 ? Math.max(...floors) : null;
  const spanEnd = Date.parse(continuity.last_rewrite_newest_ts ?? "");
  if (Number.isFinite(passTimeMs) && spanStart !== null && !(passTimeMs > spanStart)) return { ok: false, reason: "outside_certified_span" };
  return { ok: true, reason: null, generation: ledger.generation, span: { start_ms: spanStart, end_ms: Number.isFinite(spanEnd) ? spanEnd : null } };
}

export class PendingJournalWriteRefused extends Error {}

// ------------------------------------------------------------------------------------------------
// I/O
// ------------------------------------------------------------------------------------------------

async function readCheckpoint(checkpointFile, family) {
  try {
    const parsed = JSON.parse(await fs.readFile(checkpointFile, "utf8"));
    if (!parsed || parsed.v !== PENDING_JOURNAL_SCHEMA_VERSION || parsed.family !== family || !parsed.stamp
      || !Number.isSafeInteger(parsed.stamp.journal_seq) || typeof parsed.stamp.journal_head_hash !== "string"
      || !parsed.state || typeof parsed.state.items !== "object") return { status: "invalid" };
    return { status: "valid", checkpoint: parsed };
  } catch (error) {
    if (error?.code === "ENOENT") return { status: "missing" };
    return { status: "invalid" };
  }
}

/**
 * Reads, verifies and folds a family's journal (pure detection; writes nothing). Returns
 * { status: "missing" | "valid" | "discontinuity", state, cause, sources } where `sources` carries the
 * surviving material a discontinuity exit needs.
 */
export async function inspectPendingJournal(descartesPaths, family, { ledger = null, witnessExists = false } = {}) {
  const { journalFile, checkpointFile } = resolvePendingJournalPaths(descartesPaths, family);
  let read;
  try {
    read = await readJsonlStrict(journalFile);
  } catch {
    return { status: "discontinuity", cause: "journal_unreadable", state: null, sources: {} };
  }
  const checkpointRead = await readCheckpoint(checkpointFile, family);
  const checkpoint = checkpointRead.status === "valid" ? checkpointRead.checkpoint : null;
  const chain = read.bad_line === null ? verifyChain(PENDING_JOURNAL_DOMAIN, read.records, { cutKind: "cut" }) : { ...verifyChain(PENDING_JOURNAL_DOMAIN, read.records, { cutKind: "cut" }), ok: false, reason: "unparseable_line" };
  const sources = { checkpoint, prefix: chain.verified, header: chain.header, torn_tail: read.torn_tail };

  if (!read.exists || (read.records.length === 0 && !read.torn_tail)) {
    if (checkpoint) return { status: "discontinuity", cause: "journal_missing", state: null, sources };
    // Both gone: a first run, unless an independent witness (the daemon's transition log records
    // every journal creation) proves a journal existed. The witness is consulted only here.
    const witnessed = typeof witnessExists === "function" ? await witnessExists() : witnessExists === true;
    if (witnessed) return { status: "discontinuity", cause: "journal_and_checkpoint_missing", state: null, sources };
    return { status: "missing", state: emptyPendingState(family), sources };
  }
  if (!chain.ok) return { status: "discontinuity", cause: chain.reason === "unparseable_line" ? "journal_unparseable" : "chain_broken", state: null, sources };
  if (chain.header && !checkpoint) return { status: "discontinuity", cause: "checkpoint_missing_after_cut", state: null, sources };

  let state;
  if (checkpoint) {
    const stampSeq = checkpoint.stamp.journal_seq;
    if (stampSeq > chain.head_seq) return { status: "discontinuity", cause: "journal_truncated", state: null, sources };
    if (chain.header && stampSeq < chain.header.through_seq) return { status: "discontinuity", cause: "checkpoint_behind_cut", state: null, sources };
    const atStamp = stampSeq === 0 ? { hash: GENESIS_PREV_HASH } : (chain.header && stampSeq === chain.header.through_seq
      ? { hash: chain.header.through_hash }
      : chain.verified.find((record) => record.seq === stampSeq));
    if (!atStamp || atStamp.hash !== checkpoint.stamp.journal_head_hash) return { status: "discontinuity", cause: "checkpoint_contradicts_journal", state: null, sources };
    state = foldPendingEntries(checkpoint.state, chain.verified.filter((record) => record.seq > stampSeq));
  } else {
    // A missing or unreadable checkpoint with no cut is only an optimisation lost: rebuild.
    state = foldPendingEntries(emptyPendingState(family), chain.verified);
  }
  state.head_seq = chain.head_seq;
  state.head_hash = chain.head_hash;
  if (ledger && state.generation && ledger.generation !== state.generation) {
    return { status: "discontinuity", cause: "generation_change", state, sources, chain_intact: true };
  }
  return { status: "valid", state, sources, checkpoint_status: checkpointRead.status, torn_tail: read.torn_tail };
}

// I54 step 1: surviving terminal dispositions keep their provenance; where sources disagree the most
// restrictive wins, and an admission recorded only by an unverifiable source is never honoured.
export function mergeSurvivingDispositions(family, { verifiedState, unverifiableStates = [], unverifiableQuarantines = [] }) {
  const merged = verifiedState ? structuredClone(verifiedState) : emptyPendingState(family);
  for (const other of unverifiableStates) {
    for (const [id, item] of Object.entries(other?.items ?? {})) {
      const mine = merged.items[id];
      if (!mine) {
        // Known only to an unverifiable source: carried, but never as admitted.
        merged.items[id] = { ...structuredClone(item), state: item.state === "admitted" ? "pending" : item.state, disposition: item.state === "admitted" ? { unverified_admission_dropped: true } : item.disposition };
        continue;
      }
      if (DISPOSITION_RANK[item.state] > DISPOSITION_RANK[mine.state]) {
        mine.state = item.state;
        mine.disposition = { ...item.disposition, from_unverifiable_source: true };
      } else if (mine.state === "admitted" && item.state !== "admitted") {
        mine.state = item.state === "pending" ? "pending" : item.state;
      }
    }
    merged.quarantine_aggregate.count = Math.max(merged.quarantine_aggregate.count, other?.quarantine_aggregate?.count ?? 0);
  }
  for (const id of unverifiableQuarantines) {
    if (merged.items[id] && merged.items[id].state !== "quarantined") {
      merged.items[id].state = "quarantined";
      merged.items[id].disposition = { reason: "label", from_unverifiable_source: true };
    }
  }
  return merged;
}

async function writeCheckpointFile(checkpointFile, family, state, stamp) {
  const content = JSON.stringify({ v: PENDING_JOURNAL_SCHEMA_VERSION, family, stamp, state, cut: null });
  await atomicWrite(checkpointFile, content);
}

/**
 * Opens a family journal for writing in this tick: inspects it and, on a detected discontinuity,
 * performs the I54 entry (a new chain citing the lost head, carrying surviving dispositions, one
 * `unexplained_discontinuity` item for genuinely uncertain membership, an open epoch). Returns a
 * handle { family, state, head: {seq, hash}, discontinuity: {epoch, cause} | null, status }.
 */
export async function openPendingJournal(descartesPaths, family, { ledger = null, now, passId = null, witnessExists = false, unverifiableQuarantines = [] } = {}) {
  const ts = new Date(now ?? Date.now()).toISOString();
  const paths = resolvePendingJournalPaths(descartesPaths, family);
  const inspected = await inspectPendingJournal(descartesPaths, family, { ledger, witnessExists });
  if (inspected.status !== "discontinuity") {
    if (inspected.torn_tail) await trimTornTail(paths.journalFile);
    return { family, state: inspected.state, status: inspected.status, discontinuity: null, created: inspected.status === "missing" };
  }
  const nextEpoch = 1 + Math.max(0, ...(inspected.state?.epochs ?? []).map((epoch) => epoch.epoch),
    ...(inspected.sources?.checkpoint?.state?.epochs ?? []).map((epoch) => epoch.epoch),
    ...((inspected.sources?.prefix ?? []).filter((record) => record.kind === "discontinuity").map((record) => record.epoch)));
  if (inspected.chain_intact) {
    // Generation change: the chain is intact, so every certified entry stays valid; the epoch covers
    // what is scored from now on. Nothing is uncertain yet: no unexplained item.
    const handle = { family, state: inspected.state, status: "discontinuity", discontinuity: { epoch: nextEpoch, cause: inspected.cause } };
    await appendPendingEntries(descartesPaths, handle, [{ kind: "discontinuity", epoch: nextEpoch, cause: inspected.cause, ledger_generation: ledger?.generation ?? null, pass_id: passId }], { ledger, now: ts, restrictiveOnly: true });
    return handle;
  }
  // Chain-level loss: rebuild from every surviving source.
  const checkpointState = inspected.sources?.checkpoint?.state ?? null;
  const prefixState = (inspected.sources?.prefix?.length ?? 0) > 0 && !inspected.sources?.header
    ? foldPendingEntries(emptyPendingState(family), inspected.sources.prefix)
    : null;
  // The verified prefix is the verified source; a checkpoint that no longer matches the journal is
  // unverifiable. With no verified prefix, the checkpoint is the best survivor, still unverifiable.
  const merged = mergeSurvivingDispositions(family, {
    verifiedState: prefixState,
    unverifiableStates: [checkpointState].filter(Boolean),
    unverifiableQuarantines,
  });
  merged.family = family;
  merged.open_epoch = null;
  // I54 step 2: genuinely uncertain membership becomes ONE pending item, from the last certified
  // point (the last mapped observation any survivor knows) to now -- the whole raw window if none.
  const lastCertified = [prefixState?.last_observation_ts, checkpointState?.last_observation_ts].filter(Boolean).sort().at(-1) ?? null;
  const unexplainedId = pendingItemId({ alert_id: "unexplained_discontinuity", episode: `epoch-${nextEpoch}`, incident_key: family });
  merged.items[unexplainedId] = {
    item: { alert_id: "unexplained_discontinuity", episode: `epoch-${nextEpoch}`, incident_key: family },
    state: "pending",
    opened_seq: 0,
    opened_ts: ts,
    ticks: [],
    stats: null,
    exemplars: [],
    raise_ref: null,
    serving_snapshot: null,
    covers: { from_ts: lastCertified, to_ts: ts, whole_raw_window: lastCertified === null },
    disposition: null,
    disposition_seq: 0,
  };
  const { head_seq: _seq, head_hash: lostHead, ...carried } = merged;
  try {
    await fs.mkdir(paths.dir, { recursive: true, mode: 0o700 });
    await fs.rename(paths.journalFile, paths.brokenFile);
  } catch {
    // Nothing to keep aside (the journal is missing).
  }
  const first = sealRecord(PENDING_JOURNAL_DOMAIN, { prevHash: `lost:${(inspected.sources?.prefix?.at(-1)?.hash) ?? lostHead ?? "unknown"}`, seq: 1 }, {
    v: PENDING_JOURNAL_SCHEMA_VERSION,
    ts,
    kind: "discontinuity",
    family,
    restart: true,
    epoch: nextEpoch,
    cause: inspected.cause,
    pass_id: passId,
    ledger_generation: ledger?.generation ?? null,
    unexplained_item_id: unexplainedId,
    carried_state: carried,
  });
  await atomicWrite(paths.journalFile, `${JSON.stringify(first)}\n`);
  const state = foldPendingEntries(emptyPendingState(family), [first]);
  await writeCheckpointFile(paths.checkpointFile, family, state, { generation: ledger?.generation ?? null, pass_id: passId, journal_seq: first.seq, journal_head_hash: first.hash });
  return { family, state, status: "discontinuity", discontinuity: { epoch: nextEpoch, cause: inspected.cause, unexplained_item_id: unexplainedId } };
}

/**
 * Appends entries on the handle's chain. Non-restrictive entries are certified at write against the
 * given ledger and the pass they cite (I70); an uncertifiable one is refused (throws
 * PendingJournalWriteRefused) before anything is written. Mutates and returns the handle.
 */
export async function appendPendingEntries(descartesPaths, handle, bodies, { ledger = null, now, restrictiveOnly = false } = {}) {
  if (bodies.length === 0) return handle;
  const ts = new Date(now ?? Date.now()).toISOString();
  const { journalFile } = resolvePendingJournalPaths(descartesPaths, handle.family);
  const prepared = [];
  for (const body of bodies) {
    if (!ENTRY_KIND_SET.has(body.kind)) throw new PendingJournalWriteRefused(`unknown pending entry kind ${body.kind}`);
    if (restrictiveOnly && !RESTRICTIVE_KINDS.has(body.kind)) throw new PendingJournalWriteRefused(`${body.kind} is not restrictive`);
    if (body.kind === "admitted" && ![...EXPLANATION_SOURCES].includes(body.source)) throw new PendingJournalWriteRefused(`admission source ${body.source} is not in the closed set`);
    let cert = null;
    if (!RESTRICTIVE_KINDS.has(body.kind)) {
      const passId = body.scored_pass_id ?? body.pass_id;
      const certified = certifyPendingWrite({ ledger, passId, passTimeMs: body.pass_time_ms });
      if (!certified.ok) throw new PendingJournalWriteRefused(`pending entry ${body.kind} not certifiable: ${certified.reason}`);
      cert = { ledger_generation: certified.generation, span: certified.span };
    }
    const payload = { ...body };
    for (const key of ["stats", "raise_ref", "serving_snapshot", "exemplar", "evidence_ref"]) {
      if (payload[key] !== undefined) payload[key] = boundedPayload(payload[key]);
    }
    prepared.push({ v: PENDING_JOURNAL_SCHEMA_VERSION, ts, family: handle.family, ...payload, ...(cert ? { ledger_generation: cert.ledger_generation, certified_span: cert.span } : {}) });
  }
  let seq = handle.state.head_seq;
  let prevHash = handle.state.head_hash;
  const sealed = prepared.map((body) => {
    seq += 1;
    const record = sealRecord(PENDING_JOURNAL_DOMAIN, { prevHash, seq }, body);
    prevHash = record.hash;
    return record;
  });
  await appendLines(journalFile, sealed);
  handle.state = foldPendingEntries(handle.state, sealed);
  handle.appended = (handle.appended ?? 0) + sealed.length;
  return handle;
}

/**
 * Writes a fresh checkpoint stamped (generation, pass id, journal seq, head hash), drops tick marks
 * the family's retention has evicted, and cuts the journal prefix the checkpoint covers once the
 * journal is past its size bound (leaving a header with the hash at the cut).
 */
export async function checkpointPendingJournal(descartesPaths, handle, { ledger = null, passId = null, maxJournalBytes = MAX_JOURNAL_BYTES_BEFORE_CUT } = {}) {
  const paths = resolvePendingJournalPaths(descartesPaths, handle.family);
  const floor = [ledger?.age_floor_ts, ledger?.bytecap_floor_ts].filter((value) => typeof value === "string").map(Date.parse).filter(Number.isFinite);
  const floorMs = floor.length > 0 ? Math.max(...floor) : null;
  if (floorMs !== null) {
    for (const item of Object.values(handle.state.items)) {
      // The tick no longer exists to fold; the item keeps its sufficient statistics and stays as is.
      item.ticks = item.ticks.filter((tick) => !(Date.parse(tick.ts) <= floorMs));
    }
  }
  const stamp = { generation: ledger?.generation ?? handle.state.generation ?? null, pass_id: passId, journal_seq: handle.state.head_seq, journal_head_hash: handle.state.head_hash };
  await writeCheckpointFile(paths.checkpointFile, handle.family, handle.state, stamp);
  let cut = false;
  try {
    const stat = await fs.stat(paths.journalFile);
    if (stat.size > maxJournalBytes && handle.state.head_seq > 0) {
      const header = { kind: "cut", through_seq: handle.state.head_seq, through_hash: handle.state.head_hash, through_ts: new Date().toISOString(), v: PENDING_JOURNAL_SCHEMA_VERSION };
      await atomicWrite(paths.journalFile, `${JSON.stringify(header)}\n`);
      cut = true;
    }
  } catch {
    // No journal yet.
  }
  return { checkpointed: true, cut };
}

/**
 * Daemon pre-detection step for one family, after its pass committed (item 16, I69, I54 exit):
 * maps the committed pass to its observation time, journals unmapped and unscored passes as
 * excluded ranges, and re-certifies an open epoch at the first clean pass after the break.
 * `passResult` is the family's appendFactPointsByFamily entry for this tick.
 */
export async function journalCommittedPass(descartesPaths, family, { passResult, ledger, ts, witnessExists = false, censusComplete = true } = {}) {
  const now = new Date(ts ?? Date.now()).toISOString();
  const retention = passResult?.retention;
  const passId = retention?.pass_id;
  const handle = await openPendingJournal(descartesPaths, family, { ledger, now, passId: passId ?? null, witnessExists });
  const report = { family, status: handle.status, discontinuity: handle.discontinuity, created: handle.created === true, mapped: null, excluded_ranges: 0, recertified: null };
  if (!Number.isSafeInteger(passId) || passResult?.append_error || passResult?.retention_error) {
    report.mapped = "no_committed_pass";
    return { handle, report };
  }
  const state = handle.state;
  const entries = [];
  // Committed, mapped passes that were never scored (a crash between commit and detection, or a
  // failed detection): C1 does not replay them, so they are excluded(unadjudicated) -- never folded.
  const unscored = unscoredPasses(state).filter((pass) => pass.pass_id < passId);
  if (unscored.length > 0) {
    entries.push({ kind: "excluded", reason: "unadjudicated", pass_from: unscored[0].pass_id, pass_to: unscored.at(-1).pass_id,
      observation_ts_from: unscored.find((pass) => pass.observation_ts)?.observation_ts ?? null,
      observation_ts_to: [...unscored].reverse().find((pass) => pass.observation_ts)?.observation_ts ?? null });
  }
  // Passes the ledger committed that this journal never mapped. Their observations, if any, lie
  // between the last mapped observation and this one.
  if (state.last_mapped_pass_id > 0 && passId > state.last_mapped_pass_id + 1 && state.generation === ledger?.generation) {
    entries.push({ kind: "excluded", reason: "unmapped_pass", pass_from: state.last_mapped_pass_id + 1, pass_to: passId - 1,
      observation_ts_from: state.last_observation_ts, observation_ts_to: (passResult.written_count ?? 0) > 0 ? now : null });
  }
  const certified = certifyPendingWrite({ ledger, passId, passTimeMs: retention.pass_time_ms });
  if (!certified.ok) {
    entries.push({ kind: "excluded", reason: `uncertified_pass:${certified.reason}`, pass_from: passId, pass_to: passId, observation_ts_from: now, observation_ts_to: now });
    await appendPendingEntries(descartesPaths, handle, entries, { ledger, now });
    report.mapped = "uncertified";
    report.excluded_ranges = entries.length;
    return { handle, report };
  }
  if (passId > state.last_mapped_pass_id || state.generation !== ledger?.generation) {
    entries.push({ kind: "pass_committed", pass_id: passId, pass_time_ms: retention.pass_time_ms ?? null, observation_ts: (passResult.written_count ?? 0) > 0 ? now : null,
      written_count: passResult.written_count ?? 0, prev_pass_id: state.last_mapped_pass_id || null });
  }
  // I54 exit: the first clean, certified pass with a complete census AFTER the break re-certifies.
  const openEpoch = handle.state.epochs.find((epoch) => epoch.epoch === handle.state.open_epoch);
  if (openEpoch && censusComplete && (passResult.written_count ?? 0) > 0 && Number.isSafeInteger(openEpoch.opened_pass_id) && passId > openEpoch.opened_pass_id) {
    entries.push({ kind: "recertified", epoch: openEpoch.epoch, pass_id: passId, pass_time_ms: retention.pass_time_ms ?? null, carried_item_ids: pendingMembership(handle.state).slice(0, MAX_OPEN_PENDING_ITEMS) });
    report.recertified = openEpoch.epoch;
  }
  await appendPendingEntries(descartesPaths, handle, entries, { ledger, now });
  report.mapped = "mapped";
  report.excluded_ranges = entries.filter((entry) => entry.kind === "excluded").length;
  return { handle, report };
}

/** Daemon post-detection step: advance the watermark (journal, then alerts, then watermark) and checkpoint. */
export async function journalScoredThrough(descartesPaths, handle, { ledger, passId, scored, ts } = {}) {
  const now = new Date(ts ?? Date.now()).toISOString();
  if (scored && Number.isSafeInteger(passId) && passId > handle.state.watermark && handle.state.passes[passId]) {
    await appendPendingEntries(descartesPaths, handle, [{ kind: "scored_through", pass_id: passId, pass_time_ms: handle.state.passes[passId].pass_time_ms ?? null }], { ledger, now });
  }
  await checkpointPendingJournal(descartesPaths, handle, { ledger, passId });
  return { watermark: handle.state.watermark, admission: pendingAdmissionStatus(handle.state, now) };
}

/** I3: before opening new items at the cap, the oldest unadmitted pending items compact into excluded. */
export function compactionEntriesForCap(state, incomingCount = 1) {
  const pending = Object.entries(state.items).filter(([, item]) => item.state === "pending")
    .sort(([, left], [, right]) => left.opened_seq - right.opened_seq);
  const overflow = pending.length + incomingCount - MAX_OPEN_PENDING_ITEMS;
  if (overflow <= 0) return [];
  const victims = pending.slice(0, overflow);
  return [{ kind: "compacted", item_ids: victims.map(([id]) => id), digests: victims.map(([, item]) => itemDigest(item)) }];
}
