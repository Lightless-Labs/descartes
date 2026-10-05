// S3b: the per-novelty-family first/last-seen set (fact-store capacity plan §17, operator Q6).
//
// WHY. Under R0b the fact store narrows (byte-cap eviction removes an oldest-end prefix). The three
// novelty rules (service.appeared, scheduled_job.appeared, process.lineage.novel_edge) decided
// "never seen before" against the retained window, so an entity last seen BEFORE the floor would
// read as new when it returned (daybreak G1 blocker 1: present at t0, absent t1-t3, back at t4, t0
// evicted). This set keeps a compact entity -> {first_seen, last_seen} memory per novelty family,
// retained 30 days past last_seen, that eviction from the fact store never touches (I13).
//
// TRUST-BEARING, so (§17):
//   - FOLDED ONLY BY THE FACT-STORE RETENTION PASS, in the same pass as the append (fact-store.js
//     runFactRetention calls foldNoveltySeenSets after the ledger is finalized), only from COMPLETE
//     census ticks (strict census grouping, parity-tested against the detectors' groupers), only
//     ticks at or before the pass's own clock (non-future), and only from the pass's in-retention
//     candidates. Fold source deviation (plan §18): the pass's PRE-eviction candidate set, so a
//     tick this pass byte-evicts is still folded -- and so is a tick a clock rollback appended at
//     or below a prior floor (S3b review LOW-4: evicted physically, but observed) -- added memory can only
//     SUPPRESS a novelty claim, never create one, and it closes the "kept at P, fold write lost,
//     evicted at P+1" gap without relying on the next pass seeing the tick.
//   - LINEAGE-STAMPED to the fact ledger: ledger_generation + ledger_pass_id (the committed pass it
//     was folded with). A read validates the set against the SAME ledger readFactPoints just read --
//     generation match, pass id === last_committed_pass_id, no pending pass -- and anything else
//     (missing, unreadable, invalid shape, mismatch, pending, overflow) is NOT valid: the novelty
//     detector then keeps the interim full-coverage gate, so under narrowing it re-arms and claims
//     nothing (I14). Never "everything is new".
//   - RE-SEED on any loss of continuity (missing/invalid/mismatched set, overflow): rebuilt from the
//     pass's certified candidates with certified_since_ts = the newest point before which memory is
//     not certified: max(prior byte-cap floor, prior age floor, every loss marker) when this pass's
//     continuity observation is ok, else the pass time. null ONLY for a genuine first run (ENOENT
//     store) or a lineage that never evicted or lost anything -- "complete since the lineage began" --
//     and never on an install that held a legacy single store (G2 H1: marker or legacy item present;
//     the lineage began at the upgrade, not with the host's history), where it is the pass time.
//     When the prior file still parses as a valid, non-overflow set for the family, its entries are
//     carried into the re-seed (S3b review MEDIUM-1: memory that can only suppress a claim), but
//     never its certified_since_ts; if carrying them would overflow, the re-seed retries bare.
//   - BOUNDED: at most maxEntries entries. Overflow never silently drops an entry: the set is written
//     as {overflow: true, entries: {}}, which reads as not-valid (novelty ineligible, status reason
//     "overflow"), and every later pass retries a fresh re-seed.
//
// S4 (fact-store capacity plan §4.3): every entry point is keyed by family. Each novelty family's set
// lives INSIDE its own family store directory (learned/facts/<family>/seen-set.json) and pairs with
// THAT family's ledger: the family's own retention pass folds it, and a read validates it against
// the same family ledger readFactPoints just read. The pre-S4 location (learned/facts/seen-sets/)
// is legacy; S5 quarantines it with the legacy facts.jsonl so nothing under learned/facts/ is a
// directory the registry does not name.

import fs from "node:fs/promises";
import path from "node:path";
import { COMPLETENESS_LOSS_TIMESTAMP_FIELDS } from "./fact-store-completeness.js";
import { NOVELTY_FAMILIES } from "./fact-families.js";
import { legacyFactHistoryEvidence, legacyQuarantineEpoch } from "./fact-store-migration.js";

export const SEEN_SET_SCHEMA_VERSION = 1;
// Sized against §2's measured host (518 services, 175 lineage edges, 7 scheduled jobs per tick):
// distinct keys over 30 days are expected in the hundreds-to-low-thousands per family. 20,000
// entries (~2 MB at the ~100 B/entry of a hashed key + two timestamps) leaves an order of magnitude
// of headroom while bounding the per-fast-tick parse cost.
export const DEFAULT_SEEN_SET_MAX_ENTRIES = 20_000;
export const DEFAULT_SEEN_SET_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_SEEN_SET_KEY_LENGTH = 256;

const SEEN_SET_KEYS = [
  "schema_version",
  "family",
  "ledger_generation",
  "ledger_pass_id",
  "quarantine_epoch",
  "quarantine_epoch_ts",
  "certified_since_ts",
  "folded_through_ts",
  "overflow",
  "entries",
];

function requireNoveltyFamily(family) {
  if (!NOVELTY_FAMILIES.has(family)) throw new Error(`novelty-seen-set: unknown novelty family ${String(family)}`);
  return NOVELTY_FAMILIES.get(family);
}

export function resolveSeenSetPaths(descartesPaths, family) {
  requireNoveltyFamily(family);
  const dir = path.join(descartesPaths.stateDir, "learned", "facts", family);
  return { dir, file: path.join(dir, "seen-set.json") };
}

function isIsoTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * The detectors' census grouping, re-implemented here because fact-store.js cannot import a
 * detector (ESM cycle). Byte-for-byte the same semantics as groupServiceFactsByTick /
 * groupProcessLineageFactsByTick / groupScheduledJobFactsByTick (pinned by a parity test): a strict
 * "complete"/"partial" match on the census marker, anything else "unknown", a contradictory second
 * marker in the same tick "unknown", markerless ticks undefined.
 */
export function groupNoveltyFamilyTicks(points, family) {
  const { presenceFactName, censusFactName } = requireNoveltyFamily(family);
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || typeof point.ts !== "string") continue;
    if (point.fact_name !== presenceFactName && point.fact_name !== censusFactName) continue;
    if (!byTs.has(point.ts)) byTs.set(point.ts, { ts: point.ts, censusState: undefined, censusMarkerSeen: false, entityKeys: new Set() });
    const group = byTs.get(point.ts);
    if (point.fact_name === censusFactName) {
      const rawState = point.attributes?.census_state;
      const markerState = rawState === "complete" ? "complete" : rawState === "partial" ? "partial" : "unknown";
      group.censusState = group.censusMarkerSeen && markerState !== group.censusState ? "unknown" : markerState;
      group.censusMarkerSeen = true;
    } else {
      group.entityKeys.add(point.entity_key);
    }
  }
  return [...byTs.values()].sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
}

export function isValidSeenSet(raw, family, { maxEntries = DEFAULT_SEEN_SET_MAX_ENTRIES } = {}) {
  if (!isPlainObject(raw)) return false;
  const keys = Object.keys(raw).sort();
  if (keys.length !== SEEN_SET_KEYS.length || !keys.every((key, index) => key === [...SEEN_SET_KEYS].sort()[index])) return false;
  if (raw.schema_version !== SEEN_SET_SCHEMA_VERSION || raw.family !== family) return false;
  if (typeof raw.ledger_generation !== "string" || raw.ledger_generation.length === 0) return false;
  if (!Number.isSafeInteger(raw.ledger_pass_id) || raw.ledger_pass_id < 0) return false;
  if (!Number.isSafeInteger(raw.quarantine_epoch) || raw.quarantine_epoch < 0) return false;
  if (raw.quarantine_epoch_ts !== null && !isIsoTimestamp(raw.quarantine_epoch_ts)) return false;
  if (raw.certified_since_ts !== null && !isIsoTimestamp(raw.certified_since_ts)) return false;
  if (raw.folded_through_ts !== null && !isIsoTimestamp(raw.folded_through_ts)) return false;
  if (typeof raw.overflow !== "boolean" || !isPlainObject(raw.entries)) return false;
  const entries = Object.entries(raw.entries);
  if (raw.overflow && entries.length !== 0) return false;
  if (entries.length > maxEntries) return false;
  for (const [key, value] of entries) {
    if (key.length === 0 || key.length > MAX_SEEN_SET_KEY_LENGTH) return false;
    if (!Array.isArray(value) || value.length !== 2 || !isIsoTimestamp(value[0]) || !isIsoTimestamp(value[1])) return false;
    if (Date.parse(value[0]) > Date.parse(value[1])) return false;
  }
  return true;
}

export async function readSeenSetFile(descartesPaths, family, { maxEntries } = {}) {
  const { file } = resolveSeenSetPaths(descartesPaths, family);
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { set: null, reason: "missing" };
    return { set: null, reason: "unreadable" };
  }
  try {
    const parsed = JSON.parse(contents);
    return isValidSeenSet(parsed, family, { maxEntries }) ? { set: parsed, reason: null } : { set: null, reason: "invalid" };
  } catch {
    return { set: null, reason: "invalid" };
  }
}

async function writeSeenSetFile(descartesPaths, family, set) {
  const { dir, file } = resolveSeenSetPaths(descartesPaths, family);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmpFile = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, `${JSON.stringify(set)}\n`, { mode: 0o600 });
  await fs.rename(tmpFile, file);
}

function entriesToMap(rawEntries) {
  const map = new Map();
  for (const [key, [first, last]] of Object.entries(rawEntries)) map.set(key, { firstMs: Date.parse(first), lastMs: Date.parse(last) });
  return map;
}

function mapToEntries(map) {
  return Object.fromEntries([...map.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, { firstMs, lastMs }]) => [key, [new Date(firstMs).toISOString(), new Date(lastMs).toISOString()]]));
}

function foldTicks(map, records, family, nowMs) {
  let foldedThroughMs = Number.NEGATIVE_INFINITY;
  for (const group of groupNoveltyFamilyTicks(records, family)) {
    if (group.censusState !== "complete") continue; // partial/unknown/markerless ticks are never folded
    const tsMs = Date.parse(group.ts);
    if (!Number.isFinite(tsMs) || tsMs > nowMs) continue; // non-future only
    if (tsMs > foldedThroughMs) foldedThroughMs = tsMs;
    for (const key of group.entityKeys) {
      if (typeof key !== "string" || key.length === 0 || key.length > MAX_SEEN_SET_KEY_LENGTH) continue;
      const entry = map.get(key);
      if (!entry) map.set(key, { firstMs: tsMs, lastMs: tsMs });
      else map.set(key, { firstMs: Math.min(entry.firstMs, tsMs), lastMs: Math.max(entry.lastMs, tsMs) });
    }
  }
  return foldedThroughMs;
}

function expire(map, nowMs, retentionMs) {
  const cutoffMs = nowMs - retentionMs;
  for (const [key, entry] of map) if (entry.lastMs < cutoffMs) map.delete(key);
}

function laterIso(left, right) {
  if (left === null || left === undefined) return right ?? null;
  if (right === null || right === undefined) return left;
  return Date.parse(right) > Date.parse(left) ? right : left;
}

// The re-seed boundary (see the module header): memory is complete only for ticks after every
// floor the prior pass excluded and every recorded loss. Requires this pass's own continuity
// observation to be ok; otherwise nothing before the pass time is certified.
function reseedCertifiedSince({ priorLedger, nextLedger, nowIso }) {
  if (nextLedger?.continuity?.continuity_ok !== true) return nowIso;
  let since = null;
  since = laterIso(since, priorLedger?.bytecap_floor_ts ?? null);
  since = laterIso(since, priorLedger?.age_floor_ts ?? null);
  for (const field of COMPLETENESS_LOSS_TIMESTAMP_FIELDS) since = laterIso(since, nextLedger[field] ?? null);
  if (since !== null && Date.parse(since) > Date.parse(nowIso)) return nowIso;
  return since;
}

function quarantineBoundary({ priorSet, quarantineState, nowIso }) {
  const priorSince = priorSet?.certified_since_ts ?? null;
  const priorEpoch = priorSet?.quarantine_epoch ?? 0;
  const priorEpochTs = priorSet?.quarantine_epoch_ts ?? null;
  if (quarantineState.status === "unreadable" || quarantineState.status === "legacy_pending") {
    // The marker/root evidence has no trusted epoch. Every observation is therefore a new discard
    // episode: retaining an older timestamp would let newly pending legacy data pass as already
    // handled. The epoch is advanced in the seen-set itself so the next observation is distinct too.
    return { certifiedSince: nowIso, epoch: priorEpoch + 1, epochTs: nowIso };
  }
  const currentEpoch = quarantineState.epoch ?? 0;
  const currentEpochTs = quarantineState.epoch_ts ?? null;
  const epochChanged = currentEpoch !== priorEpoch || currentEpochTs !== priorEpochTs;
  if (!epochChanged) return { certifiedSince: priorSince, epoch: priorEpoch, epochTs: priorEpochTs };
  // A trusted quarantine event discards the old store's sightings. The boundary can only move
  // forward; it must never remain null when the set was certified before that event.
  const boundary = currentEpochTs ?? nowIso;
  return { certifiedSince: laterIso(priorSince, boundary) ?? nowIso, epoch: currentEpoch, epochTs: currentEpochTs ?? nowIso };
}

/**
 * Folds this retention pass's certified candidates into `family`'s seen-set (S4: the novelty
 * family's OWN store pass folds it; a non-novelty family has no set). Called by fact-store.js after
 * the ledger finalize, with:
 *   priorLedger / priorLedgerReason: the ledger as read at the START of the pass (null + reason when
 *     missing/invalid/unreadable);
 *   liveExists: whether facts.jsonl existed at the start of the pass (genuine first run detection);
 *   nextLedger / passId: the ledger this pass just committed, and its pass id;
 *   records: the pass's candidate records (normalized fact points above the prior floors);
 *   nowMs, retentionMs, maxEntries.
 * Never throws: each family's outcome (or error) is returned, and a failed write leaves the old file,
 * whose pass id then mismatches the ledger -> not valid on read, re-seeded next pass.
 */
export async function foldNoveltySeenSets(descartesPaths, {
  family: storeFamily,
  priorLedger,
  priorLedgerReason,
  liveExists,
  nextLedger,
  passId,
  records,
  nowMs,
  retentionMs = DEFAULT_SEEN_SET_RETENTION_MS,
  maxEntries = DEFAULT_SEEN_SET_MAX_ENTRIES,
}) {
  const outcomes = {};
  const nowIso = new Date(nowMs).toISOString();
  const genuineFirstRun = priorLedgerReason === "missing" && liveExists === false;
  for (const family of NOVELTY_FAMILIES.keys()) {
    if (family !== storeFamily) continue;
    try {
      const prior = await readSeenSetFile(descartesPaths, family, { maxEntries });
      const continuous = Boolean(
        prior.set
        && !prior.set.overflow
        && priorLedger
        && nextLedger
        && prior.set.ledger_generation === priorLedger.generation
        && prior.set.ledger_generation === nextLedger.generation
        && prior.set.ledger_pass_id === priorLedger.continuity.last_committed_pass_id,
      );
      const quarantineState = await legacyQuarantineEpoch(descartesPaths);
      let reseedSince = genuineFirstRun ? null : reseedCertifiedSince({ priorLedger, nextLedger, nowIso });
      // G2 H1: null means "complete since the lineage began", which is the host's whole history only
      // when no legacy single store ever existed. After an S5 upgrade every family store starts a new
      // lineage (a "genuine first run" by the store's own evidence) over sightings the quarantine
      // discarded, so a null boundary would let the 30-day scoped novelty claim reach back over them
      // and skip the Q2 horizons entirely. With legacy evidence, nothing before this pass is
      // certified. Probed only when the boundary is null and would actually be used (a re-seed).
      if (reseedSince === null && !continuous && await legacyFactHistoryEvidence(descartesPaths)) reseedSince = nowIso;
      // S3b review MEDIUM-1: a NON-continuous re-seed still starts from the prior file's entries when
      // it parses as a valid, non-overflow set for this family (readSeenSetFile enforces both) --
      // e.g. a lost fold write, or a daemon death between the ledger finalize and the set rename.
      // Those entries are real observations; added memory can only SUPPRESS a novelty claim, never
      // create one. The certified boundary is NOT taken from it: certified_since stays the re-seed
      // boundary, because continuity between that file and this ledger is exactly what is unproven.
      const carriesPrior = Boolean(prior.set && !prior.set.overflow);
      let map = carriesPrior ? entriesToMap(prior.set.entries) : new Map();
      let certifiedSince = continuous ? prior.set.certified_since_ts : reseedSince;
      let quarantineEpoch = continuous ? prior.set.quarantine_epoch : (quarantineState.epoch ?? 0);
      let quarantineEpochTs = continuous ? prior.set.quarantine_epoch_ts : (quarantineState.epoch_ts ?? null);
      if (continuous || quarantineState.status === "unreadable" || quarantineState.status === "legacy_pending") {
        const boundary = quarantineBoundary({ priorSet: prior.set, quarantineState, nowIso });
        certifiedSince = boundary.certifiedSince;
        quarantineEpoch = boundary.epoch;
        quarantineEpochTs = boundary.epochTs;
      }
      let status = continuous ? "folded" : "reseeded";
      let foldedThroughMs = foldTicks(map, records, family, nowMs);
      expire(map, nowMs, retentionMs);
      if (map.size > maxEntries && carriesPrior) {
        // Overflow of a set that carried prior memory (continuous, or a merged re-seed): retry as a
        // bare re-seed from this pass's certified candidates (older memory is discarded, so the
        // boundary moves up to the re-seed boundary).
        map = new Map();
        if (reseedSince === null && await legacyFactHistoryEvidence(descartesPaths)) reseedSince = nowIso;
        certifiedSince = reseedSince;
        quarantineEpoch = quarantineState.epoch ?? quarantineEpoch;
        quarantineEpochTs = quarantineState.epoch_ts ?? quarantineEpochTs;
        if (quarantineState.status === "unreadable" || quarantineState.status === "legacy_pending") {
          certifiedSince = laterIso(certifiedSince, nowIso) ?? nowIso;
          quarantineEpochTs = nowIso;
        }
        status = "reseeded";
        foldedThroughMs = foldTicks(map, records, family, nowMs);
        expire(map, nowMs, retentionMs);
      }
      const overflow = map.size > maxEntries;
      const priorFoldedThrough = continuous ? prior.set.folded_through_ts : null;
      const foldedThroughTs = Number.isFinite(foldedThroughMs) ? laterIso(priorFoldedThrough, new Date(foldedThroughMs).toISOString()) : priorFoldedThrough;
      await writeSeenSetFile(descartesPaths, family, {
        schema_version: SEEN_SET_SCHEMA_VERSION,
        family,
        ledger_generation: nextLedger.generation,
        ledger_pass_id: passId,
        quarantine_epoch: quarantineEpoch,
        quarantine_epoch_ts: quarantineEpochTs,
        certified_since_ts: overflow ? nowIso : certifiedSince,
        folded_through_ts: foldedThroughTs,
        overflow,
        entries: overflow ? {} : mapToEntries(map),
      });
      outcomes[family] = { status: overflow ? "overflow" : status, entry_count: overflow ? 0 : map.size };
    } catch (error) {
      outcomes[family] = { status: "error", error: (error instanceof Error ? error.message : String(error)) || "unknown seen-set error" };
    }
  }
  return outcomes;
}

/**
 * Read-side validation against the ledger the SAME readFactPoints call just read. Returns a
 * display-safe summary plus, only when valid, the entries map the novelty detectors consult.
 */
export async function readNoveltySeenSet(descartesPaths, family, { ledger, nowMs, retentionMs = DEFAULT_SEEN_SET_RETENTION_MS, maxEntries } = {}) {
  const { set, reason } = await readSeenSetFile(descartesPaths, family, { maxEntries });
  const base = { family, status: reason ?? "valid", certified_since_ts: null, scope_ts: null, entry_count: 0 };
  if (!set) return base;
  base.certified_since_ts = set.certified_since_ts;
  base.entry_count = Object.keys(set.entries).length;
  if (set.overflow) return { ...base, status: "overflow" };
  if (!ledger) return { ...base, status: "no_ledger" };
  if (ledger.continuity?.pending_pass) return { ...base, status: "pending_pass" };
  if (set.ledger_generation !== ledger.generation || set.ledger_pass_id !== ledger.continuity?.last_committed_pass_id) {
    return { ...base, status: "lineage_mismatch" };
  }
  // The claim's scope: memory runs back to certified_since (or the lineage start) but never further
  // than the 30-day retention past last_seen.
  const retentionStartMs = Number.isFinite(nowMs) ? nowMs - retentionMs : Number.NEGATIVE_INFINITY;
  const sinceMs = set.certified_since_ts === null ? Number.NEGATIVE_INFINITY : Date.parse(set.certified_since_ts);
  const scopeMs = Math.max(sinceMs, retentionStartMs);
  return {
    ...base,
    status: "valid",
    scope_ts: Number.isFinite(scopeMs) ? new Date(scopeMs).toISOString() : null,
    entries: entriesToMap(set.entries),
  };
}

/**
 * The novelty decision against the seen-set: true when `entityKey` was observed at some tick OTHER
 * than `latestTs`. The set is folded in the same pass as the append, so the latest tick's own
 * entities are already in it -- an entry whose only observation is the latest tick is still novel.
 * An observation at any other ts (earlier, or LATER -- a future-dated entry surviving a clock
 * rollback) is a prior sighting: more memory only ever suppresses a claim.
 */
export function seenBeforeTick(entries, entityKey, latestTs) {
  if (!(entries instanceof Map)) return false;
  const entry = entries.get(entityKey);
  if (!entry) return false;
  const latestMs = Date.parse(latestTs);
  return !(entry.firstMs === latestMs && entry.lastMs === latestMs);
}
