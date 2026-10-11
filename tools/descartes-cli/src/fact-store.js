import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  buildCompleteness,
  finalizeFactIntegrityLedger,
  FUTURE_FACT_TOLERANCE_MS,
  prepareFactIntegrityLedger,
  combineFamilyCompleteness,
  observeFactContinuity,
  readFactIntegrityLedger,
  resolveFactIntegrityPaths,
  resolvePriorBytecapFloor,
  writeFactIntegrityLedger,
} from "./fact-store-integrity.js";
import { foldNoveltySeenSets, readNoveltySeenSet } from "./novelty-seen-set.js";
import { CONTEXT_FACT_SCHEMAS, validateContextFact } from "./context-schemas.js";
import {
  DERIVED_FAMILIES,
  FACT_FAMILY_IDS,
  FAMILY_DEFAULT_BUDGET_BYTES,
  factFamilyForName,
  familyRetentionMs,
  groupFactPointsByFamily,
  NOVELTY_FAMILIES,
  requireFactFamily,
} from "./fact-families.js";

// Categorical fact-point store — distinct from history-store.js's numeric metric-point
// schema (whose normalizeMetricPoint throws on !Number.isFinite(value)). Structural facts
// (service presence, listening-port ownership, ...) are inherently categorical/string-valued
// and cannot live in metrics.jsonl. Mirrors history-store.js's/constraint-store.js's
// conventions (atomic tmp+rename writes for anything read back to make a decision,
// corrupt-tolerant per-line reads) — see plan §1/§3.
export const DEFAULT_FACT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
// The pre-S4 single shared store's cap. S4 (fact-store capacity plan §4.3/§4.5) replaces it with
// per-family budgets (fact-families.js FAMILY_DEFAULT_BUDGET_BYTES; watch.json fact_store_budgets);
// it survives only as the value watch.json/learned.json used to write in by default, so the Q5
// deprecation check can tell that written-in default apart from a deliberate operator value.
export const DEFAULT_FACT_MAX_BYTES = 5 * 1024 * 1024; // 5MB

// Fix 0 (trusted-state step-1 revision, "R1 made signable"): the future-fact tolerance. Defined in
// fact-store-integrity.js (the R0b future-floor clamp needs it there) and re-exported here for
// every existing importer.
export { FUTURE_FACT_TOLERANCE_MS };

// daybreak-blue security sweep (2026-09-04), fact-store HIGH #5 (cheap-caps portion): bound
// attribute-key count/length and fact_name/entity_key/source_* lengths so a doctored fact
// point can't be fully built (and later stored/read back as normal) before any cap applies.
// Over-cap input is REJECTED (throws), never silently truncated -- see normalizeAttributes
// and normalizeFactPoint below.
export const MAX_FACT_ATTRIBUTE_COUNT = 64;
export const MAX_FACT_ATTRIBUTE_KEY_LENGTH = 160;
export const MAX_FACT_NAME_LENGTH = 256;
export const MAX_FACT_ENTITY_KEY_LENGTH = 256;
export const MAX_FACT_SOURCE_LENGTH = 256;
// daybreak-blue re-gate (2026-09-04), fact-store MEDIUM: sensitivity is a short categorical
// label ("operational", "path", "process_identity", ...) throughout the codebase, never a
// free-form value -- cap it like the other fields so it can't be built unbounded either.
export const MAX_FACT_SENSITIVITY_LENGTH = 64;

/**
 * S4 (fact-store capacity plan §4.3, I7): one store per fact family, at
 * learned/facts/<family>/facts.jsonl (with its own integrity.json ledger, and for a novelty family
 * its seen-set.json, beside it). `family` is REQUIRED and must be a registry family: there is no
 * legacy single-file default, so a caller that was not migrated throws instead of silently reading
 * an empty store (which, after S5 quarantines the legacy facts.jsonl, would silently lose
 * detection). Every reader, the retention sweep and the status surfaces iterate the closed
 * registry (fact-families.js FACT_FAMILY_IDS), never the filesystem: a directory under
 * learned/facts/ is NOT a family because it exists.
 */
export function resolveFactStorePaths(descartesPaths, family) {
  const dir = path.join(resolveFactsRootDir(descartesPaths), requireFactFamily(family));
  return { dir, factsFile: path.join(dir, "facts.jsonl") };
}

// The parent of every family store directory. Never iterated to discover families (see above);
// exported for the S5 legacy-store quarantine, which moves the pre-S4 files out of it.
export function resolveFactsRootDir(descartesPaths) {
  return path.join(descartesPaths.stateDir, "learned", "facts");
}

async function ensureFactDir(descartesPaths, family) {
  await fs.mkdir(resolveFactStorePaths(descartesPaths, family).dir, { recursive: true, mode: 0o700 });
}

// daybreak-blue security sweep, fact-store HIGH #4: the raw supplied ts value must never be
// echoed into an error message (hash-at-source discipline: error/log surfaces never reflect
// raw, potentially sensitive field values). Report shape (type + string length), not content.
function describeInvalidTimestamp(value) {
  return typeof value === "string" ? `string(length=${value.length})` : typeof value;
}

function normalizeTimestamp(ts = new Date().toISOString()) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid fact timestamp: ${describeInvalidTimestamp(ts)}`);
  return date.toISOString();
}

// Same normalizeDimensions-style coercion as history-store.js: stringify, cap at 160 chars
// per value, drop undefined/null, collapse non-object/array to {}. Deliberately no
// Number.isFinite gate anywhere in this module — that gate is exactly what makes
// history-store.js unsuitable for categorical facts.
//
// Divergence from history-store.js's normalizeDimensions (daybreak-blue security sweep,
// 2026-09-04, HIGH #5): normalizeDimensions has no cap on key COUNT or key LENGTH, so an
// attacker-controlled attributes object with hundreds of thousands of keys is fully built
// before any bound applies. Here, over-cap input is REJECTED (thrown -> observable batch
// abort / schema_invalid on read), not silently truncated -- see MAX_FACT_ATTRIBUTE_COUNT /
// MAX_FACT_ATTRIBUTE_KEY_LENGTH above. history-store.js's identical gap is left as-is
// (out of scope for this fix).
function normalizeAttributes(attributes = {}) {
  if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) return {};
  const rawKeyCount = Object.keys(attributes).length;
  if (rawKeyCount > MAX_FACT_ATTRIBUTE_COUNT) {
    throw new Error(`Fact point attributes exceed max key count (${rawKeyCount} > ${MAX_FACT_ATTRIBUTE_COUNT})`);
  }
  const entries = Object.entries(attributes)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => {
      const stringKey = String(key);
      if (stringKey.length > MAX_FACT_ATTRIBUTE_KEY_LENGTH) {
        throw new Error(`Fact point attribute key exceeds max length (${stringKey.length} > ${MAX_FACT_ATTRIBUTE_KEY_LENGTH})`);
      }
      return [stringKey, String(value).slice(0, 160)];
    });
  return Object.fromEntries(entries);
}

/**
 * Fact-point schema (roadmap §7 / plan §3):
 *   { ts, fact_name, entity_key, attributes, source_envelope_id, source_tool, sensitivity }
 * Plus an additive, optional `confidence` field: translators that degrade rather than
 * fabricate (e.g. an unresolvable port owner) can fold a `confidence: 0` marker onto the
 * fact point so downstream mining (S6c) can exclude it from confirming/contradicting
 * evidence, mirroring timedEnvelope's degrade pattern without requiring the fact schema to
 * carry the envelope's full confidence/review_hint shape.
 */
export function normalizeFactPoint(point, defaults = {}) {
  if (!point || typeof point !== "object") throw new Error("Fact point must be an object");
  // daybreak-blue re-gate (2026-09-04), fact-store HIGH #3: fact_name/entity_key were trimmed
  // BEFORE their length check, so a whitespace-padded over-cap raw value (e.g. 258 chars of
  // whitespace + "x") normalized down to a tiny trimmed string and sailed through the cap. Check
  // the RAW string length first -- over-cap raw input is rejected outright, never silently
  // shrunk by trimming.
  const rawFactName = String(point.fact_name ?? "");
  if (rawFactName.length > MAX_FACT_NAME_LENGTH) {
    throw new Error(`Fact point fact_name exceeds max length (${rawFactName.length} > ${MAX_FACT_NAME_LENGTH})`);
  }
  const factName = rawFactName.trim();
  if (!factName) throw new Error("Fact point requires fact_name");
  const rawEntityKey = String(point.entity_key ?? "");
  if (rawEntityKey.length > MAX_FACT_ENTITY_KEY_LENGTH) {
    throw new Error(`Fact point entity_key exceeds max length (${rawEntityKey.length} > ${MAX_FACT_ENTITY_KEY_LENGTH})`);
  }
  const entityKey = rawEntityKey.trim();
  if (!entityKey) throw new Error("Fact point requires entity_key");
  const sourceEnvelopeId = point.source_envelope_id ? String(point.source_envelope_id) : defaults.source_envelope_id;
  if (sourceEnvelopeId && sourceEnvelopeId.length > MAX_FACT_SOURCE_LENGTH) {
    throw new Error(`Fact point source_envelope_id exceeds max length (${sourceEnvelopeId.length} > ${MAX_FACT_SOURCE_LENGTH})`);
  }
  const sourceTool = point.source_tool ? String(point.source_tool) : defaults.source_tool;
  if (sourceTool && sourceTool.length > MAX_FACT_SOURCE_LENGTH) {
    throw new Error(`Fact point source_tool exceeds max length (${sourceTool.length} > ${MAX_FACT_SOURCE_LENGTH})`);
  }
  // daybreak-blue re-gate (2026-09-04), fact-store MEDIUM: sensitivity was an uncapped string --
  // a multi-megabyte value was accepted unchanged. Mirror the other field caps.
  const sensitivity = point.sensitivity ? String(point.sensitivity) : "operational";
  if (sensitivity.length > MAX_FACT_SENSITIVITY_LENGTH) {
    throw new Error(`Fact point sensitivity exceeds max length (${sensitivity.length} > ${MAX_FACT_SENSITIVITY_LENGTH})`);
  }

  const normalized = {
    ts: normalizeTimestamp(point.ts ?? defaults.ts),
    fact_name: factName,
    entity_key: entityKey,
    attributes: normalizeAttributes(point.attributes),
    source_envelope_id: sourceEnvelopeId,
    source_tool: sourceTool,
    sensitivity,
  };

  const confidence = Number(point.confidence);
  if (point.confidence !== undefined && Number.isFinite(confidence)) {
    normalized.confidence = confidence;
  }

  // C0 review L8: a context fact is held to its closed schema (context-schemas.js, a leaf module) by
  // the store itself, at append AND on read (isStoredFactPoint drops a failing line), not only by
  // the translators: a point built outside contextFactPoint, or a line edited on disk, never lands
  // or reads back with an out-of-schema field.
  if (CONTEXT_FACT_SCHEMAS.has(factName)) {
    const verdict = validateContextFact(factName, normalized.attributes);
    if (!verdict.ok) throw new Error(`Context fact ${factName} fails its closed schema (${verdict.field}: ${verdict.reason})`);
  }

  return normalized;
}

function isStoredFactPoint(point) {
  if (!point || typeof point !== "object" || Array.isArray(point)) return false;
  if (!Object.prototype.hasOwnProperty.call(point, "ts") || point.ts === null) return false;
  if (!Number.isFinite(Date.parse(point.ts))) return false;
  try {
    normalizeFactPoint(point);
    return true;
  } catch {
    return false;
  }
}

// Mirrors history-store.js's readJsonLines exactly (duplicated rather than imported —
// convention #2/#3 treat fact-store.js as its own self-contained store, not a re-export of
// history-store.js's internals).
async function readJsonLines(file) {
  let contents;
  let rawBytes;
  try {
    rawBytes = await fs.readFile(file);
    contents = rawBytes.toString("utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return {
      records: [],
      corrupt_count: 0,
      bytes: 0,
      raw_bytes: Buffer.alloc(0),
      exists: false,
    };
    throw error;
  }

  const records = [];
  let corruptCount = 0;
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      corruptCount += 1;
    }
  }
  return { records, corrupt_count: corruptCount, bytes: rawBytes.length, raw_bytes: rawBytes, exists: true };
}

function encodeJsonLine(record) {
  return `${JSON.stringify(record)}\n`;
}

/**
 * R0b defense-in-depth (fact-store capacity plan §4.1 item 1, invariant I3): the coverage claim
 * rests on byte-cap eviction removing a strict, tick-aligned oldest-end prefix -- every evicted
 * record strictly older than every kept one. Computed over the two sets directly (never assuming
 * they are sorted), so a future change to the sort or the keep loop that breaks the property
 * aborts the pass before anything is written instead of silently opening a gap inside the
 * retained range (or keeping part of a split tick).
 */
export function assertSuffixEviction(evicted, kept) {
  if (evicted.length === 0 || kept.length === 0) return;
  let maxEvictedMs = Number.NEGATIVE_INFINITY;
  for (const { tsMs } of evicted) if (tsMs > maxEvictedMs) maxEvictedMs = tsMs;
  let minKeptMs = Number.POSITIVE_INFINITY;
  for (const { tsMs } of kept) if (tsMs < minKeptMs) minKeptMs = tsMs;
  if (!(maxEvictedMs < minKeptMs)) {
    throw new Error("enforceFactRetention suffix violation: byte-cap eviction must remove a strict, tick-aligned oldest-ts prefix");
  }
}

/**
 * Deliberate deviation from history-store.js's enforceHistoryRetention (convention #2):
 * the retention rewrite uses tmp+rename (atomic), not a direct fs.writeFile — facts feed
 * mining/promotion decisions (S6c/S7), where partial-write corruption is more consequential
 * than a dropped metric point.
 */
export async function enforceFactRetention(descartesPaths, options = {}) {
  requireFactFamily(options.family);
  // LOW-5 (review fold): `orderRetentionCandidates` (T5's non-suffix-eviction seam) is read from
  // `internal`, never from `options` directly -- see runFactRetention below. Routing it through
  // here, explicitly, is what makes it reachable ONLY via this exported, test-only entry point:
  // appendFactPoints calls runFactRetention with no third argument, so the same key in ITS options
  // can never reach the candidate order, no matter what a caller passes it.
  return runFactRetention(descartesPaths, options, { orderRetentionCandidates: options.orderRetentionCandidates });
}

async function runFactRetention(descartesPaths, options, internal = {}) {
  const family = requireFactFamily(options.family);
  const storePaths = resolveFactStorePaths(descartesPaths, family);
  // C2 (§8.1): the family's own retention unless the caller names one (a test seam / the explicit
  // enforceFactRetention entry point).
  const retentionMs = options.retentionMs ?? familyRetentionMs(family);
  const maxBytes = options.maxBytes ?? DEFAULT_FACT_MAX_BYTES;
  // daybreak-blue security sweep, fact-store BLOCKER #1: a non-finite retentionMs (e.g.
  // "garbage" -> NaN cutoff) makes every valid record satisfy neither `tsMs < cutoff`
  // (age-evicted) nor `tsMs >= cutoff` (kept candidate) -- it is silently dropped and the
  // rewrite commits as an empty, status:intact store. Validate all three inputs up front
  // instead of letting a bad value flow into arithmetic that can silently erase history.
  // Zero is a legitimate, fully-accounted degenerate case (evict-everything /
  // keep-nothing — see evidence-freeze.test.js's deliberate 0-retention/0-byte isolation
  // sweep), so only non-finite/negative values are rejected, not zero.
  if (!Number.isFinite(retentionMs) || retentionMs < 0) {
    throw new Error("enforceFactRetention requires a finite, non-negative retentionMs");
  }
  if (!Number.isFinite(maxBytes) || maxBytes < 0) {
    throw new Error("enforceFactRetention requires a finite, non-negative maxBytes");
  }
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  if (!Number.isFinite(nowMs)) {
    throw new Error("enforceFactRetention requires options.now to parse as a valid date");
  }
  const cutoffMs = nowMs - retentionMs;
  const nowIso = new Date(nowMs).toISOString();
  const {
    records,
    corrupt_count: corruptBefore,
    bytes: liveBytes,
    raw_bytes: liveRawBytes,
    exists: liveExists,
  } = await readJsonLines(storePaths.factsFile);

  const schemaInvalid = [];
  const validRecords = [];
  for (const record of records) {
    if (!isStoredFactPoint(record)) {
      schemaInvalid.push(record);
      continue;
    }
    try {
      const normalized = normalizeFactPoint(record);
      validRecords.push({ record: normalized, tsMs: new Date(normalized.ts).getTime() });
    } catch {
      schemaInvalid.push(record);
    }
  }

  // Fix 0: a fact whose ts is beyond nowMs + FUTURE_FACT_TOLERANCE_MS is dropped BEFORE it can
  // ever become a retention candidate, so it can never contaminate last_rewrite_newest_ts
  // (fact-store-integrity.js's continuity anchor). cutoffMs <= nowMs < futureThresholdMs always
  // (retentionMs/FUTURE_FACT_TOLERANCE_MS are both non-negative), so the three partitions below
  // are mutually exclusive and jointly exhaustive over validRecords -- the sum-invariant right
  // below stays a straightforward four-term sum.
  const futureThresholdMs = nowMs + FUTURE_FACT_TOLERANCE_MS;
  const futureDropped = validRecords.filter(({ tsMs }) => tsMs > futureThresholdMs);
  const ageEvicted = validRecords.filter(({ tsMs }) => tsMs < cutoffMs);
  const sortedCandidates = validRecords
    .filter(({ tsMs }) => tsMs >= cutoffMs && tsMs <= futureThresholdMs)
    .sort((left, right) => left.tsMs - right.tsMs);

  // R0b below-floor eviction (fact-store capacity plan §15.5 decision 2): a candidate at or below
  // the ledger's byte-cap floor can only have been appended AFTER the eviction that set the floor
  // (a clock rollback) -- the read side already hides it (readFactPoints never returns ts <= floor).
  // Evict it physically, counted as byte-cap, so "every kept record is strictly above the floor"
  // holds by construction: the ledger's floor-plausibility validation can then never reject this
  // pass's own output (which would fail retention on every pass from then on), and the suffix
  // assertion below covers it too. The prior floor is resolved exactly as prepareFactIntegrityLedger
  // resolves it (including the future-floor clamp), so the two can never disagree.
  const existingIntegrity = await readFactIntegrityLedger(descartesPaths, family);
  const priorFloor = resolvePriorBytecapFloor(existingIntegrity.ledger?.bytecap_floor_ts ?? null, nowIso);
  const priorFloorMs = priorFloor.floorTs === null ? Number.NEGATIVE_INFINITY : Date.parse(priorFloor.floorTs);
  const belowFloor = sortedCandidates.filter(({ tsMs }) => tsMs <= priorFloorMs);
  const aboveFloor = sortedCandidates.filter(({ tsMs }) => tsMs > priorFloorMs);
  const priorAgeFloorTs = existingIntegrity.ledger?.age_floor_ts ?? null;
  const priorAgeFloorMs = priorAgeFloorTs === null ? Number.NEGATIVE_INFINITY : Date.parse(priorAgeFloorTs);
  // A rollback can make records at or below the persisted age floor appear in the current
  // retention window again. They were already physically evicted in this lineage, so keep them
  // out of the byte-cap candidate suffix and continue counting them as age eviction.
  const ageFloorRecovered = aboveFloor.filter(({ tsMs }) => tsMs <= priorAgeFloorMs);
  const aboveAgeFloor = aboveFloor.filter(({ tsMs }) => tsMs > priorAgeFloorMs);
  // Test-only seam (fact-store capacity plan T5): lets a test force a non-suffix order through the
  // keep loop below to prove assertSuffixEviction refuses it. Read from `internal`, never
  // `options` (LOW-5, review fold): `enforceFactRetention` is the only caller that threads its own
  // `options.orderRetentionCandidates` through to `internal` above, so this is reachable only via
  // that exported, explicitly test-only entry point -- never through appendFactPoints, no matter
  // what a caller passes in its options.
  const candidates = typeof internal.orderRetentionCandidates === "function"
    ? internal.orderRetentionCandidates(aboveAgeFloor)
    : aboveAgeFloor;

  // Byte-cap selection: keep the newest records that fit, walking newest-first and stopping at the
  // FIRST record that does not fit (never skipping one to fit an older one) -- so the kept set is a
  // suffix of the ts-sorted candidates and eviction only ever removes an oldest-end prefix.
  let keepFrom = candidates.length;
  let fitBytes = 0;
  for (let index = candidates.length - 1; index >= 0; index -= 1) {
    const size = Buffer.byteLength(encodeJsonLine(candidates[index].record));
    if (fitBytes + size > maxBytes) break;
    fitBytes += size;
    keepFrom = index;
  }
  // R0b tick alignment (fact-store capacity plan §4.1 item 1, invariant I3): the sort is stable, so
  // records sharing one ts keep file order and the cut above can split a tick -- typically keeping
  // its census/overflow markers (emitted last) while evicting some of its presence facts, which
  // would read as a COMPLETE tick that is missing entities (a fabricated disappearance/count drop).
  // Evict every kept record that shares the newest evicted record's ts, so no part of a split tick
  // survives whatever the per-family record order. Degenerate cases follow: a single tick larger
  // than maxBytes, or maxBytes 0, evicts everything.
  if (keepFrom > 0) {
    const boundaryMs = candidates[keepFrom - 1].tsMs;
    while (keepFrom < candidates.length && candidates[keepFrom].tsMs === boundaryMs) keepFrom += 1;
  }
  const evictedCandidates = [...belowFloor, ...candidates.slice(0, keepFrom)];
  const keptCandidates = candidates.slice(keepFrom);
  assertSuffixEviction(evictedCandidates, keptCandidates);
  // The floor this pass contributes: the newest ts it byte-evicted (prepareFactIntegrityLedger
  // takes max(prior floor, this)).
  let bytecapEvictedNewestMs = Number.NEGATIVE_INFINITY;
  for (const { tsMs } of evictedCandidates) if (tsMs > bytecapEvictedNewestMs) bytecapEvictedNewestMs = tsMs;
  const bytecapEvictedNewestTs = evictedCandidates.length > 0 ? new Date(bytecapEvictedNewestMs).toISOString() : null;
  const allAgeEvicted = [...ageEvicted, ...ageFloorRecovered];
  let ageEvictedNewestMs = Number.NEGATIVE_INFINITY;
  for (const { tsMs } of allAgeEvicted) if (tsMs > ageEvictedNewestMs) ageEvictedNewestMs = tsMs;
  const ageEvictedNewestTs = allAgeEvicted.length > 0 ? new Date(ageEvictedNewestMs).toISOString() : null;

  const keptLines = keptCandidates.map(({ record }) => encodeJsonLine(record));
  const usedBytes = keptLines.reduce((sum, line) => sum + Buffer.byteLength(line), 0);
  const keptRecords = keptLines.map((line) => JSON.parse(line));
  const bytecapEvicted = evictedCandidates.length;
  // daybreak-blue security sweep, fact-store BLOCKER #1, fix layer 2: every valid record must
  // be either kept or counted as an observable eviction (age/bytecap) -- no valid record may
  // silently vanish from the accounting. This is a defense-in-depth backstop against this bug
  // and any future silent-drop class, regardless of which input caused it.
  if (keptRecords.length + allAgeEvicted.length + bytecapEvicted + futureDropped.length !== validRecords.length) {
    throw new Error("enforceFactRetention accounting mismatch: kept + evicted counts do not sum to the valid record count");
  }
  const counts = {
    corrupt_count: corruptBefore,
    schema_invalid_count: schemaInvalid.length,
    age_evicted_count: allAgeEvicted.length,
    bytecap_evicted_count: bytecapEvicted,
    future_fact_count: futureDropped.length,
  };
  const outputContents = keptLines.join("");
  const outputRawBytes = Buffer.from(outputContents);
  const outputDigest = outputRawBytes.length === 0
    ? null
    : crypto.createHash("sha256").update(outputRawBytes).digest("hex");
  const live = {
    record_count: records.length,
    bytes: liveBytes,
    raw_bytes: liveRawBytes,
    exists: liveExists,
    newest_ts: records.filter(isStoredFactPoint)
      .map((record) => new Date(record.ts))
      .filter((date) => Number.isFinite(date.getTime()))
      .sort((left, right) => right.getTime() - left.getTime())[0]?.toISOString() ?? null,
  };
  // prepareFactIntegrityLedger updates a valid prior ledger IN PLACE (floors, loss markers); the
  // seen-set fold below needs the ledger as it stood at the START of this pass.
  const priorLedgerSnapshot = existingIntegrity.ledger === null ? null : structuredClone(existingIntegrity.ledger);
  const prepared = prepareFactIntegrityLedger({
    ledger: existingIntegrity.ledger,
    ledgerReason: existingIntegrity.reason,
    nowIso,
    live,
    outputRecords: keptRecords,
    outputBytes: outputRawBytes.length,
    outputDigest,
    counts,
    bytecapEvictedNewestTs,
    ageEvictedNewestTs,
  });
  await ensureFactDir(descartesPaths, family);
  const tmpFile = `${storePaths.factsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, outputRawBytes, { mode: 0o600 });
  await fs.chmod(tmpFile, 0o600);
  await writeFactIntegrityLedger(descartesPaths, family, prepared.ledger);
  if (options.beforeFactsRename) await options.beforeFactsRename();
  await fs.rename(tmpFile, storePaths.factsFile);
  if (options.afterFactsRename) await options.afterFactsRename();
  const finalizedLedger = finalizeFactIntegrityLedger(prepared.ledger, prepared.passId, { allowRecovery: prepared.recoverPending });
  await writeFactIntegrityLedger(descartesPaths, family, finalizedLedger);
  // S3b (fact-store capacity plan §17): fold this pass's certified candidates into the novelty
  // seen-sets, in the SAME pass as the append, stamped with the ledger this pass just committed.
  // `sortedCandidates` is every in-retention, non-dropped candidate, BEFORE this pass's byte-cap
  // eviction (see novelty-seen-set.js for why the pre-eviction set; the fold itself keeps only
  // complete ticks at or before nowMs) -- INCLUDING the below-floor / age-floor-recovered records a
  // clock rollback can append (S3b review LOW-4): they are evicted physically, but they were
  // observed, and added memory can only suppress a novelty claim. Never throws: a failed fold leaves the old file, which
  // no longer matches the ledger's committed pass id and therefore reads as not valid (no novelty
  // claim under narrowing) until the next pass re-seeds it.
  // S4: only a novelty family's own store pass folds (its own) seen-set.
  const seenSetFold = !NOVELTY_FAMILIES.has(family) ? {} : await foldNoveltySeenSets(descartesPaths, {
    family,
    priorLedger: priorLedgerSnapshot,
    priorLedgerReason: existingIntegrity.reason,
    liveExists,
    nextLedger: finalizedLedger,
    passId: prepared.passId,
    records: sortedCandidates.map(({ record }) => record),
    nowMs,
    retentionMs,
    ...(options.seenSetMaxEntries !== undefined ? { maxEntries: options.seenSetMaxEntries } : {}),
  });
  return {
    kept_count: keptLines.length,
    dropped_count: schemaInvalid.length + allAgeEvicted.length + bytecapEvicted + futureDropped.length,
    corrupt_dropped_count: corruptBefore,
    schema_invalid_dropped_count: schemaInvalid.length,
    age_evicted_count: allAgeEvicted.length,
    bytecap_evicted_count: bytecapEvicted,
    future_fact_dropped_count: futureDropped.length,
    bytes: usedBytes,
    seen_set_fold: seenSetFold,
    // C2 (I70): the pass this call committed, so a derivation step can cite (or a lineage stamp can
    // name) it without re-reading the ledger.
    ledger_generation: finalizedLedger.generation,
    pass_id: prepared.passId,
    pass_time_ms: Date.parse(nowIso),
  };
}

/**
 * Mirrors appendMetricPoints: ensure dir -> normalize each point (throw propagates, no
 * per-point catch) -> single fs.appendFile of all encoded lines -> enforce retention.
 */
export async function appendFactPoints(descartesPaths, factPoints, options = {}) {
  const family = requireFactFamily(options.family);
  // S4 routing (§4.3, I7): every point must belong to THIS family's store. An unregistered fact_name,
  // or one routed to another family, throws BEFORE anything is written (never misrouted, never
  // silently dropped). Multi-family batches go through appendFactPointsByFamily.
  const normalized = factPoints.map((point) => normalizeFactPoint(point, { ts: options.ts ?? options.now }));
  for (const point of normalized) {
    const pointFamily = factFamilyForName(point.fact_name);
    if (pointFamily === undefined) throw new Error("fact-store: unregistered fact_name (no fact family); refusing the batch before any write");
    if (pointFamily !== family) throw new Error(`fact-store: a ${pointFamily} fact cannot be appended to the ${family} store; refusing the batch before any write`);
  }
  await ensureFactDir(descartesPaths, family);
  const storePaths = resolveFactStorePaths(descartesPaths, family);
  const encoded = normalized.map(encodeJsonLine).join("");
  // R0b / HIGH-1 (fact-store capacity plan §15.5 decision 3; LOW-1/LOW-4 review fold, 2026-10-05):
  // a missing ledger must always be resolved against the PRE-append store, never the post-append
  // one -- otherwise this call's own new data could answer, for itself, the very question
  // (`fact-store-integrity.js`'s missingLedgerOverExistingStore) of whether the ledger loss is a
  // genuine first run or a real loss over an existing store. The old design instead stat()ed the
  // file before appending and threaded an `appendedToEmptyStore` carve-out through to the single
  // post-append pass; that carve-out could not tell a genuine first run apart from an
  // evicted-then-emptied store (0 bytes either way) whose ledger was separately deleted, so it
  // silently let the floor reset with no stamp in the second case (LOW-1).
  //
  // Instead: whenever the ledger is missing, run one retention pass against whatever is on disk
  // RIGHT NOW, strictly before this call's own append. That pass's own `live.exists` check decides
  // clean-bootstrap-vs-lineage-break with no further exception -- a genuine first run (ENOENT)
  // still bootstraps clean, while an EXISTING (even 0-byte) ledger-less facts.jsonl now always
  // stamps. No append has happened yet at this point, so a thrown error here propagates: there is
  // nothing to misreport, unlike the real append/retention pass below (Finding F4-B2), where
  // records have already reached disk.
  if (normalized.length > 0) {
    const ledgerBefore = await readFactIntegrityLedger(descartesPaths, family);
    if (ledgerBefore.reason === "missing") {
      await runFactRetention(descartesPaths, options);
    }
    await fs.appendFile(storePaths.factsFile, encoded, { mode: 0o600 });
  }
  // Finding F4-B2 (daybreak-blue BLOCKER), mirrors appendMetricPoints: enforceFactRetention runs
  // AFTER the append above has already durably succeeded, so a retention-only failure must never
  // make this function throw -- that would make the caller's throw-fallback report a fabricated
  // `written_count: 0` even though `normalized.length` records genuinely reached disk, and would
  // discard the retention error entirely. Retention is now non-fatal: report the real count and,
  // if retention failed, an honestly-named `retention_error` alongside it. This function now
  // throws only when the append itself failed (records genuinely never persisted), or when the
  // pre-append pass above failed (in which case no append happened either).
  let retention;
  let retentionError;
  try {
    retention = await runFactRetention(descartesPaths, options);
  } catch (error) {
    retentionError = (error instanceof Error ? error.message : String(error)) || "unknown retention error";
  }
  return {
    written_count: normalized.length,
    // S4: this call's own appended bytes -- the family's live per-tick volume when the daemon appends
    // one structural tick, which status compares against the budget (cap_below_tick).
    appended_bytes: Buffer.byteLength(encoded),
    retention,
    ...(retention ? { pass_time_ms: Date.parse(normalizeTimestamp(options.now ?? options.ts)) } : {}),
    ...(retentionError ? { retention_error: retentionError } : {}),
  };
}

function errorMessage(error, fallback) {
  return (error instanceof Error ? error.message : String(error)) || fallback;
}

async function pathExists(file) {
  try {
    await fs.stat(file);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

/**
 * Whether a family store has ever been created: its facts.jsonl or its ledger is on disk. A store
 * that was never created (peer on a host with no VPN/Tailscale, canary with none configured) is NOT
 * created by the retention sweep -- status reports it as `not observed (no store)`.
 */
export async function factStoreExists(descartesPaths, family) {
  const { factsFile } = resolveFactStorePaths(descartesPaths, family);
  const { integrityFile } = resolveFactIntegrityPaths(descartesPaths, family);
  return (await pathExists(factsFile)) || (await pathExists(integrityFile));
}

/**
 * G2 L1: the on-disk size of a family's facts.jsonl from a stat (no read, no parse), for the status
 * block's oversize check on families the daemon makes no history read of (network, provenance).
 * undefined when the file is absent or cannot be stat'ed -- display only, consulted by no trust
 * decision, so an unknown size reports nothing rather than failing the tick.
 */
export async function factStoreFileBytes(descartesPaths, family) {
  const { factsFile } = resolveFactStorePaths(descartesPaths, family);
  try {
    const stat = await fs.stat(factsFile);
    return stat.isFile() ? stat.size : undefined;
  } catch {
    return undefined;
  }
}

/**
 * S4 daemon write path (§4.3): route a structural tick's fact points to their family stores and run
 * the registry-driven retention sweep.
 *   - Grouping happens FIRST and throws on any unregistered fact_name, so a bad batch writes nothing
 *     to any family (I7).
 *   - Each family with new points is appended with its own budget (options.budgets[family], else
 *     options.maxBytes, else the registry default). One family's append or retention failure is
 *     reported for that family and never stops another family from persisting.
 *   - Every OTHER family whose store already exists gets a retention pass too (no new points), so a
 *     family that stopped producing facts still age-evicts instead of keeping data past 30 days.
 *     Iterates the closed registry, never the filesystem; a family that appended this call already
 *     ran retention and is not swept twice; a store that was never created is not created.
 * Returns { written_count, families: {<family>: {written_count, appended_bytes?, budget_bytes,
 * retention?, retention_error?, append_error?}}, retention_error?, append_error? } -- the combined
 * error strings name their family.
 */
export async function appendFactPointsByFamily(descartesPaths, factPoints, options = {}) {
  const grouped = groupFactPointsByFamily(factPoints);
  const { budgets, maxBytes, families: selectedFamilies, ...passOptions } = options;
  const familiesToProcess = selectedFamilies ?? FACT_FAMILY_IDS;
  if (!Array.isArray(familiesToProcess) || familiesToProcess.length === 0) throw new Error("fact-store: families must be a non-empty array");
  const selected = new Set(familiesToProcess);
  for (const family of selected) requireFactFamily(family);
  for (const family of grouped.keys()) {
    if (!selected.has(family)) throw new Error(`fact-store: ${family} is outside the selected family pass`);
  }
  const families = {};
  let writtenCount = 0;
  const appendErrors = [];
  const retentionErrors = [];
  for (const family of FACT_FAMILY_IDS) {
    if (!selected.has(family)) continue;
    const budgetBytes = budgets?.[family] ?? maxBytes ?? FAMILY_DEFAULT_BUDGET_BYTES.get(family);
    const familyOptions = { ...passOptions, family, maxBytes: budgetBytes };
    // C2: a derived family (fact-families.js DERIVED_FAMILIES) is written only by its own derivation
    // step, never here: no append (refused, reported) and no sweep (it would advance the pass id its
    // lineage stamp names).
    if (DERIVED_FAMILIES.has(family)) {
      if (grouped.has(family)) {
        const message = "derived family is appended only by its own derivation step";
        families[family] = { written_count: 0, budget_bytes: budgetBytes, append_error: message };
        appendErrors.push(`${family}: ${message}`);
      }
      continue;
    }
    if (grouped.has(family)) {
      try {
        const result = await appendFactPoints(descartesPaths, grouped.get(family), familyOptions);
        writtenCount += result.written_count;
        families[family] = { ...result, budget_bytes: budgetBytes };
        if (result.retention_error) retentionErrors.push(`${family}: ${result.retention_error}`);
      } catch (error) {
        const message = errorMessage(error, "unknown fact-append error");
        families[family] = { written_count: 0, budget_bytes: budgetBytes, append_error: message };
        appendErrors.push(`${family}: ${message}`);
      }
      continue;
    }
    let exists;
    try {
      exists = await factStoreExists(descartesPaths, family);
    } catch (error) {
      const message = errorMessage(error, "unknown fact-store stat error");
      families[family] = { written_count: 0, budget_bytes: budgetBytes, retention_error: message };
      retentionErrors.push(`${family}: ${message}`);
      continue;
    }
    if (!exists) continue;
    try {
      const retention = await runFactRetention(descartesPaths, familyOptions);
      families[family] = { written_count: 0, budget_bytes: budgetBytes, retention };
    } catch (error) {
      const message = errorMessage(error, "unknown retention error");
      families[family] = { written_count: 0, budget_bytes: budgetBytes, retention_error: message };
      retentionErrors.push(`${family}: ${message}`);
    }
  }
  return {
    written_count: writtenCount,
    families,
    ...(appendErrors.length > 0 ? { append_error: appendErrors.join("; ") } : {}),
    ...(retentionErrors.length > 0 ? { retention_error: retentionErrors.join("; ") } : {}),
  };
}

/**
 * Mirrors readMetricPoints: re-validates each record through normalizeFactPoint and drops
 * (doesn't throw) any that fail — same "drop invalid, count corrupt separately" split as
 * history-store.js's readJsonLines-consuming readers.
 *
 * S4 (fact-store capacity plan §4.3, I7): exactly one of
 *   - options.family: one family store (its own ledger, floors and -- for a novelty family -- its own
 *     seen-set), or
 *   - options.families: several family stores, read independently and merged: points merged and
 *     ts-sorted, counts summed, a COMBINED completeness for display (worst status, latest of each
 *     loss timestamp, newest floors, `coverage` "unknown" > "narrowed" > "full"), and every family's
 *     own read under `family_reads` -- which the trust/coverage predicates in
 *     fact-store-completeness.js AND over (trust holds only if every family is trusted; a combined
 *     floor is never used to gate, since one family's newer age floor could otherwise mask another
 *     family's byte-cap floor).
 * is REQUIRED; a missing or unknown family throws (no legacy single-store default). A requested
 * seen-set family must be one of the families read (a set is only ever validated against its own
 * family's ledger).
 */
export async function readFactPoints(descartesPaths, options = {}) {
  const hasFamily = options.family !== undefined;
  const hasFamilies = options.families !== undefined;
  if (hasFamily === hasFamilies) {
    throw new Error("readFactPoints requires exactly one of options.family or options.families (no legacy single-store default)");
  }
  const families = hasFamily ? [requireFactFamily(options.family)] : options.families;
  if (!Array.isArray(families) || families.length === 0) throw new Error("readFactPoints requires a non-empty options.families");
  for (const family of families) requireFactFamily(family);
  const unique = [...new Set(families)];
  const seenSetFamilies = Array.isArray(options.seenSetFamilies) ? options.seenSetFamilies : [];
  for (const family of seenSetFamilies) {
    if (!unique.includes(family)) throw new Error(`readFactPoints: seen-set family ${String(family)} is not one of the families read`);
  }
  if (hasFamily) return readFamilyFactPoints(descartesPaths, unique[0], options);
  const reads = [];
  for (const family of unique) reads.push([family, await readFamilyFactPoints(descartesPaths, family, options)]);
  return mergeFamilyReads(reads);
}

function mergeFamilyReads(reads) {
  const points = reads.flatMap(([, read]) => read.points)
    .sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
  const familyReads = {};
  let seenSets;
  for (const [family, read] of reads) {
    const { points: _points, seen_sets: familySeenSets, ...rest } = read;
    familyReads[family] = { ...rest, ...(familySeenSets ? { seen_sets: familySeenSets } : {}) };
    if (familySeenSets) seenSets = { ...(seenSets ?? {}), ...familySeenSets };
  }
  const corruptCount = reads.reduce((sum, [, read]) => sum + read.corrupt_count, 0);
  const schemaInvalidCount = reads.reduce((sum, [, read]) => sum + read.schema_invalid_count, 0);
  return {
    points,
    corrupt_count: corruptCount,
    schema_invalid_count: schemaInvalidCount,
    // The combined (display) completeness is over the family stores that EXIST: a never-created store
    // is reported per family as absent ("not observed (no store)"), not folded in as "unknown".
    completeness: combineFamilyCompleteness((reads.some(([, read]) => read.store_exists) ? reads.filter(([, read]) => read.store_exists) : reads)
      .map(([, read]) => read.completeness), {
      oldestCertifiedTs: points.length > 0 ? points[0].ts : null,
    }),
    bytes: reads.reduce((sum, [, read]) => sum + read.bytes, 0),
    store_exists: reads.some(([, read]) => read.store_exists),
    families: reads.map(([family]) => family),
    family_reads: familyReads,
    ...(seenSets ? { seen_sets: seenSets } : {}),
  };
}

async function readFamilyFactPoints(descartesPaths, family, options) {
  const storePaths = resolveFactStorePaths(descartesPaths, family);
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  if (options.now !== undefined && !Number.isFinite(nowMs)) {
    throw new Error("readFactPoints requires options.now to parse as a valid date");
  }
  // daybreak-blue security sweep, fact-store BLOCKER #2: a malformed/negative windowMs made
  // sinceMs NaN, which drops every point from BOTH the point filter AND buildCompleteness's
  // asOfMs boundary -- reproduced against a PROVEN-intact store, windowMs:"garbage"/-1000
  // returned points:[] status:intact over a real store. Validate up front so sinceMs can
  // never be NaN.
  if (options.windowMs !== undefined && (!Number.isFinite(options.windowMs) || options.windowMs < 0)) {
    throw new Error("readFactPoints requires a finite, non-negative windowMs");
  }
  // LOW-6 (review fold): certified_after_ts (below) reports max(floor, retention cutoff) -- the
  // cutoff must be the SAME retentionMs the caller's own write-side retention pass actually uses,
  // or this surface over/under-claims relative to what that pass really kept. Defaults to
  // the family's own retention (fact-families.js familyRetentionMs, C2 §8.1), mirroring the write
  // side's default exactly; validated the same way as windowMs just above.
  if (options.retentionMs !== undefined && (!Number.isFinite(options.retentionMs) || options.retentionMs < 0)) {
    throw new Error("readFactPoints requires a finite, non-negative retentionMs");
  }
  const retentionMs = options.retentionMs ?? familyRetentionMs(family);
  const sinceMs = options.windowMs !== undefined ? nowMs - options.windowMs : undefined;
  const { records, corrupt_count, bytes, raw_bytes: rawBytes, exists } = await readJsonLines(storePaths.factsFile);
  const integrity = await readFactIntegrityLedger(descartesPaths, family);
  // R0b read-side floor (fact-store capacity plan §4.1 item 3, invariant I1): never return a point
  // at or below the ledger's exclusive byte-cap floor. Enforced HERE, once, in the store -- never
  // as six per-detector copies (six chances for one to be missing and fabricate). Points at or
  // below the floor are physically absent anyway once eviction is tick-aligned; this is the
  // second layer that also covers records appended with ts <= floor after a clock rollback and not
  // yet evicted by the next pass. A missing/invalid ledger carries no floor, but then completeness
  // is unknown/degraded and nothing downstream trusts the points.
  const bytecapFloorMs = integrity.ledger?.bytecap_floor_ts ? Date.parse(integrity.ledger.bytecap_floor_ts) : Number.NEGATIVE_INFINITY;
  const ageFloorMs = integrity.ledger?.age_floor_ts ? Date.parse(integrity.ledger.age_floor_ts) : Number.NEGATIVE_INFINITY;
  const floorMs = Math.max(bytecapFloorMs, ageFloorMs);
  let schemaInvalidCount = 0;
  const points = records
    .map((record) => {
      if (!isStoredFactPoint(record)) {
        schemaInvalidCount += 1;
        return undefined;
      }
      return normalizeFactPoint(record);
    })
    .filter(Boolean)
    .filter((point) => new Date(point.ts).getTime() > floorMs)
    .filter((point) => sinceMs === undefined || new Date(point.ts).getTime() >= sinceMs)
    .sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
  const live = {
    record_count: records.length,
    bytes,
    raw_bytes: rawBytes,
    exists,
    newest_ts: records.filter(isStoredFactPoint)
      .map((record) => new Date(record.ts))
      .filter((date) => Number.isFinite(date.getTime()))
      .sort((left, right) => right.getTime() - left.getTime())[0]?.toISOString() ?? null,
  };
  // S3b (§17): the novelty seen-sets the caller asked for, validated against THIS read's ledger
  // (generation, committed pass id, no pending pass) so the pair can never desync. Only a "valid"
  // set carries entries.
  let seenSets;
  const seenSetFamilies = Array.isArray(options.seenSetFamilies) ? options.seenSetFamilies.filter((name) => name === family) : [];
  if (seenSetFamilies.length > 0) {
    seenSets = {};
    for (const setFamily of seenSetFamilies) {
      seenSets[setFamily] = await readNoveltySeenSet(descartesPaths, setFamily, {
        ledger: integrity.ledger,
        nowMs,
        retentionMs,
        ...(options.seenSetMaxEntries !== undefined ? { maxEntries: options.seenSetMaxEntries } : {}),
      });
    }
  }
  const completeness = buildCompleteness(
    integrity.ledger,
    live,
    sinceMs === undefined ? Number.NEGATIVE_INFINITY : sinceMs,
    { corrupt_count, schema_invalid_count: schemaInvalidCount },
    nowMs,
    {
      retentionCutoffMs: nowMs - retentionMs,
      readWindowStartMs: sinceMs,
      oldestCertifiedTs: points.length > 0 ? points[0].ts : null,
    },
  );
  return {
    points,
    corrupt_count,
    schema_invalid_count: schemaInvalidCount,
    completeness,
    continuity_observation: observeFactContinuity(integrity.ledger, live),
    family,
    // S4 status: the store's on-disk size, and whether it was ever created (facts.jsonl or ledger on
    // disk) -- a never-created store reads as `not observed (no store)`, not "still learning".
    bytes,
    store_exists: exists || integrity.reason !== "missing",
    ...(seenSets ? { seen_sets: seenSets } : {}),
  };
}
