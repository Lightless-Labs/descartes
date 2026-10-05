import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  buildCompleteness,
  finalizeFactIntegrityLedger,
  FUTURE_FACT_TOLERANCE_MS,
  prepareFactIntegrityLedger,
  readFactIntegrityLedger,
  resolvePriorBytecapFloor,
  writeFactIntegrityLedger,
} from "./fact-store-integrity.js";

// Categorical fact-point store — distinct from history-store.js's numeric metric-point
// schema (whose normalizeMetricPoint throws on !Number.isFinite(value)). Structural facts
// (service presence, listening-port ownership, ...) are inherently categorical/string-valued
// and cannot live in metrics.jsonl. Mirrors history-store.js's/constraint-store.js's
// conventions (atomic tmp+rename writes for anything read back to make a decision,
// corrupt-tolerant per-line reads) — see plan §1/§3.
export const DEFAULT_FACT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
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

export function resolveFactStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned", "facts");
  return { dir, factsFile: path.join(dir, "facts.jsonl") };
}

async function ensureFactDir(descartesPaths) {
  await fs.mkdir(resolveFactStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
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
  // The exported entry point can never assert the first-run carve-out (see runFactRetention).
  return runFactRetention(descartesPaths, options, {});
}

// `internal.appendedToEmptyStore` is passed only by appendFactPoints, which observed it BEFORE its
// own append (fact-store capacity plan §15.5 decision 3); it is deliberately not an `options` key.
async function runFactRetention(descartesPaths, options, internal) {
  const storePaths = resolveFactStorePaths(descartesPaths);
  const retentionMs = options.retentionMs ?? DEFAULT_FACT_RETENTION_MS;
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
  const existingIntegrity = await readFactIntegrityLedger(descartesPaths);
  const priorFloor = resolvePriorBytecapFloor(existingIntegrity.ledger?.bytecap_floor_ts ?? null, nowIso);
  const priorFloorMs = priorFloor.floorTs === null ? Number.NEGATIVE_INFINITY : Date.parse(priorFloor.floorTs);
  const belowFloor = sortedCandidates.filter(({ tsMs }) => tsMs <= priorFloorMs);
  const aboveFloor = sortedCandidates.filter(({ tsMs }) => tsMs > priorFloorMs);
  // Test-only seam (fact-store capacity plan T5): lets a test force a non-suffix order through the
  // keep loop below to prove assertSuffixEviction refuses it. Never set in production.
  const candidates = typeof options.orderRetentionCandidates === "function"
    ? options.orderRetentionCandidates(aboveFloor)
    : aboveFloor;

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

  const keptLines = keptCandidates.map(({ record }) => encodeJsonLine(record));
  const usedBytes = keptLines.reduce((sum, line) => sum + Buffer.byteLength(line), 0);
  const keptRecords = keptLines.map((line) => JSON.parse(line));
  const bytecapEvicted = evictedCandidates.length;
  // daybreak-blue security sweep, fact-store BLOCKER #1, fix layer 2: every valid record must
  // be either kept or counted as an observable eviction (age/bytecap) -- no valid record may
  // silently vanish from the accounting. This is a defense-in-depth backstop against this bug
  // and any future silent-drop class, regardless of which input caused it.
  if (keptRecords.length + ageEvicted.length + bytecapEvicted + futureDropped.length !== validRecords.length) {
    throw new Error("enforceFactRetention accounting mismatch: kept + evicted counts do not sum to the valid record count");
  }
  const counts = {
    corrupt_count: corruptBefore,
    schema_invalid_count: schemaInvalid.length,
    age_evicted_count: ageEvicted.length,
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
    appendedToEmptyStore: internal.appendedToEmptyStore === true,
  });
  await ensureFactDir(descartesPaths);
  const tmpFile = `${storePaths.factsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, outputRawBytes, { mode: 0o600 });
  await fs.chmod(tmpFile, 0o600);
  await writeFactIntegrityLedger(descartesPaths, prepared.ledger);
  if (options.beforeFactsRename) await options.beforeFactsRename();
  await fs.rename(tmpFile, storePaths.factsFile);
  if (options.afterFactsRename) await options.afterFactsRename();
  await writeFactIntegrityLedger(descartesPaths, finalizeFactIntegrityLedger(prepared.ledger, prepared.passId, { allowRecovery: prepared.recoverPending }));
  return {
    kept_count: keptLines.length,
    dropped_count: schemaInvalid.length + ageEvicted.length + bytecapEvicted + futureDropped.length,
    corrupt_dropped_count: corruptBefore,
    schema_invalid_dropped_count: schemaInvalid.length,
    age_evicted_count: ageEvicted.length,
    bytecap_evicted_count: bytecapEvicted,
    future_fact_dropped_count: futureDropped.length,
    bytes: usedBytes,
  };
}

/**
 * Mirrors appendMetricPoints: ensure dir -> normalize each point (throw propagates, no
 * per-point catch) -> single fs.appendFile of all encoded lines -> enforce retention.
 */
export async function appendFactPoints(descartesPaths, factPoints, options = {}) {
  await ensureFactDir(descartesPaths);
  const storePaths = resolveFactStorePaths(descartesPaths);
  const normalized = factPoints.map((point) => normalizeFactPoint(point, { ts: options.ts ?? options.now }));
  // R0b / HIGH-1 first-run carve-out (fact-store capacity plan §15.5 decision 3): the very first
  // append writes facts.jsonl BEFORE the first retention pass creates the ledger, so "missing
  // ledger over a non-empty store" -- otherwise a lineage break -- is also the shape of a genuine
  // first run. Observe, BEFORE appending, whether the ledger is missing and the store absent or
  // empty; only then is every record the retention pass will see one this call appended. A crash
  // between this append and the retention pass below leaves exactly that shape with no ledger, and
  // the next call then (correctly, fail-closed) reads it as a lineage break.
  let appendedToEmptyStore = false;
  if (normalized.length > 0) {
    const ledgerBefore = await readFactIntegrityLedger(descartesPaths);
    if (ledgerBefore.reason === "missing") {
      const sizeBefore = await fs.stat(storePaths.factsFile).then((stat) => stat.size, (error) => {
        if (error?.code === "ENOENT") return 0;
        throw error;
      });
      appendedToEmptyStore = sizeBefore === 0;
    }
    await fs.appendFile(storePaths.factsFile, normalized.map(encodeJsonLine).join(""), { mode: 0o600 });
  }
  // Finding F4-B2 (daybreak-blue BLOCKER), mirrors appendMetricPoints: enforceFactRetention runs
  // AFTER the append above has already durably succeeded, so a retention-only failure must never
  // make this function throw -- that would make the caller's throw-fallback report a fabricated
  // `written_count: 0` even though `normalized.length` records genuinely reached disk, and would
  // discard the retention error entirely. Retention is now non-fatal: report the real count and,
  // if retention failed, an honestly-named `retention_error` alongside it. This function now
  // throws only when the append itself failed (records genuinely never persisted).
  let retention;
  let retentionError;
  try {
    retention = await runFactRetention(descartesPaths, options, { appendedToEmptyStore });
  } catch (error) {
    retentionError = (error instanceof Error ? error.message : String(error)) || "unknown retention error";
  }
  return { written_count: normalized.length, retention, ...(retentionError ? { retention_error: retentionError } : {}) };
}

/**
 * Mirrors readMetricPoints: re-validates each record through normalizeFactPoint and drops
 * (doesn't throw) any that fail — same "drop invalid, count corrupt separately" split as
 * history-store.js's readJsonLines-consuming readers.
 */
export async function readFactPoints(descartesPaths, options = {}) {
  const storePaths = resolveFactStorePaths(descartesPaths);
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
  const sinceMs = options.windowMs !== undefined ? nowMs - options.windowMs : undefined;
  const { records, corrupt_count, bytes, raw_bytes: rawBytes, exists } = await readJsonLines(storePaths.factsFile);
  const integrity = await readFactIntegrityLedger(descartesPaths);
  // R0b read-side floor (fact-store capacity plan §4.1 item 3, invariant I1): never return a point
  // at or below the ledger's exclusive byte-cap floor. Enforced HERE, once, in the store -- never
  // as six per-detector copies (six chances for one to be missing and fabricate). Points at or
  // below the floor are physically absent anyway once eviction is tick-aligned; this is the
  // second layer that also covers records appended with ts <= floor after a clock rollback and not
  // yet evicted by the next pass. A missing/invalid ledger carries no floor, but then completeness
  // is unknown/degraded and nothing downstream trusts the points.
  const floorMs = integrity.ledger?.bytecap_floor_ts ? Date.parse(integrity.ledger.bytecap_floor_ts) : Number.NEGATIVE_INFINITY;
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
  const completeness = buildCompleteness(
    integrity.ledger,
    live,
    sinceMs === undefined ? Number.NEGATIVE_INFINITY : sinceMs,
    { corrupt_count, schema_invalid_count: schemaInvalidCount },
    nowMs,
    {
      retentionCutoffMs: nowMs - DEFAULT_FACT_RETENTION_MS,
      oldestCertifiedTs: points.length > 0 ? points[0].ts : null,
    },
  );
  return { points, corrupt_count, schema_invalid_count: schemaInvalidCount, completeness };
}
