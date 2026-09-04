import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  buildCompleteness,
  finalizeFactIntegrityLedger,
  prepareFactIntegrityLedger,
  readFactIntegrityLedger,
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
 * Deliberate deviation from history-store.js's enforceHistoryRetention (convention #2):
 * the retention rewrite uses tmp+rename (atomic), not a direct fs.writeFile — facts feed
 * mining/promotion decisions (S6c/S7), where partial-write corruption is more consequential
 * than a dropped metric point.
 */
export async function enforceFactRetention(descartesPaths, options = {}) {
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

  const ageEvicted = validRecords.filter(({ tsMs }) => tsMs < cutoffMs);
  const candidates = validRecords
    .filter(({ tsMs }) => tsMs >= cutoffMs)
    .sort((left, right) => left.tsMs - right.tsMs);

  const keptReversed = [];
  let usedBytes = 0;
  for (let index = candidates.length - 1; index >= 0; index -= 1) {
    const line = encodeJsonLine(candidates[index].record);
    const size = Buffer.byteLength(line);
    if (keptReversed.length > 0 && usedBytes + size > maxBytes) break;
    if (size > maxBytes && keptReversed.length === 0) break;
    keptReversed.push(line);
    usedBytes += size;
  }

  const keptLines = keptReversed.reverse();
  const keptRecords = keptLines.map((line) => JSON.parse(line));
  const bytecapEvicted = candidates.length - keptRecords.length;
  // daybreak-blue security sweep, fact-store BLOCKER #1, fix layer 2: every valid record must
  // be either kept or counted as an observable eviction (age/bytecap) -- no valid record may
  // silently vanish from the accounting. This is a defense-in-depth backstop against this bug
  // and any future silent-drop class, regardless of which input caused it.
  if (keptRecords.length + ageEvicted.length + bytecapEvicted !== validRecords.length) {
    throw new Error("enforceFactRetention accounting mismatch: kept + evicted counts do not sum to the valid record count");
  }
  const counts = {
    corrupt_count: corruptBefore,
    schema_invalid_count: schemaInvalid.length,
    age_evicted_count: ageEvicted.length,
    bytecap_evicted_count: bytecapEvicted,
  };
  const outputContents = keptLines.join("");
  const outputRawBytes = Buffer.from(outputContents);
  const outputDigest = outputRawBytes.length === 0
    ? null
    : crypto.createHash("sha256").update(outputRawBytes).digest("hex");
  const existingIntegrity = await readFactIntegrityLedger(descartesPaths);
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
    dropped_count: schemaInvalid.length + ageEvicted.length + bytecapEvicted,
    corrupt_dropped_count: corruptBefore,
    schema_invalid_dropped_count: schemaInvalid.length,
    age_evicted_count: ageEvicted.length,
    bytecap_evicted_count: bytecapEvicted,
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
  if (normalized.length > 0) {
    await fs.appendFile(storePaths.factsFile, normalized.map(encodeJsonLine).join(""), { mode: 0o600 });
  }
  const retention = await enforceFactRetention(descartesPaths, options);
  return { written_count: normalized.length, retention };
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
    .filter((point) => sinceMs === undefined || new Date(point.ts).getTime() >= sinceMs)
    .sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
  const integrity = await readFactIntegrityLedger(descartesPaths);
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
  );
  return { points, corrupt_count, schema_invalid_count: schemaInvalidCount, completeness };
}
