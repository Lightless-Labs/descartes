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

export function resolveFactStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned", "facts");
  return { dir, factsFile: path.join(dir, "facts.jsonl") };
}

async function ensureFactDir(descartesPaths) {
  await fs.mkdir(resolveFactStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeTimestamp(ts = new Date().toISOString()) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid fact timestamp: ${ts}`);
  return date.toISOString();
}

// Same normalizeDimensions-style coercion as history-store.js: stringify, cap at 160 chars
// per value, drop undefined/null, collapse non-object/array to {}. Deliberately no
// Number.isFinite gate anywhere in this module — that gate is exactly what makes
// history-store.js unsuitable for categorical facts.
function normalizeAttributes(attributes = {}) {
  if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) return {};
  const entries = Object.entries(attributes)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => [String(key), String(value).slice(0, 160)]);
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
  const factName = String(point.fact_name ?? "").trim();
  if (!factName) throw new Error("Fact point requires fact_name");
  const entityKey = String(point.entity_key ?? "").trim();
  if (!entityKey) throw new Error("Fact point requires entity_key");

  const normalized = {
    ts: normalizeTimestamp(point.ts ?? defaults.ts),
    fact_name: factName,
    entity_key: entityKey,
    attributes: normalizeAttributes(point.attributes),
    source_envelope_id: point.source_envelope_id ? String(point.source_envelope_id) : defaults.source_envelope_id,
    source_tool: point.source_tool ? String(point.source_tool) : defaults.source_tool,
    sensitivity: point.sensitivity ? String(point.sensitivity) : "operational",
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
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
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
