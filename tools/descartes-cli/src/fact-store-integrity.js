import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export const FACT_INTEGRITY_SCHEMA_VERSION = 1;

const LEDGER_KEYS = [
  "generation",
  "schema_version",
  "corrupt_dropped_total",
  "schema_invalid_dropped_total",
  "bytecap_evicted_total",
  "age_evicted_total",
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
  "first_degraded_ts",
  "continuity",
];
const CONTINUITY_KEYS = [
  "record_count_hwm",
  "oldest_ts",
  "last_rewrite_record_count",
  "last_rewrite_newest_ts",
  "last_rewrite_bytes",
  "output_digest",
  "last_committed_pass_id",
  "continuity_ok",
  "pending_pass",
];
const PENDING_PASS_KEYS = [
  "pass_id",
  "corrupt_count",
  "schema_invalid_count",
  "bytecap_evicted_count",
  "age_evicted_count",
  "output_record_count",
  "output_newest_ts",
  "output_bytes",
  "output_digest",
];

export function resolveFactIntegrityPaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned", "facts");
  return { dir, integrityFile: path.join(dir, "integrity.json") };
}

function emptyContinuity() {
  return {
    record_count_hwm: 0,
    oldest_ts: null,
    last_rewrite_record_count: 0,
    last_rewrite_newest_ts: null,
    last_rewrite_bytes: 0,
    output_digest: null,
    last_committed_pass_id: 0,
    continuity_ok: null,
    pending_pass: null,
  };
}

export function createFactIntegrityLedger() {
  return {
    generation: crypto.randomUUID(),
    schema_version: FACT_INTEGRITY_SCHEMA_VERSION,
    corrupt_dropped_total: 0,
    schema_invalid_dropped_total: 0,
    bytecap_evicted_total: 0,
    age_evicted_total: 0,
    last_corrupt_ts: null,
    last_schema_invalid_ts: null,
    last_bytecap_evict_ts: null,
    last_continuity_break_ts: null,
    first_degraded_ts: null,
    continuity: emptyContinuity(),
  };
}

function isNullableTimestamp(value) {
  return value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
}

function isDigest(value) {
  return value === null || (typeof value === "string" && /^[a-f0-9]{64}$/.test(value));
}

function hasCoherentOutput({ recordCount, newestTs, bytes, digest }) {
  if (recordCount === 0) return newestTs === null && bytes === 0 && digest === null;
  return newestTs !== null && bytes > 0 && digest !== null;
}

function hasExactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}

function isValidPendingPass(value) {
  if (value === null) return true;
  return Boolean(
    value && typeof value === "object" &&
    !Array.isArray(value) &&
    hasExactKeys(value, PENDING_PASS_KEYS) &&
    Number.isInteger(value.pass_id) && value.pass_id > 0 &&
    Number.isInteger(value.corrupt_count) && value.corrupt_count >= 0 &&
    Number.isInteger(value.schema_invalid_count) && value.schema_invalid_count >= 0 &&
    Number.isInteger(value.bytecap_evicted_count) && value.bytecap_evicted_count >= 0 &&
    Number.isInteger(value.age_evicted_count) && value.age_evicted_count >= 0 &&
    Number.isInteger(value.output_record_count) && value.output_record_count >= 0 &&
    Number.isInteger(value.output_bytes) && value.output_bytes >= 0 &&
    isNullableTimestamp(value.output_newest_ts) &&
    isDigest(value.output_digest) &&
    hasCoherentOutput({
      recordCount: value.output_record_count,
      newestTs: value.output_newest_ts,
      bytes: value.output_bytes,
      digest: value.output_digest,
    }),
  );
}

export function isValidFactIntegrityLedger(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const totals = [
    "corrupt_dropped_total",
    "schema_invalid_dropped_total",
    "bytecap_evicted_total",
    "age_evicted_total",
  ];
  if (!hasExactKeys(value, LEDGER_KEYS)) return false;
  if (value.schema_version !== FACT_INTEGRITY_SCHEMA_VERSION || typeof value.generation !== "string" || !value.generation) return false;
  if (totals.some((key) => !Number.isInteger(value[key]) || value[key] < 0)) return false;
  if (["last_corrupt_ts", "last_schema_invalid_ts", "last_bytecap_evict_ts", "last_continuity_break_ts", "first_degraded_ts"].some((key) => !isNullableTimestamp(value[key]))) return false;

  const continuity = value.continuity;
  if (!continuity || typeof continuity !== "object" || Array.isArray(continuity)) return false;
  if (!hasExactKeys(continuity, CONTINUITY_KEYS) || !Object.prototype.hasOwnProperty.call(continuity, "pending_pass")) return false;
  if (!["record_count_hwm", "last_rewrite_record_count", "last_rewrite_bytes", "last_committed_pass_id"].every((key) => Number.isInteger(continuity[key]) && continuity[key] >= 0)) return false;
  if (!isNullableTimestamp(continuity.oldest_ts) || !isNullableTimestamp(continuity.last_rewrite_newest_ts) || !isDigest(continuity.output_digest)) return false;
  if (!hasCoherentOutput({
    recordCount: continuity.last_rewrite_record_count,
    newestTs: continuity.last_rewrite_newest_ts,
    bytes: continuity.last_rewrite_bytes,
    digest: continuity.output_digest,
  })) return false;
  if (![true, false, null].includes(continuity.continuity_ok) || !isValidPendingPass(continuity.pending_pass)) return false;
  if (continuity.pending_pass && continuity.pending_pass.pass_id <= continuity.last_committed_pass_id) return false;
  if (continuity.pending_pass && (
    continuity.pending_pass.output_record_count !== continuity.last_rewrite_record_count ||
    continuity.pending_pass.output_newest_ts !== continuity.last_rewrite_newest_ts ||
    continuity.pending_pass.output_bytes !== continuity.last_rewrite_bytes ||
    continuity.pending_pass.output_digest !== continuity.output_digest
  )) return false;
  if (value.corrupt_dropped_total > 0 && value.last_corrupt_ts === null) return false;
  if (value.schema_invalid_dropped_total > 0 && value.last_schema_invalid_ts === null) return false;
  if (value.bytecap_evicted_total > 0 && value.last_bytecap_evict_ts === null) return false;
  if (continuity.continuity_ok === false && value.last_continuity_break_ts === null) return false;
  return true;
}

export async function readFactIntegrityLedger(descartesPaths) {
  const { integrityFile } = resolveFactIntegrityPaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(integrityFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { ledger: null, reason: "missing" };
    return { ledger: null, reason: "unreadable" };
  }

  try {
    const ledger = JSON.parse(contents);
    return isValidFactIntegrityLedger(ledger)
      ? { ledger, reason: null }
      : { ledger: null, reason: "invalid" };
  } catch {
    return { ledger: null, reason: "invalid" };
  }
}

export async function writeFactIntegrityLedger(descartesPaths, ledger) {
  if (!isValidFactIntegrityLedger(ledger)) throw new Error("Invalid fact-store integrity ledger");
  const { dir, integrityFile } = resolveFactIntegrityPaths(descartesPaths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700);
  const tmpFile = `${integrityFile}.${process.pid}.tmp`;
  const canonical = Object.fromEntries(LEDGER_KEYS.map((key) => [
    key,
    key === "continuity"
      ? Object.fromEntries(CONTINUITY_KEYS.map((continuityKey) => [
        continuityKey,
        continuityKey === "pending_pass" && ledger.continuity.pending_pass !== null
          ? Object.fromEntries(PENDING_PASS_KEYS.map((pendingKey) => [pendingKey, ledger.continuity.pending_pass[pendingKey]]))
          : ledger.continuity[continuityKey],
      ]))
      : ledger[key],
  ]));
  await fs.writeFile(tmpFile, `${JSON.stringify(canonical, null, 2)}\n`, { mode: 0o600 });
  await fs.chmod(tmpFile, 0o600);
  await fs.rename(tmpFile, integrityFile);
  await fs.chmod(integrityFile, 0o600);
}

function newestTimestamp(records) {
  return records
    .map((record) => new Date(record.ts))
    .filter((date) => Number.isFinite(date.getTime()))
    .sort((left, right) => right.getTime() - left.getTime())[0]?.toISOString() ?? null;
}

function oldestTimestamp(records) {
  return records
    .map((record) => new Date(record.ts))
    .filter((date) => Number.isFinite(date.getTime()))
    .sort((left, right) => left.getTime() - right.getTime())[0]?.toISOString() ?? null;
}

export function observeFactContinuity(ledger, live) {
  if (!ledger || !isValidFactIntegrityLedger(ledger)) return "unknown";
  if (ledger.continuity.pending_pass) return "unknown";
  if (live?.exists === false) return "unknown";

  if (!Number.isInteger(live?.record_count) || live.record_count < 0 || !Number.isInteger(live?.bytes) || live.bytes < 0) return "unknown";
  if (!Buffer.isBuffer(live.raw_bytes) || live.raw_bytes.length !== live.bytes) return "unknown";

  const expectedCount = ledger.continuity.last_rewrite_record_count;
  if (live.record_count < expectedCount) return "broken";

  if (live.record_count === expectedCount && live.bytes !== ledger.continuity.last_rewrite_bytes) return "broken";

  const committedBytes = ledger.continuity.last_rewrite_bytes;
  if (live.raw_bytes.length < committedBytes) return "broken";
  if (committedBytes > 0) {
    const livePrefixDigest = crypto.createHash("sha256").update(live.raw_bytes.subarray(0, committedBytes)).digest("hex");
    if (livePrefixDigest !== ledger.continuity.output_digest) return "broken";
  } else if (ledger.continuity.output_digest !== null) {
    return "unknown";
  }

  if (live.record_count === expectedCount && live.newest_ts !== ledger.continuity.last_rewrite_newest_ts) return "broken";

  // A ledger written before facts.jsonl is renamed can be observed with the old,
  // longer file still in place. A same-newest file with excess records cannot be
  // explained by an append and is therefore unprovable rather than trusted.
  if (live.record_count > expectedCount) {
    if (live.bytes <= ledger.continuity.last_rewrite_bytes) return "broken";
    const expectedNewest = ledger.continuity.last_rewrite_newest_ts;
    if (expectedNewest && (!live.newest_ts || new Date(live.newest_ts).getTime() <= new Date(expectedNewest).getTime())) return "unknown";
    if (!expectedNewest) return "unknown";
  }

  return "ok";
}

export function prepareFactIntegrityLedger({ ledger, ledgerReason, nowIso, live, outputRecords, outputBytes, outputDigest, counts }) {
  const next = ledger ?? createFactIntegrityLedger();
  const bootstrap = ledger === null;
  const priorPending = next.continuity.pending_pass;
  const passId = Math.max(next.continuity.last_committed_pass_id, priorPending?.pass_id ?? 0) + 1;
  const continuityObservation = bootstrap ? "unknown" : observeFactContinuity(next, live);
  const outputNewestTs = newestTimestamp(outputRecords);
  const outputOldestTs = oldestTimestamp(outputRecords);
  const continuityBreak = continuityObservation === "broken";
  const pendingOutputChanged = Boolean(priorPending && priorPending.output_digest !== outputDigest);
  const retryContinuityBreak = pendingOutputChanged && continuityObservation === "unknown";
  const effectiveContinuityBreak = continuityBreak || retryContinuityBreak;
  const continuityOk = effectiveContinuityBreak ? false : continuityObservation === "unknown" ? null : true;
  const priorOldest = next.continuity.oldest_ts;
  const oldestTs = !priorOldest || (outputOldestTs && Date.parse(outputOldestTs) < Date.parse(priorOldest))
    ? outputOldestTs
    : priorOldest;

  const alreadyCounted = priorPending &&
    priorPending.output_record_count === outputRecords.length &&
    priorPending.output_bytes === outputBytes &&
    priorPending.output_newest_ts === outputNewestTs &&
    priorPending.output_digest === outputDigest;
  const offset = alreadyCounted ? priorPending : null;
  const addCount = (key, value) => Math.max(0, value - (offset?.[key] ?? 0));
  const corruptDelta = addCount("corrupt_count", counts.corrupt_count);
  const schemaInvalidDelta = addCount("schema_invalid_count", counts.schema_invalid_count);
  const bytecapDelta = addCount("bytecap_evicted_count", counts.bytecap_evicted_count);
  const ageDelta = addCount("age_evicted_count", counts.age_evicted_count);

  next.corrupt_dropped_total += corruptDelta;
  next.schema_invalid_dropped_total += schemaInvalidDelta;
  next.bytecap_evicted_total += bytecapDelta;
  next.age_evicted_total += ageDelta;
  if (corruptDelta > 0) next.last_corrupt_ts = nowIso;
  if (schemaInvalidDelta > 0) next.last_schema_invalid_ts = nowIso;
  if (bytecapDelta > 0) next.last_bytecap_evict_ts = nowIso;
  if (effectiveContinuityBreak) next.last_continuity_break_ts = nowIso;
  if ((corruptDelta + schemaInvalidDelta + bytecapDelta + effectiveContinuityBreak) > 0 && next.first_degraded_ts === null) next.first_degraded_ts = nowIso;

  next.continuity = {
    record_count_hwm: Math.max(next.continuity.record_count_hwm, live.record_count, outputRecords.length),
    oldest_ts: oldestTs,
    last_rewrite_record_count: outputRecords.length,
    last_rewrite_newest_ts: outputNewestTs,
    last_rewrite_bytes: outputBytes,
    output_digest: outputDigest,
    last_committed_pass_id: next.continuity.last_committed_pass_id,
    continuity_ok: continuityOk,
    pending_pass: {
      pass_id: passId,
      corrupt_count: counts.corrupt_count,
      schema_invalid_count: counts.schema_invalid_count,
      bytecap_evicted_count: counts.bytecap_evicted_count,
      age_evicted_count: counts.age_evicted_count,
      output_record_count: outputRecords.length,
      output_newest_ts: outputNewestTs,
      output_bytes: outputBytes,
      output_digest: outputDigest,
    },
  };
  return {
    ledger: next,
    passId,
    alreadyCounted,
    bootstrap,
    recoverPending: Boolean(priorPending && !effectiveContinuityBreak && priorPending.output_digest === outputDigest),
  };
}

export function finalizeFactIntegrityLedger(ledger, passId, { allowRecovery = false } = {}) {
  const next = structuredClone(ledger);
  if (next.continuity.pending_pass?.pass_id === passId) {
    next.continuity.last_committed_pass_id = passId;
    next.continuity.pending_pass = null;
    if (allowRecovery && next.continuity.continuity_ok === null) next.continuity.continuity_ok = true;
  }
  return next;
}

function lossAtOrAfter(timestamp, asOfMs) {
  return timestamp !== null && Date.parse(timestamp) >= asOfMs;
}

export function buildCompleteness(ledger, live, asOfMs = Number.NEGATIVE_INFINITY, currentCounts = {}) {
  const base = ledger ?? createFactIntegrityLedger();
  const continuityObservation = observeFactContinuity(ledger, live);
  const thisReadHasLoss = (currentCounts.corrupt_count ?? 0) > 0 || (currentCounts.schema_invalid_count ?? 0) > 0;
  if (continuityObservation === "broken") {
    return {
      status: "unknown",
      last_corrupt_ts: base.last_corrupt_ts,
      last_schema_invalid_ts: base.last_schema_invalid_ts,
      last_bytecap_evict_ts: base.last_bytecap_evict_ts,
      last_continuity_break_ts: base.last_continuity_break_ts,
      corrupt_dropped_total: base.corrupt_dropped_total,
      schema_invalid_dropped_total: base.schema_invalid_dropped_total,
      bytecap_evicted_total: base.bytecap_evicted_total,
      age_evicted_total: base.age_evicted_total,
      first_degraded_ts: base.first_degraded_ts,
      continuity_ok: null,
    };
  }
  const continuityOk = continuityObservation === "unknown" ? null : ledger?.continuity.continuity_ok ?? null;
  if (!ledger || continuityObservation === "unknown" || continuityOk !== true) {
    return {
      status: continuityOk === false && lossAtOrAfter(base.last_continuity_break_ts, asOfMs) ? "degraded" : "unknown",
      last_corrupt_ts: base.last_corrupt_ts,
      last_schema_invalid_ts: base.last_schema_invalid_ts,
      last_bytecap_evict_ts: base.last_bytecap_evict_ts,
      last_continuity_break_ts: base.last_continuity_break_ts,
      corrupt_dropped_total: base.corrupt_dropped_total,
      schema_invalid_dropped_total: base.schema_invalid_dropped_total,
      bytecap_evicted_total: base.bytecap_evicted_total,
      age_evicted_total: base.age_evicted_total,
      first_degraded_ts: base.first_degraded_ts,
      continuity_ok: continuityOk,
    };
  }

  const degraded = thisReadHasLoss || [
    base.last_corrupt_ts,
    base.last_schema_invalid_ts,
    base.last_bytecap_evict_ts,
    base.last_continuity_break_ts,
  ].some((timestamp) => lossAtOrAfter(timestamp, asOfMs));
  return {
    status: degraded ? "degraded" : "intact",
    last_corrupt_ts: base.last_corrupt_ts,
    last_schema_invalid_ts: base.last_schema_invalid_ts,
    last_bytecap_evict_ts: base.last_bytecap_evict_ts,
    last_continuity_break_ts: base.last_continuity_break_ts,
    corrupt_dropped_total: base.corrupt_dropped_total,
    schema_invalid_dropped_total: base.schema_invalid_dropped_total,
    bytecap_evicted_total: base.bytecap_evicted_total,
    age_evicted_total: base.age_evicted_total,
    first_degraded_ts: base.first_degraded_ts,
    continuity_ok: base.continuity.continuity_ok,
  };
}
