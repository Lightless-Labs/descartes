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
  // Fix 0 (trusted-state step-1 revision, "R1 made signable"): the future-fact continuity
  // wedge. Mirrors corrupt_dropped_total/last_corrupt_ts exactly -- a cumulative lifetime
  // total plus a most-recent-event marker for the new loss channel.
  "future_fact_dropped_total",
  "last_future_fact_ts",
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
  // Fix 0: mirrors corrupt_count exactly.
  "future_fact_count",
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
    future_fact_dropped_total: 0,
    last_future_fact_ts: null,
  };
}

// Fix 0 migration: a ledger written before this revision shipped (or a hand-built test/ops
// fixture pinned to the pre-fix0 shape) lacks future_fact_dropped_total/last_future_fact_ts
// (and pending_pass, if present, lacks future_fact_count). Per §5.3's boot_id migration
// discipline pulled one phase earlier for this one field: bootstrap the missing keys with
// their zero-value defaults BEFORE validation, rather than letting a merely-old-shaped (but
// otherwise coherent) ledger fail closed as "invalid" and take the continuity-break-stamping
// bootstrap path. This only ever ADDS defaulted keys that are absent -- it never touches a
// key that is already present (including a deliberately-wrong value under test), so it cannot
// rescue a ledger that is invalid for any other reason, and it cannot mask the identity-
// bearing-extra-keys rejection (fact-store-integrity.test.js's "must-not-persist" coverage),
// which only ever adds keys, never removes/renames them.
function migrateLedgerShape(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return raw;
  const migrated = { ...raw };
  if (!Object.prototype.hasOwnProperty.call(migrated, "future_fact_dropped_total")) {
    migrated.future_fact_dropped_total = 0;
  }
  if (!Object.prototype.hasOwnProperty.call(migrated, "last_future_fact_ts")) {
    migrated.last_future_fact_ts = null;
  }
  if (migrated.continuity && typeof migrated.continuity === "object" && !Array.isArray(migrated.continuity)) {
    const pendingPass = migrated.continuity.pending_pass;
    if (pendingPass && typeof pendingPass === "object" && !Array.isArray(pendingPass)) {
      if (!Object.prototype.hasOwnProperty.call(pendingPass, "future_fact_count")) {
        migrated.continuity = { ...migrated.continuity, pending_pass: { ...pendingPass, future_fact_count: 0 } };
      }
    }
  }
  return migrated;
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

// daybreak-blue security sweep (2026-09-04), fact-store HIGH #3: Number.isInteger(2^53) is
// true (2^53 IS an integer, just not one JS floats can distinguish from 2^53+1) -- a
// hand-crafted/tampered ledger with pass_id at or above 2^53 passed validation, then the next
// retention pass computed passId = max(2^53, 0) + 1 === 2^53 (float rounds back to the same
// value), making pending_pass.pass_id <= last_committed_pass_id and crash-looping every
// subsequent write. Number.isSafeInteger rejects these up front so a poisoned ledger fails
// closed (invalid -> bootstraps to unknown) instead of crash-looping.
function isValidPendingPass(value) {
  if (value === null) return true;
  return Boolean(
    value && typeof value === "object" &&
    !Array.isArray(value) &&
    hasExactKeys(value, PENDING_PASS_KEYS) &&
    Number.isSafeInteger(value.pass_id) && value.pass_id > 0 &&
    Number.isSafeInteger(value.corrupt_count) && value.corrupt_count >= 0 &&
    Number.isSafeInteger(value.schema_invalid_count) && value.schema_invalid_count >= 0 &&
    Number.isSafeInteger(value.bytecap_evicted_count) && value.bytecap_evicted_count >= 0 &&
    Number.isSafeInteger(value.age_evicted_count) && value.age_evicted_count >= 0 &&
    Number.isSafeInteger(value.future_fact_count) && value.future_fact_count >= 0 &&
    Number.isSafeInteger(value.output_record_count) && value.output_record_count >= 0 &&
    Number.isSafeInteger(value.output_bytes) && value.output_bytes >= 0 &&
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
    "future_fact_dropped_total",
  ];
  if (!hasExactKeys(value, LEDGER_KEYS)) return false;
  if (value.schema_version !== FACT_INTEGRITY_SCHEMA_VERSION || typeof value.generation !== "string" || !value.generation) return false;
  if (totals.some((key) => !Number.isSafeInteger(value[key]) || value[key] < 0)) return false;
  if (["last_corrupt_ts", "last_schema_invalid_ts", "last_bytecap_evict_ts", "last_continuity_break_ts", "first_degraded_ts", "last_future_fact_ts"].some((key) => !isNullableTimestamp(value[key]))) return false;

  const continuity = value.continuity;
  if (!continuity || typeof continuity !== "object" || Array.isArray(continuity)) return false;
  if (!hasExactKeys(continuity, CONTINUITY_KEYS) || !Object.prototype.hasOwnProperty.call(continuity, "pending_pass")) return false;
  if (!["record_count_hwm", "last_rewrite_record_count", "last_rewrite_bytes", "last_committed_pass_id"].every((key) => Number.isSafeInteger(continuity[key]) && continuity[key] >= 0)) return false;
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
  if (value.future_fact_dropped_total > 0 && value.last_future_fact_ts === null) return false;
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
    const ledger = migrateLedgerShape(JSON.parse(contents));
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
  // daybreak-blue re-gate (2026-09-04) HIGH (residual): a ledger whose last_committed_pass_id
  // (or a still-pending pass_id) sits exactly at Number.MAX_SAFE_INTEGER is itself perfectly
  // VALID -- isValidFactIntegrityLedger's Number.isSafeInteger check accepts it -- but the next
  // passId computed below (+1) would exceed MAX_SAFE_INTEGER. Throwing there (as this used to)
  // rejects every subsequent retention write forever: the throw happens before the facts
  // rewrite is renamed into place, so the on-disk ledger never advances past the poisoned
  // value and the same throw recurs on every future pass -- a permanent fail-STUCK crash loop
  // (appendFactPoints/enforceFactRetention can never write again), not the fail-closed behavior
  // the rest of this module aims for. Route pass_id exhaustion through the exact same
  // fail-closed path an invalid/unreadable ledger already takes below: bootstrap a fresh
  // ledger and stamp a continuity-break marker, so completeness reads degraded/unknown (never
  // intact) instead of bricking retention.
  const priorPassId = ledger
    ? Math.max(ledger.continuity.last_committed_pass_id, ledger.continuity.pending_pass?.pass_id ?? 0)
    : 0;
  const passIdExhausted = ledger !== null && priorPassId >= Number.MAX_SAFE_INTEGER;
  const bootstrap = ledger === null || passIdExhausted;
  const next = bootstrap ? createFactIntegrityLedger() : ledger;
  // daybreak-blue re-gate (2026-09-04) BLOCKER: bootstrapping straight over an INVALID
  // (tampered/corrupt), UNREADABLE, or pass_id-EXHAUSTED ledger must not let this pass's own
  // fresh observation silently bless a possibly-shortened store as trustworthy. With no valid
  // prior ledger to compare against, the freshly-bootstrapped ledger's "last rewrite" fields
  // are just an echo of whatever the live store looks like right now -- so the very next clean
  // pass finds itself self-consistent against that echo and flips continuity_ok:true with NO
  // recorded loss, even though the store may have been truncated moments before (Descartes
  // re-signing its own shortened state). A genuinely-missing ledger (first-ever run,
  // ledgerReason "missing") has nothing to distrust and must still be able to reach intact.
  // "invalid", "unreadable", and pass_id exhaustion all get a now-stamped continuity-break
  // marker instead, so buildCompleteness degrades (not intact) until that marker ages out of
  // the retention window -- the same bounded-recovery design already used for a real
  // continuity break (see lossAtOrAfter).
  const invalidLedgerBootstrap = bootstrap && (ledgerReason === "invalid" || ledgerReason === "unreadable" || passIdExhausted);
  const priorPending = next.continuity.pending_pass;
  const passId = Math.max(next.continuity.last_committed_pass_id, priorPending?.pass_id ?? 0) + 1;
  // daybreak-blue security sweep, fact-store HIGH #3, defense-in-depth: pass_id must stay in
  // the exactly-representable integer range for strict monotonicity to hold. isValidPendingPass
  // rejects >= 2^53 on load, and passIdExhausted above reroutes a ledger already AT
  // MAX_SAFE_INTEGER to a fresh bootstrap (passId resets to 1), so this should be unreachable
  // from this function -- fenced anyway in case a ledger reaches here by another path.
  if (passId > Number.MAX_SAFE_INTEGER) {
    throw new Error("fact-store integrity ledger pass_id would exceed Number.MAX_SAFE_INTEGER");
  }
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
  // counts.future_fact_count defaults to 0 (not required of every caller -- prepareFactIntegrityLedger
  // is called directly, without it, by fact-store-integrity.test.js's pass_id-exhaustion coverage);
  // an undefined value must never reach addSaturating below (NaN would poison the safe-integer check
  // and saturate every total to MAX_SAFE_INTEGER on this pass).
  const addCount = (key, value) => Math.max(0, (value ?? 0) - (offset?.[key] ?? 0));
  const corruptDelta = addCount("corrupt_count", counts.corrupt_count);
  const schemaInvalidDelta = addCount("schema_invalid_count", counts.schema_invalid_count);
  const bytecapDelta = addCount("bytecap_evicted_count", counts.bytecap_evicted_count);
  const ageDelta = addCount("age_evicted_count", counts.age_evicted_count);
  const futureFactDelta = addCount("future_fact_count", counts.future_fact_count);

  // Fix 1 (trusted-state step-1 revision, "R1 made signable"): bounded blind. Pull any of the
  // loss-timestamp fields (and first_degraded_ts, audit-trail-only) that sit FORWARD of this
  // pass's own nowIso down to nowIso, BEFORE the stamping below applies this pass's own fresh
  // deltas. Turns an unbounded fail-STUCK blind (a far-future marker that would otherwise hold
  // buildCompleteness "degraded" until real wall time catches up to it -- no fixed bound) into
  // a bounded, one-window blind for the common non-adversarial case (NTP glitch / misconfigured
  // clock / DST bug) this fix actually targets. Deliberately UNGUARDED against a deliberate
  // same-uid clock-control attacker in Phase 1 (operator-accepted decision, plan §"Fix 1" /
  // open_decisions) -- a wall-clock-only backward-step guard cannot distinguish a genuine
  // forward-clock correction from an attacker's rollback (both look identical to a wall-clock-
  // only observer); a real guard needs boot_id (Phase 3). The residual this accepts is a strict
  // subset of a capability the same-uid attacker already has today via a coincident fresh delta
  // on the same rolled-back tick (:403-406 below, unconditional even pre-fix) -- this just
  // removes the "needs a fresh delta this tick" coincidence requirement for that already-in-scope
  // attacker (§3: "a same-uid attacker is defeated" is explicitly NOT a step-1 claim).
  const nowMsForClamp = Date.parse(nowIso);
  const clampForward = (value) => {
    if (value === null) return value;
    const valueMs = Date.parse(value);
    return Number.isFinite(valueMs) && Number.isFinite(nowMsForClamp) && valueMs > nowMsForClamp ? nowIso : value;
  };
  next.last_corrupt_ts = clampForward(next.last_corrupt_ts);
  next.last_schema_invalid_ts = clampForward(next.last_schema_invalid_ts);
  next.last_bytecap_evict_ts = clampForward(next.last_bytecap_evict_ts);
  next.last_continuity_break_ts = clampForward(next.last_continuity_break_ts);
  next.first_degraded_ts = clampForward(next.first_degraded_ts);
  next.last_future_fact_ts = clampForward(next.last_future_fact_ts);

  // daybreak-blue re-gate HIGH #2: a total already at Number.MAX_SAFE_INTEGER is itself a
  // valid, safe integer, but `total + delta` (delta > 0) overflows into an UNSAFE integer --
  // isValidFactIntegrityLedger then rejects it and writeFactIntegrityLedger throws "Invalid
  // fact-store integrity ledger" on this pass. Because the throw happens before the facts
  // rewrite is renamed into place, the on-disk store (and its offending delta source, e.g. a
  // persistently-corrupt line) is untouched, so the very same overflow recurs on every future
  // pass: a permanent crash loop that bricks appendFactPoints/enforceFactRetention for good.
  // Saturate instead of incrementing past MAX_SAFE_INTEGER -- the counter stops being exact at
  // that point (an already-astronomical count), but stays a safe integer and the pass
  // completes; last_corrupt_ts/last_schema_invalid_ts/etc. below still record the ongoing loss
  // independently of the exact total, so this never masks a real, current degradation.
  // daybreak-blue re-gate HIGH #2: a total already at Number.MAX_SAFE_INTEGER is itself a
  // valid, safe integer, but `total + delta` (delta > 0) overflows into an UNSAFE integer --
  // isValidFactIntegrityLedger then rejects it and writeFactIntegrityLedger throws "Invalid
  // fact-store integrity ledger" on this pass. Because the throw happens before the facts
  // rewrite is renamed into place, the on-disk store (and its offending delta source, e.g. a
  // persistently-corrupt line) is untouched, so the very same overflow recurs on every future
  // pass: a permanent crash loop that bricks appendFactPoints/enforceFactRetention for good.
  // Saturate instead of incrementing past MAX_SAFE_INTEGER -- the counter stops being exact at
  // that point (an already-astronomical count), but stays a safe integer and the pass
  // completes; last_corrupt_ts/last_schema_invalid_ts/etc. below still record the ongoing loss
  // independently of the exact total, so this never masks a real, current degradation.
  const addSaturating = (total, delta) => {
    const sum = total + delta;
    return Number.isSafeInteger(sum) ? sum : Number.MAX_SAFE_INTEGER;
  };
  next.corrupt_dropped_total = addSaturating(next.corrupt_dropped_total, corruptDelta);
  next.schema_invalid_dropped_total = addSaturating(next.schema_invalid_dropped_total, schemaInvalidDelta);
  next.bytecap_evicted_total = addSaturating(next.bytecap_evicted_total, bytecapDelta);
  next.age_evicted_total = addSaturating(next.age_evicted_total, ageDelta);
  next.future_fact_dropped_total = addSaturating(next.future_fact_dropped_total, futureFactDelta);
  if (corruptDelta > 0) next.last_corrupt_ts = nowIso;
  if (schemaInvalidDelta > 0) next.last_schema_invalid_ts = nowIso;
  if (bytecapDelta > 0) next.last_bytecap_evict_ts = nowIso;
  if (effectiveContinuityBreak || invalidLedgerBootstrap) next.last_continuity_break_ts = nowIso;
  // Fix 0: last_future_fact_ts is always stamped with THIS pass's real nowIso -- never the
  // dropped record's own claimed future ts (see enforceFactRetention's counts.future_fact_count
  // callsite) -- mirroring last_corrupt_ts/last_schema_invalid_ts/last_bytecap_evict_ts exactly.
  if (futureFactDelta > 0) next.last_future_fact_ts = nowIso;
  if ((corruptDelta + schemaInvalidDelta + bytecapDelta + futureFactDelta + effectiveContinuityBreak + invalidLedgerBootstrap) > 0 && next.first_degraded_ts === null) next.first_degraded_ts = nowIso;

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
      // counts.future_fact_count defaults to 0 for a caller that predates fix 0 (mirrors
      // addCount's own default above).
      future_fact_count: counts.future_fact_count ?? 0,
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

// R1 (trusted-state step-1 revision, "R1 made signable"): the `lossMs <= upperBoundMs` clause
// that used to drop a future-dated loss from this evaluation is REMOVED. A future-dated loss is
// a real loss with an untrustworthy timestamp, not a non-event -- it must count. No nowMs bound
// remains here at all (see Fix 1's clamp, and buildCompleteness's own future_loss_fields, for
// how a future marker is surfaced/bounded instead of silently excluded).
function lossAtOrAfter(timestamp, asOfMs) {
  if (timestamp === null) return false;
  const lossMs = Date.parse(timestamp);
  return lossMs >= asOfMs;
}

// The five loss-timestamp channels buildCompleteness's degraded evaluation consults. Order is
// significant for degraded_reason's channel attribution below (last_future_fact_ts first: a
// future-fact-only incident should report as such, not be absorbed into a same-tick continuity-
// break attribution).
const LOSS_CHANNEL_FIELDS = [
  "last_future_fact_ts",
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
];

// Fix 2 (surfacing, additive, no trust-decision path touched): the subset of last_*_ts field
// names whose parsed value is strictly after nowMs -- i.e. still forward-dated as of this read.
// Purely diagnostic: no code path below or elsewhere consults this to make a trust decision.
function futureLossFields(base, nowMs) {
  if (!Number.isFinite(nowMs)) return [];
  return LOSS_CHANNEL_FIELDS.filter((field) => {
    const value = base[field];
    if (value === null) return false;
    const valueMs = Date.parse(value);
    return Number.isFinite(valueMs) && valueMs > nowMs;
  });
}

// Fix 2: the field set every buildCompleteness return branch shares (a deepEqual fixture across
// branches -- see fact-store-integrity.test.js -- is the signal this was done inconsistently).
function commonCompletenessFields(base, nowMs) {
  return {
    last_corrupt_ts: base.last_corrupt_ts,
    last_schema_invalid_ts: base.last_schema_invalid_ts,
    last_bytecap_evict_ts: base.last_bytecap_evict_ts,
    last_continuity_break_ts: base.last_continuity_break_ts,
    last_future_fact_ts: base.last_future_fact_ts,
    corrupt_dropped_total: base.corrupt_dropped_total,
    schema_invalid_dropped_total: base.schema_invalid_dropped_total,
    bytecap_evicted_total: base.bytecap_evicted_total,
    age_evicted_total: base.age_evicted_total,
    future_fact_dropped_total: base.future_fact_dropped_total,
    first_degraded_ts: base.first_degraded_ts,
    // Finding F2-Tier1, additive read-only reporting: mirrors ledger.continuity.oldest_ts so
    // an operator can see how much fact history is actually retained (not just a cumulative
    // lifetime eviction total) even on an unknown/broken-continuity read -- no trust-decision
    // code path consults this field.
    continuity_oldest_ts: base.continuity.oldest_ts,
    future_loss_fields: futureLossFields(base, nowMs),
  };
}

export function buildCompleteness(ledger, live, asOfMs = Number.NEGATIVE_INFINITY, currentCounts = {}, nowMs) {
  const base = ledger ?? createFactIntegrityLedger();
  const continuityObservation = observeFactContinuity(ledger, live);
  const thisReadHasLoss = (currentCounts.corrupt_count ?? 0) > 0 || (currentCounts.schema_invalid_count ?? 0) > 0;
  if (continuityObservation === "broken") {
    return {
      status: "unknown",
      ...commonCompletenessFields(base, nowMs),
      continuity_ok: null,
      degraded_reason: "continuity_unknown",
    };
  }
  // R2 (trusted-state step-1 revision, "R1 made signable"): the clock-rollback-artifact override
  // that used to flip a stale continuity_ok:false back to true whenever last_continuity_break_ts
  // sat in the future is REMOVED (dead code once R1 ships -- byte-identical status output to
  // R1-only, see the revision's own review note). continuityOk now mirrors the ledger's own
  // recorded value whenever the live observation itself is resolvable ("ok"/"broken"); only an
  // unresolvable ("unknown") live observation forces continuityOk to null.
  const rawContinuityOk = ledger?.continuity.continuity_ok ?? null;
  const continuityOk = continuityObservation === "unknown" ? null : rawContinuityOk;
  if (!ledger || continuityObservation === "unknown" || continuityOk !== true) {
    const status = continuityOk === false && lossAtOrAfter(base.last_continuity_break_ts, asOfMs) ? "degraded" : "unknown";
    return {
      status,
      ...commonCompletenessFields(base, nowMs),
      continuity_ok: continuityOk,
      degraded_reason: status === "degraded" ? "continuity_break" : "continuity_unknown",
    };
  }

  if (thisReadHasLoss) {
    return {
      status: "degraded",
      ...commonCompletenessFields(base, nowMs),
      continuity_ok: base.continuity.continuity_ok,
      degraded_reason: "this_read_loss",
    };
  }
  const lossChannel = LOSS_CHANNEL_FIELDS.find((field) => lossAtOrAfter(base[field], asOfMs));
  const degraded = lossChannel !== undefined;
  const degradedReason = !degraded
    ? "none"
    : lossChannel === "last_future_fact_ts"
      ? "future_fact"
      : Number.isFinite(nowMs) && base[lossChannel] !== null && Date.parse(base[lossChannel]) > nowMs
        ? "future_loss"
        : "in_window_loss";
  return {
    status: degraded ? "degraded" : "intact",
    ...commonCompletenessFields(base, nowMs),
    continuity_ok: base.continuity.continuity_ok,
    degraded_reason: degradedReason,
  };
}
