// Shared validation for bounded machine-output populations.
//
// A parser may preserve valid records for diagnostics, but it must not claim a complete census
// when an input row was unknown, an identity was repeated, a cross-reference disagreed, or a
// bounded read stopped before the source was exhausted.

const RFC3339_RE = /^(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$/;

function hasValidCalendarDate(value) {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  return Number.isInteger(daysInMonth) && day <= daysInMonth;
}

/** Exact string check for timestamps accepted as evidence metadata. */
export function isStrictRfc3339(value) {
  return typeof value === "string" && RFC3339_RE.test(value) && hasValidCalendarDate(value);
}

/** Parse only a timestamp which passed the exact RFC3339 grammar. */
export function strictRfc3339EpochMilliseconds(value) {
  if (!isStrictRfc3339(value)) return undefined;
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) ? epoch : undefined;
}

/**
 * Validate a bounded population without collapsing duplicate identities.
 * `records` is returned bounded for callers that need to emit the population; the metadata keeps
 * the source cardinality and says why a complete census was not established.
 */
export function finalizeCensus({ records, identity, cap = Number.POSITIVE_INFINITY, malformed = 0, truncated = false, crossReferences = [] } = {}) {
  const input = Array.isArray(records) ? records : [];
  const boundedCap = Number.isSafeInteger(cap) && cap >= 0 ? cap : Number.POSITIVE_INFINITY;
  const seen = new Set();
  let duplicate_count = 0;
  let invalid_identity_count = 0;
  for (const record of input) {
    const key = typeof identity === "function" ? identity(record) : record;
    if (typeof key !== "string" || key.length === 0) {
      invalid_identity_count += 1;
      continue;
    }
    if (seen.has(key)) duplicate_count += 1;
    seen.add(key);
  }
  const crossReferenceErrors = crossReferences.filter((reference) => reference?.ok !== true).length;
  const isTruncated = truncated === true || input.length > boundedCap;
  const malformedCount = Number.isSafeInteger(malformed) && malformed >= 0 ? malformed : 1;
  const complete = malformedCount === 0
    && duplicate_count === 0
    && invalid_identity_count === 0
    && crossReferenceErrors === 0
    && !isTruncated;
  return {
    records: input.slice(0, boundedCap),
    total_count: input.length,
    malformed_count: malformedCount,
    duplicate_count,
    invalid_identity_count,
    truncated: isTruncated,
    cross_reference_error_count: crossReferenceErrors,
    complete,
    status: complete ? "ok" : "partial",
  };
}

/** Require every referenced population to contain the same unique key multiset one-to-one. */
export function validateCrossReferenceKeys(...populations) {
  if (populations.length === 0 || populations.some((population) => !Array.isArray(population))) {
    return { ok: false, reason: "not_an_array" };
  }
  const keySets = populations.map((population) => {
    const counts = new Map();
    for (const key of population) {
      if (typeof key !== "string" || key.length === 0) return undefined;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  });
  if (keySets.some((counts) => counts === undefined)) return { ok: false, reason: "invalid_key" };
  const duplicate_count = keySets.reduce((total, counts) => total + [...counts.values()].filter((count) => count > 1).length, 0);
  if (duplicate_count > 0) return { ok: false, reason: "duplicate_key", duplicate_count };
  const first = keySets[0];
  const same = keySets.every((counts) => counts.size === first.size && [...first.keys()].every((key) => counts.has(key)));
  return same ? { ok: true, duplicate_count: 0 } : { ok: false, reason: "key_set_mismatch", duplicate_count: 0 };
}

/** Common exact-type predicates used by parser adapters. */
export const censusTypes = Object.freeze({
  string: (value) => typeof value === "string",
  boolean: (value) => typeof value === "boolean",
  finiteNumber: (value) => typeof value === "number" && Number.isFinite(value),
  safeInteger: (value) => typeof value === "number" && Number.isSafeInteger(value),
});
