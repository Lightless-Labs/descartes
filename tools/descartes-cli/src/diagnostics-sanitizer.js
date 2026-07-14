// Code-enforced allowlist/clamp for alert-candidate `diagnostics` payloads (Slice 2, plan §4).
//
// Mirrors the spirit of the redaction/truncation pattern in tools/processes.js
// (`redactAndBoundProcessArgs`: `.redacted` / `.truncated` / `.original_length`) but is
// self-contained here: this is a shallow, top-level allowlist over an already-structured
// diagnostics object, not a command-line tokenizer.
//
// Every value in the input object is independently classified. Only values that are
// UNAMBIGUOUSLY safe are passed through verbatim:
//   - finite numbers
//   - booleans
//   - short closed-enum/identifier strings (<= MAX_STRING_LENGTH chars, matching a
//     conservative safe charset: no filesystem paths, no whitespace, no command lines)
//   - fixed-length hex hashes (matches one of the well-known digest lengths)
//
// Anything else — a raw filesystem path, a username/email-shaped free-text value, a
// command-line string, an over-long string, a nested object/array, null, undefined,
// non-finite numbers — is DROPPED and replaced with a redaction marker. Nothing
// unclassified is ever passed through verbatim.
//
// Pure, deterministic, no I/O.

export const MAX_STRING_LENGTH = 64;

// Deliberately conservative: alnum start, then alnum plus a narrow set of separators
// that show up in real rule_id/family/status/enum values (dots, colons, underscores,
// hyphens). No "/", no "\", no whitespace, no "@" — those are exactly the shapes that
// distinguish paths, command lines, and free-text/username-shaped values from closed
// enum identifiers.
const SAFE_STRING_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

// Well-known hex digest lengths (crc32/8, md5, sha1, sha256, plus the 16-char digest
// alert-store's own alertId() truncates sha256 to).
const HEX_HASH_LENGTHS = new Set([8, 16, 32, 40, 64]);
const HEX_PATTERN = /^[0-9a-f]+$/i;

// Exported (additive, S6c) so downstream sanitization-gate tests (constraint-miner.test.js)
// can assert mined id/target strings satisfy the real allowlist predicates directly, rather
// than re-deriving a parallel hand-rolled regex that could silently drift from this module's.
export function isFixedLengthHexHash(value) {
  return typeof value === "string" && HEX_HASH_LENGTHS.has(value.length) && HEX_PATTERN.test(value);
}

export function isSafeEnumString(value) {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_STRING_LENGTH && SAFE_STRING_PATTERN.test(value);
}

// Slice 6 (observed-incident collectors plan) must-fix 1(ii): the exact set of keys a
// redactionMarker() object can ever carry -- used both to recognize an already-well-formed marker
// (the idempotency passthrough below) and to build one.
const REDACTION_MARKER_KEYS = new Set(["redacted", "reason", "original_length"]);

function redactionMarker(reason, rawValue) {
  return {
    redacted: true,
    reason,
    original_length: typeof rawValue === "string" ? rawValue.length : undefined,
  };
}

/**
 * Slice 6 must-fix 1(ii) (idempotency passthrough, hard requirement): alert-intelligence.js's
 * compactAlert re-runs sanitizeDiagnostics() as a defense-in-depth measure immediately before a
 * stored alert's diagnostics reach the LLM prompt (Decision 3). Without this check, re-running
 * classifyValue against an ALREADY-redacted marker object (produced by an earlier
 * sanitizeDiagnostics() call, then round-tripped through alerts.json) would fall through to the
 * generic "unsupported_type" object branch and get rewritten into a SECOND, generic redaction
 * marker -- losing the original reason/original_length and making the re-sanitization not a fixed
 * point. Recognizing the well-formed marker SHAPE explicitly (exactly the three keys above,
 * `redacted:true`, a safe-enum-string `reason`, and an `original_length` that is either absent,
 * undefined, or a finite number) and passing it through BY REFERENCE, unchanged, restores true
 * idempotency: a redacted value re-sanitizes to the identical marker, never a re-redacted one.
 */
function isWellFormedRedactionMarker(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length === 0 || !keys.every((key) => REDACTION_MARKER_KEYS.has(key))) return false;
  if (value.redacted !== true) return false;
  if (!isSafeEnumString(value.reason)) return false;
  if ("original_length" in value) {
    const originalLength = value.original_length;
    if (originalLength !== undefined && !(typeof originalLength === "number" && Number.isFinite(originalLength))) return false;
  }
  return true;
}

function classifyValue(value) {
  if (typeof value === "number") {
    return Number.isFinite(value) ? { safe: true, value } : { safe: false, reason: "non_finite_number" };
  }
  if (typeof value === "boolean") return { safe: true, value };
  if (typeof value === "string") {
    if (isFixedLengthHexHash(value)) return { safe: true, value };
    if (isSafeEnumString(value)) return { safe: true, value };
    return { safe: false, reason: value.length > MAX_STRING_LENGTH ? "string_too_long" : "unsafe_string_shape" };
  }
  if (isWellFormedRedactionMarker(value)) return { safe: true, value };
  return { safe: false, reason: value === null ? "null_value" : "unsupported_type" };
}

/**
 * Bounds/allowlists a single identity-shaped string (a service name, process command,
 * mined constraint id/target component, …) down to something that satisfies
 * `isSafeEnumString` by construction, rather than merely validating and rejecting.
 *
 * Unlike `sanitizeDiagnostics` (which classifies-and-redacts each value to a marker
 * object), callers of this function need a *string* back — entity keys and mined ids
 * are embedded directly into other strings downstream. So instead of rejecting an
 * unsafe value outright, every character outside the safe charset is replaced with
 * "_", any resulting leading run of non-alnum characters is trimmed (the safe charset
 * requires starting with an alnum), and the result is truncated to `maxLength`. This
 * guarantees "no raw path/command-line reaches the output" without silently dropping
 * the fact/record entirely just because one field needed sanitizing.
 *
 * Returns `undefined` (never a raw/partial value) when nothing safe survives — an
 * entirely-unsafe or empty input (e.g. "////", "", whitespace-only) — signaling to the
 * caller that the identity is unresolvable and the record should be dropped, matching
 * the "degrade, never fabricate" convention used elsewhere in this module.
 */
export function sanitizeIdentityString(value, { maxLength = MAX_STRING_LENGTH } = {}) {
  if (value === undefined || value === null) return undefined;
  const raw = String(value).trim();
  if (!raw) return undefined;

  const collapsed = raw
    .replace(/[^A-Za-z0-9._:-]/g, "_")
    .replace(/^[^A-Za-z0-9]+/, "");
  const truncated = collapsed.slice(0, maxLength);

  return isSafeEnumString(truncated) ? truncated : undefined;
}

/**
 * Sanitizes a candidate's `diagnostics` object down to only unambiguously-safe values.
 * Non-object input normalizes to `{}`. Every `evaluate*()` candidate family MUST route
 * its diagnostics through this gate before the candidate reaches the alert pipeline.
 */
export function sanitizeDiagnostics(diagnostics) {
  if (!diagnostics || typeof diagnostics !== "object" || Array.isArray(diagnostics)) return {};

  const sanitized = {};
  for (const [key, rawValue] of Object.entries(diagnostics)) {
    const classified = classifyValue(rawValue);
    const value = classified.safe ? classified.value : redactionMarker(classified.reason, rawValue);
    // Assign via defineProperty so a data key literally named "__proto__" (which
    // JSON.parse produces as a normal own property) is classified/redacted like any
    // other key, instead of triggering Object.prototype's __proto__ accessor — which
    // would silently drop the entry and reassign the output object's prototype.
    Object.defineProperty(sanitized, key, { value, enumerable: true, writable: true, configurable: true });
  }
  return sanitized;
}
