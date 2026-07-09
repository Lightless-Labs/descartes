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

function isFixedLengthHexHash(value) {
  return typeof value === "string" && HEX_HASH_LENGTHS.has(value.length) && HEX_PATTERN.test(value);
}

function isSafeEnumString(value) {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_STRING_LENGTH && SAFE_STRING_PATTERN.test(value);
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
  return { safe: false, reason: value === null ? "null_value" : "unsupported_type" };
}

function redactionMarker(reason, rawValue) {
  return {
    redacted: true,
    reason,
    original_length: typeof rawValue === "string" ? rawValue.length : undefined,
  };
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
