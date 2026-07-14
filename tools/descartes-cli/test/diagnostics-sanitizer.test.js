import assert from "node:assert/strict";
import test from "node:test";
import { sanitizeDiagnostics, sanitizeIdentityString } from "../src/diagnostics-sanitizer.js";

test("sanitizeDiagnostics passes finite numbers, booleans, short enum strings, and hex hashes through verbatim", () => {
  const sanitized = sanitizeDiagnostics({
    count: 3,
    min: 0.92,
    negative: -12.5,
    zero: 0,
    is_critical: true,
    is_stale: false,
    severity: "warning",
    family: "service-presence",
    rule_fragment: "daemon.samples.stale",
    short_hash_16: "a3f2b8c9d1e4f567",
    sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
  });

  assert.deepEqual(sanitized, {
    count: 3,
    min: 0.92,
    negative: -12.5,
    zero: 0,
    is_critical: true,
    is_stale: false,
    severity: "warning",
    family: "service-presence",
    rule_fragment: "daemon.samples.stale",
    short_hash_16: "a3f2b8c9d1e4f567",
    sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
  });
});

test("sanitizeDiagnostics drops a raw filesystem path and marks it redacted", () => {
  const rawPath = "/Users/alice/Projects/lightless-labs/data.db";
  const sanitized = sanitizeDiagnostics({ home: rawPath });

  assert.equal(sanitized.home.redacted, true);
  assert.equal(sanitized.home.original_length, rawPath.length);
  assert.notEqual(sanitized.home.reason, undefined);
  // Never passed through verbatim, in whole or in part.
  assert.equal(JSON.stringify(sanitized).includes("alice"), false);
  assert.equal(JSON.stringify(sanitized).includes("/Users"), false);
});

test("sanitizeDiagnostics drops a username/email-shaped free-text value", () => {
  const owner = "alice@corp.example.com";
  const sanitized = sanitizeDiagnostics({ owner });

  assert.equal(sanitized.owner.redacted, true);
  assert.equal(sanitized.owner.original_length, owner.length);
  assert.equal(JSON.stringify(sanitized).includes("alice"), false);
});

test("sanitizeDiagnostics drops a command-line string", () => {
  const commandLine = "rm -rf /tmp/data --force --user=alice";
  const sanitized = sanitizeDiagnostics({ args: commandLine });

  assert.equal(sanitized.args.redacted, true);
  assert.equal(sanitized.args.original_length, commandLine.length);
  assert.equal(JSON.stringify(sanitized).includes("rm -rf"), false);
});

test("sanitizeDiagnostics drops an over-long string even when it matches the safe charset", () => {
  const overLong = "a".repeat(200);
  const sanitized = sanitizeDiagnostics({ token: overLong });

  assert.equal(sanitized.token.redacted, true);
  assert.equal(sanitized.token.reason, "string_too_long");
  assert.equal(sanitized.token.original_length, 200);
});

test("sanitizeDiagnostics drops nested objects, arrays, null, undefined, and non-finite numbers", () => {
  const sanitized = sanitizeDiagnostics({
    nested: { a: 1, b: 2 },
    list: [1, 2, 3],
    missing: undefined,
    empty: null,
    not_a_number: NaN,
    infinite: Infinity,
  });

  for (const key of Object.keys(sanitized)) {
    assert.equal(sanitized[key].redacted, true, `expected ${key} to be redacted`);
  }
});

test("sanitizeDiagnostics normalizes non-object input to an empty object", () => {
  assert.deepEqual(sanitizeDiagnostics(undefined), {});
  assert.deepEqual(sanitizeDiagnostics(null), {});
  assert.deepEqual(sanitizeDiagnostics("not an object"), {});
  assert.deepEqual(sanitizeDiagnostics([1, 2, 3]), {});
  assert.deepEqual(sanitizeDiagnostics({}), {});
});

test("sanitizeDiagnostics is pure and deterministic", () => {
  const input = { count: 3, path: "/Users/alice/data" };
  const first = sanitizeDiagnostics(input);
  const second = sanitizeDiagnostics(input);
  assert.deepEqual(first, second);
  // Input object itself is untouched.
  assert.equal(input.path, "/Users/alice/data");
});

test("sanitizeDiagnostics classifies an own '__proto__' key without corrupting the output prototype", () => {
  // JSON.parse produces a normal own data property named "__proto__" (not a proto-setter),
  // which a future evaluate*() family could spread from externally-sourced JSON.
  const input = JSON.parse('{"__proto__": {"nested": 2}, "normal": "ok"}');
  const sanitized = sanitizeDiagnostics(input);

  // The output keeps a normal Object prototype — it must not be reassigned by the __proto__ entry.
  assert.equal(Object.getPrototypeOf(sanitized), Object.prototype);
  // The safe key still passes through.
  assert.equal(sanitized.normal, "ok");
  // The "__proto__" entry is a real own property and is redacted like any nested object,
  // never silently dropped.
  const protoDesc = Object.getOwnPropertyDescriptor(sanitized, "__proto__");
  assert.notEqual(protoDesc, undefined);
  assert.equal(protoDesc.value.redacted, true);
  // And no global prototype pollution.
  assert.equal({}.nested, undefined);
});

// --- Slice S6b: sanitizeIdentityString (shared with fact-translators.js's sanitizeEntityKey) ---

test("sanitizeIdentityString passes an already-safe enum-shaped identifier through unchanged", () => {
  assert.equal(sanitizeIdentityString("nginx.service"), "nginx.service");
  assert.equal(sanitizeIdentityString("com.example.running"), "com.example.running");
  assert.equal(sanitizeIdentityString("tcp:0.0.0.0:8080"), "tcp:0.0.0.0:8080");
});

test("sanitizeIdentityString strips a path-like value down to a bounded safe string, never leaking raw path separators", () => {
  const hostile = "/usr/local/bin/../../etc/passwd";
  const sanitized = sanitizeIdentityString(hostile);
  assert.notEqual(sanitized, undefined);
  assert.equal(sanitized.includes("/"), false);
  assert.equal(sanitized.includes("etc"), true); // truncated/redacted, not obliterated to nothing
  assert.match(sanitized, /^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
});

test("sanitizeIdentityString truncates an over-length value to the max length", () => {
  const long = `service-${"a".repeat(200)}`;
  const sanitized = sanitizeIdentityString(long);
  assert(sanitized.length <= 64);
  assert.match(sanitized, /^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
});

test("sanitizeIdentityString returns undefined for empty, whitespace-only, or entirely-unsafe input", () => {
  assert.equal(sanitizeIdentityString(""), undefined);
  assert.equal(sanitizeIdentityString("   "), undefined);
  assert.equal(sanitizeIdentityString("////"), undefined);
  assert.equal(sanitizeIdentityString(undefined), undefined);
  assert.equal(sanitizeIdentityString(null), undefined);
});

test("sanitizeIdentityString is pure and deterministic", () => {
  const input = "/some/hostile/path";
  assert.equal(sanitizeIdentityString(input), sanitizeIdentityString(input));
});

// --- Slice 6 (observed-incident collectors plan) must-fix 1(ii): redaction-marker passthrough ---
// (restores idempotency for alert-intelligence.js's compactAlert defense-in-depth re-sanitization)

test("sanitizeDiagnostics passes an already-well-formed redaction marker through UNCHANGED (by reference), preserving its original reason and original_length", () => {
  const marker = { redacted: true, reason: "unsafe_string_shape", original_length: 12 };
  const sanitized = sanitizeDiagnostics({ owner: marker });
  assert.equal(sanitized.owner, marker, "expected the exact same marker object, not a rebuilt one");
  assert.deepEqual(sanitized.owner, { redacted: true, reason: "unsafe_string_shape", original_length: 12 });
});

test("sanitizeDiagnostics passes a well-formed redaction marker through unchanged even when original_length is undefined (the non-string-original-value case)", () => {
  const marker = { redacted: true, reason: "unsupported_type", original_length: undefined };
  const sanitized = sanitizeDiagnostics({ window_ms: marker });
  assert.deepEqual(sanitized.window_ms, { redacted: true, reason: "unsupported_type", original_length: undefined });
});

test("sanitizeDiagnostics passes a well-formed redaction marker through unchanged when original_length is entirely absent (round-tripped through JSON, which drops undefined-valued keys)", () => {
  // Mirrors what a marker actually looks like after a real round-trip through alerts.json's
  // JSON.stringify/JSON.parse: an undefined-valued original_length key is dropped entirely, not
  // preserved as a literal `undefined`.
  const marker = JSON.parse(JSON.stringify({ redacted: true, reason: "unsupported_type", original_length: undefined }));
  assert.deepEqual(Object.keys(marker), ["redacted", "reason"]);
  const sanitized = sanitizeDiagnostics({ window_ms: marker });
  assert.deepEqual(sanitized.window_ms, { redacted: true, reason: "unsupported_type" });
});

test("sanitizeDiagnostics does NOT treat an object merely resembling a marker (wrong reason type, extra keys, or redacted:false) as well-formed — it is redacted like any other unsupported object", () => {
  const wrongReasonType = sanitizeDiagnostics({ owner: { redacted: true, reason: 123, original_length: 5 } });
  assert.equal(wrongReasonType.owner.redacted, true);
  assert.notDeepEqual(wrongReasonType.owner, { redacted: true, reason: 123, original_length: 5 });

  const extraKey = sanitizeDiagnostics({ owner: { redacted: true, reason: "unsafe_string_shape", original_length: 5, extra: "nope" } });
  assert.equal(extraKey.owner.redacted, true);
  assert.notDeepEqual(extraKey.owner, { redacted: true, reason: "unsafe_string_shape", original_length: 5, extra: "nope" });

  const notActuallyRedacted = sanitizeDiagnostics({ owner: { redacted: false, reason: "unsafe_string_shape", original_length: 5 } });
  assert.equal(notActuallyRedacted.owner.redacted, true);
  assert.notDeepEqual(notActuallyRedacted.owner, { redacted: false, reason: "unsafe_string_shape", original_length: 5 });
});

test("sanitizeDiagnostics re-run on its own output is a true fixed point for a mix of already-safe values and an already-redacted marker", () => {
  const input = {
    count: 3,
    hash: "a3f2b8c9d1e4f567",
    home: "/Users/alice/data", // will be redacted on the FIRST pass
  };
  const once = sanitizeDiagnostics(input);
  const twice = sanitizeDiagnostics(once);
  assert.deepEqual(twice, once, "re-sanitizing an already-sanitized object (including its redaction marker) must be a no-op");
});
