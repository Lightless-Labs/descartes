// C0.6 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, §4.4): closed per-field
// schemas for the context fact families (host_lifecycle, network_context, session_context).
//
// LEAF MODULE: imports nothing, so translators, the daemon and tests can all use it without a cycle.
//
// What a schema is. For every context fact_name: the closed set of attribute fields it may carry,
// and for each field (a) its value domain -- a closed enum, an HMAC/digest format, a bounded integer
// range or a bounded pattern, each optionally widened by closed sentinels ("unknown", "none",
// "not_applicable", ...) -- and (b) a PHYSICAL-OBJECT PROVENANCE TAG: the list of physical objects
// the value was read from or derived from. I5 (no dimension derived from the same physical object as
// a target it conditions) is checked later, statically, over these tags; C0 only records them.
//
// What validation does. `validateContextFact` is called by the translators on every point BEFORE it
// is returned. An attribute outside the schema, a missing required field, or a value outside its
// domain REJECTS the point: the translator then writes the schema's `unable` shape instead (every
// value field "unknown", collector_state "unable", rejected_field naming the offending field from the
// closed field list, or "unknown_field" for a key outside the schema, whose raw name is never
// echoed). A rejected field is never written, and never guessed into range (degrade, never fabricate).
//
// This is a schema validator, unlike diagnostics-sanitizer.js's isSafeEnumString (charset + length
// only, Astra 14).

export const HMAC_HEX_LENGTH = 16;
const HMAC_RE = /^[0-9a-f]{16}$/;

// Physical objects (closed). A field lists every object its value depends on.
export const PROVENANCE_TAGS = Object.freeze([
  "kernel.boot_session", // boot id, boot time, kernel release, OS build
  "kernel.clock", // wall / monotonic / boottime clock readings
  "kernel.power", // sleep/wake records, suspend counters
  "tailscale.daemon", // tailscaled's own status
  "net.route_table", // the default route and its interface
  "net.gateway_neighbor", // the gateway's link-layer neighbour entry
  "net.router_advertisement", // IPv6 RA-derived global prefixes
  "net.dhcp_lease", // DHCP-provided options
  "net.resolver_config", // interface-scoped resolvers
  "login.utmp", // who / last (utmpx / wtmp)
  "login.logind", // systemd-logind sessions
  "login.console", // macOS IOConsoleUsers
  "descartes.daemon", // the daemon's own clock, ledgers and collection bookkeeping
]);
const KNOWN_TAGS = new Set(PROVENANCE_TAGS);

const SENTINEL_UNKNOWN = "unknown";

// --- field-spec builders ------------------------------------------------------------------------

function enumField(values, provenance, { required = true } = {}) {
  return { kind: "enum", values: new Set(values), provenance, required };
}
function hmacField(provenance, sentinels = [SENTINEL_UNKNOWN], { required = true } = {}) {
  return { kind: "hmac", sentinels: new Set(sentinels), provenance, required };
}
function intField(min, max, provenance, sentinels = [SENTINEL_UNKNOWN], { required = true } = {}) {
  return { kind: "int", min, max, sentinels: new Set(sentinels), provenance, required };
}
function patternField(pattern, maxLength, provenance, sentinels = [SENTINEL_UNKNOWN], { required = true } = {}) {
  return { kind: "pattern", pattern, maxLength, sentinels: new Set(sentinels), provenance, required };
}

// The binary/collection states every context collector may report (§4.4 "Degrade, never
// fabricate"), plus "partial" for a multi-source collector with some sources down.
export const COLLECTOR_STATES = Object.freeze([
  "ok", "partial", "unable", "not_applicable", "not_found_on_known_paths", "untrusted_binary", "missing_permission",
]);
// A component/source state inside one fact: COLLECTOR_STATES plus "absent" (the source ran and
// genuinely reported nothing, e.g. no IPv6 router advertisement on this network).
export const COMPONENT_STATES = Object.freeze([...COLLECTOR_STATES, "absent"]);

const MAX_EPOCH_MS = 2 ** 47; // year ~6429; a bound, not a claim about time
const MAX_EPOCH_S = 2 ** 37;
const MAX_DURATION_S = 2 ** 37;
const DIGITS_RE = /^[0-9]{1,24}$/;
const DECIMAL_RE = /^[0-9]{1,20}(\.[0-9]{1,9})?$/;
const VERSION_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/;

// Common bookkeeping fields every context fact carries (§4.4: per-collector observation interval).
function commonFields(stateProvenance = ["descartes.daemon"]) {
  return {
    collector_state: enumField(COLLECTOR_STATES, stateProvenance),
    obs_start_ms: intField(0, MAX_EPOCH_MS, ["descartes.daemon"]),
    obs_end_ms: intField(0, MAX_EPOCH_MS, ["descartes.daemon"]),
  };
}

const BOOT_CONJUNCT = ["pass", "fail", "unknown"];

const FACT_SCHEMA_ENTRIES = [
  // ---------------------------------------------------------------- host_lifecycle
  ["host.boot", {
    family: "host_lifecycle",
    fields: {
      ...commonFields(["kernel.boot_session"]),
      boot_id_hmac: hmacField(["kernel.boot_session"]),
      boot_id_source: enumField(["kern.bootsessionuuid", "proc_boot_id", "unknown"], ["kernel.boot_session"]),
      boot_time_s: intField(0, MAX_EPOCH_S, ["kernel.boot_session", "kernel.clock"]),
      os_build: patternField(VERSION_TOKEN_RE, 64, ["kernel.boot_session"]),
      os_release: patternField(VERSION_TOKEN_RE, 64, ["kernel.boot_session"]),
      // Cheap boot-identity read before and after the session/peer census (§4.4 bracketing).
      bracket: enumField(["stable", "unstable", "unknown"], ["kernel.boot_session", "descartes.daemon"]),
    },
  }],
  ["host.boot_boundary", {
    family: "host_lifecycle",
    fields: {
      ...commonFields(["kernel.boot_session"]),
      verdict: enumField(["verified", "unverified", "tripwire", "unknown"], ["kernel.boot_session", "kernel.clock", "login.utmp", "descartes.daemon"]),
      failing_conjunct: enumField(["none", "unknown", "never_seen_boot_id", "daemon_restart", "boot_time_in_gap", "uptime_consistent", "no_preboot_instance"], ["descartes.daemon"]),
      tripwire: enumField(["none", "unknown", "boot_id_regression", "boot_id_change_without_daemon_restart", "boot_time_outside_gap", "uptime_inconsistent", "preboot_instance"], ["descartes.daemon"]),
      c_never_seen: enumField(BOOT_CONJUNCT, ["kernel.boot_session", "descartes.daemon"]),
      c_daemon_restart: enumField(BOOT_CONJUNCT, ["descartes.daemon", "kernel.boot_session"]),
      c_boot_time_in_gap: enumField(BOOT_CONJUNCT, ["kernel.boot_session", "kernel.clock", "descartes.daemon"]),
      c_uptime_consistent: enumField(BOOT_CONJUNCT, ["kernel.boot_session", "kernel.clock", "descartes.daemon"]),
      c_no_preboot_instance: enumField(BOOT_CONJUNCT, ["kernel.boot_session", "descartes.daemon"]),
      boot_id_hmac: hmacField(["kernel.boot_session"]),
      prev_boot_id_hmac: hmacField(["kernel.boot_session", "descartes.daemon"], [SENTINEL_UNKNOWN, "none"]),
      os_build_changed: enumField(["true", "false", "unknown"], ["kernel.boot_session", "descartes.daemon"]),
      gap_s: intField(0, MAX_DURATION_S, ["descartes.daemon", "kernel.clock"]),
      resolution_s: intField(0, 3600, ["descartes.daemon"]),
    },
  }],
  ["host.clock_reading", {
    family: "host_lifecycle",
    fields: {
      ...commonFields(["kernel.clock"]),
      boot_id_hmac: hmacField(["kernel.boot_session"]),
      wall_ms: intField(0, MAX_EPOCH_MS, ["kernel.clock"]),
      // libuv's hrtime. Which kernel clock it reads is a C0.9 measurement, so it is labelled, never
      // named as a pausing or a non-pausing clock.
      uv_hrtime_ns: patternField(DIGITS_RE, 24, ["kernel.clock"]),
      uv_version: patternField(VERSION_TOKEN_RE, 32, ["descartes.daemon"]),
      uv_hrtime_clock_id: enumField(["unverified"], ["descartes.daemon"]),
      // CLOCK_UPTIME_RAW / CLOCK_MONOTONIC / CLOCK_BOOTTIME / mach_continuous_time are not readable
      // from Node without native code; C0.9 records that instead of substituting another clock.
      named_clocks: enumField(["unavailable_without_native"], ["descartes.daemon"]),
      os_uptime_ms: intField(0, MAX_EPOCH_MS, ["kernel.clock", "kernel.boot_session"]),
      // macOS sysctls (raw text, digits only; "not_applicable" elsewhere).
      kern_monotonicclock_usecs: patternField(/^[0-9]{1,24} [0-9]{1,24}$/, 49, ["kernel.clock"], [SENTINEL_UNKNOWN, "not_applicable"]),
      kern_sleeptime_s: intField(0, MAX_EPOCH_S, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
      kern_waketime_s: intField(0, MAX_EPOCH_S, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
      kern_sleep_abs_time: patternField(DIGITS_RE, 24, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
      kern_wake_abs_time: patternField(DIGITS_RE, 24, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
      machdep_wake_abstime: patternField(DIGITS_RE, 24, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
      machdep_wake_conttime: patternField(DIGITS_RE, 24, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
      // Linux (raw text; "not_applicable" elsewhere). /proc/uptime's first field is CLOCK_BOOTTIME-based.
      proc_uptime_s: patternField(DECIMAL_RE, 31, ["kernel.clock"], [SENTINEL_UNKNOWN, "not_applicable"]),
      suspend_stats_success: intField(0, 2 ** 40, ["kernel.power"], [SENTINEL_UNKNOWN, "not_applicable"]),
    },
  }],
  ["host.suspend", {
    family: "host_lifecycle",
    fields: {
      ...commonFields(["kernel.power", "kernel.clock"]),
      // C0.9 no-go fallback until a platform is measured (F3 inactive): always "unknown" today.
      state: enumField(["unknown"], ["kernel.power", "kernel.clock"]),
      reason: enumField(["f3_inactive_c09_pending"], ["descartes.daemon"]),
      exposure_lower_s: intField(0, 0, ["descartes.daemon"]),
      exposure_upper_s: intField(0, MAX_DURATION_S, ["kernel.clock", "descartes.daemon"]),
      interval_basis: enumField(["same_boot_uptime_delta", "cross_boot", "no_previous_reading", "uptime_regressed", "unknown"], ["kernel.boot_session", "kernel.clock", "descartes.daemon"]),
    },
  }],
  ["host.boundary_census", {
    family: "host_lifecycle",
    fields: {
      ...commonFields(["kernel.boot_session", "kernel.power"]),
      trigger: enumField(["boot", "wake", "unknown"], ["kernel.boot_session", "kernel.power"]),
      status: enumField(["ran", "deferred_cost_cap", "not_enabled", "detected_after_census", "unknown"], ["descartes.daemon"]),
      boot_id_hmac: hmacField(["kernel.boot_session"]),
      pre_gap_s: intField(0, MAX_DURATION_S, ["kernel.boot_session", "kernel.power", "descartes.daemon"]),
      post_gap_s: intField(0, MAX_DURATION_S, ["kernel.boot_session", "kernel.power", "descartes.daemon"]),
    },
  }],
  // ---------------------------------------------------------------- network_context
  ["net.tailnet_state", {
    family: "network_context",
    fields: {
      ...commonFields(["tailscale.daemon"]),
      state: enumField([
        "running", "needs_login", "no_state", "stopped", "needs_machine_auth", "starting", "unrecognized_backend_state",
        "not_found_on_known_paths", "untrusted_binary", "missing_permission", "unable",
      ], ["tailscale.daemon"]),
      self_online: enumField(["true", "false", "unknown"], ["tailscale.daemon"]),
      exit_node_in_use: enumField(["true", "false", "unknown"], ["tailscale.daemon"]),
      health_issue_bucket: enumField(["0", "1", "2-4", "5+", "unknown"], ["tailscale.daemon"]),
      current_tailnet_hmac: hmacField(["tailscale.daemon"], [SENTINEL_UNKNOWN, "none"]),
    },
  }],
  ["net.config_fingerprint", {
    family: "network_context",
    fields: {
      ...commonFields(["net.route_table"]),
      fingerprint_hmac: hmacField(["net.route_table", "net.gateway_neighbor", "net.router_advertisement", "net.dhcp_lease", "net.resolver_config"]),
      components_ok: intField(0, 5, ["descartes.daemon"]),
      route_kind: enumField(["wifi", "ethernet", "cellular", "tunnel", "bridge", "loopback", "other", "none", "unknown"], ["net.route_table"]),
      route_state: enumField(COMPONENT_STATES, ["net.route_table"]),
      gateway_mac_hmac: hmacField(["net.gateway_neighbor"], [SENTINEL_UNKNOWN, "none"]),
      gateway_mac_state: enumField(COMPONENT_STATES, ["net.gateway_neighbor"]),
      ra_prefix_hmac: hmacField(["net.router_advertisement"], [SENTINEL_UNKNOWN, "none"]),
      ra_prefix_state: enumField(COMPONENT_STATES, ["net.router_advertisement"]),
      dhcp_domain_hmac: hmacField(["net.dhcp_lease"], [SENTINEL_UNKNOWN, "none"]),
      dhcp_domain_state: enumField(COMPONENT_STATES, ["net.dhcp_lease"]),
      resolvers_hmac: hmacField(["net.resolver_config"], [SENTINEL_UNKNOWN, "none"]),
      resolvers_state: enumField(COMPONENT_STATES, ["net.resolver_config"]),
    },
  }],
  // ---------------------------------------------------------------- session_context
  ["session.login_record", {
    family: "session_context",
    fields: {
      ...commonFields(["login.utmp"]),
      source: enumField(["who", "loginctl", "io_console", "unknown"], ["descartes.daemon"]),
      origin_class: enumField(["console", "local_tty", "local_display", "remote", "remote_mosh", "unknown"], ["login.utmp", "login.logind", "login.console"]),
      tty_class: enumField(["console", "tty", "pts", "ttys", "display", "none", "unknown"], ["login.utmp", "login.logind"]),
      service_class: enumField(["ssh", "local_login", "display_manager", "other", "none", "unknown"], ["login.logind"]),
      remote_host_hmac: hmacField(["login.utmp", "login.logind"], [SENTINEL_UNKNOWN, "none"]),
      user_hmac: hmacField(["login.utmp", "login.logind", "login.console"]),
      dedupe_state: enumField(["fresh", "reseeded", "unknown"], ["descartes.daemon"]),
    },
  }],
  ["session.login_history_row", {
    family: "session_context",
    fields: {
      ...commonFields(["login.utmp"]),
      origin_class: enumField(["console", "local_tty", "local_display", "remote", "remote_mosh", "unknown"], ["login.utmp"]),
      tty_class: enumField(["console", "tty", "pts", "ttys", "display", "none", "unknown"], ["login.utmp"]),
      remote_host_hmac: hmacField(["login.utmp"], [SENTINEL_UNKNOWN, "none"]),
      user_hmac: hmacField(["login.utmp"]),
      dedupe_state: enumField(["fresh", "reseeded", "unknown"], ["descartes.daemon"]),
    },
  }],
  ["session.login_census", {
    family: "session_context",
    fields: {
      ...commonFields(["login.utmp", "login.logind", "login.console"]),
      who_state: enumField(COMPONENT_STATES, ["login.utmp"]),
      last_state: enumField(COMPONENT_STATES, ["login.utmp"]),
      console_state: enumField(COMPONENT_STATES, ["login.console"]),
      loginctl_state: enumField(COMPONENT_STATES, ["login.logind"]),
      current_count: intField(0, 100000, ["login.utmp", "login.logind", "login.console"]),
      arrivals_emitted: intField(0, 1000, ["descartes.daemon"]),
      arrivals_overflow: intField(0, 100000, ["descartes.daemon"]),
      history_emitted: intField(0, 1000, ["descartes.daemon"]),
      history_overflow: intField(0, 100000, ["descartes.daemon"]),
      dedupe_state: enumField(["fresh", "reseeded", "unavailable", "unknown"], ["descartes.daemon"]),
    },
  }],
  ["user.presence", {
    family: "session_context",
    fields: {
      ...commonFields(["login.console"]),
      screen_locked: enumField(["true", "false", "unknown", "not_applicable"], ["login.console", "login.logind"]),
      idle_hint: enumField(["true", "false", "unknown", "not_applicable"], ["login.logind"]),
      source: enumField(["io_console", "loginctl", "none", "unknown"], ["descartes.daemon"]),
    },
  }],
];

function buildSchemas(entries) {
  const map = new Map();
  for (const [factName, schema] of entries) {
    if (map.has(factName)) throw new Error(`context-schemas: ${factName} declared twice`);
    for (const [field, spec] of Object.entries(schema.fields)) {
      if (!Array.isArray(spec.provenance) || spec.provenance.length === 0) throw new Error(`context-schemas: ${factName}.${field} has no provenance tag`);
      for (const tag of spec.provenance) if (!KNOWN_TAGS.has(tag)) throw new Error(`context-schemas: ${factName}.${field} has unknown provenance ${tag}`);
    }
    if (Object.prototype.hasOwnProperty.call(schema.fields, "rejected_field")) throw new Error(`context-schemas: ${factName} must not declare rejected_field`);
    const fieldNames = Object.keys(schema.fields);
    // rejected_field is added to every schema: its domain is the closed field list plus sentinels.
    const fields = {
      ...schema.fields,
      rejected_field: enumField(["none", "unknown_field", ...fieldNames], ["descartes.daemon"], { required: false }),
    };
    map.set(factName, Object.freeze({ family: schema.family, fields: Object.freeze(fields) }));
  }
  return map;
}

export const CONTEXT_FACT_SCHEMAS = buildSchemas(FACT_SCHEMA_ENTRIES);

export function contextSchemaFor(factName) {
  return CONTEXT_FACT_SCHEMAS.get(factName);
}

function valueOk(spec, value) {
  if (typeof value !== "string") return false;
  switch (spec.kind) {
    case "enum":
      return spec.values.has(value);
    case "hmac":
      return spec.sentinels.has(value) || HMAC_RE.test(value);
    case "int": {
      if (spec.sentinels.has(value)) return true;
      if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) return false;
      const n = Number(value);
      return Number.isSafeInteger(n) && n >= spec.min && n <= spec.max;
    }
    case "pattern":
      return spec.sentinels.has(value) || (value.length <= spec.maxLength && spec.pattern.test(value));
    default:
      return false;
  }
}

/**
 * Validates one fact point's attributes against its closed schema. Pure. Attributes are compared as
 * strings (the fact store stringifies every attribute value); a non-string is rejected, so a
 * translator must stringify deliberately. Returns { ok: true } or { ok: false, field } where `field`
 * is a schema field name or "unknown_field" (the raw offending key is never returned).
 */
export function validateContextFact(factName, attributes) {
  const schema = CONTEXT_FACT_SCHEMAS.get(factName);
  if (!schema) return { ok: false, field: "unknown_field", reason: "unknown_fact_name" };
  if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) return { ok: false, field: "unknown_field", reason: "not_an_object" };
  for (const key of Object.keys(attributes)) {
    if (!Object.prototype.hasOwnProperty.call(schema.fields, key)) return { ok: false, field: "unknown_field", reason: "unknown_field" };
  }
  for (const [field, spec] of Object.entries(schema.fields)) {
    const present = Object.prototype.hasOwnProperty.call(attributes, field) && attributes[field] !== undefined;
    if (!present) {
      if (spec.required) return { ok: false, field, reason: "missing" };
      continue;
    }
    if (!valueOk(spec, attributes[field])) return { ok: false, field, reason: "out_of_domain" };
  }
  return { ok: true };
}

function unableValueFor(spec) {
  if (spec.kind === "enum") {
    for (const candidate of ["unable", "unknown"]) if (spec.values.has(candidate)) return candidate;
    return undefined; // a closed single-value enum (e.g. uv_hrtime_clock_id) keeps its only value
  }
  return spec.sentinels.has(SENTINEL_UNKNOWN) ? SENTINEL_UNKNOWN : undefined;
}

/**
 * The schema's `unable` attribute shape: collector_state "unable", every other field at its
 * "unable"/"unknown" sentinel (single-value enums keep their only value; fields with no sentinel at
 * all are omitted only if optional), the observation interval kept when it is itself valid, and
 * rejected_field set. The result always validates (pinned by test).
 */
export function unableContextAttributes(factName, { rejectedField = "none", obsStartMs, obsEndMs } = {}) {
  const schema = CONTEXT_FACT_SCHEMAS.get(factName);
  if (!schema) throw new Error(`context-schemas: no schema for ${factName}`);
  const attributes = {};
  for (const [field, spec] of Object.entries(schema.fields)) {
    if (field === "rejected_field") continue;
    let value = unableValueFor(spec);
    if (value === undefined && spec.kind === "enum" && spec.values.size === 1) value = [...spec.values][0];
    if (value === undefined && spec.kind === "int" && spec.min === spec.max) value = String(spec.min);
    if (value !== undefined) attributes[field] = value;
  }
  attributes.collector_state = "unable";
  for (const [field, raw] of [["obs_start_ms", obsStartMs], ["obs_end_ms", obsEndMs]]) {
    const candidate = Number.isSafeInteger(raw) ? String(raw) : "unknown";
    attributes[field] = valueOk(schema.fields[field], candidate) ? candidate : "unknown";
  }
  const rejected = schema.fields.rejected_field.values.has(rejectedField) ? rejectedField : "unknown_field";
  attributes.rejected_field = rejected;
  return attributes;
}

/**
 * Translator helper: returns `point` when its attributes validate, else the same point with the
 * schema's `unable` attributes (and confidence 0). Never returns a point that fails validation.
 */
export function enforceContextSchema(point) {
  const verdict = validateContextFact(point.fact_name, point.attributes);
  if (verdict.ok) return point;
  const obsStartMs = Number(point.attributes?.obs_start_ms);
  const obsEndMs = Number(point.attributes?.obs_end_ms);
  return {
    ...point,
    attributes: unableContextAttributes(point.fact_name, {
      rejectedField: verdict.field,
      obsStartMs: Number.isSafeInteger(obsStartMs) ? obsStartMs : undefined,
      obsEndMs: Number.isSafeInteger(obsEndMs) ? obsEndMs : undefined,
    }),
    confidence: 0,
  };
}
