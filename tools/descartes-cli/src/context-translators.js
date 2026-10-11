// Context fact translators (docs/plans/2026-10-06-context-aware-learned-baselines.md §3 C0, §4 L1).
//
// Pure functions from context collector results to fact-store points for the three context families
// (host_lifecycle, network_context, session_context). Hard rules, shared with fact-translators.js:
//   - DATA ONLY. Nothing here builds an alert candidate, and nothing is wired into extraCandidates.
//     There is no behaviour rule in this file: no "after boot", no "expected", no threshold.
//   - Degrade, never fabricate: an unavailable value is "unknown" / "unable" / "not_applicable",
//     never a guessed value, and never a complete zero from a missing source.
//   - Hash at source: identifying values are HMAC'd with the per-install key (context-key.js) here;
//     the raw values never reach a fact point.
//   - Every point passes its closed schema (context-schemas.js) on the way out. A rejected field
//     yields the schema's unable shape, never the value (C0.6).

import { contextHmac, contextKeyId } from "./context-key.js";
import { BINARY_TRUST_REASONS, COLLECTOR_BINARY_NAMES, enforceContextSchema } from "./context-schemas.js";
import { strictRfc3339EpochMilliseconds } from "./tools/census-validate.js";

// Fixed entity keys for the per-tick context facts. Literal constants (not computed) so the T12
// source scan in fact-families.test.js resolves every emitted fact_name.
export const HOST_BOOT_FACT_NAME = "host.boot";
export const HOST_BOOT_BOUNDARY_FACT_NAME = "host.boot_boundary";
export const HOST_CLOCK_READING_FACT_NAME = "host.clock_reading";
export const HOST_SUSPEND_FACT_NAME = "host.suspend";
export const HOST_BOUNDARY_CENSUS_FACT_NAME = "host.boundary_census";
export const NET_TAILNET_STATE_FACT_NAME = "net.tailnet_state";
export const NET_CONFIG_FINGERPRINT_FACT_NAME = "net.config_fingerprint";
export const SESSION_LOGIN_RECORD_FACT_NAME = "session.login_record";
export const SESSION_LOGIN_HISTORY_ROW_FACT_NAME = "session.login_history_row";
export const SESSION_LOGIN_CENSUS_FACT_NAME = "session.login_census";
export const USER_PRESENCE_FACT_NAME = "user.presence";
export const COLLECTOR_BINARY_STATE_FACT_NAME = "collector.binary_state";
export const HOST_LIFECYCLE_RECORD_FACT_NAME = "host.lifecycle_record";
export const MAX_LIFECYCLE_RECORDS_PER_TICK = 4;
export const NET_VPN_SERVICE_CENSUS_FACT_NAME = "net.vpn_service_census";
export const NET_VPN_SERVICE_STATE_FACT_NAME = "net.vpn_service_state";
export const MAX_VPN_SERVICE_STATES_PER_TICK = 8;

// The envelope ids and tool names the context collectors stamp (bounded, closed).
export const CONTEXT_ENVELOPE_SOURCES = Object.freeze({
  host_lifecycle: Object.freeze({ id: "host-lifecycle", tool: "collect_host_lifecycle" }),
  tailscale: Object.freeze({ id: "tailscale-status", tool: "collect_tailscale_status" }),
  net_config: Object.freeze({ id: "net-config", tool: "collect_net_config" }),
  login_sessions: Object.freeze({ id: "login-sessions", tool: "collect_login_sessions" }),
  // C2: facts DERIVED by the daemon from the structural evidence it already holds (no new read).
  derived: Object.freeze({ id: "derived", tool: "derive_context" }),
});

// Per-tick emission caps for the session_context family (its T8 budget is sized on them).
export const MAX_LOGIN_ARRIVALS_PER_TICK = 8;
export const MAX_LOGIN_HISTORY_ROWS_PER_TICK = 8;

/** The one point builder every context translator uses: it always applies the closed schema. */
export function contextFactPoint({ ts, factName, entityKey, attributes, source, hmacKey }) {
  return enforceContextSchema({
    ts,
    fact_name: factName,
    entity_key: entityKey ?? factName,
    // C0 review M7: every point names the key its HMACs were made with.
    attributes: { ...attributes, hmac_key_id: contextKeyId(hmacKey) },
    source_envelope_id: source?.id,
    source_tool: source?.tool,
    sensitivity: "operational",
  });
}

export function msString(value) {
  return Number.isSafeInteger(value) && value >= 0 ? String(value) : "unknown";
}

/**
 * The observation interval of one collector run, in epoch ms (§4.4: per-collector obs_start/obs_end,
 * distinct from the tick ts). Prefers the daemon's own stamp (envelope.observation, set by the
 * per-collector sub-deadline runner), else the envelope trace (trace.ts is stamped when the envelope
 * is built, latency_ms when the run finishes). Unknown when neither is valid.
 */
export function observationInterval(envelope) {
  const stamped = envelope?.observation;
  if (Number.isSafeInteger(stamped?.start_ms) && Number.isSafeInteger(stamped?.end_ms) && stamped.start_ms <= stamped.end_ms) {
    return { obsStartMs: stamped.start_ms, obsEndMs: stamped.end_ms };
  }
  if (stamped !== undefined && stamped !== null) return { obsStartMs: undefined, obsEndMs: undefined };
  const endMs = strictRfc3339EpochMilliseconds(envelope?.trace?.ts);
  const latency = envelope?.trace?.latency_ms;
  if (Number.isFinite(endMs) && typeof latency === "number" && Number.isFinite(latency) && latency >= 0) {
    return { obsStartMs: Math.max(0, Math.round(endMs - latency)), obsEndMs: Math.round(endMs) };
  }
  return { obsStartMs: undefined, obsEndMs: undefined };
}

// ------------------------------------------------------------------------------------------------
// C0.3: net.tailnet_state, for EVERY tailscale probe outcome.
// ------------------------------------------------------------------------------------------------

const TAILNET_BACKEND_STATE_VALUES = Object.freeze({
  Running: "running",
  NeedsLogin: "needs_login",
  NoState: "no_state",
  Stopped: "stopped",
  NeedsMachineAuth: "needs_machine_auth",
  Starting: "starting",
});

const TRANSLATOR_COLLECTOR_STATES = new Set(["ok", "partial", "unable", "not_applicable", "not_found_on_known_paths", "untrusted_binary", "missing_permission"]);
const COLLECTOR_STATE_SET = TRANSLATOR_COLLECTOR_STATES;

function collectorStateFromEnvelope(envelope, result) {
  if (envelope?.status === "unable") return "unable";
  if (TRANSLATOR_COLLECTOR_STATES.has(result?.status)) {
    if (envelope?.status === "warning" && result.status === "ok") return "partial";
    return result.status;
  }
  return envelope?.status === "warning" ? "partial" : envelope?.status === "ok" ? "ok" : "unable";
}

function boolString(value) {
  return value === true ? "true" : value === false ? "false" : "unknown";
}

function healthBucket(count) {
  if (!Number.isSafeInteger(count) || count < 0) return "unknown";
  if (count === 0) return "0";
  if (count === 1) return "1";
  if (count <= 4) return "2-4";
  return "5+";
}

/**
 * evidence[] -> one net.tailnet_state point whenever the tailscale collector produced an envelope,
 * whatever its status: a missing binary, an untrusted binary, a permission denial, an exec or parse
 * failure and every backend state are each a VALUE of the fact (C0.3), never a dropped tick. `Online`
 * means connected to the control plane; it does not prove peer reachability (Astra 11).
 */
export function factPointsFromTailnetStateEvidence(evidence, { ts, hmacKey } = {}) {
  const envelope = (evidence ?? []).find((e) => e?.id === "tailscale-status");
  if (!envelope) return [];
  const result = envelope.result ?? {};
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  const tailnet = result.tailnet && typeof result.tailnet === "object" ? result.tailnet : undefined;
  const collectorState = collectorStateFromEnvelope(envelope, result);
  let state;
  if (collectorState === "ok" && tailnet && typeof tailnet.backend_state === "string") {
    // The JSON was parsed: the backend state was observed, whatever the peer census made of it.
    state = Object.prototype.hasOwnProperty.call(TAILNET_BACKEND_STATE_VALUES, tailnet.backend_state)
      ? TAILNET_BACKEND_STATE_VALUES[tailnet.backend_state]
      : "unrecognized_backend_state";
  } else {
    state = collectorState === "ok" && !tailnet ? "unable" : collectorState;
  }
  const observed = collectorState === "ok" && tailnet !== undefined && typeof tailnet.backend_state === "string";
  const attributes = {
    collector_state: collectorState,
    obs_start_ms: msString(obsStartMs),
    obs_end_ms: msString(obsEndMs),
    state,
    self_online: observed ? boolString(tailnet.self_online) : "unknown",
    exit_node_in_use: observed ? boolString(tailnet.exit_node_in_use) : "unknown",
    health_issue_bucket: observed ? healthBucket(tailnet.health_issue_count) : "unknown",
    // An absent CurrentTailnet is unknown (an older daemon may not report it), never "none".
    current_tailnet_hmac: observed && typeof tailnet.current_tailnet_name === "string"
      ? contextHmac(hmacKey, "tailnet_name", tailnet.current_tailnet_name)
      : "unknown",
    rejected_field: "none",
  };
  return [contextFactPoint({ hmacKey, ts, factName: NET_TAILNET_STATE_FACT_NAME, attributes, source: CONTEXT_ENVELOPE_SOURCES.tailscale })];
}

// ------------------------------------------------------------------------------------------------
// C0.8 / C0.9 / C0.12: host_lifecycle facts.
// ------------------------------------------------------------------------------------------------

const BOOT_ID_SOURCES = new Set(["kern.bootsessionuuid", "proc_boot_id"]);

function intString(value) {
  return Number.isSafeInteger(value) && value >= 0 ? String(value) : "unknown";
}

function tokenString(value) {
  return typeof value === "string" && value.length > 0 ? value : "unknown";
}

function platformValue(platform, wanted, value, format) {
  if (platform !== wanted) return "not_applicable";
  return value === undefined || value === null ? "unknown" : format(value);
}

function rawString(value) {
  return typeof value === "string" && value.length > 0 ? value : "unknown";
}

export function hostBootIdHmac(hmacKey, rawBootId) {
  return contextHmac(hmacKey, "boot_id", rawBootId);
}

/**
 * evidence[] + the daemon's ledger-derived context -> host_lifecycle points. Emits host.boot,
 * host.clock_reading and host.suspend whenever the host-lifecycle collector produced an envelope
 * (whatever its status), plus host.boot_boundary when a boundary verdict is supplied and
 * host.boundary_census when a boundary census record is supplied. The verdict, the census gaps and
 * the suspend exposure are computed by boot-ledger.js (pure) from the ledger; this function only
 * shapes and validates them.
 */
export function factPointsFromHostLifecycleEvidence(evidence, { ts, hmacKey, bracket, boundary, boundaryCensus, suspend } = {}) {
  const envelope = (evidence ?? []).find((e) => e?.id === "host-lifecycle");
  if (!envelope) return [];
  const result = envelope.result ?? {};
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  const collectorState = collectorStateFromEnvelope(envelope, result);
  const boot = result.boot ?? {};
  const clocks = result.clocks ?? {};
  const platform = result.platform;
  const bootIdHmac = typeof boot.boot_id === "string" ? hostBootIdHmac(hmacKey, boot.boot_id) : "unknown";
  const common = { collector_state: collectorState, obs_start_ms: msString(obsStartMs), obs_end_ms: msString(obsEndMs), rejected_field: "none" };
  const source = CONTEXT_ENVELOPE_SOURCES.host_lifecycle;
  const points = [];

  points.push(contextFactPoint({
    hmacKey,
    ts,
    factName: HOST_BOOT_FACT_NAME,
    source,
    attributes: {
      ...common,
      boot_id_hmac: bootIdHmac,
      boot_id_source: BOOT_ID_SOURCES.has(boot.boot_id_source) && typeof boot.boot_id === "string" ? boot.boot_id_source : "unknown",
      boot_time_s: intString(boot.boot_time_s),
      os_build: tokenString(boot.os_build),
      os_release: tokenString(boot.os_release),
      bracket: ["stable", "unstable"].includes(bracket) ? bracket : "unknown",
    },
  }));

  points.push(contextFactPoint({
    hmacKey,
    ts,
    factName: HOST_CLOCK_READING_FACT_NAME,
    source,
    attributes: {
      ...common,
      boot_id_hmac: bootIdHmac,
      wall_ms: intString(clocks.wall_ms),
      uv_hrtime_ns: typeof clocks.uv_hrtime_ns === "string" && /^[0-9]{1,24}$/.test(clocks.uv_hrtime_ns) ? clocks.uv_hrtime_ns : "unknown",
      uv_version: tokenString(clocks.uv_version),
      uv_hrtime_clock_id: "unverified",
      named_clocks: "unavailable_without_native",
      os_uptime_ms: intString(clocks.os_uptime_ms),
      kern_monotonicclock_usecs: platformValue(platform, "darwin", clocks.kern_monotonicclock_usecs, rawString),
      kern_sleeptime_s: platformValue(platform, "darwin", clocks.kern_sleeptime_s, intString),
      kern_waketime_s: platformValue(platform, "darwin", clocks.kern_waketime_s, intString),
      kern_sleep_abs_time: platformValue(platform, "darwin", clocks.kern_sleep_abs_time, rawString),
      kern_wake_abs_time: platformValue(platform, "darwin", clocks.kern_wake_abs_time, rawString),
      machdep_wake_abstime: platformValue(platform, "darwin", clocks.machdep_wake_abstime, rawString),
      machdep_wake_conttime: platformValue(platform, "darwin", clocks.machdep_wake_conttime, rawString),
      proc_uptime_s: platformValue(platform, "linux", clocks.proc_uptime_s, rawString),
      suspend_stats_success: platformValue(platform, "linux", clocks.suspend_stats_success, intString),
    },
  }));

  points.push(contextFactPoint({
    hmacKey,
    ts,
    factName: HOST_SUSPEND_FACT_NAME,
    source,
    attributes: {
      ...common,
      state: "unknown",
      reason: "f3_inactive_c09_pending",
      exposure_lower_s: "0",
      exposure_upper_s: intString(suspend?.exposure_upper_s),
      interval_basis: ["same_boot_uptime_delta", "cross_boot", "no_previous_reading", "uptime_regressed"].includes(suspend?.interval_basis) ? suspend.interval_basis : "unknown",
    },
  }));

  if (boundary) {
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: HOST_BOOT_BOUNDARY_FACT_NAME,
      source,
      attributes: {
        ...common,
        verdict: boundary.verdict,
        failing_conjunct: boundary.failing_conjunct,
        tripwire: boundary.tripwire,
        c_never_seen: boundary.c_never_seen,
        c_daemon_restart: boundary.c_daemon_restart,
        c_boot_time_in_gap: boundary.c_boot_time_in_gap,
        c_uptime_consistent: boundary.c_uptime_consistent,
        c_no_preboot_instance: boundary.c_no_preboot_instance,
        boot_id_hmac: typeof boundary.boot_id_hmac === "string" ? boundary.boot_id_hmac : bootIdHmac,
        prev_boot_id_hmac: typeof boundary.prev_boot_id_hmac === "string" ? boundary.prev_boot_id_hmac : "unknown",
        os_build_changed: boundary.os_build_changed,
        gap_s: intString(boundary.gap_s),
        superseded_count: intString(boundary.superseded_count),
        resolution_s: intString(boundary.resolution_s),
      },
    }));
  }

  if (boundaryCensus) {
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: HOST_BOUNDARY_CENSUS_FACT_NAME,
      source,
      attributes: {
        ...common,
        trigger: boundaryCensus.trigger,
        status: boundaryCensus.status,
        boot_id_hmac: typeof boundaryCensus.boot_id_hmac === "string" ? boundaryCensus.boot_id_hmac : bootIdHmac,
        pre_gap_s: intString(boundaryCensus.pre_gap_s),
        post_gap_s: intString(boundaryCensus.post_gap_s),
        superseded_count: intString(boundaryCensus.superseded_count),
      },
    }));
  }
  return points;
}

// ------------------------------------------------------------------------------------------------
// C0.4: session_context facts (login origin, first-observed tick, row-digest dedupe).
// ------------------------------------------------------------------------------------------------

const ORIGIN_CLASSES = new Set(["console", "local_tty", "local_display", "remote", "remote_mosh", "unknown"]);
const TTY_CLASSES = new Set(["console", "tty", "pts", "ttys", "display", "none", "unknown"]);
const SERVICE_CLASSES = new Set(["ssh", "local_login", "display_manager", "other", "none", "unknown"]);
const COMPONENT_STATE_VALUES = new Set(["ok", "partial", "unable", "not_applicable", "not_found_on_known_paths", "untrusted_binary", "missing_permission", "absent"]);

function remoteHostHmac(hmacKey, row) {
  if (row.origin_class === "remote") return typeof row.remote_host === "string" && row.remote_host ? contextHmac(hmacKey, "login_remote_host", row.remote_host) : "unknown";
  if (row.origin_class === "unknown") return "unknown";
  return "none"; // console / local / remote_mosh: the row carries no remote host
}

function loginRowAttributes(row, hmacKey, dedupeState) {
  return {
    origin_class: ORIGIN_CLASSES.has(row.origin_class) ? row.origin_class : "unknown",
    tty_class: TTY_CLASSES.has(row.tty_class) ? row.tty_class : "unknown",
    remote_host_hmac: remoteHostHmac(hmacKey, row),
    user_hmac: typeof row.user === "string" && row.user ? contextHmac(hmacKey, "login_user", row.user) : "unknown",
    dedupe_state: dedupeState,
  };
}

function loginEntityKey(factName, hmacKey, digest) {
  const keyed = contextHmac(hmacKey, "login_row_entity", digest);
  return `${factName}.${keyed}`;
}

/**
 * evidence[] + the daemon's dedupe selection -> session_context points: one session.login_record
 * per login observed for the first time (at most MAX_LOGIN_ARRIVALS_PER_TICK, the rest counted as
 * overflow), one session.login_history_row per new `last` row (at most
 * MAX_LOGIN_HISTORY_ROWS_PER_TICK), one session.login_census marker with every source's state and
 * the counts, and one user.presence. Without a dedupe selection (no seen-state could be used), no
 * record or history row is emitted and the census says so (`dedupe_state: unavailable`).
 */
export function factPointsFromLoginSessionsEvidence(evidence, { ts, hmacKey, dedupe } = {}) {
  const envelope = (evidence ?? []).find((e) => e?.id === "login-sessions");
  if (!envelope) return [];
  const result = envelope.result ?? {};
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  const collectorState = collectorStateFromEnvelope(envelope, result);
  const common = { collector_state: collectorState, obs_start_ms: msString(obsStartMs), obs_end_ms: msString(obsEndMs), rejected_field: "none" };
  const source = CONTEXT_ENVELOPE_SOURCES.login_sessions;
  const points = [];
  const dedupeState = dedupe ? dedupe.dedupeState : "unavailable";
  const newRecords = dedupe?.newRecords ?? [];
  const newHistory = dedupe?.newHistory ?? [];
  const emittedRecords = newRecords.slice(0, MAX_LOGIN_ARRIVALS_PER_TICK);
  const emittedHistory = newHistory.slice(0, MAX_LOGIN_HISTORY_ROWS_PER_TICK);
  for (const row of emittedRecords) {
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: SESSION_LOGIN_RECORD_FACT_NAME,
      entityKey: loginEntityKey(SESSION_LOGIN_RECORD_FACT_NAME, hmacKey, row.digest),
      source,
      attributes: {
        ...common,
        source: ["who", "loginctl", "io_console"].includes(row.source) ? row.source : "unknown",
        service_class: SERVICE_CLASSES.has(row.service_class) ? row.service_class : "unknown",
        ...loginRowAttributes(row, hmacKey, dedupeState),
      },
    }));
  }
  for (const row of emittedHistory) {
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: SESSION_LOGIN_HISTORY_ROW_FACT_NAME,
      entityKey: loginEntityKey(SESSION_LOGIN_HISTORY_ROW_FACT_NAME, hmacKey, row.digest),
      source,
      attributes: { ...common, ...loginRowAttributes(row, hmacKey, dedupeState) },
    }));
  }
  const sources = result.sources ?? {};
  const sourceState = (name) => (COMPONENT_STATE_VALUES.has(sources[name]) ? sources[name] : "unable");
  const recordSourceUsable = ["who", "loginctl"].some((name) => ["ok", "absent"].includes(sources[name]));
  const census = {
    ...common,
    who_state: sourceState("who"),
    last_state: sourceState("last"),
    console_state: sourceState("console"),
    loginctl_state: sourceState("loginctl"),
    current_count: recordSourceUsable && Array.isArray(result.records) ? String(result.records.length) : "unknown",
    arrivals_emitted: String(emittedRecords.length),
    arrivals_overflow: String(newRecords.length - emittedRecords.length),
    history_emitted: String(emittedHistory.length),
    history_overflow: String(newHistory.length - emittedHistory.length),
    dedupe_state: dedupeState,
  };
  points.push(contextFactPoint({ hmacKey, ts, factName: SESSION_LOGIN_CENSUS_FACT_NAME, source, attributes: census }));
  const presence = result.presence ?? {};
  const flag = (value) => (["true", "false", "unknown", "not_applicable"].includes(value) ? value : "unknown");
  points.push(contextFactPoint({
    hmacKey,
    ts,
    factName: USER_PRESENCE_FACT_NAME,
    source,
    attributes: {
      ...common,
      screen_locked: flag(presence.screen_locked),
      idle_hint: flag(presence.idle_hint),
      source: ["io_console", "loginctl", "none"].includes(presence.source) ? presence.source : "unknown",
    },
  }));
  return points;
}

// ------------------------------------------------------------------------------------------------
// C0.5: net.config_fingerprint (per-component availability, HMAC'd with the per-install key).
// ------------------------------------------------------------------------------------------------

const NET_COMPONENTS = ["gateway_mac", "ra_prefix", "dhcp_domain", "configured_search_domain", "resolvers"];
const NET_COMPONENT_PROVENANCE = {
  gateway_mac: "net.gateway_neighbor",
  ra_prefix: "net.router_advertisement",
  dhcp_domain: "net.dhcp_lease",
  configured_search_domain: "net.configured_search_domain",
  resolvers: "net.resolver_config",
};
const ROUTE_KINDS = new Set(["wifi", "ethernet", "cellular", "tunnel", "bridge", "loopback", "other", "none", "unknown"]);
// States a configuration identity may fold. `not_found_on_known_paths` is OUTSIDE the universe (I49:
// a source whose binary is not installed, e.g. nmcli or resolvectl), so the rest still fingerprints;
// the state itself is folded, so installing the binary is a regime change. `untrusted_binary`,
// `unable`, `partial` and `missing_permission` are always incomplete (C0 review M6(c)).
const BENIGN_COMPONENT_STATES = new Set(["ok", "absent", "not_applicable", "not_found_on_known_paths"]);
// Route kinds whose physical network is not observed (C0 review M6(b,d)): behind a tunnel-only default
// route the physical components are not_applicable, and an unknown kind is an unread /sys or ifconfig.
// Folding either would give every such network one shared, fabricated identity.
const UNOBSERVED_ROUTE_KINDS = new Set(["tunnel", "unknown"]);

function componentState(component, requireValue = false) {
  if (!COMPONENT_STATE_VALUES.has(component?.state)) return "unable";
  if (requireValue && component.state === "ok" && (typeof component.value !== "string" || component.value.length === 0)) return "unable";
  return component.state;
}

function componentHmac(hmacKey, name, component) {
  const state = componentState(component, true);
  if (state === "ok") return typeof component.value === "string" && component.value ? contextHmac(hmacKey, `net_${name}`, component.value) : "unknown";
  if (state === "absent" || state === "not_applicable") return "none";
  return "unknown";
}

/**
 * Returns the exact values and physical objects fed to the aggregate network fingerprint. Keep
 * this as the single input description used by both hashing and provenance regression tests.
 */
export function netConfigAggregateInputs(result = {}) {
  const components = result.components ?? {};
  const inputs = [
    { field: "route_kind", provenance: "net.route_table", value: result.route?.kind },
    { field: "route_state", provenance: "net.route_table", value: componentState(result.route) },
  ];
  for (const name of NET_COMPONENTS) {
    const component = Object.prototype.hasOwnProperty.call(components, name)
      ? components[name]
      : name === "configured_search_domain" ? { state: "not_applicable" } : undefined;
    const state = componentState(component, true);
    inputs.push({ field: `${name}_state`, provenance: NET_COMPONENT_PROVENANCE[name], value: state });
    inputs.push({ field: `${name}_value`, provenance: NET_COMPONENT_PROVENANCE[name], value: state === "ok" ? component.value : "" });
  }
  return inputs;
}

/**
 * evidence[] -> one net.config_fingerprint point whenever the net-config collector produced an
 * envelope. Each component carries its own state and HMAC. The aggregate fingerprint is an HMAC of
 * the route kind and every component's (state, value); it is "unknown" when the route or any
 * component FAILED this tick (a failure is never folded into a configuration identity), when the
 * physical network is unobserved (tunnel-only default route, unknown interface kind), or when no
 * key is usable.
 */
export function factPointsFromNetConfigEvidence(evidence, { ts, hmacKey } = {}) {
  const envelope = (evidence ?? []).find((e) => e?.id === "net-config");
  if (!envelope) return [];
  const result = envelope.result ?? {};
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  const collectorState = collectorStateFromEnvelope(envelope, result);
  const routeState = componentState(result.route);
  const components = result.components ?? {};
  const attributes = {
    collector_state: collectorState,
    obs_start_ms: msString(obsStartMs),
    obs_end_ms: msString(obsEndMs),
    rejected_field: "none",
    route_kind: ROUTE_KINDS.has(result.route?.kind) ? result.route.kind : "unknown",
    route_state: routeState,
  };
  let componentsOk = 0;
  for (const name of NET_COMPONENTS) {
    // The configured-search-domain field was added after the original C0.5 result shape. Treat
    // its absence in an old in-memory fixture as not_applicable, while a collector result always
    // carries the field explicitly.
    const component = Object.prototype.hasOwnProperty.call(components, name)
      ? components[name]
      : name === "configured_search_domain" ? { state: "not_applicable" } : undefined;
    const state = componentState(component, true);
    attributes[`${name}_state`] = state;
    attributes[`${name}_hmac`] = componentHmac(hmacKey, name, component);
    if (state === "ok") componentsOk += 1;
  }
  if (routeState === "ok") componentsOk += 1;
  attributes.components_ok = String(componentsOk);
  const allObserved = BENIGN_COMPONENT_STATES.has(routeState)
    && !UNOBSERVED_ROUTE_KINDS.has(attributes.route_kind)
    && NET_COMPONENTS.every((name) => BENIGN_COMPONENT_STATES.has(attributes[`${name}_state`]));
  attributes.fingerprint_hmac = allObserved
    ? contextHmac(hmacKey, "net_config_fingerprint", JSON.stringify(netConfigAggregateInputs(result).map((input) => input.value)))
    : "unknown";
  return [contextFactPoint({ hmacKey, ts, factName: NET_CONFIG_FINGERPRINT_FACT_NAME, source: CONTEXT_ENVELOPE_SOURCES.net_config, attributes })];
}

// ------------------------------------------------------------------------------------------------
// C2 (§3 C0.1, §4.2): collector.binary_state, from the binary provenance the structural collectors
// already report. No new read: every verdict below is one the binary resolver produced this tick.
// ------------------------------------------------------------------------------------------------

const BINARY_NAME_SET = new Set(COLLECTOR_BINARY_NAMES);
const TRUST_REASON_SET = new Set(BINARY_TRUST_REASONS);
// Bounds on the evidence walk (envelope results are bounded already; this keeps the walk itself
// bounded whatever shape a result takes).
const BINARY_WALK_MAX_DEPTH = 4;
const BINARY_WALK_MAX_ARRAY = 64;
const BINARY_WALK_MAX_OBSERVATIONS = 256;
// The envelopes that report binary provenance today. Bounding the walk to them bounds the per-tick
// record count (collector_state's T8 shape): sessions (tmux, screen), vpn-peer-status (who, last, wg,
// scutil, lsof/ss), tailscale-status (tailscale), host-lifecycle (sysctl).
const BINARY_PROVENANCE_ENVELOPE_IDS = new Set(["sessions", "vpn-peer-status", "tailscale-status", "host-lifecycle"]);
export const MAX_BINARY_STATES_PER_TICK = 12;

function binaryStateOf(provenance) {
  switch (provenance?.trust_verdict) {
    case "trusted": return "resolved";
    case "operator_trusted": return "operator_trusted";
    case "not_found_on_known_paths": return "not_found_on_known_paths";
    case "untrusted_binary": return "untrusted_binary";
    default: return "unable";
  }
}

function collectBinaryProvenance(value, depth, out) {
  if (out.length >= BINARY_WALK_MAX_OBSERVATIONS || depth > BINARY_WALK_MAX_DEPTH || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, BINARY_WALK_MAX_ARRAY)) collectBinaryProvenance(item, depth + 1, out);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (key === "binary_provenance") {
      if (child && typeof child === "object" && !Array.isArray(child) && typeof child.requested_binary === "string") out.push(child);
      continue;
    }
    collectBinaryProvenance(child, depth + 1, out);
  }
}

/**
 * evidence[] -> one collector.binary_state point per closed-list binary whose resolver verdict appears
 * in this tick's structural evidence (sessions' multiplexers, the VPN/peer sources, tailscale, the
 * host-lifecycle sysctl). A binary no collector reported this tick is absent (not observed), never
 * "not installed". Two disagreeing verdicts in one tick are "inconsistent", never one of them. Paths
 * and content hashes are HMAC'd; the offending component is never written.
 */
export function factPointsFromBinaryStateEvidence(evidence, { ts, hmacKey } = {}) {
  const byBinary = new Map();
  for (const envelope of evidence ?? []) {
    if (!envelope || typeof envelope !== "object" || envelope.source === "daemon") continue;
    if (!BINARY_PROVENANCE_ENVELOPE_IDS.has(envelope.id)) continue;
    const found = [];
    collectBinaryProvenance(envelope.result, 0, found);
    if (found.length === 0) continue;
    const { obsStartMs, obsEndMs } = observationInterval(envelope);
    for (const provenance of found) {
      if (!BINARY_NAME_SET.has(provenance.requested_binary)) continue;
      if (!byBinary.has(provenance.requested_binary)) byBinary.set(provenance.requested_binary, { observations: [], starts: [], ends: [] });
      const entry = byBinary.get(provenance.requested_binary);
      entry.observations.push(provenance);
      entry.starts.push(obsStartMs);
      entry.ends.push(obsEndMs);
    }
  }
  const points = [];
  for (const binary of COLLECTOR_BINARY_NAMES) {
    const entry = byBinary.get(binary);
    if (!entry || points.length >= MAX_BINARY_STATES_PER_TICK) continue;
    const states = new Set(entry.observations.map(binaryStateOf));
    const paths = new Set(entry.observations.map((p) => (typeof p.resolved_path === "string" ? p.resolved_path : "")));
    const hashes = new Set(entry.observations.map((p) => (typeof p.content_hash === "string" ? p.content_hash : "")));
    const reasons = new Set(entry.observations.map((p) => (typeof p.trust_reason === "string" ? p.trust_reason : "")));
    const consistent = states.size === 1 && paths.size === 1 && hashes.size === 1 && reasons.size === 1;
    const first = entry.observations[0];
    const state = consistent ? binaryStateOf(first) : "inconsistent";
    const resolved = state === "resolved" || state === "operator_trusted";
    const reason = !consistent ? "other"
      : typeof first.trust_reason !== "string" ? "none"
        : TRUST_REASON_SET.has(first.trust_reason) ? first.trust_reason : "other";
    const writable = Array.isArray(first.same_uid_writable_components) ? first.same_uid_writable_components.length > 0 : undefined;
    const allKnown = (values) => values.every((value) => Number.isSafeInteger(value));
    const attributes = {
      collector_state: consistent ? "ok" : "partial",
      obs_start_ms: allKnown(entry.starts) ? msString(Math.min(...entry.starts)) : "unknown",
      obs_end_ms: allKnown(entry.ends) ? msString(Math.max(...entry.ends)) : "unknown",
      binary,
      state,
      trust_reason: reason,
      path_hmac: !consistent ? "unknown"
        : typeof first.resolved_path === "string" && first.resolved_path ? contextHmac(hmacKey, "collector_binary_path", first.resolved_path)
          : state === "not_found_on_known_paths" ? "none" : "unknown",
      content_hmac: !consistent || !resolved ? (state === "not_found_on_known_paths" ? "none" : "unknown")
        : typeof first.content_hash === "string" && first.content_hash ? contextHmac(hmacKey, "collector_binary_content", first.content_hash) : "unknown",
      same_uid_writable: consistent && resolved && writable !== undefined ? String(writable) : "unknown",
      observations: String(Math.min(entry.observations.length, 64)),
      rejected_field: "none",
    };
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: COLLECTOR_BINARY_STATE_FACT_NAME,
      entityKey: `${COLLECTOR_BINARY_STATE_FACT_NAME}.${binary}`,
      attributes,
      source: CONTEXT_ENVELOPE_SOURCES.derived,
    }));
  }
  return points;
}

// ------------------------------------------------------------------------------------------------
// C2 (§4.2): net.vpn_service_state, from the vpn-peer-status census the daemon already holds. The
// incumbent census lists each non-Tailscale OS VPN service as a `vpn_service` peer (connected ->
// observed_active); this reads that list, never re-runs scutil, and changes nothing in it.
// ------------------------------------------------------------------------------------------------

/**
 * evidence[] -> one net.vpn_service_census marker plus at most MAX_VPN_SERVICE_STATES_PER_TICK
 * net.vpn_service_state points (service uuid HMAC'd), whenever the vpn-peer-status envelope exists.
 * A source that did not run cleanly, or a census truncated by the shared peer cap, gives unknown
 * totals and no per-service point: a missing service is never read as "disconnected".
 */
export function factPointsFromVpnServiceEvidence(evidence, { ts, hmacKey } = {}) {
  const envelope = (evidence ?? []).find((e) => e?.id === "vpn-peer-status");
  if (!envelope || typeof envelope.result !== "object" || envelope.result === null) return [];
  const result = envelope.result;
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  const daemonSynthesized = envelope.source === "daemon";
  const rawSourceState = result.sources?.vpn_services?.status;
  const sourceState = daemonSynthesized ? "unable" : COMPONENT_STATE_VALUES.has(rawSourceState) ? rawSourceState : "unable";
  const peers = Array.isArray(result.peers) ? result.peers : [];
  const services = peers.filter((peer) => peer?.source_type === "vpn_service");
  const counted = sourceState === "ok" && result.truncated !== true;
  const wellFormed = services.every((service) => typeof service.service_uuid === "string" && service.service_uuid.length > 0
    && ["observed_active", "observed_historical"].includes(service.presence_state));
  const usable = counted && wellFormed;
  const states = usable
    ? services.map((service) => ({
      hmac: contextHmac(hmacKey, "vpn_service_uuid", service.service_uuid),
      state: service.presence_state === "observed_active" ? "connected" : "not_connected",
    })).sort((a, b) => (a.hmac < b.hmac ? -1 : a.hmac > b.hmac ? 1 : 0))
    : [];
  const keyed = states.every((entry) => entry.hmac !== "unknown");
  const emitted = keyed ? states.slice(0, MAX_VPN_SERVICE_STATES_PER_TICK) : [];
  const collectorState = !usable ? (sourceState === "ok" ? "partial" : sourceState === "absent" ? "partial" : sourceState) : "ok";
  const common = { collector_state: COLLECTOR_STATE_SET.has(collectorState) ? collectorState : "unable", obs_start_ms: msString(obsStartMs), obs_end_ms: msString(obsEndMs), rejected_field: "none" };
  const source = CONTEXT_ENVELOPE_SOURCES.derived;
  const points = [contextFactPoint({
    hmacKey,
    ts,
    factName: NET_VPN_SERVICE_CENSUS_FACT_NAME,
    source,
    attributes: {
      ...common,
      source_state: sourceState,
      services_total: usable ? String(states.length) : "unknown",
      connected_total: usable ? String(states.filter((entry) => entry.state === "connected").length) : "unknown",
      emitted: String(emitted.length),
      overflow: usable && keyed ? String(states.length - emitted.length) : "unknown",
      state_digest: !usable || !keyed ? "unknown"
        : states.length === 0 ? "none"
          : contextHmac(hmacKey, "vpn_service_states", states.map((entry) => `${entry.hmac}:${entry.state}`).join(",")),
    },
  })];
  for (const entry of emitted) {
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: NET_VPN_SERVICE_STATE_FACT_NAME,
      entityKey: `${NET_VPN_SERVICE_STATE_FACT_NAME}.${entry.hmac}`,
      source,
      attributes: { ...common, service_hmac: entry.hmac, state: entry.state, kind: "os_vpn_non_tailscale" },
    }));
  }
  return points;
}

// ------------------------------------------------------------------------------------------------
// C2 (§4.1): host.lifecycle_record, the `last` reboot/shutdown rows the login collector already read
// (deduped by keyed row digest in the daemon's login seen-state: a repeated sighting is not a new row).
// ------------------------------------------------------------------------------------------------

const LIFECYCLE_KINDS = new Set(["reboot", "shutdown"]);
const LIFECYCLE_END_STATES = new Set(["still_running", "ended", "crash", "down", "none"]);

/**
 * evidence[] + the daemon's dedupe selection -> at most MAX_LIFECYCLE_RECORDS_PER_TICK
 * host.lifecycle_record points, each carrying the tick's total of new rows (so an overflow is
 * visible on every emitted record). No dedupe selection (no usable key): nothing is emitted.
 */
export function factPointsFromLifecycleRecordEvidence(evidence, { ts, hmacKey, dedupe } = {}) {
  const envelope = (evidence ?? []).find((e) => e?.id === "login-sessions" && e?.source !== "daemon");
  if (!envelope || !dedupe || !Array.isArray(dedupe.newLifecycle)) return [];
  const result = envelope.result ?? {};
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  const sourceState = COMPONENT_STATE_VALUES.has(result.lifecycle?.state) ? result.lifecycle.state : "unable";
  const collectorState = sourceState === "absent" ? "ok" : COLLECTOR_STATE_SET.has(sourceState) ? sourceState : "unable";
  const total = dedupe.newLifecycle.length;
  const points = [];
  for (const row of dedupe.newLifecycle.slice(0, MAX_LIFECYCLE_RECORDS_PER_TICK)) {
    points.push(contextFactPoint({
      hmacKey,
      ts,
      factName: HOST_LIFECYCLE_RECORD_FACT_NAME,
      entityKey: `${HOST_LIFECYCLE_RECORD_FACT_NAME}.${contextHmac(hmacKey, "lifecycle_row_entity", row.digest)}`,
      source: CONTEXT_ENVELOPE_SOURCES.login_sessions,
      attributes: {
        collector_state: collectorState,
        obs_start_ms: msString(obsStartMs),
        obs_end_ms: msString(obsEndMs),
        rejected_field: "none",
        kind: LIFECYCLE_KINDS.has(row.kind) ? row.kind : "unknown",
        start_text: typeof row.start_text === "string" ? row.start_text : "unknown",
        time_confidence: "local_minute_no_year",
        end_state: LIFECYCLE_END_STATES.has(row.end_state) ? row.end_state : "unknown",
        duration_text: typeof row.duration_text === "string" ? row.duration_text : "unknown",
        os_release: typeof row.os_release === "string" ? row.os_release : "unknown",
        new_rows_total: String(Math.min(total, 1000)),
        dedupe_state: ["fresh", "reseeded"].includes(dedupe.lifecycleDedupeState) ? dedupe.lifecycleDedupeState : "unknown",
      },
    }));
  }
  return points;
}
