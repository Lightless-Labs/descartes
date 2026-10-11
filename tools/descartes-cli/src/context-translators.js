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
import { enforceContextSchema } from "./context-schemas.js";

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

// The envelope ids and tool names the context collectors stamp (bounded, closed).
export const CONTEXT_ENVELOPE_SOURCES = Object.freeze({
  host_lifecycle: Object.freeze({ id: "host-lifecycle", tool: "collect_host_lifecycle" }),
  tailscale: Object.freeze({ id: "tailscale-status", tool: "collect_tailscale_status" }),
  net_config: Object.freeze({ id: "net-config", tool: "collect_net_config" }),
  login_sessions: Object.freeze({ id: "login-sessions", tool: "collect_login_sessions" }),
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
  const endMs = Date.parse(envelope?.trace?.ts ?? "");
  const latency = Number(envelope?.trace?.latency_ms);
  if (Number.isFinite(endMs) && Number.isFinite(latency) && latency >= 0) {
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

const TAILNET_FAILURE_STATES = new Set(["not_found_on_known_paths", "untrusted_binary", "missing_permission", "unable"]);

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
  let state;
  let collectorState;
  if (tailnet && typeof tailnet.backend_state === "string") {
    // The JSON was parsed: the backend state was observed, whatever the peer census made of it.
    collectorState = "ok";
    state = Object.prototype.hasOwnProperty.call(TAILNET_BACKEND_STATE_VALUES, tailnet.backend_state)
      ? TAILNET_BACKEND_STATE_VALUES[tailnet.backend_state]
      : "unrecognized_backend_state";
  } else {
    collectorState = TAILNET_FAILURE_STATES.has(result.status) ? result.status : "unable";
    state = collectorState;
  }
  const observed = collectorState === "ok";
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

const HOST_COLLECTOR_STATES = new Set(["ok", "partial", "unable", "not_applicable", "not_found_on_known_paths", "untrusted_binary", "missing_permission"]);
const BOOT_ID_SOURCES = new Set(["kern.bootsessionuuid", "proc_boot_id"]);

function intString(value) {
  return Number.isSafeInteger(value) && value >= 0 ? String(value) : "unknown";
}

function tokenString(value) {
  return typeof value === "string" && value.length > 0 ? value : "unknown";
}

function platformValue(platform, wanted, value, toString) {
  if (platform !== wanted) return "not_applicable";
  return value === undefined || value === null ? "unknown" : toString(value);
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
  const collectorState = HOST_COLLECTOR_STATES.has(result.status) ? result.status : "unable";
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
      kern_monotonicclock_usecs: platformValue(platform, "darwin", clocks.kern_monotonicclock_usecs, String),
      kern_sleeptime_s: platformValue(platform, "darwin", clocks.kern_sleeptime_s, intString),
      kern_waketime_s: platformValue(platform, "darwin", clocks.kern_waketime_s, intString),
      kern_sleep_abs_time: platformValue(platform, "darwin", clocks.kern_sleep_abs_time, String),
      kern_wake_abs_time: platformValue(platform, "darwin", clocks.kern_wake_abs_time, String),
      machdep_wake_abstime: platformValue(platform, "darwin", clocks.machdep_wake_abstime, String),
      machdep_wake_conttime: platformValue(platform, "darwin", clocks.machdep_wake_conttime, String),
      proc_uptime_s: platformValue(platform, "linux", clocks.proc_uptime_s, String),
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
  const collectorState = HOST_COLLECTOR_STATES.has(result.status) ? result.status : "unable";
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

function componentState(component) {
  return COMPONENT_STATE_VALUES.has(component?.state) ? component.state : "unable";
}

function componentHmac(hmacKey, name, component) {
  const state = componentState(component);
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
    const state = componentState(component);
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
  const collectorState = HOST_COLLECTOR_STATES.has(result.status) ? result.status : "unable";
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
    const state = componentState(component);
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
