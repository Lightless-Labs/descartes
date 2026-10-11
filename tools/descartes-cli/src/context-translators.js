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
export function contextFactPoint({ ts, factName, entityKey, attributes, source }) {
  return enforceContextSchema({
    ts,
    fact_name: factName,
    entity_key: entityKey ?? factName,
    attributes,
    source_envelope_id: source?.id,
    source_tool: source?.tool,
    sensitivity: "operational",
  });
}

export function msString(value) {
  return Number.isSafeInteger(value) && value >= 0 ? String(value) : "unknown";
}
