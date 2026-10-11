// Context plan C2 (docs/plans/2026-10-06-context-aware-learned-baselines.md §4, §8.1, §8.2; I50, I68,
// I70; open item 20): the per-tick derivations that need the PREVIOUS tick -- context transitions,
// session created_vs_boot, the tick_summary record with its hash chain and its certification, and the
// long-lived statistics skeleton -- plus the two ledger-stamped state files they chain through.
//
// DATA ONLY. Nothing here raises, recovers, closes or admits anything, and no detector reads what it
// writes. There is no behaviour rule here either: no "after boot", no "expected", no threshold beyond
// the one measurement resolution (I24/I66) used to tell a clock step from read jitter.
//
// Degrade, never fabricate: a missing or invalid previous state makes every interval quantity
// (arrivals, departures, transitions, episode statistics) unknown, never zero (I50); a chain that
// cannot be continued is recorded as restarted, never as continued.
//
// Pure functions (derive*) are separated from the state-file I/O (read*/write*); the daemon glue
// (daemon.js) sequences them around the fact-store passes.

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { contextHmac, contextKeyId } from "./context-key.js";
import {
  enforceContextSchema,
  SUMMARY_COLLECTOR_ORDER,
  SUMMARY_EVENT_CODES,
  SUMMARY_EVENTS_RE,
  SUMMARY_TAILNET_STATE_CODES,
  TRANSITION_DIMENSIONS,
} from "./context-schemas.js";
import {
  hashSessionIdentity,
  PEER_CENSUS_MARKER_ENTITY_KEY,
  PEER_OVERFLOW_ENTITY_KEY,
  SESSION_CENSUS_MARKER_ENTITY_KEY,
  SESSION_OVERFLOW_ENTITY_KEY,
} from "./fact-translators.js";
import { normalizeFactPoint, readFactPoints, resolveFactStorePaths } from "./fact-store.js";
import { BOOT_MEASUREMENT_RESOLUTION_S } from "./tools/host-lifecycle.js";
import { bootIdDigest, wakeMarkerOf } from "./boot-ledger.js";
import { CONTEXT_ENVELOPE_SOURCES, hostBootIdHmac, msString, observationInterval } from "./context-translators.js";

export const TICK_SUMMARY_FACT_NAME = "tick.summary";
export const CONTEXT_TRANSITION_FACT_NAME = "context.transition";
export const SESSION_CREATED_VS_BOOT_FACT_NAME = "session.created_vs_boot";
export const HOST_DAEMON_GAP_FACT_NAME = "host.daemon_gap";
export const STATS_EPISODE_FACT_NAME = "stats.episode";
export const STATS_DAILY_FACT_NAME = "stats.daily";
// One transition per dimension per interval (8 dimensions), so the cap can never truncate.
export const MAX_TRANSITIONS_PER_TICK = TRANSITION_DIMENSIONS.length;
export const MAX_CREATED_VS_BOOT_PER_TICK = 8;
// §8.1: a record is at most 1 KiB at worst case (pinned by test).
export const TICK_SUMMARY_MAX_RECORD_BYTES = 1024;
// The families whose committed passes a tick_summary record cites (I70).
export const SUMMARY_SOURCE_FAMILIES = Object.freeze(["session", "peer", "host_lifecycle", "network_context", "session_context"]);
const SUMMARY_FAMILY_CODES = Object.freeze({ session: "s", peer: "p", host_lifecycle: "h", network_context: "n", session_context: "x" });
const SUMMARY_CODE_FAMILIES = Object.freeze(Object.fromEntries(Object.entries(SUMMARY_FAMILY_CODES).map(([family, code]) => [code, family])));
// Episode follow-up samples at the next structural ticks (offsets 1, 2), while the pre-event set is
// held in the stats state (§8.2: identity statistics computed online while the raw sets exist).
export const EPISODE_MAX_OFFSET = 2;
// Bounds on the chained entity sets (the collectors' own per-tick caps; anything larger is invalid).
export const SUMMARY_MAX_SESSION_ENTITIES = 200;
export const SUMMARY_MAX_PEER_ENTITIES = 400;
const RESOLUTION_MS = BOOT_MEASUREMENT_RESOLUTION_S * 1000;

// v2 (C2 review M3): the context holds the last known reading per dimension, with its own observation end.
const CHAIN_STATE_VERSION = 3;
const STATS_STATE_VERSION = 2;
const HEX16_RE = /^[0-9a-f]{16}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const KEY_RE = /^[A-Za-z0-9._:+-]{1,256}$/;
const FP_RE = /^([0-9a-f]{16}|unknown|)$/;
const DAY_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$/;

// ------------------------------------------------------------------------------------------------
// Version and config hash (§8.1: "the Descartes version and config hash").
// ------------------------------------------------------------------------------------------------

export const DESCARTES_PACKAGE_NAME = "@lightless-labs/descartes";

/**
 * The version of the first candidate package.json that is Descartes's own (C2 review L7: its `name`
 * must match; an unrelated package.json higher up is never read as ours), or "unknown".
 */
export function readDescartesVersion(candidates) {
  for (const candidate of candidates ?? []) {
    try {
      const parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
      if (parsed?.name !== DESCARTES_PACKAGE_NAME) continue;
      const version = parsed.version;
      if (typeof version === "string" && /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$/.test(version)) return version;
    } catch {
      // next candidate
    }
  }
  return "unknown";
}

let cachedVersion;
export function descartesVersion() {
  if (cachedVersion !== undefined) return cachedVersion;
  const here = path.dirname(fileURLToPath(import.meta.url));
  // The package's own manifest first (tools/descartes-cli/package.json).
  cachedVersion = readDescartesVersion([path.resolve(here, "../package.json"), path.resolve(here, "../../../package.json")]);
  return cachedVersion;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value ?? null);
}

/** Keyed hash of the effective configuration (watch config + daemon profile), 16 hex, or "unknown". */
export function configHash(hmacKey, config) {
  try {
    return contextHmac(hmacKey, "config_hash", canonicalJson(config));
  } catch {
    return "unknown";
  }
}

// ------------------------------------------------------------------------------------------------
// The tick snapshot: what this structural tick observed, from its evidence and its (already
// schema-validated) fact points. Pure.
// ------------------------------------------------------------------------------------------------

function pointsNamed(points, factName) {
  return (points ?? []).filter((point) => point?.fact_name === factName);
}

function onePoint(points, factName) {
  const found = pointsNamed(points, factName);
  return found.length === 1 ? found[0] : undefined;
}

function safeInt(value) {
  return Number.isSafeInteger(value) ? value : undefined;
}

function intAttr(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,15})$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

/**
 * The session census of this tick from the incumbent session.presence points (read only): census
 * "c" complete | "p" partial | "u" unknown | "a" absent (no census marker this tick); the universe (the
 * marker's availability signature); and, for a complete census, the instance set (entity key ->
 * creation fingerprint). An overflow marker or a repeated key makes the census partial.
 */
export function sessionCensusOf(points) {
  const presence = pointsNamed(points, "session.presence");
  const markers = presence.filter((p) => p.entity_key === SESSION_CENSUS_MARKER_ENTITY_KEY);
  if (markers.length === 0) return { census: "a", universe: undefined, entities: undefined, count: undefined };
  const states = new Set(markers.map((m) => m.attributes?.census_state));
  const universes = new Set(markers.map((m) => m.attributes?.availability_signature ?? m.attributes?.binary_availability ?? ""));
  let census = states.size === 1 && states.has("complete") ? "c" : states.size === 1 && states.has("partial") ? "p" : "u";
  if (presence.some((p) => p.entity_key === SESSION_OVERFLOW_ENTITY_KEY)) census = census === "c" ? "p" : census;
  const entities = new Map();
  for (const point of presence) {
    if (point.entity_key === SESSION_CENSUS_MARKER_ENTITY_KEY || point.entity_key === SESSION_OVERFLOW_ENTITY_KEY) continue;
    if (!KEY_RE.test(point.entity_key ?? "") || entities.has(point.entity_key)) {
      census = census === "c" ? "p" : census;
      continue;
    }
    const fp = point.attributes?.created_at_fingerprint;
    entities.set(point.entity_key, typeof fp === "string" && FP_RE.test(fp) ? fp : "unknown");
  }
  const universe = universes.size === 1 ? [...universes][0] : undefined;
  if (universes.size !== 1) census = "u";
  return {
    census,
    universe: universe || undefined,
    entities: census === "c" && entities.size <= SUMMARY_MAX_SESSION_ENTITIES ? entities : undefined,
    count: census === "c" ? entities.size : undefined,
  };
}

/**
 * The VPN-signed peer census of this tick: active peers under the vpn-peer-status census marker,
 * excluding Tailscale peers and the OS VPN services themselves. A VPN service's connection state is
 * VPN CONTEXT (vn/vc/vd, net.vpn_service_state, the `vpn` transition); counting it as a peer too
 * would restate the context inside the target it conditions (§4.2, Astra 4; C2 review H1). Complete
 * only when the marker is present, there is no VPN overflow and the envelope's own census is ok.
 * Peers carry no instance fingerprint ("").
 */
export function peerCensusOf(points, evidence) {
  const presence = pointsNamed(points, "peer.presence");
  const markers = presence.filter((p) => p.entity_key === PEER_CENSUS_MARKER_ENTITY_KEY);
  if (markers.length === 0) return { census: "a", universe: undefined, entities: undefined, count: undefined };
  const universes = new Set(markers.map((m) => m.attributes?.availability_signature ?? ""));
  const envelope = (evidence ?? []).find((e) => e?.id === "vpn-peer-status");
  let census = universes.size === 1 && envelope?.source !== "daemon" && envelope?.result?.census_status === "ok" ? "c" : "p";
  if (presence.some((p) => p.entity_key === PEER_OVERFLOW_ENTITY_KEY && p.source_envelope_id !== "tailscale-status")) census = "p";
  const entities = new Map();
  for (const point of presence) {
    if (point.entity_key === PEER_CENSUS_MARKER_ENTITY_KEY || point.entity_key === PEER_OVERFLOW_ENTITY_KEY) continue;
    if (point.attributes?.presence_state === "observed_historical") continue;
    if (point.attributes?.source_type === "tailscale" || point.attributes?.source_type === "vpn_service") continue;
    if (!KEY_RE.test(point.entity_key ?? "") || entities.has(point.entity_key)) {
      census = "p";
      continue;
    }
    entities.set(point.entity_key, "");
  }
  const universe = universes.size === 1 ? [...universes][0] : undefined;
  if (universes.size !== 1) census = "u";
  return {
    census,
    universe: universe || undefined,
    entities: census === "c" && entities.size <= SUMMARY_MAX_PEER_ENTITIES ? entities : undefined,
    count: census === "c" ? entities.size : undefined,
  };
}

const COLLECTOR_STATE_CODES = Object.freeze({
  ok: "o", partial: "p", unable: "u", not_applicable: "n", not_found_on_known_paths: "f", untrusted_binary: "t", missing_permission: "m", absent: "o",
});

function collectorCode(envelope) {
  if (!envelope) return "a";
  if (envelope.source === "daemon") return "d";
  const status = envelope.result?.status;
  if (typeof status === "string" && COLLECTOR_STATE_CODES[status]) return COLLECTOR_STATE_CODES[status];
  if (envelope.status === "ok") return "o";
  if (envelope.status === "warning") return "p";
  return "u";
}

/**
 * evidence + this tick's fact points + the boot-ledger-derived host context -> the snapshot every
 * derivation below reads. Every value is either observed this tick or undefined (unknown).
 */
export function extractTickSnapshot({ evidence, points, hostFacts, ts, hmacKey, interval } = {}) {
  const tsMs = Date.parse(ts);
  const byId = new Map();
  for (const envelope of evidence ?? []) if (envelope?.id && !byId.has(envelope.id)) byId.set(envelope.id, envelope);
  const host = byId.get("host-lifecycle");
  const probe = host && host.source !== "daemon" ? host.result : undefined;
  const clocks = probe?.clocks ?? {};
  const rawBootId = typeof probe?.boot?.boot_id === "string" ? probe.boot.boot_id : undefined;
  const tailnet = onePoint(points, "net.tailnet_state")?.attributes;
  const vpn = onePoint(points, "net.vpn_service_census")?.attributes;
  const netConfig = onePoint(points, "net.config_fingerprint")?.attributes;
  const presence = onePoint(points, "user.presence")?.attributes;
  const obs = SUMMARY_COLLECTOR_ORDER.map((id) => observationInterval(byId.get(id) ?? {}));
  const starts = obs.map((o) => o.obsStartMs).filter(Number.isSafeInteger);
  const ends = obs.map((o) => o.obsEndMs).filter(Number.isSafeInteger);
  const hostObs = observationInterval(host ?? {});
  const tailnetObs = observationInterval(byId.get("tailscale-status") ?? {});
  const vpnObs = observationInterval(byId.get("vpn-peer-status") ?? {});
  const netObs = observationInterval(byId.get("net-config") ?? {});
  return {
    ts,
    tsMs,
    platform: probe?.platform,
    session: sessionCensusOf(points),
    peer: peerCensusOf(points, evidence),
    collectors: SUMMARY_COLLECTOR_ORDER.map((id) => collectorCode(byId.get(id))).join(""),
    obsSpan: { startMs: starts.length > 0 ? Math.min(...starts) : undefined, endMs: ends.length > 0 ? Math.max(...ends) : undefined },
    obsEnd: { host: hostObs.obsEndMs, tailnet: tailnetObs.obsEndMs, vpn: vpnObs.obsEndMs, net: netObs.obsEndMs },
    boot: {
      digest: bootIdDigest(rawBootId),
      hmac: rawBootId ? hostBootIdHmac(hmacKey, rawBootId) : "unknown",
      timeS: safeInt(probe?.boot?.boot_time_s),
      verdict: hostFacts?.boundary?.verdict,
    },
    clocks: {
      wallMs: safeInt(clocks.wall_ms),
      uptimeMs: safeInt(clocks.os_uptime_ms),
      hrtimeNs: typeof clocks.uv_hrtime_ns === "string" && /^[0-9]{1,20}$/.test(clocks.uv_hrtime_ns) ? clocks.uv_hrtime_ns : undefined,
      mono: probe?.platform === "darwin" ? clocks.kern_monotonicclock_usecs : probe?.platform === "linux" ? clocks.proc_uptime_s : undefined,
      wakeS: safeInt(clocks.kern_waketime_s),
      wakeAbs: typeof clocks.machdep_wake_abstime === "string" ? clocks.machdep_wake_abstime : undefined,
      wakeCont: typeof clocks.machdep_wake_conttime === "string" ? clocks.machdep_wake_conttime : undefined,
      suspendSuccess: safeInt(clocks.suspend_stats_success),
      wakeMarker: wakeMarkerOf(probe),
      tzHmac: typeof clocks.tz_id === "string" ? contextHmac(hmacKey, "timezone_id", clocks.tz_id) : "unknown",
      utcOffsetMin: safeInt(clocks.utc_offset_min),
    },
    suspend: hostFacts?.suspend,
    tailnet: tailnet ? { state: tailnet.state, online: tailnet.self_online } : undefined,
    vpn: vpn ? { total: intAttr(vpn.services_total), connected: intAttr(vpn.connected_total), digest: vpn.state_digest } : undefined,
    net: netConfig?.fingerprint_hmac,
    presence: presence ? { locked: presence.screen_locked, idle: presence.idle_hint } : undefined,
    interval,
  };
}

// ------------------------------------------------------------------------------------------------
// Ledger-stamped state files (I50): the census chain state (one snapshot) and the statistics state.
// ------------------------------------------------------------------------------------------------

export function resolveSummaryChainPath(descartesPaths) {
  return path.join(resolveFactStorePaths(descartesPaths, "tick_summary").dir, "chain-state.json");
}

export function resolveStatsStatePath(descartesPaths) {
  return path.join(resolveFactStorePaths(descartesPaths, "context_stats").dir, "stats-state.json");
}

export function resolveSummaryGapPath(descartesPaths) {
  return path.join(resolveFactStorePaths(descartesPaths, "tick_summary").dir, "gap-state.json");
}

async function readJsonFile(file) {
  let contents;
  try {
    contents = await fsp.readFile(file, "utf8");
  } catch (error) {
    return { status: error?.code === "ENOENT" ? "missing" : "unreadable", value: undefined };
  }
  if (contents.length > 2 * 1024 * 1024) return { status: "invalid", value: undefined };
  try {
    return { status: "ok", value: JSON.parse(contents) };
  } catch {
    return { status: "invalid", value: undefined };
  }
}

async function writeJsonFile(file, value) {
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(value), { mode: 0o600 });
  await fsp.rename(tmp, file);
}

const GAP_STATE_KEYS = ["schema_version", "ledger_generation", "ledger_pass_id", "missing_count", "first_ts", "reason"];

function isValidGapState(value) {
  return exactKeys(value, GAP_STATE_KEYS)
    && value.schema_version === 1
    && (value.ledger_generation === null || typeof value.ledger_generation === "string" && value.ledger_generation.length > 0 && value.ledger_generation.length <= 64)
    && (value.ledger_pass_id === null || Number.isSafeInteger(value.ledger_pass_id) && value.ledger_pass_id >= 0)
    && ((value.ledger_generation === null) === (value.ledger_pass_id === null))
    && Number.isSafeInteger(value.missing_count) && value.missing_count >= 0 && value.missing_count <= 2 ** 32
    && (value.missing_count === 0
      ? value.first_ts === null && value.reason === "none"
      : typeof value.first_ts === "string" && Number.isFinite(Date.parse(value.first_ts))
        && value.reason !== "none")
    && typeof value.reason === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(value.reason);
}

export async function readSummaryGapState(descartesPaths, { ledger } = {}) {
  const read = await readJsonFile(resolveSummaryGapPath(descartesPaths));
  if (read.status !== "ok") return { status: read.status };
  if (!isValidGapState(read.value)) return { status: "invalid" };
  if (ledger && (read.value.ledger_generation !== ledger.generation || read.value.ledger_pass_id !== ledger.continuity?.last_committed_pass_id)) {
    return { status: "lineage_mismatch" };
  }
  return { status: "valid", state: read.value };
}

export async function writeSummaryGapState(descartesPaths, state) {
  if (!isValidGapState(state)) throw new Error("tick_summary gap state fails its own shape");
  await writeJsonFile(resolveSummaryGapPath(descartesPaths), state);
}

export async function clearSummaryGapState(descartesPaths) {
  try {
    await fsp.rm(resolveSummaryGapPath(descartesPaths));
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function optionalInt(value) {
  return value === null || Number.isSafeInteger(value);
}

function optionalString(value, re) {
  return value === null || (typeof value === "string" && re.test(value));
}

function optionalTimestamp(value) {
  return value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
}

function validEntityList(list, cap) {
  if (list === null) return true;
  if (!Array.isArray(list) || list.length > cap) return false;
  const seen = new Set();
  for (const entry of list) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || !KEY_RE.test(entry[0]) || typeof entry[1] !== "string" || !FP_RE.test(entry[1])) return false;
    if (seen.has(entry[0])) return false;
    seen.add(entry[0]);
  }
  return true;
}

const SOURCE_STATE_KEYS = ["census", "universe", "entities"];
function validSourceState(value, cap) {
  return exactKeys(value, SOURCE_STATE_KEYS)
    && ["c", "p", "u", "a"].includes(value.census)
    && optionalString(value.universe, /^[\s\S]{1,256}$/)
    && validEntityList(value.entities, cap);
}

// The previous context (C2 review M3). Each categorical dimension holds its LAST KNOWN reading and that
// reading's own observation end (carried across a tick that could not read it), so a change across an
// unreadable tick is still recorded, over the whole gap. The wake marker is carried with the boot it
// was read in. The clock readings (wall, uptime, and the boot they were read in) are THIS tick's only,
// never carried: a cross-check is taken only between consecutive readings of one boot.
const CONTEXT_STATE_KEYS = [
  "boot_digest", "boot_hmac", "boot_end",
  "wake_marker", "wake_boot_digest", "wake_end",
  "tailnet", "tailnet_end",
  "vpn_digest", "vpn_end",
  "net", "net_end",
  "tz_hmac", "tz_end",
  "utc_offset_min", "utc_offset_end",
  "wall_ms", "uptime_ms", "clock_boot_digest", "clock_end",
];
const CONTEXT_INT_KEYS = ["boot_end", "wake_end", "tailnet_end", "vpn_end", "net_end", "tz_end", "utc_offset_end", "wall_ms", "uptime_ms", "clock_end"];
const CHAIN_STATE_KEYS = ["schema_version", "family", "ledger_generation", "ledger_pass_id", "future_loss_marker", "hmac_key_id", "seq", "record_digest", "record_ts", "session", "peer", "context"];
const TOKEN_RE = /^[A-Za-z0-9_.:+-]{1,64}$/;

/** The closed shape of the chain state (any other shape is invalid, never partially trusted). */
export function isValidSummaryChainState(value) {
  if (!exactKeys(value, CHAIN_STATE_KEYS)) return false;
  if (value.schema_version !== CHAIN_STATE_VERSION || value.family !== "tick_summary") return false;
  if (typeof value.ledger_generation !== "string" || value.ledger_generation.length === 0 || value.ledger_generation.length > 64) return false;
  if (!Number.isSafeInteger(value.ledger_pass_id) || value.ledger_pass_id < 0) return false;
  if (!optionalTimestamp(value.future_loss_marker)) return false;
  if (!HEX16_RE.test(value.hmac_key_id ?? "") && value.hmac_key_id !== "unknown") return false;
  if (!Number.isSafeInteger(value.seq) || value.seq < 0 || value.seq > 2 ** 32) return false;
  if (!HEX16_RE.test(value.record_digest ?? "")) return false;
  if (typeof value.record_ts !== "string" || !Number.isFinite(Date.parse(value.record_ts))) return false;
  if (!validSourceState(value.session, SUMMARY_MAX_SESSION_ENTITIES) || !validSourceState(value.peer, SUMMARY_MAX_PEER_ENTITIES)) return false;
  const c = value.context;
  if (!exactKeys(c, CONTEXT_STATE_KEYS)) return false;
  return optionalString(c.boot_digest, HEX32_RE)
    && optionalString(c.boot_hmac, /^([0-9a-f]{16}|unknown)$/)
    && optionalString(c.wake_boot_digest, HEX32_RE) && optionalString(c.clock_boot_digest, HEX32_RE)
    && optionalString(c.wake_marker, TOKEN_RE) && optionalString(c.tailnet, TOKEN_RE)
    && optionalString(c.vpn_digest, TOKEN_RE) && optionalString(c.net, TOKEN_RE)
    && optionalString(c.tz_hmac, TOKEN_RE) && optionalInt(c.utc_offset_min)
    && CONTEXT_INT_KEYS.every((key) => optionalInt(c[key]));
}

async function familyLedgerHasLoss(descartesPaths, family, ledger, consumedFutureLossMarker = null) {
  if (!ledger || ledger.continuity?.continuity_ok === false) return true;
  // A future record discarded by retention is a rollback loss even when the remaining file is
  // otherwise byte-consistent. The next derived record must re-anchor instead of continuing.
  const newFutureLoss = ledger.last_future_fact_ts !== null && ledger.last_future_fact_ts !== undefined && ledger.last_future_fact_ts !== consumedFutureLossMarker;
  if (newFutureLoss) return true;
  try {
    const read = await readFactPoints(descartesPaths, { family, now: new Date().toISOString() });
    const completeness = read.completeness ?? {};
    return read.continuity_observation === "broken"
      || completeness.degraded_reason === "this_read_loss"
      || completeness.degraded_reason === "future_fact" && newFutureLoss;
  } catch {
    return true;
  }
}

/**
 * The chain state read and checked against tick_summary's ledger as it stands BEFORE this tick's
 * summary pass (seen-set style, I50): same generation, the same committed pass, no pending pass, and
 * made under the same HMAC key (keyed values from another key are not comparable). Returns
 * { status: "valid" | "missing" | "unreadable" | "invalid" | "no_ledger" | "pending_pass" |
 * "lineage_mismatch" | "key_changed", state? }.
 */
export async function readSummaryChainState(descartesPaths, { ledger, hmacKeyId } = {}) {
  const read = await readJsonFile(resolveSummaryChainPath(descartesPaths));
  if (read.status !== "ok") return { status: read.status };
  if (!isValidSummaryChainState(read.value)) return { status: "invalid" };
  const state = read.value;
  if (!ledger) return { status: "no_ledger" };
  if (ledger.continuity?.pending_pass) return { status: "pending_pass" };
  if (await familyLedgerHasLoss(descartesPaths, "tick_summary", ledger, state.future_loss_marker)) return { status: "continuity_lost" };
  if (state.ledger_generation !== ledger.generation || state.ledger_pass_id !== ledger.continuity?.last_committed_pass_id) return { status: "lineage_mismatch" };
  if (state.hmac_key_id !== hmacKeyId) return { status: "key_changed" };
  return { status: "valid", state };
}

export async function writeSummaryChainState(descartesPaths, state) {
  if (!isValidSummaryChainState(state)) throw new Error("tick_summary chain state fails its own shape");
  await writeJsonFile(resolveSummaryChainPath(descartesPaths), state);
}

// ------------------------------------------------------------------------------------------------
// Context transitions (§4.2 context.transition) and the interval events. Pure.
// ------------------------------------------------------------------------------------------------

function magnitudeBucket(ms) {
  const abs = Math.abs(ms);
  if (abs < 60_000) return "lt_1m";
  if (abs < 3_600_000) return "1m_1h";
  if (abs < 86_400_000) return "1h_1d";
  return "ge_1d";
}

/**
 * The wall-clock cross-check of open item 20: within one boot, the wall delta against the uptime
 * delta (the bound's own clock), between CONSECUTIVE readings only (the previous context's clock
 * readings are never carried across a tick that could not read them). "c" consistent to the
 * resolution, "f"/"b" a forward/backward wall step, "u" unknown (no previous reading, another boot, a
 * missing reading). `crossBoot` is true when both readings' boots are known and differ (a clock delta
 * across a boot is not applicable, F2). On macOS the uptime is itself now - kern.boottime, so there
 * the check only sees a moved kern.boottime (C2 review M5; unverified until C0.9).
 */
export function wallCrossCheck(prevContext, snapshot) {
  const prevBoot = prevContext?.clock_boot_digest;
  const curBoot = snapshot.boot?.digest;
  const sameBoot = Boolean(prevBoot) && prevBoot === curBoot;
  const crossBoot = Boolean(prevBoot) && Boolean(curBoot) && prevBoot !== curBoot;
  const wallDeltaMs = Number.isSafeInteger(prevContext?.wall_ms) && Number.isSafeInteger(snapshot.clocks?.wallMs) ? snapshot.clocks.wallMs - prevContext.wall_ms : undefined;
  const uptimeDeltaMs = sameBoot && Number.isSafeInteger(prevContext?.uptime_ms) && Number.isSafeInteger(snapshot.clocks?.uptimeMs) ? snapshot.clocks.uptimeMs - prevContext.uptime_ms : undefined;
  if (wallDeltaMs === undefined || uptimeDeltaMs === undefined || uptimeDeltaMs < 0) return { code: "u", wallDeltaMs, uptimeDeltaMs, crossBoot };
  const gap = wallDeltaMs - uptimeDeltaMs;
  if (gap > RESOLUTION_MS) return { code: "f", wallDeltaMs, uptimeDeltaMs, stepMs: gap, crossBoot };
  if (gap < -RESOLUTION_MS) return { code: "b", wallDeltaMs, uptimeDeltaMs, stepMs: gap, crossBoot };
  return { code: "c", wallDeltaMs, uptimeDeltaMs, crossBoot };
}

function tokenOrUnknown(value) {
  return typeof value === "string" && TOKEN_RE.test(value) && value.length <= 32 ? value : "unknown";
}

// ev (C2 review M3): one character per dimension, in TRANSITION_DIMENSIONS order: the dimension's
// code when it changed, "-" compared and unchanged, "u" not comparable (a reading unknown on either
// side), "." not applicable (wake and clock_step across a known boot change).
const EVENT_UNKNOWN = "u";
const EVENT_SAME = "-";
const EVENT_NOT_APPLICABLE = ".";

/**
 * Previous (chain-state) context vs this snapshot -> the transitions of this interval, one per
 * dimension at most, each with the interval (the last known reading's observation end, this
 * observation end]. A dimension is compared only when this tick's reading is known and a previous
 * reading is known (the last known one, carried across ticks that could not read it); otherwise its
 * event is "u". With no valid previous state there are no transitions and the events are unknown
 * (`events: undefined`), never "none".
 */
export function deriveContextTransitions(prevChain, snapshot) {
  if (!prevChain) return { transitions: [], events: undefined };
  const prev = prevChain.context;
  // THIS tick's readings only (nothing carried): a carried value is never compared with itself.
  const cur = snapshotContextState(snapshot);
  const transitions = [];
  const codes = {};
  const push = (dimension, oldValue, newValue, startMs, endMs, extra = {}) => transitions.push({
    dimension,
    old_value: tokenOrUnknown(oldValue),
    new_value: tokenOrUnknown(newValue),
    interval_start_ms: Number.isSafeInteger(startMs) ? startMs : undefined,
    interval_end_ms: Number.isSafeInteger(endMs) ? endMs : undefined,
    magnitude: "not_applicable",
    semantics: "observed",
    ...extra,
  });
  const known = (value) => (typeof value === "string" && value !== "unknown") || Number.isSafeInteger(value);
  const compare = (dimension, prevValue, curValue, prevEnd, curEnd, { oldShown = prevValue, newShown = curValue } = {}) => {
    if (!known(prevValue) || !known(curValue)) {
      codes[dimension] = EVENT_UNKNOWN;
      return;
    }
    if (prevValue === curValue) {
      codes[dimension] = EVENT_SAME;
      return;
    }
    codes[dimension] = SUMMARY_EVENT_CODES[dimension];
    push(dimension, typeof oldShown === "number" ? String(oldShown) : oldShown, typeof newShown === "number" ? String(newShown) : newShown, prevEnd, curEnd);
  };
  // A boot is a boot-id change (the raw id's digest); the transition carries the keyed HMACs.
  compare("boot", prev.boot_digest, cur.boot_digest, prev.boot_end, cur.boot_end, { oldShown: prev.boot_hmac ?? "unknown", newShown: cur.boot_hmac ?? "unknown" });
  if (known(prev.wake_boot_digest) && known(cur.boot_digest) && prev.wake_boot_digest !== cur.boot_digest) codes.wake = EVENT_NOT_APPLICABLE;
  else compare("wake", prev.wake_boot_digest ? prev.wake_marker : null, cur.wake_marker, prev.wake_end, cur.wake_end);
  compare("tailnet", prev.tailnet, cur.tailnet, prev.tailnet_end, cur.tailnet_end);
  compare("vpn", prev.vpn_digest, cur.vpn_digest, prev.vpn_end, cur.vpn_end);
  compare("net_config", prev.net, cur.net, prev.net_end, cur.net_end);
  const cross = wallCrossCheck(prev, snapshot);
  if (cross.code === "f" || cross.code === "b") {
    codes.clock_step = SUMMARY_EVENT_CODES.clock_step;
    push("clock_step", "none", cross.code === "f" ? "forward" : "backward", prev.clock_end, cur.clock_end, { magnitude: magnitudeBucket(cross.stepMs), semantics: "clock_semantics_unverified" });
  } else codes.clock_step = cross.code === "c" ? EVENT_SAME : cross.crossBoot ? EVENT_NOT_APPLICABLE : EVENT_UNKNOWN;
  compare("timezone", prev.tz_hmac, cur.tz_hmac, prev.tz_end, cur.tz_end);
  compare("utc_offset", prev.utc_offset_min, cur.utc_offset_min, prev.utc_offset_end, cur.utc_offset_end);
  const events = TRANSITION_DIMENSIONS.map((dimension) => codes[dimension] ?? EVENT_UNKNOWN).join("");
  const ordered = TRANSITION_DIMENSIONS.flatMap((dimension) => transitions.filter((t) => t.dimension === dimension));
  return { transitions: ordered.slice(0, MAX_TRANSITIONS_PER_TICK), events, cross };
}

export function factPointsFromTransitions(transitions, { ts, hmacKey } = {}) {
  return transitions.map((t) => transitionPoint(t, { ts, hmacKey }));
}

function transitionPoint(t, { ts, hmacKey }) {
  return contextPoint({
    ts,
    hmacKey,
    factName: CONTEXT_TRANSITION_FACT_NAME,
    entityKey: `${CONTEXT_TRANSITION_FACT_NAME}.${t.dimension}`,
    attributes: {
      collector_state: "ok",
      obs_start_ms: msString(t.interval_start_ms),
      obs_end_ms: msString(t.interval_end_ms),
      rejected_field: "none",
      dimension: t.dimension,
      old_value: t.old_value,
      new_value: t.new_value,
      interval_start_ms: msString(t.interval_start_ms),
      interval_end_ms: msString(t.interval_end_ms),
      magnitude: t.magnitude,
      semantics: t.semantics,
    },
  });
}

function contextPoint({ ts, hmacKey, factName, entityKey, attributes, source = CONTEXT_ENVELOPE_SOURCES.derived }) {
  return enforceContextSchema({
    ts,
    fact_name: factName,
    entity_key: entityKey,
    attributes: { ...attributes, hmac_key_id: contextKeyId(hmacKey) },
    source_envelope_id: source?.id,
    source_tool: source?.tool,
    sensitivity: "operational",
  });
}

/**
 * The context part of the chain state (null for unknown). With `carryFrom` (the previous chain state's
 * context), a dimension this snapshot could not read keeps its last known reading and that reading's
 * observation end (C2 review M3); the clock readings are never carried. Without it: this tick only.
 */
export function snapshotContextState(snapshot, carryFrom) {
  const tn = snapshot.tailnet?.state;
  const end = (value) => (Number.isSafeInteger(value) ? value : null);
  const bootDigest = typeof snapshot.boot?.digest === "string" && HEX32_RE.test(snapshot.boot.digest) ? snapshot.boot.digest : null;
  const hostEnd = end(snapshot.obsEnd?.host);
  const wake = typeof snapshot.clocks?.wakeMarker === "string" && TOKEN_RE.test(snapshot.clocks.wakeMarker) && bootDigest ? snapshot.clocks.wakeMarker : null;
  const read = {
    boot_digest: bootDigest,
    boot_hmac: bootDigest && snapshot.boot?.hmac && snapshot.boot.hmac !== "unknown" ? snapshot.boot.hmac : null,
    boot_end: bootDigest ? hostEnd : null,
    wake_marker: wake,
    wake_boot_digest: wake ? bootDigest : null,
    wake_end: wake ? hostEnd : null,
    tailnet: typeof tn === "string" && tn !== "unable" && TOKEN_RE.test(tn) ? tn : null,
    tailnet_end: end(snapshot.obsEnd?.tailnet),
    vpn_digest: typeof snapshot.vpn?.digest === "string" && snapshot.vpn.digest !== "unknown" && TOKEN_RE.test(snapshot.vpn.digest) ? snapshot.vpn.digest : null,
    vpn_end: end(snapshot.obsEnd?.vpn),
    net: typeof snapshot.net === "string" && snapshot.net !== "unknown" && TOKEN_RE.test(snapshot.net) ? snapshot.net : null,
    net_end: end(snapshot.obsEnd?.net),
    tz_hmac: snapshot.clocks?.tzHmac && snapshot.clocks.tzHmac !== "unknown" && TOKEN_RE.test(snapshot.clocks.tzHmac) ? snapshot.clocks.tzHmac : null,
    tz_end: hostEnd,
    utc_offset_min: Number.isSafeInteger(snapshot.clocks?.utcOffsetMin) ? snapshot.clocks.utcOffsetMin : null,
    utc_offset_end: hostEnd,
    wall_ms: Number.isSafeInteger(snapshot.clocks?.wallMs) ? snapshot.clocks.wallMs : null,
    uptime_ms: Number.isSafeInteger(snapshot.clocks?.uptimeMs) ? snapshot.clocks.uptimeMs : null,
    clock_boot_digest: bootDigest,
    clock_end: hostEnd,
  };
  // A reading's end is meaningful only beside its value.
  for (const [value, endKey] of [["tailnet", "tailnet_end"], ["vpn_digest", "vpn_end"], ["net", "net_end"], ["tz_hmac", "tz_end"], ["utc_offset_min", "utc_offset_end"]]) {
    if (read[value] === null) read[endKey] = null;
  }
  if (!carryFrom) return read;
  const carried = { ...read };
  const groups = [
    ["boot_digest", ["boot_digest", "boot_hmac", "boot_end"]],
    ["wake_marker", ["wake_marker", "wake_boot_digest", "wake_end"]],
    ["tailnet", ["tailnet", "tailnet_end"]],
    ["vpn_digest", ["vpn_digest", "vpn_end"]],
    ["net", ["net", "net_end"]],
    ["tz_hmac", ["tz_hmac", "tz_end"]],
    ["utc_offset_min", ["utc_offset_min", "utc_offset_end"]],
  ];
  for (const [value, keys] of groups) {
    if (read[value] !== null) continue;
    for (const key of keys) carried[key] = carryFrom[key] ?? null;
  }
  return carried;
}

// ------------------------------------------------------------------------------------------------
// Departures and arrivals against the previous census (I50: computed once, against the immediately
// preceding record; unknown -- never zero -- when that record's set is missing, partial, or of another
// universe).
// ------------------------------------------------------------------------------------------------

export function intervalChurn(prevSource, curSource) {
  if (!prevSource || prevSource.census !== "c" || !Array.isArray(prevSource.entities)) return { arrivals: undefined, departures: undefined, arrivedKeys: undefined };
  if (curSource.census !== "c" || !(curSource.entities instanceof Map)) return { arrivals: undefined, departures: undefined, arrivedKeys: undefined };
  if ((prevSource.universe ?? null) !== (curSource.universe ?? null)) return { arrivals: undefined, departures: undefined, arrivedKeys: undefined };
  const prev = new Map(prevSource.entities);
  const arrivedKeys = [];
  let departures = 0;
  // An instance is (key, fingerprint): a recreated session (same name, new creation second) is one
  // departure and one arrival.
  for (const [key, fp] of curSource.entities) if (!prev.has(key) || prev.get(key) !== fp) arrivedKeys.push(key);
  for (const [key, fp] of prev) if (!curSource.entities.has(key) || curSource.entities.get(key) !== fp) departures += 1;
  return { arrivals: arrivedKeys.length, departures, arrivedKeys };
}

function sourceStateOf(source) {
  return {
    census: source.census,
    universe: source.universe ?? null,
    entities: source.census === "c" && source.entities instanceof Map ? [...source.entities.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)) : null,
  };
}

function setDigest(hmacKey, domain, source) {
  if (source.census !== "c" || !(source.entities instanceof Map)) return "unknown";
  if (source.entities.size === 0) return "none";
  const material = [...source.entities.entries()].map(([key, fp]) => `${key}:${fp}`).sort().join("\n");
  return contextHmac(hmacKey, domain, material);
}

function universeDigest(hmacKey, domain, source) {
  if (source.census === "a") return "none";
  if (!source.universe) return "unknown";
  const digest = contextHmac(hmacKey, domain, source.universe);
  return digest === "unknown" ? "unknown" : digest.slice(0, 8);
}

// ------------------------------------------------------------------------------------------------
// session.created_vs_boot (§4.3, I51) for newly observed instances. Pure.
// ------------------------------------------------------------------------------------------------

/**
 * For each session instance that arrived in this interval (or, with no usable previous set, each
 * instance in the census -- capped), its creation second against the current boot. `relation`: the
 * raw comparison with the reported boot time, "after_boot_time" at or after it, "before_boot_time"
 * more than the resolution before it, else unknown. `created_vs_boot`: the plan's value, which needs
 * the current boot's boundary to be VERIFIED and the interval's wall cross-check to have seen no clock
 * step (`clockStep === false`; true is a step, anything else is unknown); otherwise unknown, with the
 * reason in `basis`.
 */
export function deriveCreatedVsBoot({ evidence, snapshot, arrivedKeys, bootVerdict, clockStep, ts, hmacKey }) {
  const envelope = (evidence ?? []).find((e) => e?.id === "sessions" && e?.source !== "daemon");
  const sessions = Array.isArray(envelope?.result?.sessions) ? envelope.result.sessions : [];
  if (sessions.length === 0 || !(snapshot.session.entities instanceof Map)) return [];
  const byKey = new Map();
  for (const session of sessions) {
    const mux = session?.multiplexer === "screen" ? "screen" : "tmux";
    const key = typeof session?.session_name === "string" ? `session.${mux}.${sessionHash(mux, session.session_name)}` : undefined;
    if (key && snapshot.session.entities.has(key) && !byKey.has(key)) byKey.set(key, { mux, created: session.created_at_epoch_seconds });
  }
  const keys = (arrivedKeys ?? [...snapshot.session.entities.keys()]).filter((key) => byKey.has(key)).sort();
  const total = keys.length;
  const bootTimeS = snapshot.boot?.timeS;
  const { obsStartMs, obsEndMs } = observationInterval(envelope);
  return keys.slice(0, MAX_CREATED_VS_BOOT_PER_TICK).map((key) => {
    const { mux, created } = byKey.get(key);
    let relation = "unknown";
    let basis;
    if (!Number.isSafeInteger(created)) basis = "no_creation_time";
    else if (!Number.isSafeInteger(bootTimeS)) basis = "boot_time_unknown";
    else {
      if (created >= bootTimeS) relation = "after_boot_time";
      else if (created < bootTimeS - BOOT_MEASUREMENT_RESOLUTION_S) relation = "before_boot_time";
      // C2 review M4: `clockStep` is tri-state; only a cross-check that SAW no step (false) is "no
      // step". Unknown (no previous reading, a restarted chain, an unknown cross-check) is unknown.
      basis = clockStep === true ? "clock_step_in_interval"
        : bootVerdict === "verified" ? (clockStep === false ? "boundary_verified" : "clock_step_unknown")
          : bootVerdict === undefined ? "no_boundary_observed" : "boundary_unverified";
    }
    const verified = basis === "boundary_verified" && relation !== "unknown";
    return contextPoint({
      ts,
      hmacKey,
      factName: SESSION_CREATED_VS_BOOT_FACT_NAME,
      entityKey: `${SESSION_CREATED_VS_BOOT_FACT_NAME}.${contextHmac(hmacKey, "session_join", key.split(".").pop())}`,
      source: CONTEXT_ENVELOPE_SOURCES.derived,
      attributes: {
        collector_state: "ok",
        obs_start_ms: msString(obsStartMs),
        obs_end_ms: msString(obsEndMs),
        rejected_field: "none",
        session_key: contextHmac(hmacKey, "session_join", key.split(".").pop()),
        multiplexer: mux,
        relation,
        created_vs_boot: verified ? (relation === "after_boot_time" ? "after_boot" : "before_boot") : "unknown",
        basis: basis ?? "unknown",
        arrivals_total: String(Math.min(total, 100000)),
      },
    });
  });
}

// The incumbent session entity hash (fact-translators.js hashSessionIdentity), so a created_vs_boot
// record joins the session.presence entity of the same instance.
function sessionHash(mux, name) {
  return hashSessionIdentity(mux, name);
}

// ------------------------------------------------------------------------------------------------
// host.daemon_gap (§4.1): from the boot ledger's per-interval accumulator. Pure.
// ------------------------------------------------------------------------------------------------

export function factPointsFromDaemonGap(daemonGap, { ts, hmacKey, intervalMs, obsStartMs, obsEndMs } = {}) {
  const gap = isPlainObject(daemonGap) ? daemonGap : undefined;
  const seconds = (ms) => (Number.isSafeInteger(ms) && ms >= 0 ? String(Math.floor(ms / 1000)) : "unknown");
  return [contextPoint({
    ts,
    hmacKey,
    factName: HOST_DAEMON_GAP_FACT_NAME,
    entityKey: HOST_DAEMON_GAP_FACT_NAME,
    attributes: {
      collector_state: gap ? "ok" : "unable",
      obs_start_ms: msString(obsStartMs),
      obs_end_ms: msString(obsEndMs),
      rejected_field: "none",
      max_gap_s: gap && gap.wall_known === true ? seconds(gap.max_gap_ms) : "unknown",
      max_gap_uptime_s: !gap ? "unknown" : gap.boot_changed === true ? "not_applicable" : gap.uptime_known === true ? seconds(gap.max_gap_uptime_ms) : "unknown",
      observations: gap && Number.isSafeInteger(gap.observations) && gap.observations >= 0 ? String(Math.min(gap.observations, 1000000)) : "unknown",
      daemon_restarts: gap && Number.isSafeInteger(gap.restarts) && gap.restarts >= 0 ? String(Math.min(gap.restarts, 1000000)) : "unknown",
      boot_changed: gap ? (gap.boot_changed === true ? "true" : gap.boot_changed === false ? "false" : "unknown") : "unknown",
      expected_interval_s: seconds(intervalMs),
      cause: "unknown",
      cause_basis: "f3_inactive_c09_pending",
    },
  })];
}

// ------------------------------------------------------------------------------------------------
// Certification at derivation (I70).
// ------------------------------------------------------------------------------------------------

/**
 * Each cited source family's pass: certified when its pass committed this tick's facts with no error,
 * the ledger now names that same committed pass (no pending pass, continuity observed ok), and the
 * tick's ts lies above the family's floors (inside its certified span at this moment). A family that
 * wrote nothing this tick is cited as not contributing. Returns { cert: "certified" | "uncertified",
 * certd (a digest of every cited (family, generation, pass id, pass time, verdict)), families }.
 */
export function certifySourcePasses({ familyResults, ledgers, contributed, tsMs }) {
  const families = {};
  let certified = true;
  for (const family of SUMMARY_SOURCE_FAMILIES) {
    if (!contributed.has(family)) {
      families[family] = { verdict: "not_contributing", generation: null, pass_id: null, pass_time_ms: null, span_start_ms: null, span_end_ms: null };
      continue;
    }
    const result = familyResults?.[family];
    const ledger = ledgers?.[family];
    const retention = result?.retention;
    let verdict = "certified";
    if (!result || result.append_error || result.retention_error || !retention) verdict = "pass_failed";
    else if (!ledger || ledger.generation !== retention.ledger_generation || ledger.continuity?.last_committed_pass_id !== retention.pass_id || ledger.continuity?.pending_pass) verdict = "ledger_mismatch";
    else if (ledger.continuity?.continuity_ok === false) verdict = "continuity_lost";
    else {
      const floors = [ledger.bytecap_floor_ts, ledger.age_floor_ts].filter((v) => typeof v === "string").map((v) => Date.parse(v));
      if (floors.some((floorMs) => !(tsMs > floorMs))) verdict = "outside_certified_span";
    }
    if (verdict !== "certified") certified = false;
    const spanStart = ledger && [ledger.bytecap_floor_ts, ledger.age_floor_ts]
      .filter((value) => typeof value === "string")
      .map((value) => Date.parse(value))
      .filter(Number.isFinite)
      .reduce((max, value) => Math.max(max, value), Number.NEGATIVE_INFINITY);
    const spanEnd = Date.parse(ledger?.continuity?.last_rewrite_newest_ts ?? "");
    families[family] = {
      verdict,
      generation: retention?.ledger_generation ?? null,
      pass_id: retention?.pass_id ?? null,
      pass_time_ms: Number.isSafeInteger(retention?.pass_time_ms) ? retention.pass_time_ms : null,
      span_start_ms: Number.isFinite(spanStart) ? spanStart : null,
      span_end_ms: Number.isFinite(spanEnd) ? spanEnd : null,
    };
  }
  const tuples = Object.fromEntries(SUMMARY_SOURCE_FAMILIES.map((family) => [family, families[family]]));
  const material = canonicalJson({ tsMs, tuples });
  const everyTupleCertified = SUMMARY_SOURCE_FAMILIES.every((family) => tuples[family]?.verdict === "certified");
  return { cert: everyTupleCertified ? "certified" : "uncertified", certd: crypto.createHash("sha256").update(`descartes.tick_summary.cert.v1\u0000${material}`).digest("hex").slice(0, 16), families, tuples };
}

function certificateToken(value) {
  return value === null || value === undefined ? "-" : String(value);
}

function certificateRow(family, tuple) {
  return [
    SUMMARY_FAMILY_CODES[family],
    certificateToken(tuple?.generation),
    certificateToken(tuple?.pass_id),
    certificateToken(tuple?.pass_time_ms),
    certificateToken(tuple?.span_start_ms),
    certificateToken(tuple?.span_end_ms),
    certificateToken(tuple?.verdict),
  ].join("|");
}

function certificateTupleFromRow(row, expectedFamily) {
  if (typeof row !== "string") return undefined;
  const fields = row.split("|");
  if (fields.length !== 7 || SUMMARY_CODE_FAMILIES[fields[0]] !== expectedFamily) return undefined;
  const parseNullableInt = (value) => value === "-" ? null : (/^[0-9]+$/.test(value) && Number.isSafeInteger(Number(value)) ? Number(value) : undefined);
  const [, generation, passId, passTime, spanStart, spanEnd, verdict] = fields;
  const passTimeMs = parseNullableInt(passTime);
  const spanStartMs = parseNullableInt(spanStart);
  const spanEndMs = parseNullableInt(spanEnd);
  const normalizedPassId = passId === "-" ? null : (/^[0-9]+$/.test(passId) && Number.isSafeInteger(Number(passId)) ? Number(passId) : undefined);
  if (normalizedPassId === undefined || passTimeMs === undefined || spanStartMs === undefined || spanEndMs === undefined || !["certified", "not_contributing", "pass_failed", "ledger_mismatch", "continuity_lost", "outside_certified_span"].includes(verdict)) return undefined;
  return {
    generation: generation === "-" ? null : generation,
    pass_id: normalizedPassId,
    pass_time_ms: passTimeMs,
    span_start_ms: spanStartMs,
    span_end_ms: spanEndMs,
    verdict,
  };
}

function certificateDigest(tsMs, tuples) {
  const material = canonicalJson({ tsMs, tuples });
  return crypto.createHash("sha256").update(`descartes.tick_summary.cert.v1\u0000${material}`).digest("hex").slice(0, 16);
}

function certificatePoint({ ts, seq, tsMs, certification }) {
  if (!certification?.tuples) return undefined;
  const attributes = {
    seq: String(Math.min(seq, 2 ** 32)),
    ts_ms: String(Math.min(tsMs, 2 ** 47)),
    certd: certification.certd ?? "unknown",
    ...Object.fromEntries(SUMMARY_SOURCE_FAMILIES.map((family) => [SUMMARY_FAMILY_CODES[family], certificateRow(family, certification.tuples[family])])),
  };
  return enforceContextSchema({ ts, fact_name: "tick.summary_certificate", entity_key: `tick.summary_certificate.${Math.min(seq, 2 ** 32)}`, attributes, sensitivity: "operational" });
}

// ------------------------------------------------------------------------------------------------
// tick_summary (§8.1). Pure.
// ------------------------------------------------------------------------------------------------

/** The record digest the next record's `prev` names: over the normalized record (sorted keys). */
export function tickSummaryDigest(point) {
  const normalized = normalizeFactPoint(point);
  const material = canonicalJson({ ts: normalized.ts, fact_name: normalized.fact_name, attributes: normalized.attributes });
  return crypto.createHash("sha256").update(`descartes.tick_summary.chain.v1\u0000${material}`).digest("hex").slice(0, 16);
}

function intOrUnknown(value, max = 100000) {
  return Number.isSafeInteger(value) && value >= 0 ? String(Math.min(value, max)) : "unknown";
}

function patternOrUnknown(value, re) {
  return typeof value === "string" && re.test(value) ? value : "unknown";
}

const EXPOSURE_BASIS_CODES = Object.freeze({ cross_boot: "xb", no_previous_reading: "np", uptime_regressed: "ur" });
function exposureBasis(snapshot, suspend) {
  if (!suspend) return "u";
  if (suspend.interval_basis === "same_boot_uptime_delta") return snapshot.platform === "linux" ? "bt" : snapshot.platform === "darwin" ? "ud" : "u";
  return EXPOSURE_BASIS_CODES[suspend.interval_basis] ?? "u";
}

function presenceCode(value) {
  return value === "true" ? "t" : value === "false" ? "f" : value === "not_applicable" ? "n" : "u";
}

/**
 * Builds this tick's tick.summary point and the next chain state. `prior` is the read of the chain
 * state ({ status, state? }); `storeHadSummaries` says whether tick_summary already held records (a
 * missing state over an existing store is a restart, never a fresh start); `lastSeq` is the last seq
 * found in the store (only used to keep seq increasing across a restart).
 */
export function deriveTickSummary({ snapshot, prior, storeHadSummaries, lastSeq, certification, transitions, hmacKey, version, cfg, gapCount = 0, futureLossMarker = null }) {
  const prevState = prior?.status === "valid" ? prior.state : undefined;
  const hasGap = gapCount === "unknown" || Number.isSafeInteger(gapCount) && gapCount > 0;
  const chain = hasGap ? "gap" : prevState ? "continued" : storeHadSummaries ? "restarted" : "started";
  const seq = prevState ? prevState.seq + 1 : Number.isSafeInteger(lastSeq) ? lastSeq + 1 : 0;
  const sessionChurn = intervalChurn(hasGap ? undefined : prevState?.session, snapshot.session);
  const peerChurn = intervalChurn(hasGap ? undefined : prevState?.peer, snapshot.peer);
  const cross = transitions?.cross ?? wallCrossCheck(prevState?.context, snapshot);
  const suspend = snapshot.suspend;
  const exposureHi = Number.isSafeInteger(suspend?.exposure_upper_s) ? suspend.exposure_upper_s : undefined;
  const tn = snapshot.tailnet ? `${SUMMARY_TAILNET_STATE_CODES[snapshot.tailnet.state] ?? "u"}${snapshot.tailnet.online === "true" ? "t" : snapshot.tailnet.online === "false" ? "f" : "u"}` : "uu";
  const offset = (ms) => (Number.isSafeInteger(ms) && ms >= snapshot.tsMs && ms - snapshot.tsMs < 100_000 ? String(Math.floor((ms - snapshot.tsMs) / 100)) : "-");
  const wallOffset = Number.isSafeInteger(snapshot.clocks.wallMs) && Math.abs(snapshot.clocks.wallMs - snapshot.tsMs) < 1_000_000 ? String(snapshot.clocks.wallMs - snapshot.tsMs) : "unknown";
  const na = (platform) => (snapshot.platform === platform ? undefined : "na");
  const attributes = {
    seq: String(Math.min(seq, 2 ** 32)),
    prev: prevState ? prevState.record_digest : chain === "started" ? "none" : "unknown",
    chain,
    g: gapCount === "unknown" ? "unknown" : Math.min(hasGap ? gapCount : 0, 2 ** 32).toString(36),
    cert: certification?.cert ?? "unknown",
    cd: certification?.certd ?? "unknown",
    kid: contextKeyId(hmacKey),
    ver: patternOrUnknown(version, /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}$/),
    cfg: patternOrUnknown(cfg, HEX16_RE),
    cs: patternOrUnknown(snapshot.collectors, /^[opunftmad]{7}$/),
    ob: `${offset(snapshot.obsSpan?.startMs)}-${offset(snapshot.obsSpan?.endMs)}`,
    sn: intOrUnknown(snapshot.session.count),
    scs: snapshot.session.census,
    sa: intOrUnknown(sessionChurn.arrivals),
    sd: intOrUnknown(sessionChurn.departures),
    su: universeDigest(hmacKey, "summary_session_universe", snapshot.session),
    ss: setDigest(hmacKey, "summary_session_set", snapshot.session),
    pn: intOrUnknown(snapshot.peer.count),
    pcs: snapshot.peer.census,
    pa: intOrUnknown(peerChurn.arrivals),
    pd: intOrUnknown(peerChurn.departures),
    pu: universeDigest(hmacKey, "summary_peer_universe", snapshot.peer),
    ps: setDigest(hmacKey, "summary_peer_set", snapshot.peer),
    boot: patternOrUnknown(snapshot.boot.hmac, HEX16_RE),
    bv: snapshot.boot.verdict === undefined ? "n" : { verified: "v", unverified: "u", tripwire: "t" }[snapshot.boot.verdict] ?? "x",
    ex: exposureHi !== undefined && exposureHi < 1e10 ? `0-${exposureHi}` : "unknown",
    exb: exposureBasis(snapshot, suspend),
    wd: cross.wallDeltaMs !== undefined && Math.abs(cross.wallDeltaMs) < 1e13 ? String(Math.trunc(cross.wallDeltaMs / 1000)) : "unknown",
    wx: cross.code,
    tn,
    vn: intOrUnknown(snapshot.vpn?.total),
    vc: intOrUnknown(snapshot.vpn?.connected),
    vd: ["none", "unknown"].includes(snapshot.vpn?.digest) || HEX16_RE.test(snapshot.vpn?.digest ?? "") ? snapshot.vpn.digest : "unknown",
    net: patternOrUnknown(snapshot.net, HEX16_RE),
    tzo: Number.isSafeInteger(snapshot.clocks.utcOffsetMin) ? String(snapshot.clocks.utcOffsetMin) : "unknown",
    tz: patternOrUnknown(snapshot.clocks.tzHmac, HEX16_RE),
    pr: snapshot.presence ? `${presenceCode(snapshot.presence.locked)}${presenceCode(snapshot.presence.idle)}` : "uu",
    ev: transitions?.events ?? "unknown",
    wo: wallOffset,
    hr: patternOrUnknown(snapshot.clocks.hrtimeNs, /^[0-9]{1,20}$/),
    upm: intOrUnknown(snapshot.clocks.uptimeMs, 2 ** 47),
    mono: snapshot.platform !== "darwin" && snapshot.platform !== "linux" ? "na" : patternOrUnknown(snapshot.clocks.mono, /^([0-9]{1,20} [0-9]{1,20}|[0-9]{1,12}\.[0-9]{1,9})$/),
    wak: na("darwin") ?? intOrUnknown(snapshot.clocks.wakeS, 2 ** 37),
    wab: na("darwin") ?? patternOrUnknown(snapshot.clocks.wakeAbs, /^[0-9]{1,20}$/),
    wct: na("darwin") ?? patternOrUnknown(snapshot.clocks.wakeCont, /^[0-9]{1,20}$/),
    ssc: na("linux") ?? intOrUnknown(snapshot.clocks.suspendSuccess, 2 ** 40),
  };
  const point = enforceContextSchema({ ts: snapshot.ts, fact_name: TICK_SUMMARY_FACT_NAME, entity_key: TICK_SUMMARY_FACT_NAME, attributes, sensitivity: "operational" });
  const digest = tickSummaryDigest(point);
  const certificate = certificatePoint({ ts: snapshot.ts, seq, tsMs: snapshot.tsMs, certification });
  const nextState = (generation, passId) => ({
    schema_version: CHAIN_STATE_VERSION,
    family: "tick_summary",
    ledger_generation: generation,
    ledger_pass_id: passId,
    future_loss_marker: futureLossMarker ?? prevState?.future_loss_marker ?? null,
    hmac_key_id: contextKeyId(hmacKey),
    seq: Math.min(seq, 2 ** 32),
    record_digest: digest,
    record_ts: snapshot.ts,
    session: sourceStateOf(snapshot.session),
    peer: sourceStateOf(snapshot.peer),
    context: snapshotContextState(snapshot, prevState?.context),
  });
  return { point, certificatePoint: certificate, digest, seq, chain, sessionChurn, peerChurn, nextState };
}

/**
 * The reader's validity rule (I70): a record is valid while its OWN chain and family ledger are
 * continuous; the source families' current spans are never re-checked (intentional age or byte
 * eviction of the source facts is not loss). Walks seq-ordered tick.summary points and returns
 * { records, losses: [{ ts, reason }] }. The first retained record's predecessor may have been evicted
 * on purpose (not a loss); a "restarted" record, a broken prev link, a seq that does not follow, or a
 * later "started" is a loss marker at that record, never silence. The records themselves stay valid
 * data (each passed its closed schema); a loss marks the GAP before a record.
 */
export function verifyTickSummaryChain(points) {
  // C2 review L6: walked in seq order (ts only breaks a tie), so a backward wall step between two
  // records is never a spurious prev_mismatch. seq never decreases across a restart (lastSeq + 1).
  const seqOf = (point) => {
    const seq = Number(point.attributes?.seq);
    return Number.isSafeInteger(seq) ? seq : Number.MAX_SAFE_INTEGER;
  };
  const summaries = (points ?? []).filter((p) => p?.fact_name === TICK_SUMMARY_FACT_NAME)
    .sort((a, b) => seqOf(a) - seqOf(b) || Date.parse(a.ts) - Date.parse(b.ts));
  const records = [];
  const losses = [];
  const certificates = new Map();
  for (const point of points ?? []) {
    if (point?.fact_name !== "tick.summary_certificate") continue;
    const attrs = point.attributes ?? {};
    const seq = Number(attrs.seq);
    const tuples = Object.fromEntries(SUMMARY_SOURCE_FAMILIES.map((family) => [family, certificateTupleFromRow(attrs[SUMMARY_FAMILY_CODES[family]], family)]));
    if (Number.isSafeInteger(seq)) certificates.set(seq, { point, attrs, tuples });
  }
  let previous;
  for (const point of summaries) {
    const attrs = point.attributes ?? {};
    let reason;
    if (previous) {
      if (attrs.chain === "continued") {
        if (attrs.prev !== tickSummaryDigest(previous)) reason = "prev_mismatch";
        else if (String(Number(previous.attributes?.seq) + 1) !== attrs.seq) reason = "seq_gap";
      } else if (attrs.chain === "restarted" || attrs.chain === "gap") reason = attrs.chain;
      else reason = attrs.chain === "started" ? "started_after_records" : "chain_unknown";
    } else if (attrs.chain === "restarted" || attrs.chain === "gap") reason = attrs.chain;
    const requiresCertificate = attrs.cert !== undefined || attrs.cd !== undefined;
    if (requiresCertificate) {
      const certificate = certificates.get(Number(attrs.seq));
      const tuples = certificate?.tuples;
      const complete = tuples && SUMMARY_SOURCE_FAMILIES.every((family) => tuples[family] !== undefined);
      if (!certificate) reason = reason ?? "certificate_missing";
      else if (!complete || certificate.attrs.certd !== attrs.cd || certificate.attrs.ts_ms !== String(Date.parse(point.ts)) || certificateDigest(Date.parse(point.ts), tuples) !== attrs.cd) reason = reason ?? "certificate_mismatch";
      else if (attrs.cert !== (SUMMARY_SOURCE_FAMILIES.every((family) => tuples[family].verdict === "certified") ? "certified" : "uncertified")) reason = reason ?? "certificate_mismatch";
    }
    if (reason) losses.push({ ts: point.ts, reason });
    records.push(point);
    previous = point;
  }
  return { records, losses };
}

// ------------------------------------------------------------------------------------------------
// Long-lived statistics skeleton (§8.2). DATA ONLY.
// ------------------------------------------------------------------------------------------------

const STATS_STATE_KEYS = ["schema_version", "family", "ledger_generation", "ledger_pass_id", "future_loss_marker", "episode", "daily", "memory_lost_count", "memory_lost_ts"];
const EPISODE_KEYS = ["eseq", "kind", "ev", "offset", "cert", "pre_session", "pre_peer"];
const DAILY_KEYS = ["day", "memory", "cert", "clock_step", "intervals", "uncertified_ticks", "uncertified_exposure_s", "s_known", "p_known", "s_arr", "s_dep", "p_arr", "p_dep", "ex_hi_s", "ex_known", "first_seq", "last_seq"];
const DAILY_COUNTERS = DAILY_KEYS.filter((key) => !["day", "memory", "cert", "clock_step"].includes(key));

function validCounter(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

export function isValidStatsState(value) {
  if (!exactKeys(value, STATS_STATE_KEYS)) return false;
  if (value.schema_version !== STATS_STATE_VERSION || value.family !== "context_stats") return false;
  if (typeof value.ledger_generation !== "string" || value.ledger_generation.length === 0 || value.ledger_generation.length > 64) return false;
  if (!validCounter(value.ledger_pass_id) || !validCounter(value.memory_lost_count)) return false;
  if (!optionalTimestamp(value.future_loss_marker)) return false;
  if (value.memory_lost_ts !== null && (typeof value.memory_lost_ts !== "string" || !Number.isFinite(Date.parse(value.memory_lost_ts)))) return false;
  if (value.episode !== null) {
    const e = value.episode;
    if (!exactKeys(e, EPISODE_KEYS) || !validCounter(e.eseq) || ![...TRANSITION_DIMENSIONS].includes(e.kind)) return false;
    if (typeof e.ev !== "string" || !SUMMARY_EVENTS_RE.test(e.ev) || !Number.isSafeInteger(e.offset) || e.offset < 0 || e.offset > EPISODE_MAX_OFFSET) return false;
    if (!validSourceState(e.pre_session, SUMMARY_MAX_SESSION_ENTITIES) || !validSourceState(e.pre_peer, SUMMARY_MAX_PEER_ENTITIES)) return false;
  }
  if (value.daily !== null) {
    const d = value.daily;
    if (!exactKeys(d, DAILY_KEYS) || typeof d.day !== "string" || !DAY_RE.test(d.day)) return false;
    if (!["continuous", "first_run", "cold_start_after_loss"].includes(d.memory)) return false;
    if (!["certified", "mixed", "uncertified", "unknown"].includes(d.cert) || !["true", "false"].includes(d.clock_step)) return false;
    if (!DAILY_COUNTERS.every((k) => validCounter(d[k]))) return false;
  }
  return true;
}

/**
 * The stats state read and checked against context_stats's ledger as it stands before this tick's
 * pass. Returns { status, state? } like readSummaryChainState, plus whether the store already existed
 * (a missing or invalid state over an existing store is memory LOSS, §8.2; over no store, a first run).
 */
export async function readStatsState(descartesPaths, { ledger } = {}) {
  const read = await readJsonFile(resolveStatsStatePath(descartesPaths));
  if (read.status !== "ok") return { status: read.status };
  if (!isValidStatsState(read.value)) return { status: "invalid" };
  const state = read.value;
  if (!ledger) return { status: "no_ledger" };
  if (ledger.continuity?.pending_pass) return { status: "pending_pass" };
  if (await familyLedgerHasLoss(descartesPaths, "context_stats", ledger, state.future_loss_marker)) return { status: "continuity_lost" };
  if (state.ledger_generation !== ledger.generation || state.ledger_pass_id !== ledger.continuity?.last_committed_pass_id) return { status: "lineage_mismatch" };
  return { status: "valid", state };
}

export async function writeStatsState(descartesPaths, state) {
  if (!isValidStatsState(state)) throw new Error("context_stats state fails its own shape");
  await writeJsonFile(resolveStatsStatePath(descartesPaths), state);
}

function utcDay(tsMs) {
  return new Date(tsMs).toISOString().slice(0, 10);
}

function emptyDaily(day, memory, seq) {
  return { day, memory, cert: "certified", clock_step: "false", intervals: 0, uncertified_ticks: 0, uncertified_exposure_s: 0, s_known: 0, p_known: 0, s_arr: 0, s_dep: 0, p_arr: 0, p_dep: 0, ex_hi_s: 0, ex_known: 0, first_seq: seq, last_seq: seq };
}

function episodeIdentityStats(pre, cur) {
  // pre: a chain-state source ({census, universe, entities: [[k, fp]] | null}); cur: a snapshot source.
  if (!pre || !Array.isArray(pre.entities) || pre.census !== "c") return { st: "no_pre_set" };
  if (cur.census !== "c" || !(cur.entities instanceof Map)) return { st: "census_incomplete" };
  if ((pre.universe ?? null) !== (cur.universe ?? null)) return { st: "universe_changed" };
  const preMap = new Map(pre.entities);
  // same: same key and the same known creation fingerprint (the instance survived); recr: same key, a
  // different known fingerprint (a same-name recreation). A key whose fingerprint is unknown on either
  // side (screen exposes no creation time) is neither: pre - same - recr - dep is that ambiguous count.
  let same = 0;
  let recr = 0;
  let dep = 0;
  for (const [key, fp] of preMap) {
    if (!cur.entities.has(key)) dep += 1;
    else if (fp === "unknown" || cur.entities.get(key) === "unknown") continue;
    else if (cur.entities.get(key) === fp) same += 1;
    else recr += 1;
  }
  let arr = 0;
  for (const key of cur.entities.keys()) if (!preMap.has(key)) arr += 1;
  return { st: "ok", pre: preMap.size, post: cur.entities.size, same, recr, dep, arr };
}

function episodePoint({ ts, episode, offset, seq, sessionStats, peerStats }) {
  const attrs = { eseq: String(episode.eseq), sseq: String(seq), kind: episode.kind, ev: episode.ev, off: String(offset), cert: episode.cert ?? "unknown" };
  for (const [prefix, stats] of [["s", sessionStats], ["p", peerStats]]) {
    for (const stat of ["pre", "post", "same", "recr", "dep", "arr"]) attrs[`${prefix}_${stat}`] = intOrUnknown(stats[stat]);
    attrs[`${prefix}_st`] = stats.st ?? "unknown";
  }
  return enforceContextSchema({ ts, fact_name: STATS_EPISODE_FACT_NAME, entity_key: `${STATS_EPISODE_FACT_NAME}.${episode.eseq}`, attributes: attrs, sensitivity: "operational" });
}

function dailyPoint(ts, daily) {
  const attrs = { day: daily.day, memory: daily.memory, cert: daily.cert, clock_step: daily.clock_step };
  for (const key of DAILY_COUNTERS) attrs[key] = String(daily[key]);
  return enforceContextSchema({ ts, fact_name: STATS_DAILY_FACT_NAME, entity_key: `${STATS_DAILY_FACT_NAME}.${daily.day}`, attributes: attrs, sensitivity: "operational" });
}

// Episode kinds by priority (one open episode at a time; a later event opens a new one).
const EPISODE_KIND_PRIORITY = ["boot", "wake", "tailnet", "vpn", "net_config"];

/**
 * One structural tick folded into the long-lived statistics. Pure. `prior` is the read of the stats
 * state; `storeExisted` says whether context_stats already had a store (loss vs first run). Returns
 * { points, nextState(generation, passId), memoryLost }. Per-episode identity statistics (offset 0 at
 * the opening tick, then 1 and 2) are computed here, while the raw census sets exist; the pre-event set
 * is the previous chain state's. Daily records close when the UTC day changes.
 */
export function deriveStats({ prior, storeExisted, prevChain, snapshot, transitions, summary, nowIso, futureLossMarker = null }) {
  const prevState = prior?.status === "valid" ? prior.state : undefined;
  const summaryChain = summary.point?.attributes?.chain;
  const certified = summary.point?.attributes?.cert === "certified";
  const memoryLost = (!prevState && storeExisted) || (storeExisted && ["restarted", "gap"].includes(summaryChain));
  const points = [];
  const day = utcDay(snapshot.tsMs);
  let daily = prevState?.daily ?? null;
  if (daily && day > daily.day) {
    points.push(dailyPoint(snapshot.ts, daily));
    daily = null;
  } else if (daily && day < daily.day) {
    // A backward wall-clock step must not create a second bucket for a day already in progress.
    daily = { ...daily, clock_step: "true" };
  }
  if (!daily) daily = emptyDaily(day, prevState ? "continuous" : memoryLost ? "cold_start_after_loss" : "first_run", summary.seq);
  daily = { ...daily };
  daily.intervals += 1;
  daily.last_seq = summary.seq;
  if (!certified) {
    daily.uncertified_ticks += 1;
    daily.cert = daily.uncertified_ticks === daily.intervals ? "uncertified" : "mixed";
    if (Number.isSafeInteger(snapshot.suspend?.exposure_upper_s)) daily.uncertified_exposure_s += snapshot.suspend.exposure_upper_s;
  } else {
    daily.cert = daily.uncertified_ticks > 0 ? "mixed" : "certified";
    // Each source on its own knownness: an interval whose peer census was incomplete still counts the
    // session churn it observed, and vice versa (never a zero for the unknown one).
    if (summary.sessionChurn.arrivals !== undefined) {
      daily.s_known += 1;
      daily.s_arr += summary.sessionChurn.arrivals;
      daily.s_dep += summary.sessionChurn.departures;
    }
    if (summary.peerChurn.arrivals !== undefined) {
      daily.p_known += 1;
      daily.p_arr += summary.peerChurn.arrivals;
      daily.p_dep += summary.peerChurn.departures;
    }
    if (Number.isSafeInteger(snapshot.suspend?.exposure_upper_s)) {
      daily.ex_known += 1;
      daily.ex_hi_s += snapshot.suspend.exposure_upper_s;
    }
  }
  // Episodes are authority-bearing statistics only for certified summaries. An uncertified tick is a
  // barrier: retaining the open episode would fold its next certified sample across unknown time.
  let episode = certified ? prevState?.episode ?? null : null;
  const kind = certified ? EPISODE_KIND_PRIORITY.find((dimension) => (transitions?.transitions ?? []).some((t) => t.dimension === dimension)) : undefined;
  if (kind) {
    episode = { eseq: summary.seq, kind, ev: transitions.events ?? "uuuuuuuu", offset: 0, cert: "certified", pre_session: prevChain?.session ?? null, pre_peer: prevChain?.peer ?? null };
    if (!prevChain) episode = { ...episode, pre_session: null, pre_peer: null };
  } else if (episode) {
    episode = { ...episode, offset: episode.offset + 1, cert: "certified" };
    if (episode.offset > EPISODE_MAX_OFFSET) episode = null;
  }
  if (episode) {
    points.push(episodePoint({
      ts: snapshot.ts,
      episode,
      offset: episode.offset,
      seq: summary.seq,
      sessionStats: episodeIdentityStats(episode.pre_session, snapshot.session),
      peerStats: episodeIdentityStats(episode.pre_peer, snapshot.peer),
    }));
    if (episode.offset >= EPISODE_MAX_OFFSET) episode = null;
  }
  const nextState = (generation, passId) => ({
    schema_version: STATS_STATE_VERSION,
    family: "context_stats",
    ledger_generation: generation,
    ledger_pass_id: passId,
    future_loss_marker: futureLossMarker ?? prevState?.future_loss_marker ?? null,
    episode: episode ? {
      ...episode,
      pre_session: episode.pre_session && isPlainObject(episode.pre_session) ? episode.pre_session : { census: "u", universe: null, entities: null },
      pre_peer: episode.pre_peer && isPlainObject(episode.pre_peer) ? episode.pre_peer : { census: "u", universe: null, entities: null },
    } : null,
    daily,
    memory_lost_count: (prevState?.memory_lost_count ?? 0) + (memoryLost ? 1 : 0),
    memory_lost_ts: memoryLost ? nowIso : prevState?.memory_lost_ts ?? null,
  });
  return { points, nextState, memoryLost };
}
