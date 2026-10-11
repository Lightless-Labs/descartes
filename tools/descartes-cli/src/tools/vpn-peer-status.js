// Slice 3 (observed-incident collectors plan, docs/plans/2026-07-13-observed-incident-
// collectors.md) -- VPN/SSH peer identity baseline collector for `collect_vpn_peer_status`.
//
// Read-only, fixed-argv `execFile` (no shell, no shell-string args, no mutating flags), wrapped
// in the existing timedEnvelope fail-closed pattern -- mirrors tools/sessions.js's shape exactly.
//
// SOURCES:
//   - SSH login census: fixed `who` (currently logged-in sessions with a remote host).
//   - SSH login history: fixed, BOUNDED `last -n <N>` (must-fix 3, mirrors sessions.js's
//     DEFAULT_SESSION_ENTITY_LIMIT precedent) -- NEVER an unbounded wtmp read.
//   - WireGuard peers: a CLOSED, FIXED-ARGV ALLOWLIST -- see the "WireGuard: CLOSED ALLOWLIST"
//     block below, which is the COMPLETE set of `wg` invocations this file may ever construct.
//   - macOS VPN service state: fixed `scutil --nc list` (darwin only).
//   - Established-inbound cross-reference: `ss`/`netstat` (lowest-confidence, first-to-cut;
//     kept as raw operator-triage context only -- never translated into a persisted peer fact).
//
// Degrade-not-fabricate (hard requirement, per source): a binary missing from the pinned known
// paths (including ENOENT) degrades to "not_found_on_known_paths"; a binary that runs but is denied by the OS (EACCES/EPERM, or
// wg's own "Permission denied"/"Operation not permitted" stderr text) degrades to
// "missing_permission" and is NEVER escalated (no sudo/pkexec/setcap/doas -- see the escalation
// lint, test/escalation-lint.test.js, which scans this file too); a binary that runs and
// genuinely reports ZERO peers/logins is a REAL, DISTINGUISHABLE fact -- "ok", empty result --
// never conflated with "unable". `wg show <interface> ...` commonly needs root even for
// read-only status queries on both macOS and Linux -- a permission-denied result there sets
// `elevation_candidate: true` as a pure DOCUMENTATION marker (the S3-priv opt-in path, already
// shipped, would be the correct place to add elevated WireGuard reads later) -- this file never
// escalates privilege itself.
//
// Per-tick PEER ENTITY CAP (must-fix 3): mirrors DEFAULT_SESSION_ENTITY_LIMIT=200. When the real
// combined peer count exceeds the cap, `truncated: true` and `total_count` are carried on the
// result so fact-translators.js can emit an explicit overflow marker fact -- entities are never
// silently dropped with no indication anything was truncated.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { binaryProvenance, isBinaryNotFound, isBinaryUntrusted, runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { isLastDateStart, isLocalLoginHost } from "./login-origin.js";
import { readSharedLastHistory } from "./last-history.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_PEER_ENTITY_LIMIT = 200;
// Fact-store capacity plan §2/S4: hard UPPER clamp (the peer fact family's budget invariant, T8, is
// sized against it together with MAX_TAILSCALE_PEER_ENTITY_LIMIT).
export const MAX_PEER_ENTITY_LIMIT = 200;

// Bounded `last -n <N>` (must-fix 3, fixture-pinned): an unbounded `last` can return months of
// wtmp history, which would flood fact-history and evict other collectors' facts out of the
// shared fact-store.js retention cap. 50 is a generous recent-history window without being
// unbounded.
export const DEFAULT_LAST_HISTORY_LIMIT = 50;

// Defensive bound on the number of WireGuard interfaces this collector will enumerate peers for
// in one tick -- not called out explicitly by the plan, but consistent with every other
// per-tick cap in this codebase (a pathological number of configured interfaces should degrade
// gracefully, not fan out into an unbounded number of execFile calls).
const MAX_WG_INTERFACES = 16;

async function runFixedExecFile(command, args, options = {}) {
  return runResolvedExecFile(command, args, {
    ...options,
    timeout: options.timeout ?? 3000,
    maxBuffer: options.maxBuffer ?? 256 * 1024,
    execFileAsync,
  });
}

function probeOptions(options, overrides = {}) {
  const { runFixedExecFile: _injectedRunner, ...resolverOptions } = options;
  return { ...resolverOptions, ...overrides };
}

function isPermissionDenied(probe) {
  if (probe.code === "EACCES" || probe.code === "EPERM") return true;
  const text = `${probe.stdout ?? ""}\n${probe.stderr ?? ""}`.toLowerCase();
  return /permission denied|operation not permitted|must be run as root|requires? (root|elevated) (privileges|access)/.test(text);
}

// ---------------------------------------------------------------------------------------------
// who -- SSH/remote login census (currently logged in).
// ---------------------------------------------------------------------------------------------

// Matches "<user>  <tty>  <date/time...>  (<remote host>)" -- the trailing parenthetical remote
// host is who's own genuine remote-login signal on both GNU (Linux) and BSD (macOS) `who`. A
// local console/tty login has no trailing parens at all -- `remote_host` stays undefined for it,
// which the collector treats as "not a peer" (a real, distinguishable local session), never as
// malformed input.
//
// Context plan C0.4 (Opus M3, Astra 12): the parenthetical is not always a remote host. An X display
// "(:0)", a GNU screen tag "(:pts/3:S.0)" and a tmux tag "(tmux(1234).%0)" are LOCAL attachments
// and are no longer read as peers (login-origin.js holds the explicit patterns). The whole trailing
// parenthetical is captured, so a nested tmux tag is classified rather than half-matched.
const WHO_LINE_RE = /^(\S+)\s+(\S+)\s+[^(]*?(?:\((.+)\))?\s*$/;

export function parseWhoOutput(stdout) {
  const entries = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(WHO_LINE_RE);
    if (!match) continue; // unparseable line -- skipped, never fabricated into a partial entry
    const [, user, tty, host] = match;
    const remoteHost = host && !isLocalLoginHost(host, tty) ? host : undefined;
    entries.push({ remote_user: user, remote_host: remoteHost });
  }
  return { entries };
}

async function collectSshWho(options) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const probe = await runExec("who", [], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
  if (probe.status === "ok") {
    const { entries } = parseWhoOutput(probe.stdout);
    return { status: "ok", entries, command: probe.command, binary: probe.binary };
  }
  if (isBinaryNotFound(probe)) return { status: "not_found_on_known_paths", entries: [], command: probe.command, binary: probe.binary };
  if (isBinaryUntrusted(probe)) return { status: "untrusted_binary", entries: [], error: probe.error, command: probe.command, binary: probe.binary };
  if (isPermissionDenied(probe)) return { status: "missing_permission", entries: [], error: probe.error, command: probe.command, binary: probe.binary };
  return { status: "unable", entries: [], error: probe.error, command: probe.command, binary: probe.binary };
}

// ---------------------------------------------------------------------------------------------
// last -n <N> -- bounded SSH/remote login HISTORY.
// ---------------------------------------------------------------------------------------------

// Pseudo-entries that are never real peers: `reboot`/`shutdown` synthetic rows (whose own tty/
// host-shaped columns are actually kernel-version/boot-context text, not a real remote host --
// deliberately excluded by user rather than guessed at from the host column) and the trailing
// "wtmp begins ..." banner line some `last` implementations print.
const LAST_PSEUDO_USER_RE = /^(reboot|shutdown)$/i;
const LAST_TRAILER_RE = /^wtmp\s+begins/i;
// A "local" third column: no remote host at all (BSD/macOS `last` prints "-" or an empty-ish
// placeholder for a console/tty login; GNU `last` may print a local tty/console marker). Any of
// these mean "not a remote peer", not malformed.
const LAST_LOCAL_HOST_RE = /^(-|:0(\.0)?|console)$/i;

/**
 * Pure parser for bounded `last -n <N>` output. Per-platform `last` hostname-truncation fixtures
 * (must-fix 7) are pinned in test/vpn-peer-status.test.js: BSD/macOS `last` and Linux `last` both
 * print `<user> <tty> <host> <date/time...>` as whitespace-separated columns (host possibly
 * truncated to a fixed width by the utility itself) -- this parser takes exactly the first three
 * whitespace tokens as user/tty/host verbatim, never assuming a fixed column width itself, so
 * whatever `last` already printed (truncated or not) is what gets captured.
 */
export function parseLastOutput(stdout) {
  const entries = [];
  let malformedCount = 0;
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || LAST_TRAILER_RE.test(line)) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 3) {
      malformedCount += 1;
      continue;
    }
    const [user, tty, host] = tokens;
    if (LAST_PSEUDO_USER_RE.test(user)) continue; // reboot/shutdown -- not a peer, not malformed
    // C0.4: a local row has NO host column, so the third token is the date ("Fri Sep  4 ..."); it
    // used to be read as a remote host named "Fri". An explicit local attachment tag is local too.
    if (isLastDateStart(host, tokens[3])) continue;
    if (LAST_LOCAL_HOST_RE.test(host) || isLocalLoginHost(host, tty)) continue; // local session -- not a peer, not malformed
    entries.push({ remote_user: user, remote_host: host });
  }
  return { entries, malformed_count: malformedCount };
}

async function collectSshLast(options) {
  const n = Math.max(1, Number(options.lastHistoryLimit) || DEFAULT_LAST_HISTORY_LIMIT);
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const shared = await readSharedLastHistory(options, runExec, probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }), n);
  const probe = shared.probe;
  if (probe.status === "ok") {
    const entries = shared.rows
      .filter((row) => row.host && !isLocalLoginHost(row.host, row.tty))
      .map((row) => ({ remote_user: row.user, remote_host: row.host }));
    const malformed_count = shared.malformed;
    return { status: "ok", entries, malformed_count, requested_n: n, command: probe.command, binary: probe.binary };
  }
  if (isBinaryNotFound(probe)) return { status: "not_found_on_known_paths", entries: [], requested_n: n, command: probe.command, binary: probe.binary };
  if (isBinaryUntrusted(probe)) return { status: "untrusted_binary", entries: [], requested_n: n, error: probe.error, command: probe.command, binary: probe.binary };
  if (isPermissionDenied(probe)) return { status: "missing_permission", entries: [], requested_n: n, error: probe.error, command: probe.command, binary: probe.binary };
  return { status: "unable", entries: [], requested_n: n, error: probe.error, command: probe.command, binary: probe.binary };
}

// ---------------------------------------------------------------------------------------------
// WireGuard: CLOSED ALLOWLIST.
//
// The four functions immediately below are the COMPLETE, PINNED set of `wg` invocations this
// file may ever construct: `wg show interfaces` (enumerate), then per enumerated interface
// `wg show <if> peers`, `wg show <if> endpoints`, `wg show <if> latest-handshakes`. Each argv is
// a hardcoded array literal -- never built from a variable subcommand, a joined string, or a
// loop over an open-ended list -- so a static read of this file's source is sufficient to
// confirm no other `wg` argv is constructible (test/vpn-peer-status.test.js's allowlist negative
// test does exactly this, plus a fixture-driven behavioral check).
//
// NEVER add a fifth `wg` invocation here. In particular NEVER:
//   - `wg show <if> dump`        -- leaks the interface PRIVATE KEY and every peer's PRESHARED key
//   - `wg showconf <if>`         -- prints `PrivateKey=`/`PresharedKey=` directly
//   - `wg show <if> private-key` -- leaks the interface PRIVATE KEY
//   - `wg show <if> preshared-keys` -- leaks every peer's PRESHARED key
//
// execFile (not exec/spawn-with-shell) is used throughout, so there is no shell parsing at all:
// even an adversarial interface name (from a compromised/crafted wg config) is passed as a
// single argv array element, never concatenated into a shell string -- it cannot smuggle in an
// additional subcommand token, only ever occupy the one "<if>" array slot.
// ---------------------------------------------------------------------------------------------

async function wgShowInterfaces(runExec, options) {
  return runExec("wg", ["show", "interfaces"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
}
async function wgShowPeers(runExec, iface, options) {
  return runExec("wg", ["show", iface, "peers"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
}
async function wgShowEndpoints(runExec, iface, options) {
  return runExec("wg", ["show", iface, "endpoints"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
}
async function wgShowLatestHandshakes(runExec, iface, options) {
  return runExec("wg", ["show", iface, "latest-handshakes"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
}

export function parseWgInterfaceList(stdout) {
  return String(stdout ?? "").split(/\s+/).map((s) => s.trim()).filter(Boolean);
}

export function parseWgPeerList(stdout) {
  return String(stdout ?? "").split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
}

export function parseWgEndpoints(stdout) {
  const map = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const [pubkey, endpoint] = line.split("\t");
    if (!pubkey) continue;
    map[pubkey] = endpoint && endpoint !== "(none)" ? endpoint : undefined;
  }
  return map;
}

export function parseWgHandshakes(stdout) {
  const map = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const [pubkey, epochText] = line.split("\t");
    if (!pubkey) continue;
    const epoch = Number(epochText);
    map[pubkey] = Number.isFinite(epoch) ? epoch : undefined;
  }
  return map;
}

async function collectWireguardPeers(options) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const listProbe = await wgShowInterfaces(runExec, options);

  if (isBinaryNotFound(listProbe)) {
    return { status: "not_found_on_known_paths", interfaces: [], peers: [], elevation_candidate: false, binary: listProbe.binary };
  }
  if (isBinaryUntrusted(listProbe)) {
    return { status: "untrusted_binary", interfaces: [], peers: [], elevation_candidate: false, error: listProbe.error, binary: listProbe.binary };
  }
  if (listProbe.status !== "ok") {
    const elevationCandidate = isPermissionDenied(listProbe);
    return {
      status: elevationCandidate ? "missing_permission" : "unable",
      interfaces: [],
      peers: [],
      elevation_candidate: elevationCandidate,
      error: listProbe.error,
      binary: listProbe.binary,
    };
  }

  const allInterfaceNames = parseWgInterfaceList(listProbe.stdout);
  const interfaceNames = allInterfaceNames.slice(0, MAX_WG_INTERFACES);
  const interfaceStatuses = [];
  const peers = [];
  let anyElevationCandidate = false;

  for (const iface of interfaceNames) {
    const [peersProbe, endpointsProbe, handshakesProbe] = await Promise.all([
      wgShowPeers(runExec, iface, options),
      wgShowEndpoints(runExec, iface, options),
      wgShowLatestHandshakes(runExec, iface, options),
    ]);

    const degraded = [peersProbe, endpointsProbe, handshakesProbe].find((probe) => probe.status !== "ok");
    if (degraded) {
      const elevationCandidate = isPermissionDenied(degraded);
      anyElevationCandidate = anyElevationCandidate || elevationCandidate;
      interfaceStatuses.push({ name: iface, status: elevationCandidate ? "missing_permission" : "unable", error: degraded.error });
      continue;
    }

    const pubkeys = parseWgPeerList(peersProbe.stdout);
    const endpoints = parseWgEndpoints(endpointsProbe.stdout);
    const handshakes = parseWgHandshakes(handshakesProbe.stdout);

    for (const pubkey of pubkeys) {
      peers.push({
        source_type: "wireguard",
        presence_state: "observed_active",
        interface: iface,
        public_key: pubkey,
        endpoint: endpoints[pubkey],
        latest_handshake_epoch_seconds: handshakes[pubkey],
      });
    }
    interfaceStatuses.push({ name: iface, status: "ok" });
  }

  const allInterfacesOk = interfaceStatuses.every((entry) => entry.status === "ok");
  return {
    // "ok" covers BOTH a fully-resolved tick AND the real "wg installed, zero interfaces
    // configured" zero -- interfaceNames.length === 0 falls through the loop untouched and
    // allInterfacesOk trivially holds (vacuous truth over an empty list), which is exactly the
    // degrade-not-fabricate distinction: a genuinely-empty WireGuard setup is "ok", never
    // conflated with "unable".
    status: allInterfacesOk ? "ok" : "partial",
    interfaces: interfaceStatuses,
    peers,
    elevation_candidate: anyElevationCandidate,
    // Never silently drop interfaces beyond MAX_WG_INTERFACES: surface the truncation the same way
    // the per-tick peer-entity cap does (truncated + total_count), so a host with more configured
    // WireGuard interfaces than the cap shows an explicit indication rather than peers behind the
    // (cap+1)th interface vanishing from the census with no trace.
    interfaces_truncated: allInterfaceNames.length > MAX_WG_INTERFACES,
    total_interface_count: allInterfaceNames.length,
    binary: listProbe.binary,
  };
}

// ---------------------------------------------------------------------------------------------
// scutil --nc list -- macOS VPN service state (darwin only; degrades to "not_applicable" on
// every other platform without attempting the command at all -- scutil does not exist there).
// ---------------------------------------------------------------------------------------------

// Real output has a service-type token between the UUID and the quoted name, followed by a
// bracketed type classifier. Keep the whole pre-name token loose because macOS emits forms such
// as `VPN (...)`, `IPSec`, and `PPP --> com.example...`.
const SCUTIL_NC_LINE_RE = /^\*?\s*\(([^)]+)\)\s+([0-9A-Fa-f-]{36})\s+.+?\s+"([^"]*)"\s+\[([^\]]+)\]\s*$/;
const SCUTIL_NC_HEADER_RE = /^Available network connection services in the current set \(\*=enabled\):$/;
const VPN_SERVICE_TYPE_RE = /^(?:VPN:.*|IPSec|PPP:L2TP)$/i;
const TAILSCALE_SERVICE_TYPE_IDS = new Set(["io.tailscale.ipn.macos", "io.tailscale.ipn.macsys"]);

export function parseScutilNcListDetailed(stdout) {
  const services = [];
  let unparsed_count = 0;
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (SCUTIL_NC_HEADER_RE.test(line)) continue;
    const match = line.match(SCUTIL_NC_LINE_RE);
    if (!match) {
      unparsed_count += 1;
      continue;
    }
    const [, status, uuid, name, service_type] = match;
    const is_tailscale = TAILSCALE_SERVICE_TYPE_IDS.has(String(service_type).toLowerCase().replace(/^vpn:/, ""));
    services.push({
      status: status.trim(),
      service_uuid: uuid,
      service_name: name,
      service_type,
      is_vpn: VPN_SERVICE_TYPE_RE.test(service_type),
      is_tailscale,
    });
  }
  return { services, unparsed_count };
}

export function parseScutilNcList(stdout) {
  return parseScutilNcListDetailed(stdout).services;
}

async function collectVpnServices(options) {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") return { status: "not_applicable", services: [] };

  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const probe = await runExec("scutil", ["--nc", "list"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
  if (isBinaryNotFound(probe)) return { status: "not_found_on_known_paths", services: [], binary: probe.binary };
  if (probe.status !== "ok") {
    if (isBinaryUntrusted(probe)) return { status: "untrusted_binary", services: [], error: probe.error, binary: probe.binary };
    if (isPermissionDenied(probe)) return { status: "missing_permission", services: [], error: probe.error, binary: probe.binary };
    return { status: "unable", services: [], error: probe.error, binary: probe.binary };
  }
  const parsed = parseScutilNcListDetailed(probe.stdout);
  return {
    status: parsed.unparsed_count > 0 ? "partial" : "ok",
    services: parsed.services.filter((service) => service.is_vpn && !service.is_tailscale),
    unparsed_count: parsed.unparsed_count,
    tailscale_entry_observed: parsed.services.some((service) => service.is_tailscale),
    binary: probe.binary,
  };
}

// ---------------------------------------------------------------------------------------------
// Established-inbound cross-reference (ss/netstat) -- LOWEST CONFIDENCE, first-to-cut per the
// plan. Kept as raw operator-triage context only: it is never translated into a persisted peer
// fact (fact-translators.js's factPointsFromVpnPeerEvidence never reads this field), so it needs
// no identity hash scheme of its own.
// ---------------------------------------------------------------------------------------------

async function collectEstablishedInbound(options) {
  const platform = options.platform ?? process.platform;
  const runExec = options.runFixedExecFile ?? runFixedExecFile;

  if (platform === "linux") {
    const probe = await runExec("ss", ["-H", "-tn", "state", "established"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
    if (isBinaryNotFound(probe)) return { status: "not_found_on_known_paths", count: 0, binary: probe.binary };
    if (isBinaryUntrusted(probe)) return { status: "untrusted_binary", count: 0, error: probe.error, binary: probe.binary };
    if (probe.status !== "ok") return { status: "unable", count: 0, error: probe.error, binary: probe.binary };
    const lines = String(probe.stdout ?? "").split("\n").map((line) => line.trim()).filter(Boolean);
    return { status: "ok", count: lines.length, binary: probe.binary };
  }

  const probe = await runExec("netstat", ["-an", "-p", "tcp"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));
  if (isBinaryNotFound(probe)) return { status: "not_found_on_known_paths", count: 0, binary: probe.binary };
  if (isBinaryUntrusted(probe)) return { status: "untrusted_binary", count: 0, error: probe.error, binary: probe.binary };
  if (probe.status !== "ok") return { status: "unable", count: 0, error: probe.error, binary: probe.binary };
  const count = String(probe.stdout ?? "").split("\n").filter((line) => /established/i.test(line)).length;
  return { status: "ok", count, binary: probe.binary };
}

// ---------------------------------------------------------------------------------------------
// Assembly.
// ---------------------------------------------------------------------------------------------

function dedupeKey(remoteUser, remoteHost) {
  return JSON.stringify([remoteUser, remoteHost]);
}

/**
 * Session-status L0 collector (Slice 3). Combines SSH (who + bounded last), WireGuard, and
 * macOS VPN-service peer observations into one bounded `peers[]` list, plus lowest-confidence
 * established-inbound context. Envelope status is "ok" as soon as ANY source resolved
 * successfully this tick (mirrors tools/sessions.js's any_binary_available convention) --
 * "unable"/confidence 0 only when every source degraded.
 */
export async function collectVpnPeerStatusEvidence(options = {}) {
  const cap = Math.min(MAX_PEER_ENTITY_LIMIT, Math.max(1, Number(options.peerLimit) || DEFAULT_PEER_ENTITY_LIMIT));

  return timedEnvelope(async () => {
    if (options.signal?.aborted) throw new Error("collector_aborted");
    const platform = options.platform ?? process.platform;

    const who = await collectSshWho(options);
    if (options.signal?.aborted) throw new Error("collector_aborted");
    const last = await collectSshLast(options);
    if (options.signal?.aborted) throw new Error("collector_aborted");
    const wireguard = await collectWireguardPeers({ ...options, platform });
    if (options.signal?.aborted) throw new Error("collector_aborted");
    const vpnServices = await collectVpnServices({ ...options, platform });
    if (options.signal?.aborted) throw new Error("collector_aborted");
    const establishedInbound = await collectEstablishedInbound({ ...options, platform });

    const sshPeers = [];
    const seenSsh = new Set();
    for (const entry of who.entries ?? []) {
      if (!entry.remote_host) continue; // local session -- not a peer
      const key = dedupeKey(entry.remote_user, entry.remote_host);
      if (seenSsh.has(key)) continue;
      seenSsh.add(key);
      sshPeers.push({ source_type: "ssh", presence_state: "observed_active", remote_user: entry.remote_user, remote_host: entry.remote_host, origin: "who" });
    }
    for (const entry of last.entries ?? []) {
      const key = dedupeKey(entry.remote_user, entry.remote_host);
      if (seenSsh.has(key)) continue;
      seenSsh.add(key);
      sshPeers.push({ source_type: "ssh", presence_state: "observed_historical", remote_user: entry.remote_user, remote_host: entry.remote_host, origin: "last" });
    }

    const vpnServicePeers = (vpnServices.services ?? []).map((service) => ({
      source_type: "vpn_service",
      presence_state: /connected/i.test(service.status) && !/disconnect/i.test(service.status) ? "observed_active" : "observed_historical",
      service_name: service.service_name,
      service_uuid: service.service_uuid,
    }));

    const allPeers = [...(wireguard.peers ?? []), ...sshPeers, ...vpnServicePeers];
    const resolvedStatuses = [who.status, last.status, wireguard.status, vpnServices.status, establishedInbound.status];
    const anySourceAvailable = resolvedStatuses.some((status) => status === "ok" || status === "partial");

    return {
      platform,
      sources: {
        ssh_who: { status: who.status, error: who.error, binary_provenance: binaryProvenance(who.binary) },
        ssh_last: { status: last.status, error: last.error, requested_n: last.requested_n, binary_provenance: binaryProvenance(last.binary) },
        wireguard: {
          status: wireguard.status,
          error: wireguard.error,
          elevation_candidate: wireguard.elevation_candidate ?? false,
          interfaces: wireguard.interfaces ?? [],
          interfaces_truncated: wireguard.interfaces_truncated ?? false,
          total_interface_count: wireguard.total_interface_count ?? (wireguard.interfaces?.length ?? 0),
          binary_provenance: binaryProvenance(wireguard.binary),
        },
        vpn_services: {
          status: vpnServices.status,
          error: vpnServices.error,
          unparsed_count: vpnServices.unparsed_count ?? 0,
          tailscale_entry_observed: vpnServices.tailscale_entry_observed ?? false,
          binary_provenance: binaryProvenance(vpnServices.binary),
        },
        established_inbound: { status: establishedInbound.status, error: establishedInbound.error, binary_provenance: binaryProvenance(establishedInbound.binary) },
      },
      any_source_available: anySourceAvailable,
      total_count: allPeers.length,
      peers: allPeers.slice(0, cap),
      truncated: allPeers.length > cap,
      cap,
    };
  }, (result) => evidenceEnvelope({
    id: "vpn-peer-status",
    status: result.any_source_available
      ? (Object.values(result.sources).some((source) => source.status === "ok") ? "ok" : "warning")
      : "unable",
    source: "vpn_peer_status",
    result,
    confidence: result.any_source_available
      ? (Object.values(result.sources).some((source) => source.status === "ok") ? 1 : 0.4)
      : 0,
    reviewHint: result.any_source_available
      ? (Object.values(result.sources).some((source) => source.status === "ok") ? "none" : "ambiguous")
      : "missing_permission",
    tool: "collect_vpn_peer_status",
    target: `cap=${result.cap}`,
  }));
}
