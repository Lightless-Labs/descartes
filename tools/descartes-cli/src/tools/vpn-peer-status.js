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
// Degrade-not-fabricate (hard requirement, per source): a binary that is genuinely ABSENT
// (ENOENT) degrades to "absent"; a binary that runs but is denied by the OS (EACCES/EPERM, or
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
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_PEER_ENTITY_LIMIT = 200;

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
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 3000,
      maxBuffer: options.maxBuffer ?? 256 * 1024,
    });
    return { status: "ok", stdout, stderr, command: { argv, read_only: true } };
  } catch (error) {
    return {
      status: "error",
      code: error?.code,
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? "",
      error: error instanceof Error ? error.message : String(error),
      command: { argv, read_only: true },
    };
  }
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
const WHO_LINE_RE = /^(\S+)\s+\S+\s+.*?(?:\(([^)]+)\))?\s*$/;

export function parseWhoOutput(stdout) {
  const entries = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(WHO_LINE_RE);
    if (!match) continue; // unparseable line -- skipped, never fabricated into a partial entry
    const [, user, remoteHost] = match;
    entries.push({ remote_user: user, remote_host: remoteHost || undefined });
  }
  return { entries };
}

async function collectSshWho(options) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const probe = await runExec("who", [], { timeout: options.timeout, maxBuffer: options.maxBuffer });
  if (probe.status === "ok") {
    const { entries } = parseWhoOutput(probe.stdout);
    return { status: "ok", entries, command: probe.command };
  }
  if (probe.code === "ENOENT") return { status: "absent", entries: [], command: probe.command };
  if (isPermissionDenied(probe)) return { status: "missing_permission", entries: [], error: probe.error, command: probe.command };
  return { status: "unable", entries: [], error: probe.error, command: probe.command };
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
    const [user, , host] = tokens;
    if (LAST_PSEUDO_USER_RE.test(user)) continue; // reboot/shutdown -- not a peer, not malformed
    if (LAST_LOCAL_HOST_RE.test(host)) continue; // local session -- not a peer, not malformed
    entries.push({ remote_user: user, remote_host: host });
  }
  return { entries, malformed_count: malformedCount };
}

async function collectSshLast(options) {
  const n = Math.max(1, Number(options.lastHistoryLimit) || DEFAULT_LAST_HISTORY_LIMIT);
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const probe = await runExec("last", ["-n", String(n)], { timeout: options.timeout, maxBuffer: options.maxBuffer });
  if (probe.status === "ok") {
    const { entries, malformed_count } = parseLastOutput(probe.stdout);
    return { status: "ok", entries, malformed_count, requested_n: n, command: probe.command };
  }
  if (probe.code === "ENOENT") return { status: "absent", entries: [], requested_n: n, command: probe.command };
  if (isPermissionDenied(probe)) return { status: "missing_permission", entries: [], requested_n: n, error: probe.error, command: probe.command };
  return { status: "unable", entries: [], requested_n: n, error: probe.error, command: probe.command };
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
  return runExec("wg", ["show", "interfaces"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
}
async function wgShowPeers(runExec, iface, options) {
  return runExec("wg", ["show", iface, "peers"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
}
async function wgShowEndpoints(runExec, iface, options) {
  return runExec("wg", ["show", iface, "endpoints"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
}
async function wgShowLatestHandshakes(runExec, iface, options) {
  return runExec("wg", ["show", iface, "latest-handshakes"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
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

  if (listProbe.code === "ENOENT") {
    return { status: "absent", interfaces: [], peers: [], elevation_candidate: false };
  }
  if (listProbe.status !== "ok") {
    const elevationCandidate = isPermissionDenied(listProbe);
    return {
      status: elevationCandidate ? "missing_permission" : "unable",
      interfaces: [],
      peers: [],
      elevation_candidate: elevationCandidate,
      error: listProbe.error,
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
  };
}

// ---------------------------------------------------------------------------------------------
// scutil --nc list -- macOS VPN service state (darwin only; degrades to "not_applicable" on
// every other platform without attempting the command at all -- scutil does not exist there).
// ---------------------------------------------------------------------------------------------

// "* (Connected)    1E4E6C58-F859-4E51-92A6-BF4B14A23689 "Corp VPN"      [PPP:L2TP]" -- an
// optional leading "*" marks the default service; status in parens; a UUID; the operator-chosen
// service name in quotes.
const SCUTIL_NC_LINE_RE = /^\*?\s*\((\w[\w ]*)\)\s+([0-9A-Fa-f-]{36})\s+"([^"]*)"/;

export function parseScutilNcList(stdout) {
  const services = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(SCUTIL_NC_LINE_RE);
    if (!match) continue;
    const [, status, uuid, name] = match;
    services.push({ status: status.trim(), service_uuid: uuid, service_name: name });
  }
  return services;
}

async function collectVpnServices(options) {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") return { status: "not_applicable", services: [] };

  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const probe = await runExec("scutil", ["--nc", "list"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
  if (probe.code === "ENOENT") return { status: "absent", services: [] };
  if (probe.status !== "ok") {
    if (isPermissionDenied(probe)) return { status: "missing_permission", services: [], error: probe.error };
    return { status: "unable", services: [], error: probe.error };
  }
  return { status: "ok", services: parseScutilNcList(probe.stdout) };
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
    const probe = await runExec("ss", ["-H", "-tn", "state", "established"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
    if (probe.code === "ENOENT") return { status: "absent", count: 0 };
    if (probe.status !== "ok") return { status: "unable", count: 0, error: probe.error };
    const lines = String(probe.stdout ?? "").split("\n").map((line) => line.trim()).filter(Boolean);
    return { status: "ok", count: lines.length };
  }

  const probe = await runExec("netstat", ["-an", "-p", "tcp"], { timeout: options.timeout, maxBuffer: options.maxBuffer });
  if (probe.code === "ENOENT") return { status: "absent", count: 0 };
  if (probe.status !== "ok") return { status: "unable", count: 0, error: probe.error };
  const count = String(probe.stdout ?? "").split("\n").filter((line) => /established/i.test(line)).length;
  return { status: "ok", count };
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
  const cap = Math.max(1, Number(options.peerLimit) || DEFAULT_PEER_ENTITY_LIMIT);

  return timedEnvelope(async () => {
    const platform = options.platform ?? process.platform;

    const who = await collectSshWho(options);
    const last = await collectSshLast(options);
    const wireguard = await collectWireguardPeers({ ...options, platform });
    const vpnServices = await collectVpnServices({ ...options, platform });
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
        ssh_who: { status: who.status, error: who.error },
        ssh_last: { status: last.status, error: last.error, requested_n: last.requested_n },
        wireguard: {
          status: wireguard.status,
          error: wireguard.error,
          elevation_candidate: wireguard.elevation_candidate ?? false,
          interfaces: wireguard.interfaces ?? [],
          interfaces_truncated: wireguard.interfaces_truncated ?? false,
          total_interface_count: wireguard.total_interface_count ?? (wireguard.interfaces?.length ?? 0),
        },
        vpn_services: { status: vpnServices.status, error: vpnServices.error },
        established_inbound: { status: establishedInbound.status, error: establishedInbound.error },
      },
      any_source_available: anySourceAvailable,
      total_count: allPeers.length,
      peers: allPeers.slice(0, cap),
      truncated: allPeers.length > cap,
      cap,
    };
  }, (result) => evidenceEnvelope({
    id: "vpn-peer-status",
    status: result.any_source_available ? "ok" : "unable",
    source: "vpn_peer_status",
    result,
    confidence: result.any_source_available ? 1 : 0,
    reviewHint: result.any_source_available ? "none" : "missing_permission",
    tool: "collect_vpn_peer_status",
    target: `cap=${result.cap}`,
  }));
}
