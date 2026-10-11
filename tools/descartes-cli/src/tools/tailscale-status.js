// Read-only Tailscale/tailnet peer collector for `collect_tailscale_status`.
//
// The collector reads only the local daemon's status JSON. It deliberately has one closed,
// fixed-argv invocation and uses execFile rather than a shell, so this file cannot construct a
// mutating or authentication command from input.
//
// NEVER add a second `tailscale` invocation here. In particular NEVER: `tailscale up`, `down`,
// `set`, `logout`, `login`, `switch`, `configure`, `serve`, `funnel`, `file`, `ssh`, `lock`,
// `cert`, `web`, `debug` — any subcommand that mutates daemon/tailnet state, authenticates,
// exposes a service, or touches certificates/keys. `status --json` is read-only and prints no
// private key or auth material.
//
// Degrade-not-fabricate: a miss on pinned known paths (including ENOENT) means the binary is
// not_found_on_known_paths; a parsed logged-out backend state is
// a truthful zero; malformed output and all other failures are unable. Permission failures are
// documented as elevation candidates, but this collector never escalates.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { binaryProvenance, isBinaryNotFound, isBinaryUntrusted, runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT = 200;
// Fact-store capacity plan §2/S4: hard UPPER clamp (see vpn-peer-status.js MAX_PEER_ENTITY_LIMIT).
export const MAX_TAILSCALE_PEER_ENTITY_LIMIT = 200;

async function runFixedExecFile(command, args, options = {}) {
  return runResolvedExecFile(command, args, {
    ...options,
    timeout: options.timeout ?? 3000,
    maxBuffer: options.maxBuffer ?? 512 * 1024,
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

function parseLastHandshake(value) {
  if (value === "0001-01-01T00:00:00Z") return 0;
  if (typeof value !== "string") return undefined;
  const epochMilliseconds = Date.parse(value);
  return Number.isFinite(epochMilliseconds) ? Math.floor(epochMilliseconds / 1000) : undefined;
}

function parsePeer(peer) {
  if (!peer || typeof peer !== "object" || Array.isArray(peer) || typeof peer.PublicKey !== "string" || peer.PublicKey.length === 0) {
    return undefined;
  }
  for (const field of ["Online", "ExitNode", "ExitNodeOption"]) {
    if (Object.prototype.hasOwnProperty.call(peer, field) && typeof peer[field] !== "boolean") return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(peer, "LastHandshake") && parseLastHandshake(peer.LastHandshake) === undefined) return undefined;
  return {
    source_type: "tailscale",
    presence_state: peer.Online ? "observed_active" : "observed_historical",
    node_public_key: peer.PublicKey,
    is_exit_node_active: peer.ExitNode === true,
    is_exit_node_option: peer.ExitNodeOption === true,
    latest_handshake_epoch_seconds: parseLastHandshake(peer.LastHandshake),
  };
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

// Context plan C0.3: the daemon's own tailnet state, kept for EVERY parsed outcome (not only
// Running). Each field is undefined when the JSON does not carry it: an absent Health list or Self
// object is unknown, never a zero or a false. CurrentTailnet.Name is raw here, in memory only;
// context-translators.js HMACs it before any fact point is built.
function validateTailnetFields(parsed) {
  if (Object.prototype.hasOwnProperty.call(parsed, "Self")) {
    if (!isPlainObject(parsed.Self)) return false;
    if (Object.prototype.hasOwnProperty.call(parsed.Self, "Online") && typeof parsed.Self.Online !== "boolean") return false;
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "ExitNodeStatus")) {
    if (!isPlainObject(parsed.ExitNodeStatus)) return false;
    if (Object.prototype.hasOwnProperty.call(parsed.ExitNodeStatus, "ID") && typeof parsed.ExitNodeStatus.ID !== "string") return false;
    if (Object.prototype.hasOwnProperty.call(parsed.ExitNodeStatus, "Online") && typeof parsed.ExitNodeStatus.Online !== "boolean") return false;
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "Health")) {
    if (!Array.isArray(parsed.Health) || parsed.Health.some((issue) => typeof issue !== "string")) return false;
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "CurrentTailnet")) {
    if (!isPlainObject(parsed.CurrentTailnet)) return false;
    const tailnet = parsed.CurrentTailnet;
    if (Object.prototype.hasOwnProperty.call(tailnet, "Name") && (typeof tailnet.Name !== "string" || tailnet.Name.length === 0)) return false;
    if (Object.prototype.hasOwnProperty.call(tailnet, "MagicDNSSuffix") && typeof tailnet.MagicDNSSuffix !== "string") return false;
    if (Object.prototype.hasOwnProperty.call(tailnet, "MagicDNSEnabled") && typeof tailnet.MagicDNSEnabled !== "boolean") return false;
  }
  return true;
}

function parseTailnetState(parsed, peerMapValid, peers, valid) {
  const self = isPlainObject(parsed.Self) ? parsed.Self : undefined;
  let exitNodeInUse;
  if (valid && isPlainObject(parsed.ExitNodeStatus)) exitNodeInUse = true;
  else if (valid && peerMapValid && peers.some((peer) => peer.is_exit_node_active)) exitNodeInUse = true;
  else if (valid && peerMapValid && parsed.BackendState === "Running") exitNodeInUse = false;
  const state = {
    backend_state: parsed.BackendState,
    self_online: typeof self?.Online === "boolean" ? self.Online : undefined,
    exit_node_in_use: exitNodeInUse,
    health_issue_count: Array.isArray(parsed.Health) ? parsed.Health.length : undefined,
    current_tailnet_name: isPlainObject(parsed.CurrentTailnet) && typeof parsed.CurrentTailnet.Name === "string" && parsed.CurrentTailnet.Name.length > 0
      ? parsed.CurrentTailnet.Name
      : undefined,
  };
  if (!valid) state.valid = false;
  return state;
}

/**
 * C0 review H1: the envelope as it may leave this process for a model provider (the
 * collect_tailscale_status triage tool). The raw `CurrentTailnet.Name` is only for the daemon's own
 * translator, which HMACs it with the per-install key before any fact point; it is stripped here and
 * replaced by a presence flag, so the tool result never carries it (README data table: "not sent").
 * Pure; the input is not mutated.
 */
export function redactTailscaleEnvelopeForModel(envelope) {
  const tailnet = envelope?.result?.tailnet;
  if (!tailnet || typeof tailnet !== "object" || !Object.prototype.hasOwnProperty.call(tailnet, "current_tailnet_name")) return envelope;
  const { current_tailnet_name: name, ...rest } = tailnet;
  return {
    ...envelope,
    result: { ...envelope.result, tailnet: { ...rest, current_tailnet_name_present: typeof name === "string" && name.length > 0 } },
  };
}

/**
 * Pure parser for `tailscale status --json` output. Raw public keys remain in this in-memory
 * shape only; fact-translators.js hashes them before producing persisted fact points.
 *
 * C0.3: BackendState is required; the Peer map is NOT (a logged-out daemon omits it). When it is
 * absent or malformed, `peer_map_valid` is false and `peers` is empty; the collector then never
 * reports a Running daemon as an ok zero-peer census.
 */
export function parseTailscaleStatusJson(stdout) {
  const parsed = JSON.parse(String(stdout ?? ""));
  if (!isPlainObject(parsed) || typeof parsed.BackendState !== "string" || parsed.BackendState.length === 0) {
    throw new SyntaxError("tailscale status JSON has no valid BackendState");
  }
  const peerEntries = isPlainObject(parsed.Peer) ? Object.entries(parsed.Peer) : [];
  // A Running status is a trustworthy peer census only when EVERY entry validates. Filtering a
  // malformed entry would turn an unreadable population into a false zero and could also make the
  // remaining entries falsely prove that no exit node is in use.
  const parsedPeers = peerEntries.map(([, peer]) => parsePeer(peer));
  const peerMapValid = isPlainObject(parsed.Peer) && parsedPeers.every((peer) => peer !== undefined);
  const peerShapeValid = !Object.prototype.hasOwnProperty.call(parsed, "Peer") || peerMapValid;
  const peers = peerMapValid ? parsedPeers : [];
  const tailnetValid = validateTailnetFields(parsed);

  return {
    backend_state: parsed.BackendState,
    peer_map_valid: peerMapValid,
    peer_shape_valid: peerShapeValid,
    peers,
    tailnet: parseTailnetState(parsed, peerMapValid, peers, tailnetValid),
    tailnet_valid: tailnetValid,
  };
}

function resultForFailure(status, probe, extra = {}) {
  return {
    status,
    peers: [],
    total_count: 0,
    truncated: false,
    elevation_candidate: status === "missing_permission",
    error: probe?.error,
    command: probe?.command,
    binary_provenance: binaryProvenance(probe?.binary),
    ...(status === "untrusted_binary" ? {
      operator_override_hint: "Review the offending component and add the exact absolute Tailscale executable to trusted_binary_paths in watch.json only if the operator accepts the risk.",
    } : {}),
    ...extra,
  };
}

/**
 * L0 Tailscale/tailnet collector. The outer evidence envelope is ok only when the local daemon
 * reported BackendState=Running and the JSON was fully parsed. Logged-out is retained inside the
 * result as a truthful, distinguishable zero while the outer envelope remains unable, matching
 * the single-source collector convention.
 */
export async function collectTailscaleStatusEvidence(options = {}) {
  const cap = Math.min(MAX_TAILSCALE_PEER_ENTITY_LIMIT, Math.max(1, Number(options.peerLimit) || DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT));

  return timedEnvelope(async () => {
    const runExec = options.runFixedExecFile ?? runFixedExecFile;
    const probe = await runExec("tailscale", ["status", "--json"], probeOptions(options, { timeout: options.timeout, maxBuffer: options.maxBuffer }));

    if (isBinaryNotFound(probe)) return resultForFailure("not_found_on_known_paths", probe, { cap });
    if (probe.status !== "ok") {
      const status = isBinaryUntrusted(probe) ? "untrusted_binary" : isPermissionDenied(probe) ? "missing_permission" : "unable";
      return resultForFailure(status, probe, { cap });
    }

    let parsed;
    try {
      parsed = parseTailscaleStatusJson(probe.stdout);
    } catch (error) {
      return resultForFailure("unable", probe, { cap, error: error instanceof Error ? error.message : String(error) });
    }

    // All KNOWN non-Running BackendState values are truthful non-connected zeros, not collection
    // failures (confirmed against tailscale/ipn/ipnstate.go: NoState/NeedsLogin/NeedsMachineAuth/
    // Stopped/Starting/Running). NeedsMachineAuth (device pending tailnet-admin approval) and
    // Starting (daemon mid-bring-up) are valid daemon states — bucketing them as `unable` would
    // misreport a working daemon as a collection failure. Only an UNRECOGNIZED value falls through
    // to the `unable` fallback below (fail-safe: an unknown state is genuinely suspect).
    if (["NeedsLogin", "NoState", "Stopped", "NeedsMachineAuth", "Starting"].includes(parsed.backend_state)) {
      if (!parsed.tailnet_valid || !parsed.peer_shape_valid) {
        return resultForFailure("unable", probe, { cap, backend_state: parsed.backend_state, tailnet: parsed.tailnet, error: "tailscale status JSON has malformed fields" });
      }
      return {
        status: "logged_out",
        backend_state: parsed.backend_state,
        tailnet: parsed.tailnet,
        peers: [],
        total_count: 0,
        truncated: false,
        cap,
        elevation_candidate: false,
        command: probe.command,
        binary_provenance: binaryProvenance(probe.binary),
      };
    }

    if (parsed.backend_state !== "Running") {
      return resultForFailure("unable", probe, { cap, backend_state: parsed.backend_state, tailnet: parsed.tailnet });
    }
    if (!parsed.tailnet_valid) {
      return resultForFailure("unable", probe, { cap, backend_state: parsed.backend_state, tailnet: parsed.tailnet, error: "tailscale status JSON has malformed tailnet fields" });
    }
    // C0.3: a Running daemon whose Peer map is missing or malformed is not a peer census (never an
    // ok zero), but its tailnet state was observed and is kept.
    if (!parsed.peer_map_valid) {
      return resultForFailure("unable", probe, { cap, backend_state: parsed.backend_state, tailnet: parsed.tailnet, error: "tailscale status JSON has no valid Peer map" });
    }

    return {
      status: "ok",
      backend_state: parsed.backend_state,
      tailnet: parsed.tailnet,
      total_count: parsed.peers.length,
      peers: parsed.peers.slice(0, cap),
      truncated: parsed.peers.length > cap,
      cap,
      elevation_candidate: false,
      command: probe.command,
      binary_provenance: binaryProvenance(probe.binary),
    };
  }, (result) => evidenceEnvelope({
    id: "tailscale-status",
    status: result.status === "ok" ? "ok" : result.status === "untrusted_binary" ? "warning" : "unable",
    source: "tailscale_status",
    result,
    confidence: result.status === "ok" ? 1 : 0,
    reviewHint: result.status === "untrusted_binary" ? "untrusted_binary" : result.status === "missing_permission" ? "missing_permission" : "none",
    tool: "collect_tailscale_status",
    target: `cap=${result.cap ?? cap}`,
  }));
}
