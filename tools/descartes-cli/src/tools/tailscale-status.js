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
// Degrade-not-fabricate: ENOENT means the binary is absent; a parsed logged-out backend state is
// a truthful zero; malformed output and all other failures are unable. Permission failures are
// documented as elevation candidates, but this collector never escalates.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT = 200;

async function runFixedExecFile(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 3000,
      maxBuffer: options.maxBuffer ?? 512 * 1024,
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
  return {
    source_type: "tailscale",
    presence_state: peer.Online ? "observed_active" : "observed_historical",
    node_public_key: peer.PublicKey,
    is_exit_node_active: Boolean(peer.ExitNode),
    is_exit_node_option: Boolean(peer.ExitNodeOption),
    latest_handshake_epoch_seconds: parseLastHandshake(peer.LastHandshake),
  };
}

/**
 * Pure parser for `tailscale status --json` output. Raw public keys remain in this in-memory
 * shape only; fact-translators.js hashes them before producing persisted fact points.
 */
export function parseTailscaleStatusJson(stdout) {
  const parsed = JSON.parse(String(stdout ?? ""));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || typeof parsed.BackendState !== "string") {
    throw new SyntaxError("tailscale status JSON has no valid BackendState");
  }
  if (!parsed.Peer || typeof parsed.Peer !== "object" || Array.isArray(parsed.Peer)) {
    throw new SyntaxError("tailscale status JSON has no valid Peer map");
  }

  return {
    backend_state: parsed.BackendState,
    peers: Object.values(parsed.Peer).map(parsePeer).filter(Boolean),
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
  const cap = Math.max(1, Number(options.peerLimit) || DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT);

  return timedEnvelope(async () => {
    const runExec = options.runFixedExecFile ?? runFixedExecFile;
    const probe = await runExec("tailscale", ["status", "--json"], { timeout: options.timeout, maxBuffer: options.maxBuffer });

    if (probe.code === "ENOENT") return resultForFailure("absent", probe, { cap });
    if (probe.status !== "ok") {
      return resultForFailure(isPermissionDenied(probe) ? "missing_permission" : "unable", probe, { cap });
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
      return {
        status: "logged_out",
        backend_state: parsed.backend_state,
        peers: [],
        total_count: 0,
        truncated: false,
        cap,
        elevation_candidate: false,
        command: probe.command,
      };
    }

    if (parsed.backend_state !== "Running") {
      return resultForFailure("unable", probe, { cap, backend_state: parsed.backend_state });
    }

    return {
      status: "ok",
      backend_state: parsed.backend_state,
      total_count: parsed.peers.length,
      peers: parsed.peers.slice(0, cap),
      truncated: parsed.peers.length > cap,
      cap,
      elevation_candidate: false,
      command: probe.command,
    };
  }, (result) => evidenceEnvelope({
    id: "tailscale-status",
    status: result.status === "ok" ? "ok" : "unable",
    source: "tailscale_status",
    result,
    confidence: result.status === "ok" ? 1 : 0,
    reviewHint: result.status === "missing_permission" ? "missing_permission" : "none",
    tool: "collect_tailscale_status",
    target: `cap=${result.cap ?? cap}`,
  }));
}
