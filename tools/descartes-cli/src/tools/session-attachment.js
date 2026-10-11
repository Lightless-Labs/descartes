// Context plan C2 (docs/plans/2026-10-06-context-aware-learned-baselines.md §4.3 session.attachment):
// which terminal each tmux client is attached from, so a session can be joined to the login on that
// tty (Opus L1). This replaces v1's "creator lineage", which is infeasible: the tmux server
// daemonizes and exited creators cannot be recovered.
//
// READ ONLY, one fixed-argv `tmux list-clients -F` through the binary resolver, after the incumbent
// census, as a context collector (its own sub-deadline and abort signal). It does not touch the
// incumbent session census (tools/sessions.js). Degrade, never fabricate: a missing tmux is
// not_found_on_known_paths, no running server is "absent" (zero clients observed), and any row off
// the grammar makes the census partial.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { binaryProvenance, isBinaryNotFound, isBinaryUntrusted, runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { finalizeCensus } from "./census-validate.js";
import { throwIfCollectorAborted } from "./collector-abort.js";

const execFileAsync = promisify(execFile);

export const MAX_TMUX_CLIENTS = 32;
export const TMUX_CLIENT_FORMAT = "#{client_tty}\t#{session_name}";
const CLIENT_TTY_RE = /^\/dev\/(?:ttys[0-9]{1,5}|pts\/[0-9]{1,6}|tty[0-9A-Za-z]{1,8}|console)$/;
const MAX_SESSION_NAME_LENGTH = 256;
// tmux's own wording when no server is running (exit 1): zero clients, observed.
const NO_SERVER_RE = /^(?:no server running on |error connecting to )\S+/;

/**
 * `tmux list-clients -F '#{client_tty}\t#{session_name}'` -> { clients: [{ tty, session_name }],
 * malformed_count, duplicate_count }. Exactly two tab-separated fields per line, a /dev tty of a
 * known shape, a non-empty bounded name; a tty listed twice is a duplicate (one client per tty).
 */
export function parseTmuxClients(stdout) {
  if (typeof stdout !== "string") return { clients: [], malformed_count: 1, duplicate_count: 0 };
  const clients = [];
  let malformed_count = 0;
  for (const rawLine of stdout.split("\n")) {
    if (rawLine.length === 0) continue;
    const fields = rawLine.split("\t");
    if (fields.length !== 2) {
      malformed_count += 1;
      continue;
    }
    const [tty, sessionName] = fields;
    if (!CLIENT_TTY_RE.test(tty) || sessionName.length === 0 || sessionName.length > MAX_SESSION_NAME_LENGTH || /[\r\n]/.test(sessionName)) {
      malformed_count += 1;
      continue;
    }
    clients.push({ tty: tty.slice("/dev/".length), session_name: sessionName });
  }
  const census = finalizeCensus({ records: clients, identity: (client) => client.tty, malformed: malformed_count });
  return { clients, malformed_count, duplicate_count: census.duplicate_count };
}

async function defaultRunFixedExecFile(command, args, options = {}) {
  throwIfCollectorAborted(options.signal);
  return runResolvedExecFile(command, args, { ...options, timeout: options.timeout ?? 3000, maxBuffer: options.maxBuffer ?? 64 * 1024, execFileAsync });
}

export async function readSessionAttachments(options = {}) {
  const platform = options.platform ?? process.platform;
  const obsStartMs = (options.nowFn ?? Date.now)();
  const finish = (result) => ({ platform, ...result, observation: { start_ms: obsStartMs, end_ms: (options.nowFn ?? Date.now)() } });
  if (platform !== "darwin" && platform !== "linux") return finish({ status: "not_applicable", clients: [], total_count: 0 });
  const runExec = options.runFixedExecFile ?? defaultRunFixedExecFile;
  const { runFixedExecFile: _drop, nowFn: _now, platform: _platform, ...resolverOptions } = options;
  throwIfCollectorAborted(options.signal);
  const probe = await runExec("tmux", ["list-clients", "-F", TMUX_CLIENT_FORMAT], resolverOptions);
  if (isBinaryNotFound(probe)) return finish({ status: "not_found_on_known_paths", clients: [], total_count: 0, binary_provenance: binaryProvenance(probe?.binary) });
  if (isBinaryUntrusted(probe)) return finish({ status: "untrusted_binary", clients: [], total_count: 0, binary_provenance: binaryProvenance(probe?.binary) });
  if (probe?.status !== "ok") {
    const stderr = typeof probe?.stderr === "string" ? probe.stderr.trim() : "";
    const absent = NO_SERVER_RE.test(stderr) && (typeof probe?.stdout !== "string" || probe.stdout.trim() === "");
    return finish({ status: absent ? "absent" : "unable", clients: [], total_count: 0, binary_provenance: binaryProvenance(probe?.binary) });
  }
  const parsed = parseTmuxClients(probe.stdout);
  const truncated = parsed.clients.length > MAX_TMUX_CLIENTS;
  return finish({
    status: parsed.malformed_count > 0 || parsed.duplicate_count > 0 || truncated ? "partial" : parsed.clients.length === 0 ? "absent" : "ok",
    clients: parsed.clients.slice(0, MAX_TMUX_CLIENTS),
    total_count: parsed.clients.length,
    truncated,
    binary_provenance: binaryProvenance(probe?.binary),
  });
}

export async function collectSessionAttachmentEvidence(options = {}) {
  return timedEnvelope(async () => readSessionAttachments(options), (result) => {
    const built = evidenceEnvelope({
      id: "tmux-clients",
      status: ["ok", "absent"].includes(result.status) ? "ok" : result.status === "partial" ? "warning" : "unable",
      source: "tmux_clients",
      result,
      confidence: ["ok", "absent"].includes(result.status) ? 1 : result.status === "partial" ? 0.5 : 0,
      reviewHint: result.status === "untrusted_binary" ? "untrusted_binary" : "none",
      tool: "collect_tmux_clients",
      target: `clients<=${MAX_TMUX_CLIENTS}`,
    });
    if (result.observation) built.observation = result.observation;
    return built;
  });
}
