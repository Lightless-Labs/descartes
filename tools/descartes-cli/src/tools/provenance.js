// Layer B / Slice S3 — unprivileged runtime provenance collector.
//
// Target-first resolution (pid | port | container -> one provenance record), a deterministic
// source-classification chain, and warnings-as-facts (not yet alerts). Unprivileged only: this
// file never escalates privilege and never fabricates an unresolved pid/owner/identity. See
// docs/plans/2026-07-10-layer-b-provenance.md section 2 for the authoritative spec.
//
// Exported surface is intentionally two-layered:
//   - Orchestration (I/O-performing): resolveProvenance({pid|port|container}).
//   - Pure, no-I/O, reusable by later slices: classifySourceFromAncestry, detectWarnings, and a
//     set of small parser/matcher functions used to keep the orchestration testable via fixtures.

import { execFile } from "node:child_process";
import { readdir, readFile, readlink, stat } from "node:fs/promises";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { parseMacLsofListeningSockets } from "./network.js";
import { buildParentTreeResult, redactAndBoundProcessArgs } from "./processes.js";
import { defaultInvokeElevatedHelper, readPtraceScopeDiagnostic, resolveElevated } from "./provenance-elevated.js";
import { loadProvenanceConfig as defaultLoadProvenanceConfig } from "../provenance-elevated-config.js";

const execFileAsync = promisify(execFile);

// `ucomm` (not `comm`) is used deliberately: on macOS BSD ps, `comm` reports the full executable
// path (e.g. "/sbin/launchd"), while `ucomm` reports the short accounting name ("launchd") that
// classifySourceFromAncestry's fixed comm lists match against. Linux procps supports the same
// `ucomm` alias, so one column set works unmodified on both platforms.
const PROVENANCE_PS_COLUMNS = "pid,ppid,uid,pcpu,pmem,rss,ucomm,args";
const MAX_ANCESTRY_DEPTH = 16;
const MAX_LINUX_FD_SCAN_PIDS = 4096;

const CRON_COMMS = new Set(["cron", "crond", "atd"]);
const SHELL_COMMS = new Set(["bash", "zsh", "sh", "fish"]);
const SUPERVISOR_COMMS = new Set(["supervisord", "runit", "s6-svscan", "pm2", "forever"]);
const CONTAINER_COMMS = new Set(["containerd-shim", "dockerd", "runc", "podman"]);

// Recognized-supervisor set for the public-bind warning: process managers/init systems that imply
// a deliberate, managed launch path. Intentionally excludes shell/cron/ssh/unknown, since an
// unsupervised interactively-launched or ad hoc process bound to a public address is exactly the
// case this warning exists to surface.
const RECOGNIZED_SUPERVISOR_SOURCE_TYPES = new Set(["launchd", "systemd", "supervisor", "container", "init"]);

// Address-literal set for "public bind", pinned against real ss/lsof fixtures per the plan: plain
// all-zero IPv4/IPv6 binds, plus the bare "*" form lsof emits for an all-zero IPv4 bind.
const PUBLIC_BIND_ADDRESSES = new Set(["0.0.0.0", "[::]", "*"]);

const TCP_STATE_NAMES = { "01": "ESTABLISHED", "0A": "LISTEN", "06": "TIME_WAIT", "07": "CLOSE", "0B": "CLOSING" };

function truncate(value, max = 2048) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

async function runFixedExecFile(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 3000,
      maxBuffer: options.maxBuffer ?? 256 * 1024,
    });
    return { status: "ok", stdout, stderr: truncate(stderr), command: { argv, read_only: true } };
  } catch (error) {
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      stdout: truncate(error?.stdout ?? ""),
      stderr: truncate(error?.stderr ?? ""),
      command: { argv, read_only: true },
    };
  }
}

// ---------------------------------------------------------------------------------------------
// Target selection (pure)
// ---------------------------------------------------------------------------------------------

export function normalizeProvenanceTarget({ pid, port, container } = {}) {
  const provided = [
    pid !== undefined && pid !== null ? ["pid", pid] : undefined,
    port !== undefined && port !== null ? ["port", port] : undefined,
    container !== undefined && container !== null ? ["container", container] : undefined,
  ].filter(Boolean);

  if (provided.length !== 1) {
    return { kind: "ambiguous", value: undefined, error: provided.length === 0 ? "missing_target" : "multiple_targets" };
  }

  const [kind, rawValue] = provided[0];
  if (kind === "pid") {
    const numeric = Number(rawValue);
    if (!Number.isInteger(numeric) || numeric <= 0) return { kind, value: undefined, error: "invalid_target_value" };
    return { kind, value: numeric };
  }
  if (kind === "port") {
    const numeric = Number(rawValue);
    if (!Number.isInteger(numeric) || numeric < 1 || numeric > 65535) return { kind, value: undefined, error: "invalid_target_value" };
    return { kind, value: numeric };
  }
  const text = String(rawValue).trim();
  if (!text) return { kind, value: undefined, error: "invalid_target_value" };
  // Container refs are id/name tokens; bound them to Docker/Podman's own legal charset
  // (alnum start, then alnum plus _.- and a / for namespaced names) so a value like "-f=x"
  // can never be passed to `docker/podman inspect` as an argv flag (argument-injection into
  // the external CLI — not shell-injectable via execFile, but still refused up front).
  if (kind === "container" && !/^[A-Za-z0-9][A-Za-z0-9_.\/-]*$/.test(text)) {
    return { kind, value: undefined, error: "invalid_target_value" };
  }
  return { kind, value: text };
}

// ---------------------------------------------------------------------------------------------
// Source classification (pure, no I/O) — reusable by S4/S5.
// ---------------------------------------------------------------------------------------------

function normalizedComm(item) {
  return String(item?.comm ?? item?.command ?? "").trim().toLowerCase();
}

function sourceResult(type, matchedProcess, reason) {
  return {
    type,
    name: matchedProcess?.comm ?? matchedProcess?.command,
    confidence: 1,
    review_hint: "none",
    details: { matched_pid: matchedProcess?.pid, reason },
  };
}

export function classifySourceFromAncestry(ancestryChain = []) {
  const chain = Array.isArray(ancestryChain) ? ancestryChain : [];
  const target = chain[0];
  const parent = chain[1];
  const ancestors = chain.slice(1);

  if (target && Number(target.ppid) === 1) {
    const pid1 = chain.find((item) => Number(item.pid) === 1);
    const comm = normalizedComm(pid1);
    if (comm === "launchd") return sourceResult("launchd", pid1, "matched pid 1 launchd via ppid==1 ancestry");
    if (comm === "systemd") return sourceResult("systemd", pid1, "matched pid 1 systemd via ppid==1 ancestry");
  }

  const cronAncestor = ancestors.find((item) => CRON_COMMS.has(normalizedComm(item)));
  if (cronAncestor) return sourceResult("cron", cronAncestor, "matched cron/crond/atd ancestor");

  const sshAncestor = ancestors.find((item) => normalizedComm(item) === "sshd");
  if (sshAncestor) return sourceResult("ssh", sshAncestor, "matched sshd ancestor");

  if (parent && SHELL_COMMS.has(normalizedComm(parent))) {
    return sourceResult("shell", parent, "matched interactive shell as immediate parent");
  }

  const supervisorAncestor = ancestors.find((item) => SUPERVISOR_COMMS.has(normalizedComm(item)));
  if (supervisorAncestor) return sourceResult("supervisor", supervisorAncestor, "matched process supervisor ancestor");

  const containerAncestor = ancestors.find((item) => CONTAINER_COMMS.has(normalizedComm(item)));
  if (containerAncestor) return sourceResult("container", containerAncestor, "matched container runtime ancestor");

  if (target && (Number(target.ppid) === 0 || Number(target.pid) === 1)) {
    return sourceResult("init", target, "target itself is pid 1 or has ppid 0");
  }

  return {
    type: "unknown",
    name: undefined,
    confidence: 0,
    review_hint: "ambiguous",
    details: { reason: "no_classification_rule_matched", ancestry_depth: chain.length },
  };
}

// ---------------------------------------------------------------------------------------------
// Warnings-as-facts (pure, no I/O) — reusable by S4.
// ---------------------------------------------------------------------------------------------

export function isPublicBindAddress(address) {
  return PUBLIC_BIND_ADDRESSES.has(String(address));
}

// Exported (additive, S4) so callers that need to know "is this source type a recognized
// supervisor" without re-deriving the classification (e.g. the structural provenance-warning
// sub-collector's own per-socket narrowing step) can reuse the exact same set detectWarnings
// itself is built on, rather than maintaining a second copy.
export function isRecognizedSupervisorSourceType(sourceType) {
  return RECOGNIZED_SUPERVISOR_SOURCE_TYPES.has(sourceType);
}

// Exported (additive, S4): the "public bind with no recognized supervisor" predicate,
// extracted out of detectWarnings so a caller that needs to gate expensive per-process I/O
// (S4's bounded deleted-exe check, see provenance-warnings.js) on exactly this condition can
// call the same pure, no-I/O logic detectWarnings uses internally — never a re-derived copy.
export function hasPublicBindNoSupervisor(sourceType, sockets = []) {
  return (sockets ?? []).some(
    (socket) => isPublicBindAddress(socket?.local_address) && !isRecognizedSupervisorSourceType(sourceType)
  );
}

export function detectWarnings(record = {}, sockets = []) {
  const warnings = [];
  const resolved = record.resolved ?? {};
  const source = record.source ?? {};
  const ancestry = Array.isArray(record.ancestry) ? record.ancestry : [];

  if (resolved.deleted_exe === true) {
    const confidence = typeof resolved.deleted_exe_confidence === "number" ? resolved.deleted_exe_confidence : 1;
    warnings.push({
      rule_id: "deleted_exe_running",
      message: "Process executable path is deleted/unlinked but the process is still running.",
      severity: confidence >= 1 ? "high" : "medium",
      confidence,
    });
  }

  if (hasPublicBindNoSupervisor(source.type, sockets)) {
    warnings.push({
      rule_id: "public_bind_no_supervisor",
      message: "Socket is bound to a public address with no recognized supervising source.",
      severity: "medium",
      confidence: 0.8,
    });
  }

  if (source.type === "unknown" && ancestry.length > 1) {
    warnings.push({
      rule_id: "unexpected_parent",
      message: "Process source could not be classified and has a non-trivial ancestry chain.",
      severity: "low",
      confidence: 0.5,
    });
  }

  return warnings;
}

// ---------------------------------------------------------------------------------------------
// Linux /proc/net/{tcp,udp}[6] parsing (pure, no I/O).
// ---------------------------------------------------------------------------------------------

function decodeProcNetIPv4(hex) {
  if (!/^[0-9A-Fa-f]{8}$/.test(hex)) return undefined;
  if (/^0+$/.test(hex)) return "0.0.0.0";
  const bytes = [];
  for (let i = 0; i < 8; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
  return bytes.reverse().join(".");
}

function decodeProcNetIPv6(hex) {
  if (!/^[0-9A-Fa-f]{32}$/.test(hex)) return undefined;
  if (/^0+$/.test(hex)) return "[::]";
  const words = [];
  for (let i = 0; i < 32; i += 8) {
    const chunk = hex.slice(i, i + 8);
    words.push(chunk.slice(6, 8) + chunk.slice(4, 6) + chunk.slice(2, 4) + chunk.slice(0, 2));
  }
  const full = words.join("");
  const hextets = [];
  for (let i = 0; i < full.length; i += 4) hextets.push(full.slice(i, i + 4).replace(/^0+(?=.)/, ""));
  return `[${hextets.join(":")}]`;
}

export function parseProcNetLine(line, { protocol } = {}) {
  const parts = String(line ?? "").trim().split(/\s+/);
  if (parts.length < 10) return undefined;

  const [localHex, localPortHex] = String(parts[1] ?? "").split(":");
  if (!localHex || localPortHex === undefined) return undefined;

  const isV6 = String(protocol ?? "").includes("6") || localHex.length === 32;
  const address = isV6 ? decodeProcNetIPv6(localHex) : decodeProcNetIPv4(localHex);
  const localPort = parseInt(localPortHex, 16);
  if (address === undefined || Number.isNaN(localPort)) return undefined;

  const stateHex = String(parts[3] ?? "").toUpperCase();
  const uid = Number(parts[7]);
  const inode = parts[9];

  return {
    protocol: protocol ?? (isV6 ? "tcp6" : "tcp"),
    local_address: address,
    local_port: localPort,
    state: String(protocol ?? "").startsWith("udp") ? "UNCONN" : (TCP_STATE_NAMES[stateHex] ?? stateHex),
    uid: Number.isFinite(uid) ? uid : undefined,
    inode,
  };
}

export function parseProcNetContents(contents, { protocol } = {}) {
  const lines = String(contents ?? "").split("\n").slice(1);
  return lines.map((line) => (line.trim() ? parseProcNetLine(line, { protocol }) : undefined)).filter(Boolean);
}

// Pure inode->pid matcher over an already-performed fd scan. fdScanResults is
// [{ pid, accessible: bool, fds?: [{ fd, target }] }, ...] — accessible:false represents an
// EACCES (cross-UID, permission-limited) /proc/<pid>/fd readdir. Never fabricates a pid.
export function resolvePidFromFdScanResults(targetInode, fdScanResults = []) {
  for (const entry of fdScanResults) {
    if (entry.accessible === false) continue;
    const match = (entry.fds ?? []).find((fd) => fd.target === `socket:[${targetInode}]`);
    if (match) return { status: "ok", pid: entry.pid, confidence: 1 };
  }
  const hadInaccessible = fdScanResults.some((entry) => entry.accessible === false);
  if (hadInaccessible) return { status: "partial", pid: undefined, confidence: 0, review_hint: "missing_permission" };
  return { status: "unknown", pid: undefined, confidence: 0 };
}

// Exported (additive, S4): the structural provenance-warning collector needs to enumerate all
// pids once and fd-scan them once (bounded, see plan section 4) to resolve Linux socket owners
// across every listener in a single pass, reusing this exactly rather than re-deriving it.
export async function listProcPids() {
  // Deliberately not wrapped in try/catch: a Linux port-resolution code path running without
  // /proc mounted (e.g. an unusual chroot/container) is a genuinely exceptional condition this
  // module has no graceful degrade for; timedEnvelope's fail-closed contract covers it.
  const entries = await readdir("/proc");
  return entries.filter((name) => /^\d+$/.test(name)).map(Number).slice(0, MAX_LINUX_FD_SCAN_PIDS);
}

export async function scanProcFdForInode(candidatePids) {
  const results = [];
  for (const pid of candidatePids) {
    try {
      const fdNames = await readdir(`/proc/${pid}/fd`);
      const fds = [];
      for (const fdName of fdNames) {
        try {
          const target = await readlink(`/proc/${pid}/fd/${fdName}`);
          fds.push({ fd: fdName, target });
        } catch {
          // Individual fd readlink race/permission — skip only this fd.
        }
      }
      results.push({ pid, accessible: true, fds });
    } catch (error) {
      results.push({ pid, accessible: false, error: error?.code });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------------------------
// macOS lsof parsing (pure, no I/O) — reuses network.js's shared parser, does not reimplement it.
// ---------------------------------------------------------------------------------------------

export function buildMacPortSockets(stdout, port) {
  return parseMacLsofListeningSockets(stdout, { limit: 20 })
    .filter((entry) => entry.local_port === port)
    .map((entry) => ({
      protocol: entry.protocol,
      local_address: entry.local_address,
      local_port: entry.local_port,
      state: entry.state,
      public_bind: isPublicBindAddress(entry.local_address),
      pid: entry.pid,
      command: entry.command,
    }));
}

export function parseMacLsofTxtExecutablePath(stdout) {
  const lines = String(stdout ?? "").split("\n").slice(1);
  for (const line of lines) {
    const match = line.match(/^\S+\s+\d+\s+\S+\s+txt\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/i);
    if (match) return match[1].trim();
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// deleted_exe detection (pure, no I/O). Linux: kernel-asserted "(deleted)" readlink suffix.
// macOS: inferred from an ENOENT stat on the lsof-reported path while lsof still shows the FD
// open — there is no macOS kernel-provided suffix equivalent, per the plan.
// ---------------------------------------------------------------------------------------------

export function isLinuxDeletedExeLink(linkTarget) {
  return typeof linkTarget === "string" && linkTarget.endsWith(" (deleted)");
}

export function inferMacosDeletedExe({ exePathFromLsof, statResult } = {}) {
  if (!exePathFromLsof) return "unknown";
  if (!statResult || statResult.status === "unable") return "unknown";
  if (statResult.status === "enoent") return true;
  if (statResult.status === "ok") return false;
  return "unknown";
}

// ---------------------------------------------------------------------------------------------
// username resolution (pure parse + fixed-argv `id -un <uid>`).
// ---------------------------------------------------------------------------------------------

export function parseIdUsernameOutput(stdout) {
  const trimmed = String(stdout ?? "").trim();
  if (!trimmed || /\s/.test(trimmed)) return undefined;
  if (!/^[A-Za-z0-9_.$-]+$/.test(trimmed)) return undefined;
  return trimmed;
}

async function resolveUsernameForUid(uid) {
  if (uid === undefined || uid === null || Number.isNaN(Number(uid))) return { username: undefined, username_unavailable: true };
  const result = await runFixedExecFile("id", ["-un", String(uid)], { timeout: 2000, maxBuffer: 8192 });
  if (result.status !== "ok") return { username: undefined, username_unavailable: true };
  const username = parseIdUsernameOutput(result.stdout);
  if (!username) return { username: undefined, username_unavailable: true };
  return { username, username_unavailable: false };
}

// ---------------------------------------------------------------------------------------------
// container inspect parsing (pure).
// ---------------------------------------------------------------------------------------------

export function parseContainerInspectPid(stdout) {
  const trimmed = String(stdout ?? "").trim();
  if (!/^\d+$/.test(trimmed)) return undefined;
  const pid = Number(trimmed);
  return pid > 0 ? pid : undefined;
}

// ---------------------------------------------------------------------------------------------
// Provenance-scoped ps snapshot parsing (pure). Distinct column set from processes.js's parsePs
// (adds a `uid` column provenance needs), but reuses redactAndBoundProcessArgs verbatim so any
// command/args field in the result matches processes.js's redaction shape exactly.
// ---------------------------------------------------------------------------------------------

// Exported (additive, S4): the structural provenance-warning collector needs the exact same
// `ps` argv this module uses so its own single, shared process-table snapshot (reused across
// every listening pid in one tick) parses identically via parseProvenancePs below.
export function provenancePsArgsForPlatform(platform = process.platform) {
  return platform === "linux" ? ["-eo", PROVENANCE_PS_COLUMNS] : ["-axo", PROVENANCE_PS_COLUMNS];
}

export function parseProvenancePs(stdout) {
  const lines = String(stdout ?? "").trim().split("\n").slice(1);
  return lines.map((line) => {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\S+)\s*(.*)$/);
    if (!match) return undefined;
    const rawArgs = match[8] || match[7];
    const redaction = redactAndBoundProcessArgs(rawArgs);
    return {
      pid: Number(match[1]),
      ppid: Number(match[2]),
      uid: Number(match[3]),
      cpu_percent: Number(match[4]),
      memory_percent: Number(match[5]),
      rss_bytes: Number(match[6]) * 1024,
      command: match[7],
      args: redaction.value,
      args_redaction: {
        redacted: redaction.redacted,
        truncated: redaction.truncated,
        original_length: redaction.original_length,
        max_length: redaction.max_length,
      },
    };
  }).filter(Boolean);
}

// ---------------------------------------------------------------------------------------------
// Envelope-field policy (pure).
// ---------------------------------------------------------------------------------------------

export function computeProvenanceEnvelopeFields(resolvedStatus, sourceType) {
  const confidence = resolvedStatus === "ok" && sourceType !== "unknown" ? 1 : resolvedStatus === "partial" ? 0.4 : 0;
  const reviewHint = resolvedStatus === "partial" ? "missing_permission" : sourceType === "unknown" ? "ambiguous" : "none";
  const status = resolvedStatus === "ok" ? "ok" : resolvedStatus === "partial" ? "partial" : "unknown";
  return { status, confidence, reviewHint };
}

// ---------------------------------------------------------------------------------------------
// Orchestration (I/O-performing).
// ---------------------------------------------------------------------------------------------

// S3-priv Slice 1 (pure, behavior-preserving extraction): the old hardcoded emptyPrivilege()
// literal, unified into one shared builder so all three call sites below can never diverge.
// Called with no arguments (or all-default/false inputs — no elevated attempt made), this is
// byte-identical to the pre-S3-priv `{ mechanism: 'unprivileged', elevated_available: false,
// elevated_used: false }`. On a verified elevated success (Slice 2), the resolved mechanism plus
// elevatedAvailable/elevatedUsed:true are threaded through.
export function computePrivilege({
  mechanism = "unprivileged",
  elevatedAvailable = false,
  elevatedUsed = false,
} = {}) {
  return {
    mechanism,
    elevated_available: elevatedAvailable,
    elevated_used: elevatedUsed,
  };
}

function buildInvalidTargetResult(targetSelection) {
  return {
    target: { kind: targetSelection.kind, value: targetSelection.value },
    resolved: { status: "unknown", pid: undefined, reason: targetSelection.error },
    ancestry: [],
    source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: targetSelection.error } },
    sockets: [],
    warnings: [],
    privilege: computePrivilege(),
  };
}

function buildNotFoundResult(kind, value, probe) {
  return {
    target: { kind, value },
    resolved: { status: "unknown", pid: undefined, reason: "target_not_found_or_permission_limited", probe },
    ancestry: [],
    source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: "target_not_found" } },
    sockets: [],
    warnings: [],
    privilege: computePrivilege(),
  };
}

// S3-priv Slice 2 (additive): `privilege` is an optional override so a caller that has already
// computed a real elevated-path privilege value (resolveCrossUidPortResult, below) can supply it.
// Every pre-existing call site omits it, so `computePrivilege()`'s byte-identical default is
// unaffected.
function finalizeProvenanceResult({ targetSelection, core, sockets, privilege }) {
  const warnings = core.resolvedStatus !== "unknown" ? detectWarnings({ resolved: core.resolved, ancestry: core.ancestry, source: core.source }, sockets) : [];
  return {
    resolvedStatus: core.resolvedStatus,
    result: {
      target: { kind: targetSelection.kind, value: targetSelection.value },
      resolved: core.resolved,
      ancestry: core.ancestry,
      source: core.source,
      sockets,
      warnings,
      privilege: privilege ?? computePrivilege(),
    },
  };
}

// Exported (additive, S4): the structural provenance-warning collector's bounded deleted-exe
// check (narrowed-candidate-only, see plan section 4) reuses this exact
// lsof/fs.stat-on-macOS / readlink-on-linux orchestration rather than re-implementing it.
export async function resolveExecutableInfo(pid) {
  if (process.platform === "linux") {
    try {
      const target = await readlink(`/proc/${pid}/exe`);
      const deleted = isLinuxDeletedExeLink(target);
      return {
        executable_path: deleted ? target.replace(/\s*\(deleted\)$/, "") : target,
        executable_path_unavailable: false,
        deleted_exe: deleted,
        deleted_exe_confidence: 1,
      };
    } catch {
      return { executable_path: undefined, executable_path_unavailable: true, deleted_exe: "unknown", deleted_exe_confidence: undefined };
    }
  }

  if (process.platform === "darwin") {
    const lsofResult = await runFixedExecFile("lsof", ["-a", "-p", String(pid), "-d", "txt"], { timeout: 2500, maxBuffer: 256 * 1024 });
    if (lsofResult.status !== "ok") {
      return { executable_path: undefined, executable_path_unavailable: true, deleted_exe: "unknown", deleted_exe_confidence: undefined };
    }
    const exePath = parseMacLsofTxtExecutablePath(lsofResult.stdout);
    if (!exePath) return { executable_path: undefined, executable_path_unavailable: true, deleted_exe: "unknown", deleted_exe_confidence: undefined };

    let statStatus = "unable";
    try {
      await stat(exePath);
      statStatus = "ok";
    } catch (error) {
      statStatus = error?.code === "ENOENT" ? "enoent" : "unable";
    }
    const deleted = inferMacosDeletedExe({ exePathFromLsof: exePath, statResult: { status: statStatus } });
    return {
      executable_path: exePath,
      executable_path_unavailable: false,
      deleted_exe: deleted,
      deleted_exe_confidence: deleted === true ? 0.7 : deleted === false ? 1 : undefined,
    };
  }

  return { executable_path: undefined, executable_path_unavailable: true, deleted_exe: "unknown", deleted_exe_confidence: undefined };
}

async function resolveCodesignInfo(executablePath) {
  if (!executablePath) return { status: "unsupported", unavailable_reason: "executable_path_unavailable" };

  const codesignResult = await runFixedExecFile("codesign", ["-dv", executablePath], { timeout: 2500, maxBuffer: 256 * 1024 });
  const combined = `${codesignResult.stdout ?? ""}\n${codesignResult.stderr ?? ""}`;
  const identityMatch = combined.match(/^Authority=(.+)$/m);
  const notSigned = /code object is not signed/i.test(combined);
  const signed = codesignResult.status === "ok" && !notSigned;

  // spctl is deliberately excluded from any hard rule input (it false-positives on legitimate
  // unbundled CLI/daemon binaries) — surfaced only as a low-confidence, operator-facing signal.
  const spctlResult = await runFixedExecFile("spctl", ["--assess", "-t", "execute", executablePath], { timeout: 2500, maxBuffer: 256 * 1024 });
  const spctlCombined = `${spctlResult.stdout ?? ""}\n${spctlResult.stderr ?? ""}`;
  const notarized = /source=Notarized Developer ID/i.test(spctlCombined) ? true : spctlResult.status === "ok" ? false : undefined;

  return {
    status: codesignResult.status === "ok" || notSigned ? "ok" : "unable",
    identity: identityMatch ? identityMatch[1].trim() : undefined,
    signed,
    notarized,
    unavailable_reason: codesignResult.status !== "ok" && !notSigned ? "codesign_unable" : undefined,
    spctl_assessment: {
      status: spctlResult.status,
      accepted: spctlResult.status === "ok",
      confidence: 0.3,
      review_hint: "ambiguous",
    },
  };
}

async function resolvePidCore(pid) {
  // A busy host's full process table (unbounded args, every process) can exceed 1MB; bound
  // generously rather than silently truncating the snapshot the target pid needs to be found in.
  const psResult = await runFixedExecFile("ps", provenancePsArgsForPlatform(), { timeout: 3000, maxBuffer: 8 * 1024 * 1024 });
  const processes = psResult.status === "ok" ? parseProvenancePs(psResult.stdout) : [];
  const target = processes.find((item) => item.pid === pid);

  if (!target) {
    return {
      resolvedStatus: "unknown",
      // pid is left undefined (never the queried input echoed back as if observed), matching
      // buildNotFoundResult's degrade-not-fabricate shape for the port/container paths.
      resolved: { status: "unknown", pid: undefined, reason: "process_not_found_or_permission_limited" },
      ancestry: [],
      source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: "process_not_found" } },
    };
  }

  const treeResult = buildParentTreeResult(processes, pid, MAX_ANCESTRY_DEPTH);
  const chain = treeResult.result?.chain ?? [];
  const ancestryChain = chain.map((item) => ({ pid: item.pid, ppid: item.ppid, comm: item.command }));
  const ancestry = chain.map((item) => ({ pid: item.pid, ppid: item.ppid, command_snippet: item.command, args_redaction: item.args_redaction }));
  const source = classifySourceFromAncestry(ancestryChain);

  const [executableInfo, userInfo] = await Promise.all([resolveExecutableInfo(pid), resolveUsernameForUid(target.uid)]);
  const codesign = process.platform === "darwin" ? await resolveCodesignInfo(executableInfo.executable_path) : undefined;

  return {
    resolvedStatus: "ok",
    resolved: {
      status: "ok",
      pid: target.pid,
      ppid: target.ppid,
      // Bound the path in the emitted record (the untruncated value above still feeds the
      // local codesign check); keeps every string reaching the envelope/LLM bounded.
      executable_path: truncate(executableInfo.executable_path),
      executable_path_unavailable: executableInfo.executable_path_unavailable,
      deleted_exe: executableInfo.deleted_exe,
      deleted_exe_confidence: executableInfo.deleted_exe_confidence,
      command: target.command,
      args_redaction: target.args_redaction,
      user: { uid: target.uid, username: userInfo.username, username_unavailable: userInfo.username_unavailable },
      start_time: undefined,
      start_time_unavailable: true,
      codesign,
    },
    ancestry,
    source,
  };
}

async function resolveByPid(pid) {
  const core = await resolvePidCore(pid);
  return finalizeProvenanceResult({ targetSelection: { kind: "pid", value: pid }, core, sockets: [] });
}

async function resolveByPortMac(port) {
  const probe = await runFixedExecFile("lsof", ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN"], { timeout: 3500, maxBuffer: 512 * 1024 });
  if (probe.status !== "ok") return { resolvedStatus: "unknown", result: buildNotFoundResult("port", port, probe) };

  const sockets = buildMacPortSockets(probe.stdout, port);
  if (sockets.length === 0) return { resolvedStatus: "unknown", result: buildNotFoundResult("port", port, probe) };

  const core = await resolvePidCore(sockets[0].pid);
  return finalizeProvenanceResult({
    targetSelection: { kind: "port", value: port },
    core,
    sockets: sockets.map(({ pid: _pid, command: _command, ...socket }) => socket),
  });
}

// S3-priv Slice 2: the cross-UID (or fd-walk-unresolved) degrade, extracted into its own small
// function so the elevated *upgrade* (provenance-elevated.js's resolveElevated) can be layered on
// top without disturbing resolveByPortLinux's /proc-parsing body. Computes the graceful
// unprivileged partial/0.4/missing_permission baseline FIRST and unconditionally -- the owning UID
// is a free confident fact the unprivileged path already has -- then, only when a `paths` carrier
// was actually threaded through from the caller, offers that baseline to resolveElevated as the
// exact value to fall back to on ANY non-success exit path. THE LOAD-BEARING DEGRADE INVARIANT
// (plan §0): every elevated-path failure mode returns this unprivileged outcome UNCHANGED --
// never the more-degraded `unable`/`0` shape (that's timedEnvelope's thrown-exception contract
// only, untouched here).
export async function resolveCrossUidPortResult({ port, primary, sockets }, options = {}) {
  const unprivilegedCore = {
    resolvedStatus: "partial",
    resolved: {
      status: "partial",
      pid: undefined,
      user: { uid: primary.uid, username: undefined, username_unavailable: true },
      reason: "cross_uid_or_unresolved_pid",
    },
    ancestry: [],
    source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: "cross_uid_or_unresolved_pid" } },
  };
  const unprivilegedOutcome = finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core: unprivilegedCore, sockets });

  if (!options.paths) return unprivilegedOutcome;

  // S3-priv Slice 5 Phase 2 Part B: observe the config resolveElevated actually loaded, via a
  // thin wrapper around the exact same `loadProvenanceConfig` DI hook resolveElevated already
  // calls exactly once internally -- zero extra I/O, just a side-channel capture -- so the
  // ptrace_scope diagnostic below can be gated on "an elevation attempt was genuinely
  // CONFIGURED" (config.elevated.enabled===true), never on mere paths-presence. Every real
  // production call site threads `paths` unconditionally (pi-harness.js's createEvidenceTools),
  // so paths-presence alone is not a safe "an attempt happened" signal: the common real-world
  // state today is paths-present-but-disabled (no operator has run Slice 5's manual grant yet),
  // and that state must stay byte-identical to pre-Slice-5 output -- no `ptrace_scope` key at
  // all, on any host, Linux CI included (where the sysctl is actually readable).
  let observedConfig;
  const loadConfig = options.loadProvenanceConfig ?? defaultLoadProvenanceConfig;
  // Codex-hardening #6: capture the elevated invoke's result via the SAME side-channel-wrapper
  // pattern as observedConfig above (zero extra invocations — just observe the one resolveElevated
  // already makes) so an fd/pid-scan truncation (helper EXIT_RESOLUTION_TRUNCATED → the invoke
  // result's additive `fd_scan_truncated` flag) can be surfaced as a pure diagnostic below. Never
  // gates resolution: resolveElevated still degrades to `undefined` on the same unable status.
  let observedInvoke;
  const invoke = options.invokeElevatedHelper ?? defaultInvokeElevatedHelper;
  const upgrade = await resolveElevated(
    { target: { kind: "port", value: port, uid: primary.uid }, paths: options.paths },
    {
      ...options,
      loadProvenanceConfig: async (paths) => {
        observedConfig = await loadConfig(paths);
        return observedConfig;
      },
      invokeElevatedHelper: async (helperPath, argv, invokeOptions) => {
        observedInvoke = await invoke(helperPath, argv, invokeOptions);
        return observedInvoke;
      },
    },
  );

  // Most valuable ON FAILURE ("elevated didn't upgrade -- is ptrace_scope=2 why?"), but attached
  // on the success path too so an operator can see the value that let it work. Pure diagnostic:
  // computed only after the real attempt already ran, and it never gates resolution either way.
  const elevationWasConfigured = observedConfig?.elevated?.enabled === true;
  const ptraceScope = elevationWasConfigured ? await readPtraceScopeDiagnostic({ readFile: options.readFile }) : undefined;
  // Codex-hardening #6: the helper gave up an fd/pid scan at a cap, so a "no owner" here is uncertain
  // rather than a definitive negative. Pure diagnostic, attached the SAME way as ptrace_scope (under
  // result.privilege), never gating resolution. Only ever true on the degrade path (a successful
  // upgrade exits 0, so the flag is absent there).
  const fdScanTruncated = observedInvoke?.fd_scan_truncated === true;
  const withDiagnostics = (outcome) => {
    if (ptraceScope === undefined && !fdScanTruncated) return outcome; // byte-identical: no diagnostic fields.
    const privilege = { ...outcome.result.privilege };
    if (ptraceScope !== undefined) privilege.ptrace_scope = ptraceScope;
    if (fdScanTruncated) privilege.fd_scan_truncated = true;
    return { ...outcome, result: { ...outcome.result, privilege } };
  };

  if (!upgrade) return withDiagnostics(unprivilegedOutcome);

  // Trust model: the owning uid is a FREE, confident fact the unprivileged path already resolved
  // (primary.uid). The helper is trusted ONLY for the NEW fact it provides (the pid + exe/command),
  // never to re-assert a fact we already hold. If the helper self-reports a uid that DISAGREES with
  // the known-good one, it resolved the wrong socket/process (or is compromised), so its pid is also
  // suspect: degrade to the unprivileged baseline rather than merge an untrusted, contradictory fact.
  if (upgrade.uid !== undefined && Number(upgrade.uid) !== Number(primary.uid)) return withDiagnostics(unprivilegedOutcome);

  // Bound the untrusted helper's path/command exactly like the unprivileged path (resolvePidCore
  // truncates executable_path) before either reaches the evidence envelope / triage LLM.
  const elevatedExecutablePath = truncate(upgrade.executablePath);
  const elevatedCommand = truncate(upgrade.command);
  const upgradedCore = {
    resolvedStatus: "ok",
    resolved: {
      status: "ok",
      pid: upgrade.pid,
      executable_path: elevatedExecutablePath,
      executable_path_unavailable: !upgrade.executablePath,
      command: elevatedCommand,
      // Always the trusted, unprivileged-derived owning uid — never the helper's self-report.
      user: { uid: primary.uid, username: undefined, username_unavailable: true },
    },
    ancestry: [],
    source: {
      type: "elevated",
      name: elevatedCommand,
      confidence: 1,
      review_hint: "none",
      details: { reason: "resolved_via_elevated_helper", mechanism: upgrade.mechanism },
    },
  };
  return withDiagnostics(finalizeProvenanceResult({
    targetSelection: { kind: "port", value: port },
    core: upgradedCore,
    sockets,
    privilege: computePrivilege({ mechanism: upgrade.mechanism, elevatedAvailable: true, elevatedUsed: true }),
  }));
}

async function resolveByPortLinux(port, options = {}) {
  const sources = [
    ["tcp", "/proc/net/tcp"],
    ["tcp6", "/proc/net/tcp6"],
    ["udp", "/proc/net/udp"],
    ["udp6", "/proc/net/udp6"],
  ];
  const entries = [];
  for (const [protocol, filePath] of sources) {
    try {
      const contents = await readFile(filePath, "utf8");
      entries.push(...parseProcNetContents(contents, { protocol }));
    } catch {
      // This /proc source is unavailable on this host; continue with the others.
    }
  }

  const matches = entries.filter((entry) => entry.local_port === port && (entry.protocol.startsWith("tcp") ? entry.state === "LISTEN" : true));
  if (matches.length === 0) return { resolvedStatus: "unknown", result: buildNotFoundResult("port", port) };

  const primary = matches[0];
  const sockets = matches.map((entry) => ({
    protocol: entry.protocol,
    local_address: entry.local_address,
    local_port: entry.local_port,
    state: entry.state,
    public_bind: isPublicBindAddress(entry.local_address),
  }));

  const currentUid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (currentUid !== undefined && primary.uid === currentUid) {
    const candidatePids = await listProcPids();
    const fdScanResults = await scanProcFdForInode(candidatePids);
    const matchResult = resolvePidFromFdScanResults(primary.inode, fdScanResults);
    if (matchResult.status === "ok") {
      const core = await resolvePidCore(matchResult.pid);
      return finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core, sockets });
    }
  }

  // Cross-UID, or fd-walk could not resolve a pid: the owning UID is a confident fact; the pid
  // itself is never fabricated. See resolveCrossUidPortResult above for the S3-priv Slice 2
  // elevated-upgrade wrap.
  return resolveCrossUidPortResult({ port, primary, sockets }, options);
}

async function resolveByPort(port, options = {}) {
  if (process.platform === "darwin") return resolveByPortMac(port);
  if (process.platform === "linux") return resolveByPortLinux(port, options);
  return { resolvedStatus: "unknown", result: buildNotFoundResult("port", port) };
}

async function resolveByContainer(containerId) {
  const runtimes = ["docker", "podman"];
  let lastProbe;
  for (const runtime of runtimes) {
    // `--` terminates flag parsing so the container ref is always treated as a positional arg
    // (defense-in-depth alongside the charset guard in normalizeProvenanceTarget).
    const probe = await runFixedExecFile(runtime, ["inspect", "-f", "{{.State.Pid}}", "--", containerId], { timeout: 4000, maxBuffer: 64 * 1024 });
    lastProbe = probe;
    if (probe.status !== "ok") continue;
    const pid = parseContainerInspectPid(probe.stdout);
    if (pid === undefined) continue;

    const core = await resolvePidCore(pid);
    core.source = {
      type: "container",
      name: runtime,
      confidence: core.resolvedStatus === "ok" ? 1 : 0,
      review_hint: core.resolvedStatus === "ok" ? "none" : "ambiguous",
      details: { runtime, container_id: containerId },
    };
    return finalizeProvenanceResult({ targetSelection: { kind: "container", value: containerId }, core, sockets: [] });
  }
  return { resolvedStatus: "unknown", result: buildNotFoundResult("container", containerId, lastProbe) };
}

async function resolveByTarget(targetSelection, options = {}) {
  if (targetSelection.kind === "pid") return resolveByPid(targetSelection.value);
  if (targetSelection.kind === "port") return resolveByPort(targetSelection.value, options);
  if (targetSelection.kind === "container") return resolveByContainer(targetSelection.value);
  return { resolvedStatus: "unknown", result: buildNotFoundResult(targetSelection.kind, targetSelection.value) };
}

function provenanceEnvelopeId(targetSelection) {
  return `provenance-${targetSelection.kind}-${targetSelection.value ?? "unknown"}`;
}

// S3-priv Slice 2 (additive): `options` is a new, optional second argument carrying `paths` (the
// resolved Descartes XDG paths, needed to load configDir/provenance.json) plus DI overrides
// (probeElevatedHelper, invokeElevatedHelper, loadProvenanceConfig, statFn, helperPath, ...)
// threaded down through resolveByTarget -> resolveByPort -> resolveByPortLinux ->
// resolveCrossUidPortResult -> provenance-elevated.js's resolveElevated. Every pre-existing
// single-arg call site continues to produce byte-identical output: with no `options.paths`,
// resolveCrossUidPortResult never even calls resolveElevated (see its own guard).
export async function resolveProvenance(params = {}, options = {}) {
  let targetSelection;
  return timedEnvelope(async () => {
    // Target normalization runs inside the timedEnvelope-wrapped closure (not before it) so that
    // even a pathological/throwing input (not reachable through the tool schema's typed
    // parameters, but possible via direct calls) fails closed through timedEnvelope's contract
    // rather than rejecting resolveProvenance itself.
    targetSelection = normalizeProvenanceTarget(params);
    if (targetSelection.error) {
      return { status: "unknown", confidence: 0, reviewHint: "ambiguous", result: buildInvalidTargetResult(targetSelection) };
    }

    const { resolvedStatus, result } = await resolveByTarget(targetSelection, options);
    const fields = computeProvenanceEnvelopeFields(resolvedStatus, result.source?.type);
    return { status: fields.status, confidence: fields.confidence, reviewHint: fields.reviewHint, result };
  }, (built) => evidenceEnvelope({
    id: provenanceEnvelopeId(targetSelection ?? { kind: "unknown", value: undefined }),
    status: built.status,
    source: "provenance",
    result: built.result,
    confidence: built.confidence,
    reviewHint: built.reviewHint,
    tool: "inspect_runtime_provenance",
    target: targetSelection ? `kind=${targetSelection.kind},value=${targetSelection.value}` : "kind=unknown,value=unknown",
  }));
}
