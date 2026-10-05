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
import { open, readdir, readFile, readlink, stat } from "node:fs/promises";
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

// Owner-dependent conclusions must remain monotonic when a scan cannot prove ownership. Keep this
// classification in one place because both the per-socket and same-port aggregation paths receive
// these reasons from different layers (Node fd scans and the elevated helper).
export function classifyOwnerAmbiguityReason(reason) {
  if (typeof reason !== "string") return undefined;
  if (reason === "fd_scan_truncated") return { status: "truncated", review_hint: "out_of_range", owner_dependent: true };
  if (new Set([
    "owner_ambiguous",
    "elevated_owner_ambiguous",
    "owner_identity_unavailable",
    "fd_scan_uncertain",
    "owner_identity_changed",
    "fd_recheck_uncertain",
    "owner_fd_recheck_failed",
    "owner_recheck_exhausted",
    "procfs_pid_namespace_mismatch",
    "process_identity_unavailable",
    "socket_attribution_missing",
    "socket_attribution_incomplete",
  ]).has(reason)) {
    return { status: "ambiguous", review_hint: "ambiguous", owner_dependent: true };
  }
  if (new Set(["cross_uid_or_unresolved_pid", "socket_attribution_unresolved", "missing_permission"]).has(reason)) {
    return { status: "partial", review_hint: "missing_permission", owner_dependent: true };
  }
  return undefined;
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

  const ownerClassification = classifyOwnerAmbiguityReason(resolved.reason ?? source.details?.reason);
  const ownerFactsUncertain = ownerClassification?.owner_dependent === true && resolved.status !== "ok";
  if (!ownerFactsUncertain && hasPublicBindNoSupervisor(source.type, sockets)) {
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

export function parseProcNetLine(line, { protocol, includeAllUdpStates = false } = {}) {
  const parts = String(line ?? "").trim().split(/\s+/);
  if (parts.length < 10) return undefined;

  const [localHex, localPortHex] = String(parts[1] ?? "").split(":");
  if (!localHex || localPortHex === undefined) return undefined;

  const isV6 = String(protocol ?? "").includes("6") || localHex.length === 32;
  const address = isV6 ? decodeProcNetIPv6(localHex) : decodeProcNetIPv4(localHex);
  const localPort = parseInt(localPortHex, 16);
  if (address === undefined || Number.isNaN(localPort)) return undefined;

  const stateHex = String(parts[3] ?? "").toUpperCase();
  const isUdp = String(protocol ?? "").startsWith("udp");
  if (isUdp && stateHex !== "07" && !includeAllUdpStates) return undefined;
  const uid = Number(parts[7]);
  const inode = parts[9];

  return {
    protocol: protocol ?? (isV6 ? "tcp6" : "tcp"),
    local_address: address,
    local_port: localPort,
    state: isUdp && stateHex === "07" ? "UNCONN" : (TCP_STATE_NAMES[stateHex] ?? stateHex),
    uid: Number.isFinite(uid) ? uid : undefined,
    inode,
  };
}

export function parseProcNetContents(contents, { protocol } = {}) {
  const lines = String(contents ?? "").split("\n").slice(1);
  return lines.map((line) => (line.trim() ? parseProcNetLine(line, { protocol }) : undefined)).filter(Boolean);
}

export function buildLinuxSocketFact(entry) {
  return {
    protocol: entry.protocol,
    local_address: entry.local_address,
    local_port: entry.local_port,
    state: entry.state,
    public_bind: isPublicBindAddress(entry.local_address),
    inode: entry.inode,
    uid: entry.uid,
  };
}

// Pure inode->pid matcher over an already-performed fd scan. fdScanResults is
// [{ pid, accessible: bool, fds?: [{ fd, target }] }, ...] — accessible:false represents an
// EACCES (cross-UID, permission-limited) /proc/<pid>/fd readdir. Never fabricates a pid.
export function resolvePidFromFdScanResults(targetInode, fdScanResults = []) {
  const scanResults = Array.isArray(fdScanResults) ? fdScanResults : (fdScanResults.results ?? []);
  const scanTruncated = !Array.isArray(fdScanResults) && fdScanResults.truncated === true;
  const scanUncertain = !Array.isArray(fdScanResults) && fdScanResults.uncertain === true;
  const matches = scanResults.filter((entry) => entry.accessible !== false
    && (entry.fds ?? []).some((fd) => fd.target === `socket:[${targetInode}]`));
  if (scanTruncated) {
    return { status: "truncated", pid: undefined, confidence: 0, review_hint: "out_of_range", reason: "fd_scan_truncated" };
  }
  if (scanUncertain) {
    return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: "fd_scan_uncertain" };
  }
  if (matches.length > 0) {
    const identities = matches.map((entry) => ({
      tgid: entry.tgid ?? entry.pid,
      start_time: entry.start_time,
    }));
    if (identities.some((identity) => !Number.isInteger(identity.tgid) || typeof identity.start_time !== "string")) {
      return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: "owner_identity_unavailable" };
    }
    const distinct = new Set(identities.map((identity) => `${identity.tgid}:${identity.start_time}`));
    if (distinct.size > 1) {
      return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: "owner_ambiguous", owners: matches.map((entry, index) => ({ pid: entry.pid, ...identities[index] })) };
    }
    return { status: "ok", pid: matches[0].pid, confidence: 1, owners: matches.map((entry, index) => ({ pid: entry.pid, ...identities[index] })) };
  }
  const hadInaccessible = scanResults.some((entry) => entry.accessible === false);
  if (hadInaccessible) return { status: "partial", pid: undefined, confidence: 0, review_hint: "missing_permission" };
  return { status: "unknown", pid: undefined, confidence: 0 };
}

async function verifyProcFdHolder(targetInode, owner, options = {}) {
  const readdirFn = options.readdirFn ?? readdir;
  const readFileFn = options.readFileFn ?? readFile;
  const readlinkFn = options.readlinkFn ?? readlink;
  const openFn = options.openFn ?? open;
  try {
    const fdNames = await readdirFn(`/proc/${owner.pid}/fd`);
    const processStat = await readFileFn(`/proc/${owner.pid}/stat`, "utf8");
    const identity = parseLinuxProcessIdentity(processStat, owner.pid);
    if (identity.tgid !== owner.tgid || identity.start_time !== owner.start_time) {
      return { status: "ambiguous", reason: "owner_identity_changed" };
    }
    for (const fdName of fdNames) {
      let target;
      try {
        target = await readlinkFn(`/proc/${owner.pid}/fd/${fdName}`);
      } catch {
        return { status: "ambiguous", reason: "fd_recheck_uncertain" };
      }
      if (target !== `socket:[${targetInode}]`) continue;

      const executablePath = await readlinkFn(`/proc/${owner.pid}/exe`).catch(() => undefined);
      if (executablePath === undefined || executablePath !== owner.executable_path) {
        return { status: "ambiguous", reason: "executable_generation_changed" };
      }
      const exeFd = await openFn(`/proc/${owner.pid}/exe`, "r").catch(() => undefined);
      if (!exeFd) return { status: "ambiguous", reason: "executable_generation_unavailable" };
      let exeStat;
      try {
        exeStat = await exeFd.stat();
      } finally {
        await exeFd.close();
      }
      if (owner.executable_dev !== undefined && owner.executable_ino !== undefined
        && (String(exeStat.dev) !== String(owner.executable_dev) || String(exeStat.ino) !== String(owner.executable_ino))) {
        return { status: "ambiguous", reason: "executable_generation_changed" };
      }
      const cmdline = await readFileFn(`/proc/${owner.pid}/cmdline`, "utf8").catch(() => undefined);
      if (cmdline === undefined || (owner.cmdline !== undefined && cmdline !== owner.cmdline)) {
        return { status: "ambiguous", reason: "cmdline_changed" };
      }
      return { status: "ok" };
    }
    return { status: "ambiguous", reason: "owner_fd_recheck_failed" };
  } catch {
    return { status: "ambiguous", reason: "fd_recheck_uncertain" };
  }
}

export async function verifyFinalSocketResolution(targetInode, expectedRow, owners, options = {}) {
  const readFileFn = options.readFileFn ?? readFile;
  const readlinkFn = options.readlinkFn ?? readlink;
  const openFn = options.openFn ?? open;
  const protocolPath = `/proc/net/${expectedRow.protocol}`;
  let contents;
  try {
    contents = await readFileFn(protocolPath, "utf8");
  } catch {
    return { status: "ambiguous", reason: "socket_row_recheck_uncertain" };
  }
  const row = String(contents).split("\n")
    .map((line) => parseProcNetLine(line, { protocol: expectedRow.protocol, includeAllUdpStates: true }))
    .find((candidate) => candidate?.inode === expectedRow.inode);
  if (!row || row.local_port !== expectedRow.local_port || row.state !== expectedRow.state
    || row.uid !== expectedRow.uid || row.local_address !== expectedRow.local_address) {
    return { status: "retry", reason: "socket_row_changed" };
  }
  for (const owner of owners) {
    const verification = await verifyProcFdHolder(targetInode, owner, { readFileFn, readlinkFn, openFn });
    if (verification.status !== "ok") return verification;
  }
  return { status: "ok" };
}

const MAX_OWNER_STABILITY_PASSES = 3;

function scanResultEntries(scan) {
  return Array.isArray(scan) ? scan : (Array.isArray(scan?.results) ? scan.results : []);
}

function processIdentityKey(entry) {
  if (!entry || entry.accessible === false || !Number.isInteger(entry.tgid) || typeof entry.start_time !== "string") return undefined;
  return `${entry.tgid}:${entry.start_time}`;
}

function scanHasNewOrReusedPids(previousScan, nextScan) {
  const previous = new Map(scanResultEntries(previousScan).map((entry) => [entry.pid, processIdentityKey(entry)]));
  return scanResultEntries(nextScan).some((entry) => {
    if (!Number.isInteger(entry?.pid)) return false;
    const previousIdentity = previous.get(entry.pid);
    if (previousIdentity === undefined) return !previous.has(entry.pid);
    const nextIdentity = processIdentityKey(entry);
    return nextIdentity !== undefined && nextIdentity !== previousIdentity;
  });
}

function scanHasReusedHolder(targetInode, previousScan, nextScan) {
  const previous = new Map(scanResultEntries(previousScan).map((entry) => [entry.pid, processIdentityKey(entry)]));
  return scanResultEntries(nextScan).some((entry) => {
    if (!Number.isInteger(entry?.pid)) return false;
    const previousIdentity = previous.get(entry.pid);
    const nextIdentity = processIdentityKey(entry);
    const changed = previousIdentity !== undefined && nextIdentity !== undefined && previousIdentity !== nextIdentity;
    const holds = (entry.fds ?? []).some((fd) => fd.target === `socket:[${targetInode}]`);
    return changed && holds;
  });
}

function holderIdentitySet(scan, targetInode) {
  return scanResultEntries(scan)
    .filter((entry) => entry.accessible !== false && (entry.fds ?? []).some((fd) => fd.target === `socket:[${targetInode}]`))
    .map((entry) => `${entry.pid}:${entry.tgid}:${entry.start_time}`)
    .sort()
    .join("|");
}

// A scan snapshot is not itself a current ownership proof. Scan first, re-enumerate until the
// complete PID/holder snapshot is stable, then run ONE final verification phase strictly after
// the last enumeration. That phase rechecks the socket row, every selected holder's fd link,
// (tgid,start_time), freshly-opened-exe fstat generation, and cmdline. This ordering is an
// invariant: later edits must not move a check back in front of the final enumeration.
export async function resolveVerifiedPidFromFdScanResults(targetInode, fdScanResults, { scanAgain, verifyHolder, verifyFinal } = {}) {
  const verify = verifyHolder ?? verifyProcFdHolder;
  const verifyAll = verifyFinal ?? (async (inode, owners) => {
    for (const owner of owners) {
      const verification = await verify(inode, owner);
      if (verification.status !== "ok") return verification;
    }
    return { status: "ok" };
  });

  const resolveOnce = async (initialScan) => {
    let currentScan = initialScan;
    for (let pass = 0; pass < MAX_OWNER_STABILITY_PASSES; pass += 1) {
      const match = resolvePidFromFdScanResults(targetInode, currentScan);
      if (match.status !== "ok") return match;
      if (!scanAgain) {
        const verification = await verifyAll(targetInode, match.owners ?? [{ pid: match.pid }], currentScan);
        return verification.status === "ok" ? match : { status: "retry", reason: verification.reason };
      }

      const refreshedScan = await scanAgain();
      if (scanHasReusedHolder(targetInode, currentScan, refreshedScan)) {
        return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: "owner_identity_changed" };
      }
      const pidSetChanged = scanHasNewOrReusedPids(currentScan, refreshedScan);
      const holderSetChanged = holderIdentitySet(currentScan, targetInode) !== holderIdentitySet(refreshedScan, targetInode);
      if (pidSetChanged || holderSetChanged) {
        if (pass === MAX_OWNER_STABILITY_PASSES - 1) {
          return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: "owner_recheck_exhausted" };
        }
        // The complete refresh is authoritative. Removed PIDs/holders are intentionally not
        // merged back into the next proof; a union could resurrect a stale or reused owner.
        currentScan = refreshedScan;
        continue;
      }

      const stableMatch = resolvePidFromFdScanResults(targetInode, refreshedScan);
      if (stableMatch.status !== "ok") return stableMatch;
      const verification = await verifyAll(targetInode, stableMatch.owners ?? [{ pid: stableMatch.pid }], refreshedScan);
      return verification.status === "ok" ? stableMatch : { status: "retry", reason: verification.reason };
    }
    return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: "owner_recheck_exhausted" };
  };

  let currentScan = fdScanResults;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const outcome = await resolveOnce(currentScan);
    if (outcome.status !== "retry") return outcome;
    if (!scanAgain || attempt === 1) {
      return { status: "ambiguous", pid: undefined, confidence: 0, review_hint: "ambiguous", reason: outcome.reason ?? "owner_recheck_failed" };
    }
    // A final-generation change retries the entire scan/enumeration/verification proof once.
    currentScan = await scanAgain();
  }
}

// A numeric port is not an identity: TCP/UDP rows and SO_REUSEPORT siblings can coexist. This
// pure reducer is shared by the live Linux path and fixtures so a result is confident only when
// every matching row was attributed and all attributed rows name the same executable.
export function summarizeSocketAttributions(attributions = []) {
  if (!Array.isArray(attributions) || attributions.length === 0) {
    return { status: "ambiguous", executablePath: undefined, reason: "socket_attribution_missing" };
  }
  const identities = new Set();
  const reasons = [];
  for (const attribution of attributions) {
    if (attribution?.resolved !== true) {
      const reason = attribution?.reason ?? "socket_attribution_unresolved";
      if (!reasons.includes(reason)) reasons.push(reason);
      continue;
    }
    const identity = attribution.processIdentity;
    if (!identity || !Number.isInteger(identity.tgid) || typeof identity.start_time !== "string") {
      const classification = classifyOwnerAmbiguityReason("owner_identity_unavailable");
      return { status: classification.status, executablePath: undefined, reason: "owner_identity_unavailable" };
    }
    identities.add(`${identity.tgid}:${identity.start_time}`);
  }
  if (reasons.length > 0) {
    const classifications = reasons.map(classifyOwnerAmbiguityReason).filter(Boolean);
    const status = classifications.some((classification) => classification.status === "ambiguous")
      ? "ambiguous"
      : classifications.some((classification) => classification.status === "truncated")
        ? "truncated"
        : classifications.find((classification) => classification.status === "partial")?.status ?? "partial";
    return { status, executablePath: undefined, reason: reasons[0], reasons };
  }
  if (identities.size !== 1) {
    return { status: "ambiguous", executablePath: undefined, reason: "owner_ambiguous", reasons: ["owner_ambiguous"] };
  }
  return { status: "ok", reason: "socket_attribution_consistent" };
}

// Exported (additive, S4): the structural provenance-warning collector needs to enumerate all
// pids once and fd-scan them once (bounded, see plan section 4) to resolve Linux socket owners
// across every listener in a single pass, reusing this exactly rather than re-deriving it.
export async function listProcPids() {
  // Deliberately not wrapped in try/catch: a Linux port-resolution code path running without
  // /proc mounted (e.g. an unusual chroot/container) is a genuinely exceptional condition this
  // module has no graceful degrade for; timedEnvelope's fail-closed contract covers it.
  const entries = await readdir("/proc");
  const pids = entries.filter((name) => /^\d+$/.test(name)).map(Number);
  return { pids: pids.slice(0, MAX_LINUX_FD_SCAN_PIDS), truncated: pids.length > MAX_LINUX_FD_SCAN_PIDS };
}

// Before any Node same-UID /proc resolution, prove that this procfs view's self entry names the
// current process. An ancestor-visible procfs mount can otherwise make a numeric PID appear to
// be a local same-UID process when it belongs to another PID namespace.
export async function verifyProcfsPidNamespace({ readlinkFn = readlink } = {}) {
  try {
    return (await readlinkFn("/proc/self")) === String(process.pid);
  } catch {
    return false;
  }
}

export async function scanProcFdForInode(candidatePids, { listingTruncated = false } = {}) {
  const results = [];
  let uncertain = listingTruncated;
  for (const pid of candidatePids) {
    try {
      const fdNames = await readdir(`/proc/${pid}/fd`);
      const processStat = await readFile(`/proc/${pid}/stat`, "utf8");
      const processIdentity = parseLinuxProcessIdentity(processStat, pid);
      const fds = [];
      for (const fdName of fdNames) {
        try {
          const target = await readlink(`/proc/${pid}/fd/${fdName}`);
          fds.push({ fd: fdName, target });
        } catch {
          // An unread fd can hide the target socket. Keep scanning, but never call the result
          // exhaustive or confident.
          uncertain = true;
        }
      }
      const result = { pid, ...processIdentity, accessible: true, fds };
      if (fds.some((fd) => fd.target.startsWith("socket:["))) {
        try {
          const executablePath = await readlink(`/proc/${pid}/exe`);
          const exeFd = await open(`/proc/${pid}/exe`, "r");
          let exeStat;
          try {
            exeStat = await exeFd.stat();
          } finally {
            await exeFd.close();
          }
          result.executable_path = executablePath;
          result.executable_dev = String(exeStat.dev);
          result.executable_ino = String(exeStat.ino);
          result.cmdline = await readFile(`/proc/${pid}/cmdline`, "utf8");
        } catch {
          // A matching holder whose identity evidence cannot be read is uncertain, never a
          // confident owner. The final verification phase also requires these fields.
          uncertain = true;
        }
      }
      results.push(result);
    } catch (error) {
      uncertain = true;
      results.push({ pid, accessible: false, error: error?.code });
    }
  }
  return { results, truncated: listingTruncated, uncertain };
}

export function parseLinuxProcessIdentity(statContents, pid) {
  const afterComm = String(statContents ?? "").match(/^\d+\s+\(.*\)\s+(.*)$/s)?.[1];
  const fields = afterComm?.trim().split(/\s+/) ?? [];
  const startTime = fields[19];
  return { tgid: pid, start_time: /^\d+$/.test(startTime ?? "") ? startTime : undefined };
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
  const reviewHint = resolvedStatus === "partial" ? "missing_permission" : resolvedStatus === "truncated" ? "out_of_range" : sourceType === "unknown" || resolvedStatus === "ambiguous" ? "ambiguous" : "none";
  const status = ["ok", "partial", "ambiguous", "truncated"].includes(resolvedStatus) ? resolvedStatus : "unknown";
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
  const warnings = core.resolvedStatus === "ok" ? detectWarnings({ resolved: core.resolved, ancestry: core.ancestry, source: core.source }, sockets) : [];
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

  const processIdentity = process.platform === "linux"
    ? await (async () => {
      try {
        return parseLinuxProcessIdentity(await readFile(`/proc/${pid}/stat`, "utf8"), pid);
      } catch {
        return { tgid: pid, start_time: undefined };
      }
    })()
    : { tgid: pid, start_time: `pid:${pid}` };
  if (typeof processIdentity.start_time !== "string") {
    return {
      resolvedStatus: "unknown",
      resolved: { status: "unknown", pid: undefined, reason: "process_identity_unavailable" },
      ancestry: [],
      source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: "process_identity_unavailable" } },
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
      tgid: processIdentity.tgid,
      start_time: processIdentity.start_time,
      start_time_unavailable: false,
      process_identity: processIdentity,
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
  // 2026-10 (research finding 2): bind the elevated request to the EXACT socket this path observed
  // (`primary`, i.e. matches[0]) -- protocol + port + inode -- not a bare port the helper would
  // re-observe independently. A primary lacking a usable protocol/inode simply never attempts
  // elevation (resolveElevated's buildHelperArgv fails closed to undefined).
  const socketTarget = { kind: "socket", protocol: primary.protocol, port, inode: primary.inode, uid: primary.uid };
  const upgrade = await resolveElevated(
    { target: socketTarget, paths: options.paths },
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
  // 2026-10 (research finding 8): the helper's confinement (NNP/seccomp/cap-drop) failed to engage
  // and it aborted fail-closed -- its own exit code now, never conflated with a truncated scan.
  const helperHardeningFailure = observedInvoke?.helper_hardening_failure === true;
  // The live seccomp filter kills the helper with SIGSYS rather than returning a normal exit
  // code. Keep that distinct from its own fail-closed exit 4 so operators can tell a policy
  // violation/self-SIGSYS from an initialization failure.
  const helperSeccompKilled = observedInvoke?.helper_seccomp_killed === true;
  // execFile marks a child killed by its timeout with `killed:true`; preserve that as a separate
  // diagnostic instead of making it look like a generic unavailable helper.
  const helperTimeoutKilled = observedInvoke?.helper_timeout_killed === true;
  // 2026-10 (research finding 2): the exact socket is held by processes running different
  // executables -- the helper named no owner rather than guess.
  const ownerAmbiguous = observedInvoke?.owner_ambiguous === true;
  const procfsNamespaceMismatch = observedInvoke?.procfs_namespace_mismatch === true;
  const degradedReasons = [
    ...(fdScanTruncated ? ["fd_scan_truncated"] : []),
    ...(ownerAmbiguous ? ["elevated_owner_ambiguous"] : []),
    ...(procfsNamespaceMismatch ? ["procfs_pid_namespace_mismatch"] : []),
  ];
  const helperDiagnosticReasons = [
    ...(helperHardeningFailure ? ["helper_hardening_failure"] : []),
    ...(helperSeccompKilled ? ["helper_seccomp_killed"] : []),
    ...(helperTimeoutKilled ? ["helper_timeout_killed"] : []),
  ];
  const evidenceReasons = [...degradedReasons, ...helperDiagnosticReasons];
  const degradedClassifications = degradedReasons.map(classifyOwnerAmbiguityReason).filter(Boolean);
  const degradedClassification = degradedClassifications.find((classification) => classification.status === "ambiguous")
    ?? degradedClassifications.find((classification) => classification.status === "truncated")
    ?? degradedClassifications[0];
  const degradedReason = degradedReasons.find((reason) => classifyOwnerAmbiguityReason(reason)?.status === degradedClassification?.status)
    ?? degradedReasons[0];
  const degradedOutcome = evidenceReasons.length === 0
    ? unprivilegedOutcome
    : (() => {
      // The centralized owner classifier is the sole authority for status. In particular, a
      // procfs namespace mismatch is ambiguity about which process namespace was observed, not a
      // permission-only partial result.
      const resolvedStatus = degradedClassification?.status ?? unprivilegedCore.resolvedStatus;
      const reason = degradedReason ?? helperDiagnosticReasons[0] ?? unprivilegedCore.resolved.reason;
      const core = {
        ...unprivilegedCore,
        resolvedStatus,
        resolved: { ...unprivilegedCore.resolved, status: resolvedStatus, reason, reasons: evidenceReasons },
        source: { ...unprivilegedCore.source, details: { ...unprivilegedCore.source.details, reason, reasons: evidenceReasons } },
      };
      return finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core, sockets });
    })();
  const withDiagnostics = (outcome) => {
    if (ptraceScope === undefined && !fdScanTruncated && !helperHardeningFailure && !helperSeccompKilled && !helperTimeoutKilled && !ownerAmbiguous && !procfsNamespaceMismatch) return outcome; // byte-identical: no diagnostic fields.
    const privilege = { ...outcome.result.privilege };
    if (ptraceScope !== undefined) privilege.ptrace_scope = ptraceScope;
    if (fdScanTruncated) privilege.fd_scan_truncated = true;
    if (helperHardeningFailure) privilege.helper_hardening_failure = true;
    if (helperSeccompKilled) privilege.helper_seccomp_killed = true;
    if (helperTimeoutKilled) privilege.helper_timeout_killed = true;
    if (ownerAmbiguous) privilege.elevated_owner_ambiguous = true;
    if (procfsNamespaceMismatch) privilege.procfs_pid_namespace_mismatch = true;
    return { ...outcome, result: { ...outcome.result, privilege } };
  };

  if (!upgrade) return withDiagnostics(degradedOutcome);

  // Trust model: the owning uid is a FREE, confident fact the unprivileged path already resolved
  // (primary.uid). The helper is trusted ONLY for the NEW fact it provides (the pid + exe/command),
  // never to re-assert a fact we already hold. If the helper self-reports a uid that DISAGREES with
  // the known-good one, it resolved the wrong socket/process (or is compromised), so its pid is also
  // suspect: degrade to the unprivileged baseline rather than merge an untrusted, contradictory fact.
  if (upgrade.uid !== undefined && Number(upgrade.uid) !== Number(primary.uid)) return withDiagnostics(unprivilegedOutcome);

  // Bound the untrusted helper's path/command exactly like the unprivileged path (resolvePidCore
  // truncates executable_path) before either reaches the evidence envelope / triage LLM.
  const elevatedExecutablePath = truncate(upgrade.executablePath);
  const elevatedCommandRedaction = redactAndBoundProcessArgs(upgrade.command ?? "");
  const elevatedCommand = elevatedCommandRedaction.value;
  const upgradedCore = {
    resolvedStatus: "ok",
    resolved: {
      status: "ok",
      pid: upgrade.pid,
      tgid: upgrade.tgid,
      start_time: upgrade.startTime,
      process_identity: { tgid: upgrade.tgid, start_time: upgrade.startTime },
      executable_path: elevatedExecutablePath,
      executable_path_unavailable: !upgrade.executablePath,
      command: elevatedCommand,
      args_redaction: {
        redacted: elevatedCommandRedaction.redacted,
        truncated: elevatedCommandRedaction.truncated || upgrade.argv_truncated === true,
        original_length: elevatedCommandRedaction.original_length,
        max_length: elevatedCommandRedaction.max_length,
        ...(upgrade.argv_truncated === true ? { reason: "cmdline_truncated" } : {}),
      },
      ...(upgrade.argv_truncated === true ? { command_truncated: true, command_truncation_reason: "cmdline_truncated" } : {}),
      // Always the trusted, unprivileged-derived owning uid — never the helper's self-report.
      user: { uid: primary.uid, username: undefined, username_unavailable: true },
    },
    ancestry: [],
    source: {
      type: "elevated",
      name: elevatedCommand,
      confidence: 1,
      review_hint: "none",
      details: {
        reason: "resolved_via_elevated_helper",
        mechanism: upgrade.mechanism,
        // The bound socket identity the helper verified, and how many processes (all one
        // executable) hold it -- e.g. >1 for a pre-fork server's master + workers.
        socket: { protocol: socketTarget.protocol, inode: socketTarget.inode },
        ...(upgrade.holders !== undefined ? { socket_holders: upgrade.holders } : {}),
      },
    },
  };
  return withDiagnostics(finalizeProvenanceResult({
    targetSelection: { kind: "port", value: port },
    core: upgradedCore,
    sockets,
    privilege: computePrivilege({ mechanism: upgrade.mechanism, elevatedAvailable: true, elevatedUsed: true }),
  }));
}

export async function resolveByPortLinux(port, options = {}) {
  const readFileFn = options.readFile ?? readFile;
  const listProcPidsFn = options.listProcPids ?? listProcPids;
  const scanProcFdForInodeFn = options.scanProcFdForInode ?? scanProcFdForInode;
  const resolvePidCoreFn = options.resolvePidCore ?? resolvePidCore;
  const sources = [
    ["tcp", "/proc/net/tcp"],
    ["tcp6", "/proc/net/tcp6"],
    ["udp", "/proc/net/udp"],
    ["udp6", "/proc/net/udp6"],
  ];
  const entries = [];
  for (const [protocol, filePath] of sources) {
    try {
      const contents = await readFileFn(filePath, "utf8");
      entries.push(...parseProcNetContents(contents, { protocol }));
    } catch {
      // This /proc source is unavailable on this host; continue with the others.
    }
  }

  const matches = entries.filter((entry) => entry.local_port === port && (entry.protocol.startsWith("tcp") ? entry.state === "LISTEN" : true));
  if (matches.length === 0) return { resolvedStatus: "unknown", result: buildNotFoundResult("port", port) };

  const sockets = matches.map(buildLinuxSocketFact);

  const currentUid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const hasSameUidSocket = currentUid !== undefined && matches.some((entry) => entry.uid === currentUid);
  const procfsNamespaceMatches = !hasSameUidSocket
    || await (options.verifyProcfsPidNamespace ?? verifyProcfsPidNamespace)({ readlinkFn: options.readlink ?? readlink });
  const pidListing = procfsNamespaceMatches && hasSameUidSocket
    ? await listProcPidsFn()
    : { pids: [], truncated: false };
  const candidatePids = Array.isArray(pidListing) ? pidListing : pidListing.pids;
  const fdScanResults = candidatePids.length > 0
    ? await scanProcFdForInodeFn(candidatePids, { listingTruncated: !Array.isArray(pidListing) && pidListing.truncated })
    : { results: [], truncated: false, uncertain: false };
  const attributions = [];
  const outcomes = [];
  for (const [index, entry] of matches.entries()) {
    const socket = sockets[index];
    if (currentUid !== undefined && entry.uid === currentUid) {
      if (!procfsNamespaceMatches) {
        attributions.push({ resolved: false, reason: "procfs_pid_namespace_mismatch" });
        continue;
      }
      const matchResult = await resolveVerifiedPidFromFdScanResults(entry.inode, fdScanResults, {
        scanAgain: async () => {
          const refreshedListing = await listProcPidsFn();
          const refreshedPids = Array.isArray(refreshedListing) ? refreshedListing : refreshedListing.pids;
          return scanProcFdForInodeFn(refreshedPids, {
            listingTruncated: !Array.isArray(refreshedListing) && refreshedListing.truncated,
          });
        },
        ...(options.verifyFinal ? { verifyFinal: options.verifyFinal } : options.verifyProcFdHolder ? {} : {
          verifyFinal: (inode, owners) => verifyFinalSocketResolution(inode, entry, owners, {
            readFileFn,
            readlinkFn: options.readlink ?? readlink,
            openFn: options.open ?? open,
          }),
        }),
        ...(options.verifyProcFdHolder ? { verifyHolder: options.verifyProcFdHolder } : {}),
      });
      if (matchResult.status === "ok") {
        const cores = await Promise.all((matchResult.owners ?? [{ pid: matchResult.pid }]).map(async (owner) => ({
          owner,
          core: await resolvePidCoreFn(owner.pid),
        })));
        const resolvedCores = cores.filter(({ core }) => core.resolvedStatus === "ok");
        const identitiesAgree = resolvedCores.length === cores.length
          && resolvedCores.every(({ owner, core }) => core.resolved.process_identity?.tgid === owner.tgid
            && core.resolved.process_identity?.start_time === owner.start_time);
        const distinctIdentities = new Set(resolvedCores.map(({ core }) => {
          const identity = core.resolved.process_identity;
          return identity ? `${identity.tgid}:${identity.start_time}` : "missing";
        }));
        if (identitiesAgree && distinctIdentities.size === 1) {
          const core = resolvedCores[0].core;
          const processIdentity = core.resolved.process_identity;
          attributions.push({ resolved: true, executablePath: core.resolved.executable_path, processIdentity });
          outcomes.push(finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core, sockets }));
          continue;
        }
        attributions.push({ resolved: false, reason: distinctIdentities.size > 1 ? "owner_ambiguous" : "owner_identity_unavailable" });
        continue;
      }
      const originalReason = matchResult.reason ?? "socket_attribution_unresolved";
      if (options.paths) {
        const elevatedOutcome = await resolveCrossUidPortResult({ port, primary: entry, sockets: [socket] }, options);
        if (elevatedOutcome.resolvedStatus === "ok") {
          attributions.push({ resolved: true, executablePath: elevatedOutcome.result.resolved.executable_path, processIdentity: elevatedOutcome.result.resolved.process_identity });
          outcomes.push(elevatedOutcome);
          continue;
        }
        const originalClass = classifyOwnerAmbiguityReason(originalReason);
        const elevatedReason = elevatedOutcome.result.resolved.reason;
        const elevatedClass = classifyOwnerAmbiguityReason(elevatedReason);
        const rank = { unknown: 0, partial: 1, truncated: 2, ambiguous: 3 };
        const originalRank = rank[originalClass?.status ?? "partial"];
        const elevatedRank = rank[elevatedClass?.status ?? "partial"];
        attributions.push({ resolved: false, reason: elevatedRank >= originalRank ? elevatedReason : originalReason });
        continue;
      }
      attributions.push({ resolved: false, reason: originalReason });
      continue;
    } else if (options.paths) {
      const outcome = await resolveCrossUidPortResult({ port, primary: entry, sockets: [socket] }, options);
      if (outcome.resolvedStatus === "ok") {
        attributions.push({ resolved: true, executablePath: outcome.result.resolved.executable_path, processIdentity: outcome.result.resolved.process_identity });
        outcomes.push(outcome);
        continue;
      }
      attributions.push({ resolved: false, reason: outcome.result.resolved.reason ?? "socket_attribution_unresolved" });
      continue;
    }
    attributions.push({ resolved: false, reason: "socket_attribution_unresolved" });
  }

  if (matches.length > 1) {
    const summary = summarizeSocketAttributions(attributions);
    if (summary.status !== "ok") {
      const core = {
        resolvedStatus: summary.status,
        resolved: {
          status: summary.status,
          pid: undefined,
          user: { uid: undefined, username: undefined, username_unavailable: true },
          reason: summary.reason,
          ...(summary.reasons ? { reasons: summary.reasons } : {}),
        },
        ancestry: [],
        source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: summary.reason, ...(summary.reasons ? { reasons: summary.reasons } : {}), socket_count: matches.length } },
      };
      return finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core, sockets });
    }
    if (outcomes.length !== matches.length) {
      const core = {
        resolvedStatus: "partial",
        resolved: {
          status: "partial",
          pid: undefined,
          user: { uid: undefined, username: undefined, username_unavailable: true },
          reason: "socket_attribution_incomplete",
        },
        ancestry: [],
        source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason: "socket_attribution_incomplete", socket_count: matches.length } },
      };
      return finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core, sockets });
    }
    const selected = outcomes[0];
    return { ...selected, result: { ...selected.result, sockets } };
  }

  const primary = matches[0];
  if (outcomes.length === 1) return outcomes[0];

  if (matches.length === 1 && attributions[0]?.resolved !== true && currentUid !== undefined && primary.uid === currentUid) {
    const reason = attributions[0]?.reason ?? "socket_attribution_unresolved";
    const resolvedStatus = classifyOwnerAmbiguityReason(reason)?.status ?? "partial";
    const core = {
      resolvedStatus,
      resolved: {
        status: resolvedStatus,
        pid: undefined,
        user: { uid: primary.uid, username: undefined, username_unavailable: true },
        reason,
      },
      ancestry: [],
      source: { type: "unknown", name: undefined, confidence: 0, review_hint: "ambiguous", details: { reason } },
    };
    return finalizeProvenanceResult({ targetSelection: { kind: "port", value: port }, core, sockets });
  }

  // Cross-UID, or fd-walk could not resolve a pid: the owning UID is a confident fact; the pid
  // itself is never fabricated. See resolveCrossUidPortResult above for the S3-priv upgrade.
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
