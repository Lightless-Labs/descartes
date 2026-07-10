// Layer B / Slice S4 — structural provenance-warning sub-collector + candidate mapping.
//
// Turns S3's warnings-as-facts (deleted-exe running, public bind with no recognized
// supervisor) into sanitized alert candidates through the already-live extraCandidates merge
// (S-live-1), on the existing structural daemon cadence. See
// docs/plans/2026-07-10-layer-b-provenance.md section 4 for the authoritative spec.
//
// Two responsibilities live in this one "small new module" (per the slice's blast-radius
// note), mirroring the daemon's own two-cadence split:
//   - collectProvenanceWarningsEvidence: I/O-performing structural sub-collector, wired into
//     daemon.js's collectStructuralEvidence exactly like services/network/scheduled-jobs (slow
//     cadence, subject to the structural-tick deadline/discard discipline).
//   - provenanceWarningFactPoints / reduceLatestProvenanceWarnings /
//     buildProvenanceWarningCandidates / computeProvenanceWarningCandidates: the fast-tick
//     side, structurally mirroring computeActiveConstraintCandidates (daemon.js) — gated by the
//     same loadLearnedConfig(...).enabled short-circuit-to-[] BEFORE any I/O, reading only
//     already-persisted fact-history, never doing fresh host I/O on every tick.
//
// Reuses S3's pure exports (classifySourceFromAncestry, detectWarnings, isPublicBindAddress,
// hasPublicBindNoSupervisor, isRecognizedSupervisorSourceType, resolveExecutableInfo,
// parseProvenancePs/provenancePsArgsForPlatform, parseProcNetContents,
// listProcPids/scanProcFdForInode, resolvePidFromFdScanResults) rather than reimplementing
// classification/warning logic — see tools/provenance.js.
//
// Bounded I/O (plan section 4, load-bearing): the only NEW per-process I/O this module adds
// beyond listing sockets/processes once per structural tick is resolveExecutableInfo(pid),
// and it is invoked ONLY for pids already narrowed to a public-bind-no-supervisor candidate
// by the cheap, pure hasPublicBindNoSupervisor(source.type, sockets) predicate — never once
// per listener.

import { execFile } from "node:child_process";
import crypto from "node:crypto";
import { readFile as fsReadFile } from "node:fs/promises";
import { promisify } from "node:util";
import { alertId } from "../alert-store.js";
import { loadLearnedConfig } from "../constraint-store.js";
import { sanitizeDiagnostics, sanitizeIdentityString } from "../diagnostics-sanitizer.js";
import { readFactPoints } from "../fact-store.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { parseMacLsofListeningSockets } from "./network.js";
import { buildParentTreeResult } from "./processes.js";
import {
  classifySourceFromAncestry,
  detectWarnings,
  hasPublicBindNoSupervisor,
  isPublicBindAddress,
  isRecognizedSupervisorSourceType,
  listProcPids,
  parseProcNetContents,
  parseProvenancePs,
  provenancePsArgsForPlatform,
  resolveExecutableInfo,
  resolvePidFromFdScanResults,
  scanProcFdForInode,
} from "./provenance.js";

const execFileAsync = promisify(execFile);

export const PROVENANCE_WARNING_FACT_NAME = "provenance.warning";
export const DELETED_EXE_RULE_ID = "provenance.process.deleted_exe_running";
export const PUBLIC_BIND_RULE_ID = "provenance.socket.public_bind_no_supervisor";

// Bounds computeProvenanceWarningCandidates' fact-history read window: generous enough to
// tolerate a couple of missed/timed-out structural ticks (default structural interval is
// hourly) without flapping, but not unbounded — a warning that stops being reasserted by the
// structural collector (cleared, or its owning process/socket disappeared entirely) ages out
// of candidacy within a few structural cycles rather than persisting until the 30-day fact
// retention boundary.
export const DEFAULT_PROVENANCE_FACT_WINDOW_MS = 3 * 60 * 60 * 1000; // 3 hours

async function runFixedExecFile(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 3000,
      maxBuffer: options.maxBuffer ?? 512 * 1024,
    });
    return { status: "ok", stdout, command: { argv, read_only: true } };
  } catch (error) {
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      command: { argv, read_only: true },
    };
  }
}

// ---------------------------------------------------------------------------------------------
// Pure helpers (no I/O).
// ---------------------------------------------------------------------------------------------

export function bindAddressFamilyLabel(address) {
  if (address === "0.0.0.0") return "ipv4_any";
  if (address === "[::]") return "ipv6_any";
  if (address === "*") return "wildcard";
  return "other";
}

export function hashExecutablePath(executablePath) {
  if (typeof executablePath !== "string" || !executablePath) return undefined;
  return crypto.createHash("sha256").update(executablePath).digest("hex").slice(0, 16);
}

function mapWarningSeverity(severity) {
  if (severity === "high") return "critical";
  if (severity === "low") return "info";
  return "warning";
}

function buildAncestryChain(processes, pid, maxDepth) {
  const treeResult = buildParentTreeResult(processes, pid, maxDepth);
  const chain = treeResult.result?.chain ?? [];
  return chain.map((item) => ({ pid: item.pid, ppid: item.ppid, comm: item.command }));
}

function buildPublicBindWarningEntry(socket, source, isCandidate, detectedEntry) {
  return {
    rule_id: "public_bind_no_supervisor",
    active: isCandidate,
    severity: isCandidate ? (detectedEntry?.severity ?? "medium") : undefined,
    confidence: isCandidate ? (detectedEntry?.confidence ?? 0.8) : undefined,
    source_type: source.type,
    protocol: socket.protocol,
    local_port: socket.local_port,
    bind_address_family: bindAddressFamilyLabel(socket.local_address),
  };
}

function buildDeletedExeWarningEntry(pid, source, executableInfo, detectedEntry) {
  const active = Boolean(detectedEntry);
  return {
    rule_id: "deleted_exe_running",
    active,
    severity: detectedEntry?.severity,
    confidence: detectedEntry?.confidence,
    source_type: source.type,
    pid,
    executable_path_hash: active ? hashExecutablePath(executableInfo?.executable_path) : undefined,
  };
}

/**
 * evidence[] -> fact-store.js-shaped fact points (Slice S4, mirrors fact-translators.js's own
 * per-collector translator shape without living in that file — see module header). One point
 * per observed warning entity (every checked socket for public_bind_no_supervisor; only the
 * narrowed candidate pids for deleted_exe_running, matching what was actually checked this
 * tick). Degrade-not-fabricate: an entity whose identity cannot be sanitized to a safe string
 * is dropped, never invented.
 */
export function provenanceWarningFactPoints(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "provenance-warnings" && e.status !== "unable");
  if (!envelope) return [];
  const warnings = envelope.result?.warnings ?? [];

  return warnings.map((warning) => {
    const identity = warning.rule_id === "deleted_exe_running"
      ? (Number.isInteger(warning.pid) ? `process.${warning.pid}` : undefined)
      : (warning.protocol && Number.isFinite(warning.local_port)
        ? `socket.${warning.protocol}.${warning.local_port}.${warning.bind_address_family ?? "other"}`
        : undefined);
    if (!identity) return undefined;
    const entityKey = sanitizeIdentityString(`${warning.rule_id}.${identity}`);
    if (!entityKey) return undefined;

    const attributes = { rule_id: warning.rule_id, active: String(Boolean(warning.active)) };
    if (warning.source_type) attributes.source_type = String(warning.source_type);
    if (Number.isFinite(warning.confidence)) attributes.confidence = String(warning.confidence);
    if (warning.severity) attributes.severity = String(warning.severity);
    if (warning.rule_id === "deleted_exe_running") {
      if (Number.isInteger(warning.pid)) attributes.pid = String(warning.pid);
      if (warning.executable_path_hash) attributes.executable_path_hash = warning.executable_path_hash;
    } else {
      if (warning.protocol) attributes.protocol = String(warning.protocol);
      if (Number.isFinite(warning.local_port)) attributes.local_port = String(warning.local_port);
      if (warning.bind_address_family) attributes.bind_address_family = String(warning.bind_address_family);
    }

    return {
      ts,
      fact_name: PROVENANCE_WARNING_FACT_NAME,
      entity_key: entityKey,
      attributes,
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
    };
  }).filter(Boolean);
}

/**
 * Reduces a fact-point window down to the latest observation per entity_key (mirrors
 * shadow-store.js's buildShadowFactLookup's own "latest wins" semantics, reimplemented locally
 * rather than reusing that function directly since it hard-codes a fixed
 * fact-name -> attribute map that does not include this module's "provenance.warning" fact
 * name — see blast-radius note in the slice's own instructions: shadow-store.js is read-only
 * for this slice, not edited).
 */
export function reduceLatestProvenanceWarnings(factPoints = []) {
  const latestByEntity = new Map();
  for (const point of factPoints ?? []) {
    if (!point || point.fact_name !== PROVENANCE_WARNING_FACT_NAME) continue;
    const entityKey = point.entity_key;
    if (!entityKey) continue;
    const tsMs = new Date(point.ts).getTime();
    if (!Number.isFinite(tsMs)) continue;
    const existing = latestByEntity.get(entityKey);
    if (!existing || tsMs >= existing.tsMs) latestByEntity.set(entityKey, { tsMs, point });
  }
  return [...latestByEntity.values()].map((entry) => entry.point);
}

function buildPublicBindCandidate(point) {
  const attrs = point.attributes ?? {};
  const identity = `${attrs.protocol ?? "tcp"}.${attrs.local_port ?? "0"}.${attrs.bind_address_family ?? "other"}`;
  const fingerprint = sanitizeIdentityString(`socket.${identity}`) ?? "unknown";
  const localPort = Number(attrs.local_port);
  const confidence = Number(attrs.confidence);
  const diagnostics = sanitizeDiagnostics({
    local_port: Number.isFinite(localPort) ? localPort : undefined,
    protocol: attrs.protocol,
    bind_address_family: attrs.bind_address_family,
    source_type: attrs.source_type,
    confidence: Number.isFinite(confidence) ? confidence : undefined,
  });
  return {
    id: alertId(PUBLIC_BIND_RULE_ID, fingerprint),
    rule_id: PUBLIC_BIND_RULE_ID,
    fingerprint,
    severity: mapWarningSeverity(attrs.severity),
    title: "Public bind with no recognized supervisor",
    summary: "A listening socket is bound to a public address with no recognized supervising source.",
    diagnostics,
    evidence_refs: ["provenance-warnings"],
  };
}

function buildDeletedExeCandidate(point) {
  const attrs = point.attributes ?? {};
  const pid = Number(attrs.pid);
  const fingerprint = sanitizeIdentityString(`pid.${Number.isFinite(pid) ? pid : "unknown"}`) ?? "unknown";
  const confidence = Number(attrs.confidence);
  const diagnostics = sanitizeDiagnostics({
    pid: Number.isFinite(pid) ? pid : undefined,
    executable_path_hash: attrs.executable_path_hash,
    source_type: attrs.source_type,
    confidence: Number.isFinite(confidence) ? confidence : undefined,
  });
  return {
    id: alertId(DELETED_EXE_RULE_ID, fingerprint),
    rule_id: DELETED_EXE_RULE_ID,
    fingerprint,
    severity: mapWarningSeverity(attrs.severity),
    title: "Deleted executable still running",
    summary: "A running process's executable path is deleted/unlinked but the process is still active.",
    diagnostics,
    evidence_refs: ["provenance-warnings"],
  };
}

/**
 * latestPoints (already reduced to one-per-entity) -> alert-store candidate objects, in the
 * same shape alert-store's fixed rules and constraint-eval's evaluateConstraints already emit.
 * Only entities whose latest observation is active:"true" produce a candidate — an
 * unrecognized rule_id or an inactive/cleared observation produces nothing (degrade, not
 * fabricate).
 */
export function buildProvenanceWarningCandidates(latestPoints = []) {
  const candidates = [];
  for (const point of latestPoints ?? []) {
    if (!point || point.attributes?.active !== "true") continue;
    if (point.attributes.rule_id === "deleted_exe_running") candidates.push(buildDeletedExeCandidate(point));
    else if (point.attributes.rule_id === "public_bind_no_supervisor") candidates.push(buildPublicBindCandidate(point));
  }
  return candidates;
}

/**
 * Fast-tick side (Slice S4), structurally mirroring daemon.js's own computeActiveConstraintCandidates:
 * gated by the same loadLearnedConfig(...).enabled short-circuit-to-[] BEFORE any I/O, then
 * reads only already-persisted fact-history (never fresh host I/O) and deterministically maps
 * the latest known warning state per entity into alert candidates. Called on every daemon tick
 * from runDaemonIteration's extraCandidates concat, not just on a structural-due tick — exactly
 * like computeActiveConstraintCandidates, so an already-collected warning can keep firing (or
 * recover) without waiting for the next hourly structural collection.
 */
export async function computeProvenanceWarningCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, {
    windowMs: options.provenanceFactWindowMs ?? DEFAULT_PROVENANCE_FACT_WINDOW_MS,
    now: options.now,
  });
  return buildProvenanceWarningCandidates(reduceLatestProvenanceWarnings(points));
}

// ---------------------------------------------------------------------------------------------
// I/O-performing structural sub-collector.
// ---------------------------------------------------------------------------------------------

async function listMacListeningSockets(options) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const probe = await runExec("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], { timeout: 3500, maxBuffer: 512 * 1024 });
  if (probe.status !== "ok") return [];
  return parseMacLsofListeningSockets(probe.stdout, { limit: 200 }).map((entry) => ({
    protocol: entry.protocol,
    local_address: entry.local_address,
    local_port: entry.local_port,
    pid: entry.pid,
  }));
}

async function listLinuxListeningSockets(options) {
  const readFileFn = options.readFile ?? ((file) => fsReadFile(file, "utf8"));
  const sources = [
    ["tcp", "/proc/net/tcp"],
    ["tcp6", "/proc/net/tcp6"],
    ["udp", "/proc/net/udp"],
    ["udp6", "/proc/net/udp6"],
  ];
  const entries = [];
  for (const [protocol, filePath] of sources) {
    try {
      const contents = await readFileFn(filePath);
      entries.push(...parseProcNetContents(contents, { protocol }));
    } catch {
      // This /proc source is unavailable on this host; continue with the others.
    }
  }
  const listening = entries.filter((entry) => (entry.protocol.startsWith("tcp") ? entry.state === "LISTEN" : true));
  if (listening.length === 0) return [];

  const listPids = options.listProcPids ?? listProcPids;
  const scanFds = options.scanProcFdForInode ?? scanProcFdForInode;
  const candidatePids = await listPids();
  const fdScanResults = await scanFds(candidatePids);

  return listening.map((entry) => {
    const match = resolvePidFromFdScanResults(entry.inode, fdScanResults);
    return {
      protocol: entry.protocol,
      local_address: entry.local_address,
      local_port: entry.local_port,
      pid: match.status === "ok" ? match.pid : undefined,
    };
  });
}

/**
 * Lists every currently-listening socket with its owning pid where resolvable (macOS: always,
 * via lsof; Linux: own-UID only, via the /proc/net + fd-walk mechanism — cross-UID sockets
 * come back with pid:undefined and are silently excluded from any per-pid classification
 * below, never fabricated). Exported so it is independently unit-testable per platform.
 */
export async function listListeningSocketsWithPid(platform, options = {}) {
  if (platform === "darwin") return listMacListeningSockets(options);
  if (platform === "linux") return listLinuxListeningSockets(options);
  return [];
}

/**
 * One shared process-table snapshot for the whole structural tick (reused across every
 * listening pid's ancestry lookup below) — not one `ps` call per listener.
 */
export async function snapshotProvenanceProcesses(platform, options = {}) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const psResult = await runExec("ps", provenancePsArgsForPlatform(platform), { timeout: 3000, maxBuffer: 8 * 1024 * 1024 });
  return psResult.status === "ok" ? parseProvenancePs(psResult.stdout) : [];
}

/**
 * Structural provenance-warning sub-collector (Slice S4): wired into daemon.js's
 * collectStructuralEvidence exactly like services/network/scheduled-jobs (slow cadence,
 * subject to the structural-tick deadline/discard discipline).
 *
 * Bounded I/O (plan section 4, load-bearing): resolveExecutableInfo(pid) — the only new
 * per-process I/O this collector introduces — runs ONLY for pids the cheap, pure
 * hasPublicBindNoSupervisor(source.type, sockets) predicate has already narrowed to a
 * public-bind-no-supervisor candidate. Every other step (socket listing, one shared `ps`
 * snapshot, ancestry classification, the per-socket public-bind check) is either O(1) I/O for
 * the whole tick or pure/in-memory — never O(listeners) new host I/O calls.
 *
 * Reuses classifySourceFromAncestry and detectWarnings verbatim per pid so severity/confidence
 * values for a fired warning are always the canonical S3 values, never re-derived.
 */
export async function collectProvenanceWarningsEvidence(options = {}) {
  return timedEnvelope(async () => {
    const platform = options.platform ?? process.platform;
    const listSockets = options.listListeningSocketsWithPid ?? listListeningSocketsWithPid;
    const sockets = await listSockets(platform, options);

    const pids = [...new Set(sockets.map((socket) => socket.pid).filter((pid) => Number.isInteger(pid)))];
    const snapshotProcesses = options.snapshotProvenanceProcesses ?? snapshotProvenanceProcesses;
    const processes = pids.length > 0 ? await snapshotProcesses(platform, options) : [];

    const socketsByPid = new Map();
    for (const socket of sockets) {
      if (!Number.isInteger(socket.pid)) continue;
      if (!socketsByPid.has(socket.pid)) socketsByPid.set(socket.pid, []);
      socketsByPid.get(socket.pid).push(socket);
    }

    const maxAncestryDepth = options.maxAncestryDepth ?? 16;
    const resolveExeInfo = options.resolveExecutableInfo ?? resolveExecutableInfo;
    const warnings = [];
    let narrowedCandidateCount = 0;

    for (const pid of pids) {
      const ancestryChain = buildAncestryChain(processes, pid, maxAncestryDepth);
      const source = classifySourceFromAncestry(ancestryChain);
      const pidSockets = socketsByPid.get(pid) ?? [];

      // Cheap, pure, no I/O: gates the one expensive per-pid I/O call below — never the reverse.
      const narrowed = hasPublicBindNoSupervisor(source.type, pidSockets);
      let executableInfo;
      if (narrowed) {
        narrowedCandidateCount += 1;
        executableInfo = await resolveExeInfo(pid);
      }

      // Reuses detectWarnings verbatim so severity/confidence/message stay the canonical S3
      // values; resolved.deleted_exe is only ever populated for a narrowed pid above.
      const detected = detectWarnings(
        { resolved: { deleted_exe: executableInfo?.deleted_exe, deleted_exe_confidence: executableInfo?.deleted_exe_confidence }, source, ancestry: ancestryChain },
        pidSockets,
      );
      const publicBindEntry = detected.find((warning) => warning.rule_id === "public_bind_no_supervisor");
      const deletedExeEntry = detected.find((warning) => warning.rule_id === "deleted_exe_running");

      for (const socket of pidSockets) {
        const socketIsCandidate = isPublicBindAddress(socket.local_address) && !isRecognizedSupervisorSourceType(source.type);
        warnings.push(buildPublicBindWarningEntry(socket, source, socketIsCandidate, publicBindEntry));
      }

      if (narrowed) {
        warnings.push(buildDeletedExeWarningEntry(pid, source, executableInfo, deletedExeEntry));
      }
    }

    return {
      platform,
      checked_socket_count: sockets.length,
      narrowed_candidate_count: narrowedCandidateCount,
      warnings,
    };
  }, (result) => evidenceEnvelope({
    id: "provenance-warnings",
    status: "ok",
    source: "provenance",
    result,
    confidence: 1,
    reviewHint: "none",
    tool: "collect_provenance_warnings",
    target: `platform=${options.platform ?? process.platform}`,
  }));
}
