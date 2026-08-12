import { execFile } from "node:child_process";
import { readlink, readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { buildLineageEntityKey } from "../fact-translators.js";

const execFileAsync = promisify(execFile);
const PS_COLUMNS = "pid,ppid,pcpu,pmem,rss,comm,args";
const DEFAULT_ARGS_MAX_LENGTH = 240;
const DEFAULT_TOKEN_MAX_LENGTH = 96;

function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksHighEntropy(value) {
  const compact = value.replace(/^["']|["']$/g, "");
  if (compact.length < 32) return false;
  if (compact.includes("/") || compact.includes("\\")) return false;
  if (!/^[A-Za-z0-9+_.=:-]+$/.test(compact)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[+_.=:-]/].filter((re) => re.test(compact)).length;
  return classes >= 3 && shannonEntropy(compact) >= 3.5;
}

function redactSecretAssignments(token) {
  let redacted = false;
  const value = token.replace(
    /((?:--?)?[A-Za-z0-9_.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|key|access[_-]?token|refresh[_-]?token|auth|authorization|credential|session|bearer|jwt|private[_-]?key)[A-Za-z0-9_.-]*)(=|:)([^\s&]+)/gi,
    (_match, key, delimiter) => {
      redacted = true;
      return `${key}${delimiter}[REDACTED]`;
    }
  ).replace(
    /([?&](?:token|secret|password|passwd|pwd|api[_-]?key|apikey|key|access[_-]?token|refresh[_-]?token|auth|authorization|credential|session|bearer|jwt|private[_-]?key)=)([^&#\s]+)/gi,
    (_match, prefix) => {
      redacted = true;
      return `${prefix}[REDACTED]`;
    }
  );
  return { value, redacted };
}

function splitCommandLine(value) {
  return String(value ?? "").match(/\s+|\S+/g) ?? [];
}

function isWhitespace(token) {
  return /^\s+$/.test(token);
}

function isSecretFlag(token) {
  return /^--?[A-Za-z0-9_.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|key|access[_-]?token|refresh[_-]?token|auth|authorization|credential|session|bearer|jwt|private[_-]?key)[A-Za-z0-9_.-]*$/i.test(token);
}

function boundToken(token, maxTokenLength) {
  if (token.length <= maxTokenLength) return { value: token, truncated: false };
  return { value: `${token.slice(0, maxTokenLength)}…`, truncated: true };
}

export function redactAndBoundProcessArgs(args, options = {}) {
  const original = String(args ?? "");
  const maxLength = options.maxLength ?? DEFAULT_ARGS_MAX_LENGTH;
  const maxTokenLength = options.maxTokenLength ?? DEFAULT_TOKEN_MAX_LENGTH;
  const parts = splitCommandLine(original);
  const output = [];
  let redacted = false;
  let truncated = false;
  let redactNextValue = false;
  let seenNonWhitespace = false;

  for (const part of parts) {
    if (isWhitespace(part)) {
      output.push(part);
      continue;
    }

    let value = part;
    if (redactNextValue) {
      value = "[REDACTED]";
      redacted = true;
      redactNextValue = false;
    } else {
      const assignment = redactSecretAssignments(value);
      value = assignment.value;
      redacted ||= assignment.redacted;

      if (!seenNonWhitespace && !assignment.redacted) {
        const bounded = boundToken(value, maxTokenLength);
        value = bounded.value;
        truncated ||= bounded.truncated;
      } else if (looksHighEntropy(value)) {
        value = "[REDACTED]";
        redacted = true;
      } else {
        const bounded = boundToken(value, maxTokenLength);
        value = bounded.value;
        truncated ||= bounded.truncated;
      }
    }

    if (isSecretFlag(part)) redactNextValue = true;
    if (!isWhitespace(part)) seenNonWhitespace = true;
    output.push(value);
  }

  let value = output.join("");
  if (value.length > maxLength) {
    value = `${value.slice(0, maxLength)}…`;
    truncated = true;
  }

  return {
    value,
    redacted,
    truncated,
    original_length: original.length,
    max_length: maxLength,
  };
}

function sanitizeProcess(process) {
  const args = redactAndBoundProcessArgs(process.args || process.command || "");
  return {
    ...process,
    args: args.value,
    args_redaction: {
      redacted: args.redacted,
      truncated: args.truncated,
      original_length: args.original_length,
      max_length: args.max_length,
    },
  };
}

export function parsePs(stdout) {
  const lines = stdout.trim().split("\n").slice(1);
  return lines.map((line) => {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\S+)\s*(.*)$/);
    if (!match) return undefined;
    return sanitizeProcess({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      cpu_percent: Number(match[3]),
      memory_percent: Number(match[4]),
      rss_bytes: Number(match[5]) * 1024,
      command: match[6],
      args: match[7] || match[6],
    });
  }).filter(Boolean);
}

export function psArgsForPlatform(platform = process.platform) {
  if (platform === "linux") {
    // Procps on Linux can reject the BSD-style "-x" personality when combined
    // as "-axo" (observed on Ubuntu arm64). Use POSIX/System V -e instead.
    return ["-eo", PS_COLUMNS];
  }
  return ["-axo", PS_COLUMNS];
}

export function topProcessesBy(processes, key, limit) {
  return [...processes]
    .sort((left, right) => (right[key] ?? 0) - (left[key] ?? 0))
    .slice(0, limit);
}

async function getProcessSnapshot() {
  const args = psArgsForPlatform();
  const { stdout } = await execFileAsync("ps", args, { timeout: 3000, maxBuffer: 1024 * 1024 });
  return {
    processes: parsePs(stdout),
    command: {
      argv: ["ps", ...args],
      read_only: true,
    },
  };
}

export const MAX_LINEAGE_EDGES_PER_TICK = 200;

export function buildLineageEdges(processes = []) {
  const byPid = new Map((processes ?? []).map((process) => [process?.pid, process]));
  const candidates = [];

  for (const process of processes ?? []) {
    if (!process) continue;
    const parent = byPid.get(process.ppid);
    const parentComm = typeof parent?.command === "string" ? parent.command : undefined;
    const childComm = typeof process.command === "string" ? process.command : undefined;
    // Degrade-not-fabricate (HIGH fix, deception/anomaly-detector review): a missing or
    // unresolvable parent (root process whose ppid isn't in this snapshot, a reaped parent, a
    // truncated process table, ...) must SKIP this edge entirely. Synthesizing an "unknown ->
    // child" edge instead would fabricate an entity that reads as a genuinely NOVEL lineage edge
    // the first time any such process is observed, firing a fabricated
    // process.lineage.novel_edge anomaly on nothing more than an unresolved parent.
    if (!parentComm || !childComm) continue;
    const edgeKey = buildLineageEntityKey(parentComm, childComm);
    if (!edgeKey) continue;
    candidates.push({ edgeKey, parent_comm: parentComm, child_comm: childComm });
  }

  candidates.sort((left, right) =>
    left.edgeKey.localeCompare(right.edgeKey) ||
    String(left.parent_comm).localeCompare(String(right.parent_comm)) ||
    String(left.child_comm).localeCompare(String(right.child_comm))
  );

  const seen = new Set();
  const edges = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.edgeKey)) continue;
    seen.add(candidate.edgeKey);
    edges.push({ parent_comm: candidate.parent_comm, child_comm: candidate.child_comm });
  }

  const truncated = edges.length > MAX_LINEAGE_EDGES_PER_TICK;
  return {
    edges: truncated ? edges.slice(0, MAX_LINEAGE_EDGES_PER_TICK) : edges,
    truncated,
  };
}

export async function collectProcessLineageEvidence() {
  return timedEnvelope(async () => {
    const { processes, command } = await getProcessSnapshot();
    const { edges, truncated } = buildLineageEdges(processes);
    return { edges, edge_count: edges.length, truncated, command };
  }, (result) => evidenceEnvelope({
    id: "process-lineage-edges",
    status: result.truncated ? "warning" : "ok",
    source: "process_table",
    result,
    reviewHint: result.truncated ? "missing_permission" : "none",
    tool: "collect_process_lineage",
    target: `edges=${result.edge_count}`,
  }));
}

async function runPs(limit) {
  const { processes, command } = await getProcessSnapshot();
  return {
    top_cpu: topProcessesBy(processes, "cpu_percent", limit),
    top_memory: topProcessesBy(processes, "memory_percent", limit),
    command,
  };
}

function normalizePid(pid) {
  const number = Number(pid);
  if (!Number.isInteger(number) || number <= 0) throw new Error(`Invalid pid: ${pid}`);
  return number;
}

function processSummary(process) {
  if (!process) return undefined;
  return {
    pid: process.pid,
    ppid: process.ppid,
    command: process.command,
    args: process.args,
    args_redaction: process.args_redaction,
    cpu_percent: process.cpu_percent,
    memory_percent: process.memory_percent,
    rss_bytes: process.rss_bytes,
  };
}

async function linuxProcessMetadata(pid) {
  if (process.platform !== "linux") return {};
  const metadata = {};
  try {
    metadata.executable_path = await readlink(`/proc/${pid}/exe`);
  } catch {
    metadata.executable_path_unavailable = true;
  }
  try {
    const status = await readFile(`/proc/${pid}/status`, "utf8");
    const uid = status.match(/^Uid:\s+(\d+)/m)?.[1];
    if (uid !== undefined) metadata.uid = Number(uid);
  } catch {
    metadata.uid_unavailable = true;
  }
  return metadata;
}

export function buildInspectProcessResult(processes, pid, command = undefined, metadata = {}) {
  const normalizedPid = normalizePid(pid);
  const target = processes.find((item) => item.pid === normalizedPid);
  if (!target) {
    return {
      status: "unknown",
      reviewHint: "ambiguous",
      result: {
        pid: normalizedPid,
        found: false,
        reason: "process_not_found_or_permission_limited",
        command,
      },
    };
  }

  const children = processes.filter((item) => item.ppid === normalizedPid);
  const parent = processes.find((item) => item.pid === target.ppid);
  const topChildren = topProcessesBy(children, "cpu_percent", 8).map(processSummary);

  return {
    status: "ok",
    reviewHint: "none",
    result: {
      pid: normalizedPid,
      found: true,
      process: processSummary(target),
      executable_path: metadata.executable_path,
      uid: metadata.uid,
      parent: processSummary(parent),
      child_count: children.length,
      top_children: topChildren,
      platform_support: {
        executable_path: metadata.executable_path ? "ok" : "unavailable",
        uid: metadata.uid !== undefined ? "ok" : "unavailable",
        start_time_or_age: "unavailable",
        user: "unavailable",
      },
      command,
    },
  };
}

export function buildParentTreeResult(processes, pid, maxDepth = 16, command = undefined) {
  const normalizedPid = normalizePid(pid);
  const boundedDepth = Math.min(Math.max(Number(maxDepth) || 16, 1), 64);
  const byPid = new Map(processes.map((item) => [item.pid, item]));
  const target = byPid.get(normalizedPid);
  if (!target) {
    return {
      status: "unknown",
      reviewHint: "ambiguous",
      result: {
        pid: normalizedPid,
        found: false,
        max_depth: boundedDepth,
        reason: "process_not_found_or_permission_limited",
        command,
      },
    };
  }

  const chain = [];
  const seen = new Set();
  let current = target;
  let truncatedByDepth = false;
  let missingParent = false;
  let cycleDetected = false;

  while (current && chain.length < boundedDepth) {
    chain.push(processSummary(current));
    if (seen.has(current.pid)) {
      cycleDetected = true;
      break;
    }
    seen.add(current.pid);
    if (!current.ppid || current.ppid === current.pid) break;
    const parent = byPid.get(current.ppid);
    if (!parent) {
      missingParent = true;
      break;
    }
    current = parent;
  }

  if (current && chain.length >= boundedDepth && current.pid !== chain[chain.length - 1]?.pid) truncatedByDepth = true;

  const children = processes.filter((item) => item.ppid === normalizedPid);
  return {
    status: "ok",
    reviewHint: truncatedByDepth || missingParent || cycleDetected ? "ambiguous" : "none",
    result: {
      pid: normalizedPid,
      found: true,
      max_depth: boundedDepth,
      chain,
      truncated_by_depth: truncatedByDepth,
      missing_parent: missingParent,
      cycle_detected: cycleDetected,
      child_count: children.length,
      top_children: topProcessesBy(children, "cpu_percent", 8).map(processSummary),
      command,
    },
  };
}

export async function collectProcessEvidence({ limit = 10 } = {}) {
  return timedEnvelope(async () => runPs(limit), (result) => evidenceEnvelope({
    id: "top-processes",
    source: "process_table",
    result,
    tool: "collect_processes",
    target: `limit=${limit}`,
  }));
}

export async function inspectProcessEvidence({ pid } = {}) {
  const normalizedPid = normalizePid(pid);
  return timedEnvelope(async () => {
    const { processes, command } = await getProcessSnapshot();
    const metadata = await linuxProcessMetadata(normalizedPid);
    return buildInspectProcessResult(processes, normalizedPid, command, metadata);
  }, (inspection) => evidenceEnvelope({
    id: `process-${normalizedPid}`,
    status: inspection.status,
    source: "process_table",
    result: inspection.result,
    reviewHint: inspection.reviewHint,
    confidence: inspection.status === "ok" ? 1 : 0.4,
    tool: "inspect_process",
    target: `pid=${normalizedPid}`,
  }));
}

export async function inspectParentTreeEvidence({ pid, maxDepth = 16 } = {}) {
  const normalizedPid = normalizePid(pid);
  const boundedDepth = Math.min(Math.max(Number(maxDepth) || 16, 1), 64);
  return timedEnvelope(async () => {
    const { processes, command } = await getProcessSnapshot();
    return buildParentTreeResult(processes, normalizedPid, boundedDepth, command);
  }, (inspection) => evidenceEnvelope({
    id: `process-parent-tree-${normalizedPid}`,
    status: inspection.status,
    source: "process_table",
    result: inspection.result,
    reviewHint: inspection.reviewHint,
    confidence: inspection.status === "ok" ? 1 : 0.4,
    tool: "inspect_parent_tree",
    target: `pid=${normalizedPid},max_depth=${boundedDepth}`,
  }));
}
