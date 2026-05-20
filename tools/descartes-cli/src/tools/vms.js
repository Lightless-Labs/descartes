import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DEFAULT_VM_LIMIT = 80;

function clampNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.floor(number), min), max);
}

export function normalizeVmRequest(options = {}) {
  return {
    vm_limit: clampNumber(options.vmLimit ?? options.vm_limit, DEFAULT_VM_LIMIT, 1, 200),
  };
}

function truncate(value, max = 2048) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

async function runFixedCommand(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 4500,
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
    });
    return {
      status: "ok",
      stdout,
      stderr: truncate(stderr),
      command: { argv, read_only: true },
    };
  } catch (error) {
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      stdout: truncate(error?.stdout ?? "", 4096),
      stderr: truncate(error?.stderr ?? "", 2048),
      command: { argv, read_only: true },
    };
  }
}

function parseJsonMaybeArray(stdout) {
  const trimmed = String(stdout ?? "").trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed;
    if (Array.isArray(parsed.vms)) return parsed.vms;
    if (Array.isArray(parsed.list)) return parsed.list;
    if (Array.isArray(parsed.instances)) return parsed.instances;
    if (parsed && typeof parsed === "object") return [parsed];
  } catch {
    const rows = [];
    for (const line of trimmed.split("\n")) {
      try {
        rows.push(JSON.parse(line));
      } catch {
        // Ignore malformed rows.
      }
    }
    return rows;
  }
  return [];
}

const BYTE_UNITS = new Map([
  ["b", 1],
  ["kb", 1000], ["kib", 1024], ["k", 1024],
  ["mb", 1000 ** 2], ["mib", 1024 ** 2], ["m", 1024 ** 2],
  ["gb", 1000 ** 3], ["gib", 1024 ** 3], ["g", 1024 ** 3],
  ["tb", 1000 ** 4], ["tib", 1024 ** 4], ["t", 1024 ** 4],
]);

export function parseByteQuantity(value) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = String(value).trim();
  const match = text.match(/^([0-9.]+)\s*([KMGT]?i?B|[KMGT]B?|B)?$/i);
  if (!match) return undefined;
  const number = Number(match[1]);
  if (!Number.isFinite(number)) return undefined;
  const unit = (match[2] ?? "B").toLowerCase();
  return Math.round(number * (BYTE_UNITS.get(unit) ?? 1));
}

function normalizeVmState(value) {
  const text = String(value ?? "unknown").trim().toLowerCase();
  if (["running", "started", "up"].includes(text) || text.includes("running")) return "running";
  if (["stopped", "stop", "shut off", "powered off", "poweroff", "off"].includes(text) || text.includes("stopped") || text.includes("shut")) return "stopped";
  if (text.includes("paused")) return "paused";
  if (text.includes("suspended") || text.includes("saved")) return "suspended";
  if (text.includes("starting")) return "starting";
  return text || "unknown";
}

function boundedString(value, max = 240) {
  if (value === undefined || value === null) return undefined;
  return truncate(String(value), max);
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function asNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function normalizeIps(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String).filter(Boolean).slice(0, 8);
  return String(value).split(/[\s,]+/).filter(Boolean).slice(0, 8);
}

export function parseTartListJson(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => ({
    runtime: "tart",
    id: boundedString(firstDefined(item.id, item.ID, item.name, item.Name)),
    name: boundedString(firstDefined(item.name, item.Name)),
    state: normalizeVmState(firstDefined(item.state, item.State, item.status, item.Status)),
    backend: boundedString(firstDefined(item.backend, item.Backend, "apple_virtualization")),
    cpus: asNumber(firstDefined(item.cpus, item.cpu, item.CPUs, item.CpuCount)),
    memory_bytes: parseByteQuantity(firstDefined(item.memory, item.Memory, item.memorySize, item.MemorySize)),
    disk_bytes: parseByteQuantity(firstDefined(item.disk, item.Disk, item.diskSize, item.DiskSize)),
    ips: normalizeIps(firstDefined(item.ips, item.IPs, item.ipAddress, item.IPAddress)),
    owner_hint: boundedString(firstDefined(item.source, item.Source, item.os, item.OS)),
    source_runtime: "tart",
    confidence: 1,
  })).filter((vm) => vm.name || vm.id).slice(0, limit);
}

export function parseLimaListJson(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => ({
    runtime: "lima",
    id: boundedString(firstDefined(item.name, item.Name)),
    name: boundedString(firstDefined(item.name, item.Name)),
    state: normalizeVmState(firstDefined(item.status, item.Status, item.state)),
    backend: boundedString(firstDefined(item.vmType, item.VMType, item.driver, item.Driver, "unknown")),
    cpus: asNumber(firstDefined(item.cpus, item.CPUs, item.cpu)),
    memory_bytes: parseByteQuantity(firstDefined(item.memory, item.Memory)),
    disk_bytes: parseByteQuantity(firstDefined(item.disk, item.Disk)),
    ips: normalizeIps(firstDefined(item.ips, item.IPs, item.address, item.Address)),
    owner_hint: boundedString(firstDefined(item.dir, item.Dir, item.instanceDir)),
    source_runtime: "lima",
    confidence: 1,
  })).filter((vm) => vm.name || vm.id).slice(0, limit);
}

export function parseMultipassListJson(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => ({
    runtime: "multipass",
    id: boundedString(firstDefined(item.name, item.Name)),
    name: boundedString(firstDefined(item.name, item.Name)),
    state: normalizeVmState(firstDefined(item.state, item.State)),
    backend: "unknown",
    cpus: asNumber(firstDefined(item.cpus, item.CPUs)),
    memory_bytes: parseByteQuantity(firstDefined(item.memory, item.Memory)),
    disk_bytes: parseByteQuantity(firstDefined(item.disk, item.Disk)),
    ips: normalizeIps(firstDefined(item.ipv4, item.IPv4, item.ips)),
    owner_hint: boundedString(firstDefined(item.release, item.Release, item.image_hash)),
    source_runtime: "multipass",
    confidence: 1,
  })).filter((vm) => vm.name || vm.id).slice(0, limit);
}

export function parseVirtualBoxVms(vmsStdout, runningStdout = "", { limit = DEFAULT_VM_LIMIT } = {}) {
  const runningIds = new Set();
  const runningNames = new Set();
  for (const line of String(runningStdout ?? "").split("\n")) {
    const match = line.match(/^"(.*)"\s+\{([^}]+)\}/);
    if (match) {
      runningNames.add(match[1]);
      runningIds.add(match[2]);
    }
  }
  const vms = [];
  for (const line of String(vmsStdout ?? "").split("\n")) {
    const match = line.match(/^"(.*)"\s+\{([^}]+)\}/);
    if (!match) continue;
    const [, name, id] = match;
    vms.push({
      runtime: "virtualbox",
      id,
      name,
      state: runningIds.has(id) || runningNames.has(name) ? "running" : "stopped",
      backend: "unknown",
      source_runtime: "virtualbox",
      confidence: 1,
    });
  }
  return vms.slice(0, limit);
}

export function parseVirshList(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  const vms = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || /^Id\s+Name\s+State/i.test(line) || /^-+$/.test(line)) continue;
    const match = line.match(/^(\S+)\s+(\S+)\s+(.+)$/);
    if (!match) continue;
    const [, idText, name, stateText] = match;
    vms.push({
      runtime: "libvirt",
      id: idText === "-" ? undefined : idText,
      name,
      state: normalizeVmState(stateText),
      backend: "kvm_qemu",
      source_runtime: "libvirt",
      confidence: 1,
    });
  }
  return vms.slice(0, limit);
}

export function classifyCommandFailure(commandResult) {
  if (commandResult.status === "ok") return "ok";
  const combined = `${commandResult.error ?? ""}\n${commandResult.stderr ?? ""}`.toLowerCase();
  if (commandResult.code === "ENOENT" || combined.includes("enoent") || combined.includes("not found")) return "missing";
  if (combined.includes("permission denied") || combined.includes("access denied") || combined.includes("authentication") || combined.includes("not authorized")) return "permission_limited";
  if (combined.includes("failed to connect") || combined.includes("cannot connect") || combined.includes("connection refused") || combined.includes("no connection driver")) return "daemon_unavailable";
  return "unable";
}

function versionFromStdout(stdout) {
  const line = String(stdout ?? "").split("\n").map((item) => item.trim()).find(Boolean);
  return line ? truncate(line, 120) : undefined;
}

function runtimeFromProbe(runtime, probe, version) {
  const supportStatus = classifyCommandFailure(probe);
  return {
    runtime,
    installed: supportStatus !== "missing",
    available: supportStatus === "ok",
    version,
    support_status: supportStatus,
    source: probe.command,
    error: probe.error,
    stderr: probe.stderr,
  };
}

function probeMetadata(name, result, parser, count = 0) {
  return {
    name,
    status: result.status,
    parser,
    command: result.command,
    result_count: count,
    support_status: classifyCommandFailure(result),
    error: result.error,
    stderr: result.stderr,
  };
}

async function collectTart(request) {
  const [versionProbe, listProbe] = await Promise.all([
    runFixedCommand("tart", ["--version"], { timeout: 2500 }),
    runFixedCommand("tart", ["list", "--format", "json"], { timeout: 4500, maxBuffer: 512 * 1024 }),
  ]);
  const vms = listProbe.status === "ok" ? parseTartListJson(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("tart", versionProbe.status === "ok" ? versionProbe : listProbe, versionFromStdout(versionProbe.stdout)),
    vms,
    probes: [
      probeMetadata("tart_version", versionProbe, "version_text"),
      probeMetadata("tart_list", listProbe, "tart_list_json", vms.length),
    ],
  };
}

async function collectLima(request) {
  const listProbe = await runFixedCommand("limactl", ["list", "--json"], { timeout: 3500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseLimaListJson(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("lima", listProbe),
    vms,
    probes: [probeMetadata("lima_list", listProbe, "lima_list_json", vms.length)],
  };
}

async function collectMultipass(request) {
  const listProbe = await runFixedCommand("multipass", ["list", "--format", "json"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseMultipassListJson(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("multipass", listProbe),
    vms,
    probes: [probeMetadata("multipass_list", listProbe, "multipass_list_json", vms.length)],
  };
}

async function collectVirtualBox(request) {
  const [vmsProbe, runningProbe] = await Promise.all([
    runFixedCommand("VBoxManage", ["list", "vms"], { timeout: 4500, maxBuffer: 512 * 1024 }),
    runFixedCommand("VBoxManage", ["list", "runningvms"], { timeout: 4500, maxBuffer: 512 * 1024 }),
  ]);
  const vms = vmsProbe.status === "ok" ? parseVirtualBoxVms(vmsProbe.stdout, runningProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("virtualbox", vmsProbe, undefined),
    vms,
    probes: [
      probeMetadata("virtualbox_vms", vmsProbe, "virtualbox_list_vms", vms.length),
      probeMetadata("virtualbox_runningvms", runningProbe, "virtualbox_list_runningvms"),
    ],
  };
}

async function collectLibvirt(request) {
  const listProbe = await runFixedCommand("virsh", ["list", "--all"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseVirshList(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("libvirt", listProbe),
    vms,
    probes: [probeMetadata("libvirt_list", listProbe, "virsh_list", vms.length)],
  };
}

function summarize(runtimes, vms) {
  return {
    runtime_count: runtimes.length,
    available_runtime_count: runtimes.filter((runtime) => runtime.available).length,
    vm_count: vms.length,
    running_vm_count: vms.filter((vm) => vm.state === "running").length,
    stopped_vm_count: vms.filter((vm) => vm.state === "stopped").length,
  };
}

function envelopeStatus(result) {
  if (!result) return "unable";
  if (result.runtimes.some((runtime) => runtime.available)) return "ok";
  if (result.runtimes.some((runtime) => runtime.installed)) return "warning";
  return "unknown";
}

function reviewHint(result) {
  const status = envelopeStatus(result);
  if (status === "ok") return result.summary.running_vm_count > 0 ? "none" : "ambiguous";
  if (status === "warning") return "missing_permission";
  return "ambiguous";
}

export async function collectVmEvidence(options = {}) {
  const request = normalizeVmRequest(options);
  return timedEnvelope(async () => {
    const results = await Promise.all([
      collectTart(request),
      collectLima(request),
      collectMultipass(request),
      collectVirtualBox(request),
      collectLibvirt(request),
    ]);
    const runtimes = results.map((result) => result.runtime);
    const vms = results.flatMap((result) => result.vms ?? []).slice(0, request.vm_limit);
    const probes = results.flatMap((result) => result.probes ?? []);
    const unsupported_or_missing = runtimes.filter((runtime) => !runtime.available).map((runtime) => ({
      runtime: runtime.runtime,
      support_status: runtime.support_status,
      error: runtime.error,
    }));

    return {
      platform: process.platform,
      request,
      runtimes,
      vms,
      probes,
      unsupported_or_missing,
      summary: summarize(runtimes, vms),
      privacy: {
        bounded: true,
        note: "VM names, paths, IPs, runtime metadata, and resource snapshots are sensitive diagnostic artifacts.",
      },
    };
  }, (result) => evidenceEnvelope({
    id: "vms",
    status: envelopeStatus(result),
    source: "vm",
    result,
    confidence: result?.runtimes?.some((runtime) => runtime.available) ? 0.9 : 0.45,
    reviewHint: reviewHint(result),
    tool: "collect_vms",
    target: `limit=${request.vm_limit}`,
  }));
}
