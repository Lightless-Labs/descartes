import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { redactAndBoundProcessArgs } from "./processes.js";

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

export function parseParallelsListJson(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => ({
    runtime: "parallels",
    id: boundedString(firstDefined(item.ID, item.id, item.uuid, item.UUID)),
    name: boundedString(firstDefined(item.Name, item.name)),
    state: normalizeVmState(firstDefined(item.State, item.Status, item.state, item.status)),
    backend: "parallels",
    cpus: asNumber(firstDefined(item.CPUs, item.cpus, item.cpu_count)),
    memory_bytes: parseByteQuantity(firstDefined(item.Memory, item.memory, item.memory_size)),
    disk_bytes: parseByteQuantity(firstDefined(item.Disk, item.disk, item.hdd_size)),
    ips: normalizeIps(firstDefined(item.IP_ADDR, item.ips, item.ipv4)),
    owner_hint: boundedString(firstDefined(item.Home, item.Path, item.path, item.home), 400),
    source_runtime: "parallels",
    confidence: 1,
  })).filter((vm) => vm.name || vm.id).slice(0, limit);
}

export function parseVmrunList(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  return String(stdout ?? "").split("\n").map((line) => line.trim()).filter(Boolean)
    .filter((line) => !/^Total running VMs:/i.test(line))
    .map((vmPath) => ({
      runtime: "vmware",
      id: vmPath,
      name: path.basename(vmPath, path.extname(vmPath)) || vmPath,
      state: "running",
      backend: "vmware",
      owner_hint: vmPath,
      source_runtime: "vmware",
      confidence: 1,
    })).slice(0, limit);
}

export function parsePodmanMachineListJson(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => ({
    runtime: "podman_machine",
    id: boundedString(firstDefined(item.Name, item.name)),
    name: boundedString(firstDefined(item.Name, item.name)),
    state: normalizeVmState(item.Running === true || item.running === true ? "running" : firstDefined(item.State, item.Status, item.state, item.status, "stopped")),
    backend: boundedString(firstDefined(item.VMType, item.vmType, item.VmType, "unknown")),
    cpus: asNumber(firstDefined(item.CPUs, item.Cpus, item.cpus)),
    memory_bytes: parseByteQuantity(firstDefined(item.Memory, item.memory)),
    disk_bytes: parseByteQuantity(firstDefined(item.DiskSize, item.diskSize, item.disk_size)),
    ips: normalizeIps(firstDefined(item.IPAddress, item.ipAddress, item.ips)),
    owner_hint: boundedString(firstDefined(item.LastUp, item.Created, item.Path, item.path)),
    source_runtime: "podman_machine",
    confidence: 1,
  })).filter((vm) => vm.name || vm.id).slice(0, limit);
}

function instanceIps(item) {
  const addresses = [];
  for (const network of Object.values(item.state?.network ?? item.network ?? {})) {
    for (const address of network.addresses ?? []) {
      if (address.address) addresses.push(address.address);
    }
  }
  return addresses.slice(0, 8);
}

export function parseIncusOrLxcListJson(stdout, { runtime = "incus", limit = DEFAULT_VM_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).filter((item) => (item.type ?? item.Type) === "virtual-machine").map((item) => ({
    runtime,
    id: boundedString(firstDefined(item.name, item.Name)),
    name: boundedString(firstDefined(item.name, item.Name)),
    state: normalizeVmState(firstDefined(item.status, item.Status, item.stateful ? "suspended" : undefined)),
    backend: "qemu",
    cpus: asNumber(firstDefined(item.config?.["limits.cpu"], item.expanded_config?.["limits.cpu"])),
    memory_bytes: parseByteQuantity(firstDefined(item.config?.["limits.memory"], item.expanded_config?.["limits.memory"])),
    disk_bytes: parseByteQuantity(firstDefined(item.devices?.root?.size, item.expanded_devices?.root?.size)),
    ips: instanceIps(item),
    owner_hint: boundedString(firstDefined(item.location, item.project, item.description)),
    source_runtime: runtime,
    confidence: 1,
  })).filter((vm) => vm.name || vm.id).slice(0, limit);
}

export function parseQmList(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  const vms = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || /^VMID\s+NAME\s+STATUS/i.test(line)) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 3 || !/^\d+$/.test(parts[0])) continue;
    const [vmid, name, status, memoryMb, diskGb, pid] = parts;
    vms.push({
      runtime: "proxmox",
      id: vmid,
      name,
      state: normalizeVmState(status),
      backend: "kvm_qemu",
      memory_bytes: parseByteQuantity(memoryMb ? `${memoryMb}MiB` : undefined),
      disk_bytes: parseByteQuantity(diskGb ? `${diskGb}GiB` : undefined),
      resource_snapshot: pid && pid !== "0" ? { pid: Number(pid) } : undefined,
      source_runtime: "proxmox",
      confidence: 1,
    });
  }
  return vms.slice(0, limit);
}

export function parseXlList(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  const vms = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || /^Name\s+ID\s+Mem/i.test(line)) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;
    const [name, id, memMb, vcpus, state] = parts;
    vms.push({
      runtime: "xen",
      id: id === "-" ? undefined : id,
      name,
      state: state.includes("r") ? "running" : state.includes("p") ? "paused" : state.includes("s") ? "stopped" : "unknown",
      backend: "xen",
      cpus: asNumber(vcpus),
      memory_bytes: parseByteQuantity(`${memMb}MiB`),
      source_runtime: "xen",
      confidence: 1,
    });
  }
  return vms.slice(0, limit);
}

function psArgsForPlatform(platform = process.platform) {
  return platform === "linux" ? ["-eo", "pid,ppid,pcpu,pmem,rss,comm,args"] : ["-axo", "pid,ppid,pcpu,pmem,rss,comm,args"];
}

function argValue(args, flag) {
  const parts = String(args ?? "").match(/\S+/g) ?? [];
  const index = parts.indexOf(flag);
  return index >= 0 ? parts[index + 1] : undefined;
}

function vmNameFromPathArg(args) {
  const match = String(args ?? "").match(/([^\s]+\.(?:vmx|utm|qcow2|img|raw|iso))/i);
  return match ? path.basename(match[1], path.extname(match[1])) : undefined;
}

function processRuntime(command, args) {
  const haystack = `${command ?? ""} ${args ?? ""}`.toLowerCase();
  if (haystack.includes("qemu-system")) return "qemu";
  if (haystack.includes("vmware-vmx")) return "vmware";
  if (haystack.includes("utm")) return "utm";
  return undefined;
}

export function parseVmProcesses(stdout, { limit = DEFAULT_VM_LIMIT } = {}) {
  const vms = [];
  for (const line of String(stdout ?? "").trim().split("\n").slice(1)) {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\S+)\s*(.*)$/);
    if (!match) continue;
    const command = match[6];
    const args = match[7] || command;
    const runtime = processRuntime(command, args);
    if (!runtime) continue;
    const redacted = redactAndBoundProcessArgs(args, { maxLength: 300 });
    const pid = Number(match[1]);
    vms.push({
      runtime,
      id: String(pid),
      name: boundedString(argValue(args, "-name") ?? vmNameFromPathArg(args) ?? `${runtime}-process-${pid}`),
      state: "running",
      backend: runtime === "qemu" ? "qemu" : runtime,
      owner_hint: redacted.value,
      owner_hint_redaction: {
        redacted: redacted.redacted,
        truncated: redacted.truncated,
        original_length: redacted.original_length,
        max_length: redacted.max_length,
      },
      resource_snapshot: {
        pid,
        cpu_percent: Number(match[3]),
        memory_percent: Number(match[4]),
        rss_bytes: Number(match[5]) * 1024,
      },
      source_runtime: runtime,
      confidence: 0.4,
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
    source: result.source,
    result_count: count,
    support_status: classifyCommandFailure(result),
    error: result.error,
    stderr: result.stderr,
  };
}

async function pathExistsProbe(paths) {
  for (const candidate of paths.filter(Boolean)) {
    try {
      await access(candidate);
      return { status: "ok", source: { path: candidate, read_only: true } };
    } catch {
      // Try the next fixed candidate path.
    }
  }
  return { status: "unable", code: "ENOENT", error: `none of the fixed paths exist: ${paths.filter(Boolean).join(", ")}`, source: { paths: paths.filter(Boolean), read_only: true } };
}

function runtimeFromPathProbe(runtime, probe) {
  const supportStatus = classifyCommandFailure(probe);
  return {
    runtime,
    installed: supportStatus !== "missing",
    available: supportStatus === "ok",
    support_status: supportStatus,
    source: probe.source,
    error: probe.error,
  };
}

async function processVms(request) {
  const args = psArgsForPlatform();
  const probe = await runFixedCommand("ps", args, { timeout: 3000, maxBuffer: 1024 * 1024 });
  const vms = probe.status === "ok" ? parseVmProcesses(probe.stdout, { limit: request.vm_limit }) : [];
  const runtimes = [...new Set(vms.map((vm) => vm.runtime))].map((runtime) => ({
    runtime,
    installed: true,
    available: true,
    support_status: "ok",
    source: probe.command,
  }));
  return {
    runtimes,
    vms,
    probes: [probeMetadata("vm_process_scan", probe, "ps_vm_processes", vms.length)],
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

async function collectParallels(request) {
  const [versionProbe, listProbe] = await Promise.all([
    runFixedCommand("prlctl", ["--version"], { timeout: 2500 }),
    runFixedCommand("prlctl", ["list", "--all", "--json"], { timeout: 4500, maxBuffer: 512 * 1024 }),
  ]);
  const vms = listProbe.status === "ok" ? parseParallelsListJson(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("parallels", versionProbe.status === "ok" ? versionProbe : listProbe, versionFromStdout(versionProbe.stdout)),
    vms,
    probes: [
      probeMetadata("parallels_version", versionProbe, "version_text"),
      probeMetadata("parallels_list", listProbe, "parallels_list_json", vms.length),
    ],
  };
}

async function collectVmware(request) {
  const listProbe = await runFixedCommand("vmrun", ["list"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseVmrunList(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("vmware", listProbe),
    vms,
    probes: [probeMetadata("vmware_vmrun_list", listProbe, "vmrun_list", vms.length)],
  };
}

async function collectUtm() {
  const home = process.env.HOME;
  const appProbe = await pathExistsProbe([
    "/Applications/UTM.app",
    home ? `${home}/Applications/UTM.app` : undefined,
  ]);
  return {
    runtime: runtimeFromPathProbe("utm", appProbe),
    vms: [],
    probes: [probeMetadata("utm_app_probe", appProbe, "fixed_path_probe", appProbe.status === "ok" ? 1 : 0)],
  };
}

async function collectPodmanMachine(request) {
  const listProbe = await runFixedCommand("podman", ["machine", "list", "--format", "json"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parsePodmanMachineListJson(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("podman_machine", listProbe),
    vms,
    probes: [probeMetadata("podman_machine_list", listProbe, "podman_machine_list_json", vms.length)],
  };
}

async function collectIncus(request) {
  const listProbe = await runFixedCommand("incus", ["list", "--format", "json"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseIncusOrLxcListJson(listProbe.stdout, { runtime: "incus", limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("incus", listProbe),
    vms,
    probes: [probeMetadata("incus_list", listProbe, "incus_list_json", vms.length)],
  };
}

async function collectLxd(request) {
  const listProbe = await runFixedCommand("lxc", ["list", "--format", "json"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseIncusOrLxcListJson(listProbe.stdout, { runtime: "lxd", limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("lxd", listProbe),
    vms,
    probes: [probeMetadata("lxd_list", listProbe, "lxc_list_json", vms.length)],
  };
}

async function collectProxmox(request) {
  const listProbe = await runFixedCommand("qm", ["list"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseQmList(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("proxmox", listProbe),
    vms,
    probes: [probeMetadata("proxmox_qm_list", listProbe, "qm_list", vms.length)],
  };
}

async function collectXen(request) {
  const listProbe = await runFixedCommand("xl", ["list"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const vms = listProbe.status === "ok" ? parseXlList(listProbe.stdout, { limit: request.vm_limit }) : [];
  return {
    runtime: runtimeFromProbe("xen", listProbe),
    vms,
    probes: [probeMetadata("xen_xl_list", listProbe, "xl_list", vms.length)],
  };
}

function runtimeRank(runtime) {
  if (runtime.available) return 4;
  if (runtime.installed && runtime.support_status !== "missing") return 3;
  if (runtime.installed) return 2;
  return 1;
}

export function mergeRuntimes(runtimes) {
  const byName = new Map();
  for (const runtime of runtimes) {
    const existing = byName.get(runtime.runtime);
    if (!existing || runtimeRank(runtime) > runtimeRank(existing)) byName.set(runtime.runtime, runtime);
  }
  return [...byName.values()];
}

function normalizedIdentity(value) {
  return String(value ?? "").trim().toLowerCase();
}

function isProcessVmHint(vm) {
  return vm?.resource_snapshot?.pid !== undefined && vm.confidence <= 0.4 && ["qemu", "vmware", "utm"].includes(vm.runtime);
}

function compatibleProcessRuntime(processRuntimeName, runtimeName) {
  if (processRuntimeName === runtimeName) return true;
  if (processRuntimeName === "qemu") return ["libvirt", "proxmox", "incus", "lxd"].includes(runtimeName);
  return false;
}

function vmProcessMatchScore(vm, processHint) {
  if (!compatibleProcessRuntime(processHint.runtime, vm.runtime)) return 0;
  if (vm.state && processHint.state && vm.state !== processHint.state) return 0;

  const vmName = normalizedIdentity(vm.name ?? vm.id);
  const hintName = normalizedIdentity(processHint.name ?? processHint.id);
  if (vmName && hintName && vmName === hintName) return processHint.runtime === vm.runtime ? 4 : 3;

  const vmOwner = normalizedIdentity(vm.owner_hint);
  const hintOwner = normalizedIdentity(processHint.owner_hint);
  if (vmOwner && hintOwner && (hintOwner.includes(vmOwner) || vmOwner.includes(hintOwner))) return processHint.runtime === vm.runtime ? 3 : 2;
  if (vmName && hintOwner && hintOwner.includes(vmName)) return processHint.runtime === vm.runtime ? 3 : 2;
  return 0;
}

export function correlateVmProcessHints(vms) {
  const inventory = vms.filter((vm) => !isProcessVmHint(vm));
  const processHints = vms.filter(isProcessVmHint);
  const correlatedHintIndexes = new Set();
  const correlatedInventory = inventory.map((vm) => ({ ...vm }));

  for (const [hintIndex, processHint] of processHints.entries()) {
    let bestIndex = -1;
    let bestScore = 0;
    for (const [vmIndex, vm] of correlatedInventory.entries()) {
      const score = vmProcessMatchScore(vm, processHint);
      if (score > bestScore) {
        bestIndex = vmIndex;
        bestScore = score;
      }
    }
    if (bestIndex === -1) continue;
    const target = correlatedInventory[bestIndex];
    correlatedInventory[bestIndex] = {
      ...target,
      resource_snapshot: target.resource_snapshot ?? processHint.resource_snapshot,
      process_correlation: {
        source: "vm_process_scan",
        pid: processHint.resource_snapshot.pid,
        runtime: processHint.runtime,
        confidence: Math.min(0.95, 0.5 + bestScore / 10),
        owner_hint: processHint.owner_hint,
        owner_hint_redaction: processHint.owner_hint_redaction,
      },
    };
    correlatedHintIndexes.add(hintIndex);
  }

  const uncorrelatedProcessHints = processHints.filter((_hint, index) => !correlatedHintIndexes.has(index));
  return {
    vms: [...correlatedInventory, ...uncorrelatedProcessHints],
    correlated_process_count: correlatedHintIndexes.size,
    uncorrelated_process_hint_count: uncorrelatedProcessHints.length,
  };
}

function summarize(runtimes, vms, correlation = {}) {
  return {
    runtime_count: runtimes.length,
    available_runtime_count: runtimes.filter((runtime) => runtime.available).length,
    vm_count: vms.length,
    running_vm_count: vms.filter((vm) => vm.state === "running").length,
    stopped_vm_count: vms.filter((vm) => vm.state === "stopped").length,
    correlated_process_count: correlation.correlated_process_count ?? 0,
    uncorrelated_process_hint_count: correlation.uncorrelated_process_hint_count ?? 0,
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
      collectParallels(request),
      collectVmware(request),
      collectUtm(),
      collectPodmanMachine(request),
      collectIncus(request),
      collectLxd(request),
      collectProxmox(request),
      collectXen(request),
      processVms(request),
    ]);
    const runtimes = mergeRuntimes(results.flatMap((result) => result.runtimes ?? [result.runtime]).filter(Boolean));
    const rawVms = results.flatMap((result) => result.vms ?? []);
    const correlation = correlateVmProcessHints(rawVms);
    const vms = correlation.vms.slice(0, request.vm_limit);
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
      summary: summarize(runtimes, vms, correlation),
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
