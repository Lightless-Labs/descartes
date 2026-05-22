import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { parseVmProcesses } from "./vms.js";

const execFileAsync = promisify(execFile);
const DEFAULT_CONTAINER_LIMIT = 80;
const DEFAULT_HOST_LIMIT = 40;

function clampNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.floor(number), min), max);
}

export function normalizeContainerRequest(options = {}) {
  return {
    container_limit: clampNumber(options.containerLimit ?? options.container_limit, DEFAULT_CONTAINER_LIMIT, 1, 200),
    host_limit: clampNumber(options.hostLimit ?? options.host_limit, DEFAULT_HOST_LIMIT, 1, 100),
    include_stopped: options.includeStopped ?? options.include_stopped ?? true,
    collect_stats: options.collectStats ?? options.collect_stats ?? true,
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

function parseJsonLines(stdout) {
  const values = [];
  for (const line of String(stdout ?? "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      values.push(JSON.parse(trimmed));
    } catch {
      // Ignore malformed runtime rows; callers keep command stderr/status.
    }
  }
  return values;
}

function parseJsonMaybeArray(stdout) {
  const trimmed = String(stdout ?? "").trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === "object") return [parsed];
  } catch {
    return parseJsonLines(trimmed);
  }
  return [];
}

export function parsePercent(value) {
  if (value === undefined || value === null || value === "") return undefined;
  const text = String(value).replace(/%$/, "").trim();
  const number = Number(text);
  return Number.isFinite(number) ? number : undefined;
}

const BYTE_UNITS = new Map([
  ["b", 1],
  ["kb", 1000], ["kib", 1024],
  ["mb", 1000 ** 2], ["mib", 1024 ** 2],
  ["gb", 1000 ** 3], ["gib", 1024 ** 3],
  ["tb", 1000 ** 4], ["tib", 1024 ** 4],
]);

export function parseByteQuantity(value) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = String(value).trim();
  const match = text.match(/^([0-9.]+)\s*([KMGT]?i?B|B)?$/i);
  if (!match) return undefined;
  const number = Number(match[1]);
  if (!Number.isFinite(number)) return undefined;
  const unit = (match[2] ?? "B").toLowerCase();
  return Math.round(number * (BYTE_UNITS.get(unit) ?? 1));
}

export function parseMemoryUsagePair(value) {
  const [used, limit] = String(value ?? "").split("/").map((part) => part.trim());
  return {
    memory_usage_bytes: parseByteQuantity(used),
    memory_limit_bytes: parseByteQuantity(limit),
  };
}

function boundedString(value, max = 240) {
  if (value === undefined || value === null) return undefined;
  return truncate(String(value), max);
}

function firstName(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}

function normalizeContainerState(value) {
  const text = String(value ?? "unknown").toLowerCase();
  if (text.includes("running") || text === "up") return "running";
  if (text.includes("exited") || text.includes("stopped") || text === "configured") return "stopped";
  if (text.includes("paused")) return "paused";
  if (text.includes("created")) return "created";
  if (text.includes("restarting")) return "restarting";
  if (text.includes("dead")) return "dead";
  return text || "unknown";
}

export function parseDockerPsJsonLines(stdout, { limit = DEFAULT_CONTAINER_LIMIT, includeStopped = true } = {}) {
  return parseJsonLines(stdout).map((item) => {
    const state = normalizeContainerState(item.State ?? item.Status);
    if (!includeStopped && state !== "running") return undefined;
    return {
      runtime: "docker",
      id: item.ID,
      name: item.Names,
      image: item.Image,
      command: boundedString(item.Command),
      state,
      status: item.Status,
      ports: boundedString(item.Ports, 400),
      networks: item.Networks ? String(item.Networks).split(",").map((part) => part.trim()).filter(Boolean) : [],
      mounts: item.Mounts ? String(item.Mounts).split(",").map((part) => part.trim()).filter(Boolean).slice(0, 8) : [],
      created_at: item.CreatedAt,
      source_runtime: "docker",
      confidence: 1,
    };
  }).filter(Boolean).slice(0, limit);
}

export function parseDockerStatsJsonLines(stdout) {
  const stats = new Map();
  for (const item of parseJsonLines(stdout)) {
    const memory = parseMemoryUsagePair(item.MemUsage);
    const snapshot = {
      cpu_percent: parsePercent(item.CPUPerc),
      memory_percent: parsePercent(item.MemPerc),
      ...memory,
      net_io: item.NetIO,
      block_io: item.BlockIO,
      pids: item.PIDs === undefined ? undefined : Number(item.PIDs),
    };
    const keys = [item.ID, item.Container, item.Name].filter(Boolean);
    for (const key of keys) stats.set(String(key), snapshot);
  }
  return stats;
}

export function parsePodmanPsJson(stdout, { limit = DEFAULT_CONTAINER_LIMIT, includeStopped = true } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => {
    const state = normalizeContainerState(item.State ?? item.Status);
    if (!includeStopped && state !== "running") return undefined;
    return {
      runtime: "podman",
      id: item.Id ?? item.ID,
      name: firstName(item.Names ?? item.Namespaces),
      image: item.Image,
      command: Array.isArray(item.Command) ? boundedString(item.Command.join(" ")) : boundedString(item.Command),
      state,
      status: item.Status,
      ports: Array.isArray(item.Ports) ? item.Ports.slice(0, 12) : item.Ports,
      networks: item.Networks ?? [],
      created_at: item.CreatedAt ?? item.Created,
      source_runtime: "podman",
      confidence: 1,
    };
  }).filter(Boolean).slice(0, limit);
}

export function parsePodmanStatsJson(stdout) {
  const stats = new Map();
  for (const item of parseJsonMaybeArray(stdout)) {
    const memory = String(item.MemUsage ?? item.mem_usage ?? "").includes("/")
      ? parseMemoryUsagePair(item.MemUsage ?? item.mem_usage)
      : { memory_usage_bytes: parseByteQuantity(item.MemUsage ?? item.mem_usage) };
    const snapshot = {
      cpu_percent: parsePercent(item.CPU ?? item.cpu_percent ?? item.CPUPerc),
      memory_percent: parsePercent(item.MemPerc ?? item.mem_percent ?? item.MemPercent),
      ...memory,
      net_io: item.NetIO ?? item.net_io,
      block_io: item.BlockIO ?? item.block_io,
      pids: item.PIDS === undefined && item.pids === undefined ? undefined : Number(item.PIDS ?? item.pids),
    };
    const keys = [item.ID, item.Id, item.ContainerID, item.Name, item.name].filter(Boolean);
    for (const key of keys) stats.set(String(key), snapshot);
  }
  return stats;
}

function attachStats(containers, stats) {
  return containers.map((container) => {
    const shortId = container.id ? String(container.id).slice(0, 12) : undefined;
    const snapshot = stats.get(String(container.id)) ?? (shortId ? stats.get(shortId) : undefined) ?? stats.get(String(container.name));
    return snapshot ? { ...container, resource_snapshot: snapshot } : container;
  });
}

export function classifyCommandFailure(commandResult) {
  if (commandResult.status === "ok") return "ok";
  const combined = `${commandResult.error ?? ""}\n${commandResult.stderr ?? ""}`.toLowerCase();
  if (commandResult.code === "ENOENT" || combined.includes("enoent") || combined.includes("not found")) return "missing";
  if (combined.includes("permission denied") || combined.includes("access denied") || combined.includes("got permission denied")) return "permission_limited";
  if (combined.includes("cannot connect") || combined.includes("connection refused") || combined.includes("daemon") || combined.includes("socket")) return "daemon_unavailable";
  return "unable";
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

function parseDockerVersion(stdout) {
  const objects = parseJsonMaybeArray(stdout);
  const item = objects[0] ?? {};
  return item.Server?.Version ?? item.Client?.Version ?? item.Version;
}

function parsePodmanVersion(stdout) {
  const objects = parseJsonMaybeArray(stdout);
  const item = objects[0] ?? {};
  return item.Server?.Version ?? item.Client?.Version ?? item.Version ?? item.version;
}

function parseColimaBytes(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value * 1024 ** 3;
  return parseByteQuantity(value);
}

function vmCorrelation(runtime, name) {
  return name ? { runtime, name: String(name), confidence: 1 } : undefined;
}

export function parseColimaStatusJson(stdout) {
  const item = parseJsonMaybeArray(stdout)[0];
  if (!item) return undefined;
  const name = item.name ?? item.Name ?? "default";
  return {
    runtime: "colima",
    name,
    state: normalizeContainerState(item.status ?? item.Status ?? item.state),
    container_runtime: item.runtime,
    arch: item.arch,
    cpus: item.cpus ?? item.cpu,
    memory_bytes: parseColimaBytes(item.memory),
    disk_bytes: parseColimaBytes(item.disk),
    address: item.address,
    source_runtime: "colima",
    vm_correlation: vmCorrelation("colima", name),
    confidence: 1,
  };
}

export function parseColimaListJson(stdout, { limit = DEFAULT_HOST_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => {
    const name = item.name ?? item.Name;
    return {
      runtime: "colima",
      name,
      state: normalizeContainerState(item.status ?? item.Status ?? item.state),
      container_runtime: item.runtime,
      arch: item.arch,
      cpus: item.cpus ?? item.cpu,
      memory_bytes: parseColimaBytes(item.memory),
      disk_bytes: parseColimaBytes(item.disk),
      address: item.address,
      source_runtime: "colima",
      vm_correlation: vmCorrelation("colima", name),
      confidence: 1,
    };
  }).slice(0, limit);
}

export function parseLimaListJson(stdout, { limit = DEFAULT_HOST_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => {
    const name = item.name ?? item.Name;
    return {
      runtime: "lima",
      name,
      state: normalizeContainerState(item.status ?? item.Status),
      container_runtime: item.containerd ? "containerd" : undefined,
      arch: item.arch,
      cpus: item.cpus ?? item.CPUs,
      memory_bytes: parseByteQuantity(item.memory ?? item.Memory),
      disk_bytes: parseByteQuantity(item.disk ?? item.Disk),
      directory: item.dir ?? item.Dir,
      source_runtime: "lima",
      vm_correlation: vmCorrelation("lima", name),
      confidence: 1,
    };
  }).slice(0, limit);
}

export function parsePodmanMachineListJson(stdout, { limit = DEFAULT_HOST_LIMIT } = {}) {
  return parseJsonMaybeArray(stdout).map((item) => {
    const name = item.Name ?? item.name;
    return {
      runtime: "podman_machine",
      name,
      state: normalizeContainerState(item.Running === true || item.running === true ? "running" : (item.State ?? item.Status ?? item.state ?? item.status ?? "stopped")),
      container_runtime: "podman",
      arch: item.Arch ?? item.arch,
      cpus: item.CPUs ?? item.Cpus ?? item.cpus,
      memory_bytes: parseByteQuantity(item.Memory ?? item.memory),
      disk_bytes: parseByteQuantity(item.DiskSize ?? item.diskSize ?? item.disk_size),
      address: item.IPAddress ?? item.ipAddress,
      source_runtime: "podman_machine",
      vm_correlation: vmCorrelation("podman_machine", name),
      confidence: 1,
    };
  }).filter((host) => host.name).slice(0, limit);
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

function psArgsForPlatform(platform = process.platform) {
  return platform === "linux" ? ["-eo", "pid,ppid,pcpu,pmem,rss,comm,args"] : ["-axo", "pid,ppid,pcpu,pmem,rss,comm,args"];
}

function normalizedIdentity(value) {
  return String(value ?? "").trim().toLowerCase();
}

function compatibleHostProcessRuntime(processRuntimeName, hostRuntimeName) {
  if (processRuntimeName === hostRuntimeName) return true;
  if (processRuntimeName === "qemu") return ["colima", "lima", "podman_machine"].includes(hostRuntimeName);
  return false;
}

function containerHostProcessMatchScore(host, processHint) {
  const correlation = host.vm_correlation;
  const hostRuntime = correlation?.runtime ?? host.runtime;
  if (!compatibleHostProcessRuntime(processHint.runtime, hostRuntime)) return 0;
  if (host.state && processHint.state && host.state !== processHint.state) return 0;

  const hostName = normalizedIdentity(correlation?.name ?? host.name);
  const hintName = normalizedIdentity(processHint.name ?? processHint.id);
  if (hostName && hintName && hostName === hintName) return processHint.runtime === hostRuntime ? 4 : 3;

  const hintOwner = normalizedIdentity(processHint.owner_hint);
  if (hostName && hintOwner && hintOwner.includes(hostName)) return processHint.runtime === hostRuntime ? 3 : 2;
  return 0;
}

export function correlateContainerHostProcessHints(hosts, processHints) {
  const correlatedHosts = hosts.map((host) => ({ ...host }));
  const correlatedHintIndexes = new Set();

  for (const [hintIndex, processHint] of processHints.entries()) {
    let bestIndex = -1;
    let bestScore = 0;
    for (const [hostIndex, host] of correlatedHosts.entries()) {
      const score = containerHostProcessMatchScore(host, processHint);
      if (score > bestScore) {
        bestIndex = hostIndex;
        bestScore = score;
      }
    }
    if (bestIndex === -1) continue;
    const target = correlatedHosts[bestIndex];
    correlatedHosts[bestIndex] = {
      ...target,
      resource_snapshot: target.resource_snapshot ?? processHint.resource_snapshot,
      process_correlation: {
        source: "container_host_process_scan",
        pid: processHint.resource_snapshot.pid,
        runtime: processHint.runtime,
        confidence: Math.min(0.95, 0.5 + bestScore / 10),
        owner_hint: processHint.owner_hint,
        owner_hint_redaction: processHint.owner_hint_redaction,
      },
    };
    correlatedHintIndexes.add(hintIndex);
  }

  return {
    hosts: correlatedHosts,
    correlated_host_process_count: correlatedHintIndexes.size,
    uncorrelated_host_process_hint_count: processHints.length - correlatedHintIndexes.size,
  };
}

async function correlateContainerHostResources(hosts, request) {
  if (hosts.length === 0) return { hosts, probes: [], correlation: { correlated_host_process_count: 0, uncorrelated_host_process_hint_count: 0 } };
  const args = psArgsForPlatform();
  const probe = await runFixedCommand("ps", args, { timeout: 3000, maxBuffer: 1024 * 1024 });
  const processHints = probe.status === "ok" ? parseVmProcesses(probe.stdout, { limit: request.host_limit * 4 }) : [];
  const correlation = correlateContainerHostProcessHints(hosts, processHints);
  return {
    hosts: correlation.hosts,
    probes: [probeMetadata("container_host_process_scan", probe, "ps_vm_processes", processHints.length)],
    correlation,
  };
}

async function collectDocker(request) {
  const psArgs = ["ps", request.include_stopped ? "--all" : undefined, "--no-trunc", "--format", "{{json .}}"].filter(Boolean);
  const [versionProbe, psProbe] = await Promise.all([
    runFixedCommand("docker", ["version", "--format", "{{json .}}"], { timeout: 3500 }),
    runFixedCommand("docker", psArgs, { timeout: 5000, maxBuffer: 1024 * 1024 }),
  ]);
  const containers = psProbe.status === "ok" ? parseDockerPsJsonLines(psProbe.stdout, { limit: request.container_limit, includeStopped: request.include_stopped }) : [];
  let statsProbe;
  let stats = new Map();
  if (request.collect_stats && containers.some((container) => container.state === "running")) {
    statsProbe = await runFixedCommand("docker", ["stats", "--no-stream", "--format", "{{json .}}"], { timeout: 6500, maxBuffer: 1024 * 1024 });
    if (statsProbe.status === "ok") stats = parseDockerStatsJsonLines(statsProbe.stdout);
  }
  return {
    runtime: runtimeFromProbe("docker", versionProbe.status === "ok" ? versionProbe : psProbe, parseDockerVersion(versionProbe.stdout)),
    containers: attachStats(containers, stats),
    probes: [
      probeMetadata("docker_version", versionProbe, "docker_version_json"),
      probeMetadata("docker_ps", psProbe, "docker_ps_json_lines", containers.length),
      statsProbe ? probeMetadata("docker_stats", statsProbe, "docker_stats_json_lines", stats.size) : undefined,
    ].filter(Boolean),
  };
}

async function collectPodman(request) {
  const psArgs = ["ps", request.include_stopped ? "--all" : undefined, "--format", "json"].filter(Boolean);
  const [versionProbe, psProbe] = await Promise.all([
    runFixedCommand("podman", ["version", "--format", "json"], { timeout: 3500 }),
    runFixedCommand("podman", psArgs, { timeout: 5000, maxBuffer: 1024 * 1024 }),
  ]);
  const containers = psProbe.status === "ok" ? parsePodmanPsJson(psProbe.stdout, { limit: request.container_limit, includeStopped: request.include_stopped }) : [];
  let statsProbe;
  let stats = new Map();
  if (request.collect_stats && containers.some((container) => container.state === "running")) {
    statsProbe = await runFixedCommand("podman", ["stats", "--no-stream", "--format", "json"], { timeout: 6500, maxBuffer: 1024 * 1024 });
    if (statsProbe.status === "ok") stats = parsePodmanStatsJson(statsProbe.stdout);
  }
  return {
    runtime: runtimeFromProbe("podman", versionProbe.status === "ok" ? versionProbe : psProbe, parsePodmanVersion(versionProbe.stdout)),
    containers: attachStats(containers, stats),
    probes: [
      probeMetadata("podman_version", versionProbe, "podman_version_json"),
      probeMetadata("podman_ps", psProbe, "podman_ps_json", containers.length),
      statsProbe ? probeMetadata("podman_stats", statsProbe, "podman_stats_json", stats.size) : undefined,
    ].filter(Boolean),
  };
}

async function collectColima(request) {
  const [statusProbe, listProbe] = await Promise.all([
    runFixedCommand("colima", ["status", "--json"], { timeout: 3500 }),
    runFixedCommand("colima", ["list", "--json"], { timeout: 3500, maxBuffer: 512 * 1024 }),
  ]);
  const statusHost = statusProbe.status === "ok" ? parseColimaStatusJson(statusProbe.stdout) : undefined;
  const listHosts = listProbe.status === "ok" ? parseColimaListJson(listProbe.stdout, { limit: request.host_limit }) : [];
  const hosts = listHosts.length > 0 ? listHosts : [statusHost].filter(Boolean);
  return {
    runtime: runtimeFromProbe("colima", statusProbe.status === "ok" ? statusProbe : listProbe),
    hosts,
    probes: [
      probeMetadata("colima_status", statusProbe, "colima_status_json", statusHost ? 1 : 0),
      probeMetadata("colima_list", listProbe, "colima_list_json", listHosts.length),
    ],
  };
}

async function collectLima(request) {
  const listProbe = await runFixedCommand("limactl", ["list", "--json"], { timeout: 3500, maxBuffer: 512 * 1024 });
  const hosts = listProbe.status === "ok" ? parseLimaListJson(listProbe.stdout, { limit: request.host_limit }) : [];
  return {
    runtime: runtimeFromProbe("lima", listProbe),
    hosts,
    probes: [probeMetadata("lima_list", listProbe, "lima_list_json", hosts.length)],
  };
}

async function collectPodmanMachineHost(request) {
  const listProbe = await runFixedCommand("podman", ["machine", "list", "--format", "json"], { timeout: 4500, maxBuffer: 512 * 1024 });
  const hosts = listProbe.status === "ok" ? parsePodmanMachineListJson(listProbe.stdout, { limit: request.host_limit }) : [];
  return {
    hosts,
    probes: [probeMetadata("podman_machine_list", listProbe, "podman_machine_list_json", hosts.length)],
  };
}

function summarize(runtimes, containers, hosts, correlation = {}) {
  return {
    runtime_count: runtimes.length,
    available_runtime_count: runtimes.filter((runtime) => runtime.available).length,
    container_count: containers.length,
    running_container_count: containers.filter((container) => container.state === "running").length,
    stopped_container_count: containers.filter((container) => container.state === "stopped").length,
    host_count: hosts.length,
    running_host_count: hosts.filter((host) => host.state === "running").length,
    vm_correlatable_host_count: hosts.filter((host) => host.vm_correlation).length,
    correlated_host_process_count: correlation.correlated_host_process_count ?? 0,
    uncorrelated_host_process_hint_count: correlation.uncorrelated_host_process_hint_count ?? 0,
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
  if (status === "ok") return result.summary.running_container_count > 0 || result.summary.running_host_count > 0 ? "none" : "ambiguous";
  if (status === "warning") return "missing_permission";
  return "ambiguous";
}

export async function collectContainerEvidence(options = {}) {
  const request = normalizeContainerRequest(options);
  return timedEnvelope(async () => {
    const results = await Promise.all([
      collectDocker(request),
      collectPodman(request),
      collectColima(request),
      collectLima(request),
      collectPodmanMachineHost(request),
    ]);
    const runtimes = results.map((result) => result.runtime).filter(Boolean);
    const containers = results.flatMap((result) => result.containers ?? []).slice(0, request.container_limit);
    const rawContainerHosts = results.flatMap((result) => result.hosts ?? []).slice(0, request.host_limit);
    const hostResourceCorrelation = await correlateContainerHostResources(rawContainerHosts, request);
    const container_hosts = hostResourceCorrelation.hosts;
    const probes = [...results.flatMap((result) => result.probes ?? []), ...hostResourceCorrelation.probes];
    const unsupported_or_missing = runtimes.filter((runtime) => !runtime.available).map((runtime) => ({
      runtime: runtime.runtime,
      support_status: runtime.support_status,
      error: runtime.error,
    }));

    return {
      platform: process.platform,
      request,
      runtimes,
      containers,
      container_hosts,
      probes,
      unsupported_or_missing,
      summary: summarize(runtimes, containers, container_hosts, hostResourceCorrelation.correlation),
      privacy: {
        bounded: true,
        note: "Container names, images, commands, ports, and host instance metadata are sensitive diagnostic artifacts.",
      },
    };
  }, (result) => evidenceEnvelope({
    id: "containers",
    status: envelopeStatus(result),
    source: "container",
    result,
    confidence: result?.runtimes?.some((runtime) => runtime.available) ? 0.9 : 0.45,
    reviewHint: reviewHint(result),
    tool: "collect_containers",
    target: `limit=${request.container_limit},hosts=${request.host_limit},stopped=${request.include_stopped},stats=${request.collect_stats}`,
  }));
}
