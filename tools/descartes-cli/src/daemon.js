import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { appendMetricPoints, parseDurationMs, writeDaemonStatus } from "./history-store.js";
import { collectDiskEvidence } from "./tools/disks.js";
import { collectProcessEvidence } from "./tools/processes.js";
import { collectSystemEvidence } from "./tools/system.js";

export const DEFAULT_DAEMON_INTERVAL_MS = 60 * 1000;
export const DEFAULT_DAEMON_PROCESS_LIMIT = 5;

export function defaultDaemonProfile() {
  return {
    interval_ms: DEFAULT_DAEMON_INTERVAL_MS,
    collectors: {
      system: { enabled: true },
      processes: { enabled: true, limit: DEFAULT_DAEMON_PROCESS_LIMIT },
      disks: { enabled: true },
    },
    safety: {
      read_only: true,
      background_llm_calls: false,
      telemetry: false,
      host_mutation: false,
    },
  };
}

function metric({ ts, metric_name, dimensions = {}, value, unit, envelope, sensitivity = "operational" }) {
  return {
    ts,
    metric_name,
    dimensions,
    value,
    unit,
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity,
  };
}

function pushFinite(points, point) {
  if (Number.isFinite(Number(point.value))) points.push(point);
}

export function metricPointsFromEvidence(evidence, options = {}) {
  const ts = options.ts ?? new Date().toISOString();
  const points = [];

  const system = evidence.find((envelope) => envelope.id === "system-overview" && envelope.status === "ok");
  if (system) {
    const result = system.result ?? {};
    const [load1, load5, load15] = result.load_average ?? [];
    pushFinite(points, metric({ ts, metric_name: "system.load.1m", value: load1, unit: "load_average", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.load.5m", value: load5, unit: "load_average", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.load.15m", value: load15, unit: "load_average", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.memory.used_fraction", value: result.memory?.used_fraction, unit: "fraction", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.memory.free_bytes", value: result.memory?.free_bytes, unit: "bytes", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.swap.used_bytes", value: result.swap?.used_bytes, unit: "bytes", envelope: system }));
    pushFinite(points, metric({ ts, metric_name: "system.uptime_seconds", value: result.uptime_seconds, unit: "seconds", envelope: system }));
  }

  const processes = evidence.find((envelope) => envelope.id === "top-processes" && envelope.status === "ok");
  if (processes) {
    const topCpu = processes.result?.top_cpu ?? [];
    topCpu.forEach((process, index) => {
      const dimensions = { rank: index + 1, command: process.command ?? "unknown" };
      pushFinite(points, metric({ ts, metric_name: "process.cpu_percent", dimensions, value: process.cpu_percent, unit: "percent", envelope: processes, sensitivity: "process_identity" }));
    });
    const topMemory = processes.result?.top_memory ?? [];
    topMemory.forEach((process, index) => {
      const dimensions = { rank: index + 1, command: process.command ?? "unknown" };
      pushFinite(points, metric({ ts, metric_name: "process.memory_percent", dimensions, value: process.memory_percent, unit: "percent", envelope: processes, sensitivity: "process_identity" }));
      pushFinite(points, metric({ ts, metric_name: "process.rss_bytes", dimensions, value: process.rss_bytes, unit: "bytes", envelope: processes, sensitivity: "process_identity" }));
    });
  }

  const disks = evidence.find((envelope) => envelope.id === "disk-usage" && envelope.status === "ok");
  if (disks) {
    for (const filesystem of disks.result?.filesystems ?? []) {
      if (filesystem.pressure_relevant === false) continue;
      const dimensions = {
        mount_point: filesystem.mount_point,
        filesystem: filesystem.filesystem,
        classification: filesystem.classification,
      };
      pushFinite(points, metric({ ts, metric_name: "disk.used_fraction", dimensions, value: filesystem.used_fraction, unit: "fraction", envelope: disks, sensitivity: "path" }));
      pushFinite(points, metric({ ts, metric_name: "disk.available_bytes", dimensions, value: filesystem.available_bytes, unit: "bytes", envelope: disks, sensitivity: "path" }));
    }
    if (Array.isArray(disks.result?.inodes)) {
      for (const filesystem of disks.result.inodes) {
        if (filesystem.pressure_relevant === false) continue;
        const dimensions = {
          mount_point: filesystem.mount_point,
          filesystem: filesystem.filesystem,
          classification: filesystem.classification,
        };
        pushFinite(points, metric({ ts, metric_name: "disk.inode_used_fraction", dimensions, value: filesystem.used_fraction, unit: "fraction", envelope: disks, sensitivity: "path" }));
      }
    }
  }

  return points;
}

export async function collectDaemonEvidence(profile = defaultDaemonProfile(), collectors = {}) {
  const activeCollectors = {
    system: collectors.system ?? collectSystemEvidence,
    processes: collectors.processes ?? collectProcessEvidence,
    disks: collectors.disks ?? collectDiskEvidence,
  };
  const evidence = [];
  if (profile.collectors.system?.enabled) evidence.push(await activeCollectors.system());
  if (profile.collectors.processes?.enabled) evidence.push(await activeCollectors.processes({ limit: profile.collectors.processes.limit ?? DEFAULT_DAEMON_PROCESS_LIMIT }));
  if (profile.collectors.disks?.enabled) evidence.push(await activeCollectors.disks());
  return evidence;
}

export async function runDaemonIteration(descartesPaths, options = {}) {
  const profile = options.profile ?? defaultDaemonProfile();
  const ts = options.ts ?? new Date().toISOString();
  const evidence = await collectDaemonEvidence(profile, options.collectors);
  const points = metricPointsFromEvidence(evidence, { ts });
  const write = await appendMetricPoints(descartesPaths, points, {
    ts,
    retentionMs: options.retentionMs,
    maxBytes: options.maxBytes,
    now: options.now ?? ts,
  });
  const status = await writeDaemonStatus(descartesPaths, {
    state: "ok",
    mode: options.mode ?? "foreground",
    profile,
    collector_statuses: evidence.map((envelope) => ({ id: envelope.id, status: envelope.status, tool: envelope.trace?.tool })),
    points_written: write.written_count,
    retention: write.retention,
  });
  return { evidence, points, write, status };
}

export const DAEMON_LABEL = "com.lightless-labs.descartes.daemon";

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function systemdEscape(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function xmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function homeDir(env = process.env) {
  return env.HOME || os.homedir();
}

function daemonLogDir(descartesPaths) {
  return path.join(descartesPaths.stateDir, "daemon");
}

function xdgEnvLines(env = process.env) {
  return ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"]
    .filter((name) => env[name] && String(env[name]).trim())
    .map((name) => `Environment="${name}=${systemdEscape(env[name])}"`);
}

export function resolveDaemonServiceSpec(descartesPaths, options = {}) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const nodePath = options.nodePath ?? process.execPath;
  const cliPath = options.cliPath ?? process.argv[1];
  if (!cliPath) throw new Error("Cannot determine Descartes CLI path for daemon service installation");

  const logDir = daemonLogDir(descartesPaths);
  if (platform === "darwin") {
    const installPath = path.join(homeDir(env), "Library", "LaunchAgents", `${DAEMON_LABEL}.plist`);
    const programArguments = [nodePath, cliPath, "daemon", "run", "--foreground"];
    const argumentXml = programArguments.map((argument) => `\t\t<string>${xmlEscape(argument)}</string>`).join("\n");
    return {
      service_manager: "launchd-user",
      label: DAEMON_LABEL,
      install_path: installPath,
      log_dir: logDir,
      content: `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n\t<key>Label</key>\n\t<string>${DAEMON_LABEL}</string>\n\t<key>ProgramArguments</key>\n\t<array>\n${argumentXml}\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n\t<key>StandardOutPath</key>\n\t<string>${xmlEscape(path.join(logDir, "stdout.log"))}</string>\n\t<key>StandardErrorPath</key>\n\t<string>${xmlEscape(path.join(logDir, "stderr.log"))}</string>\n</dict>\n</plist>\n`,
    };
  }

  if (platform === "linux") {
    const configBase = path.dirname(descartesPaths.configDir);
    const installPath = path.join(configBase, "systemd", "user", "descartes.service");
    const execStart = [nodePath, cliPath, "daemon", "run", "--foreground"].map(shellQuote).join(" ");
    const envLines = xdgEnvLines(env).join("\n");
    return {
      service_manager: "systemd-user",
      label: "descartes.service",
      install_path: installPath,
      log_dir: logDir,
      content: `[Unit]\nDescription=Descartes local history daemon\nDocumentation=https://github.com/Lightless-Labs/descartes\n\n[Service]\nType=simple\nExecStart=${execStart}\nRestart=on-failure\nRestartSec=10\n${envLines ? `${envLines}\n` : ""}\n[Install]\nWantedBy=default.target\n`,
    };
  }

  throw new Error(`Daemon install is not supported on ${platform}. Use 'descartes daemon run --foreground' instead.`);
}

async function readFileIfPresent(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

export async function installDaemonService(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  await fs.mkdir(path.dirname(spec.install_path), { recursive: true, mode: 0o700 });
  await fs.mkdir(spec.log_dir, { recursive: true, mode: 0o700 });
  const existing = await readFileIfPresent(spec.install_path);
  if (existing === spec.content) {
    return { status: "unchanged", installed: true, ...spec };
  }
  await fs.writeFile(spec.install_path, spec.content, { mode: 0o600 });
  return { status: existing === undefined ? "installed" : "updated", installed: true, ...spec };
}

export async function daemonServiceStatus(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  const existing = await readFileIfPresent(spec.install_path);
  return {
    status: existing === undefined ? "not_installed" : existing === spec.content ? "installed" : "drifted",
    installed: existing !== undefined,
    content_matches: existing === spec.content,
    service_manager: spec.service_manager,
    label: spec.label,
    install_path: spec.install_path,
    log_dir: spec.log_dir,
  };
}

export async function uninstallDaemonService(descartesPaths, options = {}) {
  const spec = resolveDaemonServiceSpec(descartesPaths, options);
  try {
    await fs.unlink(spec.install_path);
    return { status: "removed", installed: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { status: "not_installed", installed: false, service_manager: spec.service_manager, label: spec.label, install_path: spec.install_path };
    }
    throw error;
  }
}

function daemonUsage() {
  return `Usage:
  descartes daemon install
  descartes daemon status
  descartes daemon uninstall
  descartes daemon run --foreground [--once] [--interval <duration>]

Install writes an idempotent user-level launchd/systemd service file. It does not start the service yet.
The foreground daemon loop is read-only, performs no background LLM calls, and takes no host actions.`;
}

function parseRunArgs(rest) {
  const options = { foreground: false, once: false, intervalMs: DEFAULT_DAEMON_INTERVAL_MS };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--foreground") options.foreground = true;
    else if (arg === "--once") options.once = true;
    else if (arg === "--interval" || arg === "--interval-seconds") {
      const value = rest[index + 1];
      if (!value) throw new Error(`${arg} requires a value`);
      options.intervalMs = arg === "--interval-seconds" ? Number(value) * 1000 : parseDurationMs(value, DEFAULT_DAEMON_INTERVAL_MS);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`Unknown daemon option: ${arg}\n\n${daemonUsage()}`);
    }
  }
  if (options.help) return options;
  if (!options.foreground) throw new Error(`Only foreground daemon runs are implemented in this milestone.\n\n${daemonUsage()}`);
  if (!Number.isFinite(options.intervalMs) || options.intervalMs < 1000) throw new Error("Daemon interval must be at least 1s");
  return options;
}

function parseDaemonArgs(args) {
  const [subcommand, ...rest] = args;
  if (!subcommand || subcommand === "--help" || subcommand === "-h") return { subcommand: "help" };
  if (!["install", "status", "uninstall", "run"].includes(subcommand)) {
    throw new Error(`Unsupported daemon command: ${subcommand}\n\n${daemonUsage()}`);
  }
  if (subcommand !== "run" && rest.length > 0) throw new Error(`Unexpected daemon ${subcommand} arguments: ${rest.join(" ")}\n\n${daemonUsage()}`);
  return subcommand === "run" ? { subcommand, ...parseRunArgs(rest) } : { subcommand };
}

export async function runDaemon(descartesPaths, args) {
  const options = parseDaemonArgs(args);
  if (options.subcommand === "help" || options.help) {
    console.log(daemonUsage());
    return;
  }
  if (options.subcommand === "install") {
    console.log(JSON.stringify(await installDaemonService(descartesPaths), null, 2));
    return;
  }
  if (options.subcommand === "status") {
    console.log(JSON.stringify(await daemonServiceStatus(descartesPaths), null, 2));
    return;
  }
  if (options.subcommand === "uninstall") {
    console.log(JSON.stringify(await uninstallDaemonService(descartesPaths), null, 2));
    return;
  }

  let stopping = false;
  const stop = () => {
    stopping = true;
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    do {
      const result = await runDaemonIteration(descartesPaths, { mode: "foreground" });
      console.log(JSON.stringify({ status: "ok", points_written: result.points.length, ts: result.status.ts }));
      if (options.once) break;
      await sleep(options.intervalMs, undefined, { ref: true });
    } while (!stopping);
  } finally {
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    if (stopping) await writeDaemonStatus(descartesPaths, { state: "stopped", mode: "foreground" });
  }
}
