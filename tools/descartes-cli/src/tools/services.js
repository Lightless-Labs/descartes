import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DEFAULT_SERVICE_LIMIT = 80;

function truncate(value, max = 2048) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

async function runFixedCommand(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 3500,
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
      stdout: truncate(error?.stdout ?? ""),
      stderr: truncate(error?.stderr ?? ""),
      command: { argv, read_only: true },
    };
  }
}

function boundedLimit(limit) {
  return Math.min(Math.max(Number(limit) || DEFAULT_SERVICE_LIMIT, 1), 200);
}

function stripSystemctlBullet(line) {
  return line.replace(/^●\s*/, "").trim();
}

export function parseSystemctlListUnits(stdout) {
  const services = [];
  for (const rawLine of stdout.split("\n")) {
    const line = stripSystemctlBullet(rawLine);
    if (!line) continue;
    if (/^UNIT\s+LOAD\s+ACTIVE\s+SUB\s+DESCRIPTION/i.test(line)) continue;
    if (/^(LOAD|ACTIVE|SUB)\s+=/i.test(line)) continue;
    if (/loaded units listed/i.test(line)) continue;

    const match = line.match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$/);
    if (!match) continue;
    const [, unit, load, active, sub, description] = match;
    if (!unit.endsWith(".service")) continue;
    services.push({
      name: unit,
      load,
      active,
      sub,
      description: description || undefined,
      failed: active === "failed" || sub === "failed",
      running: active === "active" && sub === "running",
      restarting: active === "activating" || sub.includes("auto-restart") || sub === "start-pre" || sub === "start-post",
    });
  }
  return services;
}

export function parseLaunchctlList(stdout) {
  const services = [];
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim();
    if (!line || /^PID\s+Status\s+Label$/i.test(line)) continue;
    const match = line.match(/^(\S+)\s+(-?\d+)\s+(.+)$/);
    if (!match) continue;
    const [, pidText, statusText, label] = match;
    const pid = pidText === "-" ? null : Number(pidText);
    const lastExitStatus = Number(statusText);
    services.push({
      label,
      pid,
      last_exit_status: lastExitStatus,
      state: pid === null ? "not_running" : "running",
      nonzero_exit: lastExitStatus !== 0,
    });
  }
  return services;
}

export function summarizeSystemdServices(services, { limit = DEFAULT_SERVICE_LIMIT } = {}) {
  const bounded = boundedLimit(limit);
  const failedServices = services.filter((service) => service.failed);
  const restartingServices = services.filter((service) => service.restarting);
  return {
    manager: "systemd",
    total_count: services.length,
    running_count: services.filter((service) => service.running).length,
    failed_count: failedServices.length,
    restarting_count: restartingServices.length,
    exited_count: services.filter((service) => service.active === "active" && service.sub === "exited").length,
    inactive_count: services.filter((service) => service.active === "inactive").length,
    failed_services: failedServices.slice(0, bounded),
    restarting_services: restartingServices.slice(0, bounded),
  };
}

export function summarizeLaunchdServices(services, { limit = DEFAULT_SERVICE_LIMIT } = {}) {
  const bounded = boundedLimit(limit);
  const nonzeroExitServices = services.filter((service) => service.nonzero_exit);
  return {
    manager: "launchd",
    total_count: services.length,
    running_count: services.filter((service) => service.state === "running").length,
    not_running_count: services.filter((service) => service.state === "not_running").length,
    nonzero_exit_count: nonzeroExitServices.length,
    nonzero_exit_services: nonzeroExitServices.slice(0, bounded),
  };
}

async function collectSystemdServices(limit) {
  const command = await runFixedCommand("systemctl", [
    "list-units",
    "--type=service",
    "--all",
    "--no-pager",
    "--no-legend",
  ]);
  if (command.status !== "ok") {
    return {
      platform: process.platform,
      manager: "systemd",
      status: "unable",
      summary: summarizeSystemdServices([], { limit }),
      services: [],
      truncated: false,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }

  const services = parseSystemctlListUnits(command.stdout);
  const summary = summarizeSystemdServices(services, { limit });
  return {
    platform: process.platform,
    manager: "systemd",
    status: "ok",
    summary,
    services: services.slice(0, limit),
    truncated: services.length > limit,
    command: command.command,
    stderr: command.stderr,
  };
}

async function collectLaunchdServices(limit) {
  const command = await runFixedCommand("launchctl", ["list"]);
  if (command.status !== "ok") {
    return {
      platform: process.platform,
      manager: "launchd",
      status: "unable",
      summary: summarizeLaunchdServices([], { limit }),
      services: [],
      truncated: false,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }

  const services = parseLaunchctlList(command.stdout);
  const summary = summarizeLaunchdServices(services, { limit });
  return {
    platform: process.platform,
    manager: "launchd",
    status: "ok",
    summary,
    services: services.slice(0, limit),
    truncated: services.length > limit,
    command: command.command,
    stderr: command.stderr,
  };
}

function envelopeStatus(result) {
  if (result.status === "unsupported") return "unknown";
  if (result.status !== "ok") return "unable";
  if (result.manager === "systemd" && (result.summary?.failed_count > 0 || result.summary?.restarting_count > 0)) return "warning";
  return "ok";
}

function reviewHint(result) {
  const status = envelopeStatus(result);
  if (status === "warning") return "threshold_crossed";
  if (status === "unable") return "missing_permission";
  if (status === "unknown") return "ambiguous";
  if (result.manager === "launchd" && result.summary?.nonzero_exit_count > 0) return "ambiguous";
  return "none";
}

export async function collectServiceEvidence({ serviceLimit = DEFAULT_SERVICE_LIMIT } = {}) {
  const limit = boundedLimit(serviceLimit);
  return timedEnvelope(async () => {
    if (process.platform === "linux") return collectSystemdServices(limit);
    if (process.platform === "darwin") return collectLaunchdServices(limit);
    return {
      platform: process.platform,
      manager: "unsupported",
      status: "unsupported",
      summary: {},
      services: [],
      truncated: false,
      error: `unsupported platform: ${process.platform}`,
    };
  }, (result) => evidenceEnvelope({
    id: "services",
    status: envelopeStatus(result),
    source: result?.manager === "systemd" ? "systemd" : result?.manager === "launchd" ? "launchd" : "service_manager",
    result,
    confidence: result?.status === "ok" ? 1 : 0.35,
    reviewHint: reviewHint(result),
    tool: "collect_services",
    target: `limit=${limit}`,
  }));
}
