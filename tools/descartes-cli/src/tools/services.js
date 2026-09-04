import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DEFAULT_SERVICE_LIMIT = 80;

// F3 fix (2026-09-04): the 80-item PRESENTATION limit above must never gate what the
// service-census/baseline machinery sees -- a >80-service host would otherwise have its
// service-appearance/disappearance baseline permanently stuck at censusState:"partial"
// (service-baseline.js's completeGroups filter never populates -> establishment gate never
// fires; see docs findings for F3). This is a SEPARATE, much larger AUTHORITATIVE sanity
// ceiling: it bounds the full census array returned alongside the presentation-bounded
// `services` field, and only a genuinely pathological over-enumeration (well beyond any
// plausible real host inventory) should ever hit it and flip `truncated:true`. This function
// itself always populates `services_census` (collector-level, platform-agnostic); it is
// pi-harness.js's on-demand collect_services tool that explicitly strips it back out of its
// tool result before the model ever sees it (v1: presentation limit only there) -- this
// remains purely a structural-tick/daemon-path field otherwise.
//
// Sizing: chosen conservatively against fact-store.js's shared DEFAULT_FACT_MAX_BYTES (5MB,
// cross-family) -- up to 1000 service.presence facts/tick at ~150-250 bytes/record is a
// real (~150-250KB/tick) but bounded slice of that shared budget, versus 2000 which would
// roughly double the pressure on sibling fact families' retention window for comparatively
// little extra real-world headroom (real hosts, even large ones, very rarely exceed a few
// hundred loaded service units). 1000 is still >12x the old 80 cap.
export const DEFAULT_SERVICE_CENSUS_CEILING = 1000;
// Hard upper clamp so the authoritative array can never become literally unbounded even if a
// future caller raises censusCeiling far beyond the sane default (fail-closed backstop for a
// pathological host, per the fix-spec's "must not become literally unbounded" requirement).
const MAX_SERVICE_CENSUS_CEILING = 5000;

function boundedCensusCeiling(value, presentationLimit) {
  const numeric = Number(value);
  const base = Number.isFinite(numeric) && numeric > 0 ? numeric : DEFAULT_SERVICE_CENSUS_CEILING;
  return Math.min(Math.max(base, presentationLimit), MAX_SERVICE_CENSUS_CEILING);
}

// Lighter {identity, running/state} projections for the authoritative census array, so a
// large real inventory doesn't balloon evidence-envelope size with per-unit `description`/
// `load`/`active`/`sub`/`pid`/`last_exit_status` fields that factPointsFromServiceEvidence
// never reads. Field names match what services[] already carries per-manager so downstream
// consumers (fact-translators.js) branch identically on manager without a shape change.
function projectSystemdIdentity(service) {
  return { name: service.name, running: service.running };
}

function projectLaunchdIdentity(service) {
  return { label: service.label, state: service.state };
}

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

export async function collectSystemdServices(limit, censusCeiling, runCommand) {
  const command = await runCommand("systemctl", [
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
      services_census: [],
      truncated: false,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }

  const services = parseSystemctlListUnits(command.stdout);
  const summary = summarizeSystemdServices(services, { limit });
  const truncated = services.length > censusCeiling;
  if (truncated) {
    // Never a silent cap: a host genuinely exceeding the authoritative sanity ceiling is a
    // pathological-enumeration signal worth an operator's attention immediately, not only
    // discoverable later via census_state:"partial" in fact history.
    console.warn(
      `descartes: services collector (systemd) truncated at the authoritative census sanity ceiling (${censusCeiling}); host reports ${services.length} service units -- investigate before trusting the service baseline`,
    );
  }
  return {
    platform: process.platform,
    manager: "systemd",
    status: "ok",
    summary,
    services: services.slice(0, limit),
    services_census: services.slice(0, censusCeiling).map(projectSystemdIdentity),
    truncated,
    command: command.command,
    stderr: command.stderr,
  };
}

export async function collectLaunchdServices(limit, censusCeiling, runCommand) {
  const command = await runCommand("launchctl", ["list"]);
  if (command.status !== "ok") {
    return {
      platform: process.platform,
      manager: "launchd",
      status: "unable",
      summary: summarizeLaunchdServices([], { limit }),
      services: [],
      services_census: [],
      truncated: false,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }

  const services = parseLaunchctlList(command.stdout);
  const summary = summarizeLaunchdServices(services, { limit });
  const truncated = services.length > censusCeiling;
  if (truncated) {
    console.warn(
      `descartes: services collector (launchd) truncated at the authoritative census sanity ceiling (${censusCeiling}); host reports ${services.length} jobs -- investigate before trusting the service baseline`,
    );
  }
  return {
    platform: process.platform,
    manager: "launchd",
    status: "ok",
    summary,
    services: services.slice(0, limit),
    services_census: services.slice(0, censusCeiling).map(projectLaunchdIdentity),
    truncated,
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

export async function collectServiceEvidence({
  serviceLimit = DEFAULT_SERVICE_LIMIT,
  censusCeiling = DEFAULT_SERVICE_CENSUS_CEILING,
  // Test-only dependency injection point (mirrors tools/tailscale-status.js's
  // runFixedExecFile pattern) -- production callers (daemon.js, pi-harness.js) never pass
  // this, so they always get the real execFile-backed runFixedCommand.
  runFixedCommand: injectedRunFixedCommand = runFixedCommand,
} = {}) {
  const limit = boundedLimit(serviceLimit);
  const ceiling = boundedCensusCeiling(censusCeiling, limit);
  return timedEnvelope(async () => {
    if (process.platform === "linux") return collectSystemdServices(limit, ceiling, injectedRunFixedCommand);
    if (process.platform === "darwin") return collectLaunchdServices(limit, ceiling, injectedRunFixedCommand);
    return {
      platform: process.platform,
      manager: "unsupported",
      status: "unsupported",
      summary: {},
      services: [],
      services_census: [],
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
