import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 3500;

function truncate(value, max = 2048) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function clampBoolean(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  return Boolean(value);
}

function boundedString(value, max = 240) {
  if (value === undefined || value === null || value === "") return undefined;
  return truncate(String(value), max);
}

export function validateNtpServer(value) {
  const server = boundedString(value, 253);
  if (server === undefined) return { server: undefined };
  if (server.startsWith("-")) return { server: undefined, error: "NTP server must not start with '-'" };
  if (/\s/.test(server)) return { server: undefined, error: "NTP server must not contain whitespace" };
  if (server.includes("/") || server.includes("\\")) return { server: undefined, error: "NTP server must be a hostname or IP address, not a path" };
  if (!/^[A-Za-z0-9.:-]+$/.test(server)) return { server: undefined, error: "NTP server contains unsupported characters" };
  return { server };
}

export function normalizeTimeSyncRequest(options = {}) {
  const server = validateNtpServer(options.server);
  return {
    check_offset: clampBoolean(options.checkOffset ?? options.check_offset, false),
    ...(server.server !== undefined ? { server: server.server } : {}),
    ...(server.error !== undefined ? { server_error: server.error } : {}),
  };
}

async function runFixedCommand(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? DEFAULT_TIMEOUT_MS,
      maxBuffer: options.maxBuffer ?? 512 * 1024,
    });
    return {
      status: "ok",
      stdout,
      stderr: truncate(stderr),
      command: { argv, read_only: true, network: options.network ?? false },
    };
  } catch (error) {
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      stdout: truncate(error?.stdout ?? "", 4096),
      stderr: truncate(error?.stderr ?? "", 2048),
      command: { argv, read_only: true, network: options.network ?? false },
    };
  }
}

function parseBool(value) {
  const text = String(value ?? "").trim().toLowerCase();
  if (["yes", "true", "1", "active", "enabled", "on"].includes(text)) return true;
  if (["no", "false", "0", "inactive", "disabled", "off"].includes(text)) return false;
  return undefined;
}

export function parseTimedatectlShow(stdout) {
  const result = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || !line.includes("=")) continue;
    const [key, ...rest] = line.split("=");
    const value = rest.join("=").trim();
    if (key === "Timezone") result.timezone = value || undefined;
    if (key === "LocalRTC") result.local_rtc = parseBool(value);
    if (key === "NTP") result.ntp_enabled = parseBool(value);
    if (key === "CanNTP") result.can_ntp = parseBool(value);
    if (key === "NTPSynchronized") result.synchronized = parseBool(value);
    if (key === "TimeUSec") result.time_usec = value || undefined;
    if (key === "RTCTimeUSec") result.rtc_time_usec = value || undefined;
  }
  return result;
}

export function parseTimedatectlStatus(stdout) {
  const result = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    const [rawKey, ...rest] = line.split(":");
    if (!rawKey || rest.length === 0) continue;
    const key = rawKey.trim().toLowerCase();
    const value = rest.join(":").trim();
    if (key === "time zone") result.timezone = value || undefined;
    if (key === "system clock synchronized") result.synchronized = parseBool(value);
    if (key === "ntp service") result.ntp_service_active = parseBool(value);
    if (key === "rtc in local tz") result.local_rtc = parseBool(value);
  }
  return result;
}

export function parseChronycTracking(stdout) {
  const result = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    const [rawKey, ...rest] = line.split(":");
    if (!rawKey || rest.length === 0) continue;
    const key = rawKey.trim().toLowerCase();
    const value = rest.join(":").trim();
    if (key === "reference id") result.reference_id = value || undefined;
    if (key === "stratum") {
      const number = Number(value);
      if (Number.isFinite(number)) result.stratum = number;
    }
    if (key === "ref time (utc)") result.reference_time_utc = value || undefined;
    if (key === "system time") {
      const match = value.match(/^([0-9.]+)\s+seconds\s+(fast|slow)\s+of\s+NTP\s+time/i);
      if (match) {
        const offset = Number(match[1]);
        if (Number.isFinite(offset)) result.system_time_offset_seconds = match[2].toLowerCase() === "slow" ? -offset : offset;
      }
    }
    if (key === "last offset" || key === "rms offset") {
      const match = value.match(/^([-+0-9.]+)\s+seconds/i);
      const number = match ? Number(match[1]) : undefined;
      if (Number.isFinite(number)) result[key === "last offset" ? "last_offset_seconds" : "rms_offset_seconds"] = number;
    }
    if (key === "leap status") result.leap_status = value || undefined;
  }
  return result;
}

export function parseNtpqPeers(stdout) {
  const peers = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || /^remote\s+refid\s+st\s+t\s+when\s+poll\s+reach\s+delay\s+offset\s+jitter/i.test(line)) continue;
    if (/^=+$/.test(line.replace(/\s+/g, ""))) continue;
    const match = line.match(/^([*+#ox.-]?)(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([-+0-9.]+)\s+([-+0-9.]+)\s+([-+0-9.]+)/);
    if (!match) continue;
    const [, marker, remote, refid, stratum, type, when, poll, reach, delay, offset, jitter] = match;
    peers.push({
      selected: marker === "*",
      tally: marker || undefined,
      remote,
      refid,
      stratum: Number(stratum),
      type,
      when,
      poll_seconds: Number(poll),
      reach,
      delay_ms: Number(delay),
      offset_ms: Number(offset),
      jitter_ms: Number(jitter),
    });
  }
  return peers;
}

function systemsetupNeedsAdmin(commandResult) {
  return /need administrator access/i.test(`${commandResult.stdout}\n${commandResult.stderr}\n${commandResult.error ?? ""}`);
}

function normalizeSystemsetupResult(commandResult) {
  if (!systemsetupNeedsAdmin(commandResult)) return commandResult;
  return {
    ...commandResult,
    status: "unable",
    error: "systemsetup requires administrator access for this read-only query",
  };
}

export function parseMacSystemsetup(stdout) {
  const result = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    const networkTime = line.match(/^Network Time:\s*(.+)$/i);
    if (networkTime) result.network_time_enabled = parseBool(networkTime[1]);
    const server = line.match(/^Network Time Server:\s*(.+)$/i);
    if (server) result.network_time_server = server[1].trim() || undefined;
  }
  return result;
}

export function parseLaunchctlPrintService(stdout) {
  const result = {};
  const text = String(stdout ?? "");
  const state = text.match(/\bstate\s*=\s*(\S+)/);
  if (state) result.state = state[1];
  const pid = text.match(/\bpid\s*=\s*(\d+)/);
  if (pid) result.pid = Number(pid[1]);
  const lastExit = text.match(/last exit code\s*=\s*([^\n]+)/i);
  if (lastExit) result.last_exit_code = lastExit[1].trim();
  result.running = result.state === "running" || Number.isFinite(result.pid);
  return result;
}

export function parseSntpOutput(stdout) {
  const line = String(stdout ?? "").trim().split("\n").find(Boolean);
  if (!line) return {};
  const match = line.match(/^([-+0-9.]+)\s+\+\/[-+]\s*([0-9.]+)\s+(\S+)(?:\s+(\S+))?/);
  if (!match) return { raw: truncate(line, 500) };
  return {
    offset_seconds: Number(match[1]),
    uncertainty_seconds: Number(match[2]),
    server: match[3],
    address: match[4],
  };
}

async function collectLinuxTimeSync(request) {
  const probes = [];
  const result = { platform: process.platform };

  const show = await runFixedCommand("timedatectl", [
    "show",
    "--property=Timezone",
    "--property=LocalRTC",
    "--property=NTP",
    "--property=CanNTP",
    "--property=NTPSynchronized",
    "--property=TimeUSec",
    "--property=RTCTimeUSec",
  ]);
  const showParsed = show.status === "ok" ? parseTimedatectlShow(show.stdout) : {};
  if (show.status === "ok") Object.assign(result, showParsed);
  probes.push({ source: "timedatectl_show", status: show.status, command: show.command, stderr: show.stderr, error: show.error, parsed: showParsed });

  const status = await runFixedCommand("timedatectl", ["status", "--no-pager"]);
  const statusParsed = status.status === "ok" ? parseTimedatectlStatus(status.stdout) : {};
  if (status.status === "ok") Object.assign(result, statusParsed);
  probes.push({ source: "timedatectl_status", status: status.status, command: status.command, stderr: status.stderr, error: status.error, parsed: statusParsed });

  const chrony = await runFixedCommand("chronyc", ["tracking"]);
  const chronyParsed = chrony.status === "ok" ? parseChronycTracking(chrony.stdout) : {};
  if (chrony.status === "ok") result.chrony = chronyParsed;
  probes.push({ source: "chronyc_tracking", status: chrony.status, optional: true, command: chrony.command, stderr: chrony.stderr, error: chrony.error, parsed: chronyParsed });

  const ntpq = await runFixedCommand("ntpq", ["-pn"]);
  const peers = ntpq.status === "ok" ? parseNtpqPeers(ntpq.stdout) : [];
  if (ntpq.status === "ok") result.ntpq = { peers: peers.slice(0, 20), selected_peer: peers.find((peer) => peer.selected) };
  probes.push({ source: "ntpq_peers", status: ntpq.status, optional: true, command: ntpq.command, stderr: ntpq.stderr, error: ntpq.error, result_count: peers.length });

  if (request.check_offset) {
    if (request.server_error) {
      probes.push({ source: "sntp_offset", status: "unable", optional: true, error: request.server_error, parsed: {} });
    } else {
      const server = request.server ?? "pool.ntp.org";
      const sntp = await runFixedCommand("sntp", ["-t", "2", server], { timeout: 4000, network: true });
      const sntpParsed = sntp.status === "ok" ? parseSntpOutput(sntp.stdout) : {};
      if (sntp.status === "ok") result.sntp_offset = sntpParsed;
      probes.push({ source: "sntp_offset", status: sntp.status, optional: true, command: sntp.command, stderr: sntp.stderr, error: sntp.error, parsed: sntpParsed });
    }
  }

  return { result, probes };
}

async function collectMacTimeSync(request) {
  const probes = [];
  const result = { platform: process.platform };

  const launchctl = await runFixedCommand("launchctl", ["print", "system/com.apple.timed"]);
  const launchctlParsed = launchctl.status === "ok" ? parseLaunchctlPrintService(launchctl.stdout) : {};
  if (launchctl.status === "ok") result.timed_service = launchctlParsed;
  probes.push({ source: "launchctl_timed", status: launchctl.status, command: launchctl.command, stderr: launchctl.stderr, error: launchctl.error, parsed: launchctlParsed });

  const usingNetworkTime = normalizeSystemsetupResult(await runFixedCommand("/usr/sbin/systemsetup", ["-getusingnetworktime"]));
  const networkServer = normalizeSystemsetupResult(await runFixedCommand("/usr/sbin/systemsetup", ["-getnetworktimeserver"]));
  const systemsetupParsed = parseMacSystemsetup(`${usingNetworkTime.stdout}\n${networkServer.stdout}`);
  if (Object.keys(systemsetupParsed).length > 0) Object.assign(result, systemsetupParsed);
  probes.push({ source: "systemsetup_network_time", status: usingNetworkTime.status, command: usingNetworkTime.command, stderr: usingNetworkTime.stderr, error: usingNetworkTime.error, parsed: parseMacSystemsetup(usingNetworkTime.stdout) });
  probes.push({ source: "systemsetup_network_server", status: networkServer.status, command: networkServer.command, stderr: networkServer.stderr, error: networkServer.error, parsed: parseMacSystemsetup(networkServer.stdout) });

  if (request.check_offset) {
    if (request.server_error) {
      probes.push({ source: "sntp_offset", status: "unable", optional: true, error: request.server_error, parsed: {} });
    } else {
      const server = request.server ?? result.network_time_server ?? "time.apple.com";
      const sntp = await runFixedCommand("sntp", ["-t", "2", server], { timeout: 4000, network: true });
      const sntpParsed = sntp.status === "ok" ? parseSntpOutput(sntp.stdout) : {};
      if (sntp.status === "ok") result.sntp_offset = sntpParsed;
      probes.push({ source: "sntp_offset", status: sntp.status, optional: true, command: sntp.command, stderr: sntp.stderr, error: sntp.error, parsed: sntpParsed });
    }
  }

  return { result, probes };
}

export function summarizeTimeSync(result, probes) {
  const selectedNtpqOffset = result.ntpq?.selected_peer?.offset_ms;
  const offsetSeconds = result.chrony?.system_time_offset_seconds
    ?? result.sntp_offset?.offset_seconds
    ?? (Number.isFinite(selectedNtpqOffset) ? selectedNtpqOffset / 1000 : undefined);
  const synchronized = result.synchronized;
  const ntpEnabled = result.ntp_enabled ?? result.network_time_enabled ?? result.ntp_service_active;
  return {
    synchronized,
    ntp_enabled: ntpEnabled,
    timezone: result.timezone,
    local_rtc: result.local_rtc,
    time_service_running: result.timed_service?.running,
    offset_seconds: offsetSeconds,
    offset_source: result.chrony?.system_time_offset_seconds !== undefined ? "chronyc_tracking"
      : result.sntp_offset?.offset_seconds !== undefined ? "sntp_offset"
      : Number.isFinite(selectedNtpqOffset) ? "ntpq_selected_peer"
      : undefined,
    required_unavailable_count: probes.filter((probe) => probe.status === "unable" && !probe.optional).length,
    optional_unavailable_count: probes.filter((probe) => probe.status === "unable" && probe.optional).length,
  };
}

function overallStatus(summary, probes) {
  if (probes.some((probe) => probe.status === "ok" && !probe.optional)) return "ok";
  if (probes.some((probe) => probe.status === "ok")) return "ok";
  if (probes.some((probe) => probe.status === "unable")) return "unable";
  return "unsupported";
}

function envelopeStatus(result) {
  if (result.status === "unsupported") return "unknown";
  if (result.status === "unable") return "unable";
  if (result.summary?.synchronized === false || result.summary?.ntp_enabled === false) return "warning";
  const offset = Math.abs(Number(result.summary?.offset_seconds));
  if (Number.isFinite(offset) && offset >= 1) return "warning";
  return "ok";
}

function reviewHint(result) {
  const status = envelopeStatus(result);
  if (status === "warning") return "threshold_crossed";
  if (status === "unable") return "missing_permission";
  if (status === "unknown") return "ambiguous";
  return "none";
}

export async function collectTimeSyncEvidence(options = {}) {
  const request = normalizeTimeSyncRequest(options);
  return timedEnvelope(async () => {
    let collected;
    if (process.platform === "linux") collected = await collectLinuxTimeSync(request);
    else if (process.platform === "darwin") collected = await collectMacTimeSync(request);
    else collected = {
      result: { platform: process.platform },
      probes: [{ source: "platform_time_sync", status: "unsupported", error: `unsupported platform: ${process.platform}` }],
    };

    const summary = summarizeTimeSync(collected.result, collected.probes);
    const status = overallStatus(summary, collected.probes);
    return {
      platform: process.platform,
      status,
      request,
      summary,
      ...collected.result,
      probes: collected.probes,
      note: request.check_offset
        ? "Time sync evidence is read-only and bounded; offset checks may contact the requested/default NTP server."
        : "Time sync evidence is read-only and bounded; no direct external NTP offset check was requested.",
    };
  }, (result) => evidenceEnvelope({
    id: "time-sync",
    status: envelopeStatus(result),
    source: "time_sync",
    result,
    confidence: result?.status === "ok" ? 0.85 : 0.35,
    reviewHint: reviewHint(result),
    tool: "collect_time_sync",
    target: `check_offset=${request.check_offset}${request.server ? `;server=${request.server}` : ""}`,
  }));
}
