import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, lstat, open, readdir, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { redactAndBoundProcessArgs } from "./processes.js";

const execFileAsync = promisify(execFile);
const DEFAULT_JOB_LIMIT = 80;
export const MAX_CRON_FILE_BYTES = 128 * 1024;
const MAX_LAUNCHD_PLIST_CANDIDATES = 500;

function clampNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.floor(number), min), max);
}

export function normalizeScheduledJobsRequest(options = {}) {
  return {
    job_limit: clampNumber(options.jobLimit ?? options.job_limit, DEFAULT_JOB_LIMIT, 1, 200),
    include_system: options.includeSystem ?? options.include_system ?? true,
    include_user: options.includeUser ?? options.include_user ?? true,
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
      code: error?.code,
      stdout: truncate(error?.stdout ?? "", 4096),
      stderr: truncate(error?.stderr ?? "", 2048),
      command: { argv, read_only: true },
    };
  }
}

async function pathExists(filePath) {
  try {
    await access(filePath, fsConstants.R_OK);
    return true;
  } catch {
    try {
      await access(filePath, fsConstants.F_OK);
      return true;
    } catch {
      return false;
    }
  }
}

function boundedCommand(command) {
  const redacted = redactAndBoundProcessArgs(command, { maxLength: 260, maxTokenLength: 96 });
  return {
    command: redacted.value,
    command_redaction: {
      redacted: redacted.redacted,
      truncated: redacted.truncated,
      original_length: redacted.original_length,
      max_length: redacted.max_length,
    },
  };
}

function cronLineWithoutInlineComment(line) {
  let escaped = false;
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if ((char === '"' || char === "'") && !quote) {
      quote = char;
      continue;
    }
    if (char === quote) {
      quote = null;
      continue;
    }
    if (char === "#" && !quote && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i).trimEnd();
  }
  return line.trimEnd();
}

function isCronEnvironmentLine(line) {
  return /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line);
}

function parseCronScheduleLine(line, { source, path: sourcePath, lineNumber, hasUserField }) {
  const clean = cronLineWithoutInlineComment(line).trim();
  if (!clean || clean.startsWith("#") || isCronEnvironmentLine(clean)) return undefined;

  const parts = clean.split(/\s+/);
  if (parts.length === 0) return undefined;

  let schedule;
  let user;
  let commandParts;

  if (parts[0].startsWith("@")) {
    schedule = parts[0];
    if (hasUserField) {
      if (parts.length < 3) return undefined;
      user = parts[1];
      commandParts = parts.slice(2);
    } else {
      if (parts.length < 2) return undefined;
      commandParts = parts.slice(1);
    }
  } else {
    if (parts.length < (hasUserField ? 7 : 6)) return undefined;
    schedule = parts.slice(0, 5).join(" ");
    if (hasUserField) {
      user = parts[5];
      commandParts = parts.slice(6);
    } else {
      commandParts = parts.slice(5);
    }
  }

  const commandText = commandParts.join(" ");
  if (!commandText) return undefined;
  const command = boundedCommand(commandText);
  return {
    kind: "cron",
    source,
    path: sourcePath,
    line_number: lineNumber,
    schedule,
    user,
    ...command,
  };
}

export function parseCronContent(content, options = {}) {
  const jobs = [];
  const lines = String(content ?? "").split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const job = parseCronScheduleLine(lines[index], {
      source: options.source ?? "cron",
      path: options.path,
      lineNumber: index + 1,
      hasUserField: options.hasUserField ?? false,
    });
    if (job) jobs.push(job);
  }
  return jobs;
}

export function parseSystemctlListTimers(stdout, { scope = "system" } = {}) {
  const timers = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.replace(/^●\s*/, "").trim();
    if (!line) continue;
    if (/^NEXT\s+LEFT\s+LAST\s+PASSED\s+UNIT\s+ACTIVATES/i.test(line)) continue;
    if (/^\d+\s+timers?\s+listed/i.test(line)) continue;
    if (/^Pass --all to see loaded but inactive timers/i.test(line)) continue;

    const parts = line.split(/\s+/);
    const unitIndex = parts.findIndex((part) => part.endsWith(".timer"));
    if (unitIndex === -1) continue;
    const unit = parts[unitIndex];
    const activates = parts[unitIndex + 1];
    timers.push({
      kind: "systemd_timer",
      source: scope === "user" ? "systemd_user_timers" : "systemd_timers",
      scope,
      unit,
      activates,
      timing: parts.slice(0, unitIndex).join(" ") || undefined,
      raw: truncate(line, 500),
    });
  }
  return timers;
}

function normalizeCalendarInterval(value) {
  if (value === undefined || value === null) return undefined;
  const intervals = Array.isArray(value) ? value : [value];
  return intervals.map((item) => {
    if (!item || typeof item !== "object") return item;
    return Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)));
  });
}

function programSummary(plist) {
  if (typeof plist.Program === "string") return boundedCommand(plist.Program);
  if (Array.isArray(plist.ProgramArguments) && plist.ProgramArguments.length > 0) return boundedCommand(plist.ProgramArguments.join(" "));
  return undefined;
}

export function parseLaunchdPlistObject(plist, { path: plistPath, scope = "system" } = {}) {
  if (!plist || typeof plist !== "object") return undefined;
  const hasStartInterval = plist.StartInterval !== undefined && plist.StartInterval !== null;
  const hasCalendarInterval = plist.StartCalendarInterval !== undefined && plist.StartCalendarInterval !== null;
  if (!hasStartInterval && !hasCalendarInterval) return undefined;

  const program = programSummary(plist);
  return {
    kind: "launchd_scheduled_job",
    source: "launchd_plist",
    scope,
    label: typeof plist.Label === "string" ? plist.Label : path.basename(plistPath ?? "unknown", ".plist"),
    path: plistPath,
    start_interval_seconds: typeof plist.StartInterval === "number" ? plist.StartInterval : undefined,
    start_calendar_interval: normalizeCalendarInterval(plist.StartCalendarInterval),
    run_at_load: plist.RunAtLoad === true,
    ...(program ?? {}),
  };
}

async function readBoundedRegularFile(filePath) {
  const stats = await lstat(filePath);
  if (!stats.isFile()) {
    return { status: "unable", error: "not a regular file", content: "", truncated: false, size_bytes: stats.size };
  }
  if (stats.size <= MAX_CRON_FILE_BYTES) {
    return { status: "ok", content: await readFile(filePath, { encoding: "utf8" }), truncated: false, size_bytes: stats.size };
  }

  const handle = await open(filePath, "r");
  try {
    const buffer = Buffer.alloc(MAX_CRON_FILE_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, MAX_CRON_FILE_BYTES, 0);
    return {
      status: "ok",
      content: buffer.subarray(0, bytesRead).toString("utf8"),
      truncated: true,
      size_bytes: stats.size,
    };
  } finally {
    await handle.close();
  }
}

export async function readCronFile(filePath, options = {}) {
  try {
    const file = await readBoundedRegularFile(filePath);
    if (file.status !== "ok") {
      return { status: file.status, path: filePath, error: file.error, size_bytes: file.size_bytes, jobs: [] };
    }
    return {
      status: "ok",
      path: filePath,
      truncated: file.truncated,
      size_bytes: file.size_bytes,
      jobs: parseCronContent(file.content, options),
    };
  } catch (error) {
    if (error?.code === "ENOENT") return { status: "absent", path: filePath, jobs: [] };
    return {
      status: "unable",
      path: filePath,
      error: error instanceof Error ? error.message : String(error),
      jobs: [],
    };
  }
}

async function listCronDirectory(directory, { source, schedule, limit }) {
  if (!(await pathExists(directory))) return { status: "absent", path: directory, jobs: [] };
  try {
    const entries = (await readdir(directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && !entry.name.startsWith("."))
      .map((entry) => entry.name)
      .sort();
    const jobs = entries.slice(0, limit).map((name) => ({
      kind: "periodic_directory_entry",
      source,
      path: path.join(directory, name),
      schedule,
      command: path.join(directory, name),
      command_redaction: { redacted: false, truncated: false, original_length: path.join(directory, name).length, max_length: 260 },
    }));
    return { status: "ok", path: directory, truncated: entries.length > limit, jobs };
  } catch (error) {
    return { status: "unable", path: directory, error: error instanceof Error ? error.message : String(error), jobs: [] };
  }
}

async function collectCronJobs({ limit, includeSystem, includeUser }) {
  const probes = [];
  const jobs = [];

  if (includeUser) {
    const userCrontab = await runFixedCommand("crontab", ["-l"]);
    const noCrontab = userCrontab.status !== "ok" && /no crontab/i.test(`${userCrontab.stderr}\n${userCrontab.stdout}\n${userCrontab.error ?? ""}`);
    const parsedJobs = userCrontab.status === "ok"
      ? parseCronContent(userCrontab.stdout, { source: "user_crontab", path: "crontab -l", hasUserField: false })
      : [];
    jobs.push(...parsedJobs);
    probes.push({
      source: "user_crontab",
      status: noCrontab ? "absent" : userCrontab.status,
      command: userCrontab.command,
      stderr: userCrontab.stderr,
      error: noCrontab ? undefined : userCrontab.error,
      job_count: parsedJobs.length,
    });
  }

  if (includeSystem) {
    const systemCrontab = await readCronFile("/etc/crontab", { source: "system_crontab", path: "/etc/crontab", hasUserField: true });
    jobs.push(...systemCrontab.jobs);
    probes.push({ source: "system_crontab", ...systemCrontab, jobs: undefined, job_count: systemCrontab.jobs.length });

    if (await pathExists("/etc/cron.d")) {
      try {
        const files = (await readdir("/etc/cron.d", { withFileTypes: true }))
          .filter((entry) => entry.isFile() && !entry.name.startsWith("."))
          .map((entry) => path.join("/etc/cron.d", entry.name))
          .sort()
          .slice(0, limit);
        let truncated = false;
        for (const filePath of files) {
          const file = await readCronFile(filePath, { source: "cron_d", path: filePath, hasUserField: true });
          jobs.push(...file.jobs);
          probes.push({ source: "cron_d", ...file, jobs: undefined, job_count: file.jobs.length });
        }
        const allEntries = await readdir("/etc/cron.d", { withFileTypes: true });
        truncated = allEntries.filter((entry) => entry.isFile() && !entry.name.startsWith(".")).length > files.length;
        if (truncated) probes.push({ source: "cron_d", status: "truncated", path: "/etc/cron.d", job_count: 0 });
      } catch (error) {
        probes.push({ source: "cron_d", status: "unable", path: "/etc/cron.d", error: error instanceof Error ? error.message : String(error), job_count: 0 });
      }
    } else {
      probes.push({ source: "cron_d", status: "absent", path: "/etc/cron.d", job_count: 0 });
    }

    const periodicDirs = [
      ["/etc/cron.hourly", "hourly"],
      ["/etc/cron.daily", "daily"],
      ["/etc/cron.weekly", "weekly"],
      ["/etc/cron.monthly", "monthly"],
      ["/etc/periodic/hourly", "hourly"],
      ["/etc/periodic/daily", "daily"],
      ["/etc/periodic/weekly", "weekly"],
      ["/etc/periodic/monthly", "monthly"],
    ];
    for (const [directory, schedule] of periodicDirs) {
      const probe = await listCronDirectory(directory, { source: "periodic_directory", schedule, limit });
      jobs.push(...probe.jobs);
      probes.push({ source: "periodic_directory", ...probe, jobs: undefined, job_count: probe.jobs.length });
    }
  }

  return { jobs, probes };
}

async function collectSystemdTimers({ limit, includeSystem, includeUser }) {
  const probes = [];
  const jobs = [];
  if (includeSystem) {
    const command = await runFixedCommand("systemctl", ["list-timers", "--all", "--no-pager", "--no-legend"]);
    const parsed = command.status === "ok" ? parseSystemctlListTimers(command.stdout, { scope: "system" }) : [];
    jobs.push(...parsed);
    probes.push({ source: "systemd_timers", status: command.status, command: command.command, stderr: command.stderr, error: command.error, job_count: parsed.length });
  }
  if (includeUser) {
    const command = await runFixedCommand("systemctl", ["--user", "list-timers", "--all", "--no-pager", "--no-legend"]);
    const parsed = command.status === "ok" ? parseSystemctlListTimers(command.stdout, { scope: "user" }) : [];
    jobs.push(...parsed);
    probes.push({ source: "systemd_user_timers", status: command.status, command: command.command, stderr: command.stderr, error: command.error, job_count: parsed.length });
  }
  return { jobs, probes };
}

async function listLaunchdPlists({ limit, includeSystem, includeUser }) {
  const directories = [];
  if (includeSystem) {
    directories.push(["/Library/LaunchAgents", "system"]);
    directories.push(["/Library/LaunchDaemons", "system"]);
  }
  if (includeUser) directories.push([path.join(os.homedir(), "Library/LaunchAgents"), "user"]);

  const files = [];
  const probes = [];
  for (const [directory, scope] of directories) {
    if (!(await pathExists(directory))) {
      probes.push({ source: "launchd_plist_directory", status: "absent", path: directory, job_count: 0 });
      continue;
    }
    try {
      const names = (await readdir(directory, { withFileTypes: true }))
        .filter((entry) => entry.isFile() && entry.name.endsWith(".plist"))
        .map((entry) => entry.name)
        .sort();
      const candidateLimit = Math.min(MAX_LAUNCHD_PLIST_CANDIDATES, Math.max(limit * 10, limit));
      files.push(...names.slice(0, candidateLimit).map((name) => ({ path: path.join(directory, name), scope })));
      probes.push({ source: "launchd_plist_directory", status: "ok", path: directory, truncated: names.length > candidateLimit, file_count: names.length, inspected_candidate_count: Math.min(names.length, candidateLimit), job_count: 0 });
    } catch (error) {
      probes.push({ source: "launchd_plist_directory", status: "unable", path: directory, error: error instanceof Error ? error.message : String(error), job_count: 0 });
    }
  }
  return { files: files.slice(0, MAX_LAUNCHD_PLIST_CANDIDATES), probes };
}

async function collectLaunchdScheduledJobs({ limit, includeSystem, includeUser }) {
  const { files, probes } = await listLaunchdPlists({ limit, includeSystem, includeUser });
  const jobs = [];
  for (const file of files) {
    const command = await runFixedCommand("plutil", ["-convert", "json", "-o", "-", file.path], { timeout: 2500 });
    if (command.status !== "ok") {
      probes.push({ source: "launchd_plist", status: "unable", path: file.path, command: command.command, stderr: command.stderr, error: command.error, job_count: 0 });
      continue;
    }
    try {
      const parsed = JSON.parse(command.stdout);
      const job = parseLaunchdPlistObject(parsed, { path: file.path, scope: file.scope });
      if (job) jobs.push(job);
      probes.push({ source: "launchd_plist", status: "ok", path: file.path, command: command.command, job_count: job ? 1 : 0 });
    } catch (error) {
      probes.push({ source: "launchd_plist", status: "unable", path: file.path, command: command.command, error: `invalid plist json: ${error instanceof Error ? error.message : String(error)}`, job_count: 0 });
    }
    if (jobs.length >= limit) break;
  }
  return { jobs, probes };
}

function countByKind(jobs) {
  return jobs.reduce((acc, job) => {
    acc[job.kind] = (acc[job.kind] ?? 0) + 1;
    return acc;
  }, {});
}

export function selectScheduledJobsFairly(jobs, limit) {
  const buckets = new Map();
  for (const job of jobs) {
    const key = `${job.source ?? "unknown"}:${job.kind ?? "unknown"}`;
    const bucket = buckets.get(key) ?? [];
    bucket.push(job);
    buckets.set(key, bucket);
  }

  const selected = [];
  const keys = [...buckets.keys()];
  while (selected.length < limit && keys.length > 0) {
    for (let index = 0; index < keys.length && selected.length < limit;) {
      const bucket = buckets.get(keys[index]);
      const next = bucket.shift();
      if (next) selected.push(next);
      if (bucket.length === 0) keys.splice(index, 1);
      else index += 1;
    }
  }
  return selected;
}

function summarizeScheduledJobs(returnedJobs, allJobs, probes, { limit }) {
  const unavailableSources = probes.filter((probe) => probe.status === "unable").map((probe) => ({
    source: probe.source,
    path: probe.path,
    command: probe.command,
    error: probe.error,
    stderr: probe.stderr,
  })).slice(0, limit);
  return {
    total_count: allJobs.length,
    returned_count: returnedJobs.length,
    by_kind: countByKind(allJobs),
    returned_by_kind: countByKind(returnedJobs),
    unavailable_count: probes.filter((probe) => probe.status === "unable").length,
    unavailable_sources: unavailableSources,
  };
}

function overallProbeStatus(probes) {
  if (probes.some((probe) => probe.status === "ok" || probe.status === "absent")) return "ok";
  if (probes.some((probe) => probe.status === "unable")) return "unable";
  return "unsupported";
}

function envelopeStatus(result) {
  if (result.status === "unsupported") return "unknown";
  if (result.status === "unable") return "unable";
  if (result.summary?.unavailable_count > 0) return "warning";
  return "ok";
}

function reviewHint(result) {
  const status = envelopeStatus(result);
  if (status === "warning") return "missing_permission";
  if (status === "unable") return "missing_permission";
  if (status === "unknown") return "ambiguous";
  return "none";
}

export async function collectScheduledJobsEvidence(options = {}) {
  const request = normalizeScheduledJobsRequest(options);
  return timedEnvelope(async () => {
    const cron = await collectCronJobs({ limit: request.job_limit, includeSystem: request.include_system, includeUser: request.include_user });
    let platformJobs = [];
    let platformProbes = [];

    if (process.platform === "linux") {
      const timers = await collectSystemdTimers({ limit: request.job_limit, includeSystem: request.include_system, includeUser: request.include_user });
      platformJobs = timers.jobs;
      platformProbes = timers.probes;
    } else if (process.platform === "darwin") {
      const launchd = await collectLaunchdScheduledJobs({ limit: request.job_limit, includeSystem: request.include_system, includeUser: request.include_user });
      platformJobs = launchd.jobs;
      platformProbes = launchd.probes;
    } else {
      platformProbes = [{ source: "platform_scheduler", status: "unsupported", error: `unsupported platform: ${process.platform}`, job_count: 0 }];
    }

    const probes = [...cron.probes, ...platformProbes];
    const allJobs = [...cron.jobs, ...platformJobs];
    const jobs = selectScheduledJobsFairly(allJobs, request.job_limit);
    const truncated = allJobs.length > jobs.length || probes.some((probe) => probe.truncated);
    const status = overallProbeStatus(probes);
    return {
      platform: process.platform,
      status,
      request,
      summary: summarizeScheduledJobs(jobs, allJobs, probes, { limit: request.job_limit }),
      jobs,
      truncated,
      probes,
      note: "Scheduled job evidence is read-only and bounded; command lines are redacted for obvious secrets but remain sensitive diagnostic artifacts.",
    };
  }, (result) => evidenceEnvelope({
    id: "scheduled-jobs",
    status: envelopeStatus(result),
    source: "scheduler",
    result,
    confidence: result?.status === "ok" ? 0.9 : 0.35,
    reviewHint: reviewHint(result),
    tool: "collect_scheduled_jobs",
    target: `limit=${request.job_limit};include_system=${request.include_system};include_user=${request.include_user}`,
  }));
}
