import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DEFAULT_WINDOW_MINUTES = 30;
const DEFAULT_EVENT_LIMIT = 80;
const DEFAULT_MESSAGE_CHARS = 500;
// 72h ceiling (widened from 6h, Slice 0) so a retrospective incident review isn't structurally
// capped below the incident's actual duration. DEFAULT_WINDOW_MINUTES stays 30 so existing callers
// are unaffected. Exported as the single source of truth for the pi-harness collect_recent_logs
// schema bound (which imports it) so the two enforcement points can never drift. NOTE: output is
// still bounded by MAX_EVENT_LIMIT, so a wider window samples more sparsely — a genuinely useful
// 7-day window would need pre-computed aggregates rather than a raw event cap (deferred, see the
// plan's open questions).
export const MAX_WINDOW_MINUTES = 4320;
const MAX_EVENT_LIMIT = 200;

function clampNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.floor(number), min), max);
}

export function normalizeLogRequest(options = {}) {
  return {
    window_minutes: clampNumber(options.windowMinutes ?? options.window_minutes, DEFAULT_WINDOW_MINUTES, 1, MAX_WINDOW_MINUTES),
    event_limit: clampNumber(options.eventLimit ?? options.event_limit, DEFAULT_EVENT_LIMIT, 1, MAX_EVENT_LIMIT),
    message_chars: clampNumber(options.messageChars ?? options.message_chars, DEFAULT_MESSAGE_CHARS, 80, 1200),
    include_security: options.includeSecurity ?? options.include_security ?? true,
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
      timeout: options.timeout ?? 5000,
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
    });
    return {
      status: "ok",
      stdout,
      stderr: truncate(stderr),
      command: { argv, read_only: true },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (options.allowPartial && message.includes("stdout maxBuffer") && error?.stdout) {
      return {
        status: "ok",
        partial_output: true,
        error: message,
        stdout: error.stdout,
        stderr: truncate(error?.stderr ?? "", 2048),
        command: { argv, read_only: true },
      };
    }
    return {
      status: "unable",
      error: message,
      stdout: truncate(error?.stdout ?? "", 4096),
      stderr: truncate(error?.stderr ?? "", 2048),
      command: { argv, read_only: true },
    };
  }
}

function looksSecretToken(value) {
  const compact = String(value ?? "").replace(/^['\"]|['\"]$/g, "");
  return compact.length >= 32
    && /^[A-Za-z0-9+_.=:/-]+$/.test(compact)
    && /[A-Za-z]/.test(compact)
    && /[0-9]/.test(compact)
    && !compact.includes("/");
}

export function redactAndBoundLogMessage(message, { maxChars = DEFAULT_MESSAGE_CHARS } = {}) {
  const original = String(message ?? "");
  let redacted = false;
  let value = original
    .replace(/\b(authorization:\s*bearer)\s+\S+/gi, (_match, prefix) => {
      redacted = true;
      return `${prefix} [REDACTED]`;
    })
    .replace(/\b((?:token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth|credential|session|jwt|private[_-]?key)[A-Za-z0-9_.-]*)(=|:)([^\s,&;]+)/gi, (_match, key, delimiter) => {
      redacted = true;
      return `${key}${delimiter}[REDACTED]`;
    })
    .replace(/([?&](?:token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth|credential|session|jwt)=)([^&#\s]+)/gi, (_match, prefix) => {
      redacted = true;
      return `${prefix}[REDACTED]`;
    })
    .replace(/\b[A-Za-z0-9+_.=:/-]{32,}\b/g, (token) => {
      if (!looksSecretToken(token)) return token;
      redacted = true;
      return "[REDACTED]";
    });

  let truncated = false;
  if (value.length > maxChars) {
    value = `${value.slice(0, maxChars)}…`;
    truncated = true;
  }

  return {
    value,
    redacted,
    truncated,
    original_length: original.length,
    max_chars: maxChars,
  };
}

function prioritySeverity(priority) {
  const number = Number(priority);
  if (!Number.isFinite(number)) return "unknown";
  if (number <= 3) return "error";
  if (number === 4) return "warning";
  if (number === 5) return "notice";
  if (number === 6) return "info";
  return "debug";
}

function macSeverity(messageType) {
  const value = String(messageType ?? "").toLowerCase();
  if (value === "fault" || value === "error") return "error";
  if (value === "warning") return "warning";
  if (value === "info") return "info";
  if (value === "debug") return "debug";
  return value || "unknown";
}

export function categorizeLogEntry(entry) {
  const haystack = [entry.message, entry.unit, entry.identifier, entry.process, entry.subsystem, entry.source].filter(Boolean).join(" ").toLowerCase();
  if (/fail2ban|f2b/.test(haystack)) return "fail2ban";
  if (/\b(ufw|firewalld|firewall|nftables|iptables|ip6tables|pf|socketfilterfw|block(?:ed)?|den(?:y|ied)|drop(?:ped)?|reject(?:ed)?)\b/.test(haystack)) return "firewall";
  if (/\b(sshd?|pam|sudo|login|auth(?:entication)?|invalid user|failed password)\b/.test(haystack)) return "auth";
  if (/\b(crash(?:ed)?|panic|segfault|exception|traceback|oom|out of memory)\b/.test(haystack)) return "crash";
  return "general";
}

function isoFromJournalMicros(value) {
  const micros = Number(value);
  if (!Number.isFinite(micros)) return undefined;
  return new Date(Math.floor(micros / 1000)).toISOString();
}

function sanitizeEntry(entry, { messageChars = DEFAULT_MESSAGE_CHARS } = {}) {
  const message = redactAndBoundLogMessage(entry.message, { maxChars: messageChars });
  const sanitized = {
    ts: entry.ts,
    source: entry.source,
    category: entry.category ?? categorizeLogEntry(entry),
    severity: entry.severity ?? "unknown",
    message: message.value,
    message_redaction: {
      redacted: message.redacted,
      truncated: message.truncated,
      original_length: message.original_length,
      max_chars: message.max_chars,
    },
  };

  for (const [key, value] of Object.entries({
    priority: entry.priority,
    unit: entry.unit,
    identifier: entry.identifier,
    process: entry.process,
    subsystem: entry.subsystem,
    pid: entry.pid,
    raw_file: entry.raw_file,
  })) {
    if (value !== undefined && value !== "") sanitized[key] = value;
  }
  return sanitized;
}

export function parseJournalctlJsonLines(stdout, { limit = DEFAULT_EVENT_LIMIT, messageChars = DEFAULT_MESSAGE_CHARS, categoryFilter } = {}) {
  const entries = [];
  for (const line of String(stdout ?? "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let item;
    try {
      item = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const raw = {
      ts: isoFromJournalMicros(item.__REALTIME_TIMESTAMP ?? item._SOURCE_REALTIME_TIMESTAMP),
      source: "journal",
      priority: item.PRIORITY === undefined ? undefined : Number(item.PRIORITY),
      severity: prioritySeverity(item.PRIORITY),
      unit: item._SYSTEMD_UNIT ?? item.UNIT,
      identifier: item.SYSLOG_IDENTIFIER,
      pid: item._PID === undefined ? undefined : Number(item._PID),
      message: item.MESSAGE ?? "",
    };
    raw.category = categorizeLogEntry(raw);
    if (categoryFilter && !categoryFilter(raw.category, raw)) continue;
    entries.push(sanitizeEntry(raw, { messageChars }));
  }
  return entries.slice(0, limit);
}

function parseJsonObjects(stdout) {
  const trimmed = String(stdout ?? "").trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return trimmed.split("\n").map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return undefined;
    }
  }).filter(Boolean);
}

export function parseMacUnifiedLogJson(stdout, { limit = DEFAULT_EVENT_LIMIT, messageChars = DEFAULT_MESSAGE_CHARS, categoryFilter } = {}) {
  const entries = [];
  for (const item of parseJsonObjects(stdout)) {
    const raw = {
      ts: item.timestamp,
      source: "unified_log",
      severity: macSeverity(item.messageType ?? item.eventType),
      process: item.process ?? item.processImagePath,
      subsystem: item.subsystem,
      message: item.eventMessage ?? item.composedMessage ?? item.message ?? "",
    };
    raw.category = categorizeLogEntry(raw);
    if (categoryFilter && !categoryFilter(raw.category, raw)) continue;
    entries.push(sanitizeEntry(raw, { messageChars }));
  }
  return entries.slice(0, limit);
}

export function parseSyslogLines(stdout, { source = "syslog", rawFile, limit = DEFAULT_EVENT_LIMIT, messageChars = DEFAULT_MESSAGE_CHARS, categoryFilter } = {}) {
  const entries = [];
  for (const line of String(stdout ?? "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^([A-Z][a-z]{2}\s+\d+\s+[0-9:]+)\s+(\S+)\s+([^:]+):\s*(.*)$/);
    const raw = match ? {
      ts: match[1],
      source,
      identifier: match[3].replace(/\[\d+\]$/, ""),
      message: match[4],
      raw_file: rawFile,
    } : {
      source,
      message: trimmed,
      raw_file: rawFile,
    };
    raw.category = categorizeLogEntry(raw);
    raw.severity = /\b(error|fail(?:ed|ure)?|denied|blocked|drop|reject)\b/i.test(raw.message) ? "warning" : "info";
    if (categoryFilter && !categoryFilter(raw.category, raw)) continue;
    entries.push(sanitizeEntry(raw, { messageChars }));
  }
  return entries.slice(0, limit);
}

function combineEntries(probes, limit) {
  const seen = new Set();
  const entries = [];
  for (const probe of probes) {
    for (const entry of probe.entries ?? []) {
      const key = `${entry.source}:${entry.ts ?? ""}:${entry.identifier ?? entry.process ?? ""}:${entry.message}`;
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push(entry);
    }
  }
  return entries.slice(0, limit);
}

function categoryCounts(entries) {
  const counts = {};
  for (const entry of entries) counts[entry.category] = (counts[entry.category] ?? 0) + 1;
  return counts;
}

function probeResult({ name, source, command, entries, parsedTotal, parser, category, error, stderr }) {
  return {
    name,
    source,
    status: command.status,
    parser,
    category_focus: category,
    command: command.command,
    entries,
    entry_count: entries.length,
    truncated: parsedTotal > entries.length,
    error: command.error ?? error,
    stderr: command.stderr ?? stderr,
    partial_output: command.partial_output === true,
  };
}

async function journalProbe({ name, args, source = "journal", limit, messageChars, category, categoryFilter }) {
  const command = await runFixedCommand("journalctl", args, { timeout: 5000, maxBuffer: 1024 * 1024 });
  if (command.status !== "ok") return probeResult({ name, source, command, entries: [], parsedTotal: 0, parser: "journal_json", category });
  const all = parseJournalctlJsonLines(command.stdout, { limit: MAX_EVENT_LIMIT * 4, messageChars, categoryFilter });
  return probeResult({ name, source, command, entries: all.slice(0, limit), parsedTotal: all.length, parser: "journal_json", category });
}

async function tailProbe({ name, path, source, limit, messageChars, category, categoryFilter }) {
  const command = await runFixedCommand("tail", ["-n", String(limit), path], { timeout: 2500, maxBuffer: 256 * 1024 });
  if (command.status !== "ok") return probeResult({ name, source, command, entries: [], parsedTotal: 0, parser: "syslog_lines", category });
  const all = parseSyslogLines(command.stdout, { source, rawFile: path, limit: MAX_EVENT_LIMIT * 4, messageChars, categoryFilter });
  return probeResult({ name, source, command, entries: all.slice(0, limit), parsedTotal: all.length, parser: "syslog_lines", category });
}

async function macLogProbe({ name, predicate, limit, messageChars, category, categoryFilter, windowMinutes }) {
  const command = await runFixedCommand("log", [
    "show",
    "--last",
    `${windowMinutes}m`,
    "--style",
    "ndjson",
    "--predicate",
    predicate,
  ], { timeout: 6500, maxBuffer: 1024 * 1024, allowPartial: true });
  if (command.status !== "ok") return probeResult({ name, source: "unified_log", command, entries: [], parsedTotal: 0, parser: "mac_unified_log_json", category });
  const all = parseMacUnifiedLogJson(command.stdout, { limit: MAX_EVENT_LIMIT * 4, messageChars, categoryFilter });
  return probeResult({ name, source: "unified_log", command, entries: all.slice(0, limit), parsedTotal: all.length, parser: "mac_unified_log_json", category });
}

function securityCategory(category) {
  return category === "fail2ban" || category === "firewall" || category === "auth";
}

async function collectLinuxLogProbes(request) {
  const since = `${request.window_minutes} minutes ago`;
  const limit = request.event_limit;
  const probes = [
    journalProbe({
      name: "recent_warnings_errors",
      args: ["--since", since, "--priority", "warning", "--no-pager", "--output", "json", "--lines", String(limit)],
      limit,
      messageChars: request.message_chars,
      category: "general",
    }),
  ];

  if (request.include_security) {
    probes.push(
      journalProbe({
        name: "fail2ban_journal",
        args: ["--since", since, "--unit", "fail2ban.service", "--no-pager", "--output", "json", "--lines", String(limit)],
        limit,
        messageChars: request.message_chars,
        category: "fail2ban",
        categoryFilter: (category) => category === "fail2ban" || category === "auth" || category === "general",
      }),
      journalProbe({
        name: "firewall_units_journal",
        args: ["--since", since, "--unit", "ufw.service", "--unit", "firewalld.service", "--unit", "nftables.service", "--no-pager", "--output", "json", "--lines", String(limit)],
        limit,
        messageChars: request.message_chars,
        category: "firewall",
        categoryFilter: (category) => category === "firewall" || category === "general",
      }),
      journalProbe({
        name: "kernel_firewall_journal",
        args: ["--since", since, "--dmesg", "--no-pager", "--output", "json", "--lines", String(Math.min(limit * 2, MAX_EVENT_LIMIT * 2))],
        limit,
        messageChars: request.message_chars,
        category: "firewall",
        categoryFilter: (category) => category === "firewall",
      }),
      tailProbe({
        name: "fail2ban_log_file",
        path: "/var/log/fail2ban.log",
        source: "fail2ban_log",
        limit,
        messageChars: request.message_chars,
        category: "fail2ban",
        categoryFilter: (category) => category === "fail2ban" || category === "auth" || category === "general",
      }),
      tailProbe({
        name: "ufw_log_file",
        path: "/var/log/ufw.log",
        source: "ufw_log",
        limit,
        messageChars: request.message_chars,
        category: "firewall",
        categoryFilter: (category) => category === "firewall",
      })
    );
  }

  return Promise.all(probes);
}

async function collectMacLogProbes(request) {
  const limit = request.event_limit;
  const probes = [
    macLogProbe({
      name: "recent_errors_faults",
      predicate: "messageType == \"error\" OR messageType == \"fault\"",
      limit,
      messageChars: request.message_chars,
      category: "general",
      windowMinutes: request.window_minutes,
    }),
  ];

  if (request.include_security) {
    probes.push(macLogProbe({
      name: "firewall_security_unified_log",
      predicate: "process == \"socketfilterfw\" OR subsystem CONTAINS[c] \"firewall\" OR eventMessage CONTAINS[c] \"fail2ban\" OR composedMessage CONTAINS[c] \"fail2ban\" OR eventMessage CONTAINS[c] \"blocked\" OR composedMessage CONTAINS[c] \"blocked\" OR eventMessage CONTAINS[c] \"denied\" OR composedMessage CONTAINS[c] \"denied\"",
      limit,
      messageChars: request.message_chars,
      category: "firewall_or_fail2ban",
      categoryFilter: securityCategory,
      windowMinutes: request.window_minutes,
    }));
  }

  return Promise.all(probes);
}

function envelopeStatus(result) {
  if (result.status === "unsupported") return "unknown";
  if (result.ok_probe_count === 0) return "unable";
  return "ok";
}

function reviewHint(result) {
  if (result.status === "unsupported") return "ambiguous";
  if (result.ok_probe_count === 0) return "missing_permission";
  if ((result.category_counts.fail2ban ?? 0) > 0 || (result.category_counts.firewall ?? 0) > 0) return "novel_pattern";
  return "none";
}

export async function collectRecentLogsEvidence(options = {}) {
  const request = normalizeLogRequest(options);
  return timedEnvelope(async () => {
    let probes;
    if (process.platform === "linux") probes = await collectLinuxLogProbes(request);
    else if (process.platform === "darwin") probes = await collectMacLogProbes(request);
    else {
      return {
        platform: process.platform,
        status: "unsupported",
        request,
        privacy: {
          bounded: true,
          note: "Log excerpts are sensitive diagnostic artifacts; Descartes bounds and redacts obvious secrets but does not make logs safe for broad sharing.",
        },
        probes: [],
        entries: [],
        category_counts: {},
        ok_probe_count: 0,
        unable_probe_count: 0,
      };
    }

    const entries = combineEntries(probes, request.event_limit);
    return {
      platform: process.platform,
      status: probes.some((probe) => probe.status === "ok") ? "ok" : "unable",
      request,
      privacy: {
        bounded: true,
        note: "Log excerpts are sensitive diagnostic artifacts; Descartes bounds and redacts obvious secrets but does not make logs safe for broad sharing.",
      },
      probes,
      entries,
      category_counts: categoryCounts(entries),
      ok_probe_count: probes.filter((probe) => probe.status === "ok").length,
      unable_probe_count: probes.filter((probe) => probe.status !== "ok").length,
    };
  }, (result) => evidenceEnvelope({
    id: "recent-logs",
    status: envelopeStatus(result),
    source: "logs",
    result,
    confidence: result?.ok_probe_count > 0 ? 0.85 : 0.25,
    reviewHint: reviewHint(result),
    tool: "collect_recent_logs",
    target: `window=${request.window_minutes}m,limit=${request.event_limit},security=${request.include_security}`,
  }));
}
