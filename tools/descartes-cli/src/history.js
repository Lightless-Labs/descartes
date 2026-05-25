import { buildHistorySummary, parseDurationMs, readDaemonStatus } from "./history-store.js";

function historyUsage() {
  return `Usage:
  descartes history summary [--json] [--verbose] [--window <duration>]

Summarizes bounded local metric history without invoking an LLM.
Default human output is compact; use --verbose for the full metric table.`;
}

function parseHistoryArgs(args) {
  const [subcommand, ...rest] = args;
  if (subcommand !== "summary") throw new Error(`Unsupported history command: ${subcommand ?? ""}\n\n${historyUsage()}`);
  const options = { json: false, verbose: false, window: "1h" };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--json") options.json = true;
    else if (arg === "--verbose") options.verbose = true;
    else if (arg === "--window") {
      const value = rest[index + 1];
      if (!value) throw new Error("--window requires a value");
      options.window = value;
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`Unknown history option: ${arg}\n\n${historyUsage()}`);
    }
  }
  options.windowMs = parseDurationMs(options.window, 60 * 60 * 1000);
  return options;
}

function formatValue(value) {
  if (value === undefined) return "n/a";
  if (Math.abs(value) >= 1000) return value.toFixed(0);
  if (Math.abs(value) >= 10) return value.toFixed(2);
  return value.toFixed(3);
}

function formatNumber(value, digits = 2) {
  if (value === undefined || value === null || !Number.isFinite(Number(value))) return "n/a";
  return Number(value).toFixed(digits).replace(/\.0+$/, "").replace(/(\.\d*[1-9])0+$/, "$1");
}

function formatPercent(fraction) {
  if (fraction === undefined || fraction === null || !Number.isFinite(Number(fraction))) return "n/a";
  return `${formatNumber(Number(fraction) * 100, 1)}%`;
}

function formatBytes(bytes) {
  if (bytes === undefined || bytes === null || !Number.isFinite(Number(bytes))) return "n/a";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = Math.abs(Number(bytes));
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const sign = Number(bytes) < 0 ? "-" : "";
  return `${sign}${formatNumber(value, value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "unknown";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 60 * 60_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 24 * 60 * 60_000) return `${formatNumber(ms / (60 * 60_000), 1)}h`;
  return `${formatNumber(ms / (24 * 60 * 60_000), 1)}d`;
}

function metricByName(summary) {
  return new Map(summary.metrics.map((metric) => [metric.metric_name, metric]));
}

function newestMetricTimestamp(summary) {
  const timestamps = summary.metrics
    .map((metric) => new Date(metric.last_ts).getTime())
    .filter(Number.isFinite);
  if (timestamps.length === 0) return undefined;
  return Math.max(...timestamps);
}

function lastSampleDescription(summary, daemonStatus) {
  const untilMs = new Date(summary.until).getTime();
  const metricTs = newestMetricTimestamp(summary);
  const statusTs = daemonStatus?.ts ? new Date(daemonStatus.ts).getTime() : undefined;
  const ts = Number.isFinite(metricTs) ? metricTs : statusTs;
  if (!Number.isFinite(ts) || !Number.isFinite(untilMs)) return "unknown";
  return `${formatDuration(untilMs - ts)} ago`;
}

function cadenceDescription(daemonStatus) {
  const intervalMs = daemonStatus?.profile?.interval_ms;
  if (!Number.isFinite(Number(intervalMs))) return undefined;
  return `~${formatDuration(Number(intervalMs))}`;
}

function pushIfMetric(lines, label, metric, formatter = formatValue) {
  if (!metric) return;
  lines.push(`- ${label}: last ${formatter(metric.last)}, avg ${formatter(metric.mean)}, peak ${formatter(metric.max)} (${metric.count} samples)`);
}

export function renderVerboseHistorySummary(summary, daemonStatus) {
  const lines = [];
  lines.push(`History summary (${summary.point_count} points, window ${Math.round(summary.window_ms / 1000)}s)`);
  lines.push(`Range: ${summary.since} → ${summary.until}`);
  if (daemonStatus) lines.push(`Daemon status: ${daemonStatus.state ?? "unknown"} at ${daemonStatus.ts ?? "unknown time"}`);
  if (summary.corrupt_count > 0) lines.push(`Skipped corrupt history records: ${summary.corrupt_count}`);
  if (summary.metrics.length === 0) {
    lines.push("No metric history is available for this window.");
    return lines.join("\n");
  }
  lines.push("");
  for (const metric of summary.metrics) {
    lines.push(`- ${metric.metric_name}: count=${metric.count}, last=${formatValue(metric.last)} ${metric.unit}, min=${formatValue(metric.min)}, max=${formatValue(metric.max)}, mean=${formatValue(metric.mean)}, p95=${formatValue(metric.p95)}, dimensions=${metric.dimensions_seen}`);
  }
  return lines.join("\n");
}

export function renderCompactHistorySummary(summary, daemonStatus) {
  const lines = [];
  const window = formatDuration(summary.window_ms);
  const cadence = cadenceDescription(daemonStatus);
  lines.push(`History summary: ${summary.point_count} points over ${window}`);
  lines.push(`Last sample: ${lastSampleDescription(summary, daemonStatus)}${cadence ? ` (cadence ${cadence})` : ""}`);
  lines.push(`Daemon: ${daemonStatus?.state ?? "unknown"}${daemonStatus?.mode ? ` (${daemonStatus.mode})` : ""}`);
  if (summary.corrupt_count > 0) lines.push(`Skipped corrupt history records: ${summary.corrupt_count}`);
  if (summary.metrics.length === 0) {
    lines.push("No recent metric history is available for this window.");
    lines.push("Try starting the daemon or widening --window if it was recently stopped.");
    return lines.join("\n");
  }

  const metrics = metricByName(summary);
  lines.push("");
  lines.push("Highlights:");
  pushIfMetric(lines, "Load 1m", metrics.get("system.load.1m"), (value) => formatNumber(value, 2));
  pushIfMetric(lines, "Memory used", metrics.get("system.memory.used_fraction"), formatPercent);
  pushIfMetric(lines, "Swap used", metrics.get("system.swap.used_bytes"), formatBytes);
  const diskUsed = metrics.get("disk.used_fraction");
  if (diskUsed) lines.push(`- Disk used: peak ${formatPercent(diskUsed.max)}, avg ${formatPercent(diskUsed.mean)} across ${diskUsed.dimensions_seen} filesystem(s) (${diskUsed.count} samples)`);
  const processCpu = metrics.get("process.cpu_percent");
  if (processCpu) lines.push(`- Process CPU: peak ${formatNumber(processCpu.max, 1)}%, avg ${formatNumber(processCpu.mean, 1)}% across ${processCpu.dimensions_seen} command/rank sample(s)`);
  const processMemory = metrics.get("process.memory_percent");
  if (processMemory) lines.push(`- Process memory: peak ${formatNumber(processMemory.max, 1)}%, avg ${formatNumber(processMemory.mean, 1)}% across ${processMemory.dimensions_seen} command/rank sample(s)`);

  const freeMemory = metrics.get("system.memory.free_bytes");
  if (freeMemory) lines.push(`- Free memory: last ${formatBytes(freeMemory.last)}, low ${formatBytes(freeMemory.min)}`);
  const diskAvailable = metrics.get("disk.available_bytes");
  if (diskAvailable) lines.push(`- Disk available: low ${formatBytes(diskAvailable.min)} across ${diskAvailable.dimensions_seen} filesystem(s)`);

  const highlightedNames = new Set([
    "system.load.1m",
    "system.memory.used_fraction",
    "system.swap.used_bytes",
    "disk.used_fraction",
    "process.cpu_percent",
    "process.memory_percent",
    "system.memory.free_bytes",
    "disk.available_bytes",
  ]);
  const remaining = summary.metrics.filter((metric) => !highlightedNames.has(metric.metric_name)).length;
  if (remaining > 0) lines.push(`- ${remaining} additional metric type(s); use --verbose or --json for details.`);
  return lines.join("\n");
}

export function renderHistorySummary(summary, daemonStatus, options = {}) {
  return options.verbose ? renderVerboseHistorySummary(summary, daemonStatus) : renderCompactHistorySummary(summary, daemonStatus);
}

export async function runHistory(descartesPaths, args) {
  const options = parseHistoryArgs(args);
  if (options.help) {
    console.log(historyUsage());
    return;
  }
  const [summary, daemonStatus] = await Promise.all([
    buildHistorySummary(descartesPaths, { windowMs: options.windowMs }),
    readDaemonStatus(descartesPaths),
  ]);
  if (options.json) {
    console.log(JSON.stringify({ history: summary, daemon_status: daemonStatus ?? null }, null, 2));
    return;
  }
  console.log(renderHistorySummary(summary, daemonStatus, { verbose: options.verbose }));
}
