import { buildHistorySummary, parseDurationMs, readDaemonStatus } from "./history-store.js";

function historyUsage() {
  return `Usage:
  descartes history summary [--json] [--window <duration>]

Summarizes bounded local metric history without invoking an LLM.`;
}

function parseHistoryArgs(args) {
  const [subcommand, ...rest] = args;
  if (subcommand !== "summary") throw new Error(`Unsupported history command: ${subcommand ?? ""}\n\n${historyUsage()}`);
  const options = { json: false, window: "1h" };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--json") options.json = true;
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

export function renderHistorySummary(summary, daemonStatus) {
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
  console.log(renderHistorySummary(summary, daemonStatus));
}
