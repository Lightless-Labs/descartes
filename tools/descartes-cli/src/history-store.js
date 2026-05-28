import fs from "node:fs/promises";
import path from "node:path";

export const DEFAULT_HISTORY_RETENTION_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_HISTORY_MAX_BYTES = 5 * 1024 * 1024;
export const DEFAULT_HISTORY_POINT_LIMIT = 10000;

export function resolveHistoryStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "history");
  return {
    dir,
    metricsFile: path.join(dir, "metrics.jsonl"),
    statusFile: path.join(dir, "daemon-status.json"),
  };
}

async function ensureHistoryDir(descartesPaths) {
  await fs.mkdir(resolveHistoryStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeTimestamp(ts = new Date().toISOString()) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid metric timestamp: ${ts}`);
  return date.toISOString();
}

function normalizeDimensions(dimensions = {}) {
  if (!dimensions || typeof dimensions !== "object" || Array.isArray(dimensions)) return {};
  const entries = Object.entries(dimensions)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => [String(key), String(value).slice(0, 160)]);
  return Object.fromEntries(entries);
}

export function normalizeMetricPoint(point, defaults = {}) {
  if (!point || typeof point !== "object") throw new Error("Metric point must be an object");
  const metricName = String(point.metric_name ?? "").trim();
  if (!metricName) throw new Error("Metric point requires metric_name");
  const value = Number(point.value);
  if (!Number.isFinite(value)) throw new Error(`Metric point ${metricName} requires a finite numeric value`);

  return {
    ts: normalizeTimestamp(point.ts ?? defaults.ts),
    metric_name: metricName,
    dimensions: normalizeDimensions(point.dimensions),
    value,
    unit: point.unit ? String(point.unit) : "count",
    source_envelope_id: point.source_envelope_id ? String(point.source_envelope_id) : defaults.source_envelope_id,
    source_tool: point.source_tool ? String(point.source_tool) : defaults.source_tool,
    sensitivity: point.sensitivity ? String(point.sensitivity) : "operational",
  };
}

async function readJsonLines(file) {
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { records: [], corrupt_count: 0 };
    throw error;
  }

  const records = [];
  let corruptCount = 0;
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      corruptCount += 1;
    }
  }
  return { records, corrupt_count: corruptCount };
}

function encodeJsonLine(record) {
  return `${JSON.stringify(record)}\n`;
}

export async function enforceHistoryRetention(descartesPaths, options = {}) {
  const storePaths = resolveHistoryStorePaths(descartesPaths);
  const retentionMs = options.retentionMs ?? DEFAULT_HISTORY_RETENTION_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_HISTORY_MAX_BYTES;
  const nowMs = options.now ? new Date(options.now).getTime() : Date.now();
  const cutoffMs = nowMs - retentionMs;
  const { records, corrupt_count: corruptBefore } = await readJsonLines(storePaths.metricsFile);

  const candidates = records
    .map((record) => {
      const tsMs = new Date(record.ts).getTime();
      return { record, tsMs };
    })
    .filter(({ tsMs }) => Number.isFinite(tsMs) && tsMs >= cutoffMs)
    .sort((left, right) => left.tsMs - right.tsMs);

  const keptReversed = [];
  let usedBytes = 0;
  for (let index = candidates.length - 1; index >= 0; index -= 1) {
    const line = encodeJsonLine(candidates[index].record);
    const size = Buffer.byteLength(line);
    if (keptReversed.length > 0 && usedBytes + size > maxBytes) break;
    if (size > maxBytes && keptReversed.length === 0) break;
    keptReversed.push(line);
    usedBytes += size;
  }

  const keptLines = keptReversed.reverse();
  await ensureHistoryDir(descartesPaths);
  await fs.writeFile(storePaths.metricsFile, keptLines.join(""), { mode: 0o600 });
  return {
    kept_count: keptLines.length,
    dropped_count: records.length - keptLines.length,
    corrupt_dropped_count: corruptBefore,
    bytes: usedBytes,
  };
}

export async function appendMetricPoints(descartesPaths, points, options = {}) {
  await ensureHistoryDir(descartesPaths);
  const storePaths = resolveHistoryStorePaths(descartesPaths);
  const normalized = points.map((point) => normalizeMetricPoint(point, { ts: options.ts }));
  if (normalized.length > 0) {
    await fs.appendFile(storePaths.metricsFile, normalized.map(encodeJsonLine).join(""), { mode: 0o600 });
  }
  const retention = await enforceHistoryRetention(descartesPaths, options);
  return { written_count: normalized.length, retention };
}

export async function readMetricPoints(descartesPaths, options = {}) {
  const storePaths = resolveHistoryStorePaths(descartesPaths);
  const sinceMs = options.since ? new Date(options.since).getTime() : undefined;
  const limit = options.limit ?? DEFAULT_HISTORY_POINT_LIMIT;
  const { records, corrupt_count } = await readJsonLines(storePaths.metricsFile);
  const matched = records
    .map((record) => {
      try {
        return normalizeMetricPoint(record);
      } catch {
        return undefined;
      }
    })
    .filter(Boolean)
    .filter((point) => sinceMs === undefined || new Date(point.ts).getTime() >= sinceMs)
    .sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
  const points = matched.slice(-limit);
  return {
    points,
    corrupt_count,
    matched_count: matched.length,
    point_limit: limit,
    truncated: matched.length > points.length,
  };
}

function percentile(values, fraction) {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1));
  return sorted[index];
}

export function summarizeMetricPoints(points) {
  const byMetric = new Map();
  for (const point of points) {
    const current = byMetric.get(point.metric_name) ?? {
      metric_name: point.metric_name,
      unit: point.unit,
      count: 0,
      min: undefined,
      max: undefined,
      mean: undefined,
      last: undefined,
      p95: undefined,
      first_ts: point.ts,
      last_ts: point.ts,
      dimensions_seen: 0,
      sensitivity: point.sensitivity,
      _sum: 0,
      _values: [],
      _dimensions: new Set(),
    };
    current.count += 1;
    current.min = current.min === undefined ? point.value : Math.min(current.min, point.value);
    current.max = current.max === undefined ? point.value : Math.max(current.max, point.value);
    current._sum += point.value;
    current._values.push(point.value);
    current.last = point.value;
    current.last_ts = point.ts;
    current.unit = point.unit || current.unit;
    current.sensitivity = point.sensitivity || current.sensitivity;
    current._dimensions.add(JSON.stringify(point.dimensions ?? {}));
    byMetric.set(point.metric_name, current);
  }

  return [...byMetric.values()].map((summary) => {
    summary.mean = summary.count > 0 ? summary._sum / summary.count : undefined;
    summary.p95 = percentile(summary._values, 0.95);
    summary.dimensions_seen = summary._dimensions.size;
    delete summary._sum;
    delete summary._values;
    delete summary._dimensions;
    return summary;
  }).sort((left, right) => left.metric_name.localeCompare(right.metric_name));
}

export function parseDurationMs(value, fallbackMs = 60 * 60 * 1000) {
  if (value === undefined || value === null || value === "") return fallbackMs;
  if (typeof value === "number") return value;
  const match = String(value).trim().match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/i);
  if (!match) throw new Error(`Invalid duration: ${value}`);
  const amount = Number(match[1]);
  const unit = (match[2] ?? "ms").toLowerCase();
  const multipliers = { ms: 1, s: 1000, m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };
  return amount * multipliers[unit];
}

export async function buildHistorySummary(descartesPaths, options = {}) {
  const windowMs = options.windowMs ?? parseDurationMs(options.window ?? "1h");
  const now = options.now ? new Date(options.now) : new Date();
  const since = new Date(now.getTime() - windowMs).toISOString();
  const { points, corrupt_count, matched_count, point_limit, truncated } = await readMetricPoints(descartesPaths, { since, limit: options.limit });
  return {
    window_ms: windowMs,
    since,
    until: now.toISOString(),
    point_count: points.length,
    matched_point_count: matched_count,
    point_limit,
    truncated,
    corrupt_count,
    metrics: summarizeMetricPoints(points),
  };
}

export async function writeDaemonStatus(descartesPaths, status) {
  await ensureHistoryDir(descartesPaths);
  const storePaths = resolveHistoryStorePaths(descartesPaths);
  const record = {
    ts: new Date().toISOString(),
    ...status,
  };
  await fs.writeFile(storePaths.statusFile, JSON.stringify(record, null, 2), { mode: 0o600 });
  return record;
}

export async function readDaemonStatus(descartesPaths) {
  const storePaths = resolveHistoryStorePaths(descartesPaths);
  try {
    return JSON.parse(await fs.readFile(storePaths.statusFile, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}
