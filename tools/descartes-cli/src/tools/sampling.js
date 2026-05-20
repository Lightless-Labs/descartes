import crypto from "node:crypto";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { collectProcessEvidence } from "./processes.js";
import { collectSystemEvidence } from "./system.js";

export const SAMPLING_POLICY = Object.freeze({
  max_duration_seconds: 60,
  min_interval_seconds: 1,
  max_samples: 120,
  max_top_n: 20,
  max_artifact_bytes: 1024 * 1024,
  read_excerpt_max_samples: 25,
});

const SUPPORTED_DIMENSIONS = new Set(["cpu_processes", "memory_processes", "load_memory_swap"]);
const ARTIFACT_ID_RE = /^sampling-[a-f0-9-]+\.json$/;

function clampNumber(value, { min, max, fallback }) {
  const number = Number(value);
  const chosen = Number.isFinite(number) ? number : fallback;
  return Math.min(Math.max(chosen, min), max);
}

export function normalizeSamplingRequest(request = {}) {
  const dimension = SUPPORTED_DIMENSIONS.has(request.dimension) ? request.dimension : "load_memory_swap";
  const durationSeconds = clampNumber(request.duration_seconds, { min: SAMPLING_POLICY.min_interval_seconds, max: SAMPLING_POLICY.max_duration_seconds, fallback: 10 });
  const intervalSeconds = clampNumber(request.interval_seconds, { min: SAMPLING_POLICY.min_interval_seconds, max: durationSeconds, fallback: 2 });
  const requestedSamples = Math.floor(durationSeconds / intervalSeconds) + 1;
  const sampleCount = Math.min(requestedSamples, SAMPLING_POLICY.max_samples);
  const topN = Math.trunc(clampNumber(request.top_n, { min: 1, max: SAMPLING_POLICY.max_top_n, fallback: 10 }));
  const aggregation = ["summary", "timeseries", "summary_and_timeseries_ref"].includes(request.aggregation)
    ? request.aggregation
    : "summary";

  return {
    dimension,
    duration_seconds: durationSeconds,
    interval_seconds: intervalSeconds,
    sample_count: sampleCount,
    top_n: topN,
    aggregation,
    clamped: {
      duration_seconds: durationSeconds !== Number(request.duration_seconds ?? durationSeconds),
      interval_seconds: intervalSeconds !== Number(request.interval_seconds ?? intervalSeconds),
      top_n: topN !== Number(request.top_n ?? topN),
      sample_count: requestedSamples !== sampleCount,
      dimension: dimension !== request.dimension && request.dimension !== undefined,
    },
  };
}

function mean(values) {
  if (values.length === 0) return undefined;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function max(values) {
  return values.length === 0 ? undefined : Math.max(...values);
}

function min(values) {
  return values.length === 0 ? undefined : Math.min(...values);
}

function p95(values) {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)];
}

function round(value, digits = 2) {
  return typeof value === "number" ? Number(value.toFixed(digits)) : value;
}

function numericStats(values) {
  return {
    min: round(min(values)),
    max: round(max(values)),
    mean: round(mean(values)),
    p95: round(p95(values)),
  };
}

function processKey(process) {
  return `${process.pid}:${process.command}`;
}

function aggregateProcesses(samples, listKey, sortKey) {
  const byProcess = new Map();
  for (const sample of samples) {
    for (const process of sample[listKey] ?? []) {
      const key = processKey(process);
      const entry = byProcess.get(key) ?? {
        pid: process.pid,
        command: process.command,
        args: process.args,
        args_redaction: process.args_redaction,
        observations: 0,
        cpu_values: [],
        memory_values: [],
        rss_values: [],
      };
      entry.observations += 1;
      if (typeof process.cpu_percent === "number") entry.cpu_values.push(process.cpu_percent);
      if (typeof process.memory_percent === "number") entry.memory_values.push(process.memory_percent);
      if (typeof process.rss_bytes === "number") entry.rss_values.push(process.rss_bytes);
      byProcess.set(key, entry);
    }
  }

  return [...byProcess.values()].map((entry) => ({
    pid: entry.pid,
    command: entry.command,
    args: entry.args,
    args_redaction: entry.args_redaction,
    observations: entry.observations,
    average_cpu_percent: round(mean(entry.cpu_values) ?? 0),
    peak_cpu_percent: round(max(entry.cpu_values) ?? 0),
    average_memory_percent: round(mean(entry.memory_values) ?? 0),
    peak_memory_percent: round(max(entry.memory_values) ?? 0),
    peak_rss_bytes: max(entry.rss_values) ?? 0,
  })).sort((left, right) => (right[sortKey] ?? 0) - (left[sortKey] ?? 0));
}

export function aggregateSamples(dimension, samples, topN = 10) {
  if (dimension === "cpu_processes") {
    return {
      top_contributors_by_average_cpu: aggregateProcesses(samples, "top_cpu", "average_cpu_percent").slice(0, topN),
      top_contributors_by_peak_cpu: aggregateProcesses(samples, "top_cpu", "peak_cpu_percent").slice(0, topN),
    };
  }

  if (dimension === "memory_processes") {
    return {
      top_contributors_by_average_memory: aggregateProcesses(samples, "top_memory", "average_memory_percent").slice(0, topN),
      top_contributors_by_peak_memory: aggregateProcesses(samples, "top_memory", "peak_memory_percent").slice(0, topN),
    };
  }

  return {
    load_1m: numericStats(samples.map((sample) => sample.load_average?.[0]).filter((value) => typeof value === "number")),
    memory_used_fraction: numericStats(samples.map((sample) => sample.memory?.used_fraction).filter((value) => typeof value === "number")),
    swap_used_bytes: numericStats(samples.map((sample) => sample.swap?.used_bytes).filter((value) => typeof value === "number")),
  };
}

function stabilityNotes(dimension, samples, summary) {
  if (samples.length < 2) return ["Only one sample collected; temporal stability cannot be assessed."];
  if (dimension === "cpu_processes") {
    const peak = summary.top_contributors_by_peak_cpu?.[0];
    if (peak?.peak_cpu_percent >= 100 && peak.observations >= Math.ceil(samples.length / 2)) {
      return [`${peak.command} appeared in at least half of samples and peaked at ${peak.peak_cpu_percent}% CPU.`];
    }
  }
  if (dimension === "memory_processes") {
    const peak = summary.top_contributors_by_peak_memory?.[0];
    if (peak?.peak_memory_percent >= 10 && peak.observations >= Math.ceil(samples.length / 2)) {
      return [`${peak.command} appeared in at least half of samples and peaked at ${peak.peak_memory_percent}% memory.`];
    }
  }
  return ["No deterministic flapping or sustained-dominance pattern was identified in this bounded sample."];
}

function artifactDir(paths) {
  if (!paths?.cacheDir) throw new Error("Sampling artifacts require a Descartes cacheDir.");
  return path.join(paths.cacheDir, "sampling");
}

function assertArtifactPathUnderCache(paths, artifactPath) {
  const dir = path.resolve(artifactDir(paths));
  const resolved = path.resolve(artifactPath);
  if (resolved !== dir && !resolved.startsWith(`${dir}${path.sep}`)) {
    throw new Error("Sampling artifact path escaped Descartes cache directory.");
  }
}

export async function writeSamplingArtifact(paths, payload) {
  const dir = artifactDir(paths);
  await mkdir(dir, { recursive: true });
  const artifactId = `sampling-${crypto.randomUUID()}.json`;
  const artifactPath = path.join(dir, artifactId);
  assertArtifactPathUnderCache(paths, artifactPath);
  const content = JSON.stringify(payload, null, 2);
  if (Buffer.byteLength(content, "utf8") > SAMPLING_POLICY.max_artifact_bytes) {
    throw new Error("Sampling artifact exceeded max artifact size.");
  }
  await writeFile(artifactPath, content, { mode: 0o600 });
  return { artifact_id: artifactId, path: artifactPath, bytes: Buffer.byteLength(content, "utf8") };
}

export function samplingArtifactPath(paths, artifactId) {
  if (!ARTIFACT_ID_RE.test(artifactId ?? "")) throw new Error("Invalid sampling artifact id.");
  const artifactPath = path.join(artifactDir(paths), artifactId);
  assertArtifactPathUnderCache(paths, artifactPath);
  return artifactPath;
}

async function defaultCollectSample(normalized) {
  if (normalized.dimension === "cpu_processes" || normalized.dimension === "memory_processes") {
    const envelope = await collectProcessEvidence({ limit: normalized.top_n });
    if (envelope.status !== "ok") throw new Error(envelope.result?.error ?? "process sample failed");
    return normalized.dimension === "cpu_processes"
      ? { top_cpu: envelope.result.top_cpu ?? [] }
      : { top_memory: envelope.result.top_memory ?? [] };
  }

  const envelope = await collectSystemEvidence();
  if (envelope.status !== "ok") throw new Error(envelope.result?.error ?? "system sample failed");
  return {
    load_average: envelope.result.load_average,
    memory: envelope.result.memory,
    swap: envelope.result.swap,
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function collectSamples(normalized, options = {}) {
  const collectSample = options.collectSample ?? defaultCollectSample;
  const sleepFn = options.sleepFn ?? sleep;
  const samples = [];
  const started = Date.now();
  for (let index = 0; index < normalized.sample_count; index += 1) {
    samples.push({
      index,
      elapsed_ms: Date.now() - started,
      ts: new Date().toISOString(),
      ...(await collectSample(normalized, index)),
    });
    if (index < normalized.sample_count - 1) await sleepFn(normalized.interval_seconds * 1000);
  }
  return { samples, elapsed_ms: Date.now() - started };
}

export async function sampleDimensionEvidence(request = {}, paths, options = {}) {
  const normalized = normalizeSamplingRequest(request);
  return timedEnvelope(async () => {
    const { samples, elapsed_ms } = await collectSamples(normalized, options);
    const summary = aggregateSamples(normalized.dimension, samples, normalized.top_n);
    const result = {
      dimension: normalized.dimension,
      policy: SAMPLING_POLICY,
      requested: request,
      effective: normalized,
      sample_count: samples.length,
      elapsed_ms,
      summary,
      stability_notes: stabilityNotes(normalized.dimension, samples, summary),
      sensitivity: "Sampling artifacts may contain process names, command lines, paths, and usernames; treat them as sensitive diagnostic data.",
    };

    if (normalized.aggregation === "timeseries") {
      result.samples = samples;
    } else if (normalized.aggregation === "summary_and_timeseries_ref") {
      result.artifact = await writeSamplingArtifact(paths, {
        kind: "descartes_sampling_timeseries",
        dimension: normalized.dimension,
        effective: normalized,
        samples,
      });
    }

    return result;
  }, (result) => evidenceEnvelope({
    id: `sample-${normalized.dimension}`,
    source: "sampler",
    result,
    tool: "sample_dimension",
    target: `${normalized.dimension},duration=${normalized.duration_seconds},interval=${normalized.interval_seconds},samples=${normalized.sample_count}`,
  }));
}

export async function readSamplingArtifactEvidence({ artifact_id: artifactId, max_samples: maxSamples } = {}, paths) {
  return timedEnvelope(async () => {
    const artifactPath = samplingArtifactPath(paths, artifactId);
    const raw = await readFile(artifactPath, "utf8");
    if (Buffer.byteLength(raw, "utf8") > SAMPLING_POLICY.max_artifact_bytes) throw new Error("Sampling artifact exceeds read limit.");
    const parsed = JSON.parse(raw);
    const limit = Math.trunc(clampNumber(maxSamples, { min: 1, max: SAMPLING_POLICY.read_excerpt_max_samples, fallback: SAMPLING_POLICY.read_excerpt_max_samples }));
    const samples = Array.isArray(parsed.samples) ? parsed.samples.slice(0, limit) : [];
    return {
      artifact_id: artifactId,
      kind: parsed.kind,
      dimension: parsed.dimension,
      total_samples: Array.isArray(parsed.samples) ? parsed.samples.length : 0,
      returned_samples: samples.length,
      samples,
      sensitivity: "Sampling artifacts may contain process names, command lines, paths, and usernames; treat them as sensitive diagnostic data.",
    };
  }, (result) => evidenceEnvelope({
    id: `sampling-artifact-${artifactId}`,
    source: "sampler",
    result,
    tool: "read_sampling_artifact",
    target: artifactId,
  }));
}
