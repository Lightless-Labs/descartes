import assert from "node:assert/strict";
import test from "node:test";
import {
  renderCompactHistorySummary,
  renderHistorySummary,
  renderVerboseHistorySummary,
} from "../src/history.js";

function summary(overrides = {}) {
  return {
    window_ms: 60 * 60 * 1000,
    since: "2026-05-24T11:00:00.000Z",
    until: "2026-05-24T12:00:00.000Z",
    point_count: 42,
    corrupt_count: 0,
    metrics: [
      {
        metric_name: "system.load.1m",
        unit: "load_average",
        count: 3,
        min: 0.5,
        max: 2.25,
        mean: 1.25,
        last: 1.5,
        p95: 2.25,
        first_ts: "2026-05-24T11:58:00.000Z",
        last_ts: "2026-05-24T11:59:30.000Z",
        dimensions_seen: 1,
        sensitivity: "operational",
      },
      {
        metric_name: "system.memory.used_fraction",
        unit: "fraction",
        count: 3,
        min: 0.5,
        max: 0.75,
        mean: 0.625,
        last: 0.7,
        p95: 0.75,
        first_ts: "2026-05-24T11:58:00.000Z",
        last_ts: "2026-05-24T11:59:30.000Z",
        dimensions_seen: 1,
        sensitivity: "operational",
      },
      {
        metric_name: "disk.available_bytes",
        unit: "bytes",
        count: 2,
        min: 1073741824,
        max: 2147483648,
        mean: 1610612736,
        last: 1073741824,
        p95: 2147483648,
        first_ts: "2026-05-24T11:58:00.000Z",
        last_ts: "2026-05-24T11:59:30.000Z",
        dimensions_seen: 2,
        sensitivity: "path",
      },
    ],
    ...overrides,
  };
}

const daemonStatus = {
  state: "ok",
  mode: "foreground",
  ts: "2026-05-24T11:59:30.000Z",
  profile: { interval_ms: 60_000 },
};

test("compact history summary highlights operator signals and sample cadence", () => {
  const output = renderCompactHistorySummary(summary(), daemonStatus);
  assert.match(output, /History summary: 42 points over 1h/);
  assert.match(output, /Last sample: 30s ago \(cadence ~1m\)/);
  assert.match(output, /Daemon: ok \(foreground\)/);
  assert.match(output, /Highlights:/);
  assert.match(output, /Load 1m: last 1\.5, avg 1\.25, peak 2\.25/);
  assert.match(output, /Memory used: last 70%, avg 62\.5%, peak 75%/);
  assert.match(output, /Disk available: low 1 GiB across 2 filesystem\(s\)/);
  assert.doesNotMatch(output, /count=3, last=/);
});

test("verbose history summary keeps full metric table", () => {
  const output = renderVerboseHistorySummary(summary(), daemonStatus);
  assert.match(output, /History summary \(42 points, window 3600s\)/);
  assert.match(output, /Range: 2026-05-24T11:00:00\.000Z → 2026-05-24T12:00:00\.000Z/);
  assert.match(output, /system\.load\.1m: count=3, last=1\.500 load_average/);
});

test("renderHistorySummary switches verbose mode explicitly", () => {
  assert.match(renderHistorySummary(summary(), daemonStatus), /Highlights:/);
  assert.match(renderHistorySummary(summary(), daemonStatus, { verbose: true }), /count=3, last=/);
});

test("compact history summary explains empty windows", () => {
  const output = renderCompactHistorySummary(summary({ point_count: 0, metrics: [] }), undefined);
  assert.match(output, /No recent metric history is available/);
  assert.match(output, /widening --window/);
});
