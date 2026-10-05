// T1 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §8): end-to-end lockout at
// real per-tick volume, on the real daemon path (runDaemonIteration -> real translators -> real
// fact store at its 5 MB default -> real detectors -> computeCoveredAlerts).
//
// On HEAD 134e811 every structural tick past ~28 byte-evicts, byte-cap eviction is a loss channel,
// so (Leg A) the daemon's history read stays `degraded` for 31 days and (Leg B) every detector's
// cold-start anchor re-arms each hour: the watch tier never evaluates. This test asserts the
// absence of that lockout, so it is RED on HEAD and turns green once R0b (S2) reclassifies
// byte-cap eviction as coverage narrowing.
//
// Scope: Leg A/B/C only. The count rules (session.count_drop, peer.count_*) cannot reach
// MIN_SAMPLE_COUNT=30 in a 5 MB shared store at this volume (Leg D); that is T2's job once the
// per-family budgets (S4) land, so it is deliberately NOT asserted here.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { DEFAULT_FACT_MAX_BYTES } from "../src/fact-store.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { computeServiceAppearanceCandidates, computeServiceBaselineCandidates, loadServiceBaselineStore } from "../src/service-baseline.js";
import { computeProcessLineageBaselineCandidates, loadProcessLineageBaselineStore } from "../src/process-lineage-baseline.js";
import { computeScheduledJobBaselineCandidates, loadPersistenceBaselineStore } from "../src/persistence-baseline.js";
import { realVolumeStructuralCollectors } from "./fixtures/real-volume-tick.js";

const HOUR_MS = 60 * 60 * 1000;
const BASE_MS = Date.parse("2026-10-01T00:00:00.000Z");
const STRUCTURAL_TICKS = 40;

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-lockout-e2e-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function fastCollectorFakes() {
  const env = (id, tool, result) => ({ id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: "2026-10-01T00:00:00.000Z" } });
  return {
    system: async () => env("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => env("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => env("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

test("T1: at real per-tick volume and the 5 MB default, routine byte-cap eviction does not lock the watch tier out (no 31-day degraded tail, no hourly anchor re-arm, coverage keeps being reported)", { timeout: 300_000 }, async () => {
  const paths = await tempPaths();
  const { collectors, structuralCollectorToggles } = realVolumeStructuralCollectors();
  const profile = {
    interval_ms: 60_000,
    collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
    structural: { interval_ms: HOUR_MS, collectors: structuralCollectorToggles },
  };
  // Capture each converted watch-tier producer's real result (it runs unmodified; we only observe).
  const coverage = new Map();
  const observe = (label, compute) => async (...args) => {
    const result = await compute(...args);
    coverage.set(label, Array.isArray(result?.evaluatedAlertKeys) ? result.evaluatedAlertKeys.length : -1);
    return result;
  };
  const observers = {
    computeServiceBaselineCandidates: observe("service", computeServiceBaselineCandidates),
    computeServiceAppearanceCandidates: observe("service-appearance", computeServiceAppearanceCandidates),
    computeProcessLineageBaselineCandidates: observe("process-lineage", computeProcessLineageBaselineCandidates),
    computeScheduledJobBaselineCandidates: observe("scheduled-job", computeScheduledJobBaselineCandidates),
  };

  const ticks = [];
  for (let index = 0; index < STRUCTURAL_TICKS; index += 1) {
    const ts = new Date(BASE_MS + index * HOUR_MS).toISOString();
    coverage.clear();
    const structural = await runDaemonIteration(paths, {
      profile,
      collectors: fastCollectorFakes(),
      structuralCollectors: collectors,
      ts,
      now: ts,
      evaluateAlerts: true,
      ...observers,
    });
    const anchors = {
      service: (await loadServiceBaselineStore(paths)).state,
      lineage: (await loadProcessLineageBaselineStore(paths)).state,
      persistence: (await loadPersistenceBaselineStore(paths)).state,
    };
    const tick = {
      index,
      ts,
      bytecapEvicted: structural.structuralFacts?.retention?.bytecap_evicted_count ?? 0,
      written: structural.structuralFacts?.written_count ?? 0,
      status: structural.status.fact_store_completeness?.status,
      coverage: Object.fromEntries(coverage),
      anchors: Object.fromEntries(Object.entries(anchors).map(([key, state]) => [key, { pending: state.cold_start_pending, since: state.cold_start_since_ts }])),
    };
    // A fast tick between structural ticks (structural not due): Leg A keeps trust false here on
    // HEAD, which is what keeps the re-accumulation branch from ever running.
    if (index >= 26) {
      const fastTs = new Date(BASE_MS + index * HOUR_MS + 30 * 60 * 1000).toISOString();
      const fast = await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), structuralCollectors: collectors, ts: fastTs, now: fastTs, ...observers });
      assert.equal(fast.structuralFacts, undefined, "the half-hour tick must not be a structural tick");
      tick.fastStatus = fast.status.fact_store_completeness?.status;
    }
    ticks.push(tick);
  }

  // Precondition: the generated tick is real-host-sized and the store is at its 5 MB default.
  assert.ok(ticks[0].written >= 700, `expected ~722 records per tick, got ${ticks[0].written}`);
  const firstEviction = ticks.find((tick) => tick.bytecapEvicted > 0);
  assert.ok(firstEviction, "the 5 MB default store must start byte-evicting within 40 real-volume ticks");
  assert.ok(firstEviction.index >= 20 && firstEviction.index <= 30, `eviction should start near tick 28 (5 MB / ~185 KB), started at ${firstEviction.index}`);
  assert.equal(DEFAULT_FACT_MAX_BYTES, 5 * 1024 * 1024);
  const afterEviction = ticks.filter((tick) => tick.index > firstEviction.index);
  assert.ok(afterEviction.length >= 8);
  // Eviction is routine: it keeps happening on every structural tick once full.
  for (const tick of afterEviction) assert.ok(tick.bytecapEvicted > 0, `tick ${tick.index} should byte-evict`);

  // Every lockout symptom is collected (not fail-fast) so a red run shows all three legs at once.
  const problems = [];
  // Leg A: the daemon's own (no-anchor) history read must not read degraded merely because the
  // store byte-evicted -- on structural AND fast ticks.
  for (const tick of afterEviction) {
    if (tick.status !== "intact") problems.push(`Leg A: tick ${tick.index} daemon fact-history read is ${tick.status}`);
    if (tick.fastStatus !== undefined && tick.fastStatus !== "intact") problems.push(`Leg A: tick ${tick.index}+30m fast-tick history read is ${tick.fastStatus}`);
  }
  // Leg B: no detector's cold-start anchor re-arms hourly; each family is established well before
  // eviction starts and stays established through it.
  const last = ticks[ticks.length - 1];
  for (const [family, anchor] of Object.entries(last.anchors)) {
    if (anchor.pending !== false) problems.push(`Leg B: ${family} detector still cold-start pending at tick ${last.index} (anchor ${anchor.since})`);
  }
  for (const tick of afterEviction) {
    for (const [family, anchor] of Object.entries(tick.anchors)) {
      if (anchor.since === tick.ts) problems.push(`Leg B: ${family} cold-start anchor re-armed to tick ${tick.index} after a byte-cap eviction`);
    }
  }
  // Leg C: the converted watch-tier producers keep reporting coverage while eviction continues.
  for (const tick of afterEviction) {
    for (const label of ["service", "service-appearance", "process-lineage", "scheduled-job"]) {
      if (!((tick.coverage[label] ?? 0) > 0)) problems.push(`Leg C: tick ${tick.index} ${label} reported no evaluated alert keys`);
    }
  }
  assert.deepEqual(problems, [], `watch-tier lockout under routine byte-cap eviction:\n${problems.join("\n")}`);
});
