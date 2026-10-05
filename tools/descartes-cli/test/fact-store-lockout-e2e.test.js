// T1 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §8): end-to-end lockout at
// real per-tick volume, on the real daemon path (runDaemonIteration -> real translators -> real
// fact store at its 5 MB default -> real detectors -> computeCoveredAlerts).
//
// The daemon's own history read remains usable when byte-cap eviction narrows coverage. Since S3b
// (plan §17) the three novelty paths decide against their first/last-seen set, which the same
// retention pass folds and which eviction never touches (I13): with the set valid they keep
// evaluating through routine eviction instead of re-arming (the S2-interim behavior this test pinned
// before S3b: re-arm on every narrowed structural read, no evaluated keys).
//
// S4 (per-family stores, §4.3/§4.5): the default budgets (service 18 MiB, ...) would not byte-evict
// within 40 real-volume ticks, and watch.json cannot configure a budget below the T8 horizon floor,
// so this test forces routine eviction through the daemon's TEST-ONLY `factStoreBudgets` seam: the
// three novelty families' stores are sized to fill after ~27 real-volume ticks (like the old shared
// 5 MB store did) and then evict on every structural tick.
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
import { FAMILY_DEFAULT_BUDGET_BYTES } from "../src/fact-families.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { computeServiceAppearanceCandidates, computeServiceBaselineCandidates, loadServiceBaselineStore } from "../src/service-baseline.js";
import { computeProcessLineageBaselineCandidates, loadProcessLineageBaselineStore } from "../src/process-lineage-baseline.js";
import { computeScheduledJobBaselineCandidates, loadPersistenceBaselineStore } from "../src/persistence-baseline.js";
import { realVolumeStructuralCollectors } from "./fixtures/real-volume-tick.js";

const HOUR_MS = 60 * 60 * 1000;
const BASE_MS = Date.parse("2026-10-01T00:00:00.000Z");
const STRUCTURAL_TICKS = 40;
const MIB = 1024 * 1024;
// ~27 ticks of each novelty family at the generated tick's volume (service ~132 KB, lineage ~44 KB,
// scheduled_job ~2.6 KB per tick); every other family keeps its default budget.
const FORCED_BUDGETS = {
  ...Object.fromEntries(FAMILY_DEFAULT_BUDGET_BYTES),
  service: 3.5 * MIB,
  process_lineage: 1.15 * MIB,
  scheduled_job: 0.07 * MIB,
};
const EVICTING_FAMILIES = ["service", "process_lineage", "scheduled_job"];

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

test("T1: at real per-tick volume with the novelty family stores forced to fill, routine byte-cap eviction does not lock the watch tier out (no 31-day degraded tail, no hourly anchor re-arm, coverage keeps being reported)", { timeout: 300_000 }, async () => {
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
      factStoreBudgets: FORCED_BUDGETS,
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
      bytecapEvicted: Math.min(...EVICTING_FAMILIES.map((family) => structural.structuralFacts?.families?.[family]?.retention?.bytecap_evicted_count ?? 0)),
      written: structural.structuralFacts?.written_count ?? 0,
      status: structural.status.fact_store_completeness?.status,
      familyStatus: Object.fromEntries(EVICTING_FAMILIES.map((family) => [family, structural.status.fact_store_completeness?.families?.[family]?.status])),
      seenSets: structural.status.novelty_seen_sets,
      coverage: Object.fromEntries(coverage),
      anchors: Object.fromEntries(Object.entries(anchors).map(([key, state]) => [key, { pending: state.cold_start_pending, since: state.cold_start_since_ts }])),
    };
    // A fast tick between structural ticks (structural not due): Leg A keeps trust false here on
    // HEAD, which is what keeps the re-accumulation branch from ever running.
    if (index >= 26) {
      const fastTs = new Date(BASE_MS + index * HOUR_MS + 30 * 60 * 1000).toISOString();
      const fast = await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), structuralCollectors: collectors, ts: fastTs, now: fastTs, factStoreBudgets: FORCED_BUDGETS, ...observers });
      assert.equal(fast.structuralFacts, undefined, "the half-hour tick must not be a structural tick");
      tick.fastStatus = fast.status.fact_store_completeness?.status;
      tick.fastSeenSets = fast.status.novelty_seen_sets;
    }
    ticks.push(tick);
  }

  // Precondition: the generated tick is real-host-sized and EVERY novelty family store evicts.
  assert.ok(ticks[0].written >= 700, `expected ~722 records per tick, got ${ticks[0].written}`);
  const firstEviction = ticks.find((tick) => tick.bytecapEvicted > 0);
  assert.ok(firstEviction, "the forced novelty-family stores must all start byte-evicting within 40 real-volume ticks");
  assert.ok(firstEviction.index >= 20 && firstEviction.index <= 32, `eviction should start near tick 27, started at ${firstEviction.index}`);
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
    for (const [family, status] of Object.entries(tick.familyStatus)) {
      if (status !== "intact") problems.push(`Leg A: tick ${tick.index} ${family} store read is ${status}`);
    }
    if (tick.fastStatus !== undefined && tick.fastStatus !== "intact") problems.push(`Leg A: tick ${tick.index}+30m fast-tick history read is ${tick.fastStatus}`);
  }
  // Leg B: no detector re-arms on byte-cap eviction -- the ordinary service baseline AND (S3b) the
  // novelty paths, whose seen-sets stay valid through eviction.
  const last = ticks[ticks.length - 1];
  for (const [family, anchor] of Object.entries(last.anchors)) {
    if (anchor.pending !== false) problems.push(`Leg B: ${family} detector unexpectedly cold-start pending at tick ${last.index} (anchor ${anchor.since})`);
  }
  for (const tick of afterEviction) {
    for (const [family, anchor] of Object.entries(tick.anchors)) {
      if (anchor.since === tick.ts) problems.push(`Leg B: ${family} anchor re-armed to tick ${tick.index} after a byte-cap eviction`);
    }
    for (const family of ["service", "process_lineage", "scheduled_job"]) {
      if (tick.seenSets?.[family]?.status !== "valid") problems.push(`Leg B: tick ${tick.index} ${family} seen-set is ${tick.seenSets?.[family]?.status}`);
      if (tick.fastSeenSets !== undefined && tick.fastSeenSets?.[family]?.status !== "valid") problems.push(`Leg B: tick ${tick.index}+30m ${family} seen-set is ${tick.fastSeenSets?.[family]?.status}`);
    }
  }
  // Leg C: every converted watch-tier producer keeps reporting coverage through routine eviction.
  for (const tick of afterEviction) {
    for (const label of ["service", "service-appearance", "process-lineage", "scheduled-job"]) {
      if (!((tick.coverage[label] ?? 0) > 0)) problems.push(`Leg C: tick ${tick.index} ${label} reported no evaluated alert keys`);
    }
  }
  assert.deepEqual(problems, [], `watch-tier lockout under routine byte-cap eviction:\n${problems.join("\n")}`);
});
