// T10 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §8, §4.6 M2/M3): an install
// that is ALREADY locked out on the pre-S4 shared store upgrades cleanly.
//
// Fixture: the legacy learned/facts/facts.jsonl + a v1 integrity.json carrying an in-window
// last_bytecap_evict_ts (the 31-day degraded tail of §3 Leg A), the pre-S4 seen-sets/, and every
// watch-tier detector store cold-start pending on an old anchor (§3 Leg B). Then clean hourly
// structural ticks on the real daemon path. Asserts: the legacy store is quarantined OUTSIDE
// learned/facts/ and never read again; the per-family stores start fresh with no 31-day tail; the
// lockout clears within 8 structural ticks; the count rules (30 samples) establish within 32; the
// novelty rules are reported horizon-short from the upgrade until their Q2 horizons (48 h / 48 h /
// 6 d) are met, never eligible over a 30-day scope the quarantine discarded (G2 H1, §4.6 M2
// addendum); and provenance-warnings still produces deleted_exe_running candidates from its own
// family store.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { alertId } from "../src/alert-store.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { appendFactPointsByFamily, readFactPoints } from "../src/fact-store.js";
import { FACT_FAMILY_IDS, NOVELTY_FAMILIES } from "../src/fact-families.js";
import { noveltyRuleEligible } from "../src/fact-store-completeness.js";
import { resolveLegacyFactStorePaths } from "../src/fact-store-migration.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { computeServiceAppearanceCandidates, computeServiceBaselineCandidates, loadServiceAppearanceBaselineStore, loadServiceBaselineStore, SERVICE_APPEARED_RULE_ID, writeServiceAppearanceBaselineStore, writeServiceBaselineStore } from "../src/service-baseline.js";
import { computeProcessLineageBaselineCandidates, loadProcessLineageBaselineStore, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, writeProcessLineageBaselineStore } from "../src/process-lineage-baseline.js";
import { computeScheduledJobBaselineCandidates, loadPersistenceBaselineStore, SCHEDULED_JOB_APPEARED_RULE_ID, writePersistenceBaselineStore } from "../src/persistence-baseline.js";
import { computeSessionBaselineCandidates, SESSION_COUNT_DROP_RULE_ID, writeSessionBaselineStore } from "../src/session-baseline.js";
import { computePeerBaselineCandidates, PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_VPN_FINGERPRINT, writePeerBaselineStore } from "../src/peer-baseline.js";
import { computeProvenanceWarningCandidates, DELETED_EXE_RULE_ID } from "../src/tools/provenance-warnings.js";
import { realVolumeStructuralCollectors } from "./fixtures/real-volume-tick.js";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const BASE_MS = Date.parse("2026-10-06T00:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();
const NOVELTY_FAMILY_IDS = [...NOVELTY_FAMILIES.keys()];
const NOVELTY_RULE_IDS = [...NOVELTY_FAMILIES.values()].map((entry) => entry.ruleId);

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-locked-out-upgrade-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function fastCollectorFakes() {
  const env = (id, tool, result) => ({ id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: iso(BASE_MS) } });
  return {
    system: async () => env("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => env("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => env("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

// The pre-S4 shared store exactly as a locked-out host left it: a full 5 MB-era store whose v1 ledger
// byte-evicted 2 h ago (in-window: §3 Leg A would read it `degraded` for 31 days).
async function seedLockedOutLegacyStore(paths) {
  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(path.join(factsRootDir, "seen-sets"), { recursive: true });
  const legacyFacts = Array.from({ length: 4 }, (_, index) => JSON.stringify({
    ts: iso(BASE_MS - (4 - index) * HOUR_MS), fact_name: "service.presence", entity_key: `legacy-${index}`, attributes: { running: "true" }, sensitivity: "operational",
  })).join("\n");
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${legacyFacts}\n`);
  const evictTs = iso(BASE_MS - 2 * HOUR_MS);
  await fs.writeFile(path.join(factsRootDir, "integrity.json"), JSON.stringify({
    generation: "legacy-generation",
    schema_version: 1,
    corrupt_dropped_total: 0,
    schema_invalid_dropped_total: 0,
    bytecap_evicted_total: 12_345,
    age_evicted_total: 0,
    last_corrupt_ts: null,
    last_schema_invalid_ts: null,
    last_bytecap_evict_ts: evictTs,
    last_continuity_break_ts: null,
    first_degraded_ts: evictTs,
    continuity: { record_count_hwm: 20_000, oldest_ts: iso(BASE_MS - 30 * DAY_MS), last_rewrite_record_count: 4, last_rewrite_newest_ts: iso(BASE_MS - HOUR_MS), last_rewrite_bytes: legacyFacts.length + 1, output_digest: null, last_committed_pass_id: 9_999, continuity_ok: true, pending_pass: null },
    future_fact_dropped_total: 0,
    last_future_fact_ts: null,
  }, null, 2));
  await fs.writeFile(path.join(factsRootDir, "seen-sets", "service.json"), "{\"legacy\":true}\n");
}

async function seedLockedOutDetectors(paths) {
  const oldAnchor = iso(BASE_MS - 20 * DAY_MS);
  const pending = { cold_start_pending: true, cold_start_since_ts: oldAnchor };
  await writeServiceBaselineStore(paths, pending);
  await writeServiceAppearanceBaselineStore(paths, pending);
  await writeProcessLineageBaselineStore(paths, pending);
  await writePersistenceBaselineStore(paths, pending);
  await writeSessionBaselineStore(paths, pending);
  await writePeerBaselineStore(paths, pending);
}

test("T10: an already-locked-out install upgrades: legacy quarantined outside learned/facts/ and unread, no 31-day tail, lockout clears within 8 structural ticks, count rules establish within 32, novelty horizon-short until its Q2 horizon, provenance-warnings still fires", { timeout: 300_000 }, async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await seedLockedOutLegacyStore(paths);
  await seedLockedOutDetectors(paths);
  const { factsRootDir, learnedDir } = resolveLegacyFactStorePaths(paths);
  const legacyIntegrity = await fs.readFile(path.join(factsRootDir, "integrity.json"), "utf8");

  const { collectors, structuralCollectorToggles } = realVolumeStructuralCollectors({ scale: 0.2 });
  const profile = {
    interval_ms: 60_000,
    collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
    structural: { interval_ms: HOUR_MS, collectors: structuralCollectorToggles },
  };
  const coverage = new Map();
  const observe = (label, compute) => async (...args) => {
    const result = await compute(...args);
    coverage.set(label, Array.isArray(result?.evaluatedAlertKeys) ? result.evaluatedAlertKeys : []);
    return result;
  };
  const observers = {
    computeServiceBaselineCandidates: observe("service", computeServiceBaselineCandidates),
    computeServiceAppearanceCandidates: observe("service-appearance", computeServiceAppearanceCandidates),
    computeProcessLineageBaselineCandidates: observe("process-lineage", computeProcessLineageBaselineCandidates),
    computeScheduledJobBaselineCandidates: observe("scheduled-job", computeScheduledJobBaselineCandidates),
    computeSessionBaselineCandidates: observe("session", computeSessionBaselineCandidates),
    computePeerBaselineCandidates: observe("peer", computePeerBaselineCandidates),
  };

  let lockoutClearedAt;
  let countRulesAt;
  const statusProblems = [];
  const noveltyProblems = [];
  let lastResult;
  for (let index = 0; index < 34; index += 1) {
    const ts = iso(BASE_MS + index * HOUR_MS);
    coverage.clear();
    const result = await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), structuralCollectors: collectors, ts, now: ts, ...observers });
    assert.ok(result.structuralFacts?.written_count > 0, `tick ${index} is a structural tick`);
    lastResult = result;
    if (index === 0) {
      // M3: quarantined before any per-family write, outside the facts tree.
      assert.equal(result.status.fact_store_legacy.status, "quarantined");
      const quarantine = path.join(learnedDir, result.status.fact_store_legacy.quarantine_dir);
      assert.equal(path.dirname(quarantine), learnedDir);
      for (const item of ["facts.jsonl", "integrity.json", "seen-sets"]) {
        assert.equal(await fs.stat(path.join(quarantine, item)).then(() => true), true, `${item} quarantined`);
      }
      assert.equal(await fs.readFile(path.join(quarantine, "integrity.json"), "utf8"), legacyIntegrity, "never read-modified");
    }
    // Only registry family directories live under learned/facts/ from now on.
    for (const name of await fs.readdir(factsRootDir)) assert.ok(FACT_FAMILY_IDS.includes(name), `unexpected ${name} under learned/facts/`);
    // No 31-day tail: once a family store has committed its first passes, it is never `degraded`
    // (the legacy byte-cap marker did not travel with it -- fresh per-family stores, M2/I8).
    for (const [family, entry] of Object.entries(result.status.fact_store_completeness?.families ?? {})) {
      if (entry.status === "degraded") statusProblems.push(`tick ${index}: ${family} reads degraded (${entry.degraded_reason})`);
      if (index >= 2 && entry.store === "present" && entry.status !== "intact") statusProblems.push(`tick ${index}: ${family} reads ${entry.status}`);
    }
    // The lockout (§3 Leg B: every watch-tier detector cold-start pending) clears on all four stores,
    // and the non-novelty rule (service.disappeared) evaluates again.
    const watchTierClear = (await Promise.all([
      loadServiceBaselineStore(paths), loadServiceAppearanceBaselineStore(paths), loadProcessLineageBaselineStore(paths), loadPersistenceBaselineStore(paths),
    ])).every((store) => store.state.cold_start_pending === false)
      && (coverage.get("service") ?? []).length > 0;
    if (watchTierClear && lockoutClearedAt === undefined) lockoutClearedAt = index;
    // G2 H1 (§4.6 M2 addendum): the legacy store's sightings were quarantined, so novelty memory is
    // certified only from the upgrade (tick 0). The three novelty rules stay horizon-SHORT (48 h /
    // 48 h / 6 d) for this whole 34-tick run -- reported, never silently eligible over a 30-day scope
    // -- with the since_ts carried from the first tick, and they evaluate nothing.
    if (index >= 1) {
      for (const ruleId of NOVELTY_RULE_IDS) {
        const since = result.status.history_horizon_short?.rules?.[ruleId]?.since_ts;
        if (since !== iso(BASE_MS)) noveltyProblems.push(`tick ${index}: ${ruleId} horizon-short since ${since}`);
      }
      for (const family of NOVELTY_FAMILY_IDS) {
        const since = result.status.fact_store_completeness?.families?.[family]?.horizon_short_since;
        if (since !== iso(BASE_MS)) noveltyProblems.push(`tick ${index}: ${family} horizon_short_since ${since}`);
      }
      for (const label of ["service-appearance", "process-lineage", "scheduled-job"]) {
        if ((coverage.get(label) ?? []).length > 0) noveltyProblems.push(`tick ${index}: ${label} evaluated while horizon-short`);
      }
    }
    const countRules = (coverage.get("session") ?? []).includes(alertId(SESSION_COUNT_DROP_RULE_ID, "v2:tmux"))
      // Merge (R8 identities): marker-backed peer counts evaluate under v2:vpn, never legacy "global".
      && (coverage.get("peer") ?? []).includes(alertId(PEER_COUNT_DROP_RULE_ID, PEER_COUNT_VPN_FINGERPRINT))
      && (coverage.get("peer") ?? []).includes(alertId(PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_VPN_FINGERPRINT));
    if (countRules && countRulesAt === undefined) countRulesAt = index;
  }
  assert.deepEqual(statusProblems, []);
  assert.deepEqual(noveltyProblems, []);
  assert.ok(lockoutClearedAt !== undefined && lockoutClearedAt < 8, `the watch-tier lockout must clear within 8 structural ticks (cleared at ${lockoutClearedAt})`);
  assert.ok(countRulesAt !== undefined && countRulesAt < 32, `the 30-sample count rules must establish within 32 structural ticks (at ${countRulesAt})`);

  // A stated consequence (§4.6 M2 addendum): short for more than N = 24 structural intervals, the
  // fixed operator signal fires on an upgraded host and names the three novelty rules.
  const signal = lastResult.alerts.alerts.find((alert) => alert.rule_id === "daemon.fact_history.horizon_short");
  assert.equal(signal?.status, "active", "the horizon-short signal is raised, not silent");
  for (const ruleId of NOVELTY_RULE_IDS) assert.ok(String(signal.diagnostics.rule_ids).includes(ruleId), `the signal names ${ruleId}`);

  // ...and the novelty horizons recover exactly on schedule, measured from the upgrade: the seen-sets
  // are valid, scoped to the upgrade (never 30 days back), and eligible once their Q2 horizon is met.
  const lastNowMs = BASE_MS + 33 * HOUR_MS;
  for (const [family, ruleId, horizonMs] of [["service", SERVICE_APPEARED_RULE_ID, 48 * HOUR_MS], ["scheduled_job", SCHEDULED_JOB_APPEARED_RULE_ID, 48 * HOUR_MS], ["process_lineage", PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, 6 * DAY_MS]]) {
    const read = await readFactPoints(paths, { family, windowMs: 31 * DAY_MS, now: lastNowMs, seenSetFamilies: [family] });
    assert.equal(read.seen_sets[family].status, "valid", `${family} seen-set valid`);
    assert.equal(read.seen_sets[family].certified_since_ts, iso(BASE_MS), `${family} memory certified from the upgrade only`);
    assert.equal(read.seen_sets[family].scope_ts, iso(BASE_MS), `${family} claim scope is the upgrade, not 30 days back`);
    assert.equal(noveltyRuleEligible(read, ruleId, BASE_MS + horizonMs - 1), false, `${ruleId} short just before its horizon`);
    assert.equal(noveltyRuleEligible(read, ruleId, BASE_MS + horizonMs), true, `${ruleId} eligible once its horizon is met`);
  }

  // provenance-warnings reads its own family store after the upgrade (§4.3; Q8 keeps the store).
  const now = iso(BASE_MS + 34 * HOUR_MS);
  await appendFactPointsByFamily(paths, [{
    ts: now,
    fact_name: "provenance.warning",
    entity_key: "deleted_exe_running.process.4821",
    attributes: { rule_id: "deleted_exe_running", active: "true", pid: "4821", executable_path_hash: "abc0123456789def", source_type: "shell", confidence: "1", severity: "high" },
  }], { now });
  const candidates = await computeProvenanceWarningCandidates(paths, { now });
  assert.ok(candidates.some((candidate) => candidate.rule_id === DELETED_EXE_RULE_ID), "deleted_exe_running still produces a candidate after the upgrade");
});
