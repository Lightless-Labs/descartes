// T9 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §8, §4.5, §15.4): the read-cost
// guard. Every fact-store read one FAST daemon tick makes (watch AND learned on, an active
// constraint present, so every fast-tick reader actually reads: the daemon's per-family history
// veto, the eight watch/learned detectors, correlation, canary, active-constraint and
// provenance-warning) is captured from the real tick, then costed at every family's DEFAULT budget
// plus a full-size seen-set for each seen-set read (S3b/G2 question 8). A budget increase, a new
// fast-tick reader, or a reader that widens to more families moves this number and must stay under
// the bound -- or be argued for in review with the new figure (§4.5 read-cost decision rule).
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { buildConstraintTarget, writeConstraints, writeLearnedConfig } from "../src/constraint-store.js";
import { writeWatchConfig } from "../src/watch-store.js";
import { readFactPoints } from "../src/fact-store.js";
import { FACT_FAMILY_IDS, FAMILY_DEFAULT_BUDGET_BYTES, NOVELTY_FAMILIES } from "../src/fact-families.js";
import { DEFAULT_SEEN_SET_MAX_ENTRIES } from "../src/novelty-seen-set.js";
import { resolveDescartesPaths } from "../src/paths.js";

const NOW = "2026-05-24T00:00:00.000Z";
const MIB = 1024 * 1024;
// §2/§15.4: readFactPoints parses and prefix-hashes the whole file, measured at ~74 ms for 5 MB and
// ~235 ms for 16 MB on the dev machine -> ~15 ms per MiB (the §15.4 interpolation). A seen-set read
// is a JSON.parse of the set file, costed at the same rate (conservative: no line splitting/hashing).
const MS_PER_MIB = 15;
const READ_COST_BOUND_MS = 5_000;

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-read-cost-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function envelope(id, tool, result) {
  return { id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: NOW } };
}

function activeConstraint() {
  return {
    id: "constraint.mined.service-presence.cafebabecafebabe",
    kind: "constraint",
    family: "service-presence",
    target: buildConstraintTarget("service.presence", "nginx.service"),
    expected: { comparator: "eq", value: "true" },
    status: "active",
    confidence: 1,
    provenance: { window: "7d", samples: 5, source_collectors: ["services"], mined_at: NOW },
    fixtures: [
      { input: { "service.presence": "true" }, expect_match: true },
      { input: { "service.presence": "false" }, expect_match: false },
    ],
    promotion_history: [
      { ts: "2026-05-22T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" },
      { ts: "2026-05-23T00:00:00.000Z", from: "shadow", to: "review-ready", actor: "deterministic-gate", note: "soak complete" },
      { ts: NOW, from: "review-ready", to: "active", actor: "human:alice", note: "approved" },
    ],
    first_observed: "2026-05-22T00:00:00.000Z",
    last_verified: NOW,
    sensitivity: "operational",
    schema_version: 1,
  };
}

// The largest seen-set file the cap allows: DEFAULT_SEEN_SET_MAX_ENTRIES entries with 64-character
// keys (sanitized service identities are bounded at 64; lineage/job keys are fixed-length hashes).
function maxSeenSetBytes() {
  const iso = "2026-05-24T00:00:00.000Z";
  const entries = {};
  for (let index = 0; index < DEFAULT_SEEN_SET_MAX_ENTRIES; index += 1) entries[String(index).padStart(64, "k")] = [iso, iso];
  return Buffer.byteLength(`${JSON.stringify({ schema_version: 1, family: "process_lineage", ledger_generation: "x".repeat(36), ledger_pass_id: 1, certified_since_ts: iso, folded_through_ts: iso, overflow: false, entries })}\n`);
}

test("T9: one fast tick's fact-store reads, costed at every family's default budget plus full-size seen-sets, stay under the read-cost bound", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraint()]);
  const reads = [];
  await runDaemonIteration(paths, {
    profile: { interval_ms: 60_000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } } },
    collectors: {
      system: async () => envelope("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
      processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
      disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
    },
    ts: NOW,
    now: NOW,
    readFactPoints: async (descartesPaths, options) => {
      reads.push({ families: options.family !== undefined ? [options.family] : [...options.families], seenSetFamilies: [...(options.seenSetFamilies ?? [])] });
      return readFactPoints(descartesPaths, options);
    },
  });

  // Every read names registered families only; seen-sets only for novelty families it reads.
  for (const read of reads) {
    for (const family of read.families) assert.ok(FACT_FAMILY_IDS.includes(family), family);
    for (const family of read.seenSetFamilies) assert.ok(NOVELTY_FAMILIES.has(family) && read.families.includes(family));
  }
  // The reader inventory this tick (§15.2 fast-tick readers), so a new or widened reader is visible.
  const perFamily = Object.fromEntries(FACT_FAMILY_IDS.map((family) => [family, reads.filter((read) => read.families.includes(family)).length]));
  assert.deepEqual(perFamily, {
    service: 4, // daemon veto, service.disappeared, service.appeared, active-constraint
    process_lineage: 2, // daemon veto, detector
    scheduled_job: 2, // daemon veto, detector
    session: 2, // daemon veto, detector
    peer: 3, // daemon veto, detector, correlation
    canary: 2, // daemon veto, detector
    network: 1, // active-constraint
    provenance: 1, // provenance-warning
    // Context families (context plan C0) are DATA only: no fast-tick reader yet.
    host_lifecycle: 0,
    network_context: 0,
    session_context: 0,
  });
  const seenSetReads = reads.reduce((sum, read) => sum + read.seenSetFamilies.length, 0);
  assert.equal(seenSetReads, 6, "the daemon veto and the three novelty detectors each read their family's seen-set");

  const factBytes = reads.reduce((sum, read) => sum + read.families.reduce((inner, family) => inner + FAMILY_DEFAULT_BUDGET_BYTES.get(family), 0), 0);
  const seenSetBytes = seenSetReads * maxSeenSetBytes();
  const costMs = ((factBytes + seenSetBytes) / MIB) * MS_PER_MIB;
  assert.ok(costMs < READ_COST_BOUND_MS, `fast-tick read cost ${Math.round(costMs)} ms (facts ${Math.round(factBytes / MIB)} MiB, seen-sets ${Math.round(seenSetBytes / MIB)} MiB) exceeds the ${READ_COST_BOUND_MS} ms bound`);
  // Pin the current figure loosely so a large silent increase is noticed (§15.4 estimated ~2.1 s
  // without the active-constraint service read and the seen-sets).
  assert.ok(costMs > 2_000 && costMs < 3_500, `expected ~2.9 s at the S0-revised budgets, got ${Math.round(costMs)} ms`);
});
