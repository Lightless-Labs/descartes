// S3b (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §17): the per-novelty-family
// first/last-seen set. Fold rule, read-side validation, lineage, overflow, I13/I14, the G1
// reproduction, and the daemon referent.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { appendFactPoints, enforceFactRetention, normalizeFactPoint, readFactPoints } from "../src/fact-store.js";
import { resolveFactIntegrityPaths } from "../src/fact-store-integrity.js";
import {
  groupNoveltyFamilyTicks,
  readSeenSetFile,
  resolveSeenSetPaths,
  seenBeforeTick,
} from "../src/novelty-seen-set.js";
import { noveltyRuleEligible } from "../src/fact-store-completeness.js";
import { groupServiceFactsByTick, computeServiceAppearanceCandidates, detectServiceAppearances, loadServiceAppearanceBaselineStore, writeServiceAppearanceBaselineStore, SERVICE_APPEARED_RULE_ID } from "../src/service-baseline.js";
import { groupProcessLineageFactsByTick } from "../src/process-lineage-baseline.js";
import { groupScheduledJobFactsByTick } from "../src/persistence-baseline.js";
import { writeWatchConfig } from "../src/watch-store.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { alertId, writeAlertRecords } from "../src/alert-store.js";
import { runDaemonIteration } from "../src/daemon.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const BASE = Date.parse("2026-10-01T00:00:00.000Z");
const at = (hours) => new Date(BASE + hours * HOUR).toISOString();

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-seen-set-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function presence(ts, key, factName = "service.presence") {
  return { ts, fact_name: factName, entity_key: key, attributes: { running: "true" }, source_tool: "test" };
}

function marker(ts, state = "complete", factName = "service.census") {
  return { ts, fact_name: factName, entity_key: "census-marker", attributes: { census_state: state }, source_tool: "test", confidence: 0 };
}

function serviceTick(ts, keys, state = "complete") {
  return [...keys.map((key) => presence(ts, key)), marker(ts, state)];
}

function tickBytes(points) {
  return points.reduce((sum, point) => sum + Buffer.byteLength(`${JSON.stringify(normalizeFactPoint(point))}\n`), 0);
}

async function seenEntries(paths, family = "service") {
  const { set } = await readSeenSetFile(paths, family);
  return set ? set.entries : undefined;
}

test("grouping parity: the leaf grouper matches each detector's own grouper on complete, partial, unknown, contradictory and markerless ticks", () => {
  const families = [
    ["service", "service.presence", "service.census", groupServiceFactsByTick],
    ["process_lineage", "process.lineage_edge", "process.lineage_edge.census", groupProcessLineageFactsByTick],
    ["scheduled_job", "scheduled_job.presence", "scheduled_job.census", groupScheduledJobFactsByTick],
  ];
  for (const [family, presenceName, censusName, detectorGrouper] of families) {
    const points = [
      presence(at(0), "a", presenceName), presence(at(0), "b", presenceName), marker(at(0), "complete", censusName),
      presence(at(1), "a", presenceName), marker(at(1), "partial", censusName),
      presence(at(2), "a", presenceName), marker(at(2), "garbled", censusName),
      presence(at(3), "a", presenceName), marker(at(3), "complete", censusName), marker(at(3), "partial", censusName),
      presence(at(4), "a", presenceName),
      presence(at(5), "c", presenceName), marker(at(5), "complete", censusName), marker(at(5), "complete", censusName),
      presence(at(6), "z", "unrelated.fact"), marker(at(6), "complete", censusName),
    ];
    const normalize = (groups) => groups.map((group) => ({ ts: group.ts, censusState: group.censusState, keys: [...group.entityKeys].sort() }));
    assert.deepEqual(normalize(groupNoveltyFamilyTicks(points, family)), normalize(detectorGrouper(points)), `${family} grouping parity`);
  }
});

test("seenBeforeTick: an entry whose only observation is the latest tick is novel; any other observation (earlier, or later after a rollback) is a prior sighting", () => {
  const latest = at(4);
  const entries = new Map([
    ["only-latest", { firstMs: Date.parse(latest), lastMs: Date.parse(latest) }],
    ["earlier", { firstMs: Date.parse(at(0)), lastMs: Date.parse(latest) }],
    ["future", { firstMs: Date.parse(at(10)), lastMs: Date.parse(at(12)) }],
  ]);
  assert.equal(seenBeforeTick(entries, "only-latest", latest), false);
  assert.equal(seenBeforeTick(entries, "earlier", latest), true);
  assert.equal(seenBeforeTick(entries, "future", latest), true, "future-dated entries surviving a rollback still suppress");
  assert.equal(seenBeforeTick(entries, "absent", latest), false);
  assert.equal(seenBeforeTick(undefined, "earlier", latest), false);
});

test("day 1: a genuine first run (absent store) seeds a VALID set with certified_since null, folded in the same pass as the append", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a", "b"]), { now: at(0) });
  const { set } = await readSeenSetFile(paths, "service");
  assert.equal(set.certified_since_ts, null);
  assert.deepEqual(Object.keys(set.entries).sort(), ["a", "b"]);
  const read = await readFactPoints(paths, { now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service", "process_lineage", "scheduled_job"] });
  assert.equal(read.seen_sets.service.status, "valid");
  assert.equal(read.seen_sets.process_lineage.status, "valid", "every novelty family's set is maintained, even with no facts");
  assert.equal(read.seen_sets.process_lineage.entry_count, 0);
});

test("fold rule: partial, unknown and markerless ticks are never folded; neither is a tick dated after the pass clock", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [
    ...serviceTick(at(0), ["complete-one"]),
    ...serviceTick(at(1), ["partial-only"], "partial"),
    ...serviceTick(at(2), ["unknown-only"], "garbled"),
    presence(at(3), "markerless-only"),
    ...serviceTick(at(5), ["future-only"]), // within the 6 h future tolerance, so the store keeps it
  ], { now: at(3) });
  assert.deepEqual(Object.keys(await seenEntries(paths)), ["complete-one"]);
});

test("I13: eviction from the fact store never changes a seen-set answer -- the same append sequence under a huge and a tiny budget yields identical entries and certified_since", async () => {
  const big = await tempPaths();
  const tiny = await tempPaths();
  for (let hour = 0; hour < 10; hour += 1) {
    const tick = serviceTick(at(hour), [`steady`, `rotating-${hour % 4}`, `once-${hour}`]);
    await appendFactPoints(big, tick, { now: at(hour), maxBytes: 10 * 1024 * 1024 });
    await appendFactPoints(tiny, tick, { now: at(hour), maxBytes: tickBytes(tick) + 10 });
  }
  const tinyRead = await readFactPoints(tiny, { now: at(9), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(tinyRead.completeness.coverage, "narrowed", "the tiny store really evicted");
  const bigSet = (await readSeenSetFile(big, "service")).set;
  const tinySet = (await readSeenSetFile(tiny, "service")).set;
  assert.deepEqual(tinySet.entries, bigSet.entries);
  assert.equal(tinySet.certified_since_ts, bigSet.certified_since_ts);
  assert.equal(tinyRead.seen_sets.service.status, "valid");
});

test("read validation: the set is valid only against the SAME ledger lineage and committed pass; a stale pass id, another generation, or a missing set is not", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a"]), { now: at(0) });
  const { file } = resolveSeenSetPaths(paths, "service");
  const stale = await fs.readFile(file, "utf8");
  await appendFactPoints(paths, serviceTick(at(1), ["a"]), { now: at(1) });
  const read = (now) => readFactPoints(paths, { now, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal((await read(at(1))).seen_sets.service.status, "valid");
  await fs.writeFile(file, stale);
  assert.equal((await read(at(1))).seen_sets.service.status, "lineage_mismatch", "a set from an older pass (e.g. its write was lost) is not valid");
  assert.equal((await read(at(1))).seen_sets.service.entries, undefined, "and carries no entries a detector could consult");
  await fs.rm(file);
  assert.equal((await read(at(1))).seen_sets.service.status, "missing");
  await fs.writeFile(file, "{not json");
  assert.equal((await read(at(1))).seen_sets.service.status, "invalid");
});

test("crash/lost fold: a tick kept at pass P whose fold write is lost, then byte-evicted at P+1, is still remembered (pre-eviction fold) -- the entity never reads as new later", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2, 3, 4].map((hour) => serviceTick(at(hour), hour === 1 ? ["base", "returner"] : ["base"]));
  const budget = tickBytes(ticks[2]) + tickBytes(ticks[3]) + 10;
  const { file } = resolveSeenSetPaths(paths, "service");
  await appendFactPoints(paths, ticks[0], { now: at(0), maxBytes: budget });
  const beforeP = await fs.readFile(file, "utf8");
  await appendFactPoints(paths, ticks[1], { now: at(1), maxBytes: budget }); // pass P keeps tick 1
  await fs.writeFile(file, beforeP); // ...but its fold write is "lost"
  await appendFactPoints(paths, ticks[2], { now: at(2), maxBytes: budget });
  await appendFactPoints(paths, ticks[3], { now: at(3), maxBytes: budget }); // tick 1 is evicted by now
  const read = await readFactPoints(paths, { now: at(3), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.ok(!read.points.some((point) => point.entity_key === "returner"), "tick 1 really was evicted");
  assert.equal(read.seen_sets.service.status, "valid", "the next pass re-seeded the set");
  assert.ok(read.seen_sets.service.entries.has("returner"), "the returner observed only in the lost-fold tick is still remembered");
  assert.equal(seenBeforeTick(read.seen_sets.service.entries, "returner", at(4)), true);
});

test("re-seed boundary: a set lost over a NARROWED store re-seeds with certified_since = the prior byte-cap floor (memory is complete only after it), and a re-bootstrapped ledger re-seeds at the pass time", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2, 3].map((hour) => serviceTick(at(hour), ["base"]));
  const budget = tickBytes(ticks[0]) * 2 + 10;
  for (let hour = 0; hour < 3; hour += 1) await appendFactPoints(paths, ticks[hour], { now: at(hour), maxBytes: budget });
  const before = await readFactPoints(paths, { now: at(2), windowMs: 31 * DAY });
  const floor = before.completeness.bytecap_floor_ts;
  assert.equal(floor, at(0));
  await fs.rm(resolveSeenSetPaths(paths, "service").file);
  await appendFactPoints(paths, ticks[3], { now: at(3), maxBytes: budget });
  const reseeded = (await readSeenSetFile(paths, "service")).set;
  assert.equal(reseeded.certified_since_ts, floor, "never null over a narrowed store: memory before the floor is gone");

  // Ledger deleted over a surviving store: the lineage breaks (HIGH-1), the set's generation no longer
  // matches, and the re-seed certifies nothing before the pass that re-bootstrapped.
  await fs.rm(resolveFactIntegrityPaths(paths).integrityFile);
  await appendFactPoints(paths, serviceTick(at(4), ["base"]), { now: at(4), maxBytes: budget });
  const afterBreak = (await readSeenSetFile(paths, "service")).set;
  assert.equal(afterBreak.certified_since_ts, at(4));
});

test("LOW-4 (S3b review): a complete tick appended at or below the byte-cap floor after a small clock rollback is still folded -- memory only ever suppresses a claim", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2].map((hour) => serviceTick(at(hour), ["base"]));
  const budget = tickBytes(ticks[0]) * 2 + 10;
  for (let hour = 0; hour < 3; hour += 1) await appendFactPoints(paths, ticks[hour], { now: at(hour), maxBytes: budget });
  const floor = (await readFactPoints(paths, { now: at(2), windowMs: 31 * DAY })).completeness.bytecap_floor_ts;
  assert.equal(floor, at(0));
  // The clock steps back below the floor (within the future tolerance, so no loss is stamped) and a
  // complete tick lands there: the store evicts it physically (below-floor), but it was observed.
  const rolledBack = new Date(Date.parse(at(0)) - HOUR / 2).toISOString();
  await appendFactPoints(paths, serviceTick(rolledBack, ["rb-only"]), { now: at(0), maxBytes: budget });
  const entries = await seenEntries(paths);
  assert.deepEqual(entries["rb-only"], [rolledBack, rolledBack], "the below-floor tick's observation is remembered");
});

test("overflow: a set past its cap is never silently truncated -- it reads as overflow (novelty ineligible), and a later pass whose seed fits recovers it", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a", "b", "c"]), { now: at(0), seenSetMaxEntries: 2 });
  const overflowed = await readFactPoints(paths, { now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service"], seenSetMaxEntries: 2 });
  assert.equal(overflowed.seen_sets.service.status, "overflow");
  assert.equal(overflowed.seen_sets.service.entries, undefined);
  assert.equal(noveltyRuleEligible({ ...overflowed, completeness: { ...overflowed.completeness, coverage: "narrowed", bytecap_floor_ts: at(-100) } }, SERVICE_APPEARED_RULE_ID, Date.parse(at(0))), false, "overflow under narrowing: ineligible");

  // The store ages the three-entity tick out; the next pass's seed fits under the cap again.
  const later = new Date(Date.parse(at(0)) + 31 * DAY).toISOString();
  await appendFactPoints(paths, serviceTick(later, ["a"]), { now: later, seenSetMaxEntries: 2 });
  const recovered = await readFactPoints(paths, { now: later, windowMs: 31 * DAY, seenSetFamilies: ["service"], seenSetMaxEntries: 2 });
  assert.equal(recovered.seen_sets.service.status, "valid");
  assert.deepEqual([...recovered.seen_sets.service.entries.keys()], ["a"]);
  // The recovery is a RE-SEED from the store's certified candidates, so its boundary is the re-seed
  // boundary: max(prior floors, loss markers). This store never byte-evicted or lost anything and the
  // prior pass had no age floor, so the seed holds every complete tick of the lineage: null is true.
  assert.equal(recovered.seen_sets.service.certified_since_ts, null);
});

test("expiry: an entry is dropped 30 days past its last sighting, and the claim scope never reaches further back than the retention", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["old", "keep"]), { now: at(0) });
  const later = new Date(BASE + 31 * DAY).toISOString();
  await appendFactPoints(paths, serviceTick(later, ["keep"]), { now: later });
  const read = await readFactPoints(paths, { now: later, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.deepEqual([...read.seen_sets.service.entries.keys()], ["keep"]);
  assert.equal(read.seen_sets.service.scope_ts, new Date(BASE + DAY).toISOString(), "scope = max(certified_since, now - 30 d)");
});

// ---------------------------------------------------------------------------------------------
// Detector level: the G1 reproduction (daybreak G1 blocker 1) and I14.
// ---------------------------------------------------------------------------------------------

async function g1Store() {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  const ticks = [
    serviceTick(at(0), ["base-a", "base-b", "returner"]),
    serviceTick(at(1), ["base-a", "base-b"]),
    serviceTick(at(2), ["base-a", "base-b"]),
    serviceTick(at(3), ["base-a", "base-b"]),
    serviceTick(at(4), ["base-a", "base-b", "returner"]),
  ];
  // Room for exactly t1..t4: t0 is byte-evicted when t4 lands.
  const budget = ticks.slice(1).reduce((sum, tick) => sum + tickBytes(tick), 0);
  for (let hour = 0; hour < 5; hour += 1) await appendFactPoints(paths, ticks[hour], { now: at(hour), maxBytes: budget });
  return paths;
}

test("G1 reproduction (S3b): returner at t0, absent t1-t3, back at t4 with t0 byte-evicted -> NO first-seen claim, while the gate is LIFTED (the detector evaluated and stayed established)", async () => {
  const paths = await g1Store();
  const read = await readFactPoints(paths, { now: at(4), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(read.completeness.coverage, "narrowed");
  assert.equal(read.completeness.bytecap_floor_ts, at(0), "t0 really was evicted");
  assert.ok(!read.points.some((point) => point.ts === at(0)));
  // Discriminating control: the retained window ALONE would fabricate the claim.
  const windowOnly = detectServiceAppearances(groupServiceFactsByTick(read.points), { nowMs: Date.parse(at(4)) });
  assert.deepEqual(windowOnly.map((entry) => entry.entity_key), ["returner"], "control: without the seen-set the narrowed window calls the returner new");

  const result = await computeServiceAppearanceCandidates(paths, { now: at(4) });
  assert.deepEqual(result.candidates, [], "the seen-set remembers t0: no fabricated first-seen claim");
  assert.ok(result.evaluatedAlertKeys.length > 0, "the interim full-coverage gate is lifted: the detector genuinely evaluated");
  assert.equal((await loadServiceAppearanceBaselineStore(paths)).state.cold_start_pending, false, "and did not re-arm on narrowing");
});

test("I14 (S3b): the same narrowed store with its seen-set lost re-arms and claims nothing -- never 'everything is new'", async () => {
  const paths = await g1Store();
  await fs.rm(resolveSeenSetPaths(paths, "service").file);
  const result = await computeServiceAppearanceCandidates(paths, { now: at(4) });
  assert.deepEqual(result.candidates, []);
  assert.deepEqual(result.evaluatedAlertKeys, [], "no valid set under narrowing: nothing evaluated");
  assert.equal((await loadServiceAppearanceBaselineStore(paths)).state.cold_start_pending, true, "loss of the set's continuity re-arms the lockout");
});

test("S3b: a genuinely NEW service still alerts through the seen-set (the set suppresses only prior sightings)", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  const ticks = [0, 1, 2, 3].map((hour) => serviceTick(at(hour), ["base"]));
  ticks.push(serviceTick(at(4), ["base", "brand-new"]));
  const budget = ticks.slice(1).reduce((sum, tick) => sum + tickBytes(tick), 0);
  for (let hour = 0; hour < 5; hour += 1) await appendFactPoints(paths, ticks[hour], { now: at(hour), maxBytes: budget });
  const result = await computeServiceAppearanceCandidates(paths, { now: at(4) });
  assert.deepEqual(result.candidates.map((candidate) => candidate.rule_id), [SERVICE_APPEARED_RULE_ID]);
  assert.equal(result.candidates[0].diagnostics.history_certified_after_ts, new Date(Date.parse(at(4)) - 30 * DAY).toISOString(), "scope: the seen-set's memory (max(certified_since, now - 30 d))");
});

test("S3b: a store older than the 30-day retention (age floor inside the 31 d detector window) keeps novelty evaluating with a valid seen-set -- the interim gate silenced it permanently", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  await appendFactPoints(paths, serviceTick(at(0), ["base"]), { now: at(0) });
  const start = BASE + 30 * DAY + HOUR;
  for (let hour = 0; hour < 5; hour += 1) {
    const ts = new Date(start + hour * HOUR).toISOString();
    await appendFactPoints(paths, serviceTick(ts, ["base"]), { now: ts });
  }
  const now = new Date(start + 4 * HOUR).toISOString();
  const read = await readFactPoints(paths, { now, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(read.completeness.coverage, "narrowed", "the age floor sits inside the 31 d window");
  assert.equal(read.completeness.bytecap_floor_ts, null, "no byte-cap eviction at all");
  const result = await computeServiceAppearanceCandidates(paths, { now });
  assert.ok(result.evaluatedAlertKeys.length > 0, "novelty still evaluates");
  assert.equal((await loadServiceAppearanceBaselineStore(paths)).state.cold_start_pending, false);
});

test("S3b: an injected read that carries no seen-set keeps the interim behavior -- full coverage still fires novelty", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  const points = [0, 1, 2, 3].flatMap((hour) => serviceTick(at(hour), ["base"])).concat(serviceTick(at(4), ["base", "new-one"]));
  const result = await computeServiceAppearanceCandidates(paths, {
    now: at(4),
    readFactPoints: async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact", coverage: "full" } }),
  });
  assert.equal(result.candidates.length, 1);
});

// ---------------------------------------------------------------------------------------------
// Daemon referent: the daemon's novelty veto uses the same predicate as the detectors.
// ---------------------------------------------------------------------------------------------

test("S3b daemon referent: on a narrowed store, a valid seen-set lets a covered service.appeared alert recover; with the set lost it stays frozen, and the status names the set's state", async () => {
  for (const loseSet of [false, true]) {
    const paths = await g1Store();
    await writeLearnedConfig(paths, { enabled: true });
    if (loseSet) await fs.rm(resolveSeenSetPaths(paths, "service").file);
    const fingerprint = "0123456789abcdef";
    await writeAlertRecords(paths, [{ rule_id: SERVICE_APPEARED_RULE_ID, fingerprint, status: "active", severity: "warning", title: "t", summary: "t", first_seen: at(4), last_seen: at(4), diagnostics: {} }]);
    const result = await runDaemonIteration(paths, {
      profile: { interval_ms: 60000, collectors: {} },
      collectors: {},
      ts: at(4),
      now: at(4),
      computeServiceAppearanceCandidates: async () => ({ candidates: [], evaluatedAlertKeys: [alertId(SERVICE_APPEARED_RULE_ID, fingerprint)] }),
    });
    const alert = result.alerts.alerts.find((entry) => entry.rule_id === SERVICE_APPEARED_RULE_ID);
    assert.equal(alert.status, loseSet ? "active" : "recovered");
    assert.equal(result.status.novelty_seen_sets.service.status, loseSet ? "missing" : "valid");
    assert.equal(Boolean(result.status.history_horizon_short?.rules?.[SERVICE_APPEARED_RULE_ID]), loseSet, "a lost set under narrowing is reported as novelty-ineligible");
  }
});

test("enforceFactRetention reports the fold outcome per family, and a fold failure is non-fatal to retention", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a"]), { now: at(0) });
  const ok = await enforceFactRetention(paths, { now: at(0) });
  assert.equal(ok.seen_set_fold.service.status, "folded");
  // Make the seen-set directory unwritable by replacing it with a file.
  const { dir } = resolveSeenSetPaths(paths, "service");
  await fs.rm(dir, { recursive: true });
  await fs.writeFile(dir, "not a directory");
  const failed = await enforceFactRetention(paths, { now: at(0) });
  assert.equal(failed.seen_set_fold.service.status, "error");
  assert.equal(failed.kept_count, 2, "retention itself still committed");
  const read = await readFactPoints(paths, { now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.notEqual(read.seen_sets.service.status, "valid", "an unwritten fold is never read as valid");
});

test("G1 reproduction (S3b) for process.lineage.novel_edge and scheduled_job.appeared: no first-seen claim for a returner whose earlier sighting was byte-evicted, with the detector still evaluating", async () => {
  const { computeProcessLineageBaselineCandidates, writeProcessLineageBaselineStore, loadProcessLineageBaselineStore } = await import("../src/process-lineage-baseline.js");
  const { computeScheduledJobBaselineCandidates, writePersistenceBaselineStore, loadPersistenceBaselineStore } = await import("../src/persistence-baseline.js");
  const cases = [
    ["process_lineage", "process.lineage_edge", "process.lineage_edge.census", writeProcessLineageBaselineStore, loadProcessLineageBaselineStore, computeProcessLineageBaselineCandidates],
    ["scheduled_job", "scheduled_job.presence", "scheduled_job.census", writePersistenceBaselineStore, loadPersistenceBaselineStore, computeScheduledJobBaselineCandidates],
  ];
  for (const [family, presenceName, censusName, writeStore, loadStore, compute] of cases) {
    const paths = await tempPaths();
    await writeWatchConfig(paths, { enabled: true });
    await writeStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
    const tick = (hour, keys) => [...keys.map((key) => presence(at(hour), key, presenceName)), marker(at(hour), "complete", censusName)];
    const ticks = [tick(0, ["base", "returner"]), tick(1, ["base"]), tick(2, ["base"]), tick(3, ["base"]), tick(4, ["base", "returner"])];
    const budget = ticks.slice(1).reduce((sum, points) => sum + tickBytes(points), 0);
    for (let hour = 0; hour < 5; hour += 1) await appendFactPoints(paths, ticks[hour], { now: at(hour), maxBytes: budget });
    const read = await readFactPoints(paths, { now: at(4), windowMs: 31 * DAY, seenSetFamilies: [family] });
    assert.equal(read.completeness.bytecap_floor_ts, at(0), `${family}: t0 evicted`);
    const result = await compute(paths, { now: at(4), minHistoryTickCount: 3, activeFreshnessMs: HOUR });
    assert.deepEqual(result.candidates, [], `${family}: no fabricated first-seen claim`);
    assert.ok(result.evaluatedAlertKeys.length > 0, `${family}: gate lifted, detector evaluated`);
    assert.equal((await loadStore(paths)).state.cold_start_pending, false, `${family}: no re-arm`);
  }
});

test("S3/S3b novelty horizon: with a valid seen-set the 48 h horizon is measured against the set's certified span -- short emits nothing, reports no coverage and never re-arms; met resumes on the same tick", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  const points = [0, 1, 2, 3].flatMap((hour) => serviceTick(at(hour), ["base"])).concat(serviceTick(at(4), ["base", "brand-new"]));
  const nowMs = Date.parse(at(4));
  const run = (certifiedSinceMs) => computeServiceAppearanceCandidates(paths, {
    now: at(4),
    readFactPoints: async () => ({
      points,
      corrupt_count: 0,
      schema_invalid_count: 0,
      completeness: { status: "intact", coverage: "narrowed", bytecap_floor_ts: at(-1), age_floor_ts: null },
      seen_sets: { service: { family: "service", status: "valid", certified_since_ts: new Date(certifiedSinceMs).toISOString(), scope_ts: new Date(certifiedSinceMs).toISOString(), entry_count: 0, entries: new Map() } },
    }),
  });
  const short = await run(nowMs - 47 * HOUR);
  assert.deepEqual(short.candidates, []);
  assert.deepEqual(short.evaluatedAlertKeys, []);
  assert.equal((await loadServiceAppearanceBaselineStore(paths)).state.cold_start_pending, false, "a short novelty horizon never re-arms (I5)");
  const met = await run(nowMs - 48 * HOUR);
  assert.equal(met.candidates.length, 1, "exactly 48 h of certified seen-set memory: the genuinely new service alerts");
  assert.ok(met.evaluatedAlertKeys.length > 0);
});
