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
import { computeProcessLineageBaselineCandidates, groupProcessLineageFactsByTick, writeProcessLineageBaselineStore, PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID } from "../src/process-lineage-baseline.js";
import { computeScheduledJobBaselineCandidates, groupScheduledJobFactsByTick, writePersistenceBaselineStore, SCHEDULED_JOB_APPEARED_RULE_ID } from "../src/persistence-baseline.js";
import { writeWatchConfig } from "../src/watch-store.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { migrateLegacyFactStore, resolveLegacyFactStorePaths } from "../src/fact-store-migration.js";
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
  await appendFactPoints(paths, serviceTick(at(0), ["a", "b"]), { family: "service", now: at(0) });
  const { set } = await readSeenSetFile(paths, "service");
  assert.equal(set.certified_since_ts, null);
  assert.deepEqual(Object.keys(set.entries).sort(), ["a", "b"]);
  const read = await readFactPoints(paths, { family: "service", now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(read.seen_sets.service.status, "valid");
  // S4: each novelty family's set lives in, and is folded by, its OWN family store -- a family whose
  // store was never created has no set (and no claim), never a borrowed one.
  const lineage = await readFactPoints(paths, { family: "process_lineage", now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["process_lineage"] });
  assert.equal(lineage.store_exists, false);
  assert.equal(lineage.seen_sets.process_lineage.status, "missing");
  // A seen-set is only ever validated against its own family's ledger.
  await assert.rejects(() => readFactPoints(paths, { family: "service", now: at(0), seenSetFamilies: ["process_lineage"] }), /not one of the families read/);
});

// G2 H1: an upgraded install's family store is born at the missing-ledger bootstrap exactly like a
// fresh install's, but the legacy single store it replaced held real sightings that S5 quarantined
// (never read again). Its first pass is therefore NOT a genuine first run: memory is certified only
// from that pass, so the Q2 novelty horizons (48 h / 6 d) apply -- never a 30-day scoped "new" claim
// over history the system discarded itself.
async function seedLegacyEvidence(paths, kind) {
  const learned = path.join(paths.stateDir, "learned");
  await fs.mkdir(path.join(learned, "facts"), { recursive: true });
  if (kind === "marker") {
    await fs.writeFile(path.join(learned, "facts-legacy.json"), JSON.stringify({ schema_version: 1, in_progress: null, quarantines: [{ dir: "facts-legacy-2026-10-01T00-00-00-000Z", quarantined_ts: at(0) }] }));
  } else if (kind === "garbled-marker") {
    await fs.writeFile(path.join(learned, "facts-legacy.json"), "{not json");
  } else if (kind === "legacy-file") {
    // The quarantine failed this tick (daemon.js reports it and continues): the legacy store is still
    // in place when the family stores are first written.
    await fs.writeFile(path.join(learned, "facts", "facts.jsonl"), `${JSON.stringify(presence(at(-1), "weekly.service"))}\n`);
  } else if (kind === "legacy-seen-sets") {
    await fs.mkdir(path.join(learned, "facts", "seen-sets"), { recursive: true });
  } else if (kind === "legacy-tmp") {
    await fs.writeFile(path.join(learned, "facts", "integrity.json.4242.tmp"), "{}");
  }
}

for (const kind of ["marker", "garbled-marker", "legacy-file", "legacy-seen-sets", "legacy-tmp"]) {
  test(`G2 H1: a family store's first pass after a legacy quarantine (${kind}) is not a genuine first run -- certified_since is the pass time and the novelty horizon applies`, async () => {
    const paths = await tempPaths();
    await seedLegacyEvidence(paths, kind);
    await appendFactPoints(paths, serviceTick(at(0), ["a"]), { family: "service", now: at(0) });
    for (let hour = 1; hour <= 3; hour += 1) await appendFactPoints(paths, serviceTick(at(hour), ["a"]), { family: "service", now: at(hour) });
    const { set } = await readSeenSetFile(paths, "service");
    const expectedBoundary = kind === "marker" ? at(0) : at(3);
    assert.equal(set.certified_since_ts, expectedBoundary, "an unreadable or pending migration is a fresh discard episode on every observed pass");
    const read = await readFactPoints(paths, { family: "service", now: at(3), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
    const markerTrusted = kind === "marker";
    const expectedStatus = markerTrusted ? "valid" : kind === "garbled-marker" ? "quarantine_marker_unreadable" : "quarantine_migration_pending";
    assert.equal(read.seen_sets.service.status, expectedStatus, "the read path exposes unresolved migration evidence");
    if (markerTrusted) assert.equal(read.seen_sets.service.scope_ts, expectedBoundary, "the claim scope never reaches back past the latest observed discard");
    assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(at(3))), false, "horizon-short, not silently eligible");
    assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(at(47))), false);
    assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(at(Date.parse(expectedBoundary) === Date.parse(at(0)) ? 48 : 51))), markerTrusted, "only a trusted marker can let the 48 h horizon recover");
  });
}

test("G2 H1: a seen-set lost AFTER an upgrade re-seeds at the pass time, never null -- the lineage's start is not the start of the host's history", async () => {
  const paths = await tempPaths();
  await seedLegacyEvidence(paths, "marker");
  for (let hour = 0; hour <= 4; hour += 1) await appendFactPoints(paths, serviceTick(at(hour), ["a"]), { family: "service", now: at(hour) });
  await fs.rm(resolveSeenSetPaths(paths, "service").file);
  await appendFactPoints(paths, serviceTick(at(5), ["a"]), { family: "service", now: at(5) });
  assert.equal((await readSeenSetFile(paths, "service")).set.certified_since_ts, at(5));
});

test("G2 H1 regression guard: a fresh install (no marker, no legacy item) still seeds certified_since null on its first pass", async () => {
  const paths = await tempPaths();
  await fs.mkdir(path.join(paths.stateDir, "learned", "facts"), { recursive: true });
  await appendFactPoints(paths, serviceTick(at(0), ["a"]), { family: "service", now: at(0) });
  await appendFactPoints(paths, serviceTick(at(1), ["a"]), { family: "service", now: at(1) });
  assert.equal((await readSeenSetFile(paths, "service")).set.certified_since_ts, null);
});

test("G2 HIGH-1: a later legacy quarantine advances a continuous null seen-set before it can claim the quarantined entity new", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
  await appendFactPoints(paths, serviceTick(at(1), ["svc-A"]), { family: "service", now: at(1) });
  assert.equal((await readSeenSetFile(paths, "service")).set.certified_since_ts, null, "the pre-quarantine lineage is continuous and null-certified");

  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(1), "svc-B"))}\n`);
  const quarantine = await migrateLegacyFactStore(paths, { now: at(2) });
  assert.equal(quarantine.status, "quarantined");

  await appendFactPoints(paths, serviceTick(at(2), ["svc-A"]), { family: "service", now: at(2) });
  const setAfterQuarantine = (await readSeenSetFile(paths, "service")).set;
  assert.equal(setAfterQuarantine.certified_since_ts, at(2), "the quarantine epoch revokes the old null boundary");
  assert.equal(setAfterQuarantine.quarantine_epoch, 1);
  assert.equal(setAfterQuarantine.quarantine_epoch_ts, at(2));

  await appendFactPoints(paths, serviceTick(at(3), ["svc-A", "svc-B"]), { family: "service", now: at(3) });
  const read = await readFactPoints(paths, { family: "service", now: at(3), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(read.seen_sets.service.scope_ts, at(2), "scope starts at the quarantine, not at now minus 30 days");
  assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(at(3))), false, "svc-B cannot be claimed new before the 48 h horizon");
  const result = await computeServiceAppearanceCandidates(paths, { now: at(3) });
  assert.deepEqual(result.candidates, [], "the detector stays quiet during the quarantine horizon");
});

test("G2 HIGH-1 re-gate: every later quarantine has its own epoch timestamp, so the second discarded store cannot be claimed new", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
  await appendFactPoints(paths, serviceTick(at(1), ["svc-A"]), { family: "service", now: at(1) });

  const { factsRootDir, markerFile } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(2), "svc-B"))}\n`);
  await migrateLegacyFactStore(paths, { now: at(2) });
  await appendFactPoints(paths, serviceTick(at(2), ["svc-A"]), { family: "service", now: at(2) });

  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(60), "svc-C"))}\n`);
  await migrateLegacyFactStore(paths, { now: at(60) });
  const markerAfterSecond = JSON.parse(await fs.readFile(markerFile, "utf8"));
  assert.equal(markerAfterSecond.quarantine_epoch, 2);
  assert.equal(markerAfterSecond.quarantine_epoch_ts, at(60), "the second quarantine records its own pass time");

  await appendFactPoints(paths, serviceTick(at(60), ["svc-A"]), { family: "service", now: at(60) });
  await appendFactPoints(paths, serviceTick(at(61), ["svc-A", "svc-C"]), { family: "service", now: at(61) });
  const set = (await readSeenSetFile(paths, "service")).set;
  assert.equal(set.certified_since_ts, at(60), "the second quarantine advances the certification boundary");
  const result = await computeServiceAppearanceCandidates(paths, { now: at(61) });
  assert.deepEqual(result.candidates, [], "svc-C from the second discarded store is not claimed new at +1h");
});

test("G2 HIGH-1 re-gate: a resumed quarantine with root data is a new discard episode at the resume pass", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
  await appendFactPoints(paths, serviceTick(at(1), ["svc-A"]), { family: "service", now: at(1) });

  const { factsRootDir, learnedDir, markerFile } = resolveLegacyFactStorePaths(paths);
  const dir = "facts-legacy-2026-10-01T02-00-00-000Z";
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.mkdir(path.join(learnedDir, dir), { recursive: true });
  await fs.writeFile(path.join(learnedDir, dir, "facts.jsonl"), `${JSON.stringify(presence(at(2), "svc-B"))}\n`);
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(60), "svc-C"))}\n`);
  await fs.writeFile(markerFile, JSON.stringify({
    schema_version: 2,
    in_progress: { dir, started_ts: at(2), quarantine_epoch: 1, quarantine_ts: at(2) },
    quarantines: [],
    quarantine_epoch: 1,
    quarantine_epoch_ts: at(2),
  }));

  await migrateLegacyFactStore(paths, { now: at(60) });
  const markerAfterResume = JSON.parse(await fs.readFile(markerFile, "utf8"));
  assert.equal(markerAfterResume.quarantine_epoch, 2);
  assert.equal(markerAfterResume.quarantine_epoch_ts, at(60));

  for (let hour = 60; hour <= 66; hour += 1) {
    await appendFactPoints(paths, serviceTick(at(hour), ["svc-A"]), { family: "service", now: at(hour) });
  }
  await appendFactPoints(paths, serviceTick(at(67), ["svc-A", "svc-C"]), { family: "service", now: at(67) });
  const result = await computeServiceAppearanceCandidates(paths, { now: at(67) });
  assert.deepEqual(result.candidates, [], "svc-C from a resumed quarantine is not claimed new at +7h");
});

test("G3 blocker: a non-structural migration epoch change invalidates all novelty families until the next fold", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  const families = [
    {
      family: "service",
      ruleId: SERVICE_APPEARED_RULE_ID,
      writeStore: writeServiceAppearanceBaselineStore,
      compute: computeServiceAppearanceCandidates,
      pointsForTick: (ts, latest) => serviceTick(ts, latest ? ["svc-A", "svc-B"] : ["svc-A"]),
      options: { minHistoryTickCount: 1, establishedMinCensusCount: 2 },
    },
    {
      family: "scheduled_job",
      ruleId: SCHEDULED_JOB_APPEARED_RULE_ID,
      writeStore: writePersistenceBaselineStore,
      compute: computeScheduledJobBaselineCandidates,
      pointsForTick: (ts, latest) => [
        presence(ts, latest ? "job-A" : "job-base", "scheduled_job.presence"),
        marker(ts, "complete", "scheduled_job.census"),
      ],
      options: { minHistoryTickCount: 1 },
    },
    {
      family: "process_lineage",
      ruleId: PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
      writeStore: writeProcessLineageBaselineStore,
      compute: computeProcessLineageBaselineCandidates,
      pointsForTick: (ts, latest) => [
        presence(ts, latest ? "edge-new" : "edge-base", "process.lineage_edge"),
        marker(ts, "complete", "process.lineage_edge.census"),
      ],
      options: { minHistoryTickCount: 1 },
    },
  ];
  const latest = at(72);
  for (const entry of families) {
    await entry.writeStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
    for (const hour of [0, 24, 48, 72]) {
      await appendFactPoints(paths, entry.pointsForTick(at(hour), hour === 72), { family: entry.family, now: at(hour) });
    }
  }

  // This is the fast-tick window: migration advances the current marker after the last append and
  // no structural append/fold runs before the producers read their old epoch-0 seen-sets.
  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(48), "legacy-svc"))}\n`);
  const migration = await migrateLegacyFactStore(paths, { now: latest });
  assert.equal(migration.status, "quarantined");

  // Combine the migration with the other non-valid status that previously masked it. This models
  // a lost fold write after the last committed pass: the set's ledger lineage is stale, while the
  // migration marker also advanced on this fast tick.
  for (const entry of families) {
    const { file } = resolveSeenSetPaths(paths, entry.family);
    const set = JSON.parse(await fs.readFile(file, "utf8"));
    set.ledger_pass_id += 1;
    await fs.writeFile(file, `${JSON.stringify(set)}\n`);
  }

  for (const entry of families) {
    const read = await readFactPoints(paths, { family: entry.family, now: latest, windowMs: 31 * DAY, seenSetFamilies: [entry.family] });
    assert.equal(read.seen_sets[entry.family].status, "lineage_mismatch", `${entry.family}: stale set reports its underlying status after migration`);
    assert.equal(noveltyRuleEligible(read, entry.ruleId, Date.parse(latest)), false, `${entry.family}: shared eligibility predicate vetoes stale epoch`);

    const result = await entry.compute(paths, {
      now: latest,
      activeFreshnessMs: 2 * HOUR,
      ...entry.options,
    });
    assert.deepEqual(result.candidates, [], `${entry.family}: no candidate from stale novelty memory`);
    assert.deepEqual(result.evaluatedAlertKeys, [], `${entry.family}: no recovery coverage from stale novelty memory`);
    assert.equal(result.ruleEvaluations[entry.ruleId].gate, "history_horizon_short", `${entry.family}: status uses the same horizon-short gate`);
    assert.equal(result.ruleEvaluations[entry.ruleId].horizon_reason, "lineage_mismatch", `${entry.family}: status retains the underlying seen-set reason`);
    assert.equal(result.ruleEvaluations[entry.ruleId].evaluable, false, `${entry.family}: rule is not evaluable`);
  }

  // The daemon has its own recovery pass. Feed it a producer report that would otherwise cover an
  // active appearance alert; its independent veto must use the same stale-epoch predicate and keep
  // that alert active.
  await writeLearnedConfig(paths, { enabled: true });
  const fingerprint = "0123456789abcdef";
  const daemonAlerts = families.map((entry) => ({
    rule_id: entry.ruleId,
    fingerprint,
    status: "active",
    severity: "warning",
    title: "t",
    summary: "t",
    first_seen: latest,
    last_seen: latest,
    diagnostics: {},
  }));
  await writeAlertRecords(paths, daemonAlerts);
  const daemon = await runDaemonIteration(paths, {
    profile: { interval_ms: 60000, collectors: {} },
    collectors: {},
    ts: latest,
    now: latest,
    computeServiceAppearanceCandidates: async () => ({
      candidates: [],
      evaluatedAlertKeys: [alertId(SERVICE_APPEARED_RULE_ID, fingerprint)],
    }),
    computeScheduledJobBaselineCandidates: async () => ({
      candidates: [],
      evaluatedAlertKeys: [alertId(SCHEDULED_JOB_APPEARED_RULE_ID, fingerprint)],
    }),
    computeProcessLineageBaselineCandidates: async () => ({
      candidates: [],
      evaluatedAlertKeys: [alertId(PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, fingerprint)],
    }),
  });
  for (const entry of families) {
    const alert = daemon.alerts.alerts.find((candidate) => candidate.rule_id === entry.ruleId);
    assert.equal(alert.status, "active", `${entry.family}: daemon veto freezes recovery on a stale migration epoch`);
  }
  assert.equal(daemon.status.novelty_seen_sets.service.status, "lineage_mismatch");

  for (const entry of families) {
    await enforceFactRetention(paths, { family: entry.family, now: latest });
    const recertified = await readFactPoints(paths, { family: entry.family, now: latest, windowMs: 31 * DAY, seenSetFamilies: [entry.family] });
    assert.equal(recertified.seen_sets[entry.family].status, "valid", `${entry.family}: the next fold re-certifies the current epoch`);
  }
});

test("G3 blocker audit: every ordinary non-valid seen-set status is reported first and remains ineligible", async () => {
  const statuses = ["missing", "unreadable", "invalid", "no_ledger", "pending_pass", "lineage_mismatch", "overflow"];
  for (const expectedStatus of statuses) {
    const paths = await tempPaths();
    await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
    const { factsRootDir } = resolveLegacyFactStorePaths(paths);
    await fs.mkdir(factsRootDir, { recursive: true });
    await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(1), "legacy-svc"))}\n`);
    const migration = await migrateLegacyFactStore(paths, { now: at(2) });
    assert.equal(migration.status, "quarantined");

    const { file: seenSetFile } = resolveSeenSetPaths(paths, "service");
    const { integrityFile } = resolveFactIntegrityPaths(paths, "service");
    if (expectedStatus === "missing") {
      await fs.unlink(seenSetFile);
    } else if (expectedStatus === "unreadable") {
      // A malformed JSON file is `invalid`, not `unreadable`. Use a directory at the file path so
      // fs.readFile fails with EISDIR and the read path reports the underlying I/O status.
      await fs.unlink(seenSetFile);
      await fs.mkdir(seenSetFile, { recursive: true });
    } else {
      const set = JSON.parse(await fs.readFile(seenSetFile, "utf8"));
      if (expectedStatus === "invalid") {
        set.entries = [];
      } else if (expectedStatus === "no_ledger") {
        await fs.unlink(integrityFile);
      } else if (expectedStatus === "pending_pass") {
        const ledger = JSON.parse(await fs.readFile(integrityFile, "utf8"));
        ledger.continuity.pending_pass = {
          pass_id: ledger.continuity.last_committed_pass_id + 1,
          corrupt_count: ledger.corrupt_dropped_total,
          schema_invalid_count: ledger.schema_invalid_dropped_total,
          bytecap_evicted_count: ledger.bytecap_evicted_total,
          age_evicted_count: ledger.age_evicted_total,
          output_record_count: ledger.continuity.last_rewrite_record_count,
          output_newest_ts: ledger.continuity.last_rewrite_newest_ts,
          output_bytes: ledger.continuity.last_rewrite_bytes,
          output_digest: ledger.continuity.output_digest,
          future_fact_count: ledger.future_fact_dropped_total,
        };
        await fs.writeFile(integrityFile, `${JSON.stringify(ledger)}\n`);
      } else if (expectedStatus === "lineage_mismatch") {
        set.ledger_pass_id += 1;
      } else if (expectedStatus === "overflow") {
        set.overflow = true;
        set.entries = {};
      }
      if (expectedStatus !== "no_ledger" && expectedStatus !== "pending_pass") {
        await fs.writeFile(seenSetFile, `${JSON.stringify(set)}\n`);
      }
    }

    const read = await readFactPoints(paths, { family: "service", now: at(2), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
    assert.equal(read.seen_sets.service.status, expectedStatus, `${expectedStatus} is reported before any migration status`);
    assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(at(2))), false, `${expectedStatus} cannot authorize full-store novelty fallback`);
  }
});

test("G3: same-epoch seen-set loss at t7 is horizon-short, not a full-store novelty claim, and cannot recover a daemon alert", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });

  // The legacy store contains svc-B and is quarantined at t0. The current epoch is therefore
  // valid, but its seen-set is the only trusted memory that can distinguish svc-B's return.
  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(0), "svc-B"))}\n`);
  await migrateLegacyFactStore(paths, { now: at(0) });
  for (let hour = 0; hour <= 7; hour += 1) {
    await appendFactPoints(paths, serviceTick(at(hour), hour === 7 ? ["svc-A", "svc-B"] : ["svc-A"]), { family: "service", now: at(hour) });
  }
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(7) });
  await fs.unlink(resolveSeenSetPaths(paths, "service").file);

  const latest = at(7);
  const read = await readFactPoints(paths, { family: "service", now: latest, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(read.completeness.coverage, "full", "the reproduction keeps full fact-store coverage so only the seen-set gate can stop it");
  assert.equal(read.seen_sets.service.status, "missing");
  assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(latest)), false);

  const result = await computeServiceAppearanceCandidates(paths, {
    now: latest,
    activeFreshnessMs: 2 * HOUR,
    minHistoryTickCount: 1,
    establishedMinCensusCount: 2,
  });
  assert.deepEqual(result.candidates, [], "svc-B is not claimable seven hours into the 48-hour horizon");
  assert.deepEqual(result.evaluatedAlertKeys, [], "horizon-short novelty reports no recovery coverage");
  assert.equal(result.ruleEvaluations[SERVICE_APPEARED_RULE_ID].gate, "history_horizon_short");
  assert.equal(result.ruleEvaluations[SERVICE_APPEARED_RULE_ID].horizon_reason, "missing");

  await writeLearnedConfig(paths, { enabled: true });
  const fingerprint = "0123456789abcdef";
  await writeAlertRecords(paths, [{
    rule_id: SERVICE_APPEARED_RULE_ID,
    fingerprint,
    status: "active",
    severity: "warning",
    title: "t",
    summary: "t",
    first_seen: latest,
    last_seen: latest,
    diagnostics: {},
  }]);
  const daemon = await runDaemonIteration(paths, {
    profile: { interval_ms: 60000, collectors: {} },
    collectors: {},
    ts: latest,
    now: latest,
    computeServiceAppearanceCandidates: async () => ({
      candidates: [],
      evaluatedAlertKeys: [alertId(SERVICE_APPEARED_RULE_ID, fingerprint)],
    }),
  });
  const alert = daemon.alerts.alerts.find((candidate) => candidate.rule_id === SERVICE_APPEARED_RULE_ID);
  assert.equal(alert.status, "active", "the daemon veto keeps the active novelty alert from recovering");
  assert.equal(daemon.status.novelty_seen_sets.service.status, "missing");
});

test("G3: a successful fold re-certifies lost seen-set memory, but eligibility waits for the full novelty horizon", async () => {
  const paths = await tempPaths();
  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(0), "svc-B"))}\n`);
  await migrateLegacyFactStore(paths, { now: at(0) });
  for (let hour = 0; hour <= 7; hour += 1) {
    await appendFactPoints(paths, serviceTick(at(hour), hour === 7 ? ["svc-A", "svc-B"] : ["svc-A"]), { family: "service", now: at(hour) });
  }
  await fs.unlink(resolveSeenSetPaths(paths, "service").file);

  await enforceFactRetention(paths, { family: "service", now: at(7) });
  const recertified = await readFactPoints(paths, { family: "service", now: at(7), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(recertified.seen_sets.service.status, "valid");
  assert.equal(recertified.seen_sets.service.certified_since_ts, at(7));

  const shortNow = at(54); // 47 h after the successful fold
  const eligibleNow = at(55); // 48 h after the successful fold
  const shortRead = await readFactPoints(paths, { family: "service", now: shortNow, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  const eligibleRead = await readFactPoints(paths, { family: "service", now: eligibleNow, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(noveltyRuleEligible(shortRead, SERVICE_APPEARED_RULE_ID, Date.parse(shortNow)), false);
  assert.equal(noveltyRuleEligible(eligibleRead, SERVICE_APPEARED_RULE_ID, Date.parse(eligibleNow)), true);
});

test("G3: marker and epoch failures remain non-valid seen-set reasons", async () => {
  const cases = [
    ["quarantine_epoch_mismatch", async ({ seenSetFile }) => {
      const set = JSON.parse(await fs.readFile(seenSetFile, "utf8"));
      set.quarantine_epoch = 0;
      await fs.writeFile(seenSetFile, `${JSON.stringify(set)}\n`);
    }],
    ["quarantine_marker_unreadable", async ({ markerFile }) => fs.writeFile(markerFile, "{not json")],
    ["quarantine_migration_pending", async ({ factsRootDir }) => fs.writeFile(path.join(factsRootDir, "facts.jsonl"), "pending")],
    ["quarantine_marker_future", async ({ markerFile }) => fs.writeFile(markerFile, JSON.stringify({
      schema_version: 2,
      in_progress: null,
      quarantines: [],
      quarantine_epoch: 1,
      quarantine_epoch_ts: "2099-01-01T00:00:00.000Z",
    }))],
  ];
  for (const [expectedStatus, mutate] of cases) {
    const paths = await tempPaths();
    const { factsRootDir, markerFile } = resolveLegacyFactStorePaths(paths);
    await fs.mkdir(factsRootDir, { recursive: true });
    await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(0), "legacy-svc"))}\n`);
    await migrateLegacyFactStore(paths, { now: at(0) });
    await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
    const { file: seenSetFile } = resolveSeenSetPaths(paths, "service");
    await mutate({ factsRootDir, markerFile, seenSetFile });

    const read = await readFactPoints(paths, { family: "service", now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
    assert.equal(read.seen_sets.service.status, expectedStatus);
    assert.equal(noveltyRuleEligible(read, SERVICE_APPEARED_RULE_ID, Date.parse(at(0))), false);
  }
});

test("G2 HIGH-1 re-gate: a crash after rename with an empty root still advances the resume epoch and suppresses svc-C at +7h", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
  await appendFactPoints(paths, serviceTick(at(1), ["svc-A"]), { family: "service", now: at(1) });

  const { factsRootDir, learnedDir, markerFile } = resolveLegacyFactStorePaths(paths);
  const dir = "facts-legacy-2026-10-01T02-00-00-000Z";
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.mkdir(path.join(learnedDir, dir), { recursive: true });
  // Simulate the pre-fix crash: the item was renamed at 60h, but the marker still describes the
  // 2h episode and has no complete per-item metadata because finalize never ran.
  await fs.writeFile(path.join(learnedDir, dir, "facts.jsonl"), `${JSON.stringify(presence(at(60), "svc-C"))}\n`);
  await fs.writeFile(markerFile, JSON.stringify({
    schema_version: 2,
    in_progress: { dir, started_ts: at(2), quarantine_epoch: 1, quarantine_ts: at(2) },
    quarantines: [],
    quarantine_epoch: 1,
    quarantine_epoch_ts: at(2),
  }));

  await migrateLegacyFactStore(paths, { now: at(60) });
  const markerAfterResume = JSON.parse(await fs.readFile(markerFile, "utf8"));
  assert.equal(markerAfterResume.quarantine_epoch, 2);
  assert.equal(markerAfterResume.quarantine_epoch_ts, at(60));

  for (let hour = 60; hour <= 66; hour += 1) {
    await appendFactPoints(paths, serviceTick(at(hour), ["svc-A"]), { family: "service", now: at(hour) });
  }
  await appendFactPoints(paths, serviceTick(at(67), ["svc-A", "svc-C"]), { family: "service", now: at(67) });
  const result = await computeServiceAppearanceCandidates(paths, { now: at(67) });
  assert.deepEqual(result.candidates, [], "svc-C moved before the crash is not claimed new at +7h");
});

test("G2 HIGH-1 re-gate: corrupted marker plus pending legacy data is a new discard episode on every observation", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["svc-A"]), { family: "service", now: at(0) });
  const { factsRootDir, markerFile } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(2), "svc-B"))}\n`);
  await migrateLegacyFactStore(paths, { now: at(2) });
  await appendFactPoints(paths, serviceTick(at(2), ["svc-A"]), { family: "service", now: at(2) });
  assert.equal((await readSeenSetFile(paths, "service")).set.certified_since_ts, at(2));

  await fs.writeFile(markerFile, "{not json");
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(at(3), "svc-C"))}\n`);
  await appendFactPoints(paths, serviceTick(at(3), ["svc-A"]), { family: "service", now: at(3) });
  const firstUnreadable = (await readSeenSetFile(paths, "service")).set;
  assert.equal(firstUnreadable.certified_since_ts, at(3), "the first corrupt-marker observation advances to the pass");

  await appendFactPoints(paths, serviceTick(at(4), ["svc-A"]), { family: "service", now: at(4) });
  const secondUnreadable = (await readSeenSetFile(paths, "service")).set;
  assert.equal(secondUnreadable.certified_since_ts, at(4), "a later corrupt-marker observation is not already handled");
});

test("G2 MEDIUM re-gate: a future quarantine epoch is corrected at the pass time, so novelty eligibility starts from the correction", async () => {
  const paths = await tempPaths();
  const future = "2099-01-01T00:00:00.000Z";
  const corrected = "2026-10-05T00:00:00.000Z";
  const { factsRootDir, markerFile } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(factsRootDir, { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), `${JSON.stringify(presence(future, "svc-future"))}\n`);
  await migrateLegacyFactStore(paths, { now: future });
  await appendFactPoints(paths, serviceTick(future, ["svc-A"]), { family: "service", now: future });
  assert.equal((await readSeenSetFile(paths, "service")).set.certified_since_ts, future);

  await migrateLegacyFactStore(paths, { now: corrected });
  const correctedMarker = JSON.parse(await fs.readFile(markerFile, "utf8"));
  assert.equal(correctedMarker.quarantine_epoch_ts, corrected, "the future marker is stamped at the correction pass");
  await appendFactPoints(paths, serviceTick(corrected, ["svc-A"]), { family: "service", now: corrected });

  const shortNow = new Date(Date.parse(corrected) + 47 * HOUR).toISOString();
  const eligibleNow = new Date(Date.parse(corrected) + 48 * HOUR).toISOString();
  const shortRead = await readFactPoints(paths, { family: "service", now: shortNow, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  const eligibleRead = await readFactPoints(paths, { family: "service", now: eligibleNow, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(shortRead.seen_sets.service.certified_since_ts, corrected);
  assert.equal(noveltyRuleEligible(shortRead, SERVICE_APPEARED_RULE_ID, Date.parse(shortNow)), false);
  assert.equal(noveltyRuleEligible(eligibleRead, SERVICE_APPEARED_RULE_ID, Date.parse(eligibleNow)), true, "the registered horizon starts at the corrected pass, not 2099");
});

test("fold rule: partial, unknown and markerless ticks are never folded; neither is a tick dated after the pass clock", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [
    ...serviceTick(at(0), ["complete-one"]),
    ...serviceTick(at(1), ["partial-only"], "partial"),
    ...serviceTick(at(2), ["unknown-only"], "garbled"),
    presence(at(3), "markerless-only"),
    ...serviceTick(at(5), ["future-only"]), // within the 6 h future tolerance, so the store keeps it
  ], { family: "service", now: at(3) });
  assert.deepEqual(Object.keys(await seenEntries(paths)), ["complete-one"]);
});

test("I13: eviction from the fact store never changes a seen-set answer -- the same append sequence under a huge and a tiny budget yields identical entries and certified_since", async () => {
  const big = await tempPaths();
  const tiny = await tempPaths();
  for (let hour = 0; hour < 10; hour += 1) {
    const tick = serviceTick(at(hour), [`steady`, `rotating-${hour % 4}`, `once-${hour}`]);
    await appendFactPoints(big, tick, { family: "service", now: at(hour), maxBytes: 10 * 1024 * 1024 });
    await appendFactPoints(tiny, tick, { family: "service", now: at(hour), maxBytes: tickBytes(tick) + 10 });
  }
  const tinyRead = await readFactPoints(tiny, { family: "service", now: at(9), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(tinyRead.completeness.coverage, "narrowed", "the tiny store really evicted");
  const bigSet = (await readSeenSetFile(big, "service")).set;
  const tinySet = (await readSeenSetFile(tiny, "service")).set;
  assert.deepEqual(tinySet.entries, bigSet.entries);
  assert.equal(tinySet.certified_since_ts, bigSet.certified_since_ts);
  assert.equal(tinyRead.seen_sets.service.status, "valid");
});

test("read validation: the set is valid only against the SAME ledger lineage and committed pass; a stale pass id, another generation, or a missing set is not", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a"]), { family: "service", now: at(0) });
  const { file } = resolveSeenSetPaths(paths, "service");
  const stale = await fs.readFile(file, "utf8");
  await appendFactPoints(paths, serviceTick(at(1), ["a"]), { family: "service", now: at(1) });
  const read = (now) => readFactPoints(paths, { family: "service", now, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
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
  await appendFactPoints(paths, ticks[0], { family: "service", now: at(0), maxBytes: budget });
  const beforeP = await fs.readFile(file, "utf8");
  await appendFactPoints(paths, ticks[1], { family: "service", now: at(1), maxBytes: budget }); // pass P keeps tick 1
  await fs.writeFile(file, beforeP); // ...but its fold write is "lost"
  await appendFactPoints(paths, ticks[2], { family: "service", now: at(2), maxBytes: budget });
  await appendFactPoints(paths, ticks[3], { family: "service", now: at(3), maxBytes: budget }); // tick 1 is evicted by now
  const read = await readFactPoints(paths, { family: "service", now: at(3), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.ok(!read.points.some((point) => point.entity_key === "returner"), "tick 1 really was evicted");
  assert.equal(read.seen_sets.service.status, "valid", "the next pass re-seeded the set");
  assert.ok(read.seen_sets.service.entries.has("returner"), "the returner observed only in the lost-fold tick is still remembered");
  assert.equal(seenBeforeTick(read.seen_sets.service.entries, "returner", at(4)), true);
});

test("re-seed boundary: a set lost over a NARROWED store re-seeds with certified_since = the prior byte-cap floor (memory is complete only after it), and a re-bootstrapped ledger re-seeds at the pass time", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2, 3].map((hour) => serviceTick(at(hour), ["base"]));
  const budget = tickBytes(ticks[0]) * 2 + 10;
  for (let hour = 0; hour < 3; hour += 1) await appendFactPoints(paths, ticks[hour], { family: "service", now: at(hour), maxBytes: budget });
  const before = await readFactPoints(paths, { family: "service", now: at(2), windowMs: 31 * DAY });
  const floor = before.completeness.bytecap_floor_ts;
  assert.equal(floor, at(0));
  await fs.rm(resolveSeenSetPaths(paths, "service").file);
  await appendFactPoints(paths, ticks[3], { family: "service", now: at(3), maxBytes: budget });
  const reseeded = (await readSeenSetFile(paths, "service")).set;
  assert.equal(reseeded.certified_since_ts, floor, "never null over a narrowed store: memory before the floor is gone");

  // Ledger deleted over a surviving store: the lineage breaks (HIGH-1), the set's generation no longer
  // matches, and the re-seed certifies nothing before the pass that re-bootstrapped.
  await fs.rm(resolveFactIntegrityPaths(paths, "service").integrityFile);
  await appendFactPoints(paths, serviceTick(at(4), ["base"]), { family: "service", now: at(4), maxBytes: budget });
  const afterBreak = (await readSeenSetFile(paths, "service")).set;
  assert.equal(afterBreak.certified_since_ts, at(4));
});

test("MEDIUM-1 (S3b review): a non-continuous re-seed keeps the prior set's entries (memory that can only suppress) while certified_since stays at the re-seed boundary", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2, 3, 4].map((hour) => serviceTick(at(hour), hour === 0 ? ["base", "returner"] : ["base"]));
  const budget = tickBytes(ticks[1]) * 2 + 10;
  const { file } = resolveSeenSetPaths(paths, "service");
  for (let hour = 0; hour < 3; hour += 1) await appendFactPoints(paths, ticks[hour], { family: "service", now: at(hour), maxBytes: budget });
  const afterP2 = await fs.readFile(file, "utf8");
  assert.ok(JSON.parse(afterP2).entries.returner, "the returner was folded while its tick was retained");
  await appendFactPoints(paths, ticks[3], { family: "service", now: at(3), maxBytes: budget });
  await fs.writeFile(file, afterP2); // pass 3's fold write is "lost": the set no longer matches the ledger
  const floorBefore = (await readFactPoints(paths, { family: "service", now: at(3), windowMs: 31 * DAY })).completeness.bytecap_floor_ts;
  await appendFactPoints(paths, ticks[4], { family: "service", now: at(4), maxBytes: budget });
  const read = await readFactPoints(paths, { family: "service", now: at(4), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.ok(!read.points.some((point) => point.entity_key === "returner"), "tick 0 is long evicted from the store");
  assert.equal(read.seen_sets.service.status, "valid", "re-seeded");
  assert.deepEqual(read.seen_sets.service.entries.get("returner"), { firstMs: Date.parse(at(0)), lastMs: Date.parse(at(0)) }, "the prior set's memory survives the re-seed");
  assert.equal(seenBeforeTick(read.seen_sets.service.entries, "returner", at(60)), true, "so the returner never reads as new");
  assert.equal(read.seen_sets.service.certified_since_ts, floorBefore, "the certified boundary is still the re-seed boundary, never the prior set's");
  assert.notEqual(floorBefore, null);
});

test("MEDIUM-1 (S3b review): a merged re-seed that would overflow retries bare before declaring overflow", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a", "b"]), { family: "service", now: at(0), seenSetMaxEntries: 2 });
  const { file } = resolveSeenSetPaths(paths, "service");
  const stale = await fs.readFile(file, "utf8");
  await appendFactPoints(paths, serviceTick(at(1), ["a"]), { family: "service", now: at(1), seenSetMaxEntries: 2 });
  await fs.writeFile(file, stale.replace("\"a\":", "\"x\":")); // stale + different memory: merged it would be 3 > 2
  const outcome = await enforceFactRetention(paths, { family: "service", now: at(1), seenSetMaxEntries: 2 });
  assert.equal(outcome.seen_set_fold.service.status, "reseeded");
  assert.deepEqual(Object.keys(await seenEntries(paths)).sort(), ["a", "b"], "bare re-seed from the store's candidates, never a silent truncation");
});

test("LOW-4 (S3b review): a complete tick appended at or below the byte-cap floor after a small clock rollback is still folded -- memory only ever suppresses a claim", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2].map((hour) => serviceTick(at(hour), ["base"]));
  const budget = tickBytes(ticks[0]) * 2 + 10;
  for (let hour = 0; hour < 3; hour += 1) await appendFactPoints(paths, ticks[hour], { family: "service", now: at(hour), maxBytes: budget });
  const floor = (await readFactPoints(paths, { family: "service", now: at(2), windowMs: 31 * DAY })).completeness.bytecap_floor_ts;
  assert.equal(floor, at(0));
  // The clock steps back below the floor (within the future tolerance, so no loss is stamped) and a
  // complete tick lands there: the store evicts it physically (below-floor), but it was observed.
  const rolledBack = new Date(Date.parse(at(0)) - HOUR / 2).toISOString();
  await appendFactPoints(paths, serviceTick(rolledBack, ["rb-only"]), { family: "service", now: at(0), maxBytes: budget });
  const entries = await seenEntries(paths);
  assert.deepEqual(entries["rb-only"], [rolledBack, rolledBack], "the below-floor tick's observation is remembered");
});

test("overflow: a set past its cap is never silently truncated -- it reads as overflow (novelty ineligible), and a later pass whose seed fits recovers it", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["a", "b", "c"]), { family: "service", now: at(0), seenSetMaxEntries: 2 });
  const overflowed = await readFactPoints(paths, { family: "service", now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service"], seenSetMaxEntries: 2 });
  assert.equal(overflowed.seen_sets.service.status, "overflow");
  assert.equal(overflowed.seen_sets.service.entries, undefined);
  assert.equal(noveltyRuleEligible({ ...overflowed, completeness: { ...overflowed.completeness, coverage: "narrowed", bytecap_floor_ts: at(-100) } }, SERVICE_APPEARED_RULE_ID, Date.parse(at(0))), false, "overflow under narrowing: ineligible");

  // The store ages the three-entity tick out; the next pass's seed fits under the cap again.
  const later = new Date(Date.parse(at(0)) + 31 * DAY).toISOString();
  await appendFactPoints(paths, serviceTick(later, ["a"]), { family: "service", now: later, seenSetMaxEntries: 2 });
  const recovered = await readFactPoints(paths, { family: "service", now: later, windowMs: 31 * DAY, seenSetFamilies: ["service"], seenSetMaxEntries: 2 });
  assert.equal(recovered.seen_sets.service.status, "valid");
  assert.deepEqual([...recovered.seen_sets.service.entries.keys()], ["a"]);
  // The recovery is a RE-SEED from the store's certified candidates, so its boundary is the re-seed
  // boundary: max(prior floors, loss markers). This store never byte-evicted or lost anything and the
  // prior pass had no age floor, so the seed holds every complete tick of the lineage: null is true.
  assert.equal(recovered.seen_sets.service.certified_since_ts, null);
});

test("expiry: an entry is dropped 30 days past its last sighting, and the claim scope never reaches further back than the retention", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, serviceTick(at(0), ["old", "keep"]), { family: "service", now: at(0) });
  const later = new Date(BASE + 31 * DAY).toISOString();
  await appendFactPoints(paths, serviceTick(later, ["keep"]), { family: "service", now: later });
  const read = await readFactPoints(paths, { family: "service", now: later, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
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
  for (let hour = 0; hour < 5; hour += 1) await appendFactPoints(paths, ticks[hour], { family: "service", now: at(hour), maxBytes: budget });
  return paths;
}

test("G1 reproduction (S3b): returner at t0, absent t1-t3, back at t4 with t0 byte-evicted -> NO first-seen claim, while the gate is LIFTED (the detector evaluated and stayed established)", async () => {
  const paths = await g1Store();
  const read = await readFactPoints(paths, { family: "service", now: at(4), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
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
  for (let hour = 0; hour < 5; hour += 1) await appendFactPoints(paths, ticks[hour], { family: "service", now: at(hour), maxBytes: budget });
  const result = await computeServiceAppearanceCandidates(paths, { now: at(4) });
  assert.deepEqual(result.candidates.map((candidate) => candidate.rule_id), [SERVICE_APPEARED_RULE_ID]);
  assert.equal(result.candidates[0].diagnostics.history_certified_after_ts, new Date(Date.parse(at(4)) - 30 * DAY).toISOString(), "scope: the seen-set's memory (max(certified_since, now - 30 d))");
});

test("S3b: a store older than the 30-day retention (age floor inside the 31 d detector window) keeps novelty evaluating with a valid seen-set -- the interim gate silenced it permanently", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  await appendFactPoints(paths, serviceTick(at(0), ["base"]), { family: "service", now: at(0) });
  const start = BASE + 30 * DAY + HOUR;
  for (let hour = 0; hour < 5; hour += 1) {
    const ts = new Date(start + hour * HOUR).toISOString();
    await appendFactPoints(paths, serviceTick(ts, ["base"]), { family: "service", now: ts });
  }
  const now = new Date(start + 4 * HOUR).toISOString();
  const read = await readFactPoints(paths, { family: "service", now, windowMs: 31 * DAY, seenSetFamilies: ["service"] });
  assert.equal(read.completeness.coverage, "narrowed", "the age floor sits inside the 31 d window");
  assert.equal(read.completeness.bytecap_floor_ts, null, "no byte-cap eviction at all");
  const result = await computeServiceAppearanceCandidates(paths, { now });
  assert.ok(result.evaluatedAlertKeys.length > 0, "novelty still evaluates");
  assert.equal((await loadServiceAppearanceBaselineStore(paths)).state.cold_start_pending, false);
});

test("G3: an injected read that carries no seen-set is never eligible, even with full coverage", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: at(-1) });
  const points = [0, 1, 2, 3].flatMap((hour) => serviceTick(at(hour), ["base"])).concat(serviceTick(at(4), ["base", "new-one"]));
  const result = await computeServiceAppearanceCandidates(paths, {
    now: at(4),
    readFactPoints: async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact", coverage: "full" } }),
  });
  assert.deepEqual(result.candidates, []);
  assert.deepEqual(result.evaluatedAlertKeys, []);
  assert.equal(result.ruleEvaluations[SERVICE_APPEARED_RULE_ID].horizon_reason, undefined);
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
  await appendFactPoints(paths, serviceTick(at(0), ["a"]), { family: "service", now: at(0) });
  const ok = await enforceFactRetention(paths, { family: "service", now: at(0) });
  assert.equal(ok.seen_set_fold.service.status, "folded");
  // Make the seen-set file unwritable by replacing it with a (non-empty) directory: the fold's
  // tmp+rename then fails. (S4: the set lives inside the family store directory, so the store
  // directory itself must stay intact.)
  const { file } = resolveSeenSetPaths(paths, "service");
  await fs.rm(file);
  await fs.mkdir(path.join(file, "blocker"), { recursive: true });
  const failed = await enforceFactRetention(paths, { family: "service", now: at(0) });
  assert.equal(failed.seen_set_fold.service.status, "error");
  assert.equal(failed.kept_count, 2, "retention itself still committed");
  const read = await readFactPoints(paths, { family: "service", now: at(0), windowMs: 31 * DAY, seenSetFamilies: ["service"] });
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
    for (let hour = 0; hour < 5; hour += 1) await appendFactPoints(paths, ticks[hour], { family, now: at(hour), maxBytes: budget });
    const read = await readFactPoints(paths, { family, now: at(4), windowMs: 31 * DAY, seenSetFamilies: [family] });
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
