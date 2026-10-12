// Context plan C1.4 (§6.4, I44, I52-I54, I69, I70, I3; open item 16): the pending journal.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createFactIntegrityLedger } from "../src/fact-store-integrity.js";
import {
  appendPendingEntries,
  checkpointPendingJournal,
  compactionEntriesForCap,
  emptyPendingState,
  foldPendingEntries,
  inspectPendingJournal,
  journalCommittedPass,
  journalScoredThrough,
  MAX_OPEN_PENDING_ITEMS,
  MAX_RETAINED_SCORED_PASSES,
  openPendingJournal,
  PENDING_JOURNAL_FAMILIES,
  pendingAdmissionStatus,
  pendingItemId,
  pendingMembership,
  PendingJournalWriteRefused,
  resolvePendingJournalPaths,
  unscoredPasses,
} from "../src/pending-journal.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-pending-journal-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const FAMILY = "session";
const HOUR = 60 * 60 * 1000;
const T0 = Date.UTC(2026, 9, 12, 0, 0);
function iso(hours) {
  return new Date(T0 + hours * HOUR).toISOString();
}
function ledgerAt(passId, { generation = "gen-a", ageFloorHours = null } = {}) {
  const ledger = createFactIntegrityLedger();
  return {
    ...ledger,
    generation,
    age_floor_ts: ageFloorHours === null ? null : iso(ageFloorHours),
    continuity: { ...ledger.continuity, last_committed_pass_id: passId, continuity_ok: true, pending_pass: null, last_rewrite_newest_ts: iso(passId) },
  };
}
function passResult(passId, written = 3) {
  return { written_count: written, retention: { pass_id: passId, ledger_generation: "gen-a", pass_time_ms: T0 + passId * HOUR } };
}

async function scoredTick(paths, passId, options = {}) {
  const ledger = options.ledger ?? ledgerAt(passId);
  const { handle, report } = await journalCommittedPass(paths, FAMILY, { passResult: options.passResult ?? passResult(passId), ledger, ts: iso(passId), witnessExists: options.witnessExists ?? false });
  if (options.score !== false) await journalScoredThrough(paths, handle, { ledger, passId, scored: true, ts: iso(passId) });
  return { handle, report };
}

const ITEM = { alert_id: "alert_aaaaaaaaaaaaaaaa", episode: iso(0), incident_key: "lvl:r:4" };

test("journaled families are derived from the declared incumbent rules", () => {
  assert.deepEqual(PENDING_JOURNAL_FAMILIES, ["peer", "process_lineage", "scheduled_job", "service", "session"]);
});

test("pending_restamped_each_pass: each structural pass is mapped, scored and checkpointed, with no discontinuity", async () => {
  const paths = await tempPaths();
  for (let pass = 1; pass <= 3; pass += 1) {
    const { report } = await scoredTick(paths, pass);
    assert.equal(report.discontinuity, null);
    assert.equal(report.mapped, "mapped");
  }
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(3) });
  assert.equal(inspected.status, "valid");
  assert.equal(inspected.state.watermark, 3);
  assert.equal(inspected.state.passes[3].observation_ts, iso(3), "item 16: the durable pass -> observation mapping");
  assert.deepEqual(unscoredPasses(inspected.state), []);
});

test("pending_fast_tick_no_discontinuity: a tick with no committed pass writes nothing", async () => {
  const paths = await tempPaths();
  await scoredTick(paths, 1);
  const { report } = await journalCommittedPass(paths, FAMILY, { passResult: { written_count: 0 }, ledger: ledgerAt(1), ts: iso(1.5) });
  assert.equal(report.mapped, "no_committed_pass");
  assert.equal(report.discontinuity, null);
});

test("watermark_unscorable_pass_excluded: a committed pass never scored is excluded(unadjudicated), never silently normal", async () => {
  const paths = await tempPaths();
  await scoredTick(paths, 1);
  await scoredTick(paths, 2, { score: false }); // crash between the fact commit and detection
  const { handle } = await scoredTick(paths, 3);
  const range = handle.state.ranges.find((entry) => entry.reason === "unadjudicated");
  assert.deepEqual([range.pass_from, range.pass_to, range.observation_ts_from], [2, 2, iso(2)]);
  assert.equal(handle.state.watermark, 3);
  assert.equal(handle.state.passes[2].excluded, "unadjudicated");
});

test("item 16: passes the ledger committed but the journal never mapped are an explicit excluded range", async () => {
  const paths = await tempPaths();
  await scoredTick(paths, 1);
  const { handle } = await scoredTick(paths, 4);
  const range = handle.state.ranges.find((entry) => entry.reason === "unmapped_pass");
  assert.deepEqual([range.pass_from, range.pass_to, range.observation_ts_from, range.observation_ts_to], [2, 3, iso(1), iso(4)]);
});

test("pending_stale_checkpoint_rebuilt: a missing or stale checkpoint is rebuilt with no loss", async () => {
  const paths = await tempPaths();
  const { checkpointFile } = resolvePendingJournalPaths(paths, FAMILY);
  await scoredTick(paths, 1);
  const stale = await fs.readFile(checkpointFile, "utf8");
  await scoredTick(paths, 2);
  await fs.writeFile(checkpointFile, stale);
  const fromStale = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(2) });
  assert.equal(fromStale.status, "valid");
  assert.equal(fromStale.state.watermark, 2);
  await fs.rm(checkpointFile);
  const rebuilt = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(2) });
  assert.equal(rebuilt.status, "valid");
  assert.equal(rebuilt.state.watermark, 2);
});

test("torn_final_record_opens_a_discontinuity: recovery never trims a partial tail as if it were clean", async () => {
  const paths = await tempPaths();
  await scoredTick(paths, 1);
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  await fs.appendFile(journalFile, '{"kind":"torn"');
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) });
  assert.equal(inspected.status, "discontinuity");
  assert.equal(inspected.cause, "journal_torn_tail");
  const handle = await openPendingJournal(paths, FAMILY, { ledger: ledgerAt(2), now: iso(2), passId: 2 });
  assert.equal(handle.discontinuity.cause, "journal_torn_tail");
  assert.equal(handle.state.open_epoch, 1);
});

test("journal_read_error_still_unions_checkpoint: an unreadable journal cannot release its quarantine", async () => {
  const paths = await tempPaths();
  const handle = await quarantinedJournal(paths);
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  await fs.rm(journalFile);
  await fs.mkdir(journalFile);
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) });
  assert.equal(inspected.status, "discontinuity");
  assert.equal(inspected.cause, "journal_unreadable");
  assert.equal(inspected.sources.checkpoint.state.items[idA].state, "quarantined");
  const recovered = await openPendingJournal(paths, FAMILY, { ledger: ledgerAt(2), now: iso(2), passId: 2 });
  assert.equal(recovered.state.items[idA].state, "quarantined");
});

test("pending_checkpoint_bounds_all_passes: 2,000 unscored passes retain at most the advertised 64", () => {
  let state = emptyPendingState(FAMILY);
  const entries = Array.from({ length: 2000 }, (_, index) => ({
    seq: index + 1,
    hash: `h${index + 1}`,
    kind: "pass_committed",
    pass_id: index + 1,
    observation_ts: iso(index + 1),
    pass_time_ms: T0 + (index + 1) * HOUR,
    written_count: 1,
  }));
  state = foldPendingEntries(state, entries);
  assert.ok(Object.keys(state.passes).length <= MAX_RETAINED_SCORED_PASSES);
  assert.ok(state.pass_aggregate.count >= 1900);
});

test("a checkpoint that contradicts the journal is a discontinuity with an open epoch and suspended admission", async () => {
  const paths = await tempPaths();
  const { checkpointFile } = resolvePendingJournalPaths(paths, FAMILY);
  await scoredTick(paths, 1);
  const checkpoint = JSON.parse(await fs.readFile(checkpointFile, "utf8"));
  checkpoint.stamp.journal_head_hash = "0".repeat(64);
  await fs.writeFile(checkpointFile, JSON.stringify(checkpoint));
  const { report, handle } = await scoredTick(paths, 2);
  assert.equal(report.discontinuity.cause, "checkpoint_contradicts_journal");
  assert.equal(handle.state.open_epoch, 1);
  assert.deepEqual(pendingAdmissionStatus(handle.state, iso(2)), { suspended: true, reason: "open_epoch" });
  assert.equal(pendingMembership(handle.state).length, 1, "one unexplained_discontinuity item holds the uncertain membership");
});

test("pending_journal_corrupt_fails_closed: a broken chain restarts on a new chain, keeps the broken file aside", async () => {
  const paths = await tempPaths();
  const { journalFile, brokenFile } = resolvePendingJournalPaths(paths, FAMILY);
  await scoredTick(paths, 1);
  await scoredTick(paths, 2);
  const lines = (await fs.readFile(journalFile, "utf8")).trim().split("\n");
  const edited = JSON.parse(lines[0]);
  edited.observation_ts = iso(99);
  lines[0] = JSON.stringify(edited);
  await fs.writeFile(journalFile, `${lines.join("\n")}\n`);
  const { report, handle } = await scoredTick(paths, 3);
  assert.equal(report.discontinuity.cause, "chain_broken");
  await fs.access(brokenFile);
  const restarted = (await fs.readFile(journalFile, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(restarted[0].kind, "discontinuity");
  assert.equal(restarted[0].restart, true);
  assert.ok(restarted[0].prev_hash.startsWith("lost:"));
  assert.equal((await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(3) })).status, "valid");
  assert.equal(handle.state.open_epoch, 1);
});

async function journalWithItems(paths, entriesFor) {
  const ledger = ledgerAt(1);
  const { handle } = await journalCommittedPass(paths, FAMILY, { passResult: passResult(1), ledger, ts: iso(1) });
  await appendPendingEntries(paths, handle, entriesFor(), { ledger, now: iso(1) });
  await checkpointPendingJournal(paths, handle, { ledger, passId: 1 });
  return handle;
}

const idA = pendingItemId({ ...ITEM, incident_key: "a" });
const idB = pendingItemId({ ...ITEM, incident_key: "b" });

test("pending_discontinuity_keeps_quarantine and pending_discontinuity_unverified_admission_not_honoured", async () => {
  const paths = await tempPaths();
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  await journalWithItems(paths, () => [
    { kind: "opened", item: { ...ITEM, incident_key: "a" }, item_id: idA, scored_pass_id: 1, pass_time_ms: T0 + HOUR, tick: { ts: iso(1), pass_id: 1 } },
    { kind: "opened", item: { ...ITEM, incident_key: "b" }, item_id: idB, scored_pass_id: 1, pass_time_ms: T0 + HOUR, tick: { ts: iso(1), pass_id: 1 } },
    { kind: "quarantined", item_id: idA, reason: "label" },
    { kind: "admitted", item_id: idB, source: "label", scored_pass_id: 1, pass_time_ms: T0 + HOUR },
  ]);
  // Corrupt the admission entry: the verified prefix ends before it; the checkpoint (which still says
  // admitted) no longer matches the journal and is only an unverifiable survivor.
  const lines = (await fs.readFile(journalFile, "utf8")).trim().split("\n");
  const admissionIndex = lines.findIndex((line) => JSON.parse(line).kind === "admitted");
  const admission = JSON.parse(lines[admissionIndex]);
  admission.source = "earned_promotion";
  lines[admissionIndex] = JSON.stringify(admission);
  await fs.writeFile(journalFile, `${lines.join("\n")}\n`);
  const handle = await openPendingJournal(paths, FAMILY, { ledger: ledgerAt(2), now: iso(2), passId: 2 });
  assert.equal(handle.discontinuity.cause, "chain_broken");
  assert.equal(handle.state.items[idA].state, "quarantined", "a surviving quarantine is kept");
  assert.equal(handle.state.items[idB].state, "pending", "an admission only an unverifiable source records is never honoured");
});

test("a lost journal keeps the checkpoint's quarantine; nothing quarantined is ever released", async () => {
  const paths = await tempPaths();
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  await journalWithItems(paths, () => [
    { kind: "opened", item: { ...ITEM, incident_key: "a" }, item_id: idA, scored_pass_id: 1, pass_time_ms: T0 + HOUR },
    { kind: "quarantined", item_id: idA, reason: "label" },
  ]);
  await fs.rm(journalFile);
  const handle = await openPendingJournal(paths, FAMILY, { ledger: ledgerAt(2), now: iso(2), passId: 2 });
  assert.equal(handle.discontinuity.cause, "journal_missing");
  assert.equal(handle.state.items[idA].state, "quarantined");
});

test("both journal and checkpoint deleted, with a surviving witness, is a discontinuity, never a first run", async () => {
  const paths = await tempPaths();
  const { dir } = resolvePendingJournalPaths(paths, FAMILY);
  await scoredTick(paths, 1);
  await fs.rm(dir, { recursive: true });
  const { report } = await scoredTick(paths, 2, { witnessExists: true });
  assert.equal(report.discontinuity.cause, "journal_and_checkpoint_missing");
  const fresh = await tempPaths();
  const { report: first } = await scoredTick(fresh, 1);
  assert.equal(first.created, true);
  assert.equal(first.discontinuity, null);
});

test("pending_recertifies_after_clean_pass: the first clean certified pass after the break closes the epoch", async () => {
  const paths = await tempPaths();
  const { checkpointFile } = resolvePendingJournalPaths(paths, FAMILY);
  await scoredTick(paths, 1);
  await fs.writeFile(checkpointFile, "{not json");
  // Unparseable checkpoint with no cut: only an optimisation lost, no epoch.
  const { report: rebuilt } = await scoredTick(paths, 2);
  assert.equal(rebuilt.discontinuity, null);
  const checkpoint = JSON.parse(await fs.readFile(checkpointFile, "utf8"));
  checkpoint.stamp.journal_seq = 999;
  await fs.writeFile(checkpointFile, JSON.stringify(checkpoint));
  const { report: broke } = await scoredTick(paths, 3);
  assert.equal(broke.discontinuity.cause, "journal_truncated");
  assert.equal(broke.recertified, null, "the pass of the detecting tick does not re-certify");
  const { report: next, handle } = await scoredTick(paths, 4);
  assert.equal(next.recertified, 1);
  assert.equal(handle.state.open_epoch, null);
  assert.equal(pendingAdmissionStatus(handle.state, iso(4)).suspended, false);
  assert.equal(pendingMembership(handle.state).length, 1, "the unexplained item stays pending after re-certification");
});

test("pending_discontinuity_budget_exhausted_suspends_unattended beyond the per-family budget", () => {
  let state = emptyPendingState(FAMILY);
  for (let epoch = 1; epoch <= 4; epoch += 1) {
    state = foldPendingEntries(state, [
      { seq: epoch * 2 - 1, hash: `h${epoch}a`, kind: "discontinuity", epoch, cause: "chain_broken", ts: iso(epoch), pass_id: epoch },
      { seq: epoch * 2, hash: `h${epoch}b`, kind: "recertified", epoch, ts: iso(epoch + 0.5) },
    ]);
  }
  assert.deepEqual(pendingAdmissionStatus(state, iso(5)), { suspended: true, reason: "discontinuity_budget", epochs_in_window: 4 });
  assert.equal(pendingAdmissionStatus(state, new Date(T0 + 31 * 24 * HOUR).toISOString()).suspended, false, "back within budget once the trailing count drops");
});

test("a ledger generation change is a discontinuity on the intact chain; the pass map restarts", async () => {
  const paths = await tempPaths();
  await scoredTick(paths, 5);
  const ledger = ledgerAt(1, { generation: "gen-b" });
  const { report, handle } = await journalCommittedPass(paths, FAMILY, { passResult: { written_count: 2, retention: { pass_id: 1, ledger_generation: "gen-b", pass_time_ms: T0 + 6 * HOUR } }, ledger, ts: iso(6) });
  assert.equal(report.discontinuity.cause, "generation_change");
  assert.equal(handle.state.passes[1]?.observation_ts, iso(6));
  assert.equal(pendingMembership(handle.state).length, 0, "an intact chain has no uncertain membership");
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  const records = (await fs.readFile(journalFile, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(records.some((record) => record.restart), false);
});

test("pending_entry_valid_after_source_age_eviction: certified at write, valid after its source pass ages out", async () => {
  const paths = await tempPaths();
  await journalWithItems(paths, () => [
    { kind: "opened", item: ITEM, item_id: pendingItemId(ITEM), scored_pass_id: 1, pass_time_ms: T0 + HOUR, tick: { ts: iso(1), pass_id: 1 } },
  ]);
  const aged = ledgerAt(40, { ageFloorHours: 30 });
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: aged });
  assert.equal(inspected.status, "valid");
  assert.equal(inspected.state.items[pendingItemId(ITEM)].state, "pending");
  // Retention drops the tick mark (the tick is gone) but the item stays pending.
  const handle = await openPendingJournal(paths, FAMILY, { ledger: aged, now: iso(40) });
  await checkpointPendingJournal(paths, handle, { ledger: aged, passId: 40 });
  const after = await inspectPendingJournal(paths, FAMILY, { ledger: aged });
  assert.deepEqual(after.state.items[pendingItemId(ITEM)].ticks, []);
  assert.equal(after.state.items[pendingItemId(ITEM)].state, "pending");
});

test("certification at write refuses an entry outside the certified span or citing an uncommitted pass", async () => {
  const paths = await tempPaths();
  const ledger = ledgerAt(3, { ageFloorHours: 2 });
  const handle = await openPendingJournal(paths, FAMILY, { ledger, now: iso(3) });
  await assert.rejects(appendPendingEntries(paths, handle, [{ kind: "opened", item: ITEM, item_id: pendingItemId(ITEM), scored_pass_id: 9, pass_time_ms: T0 + 3 * HOUR }], { ledger, now: iso(3) }), PendingJournalWriteRefused);
  await assert.rejects(appendPendingEntries(paths, handle, [{ kind: "opened", item: ITEM, item_id: pendingItemId(ITEM), scored_pass_id: 1, pass_time_ms: T0 + HOUR }], { ledger, now: iso(3) }), PendingJournalWriteRefused);
  await assert.rejects(appendPendingEntries(paths, handle, [{ kind: "admitted", item_id: "x", source: "federated_signature", scored_pass_id: 3, pass_time_ms: T0 + 3 * HOUR }], { ledger, now: iso(3) }), PendingJournalWriteRefused, "federated_signature is reserved and inactive");
  // Restrictive entries never need certification.
  await appendPendingEntries(paths, handle, [{ kind: "excluded", reason: "unadjudicated", pass_from: 1, pass_to: 1 }], { ledger: null, now: iso(3) });
  assert.equal(handle.state.ranges.length, 1);
});

test("pending_cap_compacts_to_excluded: at the cap the oldest unadmitted items compact, never fold, never freeze", () => {
  let state = emptyPendingState(FAMILY);
  const entries = [];
  for (let index = 0; index < MAX_OPEN_PENDING_ITEMS; index += 1) {
    const item = { ...ITEM, incident_key: `k${index}` };
    entries.push({ seq: index + 1, hash: `h${index}`, kind: "opened", item, item_id: pendingItemId(item), ts: iso(1) });
  }
  state = foldPendingEntries(state, entries);
  const compaction = compactionEntriesForCap(state, 1);
  assert.equal(compaction.length, 1);
  assert.deepEqual(compaction[0].item_ids, [pendingItemId({ ...ITEM, incident_key: "k0" })]);
  state = foldPendingEntries(state, [{ seq: MAX_OPEN_PENDING_ITEMS + 1, hash: "hc", ...compaction[0], ts: iso(2) }]);
  assert.equal(state.items[pendingItemId({ ...ITEM, incident_key: "k0" })].state, "excluded");
  assert.equal(state.excluded_summary.by_reason.compacted, 1);
  assert.equal(pendingMembership(state).length, MAX_OPEN_PENDING_ITEMS - 1);
});

test("a cut journal verifies through its header; losing the checkpoint after a cut is a discontinuity", async () => {
  const paths = await tempPaths();
  const { checkpointFile } = resolvePendingJournalPaths(paths, FAMILY);
  for (let pass = 1; pass <= 3; pass += 1) {
    const ledger = ledgerAt(pass);
    const { handle } = await journalCommittedPass(paths, FAMILY, { passResult: passResult(pass), ledger, ts: iso(pass) });
    await appendPendingEntries(paths, handle, [{ kind: "scored_through", pass_id: pass, pass_time_ms: T0 + pass * HOUR }], { ledger, now: iso(pass) });
    await checkpointPendingJournal(paths, handle, { ledger, passId: pass, maxJournalBytes: 100 });
  }
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(3) });
  assert.equal(inspected.status, "valid");
  assert.equal(inspected.state.watermark, 3);
  await fs.rm(checkpointFile);
  const lost = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(3) });
  assert.equal(lost.status, "discontinuity");
  assert.equal(lost.cause, "checkpoint_missing_after_cut");
});

// Adversarial review M5: a restart record is legitimate only as the first record of a fresh chain.
import { sealRecord, verifyChain } from "../src/hash-chain.js";
import { PENDING_JOURNAL_DOMAIN } from "../src/pending-journal.js";

async function quarantinedJournal(paths) {
  const ledger = ledgerAt(1);
  const { handle } = await journalCommittedPass(paths, FAMILY, { passResult: passResult(1), ledger, ts: iso(1) });
  await journalScoredThrough(paths, handle, { ledger, passId: 1, scored: true, ts: iso(1) });
  await appendPendingEntries(paths, handle, [{ kind: "opened", item_id: idA, item: { ...ITEM, incident_key: "a" }, scored_pass_id: 1, pass_time_ms: T0 + HOUR }], { ledger, now: iso(1) });
  await appendPendingEntries(paths, handle, [{ kind: "quarantined", item_id: idA, reason: "label" }], { now: iso(1), restrictiveOnly: true });
  await checkpointPendingJournal(paths, handle, { ledger, passId: 1 });
  return handle;
}

test("a mid-chain restart record is a chain break; its carried_state never replaces the state", async () => {
  const paths = await tempPaths();
  await quarantinedJournal(paths);
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) });
  assert.equal(inspected.state.items[idA].state, "quarantined");
  const carried = structuredClone(inspected.state);
  delete carried.head_seq;
  delete carried.head_hash;
  carried.items[idA].state = "admitted";
  carried.items[idA].disposition = { source: "earned_promotion" };
  const forged = sealRecord(PENDING_JOURNAL_DOMAIN, { prevHash: "lost:x", seq: inspected.state.head_seq + 1 }, { v: 1, ts: iso(2), kind: "discontinuity", family: FAMILY, restart: true, epoch: 1, cause: "x", carried_state: carried });
  await fs.appendFile(journalFile, `${JSON.stringify(forged)}\n`);
  const after = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) });
  assert.equal(after.status, "discontinuity");
  assert.equal(after.cause, "chain_broken");
  const handle = await openPendingJournal(paths, FAMILY, { ledger: ledgerAt(2), now: iso(2), passId: 2 });
  assert.equal(handle.state.items[idA].state, "quarantined", "nothing quarantined is ever released");
});

test("verifyChain accepts a restart citation only on the first record of a chain with no cut header", () => {
  const first = sealRecord("d", { prevHash: "lost:abc", seq: 1 }, { kind: "x", restart: true });
  assert.equal(verifyChain("d", [first]).ok, true);
  const second = sealRecord("d", { prevHash: "lost:def", seq: 2 }, { kind: "x", restart: true });
  assert.equal(verifyChain("d", [first, second]).ok, false);
  const header = { kind: "compacted", through_seq: 4, through_hash: "h4" };
  const afterCut = sealRecord("d", { prevHash: "lost:h4", seq: 5 }, { kind: "x", restart: true });
  assert.equal(verifyChain("d", [header, afterCut]).ok, false);
});

test("a non-restart discontinuity entry's carried_state is never folded", () => {
  const state = foldPendingEntries(emptyPendingState(FAMILY), [
    { seq: 1, hash: "h1", kind: "opened", item_id: idA, item: ITEM, ts: iso(1) },
    { seq: 2, hash: "h2", kind: "quarantined", item_id: idA, reason: "label", ts: iso(1) },
    { seq: 3, hash: "h3", kind: "discontinuity", epoch: 1, cause: "x", ts: iso(2), carried_state: { items: {} } },
  ]);
  assert.equal(state.items[idA].state, "quarantined");
});

// Adversarial review H1: the checkpoint's state is bound to the chain by a chained `checkpointed`
// entry carrying its digest, so editing it in place is a contradiction, before and after a cut.
test("editing checkpoint.json state in place (stamp untouched) is checkpoint_contradicts_journal; nothing quarantined is released", async () => {
  const paths = await tempPaths();
  await quarantinedJournal(paths);
  const { checkpointFile } = resolvePendingJournalPaths(paths, FAMILY);
  const checkpoint = JSON.parse(await fs.readFile(checkpointFile, "utf8"));
  checkpoint.state.items[idA].state = "admitted";
  checkpoint.state.items[idA].disposition = { source: "earned_promotion" };
  checkpoint.state.epochs = [];
  checkpoint.state.open_epoch = null;
  await fs.writeFile(checkpointFile, JSON.stringify(checkpoint));
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) });
  assert.equal(inspected.status, "discontinuity");
  assert.equal(inspected.cause, "checkpoint_contradicts_journal");
  const handle = await openPendingJournal(paths, FAMILY, { ledger: ledgerAt(2), now: iso(2), passId: 2 });
  assert.equal(handle.state.items[idA].state, "quarantined", "the verified journal prefix wins over the edited checkpoint");
});

test("after a cut, an in-place checkpoint state edit is still a contradiction", async () => {
  const paths = await tempPaths();
  const handle = await quarantinedJournal(paths);
  await checkpointPendingJournal(paths, handle, { ledger: ledgerAt(1), passId: 1, maxJournalBytes: 10 });
  const { checkpointFile, journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  assert.equal((await fs.readFile(journalFile, "utf8")).trim().split("\n").length, 1, "only the cut header is left");
  assert.equal((await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) })).status, "valid");
  const checkpoint = JSON.parse(await fs.readFile(checkpointFile, "utf8"));
  checkpoint.state.items[idA].state = "admitted";
  await fs.writeFile(checkpointFile, JSON.stringify(checkpoint));
  const inspected = await inspectPendingJournal(paths, FAMILY, { ledger: ledgerAt(1) });
  assert.equal(inspected.status, "discontinuity");
  assert.equal(inspected.cause, "checkpoint_contradicts_journal");
});

// Adversarial review L1: a family's first tick with no committed pass must not leave a checkpoint
// with no journal (the next tick would read a false journal_missing discontinuity).
test("a first tick with no committed pass creates the journal it reports, and the next tick is clean", async () => {
  const paths = await tempPaths();
  const { handle, report } = await journalCommittedPass(paths, FAMILY, { passResult: { written_count: 3, retention_error: "boom", retention: { pass_id: 1, pass_time_ms: T0 + HOUR } }, ledger: ledgerAt(1), ts: iso(1) });
  assert.equal(report.mapped, "no_committed_pass");
  assert.equal(report.created, true);
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  await fs.access(journalFile);
  await journalScoredThrough(paths, handle, { ledger: ledgerAt(1), passId: 1, scored: true, ts: iso(1) });
  const { report: next } = await scoredTick(paths, 2, { witnessExists: true });
  assert.equal(next.discontinuity, null);
  assert.equal(next.mapped, "mapped");
});

// Adversarial review M2: the discontinuity budget counts every epoch any survivor knows, so repeated
// chain-level loss with no verified prefix still trips it.
test("repeated first-line corruption still trips the discontinuity budget (epochs carried from every survivor)", async () => {
  const paths = await tempPaths();
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  let pass = 1;
  await scoredTick(paths, pass);
  const seen = [];
  for (let round = 0; round < 5; round += 1) {
    const lines = (await fs.readFile(journalFile, "utf8")).split("\n");
    lines[0] = "{not json";
    await fs.writeFile(journalFile, lines.join("\n"));
    pass += 1;
    const { report } = await scoredTick(paths, pass);
    pass += 1;
    const { handle } = await scoredTick(paths, pass);
    seen.push({ epoch: report.discontinuity?.epoch, admission: pendingAdmissionStatus(handle.state, iso(pass)) });
  }
  assert.deepEqual(seen.map((entry) => entry.epoch), [1, 2, 3, 4, 5]);
  assert.deepEqual(seen.map((entry) => entry.admission.suspended), [false, false, false, true, true], "beyond 3 epochs in the window unattended admission stays suspended");
});

test("a witnessed double wipe carries the transition log's epochs into the budget", async () => {
  const paths = await tempPaths();
  const { dir } = resolvePendingJournalPaths(paths, FAMILY);
  await scoredTick(paths, 1);
  await fs.rm(dir, { recursive: true });
  const priorEpochs = [1, 2, 3].map((epoch) => ({ epoch, opened_at: iso(0.5), cause: "chain_broken" }));
  const ledger = ledgerAt(2);
  const { report, handle } = await journalCommittedPass(paths, FAMILY, { passResult: passResult(2), ledger, ts: iso(2), witnessExists: true, priorEpochs });
  assert.equal(report.discontinuity.cause, "journal_and_checkpoint_missing");
  assert.equal(report.discontinuity.epoch, 4, "epoch numbers continue across a wipe");
  assert.deepEqual(handle.state.epochs.map((epoch) => epoch.epoch), [1, 2, 3, 4]);
  const { handle: after } = await scoredTick(paths, 3);
  assert.equal(after.state.open_epoch, null, "re-certified");
  assert.equal(pendingAdmissionStatus(after.state, iso(3)).suspended, true, "the budget still counts the witnessed epochs");
});

// Adversarial review M3 (daemon seam): after the transition log compacted the creation record away,
// wiping the journal directory is still a witnessed discontinuity, never a silent first run.
import { recordAlertTransitions } from "../src/alert-transitions.js";
import { runPendingJournalPrePass } from "../src/pending-journal-daemon.js";

test("the pre-pass reads the carried witness: a wipe after transition-log compaction is a discontinuity", async () => {
  const paths = await tempPaths();
  const structuralFacts = (passId) => ({ families: { session: { written_count: 3, retention: { pass_id: passId, pass_time_ms: T0 + passId * HOUR } } } });
  const first = await runPendingJournalPrePass(paths, { structuralFacts: structuralFacts(1), ts: iso(1), families: ["session"], deliverNotification: async () => ({ status: "delivered" }) });
  assert.equal(first.families.session.report.created, true);
  await recordAlertTransitions(paths, { now: iso(1), alerts: [], extraRecords: [{ kind: "pending_journal_created", family: "session" }] });
  for (let index = 1; index < 60; index += 1) {
    await recordAlertTransitions(paths, { now: iso(1 + index / 100), alerts: [], extraRecords: [{ kind: "excluded_unadjudicated", family: "session", ranges: 1, pad: "x".repeat(200) }], maxBytes: 4000 });
  }
  const { dir } = resolvePendingJournalPaths(paths, FAMILY);
  await fs.rm(dir, { recursive: true });
  const second = await runPendingJournalPrePass(paths, { structuralFacts: structuralFacts(2), ts: iso(2), families: ["session"], deliverNotification: async () => ({ status: "delivered" }) });
  assert.equal(second.families.session.report.created, false);
  assert.equal(second.families.session.report.discontinuity?.cause, "journal_and_checkpoint_missing");
});

// Adversarial review L2: the pre-pass runs before detection, so it never waits on a notification;
// the discontinuity notice is delivered after detection, and an error status is not "notified".
import { deliverPendingJournalNotices } from "../src/pending-journal-daemon.js";

test("the pre-pass never delivers; discontinuity notices go out after detection and an error status is not notified", async () => {
  const paths = await tempPaths();
  const structuralFacts = (passId) => ({ families: { session: { written_count: 3, retention: { pass_id: passId, pass_time_ms: T0 + passId * HOUR } } } });
  const never = async () => { throw new Error("the pre-pass must not deliver"); };
  await runPendingJournalPrePass(paths, { structuralFacts: structuralFacts(1), ts: iso(1), families: ["session"], deliverNotification: never });
  const { journalFile } = resolvePendingJournalPaths(paths, FAMILY);
  await fs.writeFile(journalFile, "{not json\n{}\n");
  const prePass = await runPendingJournalPrePass(paths, { structuralFacts: structuralFacts(2), ts: iso(2), families: ["session"], deliverNotification: never });
  assert.ok(prePass.families.session.report.discontinuity);
  assert.equal(prePass.families.session.report.notified, undefined);
  const failed = await deliverPendingJournalNotices(paths, prePass, { ts: iso(2), deliverNotification: async () => ({ status: "error", error: "timeout" }) });
  assert.equal(failed.length, 1);
  assert.equal(prePass.families.session.report.notified, false);
  assert.equal(prePass.families.session.report.notify_status, "error");
  const delivered = await deliverPendingJournalNotices(paths, prePass, { ts: iso(2), deliverNotification: async () => ({ status: "delivered" }) });
  assert.equal(delivered.length, 1);
  assert.equal(prePass.families.session.report.notified, true);
});

// Adversarial review L4: at a chain-level loss, the label log's quarantining labels are consulted, so a
// quarantine the lost chain recorded is re-applied to every surviving item in its scope.
import { appendAlertLabel } from "../src/alert-labels.js";

test("a discontinuity re-applies the label log's quarantines to surviving items (restrictive only)", async () => {
  const paths = await tempPaths();
  const ledger = ledgerAt(1);
  const { handle } = await journalCommittedPass(paths, FAMILY, { passResult: passResult(1), ledger, ts: iso(1) });
  const opened = { ...ITEM, incident_key: "a" };
  await appendPendingEntries(paths, handle, [{ kind: "opened", item_id: idA, item: opened, scored_pass_id: 1, pass_time_ms: T0 + HOUR }], { ledger, now: iso(1) });
  await checkpointPendingJournal(paths, handle, { ledger, passId: 1 });
  await appendAlertLabel(paths, { label: "suspicious", scope: { kind: "alert", alert_id: ITEM.alert_id }, now: iso(1.5) });
  // The whole journal is lost; only the checkpoint (now unverifiable) survives, with the item pending.
  await fs.rm(resolvePendingJournalPaths(paths, FAMILY).journalFile);
  const prePass = await runPendingJournalPrePass(paths, { structuralFacts: { families: { session: passResult(2) } }, ts: iso(2), families: ["session"] });
  const after = prePass.families.session.handle;
  assert.equal(prePass.families.session.report.discontinuity?.cause, "journal_missing");
  assert.equal(after.state.items[idA].state, "quarantined");
  assert.equal(after.state.items[idA].disposition.from_unverifiable_source, true);
});

test("a verified prefix headed by a restart record contributes the epochs its carried state holds", async () => {
  const paths = await tempPaths();
  const { journalFile, checkpointFile } = resolvePendingJournalPaths(paths, FAMILY);
  let pass = 1;
  await scoredTick(paths, pass);
  for (let round = 0; round < 2; round += 1) {
    const lines = (await fs.readFile(journalFile, "utf8")).split("\n");
    lines[0] = "{not json";
    await fs.writeFile(journalFile, lines.join("\n"));
    pass += 1;
    await scoredTick(paths, pass);
  }
  // Now break the tail (the prefix keeps the restart record) and lose the checkpoint.
  const lines = (await fs.readFile(journalFile, "utf8")).trim().split("\n");
  lines[lines.length - 1] = "{not json";
  await fs.writeFile(journalFile, `${lines.join("\n")}\n`);
  await fs.rm(checkpointFile);
  pass += 1;
  const { report, handle } = await scoredTick(paths, pass);
  assert.equal(report.discontinuity.epoch, 3);
  assert.deepEqual(handle.state.epochs.map((epoch) => epoch.epoch), [1, 2, 3]);
});

test("future-dated quarantining labels are not re-applied before their time", async () => {
  const { labelQuarantineScopes } = await import("../src/alert-labels.js");
  const paths = await tempPaths();
  await appendAlertLabel(paths, { label: "suspicious", scope: { kind: "alert", alert_id: ITEM.alert_id }, now: iso(100) });
  assert.equal((await labelQuarantineScopes(paths, { now: iso(1) })).length, 0);
  assert.equal((await labelQuarantineScopes(paths, { now: iso(101) })).length, 1);
});
