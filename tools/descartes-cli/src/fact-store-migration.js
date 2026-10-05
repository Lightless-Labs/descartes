// S5: the legacy single-store quarantine (fact-store capacity plan 2026-10-05 §4.6 M2/M3; operator
// Q3 = fresh per-family stores, Q4 = quarantine for 31 days outside the facts tree, then delete).
//
// M2 needs no code: S4 moved every store to learned/facts/<family>/, so each family store starts at
// the existing missing-ledger bootstrap (first read `unknown`, then `intact`) and no trust is ever
// carried over from the legacy file (I8). What remains is the legacy tree itself:
//   - learned/facts/facts.jsonl and learned/facts/integrity.json (the pre-S4 shared store + ledger;
//     on a real host the ledger carries an in-window last_bytecap_evict_ts -- the 31-day tail);
//   - learned/facts/seen-sets/ (the pre-S4 S3b seen-set location, plan §18 deviation 11);
//   - stray `facts.jsonl.<pid>.tmp` / `integrity.json.<pid>.tmp` rewrite leftovers.
// M3 moves them OUT of the facts tree into learned/facts-legacy-<iso>/, so nothing under
// learned/facts/ is a file or directory the registry does not name (every reader and the sweep
// iterate the registry anyway; this is the second layer). No trust path reads the quarantine.
//
// Idempotent per file: the marker (learned/facts-legacy.json) records the target directory BEFORE
// anything moves, so a crash between two renames resumes into the SAME directory and the half-moved
// state is never treated as a live store. A legacy file that reappears after a completed quarantine
// (a downgrade, then an upgrade) goes to a NEW directory.
//
// Deletion (Q4): a quarantine is removed 31 days after it was taken. The marker is same-UID writable,
// so a directory is deleted only when the marker lists it AND its name matches the strict
// facts-legacy-<safe iso> pattern (no separators, no dot segments) -- a tampered marker can at worst
// delete another quarantine early, never anything else. An unparseable marker deletes nothing.

import fs from "node:fs/promises";
import path from "node:path";

export const LEGACY_QUARANTINE_RETENTION_MS = 31 * 24 * 60 * 60 * 1000;
const MARKER_SCHEMA_VERSION = 2;
const LEGACY_ITEMS = ["facts.jsonl", "integrity.json", "seen-sets"];
const LEGACY_TMP_PATTERN = /^(facts\.jsonl|integrity\.json)\.\d+\.tmp$/;
const QUARANTINE_DIR_PATTERN = /^facts-legacy-[0-9A-Za-z-]+$/;

export function resolveLegacyFactStorePaths(descartesPaths) {
  const learnedDir = path.join(descartesPaths.stateDir, "learned");
  return {
    learnedDir,
    factsRootDir: path.join(learnedDir, "facts"),
    markerFile: path.join(learnedDir, "facts-legacy.json"),
  };
}

function isQuarantineDirName(value) {
  return typeof value === "string" && QUARANTINE_DIR_PATTERN.test(value);
}

function isIso(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

async function exists(file) {
  try {
    await fs.lstat(file);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

// { marker, valid } -- `valid: false` for a present but unparseable/ill-shaped marker: its entries are
// never acted on (nothing is deleted on its say-so).
async function readMarker(markerFile) {
  let contents;
  try {
    contents = await fs.readFile(markerFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { marker: { schema_version: MARKER_SCHEMA_VERSION, in_progress: null, quarantines: [], quarantine_epoch: 0, quarantine_epoch_ts: null }, valid: true, present: false };
    throw error;
  }
  try {
    const parsed = JSON.parse(contents);
    const baseShapeOk = parsed && typeof parsed === "object" && !Array.isArray(parsed)
      && (parsed.schema_version === 1 || parsed.schema_version === MARKER_SCHEMA_VERSION)
      && Array.isArray(parsed.quarantines)
      && (parsed.in_progress === null || (parsed.in_progress && typeof parsed.in_progress === "object"));
    if (!baseShapeOk) return { marker: { schema_version: MARKER_SCHEMA_VERSION, in_progress: null, quarantines: [], quarantine_epoch: 0, quarantine_epoch_ts: null }, valid: false, present: true };
    const validV2 = parsed.schema_version === MARKER_SCHEMA_VERSION
      && Number.isSafeInteger(parsed.quarantine_epoch)
      && parsed.quarantine_epoch >= 0
      && (parsed.quarantine_epoch_ts === null || isIso(parsed.quarantine_epoch_ts));
    if (parsed.schema_version === MARKER_SCHEMA_VERSION && !validV2) {
      return { marker: { schema_version: MARKER_SCHEMA_VERSION, in_progress: null, quarantines: [], quarantine_epoch: 0, quarantine_epoch_ts: null }, valid: false, present: true };
    }
    // Schema 1 markers predate the epoch. They remain readable, but their latest quarantine time
    // becomes the epoch's timestamp so a later re-quarantine is still distinguishable.
    const latestQuarantineTs = parsed.quarantines
      .map((entry) => entry?.quarantined_ts)
      .filter(isIso)
      .sort()
      .at(-1) ?? null;
    return {
      marker: {
        ...parsed,
        schema_version: MARKER_SCHEMA_VERSION,
        quarantine_epoch: parsed.schema_version === MARKER_SCHEMA_VERSION ? parsed.quarantine_epoch : 0,
        quarantine_epoch_ts: parsed.schema_version === MARKER_SCHEMA_VERSION ? parsed.quarantine_epoch_ts : latestQuarantineTs,
      },
      valid: true,
      present: true,
    };
  } catch {
    return { marker: { schema_version: MARKER_SCHEMA_VERSION, in_progress: null, quarantines: [], quarantine_epoch: 0, quarantine_epoch_ts: null }, valid: false, present: true };
  }
}

async function writeMarker(markerFile, marker) {
  await fs.mkdir(path.dirname(markerFile), { recursive: true, mode: 0o700 });
  const tmpFile = `${markerFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, `${JSON.stringify(marker, null, 2)}\n`, { mode: 0o600 });
  await fs.rename(tmpFile, markerFile);
}

async function presentLegacyItems(factsRootDir) {
  const items = [];
  for (const item of LEGACY_ITEMS) if (await exists(path.join(factsRootDir, item))) items.push(item);
  let names = [];
  try {
    names = await fs.readdir(factsRootDir);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  for (const name of names.sort()) if (LEGACY_TMP_PATTERN.test(name)) items.push(name);
  return items;
}

/**
 * G2 H1: whether this install ever held (or still holds) a legacy single store -- the marker exists
 * (in any state, even unparseable), or any legacy item is still at the facts root (a quarantine that
 * failed or has not run yet). Consulted by the novelty seen-set fold when it would otherwise certify
 * memory "complete since the lineage began" (certified_since_ts null): after an upgrade a family
 * store's lineage begins at the upgrade, but the host's history does not -- the sightings it held
 * were quarantined, never read again. Read-only. Any error other than ENOENT counts as evidence
 * (fail conservative: a horizon-short window, never a claim over lost history).
 */
export async function legacyFactHistoryEvidence(descartesPaths) {
  const { factsRootDir, markerFile } = resolveLegacyFactStorePaths(descartesPaths);
  try {
    if (await exists(markerFile)) return true;
    return (await presentLegacyItems(factsRootDir)).length > 0;
  } catch {
    return true;
  }
}

/**
 * Return the last trusted quarantine epoch for the seen-set certification boundary. A present but
 * unreadable/ill-shaped marker is explicitly untrusted: callers must advance their boundary to
 * their current pass time rather than continue a null/old certification. Root legacy items without
 * a marker are likewise conservative evidence of a migration that did not complete.
 */
export async function legacyQuarantineEpoch(descartesPaths, { now } = {}) {
  const { factsRootDir, markerFile } = resolveLegacyFactStorePaths(descartesPaths);
  const nowMs = now !== undefined ? new Date(now).getTime() : Date.now();
  let markerResult;
  try {
    markerResult = await readMarker(markerFile);
  } catch {
    return { status: "unreadable", epoch: null, epoch_ts: null };
  }
  if (!markerResult.valid) return { status: "unreadable", epoch: null, epoch_ts: null };
  const rootItems = await presentLegacyItems(factsRootDir).catch(() => null);
  if (rootItems === null) return { status: "unreadable", epoch: null, epoch_ts: null };
  if (rootItems.length > 0) return { status: "legacy_pending", epoch: null, epoch_ts: null };
  if (Number.isFinite(nowMs) && markerResult.marker.quarantine_epoch_ts !== null
    && Date.parse(markerResult.marker.quarantine_epoch_ts) > nowMs) {
    // A clock correction makes the marker's future timestamp untrustworthy. Present it as a new
    // discard episode at this pass, so the seen-set cannot remain ineligible until the old future.
    return { status: "future", epoch: markerResult.marker.quarantine_epoch + 1, epoch_ts: new Date(nowMs).toISOString() };
  }
  return {
    status: markerResult.present ? "valid" : "absent",
    epoch: markerResult.marker.quarantine_epoch,
    epoch_ts: markerResult.marker.quarantine_epoch_ts,
  };
}

function quarantineDirName(nowIso) {
  return `facts-legacy-${nowIso.replace(/[:.]/g, "-")}`;
}

async function uniqueTarget(dir, item) {
  let candidate = path.join(dir, item);
  for (let suffix = 1; await exists(candidate); suffix += 1) candidate = path.join(dir, `${item}.${suffix}`);
  return candidate;
}

function normalizeMovedItems(value) {
  const byItem = new Map();
  for (const entry of Array.isArray(value) ? value : []) {
    if (entry && typeof entry.item === "string" && entry.item.length > 0 && isIso(entry.moved_ts)) {
      byItem.set(entry.item, entry.moved_ts);
    }
  }
  return byItem;
}

function serializeMovedItems(movedItems) {
  return [...movedItems.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([item, moved_ts]) => ({ item, moved_ts }));
}

function quarantineDeleteAfterMs(entry) {
  const timestamps = [entry.quarantined_ts, ...normalizeMovedItems(entry.moved_items).values()]
    .map((value) => Date.parse(value))
    .filter(Number.isFinite);
  return timestamps.length > 0 ? Math.max(...timestamps) + LEGACY_QUARANTINE_RETENTION_MS : Number.NaN;
}

/**
 * Quarantines the legacy single store (M3) and deletes quarantines older than 31 days (Q4). Returns
 * { status: "none" | "quarantined" | "resumed", quarantine_dir?, moved: [...], deleted: [...],
 * pending: [{dir, quarantined_ts, delete_after_ts}] }. Throws on an I/O failure (the daemon reports
 * it and retries next tick; a half-done move resumes into the same directory).
 */
export async function migrateLegacyFactStore(descartesPaths, { now } = {}) {
  const nowMs = now !== undefined ? new Date(now).getTime() : Date.now();
  if (!Number.isFinite(nowMs)) throw new Error("migrateLegacyFactStore requires a valid now");
  const nowIso = new Date(nowMs).toISOString();
  const { learnedDir, factsRootDir, markerFile } = resolveLegacyFactStorePaths(descartesPaths);
  const { marker, valid, present } = await readMarker(markerFile);
  const quarantines = valid ? marker.quarantines.filter((entry) => entry && isQuarantineDirName(entry.dir) && isIso(entry.quarantined_ts)) : [];
  const resumable = valid && marker.in_progress && isQuarantineDirName(marker.in_progress.dir) && isIso(marker.in_progress.started_ts)
    ? marker.in_progress
    : null;

  let status = "none";
  let quarantineDir;
  let markerEpoch = marker.quarantine_epoch;
  let markerEpochTs = marker.quarantine_epoch_ts;
  const moved = [];
  const items = await presentLegacyItems(factsRootDir);
  if (valid && !resumable && items.length === 0 && isIso(markerEpochTs) && Date.parse(markerEpochTs) > nowMs) {
    // A future-dated marker is itself discarded evidence after a clock rollback. Advance the epoch
    // and stamp the correction pass even when no legacy file remains to move.
    markerEpoch += 1;
    markerEpochTs = nowIso;
    await writeMarker(markerFile, {
      schema_version: MARKER_SCHEMA_VERSION,
      in_progress: null,
      quarantines,
      quarantine_epoch: markerEpoch,
      quarantine_epoch_ts: markerEpochTs,
    });
  }
  if (items.length > 0 || resumable) {
    // A pass that moves root data is a new discard episode, even when it resumes an existing
    // quarantine directory. Seen-sets use this pair as their novelty boundary; retaining the old
    // pair would let data discovered during downtime become eligible immediately after resume.
    const movesRootItems = items.length > 0;
    const eventEpoch = movesRootItems ? markerEpoch + 1 : (resumable?.quarantine_epoch ?? (markerEpoch + 1));
    const eventTs = movesRootItems ? nowIso : (resumable?.quarantine_ts ?? resumable?.started_ts ?? nowIso);
    markerEpoch = eventEpoch;
    markerEpochTs = eventTs;
    const movedItems = normalizeMovedItems(resumable?.moved_items);
    const inProgress = resumable
      ? { ...resumable, quarantine_epoch: eventEpoch, quarantine_ts: eventTs, moved_items: serializeMovedItems(movedItems) }
      : { dir: quarantineDirName(nowIso), started_ts: nowIso, quarantine_epoch: eventEpoch, quarantine_ts: eventTs, moved_items: [] };
    status = resumable ? "resumed" : "quarantined";
    quarantineDir = inProgress.dir;
    // Record the target BEFORE anything moves (crash -> resume into the same directory).
    await writeMarker(markerFile, {
      schema_version: MARKER_SCHEMA_VERSION,
      in_progress: inProgress,
      quarantines,
      quarantine_epoch: eventEpoch,
      quarantine_epoch_ts: eventTs,
    });
    const target = path.join(learnedDir, inProgress.dir);
    await fs.mkdir(target, { recursive: true, mode: 0o700 });
    if (resumable) {
      // An old in-progress marker may predate per-item timestamps. Stamp already-present target
      // items at this observation before any deletion decision; extending retention is safe, while
      // falling back to the original started_ts could delete a half-moved item too early.
      for (const targetItem of (await fs.readdir(target)).sort()) {
        if (!movedItems.has(targetItem)) movedItems.set(targetItem, nowIso);
      }
      inProgress.moved_items = serializeMovedItems(movedItems);
      await writeMarker(markerFile, {
        schema_version: MARKER_SCHEMA_VERSION,
        in_progress: inProgress,
        quarantines,
        quarantine_epoch: eventEpoch,
        quarantine_epoch_ts: eventTs,
      });
    }
    for (const item of items) {
      const destination = await uniqueTarget(target, item);
      movedItems.set(path.basename(destination), nowIso);
      inProgress.moved_items = serializeMovedItems(movedItems);
      // Record the per-item move time before the rename, so a crash after the rename cannot lose
      // the retention boundary for the newly moved item.
      await writeMarker(markerFile, {
        schema_version: MARKER_SCHEMA_VERSION,
        in_progress: inProgress,
        quarantines,
        quarantine_epoch: eventEpoch,
        quarantine_epoch_ts: eventTs,
      });
      await fs.rename(path.join(factsRootDir, item), destination);
      moved.push(item);
    }
    const quarantineEntry = quarantines.find((entry) => entry.dir === inProgress.dir);
    if (quarantineEntry) quarantineEntry.moved_items = serializeMovedItems(movedItems);
    else quarantines.push({ dir: inProgress.dir, quarantined_ts: inProgress.started_ts, moved_items: serializeMovedItems(movedItems) });
    await writeMarker(markerFile, {
      schema_version: MARKER_SCHEMA_VERSION,
      in_progress: null,
      quarantines,
      quarantine_epoch: eventEpoch,
      quarantine_epoch_ts: eventTs,
    });
  }

  const deleted = [];
  if (valid) {
    const kept = [];
    for (const entry of quarantines) {
      if (nowMs >= quarantineDeleteAfterMs(entry)) {
        await fs.rm(path.join(learnedDir, entry.dir), { recursive: true, force: true });
        deleted.push(entry.dir);
      } else {
        kept.push(entry);
      }
    }
    if (deleted.length > 0) await writeMarker(markerFile, {
      schema_version: MARKER_SCHEMA_VERSION,
      in_progress: null,
      quarantines: kept,
      quarantine_epoch: markerEpoch,
      quarantine_epoch_ts: markerEpochTs,
    });
    quarantines.splice(0, quarantines.length, ...kept);
  }
  return {
    status,
    ...(quarantineDir ? { quarantine_dir: quarantineDir } : {}),
    moved,
    deleted,
    ...(present && !valid ? { marker: "invalid" } : {}),
    pending: quarantines.map((entry) => ({
      dir: entry.dir,
      quarantined_ts: entry.quarantined_ts,
      delete_after_ts: new Date(quarantineDeleteAfterMs(entry)).toISOString(),
    })),
  };
}
