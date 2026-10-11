// Context plan C2 (docs/plans/2026-10-06-context-aware-learned-baselines.md §8.1): store plumbing for
// the long-memory families -- per-family retention, derived families, and the pass a retention run
// committed.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { appendFactPoints, DEFAULT_FACT_RETENTION_MS, enforceFactRetention } from "../src/fact-store.js";
import { readFactIntegrityLedger } from "../src/fact-store-integrity.js";
import {
  DEFAULT_FAMILY_RETENTION_MS,
  FACT_FAMILY_IDS,
  FAMILY_HORIZON_MAX_MS,
  FAMILY_RETENTION_MS,
  familyRetentionMs,
} from "../src/fact-families.js";

const DAY = 24 * 60 * 60 * 1000;

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-c2-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("C2 per-family retention: every family has one, the default is the old shared 30 days, and none is shorter than its horizon", () => {
  assert.equal(DEFAULT_FAMILY_RETENTION_MS, DEFAULT_FACT_RETENTION_MS);
  assert.equal(DEFAULT_FAMILY_RETENTION_MS, 30 * DAY);
  for (const family of FACT_FAMILY_IDS) {
    assert.ok(FAMILY_RETENTION_MS.has(family), family);
    assert.equal(familyRetentionMs(family), FAMILY_RETENTION_MS.get(family));
    assert.ok(familyRetentionMs(family) >= (FAMILY_HORIZON_MAX_MS.get(family) ?? 0), `${family}: retention below its horizon`);
  }
  assert.throws(() => familyRetentionMs("not_a_family"), /unknown fact family/);
});

test("C2 retention result names the pass it committed (generation and pass id), matching the ledger", async () => {
  const paths = await tempPaths();
  const ts = "2026-10-11T10:00:00.000Z";
  const appended = await appendFactPoints(paths, [{ ts, fact_name: "service.presence", entity_key: "svc.a", attributes: {} }], { family: "service", now: ts });
  const { ledger } = await readFactIntegrityLedger(paths, "service");
  assert.equal(appended.retention.ledger_generation, ledger.generation);
  assert.equal(appended.retention.pass_id, ledger.continuity.last_committed_pass_id);
  const swept = await enforceFactRetention(paths, { family: "service", now: ts });
  const { ledger: after } = await readFactIntegrityLedger(paths, "service");
  assert.equal(swept.pass_id, appended.retention.pass_id + 1);
  assert.equal(swept.pass_id, after.continuity.last_committed_pass_id);
});
