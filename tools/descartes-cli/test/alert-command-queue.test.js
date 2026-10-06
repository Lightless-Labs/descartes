import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { applyQueuedAlertCommands, queueOrApplyAlertCommand, resolveAlertCommandQueuePath } from "../src/alert-command-queue.js";
import { writeAlertRecords, readAlertRecords } from "../src/alert-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-command-queue-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_STATE_HOME: path.join(root, "state"), XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_CACHE_HOME: path.join(root, "cache") });
}

test("ack queues while a daemon singleton is owned and daemon application consumes it", async () => {
  const paths = await tempPaths();
  const [alert] = await writeAlertRecords(paths, [{ id: "alert-queued", rule_id: "test.rule", title: "Queued", first_seen: "2026-10-06T00:00:00.000Z" }]);
  const owner = await queueOrApplyAlertCommand(paths, { type: "ack", alert_id: alert.id }, {
    singleton: {
      acquire: async () => { const error = new Error("busy"); error.code = "DAEMON_SINGLETON_BUSY"; throw error; },
    },
    now: "2026-10-06T00:01:00.000Z",
  });
  assert.equal(owner.queued, true);
  assert.match(await fs.readFile(resolveAlertCommandQueuePath(paths), "utf8"), /alert-queued/);
  assert.equal((await readAlertRecords(paths))[0].status, "active");

  const applied = await applyQueuedAlertCommands(paths, { now: "2026-10-06T00:02:00.000Z" });
  assert.deepEqual(applied.applied, [alert.id]);
  assert.equal((await readAlertRecords(paths))[0].status, "acknowledged");
});

test("ack applies directly when the CLI owns the singleton", async () => {
  const paths = await tempPaths();
  const [alert] = await writeAlertRecords(paths, [{ id: "alert-direct", rule_id: "test.rule", title: "Direct", first_seen: "2026-10-06T00:00:00.000Z" }]);
  const result = await queueOrApplyAlertCommand(paths, { type: "ack", alert_id: alert.id }, { now: "2026-10-06T00:01:00.000Z" });
  assert.equal(result.queued, false);
  assert.equal(result.alert.status, "acknowledged");
});
