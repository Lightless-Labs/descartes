import assert from "node:assert/strict";
import { test } from "node:test";
import { collectStructuralEvidence, defaultDaemonProfile } from "../src/daemon.js";

test("default profile and structural collection include the canary sub-collector", async () => {
  const profile = defaultDaemonProfile();
  assert.equal(profile.structural.collectors.canary.enabled, true);
  const evidence = await collectStructuralEvidence({ collectors: { canary: { enabled: true } } }, {
    canary: async () => ({ id: "canary", status: "ok", result: { summary: { total_count: 0 }, canaries: [] } }),
  });
  assert.deepEqual(evidence.map((entry) => entry.id), ["canary"]);
});
