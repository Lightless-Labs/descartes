import assert from "node:assert/strict";
import test from "node:test";
import { assertSafeTriageToolNames, FORBIDDEN_TRIAGE_TOOL_NAMES, TRIAGE_TOOL_NAMES } from "../src/tool-policy.js";

test("triage investigation active tools are exactly Descartes read-only evidence tools", () => {
  assert.deepEqual(TRIAGE_TOOL_NAMES, [
    "collect_system",
    "collect_processes",
    "collect_disks",
    "inspect_process",
    "inspect_parent_tree",
    "sample_dimension",
    "read_sampling_artifact",
    "collect_triage_evidence",
    "derive_findings",
  ]);
  assert.doesNotThrow(() => assertSafeTriageToolNames(TRIAGE_TOOL_NAMES));
});

test("triage investigation tool policy rejects Pi coding and shell tools", () => {
  for (const forbidden of FORBIDDEN_TRIAGE_TOOL_NAMES) {
    assert.throws(
      () => assertSafeTriageToolNames([...TRIAGE_TOOL_NAMES, forbidden]),
      /Unsafe Descartes triage tool surface/
    );
  }
});

test("triage investigation tool policy rejects missing or unexpected tools", () => {
  assert.throws(() => assertSafeTriageToolNames(TRIAGE_TOOL_NAMES.slice(1)), /missing tools/);
  assert.throws(() => assertSafeTriageToolNames([...TRIAGE_TOOL_NAMES, "collect_logs"]), /unexpected tools/);
});
