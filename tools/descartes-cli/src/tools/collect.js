import { collectDiskEvidence } from "./disks.js";
import { collectProcessEvidence } from "./processes.js";
import { collectSystemEvidence } from "./system.js";
import { deriveFindings } from "./findings.js";

export async function collectAllEvidence(options = {}) {
  const evidence = await Promise.all([
    collectSystemEvidence(options),
    collectProcessEvidence(options),
    collectDiskEvidence(options),
  ]);
  return {
    evidence,
    findings: deriveFindings(evidence),
    actions_taken: [],
  };
}
