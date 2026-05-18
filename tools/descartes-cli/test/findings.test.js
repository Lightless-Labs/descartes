import assert from "node:assert/strict";
import test from "node:test";
import { deriveFindings, formatBytes } from "../src/tools/findings.js";

test("deriveFindings detects load, memory, swap, disk, and dominant processes", () => {
  const findings = deriveFindings([
    {
      id: "system-overview",
      result: {
        cpu_count: 4,
        load_average: [6, 5, 4],
        memory: { used_fraction: 0.93 },
        swap: { used_bytes: 2 * 1024 ** 3 },
      },
    },
    {
      id: "disk-usage",
      result: { filesystems: [{ mount_point: "/", used_fraction: 0.94 }] },
    },
    {
      id: "top-processes",
      result: {
        top_cpu: [{ command: "Docker", cpu_percent: 350 }],
        top_memory: [{ command: "Docker", memory_percent: 31 }],
      },
    },
  ]);

  assert.deepEqual(findings.map((finding) => finding.id), [
    "high_load_relative_to_cpu_count",
    "memory_pressure",
    "swap_pressure",
    "disk_pressure:/",
    "single_dominant_cpu_process",
    "single_dominant_memory_process",
  ]);
});

test("deriveFindings emits insufficient_evidence when no thresholds trip", () => {
  const findings = deriveFindings([
    { id: "system-overview", result: { cpu_count: 8, load_average: [1, 1, 1], memory: { used_fraction: 0.4 }, swap: { used_bytes: 0 } } },
    { id: "disk-usage", result: { filesystems: [{ mount_point: "/", used_fraction: 0.5 }] } },
    { id: "top-processes", result: { top_cpu: [{ command: "idle", cpu_percent: 2 }], top_memory: [{ command: "idle", memory_percent: 1 }] } },
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "insufficient_evidence");
});

test("formatBytes uses operator-friendly binary units", () => {
  assert.equal(formatBytes(2 * 1024 ** 3), "2.0 GB");
  assert.equal(formatBytes(512), "512 B");
});
