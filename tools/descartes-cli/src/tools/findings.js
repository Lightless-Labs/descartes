export function deriveFindings(evidence) {
  const findings = [];
  const byId = Object.fromEntries(evidence.map((item) => [item.id, item]));
  const system = byId["system-overview"]?.result;
  const processes = byId["top-processes"]?.result;
  const disks = byId["disk-usage"]?.result;

  if (system) {
    const [load1] = system.load_average ?? [];
    if (typeof load1 === "number" && system.cpu_count && load1 > system.cpu_count) {
      findings.push({
        id: "high_load_relative_to_cpu_count",
        severity: load1 > system.cpu_count * 1.5 ? "warning" : "notice",
        summary: `1-minute load average ${load1.toFixed(2)} exceeds ${system.cpu_count} CPU cores`,
        evidence_refs: ["system-overview"],
      });
    }

    const used = system.memory?.used_fraction;
    if (typeof used === "number" && used >= 0.9) {
      findings.push({
        id: "memory_pressure",
        severity: used >= 0.97 ? "critical" : "warning",
        summary: `Memory is ${(used * 100).toFixed(0)}% used`,
        evidence_refs: ["system-overview"],
      });
    }

    const swapUsed = system.swap?.used_bytes;
    if (typeof swapUsed === "number" && swapUsed > 0) {
      findings.push({
        id: "swap_pressure",
        severity: swapUsed > 1024 ** 3 ? "warning" : "notice",
        summary: `Swap is active (${formatBytes(swapUsed)} used)`,
        evidence_refs: ["system-overview"],
      });
    }
  }

  if (Array.isArray(disks?.filesystems)) {
    for (const fs of disks.filesystems) {
      if (typeof fs.used_fraction === "number" && fs.used_fraction >= 0.9) {
        findings.push({
          id: `disk_pressure:${fs.mount_point}`,
          severity: fs.used_fraction >= 0.97 ? "critical" : "warning",
          summary: `${fs.mount_point} is ${(fs.used_fraction * 100).toFixed(0)}% full`,
          evidence_refs: ["disk-usage"],
        });
      }
    }
  }

  const topCpu = processes?.top_cpu?.[0];
  if (topCpu && topCpu.cpu_percent >= 100) {
    findings.push({
      id: "single_dominant_cpu_process",
      severity: topCpu.cpu_percent >= 300 ? "warning" : "notice",
      summary: `${topCpu.command} is the top CPU process at ${topCpu.cpu_percent}% CPU`,
      evidence_refs: ["top-processes"],
    });
  }

  const topMemory = processes?.top_memory?.[0];
  if (topMemory && topMemory.memory_percent >= 20) {
    findings.push({
      id: "single_dominant_memory_process",
      severity: topMemory.memory_percent >= 40 ? "warning" : "notice",
      summary: `${topMemory.command} is the top memory process at ${topMemory.memory_percent}% memory`,
      evidence_refs: ["top-processes"],
    });
  }

  if (findings.length === 0) {
    findings.push({
      id: "insufficient_evidence",
      severity: "notice",
      summary: "Initial resource probes did not identify obvious CPU, memory, swap, or disk pressure",
      evidence_refs: evidence.map((item) => item.id),
    });
  }

  return findings;
}

export function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (Math.abs(value) >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}
