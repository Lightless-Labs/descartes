import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const PS_COLUMNS = "pid,ppid,pcpu,pmem,rss,comm,args";

export function parsePs(stdout) {
  const lines = stdout.trim().split("\n").slice(1);
  return lines.map((line) => {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\S+)\s*(.*)$/);
    if (!match) return undefined;
    return {
      pid: Number(match[1]),
      ppid: Number(match[2]),
      cpu_percent: Number(match[3]),
      memory_percent: Number(match[4]),
      rss_bytes: Number(match[5]) * 1024,
      command: match[6],
      args: match[7] || match[6],
    };
  }).filter(Boolean);
}

export function psArgsForPlatform(platform = process.platform) {
  if (platform === "linux") {
    // Procps on Linux can reject the BSD-style "-x" personality when combined
    // as "-axo" (observed on Ubuntu arm64). Use POSIX/System V -e instead.
    return ["-eo", PS_COLUMNS];
  }
  return ["-axo", PS_COLUMNS];
}

export function topProcessesBy(processes, key, limit) {
  return [...processes]
    .sort((left, right) => (right[key] ?? 0) - (left[key] ?? 0))
    .slice(0, limit);
}

async function runPs(limit) {
  const args = psArgsForPlatform();
  const { stdout } = await execFileAsync("ps", args, { timeout: 3000, maxBuffer: 1024 * 1024 });
  const processes = parsePs(stdout);
  return {
    top_cpu: topProcessesBy(processes, "cpu_percent", limit),
    top_memory: topProcessesBy(processes, "memory_percent", limit),
    command: {
      argv: ["ps", ...args],
      read_only: true,
    },
  };
}

export async function collectProcessEvidence({ limit = 10 } = {}) {
  return timedEnvelope(async () => runPs(limit), (result) => evidenceEnvelope({
    id: "top-processes",
    source: "process_table",
    result,
    tool: "collect_processes",
    target: `limit=${limit}`,
  }));
}
