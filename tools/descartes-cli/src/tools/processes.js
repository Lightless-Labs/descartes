import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

function parsePs(stdout) {
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

async function runPs(sortFlag, limit) {
  const args = ["-axo", "pid,ppid,pcpu,pmem,rss,comm,args", sortFlag];
  const { stdout } = await execFileAsync("ps", args, { timeout: 3000, maxBuffer: 1024 * 1024 });
  return parsePs(stdout).slice(0, limit);
}

export async function collectProcessEvidence({ limit = 10 } = {}) {
  return timedEnvelope(async () => {
    const [topCpu, topMemory] = await Promise.all([
      runPs("-r", limit),
      runPs("-m", limit),
    ]);

    return {
      top_cpu: topCpu,
      top_memory: topMemory,
      command: {
        argv: ["ps", "-axo", "pid,ppid,pcpu,pmem,rss,comm,args", "-r|-m"],
        read_only: true,
      },
    };
  }, (result) => evidenceEnvelope({
    id: "top-processes",
    source: "process_table",
    result,
    tool: "collect_processes",
    target: `limit=${limit}`,
  }));
}
