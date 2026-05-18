import os from "node:os";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

async function collectSwap() {
  if (process.platform === "linux") {
    try {
      const meminfo = await fs.readFile("/proc/meminfo", "utf8");
      const values = Object.fromEntries(
        meminfo.split("\n").map((line) => {
          const match = line.match(/^([^:]+):\s+(\d+)/);
          return match ? [match[1], Number(match[2]) * 1024] : undefined;
        }).filter(Boolean)
      );
      const total = values.SwapTotal ?? 0;
      const free = values.SwapFree ?? 0;
      return { total_bytes: total, free_bytes: free, used_bytes: Math.max(0, total - free), source: "/proc/meminfo" };
    } catch (error) {
      return { unable: error instanceof Error ? error.message : String(error), source: "/proc/meminfo" };
    }
  }

  if (process.platform === "darwin") {
    try {
      const { stdout } = await execFileAsync("sysctl", ["vm.swapusage"], { timeout: 2000, maxBuffer: 1024 * 64 });
      const total = stdout.match(/total = ([\d.]+)([MG])/)?.slice(1, 3);
      const used = stdout.match(/used = ([\d.]+)([MG])/)?.slice(1, 3);
      const free = stdout.match(/free = ([\d.]+)([MG])/)?.slice(1, 3);
      const toBytes = (pair) => {
        if (!pair) return undefined;
        const [value, unit] = pair;
        return Number(value) * (unit === "G" ? 1024 ** 3 : 1024 ** 2);
      };
      return {
        total_bytes: toBytes(total),
        used_bytes: toBytes(used),
        free_bytes: toBytes(free),
        source: "sysctl vm.swapusage",
      };
    } catch (error) {
      return { unable: error instanceof Error ? error.message : String(error), source: "sysctl vm.swapusage" };
    }
  }

  return { unable: `unsupported platform: ${process.platform}` };
}

export async function collectSystemEvidence() {
  return timedEnvelope(async () => {
    const cpus = os.cpus();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const swap = await collectSwap();

    return {
      hostname: os.hostname(),
      platform: process.platform,
      os_type: os.type(),
      os_release: os.release(),
      arch: os.arch(),
      uptime_seconds: os.uptime(),
      cpu_count: cpus.length,
      load_average: os.loadavg(),
      memory: {
        total_bytes: totalMem,
        free_bytes: freeMem,
        used_bytes: Math.max(0, totalMem - freeMem),
        used_fraction: totalMem > 0 ? (totalMem - freeMem) / totalMem : undefined,
      },
      swap,
    };
  }, (result) => evidenceEnvelope({
    id: "system-overview",
    source: "os",
    result,
    tool: "collect_system",
    reviewHint: "none",
  }));
}
