import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

function parseDf(stdout) {
  const lines = stdout.trim().split("\n").slice(1);
  return lines.map((line) => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6) return undefined;
    const [filesystem, blocks, used, available, capacity, ...mountParts] = parts;
    return {
      filesystem,
      size_bytes: Number(blocks) * 1024,
      used_bytes: Number(used) * 1024,
      available_bytes: Number(available) * 1024,
      used_fraction: Number(capacity.replace("%", "")) / 100,
      mount_point: mountParts.join(" "),
    };
  }).filter(Boolean);
}

function parseDfInodes(stdout) {
  const lines = stdout.trim().split("\n").slice(1);
  return lines.map((line) => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6) return undefined;
    const [filesystem, inodes, used, free, capacity, ...mountParts] = parts;
    return {
      filesystem,
      inodes: Number(inodes),
      used_inodes: Number(used),
      free_inodes: Number(free),
      used_fraction: Number(capacity.replace("%", "")) / 100,
      mount_point: mountParts.join(" "),
    };
  }).filter(Boolean);
}

export async function collectDiskEvidence() {
  return timedEnvelope(async () => {
    const [space, inodes] = await Promise.all([
      execFileAsync("df", ["-kP"], { timeout: 3000, maxBuffer: 1024 * 1024 }).then(({ stdout }) => parseDf(stdout)),
      execFileAsync("df", ["-iP"], { timeout: 3000, maxBuffer: 1024 * 1024 }).then(({ stdout }) => parseDfInodes(stdout)).catch((error) => ({ unable: error instanceof Error ? error.message : String(error) })),
    ]);

    return {
      filesystems: space,
      inodes,
      command: {
        argv: [["df", "-kP"], ["df", "-iP"]],
        read_only: true,
      },
    };
  }, (result) => evidenceEnvelope({
    id: "disk-usage",
    source: "filesystem",
    result,
    tool: "collect_disks",
  }));
}
