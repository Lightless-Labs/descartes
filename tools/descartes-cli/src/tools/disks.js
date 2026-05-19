import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const VIRTUAL_FILESYSTEMS = new Set([
  "autofs",
  "binfmt_misc",
  "bpf",
  "cgroup",
  "cgroup2",
  "configfs",
  "debugfs",
  "devfs",
  "devpts",
  "devtmpfs",
  "efivarfs",
  "fusectl",
  "hugetlbfs",
  "mqueue",
  "proc",
  "pstore",
  "securityfs",
  "sysfs",
  "tmpfs",
  "tracefs",
]);

function parseNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function parseDfRow(line, kind) {
  const parts = line.trim().split(/\s+/);
  const capacityIndex = parts.findIndex((part) => /^\d+%$/.test(part));
  if (capacityIndex < 4) return undefined;

  const metric1 = parseNumber(parts[capacityIndex - 3]);
  const metric2 = parseNumber(parts[capacityIndex - 2]);
  const metric3 = parseNumber(parts[capacityIndex - 1]);
  const filesystem = parts.slice(0, capacityIndex - 3).join(" ");
  const capacity = Number(parts[capacityIndex].replace("%", "")) / 100;
  const mountPoint = parts.slice(capacityIndex + 1).join(" ");
  if (!filesystem || !mountPoint || !Number.isFinite(capacity)) return undefined;

  const base = {
    filesystem,
    used_fraction: capacity,
    mount_point: mountPoint,
  };

  if (kind === "space") {
    return classifyFilesystem({
      ...base,
      size_bytes: metric1 === null ? null : metric1 * 1024,
      used_bytes: metric2 === null ? null : metric2 * 1024,
      available_bytes: metric3 === null ? null : metric3 * 1024,
    });
  }

  return classifyFilesystem({
    ...base,
    inodes: metric1,
    used_inodes: metric2,
    free_inodes: metric3,
  });
}

export function parseDf(stdout) {
  const lines = stdout.trim().split("\n").slice(1);
  return lines.map((line) => parseDfRow(line, "space")).filter(Boolean);
}

export function parseDfInodes(stdout) {
  const lines = stdout.trim().split("\n").slice(1);
  return lines.map((line) => parseDfRow(line, "inodes")).filter(Boolean);
}

export function classifyFilesystem(fs) {
  const filesystem = String(fs.filesystem ?? "");
  const mountPoint = String(fs.mount_point ?? "");
  const lowerFs = filesystem.toLowerCase();

  let classification = "external_or_other";
  let pressure_relevant = true;

  if (VIRTUAL_FILESYSTEMS.has(lowerFs) || lowerFs.startsWith("map ") || lowerFs === "map") {
    classification = "virtual";
    pressure_relevant = false;
  } else if (
    mountPoint.includes("/Library/Developer/CoreSimulator/Volumes/") ||
    mountPoint.includes("/Library/Developer/CoreSimulator/Cryptex/Images/") ||
    mountPoint.includes("/private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain")
  ) {
    classification = "developer_runtime_image";
    pressure_relevant = false;
  } else if (mountPoint === "/System/Volumes/Data" || mountPoint.startsWith("/System/Volumes/Data/")) {
    classification = "apfs_data";
  } else if (
    (mountPoint === "/" && /^\/dev\/disk/i.test(filesystem)) ||
    mountPoint.startsWith("/System/Volumes/Preboot") ||
    mountPoint.startsWith("/System/Volumes/Update") ||
    mountPoint.startsWith("/System/Volumes/VM") ||
    mountPoint.startsWith("/System/Volumes/xarts") ||
    mountPoint.startsWith("/System/Volumes/iSCPreboot") ||
    mountPoint.startsWith("/System/Volumes/Hardware")
  ) {
    classification = "apfs_system";
  }

  return {
    ...fs,
    classification,
    pressure_relevant,
  };
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
