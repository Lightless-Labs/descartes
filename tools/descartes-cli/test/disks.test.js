import assert from "node:assert/strict";
import test from "node:test";
import { classifyFilesystem, parseDf, parseDfInodes } from "../src/tools/disks.js";

test("parseDf classifies macOS virtual and CoreSimulator filesystems", () => {
  const filesystems = parseDf(`Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/disk3s1s1 1948455240 12161344 88418844 13% /
devfs 249 249 0 100% /dev
/dev/disk3s5 1948455240 1834502720 88418844 96% /System/Volumes/Data
/dev/disk7s1 19380224 18845428 486292 98% /Library/Developer/CoreSimulator/Volumes/iOS_22D8075
`);

  assert.equal(filesystems[0].classification, "apfs_system");
  assert.equal(filesystems[0].pressure_relevant, true);
  assert.equal(filesystems[1].classification, "virtual");
  assert.equal(filesystems[1].pressure_relevant, false);
  assert.equal(filesystems[2].classification, "apfs_data");
  assert.equal(filesystems[2].pressure_relevant, true);
  assert.equal(filesystems[3].classification, "developer_runtime_image");
  assert.equal(filesystems[3].pressure_relevant, false);
  assert.equal(classifyFilesystem({
    filesystem: "/dev/disk12s1",
    mount_point: "/private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain-v17.3.48.0.AvFyDt",
    used_fraction: 0.97,
  }).pressure_relevant, false);
});

test("parseDf handles macOS map rows with spaces in filesystem name", () => {
  const filesystems = parseDf(`Filesystem 1024-blocks Used Available Capacity Mounted on
map -hosts 0 0 0 100% /System/Volumes/Data/home
`);

  assert.deepEqual(filesystems[0], {
    filesystem: "map -hosts",
    size_bytes: 0,
    used_bytes: 0,
    available_bytes: 0,
    used_fraction: 1,
    mount_point: "/System/Volumes/Data/home",
    classification: "virtual",
    pressure_relevant: false,
  });
});

test("parseDfInodes handles map rows and preserves null nonnumeric inode metrics", () => {
  const inodes = parseDfInodes(`Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on
map -hosts 0 0 0 100% /System/Volumes/Data/home
map auto_home - - - 100% /System/Volumes/Data/home
`);

  assert.equal(inodes[0].mount_point, "/System/Volumes/Data/home");
  assert.equal(inodes[0].classification, "virtual");
  assert.equal(inodes[1].filesystem, "map auto_home");
  assert.equal(inodes[1].inodes, null);
});

test("classifyFilesystem treats Linux pseudo filesystems as virtual but leaves normal mounts relevant", () => {
  assert.deepEqual(classifyFilesystem({ filesystem: "tmpfs", mount_point: "/run", used_fraction: 0.99 }), {
    filesystem: "tmpfs",
    mount_point: "/run",
    used_fraction: 0.99,
    classification: "virtual",
    pressure_relevant: false,
  });
  assert.deepEqual(classifyFilesystem({ filesystem: "/dev/nvme0n1p2", mount_point: "/", used_fraction: 0.91 }), {
    filesystem: "/dev/nvme0n1p2",
    mount_point: "/",
    used_fraction: 0.91,
    classification: "external_or_other",
    pressure_relevant: true,
  });
});
