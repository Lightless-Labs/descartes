import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  acquireDaemonSingleton,
  daemonSingletonPath,
  ownerIsProvablyGone,
} from "../src/daemon-singleton.js";

async function pathsFor(platform = "linux") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-singleton-test-"));
  return {
    stateDir: path.join(root, "state"),
    runtimeDir: path.join(root, "runtime"),
    platform,
  };
}

test("daemon singleton uses O_EXCL and rejects a second owner", async () => {
  const paths = await pathsFor();
  const first = await acquireDaemonSingleton(paths, {
    platform: "linux",
    pid: 101,
    processStartIdentity: "start-a",
    bootIdentity: "boot-a",
    nonce: "nonce-a",
    processAlive: async () => true,
    processStartIdentityForPid: async () => "start-a",
  });

  await assert.rejects(
    acquireDaemonSingleton(paths, {
      platform: "linux",
      pid: 102,
      processStartIdentity: "start-b",
      bootIdentity: "boot-a",
      nonce: "nonce-b",
      processAlive: async () => true,
      processStartIdentityForPid: async () => "start-a",
    }),
    /daemon singleton is already owned/i,
  );

  const stored = JSON.parse(await fs.readFile(daemonSingletonPath(paths), "utf8"));
  assert.deepEqual(stored, {
    pid: 101,
    process_start_identity: "start-a",
    boot_identity: "boot-a",
    nonce: "nonce-a",
  });
  await first.release();
  await assert.rejects(fs.access(daemonSingletonPath(paths)));
});

test("a Linux singleton with a provably dead owner is reclaimed", async () => {
  const paths = await pathsFor();
  await fs.mkdir(path.dirname(daemonSingletonPath(paths)), { recursive: true });
  await fs.writeFile(daemonSingletonPath(paths), JSON.stringify({
    pid: 99999999,
    process_start_identity: "dead-start",
    boot_identity: "boot-a",
    nonce: "old",
  }), { flag: "wx" });

  const owner = await acquireDaemonSingleton(paths, {
    platform: "linux",
    pid: 101,
    processStartIdentity: "start-a",
    bootIdentity: "boot-a",
    nonce: "new",
    processAlive: async () => false,
    processStartIdentityForPid: async () => undefined,
  });
  assert.equal(JSON.parse(await fs.readFile(daemonSingletonPath(paths), "utf8")).nonce, "new");
  await owner.release();
});

test("macOS without a process-start identity refuses to guess that an owner is stale", async () => {
  const paths = await pathsFor("darwin");
  await fs.mkdir(path.dirname(daemonSingletonPath(paths)), { recursive: true });
  await fs.writeFile(daemonSingletonPath(paths), JSON.stringify({
    pid: 99999999,
    process_start_identity: null,
    boot_identity: "boot-a",
    nonce: "old",
  }), { flag: "wx" });

  await assert.rejects(
    acquireDaemonSingleton(paths, {
      platform: "darwin",
      pid: 101,
      processStartIdentity: null,
      bootIdentity: "boot-a",
      processAlive: async () => false,
    }),
    /cannot prove.*gone|clear.*singleton/i,
  );
  assert.equal(JSON.parse(await fs.readFile(daemonSingletonPath(paths), "utf8")).nonce, "old");
});

test("singleton retry timeout uses a monotonic clock", async () => {
  const paths = await pathsFor();
  const clock = [0, 3, 7, 11];
  await fs.mkdir(path.dirname(daemonSingletonPath(paths)), { recursive: true });
  await fs.writeFile(daemonSingletonPath(paths), JSON.stringify({
    pid: 101,
    process_start_identity: "live",
    boot_identity: "boot-a",
    nonce: "live",
  }), { flag: "wx" });

  await assert.rejects(
    acquireDaemonSingleton(paths, {
      platform: "linux",
      timeoutMs: 10,
      retryMs: 1,
      monotonicNow: () => clock.shift() ?? 11,
      processAlive: async () => true,
      processStartIdentityForPid: async () => "live",
    }),
    /timed out.*monotonic/i,
  );
});
