import assert from "node:assert/strict";
import test from "node:test";
import { candidatePaths, resolveCollectorBinary, runResolvedExecFile } from "../src/tools/binary-resolver.js";

function regularExecutable(mode = 0o100755) {
  return { mode, uid: 0, dev: 1, ino: 2, isFile: () => true };
}

function directory(mode = 0o40755, uid = 0) {
  return { mode, uid, dev: 1, ino: 3, isDirectory: () => true };
}

function trustedStats(filePath, { file = regularExecutable(), ancestors = {} } = {}) {
  const stats = new Map([
    [filePath, file],
    ["/", directory(0o40755, 0)],
    ...Object.entries(ancestors),
  ]);
  return async (target) => {
    const result = stats.get(target);
    if (result) return result;
    throw Object.assign(new Error(`missing ${target}`), { code: "ENOENT" });
  };
}

test("resolveCollectorBinary uses only pinned absolute candidates and accepts a regular executable", async () => {
  const seen = [];
  const resolution = await resolveCollectorBinary("tailscale", {
    platform: "darwin",
    realpathFn: async (candidate) => {
      if (candidate === "/usr/local/bin/tailscale") return candidate;
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    statFn: async (candidate) => {
      seen.push(candidate);
      if (candidate === "/usr/local/bin/tailscale") return regularExecutable(0o100700);
      if (candidate === "/usr/local/bin") return directory(0o40700, 501);
      if (candidate === "/usr/local") return directory(0o40755, 0);
      if (candidate === "/usr") return directory(0o40755, 0);
      if (candidate === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    expectedUid: 501,
  });

  assert.equal(resolution.status, "resolved", JSON.stringify(resolution));
  assert.equal(resolution.path, "/usr/local/bin/tailscale");
  assert.equal(resolution.trust_verdict, "trusted");
  assert.ok(seen.every((candidate) => candidate.startsWith("/")));
  assert.equal(seen.includes("tailscale"), false);
});

test("candidatePaths includes the standard Nix profile locations for the daemon user", () => {
  const candidates = candidatePaths("tmux", "linux", { homeDir: "/home/daemon", username: "daemon" });
  assert.equal(candidates.includes("/nix/var/nix/profiles/default/bin/tmux"), true);
  assert.equal(candidates.includes("/home/daemon/.nix-profile/bin/tmux"), true);
  assert.equal(candidates.includes("/etc/profiles/per-user/daemon/bin/tmux"), true);
});

test("resolveCollectorBinary rejects a candidate in a world-writable directory as untrusted_binary", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => {
      if (candidate === "/opt/homebrew/bin/tmux") return candidate;
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    statFn: async (candidate) => {
      if (candidate === "/opt/homebrew/bin/tmux") return regularExecutable();
      if (candidate === "/opt/homebrew/bin") return { mode: 0o40777, uid: 0, isDirectory: () => true };
      if (candidate === "/opt/homebrew") return directory(0o40755, 0);
      if (candidate === "/opt") return directory(0o40755, 0);
      if (candidate === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.path, undefined);
  assert.equal(resolution.offending_component, "/opt/homebrew/bin");
});

test("resolveCollectorBinary rejects a regular executable owned by another non-root user", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate,
    statFn: trustedStats("/usr/bin/tmux", {
      file: { ...regularExecutable(0o100755), uid: 2000 },
      ancestors: {
        "/usr": directory(0o40755, 0),
        "/usr/bin": directory(0o40755, 0),
      },
    }),
    expectedUid: 1000,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/usr/bin/tmux");
  assert.equal(resolution.trust_verdict, "untrusted_binary");
});

test("resolveCollectorBinary resolves symlinks before checking a world-writable target ancestor", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate === "/usr/bin/tmux" ? "/unsafe/tmux" : candidate,
    statFn: trustedStats("/unsafe/tmux", {
      ancestors: {
        "/unsafe": directory(0o40777, 1000),
      },
    }),
    expectedUid: 1000,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/unsafe");
  assert.equal(resolution.resolved_path, "/unsafe/tmux");
});

test("resolveCollectorBinary treats an ancestor stat failure as untrusted_binary", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate,
    statFn: async (target) => {
      if (target === "/usr/bin/tmux") return regularExecutable();
      if (target === "/usr/bin") throw Object.assign(new Error("EIO"), { code: "EIO" });
      if (target === "/usr") return directory(0o40755, 0);
      if (target === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    expectedUid: 1000,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/usr/bin");
  assert.equal(resolution.trust_reason, "stat_failed");
});

test("resolveCollectorBinary accepts an explicit absolute operator-trusted path after realpath+regular-file checks", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    trustedBinaryPaths: ["/operator/tmux"],
    realpathFn: async (candidate) => candidate,
    statFn: async (target) => {
      if (target === "/operator/tmux") return { ...regularExecutable(0o100777), uid: 2000 };
      throw Object.assign(new Error("not checked for operator override"), { code: "ENOENT" });
    },
    expectedUid: 1000,
  });

  assert.equal(resolution.status, "resolved");
  assert.equal(resolution.path, "/operator/tmux");
  assert.equal(resolution.resolved_path, "/operator/tmux");
  assert.equal(resolution.trust_verdict, "operator_trusted");
});

test("runResolvedExecFile invokes the resolved absolute path, never ambient PATH lookup", async () => {
  const calls = [];
  const result = await runResolvedExecFile("tmux", ["list-sessions"], {
    platform: "darwin",
    realpathFn: async (candidate) => candidate,
    statFn: async (candidate) => {
      if (candidate === "/opt/homebrew/bin/tmux") return regularExecutable();
      if (candidate === "/opt/homebrew/bin") return directory(0o40755, 0);
      if (candidate === "/opt/homebrew") return directory(0o40755, 0);
      if (candidate === "/opt") return directory(0o40755, 0);
      if (candidate === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    expectedUid: 0,
    execFileAsync: async (...args) => {
      calls.push(args);
      return { stdout: "", stderr: "" };
    },
  });

  assert.equal(result.status, "ok");
  assert.equal(calls[0][0], "/opt/homebrew/bin/tmux");
  assert.deepEqual(result.command.argv, ["/opt/homebrew/bin/tmux", "list-sessions"]);
  assert.equal(result.command.requested_binary, "tmux");
});

test("runResolvedExecFile rechecks the resolved file identity immediately before exec and refuses replacement", async () => {
  const calls = [];
  let statCount = 0;
  const result = await runResolvedExecFile("tmux", ["list-sessions"], {
    platform: "linux",
    realpathFn: async (candidate) => candidate,
    statFn: async (candidate) => {
      if (candidate === "/usr/bin/tmux") return { ...regularExecutable(), ino: statCount++ === 0 ? 2 : 99 };
      if (candidate === "/usr/bin") return directory(0o40755, 0);
      if (candidate === "/usr") return directory(0o40755, 0);
      if (candidate === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    expectedUid: 1000,
    execFileAsync: async (...args) => {
      calls.push(args);
      return { stdout: "", stderr: "" };
    },
  });

  assert.equal(result.status, "untrusted_binary");
  assert.equal(calls.length, 0);
  assert.equal(result.binary.trust_reason, "file_identity_changed");
});
