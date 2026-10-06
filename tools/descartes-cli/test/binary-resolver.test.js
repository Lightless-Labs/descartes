import assert from "node:assert/strict";
import test from "node:test";
import { resolveCollectorBinary, runResolvedExecFile } from "../src/tools/binary-resolver.js";

function regularExecutable(mode = 0o100755) {
  return { mode, isFile: () => true };
}

test("resolveCollectorBinary uses only pinned absolute candidates and accepts a regular executable", async () => {
  const seen = [];
  const resolution = await resolveCollectorBinary("tailscale", {
    platform: "darwin",
    statFn: async (candidate) => {
      seen.push(candidate);
      if (candidate === "/usr/local/bin/tailscale") return regularExecutable();
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
  });

  assert.equal(resolution.status, "resolved");
  assert.equal(resolution.path, "/usr/local/bin/tailscale");
  assert.ok(seen.every((candidate) => candidate.startsWith("/")));
  assert.equal(seen.includes("tailscale"), false);
});

test("resolveCollectorBinary rejects a candidate in a world-writable directory and reports known-path miss", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    statFn: async (candidate) => {
      if (candidate === "/opt/homebrew/bin/tmux") return regularExecutable();
      if (candidate === "/opt/homebrew/bin") return { mode: 0o40777, isDirectory: () => true };
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
  });

  assert.equal(resolution.status, "not_found_on_known_paths");
  assert.equal(resolution.path, undefined);
});

test("runResolvedExecFile invokes the resolved absolute path, never ambient PATH lookup", async () => {
  const calls = [];
  const result = await runResolvedExecFile("tmux", ["list-sessions"], {
    platform: "darwin",
    statFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux"
      ? regularExecutable()
      : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
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
