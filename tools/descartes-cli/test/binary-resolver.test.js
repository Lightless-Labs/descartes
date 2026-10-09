import assert from "node:assert/strict";
import test from "node:test";
import { candidatePaths, parseMacOsAclStatus, resolveCollectorBinary, runResolvedExecFile } from "../src/tools/binary-resolver.js";

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

const readableBinary = async () => Buffer.from("not a script");
const aclAbsent = async () => "absent";

test("parseMacOsAclStatus recognizes a plain file from real ls -led output as ACL-free", () => {
  assert.equal(parseMacOsAclStatus("-rwxr-xr-x  1 root  wheel  170816 Oct  9 16:27 /usr/bin/tool\n"), "absent");
});

test("parseMacOsAclStatus accepts setuid permission bits in real ls -led output", () => {
  assert.equal(parseMacOsAclStatus("-rwsr-xr-x   1 root  wheel  170816 Nov 22  2025 /bin/ps\n"), "absent");
});

test("parseMacOsAclStatus treats an xattr-marked directory as ACL-free", () => {
  assert.equal(parseMacOsAclStatus("drwxr-xr-x@ 39 root  wheel 1248 Nov 22  2025 /bin\n"), "absent");
});

test("parseMacOsAclStatus recognizes a plus-marked ACL and its numbered ACE lines", () => {
  assert.equal(parseMacOsAclStatus(
    "-rw-r--r--+  1 thomas  wheel  0 Oct  9 16:27 /tmp/file\n"
      + " 0: FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6 allow read,write,execute,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity\n",
  ), "present");
});

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
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
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

test("resolveCollectorBinary rejects an ACL-granted writer even when mode bits look safe", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/usr/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/usr/bin/tmux", {
      file: regularExecutable(0o100555),
      ancestors: { "/usr/bin": directory(), "/usr": directory(), "/": directory() },
    }),
    readFileFn: readableBinary,
    aclCheckFn: async (component) => component === "/usr/bin/tmux" ? "present" : "absent",
    expectedUid: 0,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/usr/bin/tmux");
  assert.equal(resolution.trust_reason, "acl_present");
  assert.match(resolution.operator_override_hint, /trusted_binary_paths/);
});

test("resolveCollectorBinary fails closed when ACL state cannot be determined", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate === "/usr/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/usr/bin/tmux", {
      file: regularExecutable(),
      ancestors: { "/usr/bin": directory(), "/usr": directory(), "/": directory() },
    }),
    readFileFn: readableBinary,
    aclCheckFn: async () => "unknown",
    expectedUid: 0,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/usr/bin/tmux");
  assert.equal(resolution.trust_reason, "acl_unknown");
});

test("resolveCollectorBinary rejects a non-writable executable owned by another user", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate,
    statFn: trustedStats("/usr/bin/tmux", {
      file: { ...regularExecutable(0o100555), uid: 2000 },
      ancestors: {
        "/usr": directory(0o40755, 0),
        "/usr/bin": directory(0o40755, 0),
      },
    }),
    readFileFn: readableBinary,
    expectedUid: 1000,
  });

  assert.equal(resolution.status, "untrusted_binary", JSON.stringify(resolution));
  assert.equal(resolution.offending_component, "/usr/bin/tmux");
  assert.equal(resolution.trust_reason, "foreign_owner");
});

test("resolveCollectorBinary rejects an owner-writable executable owned by another user", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate,
    statFn: trustedStats("/usr/bin/tmux", {
      file: { ...regularExecutable(0o100755 | 0o200), uid: 2000 },
      ancestors: {
        "/usr": directory(0o40755, 0),
        "/usr/bin": directory(0o40755, 0),
      },
    }),
    readFileFn: readableBinary,
    expectedUid: 1000,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/usr/bin/tmux");
  assert.equal(resolution.trust_reason, "foreign_owner");
});

test("resolveCollectorBinary rejects a group-writable ancestor without resolving group membership", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: {
        "/opt": directory(),
        "/opt/homebrew": directory(),
        "/opt/homebrew/bin": { ...directory(0o40775, 0), gid: 80 },
      },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    expectedUid: 501,
  });

  assert.equal(resolution.status, "untrusted_binary", JSON.stringify(resolution));
  assert.equal(resolution.offending_component, "/opt/homebrew/bin");
  assert.equal(resolution.trust_reason, "group_writable");
});

test("resolveCollectorBinary rejects a group-writable ancestor with a second admin and exposes the operator override", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: {
        "/opt/homebrew": directory(),
        "/opt/homebrew/bin": { ...directory(0o40775, 0), gid: 80 },
      },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    expectedUid: 501,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/opt/homebrew/bin");
  assert.equal(resolution.trust_reason, "group_writable");
  assert.match(resolution.operator_override_hint, /trusted_binary_paths/);
});

test("resolveCollectorBinary never accepts a trusted shell wrapper as a substitute for a rejected direct binary", async () => {
  const appBinary = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
  const wrapper = "/usr/local/bin/tailscale";
  const resolution = await resolveCollectorBinary("tailscale", {
    platform: "darwin",
    realpathFn: async (candidate) => {
      if (candidate === appBinary || candidate === wrapper) return candidate;
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    statFn: async (target) => {
      if (target === appBinary || target === wrapper) return regularExecutable();
      if (target === "/Applications") return { ...directory(0o40775, 0), gid: 80 };
      if (target === "/Applications/Tailscale.app") return directory();
      if (target === "/Applications/Tailscale.app/Contents") return directory();
      if (target === "/Applications/Tailscale.app/Contents/MacOS") return directory();
      if (target === "/usr/local/bin") return directory();
      if (target === "/usr/local") return directory();
      if (target === "/usr") return directory();
      if (target === "/") return directory();
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    readFileFn: async (target) => target === wrapper ? "#!/bin/sh\n/Applications/Tailscale.app/Contents/MacOS/Tailscale\n" : "mach-o",
    aclCheckFn: aclAbsent,
    expectedUid: 501,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/Applications");
  assert.equal(resolution.trust_reason, "group_writable");
});

test("resolveCollectorBinary resolves symlinks before checking a world-writable target ancestor", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate === "/usr/bin/tmux" ? "/unsafe/tmux" : candidate,
    statFn: trustedStats("/unsafe/tmux", {
      file: { ...regularExecutable(), uid: 1000 },
      ancestors: {
        "/unsafe": directory(0o40777, 1000),
      },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
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
      if (target === "/usr/bin/tmux") return { ...regularExecutable(), uid: 1000 };
      if (target === "/usr/bin") throw Object.assign(new Error("EIO"), { code: "EIO" });
      if (target === "/usr") return directory(0o40755, 0);
      if (target === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
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
    readFileFn: async () => "#!/bin/sh\n",
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
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
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
      if (candidate === "/usr/bin/tmux") return { ...regularExecutable(), uid: 1000, ino: statCount++ === 0 ? 2 : 99 };
      if (candidate === "/usr/bin") return directory(0o40755, 0);
      if (candidate === "/usr") return directory(0o40755, 0);
      if (candidate === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
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
