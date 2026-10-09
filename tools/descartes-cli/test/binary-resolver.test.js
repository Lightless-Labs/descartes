import assert from "node:assert/strict";
import test from "node:test";
import {
  candidatePaths,
  binaryProvenance,
  detectAclStatus,
  parseMacOsAclStatus,
  resolveCollectorBinary,
  runResolvedExecFile,
} from "../src/tools/binary-resolver.js";

function regularExecutable(mode = 0o100755) {
  return { mode, uid: 0, dev: 1, ino: 2, isFile: () => true };
}

function directory(mode = 0o40755, uid = 0) {
  return { mode, uid, dev: 1, ino: 3, isDirectory: () => true };
}

function groupWritableDirectory(gid, uid = 0) {
  return { ...directory(0o40775, uid), gid };
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

test("Linux ACL probe does not treat a bare getfattr exit 1 as proof that an ACL is absent", async () => {
  const status = await detectAclStatus("/usr/bin/tmux", {
    platform: "linux",
    stat: regularExecutable(),
    execFileAsync: async () => {
      throw Object.assign(new Error("Permission denied"), { code: 1, stderr: "Permission denied" });
    },
  });

  assert.equal(status, "unknown");
});

test("Linux ACL probe accepts only explicit absent-attribute evidence for access and directory-default ACLs", async () => {
  const calls = [];
  const status = await detectAclStatus("/usr/local/bin", {
    platform: "linux",
    stat: directory(),
    execFileAsync: async (command, args) => {
      calls.push(args);
      throw Object.assign(new Error("No such attribute"), { code: 1, stderr: "getfattr: /usr/local/bin: No such attribute" });
    },
  });

  assert.equal(status, "absent");
  assert.deepEqual(calls.map((args) => args[1]), ["--name=system.posix_acl_access", "--name=system.posix_acl_default"]);
});

test("Linux ACL probe accepts ENODATA as absent but keeps other nonzero ACL errors unknown", async () => {
  const absent = await detectAclStatus("/usr/bin/tmux", {
    platform: "linux",
    stat: regularExecutable(),
    execFileAsync: async () => {
      throw Object.assign(new Error("No data"), { code: "ENODATA", stderr: "" });
    },
  });
  const unknown = await detectAclStatus("/usr/bin/tmux", {
    platform: "linux",
    stat: regularExecutable(),
    execFileAsync: async () => {
      throw Object.assign(new Error("unsupported"), { code: 95, stderr: "Operation not supported" });
    },
  });

  assert.equal(absent, "absent");
  assert.equal(unknown, "unknown");
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

test("resolveCollectorBinary trusts a macOS admin group containing root, a non-authenticating system account, and the daemon", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: {
        "/opt": directory(),
        "/opt/homebrew": directory(),
        "/opt/homebrew/bin": groupWritableDirectory(80),
      },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root _mbsetupuser thomas\nPrimaryGroupID: 80\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root _mbsetupuser thomas\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\n_mbsetupuser 248\nthomas 20\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/_mbsetupuser AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 248\nNo such key: AuthenticationAuthority\n" };
      if (args.join(" ") === ". -read /Users/thomas AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 502\nAuthenticationAuthority: ;ShadowHash;\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "resolved", JSON.stringify(resolution));
  assert.equal(resolution.path, "/opt/homebrew/bin/tmux");
  assert.deepEqual(resolution.accepted_system_accounts, [{ name: "_mbsetupuser", uid: 248 }]);
  assert.deepEqual(binaryProvenance(resolution).accepted_system_accounts, [{ name: "_mbsetupuser", uid: 248 }]);
});

test("resolveCollectorBinary rejects a partial macOS GroupMembership lookup even when the full record named writers", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root thomas attacker\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") throw new Error("partial dscl attribute read");
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.trust_reason, "group_membership_unverifiable");
});

test("resolveCollectorBinary rejects a macOS uid-below-501 account with ShadowHash authentication", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt": directory(), "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root olduser thomas\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root olduser thomas\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/olduser AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 400\nAuthenticationAuthority: ;ShadowHash;\n" };
      if (args.join(" ") === ". -read /Users/thomas AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 502\nAuthenticationAuthority: ;ShadowHash;\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/opt/homebrew/bin");
  assert.equal(resolution.trust_reason, "writer_set_not_subset_allowed");
  assert.deepEqual(resolution.writer_uids, [0, 400, 502]);
});

test("resolveCollectorBinary rejects every low-UID macOS account authority except absent or DisabledUser", async () => {
  for (const authority of [";LocalCachedUser;", ";ApplePasswordServer;", ";ShadowHash;", ";Kerberos;", ";Unknown;"]) {
    const resolution = await resolveCollectorBinary("tmux", {
      platform: "darwin",
      realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
      statFn: trustedStats("/opt/homebrew/bin/tmux", {
        ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
      }),
      readFileFn: readableBinary,
      aclCheckFn: aclAbsent,
      execFileAsync: async (command, args) => {
        assert.equal(command, "/usr/bin/dscl");
        if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
        if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
        if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root olduser\n" };
        if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root olduser\n" };
        if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\n" };
        if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
        if (args.join(" ") === ". -read /Users/olduser AuthenticationAuthority UniqueID") return { stdout: `UniqueID: 400\nAuthenticationAuthority: ${authority}\n` };
        throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
      },
      expectedUid: 502,
    });

    assert.equal(resolution.status, "untrusted_binary", authority);
    assert.equal(resolution.trust_reason, "writer_set_not_subset_allowed", authority);
  }
});

test("resolveCollectorBinary accepts a low-UID macOS account disabled by AuthenticationAuthority", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt": directory(), "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default /BSD/local\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root disabled\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root disabled\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/disabled AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 400\nAuthenticationAuthority: ;DisabledUser;\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "resolved", JSON.stringify(resolution));
  assert.deepEqual(resolution.accepted_system_accounts, [{ name: "disabled", uid: 400 }]);
});

test("resolveCollectorBinary includes macOS GroupMembers GUIDs and rejects an extra resolved local user", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root thomas\nGroupMembers: GUID-ATTACKER\n" };
      if (args.join(" ") === ". -search /Users GeneratedUID GUID-ATTACKER") return { stdout: "attacker\t\tGeneratedUID = (\n    \"GUID-ATTACKER\"\n)\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root thomas\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\nthomas 20\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/thomas AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 502\nAuthenticationAuthority: ;ShadowHash;\n" };
      if (args.join(" ") === ". -read /Users/attacker AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 503\nAuthenticationAuthority: ;ShadowHash;\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.trust_reason, "writer_set_not_subset_allowed");
  assert.deepEqual(resolution.writer_uids, [0, 502, 503]);
});

test("resolveCollectorBinary fails closed with directory_bound when macOS authentication search policy is not local-only", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default /LDAPv3/example.com\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.trust_reason, "directory_bound");
});

test("resolveCollectorBinary rejects a macOS uid-at-or-above-501 extra user even without authentication authority", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root thomas other\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root thomas other\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/thomas AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 502\nAuthenticationAuthority: ;ShadowHash;\n" };
      if (args.join(" ") === ". -read /Users/other AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 503\nNo such key: AuthenticationAuthority\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/opt/homebrew/bin");
  assert.equal(resolution.trust_reason, "writer_set_not_subset_allowed");
  assert.deepEqual(resolution.writer_uids, [0, 502, 503]);
});

test("resolveCollectorBinary rejects a macOS group-writable ancestor when the local group has another user", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: {
        "/opt/homebrew": directory(),
        "/opt/homebrew/bin": groupWritableDirectory(80),
      },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root thomas other\nPrimaryGroupID: 80\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root thomas other\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\nthomas 20\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/thomas AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 502\n" };
      if (args.join(" ") === ". -read /Users/other AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 503\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/opt/homebrew/bin");
  assert.equal(resolution.trust_reason, "writer_set_not_subset_allowed");
  assert.deepEqual(resolution.writer_uids, [0, 502, 503]);
  assert.match(resolution.operator_override_hint, /trusted_binary_paths/);
});

test("resolveCollectorBinary rejects a macOS nested group as unverifiable", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root thomas\nNestedGroups: nested-uuid\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.trust_reason, "group_membership_unverifiable");
});

test("resolveCollectorBinary rejects a macOS non-local group node as unverifiable", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "darwin",
    realpathFn: async (candidate) => candidate === "/opt/homebrew/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/opt/homebrew/bin/tmux", {
      ancestors: { "/opt/homebrew": directory(), "/opt/homebrew/bin": groupWritableDirectory(80) },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /LDAPv3/example\nGroupMembership: root thomas\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 502,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.trust_reason, "group_membership_unverifiable");
});

test("resolveCollectorBinary rejects every Linux group-writable component", async () => {
  const resolution = await resolveCollectorBinary("tmux", {
    platform: "linux",
    realpathFn: async (candidate) => candidate === "/usr/local/bin/tmux" ? candidate : (() => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })(),
    statFn: trustedStats("/usr/local/bin/tmux", {
      ancestors: { "/usr": directory(), "/usr/local": directory(), "/usr/local/bin": groupWritableDirectory(80) },
      file: { ...regularExecutable(), uid: 0, gid: 80 },
    }),
    readFileFn: readableBinary,
    aclCheckFn: aclAbsent,
    expectedUid: 501,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.trust_reason, "group_writable");
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
    execFileAsync: async (command, args) => {
      assert.equal(command, "/usr/bin/dscl");
      if (args.join(" ") === "/Search -read / CSPSearchPath") return { stdout: "CSPSearchPath: /Local/Default\n" };
      if (args.join(" ") === ". -list /Groups PrimaryGroupID") return { stdout: "admin 80\n" };
      if (args.join(" ") === ". -read /Groups/admin") return { stdout: "AppleMetaNodeLocation: /Local/Default\nGroupMembership: root thomas other\n" };
      if (args.join(" ") === ". -read /Groups/admin GroupMembership") return { stdout: "GroupMembership: root thomas other\n" };
      if (args.join(" ") === ". -list /Users PrimaryGroupID") return { stdout: "root 0\nthomas 20\n" };
      if (args.join(" ") === ". -read /Users/root AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 0\n" };
      if (args.join(" ") === ". -read /Users/thomas AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 501\n" };
      if (args.join(" ") === ". -read /Users/other AuthenticationAuthority UniqueID") return { stdout: "UniqueID: 503\n" };
      throw new Error(`unexpected dscl argv: ${args.join(" ")}`);
    },
    expectedUid: 501,
  });

  assert.equal(resolution.status, "untrusted_binary");
  assert.equal(resolution.offending_component, "/Applications");
  assert.equal(resolution.trust_reason, "writer_set_not_subset_allowed");
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

test("runResolvedExecFile refuses an in-place content change on the same file identity", async () => {
  const calls = [];
  let readCount = 0;
  const result = await runResolvedExecFile("tmux", ["list-sessions"], {
    platform: "linux",
    realpathFn: async (candidate) => candidate,
    statFn: async (candidate) => {
      if (candidate === "/usr/bin/tmux") return { ...regularExecutable(), uid: 1000, size: 4, mtimeMs: 10 };
      if (candidate === "/usr/bin") return directory(0o40755, 0);
      if (candidate === "/usr") return directory(0o40755, 0);
      if (candidate === "/") return directory(0o40755, 0);
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
    readFileFn: async () => Buffer.from(readCount++ === 0 ? "good" : "evil"),
    aclCheckFn: aclAbsent,
    expectedUid: 1000,
    execFileAsync: async (...args) => {
      calls.push(args);
      return { stdout: "", stderr: "" };
    },
  });

  assert.equal(result.status, "untrusted_binary");
  assert.equal(calls.length, 0);
  assert.equal(result.binary.trust_reason, "content_changed_in_place");
});

test("resolveCollectorBinary evaluates a brew-upgrade path with a new inode independently", async () => {
  let version = "3.6a";
  const contentHashCache = new Map();
  const statFn = async (target) => {
    if (target === "/opt/homebrew/bin/tmux") {
      return { ...regularExecutable(), uid: 0, dev: 1, ino: version === "3.6a" ? 2 : 99, size: 4, mtimeMs: 10 };
    }
    if (target.startsWith("/opt/homebrew/Cellar/") || target === "/opt/homebrew/bin") return directory(0o40755, 0);
    if (target === "/opt/homebrew" || target === "/opt") return directory(0o40755, 0);
    if (target === "/") return directory(0o40755, 0);
    throw Object.assign(new Error("missing"), { code: "ENOENT" });
  };
  const realpathFn = async (target) => {
    if (target === "/opt/homebrew/bin/tmux") return `/opt/homebrew/Cellar/tmux/${version}/bin/tmux`;
    throw Object.assign(new Error("missing"), { code: "ENOENT" });
  };
  const readFileFn = async () => Buffer.from(version);
  const options = {
    platform: "darwin",
    realpathFn,
    statFn,
    readFileFn,
    aclCheckFn: aclAbsent,
    expectedUid: 0,
    contentHashCache,
  };

  const first = await resolveCollectorBinary("tmux", options);
  version = "3.6b";
  const second = await resolveCollectorBinary("tmux", options);

  assert.equal(first.status, "resolved", JSON.stringify(first));
  assert.equal(second.status, "resolved", JSON.stringify(second));
  assert.notEqual(first.resolved_path, second.resolved_path);
  assert.notEqual(first.file_stat.ino, second.file_stat.ino);
});
