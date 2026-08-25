import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  CREDENTIAL_CATEGORY_VALUES,
  collectCredentialAccessEvidence,
  credentialPathHash,
  resolveDefaultCredentialPaths,
} from "../src/tools/credential-access.js";

test("resolveDefaultCredentialPaths returns the fixed v1 list — every entry watches only mtime/ino (O7: atime disabled for all v1 entries), every category is closed-enum, and every entry is a FIXED LITERAL filename (no glob)", () => {
  const entries = resolveDefaultCredentialPaths({ homeDir: "/home/op" });
  assert.ok(entries.length > 0);
  for (const entry of entries) {
    assert.ok(CREDENTIAL_CATEGORY_VALUES.has(entry.category), `unexpected category ${entry.category}`);
    assert.deepEqual(entry.watch, ["mtime", "ino"], "O7: no v1 entry may watch atime");
    assert.equal(typeof entry.path, "string");
    assert.equal(entry.path.includes("*"), false, "must be a fixed literal filename, never a glob pattern");
  }
  // O6: none of the high-churn paths excluded from v1 are present.
  const paths = entries.map((entry) => entry.path);
  assert.equal(paths.some((p) => p.includes(".kube")), false);
  assert.equal(paths.some((p) => p.includes(".docker")), false);
  assert.equal(paths.some((p) => p.includes("gcloud")), false);
  assert.equal(paths.some((p) => p.endsWith(".npmrc")), false);
});

test("credentialPathHash is a stable 16-hex digest of the literal path, domain-separated, and the literal path never survives into the hash string", () => {
  const hash = credentialPathHash("/home/op/.ssh/id_ed25519");
  assert.match(hash, /^[0-9a-f]{16}$/);
  assert.equal(hash, credentialPathHash("/home/op/.ssh/id_ed25519"));
  assert.notEqual(hash, credentialPathHash("/home/op/.ssh/id_rsa"));
});

test("a missing path degrades to status:'absent' -- never a fabricated stat (P5)", async () => {
  const evidence = await collectCredentialAccessEvidence({
    paths: [{ category: "ssh_private_key", path: "/no/such/file", watch: ["mtime", "ino"] }],
    lstat: async () => { const error = new Error("missing"); error.code = "ENOENT"; throw error; },
  });
  assert.equal(evidence.status, "ok");
  const entry = evidence.result.entries[0];
  assert.equal(entry.status, "absent");
  assert.equal(entry.atime, undefined);
  assert.equal(entry.mtime, undefined);
  assert.equal(entry.ino, undefined);
});

test("a permission-denied lstat degrades to status:'unreadable' -- never 'untouched' (P4), and the envelope degrades to warning", async () => {
  const evidence = await collectCredentialAccessEvidence({
    paths: [{ category: "aws_credentials", path: "/restricted/credentials", watch: ["mtime", "ino"] }],
    lstat: async () => { const error = new Error("denied"); error.code = "EACCES"; throw error; },
  });
  assert.equal(evidence.result.entries[0].status, "unreadable");
  assert.equal(evidence.status, "warning");
});

test("a present, readable path returns numeric atime/mtime/ino plus the closed-enum category and hashed path_hash", async () => {
  const stat = { atime: new Date("2026-08-24T00:00:00.000Z"), mtime: new Date("2026-08-24T00:00:00.000Z"), ino: 12345, size: 400 };
  const evidence = await collectCredentialAccessEvidence({
    paths: [{ category: "netrc", path: "/home/op/.netrc", watch: ["mtime", "ino"] }],
    lstat: async () => stat,
  });
  const entry = evidence.result.entries[0];
  assert.equal(entry.status, "ok");
  assert.equal(entry.category, "netrc");
  assert.equal(entry.path_hash, credentialPathHash("/home/op/.netrc"));
  assert.equal(typeof entry.atime, "number");
  assert.equal(typeof entry.mtime, "number");
  assert.equal(typeof entry.ino, "number");
  assert.equal(entry.ino, 12345);
  assert.equal(entry.size, 400);
  assert.deepEqual(entry.watch, ["mtime", "ino"]);
});

test("a non-finite lstat stat degrades to unreadable and never emits NaN evidence", async () => {
  const evidence = await collectCredentialAccessEvidence({
    paths: [{ category: "ssh_private_key", path: "/home/op/.ssh/id_ed25519", watch: ["mtime", "ino"] }],
    lstat: async () => ({ atime: new Date(1), mtime: Number.NaN, ino: 3, size: 4 }),
  });
  assert.equal(evidence.status, "warning");
  assert.equal(evidence.result.entries[0].status, "unreadable");
  assert.equal("mtime" in evidence.result.entries[0], false);
});

test("path never leaks: no literal path/username substring survives into any evidence field, only category + path_hash", async () => {
  const homeDir = "/Users/attacker-victim-name";
  const entries = resolveDefaultCredentialPaths({ homeDir });
  const evidence = await collectCredentialAccessEvidence({
    paths: entries,
    lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
  });
  const serialized = JSON.stringify(evidence);
  assert.equal(serialized.includes("attacker-victim-name"), false);
  assert.equal(serialized.includes(homeDir), false);
});

test("content-read invariant: the CODE (comments stripped) never references readFile/open/readdir/execFile as a bare identifier — lstat only, no directory enumeration surface, no subprocess", async () => {
  const source = await fs.readFile(new URL("../src/tools/credential-access.js", import.meta.url), "utf8");
  const codeOnly = source
    .split("\n")
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  assert.doesNotMatch(codeOnly, /\breadFile\b/);
  assert.doesNotMatch(codeOnly, /\bopen\s*\(/);
  assert.doesNotMatch(codeOnly, /\breaddir\b/);
  assert.doesNotMatch(codeOnly, /execFile|child_process/);
});

test("collectCredentialAccessEvidence calls lstat exactly once per configured path and never any other fs read primitive (injected spy proof)", async () => {
  let lstatCalls = 0;
  const paths = [
    { category: "ssh_private_key", path: "/a", watch: ["mtime", "ino"] },
    { category: "ssh_config", path: "/b", watch: ["mtime", "ino"] },
  ];
  const evidence = await collectCredentialAccessEvidence({
    paths,
    lstat: async () => { lstatCalls += 1; return { atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }; },
  });
  assert.equal(lstatCalls, 2);
  assert.equal(evidence.result.entries.length, 2);
  assert.equal(evidence.result.summary.total_count, 2);
  assert.equal(evidence.result.summary.ok_count, 2);
});

test("real filesystem smoke test (native, no injected lstat): a real present file yields status 'ok' with a real numeric mtime/ino, a real absent path yields 'absent'", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-credential-access-"));
  try {
    const file = path.join(dir, "id_ed25519");
    await fs.writeFile(file, "fixture-key-material");
    const evidence = await collectCredentialAccessEvidence({
      paths: [
        { category: "ssh_private_key", path: file, watch: ["mtime", "ino"] },
        { category: "ssh_private_key", path: path.join(dir, "does-not-exist"), watch: ["mtime", "ino"] },
      ],
    });
    assert.equal(evidence.result.entries[0].status, "ok");
    assert.ok(Number.isFinite(evidence.result.entries[0].mtime));
    assert.ok(Number.isFinite(evidence.result.entries[0].ino));
    assert.equal(evidence.result.entries[1].status, "absent");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
