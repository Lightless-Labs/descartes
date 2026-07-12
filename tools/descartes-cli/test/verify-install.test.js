// S3-priv Slice 5 Phase 2 Part D — verify-install.sh checking-logic tests, against locally-created
// scratch fixtures (one per failure mode). See
// crates/descartes-root-helper/scripts/verify-install.sh's own header comment for the full check
// list, and docs/plans/2026-07-11-s3-priv-elevated-read-path.md Slice 5 for the acceptance
// criteria this exercises.
//
// Linux-gated throughout (`{ skip: process.platform !== "linux" }`, matching this repo's existing
// darwin-only-skip pattern in provenance-warnings.test.js / provenance.test.js) so this file runs
// in the Linux CI `npm test` job and skips entirely on macOS. getcap/findmnt/GNU-stat are
// confirmed present on the CI guest (pre-flight probe, Buildkite #123).
//
// Fixtures that need a root-owned leaf file (to isolate a check that runs AFTER the owner check
// in the script -- group, mode, ancestor-directory, getcap, mount) additionally require
// passwordless `sudo` (also confirmed available on the CI guest) plus a real, locally-created
// `descartes-provenance` system group (created once via `groupadd -f --system`, mirroring step 1
// of docs/operator/linux-elevated-provenance-setup.md -- safe/self-cleaning here because tart-ci
// VMs are ephemeral per-job clones). On a Linux dev box WITHOUT passwordless sudo, those specific
// tests are individually skipped (registered with a per-test `skip`, computed once at module
// load, exactly like the platform check) rather than failing -- only the getcap/setcap POSITIVE
// case needs a real grant, which is Slice 6's privileged CI job, not this file.
//
// The named-systemd-fallback checks (script section 8) are exercised the same fixture-driven way,
// but via a fake `systemctl` shim on PATH (see buildSystemctlShim below) rather than a real
// systemd install/unit -- no version of Descartes CI runs inside a live systemd instance, so this
// is the only way to cover that block at all, not just the cheapest one.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(new URL("../../../crates/descartes-root-helper/scripts/verify-install.sh", import.meta.url));

const IS_LINUX = process.platform === "linux";

// Computed once, synchronously, Linux-only -- never shells out to `sudo`/`groupadd` on macOS.
function probeSudo() {
  if (!IS_LINUX) return false;
  const result = spawnSync("sudo", ["-n", "true"], { stdio: "ignore" });
  return result.status === 0;
}

function ensureProvenanceGroup() {
  const result = spawnSync("sudo", ["-n", "groupadd", "-f", "--system", "descartes-provenance"], { stdio: "ignore" });
  return result.status === 0;
}

const HAVE_SUDO = probeSudo();
const HAVE_GROUP = HAVE_SUDO && ensureProvenanceGroup();

function runVerify(args, options = {}) {
  return spawnSync(SCRIPT_PATH, args, { encoding: "utf8", ...options });
}

function sudo(args) {
  return spawnSync("sudo", ["-n", ...args], { encoding: "utf8" });
}

function mkScratchDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "descartes-verify-install-test-"));
}

function cleanup(dir) {
  try {
    // The common case: nothing under `dir` was ever chowned to root, so this test process (the
    // owner of `dir`, created via mkdtemp) can unlink everything directly.
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // buildTrustedLeaf chowns the leaf's immediate parent directory to root (needed to pass the
    // script's ancestor-walk check); most temp dirs live under a sticky-bit /tmp, so once `dir`
    // itself is root-owned, this unprivileged process can no longer remove the `dir` ENTRY at
    // all (sticky bit restricts removal within the parent to the entry's own owner or root),
    // regardless of `dir`'s own mode. Fall back to the same passwordless sudo these tests
    // already require to have been constructed in the first place.
    sudo(["rm", "-rf", dir]);
  }
}

// Builds a root-owned, correctly-scoped baseline leaf fixture (owner root, group
// descartes-provenance, mode 0750) so a later, deliberately-wrong check can be reached and
// exercised in isolation rather than being masked by an earlier (owner/group/mode) failure.
// Must be called BEFORE the containing tree is sealed (see mkTrustedHelperTree/
// sealTrustedHelperTree) -- this writes the file as the unprivileged test process, which needs
// write access to the containing directory to do so.
function buildTrustedLeaf(helperPath) {
  fs.writeFileSync(helperPath, "#!/bin/sh\nexit 0\n");
  const chown = sudo(["chown", "root:descartes-provenance", helperPath]);
  if (chown.status !== 0) return false;
  const chmod = sudo(["chmod", "0750", helperPath]);
  return chmod.status === 0;
}

// The script's ancestor-directory walk requires EVERY directory from the leaf's immediate parent
// up to and including '/' to be root-owned -- not merely the immediate parent. '/tmp' and '/'
// are already root-owned by default, but a fresh `mkScratchDir()` result (and, transitively, a
// nested subdirectory under it) is owned by this unprivileged test process, so BOTH it and a
// nested "libexec" leaf-holding directory must be sealed to root -- mirroring the real deployment
// shape of `/usr/local/libexec/descartes/` sitting inside root-owned `/usr/local/libexec`.
// This tree is used for NOTHING but the helper leaf/leaves: any ancillary fixture a test needs
// (a config file, a PATH shim dir) must live in an entirely separate `mkScratchDir()` tree that
// is never sealed, since an unprivileged process can no longer write into this one once sealed.
// Call `buildTrustedLeaf` for every leaf that belongs inside it FIRST, THEN call
// `sealTrustedHelperTree` exactly once.
function mkTrustedHelperTree() {
  // Deliberately NOT under os.tmpdir(): /tmp is unconditionally mode 1777 (world-writable,
  // mitigated only by the sticky bit) on every mainstream Linux distro, which the script's
  // ancestor-walk correctly and unconditionally rejects -- a fixture meant to PASS that walk can
  // never live under /tmp at all, regardless of anything this test does to it. `/opt` (like the
  // real deployment prefix `/usr/local`) is root-owned and not group/world-writable by default.
  const root = `/opt/descartes-verify-install-test-${randomUUID()}`;
  const helperDir = path.join(root, "libexec");
  const username = os.userInfo().username;
  assert.equal(sudo(["mkdir", "-p", helperDir]).status, 0, `could not create ${helperDir} under /opt`);
  // Hand ownership of the freshly-created tree to this unprivileged test process first, so
  // buildTrustedLeaf's plain fs.writeFileSync can populate it; sealTrustedHelperTree flips it
  // back to root afterward.
  assert.equal(sudo(["chown", "-R", `${username}:${username}`, root]).status, 0);
  return { root, helperDir };
}

function sealTrustedHelperTree({ root, helperDir }) {
  // 0755 (not the mkdtemp default 0700): verify-install.sh itself runs as this unprivileged test
  // process, which needs SEARCH (execute) permission on every ancestor directory just to `stat`
  // the leaf at all -- matching how real system directories like `/usr/local/libexec` are
  // normally world-readable/traversable, just not world-WRITABLE. 0755 has no group/other write
  // bit, so it still satisfies the script's own ancestor-writability check.
  for (const target of [helperDir, root]) {
    if (sudo(["chown", "root:root", target]).status !== 0) return false;
    if (sudo(["chmod", "0755", target]).status !== 0) return false;
  }
  return true;
}

function buildMinimalPathDir(names, shims = {}) {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-verify-install-minpath-"));
  for (const name of names) {
    const which = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
    const real = which.status === 0 ? which.stdout.trim() : undefined;
    if (real) fs.symlinkSync(real, path.join(binDir, name));
  }
  for (const [name, script] of Object.entries(shims)) {
    const shimPath = path.join(binDir, name);
    fs.writeFileSync(shimPath, script, { mode: 0o755 });
  }
  return binDir;
}

// Every check past "does getcap/findmnt/stat exist" needs these base tools resolvable via PATH.
// Every non-shimmed, non-optional external command verify-install.sh may invoke before/through the
// checks these tests exercise. getcap/findmnt/systemctl are provided as shims per-test; getfacl is
// optional (absent -> the script skips its ACL check, which the guest itself does). The 2-cap getcap
// parser added `wc`/`sort`, and the script also uses `grep`/`sed`/`readlink` -- all must resolve on
// the deliberately-minimal test PATH or the script dies with "command not found" (a prior run failed
// exactly this way: "wc: command not found").
const BASE_TOOLS = ["bash", "sh", "uname", "realpath", "stat", "dirname", "tr", "cat", "wc", "sort", "grep", "sed", "readlink"];

// A deterministic "not nosuid" findmnt shim. Deliberately NOT the real findmnt binary for any
// test that needs the nosuid check to cleanly PASS: many modern Linux distros (including
// systemd's default `tmp.mount` unit, shipped since Ubuntu 21.04) mount `/tmp` -- where
// `os.tmpdir()` fixtures live -- with `nosuid` by default, which would make the REAL findmnt
// check fail unpredictably depending on the host, independent of anything this test is actually
// trying to exercise.
const PASSING_FINDMNT_SHIM = '#!/bin/sh\necho "rw,relatime"\n';

// A fake `systemctl` standing in for a real systemd install, so the named-fallback checks
// (verify-install.sh section 8) can be exercised without root or a real unit. Replicates the
// EXACT invocation shape the script uses -- `systemctl show -p <Prop> --value "$UNIT"` -- so the
// shim's own $3 is always the property name; matching on that alone is sufficient because the
// service unit's properties (User/CapabilityBoundingSet/NoNewPrivileges/ProtectSystem) and the
// socket unit's (SocketMode/SocketUser/SocketGroup) never collide, so the unit name in $5 never
// needs to be inspected. `--value` is what makes the real systemctl print the bare value with no
// "Prop=" prefix, which is why the shim's `echo` also prints the bare value.
function buildSystemctlShim(overrides = {}) {
  const values = {
    User: "root",
    // S3-priv Slice 6 fix (2026-07-12): the 2-capability union, cap-number order (DAC_READ_SEARCH=2
    // before SYS_PTRACE=19) -- matching what a real `systemctl show` prints, though
    // verify-install.sh's own comparison is order-independent (a sorted-word-set compare; see the
    // dedicated order-independence test below).
    CapabilityBoundingSet: "CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
    NoNewPrivileges: "yes",
    ProtectSystem: "strict",
    SocketMode: "0660",
    SocketUser: "root",
    SocketGroup: "descartes-provenance",
    ...overrides,
  };
  const cases = Object.entries(values)
    .map(([prop, val]) => `    ${prop}) echo "${val}" ;;`)
    .join("\n");
  return `#!/bin/sh\ncase "$3" in\n${cases}\n    *) echo "" ;;\nesac\n`;
}

const SERVICE_UNIT = "descartes-root-helper.service";
const SOCKET_UNIT = "descartes-root-helper.socket";

// ---------------------------------------------------------------------------------------------
// Unprivileged-constructible fixtures (checked before the owner check, or ARE the owner check).
// ---------------------------------------------------------------------------------------------

test("verify-install.sh exits nonzero when the helper binary is missing", { skip: !IS_LINUX }, () => {
  const dir = mkScratchDir();
  const helperPath = path.join(dir, "descartes-root-helper");
  const result = runVerify([helperPath]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not found/);
  cleanup(dir);
});

test("verify-install.sh exits nonzero when the helper path is a symlink", { skip: !IS_LINUX }, () => {
  const dir = mkScratchDir();
  const realTarget = path.join(dir, "real-helper");
  fs.writeFileSync(realTarget, "#!/bin/sh\nexit 0\n", { mode: 0o750 });
  const helperPath = path.join(dir, "descartes-root-helper");
  fs.symlinkSync(realTarget, helperPath);
  const result = runVerify([helperPath]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /symlink/);
  cleanup(dir);
});

test("verify-install.sh exits nonzero when an ancestor of the helper path is a symlink (canonical path diverges from the configured path)", { skip: !IS_LINUX }, () => {
  const dir = mkScratchDir();
  const realDir = path.join(dir, "real-libexec");
  fs.mkdirSync(realDir);
  fs.writeFileSync(path.join(realDir, "descartes-root-helper"), "#!/bin/sh\nexit 0\n", { mode: 0o750 });
  const linkedDir = path.join(dir, "libexec"); // symlinked ancestor.
  fs.symlinkSync(realDir, linkedDir);
  const helperPath = path.join(linkedDir, "descartes-root-helper");
  const result = runVerify([helperPath]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /canonical path/);
  cleanup(dir);
});

test("verify-install.sh exits nonzero when the helper is not root-owned", { skip: !IS_LINUX }, () => {
  const dir = mkScratchDir();
  const helperPath = path.join(dir, "descartes-root-helper");
  fs.writeFileSync(helperPath, "#!/bin/sh\nexit 0\n", { mode: 0o750 });
  const result = runVerify([helperPath]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /owned by/);
  cleanup(dir);
});

test("verify-install.sh exits nonzero on a relative helper path argument", { skip: !IS_LINUX }, () => {
  const result = runVerify(["relative/path/descartes-root-helper"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /absolute/);
});

// ---------------------------------------------------------------------------------------------
// Fixtures needing a real root-owned leaf (sudo + a real descartes-provenance group) to isolate
// a check that runs AFTER owner/group/mode in the script.
// ---------------------------------------------------------------------------------------------

test("verify-install.sh exits nonzero when the helper's group is not descartes-provenance", { skip: !IS_LINUX || !HAVE_SUDO }, () => {
  const dir = mkScratchDir();
  const helperPath = path.join(dir, "descartes-root-helper");
  fs.writeFileSync(helperPath, "#!/bin/sh\nexit 0\n");
  assert.equal(sudo(["chown", "root:root", helperPath]).status, 0);
  assert.equal(sudo(["chmod", "0750", helperPath]).status, 0);
  const result = runVerify([helperPath]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /group/);
  cleanup(dir);
});

for (const badMode of ["0755", "4750"]) {
  test(`verify-install.sh exits nonzero when the helper mode is ${badMode} (not exactly 750)`, { skip: !IS_LINUX || !HAVE_GROUP }, () => {
    const dir = mkScratchDir();
    const helperPath = path.join(dir, "descartes-root-helper");
    fs.writeFileSync(helperPath, "#!/bin/sh\nexit 0\n");
    assert.equal(sudo(["chown", "root:descartes-provenance", helperPath]).status, 0);
    assert.equal(sudo(["chmod", badMode, helperPath]).status, 0);
    const result = runVerify([helperPath]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /mode/);
    cleanup(dir);
  });
}

test("verify-install.sh exits nonzero when an ancestor directory is group/world-writable (dir-hijack)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const root = mkScratchDir();
  const subDir = path.join(root, "libexec");
  fs.mkdirSync(subDir);
  const helperPath = path.join(subDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sudo(["chown", "root:root", subDir]).status, 0);
  assert.equal(sudo(["chmod", "0777", subDir]).status, 0); // world-writable ancestor -- the dir-hijack vector.
  const result = runVerify([helperPath]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /writable/);
  cleanup(root);
});

test("verify-install.sh HARD FAILS (never silently skips) when getcap is not present on PATH", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"]); // deliberately no getcap.
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /getcap not found/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh exits nonzero when getcap reports empty output (no capability granted)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"], {
    getcap: "#!/bin/sh\nexit 0\n", // prints nothing -- the "no cap set" shape.
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /no capabilities/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh exits nonzero when getcap reports a broader capability set than the required cap_dac_read_search,cap_sys_ptrace union (extra cap_dac_override)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"], {
    getcap: `#!/bin/sh\necho "$1 cap_dac_override,cap_dac_read_search,cap_sys_ptrace=ep"\n`,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected exactly/);
  cleanup(root);
  cleanup(binDir);
});

// S3-priv Slice 6 fix (2026-07-12) regression test: a real privileged CI run proved the OLD
// single-cap grant (cap_sys_ptrace=ep alone, with no cap_dac_read_search) is insufficient for
// cross-UID PORT resolution -- verify-install.sh must fail closed on exactly this stale-grant
// shape, not just on an unrelated "broader" one, so a host that never re-ran setcap after the fix
// is caught, not silently accepted as still-correctly-scoped.
test("verify-install.sh exits nonzero when getcap reports only the OLD single-cap grant (cap_sys_ptrace=ep, missing cap_dac_read_search)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"], {
    getcap: `#!/bin/sh\necho "$1 cap_sys_ptrace=ep"\n`,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected exactly/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh exits nonzero when getcap reports the wrong single cap (cap_dac_read_search=ep alone, missing cap_sys_ptrace)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"], {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search=ep"\n`,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected exactly/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh exits nonzero when getcap reports the correct capability names but wrong flags (eip instead of ep)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"], {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=eip"\n`,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh exits nonzero when getcap output is unparseable garbage", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir([...BASE_TOOLS, "findmnt"], {
    getcap: `#!/bin/sh\necho "not a capability line at all"\n`,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected exactly/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh accepts BOTH real getcap output formats (older '= cap+ep', newer 'cap=ep') as PASSING that one check", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const cases = [
    ["older", `#!/bin/sh\necho "$1 = cap_dac_read_search,cap_sys_ptrace+ep"\n`],
    ["newer", `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`],
  ];
  // Both leaves are written (as this unprivileged process) BEFORE the tree is sealed to root --
  // sealing must happen exactly once, after every leaf inside it already exists.
  for (const [label] of cases) {
    assert.equal(buildTrustedLeaf(path.join(helperDir, `descartes-root-helper-${label}`)), true);
  }
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  for (const [label, shim] of cases) {
    const helperPath = path.join(helperDir, `descartes-root-helper-${label}`);
    const binDir = buildMinimalPathDir(BASE_TOOLS, { getcap: shim, findmnt: PASSING_FINDMNT_SHIM });
    const result = runVerify([helperPath], { env: { PATH: binDir } });
    assert.equal(result.status, 0, `expected PASS for the ${label} getcap format; stderr: ${result.stderr}`);
    cleanup(binDir);
  }
  cleanup(root);
});

// S3-priv Slice 6 fix (2026-07-12), Fable robustness requirement: verify-install.sh's getcap check
// must compare a SORTED capability-name SET, not a literal string -- so it must PASS even if the
// two capability names appear in a non-canonical order (a real `getcap` always prints
// capability-number order, DAC_READ_SEARCH=2 before SYS_PTRACE=19, but the script's own logic must
// not silently depend on that).
test("verify-install.sh accepts the capability names in either order (order-independent set compare)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_sys_ptrace,cap_dac_read_search=ep"\n`, // reversed vs. canonical order.
    findmnt: PASSING_FINDMNT_SHIM,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.equal(result.status, 0, `expected PASS; stderr: ${result.stderr}`);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh exits nonzero when the target filesystem is mounted nosuid (findmnt shim)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: `#!/bin/sh\necho "rw,nosuid,relatime"\n`, // always reports nosuid, regardless of target.
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /nosuid/);
  cleanup(root);
  cleanup(binDir);
});

test("verify-install.sh HARD FAILS when findmnt is not present on PATH (fails closed, never silently skips)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    // deliberately no findmnt shim, and BASE_TOOLS excludes the real one.
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /findmnt not found/);
  cleanup(root);
  cleanup(binDir);
});

// ---------------------------------------------------------------------------------------------
// Config file / directory writability (optional second argument). The config file/dir is
// deliberately a SEPARATE, never-sealed `mkScratchDir()` tree -- the helper's own tree is fully
// root-owned once sealed (needed for the ancestor-walk check above) and this unprivileged process
// can no longer write into it afterward.
// ---------------------------------------------------------------------------------------------

test("verify-install.sh exits nonzero when the provided config file is group/world-writable", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: PASSING_FINDMNT_SHIM,
  });
  const configDir = mkScratchDir();
  const configFile = path.join(configDir, "provenance.json");
  fs.writeFileSync(configFile, "{}");
  // writeFileSync's own `mode` option is subject to the process umask (0022 on a typical CI/dev
  // box) just like open(2)'s O_CREAT mode -- requesting 0o666 there would silently become 0o644
  // (no group/other write bit at all), defeating the point of this fixture. chmod sets the exact
  // mode requested, unaffected by umask.
  fs.chmodSync(configFile, 0o666);
  const result = runVerify([helperPath, configFile], { env: { PATH: binDir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /config file/);
  cleanup(root);
  cleanup(binDir);
  cleanup(configDir);
});

test("verify-install.sh skips the config check (does not fail) when no config_file argument is given", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: PASSING_FINDMNT_SHIM,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /no config_file argument/);
  cleanup(root);
  cleanup(binDir);
});

// ---------------------------------------------------------------------------------------------
// A fully-correct fixture (constructible unprivileged-plus-sudo-chown, no real setcap needed)
// reaches PASS. The getcap/setcap POSITIVE case against a REAL grant is Slice 6, not here.
// ---------------------------------------------------------------------------------------------

test("verify-install.sh exits zero (PASS) for a fully-correct fixture, using a getcap shim standing in for a real grant", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: PASSING_FINDMNT_SHIM,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.equal(result.status, 0, `expected PASS; stderr: ${result.stderr}`);
  assert.match(result.stdout, /PASS/);
  cleanup(root);
  cleanup(binDir);
});

// ---------------------------------------------------------------------------------------------
// Named systemd fallback (section 8 of the script; only reachable when BOTH unit-name arguments
// are given). Exercised via the fake `systemctl` shim above rather than a real systemd install.
// Reuses the same sudo-built, fully-correct file-side fixture as the PASS test directly above --
// the script's own check order is untouched by these tests (section 8 only runs after every
// file-side check already passed), so reaching it still requires that fixture, not a shortcut
// around it.
// ---------------------------------------------------------------------------------------------

test("verify-install.sh exits zero (PASS) when the named systemd fallback units are also fully correct (fake systemctl)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: PASSING_FINDMNT_SHIM,
    systemctl: buildSystemctlShim(),
  });
  const result = runVerify([helperPath, "", SERVICE_UNIT, SOCKET_UNIT], { env: { PATH: binDir } });
  assert.equal(result.status, 0, `expected PASS; stderr: ${result.stderr}`);
  assert.match(result.stdout, /PASS/);
  cleanup(root);
  cleanup(binDir);
});

// S3-priv Slice 6 fix (2026-07-12), Fable robustness requirement: the CapabilityBoundingSet check
// must compare a SORTED WORD SET, not assume `systemctl show`'s printed order -- so it must PASS
// even when the fake systemctl reports the two caps in a non-canonical order.
test("verify-install.sh accepts the systemd CapabilityBoundingSet in either word order (order-independent set compare)", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: PASSING_FINDMNT_SHIM,
    systemctl: buildSystemctlShim({ CapabilityBoundingSet: "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH" }), // reversed vs. canonical order.
  });
  const result = runVerify([helperPath, "", SERVICE_UNIT, SOCKET_UNIT], { env: { PATH: binDir } });
  assert.equal(result.status, 0, `expected PASS; stderr: ${result.stderr}`);
  cleanup(root);
  cleanup(binDir);
});

// One property wrong at a time -- every other property keeps its passing default from
// buildSystemctlShim, isolating each failure mode exactly like the getcap/findmnt cases above.
const SYSTEMD_FAILURE_CASES = [
  ["the service unit's User is not root", { User: "someoneelse" }, /User='someoneelse'/],
  ["the service unit's CapabilityBoundingSet is broader than the required {CAP_DAC_READ_SEARCH, CAP_SYS_PTRACE} set", { CapabilityBoundingSet: "CAP_DAC_READ_SEARCH CAP_SYS_ADMIN CAP_SYS_PTRACE" }, /CapabilityBoundingSet=/],
  // S3-priv Slice 6 fix (2026-07-12): the OLD single-cap bounding set (CAP_SYS_PTRACE alone) is
  // now a FAIL, not a PASS -- a process's effective capabilities are bounded by this set even
  // when it runs as literal root, so a bounding-set-restricted root would reproduce the exact
  // same cross-UID /proc/<pid>/fd enumeration failure the stale file-capability grant does.
  ["the service unit's CapabilityBoundingSet is only the OLD single-cap CAP_SYS_PTRACE (missing CAP_DAC_READ_SEARCH)", { CapabilityBoundingSet: "CAP_SYS_PTRACE" }, /CapabilityBoundingSet=/],
  ["the service unit's NoNewPrivileges is not yes", { NoNewPrivileges: "no" }, /NoNewPrivileges='no'/],
  ["the service unit's ProtectSystem is 'full' instead of 'strict'", { ProtectSystem: "full" }, /ProtectSystem='full'/],
  ["the service unit's ProtectSystem is unset (empty)", { ProtectSystem: "" }, /ProtectSystem=''/],
  ["the socket unit's SocketMode is not 0660", { SocketMode: "0666" }, /SocketMode='0666'/],
  ["the socket unit's SocketGroup is not descartes-provenance", { SocketGroup: "root" }, /SocketGroup='root'/],
];

for (const [label, overrides, stderrPattern] of SYSTEMD_FAILURE_CASES) {
  test(`verify-install.sh exits nonzero when ${label} (fake systemctl)`, { skip: !IS_LINUX || !HAVE_GROUP }, () => {
    const { root, helperDir } = mkTrustedHelperTree();
    const helperPath = path.join(helperDir, "descartes-root-helper");
    assert.equal(buildTrustedLeaf(helperPath), true);
    assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
    const binDir = buildMinimalPathDir(BASE_TOOLS, {
      getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
      findmnt: PASSING_FINDMNT_SHIM,
      systemctl: buildSystemctlShim(overrides),
    });
    const result = runVerify([helperPath, "", SERVICE_UNIT, SOCKET_UNIT], { env: { PATH: binDir } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, stderrPattern);
    cleanup(root);
    cleanup(binDir);
  });
}

test("verify-install.sh skips the systemd fallback checks (does not fail) when unit names aren't given", { skip: !IS_LINUX || !HAVE_GROUP }, () => {
  const { root, helperDir } = mkTrustedHelperTree();
  const helperPath = path.join(helperDir, "descartes-root-helper");
  assert.equal(buildTrustedLeaf(helperPath), true);
  assert.equal(sealTrustedHelperTree({ root, helperDir }), true);
  const binDir = buildMinimalPathDir(BASE_TOOLS, {
    getcap: `#!/bin/sh\necho "$1 cap_dac_read_search,cap_sys_ptrace=ep"\n`,
    findmnt: PASSING_FINDMNT_SHIM,
  });
  const result = runVerify([helperPath], { env: { PATH: binDir } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /no systemd fallback units named/);
  cleanup(root);
  cleanup(binDir);
});
