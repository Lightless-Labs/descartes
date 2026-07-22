import { test, before, after } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Host-runnable tests for the notifier reuse-vs-rebuild pipeline
// (docs/plans/2026-07-22-notifier-notarization-skip.md):
//   scripts/notifier-source-digest.sh   - stable content digest of notifier sources
//   scripts/notifier-reuse-decision.sh  - reuse-vs-build decision + verified download
//
// Mirrors tap-bump.test.js: real subprocesses, a local http.createServer standing
// in for the GitHub API + release-asset download host (via the
// DESCARTES_GITHUB_API_URL / DESCARTES_GITHUB_DOWNLOAD_URL overrides), and
// PATH-stubbed macOS binaries (stapler/spctl/codesign/unzip/plutil) so the
// integrity/identity/notarization gates are exercised without a real signed app.

const digestScriptPath = fileURLToPath(
  new URL("../../../scripts/notifier-source-digest.sh", import.meta.url),
);
const decisionScriptPath = fileURLToPath(
  new URL("../../../scripts/notifier-reuse-decision.sh", import.meta.url),
);

const hasBash = (() => {
  const probe = spawnSync("bash", ["--version"], { encoding: "utf8" });
  return !probe.error && probe.status === 0;
})();

const REPO = "TestOrg/descartes-notifier-fixture";
const CURRENT_TAG = "v0.0.30";
const SOURCE_DIGEST = "a".repeat(64);
const BUNDLE_ID = "com.bande-a-bonnot.lightless-labs.descartes.macos.notifier";
const BUNDLE_EXECUTABLE = "DescartesNotifier";
const ZIP_ASSET_NAME = "DescartesNotifier.app.zip";
const REUSE_ASSET_NAME = "notifier-reuse.json";

// ---------------------------------------------------------------------------
// scripts/notifier-source-digest.sh
// ---------------------------------------------------------------------------

function writeDigestFixture(dir) {
  const nativeDir = path.join(dir, "tools/descartes-cli/native/macos");
  const scriptsDir = path.join(dir, "scripts");
  fs.mkdirSync(nativeDir, { recursive: true });
  fs.mkdirSync(scriptsDir, { recursive: true });
  fs.writeFileSync(
    path.join(nativeDir, "DescartesNotifier.swift"),
    "// fixture swift source\nprint(\"hello\")\n",
  );
  fs.writeFileSync(
    path.join(nativeDir, "DescartesNotifier-Info.plist"),
    [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<plist version="1.0"><dict>',
      "<key>CFBundleShortVersionString</key><string>__DESCARTES_VERSION__</string>",
      "<key>CFBundleVersion</key><string>__DESCARTES_BUILD__</string>",
      "</dict></plist>",
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(scriptsDir, "build-macos-notifier.sh"),
    "#!/usr/bin/env bash\necho fixture build script\n",
  );
  fs.writeFileSync(
    path.join(scriptsDir, "notarize-macos-notifier.sh"),
    "#!/usr/bin/env bash\necho fixture notarize script\n",
  );
  return { nativeDir, scriptsDir };
}

function runDigest(root) {
  const result = spawnSync("bash", [digestScriptPath, "--root", root], { encoding: "utf8" });
  return result;
}

test("notifier source digest is stable across repeated runs", { skip: !hasBash && "bash unavailable" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-digest-"));
  try {
    writeDigestFixture(dir);
    const r1 = runDigest(dir);
    const r2 = runDigest(dir);
    assert.equal(r1.status, 0, `stdout: ${r1.stdout}\nstderr: ${r1.stderr}`);
    assert.equal(r2.status, 0);
    assert.match(r1.stdout.trim(), /^[0-9a-f]{64}$/);
    assert.equal(r1.stdout, r2.stdout, "digest must be stable across repeated runs");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("notifier source digest changes when a .swift byte changes", { skip: !hasBash && "bash unavailable" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-digest-"));
  try {
    const { nativeDir } = writeDigestFixture(dir);
    const before = runDigest(dir).stdout;
    const swiftPath = path.join(nativeDir, "DescartesNotifier.swift");
    fs.appendFileSync(swiftPath, "// one more byte\n");
    const afterDigest = runDigest(dir).stdout;
    assert.notEqual(before, afterDigest, "changing the .swift source must change the digest");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("notifier source digest is invariant to the version VALUE substituted at build time (template is hashed, not a substituted plist)", { skip: !hasBash && "bash unavailable" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-digest-"));
  try {
    const { nativeDir } = writeDigestFixture(dir);
    const templatePath = path.join(nativeDir, "DescartesNotifier-Info.plist");
    const template = fs.readFileSync(templatePath, "utf8");

    const digestBeforeBuild = runDigest(dir).stdout;

    // Simulate build-macos-notifier.sh's own substitution (the same sed
    // pattern), twice, with two DIFFERENT versions, writing the result OUTSIDE
    // the hashed native/macos/ tree (as the real build does, into a build dir).
    const buildOutDir = path.join(dir, ".build-out");
    fs.mkdirSync(buildOutDir, { recursive: true });
    const substituted1 = template
      .replace(/__DESCARTES_VERSION__/g, "1.2.3")
      .replace(/__DESCARTES_BUILD__/g, "123");
    const substituted2 = template
      .replace(/__DESCARTES_VERSION__/g, "9.9.9")
      .replace(/__DESCARTES_BUILD__/g, "999");
    fs.writeFileSync(path.join(buildOutDir, "Info-v1.plist"), substituted1);
    fs.writeFileSync(path.join(buildOutDir, "Info-v2.plist"), substituted2);

    // Sanity: the two substituted (built) plists really do differ from each
    // other and from the template - the substitution mechanism is real.
    assert.notEqual(substituted1, substituted2);
    assert.notEqual(substituted1, template);

    // The template in the source tree itself is untouched by "building".
    assert.equal(fs.readFileSync(templatePath, "utf8"), template);

    const digestAfterBuild = runDigest(dir).stdout;
    assert.equal(
      digestBeforeBuild,
      digestAfterBuild,
      "digest must not change when a version is substituted at build time outside the source tree",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// scripts/notifier-reuse-decision.sh
// ---------------------------------------------------------------------------

const hasRequiredTools = (() => {
  for (const tool of ["curl", "python3", "shasum", "unzip", "plutil", "codesign"]) {
    const probe = spawnSync(tool, ["--version"], { encoding: "utf8" });
    if (probe.error) return false;
  }
  return true;
})();
const skipDecisionTests = !hasBash || !hasRequiredTools;

let stubBinDir;

before(() => {
  stubBinDir = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-notifier-stubs-"));

  const writeStub = (name, body) => {
    const stubPath = path.join(stubBinDir, name);
    fs.writeFileSync(stubPath, `#!/usr/bin/env bash\nset -euo pipefail\n${body}\n`);
    fs.chmodSync(stubPath, 0o755);
  };

  // unzip -q -o <zip> -d <dest>: on success, materializes a fixed
  // DescartesNotifier.app/Contents/Info.plist regardless of the actual
  // (fake) zip bytes - plutil is separately stubbed to report bundle fields.
  writeStub(
    "unzip",
    [
      'if [[ "${FAKE_UNZIP_EXIT:-0}" != "0" ]]; then',
      '  echo "fake unzip: forced failure" >&2',
      '  exit "${FAKE_UNZIP_EXIT}"',
      "fi",
      'dest=""',
      'prev=""',
      'for arg in "$@"; do',
      '  if [[ "$prev" == "-d" ]]; then dest="$arg"; fi',
      '  prev="$arg"',
      "done",
      '[[ -n "$dest" ]] || { echo "fake unzip: no -d destination" >&2; exit 1; }',
      'mkdir -p "$dest/DescartesNotifier.app/Contents"',
      'printf \'<plist/>\' > "$dest/DescartesNotifier.app/Contents/Info.plist"',
    ].join("\n"),
  );

  // plutil -extract KEY raw -o - <plist>
  writeStub(
    "plutil",
    [
      'key="${2:-}"',
      'case "$key" in',
      "  CFBundleIdentifier)",
      '    echo "${FAKE_BUNDLE_ID:-com.bande-a-bonnot.lightless-labs.descartes.macos.notifier}"',
      "    ;;",
      "  CFBundleExecutable)",
      '    echo "${FAKE_BUNDLE_EXECUTABLE:-DescartesNotifier}"',
      "    ;;",
      "  *)",
      '    echo "fake plutil: unsupported key $key" >&2',
      "    exit 1",
      "    ;;",
      "esac",
    ].join("\n"),
  );

  // codesign --verify --deep --strict <app>   -> exit FAKE_CODESIGN_VERIFY_EXIT
  // codesign -dvv <app>                       -> prints TeamIdentifier= to stderr
  writeStub(
    "codesign",
    [
      'if [[ "${1:-}" == "--verify" ]]; then',
      '  exit "${FAKE_CODESIGN_VERIFY_EXIT:-0}"',
      'elif [[ "${1:-}" == "-dvv" ]]; then',
      '  echo "Executable=/fake/DescartesNotifier.app/Contents/MacOS/DescartesNotifier" >&2',
      '  echo "TeamIdentifier=${FAKE_TEAM_ID:-ABCDE12345}" >&2',
      '  exit "${FAKE_CODESIGN_DVV_EXIT:-0}"',
      "else",
      '  echo "fake codesign: unsupported args: $*" >&2',
      "  exit 1",
      "fi",
    ].join("\n"),
  );

  writeStub("stapler", 'exit "${FAKE_STAPLER_EXIT:-0}"');
  writeStub("spctl", 'exit "${FAKE_SPCTL_EXIT:-0}"');
});

after(() => {
  if (stubBinDir) fs.rmSync(stubBinDir, { recursive: true, force: true });
});

function startFixtureServer({ releases, attestations = {}, zips = {} }) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const pathname = url.pathname;

    if (req.method === "GET" && pathname === `/repos/${REPO}/releases`) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(releases));
      return;
    }

    const reuseJsonPrefix = `/${REPO}/releases/download/`;
    if (req.method === "GET" && pathname.startsWith(reuseJsonPrefix)) {
      const rest = pathname.slice(reuseJsonPrefix.length);
      const slash = rest.indexOf("/");
      const tag = rest.slice(0, slash);
      const assetName = rest.slice(slash + 1);
      if (assetName === REUSE_ASSET_NAME && Object.prototype.hasOwnProperty.call(attestations, tag)) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(attestations[tag]);
        return;
      }
      if (assetName === ZIP_ASSET_NAME && Object.prototype.hasOwnProperty.call(zips, tag)) {
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        res.end(zips[tag]);
        return;
      }
      res.writeHead(404);
      res.end("not found");
      return;
    }

    res.writeHead(404);
    res.end("not found");
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

async function withFixtureServer(config, fn) {
  const { server, baseUrl } = await startFixtureServer(config);
  try {
    return await fn(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// Must be async `spawn`, NOT `spawnSync`: the fixture HTTP server lives in
// this SAME process/event loop. A synchronous spawnSync would freeze that
// event loop for the whole child lifetime, so the server could never accept
// or answer the child's requests until the child's OWN timeout gave up -
// i.e. every call would appear to "work" only by masquerading as a network
// timeout. (Mirrors tap-bump.test.js's runTokenCheck, which uses async
// spawn for exactly this reason; only its non-networked runBump uses sync.)
function runDecision(baseUrl, envOverrides = {}) {
  const outZip = envOverrides.OUT_ZIP
    ?? path.join(fs.mkdtempSync(path.join(os.tmpdir(), "descartes-notifier-outzip-")), "DescartesNotifier.app.zip");
  return new Promise((resolve) => {
    const child = spawn("bash", [decisionScriptPath], {
      env: {
        ...process.env,
        PATH: `${stubBinDir}:${process.env.PATH}`,
        SOURCE_DIGEST,
        GH_RELEASE_REPO: REPO,
        GITHUB_TOKEN: "test-token",
        CURRENT_TAG,
        OUT_ZIP: outZip,
        DESCARTES_GITHUB_API_URL: baseUrl,
        DESCARTES_GITHUB_DOWNLOAD_URL: baseUrl,
        DESCARTES_NOTIFIER_FORCE_REBUILD: "",
        EXPECTED_TEAM_ID: "",
        // The script itself must preserve normal proxy behavior in production;
        // only this fixture subprocess clears proxies so requests reach the
        // in-process server.
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        http_proxy: "",
        https_proxy: "",
        all_proxy: "",
        NO_PROXY: "127.0.0.1,localhost",
        no_proxy: "127.0.0.1,localhost",
        ...envOverrides,
        OUT_ZIP: outZip,
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => resolve({ status: null, error, stdout, stderr, outZip }));
    child.on("close", (status, signal) => resolve({ status, signal, stdout, stderr, outZip }));
  });
}

function eligibleRelease(tag, overrides = {}) {
  return {
    tag_name: tag,
    draft: false,
    prerelease: false,
    assets: [{ name: ZIP_ASSET_NAME }, { name: REUSE_ASSET_NAME }],
    ...overrides,
  };
}

function goodZipAndAttestation(tag, sourceDigest = SOURCE_DIGEST, sourceVersion = "0.0.10") {
  const zip = Buffer.from(`fake-notifier-zip-bytes-${tag}`);
  const zipSha256 = crypto.createHash("sha256").update(zip).digest("hex");
  const attestation = JSON.stringify({
    source_digest: sourceDigest,
    zip_sha256: zipSha256,
    source_version: sourceVersion,
  });
  return { zip, zipSha256, attestation };
}

test("decision: DESCARTES_NOTIFIER_FORCE_REBUILD=1 forces build immediately", { skip: skipDecisionTests }, async () => {
  await withFixtureServer({ releases: [] }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl, { DESCARTES_NOTIFIER_FORCE_REBUILD: "1" });
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: missing GITHUB_TOKEN forces build", { skip: skipDecisionTests }, async () => {
  await withFixtureServer({ releases: [] }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl, { GITHUB_TOKEN: "" });
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: no prior release is build", { skip: skipDecisionTests }, async () => {
  await withFixtureServer({ releases: [] }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl);
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: prior release lacking the reuse attestation asset is build", { skip: skipDecisionTests }, async () => {
  const releases = [
    eligibleRelease("v0.0.10", { assets: [{ name: ZIP_ASSET_NAME }] }), // no notifier-reuse.json
  ];
  await withFixtureServer({ releases }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl);
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: unparsable attestation JSON is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const attestations = { "v0.0.10": "{ not valid json" };
  await withFixtureServer({ releases, attestations }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl);
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: attestation missing required fields is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const attestations = { "v0.0.10": JSON.stringify({ source_version: "0.0.10" }) };
  await withFixtureServer({ releases, attestations }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl);
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: source digest mismatch is build (never reuse without a positive digest match)", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { attestation } = goodZipAndAttestation("v0.0.10", "b".repeat(64));
  await withFixtureServer({ releases, attestations: { "v0.0.10": attestation } }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl);
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: draft, prerelease, newer, and non-semver candidates are all ignored", { skip: skipDecisionTests }, async () => {
  const releases = [
    eligibleRelease("v0.0.5", { draft: true }),
    eligibleRelease("v0.0.6", { prerelease: true }),
    eligibleRelease("v0.1.0"), // newer than CURRENT_TAG (v0.0.30)
    eligibleRelease("latest"), // not semver-shaped
  ];
  await withFixtureServer({ releases }, async (baseUrl) => {
    const { status, stdout } = await runDecision(baseUrl);
    assert.equal(status, 0);
    assert.equal(stdout.trim(), "build");
  });
});

test("decision: digest match + all gates passing yields reuse <tag> and leaves a verified zip at OUT_ZIP", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10"), eligibleRelease("v0.0.20")];
  const fixtureA = goodZipAndAttestation("v0.0.10");
  const fixtureB = goodZipAndAttestation("v0.0.20");
  await withFixtureServer(
    {
      releases,
      attestations: { "v0.0.10": fixtureA.attestation, "v0.0.20": fixtureB.attestation },
      zips: { "v0.0.10": fixtureA.zip, "v0.0.20": fixtureB.zip },
    },
    async (baseUrl) => {
      const { status, stdout, stderr, outZip } = await runDecision(baseUrl);
      assert.equal(status, 0, `stdout: ${stdout}\nstderr: ${stderr}`);
      // The highest eligible semver (v0.0.20) must win over v0.0.10.
      assert.equal(stdout.trim(), "reuse v0.0.20", `stdout: ${stdout}\nstderr: ${stderr}`);
      assert.match(stderr, /embedded version/);
      assert.ok(fs.existsSync(outZip), "verified zip must be left at OUT_ZIP");
      const actualSha = crypto.createHash("sha256").update(fs.readFileSync(outZip)).digest("hex");
      assert.equal(actualSha, fixtureB.zipSha256);
    },
  );
});

test("decision: downloaded zip sha256 mismatch against the attestation is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { attestation } = goodZipAndAttestation("v0.0.10");
  const wrongZip = Buffer.from("this-is-not-the-attested-zip-bytes");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": wrongZip } },
    async (baseUrl) => {
      const { status, stdout, outZip } = await runDecision(baseUrl);
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
      assert.ok(!fs.existsSync(outZip), "a sha256-mismatched zip must not be left behind");
    },
  );
});

test("decision: wrong CFBundleIdentifier in the downloaded app is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout } = await runDecision(baseUrl, { FAKE_BUNDLE_ID: "com.example.not-descartes" });
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});

test("decision: wrong CFBundleExecutable in the downloaded app is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout } = await runDecision(baseUrl, { FAKE_BUNDLE_EXECUTABLE: "NotDescartes" });
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});

test("decision: codesign --verify failure is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout } = await runDecision(baseUrl, { FAKE_CODESIGN_VERIFY_EXIT: "1" });
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});

test("decision: an ad-hoc/unsigned app (TeamIdentifier=not set) is build even without EXPECTED_TEAM_ID", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout } = await runDecision(baseUrl, { FAKE_TEAM_ID: "not set" });
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});

test("decision: EXPECTED_TEAM_ID mismatch is build", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout } = await runDecision(baseUrl, { FAKE_TEAM_ID: "ABCDE12345", EXPECTED_TEAM_ID: "ZZZZZ99999" });
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});

test("decision: a nonzero stapler exit is build, not a crash", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout, signal } = await runDecision(baseUrl, { FAKE_STAPLER_EXIT: "1" });
      assert.equal(signal, null, "must not terminate via signal (no crash)");
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});

test("decision: a nonzero spctl exit is build, not a crash", { skip: skipDecisionTests }, async () => {
  const releases = [eligibleRelease("v0.0.10")];
  const { zip, attestation } = goodZipAndAttestation("v0.0.10");
  await withFixtureServer(
    { releases, attestations: { "v0.0.10": attestation }, zips: { "v0.0.10": zip } },
    async (baseUrl) => {
      const { status, stdout, signal } = await runDecision(baseUrl, { FAKE_SPCTL_EXIT: "1" });
      assert.equal(signal, null, "must not terminate via signal (no crash)");
      assert.equal(status, 0);
      assert.equal(stdout.trim(), "build");
    },
  );
});
