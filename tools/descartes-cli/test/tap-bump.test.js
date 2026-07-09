import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Executes the exact python embedded in the release script's Homebrew tap bump
// step against a formula fixture, with the GitHub Contents API stubbed out.

const scriptPath = fileURLToPath(
  new URL("../../../scripts/release-macos-notifier-buildkite.sh", import.meta.url),
);
const tokenCheckScriptPath = fileURLToPath(
  new URL("../../../scripts/check-homebrew-tap-token.sh", import.meta.url),
);

const TARBALL_SHA_OLD = "1".repeat(64);
const HELPER_SHA_OLD = "2".repeat(64);
const FIXTURE_FORMULA = `class Descartes < Formula
  desc "LLM-backed local system triage, monitoring, and alerting CLI"
  homepage "https://github.com/Lightless-Labs/descartes"
  url "https://github.com/Lightless-Labs/descartes/archive/refs/tags/v0.0.47.tar.gz"
  sha256 "${TARBALL_SHA_OLD}"

  depends_on "node"

  resource "descartes-notifier" do
    url "https://github.com/Lightless-Labs/descartes/releases/download/v0.0.47/DescartesNotifier.app.zip"
    sha256 "${HELPER_SHA_OLD}"
  end

  def install
    system "npm", "install", *std_npm_args
  end
end
`;

const URLLIB_STUB = `
import base64, io, json, os, time
import urllib.error, urllib.request

# Make backoff instantaneous so retry paths run without wall-clock delay.
time.sleep = lambda *a, **k: None

_formula = open(os.environ["FAKE_FORMULA_PATH"], "rb").read()
_put_log = os.environ["FAKE_PUT_LOG"]
_put_failures = int(os.environ.get("FAKE_PUT_FAILURES", "0"))
_state = {"puts": 0}

def _fake_urlopen(req, timeout=None):
    method = req.get_method()
    url = req.full_url
    if method == "GET" and "/contents/" in url:
        body = json.dumps({
            "content": base64.b64encode(_formula).decode(),
            "sha": "fixture-sha",
        }).encode()
        return io.BytesIO(body)
    if method == "PUT" and "/contents/" in url:
        _state["puts"] += 1
        if _state["puts"] <= _put_failures:
            raise urllib.error.HTTPError(url, 503, "Service Unavailable", {}, io.BytesIO(b""))
        with open(_put_log, "ab") as f:
            f.write(req.data + b"\\n")
        return io.BytesIO(json.dumps({"commit": {"sha": "abc123def4567890"}}).encode())
    raise AssertionError("unexpected request: " + method + " " + url)

urllib.request.urlopen = _fake_urlopen
`;

function extractBumpPython() {
  const script = fs.readFileSync(scriptPath, "utf8");
  const blocks = [...script.matchAll(/python3 <<'PY'\n([\s\S]*?)\nPY\n/g)].map((m) => m[1]);
  const block = blocks.find((b) => b.includes('os.environ["TAP_REPO"]'));
  assert(block, "tap-bump python heredoc not found in release script");
  return block;
}

const hasPython3 = (() => {
  const probe = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return !probe.error && probe.status === 0;
})();

async function withFakeGitHubTokenApi(permissions, fn, expectedToken = "test-token") {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ url: req.url, authorization: req.headers.authorization });
    if (req.headers.authorization !== `Bearer ${expectedToken}`) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "bad token" }));
      return;
    }
    if (req.method === "GET" && req.url === "/repos/Lightless-Labs/homebrew-tap") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ full_name: "Lightless-Labs/homebrew-tap", permissions }));
      return;
    }
    if (req.method === "GET" && req.url === "/repos/Lightless-Labs/homebrew-tap/contents/Formula/descartes.rb") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ type: "file", sha: "fixture-formula-sha" }));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: `unexpected ${req.method} ${req.url}` }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try {
    return await fn(`http://127.0.0.1:${address.port}`, requests);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function runTokenCheck(apiUrl, envOverrides = {}) {
  return new Promise((resolve) => {
    const child = spawn("bash", [tokenCheckScriptPath], {
      env: {
        ...process.env,
        GITHUB_TOKEN: "test-token",
        HOMEBREW_TAP_GITHUB_TOKEN: "",
        DOPPLER_TOKEN: "",
        ...envOverrides,
        DESCARTES_GITHUB_API_URL: apiUrl,
        // The script itself must preserve normal proxy behavior; only the localhost
        // fixture subprocess clears proxies so the request reaches the in-process server.
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        http_proxy: "",
        https_proxy: "",
        all_proxy: "",
        NO_PROXY: "127.0.0.1,localhost",
        no_proxy: "127.0.0.1,localhost",
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => resolve({ status: null, error, stdout, stderr }));
    child.on("close", (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

function runBump({ tag, tarballSha, helperSha, formula, putFailures = 0 }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-tap-bump-"));
  try {
    const formulaPath = path.join(dir, "formula.rb");
    const putLog = path.join(dir, "puts.jsonl");
    const runner = path.join(dir, "runner.py");
    fs.writeFileSync(formulaPath, formula);
    fs.writeFileSync(runner, `${URLLIB_STUB}\n${extractBumpPython()}`);
    const result = spawnSync("python3", [runner], {
      encoding: "utf8",
      env: {
        ...process.env,
        TAP_TOKEN: "test-token",
        TAP_REPO: "Lightless-Labs/homebrew-tap",
        FORMULA_PATH: "Formula/descartes.rb",
        RELEASE_TAG: tag,
        TARBALL_SHA256: tarballSha,
        HELPER_SHA256: helperSha,
        FAKE_FORMULA_PATH: formulaPath,
        FAKE_PUT_LOG: putLog,
        FAKE_PUT_FAILURES: String(putFailures),
      },
    });
    const puts = fs.existsSync(putLog)
      ? fs.readFileSync(putLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
      : [];
    return { result, puts };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("tap bump rewrites version and pairwise sha256 values via one Contents API PUT", { skip: !hasPython3 && "python3 unavailable" }, () => {
  const tarballSha = "a".repeat(64);
  const helperSha = "b".repeat(64);
  const { result, puts } = runBump({
    tag: "v0.1.0",
    tarballSha,
    helperSha,
    formula: FIXTURE_FORMULA,
  });
  assert.equal(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
  assert.equal(puts.length, 1);
  assert.equal(puts[0].message, "descartes: update to 0.1.0");
  assert.equal(puts[0].sha, "fixture-sha");
  const updated = Buffer.from(puts[0].content, "base64").toString("utf8");
  assert.match(updated, /archive\/refs\/tags\/v0\.1\.0\.tar\.gz/);
  assert.match(updated, /releases\/download\/v0\.1\.0\/DescartesNotifier\.app\.zip/);
  assert.doesNotMatch(updated, /v0\.0\.47/);
  const lines = updated.split("\n");
  lines.forEach((line, i) => {
    if (line.includes("archive/refs/tags/")) {
      assert.match(lines[i + 1], new RegExp(tarballSha), "tarball sha must follow its url line");
    }
    if (line.includes("releases/download/")) {
      assert.match(lines[i + 1], new RegExp(helperSha), "helper sha must follow its url line");
    }
  });
});

test("tap bump is a no-op when the formula already matches the release", { skip: !hasPython3 && "python3 unavailable" }, () => {
  const { result, puts } = runBump({
    tag: "v0.0.47",
    tarballSha: TARBALL_SHA_OLD,
    helperSha: HELPER_SHA_OLD,
    formula: FIXTURE_FORMULA,
  });
  assert.equal(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
  assert.equal(puts.length, 0);
  assert.match(result.stdout, /already current/);
});

test("tap bump retries transient 5xx on the PUT with backoff and then succeeds", { skip: !hasPython3 && "python3 unavailable" }, () => {
  const { result, puts } = runBump({
    tag: "v0.1.0",
    tarballSha: "a".repeat(64),
    helperSha: "b".repeat(64),
    formula: FIXTURE_FORMULA,
    putFailures: 2, // first two PUTs return 503, third succeeds — within MAX_ATTEMPTS=4
  });
  assert.equal(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
  assert.equal(puts.length, 1, "exactly one PUT should land after the transient failures");
  const updated = Buffer.from(puts[0].content, "base64").toString("utf8");
  assert.match(updated, /archive\/refs\/tags\/v0\.1\.0\.tar\.gz/);
});

test("tap bump gives up after exhausting retries on persistent 5xx", { skip: !hasPython3 && "python3 unavailable" }, () => {
  const { result, puts } = runBump({
    tag: "v0.1.0",
    tarballSha: "a".repeat(64),
    helperSha: "b".repeat(64),
    formula: FIXTURE_FORMULA,
    putFailures: 99, // never recovers
  });
  assert.notEqual(result.status, 0, "should exit nonzero so the shell falls back to best-effort warn");
});

test("tap bump refuses to PUT when the formula shape is unexpected", { skip: !hasPython3 && "python3 unavailable" }, () => {
  const broken = FIXTURE_FORMULA.replace(`sha256 "${HELPER_SHA_OLD}"`, "");
  const { result, puts } = runBump({
    tag: "v0.1.0",
    tarballSha: "a".repeat(64),
    helperSha: "b".repeat(64),
    formula: broken,
  });
  assert.notEqual(result.status, 0);
  assert.equal(puts.length, 0);
  assert.match(result.stderr, /unexpected formula shape/);
});

test("tap token preflight verifies formula read and write permission without leaking the token", { skip: !hasPython3 && "python3 unavailable" }, async () => {
  await withFakeGitHubTokenApi({ pull: true, push: true }, async (apiUrl, requests) => {
    const result = await runTokenCheck(apiUrl);
    assert.equal(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
    assert.match(result.stdout, /Homebrew tap token check OK/);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /test-token/);
    assert.deepEqual(requests.map((r) => r.url), [
      "/repos/Lightless-Labs/homebrew-tap",
      "/repos/Lightless-Labs/homebrew-tap/contents/Formula/descartes.rb",
    ]);
  });
});

test("tap token preflight fails closed when write permission is not reported", { skip: !hasPython3 && "python3 unavailable" }, async () => {
  await withFakeGitHubTokenApi({ pull: true, push: false }, async (apiUrl) => {
    const result = await runTokenCheck(apiUrl);
    assert.equal(result.status, 1, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
    assert.match(result.stderr, /does not report push\/write permission/);
    assert.match(result.stderr, /HOMEBREW_TAP_GITHUB_TOKEN/);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /test-token/);
  });
});

test("tap token preflight prefers the dedicated tap token over the release token", { skip: !hasPython3 && "python3 unavailable" }, async () => {
  await withFakeGitHubTokenApi({ pull: true, push: true }, async (apiUrl, requests) => {
    const result = await runTokenCheck(apiUrl, {
      GITHUB_TOKEN: "release-token-should-not-be-used",
      HOMEBREW_TAP_GITHUB_TOKEN: "tap-token",
    });
    assert.equal(result.status, 0, `stdout: ${result.stdout}\nstderr: ${result.stderr}`);
    assert.match(result.stdout, /HOMEBREW_TAP_GITHUB_TOKEN/);
    assert.deepEqual(requests.map((r) => r.authorization), ["Bearer tap-token", "Bearer tap-token"]);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /tap-token|release-token-should-not-be-used/);
  }, "tap-token");
});
