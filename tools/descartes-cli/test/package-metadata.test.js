import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const rootPackage = JSON.parse(fs.readFileSync(fileURLToPath(new URL("../../../package.json", import.meta.url)), "utf8"));
const nestedPackage = JSON.parse(fs.readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"));
const cliPath = fileURLToPath(new URL("../src/index.js", import.meta.url));

test("root and nested package metadata stay aligned", () => {
  assert.equal(rootPackage.version, nestedPackage.version);
  assert.equal(rootPackage.name, nestedPackage.name);
  assert.equal(rootPackage.description, nestedPackage.description);
  assert.equal(rootPackage.engines.node, nestedPackage.engines.node);
  assert.equal(rootPackage.engines.node, ">=22.19.0");
  assert.equal(rootPackage.dependencies["@earendil-works/pi-coding-agent"], nestedPackage.dependencies["@earendil-works/pi-coding-agent"]);
  assert(!rootPackage.dependencies["@mariozechner/pi-coding-agent"]);
  assert(!nestedPackage.dependencies["@mariozechner/pi-coding-agent"]);
  assert.equal(rootPackage.bin.descartes, "tools/descartes-cli/src/index.js");
  assert.equal(nestedPackage.bin.descartes, "src/index.js");
});

test("published package includes runtime files but not tests", () => {
  assert(rootPackage.files.includes("README.md"));
  assert(rootPackage.files.includes("docs/reference"));
  assert(rootPackage.files.includes("tools/descartes-cli/src"));
  assert(!rootPackage.files.includes("tools/descartes-cli/native"));
  assert(!nestedPackage.files.includes("native"));
  assert(!rootPackage.files.includes("tools/descartes-cli/test"));
});

test("macOS notifier release scripts are maintainer-only and use the assigned bundle id", () => {
  const bundleId = "com.bande-a-bonnot.lightless-labs.descartes.macos.notifier";
  const plist = fs.readFileSync(fileURLToPath(new URL("../native/macos/DescartesNotifier-Info.plist", import.meta.url)), "utf8");
  const buildScript = fs.readFileSync(fileURLToPath(new URL("../../../scripts/build-macos-notifier.sh", import.meta.url)), "utf8");
  const notarizeScript = fs.readFileSync(fileURLToPath(new URL("../../../scripts/notarize-macos-notifier.sh", import.meta.url)), "utf8");

  assert.match(plist, new RegExp(bundleId.replaceAll(".", "\\.")));
  assert.match(plist, /<key>LSUIElement<\/key>\s*<true\/>/);
  assert.match(plist, /<key>CFBundlePackageType<\/key>\s*<string>APPL<\/string>/);
  assert.match(buildScript, /\.build\/macos-notifier/);
  assert.match(notarizeScript, /notarytool submit/);
  assert.match(notarizeScript, /stapler staple/);
  assert.match(notarizeScript, /spctl --assess/);
});

test("CLI version and help are generated from current metadata/options", () => {
  const version = execFileSync(process.execPath, [cliPath, "--version"], { encoding: "utf8" }).trim();
  assert.equal(version, rootPackage.version);

  const help = execFileSync(process.execPath, [cliPath, "--help"], { encoding: "utf8" });
  assert.match(help, /--model <MODEL>/);
  assert.match(help, /--thinking <LEVEL>/);
  assert.match(help, /--no-investigate/);
  assert.match(help, /--use-history/);
  assert.match(help, /--no-history/);
  assert.match(help, /--history-window <DURATION>/);
  assert.match(help, /daemon install\|start\|status\|stop\|uninstall \[--json\]/);
  assert.match(help, /daemon run --foreground/);
  assert.match(help, /history summary/);
  assert.match(help, /alerts list/);
  assert.match(help, /alerts watch/);
  assert.match(help, /alerts ack/);
  assert.match(help, /alerts intelligence status\|enable\|disable/);
  assert.match(help, /alerts notifications status\|setup\|test\|disable/);
  assert.match(help, /--channel cli\|desktop\|macos\|native\|linux\|syslog/);
});

test("CLI entrypoint works when launched through an npm-style symlink", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-bin-"));
  const link = path.join(tmp, "descartes");
  fs.symlinkSync(cliPath, link);
  try {
    const version = execFileSync(process.execPath, [link, "--version"], { encoding: "utf8" }).trim();
    assert.equal(version, rootPackage.version);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
