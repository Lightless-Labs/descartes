import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
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
  assert.equal(rootPackage.bin.descartes, "tools/descartes-cli/src/index.js");
  assert.equal(nestedPackage.bin.descartes, "src/index.js");
});

test("published package includes runtime files but not tests", () => {
  assert(rootPackage.files.includes("README.md"));
  assert(rootPackage.files.includes("tools/descartes-cli/src"));
  assert(!rootPackage.files.includes("tools/descartes-cli/test"));
});

test("CLI version and help are generated from current metadata/options", () => {
  const version = execFileSync(process.execPath, [cliPath, "--version"], { encoding: "utf8" }).trim();
  assert.equal(version, rootPackage.version);

  const help = execFileSync(process.execPath, [cliPath, "--help"], { encoding: "utf8" });
  assert.match(help, /--model <MODEL>/);
  assert.match(help, /--thinking <LEVEL>/);
  assert.match(help, /--no-investigate/);
});
