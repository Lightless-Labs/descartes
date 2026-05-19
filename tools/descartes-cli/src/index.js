#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "./paths.js";

export const MIN_NODE_VERSION = "22.19.0";
export const SUPPORTED_NODE_RANGE = `>=${MIN_NODE_VERSION}`;

function parseNodeVersion(version) {
  return String(version).replace(/^v/, "").split(".").slice(0, 3).map((part) => Number.parseInt(part, 10));
}

export function isNodeVersionAtLeast(version, minimum) {
  const actual = parseNodeVersion(version);
  const required = parseNodeVersion(minimum);
  if (actual.length < 3 || required.length < 3 || actual.some(Number.isNaN) || required.some(Number.isNaN)) {
    return false;
  }
  for (let i = 0; i < 3; i += 1) {
    if (actual[i] > required[i]) return true;
    if (actual[i] < required[i]) return false;
  }
  return true;
}

export function isSupportedNodeVersion(version) {
  return isNodeVersionAtLeast(version, MIN_NODE_VERSION);
}

export function unsupportedNodeVersionMessage(version = process.version) {
  return `Descartes requires Node.js ${SUPPORTED_NODE_RANGE} because its embedded agent harness dependencies require current Node APIs. Current Node.js is ${version}. Install Node ${MIN_NODE_VERSION}+ and retry.`;
}

function usage() {
  return `Descartes

Usage:
  descartes login [provider] [--api-key] [--no-open]
  descartes triage <PROMPT> [--json] [--model <MODEL>] [--thinking <LEVEL>] [--no-investigate]
  descartes --version

Safety: v0 local evidence collection is read-only. No actions are taken.`;
}

function packageVersion() {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(currentDir, "../../../package.json"),
    path.resolve(currentDir, "../package.json"),
  ];
  for (const candidate of candidates) {
    try {
      return JSON.parse(fs.readFileSync(candidate, "utf8")).version;
    } catch {
      // Try the next package location.
    }
  }
  return "unknown";
}

async function main(argv) {
  if (!isSupportedNodeVersion(process.versions.node)) {
    throw new Error(unsupportedNodeVersionMessage());
  }

  const [command, ...args] = argv;
  if (!command || command === "--help" || command === "-h") {
    console.log(usage());
    return;
  }
  if (command === "--version" || command === "version") {
    console.log(packageVersion());
    return;
  }

  const paths = resolveDescartesPaths();
  assertNoPiOwnedPath(paths);

  if (command === "login") {
    const { runLogin } = await import("./login.js");
    await runLogin(paths, args);
    return;
  }
  if (command === "triage") {
    const { runTriage } = await import("./triage.js");
    await runTriage(paths, args);
    return;
  }

  throw new Error(`Unknown command: ${command}\n\n${usage()}`);
}

function realpathIfPresent(candidate) {
  if (!candidate) return undefined;
  try {
    return fs.realpathSync(candidate);
  } catch {
    return path.resolve(candidate);
  }
}

const entrypoint = realpathIfPresent(process.argv[1]);
const modulePath = realpathIfPresent(fileURLToPath(import.meta.url));
if (entrypoint === modulePath) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
