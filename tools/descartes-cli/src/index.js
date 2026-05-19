#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "./paths.js";

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

main(process.argv.slice(2)).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
