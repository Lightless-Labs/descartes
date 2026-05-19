#!/usr/bin/env node
import { assertNoPiOwnedPath, resolveDescartesPaths } from "./paths.js";

function usage() {
  return `Descartes

Usage:
  descartes login [provider] [--api-key] [--no-open]
  descartes triage <PROMPT> [--json]
  descartes --version

Safety: v0 local evidence collection is read-only. No actions are taken.`;
}

async function main(argv) {
  const [command, ...args] = argv;
  if (!command || command === "--help" || command === "-h") {
    console.log(usage());
    return;
  }
  if (command === "--version" || command === "version") {
    console.log("0.0.3");
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
