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
  descartes triage <PROMPT> [--json] [--model <MODEL>] [--thinking <LEVEL>] [--no-investigate] [--use-history|--no-history] [--history-window <DURATION>]
  descartes daemon install|start|status|stop|uninstall [--json]
  descartes daemon run --foreground [--once] [--interval <duration>]
  descartes history summary [--json] [--verbose] [--window <duration>]
  descartes alerts list [--json] [--all]
  descartes alerts watch [--json] [--interval <duration>] [--once] [--all]
  descartes alerts ack <alert-id> [--json]
  descartes alerts intelligence status|enable|disable [--json]
  descartes alerts notifications status|setup|test|disable [--json] [--channel cli|desktop|macos|native|linux|syslog]
  descartes learned mine [--json] [--window <duration>]
  descartes learned soak [--json]
  descartes learned calibration [--json] [--since <duration>] [--family <rule_id-prefix>]
  descartes learned review [--json]
  descartes learned approve <constraint-id> --nonce <nonce> [--note <text>] [--json]
  descartes learned reject <constraint-id> --nonce <nonce> [--note <text>] [--json]
  descartes learned enable [--json]
  descartes learned disable [--json]
  descartes learned status [--json]
  descartes provenance snapshot [--json]
  descartes provenance baseline show [--identity <hash>] [--json]
  descartes incident freeze [--reason <text>] [--json]
  descartes --version

Safety: v0 local evidence collection is read-only. No actions are taken. "descartes incident
freeze" persists a Descartes-owned forensic evidence bundle by calling only already-registered
read-only evidence tools -- it still mutates nothing on the monitored host.`;
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
  if (command === "daemon") {
    const { runDaemon } = await import("./daemon.js");
    await runDaemon(paths, args);
    return;
  }
  if (command === "history") {
    const { runHistory } = await import("./history.js");
    await runHistory(paths, args);
    return;
  }
  if (command === "alerts") {
    const { runAlerts } = await import("./alerts.js");
    await runAlerts(paths, args);
    return;
  }
  if (command === "learned") {
    // "soak" (Slice S7a, draft->shadow enrollment + shadow->review-ready promotion) is
    // dispatched here rather than added to constraint-miner.js's runLearned — keeps
    // constraint-miner.js's blast radius untouched by this slice. Every other learned
    // subcommand (currently just "mine", plus bare/--help) is unchanged, delegated exactly
    // as before.
    if (args[0] === "soak") {
      const { runLearnedSoak } = await import("./shadow-store.js");
      await runLearnedSoak(paths, args.slice(1));
      return;
    }
    // "calibration" (Slice S15, the read-only foundation for S14 compile-down): a deterministic,
    // NO-LLM per-artifact precision/recall PROXY report over existing outcome signals. Lives in
    // its own module (calibration.js) rather than constraint-miner.js/shadow-store.js -- it reads
    // across FOUR different existing stores (alerts, LLM-decisions, notification-delivery, shadow
    // violations), which doesn't naturally belong to any single one of them.
    if (args[0] === "calibration") {
      const { runLearnedCalibration } = await import("./calibration.js");
      await runLearnedCalibration(paths, args.slice(1));
      return;
    }
    // "review"/"approve"/"reject" (Slice S7b, the human authority gate) live in
    // promotion-store.js — the only module that can advance a constraint past review-ready.
    if (args[0] === "review") {
      const { runLearnedReview } = await import("./promotion-store.js");
      await runLearnedReview(paths, args.slice(1));
      return;
    }
    if (args[0] === "approve") {
      const { runLearnedApprove } = await import("./promotion-store.js");
      await runLearnedApprove(paths, args.slice(1));
      return;
    }
    if (args[0] === "reject") {
      const { runLearnedReject } = await import("./promotion-store.js");
      await runLearnedReject(paths, args.slice(1));
      return;
    }
    // "enable"/"disable"/"status" (minor Codex review finding): the configDir/learned.json
    // kill switch had no dedicated command — see constraint-store.js's runLearnedConfigCommand.
    if (args[0] === "enable" || args[0] === "disable" || args[0] === "status") {
      const { runLearnedConfigCommand } = await import("./constraint-store.js");
      await runLearnedConfigCommand(paths, args[0], args.slice(1));
      return;
    }
    const { runLearned } = await import("./constraint-miner.js");
    await runLearned(paths, args);
    return;
  }
  if (command === "provenance") {
    // Slice S5: identity-baseline store CLI (`snapshot`/`baseline show`), mirroring every other
    // top-level command's dedicated-module + run<Thing>(paths, args) dispatch pattern.
    const { runProvenanceStore } = await import("./provenance-store.js");
    await runProvenanceStore(paths, args);
    return;
  }
  if (command === "incident") {
    // Observed-incident collectors plan, Slice 2: evidence-freeze/forensic-snapshot action --
    // read-only against the monitored host (see evidence-freeze.js's module header), mirroring
    // the same dedicated-module + run<Thing>(paths, args) dispatch pattern as every other
    // top-level command above.
    const { runIncident } = await import("./evidence-freeze.js");
    await runIncident(paths, args);
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
