// Slice 7.2.b (recommend-only containment surface plan, docs/plans/
// 2026-08-21-slice-7.2-recommend-only-containment-surface.md) -- operator CLI face for the
// dedicated, default-OFF containment-recommend.json opt-in, mirroring alerts.js's
// `alerts intelligence status|enable|disable` shape and constraint-store.js's
// `runLearnedConfigCommand` template exactly. This module contains NO execution logic of any
// kind -- it only reads/writes containment-recommend.json via containment-recommend.js.
import { loadLearnedConfig } from "./constraint-store.js";
import {
  readContainmentRecommendConfig,
  resolveContainmentRecommendPaths,
  writeContainmentRecommendConfig,
} from "./containment-recommend.js";

function containmentUsage() {
  return `Usage:
  descartes containment recommend status [--json]
  descartes containment recommend enable [--json]
  descartes containment recommend disable [--json]

Controls the RECOMMEND-ONLY containment surface's dedicated opt-in (configDir/
containment-recommend.json), independent of 'descartes learned enable' (monitoring) and of the
future containment authority gate. This surface never executes a containment action -- it only
proposes one (throttle/block/quarantine; kill/revoke are never emitted by the current default
map) via the existing local-notification path, always labeled RECOMMEND-ONLY. 'enable' requires
'descartes learned enable' to already be on (this surface only recommends on signals produced by
the learned detectors) and refuses with an honest error otherwise, leaving the config unchanged --
it never silently enables monitoring as a side effect.`;
}

function renderContainmentRecommendStatus(config, configFile) {
  const lines = [`Containment recommend-only surface: ${config.enabled ? "enabled" : "disabled"}`];
  lines.push(`Config path: ${configFile}`);
  if (config.updated_at) lines.push(`Last updated: ${config.updated_at}`);
  if (config.corrupt) lines.push("WARNING: containment-recommend.json was corrupt on disk; treated as disabled defaults until repaired and rewritten.");
  if (config.unavailable) lines.push("WARNING: containment-recommend.json could not be read (filesystem error); treated as disabled defaults until the read succeeds again. 'enable'/'disable' will refuse to write until then.");
  lines.push("This surface never executes a containment action; it only proposes one, for a human to act on manually.");
  return lines.join("\n");
}

export async function runContainment(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const argv = Array.isArray(args) ? args : [];

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    output(containmentUsage());
    return undefined;
  }
  if (argv[0] !== "recommend") {
    throw new Error(`Unknown containment subcommand: ${argv[0]}\n\n${containmentUsage()}`);
  }

  const subcommand = argv[1];
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    output(containmentUsage());
    return undefined;
  }
  if (!["status", "enable", "disable"].includes(subcommand)) {
    throw new Error(`Unknown containment recommend subcommand: ${subcommand}\n\n${containmentUsage()}`);
  }
  const json = argv.slice(2).includes("--json");
  const unexpected = argv.slice(2).filter((arg) => arg !== "--json");
  if (unexpected.length > 0) {
    throw new Error(`Unexpected containment recommend argument: ${unexpected[0]}\n\n${containmentUsage()}`);
  }

  const { configFile } = resolveContainmentRecommendPaths(descartesPaths);
  let config;
  if (subcommand === "status") {
    config = await readContainmentRecommendConfig(descartesPaths);
  } else if (subcommand === "disable") {
    config = await writeContainmentRecommendConfig(descartesPaths, { enabled: false }, { now: runtime.now });
  } else if (subcommand === "enable") {
    // P4: enabling this surface requires learned.json (monitoring) to already be ON -- you
    // cannot recommend containment on signals you are not collecting. Fails honestly, config
    // unchanged, rather than silently enabling monitoring as a side effect.
    const loadLearned = runtime.loadLearnedConfig ?? loadLearnedConfig;
    const learnedConfig = await loadLearned(descartesPaths);
    if (!learnedConfig.enabled) {
      throw new Error(
        `Cannot enable the containment recommend-only surface: 'descartes learned' monitoring is OFF. Run 'descartes learned enable' first -- this surface only recommends on signals produced by the learned detectors, and enabling it does not itself enable monitoring.\n\n${containmentUsage()}`,
      );
    }
    config = await writeContainmentRecommendConfig(descartesPaths, { enabled: true }, { now: runtime.now });
  }

  if (json) output(JSON.stringify({ containment_recommend: { ...config, config_path: configFile } }, null, 2));
  else output(renderContainmentRecommendStatus(config, configFile));
  return config;
}
