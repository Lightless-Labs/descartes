import os from "node:os";
import path from "node:path";

function homeDir(env = process.env) {
  return env.HOME || os.homedir();
}

function baseFromEnv(envName, fallbackSegments, env = process.env) {
  const configured = env[envName];
  if (configured && configured.trim().length > 0) return configured;
  return path.join(homeDir(env), ...fallbackSegments);
}

export function resolveDescartesPaths(env = process.env) {
  const configBase = baseFromEnv("XDG_CONFIG_HOME", [".config"], env);
  const dataBase = baseFromEnv("XDG_DATA_HOME", [".local", "share"], env);
  const stateBase = baseFromEnv("XDG_STATE_HOME", [".local", "state"], env);
  const cacheBase = baseFromEnv("XDG_CACHE_HOME", [".cache"], env);
  const runtimeBase = env.XDG_RUNTIME_DIR && env.XDG_RUNTIME_DIR.trim().length > 0 ? env.XDG_RUNTIME_DIR : undefined;

  return {
    configDir: path.join(configBase, "descartes"),
    authFile: path.join(configBase, "descartes", "auth.json"),
    modelsFile: path.join(configBase, "descartes", "models.json"),
    dataDir: path.join(dataBase, "descartes"),
    stateDir: path.join(stateBase, "descartes"),
    sessionDir: path.join(stateBase, "descartes", "sessions"),
    cacheDir: path.join(cacheBase, "descartes"),
    runtimeDir: runtimeBase ? path.join(runtimeBase, "descartes") : undefined,
  };
}

export function assertNoPiOwnedPath(resolvedPaths) {
  for (const [key, value] of Object.entries(resolvedPaths)) {
    if (!value) continue;
    const normalized = value.split(path.sep).join("/");
    if (/(^|\/)\.pi(\/|$)/.test(normalized) || normalized.includes("/.pi/agent/")) {
      throw new Error(`Descartes path ${key} resolves into a Pi-owned location: ${value}`);
    }
  }
}
