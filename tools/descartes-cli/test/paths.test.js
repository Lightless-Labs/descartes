import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";

test("XDG path resolution honors explicit base directories", () => {
  const env = {
    HOME: "/home/alice",
    XDG_CONFIG_HOME: "/tmp/config",
    XDG_DATA_HOME: "/tmp/data",
    XDG_STATE_HOME: "/tmp/state",
    XDG_CACHE_HOME: "/tmp/cache",
    XDG_RUNTIME_DIR: "/tmp/runtime",
  };

  assert.deepEqual(resolveDescartesPaths(env), {
    configDir: path.join("/tmp/config", "descartes"),
    authFile: path.join("/tmp/config", "descartes", "auth.json"),
    modelsFile: path.join("/tmp/config", "descartes", "models.json"),
    dataDir: path.join("/tmp/data", "descartes"),
    stateDir: path.join("/tmp/state", "descartes"),
    sessionDir: path.join("/tmp/state", "descartes", "sessions"),
    cacheDir: path.join("/tmp/cache", "descartes"),
    runtimeDir: path.join("/tmp/runtime", "descartes"),
  });
});

test("XDG path resolution uses Unix defaults under HOME", () => {
  const paths = resolveDescartesPaths({ HOME: "/home/alice" });
  assert.equal(paths.configDir, path.join("/home/alice", ".config", "descartes"));
  assert.equal(paths.dataDir, path.join("/home/alice", ".local", "share", "descartes"));
  assert.equal(paths.stateDir, path.join("/home/alice", ".local", "state", "descartes"));
  assert.equal(paths.cacheDir, path.join("/home/alice", ".cache", "descartes"));
  assert.equal(paths.runtimeDir, undefined);
});

test("Descartes path resolution does not use Pi-owned defaults", () => {
  const paths = resolveDescartesPaths({ HOME: "/home/alice" });
  assert.doesNotThrow(() => assertNoPiOwnedPath(paths));
  for (const value of Object.values(paths)) {
    if (value) {
      assert(!value.includes("/.pi"));
      assert(!value.includes("/.pi/agent"));
    }
  }
});

test("Pi-owned path guard rejects accidental .pi paths", () => {
  assert.throws(
    () => assertNoPiOwnedPath({ configDir: "/home/alice/.pi/agent" }),
    /Pi-owned location/
  );
});
