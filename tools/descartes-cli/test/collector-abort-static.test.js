import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOLS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "tools");

function toolFiles() {
  return fs.readdirSync(TOOLS_DIR, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".js"))
    .map((entry) => path.join(entry.parentPath ?? entry.path, entry.name));
}

test("MEDIUM 1: every runner launch call site is individually behind the shared abort-before-launch helper", () => {
  const files = ["vpn-peer-status.js", "login-sessions.js", "last-history.js", "net-config.js", "tailscale-status.js", "host-lifecycle.js", "network.js"];
  const offenders = [];
  let callSiteCount = 0;
  for (const file of files) {
    const source = fs.readFileSync(path.join(TOOLS_DIR, file), "utf8");
    const calls = [...source.matchAll(/\b(?:runExec|runResolvedExecFile)\s*\(/g)]
      .filter((match) => !/\b(?:async\s+)?function\s+\w*\s*$/.test(source.slice(Math.max(0, match.index - 32), match.index)));
    callSiteCount += calls.length;
    for (const match of calls) {
      const prefix = source.slice(Math.max(0, match.index - 420), match.index);
      if (!/throwIfCollectorAborted\s*\(|abortIfNeeded\s*\(/.test(prefix)) offenders.push(`${file}:${source.slice(0, match.index).split("\n").length}`);
    }
  }
  assert.ok(callSiteCount > files.length, "the regression must inspect individual calls, not one result per file");
  assert.deepEqual(offenders, [], "every subprocess runner call site must have a preceding abort guard");
});

test("LOW: every execFile/spawn-family launch under src/tools has its own preceding abort guard", () => {
  const launch = /\b(?:execFile(?:Async|Sync)?|spawn(?:Sync)?)\s*\(/;
  const offenders = [];
  let callSiteCount = 0;
  for (const filename of toolFiles()) {
    const lines = fs.readFileSync(filename, "utf8").split("\n").map((line) => line.replace(/\/\/.*$/, ""));
    for (let index = 0; index < lines.length; index += 1) {
      if (!launch.test(lines[index]) || /\bfunction\s+(?:execFile|spawn|runResolvedExecFile)\b/.test(lines[index])) continue;
      callSiteCount += 1;
      let previous = index - 1;
      while (previous >= 0 && lines[previous].trim() === "") previous -= 1;
      if (previous < 0 || !/throwIfCollectorAborted\s*\(/.test(lines[previous])) {
        offenders.push(`${path.relative(TOOLS_DIR, filename)}:${index + 1}`);
      }
    }
  }
  assert.ok(callSiteCount > 0);
  assert.deepEqual(offenders, []);
});
