import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOLS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "tools");

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
