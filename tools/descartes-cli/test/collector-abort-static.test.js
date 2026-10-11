import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOLS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "tools");

test("MEDIUM 1: every raw execFileAsync launch in tools is behind the shared abort-before-launch helper", () => {
  const files = fs.readdirSync(TOOLS_DIR).filter((name) => name.endsWith(".js"));
  const offenders = [];
  for (const file of files) {
    const source = fs.readFileSync(path.join(TOOLS_DIR, file), "utf8");
    if (!/\bexecFileAsync\s*\(/.test(source)) continue;
    if (!/throwIfCollectorAborted\s*\(/.test(source)) offenders.push(file);
  }
  assert.deepEqual(offenders, [], "every subprocess-launching tool must use throwIfCollectorAborted");
});
