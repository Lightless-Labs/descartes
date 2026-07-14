// Slice 6 (observed-incident collectors plan), Decision 3, must-fix 4: a from-scratch, static
// source-scan test for the S13 `enableTools` invariant. Genuinely a S13 invariant, not specific to
// Slice 6 — but Slice 6 is the slice whose Definition of Done finally requires it to exist,
// because a cross-stream correlation module is the change most tempted to reach for a session
// directly. Confirmed by a whole-tree grep (reproducible by any implementer with the same
// command) that this test does not exist anywhere in the suite before this slice.
//
// Grounded against the exact, currently-verified call-site inventory:
//   - createAgentSession( -- exactly one call site: pi-harness.js, inside the shared
//     createPrivateSession helper.
//   - createPrivateAlertSession -- exactly one production reference outside its own definition:
//     alert-intelligence.js (adjudicateAlertNotifications, via a dynamic import).
//   - createPrivateTriageSession -- exactly one production reference outside its own definition:
//     triage.js (the `descartes triage` CLI command).
//
// Follows the exact static-source-scan idiom already established in this codebase for this class
// of invariant (evidence-freeze.test.js's findExecLikeCallSites/comment-stripped-source pattern).
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SRC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

// Mirrors evidence-freeze.test.js's/escalation-lint.test.js's own comment-stripping helper —
// deliberately duplicated rather than imported, keeping this file self-contained (same convention
// this repo already applies to fact-store.js's own duplicated readJsonLines).
function stripLineAndBlockComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function walkJsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkJsFiles(p));
    else if (entry.isFile() && entry.name.endsWith(".js") && !entry.name.endsWith(".test.js")) out.push(p);
  }
  return out;
}

function countOccurrences(source, literal) {
  const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return (source.match(new RegExp(escaped, "g")) ?? []).length;
}

// Scanned and comment-stripped ONCE at module load (not per test) — the tree is read-only static
// source, so there is no reason to re-walk/re-read/re-strip the whole src/ tree once per test.
const SCANNED_FILES = walkJsFiles(SRC_DIR).map((file) => ({
  file,
  relative: path.relative(SRC_DIR, file),
  stripped: stripLineAndBlockComments(readFileSync(file, "utf8")),
}));

// Returns { total, perFile: [{file, count}] } across the whole tree, scanning COMMENT-STRIPPED
// source only — a mention inside a comment (e.g. evidence-freeze.js's own "this file never calls
// createPrivateAlertSession..." doc comment) must never count as a real reference.
function occurrencesAcrossTree(literal) {
  const perFile = [];
  let total = 0;
  for (const entry of SCANNED_FILES) {
    const count = countOccurrences(entry.stripped, literal);
    if (count > 0) perFile.push({ file: entry.relative, count });
    total += count;
  }
  return { total, perFile };
}

test("createAgentSession( appears exactly once across the whole tools/descartes-cli/src tree — pi-harness.js's shared createPrivateSession helper is the sole funnel point for a tool-capable agent session", () => {
  assert.ok(SCANNED_FILES.length > 10, `expected to scan a substantial number of source files, only found ${SCANNED_FILES.length}`);
  const { total, perFile } = occurrencesAcrossTree("createAgentSession(");
  assert.equal(total, 1, `expected exactly one createAgentSession( call site, found ${total}: ${JSON.stringify(perFile)}`);
  assert.deepEqual(perFile, [{ file: "pi-harness.js", count: 1 }]);
});

test("createPrivateAlertSession has exactly one production reference outside its own definition (alert-intelligence.js) — Slice 6's own incident-correlation.js must NOT appear in this list", () => {
  const { perFile } = occurrencesAcrossTree("createPrivateAlertSession");
  const outsideDefinition = perFile.filter((entry) => entry.file !== "pi-harness.js");
  assert.deepEqual(outsideDefinition.map((entry) => entry.file), ["alert-intelligence.js"]);
  assert.equal(outsideDefinition.some((entry) => entry.file === "incident-correlation.js"), false, "incident-correlation.js produces a candidate object only and must never import pi-harness.js at all");
});

test("evidence-freeze.js's mention of createPrivateAlertSession is comment-only and is excluded by the comment-stripping scan (the one real pre-existing case that exercises the scanner's correctness, not merely a count that happens to be right)", () => {
  const evidenceFreezePath = path.join(SRC_DIR, "evidence-freeze.js");
  const raw = readFileSync(evidenceFreezePath, "utf8");
  assert.ok(raw.includes("createPrivateAlertSession"), "expected evidence-freeze.js's raw source to mention this literal (inside a comment) — otherwise this negative case tests nothing");

  const { perFile } = occurrencesAcrossTree("createPrivateAlertSession");
  assert.equal(perFile.some((entry) => entry.file === "evidence-freeze.js"), false, "evidence-freeze.js must be excluded once comments are stripped — its raw source mentions this literal only inside a comment");
});

test("createPrivateTriageSession has exactly one production reference outside its own definition (triage.js)", () => {
  const { perFile } = occurrencesAcrossTree("createPrivateTriageSession");
  const outsideDefinition = perFile.filter((entry) => entry.file !== "pi-harness.js");
  assert.deepEqual(outsideDefinition.map((entry) => entry.file), ["triage.js"]);
});

test("createPrivateAlertSession hardcodes enableTools:false, positioned AFTER ...options in the object spread — the load-bearing property that makes it unconditional rather than merely defaulted (no caller-supplied options.enableTools can ever override it back to true)", () => {
  const stripped = stripLineAndBlockComments(readFileSync(path.join(SRC_DIR, "pi-harness.js"), "utf8"));
  const defIndex = stripped.indexOf("export async function createPrivateAlertSession");
  assert.notEqual(defIndex, -1, "expected to find createPrivateAlertSession's own definition");
  const body = stripped.slice(defIndex);

  const optionsSpreadIndex = body.indexOf("...options");
  const enableToolsFalseIndex = body.indexOf("enableTools: false");
  assert.notEqual(optionsSpreadIndex, -1, "expected createPrivateAlertSession's body to spread ...options");
  assert.notEqual(enableToolsFalseIndex, -1, "expected createPrivateAlertSession's body to hardcode enableTools: false");
  assert.ok(optionsSpreadIndex < enableToolsFalseIndex, "enableTools: false must come AFTER ...options in the object literal so it cannot be overridden by a caller-supplied options.enableTools");
});

test("createPrivateTriageSession does NOT hardcode enableTools:false — it legitimately supports investigate mode with tools enabled, a pre-existing, reviewed capability this slice must not mischaracterize or weaken", () => {
  const stripped = stripLineAndBlockComments(readFileSync(path.join(SRC_DIR, "pi-harness.js"), "utf8"));
  const defIndex = stripped.indexOf("export async function createPrivateTriageSession");
  const nextDefIndex = stripped.indexOf("export async function createPrivateAlertSession");
  assert.notEqual(defIndex, -1);
  assert.notEqual(nextDefIndex, -1);
  const body = stripped.slice(defIndex, nextDefIndex);
  assert.equal(body.includes("enableTools: false"), false);
  assert.equal(body.includes("enableTools: true"), false);
});
