// Slice 7.2.d (recommend-only containment surface plan, docs/plans/
// 2026-08-21-slice-7.2-recommend-only-containment-surface.md) -- the structural-incapability
// guard, as executable tests. This slice IS the adversarial artifact: it encodes "structurally
// incapable of acting" as assertions that fail if a future change ever adds an execution edge to
// this surface. If an assertion here becomes awkward to express, that is signal the boundary is
// not as clean as claimed (plan §Slice 7.2.d).
//
// The repo-wide zero-new-execFile escalation lint (test/escalation-lint.test.js) already scans
// the ENTIRE src/ tree, including containment-recommend.js/containment.js, for exec/spawn-family
// calls to an escalation binary and macOS privileged-helper API references -- this file does not
// duplicate that general scan. It instead asserts the SPECIFIC, narrower claims Slice 7.2.d's
// plan text calls out: no reference anywhere in this surface to a capability token / helper
// process / authority store / execFile-family identifier at all (stricter than the general lint,
// which only flags escalation-binary arguments), the closed-verb-enum guarantee, and the
// namespace hard-exclude posture re-asserted as a standing boundary invariant.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { classifyAlertNamespace } from "../src/alert-intelligence.js";
import {
  KNOWN_CONTAINMENT_VERBS,
  containmentRecommendationRuleIds,
  mapAlertToRecommendation,
  renderRecommendationText,
} from "../src/containment-recommend.js";

const SRC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

const CONTAINMENT_SURFACE_FILES = ["containment-recommend.js", "containment.js"];

// Minimal comment stripper (line `//` and block `/* */`), string-literal-aware so a quote inside
// a string is never misread as a comment delimiter. This module's own header/JSDoc comments
// deliberately DISCUSS the very things these tests must prove are ABSENT from real code (e.g.
// "no child_process import", "no capability token") -- without stripping comments first, those
// documentation sentences would trip every assertion below on the file's own prose. Deliberately
// simpler than escalation-lint.test.js's own stripComments (no regex-literal awareness): the two
// files scanned here are hand-authored in this slice and contain no regex literals; if that ever
// changes, escalation-lint.test.js's own whole-src-tree scan is the general-purpose backstop.
function stripComments(source) {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    const c2 = source[i + 1];
    if (c === "/" && c2 === "/") {
      while (i < n && source[i] !== "\n") { out += " "; i++; }
      continue;
    }
    if (c === "/" && c2 === "*") {
      out += "  ";
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        out += source[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) { out += "  "; i += 2; }
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n && source[i] !== quote) {
        if (source[i] === "\\" && i + 1 < n) { out += source[i] + source[i + 1]; i += 2; continue; }
        out += source[i];
        i++;
      }
      if (i < n) { out += source[i]; i++; }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function readSurfaceSource(filename) {
  return stripComments(readFileSync(path.join(SRC_DIR, filename), "utf8"));
}

// Blanks string-literal CONTENTS too (keeping the quotes), on top of stripComments — used only
// for identifier/token-shaped checks (e.g. an actual `spawn(` call site) where a prose string like
// this module's own "process spawn relationship" rationale text must never false-positive. Import
// specifiers (e.g. "node:child_process") are intentionally checked against the STRING-PRESERVING
// stripComments output instead (readSurfaceSource above), not this one.
function readSurfaceCodeOnly(filename) {
  const withoutComments = stripComments(readFileSync(path.join(SRC_DIR, filename), "utf8"));
  let out = "";
  let i = 0;
  const n = withoutComments.length;
  while (i < n) {
    const c = withoutComments[i];
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n && withoutComments[i] !== quote) {
        if (withoutComments[i] === "\\" && i + 1 < n) { out += "  "; i += 2; continue; }
        out += " ";
        i++;
      }
      if (i < n) { out += withoutComments[i]; i++; }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

test("no module in the containment-recommend surface imports child_process, and no real code (not prose inside a string) references any exec/spawn-family identifier", () => {
  for (const filename of CONTAINMENT_SURFACE_FILES) {
    // Import-specifier check against the string-preserving source (an import path IS a string
    // literal, e.g. `from "node:child_process"`).
    assert.equal(/child_process/i.test(readSurfaceSource(filename)), false, `${filename} must never import node:child_process`);
    // Identifier-shaped check against the code-only source (string CONTENTS blanked), so a prose
    // rationale sentence mentioning "process spawn relationship" or similar never false-positives.
    const codeOnly = readSurfaceCodeOnly(filename);
    assert.equal(/\bexec(File|Sync|FileSync)?\b/.test(codeOnly), false, `${filename} must never reference an exec-family identifier in real code`);
    assert.equal(/\bspawn(Sync)?\b/.test(codeOnly), false, `${filename} must never reference a spawn-family identifier in real code`);
  }
});

test("no reference anywhere in the containment-recommend surface's real code to a capability token, a helper process, or an authority store", () => {
  for (const filename of CONTAINMENT_SURFACE_FILES) {
    const codeOnly = readSurfaceCodeOnly(filename);
    assert.equal(/capability.?token/i.test(codeOnly), false, `${filename} must never reference a capability token`);
    assert.equal(/authority[/\\]containment/i.test(codeOnly), false, `${filename} must never reference authority/containment.json — that is §(e) Slice 7.3, out of scope here`);
    assert.equal(/root_helper|privileged.?helper/i.test(codeOnly), false, `${filename} must never reference a privileged/root helper process`);
  }
});

test("no reference anywhere in the containment-recommend surface's real code to any mutating syscall/subprocess API (kill, chmod)", () => {
  for (const filename of CONTAINMENT_SURFACE_FILES) {
    const codeOnly = readSurfaceCodeOnly(filename);
    // containment-recommend.js legitimately uses fs.writeFile/fs.rename/fs.mkdir to persist its
    // OWN config file (Slice 7.2.b) -- that is Descartes-owned config state, not a mutation of the
    // monitored host, and is explicitly out of scope for this specific assertion (the module
    // header + Slice 7.2.b's own tests cover that file's contents). This assertion targets host-
    // mutating primitives that have NO legitimate reason to appear in this surface at all.
    assert.equal(/\bprocess\.kill\b/.test(codeOnly), false, `${filename} must never reference process.kill`);
    assert.equal(/\bos\.kill\b/.test(codeOnly), false, `${filename} must never reference os.kill`);
    assert.equal(/\bfs\.chmod\b|\bchmodSync\b/.test(codeOnly), false, `${filename} must never reference fs.chmod (a permission mutation)`);
  }
});

test("the recommendation record's verb field is always a closed-enum member — a hand-forged out-of-enum verb never renders", () => {
  for (const verb of ["nuke", "delete-everything", "revoke; rm -rf /", ""]) {
    assert.equal(renderRecommendationText({ verb, target_repr: "global", rationale: "x" }), undefined, `verb "${verb}" must be rejected, not rendered`);
  }
  assert.equal(KNOWN_CONTAINMENT_VERBS.length, 5);
  assert.deepEqual([...KNOWN_CONTAINMENT_VERBS].sort(), ["block", "kill", "quarantine", "revoke", "throttle"]);
});

test("no consumer of a containment.recommend.* record re-resolves target_repr to a live/raw target — grep-assert: target_repr never appears interpolated into an execFile-shaped call anywhere in src/", () => {
  // Scans the WHOLE src tree (not just the containment surface) for any source line that
  // mentions both "target_repr" and an exec/spawn-family identifier -- the shape a future
  // regression (a new consumer wiring the recommendation's target into an action) would take.
  // Slice 7.2.c's plan text carves out the three legitimate readers of a containment.recommend.*
  // record: renderRecommendationText/renderStoredRecommendationText + the
  // buildSessionAlertNotificationDecision branch that calls it (alert-intelligence.js), the
  // pre-existing emitSessionAlertSignals deterministic-local-delivery sink (also
  // alert-intelligence.js), and tests -- none of which ever combines target_repr with an
  // exec/spawn-family call.
  const violations = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!entry.name.endsWith(".js") || entry.name.endsWith(".test.js")) continue;
      const source = readFileSync(full, "utf8");
      for (const [index, line] of source.split("\n").entries()) {
        if (line.includes("target_repr") && /exec(File|Sync)?\(|spawn(Sync)?\(/.test(line)) {
          violations.push(`${path.relative(SRC_DIR, full)}:${index + 1}: ${line.trim()}`);
        }
      }
    }
  };
  walk(SRC_DIR);
  assert.deepEqual(violations, []);
});

test("standing boundary invariant: every containment.recommend.<verb> rule_id is hard-excluded (not merely unknown_namespace), and the exclusion cannot be opted around by a forged/malicious enabled_namespaces config", () => {
  for (const ruleId of containmentRecommendationRuleIds()) {
    const classified = classifyAlertNamespace(ruleId);
    assert.equal(classified.hardExcluded, true, `${ruleId} must be hardExcluded`);
    assert.equal(classified.namespace, "containment", `${ruleId} must classify as the containment namespace, not fall through to unknown_namespace`);
  }
});

test("standing boundary invariant: mapAlertToRecommendation never returns a recommendation whose verb escapes KNOWN_CONTAINMENT_VERBS, across every shipped trigger rule_id this module knows about", () => {
  const plausibleDiagnosticsByRuleId = {
    "session.count_drop": { observed_count: 0, mean_before: 20 },
    "session.churn": { entity_key: "session.tmux.aaaaaaaaaaaaaaaa" },
    "peer.count_spike": { observed_count: 8, mean_before: 2 },
    "canary.tripped": { canary_id_hash: "abcdef0123456789" },
    "canary.tampered": { tamper_reason: "canary_vanished", canary_id_hash: "abcdef0123456789" },
    "process.lineage.novel_edge": { entity_key_hash: "abcdef0123456789" },
  };
  let sawAtLeastOneRecommendation = false;
  for (const [ruleId, diagnostics] of Object.entries(plausibleDiagnosticsByRuleId)) {
    const rec = mapAlertToRecommendation({ rule_id: ruleId, diagnostics });
    if (!rec) continue;
    sawAtLeastOneRecommendation = true;
    assert.ok(KNOWN_CONTAINMENT_VERBS.includes(rec.verb));
    assert.equal(rec.rule_id, `containment.recommend.${rec.verb}`);
  }
  assert.ok(sawAtLeastOneRecommendation, "sanity: at least one shipped trigger must actually produce a recommendation, or this test proves nothing");
});
