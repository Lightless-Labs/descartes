// Standing lint for the Safety Invariant in AGENTS.md: "No silent privilege escalation" -- the
// daemon/provenance runtime must never shell out to escalate. docs/operator/
// linux-elevated-provenance-setup.md asserts this is "enforced by a standing CI lint"; this file
// IS that lint. It runs on every `npm test`, i.e. every CI build and every local run.
//
// Deliberately dependency-free (no `ast-grep`/`sg` subprocess): this repo's own
// scripts/ci-elevated-provenance.sh already uses the name `sg` for the Unix "switch group"
// command, so shelling out to a binary named `sg` here would be ambiguous depending on what's
// first on PATH -- exactly the kind of environment-dependent flake a "standing" lint must not
// have. The scan shapes below were designed and validated against fixtures with ast-grep (see
// this repo's CLAUDE.md preference for it) before being ported to this self-contained scanner.
//
// Detects two escalation shapes in REAL CODE (not comments, not unrelated strings):
//   (a) a call whose callee identifier contains "exec" or "spawn" (case-insensitively, bare or
//       as a member -- `execFile(`, `cp.execFile(`, `execFileAsync(`, `runFixedExecFile(`, ...)
//       where ANY string-literal argument, once split into whitespace/"/"-separated tokens,
//       contains an escalation binary (sudo/setcap/pkexec/doas) as an exact token -- not a
//       substring, so "sudoku"/"foosudo" don't match but "/usr/bin/sudo" and
//       "sudo setcap cap_sys_ptrace=ep /bin/foo" do -- or whose arguments invoke osascript
//       together with an administrator-privilege argument.
//   (b) any reference (identifier or string literal) to a macOS privileged-helper elevation API
//       (SMJobBless/SMAppService/AuthorizationExecuteWithPrivileges).
//
// The callee match in (a) is deliberately broad (any "exec"/"spawn"-ish name, not a fixed list of
// Node.js API names) so it also catches this repo's own aliases/wrappers -- execFileAsync =
// promisify(execFile) (provenance.js, provenance-elevated.js, daemon.js, and most tools/*.js) and
// provenance.js's runFixedExecFile wrapper (used 7x) -- and any future exec/spawn wrapper someone
// adds, without needing this file updated every time. That breadth is safe ONLY because every
// match is then gated on an actual escalation-binary token appearing in a string-literal argument:
// a benign call like executeQuery("select ...") is never flagged because none of its argument
// tokens are sudo/setcap/pkexec/doas. Known, deliberately-accepted residual (out of scope for an
// accidental-reintroduction tripwire; closing it needs real dataflow analysis, not a regex/token
// scanner): destructured-rename to an arbitrary identifier (`const run = execFile; run("sudo")`),
// command names held in variables or computed strings (`execFile(cfg.command, ...)`), and other
// fully-indirected calls.
//
// Comment-safety: source is scanned with comments replaced by whitespace (via stripComments)
// before matching, so a comment like "no setcap/sudo anywhere in this file" (see
// src/tools/provenance-elevated.js's header) never trips this lint -- only real code does.
// stripComments also has minimal regex-literal awareness (a `/.../ ` is consumed as a unit, so a
// quote INSIDE a regex literal -- e.g. `/it's/`, which real code uses at src/tools/logs.js:136's
// `/\b(sshd?|pam|sudo|login|...)\b/` -- never desyncs the string-vs-comment state machine and
// leaks a later real comment's escalation words into the scanned code).

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SRC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

const ESCALATION_BINARIES = new Set(["sudo", "setcap", "pkexec", "doas"]);
const MACOS_API_NAMES = ["SMJobBless", "SMAppService", "AuthorizationExecuteWithPrivileges"];

// Any call whose callee identifier contains "exec" or "spawn" is a candidate exec-family call --
// see the module-level comment above for why this is deliberately broader than a fixed list of
// Node.js API names, and why that's safe (gated on ESCALATION_BINARIES token matches below).
const EXEC_LIKE_CALLEE_RE = /exec|spawn/i;

// Keywords after which a `/` starts an expression (so a following `/` is a regex literal, not
// division) even though the keyword itself is a word character sequence like an identifier.
const REGEX_PRECEDING_KEYWORDS = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);

// Heuristic for whether a `/` at the current scan position starts a regex literal, as opposed to
// being a division operator: looks at the last non-whitespace character already emitted to `out`.
// A `/` following an identifier/number/`)`/`]` is division UNLESS that identifier is a keyword
// that only ever precedes an expression (e.g. `return /foo/`). A `/` following anything else
// (an operator, punctuation, or the start of file) is a regex literal. This is a heuristic, not a
// full parser, but source in this repo doesn't need more than that: it only has to keep a quote
// INSIDE a regex literal from being misread as a string delimiter.
function looksLikeRegexStart(out) {
  let i = out.length - 1;
  while (i >= 0 && /\s/.test(out[i])) i--;
  if (i < 0) return true;
  const prevChar = out[i];
  if (/[A-Za-z0-9_$)\]]/.test(prevChar)) {
    const identMatch = out.slice(0, i + 1).match(/[A-Za-z_$][A-Za-z0-9_$]*$/);
    return !!identMatch && REGEX_PRECEDING_KEYWORDS.has(identMatch[0]);
  }
  return true;
}

// Replaces comment characters with spaces, preserving newlines and every other character's
// offset (so line numbers computed against the result still match the original file), and
// tracks string state so a `/` or quote character INSIDE a string is never misread as a comment
// delimiter. Regex literals are consumed as a unit (via looksLikeRegexStart) so a quote inside one
// (e.g. `/it's/`) can't desync the string-tracking state and leak a later comment as code.
function stripComments(source) {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    const c2 = source[i + 1];
    if (c === "/" && c2 === "/") {
      while (i < n && source[i] !== "\n") {
        out += " ";
        i++;
      }
      continue;
    }
    if (c === "/" && c2 === "*") {
      out += "  ";
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        out += source[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += "  ";
        i += 2;
      }
      continue;
    }
    if (c === "/" && c2 !== "/" && c2 !== "*" && looksLikeRegexStart(out)) {
      out += c;
      i++;
      let inCharClass = false;
      let closed = false;
      while (i < n) {
        const rc = source[i];
        if (rc === "\\" && i + 1 < n) {
          out += rc + source[i + 1];
          i += 2;
          continue;
        }
        if (rc === "\n") break; // unterminated regex literal (shouldn't happen in valid JS) -- bail
        if (rc === "[") inCharClass = true;
        else if (rc === "]") inCharClass = false;
        const isClosingSlash = rc === "/" && !inCharClass;
        out += rc;
        i++;
        if (isClosingSlash) {
          closed = true;
          break;
        }
      }
      if (closed) {
        while (i < n && /[a-zA-Z]/.test(source[i])) {
          out += source[i];
          i++;
        }
      }
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n && source[i] !== quote) {
        if (source[i] === "\\" && i + 1 < n) {
          out += source[i] + source[i + 1];
          i += 2;
          continue;
        }
        out += source[i];
        i++;
      }
      if (i < n) {
        out += source[i];
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function lineOf(source, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (source[i] === "\n") line++;
  return line;
}

// Reads a quoted string literal starting at `start` (which must point at a quote char) and
// returns { value, end } where end is the index just past the closing quote, or undefined if
// unterminated.
function readStringLiteral(source, start) {
  const quote = source[start];
  if (quote !== '"' && quote !== "'" && quote !== "`") return undefined;
  let i = start + 1;
  let value = "";
  while (i < source.length && source[i] !== quote) {
    if (source[i] === "\\" && i + 1 < source.length) {
      value += source[i + 1];
      i += 2;
      continue;
    }
    value += source[i];
    i++;
  }
  if (i >= source.length) return undefined;
  return { value, end: i + 1 };
}

function basenameTerm(value) {
  const segments = value.trim().split("/");
  return segments[segments.length - 1];
}

// Splits a string-literal argument on whitespace and "/" (so a shell-string argument like
// "sudo setcap cap_sys_ptrace=ep /bin/foo" and a full-path argument like "/usr/bin/sudo" both
// yield a "sudo" token) for exact basename-token equality against ESCALATION_BINARIES -- this is
// NOT a substring test, so "sudoku"/"foosudo" never match.
function tokenizeArgString(value) {
  return value.split(/[\s/]+/).filter(Boolean);
}

// Finds the end of a call's argument list, i.e. the index just past the `)` matching the `(` at
// openParenIndex, respecting nested parens and string literals.
function findArgListEnd(source, openParenIndex) {
  let depth = 0;
  let i = openParenIndex;
  while (i < source.length) {
    const c = source[i];
    if (c === "(") {
      depth++;
      i++;
      continue;
    }
    if (c === ")") {
      depth--;
      i++;
      if (depth === 0) return i;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const lit = readStringLiteral(source, i);
      if (!lit) return source.length;
      i = lit.end;
      continue;
    }
    i++;
  }
  return source.length;
}

// Scans (already comment-stripped) source for the escalation shapes and returns a list of
// { file, line, reason, text } violations.
export function findEscalationViolations(filePath, rawSource) {
  const source = stripComments(rawSource);
  const violations = [];

  const callRe = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
  let m;
  while ((m = callRe.exec(source))) {
    if (!EXEC_LIKE_CALLEE_RE.test(m[1])) continue;

    const openParen = m.index + m[0].length - 1;
    const argEnd = findArgListEnd(source, openParen);
    const argListText = source.slice(openParen, argEnd);

    const strings = [];
    let j = 0;
    while (j < argListText.length) {
      const c = argListText[j];
      if (c === '"' || c === "'" || c === "`") {
        const lit = readStringLiteral(argListText, j);
        if (!lit) break;
        strings.push(lit.value);
        j = lit.end;
        continue;
      }
      j++;
    }
    if (strings.length === 0) continue;

    let escalationHit;
    for (const s of strings) {
      const token = tokenizeArgString(s).find((t) => ESCALATION_BINARIES.has(t));
      if (token) {
        escalationHit = { token, source: s };
        break;
      }
    }
    if (escalationHit) {
      violations.push({
        file: filePath,
        line: lineOf(source, m.index),
        reason: `exec-family call to escalation binary "${escalationHit.token}"`,
        text: `${m[0].trim()} ... "${escalationHit.source}"`,
      });
      continue;
    }
    const hasOsascript = strings.some((s) => basenameTerm(s) === "osascript");
    const hasAdministrator = strings.some((s) => /administrator/i.test(s));
    if (hasOsascript && hasAdministrator) {
      violations.push({
        file: filePath,
        line: lineOf(source, m.index),
        reason: "osascript invoked with an administrator-privilege argument",
        text: `${m[0].trim()} ... osascript+administrator`,
      });
    }
  }

  for (const name of MACOS_API_NAMES) {
    const nameRe = new RegExp(`\\b${name}\\b`, "g");
    let nm;
    while ((nm = nameRe.exec(source))) {
      violations.push({
        file: filePath,
        line: lineOf(source, nm.index),
        reason: `reference to macOS privileged-helper API "${name}"`,
        text: name,
      });
    }
  }

  return violations;
}

function walkJsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkJsFiles(p));
    } else if (entry.isFile() && entry.name.endsWith(".js") && !entry.name.endsWith(".test.js")) {
      out.push(p);
    }
  }
  return out;
}

function formatViolations(violations) {
  return violations.map((v) => `${v.file}:${v.line}: ${v.reason} (${v.text})`).join("\n");
}

test("daemon runtime source (tools/descartes-cli/src) contains no privilege-escalation shell-outs or macOS elevation API references", () => {
  const files = walkJsFiles(SRC_DIR);
  assert.ok(files.length > 10, `expected to scan a substantial number of source files, only found ${files.length} under ${SRC_DIR}`);

  const violations = files.flatMap((file) => findEscalationViolations(path.relative(SRC_DIR, file), readFileSync(file, "utf8")));

  assert.equal(
    violations.length,
    0,
    `found ${violations.length} privilege-escalation shape(s) in daemon runtime source -- the daemon must never shell out to escalate (AGENTS.md Safety Invariant "No silent privilege escalation"):\n${formatViolations(violations)}`
  );
});

test("escalation scanner flags a direct shell-out to an escalation binary", () => {
  const source = `
    import { execFileSync } from "node:child_process";
    export function escalate() {
      return execFileSync("sudo", ["setcap", "cap_sys_ptrace=ep", "/bin/foo"]);
    }
  `;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /escalation binary "sudo"/);
});

test("escalation scanner flags a shell-string escalation (sh -c \"sudo ...\")", () => {
  const source = `
    import { execFile } from "node:child_process";
    export function escalate() {
      return execFile("sh", ["-c", "sudo setcap cap_sys_ptrace=ep /bin/foo"]);
    }
  `;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /escalation binary "sudo"/);
});

test("escalation scanner flags escalation via the execFileAsync wrapper alias", () => {
  const source = `
    import { execFile } from "node:child_process";
    import { promisify } from "node:util";
    const execFileAsync = promisify(execFile);
    export async function escalate() {
      return execFileAsync("sudo", ["id"]);
    }
  `;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /escalation binary "sudo"/);
});

test("escalation scanner flags escalation via a runFixedExecFile-style wrapper", () => {
  const source = `
    async function runFixedExecFile(command, args, options = {}) {
      return execFileAsync(command, args, options);
    }
    export async function escalate() {
      return runFixedExecFile("sudo", ["id"]);
    }
  `;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /escalation binary "sudo"/);
});

test("escalation scanner flags a full-path escalation binary argument", () => {
  const source = `
    import { execFile } from "node:child_process";
    export function escalate() {
      return execFile("/usr/bin/sudo", ["id"]);
    }
  `;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /escalation binary "sudo"/);
});

test("escalation scanner flags osascript invoked with administrator privileges", () => {
  const source = `
    import { execFile } from "node:child_process";
    export function escalate() {
      return execFile("osascript", ["-e", 'do shell script "id" with administrator privileges']);
    }
  `;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /administrator-privilege argument/);
});

test("escalation scanner flags references to macOS privileged-helper elevation APIs", () => {
  const source = `export function bless() { return globalThis.SMJobBless("com.example.helper"); }`;
  const violations = findEscalationViolations("fixture.js", source);
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /SMJobBless/);
});

test("escalation scanner ignores escalation terms mentioned only in comments", () => {
  const source = `
    // no setcap/sudo anywhere in this file; never calls SMJobBless, SMAppService, or
    // AuthorizationExecuteWithPrivileges
    import { execFile } from "node:child_process";
    export function ok() {
      return execFile("ls", ["-la"]);
    }
  `;
  assert.deepEqual(findEscalationViolations("fixture.js", source), []);
});

test("escalation scanner ignores benign exec-family calls and osascript without administrator", () => {
  const source = `
    import { execFile } from "node:child_process";
    export function notify() {
      return execFile("osascript", ["-e", 'display notification "hi"']);
    }
  `;
  assert.deepEqual(findEscalationViolations("fixture.js", source), []);
});

test("escalation scanner ignores a benign call whose name merely contains \"exec\"", () => {
  const source = `
    export function executeQuery(sql) {
      return db.exec(sql);
    }
    executeQuery("select * from users");
  `;
  assert.deepEqual(findEscalationViolations("fixture.js", source), []);
});

test("escalation scanner does not desync on a regex literal containing a quote (Fix C)", () => {
  // Mirrors the real shape at src/tools/logs.js:136 (a word-boundary regex mentioning "sudo")
  // followed downstream by a real comment -- before regex-literal awareness, the apostrophe in
  // /it's/ was misread as a string-open quote, and since no matching close quote followed, the
  // rest of the file (including the comment's "SMJobBless" mention) was copied through
  // un-blanked by stripComments and falsely flagged as a real code reference.
  const source = `
    export function check(s) {
      const hasApostrophe = /it's/.test(s);
      // mentions SMJobBless only in a comment, should not flag
      return hasApostrophe;
    }
  `;
  assert.deepEqual(findEscalationViolations("fixture.js", source), []);
});

test("escalation scanner does not flag logs.js's real auth-classification regex", () => {
  // logs.js:136's own regex mentions "sudo" (and other escalation-adjacent terms) as part of a
  // log-line auth classifier -- it's a regex literal, not a string-literal argument to an
  // exec-family call, so it must never be flagged.
  const source = `
    export function categorizeLogEntry(entry) {
      const haystack = "x";
      if (/\\b(sshd?|pam|sudo|login|auth(?:entication)?|invalid user|failed password)\\b/.test(haystack)) return "auth";
      return "general";
    }
  `;
  assert.deepEqual(findEscalationViolations("fixture.js", source), []);
});
