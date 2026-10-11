import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  CONTEXT_FACT_SCHEMAS,
  enforceContextSchema,
  PROVENANCE_TAGS,
  unableContextAttributes,
  validateContextFact,
} from "../src/context-schemas.js";
import { CONTEXT_KEY_BYTES, contextHmac, loadOrCreateContextKey, resolveContextKeyPath } from "../src/context-key.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-context-schema-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("C0.6: every context schema field carries a non-empty physical-object provenance tag from the closed set", () => {
  assert.ok(CONTEXT_FACT_SCHEMAS.size >= 11);
  for (const [factName, schema] of CONTEXT_FACT_SCHEMAS) {
    assert.ok(["host_lifecycle", "network_context", "session_context"].includes(schema.family), factName);
    for (const [field, spec] of Object.entries(schema.fields)) {
      assert.ok(spec.provenance.length > 0, `${factName}.${field}`);
      for (const tag of spec.provenance) assert.ok(PROVENANCE_TAGS.includes(tag), `${factName}.${field}: ${tag}`);
    }
    for (const common of ["collector_state", "obs_start_ms", "obs_end_ms", "rejected_field"]) assert.ok(schema.fields[common], `${factName} lacks ${common}`);
  }
});

test("C0.6: the unable shape of every schema validates, names the rejected field, and fabricates no value", () => {
  for (const factName of CONTEXT_FACT_SCHEMAS.keys()) {
    const attrs = unableContextAttributes(factName, { rejectedField: "unknown_field", obsStartMs: 1000, obsEndMs: 2000 });
    assert.deepEqual(validateContextFact(factName, attrs), { ok: true }, factName);
    assert.equal(attrs.collector_state, "unable");
    assert.equal(attrs.rejected_field, "unknown_field");
    assert.equal(attrs.obs_start_ms, "1000");
    for (const [field, value] of Object.entries(attrs)) {
      if (["collector_state", "rejected_field", "obs_start_ms", "obs_end_ms"].includes(field)) continue;
      const spec = CONTEXT_FACT_SCHEMAS.get(factName).fields[field];
      const singleValued = (spec.kind === "enum" && spec.values.size === 1) || (spec.kind === "int" && spec.min === spec.max);
      assert.ok(["unknown", "unable"].includes(value) || singleValued, `${factName}.${field} = ${value} in the unable shape`);
    }
  }
});

test("C0.6: validation rejects an unknown field, a missing field and an out-of-domain value, at the translator boundary", () => {
  const good = {
    ...unableContextAttributes("net.tailnet_state"),
    collector_state: "ok", state: "running", self_online: "true", exit_node_in_use: "false",
    health_issue_bucket: "0", current_tailnet_hmac: "0123456789abcdef", obs_start_ms: "1", obs_end_ms: "2", rejected_field: "none",
  };
  assert.deepEqual(validateContextFact("net.tailnet_state", good), { ok: true });
  assert.equal(validateContextFact("net.tailnet_state", { ...good, tailnet_name: "corp.example" }).field, "unknown_field");
  const { self_online: _drop, ...missing } = good;
  assert.equal(validateContextFact("net.tailnet_state", missing).field, "self_online");
  assert.equal(validateContextFact("net.tailnet_state", { ...good, state: "Running" }).field, "state");
  assert.equal(validateContextFact("net.tailnet_state", { ...good, current_tailnet_hmac: "corp.example.ts.net" }).field, "current_tailnet_hmac");
  assert.equal(validateContextFact("net.tailnet_state", { ...good, obs_start_ms: "-1" }).field, "obs_start_ms");
  assert.equal(validateContextFact("net.tailnet_state", { ...good, obs_start_ms: 1 }).field, "obs_start_ms", "non-strings are rejected");
  assert.equal(validateContextFact("host.boot", { ...unableContextAttributes("host.boot"), os_build: "x".repeat(65) }).field, "os_build");
  assert.equal(validateContextFact("no.such.fact", {}).ok, false);
});

test("C0.6: enforceContextSchema writes the unable shape on rejection, never the rejected value, and never echoes an unknown key", () => {
  const point = {
    ts: "2026-10-11T00:00:00.000Z",
    fact_name: "net.tailnet_state",
    entity_key: "net.tailnet_state",
    attributes: { ...unableContextAttributes("net.tailnet_state"), state: "running", collector_state: "ok", obs_start_ms: "5", obs_end_ms: "6", "corp-secret-key": "leak" },
  };
  const enforced = enforceContextSchema(point);
  assert.equal(enforced.attributes.collector_state, "unable");
  assert.equal(enforced.attributes.rejected_field, "unknown_field");
  assert.equal(enforced.attributes.state, "unable");
  assert.equal(enforced.attributes.obs_start_ms, "5");
  assert.equal(enforced.confidence, 0);
  assert.ok(!JSON.stringify(enforced).includes("corp-secret-key"));
  assert.ok(!JSON.stringify(enforced).includes("leak"));
  const valid = { ...point, attributes: { ...point.attributes } };
  delete valid.attributes["corp-secret-key"];
  assert.equal(enforceContextSchema(valid), valid, "a valid point passes through untouched");
});

test("C0.5: the per-install context key is created once, 0600 in a 0700 dir outside fact history, and reused", async () => {
  const paths = await tempPaths();
  const first = await loadOrCreateContextKey(paths);
  assert.equal(first.status, "ok");
  assert.equal(first.created, true);
  assert.equal(first.key.length, CONTEXT_KEY_BYTES);
  const file = resolveContextKeyPath(paths);
  assert.ok(!file.includes(`${path.sep}facts${path.sep}`), "the key lives outside the fact store");
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(path.dirname(file))).mode & 0o777, 0o700);
  const second = await loadOrCreateContextKey(paths);
  assert.equal(second.status, "ok");
  assert.equal(second.created, false);
  assert.ok(second.key.equals(first.key));
  assert.deepEqual((await fs.readdir(path.dirname(file))).sort(), ["context-hmac.key"], "no tmp file is left behind");
});

test("C0.5: a key with a wide mode, a wrong size, a foreign owner or a symlink is unable -- never used, never replaced silently", async () => {
  const paths = await tempPaths();
  const file = resolveContextKeyPath(paths);
  await loadOrCreateContextKey(paths);
  await fs.chmod(file, 0o644);
  assert.deepEqual(await loadOrCreateContextKey(paths), { status: "unable", reason: "mode_too_wide" });
  await fs.chmod(file, 0o600);
  assert.deepEqual(await loadOrCreateContextKey(paths, { expectedUid: 12345678 }), { status: "unable", reason: "foreign_owner" });
  await fs.writeFile(file, Buffer.alloc(7), { mode: 0o600 });
  assert.deepEqual(await loadOrCreateContextKey(paths), { status: "unable", reason: "wrong_size" });
  await fs.unlink(file);
  const target = path.join(path.dirname(file), "elsewhere");
  await fs.writeFile(target, Buffer.alloc(CONTEXT_KEY_BYTES), { mode: 0o600 });
  await fs.symlink(target, file);
  assert.deepEqual(await loadOrCreateContextKey(paths), { status: "unable", reason: "not_a_regular_file" });
});

test("C0.5: contextHmac is keyed and domain-separated, and degrades to unknown without a usable key (never an unkeyed hash)", () => {
  const keyA = Buffer.alloc(CONTEXT_KEY_BYTES, 1);
  const keyB = Buffer.alloc(CONTEXT_KEY_BYTES, 2);
  const a = contextHmac(keyA, "gateway_mac", "aa:bb:cc:dd:ee:ff");
  assert.match(a, /^[0-9a-f]{16}$/);
  assert.notEqual(a, contextHmac(keyB, "gateway_mac", "aa:bb:cc:dd:ee:ff"));
  assert.notEqual(a, contextHmac(keyA, "dhcp_domain", "aa:bb:cc:dd:ee:ff"));
  assert.equal(a, contextHmac(keyA, "gateway_mac", "aa:bb:cc:dd:ee:ff"));
  assert.equal(contextHmac(undefined, "gateway_mac", "x"), "unknown");
  assert.equal(contextHmac(Buffer.alloc(4), "gateway_mac", "x"), "unknown");
  assert.equal(contextHmac(keyA, "gateway_mac", ""), "unknown");
  assert.equal(contextHmac(keyA, "gateway_mac", undefined), "unknown");
});
