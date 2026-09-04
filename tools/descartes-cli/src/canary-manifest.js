// Hand-authored, read-only canary manifest loader. Operators MUST place decoys where every real
// system parser will ignore them (for example ~/.aws/credentials.bak, never the live credentials
// path). This loader intentionally has no writer and v0 has no listening/service canary kind.
import fs from "node:fs/promises";
import path from "node:path";
import { sanitizeEntityKey } from "./fact-translators.js";
import { MAX_CANARIES } from "./tools/canary.js";

export const CANARY_KINDS = [
  "credential-file",
  "scheduled-job",
  "suid-binary",
  "sudoers-entry",
  "writable-directory",
];
export const CANARY_WATCHES = ["atime", "mtime", "executed"];

export function resolveCanaryManifestPaths(descartesPaths) {
  return { manifestFile: path.join(descartesPaths.configDir, "canaries.json") };
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

// Tamper fix (canary v0 finalization): the top-level SHAPE check below (object, schema_version:1,
// `canaries` an array) is a distinct failure class from per-entry filtering just past it. A
// document that fails THIS check (not an object at all, wrong/missing schema_version, or
// `canaries` not an array — e.g. truncated-but-still-valid-JSON, a stray top-level array, an
// attacker's crude tamper attempt that isn't even shaped like a manifest) is schema-invalid: it is
// NOT reliably distinguishable from an intentional edit, so it must NOT be treated the same as a
// genuinely-authored, valid, empty `{schema_version:1, canaries:[]}` decommission. `schema_valid`
// lets loadCanaryManifest (below) tell the two apart and mark ONLY the invalid-shape case
// read_ok:false. Per-entry drops (a single malformed canary inside an otherwise-valid document)
// stay schema_valid:true and read_ok:true, unchanged — that is ordinary data-quality filtering,
// not evidence of tampering with the manifest itself.
export function normalizeCanaryManifest(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || raw.schema_version !== 1 || !Array.isArray(raw.canaries)) {
    return { canaries: [], schema_valid: false };
  }
  // Round-2 fix (positive-evidence re-gate, finding 1): a watch:["executed", ...] entry with NO
  // sentinel_path is a config error for the "executed" watch specifically -- tools/canary.js's
  // collectOneCanary can only emit executed:"unknown" for it, EVERY tick, forever, which
  // permanently forces the census marker to "partial" (fact-translators.js's degrade-not-fabricate
  // rule) and would collaterally kill canary.tripped/canary_vanished detection for every canary in
  // the manifest. Round 1 fixed this by dropping the WHOLE entry, which went over-broad: it also
  // discarded any OTHER legitimate watch (mtime/atime) the same entry carried. Strip ONLY the
  // "executed" watch instead -- the entry (and its remaining legit watches) survives; it is
  // dropped only if nothing legitimate is left to watch afterward, same as any other
  // watch:[]-after-filtering entry.
  // Round-4 fix (positive-evidence isolation completeness, daybreak-blue finding 3): a per-entry
  // validation failure below that STILL carries a USABLE declared id (nonEmptyString(entry.id) AND
  // sanitizeEntityKey(entry.id) truthy) is a DIFFERENT class of drop from an entry with no usable
  // id at all. An entry with no usable id can never resolve to a real canary_id downstream, so
  // isolating it would be meaningless -- it stays a silent drop, exactly as before. But an entry
  // whose id IS usable (e.g. an established canary's own id, with its `path` accidentally dropped
  // by a config edit) was, until this fix, dropped by the SAME silent `return undefined` -- never
  // added to `invalid_entries`, so canary-baseline.js's isolatedEntityKeys (see its own header
  // comment) never admits that id past the currentCanaryIds gate, and a genuine, already-computed
  // two-snapshot rawTrip for that id is filtered out as if the canary had been cleanly
  // decommissioned. `dropOrIsolate` below isolates ONLY the usable-id case (reason:
  // "schema_invalid"), collected into `schemaInvalidEntries` and surfaced via `invalid_entries`
  // exactly like the entity_key_collision/manifest_oversized isolation already does. It still
  // returns `undefined` from the map either way, so an isolated entry never reaches `canaries`/
  // `withinCap`/the cap+collision passes below -- it must not be counted as monitored.
  const schemaInvalidEntries = [];
  function hasUsableDeclaredId(entry) {
    return nonEmptyString(entry.id) && Boolean(sanitizeEntityKey(entry.id));
  }
  const validated = raw.canaries
    .map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) return undefined;
      const dropOrIsolate = () => {
        if (hasUsableDeclaredId(entry)) schemaInvalidEntries.push(entry);
        return undefined;
      };
      if (!nonEmptyString(entry.id) || !nonEmptyString(entry.path) || !CANARY_KINDS.includes(entry.kind)) return dropOrIsolate();
      if (!Array.isArray(entry.watch) || entry.watch.length === 0 || !entry.watch.every((watch) => CANARY_WATCHES.includes(watch))) return dropOrIsolate();
      if (entry.sentinel_path !== undefined && !nonEmptyString(entry.sentinel_path)) return dropOrIsolate();
      let watch = entry.watch;
      if (watch.includes("executed") && !nonEmptyString(entry.sentinel_path)) {
        watch = watch.filter((item) => item !== "executed");
        if (watch.length === 0) return dropOrIsolate();
      }
      return watch === entry.watch ? entry : { ...entry, watch };
    })
    .filter((entry) => entry !== undefined);

  // Round-2 fix (finding 3): cap the manifest itself, in manifest order, at the SAME MAX_CANARIES
  // bound tools/canary.js's collector already enforces -- so the collector never actually receives
  // a truncated set (truncated stays false, the census marker stays "complete") and
  // canary.tripped/canary_vanished keep working for every canary that IS monitored. Beyond-cap
  // entries are isolated (flagged "manifest_oversized" below) rather than silently dropped, and are
  // excluded from `canaries` so daemon.js's currentCanaryIds/manifest-gate (canary-baseline.js)
  // never treats them as monitored -- a canary that slides past the cap (e.g. an operator inserts
  // an entry above it) is read as decommissioned, not fabricated as vanished. The collector's own
  // MAX_CANARIES slice stays in place as a never-hit backstop.
  const withinCap = validated.slice(0, MAX_CANARIES);
  const oversized = validated.slice(MAX_CANARIES);

  // Round-2 fix (findings 2 + 5): isolate rather than fail the WHOLE manifest.
  //   - finding 2 (entity_key collision): canary-baseline.js's groupCanaryFactsByTick keys each
  //     tick's presence facts by the SANITIZED (not hashed) manifest id -- fact-translators.js's
  //     sanitizeEntityKey substitutes disallowed characters and truncates, so two distinct manifest
  //     ids (e.g. "prod/key" and "prod_key") can collapse onto the SAME entity_key. Undetected, the
  //     later-written presence fact would silently overwrite the earlier one in that tick's Map.
  //     Round 1 routed the WHOLE manifest to `canaries:[]`/read_ok:false on any collision, which
  //     went over-broad: it silenced every OTHER, unrelated canary's collection too. Isolate
  //     instead: only the colliding entries are pulled out of `canaries`.
  //   - finding 5 (empty entity_key): an id that sanitizes to nothing safe (e.g. "////") bypassed
  //     collision handling entirely (the old loop's `if (!entityKey) continue;`) and silently lost
  //     its evidence downstream -- fact-translators.js's factPointsFromCanaryEvidence can't emit a
  //     presence fact with no entity_key, so the canary is collected (lstat succeeds) but nothing
  //     is ever recorded, with no operator-visible signal at all. Routed the same way as a
  //     collision: pulled out of `canaries`, flagged for a canary.tampered alert.
  // Computed AFTER the cap above so a beyond-cap entry -- never going to be monitored anyway --
  // cannot also sacrifice an in-cap entry's evidence purely by colliding with it.
  const groupsByEntityKey = new Map();
  const emptyKeyEntries = [];
  for (const entry of withinCap) {
    const entityKey = sanitizeEntityKey(entry.id);
    if (!entityKey) {
      emptyKeyEntries.push(entry);
      continue;
    }
    if (!groupsByEntityKey.has(entityKey)) groupsByEntityKey.set(entityKey, []);
    groupsByEntityKey.get(entityKey).push(entry);
  }
  const collidedEntries = [];
  const canaries = [];
  for (const group of groupsByEntityKey.values()) {
    if (group.length > 1) collidedEntries.push(...group);
    else canaries.push(...group);
  }

  // Surfaced to canary-baseline.js so each isolated entry raises its own canary.tampered rather
  // than silently vanishing -- see the tamperEntries wiring there. Omitted entirely when empty so
  // every existing read_ok:true fixture/test (`{ canaries, read_ok: true }`) keeps its exact shape.
  const invalidEntries = [
    ...collidedEntries.map((entry) => ({ id: entry.id, kind: entry.kind, reason: "entity_key_collision" })),
    ...emptyKeyEntries.map((entry) => ({ id: entry.id, kind: entry.kind, reason: "empty_entity_key" })),
    ...oversized.map((entry) => ({ id: entry.id, kind: entry.kind, reason: "manifest_oversized" })),
    // Round-4 fix: unlike the three isolation reasons above (whose source entries already passed
    // full per-entry validation, so `kind` is always a valid CANARY_KINDS string), a
    // schema-invalid entry may carry a missing/non-string `kind` -- that can be exactly WHY it was
    // isolated. Only include `kind` when it is actually a string, so this never fabricates a kind
    // value that was never declared.
    ...schemaInvalidEntries.map((entry) => ({
      id: entry.id,
      ...(typeof entry.kind === "string" ? { kind: entry.kind } : {}),
      reason: "schema_invalid",
    })),
  ];

  const result = { canaries, schema_valid: true };
  if (invalidEntries.length > 0) result.invalid_entries = invalidEntries;
  return result;
}

// P1 fix (canary collector review round 2): callers (canary-baseline.js's current-manifest gate)
// MUST be able to tell a legitimately empty/absent manifest apart from one this loader failed to
// read or parse. Without that distinction, degrading BOTH cases to the identical `{ canaries: [] }`
// shape lets an attacker who corrupts, deletes-and-recreates-unreadably, or chmods canaries.json
// silence every established canary's alerts (the gate treats the degraded empty manifest as
// authoritative and suppresses all candidates) — a security primitive silenced by attacking its
// own config file. `read_ok` makes the distinction explicit and load-bearing for every caller:
//   - read_ok:true  -- the manifest was read (or is genuinely absent, ENOENT) and parsed
//                      successfully; `canaries` is authoritative, including when empty (a real
//                      decommission/opt-out).
//   - read_ok:false -- the manifest could not be READ (non-ENOENT fs error) or could not be
//                      PARSED (corrupt JSON / failed schema shape). `canaries` is always `[]` here
//                      too (nothing safe to trust was recovered) but it must NOT be treated as an
//                      authoritative empty set by any decommission-style gate.
export async function loadCanaryManifest(descartesPaths) {
  const { manifestFile } = resolveCanaryManifestPaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(manifestFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { canaries: [], read_ok: true };
    return { canaries: [], unreadable: true, read_ok: false };
  }
  let parsed;
  try {
    parsed = JSON.parse(contents);
  } catch {
    return { canaries: [], corrupt: true, read_ok: false };
  }
  // Tamper fix (canary v0 finalization): valid JSON that fails the manifest's own top-level
  // shape check (see normalizeCanaryManifest's `schema_valid` above) is SCHEMA-INVALID -- treated
  // identically to a parse/fs failure (read_ok:false), not as an authoritative empty manifest.
  // `schema_valid` itself never leaks into the returned shape, keeping it identical to every
  // existing caller/fixture's expectations for the read_ok:true path.
  const { canaries, schema_valid: schemaValid, invalid_entries: invalidEntries } = normalizeCanaryManifest(parsed);
  if (!schemaValid) return { canaries: [], schema_invalid: true, read_ok: false };
  // Round-2 fix (findings 2/3/5): a collision, an empty-sanitizing id, or a beyond-cap entry no
  // longer fails the WHOLE manifest closed -- see normalizeCanaryManifest's own header comment
  // above invalidEntries. read_ok stays true (every OTHER, non-isolated canary keeps collecting
  // and gating normally); `invalid_entries` is surfaced only when non-empty so the read_ok:true
  // shape stays byte-identical for every manifest with nothing isolated.
  if (invalidEntries && invalidEntries.length > 0) return { canaries, invalid_entries: invalidEntries, read_ok: true };
  return { canaries, read_ok: true };
}
