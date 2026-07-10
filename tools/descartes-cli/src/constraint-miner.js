// Deterministic constraint miner (Slice S6c, plan §4). Pure, no I/O, no LLM: turns S6b's
// fact-history (readFactPoints output) into status:"draft" constraint-store.js-shaped
// records for exactly two families — service-presence and port-binding-identity. Mined
// drafts are INERT: constraint-eval.js's evaluateConstraints() only ever processes
// status==="active", so a freshly-mined draft is never evaluated, never alerts, never
// reaches a user automatically (plan §4/§6). All file I/O (readFactPoints, load/write
// constraints.json) is isolated to runLearned(), the on-demand `descartes learned mine`
// CLI wrapper at the bottom of this file — mineConstraintCandidates() itself never touches
// the filesystem, mirroring evaluateConstraints()'s "pure, no I/O" contract.

import crypto from "node:crypto";
import { loadConstraints, SCHEMA_VERSION, writeConstraints } from "./constraint-store.js";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { parseDurationMs } from "./history-store.js";
import { readFactPoints } from "./fact-store.js";

// Reserved id namespace (plan §4, §0.1): every mined id starts with this prefix, making
// mined provenance structurally distinguishable from hand-authored SEED_CONSTRAINTS ids by
// prefix alone. Never used for anything but constraint-miner.js-authored ids.
export const MINED_ID_PREFIX = "constraint.mined.";

const DEFAULT_MIN_OBSERVATION_DAYS = 7;
const DEFAULT_MIN_SAMPLES = 3;
const DAY_MS = 24 * 60 * 60 * 1000;

// Closed enum: fact_name -> mined family. Only these two fact_names are ever mined; any
// other fact_name present in the input (e.g. a future family's facts) is ignored outright
// rather than guessed at. Family is therefore always drawn from this closed set, never
// derived from raw fact data — no sanitization is needed for `family` itself (plan §4's
// sanitization-gate note), only defensive validation that it is one of these two values.
const FAMILY_BY_FACT_NAME = {
  "service.presence": "service-presence",
  "network.listening_port.owner": "port-binding-identity",
};

// Which attributes key holds the "key attribute" whose stability is mined, per family.
const KEY_ATTRIBUTE_BY_FACT_NAME = {
  "service.presence": "running",
  "network.listening_port.owner": "owner",
};

export const MINED_FAMILIES = Object.freeze([...new Set(Object.values(FAMILY_BY_FACT_NAME))]);

/**
 * A fact point counts neither as confirming nor contradicting evidence when the
 * translator degraded rather than fabricated (plan §3/§4's owner_known:"false"/
 * confidence:0 degrade pattern) — e.g. an unresolvable port owner on Linux.
 */
function isDegradedObservation(point) {
  return point?.attributes?.owner_known === "false" || point?.confidence === 0;
}

function groupKey(point) {
  return `${point.fact_name}\0${point.entity_key}`;
}

/**
 * Groups raw fact points by (fact_name, entity_key), keeping only points from the two known
 * mineable families. Degraded observations are tracked separately (`all`) from confirming
 * ones (`confirming`) so degraded samples never participate in the contradiction check.
 */
function groupFactPoints(factHistory) {
  const points = Array.isArray(factHistory) ? factHistory : factHistory?.points ?? [];
  const groups = new Map();

  for (const point of points) {
    if (!point || typeof point !== "object") continue;
    const family = FAMILY_BY_FACT_NAME[point.fact_name];
    if (!family) continue; // not a mineable family — ignored outright, not an error
    const entityKey = String(point.entity_key ?? "").trim();
    if (!entityKey) continue;

    const key = groupKey(point);
    let group = groups.get(key);
    if (!group) {
      group = { fact_name: point.fact_name, entity_key: entityKey, family, all: [], confirming: [] };
      groups.set(key, group);
    }
    group.all.push(point);
    if (!isDegradedObservation(point)) group.confirming.push(point);
  }

  return [...groups.values()];
}

function differentFixtureValue(observedValue) {
  if (observedValue === "true") return "false";
  if (observedValue === "false") return "true";
  return `not-${observedValue}`;
}

/**
 * Builds one hash-derived, fixed-length-hex mined id from (family, entity_key). Hashing
 * (rather than concatenating the raw entity_key) is the load-bearing sanitization move
 * here (plan §4/§6): a crypto digest is safe-by-construction regardless of what the source
 * entity_key looked like, so `id` always satisfies diagnostics-sanitizer.js's
 * isFixedLengthHexHash allowlist check without needing entity_key to have been sanitized
 * first. Reuses alert-store.js's alertId()-style truncated-sha256-hex pattern.
 */
function minedId(family, entityKey) {
  const digest = crypto.createHash("sha256").update(`${family}\0${entityKey}`).digest("hex").slice(0, 16);
  return `${MINED_ID_PREFIX}${family}.${digest}`;
}

/**
 * Builds one draft constraint record from a stable, non-contradicted group, or returns
 * undefined if the group's entity_key cannot be sanitized into anything safe at all
 * (degrade-don't-fabricate — mirrors fact-translators.js's "drop unresolvable identity"
 * convention rather than emitting a constraint with an empty/unsafe target).
 */
function buildMinedConstraint(group, { minObservationDays, nowIso }) {
  const { family, fact_name, entity_key, confirming, all } = group;

  // Pre-mining sanitization gate, defense-in-depth (plan §6 point 2): re-apply the same
  // sanitizer the S6b translator already ran at emission time. Never trust that facts.jsonl
  // stayed clean (hand-edited file, future translator regression, ...).
  const sanitizedEntityKey = sanitizeIdentityString(entity_key);
  if (!sanitizedEntityKey) return undefined; // entirely-unsafe identity — drop, never fabricate

  const target = sanitizeIdentityString(`${fact_name}.${sanitizedEntityKey}`);
  if (!target) return undefined; // defensive; should not happen given fact_name/sanitizedEntityKey are already safe

  const attributeKey = KEY_ATTRIBUTE_BY_FACT_NAME[fact_name];
  const observedValue = confirming[0]?.attributes?.[attributeKey];
  if (observedValue === undefined) return undefined;

  const timestampsMs = confirming.map((point) => new Date(point.ts).getTime()).filter(Number.isFinite);
  if (timestampsMs.length === 0) return undefined;
  const firstObservedMs = Math.min(...timestampsMs);
  const lastVerifiedMs = Math.max(...timestampsMs);
  const sourceCollectors = [...new Set(confirming.map((point) => point.source_envelope_id).filter(Boolean))];
  const confidence = Math.min(1, Math.max(0, confirming.length / all.length));

  return {
    id: minedId(family, entity_key),
    kind: "constraint",
    family,
    target,
    expected: { comparator: "eq", value: String(observedValue) },
    status: "draft",
    confidence,
    provenance: {
      window: `${minObservationDays}d`,
      samples: confirming.length,
      source_collectors: sourceCollectors,
      mined_at: nowIso,
    },
    fixtures: [
      { input: { [fact_name]: observedValue }, expect_match: true },
      { input: { [fact_name]: differentFixtureValue(String(observedValue)) }, expect_match: false },
    ],
    promotion_history: [],
    first_observed: new Date(firstObservedMs).toISOString(),
    last_verified: new Date(lastVerifiedMs).toISOString(),
    sensitivity: "operational",
    schema_version: SCHEMA_VERSION,
  };
}

/**
 * Mines status:"draft" constraint candidates from a categorical fact-history window.
 *
 * `snapshots` is a RESERVED, UNUSED parameter for this slice (plan §4): it exists so the
 * exported three-argument signature matches the roadmap's documented contract for future
 * mining families (e.g. process-ancestry) that need point-in-time snapshots rather than
 * pure fact-history deltas. Neither service-presence nor port-binding-identity needs
 * snapshot data — both are evaluated purely over `factHistory` — so it is accepted but
 * genuinely ignored here, deliberately, not silently dropped scope.
 *
 * Mining rule per group (fact_name, entity_key): discard degraded observations
 * (owner_known:"false"/confidence:0) from both the sample count and the contradiction
 * check; require >= minSamples confirming samples spanning >= minObservationDays days with
 * exactly one distinct observed value (zero contradictions) to emit exactly one draft.
 *
 * Pure, deterministic, no I/O, no LLM: same factHistory/options in -> identical candidates
 * out. `options.now` (not Date.now()) is the only source of "current time" — callers that
 * omit it get Date.now(), but every id/hash/grouping decision itself is derived solely from
 * factHistory content, never from wall-clock time, so re-mining unchanged facts at a later
 * `now` still yields the same ids.
 */
export function mineConstraintCandidates(factHistory, snapshots, options = {}) {
  void snapshots; // reserved-but-unused for service-presence/port-binding-identity (see doc comment above)

  const minObservationDays = Number.isFinite(options.minObservationDays) ? options.minObservationDays : DEFAULT_MIN_OBSERVATION_DAYS;
  const minSamples = Number.isFinite(options.minSamples) ? options.minSamples : DEFAULT_MIN_SAMPLES;
  const now = options.now ?? Date.now();
  const nowIso = new Date(now).toISOString();
  const minSpanMs = minObservationDays * DAY_MS;

  const candidates = [];
  for (const group of groupFactPoints(factHistory)) {
    if (group.confirming.length < minSamples) continue;

    const timestampsMs = group.confirming.map((point) => new Date(point.ts).getTime()).filter(Number.isFinite);
    if (timestampsMs.length === 0) continue;
    const spanMs = Math.max(...timestampsMs) - Math.min(...timestampsMs);
    if (spanMs < minSpanMs) continue;

    const attributeKey = KEY_ATTRIBUTE_BY_FACT_NAME[group.fact_name];
    const distinctValues = new Set(group.confirming.map((point) => point.attributes?.[attributeKey]));
    if (distinctValues.size !== 1) continue; // contradiction (fact flipped) — never mine, by design

    const constraint = buildMinedConstraint(group, { minObservationDays, nowIso });
    if (constraint) candidates.push(constraint);
  }

  return candidates;
}

/**
 * Merges freshly-mined candidates into an existing constraints.json array, idempotently:
 *   - a candidate whose id is new is added as a new draft.
 *   - a candidate whose id already exists AND that existing record is still status:"draft"
 *     AND carries the reserved constraint.mined. prefix is updated in place (re-mining the
 *     same stable fact refreshes last_verified/provenance/fixtures/confidence rather than
 *     duplicating).
 *   - anything else sharing that id (an active/shadow/review-ready/retired constraint, or a
 *     hand-authored non-mined record) is left completely untouched — mining never clobbers
 *     a constraint it does not own the lifecycle of.
 * Pure, no I/O — the caller (runLearned) is responsible for loadConstraints/writeConstraints.
 */
export function mergeMinedConstraints(existingConstraints, minedCandidates) {
  const byId = new Map((existingConstraints ?? []).map((constraint) => [constraint.id, constraint]));
  let newCount = 0;
  let updatedCount = 0;
  let unchangedCount = 0;

  for (const candidate of minedCandidates ?? []) {
    const existing = byId.get(candidate.id);
    if (!existing) {
      byId.set(candidate.id, candidate);
      newCount += 1;
      continue;
    }

    if (existing.status !== "draft" || !String(existing.id).startsWith(MINED_ID_PREFIX)) {
      // Not ours to touch: a hand-authored constraint, or a mined draft a human has since
      // promoted past draft. Preserve it exactly as-is.
      unchangedCount += 1;
      continue;
    }

    const merged = {
      ...existing,
      expected: candidate.expected,
      confidence: candidate.confidence,
      provenance: candidate.provenance,
      fixtures: candidate.fixtures,
      last_verified: candidate.last_verified,
    };
    const changed = JSON.stringify(merged) !== JSON.stringify(existing);
    byId.set(candidate.id, merged);
    if (changed) updatedCount += 1;
    else unchangedCount += 1;
  }

  return {
    constraints: [...byId.values()],
    new_count: newCount,
    updated_count: updatedCount,
    unchanged_count: unchangedCount,
  };
}

function learnedUsage() {
  return `Usage:
  descartes learned mine [--json] [--window <duration>]

Mines status:"draft" constraints from the accumulated categorical fact-history window
(stateDir/learned/facts/facts.jsonl). Mined drafts are inert: they are never evaluated,
never alert, and only ever reachable through future 'descartes learned review/approve'
commands (a later slice). Read-only of facts; writes only new/updated draft constraints.`;
}

function renderMineSummary(candidateCount, merge) {
  return `Mined ${candidateCount} candidate(s) from the current fact-history window: ` +
    `${merge.new_count} new draft(s), ${merge.updated_count} updated, ${merge.unchanged_count} unchanged.`;
}

/**
 * `descartes learned mine` — the first `learned` CLI subcommand (plan §4). Explicit,
 * on-demand, human-invoked: NOT gated by configDir/learned.json's enabled flag (convention
 * #4 — that flag gates automatic/background work only). Reads facts, mines candidates,
 * merges them into constraints.json, prints a summary.
 */
export async function runLearned(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const [subcommand, ...rest] = args ?? [];

  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    output(learnedUsage());
    return;
  }
  if (subcommand !== "mine") {
    throw new Error(`Unsupported learned command: ${subcommand}\n\n${learnedUsage()}`);
  }

  const options = { json: false, windowMs: undefined };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--window") {
      const value = rest[index + 1];
      if (!value) throw new Error(`--window requires a value\n\n${learnedUsage()}`);
      options.windowMs = parseDurationMs(value, options.windowMs);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      output(learnedUsage());
      return;
    } else {
      throw new Error(`Unexpected learned mine argument: ${arg}\n\n${learnedUsage()}`);
    }
  }

  const { points } = await readFactPoints(descartesPaths, { windowMs: options.windowMs, now: runtime.now });
  const candidates = mineConstraintCandidates(points, [], { now: runtime.now, ...runtime.mineOptions });
  const { constraints: existing } = await loadConstraints(descartesPaths);
  const merge = mergeMinedConstraints(existing, candidates);
  await writeConstraints(descartesPaths, merge.constraints);

  const summary = {
    mined_candidates: candidates.length,
    new_drafts: merge.new_count,
    updated_drafts: merge.updated_count,
    unchanged_drafts: merge.unchanged_count,
  };
  if (options.json) output(JSON.stringify({ learned_mine: summary }, null, 2));
  else output(renderMineSummary(candidates.length, merge));
}
