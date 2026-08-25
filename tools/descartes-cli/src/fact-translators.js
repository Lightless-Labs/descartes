// Per-collector translators: pure functions from a structural collector's evidence envelope
// (as produced by S6a's collectStructuralEvidence) into fact-store.js's fact-point schema.
// Kept as a sibling file to fact-store.js so the storage module stays a pure storage
// concern, mirroring how constraint-eval.js is separate from constraint-store.js (plan §3).
//
// Hard invariant across every translator in this file: degrade, never fabricate. An
// unresolvable identity/owner is either omitted entirely or marked owner_known:"false" —
// it is never guessed or defaulted to a placeholder that could be mistaken for a real
// observation.
import crypto from "node:crypto";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { computePeerIdentitySignature } from "./peer-signature-store.js";

export function sanitizeEntityKey(value) {
  return sanitizeIdentityString(value);
}

// The service census marker makes "the services collector ran this tick, and here is whether its
// enumeration was complete" representable — the prerequisite for ever detecting a service that
// DISAPPEARS (Codex finding #9: today a vanished service simply stops producing facts, which is
// indistinguishable from "never observed" / "collector didn't run"). It does NOT itself alert on
// disappearance; it only makes absence observable for a future absence-diff slice.
//
// It uses its OWN fact_name ("service.census"), NOT "service.presence": service entity_keys are the
// sanitized (NOT hashed) service name/label, so a launchd job could be labelled exactly the reserved
// marker key. A distinct fact_name means the marker can never share a miner group or a
// buildShadowFactLookup key-attribute with a real service.presence fact even on an entity_key
// collision (both `SHADOW_KEY_ATTRIBUTE_BY_FACT_NAME` and the miner's `FAMILY_BY_FACT_NAME` lack a
// "service.census" entry → it is skipped before any grouping/resolution). confidence:0 is kept as
// belt-and-suspenders. (Sessions can safely reuse "session.presence" for their marker because their
// real entity_keys are hashes and cannot collide with the literal marker key; services can't.)
export const SERVICE_CENSUS_FACT_NAME = "service.census";
export const SERVICE_CENSUS_MARKER_ENTITY_KEY = "service.census-marker.v1";

export const PROCESS_LINEAGE_EDGE_FACT_NAME = "process.lineage_edge";
export const PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME = "process.lineage_edge.census";
export const PROCESS_LINEAGE_EDGE_CENSUS_MARKER_ENTITY_KEY = "process.lineage_edge.census-marker.v1";

// HASH-AT-SOURCE (HIGH fix, deception/anomaly-detector review): a process `comm` (parent or
// child) is operator/attacker-influenced free text (an exec'd binary can be named almost
// anything) -- exactly the same identity-confidentiality class as a tmux/screen session name
// (SESSION_ENTITY_HASH_DOMAIN above) or a peer identifier (peer-signature-store.js). Sanitizing
// (charset-substitution + truncation) is NOT a confidentiality control -- it leaves a
// recognizable, human-readable comm string sitting in fact-history forever, and its lossiness
// (distinct raw names can sanitize/truncate to the same string) makes entity-key collisions a
// SANITIZER accident rather than a cryptographic one. The PERSISTED entity_key is therefore a
// domain-prefixed SHA-256 of the NUL-joined (parent_comm, child_comm) pair, truncated to the same
// 16 hex chars as every other hash-at-source scheme in this file -- it carries no cleartext comm
// and two structurally different (parent, child) splits (e.g. ("a","bc") vs ("ab","c")) cannot
// collide because the NUL separator is never itself a valid comm character. The alert BODY
// (process-lineage-baseline.js's hashLineageEdgeEntityKey) hashes this value AGAIN under its own
// rule-scoped domain -- cleartext comm is deferred/never surfaced there either, per the plan.
const LINEAGE_ENTITY_HASH_DOMAIN = "descartes.fact.process_lineage_edge.v1";

// A literal NUL separator (never a valid `comm` character) so two structurally different
// (parent, child) splits can never collide when concatenated -- e.g. ("a","bc") and ("ab","c")
// hash to different preimages ("a\0bc" vs "ab\0c"). Kept as its own named constant (built from
// the `\u0000` escape, not a raw byte pasted into this source file) purely for readability at
// the call site below.
const LINEAGE_IDENTITY_SEPARATOR = "\u0000";

export function hashLineageEdgeIdentity(parentComm, childComm) {
  return crypto.createHash("sha256")
    .update(`${LINEAGE_ENTITY_HASH_DOMAIN}:${parentComm}${LINEAGE_IDENTITY_SEPARATOR}${childComm}`)
    .digest("hex")
    .slice(0, 16);
}

// Degrade-not-fabricate: an unresolvable (non-string/empty) parent or child comm returns
// `undefined` -- signaling to callers that this edge's identity cannot be established and the
// record must be dropped, never hashed-and-persisted as a placeholder identity.
export function buildLineageEntityKey(parentComm, childComm) {
  const parent = typeof parentComm === "string" ? parentComm.trim() : "";
  const child = typeof childComm === "string" ? childComm.trim() : "";
  if (!parent || !child) return undefined;
  return `process.lineage_edge.${hashLineageEdgeIdentity(parent, child)}`;
}

// Canary presence uses its own fact_name because operator-chosen ids are cleartext-sanitized and
// could collide with the reserved census marker entity key. The marker is separate for the same
// collision-avoidance reason as service.census.
export const CANARY_PRESENCE_FACT_NAME = "canary.presence";
export const CANARY_CENSUS_FACT_NAME = "canary.census";
export const CANARY_CENSUS_MARKER_ENTITY_KEY = "canary.census-marker.v1";

/**
 * services[] is NOT uniform across managers (grounded against tools/services.js):
 *   - systemd (parseSystemctlListUnits): {name, load, active, sub, description, failed,
 *     running:<boolean>, restarting}
 *   - launchd (parseLaunchctlList): {label, pid, last_exit_status, state:"running"|
 *     "not_running", nonzero_exit} — no `name`/`running` keys at all.
 * Must branch explicitly on result.manager; a naive service.running read against launchd's
 * shape would silently read undefined.
 */
export function factPointsFromServiceEvidence(evidence, { ts } = {}) {
  const envelope = evidence.find((e) => e.id === "services" && e.status !== "unable");
  if (!envelope) return [];
  const services = envelope.result?.services ?? [];
  const manager = envelope.result?.manager;

  const points = services
    .map((service) => {
      const identity = manager === "launchd" ? service.label : service.name;
      const running = manager === "launchd" ? service.state === "running" : Boolean(service.running);
      const entityKey = sanitizeEntityKey(identity);
      if (!entityKey) return undefined; // unresolvable identity — dropped, never invented

      return {
        ts,
        fact_name: "service.presence",
        entity_key: entityKey,
        attributes: { running: String(running), manager: String(manager) },
        source_envelope_id: envelope.id,
        source_tool: envelope.trace?.tool,
        sensitivity: "operational",
      };
    })
    .filter(Boolean);

  // Slice C (Codex-hardening): the census marker is appended whenever the collector GENUINELY
  // enumerated — status "ok" or "warning" (units unhealthy but the service list is complete) —
  // including a zero-service tick, so absence becomes representable. It is NOT emitted on an
  // "unknown" (unsupported-platform) envelope, which never ran a census: emitting a "complete" marker
  // there would falsely claim an enumeration and collapse the "collector didn't run" vs "ran, saw
  // nothing" distinction the marker exists to preserve. (A status:"unable" envelope was already
  // dropped by the find() filter above.) The marker is inert by construction — its distinct
  // "service.census" fact_name is unknown to both the lookup and the miner, and confidence:0 backs
  // that up — so it can never be read as a presence claim or mined.
  if (envelope.status === "ok" || envelope.status === "warning") {
    points.push(buildServiceCensusMarkerFactPoint(envelope.result, envelope, ts));
  }
  return points;
}

// ---------------------------------------------------------------------------------------------
// Persistence baseline, Slice A (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md) —
// scheduled-jobs fact-store wiring. FACTS ONLY: this section builds no alert candidate and is
// never wired into daemon.js's extraCandidates (that is Slice B's job, persistence-baseline.js).
// Pure L0 fact source, mirroring factPointsFromServiceEvidence's/factPointsFromSessionEvidence's
// shape: a presence fact per returned job (deduped by composite entity key) plus one census
// marker per genuinely-enumerated tick (including a genuine zero-job tick).
// ---------------------------------------------------------------------------------------------

export const SCHEDULED_JOB_PRESENCE_FACT_NAME = "scheduled_job.presence";
export const SCHEDULED_JOB_CENSUS_FACT_NAME = "scheduled_job.census";
export const SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY = "scheduled_job.census-marker.v1";

// [REVIEW 2026-08-21, must-fix] Per-entry identity, not job.label ?? job.unit ?? job.path. A
// parsed cron job (tools/scheduled-jobs.js's parseCronScheduleLine) has NEITHER label NOR unit —
// only {kind:"cron", source, path, line_number, schedule, user, command}. `path` is shared by
// EVERY line in the same crontab file (every user-crontab entry shares "crontab -l", every
// /etc/crontab entry shares "/etc/crontab", every entry in one /etc/cron.d/<file> shares that
// file's path). Using path alone as the name leg would collapse every entry in one crontab to ONE
// entity key, making a new malicious line appended to an already-established crontab silently
// undetectable by Slice B — the plan's own canonical threat. Fixed here: the cron name leg is a
// domain-separated digest of the entry's STABLE content (path, schedule, user, bounded/redacted
// command) — never the raw command text embedded verbatim (hash-at-source: the command line is a
// sensitive diagnostic artifact per tools/scheduled-jobs.js's own module note). `line_number` is
// deliberately NOT part of the identity: pure reordering (same entries, different line order)
// must not read as churn. Editing an existing entry's schedule/user/command IS a real identity
// change and correctly reads as disappear-then-appear (a rewritten cron command is itself a
// persistence-relevant event — desired, not a false positive).
const SCHEDULED_JOB_CRON_IDENTITY_HASH_DOMAIN = "descartes.schedjob.cron.v1";
const SCHEDULED_JOB_IDENTITY_SEPARATOR = " ";

function cronJobIdentityDigest(job) {
  const preimage = [
    SCHEDULED_JOB_CRON_IDENTITY_HASH_DOMAIN,
    String(job?.path ?? ""),
    String(job?.schedule ?? ""),
    String(job?.user ?? ""),
    String(job?.command ?? ""),
  ].join(SCHEDULED_JOB_IDENTITY_SEPARATOR);
  return crypto.createHash("sha256").update(preimage).digest("hex").slice(0, 16);
}

export const SCHEDULED_JOB_KIND_VALUES = new Set([
  "cron",
  "systemd_timer",
  "launchd_scheduled_job",
  "periodic_directory_entry",
]);

export const SCHEDULED_JOB_SOURCE_VALUES = new Set([
  "cron",
  "user_crontab",
  "system_crontab",
  "cron_d",
  "periodic_directory",
  "systemd_timers",
  "systemd_user_timers",
  "launchd_plist",
]);

const SCHEDULED_JOB_KIND_SOURCE_PAIRS = new Set([
  "cron\u0000cron",
  "cron\u0000user_crontab",
  "cron\u0000system_crontab",
  "cron\u0000cron_d",
  "systemd_timer\u0000systemd_timers",
  "systemd_timer\u0000systemd_user_timers",
  "launchd_scheduled_job\u0000launchd_plist",
  "periodic_directory_entry\u0000periodic_directory",
]);

const SCHEDULED_JOB_IDENTITY_HASH_DOMAIN = "descartes.schedjob.identity.v1";

function isValidScheduledJobKindSource(kind, source) {
  return typeof kind === "string" && typeof source === "string"
    && SCHEDULED_JOB_KIND_VALUES.has(kind)
    && SCHEDULED_JOB_SOURCE_VALUES.has(source)
    && SCHEDULED_JOB_KIND_SOURCE_PAIRS.has(`${kind}\u0000${source}`);
}

function hashScheduledJobIdentityLeg(kind, source, identity) {
  return crypto.createHash("sha256")
    .update(`${SCHEDULED_JOB_IDENTITY_HASH_DOMAIN}\u0000${kind}\u0000${source}\u0000${identity}`)
    .digest("hex")
    .slice(0, 16);
}

// systemd_timer (unit) / launchd_scheduled_job (label) / periodic_directory_entry (path) all
// carry real, structurally-distinct per-entry identity. They are still operator/attacker-
// controlled identifiers, so hash them at source just like cron identity. Only the closed kind
// and source enums remain visible in the persisted fact.
function scheduledJobIdentityLeg(job) {
  const { kind, source } = job ?? {};
  if (!isValidScheduledJobKindSource(kind, source)) return undefined;
  if (kind === "cron") {
    if (![job.path, job.schedule, job.user, job.command].every((value) => typeof value === "string" && value.length > 0)) {
      return undefined;
    }
    return cronJobIdentityDigest(job);
  }

  const identity = kind === "systemd_timer"
    ? job.unit
    : kind === "launchd_scheduled_job"
      ? job.label
      : job.path;
  if (typeof identity !== "string" || identity.length === 0) return undefined;
  return hashScheduledJobIdentityLeg(kind, source, identity);
}

// Length-prefixed composite framing (NOT delimiter-joined — inherits Gap 1/process-lineage's
// resolved separator-collision fix): `${segment.length}:${segment}` for each of the three legs
// (kind, source, identity) makes the boundary between segments unambiguous regardless of what
// characters a segment happens to contain, so two differently-split (kind, source, identity)
// triples can never collide by concatenation ambiguity — e.g. (source="a", identity="bc") and
// (source="ab", identity="c") hash/frame to different composite strings. `kind`/`source` are
// always one of this collector's own closed-enum literals (never raw/attacker-controlled text);
// a name field that reduces to empty falls back to "unknown" per segment (degrade-not-fabricate,
// never drop the whole fact silently).
function lengthPrefixedSegment(value) {
  const segment = typeof value === "string" && value ? value : "unknown";
  return `${segment.length}:${segment}`;
}

export function buildScheduledJobEntityKey(kind, source, identityLeg) {
  const kindSeg = sanitizeIdentityString(kind, { maxLength: 64 }) ?? "unknown";
  const sourceSeg = sanitizeIdentityString(source, { maxLength: 64 }) ?? "unknown";
  const identitySeg = typeof identityLeg === "string" && identityLeg ? identityLeg : "unknown";
  return `scheduled_job.${lengthPrefixedSegment(kindSeg)}.${lengthPrefixedSegment(sourceSeg)}.${lengthPrefixedSegment(identitySeg)}`;
}

// [REVIEW 2026-08-21, must-fix] census_state = "complete" iff summary.unavailable_count === 0 AND
// evidence.truncated !== true; otherwise "partial". The envelope-level `truncated` flag
// (tools/scheduled-jobs.js: `allJobs.length > jobs.length || probes.some(p => p.truncated)`)
// subsumes BOTH the total-vs-returned leg AND every probe-level truncation (directory-listing
// caps, launchd candidate caps, truncated cron-file reads) — using it instead of re-deriving from
// total_count === returned_count closes the fabrication path where jobs are dropped BEFORE
// allJobs is ever assembled (a probe can report truncated:true while total_count still equals
// returned_count, because the drop happened upstream of both counts).
function scheduledJobCensusStateFor(result) {
  const summary = result?.summary;
  const unavailableClean = summary !== null
    && typeof summary === "object"
    && !Array.isArray(summary)
    && typeof summary.unavailable_count === "number"
    && Number.isFinite(summary.unavailable_count)
    && summary.unavailable_count === 0;
  const isPartial = !Array.isArray(result?.jobs) || result?.truncated === true || !unavailableClean;
  return isPartial ? "partial" : "complete";
}

function buildScheduledJobCensusMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: SCHEDULED_JOB_CENSUS_FACT_NAME,
    entity_key: SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: scheduledJobCensusStateFor(result) },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}

/**
 * evidence[] -> fact-store.js-shaped fact points for Slice A's scheduled-jobs collector
 * (tools/scheduled-jobs.js). Pure L0 fact source: this translator never builds an alert
 * candidate and is never wired into daemon.js's extraCandidates — alerting on a novel scheduled
 * job (scheduled_job.appeared) is Slice B's job (persistence-baseline.js), which consumes this
 * fact-history rather than emitting candidates here.
 */
export function factPointsFromScheduledJobsEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "scheduled-jobs" && e.status !== "unable");
  if (!envelope) return [];
  const jobs = Array.isArray(envelope.result?.jobs) ? envelope.result.jobs : [];
  let invalidJob = !Array.isArray(envelope.result?.jobs);

  const points = jobs.map((job) => {
    const identityLeg = scheduledJobIdentityLeg(job);
    if (!identityLeg) {
      invalidJob = true;
      return undefined;
    }
    const entityKey = buildScheduledJobEntityKey(job.kind, job.source, identityLeg);
    return {
      ts,
      fact_name: SCHEDULED_JOB_PRESENCE_FACT_NAME,
      entity_key: entityKey,
      attributes: {
        kind: job.kind,
        source: job.source,
      },
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
    };
  }).filter(Boolean);

  // Emitted only on a genuine enumeration ("ok"/"warning") — never on "unknown" (unsupported
  // platform, no real census ran) or "unable" (already excluded by the find() filter above).
  // Includes a genuine zero-job tick, mirroring factPointsFromServiceEvidence's own precedent.
  if (envelope.status === "ok" || envelope.status === "warning") {
    const marker = buildScheduledJobCensusMarkerFactPoint(envelope.result, envelope, ts);
    if (invalidJob) marker.attributes.census_state = "partial";
    points.push(marker);
  }
  return points;
}

export function factPointsFromProcessLineageEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "process-lineage-edges" && e.status !== "unable");
  if (!envelope) return [];
  const edges = envelope.result?.edges ?? [];

  const points = edges.map((edge) => {
    const entityKey = buildLineageEntityKey(edge.parent_comm, edge.child_comm);
    if (!entityKey) return undefined;
    return {
      ts,
      fact_name: PROCESS_LINEAGE_EDGE_FACT_NAME,
      entity_key: entityKey,
      attributes: {},
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
    };
  }).filter(Boolean);

  if (envelope.status === "ok" || envelope.status === "warning") {
    points.push({
      ts,
      fact_name: PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME,
      entity_key: PROCESS_LINEAGE_EDGE_CENSUS_MARKER_ENTITY_KEY,
      attributes: { census_state: envelope.result?.truncated ? "partial" : "complete" },
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
      confidence: 0,
    });
  }
  return points;
}

// "partial" whenever this tick's service enumeration was truncated (tools/services.js capped the list
// at its own limit), else "complete". A partial census must never be read as an authoritative "these
// are ALL the services" set by any future absence-diff. Mirrors censusStateFor's role for sessions,
// adapted to the services result shape (no per-manager `multiplexers` array — `truncated` is its only
// incompleteness signal).
function serviceCensusStateFor(result) {
  return result?.truncated ? "partial" : "complete";
}

// confidence:0 (exactly like the session census/overflow markers): carries no service-presence
// evidence of its own and must never be mistaken for one downstream.
function buildServiceCensusMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: SERVICE_CENSUS_FACT_NAME,
    entity_key: SERVICE_CENSUS_MARKER_ENTITY_KEY,
    attributes: {
      census_state: serviceCensusStateFor(result),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}

export function factPointsFromCanaryEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "canary" && e.status !== "unable");
  if (!envelope) return [];
  const points = (envelope.result?.canaries ?? [])
    .filter((canary) => canary?.status === "ok")
    .map((canary) => {
      const entityKey = sanitizeEntityKey(canary.id);
      if (typeof entityKey !== "string" || !entityKey) return undefined;
      const watch = Array.isArray(canary.watch) ? canary.watch : [];
      // FIX-A (identity binding, canary v0 finalization): pass the collector's identity_fingerprint
      // straight through as an attribute, unmodified — it is already a hash (tools/canary.js's
      // canaryIdentityFingerprint), never a raw path, so no further sanitization is needed here.
      // canary-baseline.js binds its trip comparison to (canary_id + this fingerprint) so a
      // manifest path/sentinel_path edit, or a canary_id reused for a different underlying file,
      // cannot fabricate a trip by comparing the OLD file's facts against the NEW file's under the
      // same entity_key. Omitted (rather than included as an explicit `undefined`) when the
      // collector didn't supply one (older/simplified evidence shapes) — normalizeAttributes in
      // fact-store.js already drops undefined values, and canary-baseline.js's own snapshot/
      // comparison logic degrades a missing fingerprint to "identity not verified, skip" rather
      // than fabricating a match.
      const identityFingerprint = typeof canary.identity_fingerprint === "string" && canary.identity_fingerprint
        ? { identity_fingerprint: canary.identity_fingerprint }
        : {};
      return {
        ts,
        fact_name: CANARY_PRESENCE_FACT_NAME,
        entity_key: entityKey,
        attributes: {
          atime: canary.atime,
          mtime: canary.mtime,
          ino: canary.ino,
          size: canary.size,
          executed: canary.executed,
          kind: canary.kind,
          watch: watch.join(","),
          ...identityFingerprint,
        },
        source_envelope_id: envelope.id,
        source_tool: envelope.trace?.tool,
        sensitivity: "operational",
      };
    })
    .filter(Boolean);

  const totalCount = Number(envelope.result?.summary?.total_count);
  if ((envelope.status === "ok" || envelope.status === "warning") && totalCount >= 1) {
    // Degrade-not-fabricate (HIGH fix, canary collector review): a tick with even one
    // unreadable canary (lstat EACCES etc.) must NOT be labelled "complete" — that canary is
    // silently absent from `points` above (collectOneCanary never emitted a presence fact for
    // it), so a "complete" marker here would let detectCanaryTrips's two-COMPLETE-group diff
    // skip straight over the blackout tick, opening a one-tick evasion window for an attacker
    // who times their atime/mtime change to land inside it. `envelope.status !== "ok"` is a
    // second, independent guard (tools/canary.js already flips status to "warning" whenever
    // unreadable_count>0, but this stays defensive against any future collector/fixture that
    // decouples the two) — any of the signals below (including the execution-unknown check just
    // past it) is enough to fall back to "partial", which EXCLUDES this tick from the
    // clean-comparison set entirely, so the eventual two-COMPLETE-group diff spans the blackout
    // and detects the attacker's change instead of missing it.
    const unreadableCount = Number(envelope.result?.summary?.unreadable_count);
    // P1 fix (canary collector review round 2): a per-canary EXECUTION-check failure (sentinel
    // access() EACCES/etc, degraded by tools/canary.js to executed:"unknown") is exactly as
    // much a this-tick read failure as an lstat "unreadable" canary — it must ALSO force this
    // tick's census to "partial", or a real false->unknown->true execution spanning the
    // blackout tick is lost: the blackout tick would wrongly stay in the two-COMPLETE-group
    // comparison set, so detectCanaryTrips's previous/latest pair straddles it and never sees
    // the false->true transition at all (unknown never trips on its own either — see
    // canary-baseline.js's `previousSnapshot.executed === "false"` guard). Checked two ways,
    // same defense-in-depth posture as the unreadable_count check above: the collector's own
    // summary.execution_unknown_count (added alongside this fix) AND a direct scan of the
    // per-canary records, so a fixture/future collector that populates one but not the other
    // still degrades correctly.
    const executionUnknownCount = Number(envelope.result?.summary?.execution_unknown_count);
    const anyExecutionUnknown =
      (Number.isFinite(executionUnknownCount) && executionUnknownCount > 0) ||
      (Array.isArray(envelope.result?.canaries) && envelope.result.canaries.some((canary) => canary?.executed === "unknown"));
    const isPartial =
      Boolean(envelope.result?.truncated) ||
      (Number.isFinite(unreadableCount) && unreadableCount > 0) ||
      envelope.status !== "ok" ||
      anyExecutionUnknown;
    points.push({
      ts,
      fact_name: CANARY_CENSUS_FACT_NAME,
      entity_key: CANARY_CENSUS_MARKER_ENTITY_KEY,
      attributes: {
        census_state: isPartial ? "partial" : "complete",
      },
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
      confidence: 0,
    });
  }
  return points;
}

/**
 * Grounded against tools/network.js's REAL collectNetworkEvidence() result shape:
 * result.listening_sockets, elements {protocol, state, local_address, local_port, raw?} on
 * Linux (parseLinuxListeningSockets — no pid/command field at all) and {protocol, state,
 * command, pid, local_address, local_port} on macOS (parseMacLsofListeningSockets).
 *
 * entity_key includes local_address (not just protocol:port) to avoid collisions between
 * genuinely distinct sockets that differ only by bind address (e.g. 0.0.0.0:8080 vs
 * [::]:8080). Owner resolution is macOS-only in effect today — the Linux parser never
 * populates `command`, so port-binding-identity mining will, in practice, produce
 * owner_known:"false" on every Linux sample; this is an accepted v1 scope note, not a bug.
 */
export function factPointsFromNetworkEvidence(evidence, { ts } = {}) {
  const envelope = evidence.find((e) => e.id === "network-basics" && e.status !== "unable");
  if (!envelope) return [];
  const sockets = envelope.result?.listening_sockets ?? [];

  return sockets
    .map((socket) => {
      const entityKey = sanitizeEntityKey(`${socket.protocol}:${socket.local_address}:${socket.local_port}`);
      if (!entityKey) return undefined; // unresolvable identity — dropped, never invented

      const rawOwner = typeof socket.command === "string" ? sanitizeEntityKey(socket.command) : undefined;
      const ownerKnown = Boolean(rawOwner);

      const point = {
        ts,
        fact_name: "network.listening_port.owner",
        entity_key: entityKey,
        attributes: ownerKnown
          ? { owner: rawOwner, owner_known: "true" }
          : { owner_known: "false" },
        source_envelope_id: envelope.id,
        source_tool: envelope.trace?.tool,
        sensitivity: "operational",
      };
      // Degrade-don't-fabricate marker (mirrors timedEnvelope's confidence:0 pattern):
      // owner_known:"false" facts must never count as confirming or contradicting evidence
      // downstream (S6c's miner), so they carry an explicit confidence:0.
      if (!ownerKnown) point.confidence = 0;
      return point;
    })
    .filter(Boolean);
}

// ---------------------------------------------------------------------------------------------
// Slice 1 (observed-incident collectors plan) — session-census translator.
//
// MUST-FIX 3 (hash-at-source, hard requirement): a tmux/screen session name is
// operator/attacker-chosen free text (a project name, a hostname, an IP address, a shell
// snippet pasted as a session title — anything). `sanitizeIdentityString` alone is
// charset-substitution + truncation, NOT a confidentiality control (plan §1) — it would leave
// a recognizable, human-readable name (with unsafe characters swapped for "_") sitting in
// fact-history forever. The PERSISTED entity_key here is therefore a FIXED-LENGTH HEX HASH of
// the session identity, never a sanitized/substituted version of the raw name.
//
// Domain separation (must-fix 3): the hash preimage is prefixed with a scheme-specific,
// versioned domain tag (SESSION_ENTITY_HASH_DOMAIN) BEFORE the multiplexer/session-name are
// appended, so this session-identity hash space can never collide with a future peer/process
// identity hash scheme (Slice 3's own peer-identity hashing variant) even if the raw input
// bytes happened to coincide — mirrors provenance-warnings.js's hashExecutablePath /
// provenance-store.js's own per-scheme hashing discipline.
// Exported (additive, Slice 3) so test/fact-translators.test.js and
// test/peer-signature-store.test.js can run a direct session-vs-peer domain-separation
// differentiation test (must-fix 6) against the ACTUAL shipped session hash scheme, rather than
// re-deriving a parallel copy that could silently drift from this one.
export const SESSION_ENTITY_HASH_DOMAIN = "descartes.fact.session.v1";

// A session-identity hash is intentionally NOT emitted for this fixed marker — it carries no
// session identity at all (see buildSessionOverflowMarkerFactPoint below), so it is a plain,
// versioned closed-enum string rather than a hash of anything. Exported (Slice 4, observed-
// incident collectors plan, Decision 3) so session-baseline.js's tick-grouping can recognize and
// exclude this exact marker entity from the windowed Welford recompute without re-deriving a
// parallel copy of the literal that could silently drift from this one.
export const SESSION_OVERFLOW_ENTITY_KEY = "session.overflow-marker.v1";

// ---------------------------------------------------------------------------------------------
// Slice 4 (observed-incident collectors plan) Slice 1 addendum — must-fixes 1 & 2 (Fable review,
// 2026-07-14): a per-tick CENSUS MARKER fact, emitted on EVERY successful sessions envelope,
// regardless of how many sessions were observed — including exactly zero.
//
// MUST-FIX 1: without this marker, a mass session-drop to ZERO is structurally invisible — a
// zero-session tick emits no session.presence facts at all (see factPointsFromSessionEvidence's
// `sessions.map(...)` below), so Slice 4's fold has no tick-group to see and can never treat "0"
// as a real observation (a fold cannot safely infer "0 sessions" from an absent tick-group without
// fabricating — that would violate degrade-not-fabricate, plan §1). This marker's mere presence
// turns "zero non-marker session.presence points + a complete marker" into a real, foldable 0.
//
// MUST-FIX 2: a partially-degraded census (e.g. tmux ok, screen genuinely errored/"unable") is
// currently indistinguishable, at the fact-history layer, from a complete census — undercounting
// silently and able to false-fire a downstream count-drop signature on nothing more than a flaky
// `screen` binary. `census_state` surfaces this: "partial" whenever ANY multiplexer in this tick's
// `result.multiplexers` reported status "unable" (a multiplexer reporting "absent" — genuinely not
// installed — does NOT count as partial: a host with no `screen` at all still has a complete
// census of what it actually runs).
//
// Fixed, non-hashed entity_key (mirrors SESSION_OVERFLOW_ENTITY_KEY's own convention exactly) —
// this marker carries no session identity, so nothing needs hashing. Exported so
// session-baseline.js's tick-grouping (Decision 3) can recognize this exact literal, and
// re-exported from session-baseline.js for convenience (plan Decision 6).
export const SESSION_CENSUS_MARKER_ENTITY_KEY = "session.census-marker.v1";

// MUST-FIX 6 churn detector. A kill-then-resurrect reuses the same session NAME, so the entity_key
// (a hash of mux+name) is UNCHANGED across ticks — the only signal that a session was recreated is
// that its creation time changed. Any coarse *bucket* (hour, or even 10-minute) can HIDE this: a
// resurrect whose new created_at happens to land in the same bucket as the original produces an
// IDENTICAL value = zero churn — exactly the fast-resurrect case an adversary would use, and the
// gap an adversarial review flagged. So instead of a bucket we persist a FINGERPRINT: a
// fixed-length hex hash of the raw creation second. It changes on ANY recreation (1-second
// resolution), independent of window alignment, while never persisting the raw timestamp itself.
// Domain-separated from the identity hash so the two schemes can never collide on shared inputs.
const SESSION_CREATED_FINGERPRINT_DOMAIN = "descartes.fact.session.created.v1";

// Exported (additive, Slice 3) for the same reason as SESSION_ENTITY_HASH_DOMAIN above.
export function hashSessionIdentity(multiplexer, sessionName) {
  return crypto.createHash("sha256").update(`${SESSION_ENTITY_HASH_DOMAIN}:${multiplexer}:${sessionName}`).digest("hex").slice(0, 16);
}

// multiplexer is always one of this collector's own closed-enum literals ("tmux"/"screen"),
// never raw/attacker-controlled text, so it is safe to embed directly (unhashed) in entity_key —
// only the free-text session_name component is hashed.
function sessionEntityKey(multiplexer, sessionName) {
  const mux = multiplexer === "screen" ? "screen" : "tmux";
  return `session.${mux}.${hashSessionIdentity(mux, sessionName)}`;
}

// Closed-enum bucket, never the raw integer window count.
function bucketWindowCount(count) {
  if (!Number.isFinite(count) || count < 0) return "unknown";
  if (count === 0) return "0";
  if (count === 1) return "1";
  if (count <= 4) return "2-4";
  if (count <= 9) return "5-9";
  return "10+";
}

// Opaque fixed-length hex fingerprint of the raw creation second — never a formatted date/ISO
// string and never the raw epoch value. "unknown" when the multiplexer doesn't expose a creation
// time (always the case for `screen -ls`). Changes iff the creation second changes, so any
// recreation surfaces as attribute churn (see SESSION_CREATED_FINGERPRINT_DOMAIN doc above).
function fingerprintCreatedAt(epochSeconds) {
  if (!Number.isFinite(epochSeconds)) return "unknown";
  return crypto.createHash("sha256").update(`${SESSION_CREATED_FINGERPRINT_DOMAIN}:${epochSeconds}`).digest("hex").slice(0, 16);
}

// Closed-enum bucket for the marker's total-count context — never the raw total_count integer
// verbatim (kept consistent with every other bucketed attribute in this translator).
function bucketOverflowTotal(count) {
  if (!Number.isFinite(count) || count < 0) return "unknown";
  if (count <= 200) return "<=200";
  if (count <= 500) return "201-500";
  if (count <= 1000) return "501-1000";
  return "1000+";
}

function buildSessionFactPoint(session, envelope, ts) {
  const entityKey = sessionEntityKey(session.multiplexer, session.session_name);
  return {
    ts,
    fact_name: "session.presence",
    entity_key: entityKey,
    attributes: {
      multiplexer: session.multiplexer === "screen" ? "screen" : "tmux",
      attached: String(Boolean(session.attached)),
      window_count_bucket: bucketWindowCount(session.window_count),
      created_at_fingerprint: fingerprintCreatedAt(session.created_at_epoch_seconds),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
  };
}

// MUST-FIX 5 (flood cap, hard requirement): emitted only when the collector already reported
// `truncated:true` — i.e. the real per-tick session count exceeded tools/sessions.js's own
// DEFAULT_SESSION_ENTITY_LIMIT cap. This marker fact carries no session identity at all (no
// hash, no per-session attributes) and is explicitly confidence:0 so it can never be mistaken
// for real session-presence evidence downstream — it exists purely so a pathological session
// flood is visible as "truncation happened" rather than silently dropped with no indication.
function buildSessionOverflowMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: SESSION_OVERFLOW_ENTITY_KEY,
    attributes: {
      overflow: "true",
      total_count_bucket: bucketOverflowTotal(result.total_count),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}

// Must-fix 2: "partial" iff ANY multiplexer this tick reported status "unable" — "absent"
// (genuinely not installed) does NOT count as partial. `result.multiplexers` is the real
// collector's per-mux status array (tools/sessions.js's collectSessionEvidence); a fixture that
// omits it entirely (e.g. legacy/simplified test evidence) degrades to "complete" rather than
// throwing — an absent multiplexers array carries no evidence of degradation either way.
function censusStateFor(result) {
  const multiplexers = Array.isArray(result?.multiplexers) ? result.multiplexers : [];
  const anyUnable = multiplexers.some((mux) => mux?.status === "unable");
  return anyUnable ? "partial" : "complete";
}

// Must-fix 1/2: emitted unconditionally on every successful sessions envelope — including a
// genuinely zero-session tick — so the fold (Slice 4) always has a real tick-group to see. Marked
// confidence:0 like the overflow marker above: it carries no session-presence evidence of its
// own and must never be mistaken for one downstream.
function buildSessionCensusMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: SESSION_CENSUS_MARKER_ENTITY_KEY,
    attributes: {
      census_state: censusStateFor(result),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}

/**
 * evidence[] -> fact-store.js-shaped fact points for Slice 1's session-census collector
 * (tools/sessions.js). Mirrors factPointsFromServiceEvidence's overall shape. Pure L0 fact
 * source: this translator never builds an alert candidate and is never wired into daemon.js's
 * extraCandidates — alerting on session-count deviation/churn is Slice 4's job
 * (session-baseline.js), which consumes this fact-history rather than emitting candidates here.
 */
export function factPointsFromSessionEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "sessions" && e.status !== "unable");
  if (!envelope) return [];
  const sessions = envelope.result?.sessions ?? [];

  const points = sessions.map((session) => buildSessionFactPoint(session, envelope, ts));
  // Slice 4 Slice-1-addendum (must-fixes 1/2): the census marker is ALWAYS appended, after every
  // real session fact, on every successful envelope — including a zero-session tick. It is
  // excluded from the per-tick entity cap/count (must-fix 5, already enforced by tools/sessions.js
  // before this translator ever runs), from churn detection, and from Slice 4's session count,
  // exactly the way SESSION_OVERFLOW_ENTITY_KEY already is excluded.
  points.push(buildSessionCensusMarkerFactPoint(envelope.result, envelope, ts));
  if (envelope.result?.truncated) {
    points.push(buildSessionOverflowMarkerFactPoint(envelope.result, envelope, ts));
  }
  return points;
}

// ---------------------------------------------------------------------------------------------
// Slice 3 (observed-incident collectors plan) — VPN/SSH peer identity translator.
//
// entity_key IS the peer-identity hash (hash-at-source, must-fix 3): computed by
// peer-signature-store.js's computePeerIdentitySignature, a domain-separated ("descartes.peer.v1")
// scheme distinct from both the process scheme (provenance-store.js's computeIdentitySignature,
// which carries no domain tag) and the session scheme above (SESSION_ENTITY_HASH_DOMAIN,
// "descartes.fact.session.v1") — see peer-signature-store.js's own module header for the full
// identity-vs-attribute split (WireGuard/vpn_service identity = pubkey/UUID only; SSH identity =
// source_type+user+host).
//
// Every persisted attribute below is a CLOSED-ENUM literal — never a raw WG public key, raw
// IP/hostname/username, raw scutil VPN service name/UUID, or raw timestamp/epoch. This is a hard
// requirement (must-fix 3/5): fact-store.js's attributes are unsanitized
// `String(value).slice(0,160)` (fact-store.js:36) — hashing/bucketing at THIS translator is the
// ONLY control, there is no downstream sanitization gate for fact-history.
const PEER_FACT_NAME = "peer.presence";

// Marker entity_key for the overflow fact — carries no peer identity at all, so no hash is
// computed for it (mirrors SESSION_OVERFLOW_ENTITY_KEY's convention exactly). Exported (Slice 6,
// observed-incident collectors plan, must-fix 5) so incident-correlation.js's overflow-degraded-
// window gate can import and compare against it directly, rather than duplicating the
// "peer.overflow-marker.v1" literal.
export const PEER_OVERFLOW_ENTITY_KEY = "peer.overflow-marker.v1";

// Slice 4c (observed-incident collectors plan) — peer census-marker addendum, mirrors
// SESSION_CENSUS_MARKER_ENTITY_KEY exactly: emitted unconditionally on every successful
// vpn-peer-status envelope (including a zero-peer tick), so a true zero is foldable by
// peer.count_drop. Unlike the session marker, it ALSO carries a closed-enum per-tick
// source-availability signature (Decision 1 below) so peer-baseline.js's regime-keyed fold can
// bucket ticks by which peer sources were up this tick.
export const PEER_CENSUS_MARKER_ENTITY_KEY = "peer.census-marker.v1";

// Decision 1 (plan pinned): a single closed-enum bucketed string, versioned, built from the
// 5 fixed source keys vpn-peer-status.js's envelope always produces (sources.{ssh_who,ssh_last,
// wireguard,vpn_services,established_inbound}.status). Grounded against tools/vpn-peer-status.js's
// real closed status vocabulary (confirmed by direct read): "ok" | "partial" | "absent" |
// "missing_permission" | "unable" | "not_applicable" (not every source can emit every value --
// e.g. only wireguard emits "partial", only vpn_services emits "not_applicable" -- but the bucket
// function below is defensive against ANY future status literal, mapping anything outside this
// closed set to "unknown" rather than embedding an unrecognized raw string).
const CLOSED_PEER_SOURCE_STATUS_VALUES = new Set([
  "ok", "partial", "absent", "missing_permission", "unable", "not_applicable",
]);

function normalizedSourceStatus(status) {
  return CLOSED_PEER_SOURCE_STATUS_VALUES.has(status) ? status : "unknown";
}

// Fixed order, never derived from Object.keys (whose iteration order is an accident of insertion,
// not a contract) -- a stable, versioned signature format lets peer-baseline.js compare two
// signatures with simple string equality.
const PEER_AVAILABILITY_SOURCE_ORDER = ["ssh_who", "ssh_last", "wireguard", "vpn_services", "established_inbound"];
const PEER_AVAILABILITY_SIGNATURE_VERSION = "v1";

// Degrade-not-fabricate: a missing/malformed `sources` object (e.g. a simplified test fixture)
// degrades every source to "unknown" rather than throwing -- mirrors censusStateFor's own
// "absent multiplexers array carries no evidence of degradation either way" posture.
function buildPeerAvailabilitySignature(sources) {
  const codes = PEER_AVAILABILITY_SOURCE_ORDER.map((key) => normalizedSourceStatus(sources?.[key]?.status));
  return `${PEER_AVAILABILITY_SIGNATURE_VERSION}:${codes.join("-")}`;
}

// Emitted unconditionally on every successful vpn-peer-status envelope, including a genuinely
// zero-peer tick -- so peer-baseline.js's fold always has a real tick-group to see for the drop
// direction. confidence:0, non-hashed fixed entity_key literal (mirrors PEER_OVERFLOW_ENTITY_KEY's
// own convention -- it carries no peer identity, nothing needs hashing).
function buildPeerCensusMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: PEER_FACT_NAME,
    entity_key: PEER_CENSUS_MARKER_ENTITY_KEY,
    attributes: {
      availability_signature: buildPeerAvailabilitySignature(result?.sources),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}

const CLOSED_PEER_SOURCE_TYPES = new Set(["wireguard", "ssh", "vpn_service", "tailscale"]);

function normalizedPeerSourceType(sourceType) {
  return CLOSED_PEER_SOURCE_TYPES.has(sourceType) ? sourceType : "unknown";
}

// sourceType is always one of this collector's own closed-enum literals — safe to embed
// directly (unhashed) in entity_key, exactly like sessionEntityKey's `mux` component above; only
// the free-text/secret-shaped identity fields (pubkey/uuid/user/host) are ever hashed.
function peerEntityKey(peer) {
  const sourceType = normalizedPeerSourceType(peer.source_type);
  const hash = computePeerIdentitySignature({
    sourceType,
    peerIdentifier: sourceType === "wireguard" ? peer.public_key : sourceType === "tailscale" ? peer.node_public_key : sourceType === "vpn_service" ? peer.service_uuid : undefined,
    remoteUser: sourceType === "ssh" ? peer.remote_user : undefined,
    remoteHost: sourceType === "ssh" ? peer.remote_host : undefined,
  });
  return `peer.${sourceType}.${hash}`;
}

// Closed-enum local hour-of-day bucket ("00".."23", or "unknown") — the hour at which THIS
// observation tick occurred, never a raw/precise timestamp. Deliberately NOT derived from
// parsing an exact login instant out of who/last's locale-dependent date columns (fragile across
// BSD/GNU implementations and timezones) — the tick's own hour is what "odd-hour" statistical
// judgment (deferred to Slice 4) will actually consume.
function bucketLoginHour(ts) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "unknown";
  return String(date.getHours()).padStart(2, "0");
}

// Closed-enum handshake-age bucket (must-fix 5, hard requirement) — NEVER a raw epoch or precise
// seconds value, the same occupancy-signal sensitivity class as a raw creation timestamp
// (mirrors Slice 1's created_at_fingerprint reasoning, but a bucket suffices here since
// handshake age is not itself the churn-detection signal must-fix 6 was about). "n/a" for any
// non-WireGuard/Tailscale peer, keeping every peer fact's attribute-key set uniform.
function bucketHandshakeAge(epochSeconds, nowEpochSeconds) {
  if (!Number.isFinite(epochSeconds)) return "unknown";
  if (epochSeconds === 0) return "never"; // WireGuard's own "never handshaked" signal
  const ageSeconds = nowEpochSeconds - epochSeconds;
  if (!Number.isFinite(ageSeconds) || ageSeconds < 0) return "unknown";
  if (ageSeconds < 300) return "lt_5m";
  if (ageSeconds < 3600) return "lt_1h";
  if (ageSeconds < 86400) return "lt_1d";
  if (ageSeconds < 7 * 86400) return "lt_7d";
  return "gte_7d";
}

// Closed-enum bucket for the marker's total-count context — mirrors bucketOverflowTotal exactly
// (never the raw total_count integer verbatim).
function bucketPeerOverflowTotal(count) {
  if (!Number.isFinite(count) || count < 0) return "unknown";
  if (count <= 200) return "<=200";
  if (count <= 500) return "201-500";
  if (count <= 1000) return "501-1000";
  return "1000+";
}

function bucketExitNodeRole(peer, sourceType) {
  if (sourceType !== "tailscale") return "n/a";
  if (peer.is_exit_node_active) return "in_use";
  if (peer.is_exit_node_option) return "advertised_unused";
  return "none";
}

function buildPeerFactPoint(peer, envelope, ts) {
  const sourceType = normalizedPeerSourceType(peer.source_type);
  const nowEpochSeconds = Math.floor(new Date(ts).getTime() / 1000);
  return {
    ts,
    fact_name: PEER_FACT_NAME,
    entity_key: peerEntityKey(peer),
    attributes: {
      source_type: sourceType,
      presence_state: peer.presence_state === "observed_historical" ? "observed_historical" : "observed_active",
      login_hour_bucket: bucketLoginHour(ts),
      handshake_age_bucket: sourceType === "wireguard" || sourceType === "tailscale" ? bucketHandshakeAge(peer.latest_handshake_epoch_seconds, nowEpochSeconds) : "n/a",
      exit_node_role: bucketExitNodeRole(peer, sourceType),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
  };
}

// Emitted only when the collector already reported `truncated:true` (must-fix 3, mirrors
// buildSessionOverflowMarkerFactPoint's flood-cap convention exactly) — explicit confidence:0 so
// it can never be mistaken for real peer-presence evidence downstream.
function buildPeerOverflowMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: PEER_FACT_NAME,
    entity_key: PEER_OVERFLOW_ENTITY_KEY,
    attributes: {
      overflow: "true",
      total_count_bucket: bucketPeerOverflowTotal(result.total_count),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}

/**
 * evidence[] -> fact-store.js-shaped fact points for Slice 3's peer-status collector
 * (tools/vpn-peer-status.js). Pure L0 fact source, mirroring factPointsFromSessionEvidence's
 * shape exactly: this translator never builds an alert candidate and is NEVER wired into
 * daemon.js's extraCandidates. Slice 3's Alert-emission scope decision (RESOLVED option 1, plan
 * §Slice 3) is that this slice emits ZERO alert candidates in v0 — it only accumulates peer
 * fact-history; alerting on unattributed/odd-hour peer logins is deferred to Slice 4/6.
 */
export function factPointsFromVpnPeerEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "vpn-peer-status" && e.status !== "unable");
  if (!envelope) return [];
  const peers = envelope.result?.peers ?? [];

  const points = peers.map((peer) => buildPeerFactPoint(peer, envelope, ts));
  // Slice 4c (observed-incident collectors plan): the census marker is ALWAYS appended, after
  // every real peer fact, on every successful envelope — including a zero-peer tick — mirroring
  // factPointsFromSessionEvidence's own append order (census marker first, overflow marker
  // second).
  points.push(buildPeerCensusMarkerFactPoint(envelope.result, envelope, ts));
  if (envelope.result?.truncated) {
    points.push(buildPeerOverflowMarkerFactPoint(envelope.result, envelope, ts));
  }
  return points;
}

/**
 * evidence[] -> fact-store.js-shaped fact points for the read-only Tailscale status collector.
 * Tailscale intentionally does NOT emit PEER_CENSUS_MARKER_ENTITY_KEY: that single-value marker
 * belongs exclusively to vpn-peer-status, whose five-source availability signature must not be
 * overwritten by a second collector on the same tick. Tailscale peers still share peer.presence,
 * and its overflow marker safely composes with the sibling collector's overflow marker.
 */
export function factPointsFromTailscaleStatusEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "tailscale-status" && e.status !== "unable");
  if (!envelope) return [];
  const peers = envelope.result?.peers ?? [];
  const points = peers.map((peer) => buildPeerFactPoint(peer, envelope, ts));
  if (envelope.result?.truncated) {
    points.push(buildPeerOverflowMarkerFactPoint(envelope.result, envelope, ts));
  }
  return points;
}
