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

export function sanitizeEntityKey(value) {
  return sanitizeIdentityString(value);
}

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

  return services
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
const SESSION_ENTITY_HASH_DOMAIN = "descartes.fact.session.v1";

// A session-identity hash is intentionally NOT emitted for this fixed marker — it carries no
// session identity at all (see buildSessionOverflowMarkerFactPoint below), so it is a plain,
// versioned closed-enum string rather than a hash of anything.
const SESSION_OVERFLOW_ENTITY_KEY = "session.overflow-marker.v1";

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

function hashSessionIdentity(multiplexer, sessionName) {
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

/**
 * evidence[] -> fact-store.js-shaped fact points for Slice 1's session-census collector
 * (tools/sessions.js). Mirrors factPointsFromServiceEvidence's overall shape. Pure L0 fact
 * source: this translator never builds an alert candidate and is never wired into daemon.js's
 * extraCandidates — alerting on session-count deviation/churn is explicitly Slice 4's job, not
 * this slice's (plan Slice 1 Definition of Done).
 */
export function factPointsFromSessionEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "sessions" && e.status !== "unable");
  if (!envelope) return [];
  const sessions = envelope.result?.sessions ?? [];

  const points = sessions.map((session) => buildSessionFactPoint(session, envelope, ts));
  if (envelope.result?.truncated) {
    points.push(buildSessionOverflowMarkerFactPoint(envelope.result, envelope, ts));
  }
  return points;
}
