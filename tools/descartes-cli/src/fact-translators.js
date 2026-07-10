// Per-collector translators: pure functions from a structural collector's evidence envelope
// (as produced by S6a's collectStructuralEvidence) into fact-store.js's fact-point schema.
// Kept as a sibling file to fact-store.js so the storage module stays a pure storage
// concern, mirroring how constraint-eval.js is separate from constraint-store.js (plan §3).
//
// Hard invariant across every translator in this file: degrade, never fabricate. An
// unresolvable identity/owner is either omitted entirely or marked owner_known:"false" —
// it is never guessed or defaulted to a placeholder that could be mistaken for a real
// observation.
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
