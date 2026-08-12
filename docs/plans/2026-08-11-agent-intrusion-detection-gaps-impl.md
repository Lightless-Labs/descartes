# Agent-intrusion host-detection gaps — implementation plan

**Created:** 2026-08-11
**Todo:** `todos/2026-08-11-agent-intrusion-detection-gaps.md`
**Research:** `docs/research/2026-08-11-agentic-intrusion-defense.md` (§2.3 names the three gaps; §3
is the sibling deception/canary design this plan's gap 3 explicitly overlaps and should reuse from)
**Purpose:** turn the research doc's three named structural gaps into buildable slices, mirroring
the shipped `service-baseline.js` / `session-baseline.js` census+set-diff pattern exactly. Gap 1
(process-lineage / child-spawn anomaly) gets full implementation detail — it is the highest-value
gap and sits directly on top of the already-shipped `inspect_process`/`inspect_parent_tree`
snapshot machinery. Gaps 2 (persistence baseline) and 3 (credential-file access) are specced as
follow-ons at the depth needed to start a tight review cycle on each, not implemented here.

**Reviewed:** 2026-08-11 (Fable + gpt-5.6-sol) — Fable GO_WITH_CHANGES, sol UNAVAILABLE. All four
combined must-fixes resolved in plan text (design-only): (1) test-plan seam corrected — gap 1's
unit coverage no longer claims a `processes.test.js` injection point that doesn't exist; (2)
entity-key construction redesigned around a length-prefixed encoding so the sanitizer's own
in-charset separator collision (`a>b->c` / `a_b->c` → identical) is structurally impossible, not
just documented; (3) the collision note now names all three concurrently-drafted 2026-08-11 sibling
plans by file and by exact seam touched, and drops the inconsistent ordinal claims in favor of an
explicit today's-code baseline (six structural sub-collectors, seven `extraCandidates` entries) plus
the assumed landing order; (4) a fact-store shared-budget sizing note is added, with
`MAX_LINEAGE_EDGES_PER_TICK` lowered from a bare provisional 500 to a precedent-justified 200. See
each fix inline at its resolution point below.

**Addendum:** 2026-08-12 — while closing a BOUNDED corrupt/missing-baseline-store fabrication gap
in `process-lineage-baseline.js` (self-heal-and-immediately-fire; fixed with a persistent
cold-start lockout), a CROSS-DETECTOR architectural gap was discovered one layer down, in
`fact-store.js` itself, shared by every gap-1-shaped detector. Documented, not fixed, below — see
"Known limitation — cross-detector history-completeness (fact-store corruption/retention)".

## Grounding read (what this plan mirrors)

- `tools/descartes-cli/src/service-baseline.js` — the exact pattern gap 1 mirrors: stateless
  set-diff detector over fact-store.js history, own tiny atomic-write store for cumulative
  counters only, `computeXBaselineCandidates(descartesPaths, options)` gated by
  `loadLearnedConfig(...).enabled` checked before any I/O, `buildXCandidates` producing
  `alert-store.js`-shaped candidates via `alertId`/`sanitizeDiagnostics`.
- `tools/descartes-cli/src/fact-translators.js` — the `SERVICE_CENSUS_FACT_NAME` /
  `buildServiceCensusMarkerFactPoint` pattern: a census marker on its OWN `fact_name` (never
  reusing the presence fact_name), `confidence: 0`, emitted on every `status:"ok"|"warning"` tick
  including a zero-entity tick, `census_state: "complete"|"partial"` from the collector's own
  `truncated` flag — never inferred.
- `tools/descartes-cli/src/tools/processes.js` — the already-shipped, already-approved `ps`
  snapshot machinery (`getProcessSnapshot`, fixed argv `ps -axo/-eo pid,ppid,pcpu,pmem,rss,comm,args`)
  that `inspect_process`/`inspect_parent_tree` already read from. Gap 1 adds a THIRD consumer of
  this same function — no new `execFile` call, no new command.
- `tools/descartes-cli/src/daemon.js` — `collectStructuralEvidence` (hourly-default structural
  cadence: services/network/scheduled-jobs/provenance/sessions/vpn-peer-status), the
  `factPointsFromXEvidence(...)` concatenation inside `runDaemonIteration`, and the
  `extraCandidates` concatenation feeding `evaluateAndPersistAlerts`.
- `tools/descartes-cli/src/alert-intelligence.js` — `classifyAlertNamespace` (prefix-based,
  fail-closed to `unknown_namespace` for anything not explicitly listed) and
  `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (the explicit allowlist that lets an
  `unknown_namespace` rule still reach the operator through the deterministic, non-LLM
  `emitSessionAlertSignals` path).
- `tools/descartes-cli/src/calibration.js` — `CLOSED_RULE_IDS` (the set of rule_ids the
  read-only calibration report attributes fired/suppressed counts to).

---

## Gap 1 — process-lineage / child-spawn anomaly baseline (FULL DETAIL, build now)

### What it is

TTPs #4, #7, #13, #15 in the research doc all reduce to the same host shadow: *an unexpected
process spawned an unexpected child*. Descartes already has `inspect_process`/`inspect_parent_tree`
(shipped, `todos/2026-05-19-process-identity-lineage-tools.md`, COMPLETED) — a single-PID snapshot
tool for on-demand triage. What's missing is the Layer-1 behavioral baseline on top: a periodic
census of parent→child spawn *relationships*, set-diffed against a learned baseline, alerting when
a **spawn edge never seen before appears**.

This is the mirror-image of `service.disappeared`: that rule fires when an established entity
*stops* appearing; this rule fires when a *novel* entity (a spawn edge) *starts* appearing. Same
census+set-diff shape, opposite trigger direction.

### The identity: comm-only edges, not PIDs, not full command lines

A process's `pid` is meaningless across ticks (it gets reused). Its full `args` are unbounded,
high-cardinality, and privacy-sensitive (already the reason `redactAndBoundProcessArgs` exists). The
stable, bounded, low-cardinality identity for a *baseline* is the **executable-name pair**.

**Resolved must-fix (Fable) — separator collision.** An earlier draft of this plan built the
entity_key by string-templating `${parent_comm}->${child_comm}` and THEN sanitizing the whole
thing with `sanitizeEntityKey`/`sanitizeIdentityString` (`diagnostics-sanitizer.js`, charset
`[A-Za-z0-9._:-]`). That collapses `>` to `_` but leaves the pre-existing `-` untouched, so the
`->` separator survives sanitization as the substring `-_` — which is itself entirely inside the
allowed charset. Two *different* raw edges can then sanitize to the *same* key: `a>b->c` (parent
`a>b`, child `c`) and `a_b->c` (parent `a_b`, child `c`) both produce `a_b-_c`. Because the
separator is drawn from the same alphabet the two halves are allowed to contain, **no fixed-string
delimiter is safe here** — any delimiter choice (`:`, `-_`, `::`, …) is provably collision-prone by
the same argument, so "pick a different in-charset delimiter and document it" (one of the two
options this finding offered) does not actually fix the bug, only relocates it. The fix is a
length-prefixed encoding instead of a delimiter:

```js
// fact-translators.js — the ONE place this composite key is built. Both buildLineageEdges'
// in-tick dedup key and the persisted fact entity_key call this exact function, so dedup
// identity and fact identity cannot diverge (the other half of this must-fix).
const LINEAGE_KEY_SEGMENT_MAX_LENGTH = 24; // comm is already OS-truncated to ~15-32 chars; this
  // keeps the worst-case composite (below) comfortably under diagnostics-sanitizer's
  // MAX_STRING_LENGTH (64): "24:" (3) + 24 + 24 = 51.

export function buildLineageEntityKey(parentComm, childComm) {
  const parentSan = sanitizeIdentityString(parentComm, { maxLength: LINEAGE_KEY_SEGMENT_MAX_LENGTH }) ?? "unknown";
  const childSan = sanitizeIdentityString(childComm, { maxLength: LINEAGE_KEY_SEGMENT_MAX_LENGTH }) ?? "unknown";
  // Length-prefix, not a delimiter: the prefix marks exactly where parentSan ends, so two
  // different (parent, child) sanitized pairs can never encode to the same string — this is
  // true regardless of what characters parentSan/childSan themselves contain, which is exactly
  // the property a fixed delimiter cannot provide when drawn from the same alphabet as the
  // payload. (Same technique as length-prefixed/Bencode-style framing.)
  return `${parentSan.length}:${parentSan}${childSan}`;
}
```

`comm` (the `ps` short-name column, already OS-truncated to ~15–32 chars) is exactly what
`processes.js` already parses. No PID, no args, no timestamp goes into the identity — only the
executable-name relationship. This keeps the entity-key space small and stable (a healthy host has
a bounded, mostly-repeating set of parent/child executable-name pairs: `launchd->sshd`,
`bash->node`, `sshd->bash`, etc.) exactly the way a healthy host has a bounded, mostly-repeating set
of service names — the property `service-baseline.js`'s whole design leans on.

**Honest limitation, stated up front:** this is a `comm`-only signature. `jruby->bash` fires once as
a novel edge; `jruby->bash` again next week (same binaries, different attacker, different args)
does **not** re-fire — it's now "established." This is a deliberate scope cut (v1 catches the FIRST
occurrence of a new spawn relationship, not every occurrence of a bad one) and is explicitly listed
under "what this does NOT do" below.

### Cadence: reuses the existing hourly structural tick — explicit trade-off, not a gap the plan hides

`collectDaemonEvidence`'s fast (60s) tick writes to `history-store.js` (numeric metrics only,
`metricPointsFromEvidence`); the census+set-diff baseline family reads exclusively from
`fact-store.js`, which is populated only inside `collectStructuralEvidence`'s block on the slower
structural cadence (`DEFAULT_STRUCTURAL_INTERVAL_MS` = 1h by default). Gap 1 rides that same
structural cadence, as an additional sub-collector alongside services/network/scheduled-jobs/
provenance/sessions/vpn-peer-status (today's six) — not a new timer, not a new checkpoint (YAGNI: a
second polling loop is unjustified complexity for v1). Its exact ordinal position depends on
cross-plan landing order — see "resolved must-fix (Fable) — ordinals" in the collision section
below; this plan does not hard-code a number.

**Consequence, stated honestly:** a short-lived exec chain (spawn shell, run one command, exit —
exactly the "deserialize-then-exec" shape TTP #7 describes) that starts and finishes inside one
hourly window is invisible to this detector unless *some* instance of the edge is still alive (or
recurs) at the moment of a poll. This mirrors `service.disappeared`'s own already-accepted "up to
one structural interval of latency" trade-off. An operator who wants tighter coverage for this
specific TTP class can lower `structuralProfile.interval_ms` globally (existing knob, affects all
structural sub-collectors, more `ps`/`systemctl`/plist overhead) — a **process-lineage-specific
faster cadence is out of scope for v1** and is called out as an open question below, not silently
punted.

### New/changed code, by file

#### 1. `tools/descartes-cli/src/tools/processes.js` (new exports; ONE new import)

**Resolved must-fix (Fable) — dedup key vs. persisted entity_key divergence.** `buildLineageEdges`
now imports `buildLineageEntityKey` from `./fact-translators.js` (the plan's one new cross-file
import in this section — every other new export in this file needs zero new imports) and uses it
for the in-tick dedup key. This is the same function `factPointsFromProcessLineageEvidence` (§2)
calls to build the persisted `entity_key`, so the two can never diverge by construction — dedup
identity and fact identity are literally one code path, not two implementations that happen to
agree today.

```js
export const MAX_LINEAGE_EDGES_PER_TICK = 200; // see "Fact-store budget interplay" below for the
  // sizing rationale — matches DEFAULT_SESSION_ENTITY_LIMIT/DEFAULT_PEER_ENTITY_LIMIT exactly,
  // not an independent provisional guess.

export function buildLineageEdges(processes) {
  // pure function: {pid,ppid,command}[] -> deduped edge list
  // - byPid = Map(pid -> process)
  // - for each process: parentComm = byPid.get(process.ppid)?.command ?? "unknown"
  //   (explicit degrade-not-fabricate marker — NEVER assume launchd/init/systemd on a lookup miss)
  // - edgeKey = buildLineageEntityKey(parentComm, process.command) — the SAME composite-key
  //   function §2's factPointsFromProcessLineageEvidence uses for the persisted entity_key (see
  //   resolved must-fix above); dedup via a Set/Map keyed on edgeKey (multiple children of the
  //   same parent+comm collapse to ONE edge — this is a set-membership signal, not a count)
  // - if the deduped edge count exceeds MAX_LINEAGE_EDGES_PER_TICK: truncate deterministically
  //   (sort edges, slice) and return truncated:true — the caller degrades this tick's census_state
  //   to "partial", it never silently drops edges into a "complete" claim
  // returns { edges: [{parent_comm, child_comm}], truncated }
}

export async function collectProcessLineageEvidence() {
  // reuses the EXISTING getProcessSnapshot() — same fixed argv as collectProcessEvidence,
  // inspectProcessEvidence, inspectParentTreeEvidence. Zero new command surface.
  return timedEnvelope(async () => {
    const { processes, command } = await getProcessSnapshot();
    const { edges, truncated } = buildLineageEdges(processes);
    return { edges, edge_count: edges.length, truncated, command };
  }, (result) => evidenceEnvelope({
    id: "process-lineage-edges",
    source: "process_table",
    result,
    tool: "collect_process_lineage",
    target: `edges=${result.edge_count}`,
  }));
}
```

`envelopeStatus`/`reviewHint` follow the same shape `collectScheduledJobsEvidence` already uses:
`warning` + `review_hint: "missing_permission"`-equivalent when `truncated`, `ok` otherwise. Reuse
`evidenceEnvelope`'s existing status inference or add the same tiny `envelopeStatus`-style helper
already present in `scheduled-jobs.js` — do not invent a third convention.

#### 2. `tools/descartes-cli/src/fact-translators.js` (new exports)

`buildLineageEntityKey` (the length-prefixed composite-key function) is specced in full above,
under the resolved separator-collision must-fix — it lives in THIS file (both because
`sanitizeIdentityString` is already imported here and because processes.js needs to import it,
never the reverse; no circular import). The rest of this file's new exports:

```js
export const PROCESS_LINEAGE_EDGE_FACT_NAME = "process.lineage_edge";
export const PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME = "process.lineage_edge.census";
export const PROCESS_LINEAGE_EDGE_CENSUS_MARKER_ENTITY_KEY = "process.lineage_edge.census-marker.v1";

export function factPointsFromProcessLineageEvidence(evidence, { ts } = {}) {
  const envelope = evidence.find((e) => e.id === "process-lineage-edges" && e.status !== "unable");
  if (!envelope) return [];
  const edges = envelope.result?.edges ?? [];

  const points = edges.map((edge) => {
    // buildLineageEntityKey never returns undefined/empty (falls back to "unknown" per segment —
    // see the resolved must-fix above), so unlike the old sanitizeEntityKey(...) call this branch
    // is unreachable in practice; kept only as defense-in-depth, not a real drop path.
    const entityKey = buildLineageEntityKey(edge.parent_comm, edge.child_comm);
    if (!entityKey) return undefined; // unresolvable identity — dropped, never invented
    return {
      ts,
      fact_name: PROCESS_LINEAGE_EDGE_FACT_NAME,
      entity_key: entityKey,
      attributes: {}, // identity is fully carried in entity_key; nothing else needed for detection
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
    };
  }).filter(Boolean);

  // Own fact_name for the marker (never reuses PROCESS_LINEAGE_EDGE_FACT_NAME), confidence:0,
  // emitted on "ok"/"warning" only — same discipline as buildServiceCensusMarkerFactPoint.
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
```

#### 3. `tools/descartes-cli/src/process-lineage-baseline.js` (NEW FILE — sibling of `service-baseline.js`)

Same store shape (atomic tmp+rename 0o600, corrupt-tolerant, `learned/process-lineage-baseline.json`):

```js
{ version: 1, last_folded_ts, skipped_partial_tick_count, novel_edge_event_count }
```

```js
export const PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID = "process.lineage.novel_edge";

// Provisional (mirrors DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT's own "unblock v0, tune
// post-ship" framing) — larger than the service default (3) because spawn-edge diversity on a
// dev/build host is naturally higher than service-unit diversity; needs MORE historical
// tick-groups before an edge's absence-from-history is trustworthy signal rather than noise.
export const DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT = 6;

export const DEFAULT_LINEAGE_FRESHNESS_FALLBACK_MS = 3 * 60 * 60 * 1000; // matches service's 3h fallback

export function groupProcessLineageFactsByTick(points) { /* byte-identical shape to
  groupServiceFactsByTick, discriminating on PROCESS_LINEAGE_EDGE_FACT_NAME vs
  PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME */ }

export function detectNovelProcessLineageEdges(groups = [], options = {}) {
  const { nowMs = Date.now(), freshnessMs = DEFAULT_LINEAGE_FRESHNESS_FALLBACK_MS,
          minHistoryTickCount = DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT } = options;

  const completeGroups = groups.filter((g) => g.censusState === "complete");
  // Cold-start gate: need minHistoryTickCount PRIOR complete groups plus the one being evaluated.
  // Degrade-not-fabricate: a nascent host with too little history makes NO novelty claims at all,
  // rather than treating "no history yet" as "everything is novel" (which would storm on first boot).
  if (completeGroups.length < minHistoryTickCount + 1) return [];

  const latest = completeGroups[completeGroups.length - 1];
  const latestMs = new Date(latest.ts).getTime();
  if (!(nowMs - latestMs <= freshnessMs)) return []; // freshness gate, same as service-baseline

  // Historical set = union of entity_keys across every complete group EXCEPT latest.
  const historical = new Set();
  for (const group of completeGroups.slice(0, -1)) {
    for (const key of group.entityKeys) historical.add(key);
  }

  const novel = [];
  for (const entityKey of latest.entityKeys) {
    if (historical.has(entityKey)) continue; // seen before in the window — established, not novel
    novel.push({ entity_key: entityKey, first_seen_ts: latest.ts });
  }
  return novel;
}

export function buildNovelEdgeCandidates(entries = []) {
  // mirrors buildDisappearedCandidates exactly:
  //  - hashLineageEdgeEntityKey: sha256("process.lineage.novel_edge:" + entityKey).slice(0,16)
  //  - fingerprint/id: HASHED (dedup/edge-trigger keys never cleartext, unconditionally)
  //  - severity: "warning" UNCONDITIONALLY — this is a statistical/heuristic novelty signal with a
  //    real false-positive rate (a new one-off build script is indistinguishable in shape from a
  //    genuine attacker-spawned shell), NOT the near-zero-FP canary-trip signal from the research
  //    doc's §3 (that one earns "critical"; this one explicitly does not — do not conflate them)
  //  - diagnostics: sanitizeDiagnostics({ parent_comm, child_comm, entity_key_hash, first_seen_ts })
  //    — see "Open question: cleartext parent/child names" below before wiring this field
}

export async function computeProcessLineageBaselineCandidates(descartesPaths, options = {}) {
  // byte-identical control flow to computeServiceBaselineCandidates:
  //  1. loadLearnedConfig(...).enabled short-circuit to [] BEFORE any I/O (default-OFF kill switch)
  //  2. readFactPoints(descartesPaths, { windowMs: DEFAULT_BASELINE_FACT_WINDOW_MS, now })
  //  3. groupProcessLineageFactsByTick(points)
  //  4. loadProcessLineageBaselineStore -> persistedState
  //  5. detectNovelProcessLineageEdges(groups, { nowMs, freshnessMs: options.activeFreshnessMs,
  //     minHistoryTickCount })
  //  6. fold-time-only counter increment: skipped_partial_tick_count / novel_edge_event_count
  //     advance ONLY for tick-groups newly observed beyond persistedState.last_folded_ts on THIS
  //     call — never per recomputation. Candidate list is rebuilt fresh from `novel` EVERY call
  //     regardless of whether a store write happened (same re-emission-every-tick contract as
  //     every sibling; alert-store.js's cooldown handles dedup).
  //  7. writeProcessLineageBaselineStore(descartesPaths, nextState) only when newGroups.length > 0
  //  8. return buildNovelEdgeCandidates(novel)
}
```

### Fact-store budget interplay (resolved must-fix, Fable)

`fact-store.js`'s `DEFAULT_FACT_MAX_BYTES` (5MB) is a **single, global, newest-first cap shared
across every fact family** — services, sessions, peers, provenance, and now process-lineage all
write into the same `facts.jsonl`, and once the file exceeds the cap the OLDEST lines are evicted
first regardless of which family they belong to (`fact-store.js` lines ~112–131). A per-tick volume
increase in one family shrinks every other family's effective retention window in tick-count terms,
including gap 1's own `minHistoryTickCount` (6) cold-start gate — this is not hypothetical, it is
how the shared store is built today.

**Sizing, not hand-waving.** The two existing per-tick entity caps that already share this budget
are `DEFAULT_SESSION_ENTITY_LIMIT` and `DEFAULT_PEER_ENTITY_LIMIT` (`sessions.js`/
`vpn-peer-status.js`), both **200 entities/tick**. The original `MAX_LINEAGE_EDGES_PER_TICK = 500`
in this plan's earlier draft was 2.5x either of those with no stated justification beyond
"provisional" — worst case, at ~200 bytes/line for a fact point this shape (`ts`, `fact_name`,
`entity_key`, empty `attributes`, `source_envelope_id`, `source_tool`, `sensitivity`), 500
lineage edges is ~100KB in a single structural tick, which would very nearly double the combined
per-tick write volume of services+sessions+peers+lineage together and correspondingly roughly halve
every family's effective history window inside the shared 5MB cap.

**Resolution:** `MAX_LINEAGE_EDGES_PER_TICK` is lowered to **200**, matching
`DEFAULT_SESSION_ENTITY_LIMIT`/`DEFAULT_PEER_ENTITY_LIMIT` exactly (see the code block above) —
this makes lineage's worst-case per-tick contribution cost-neutral against the two nearest
precedents instead of an independently-chosen multiple of them, and is a considered default rather
than a bare "provisional" placeholder. A healthy host's REAL parent→child comm-pair cardinality is
expected to be far below even this lower cap (a bounded, mostly-repeating set of shells/daemons/
build tools — the same "bounded and mostly-repeating" property `service-baseline.js` leans on, see
above), so 200 is not expected to bind in the common case; it exists as a hard ceiling for the
degenerate case (e.g. a fork-bomb-shaped incident, which is exactly the kind of event this detector
exists to catch) rather than as a cardinality estimate of normal operation.

**Left honestly open, not silently assumed:** this sizing is reasoned from the existing
session/peer precedent, not from a real-host edge-count measurement — mirrors gap 2's own open
question about `job_limit` (80) vs. real host job counts. Added to the "Open questions" list below:
validate `MAX_LINEAGE_EDGES_PER_TICK = 200` against a real host's actual comm-pair cardinality before
or shortly after this ships, and revisit the shared 5MB budget's per-family effective retention math
once lineage is live and contributing real volume (not just gap 1's — the same recon applies once
gap 2's `service.appeared`/`scheduled_job.appeared` and gap 3's credential-access facts, if scoped
through `fact-store.js` at all, add their own volume on top).

### The alert

| Field | Value |
|---|---|
| `rule_id` | `process.lineage.novel_edge` |
| `severity` | `warning` (unconditional hard cap — see rationale above) |
| `title` | "Unexpected process lineage" |
| `summary` | "A process spawn relationship not seen in this host's recent history just appeared." |
| `fingerprint` / `id` | HASHED (`hashLineageEdgeEntityKey`), never cleartext — dedup/edge-trigger keys, unconditional |
| `diagnostics` | `{ entity_key_hash, first_seen_ts }` always; `{ parent_comm, child_comm }` — see open question below |
| `evidence_refs` | `["process-lineage-baseline"]` |

**Open question — cleartext `parent_comm`/`child_comm` in diagnostics/notification body.**
`service.disappeared` got a scoped 2026-07-24 operator exception to show the service name in
cleartext because "which service vanished IS the operational point." The identical argument applies
here even more strongly — a hash-only alert ("edge `a1b2c3d4e5f6` appeared") is nearly useless to an
operator deciding whether to act; they need to see `jruby->bash` or `sshd->curl` to triage. Executable
`comm` names are not raw PII (unlike a session/peer identity). This plan's default recommendation is
to extend the SAME scoped exception to `process.lineage.novel_edge` — but per the existing precedent
("this exception is SCOPED... do not generalize"), that extension needs its own explicit operator
sign-off before `buildNovelEdgeCandidates` ships with cleartext fields, not an inherited default.
Ship the hash-only version first if sign-off isn't available in time; flip the diagnostics field
in a follow-up commit once decided — this does not block the rest of gap 1.

### Exact wiring edits

**`tools/descartes-cli/src/tools/processes.js`** — add `MAX_LINEAGE_EDGES_PER_TICK`,
`buildLineageEdges`, `collectProcessLineageEvidence` (as specced above). One new import:
`buildLineageEntityKey` from `./fact-translators.js` (resolved must-fix above).

**`tools/descartes-cli/src/fact-translators.js`** — add `PROCESS_LINEAGE_EDGE_FACT_NAME`,
`PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME`, `PROCESS_LINEAGE_EDGE_CENSUS_MARKER_ENTITY_KEY`,
`buildLineageEntityKey`, `factPointsFromProcessLineageEvidence`.

**`tools/descartes-cli/src/process-lineage-baseline.js`** — new file, full module as specced above.

**`tools/descartes-cli/src/daemon.js`**:
- import line block (top, alongside the other `./tools/processes.js` and `./fact-translators.js`
  imports): add `collectProcessLineageEvidence` to the `processes.js` import; add
  `factPointsFromProcessLineageEvidence` to the `fact-translators.js` named-import block; add
  `import { computeProcessLineageBaselineCandidates } from "./process-lineage-baseline.js";`
  alongside the `computeServiceBaselineCandidates` import.
- `defaultDaemonProfile()` → `structural.collectors`: add
  `"process-lineage": { enabled: true }` (default true, same rationale every existing sibling
  comment gives: safe because the outer `learned.json` kill switch gates the whole structural tick
  before this sub-collector ever runs).
- `collectStructuralEvidence(...)`: add
  `"process-lineage": collectors["process-lineage"] ?? collectProcessLineageEvidence,` to
  `activeCollectors`, and
  `if (structuralProfile.collectors?.["process-lineage"]?.enabled) evidence.push(await activeCollectors["process-lineage"]());`
  to the push sequence, same shape as every existing sibling. **Resolved must-fix (Fable) —
  dropped ordinal claim:** today's code has six structural sub-collectors
  (services/network/scheduled-jobs/provenance/sessions/vpn-peer-status); this plan does not assert
  gap 1 lands as the "seventh," "eighth," or "ninth" — that number depends entirely on whether
  `tailscale-collector-impl.md`'s `"tailscale-status"` entry and/or
  `deception-canary-collector-impl.md`'s `"canary"` entry (both also 2026-08-11 sibling plans
  targeting this exact same `structural.collectors` object literal) land before or after gap 1. See
  the collision section below for the assumed order; the wiring instruction itself ("add one more
  key to the object, one more line to `activeCollectors`, one more `if` to the push sequence") holds
  regardless of position.
- `runDaemonIteration(...)`'s `factPoints` array: add
  `...factPointsFromProcessLineageEvidence(structuralEvidence, { ts }),` alongside the other five
  `factPointsFromXEvidence` spreads.
- `extraCandidates` array inside the `evaluateAndPersistAlerts` call: add
  `...await computeProcessLineageBaselineCandidates(descartesPaths, { ...options, activeFreshnessMs }),`
  threading the same `activeFreshnessMs` every sibling already threads. **Resolved must-fix
  (Fable) — dropped ordinal claim:** today's code has seven `extraCandidates` entries (constraint,
  provenance-warning, provenance-identity, session-baseline, correlation, peer-baseline,
  service-baseline — the last one's own comment literally says "seventh"); this plan does not
  assert gap 1 lands as the "eighth" or "ninth" entry, since
  `deception-canary-collector-impl.md`'s `computeCanaryBaselineCandidates` addition (also explicitly
  labeled "an eighth entry" in that plan) targets the identical array literal. Both plans cannot
  both be "the eighth entry" — see the sequencing requirement in the collision section below for
  the assumed landing order this ambiguity resolves to.

**`tools/descartes-cli/src/alert-intelligence.js`**:
- import `PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID` from `./process-lineage-baseline.js`.
- add it to `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (composed locally in this file — do NOT
  widen `session-baseline.js`'s own export, same discipline the file's header comment already
  states for every prior addition).
- add a new branch to `buildSessionAlertNotificationDecision` for
  `PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID`: `title: "Descartes: unexpected process lineage"`, body per
  the cleartext-vs-hash open question above (ship the hash-only body — `` `Novel process spawn edge ${diagnostics.entity_key_hash} appeared.` `` — if sign-off is pending; switch to naming `parent_comm`/`child_comm` once decided).
- **No edit needed to `classifyAlertNamespace`** — `process.lineage.novel_edge` does not start with
  any reserved prefix (`learned.`/`daemon.`/`system.`/`disk.`/`constraint.`/`provenance.`/
  `baseline.`/`identity.`/`correlation.`), so it classifies as `unknown_namespace` automatically and
  can structurally never reach LLM adjudication. **Verified by inspection; pin it with a test** (see
  test plan) rather than trusting the prefix scheme to hold by inspection alone forever.

**`tools/descartes-cli/src/calibration.js`**:
- import `PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID` from `./process-lineage-baseline.js`.
- add it to `CLOSED_RULE_IDS` (parity with `SESSION_CHURN_RULE_ID`/`PEER_COUNT_SPIKE_RULE_ID`, both
  of which ARE in this set today). Note in the commit message: `SERVICE_DISAPPEARED_RULE_ID` is
  conspicuously **absent** from `CLOSED_RULE_IDS` today — this looks like a pre-existing gap in the
  shipped code, not a precedent to copy. Do not silently omit the new rule_id to match it; flag the
  `service.disappeared` omission as a separate one-line follow-up if confirmed to be a bug, out of
  scope for this plan to fix.

**`learned.json` / `constraint-store.js`** — no schema change. Reuses the existing global `enabled`
boolean kill switch exactly like every sibling baseline (default OFF at the top level; this plan
ships nothing that flips that default).

### Test plan (fixture-driven, node:test, mirrors `test/service-baseline.test.js`/`test/processes.test.js`)

New file `test/process-lineage-baseline.test.js`, structured like `test/service-baseline.test.js`
(helper builders `tickTs`, `lineagePoint`, `censusMarkerPoint`, `completeTick`/`partialTick`,
`flatten`, `establishedTicks`, `seedAndCompute`, `expectedHash` — same names/shapes, new domain):

- `groupProcessLineageFactsByTick` — complete/partial/unknown/markerless tick-group dispositions,
  byte-parity with `groupServiceFactsByTick`'s own test table.
- `detectNovelProcessLineageEdges`:
  - cold-start: fewer than `minHistoryTickCount + 1` complete groups → `[]`.
  - genuinely novel edge in latest, absent from every prior complete group → fires.
  - edge present in ANY prior complete group (even just one, even several ticks back) → does NOT
    fire (established, no re-alert).
  - partial/unknown/markerless tick-groups excluded wholesale from both the historical-set union
    and the latest-group comparison (degrade-not-fabricate).
  - freshness gate: stale latest-complete group → `[]`.
  - self-resolving: an edge that fires on tick N is absent from the candidate list on tick N+1
    (once tick N itself ages into the "except latest" historical slice).
- `buildNovelEdgeCandidates` — hashed fingerprint/id stability across calls, `severity` always
  `"warning"` regardless of input, diagnostics shape/sanitization.
- `computeProcessLineageBaselineCandidates`:
  - `learned.json` disabled → `[]`, asserting **zero calls** into `readFactPoints`/
    `loadProcessLineageBaselineStore` (mirrors service-baseline's own "checked before ANY I/O" test
    via injected spies).
  - fold-time-only counter semantics: repeated calls against the SAME tick-group window increment
    `novel_edge_event_count`/`skipped_partial_tick_count` exactly once, not once per call.
  - end-to-end via `seedAndCompute`: seed N established ticks with edge set A, one more tick adds
    edge B → exactly one candidate for B, none for A.

**Resolved must-fix (Fable) — no such injection point exists.** An earlier draft of this plan
claimed `collectProcessLineageEvidence` would be unit-tested via "the SAME `getProcessSnapshot`
injection point the existing `collectProcessEvidence`/`inspectProcessEvidence` tests already use."
Checked directly: `test/processes.test.js` today tests only pure functions
(`psArgsForPlatform`, `redactAndBoundProcessArgs`, `parsePs`, `buildInspectProcessResult`,
`buildParentTreeResult`) — it contains **zero** references to `getProcessSnapshot`,
`collectProcessEvidence`, `inspectProcessEvidence`, or `inspectParentTreeEvidence`.
`getProcessSnapshot` itself is a module-private (non-exported) function in
`tools/processes.js` with no options-based injection seam at all; none of the three existing
`collectXEvidence`-shaped consumers of it are unit-tested at that layer today — this is the
established pattern in this codebase (`collectServiceEvidence`/`collectScheduledJobsEvidence` are
likewise not directly unit-tested with a mocked shell-out; only their pure parsing/building
helpers are), not an oversight specific to `processes.js`. The "same mock covers it / zero new
command surface by construction" claim in the original test plan therefore had no actual seam to
attach to and is dropped. Fix, following the codebase's own established convention (option (b) of
the finding) rather than inventing a new injectable-parameter convention this file's siblings don't
use:

New tests appended to `test/processes.test.js` — **pure-function coverage only**:
- `buildLineageEdges` — normal edges; missing-parent lookup → `parent_comm: "unknown"`; dedup
  (multiple children sharing a parent+comm pair collapse to one edge, via `buildLineageEntityKey` —
  see resolved must-fix above); cap/truncation at `MAX_LINEAGE_EDGES_PER_TICK` sets
  `truncated: true` deterministically; empty process list → `[]`. This is the ONLY new
  `processes.js` export this plan unit-tests directly, matching how `parsePs`/
  `buildInspectProcessResult`/`buildParentTreeResult` are the ONLY existing exports tested there
  today (the `collectXEvidence` wrapper functions themselves are not).

`collectProcessLineageEvidence`'s own wiring (that it calls `getProcessSnapshot`, builds an
envelope, and surfaces `edge_count`/`truncated` correctly) is instead covered at the **daemon
integration layer**, via the injectable-collectors seam `test/daemon.test.js` already has and
already uses for every sibling structural collector (`structuralCollectorFakes(calls)`,
consumed by `collectStructuralEvidence(profile, collectors)` — see `test/daemon.test.js`
`"collectStructuralEvidence calls only enabled structural collectors in a stable order"` for the
existing pattern this plan's own daemon-integration tests, listed below, extend with a
`"process-lineage"` fake). This is a real, already-existing seam — not a mock this plan has to
invent — and matches where `collectServiceEvidence`/`collectScheduledJobsEvidence` wiring is
actually verified today (at `collectStructuralEvidence`'s injection boundary, not inside
`services.js`'s/`scheduled-jobs.js`'s own test files).

New tests appended to `test/fact-translators.test.js` (or wherever `factPointsFromServiceEvidence`
is tested — mirror that file's structure exactly):
- envelope missing/`status:"unable"` → `[]`.
- `status:"ok"`/`"warning"` → one fact point per deduped edge + exactly one census marker,
  `confidence: 0` on the marker, correct `census_state` from `result.truncated`.
- `status:"unknown"`/unsupported → no marker emitted (collector never ran a real census).
- unresolvable/empty-string entity key → dropped, never a fabricated fact point.

Integration touches:
- `test/daemon.test.js` — assert `"process-lineage"` present in `defaultDaemonProfile().structural.collectors`
  with `enabled: true`; assert it appears in `collectStructuralEvidence`'s evidence array when
  enabled; assert `computeProcessLineageBaselineCandidates`'s candidates flow into
  `evaluateAndPersistAlerts`'s output via injected-collector + injected-compute-function spies
  (same injection pattern the file already uses for `computeServiceBaselineCandidates`).
- `test/alert-intelligence.test.js` — **fail-closed pin test**: assert
  `classifyAlertNamespace(PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID)` returns `{ namespace: undefined, hardExcluded: false }`
  (i.e. `unknown_namespace`, structurally ineligible for LLM adjudication regardless of
  `enabled_namespaces` config) — this is the safety invariant, pin it explicitly rather than relying
  on prefix-scheme inspection. Assert `PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID` IS in
  `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` and that `emitSessionAlertSignals` delivers a due
  candidate through the deterministic (non-LLM) path.
- `test/calibration.test.js` — assert the rule_id is attributed correctly in
  `computeCalibrationReport`'s fired-count/family grouping (mirrors the existing
  `SESSION_CHURN_RULE_ID`/`PEER_COUNT_SPIKE_RULE_ID` calibration test cases).

All fixtures are synthetic in-memory fact points / process-row arrays constructed directly by test
helpers — **no real `ps` invocation, no VM** (this dev machine cannot run VMs; every existing
sibling test in this codebase already follows this discipline and this plan does not deviate).

### What gap 1 explicitly does NOT do

- Does not catch a spawn edge that starts and fully exits within one structural interval unless
  some instance recurs across a poll boundary (stated cadence trade-off above).
- Does not fingerprint by command-line arguments, only by executable short-name — a `comm`-identical
  edge with a malicious argv is invisible to this detector (that's `inspect_process`'s job, on
  operator/L2-triggered demand, not this baseline's).
- Does not re-alert on a *recurrence* of a previously-novel edge once it has aged into the
  established historical window — v1 catches first-appearance only.
- Does not touch `provenance-elevated.js`/privesc detection, outbound-connection visibility, or any
  cloud/cluster control-plane signal (all explicitly out of scope per the research doc's §2.0 scope
  box).
- No new `execFile`/shell surface: reuses `getProcessSnapshot()`'s existing fixed `ps` argv, the
  same command already approved for `collect_processes`/`inspect_process`/`inspect_parent_tree`.

---

## Gap 2 — persistence baseline ("a new service / scheduled job appeared") — FOLLOW-ON, specced not built

### Shape

Two sub-parts, both mirroring the same set-diff pattern but **inverted relative to
`service.disappeared`** (fire on first-appearance-in-latest, not on absence-from-latest) — the
identical inversion gap 1 already implements, so gap 2's detector logic can largely reuse gap 1's
`detectNovelProcessLineageEdges` SHAPE (generalize it, or copy-and-adapt; do not prematurely
abstract a shared "novelty set-diff" helper until a third consumer exists — YAGNI).

**2a. `service.appeared`.** Reuses the EXISTING `service.presence`/`service.census` facts
`service-baseline.js` already reads — no new collector, no new fact translator. Add
`detectServiceAppearances`/`buildAppearedCandidates`/`computeServiceAppearanceCandidates` to
`service-baseline.js` itself (natural home: it already owns the grouped facts). Rule_id:
`service.appeared`, severity `warning` (mirrors `service.disappeared`'s own hard cap).

**2b. `scheduled_job.appeared`.** `scheduled-jobs.js` (`collectScheduledJobsEvidence`) is already
wired into `collectStructuralEvidence` (structural sub-collector #3, `enabled: true` by default)
but has **zero fact-store wiring today** — this is the actual blind spot the todo names. Needed
before any baseline can exist:
- A NEW `factPointsFromScheduledJobsEvidence` in `fact-translators.js`. Scheduled jobs are
  heterogeneous (`cron`/`systemd_timer`/`launchd_scheduled_job`/`periodic_directory_entry` — no
  single uniform "name" field, grounded against `parseCronScheduleLine`/`parseSystemctlListTimers`/
  `parseLaunchdPlistObject`'s actual shapes). Entity key must be a composite:
  `sanitizeEntityKey(`${job.kind}:${job.source}:${job.label ?? job.unit ?? job.path}`)`.
- A NEW census marker (`scheduled_job.census`), `census_state` derived from
  `result.summary.unavailable_count === 0` AND `total_count === returned_count` (the collector's
  own `selectScheduledJobsFairly` silently caps at `job_limit` — a `total_count > returned_count`
  tick MUST classify `"partial"`, exactly like `service.js`'s `truncated` flag; this is a real,
  easy-to-miss correctness trap for whoever picks this up — the marker must read BOTH
  `unavailable_count` and the total-vs-returned gap, not just one).
- Then a `persistence-baseline.js` (new file) housing `detectScheduledJobAppearances`/
  `buildScheduledJobAppearedCandidates`/`computeScheduledJobBaselineCandidates`, same shape as
  gap 1. Rule_id: `scheduled_job.appeared`, severity `warning`.

### Wiring touchpoints (same shared seam files as gap 1 — see collision note below)
`daemon.js` (`factPointsFromScheduledJobsEvidence` added to the structural fact-points array;
`computeServiceAppearanceCandidates`/`computeScheduledJobBaselineCandidates` added to
`extraCandidates`), `alert-intelligence.js` (`ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` +
notification-body branches for both new rule_ids), `calibration.js` (`CLOSED_RULE_IDS`).

### Open questions to resolve before implementing gap 2
- Cleartext vs. hash-only diagnostics for `service.appeared`/`scheduled_job.appeared` — same
  question as gap 1, needs its own explicit sign-off (a NEW service/job appearing is arguably an
  even stronger "operator needs the name to act" case than disappearance).
- `job_limit` default (80) vs. real host job counts — does the fairness-bucketed truncation make
  `"partial"` the common case on hosts with many periodic-directory entries, starving the detector
  of `"complete"` tick-groups to compare? Needs a quick recon pass against a real host's job count
  before committing to the default cold-start gate value.

---

## Gap 3 — credential-file-access signal — FOLLOW-ON, specced not built

### Shape

Structurally **different** from gaps 1/2: not a periodic-census set-diff over many entities, but a
small, FIXED set of real, already-existing credential paths (`~/.ssh/id_*`, `~/.aws/credentials`,
`~/.config/gcloud/*`, `~/.npmrc`, etc. — existence-gated, never fabricating an `lstat` on a path this
host doesn't have), each `lstat`-diffed against a persisted `{atime, mtime, ino}` baseline. This is
the **same design already fully sketched** in
`docs/research/2026-08-11-agentic-intrusion-defense.md` §3.3 (the canary-collector v0 sketch,
Components 2–3: poll-based `lstat`, atomic-write baseline store, edge-triggered stat-diff) — applied
to REAL credential paths instead of planted decoys, per the todo's own framing ("overlaps with the
canary tier... but for REAL credential paths").

**Sequencing recommendation:** `todos/2026-08-11-deception-canary-collector.md` should land FIRST.
Its `lstat`-diff primitive (whatever shape Components 2–3 take when implemented) is directly
reusable here — gap 3's real-credential module should be a sibling consumer of the SAME stat-diff
helper, not a second independent implementation of atime/mtime baseline logic. If canary lands
first, extract the shared primitive then; do not block gap 3 on canary, but do not duplicate the
logic either if canary is already in flight.

### Key differences from the canary tier (why this is NOT copy-paste)
- **Real files, real false-positive rate.** Unlike a decoy nobody has legitimate reason to touch, a
  real `~/.ssh/id_ed25519` IS legitimately read by `ssh`/`git`/agent-forwarding routinely. Severity
  must be `warning`, not the canary tier's `critical` — this is explicitly the todo's own
  "overlaps... but" caveat, not an oversight.
- **Metadata-only, never content.** The collector must `lstat` only — it must never `readFile` the
  contents of a credential path. This is a stronger, more explicit invariant than
  `scheduled-jobs.js`'s own file reads (which read job DEFINITIONS, not secrets) and should be
  stated as a standalone safety invariant in that slice's own plan, not inherited implicitly.
- **`atime` unreliability, stated honestly.** `relatime`/`noatime` mounts blunt atime as a signal —
  the research doc's own §3.3 "atime caveat" note applies verbatim; lean on `mtime`-change detection
  (a credential file being REWRITTEN is a stronger and more reliable signal than being read) as the
  primary trigger, with atime as best-effort supplementary evidence only.
- **Path sanitization for diagnostics.** A raw filesystem path can embed a username/home-directory
  detail. Diagnostics should carry a closed-enum PATH CATEGORY (`ssh_private_key`,
  `aws_credentials`, `npmrc_token`, …), not the literal path; hash the literal path for
  fingerprint/dedup only.

### Wiring touchpoints (same shared seam files as gaps 1/2 — see collision note below)
Same three seam files, plus a NEW small state file (`learned/credential-access-baseline.json`),
plus (unlike gaps 1/2) this one plausibly does NOT need `fact-store.js`/census-marker machinery at
all — a per-path `{atime, mtime, ino}` baseline is closer to `peer-signature-store.js`'s
domain-specific store shape than to the generic fact-point census pattern. Confirm this scoping
decision during that slice's own tight-plan pass rather than assuming fact-store reuse by default.

### Open questions to resolve before implementing gap 3
- Fixed code-defined path list (v1, YAGNI) vs. the canary manifest's operator-authored config
  approach (§3.3 Component 1) — recommend fixed list for v1 to avoid shipping a second
  XDG-config-manifest format before the canary tier's own manifest format is proven.
- Does this land as its own `credential-access-baseline.js`, or as a generalization once the canary
  collector's stat-diff primitive exists? Depends on canary sequencing (see above).

---

## COLLISION-WITH-SHARED-ALERT-PIPELINE — Phase-2 sequencing (read before dispatching gaps 2/3)

Gaps 1, 2, and 3 all append to the **identical seam points** in the **identical four files**
(**resolved must-fix (Fable) — `fact-translators.js` was missing from this list**; it is a real,
independently-editable collision surface, not folded into the `daemon.js` entry, since two
plans can each add a NEW named export to it without touching each other's export but still produce
a textual merge conflict if both insert near the same location or both need the same import
ordering — see the sibling-plan list below for concrete cases):

1. `daemon.js` — the `extraCandidates` array literal inside `runDaemonIteration`'s
   `evaluateAndPersistAlerts` call, and (for gaps 1/2) `collectStructuralEvidence`'s
   `activeCollectors` object + push sequence + `defaultDaemonProfile().structural.collectors`.
2. `fact-translators.js` — each gap/sibling adds its own new `factPointsFromXEvidence` translator
   (and, where applicable, its own census-marker constants) as an additive block; low
   per-plan textual conflict risk (each plan's addition is a self-contained new export) but a real
   ordering/merge-base hazard when two plans' additive blocks are drafted against the same stale
   snapshot of the file, same as the array literals below.
3. `alert-intelligence.js` — the `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` array literal, and the
   `if (alert?.rule_id === ...)` chain inside `buildSessionAlertNotificationDecision`.
4. `calibration.js` — the `CLOSED_RULE_IDS` set literal.

Every one of these is a **single array/object literal with one entry appended per rule_id** — the
exact shape `plan-before-dispatch`'s own trigger warns about (parallel edits to the same literal
racing/silently overwriting each other, or landing with only some entries present because two
agents each based their edit on a stale pre-edit copy of the file).

**Resolved must-fix (Fable) — collision list was incomplete.** The collision was originally scoped
to only this plan's own three internal gaps. Checked directly against the other 2026-08-11 plans in
`docs/plans/`: three sibling plans, drafted concurrently, touch these SAME seam points:

- **`docs/plans/2026-08-11-tailscale-collector-impl.md`** — adds `"tailscale-status"` to
  `defaultDaemonProfile().structural.collectors`, to `collectStructuralEvidence`'s
  `activeCollectors`, and to its push sequence (seam 1's structural-collector half only).
  Explicitly adds **zero** new `extraCandidates` entries and **zero** new rule_ids (pure L0 fact
  source, no alerting in v1 — stated in that plan's own text) — so it does NOT touch
  `extraCandidates`, `alert-intelligence.js`, or `calibration.js`. Lowest collision footprint of
  the three siblings.
- **`docs/plans/2026-08-11-apple-container-collector-impl.md`** — its Phase 1 (the part actually
  being built now) is confirmed by that plan's own direct `ast-grep`/`grep` check to touch **zero**
  of `daemon.js`/`fact-translators.js`/`alert-intelligence.js`/`calibration.js` — no current
  collision. A hypothetical future Phase 2 (not in scope, not scheduled) would add a
  `container.disappeared`-style `extraCandidates` entry and a `factPointsFromContainerEvidence`
  translator; that plan already flags this itself and is out of scope for this collision note until
  Phase 2 is actually picked up.
- **`docs/plans/2026-08-11-deception-canary-collector-impl.md`** — collides on FOUR of gap 1's five
  seam points: adds a seventh `structural.collectors` entry (`"canary"`) + `activeCollectors` +
  push sequence, an eighth `extraCandidates` entry (`computeCanaryBaselineCandidates`), a new
  `fact-translators.js` translator (`factPointsFromCanaryEvidence`, `canary.census`), and its own
  `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` entry in `alert-intelligence.js`. It explicitly does
  **not** touch `calibration.js`'s `CLOSED_RULE_IDS` (that plan's own §2.3 leaves `canary.tripped`
  out of calibration for its first cut, by the same precedent this plan's own daemon.js wiring
  section notes `service.disappeared` already sets) — so the `calibration.js` seam is NOT a
  collision with this plan's gap 1, only `daemon.js` (both sub-seams) and `alert-intelligence.js`
  are.

All four plans (this one plus the three named above) were drafted against the SAME starting
snapshot of the code (six structural sub-collectors today, seven `extraCandidates` entries today)
and each independently numbers its own addition as if it will land alone — which is exactly the
inconsistency the dropped "eighth"/"ninth" ordinal claims elsewhere in this plan were symptomatic
of (see the two "Resolved must-fix (Fable) — dropped ordinal claim" notes under "Exact wiring
edits" above). None of the four plans' stated ordinals can all be correct simultaneously.

**Assumed cross-plan landing order (recommendation, not an operator-confirmed sequence — reconfirm
against the live file state immediately before any dispatch):**

1. **Gap 1 (this plan)** first — highest-value gap per this plan's own header framing, and the
   plan with the most fully-specced detail of the four, so the least design risk in landing it
   first.
2. **`tailscale-collector-impl.md`** second — touches only the structural-collector seam (no
   `extraCandidates`, no `alert-intelligence.js`/`calibration.js`), the smallest surface of the
   remaining three, so it can slot in immediately after gap 1 with minimal rebase risk.
3. **`deception-canary-collector-impl.md`** third — the full-collision sibling; landing it last
   means its `structural.collectors`/`extraCandidates` additions are based on a working tree that
   already includes both gap 1's and tailscale's edits, avoiding a three-way conflict.
4. **`apple-container-collector-impl.md`** Phase 1 has no ordering constraint relative to the other
   three (confirmed zero collision) and can land at any point in this sequence, including in
   parallel with any of the above.
5. **Gaps 2 and 3 (this plan's own follow-ons)** land after all of the above, per the original
   sequencing requirement below — they were drafted with full knowledge of gap 1's shape and
   should target whatever the seam files look like once 1–3 above have landed.

**Sequencing requirement:** implement and land gap 1 FIRST, as its own atomic commit (or small
commit series) touching these four files, and get it merged/committed before gap 2's or gap 3's
edits to the SAME four files begin. Do not dispatch gaps 2 and 3 as parallel agents/worktrees
against `main` concurrently with each other either, for the same reason — serialize all three:
**gap 1 → gap 2 → gap 3**, each fully landed before the next's seam-file edits start. Do not
dispatch gap 1 concurrently with `tailscale-collector-impl.md` or `deception-canary-collector-impl.md`
either, for the identical reason — follow the assumed order above (or an explicitly re-confirmed
alternative) for all four plans, not just this one's internal three gaps. This is a process
constraint on HOW this plan gets executed, not a code change.

---

## Safety invariants preserved (all three gaps)

- **Read-only.** No new mutating verb anywhere in any of the three gaps. Gap 1 adds zero new
  `execFile` calls (reuses `getProcessSnapshot`). Gap 2 adds zero new `execFile` calls beyond what
  `scheduled-jobs.js`/`services.js` already run. Gap 3 is `fs.lstat`-only, strictly smaller surface
  than `scheduled-jobs.js`'s own file reads (no `readFile` of credential contents, ever).
- **Bounded.** `MAX_LINEAGE_EDGES_PER_TICK` caps gap 1's per-tick cardinality with an explicit
  `truncated`/`"partial"` degrade path, mirroring every existing overflow-marker precedent
  (`SESSION_OVERFLOW_ENTITY_KEY`/`PEER_OVERFLOW_ENTITY_KEY`). Gap 2 inherits `scheduled-jobs.js`'s
  existing `job_limit` bound. Gap 3's path list is a small fixed set by design.
- **Evidence-envelope-shaped.** Gap 1's new collector output goes through the same
  `evidenceEnvelope`/`timedEnvelope` helpers every existing tool uses; no bespoke result shape.
- **Default-OFF behind `learned.json`.** All three gaps' candidate-computation entry points check
  `loadLearnedConfig(...).enabled` and short-circuit to `[]` before any I/O, exactly like every
  shipped baseline sibling. Collector-level `structural.collectors.X.enabled` flags default `true`
  (safe, because the outer `learned.json` kill switch gates the entire structural tick before any
  sub-collector runs) — this is the SAME two-gate pattern every existing structural sub-collector
  already uses, not a new convention.
- **Deterministic, NO-LLM alert path.** New rule_ids (`process.lineage.novel_edge`,
  `service.appeared`, `scheduled_job.appeared`, `credential.file_access`) all use prefixes absent
  from `classifyAlertNamespace`'s reserved list, so they classify as `unknown_namespace` and are
  structurally unreachable by LLM adjudication regardless of `enabled_namespaces` config — verified
  by inspection for gap 1, pinned by an explicit test (see test plan), and the SAME verification
  step is required for gaps 2/3's chosen rule_ids before they ship.
- **Fail-closed alert namespace.** None of the three gaps' rule_ids are ever added to
  `KNOWN_ALERT_NAMESPACES` or given a `PROMPT_TEMPLATES` entry — they reach the operator ONLY
  through the deterministic `emitSessionAlertSignals`/`ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS`
  path, never through `adjudicateAlertNotifications`.
- **Degrade-not-fabricate.** Every detector returns `[]` on insufficient/partial/stale evidence
  rather than guessing: cold-start gates (gap 1's `minHistoryTickCount`, gap 2's established-count
  gates), `"partial"`/`"unknown"` census states excluded wholesale from comparison, freshness gates
  on the latest complete tick-group, `lstat` read errors on a gap-3 canary path degrading to
  no-claim rather than fabricating a trip.
- **Hash/bucket identity at source.** `fingerprint`/`id` stay HASHED unconditionally across all
  three gaps (never cleartext) — only the DISPLAYED diagnostics fields are candidates for the
  scoped cleartext exception, and only after an explicit operator decision per gap, mirroring the
  2026-07-24 `service.disappeared` precedent rather than assuming it generalizes.
- **Honest single-host-edge scope.** None of the three gaps claim coverage of anything the research
  doc's §2.0 scope box already marks OUT-OF-SCOPE (cloud IAM, Kubernetes RBAC, cluster velocity,
  outbound/ESTABLISHED-connection visibility). All three stay strictly inside "this host's own
  process table / service+job census / filesystem metadata."

## Known limitation — cross-detector history-completeness (fact-store corruption/retention)

**Status: design-only, NOT fixed here.** Discovered 2026-08-12 while closing a BOUNDED fabrication
gap in `process-lineage-baseline.js` (a corrupt/missing persisted baseline store used to
self-heal-and-immediately-fire instead of forcing a persistent cold-start re-accumulation — fixed
in that file: `cold_start_pending`/`_reason`/`_since_ts` now survive across ticks until
`minHistoryTickCount` genuinely new complete ticks have re-accumulated). That fix closes the
baseline-store-level exposure. It does **not** close a related, structurally deeper exposure one
layer down, in `fact-store.js` itself — and this is a CROSS-DETECTOR class of gap, not specific to
process-lineage, so it needs its own dedicated design pass rather than a per-detector patch.

**The gap:** `fact-store.js`'s `readJsonLines` (consumed by `readFactPoints`) drops any
unparseable JSONL line *before* returning, reporting only a `corrupt_count` alongside the
survivors. Separately, `enforceFactRetention` (called at the end of every `appendFactPoints`)
rewrites `facts.jsonl` to only the records inside the retention window / byte budget, silently
dropping everything else — including any corrupt lines it encountered on ITS OWN read of the file
(`corrupt_dropped_count` is returned to the caller of `enforceFactRetention`, but that caller is
whatever just appended new points, not the next detector to read the file; the signal does not
travel forward). The net effect: by the time any detector calls `readFactPoints` for its own tick,
the file it reads may already have been silently shortened by a PRIOR write's retention pass, with
no `corrupt_count` at all on the read that matters (`corrupt_count:0`) — the detector has no way to
tell "genuinely zero corruption ever" apart from "corruption already happened and was already
compacted away by retention." A `corrupt_count:0` read is therefore not proof of a complete
history; it only proves the CURRENT read had no unparseable lines, which is a weaker claim than
every consuming detector's cold-start/established-count logic implicitly relies on.

Separately, `readFactPoints` re-validates each surviving record through `normalizeFactPoint` and
silently `.filter(Boolean)`-drops any that are parseable JSON but fail the fact-point schema (e.g.
missing `fact_name`/`entity_key`) — with zero count, zero signal, not even folded into
`corrupt_count`. This is a second, currently completely invisible, silent-truncation path.

**Why this matters across detectors, not just process-lineage:** every novelty/baseline detector
that reconstructs its "historical" set by re-reading the live fact-store window on each tick shares
this exposure, because none of them can distinguish "this window is the complete, un-truncated
history" from "retention/corruption already quietly shortened it, dropping exactly the older
tick(s) that would have shown some entity/edge/session as already established." A silently
shortened history makes a perfectly normal, long-standing fact look novel — the identical
fabrication shape the BOUNDED fix above closes, but at the fact-store layer instead of the
baseline-store layer, and not something any single detector's baseline-store fix can close on its
own. Affected/exposed today: `process-lineage-baseline.js` (novel-edge), `service-baseline.js`
(disappearance), `session-baseline.js` (churn/count-drop), `peer-baseline.js`
(count-spike/count-drop), and the deception-canary detector family — every reader of
`readFactPoints`.

**Why not fixed here:** this is a fact-store-layer contract change (readers need a
"was-this-history-truncated" signal that survives past a single `readFactPoints` call, and
retention needs to either preserve or forward its own drop signal to future readers, not just the
immediate writer) — it needs a dedicated design pass across every consumer, not a bolt-on inside
one detector. Scope-bounding it out of this pass keeps the process-lineage fix reviewable and
avoids a half-migrated fact-store contract landing underneath detectors that haven't been updated
to use it yet.

**Follow-on needed:** a dedicated `fact-store-completeness` design (new todo/plan) that gives
`readFactPoints` (or a wrapping helper) a way to report "this window may be missing data due to
past corruption/retention, not just this read's own corrupt_count" — likely a persisted
high-water-mark of retention/corruption events in `fact-store.js`'s own state, surfaced to every
caller — so a detector can fail closed (cold-start, same shape as the fix above) instead of
fabricating novelty from a silently-shortened window. Until that lands, every detector in the list
above remains exposed to this exact class of fabrication, independent of any per-detector
baseline-store hardening.

**Related host-local limit (schema-valid store forgery):** even with `process-lineage-baseline.js`'s
`isValidProcessLineageBaselineStoreShape` now exact-schema (rejecting missing/foreign/out-of-range
fields into cold-start), a root-capable local attacker who WRITES a crafted, schema-valid baseline
store on the host can suppress this detector's cold-start (or otherwise seed its state) — this is
an INHERENT host-local limit (the store is the attacker's own file to write), the same class of
exposure as the cross-detector fact-store completeness gap above, and is addressed by the
fleet/dead-man's-switch layer, not by any within-collector fix.

## Open questions (repeated from above, collected)

1. Cleartext vs. hash-only `parent_comm`/`child_comm` in gap 1's diagnostics/notification body —
   needs an explicit operator decision before that field ships (default: ship hash-only first,
   flip in a follow-up once decided).
2. Same cleartext-vs-hash question for gap 2's `service.appeared`/`scheduled_job.appeared`.
3. Gap 2: does `scheduled-jobs.js`'s `job_limit` (80) truncate often enough on real hosts to starve
   the detector of `"complete"` tick-groups? Needs a quick recon pass before committing to defaults.
4. Gap 3: sequence after or alongside `todos/2026-08-11-deception-canary-collector.md`? Recommend
   after, to reuse its stat-diff primitive rather than duplicating it — confirm when that todo is
   picked up.
5. Gap 1: is a process-lineage-specific faster-than-structural cadence worth the added
   timer/checkpoint complexity in a later iteration, given the "misses sub-hour ephemeral exec
   chains" honesty caveat? Explicitly deferred, not silently dropped.
6. Gap 1 (added resolving Fable's fact-store-budget must-fix): `MAX_LINEAGE_EDGES_PER_TICK = 200`
   is sized by precedent (matches `DEFAULT_SESSION_ENTITY_LIMIT`/`DEFAULT_PEER_ENTITY_LIMIT`), not
   by a real-host comm-pair-cardinality measurement — validate against actual hosts once gap 1 is
   live, and revisit the shared `DEFAULT_FACT_MAX_BYTES` (5MB) per-family effective-retention math
   once lineage (and later gap 2/3, if they also write through `fact-store.js`) are contributing
   real volume alongside services/sessions/peers. See "Fact-store budget interplay" under gap 1.
