# Deception / canary collector — implementation plan (Slice 7.1)

**Created:** 2026-08-11
**Purpose:** implement the `canary` L0 collector + `canary.tripped` deterministic alert designed in
`docs/research/2026-08-11-agentic-intrusion-defense.md` §3 — an inert, fs-only honey-token/decoy
detector that plants no state itself (planting is an out-of-band operator action), mutates nothing
on the host, needs no `execFile`/privilege surface, and slots into the same
`extraCandidates`/`evaluateAndPersistAlerts` merge seam every prior deterministic alert (session,
peer, service.disappeared) already uses. This is the "defend/repel below containment" rung of the
response ladder — shippable without the Slice-7 authority/containment plane.
**Todo:** `todos/2026-08-11-deception-canary-collector.md`
**Status:** DRAFT — not yet implemented.
**Reviewed:** 2026-08-11 (Fable + gpt-5.6-sol) — Fable GO_WITH_CHANGES (4 must-fixes, all folded
below as design changes); sol UNAVAILABLE (no review produced, nothing to fold).
**Addendum:** 2026-08-12 — two must-close findings on the (uncommitted) canary collector fixed:
FIX-A (identity binding: `canary_id` alone is not enough to gate the baseline/trip comparison — a
manifest path/sentinel_path edit or a canary_id reused for a different file could fabricate a trip;
now bound to `canary_id` + `tools/canary.js`'s hashed `identity_fingerprint`) and FIX-B (a
deterministic alert-delivery I/O failure inside `emitSessionAlertSignals` — a pre-existing general
pattern shared by every rule_id in that loop, not canary-specific — could abort the entire daemon
tick; now degrades per-alert instead). See "Known v0 limitations" below for the residual,
inherent, fleet-addressed gaps recorded alongside this pass.

---

## 0. Scope discipline (YAGNI)

In scope for v0:
- Filesystem-observable canaries only: credential-file, scheduled-job/persistence, SUID-binary,
  sudoers-entry, writable-directory decoys. Detection signals: `atime` advance, `mtime` change,
  execution-sentinel trip.
- One new alert, `canary.tripped`, severity **critical**, unconditional (no tiering).
- Manifest is **hand-authored JSON**, loaded read-only. No `descartes canary ...` CLI, no
  plant/remove/verify tooling, no writer for the manifest file.

Explicitly OUT of scope for v0 (name it, don't build it):
- **Any listening decoy (socket/service).** Standing up and maintaining a live listener is new
  attack surface and a mutating action — it fails the fs-only, "mutates nothing on the host"
  invariant this whole slice exists to preserve. Deferred to its own future slice with its own
  doors-and-corners pass (§3.2's "decoy writable service" gap stays unclosed by v0 — noted, not
  silently dropped).
- **Canary-deletion detection** (the mirror of `service.disappeared`, applied to `canary.presence`
  entity_keys — "a canary that stops appearing"). Structurally trivial to add later by reusing
  `detectServiceDisappearances`' own set-diff shape, but the todo scopes this slice to
  access/modification only (`atime_advanced` / `mtime_changed` / `executed`), not disappearance.
  Flagged as the obvious, cheap Phase-2 follow-up.
- Any `descartes canary` CLI surface, manifest writer, or planting/verification tooling.
- `calibration.js` self-audit hookup (see §5 — mirrors `service.disappeared`'s own precedent of
  staying out of `CLOSED_RULE_IDS`).
- Cross-host / federated forwarding of anything (see §7, the collision note).

---

## 1. New modules

### 1.1 `tools/descartes-cli/src/tools/canary.js` (new) — L0 collector, fs-only

Sibling to `tools/services.js`/`tools/scheduled-jobs.js` but **strictly smaller surface**: no
`execFile`, no shell — `node:fs/promises` `lstat`/`access` only (both injectable via `options` for
deterministic fixture-driven tests, mirroring how `service-baseline.js` injects
`options.readFactPoints`/`options.loadServiceBaselineStore`).

```js
export async function collectCanaryEvidence(canaries = [], options = {}) { ... }
```

- Input: `canaries` — an already-loaded, already-validated array of manifest entries
  `{ id, kind, path, watch, sentinel_path? }` (see §1.2 — the collector itself never reads config
  off disk; that's the manifest loader's job, keeping this module pure/injectable).
- Per entry: `lstat(path)`. On success, capture `{ atime, mtime, ino, size }` (ISO/string-coerced —
  `fact-store.js`'s `normalizeAttributes` stringifies everything anyway). On `ENOENT`, mark the
  entry `status: "absent"` and emit **no** attribute data for it this tick (degrade, not fabricate —
  matches `factPointsFromServiceEvidence`'s `if (!entityKey) return undefined` discipline). On any
  other error (EACCES, etc.), mark `status: "unreadable"` — contributes to envelope `"warning"`, not
  a whole-collector failure.
- `watch.includes("executed")`: `access(sentinel_path, fsConstants.F_OK)` (no read of contents) to
  set `executed: "true"/"false"`. Absent `sentinel_path` on an `"executed"`-watched entry degrades
  to `executed: "false"` (never fabricate a trip from a misconfigured manifest entry).
- Bound: `MAX_CANARIES = 200` (defense-in-depth per AGENTS.md's "bounded" collector invariant, even
  though the manifest is small/hand-authored) — entries beyond the bound are dropped and
  `result.truncated = true` is surfaced, mirroring `scheduled-jobs.js`'s truncation flag.
- Envelope: `evidenceEnvelope({ id: "canary", source: "filesystem", ... })` via the existing
  `timedEnvelope`/`evidenceEnvelope` helpers in `tools/envelope.js` — **no new envelope shape**.
  `confidence: 0.9` when every entry resolved (`"ok"`), `0.5` when any entry is `"unreadable"`
  (mirrors `services.js`'s confidence-per-status convention), `0` only on the `timedEnvelope`
  catch-all (unexpected throw).
- Each `"ok"` entry also carries through `watch` (the manifest entry's own `watch: string[]`,
  copied verbatim, never re-derived) — this is what lets §1.3 persist `watch` onto the
  `canary.presence` fact itself, which is in turn what makes `detectCanaryTrips` (§1.4) able to stay
  a pure function over facts alone (see the provenance note added there for the full reasoning).
- Result shape: `{ platform, status, request: { canary_count }, summary: { total_count, ok_count,
  absent_count, unreadable_count }, canaries: [{ id, kind, status, atime, mtime, ino, size,
  executed, watch }], truncated, note }`.

### 1.2 `tools/descartes-cli/src/canary-manifest.js` (new) — config loader

Structural copy of `provenance-elevated-config.js`'s own template (its file header literally says
"structural copy of constraint-store.js's loadLearnedConfig/... template" — same lineage, applied a
third time): `resolveCanaryManifestPaths`, `normalizeCanaryManifest`, `loadCanaryManifest`. No
`writeCanaryManifest` in v0 (no CLI writes it — YAGNI, see §0); the operator hand-edits the JSON
file directly, exactly like `learned.json` before it got a CLI face.

- Path: `configDir/canaries.json` (config, not state — human-authored, like `learned.json` /
  `provenance.json`).
- Schema: `{ schema_version: 1, canaries: [{ id, kind, path, watch: string[], sentinel_path? }] }`.
  `kind` is a closed enum: `["credential-file", "scheduled-job", "suid-binary", "sudoers-entry",
  "writable-directory"]` — **deliberately excludes any "decoy-service"/listening kind** (§0).
  `watch` entries are a closed enum: `["atime", "mtime", "executed"]`.
- `normalizeCanaryManifest`: drops individual invalid/malformed entries silently rather than
  throwing (mirrors `loadConstraints`' per-record tolerance) — one bad hand-edited entry must never
  crash the whole structural tick. Valid entries pass through unchanged.
- `loadCanaryManifest`: `ENOENT` → `{ canaries: [] }` (empty manifest = collector is a pure no-op —
  this is the *actual* "opt-in default-off" the todo means, expressed as data rather than a second
  code-level kill switch). Malformed JSON → `{ canaries: [], corrupt: true }`, fail-closed exactly
  like `loadLearnedConfig`'s own corrupt-file tolerance.
- **Operator-facing safety note (documented in this file's header comment, not enforced in code for
  v0 — see §6's doors-and-corners discussion):** a decoy MUST be inert to every real system parser.
  Never point `path` literally at a live-parsed location a real loader will act on (e.g. a decoy
  entry actually inside `/etc/sudoers` itself, or a `.plist` actually inside the real
  `/Library/LaunchDaemons` search path that launchd would load) — use a look-alike-but-unparsed
  location instead (the research doc's own example: `~/.aws/credentials.bak`, never
  `~/.aws/credentials`). v0 does not validate this automatically; it is an operator-setup
  responsibility, stated plainly in the manifest schema's doc comment.

### 1.3 `tools/descartes-cli/src/fact-translators.js` (edit) — the `canary.census` fact

Add, mirroring `SERVICE_CENSUS_FACT_NAME`'s exact role and the two-fact_name collision-avoidance
reasoning verbatim (a canary_id is operator-chosen and could otherwise collide with a reserved
marker key):

```js
export const CANARY_PRESENCE_FACT_NAME = "canary.presence";   // per-canary observed attributes
export const CANARY_CENSUS_FACT_NAME = "canary.census";        // completeness marker (mirrors SERVICE_CENSUS_FACT_NAME)
export const CANARY_CENSUS_MARKER_ENTITY_KEY = "canary.census-marker.v1";

export function factPointsFromCanaryEvidence(evidence, { ts } = {}) { ... }
```

- Structural copy of `factPointsFromServiceEvidence`: find envelope `id === "canary" && status !==
  "unable"`; for each `result.canaries` entry with `status === "ok"`, emit a `canary.presence` fact
  point with `entity_key: sanitizeEntityKey(canary.id)` — **cleartext** (sanitized, not hashed) —
  this is the scoped 2026-07-24 `service.disappeared` exception, extended here at the *fact* layer
  exactly as it already exists at the fact layer for services (`service.presence`'s entity_key is
  already cleartext-sanitized, not hashed — only `buildDisappearedCandidates`' alert
  `fingerprint`/`id` hash). `attributes: { atime, mtime, ino, size, executed, kind: canary.kind,
  watch: canary.watch.join(",") }` — **`executed` and `watch` are both load-bearing additions, not
  cosmetic:**
  - `executed` must be persisted here because `detectCanaryTrips` (§1.4) step 4 compares
    `latest.executed`/`previous.executed` off the tick-group snapshot, and that snapshot is built
    only from what this fact carries. Without it the `"executed"` trip reason could never fire —
    caught in review; every place `executed` is read downstream now has a place it was written.
  - `watch` is persisted (as a stringified, comma-joined list — `fact-store.js`'s
    `normalizeAttributes` stringifies attribute values anyway, matching how every other
    array/object-shaped attribute in this codebase already crosses the fact-store boundary) so that
    `detectCanaryTrips` can stay a **pure function over facts alone**, with no manifest read of its
    own. See §1.4's `detectCanaryTrips` for the full provenance/precedence rule this establishes.
  - Entries with `status !== "ok"` (`"absent"`/`"unreadable"`) are skipped this tick — degrade,
    don't fabricate, and (load-bearing) this is *why* a permission blip or a not-yet-planted canary
    can never itself register as a spurious "attribute advanced" trip: `detectCanaryTrips` (§1.4)
    only ever compares an id present in **both** of two consecutive complete tick-groups.
- **Census marker, corrected to resolve a self-contradiction caught in review:** append the
  `canary.census` marker fact (confidence `0`, exactly like `buildServiceCensusMarkerFactPoint`) iff
  **both** (a) `envelope.status === "ok" || envelope.status === "warning"` (the collector genuinely
  attempted the manifest this tick) **and** (b) `result.summary.total_count >= 1` (the manifest
  actually names at least one canary). `census_state`: `"partial"` iff `result.truncated`, else
  `"complete"` — same rule as `serviceCensusStateFor`.
  - **Why the `total_count >= 1` gate was added:** the original draft appended the marker on every
    `"ok"`/`"warning"` tick unconditionally, "even a zero-canary manifest." That directly
    contradicted §4 test 5's load-bearing regression pin, which requires an absent/empty
    `configDir/canaries.json` to produce **zero** `canary.*` facts, byte-identical to the
    pre-canary baseline — which is also what makes §2.1's "empty manifest = genuine no-op" default-
    ON story safe to ship to the existing installed base. Resolved in favor of the regression pin
    (the more load-bearing, more testable, and more conservative of the two): the completeness
    semantics a census marker exists to provide are only meaningful once ≥1 canary is configured to
    have completeness over; a zero-entry manifest has nothing to be complete or partial *about*, so
    the collector degrades to a genuine no-op — zero facts, zero writes — exactly like the outer
    `learned.json {enabled:false}` kill switch already guarantees for the whole structural tick.
    This also means `computeCanaryBaselineCandidates` (§1.4) never sees a lone census-marker-only
    tick-group with an empty attribute map, one less shape its grouping logic needs to tolerate.

### 1.4 `tools/descartes-cli/src/canary-baseline.js` (new) — the detector

Sibling to `service-baseline.js`, same file-header discipline (states plainly: NO LLM anywhere in
this file; stateless detection; tiny store holds only genuinely-cumulative bookkeeping).

```js
export const CANARY_TRIPPED_RULE_ID = "canary.tripped";
export const DEFAULT_CANARY_ESTABLISHED_MIN_CENSUS_COUNT = 3; // PROVISIONAL, mirrors service-baseline.js's own placeholder

export function resolveCanaryBaselineStorePaths(descartesPaths) { ... }   // stateDir/learned/canary-baseline.json
export async function loadCanaryBaselineStore(descartesPaths) { ... }
export async function writeCanaryBaselineStore(descartesPaths, state) { ... }

export function groupCanaryFactsByTick(points = []) { ... }
export function detectCanaryTrips(groups = [], options = {}) { ... }
export function buildCanaryTrippedCandidates(entries = []) { ... }
export async function computeCanaryBaselineCandidates(descartesPaths, options = {}) { ... }
```

**`groupCanaryFactsByTick`** — like `groupServiceFactsByTick` but each tick-group carries a
`Map<entity_key, {atime, mtime, ino, size, executed, kind, watch}>` (attribute snapshot, not just a
presence `Set`) alongside the same three-way `censusState` (`"complete"`/`"partial"`/`"unknown"`,
matched strictly, never defaulted to `"complete"` — identical fail-closed discipline as the service
module). **`executed` and `watch` were added to this snapshot in review** — the original draft's
snapshot shape (`{atime, mtime, ino, size, kind}`) omitted both, which made `detectCanaryTrips`
step 4's `latest.executed`/`previous.executed` comparison (see below) unimplementable and left
`watch` provenance for step 4's attribute filter unspecified; both are now carried straight through
from `canary.presence`'s own attributes (§1.3), so this function stays a pure reshape with no new
I/O or manifest dependency.

**`detectCanaryTrips`** — the "stateless set/stat-diff" the todo calls for. Pure function, no I/O,
recomputed fully fresh from `groups` on every call (no persisted per-canary map — mirrors
`detectServiceDisappearances`'s own statelessness exactly):

1. Filter to `censusState === "complete"` tick-groups only. Fewer than 2 → `[]`.
2. `latest`/`previous` = the two most recent complete tick-groups. Freshness gate: `latest.ts` must
   be within `freshnessMs` of `nowMs`, else `[]` (identical shape to
   `detectServiceDisappearances`'s own freshness gate).
3. Established gate (cold-start protection, per the todo's "so a freshly-planted canary doesn't
   storm on first observation"): a canary `id` must appear in at least `minEstablishedCount`
   complete tick-groups in the window before it's eligible to fire.
4. For each established canary present in **both** `previous` and `latest`: compare only the
   attributes its `watch` list names.
   - **Watch-list provenance and precedence (specified in review, previously unstated):**
     `detectCanaryTrips` is a pure function over `groups` only — it never loads
     `canary-manifest.js` itself, and `computeCanaryBaselineCandidates` (below) never loads or
     threads the manifest into it either. The `watch` list used for the comparison in this step is
     **`latest.watch`** — the watch list persisted onto the *freshest* tick-group's
     `canary.presence` fact (§1.3, `factPointsFromCanaryEvidence`), which is itself a verbatim copy
     of whatever `canary-manifest.js` returned for that entry at collection time (§1.1). This keeps
     the detector self-consistent across manifest edits mid-window: an operator who edits
     `canaries.json` between ticks changes what gets *collected and persisted* starting next tick,
     and the detector picks that up automatically the moment it becomes the freshest tick-group's
     value, with no separate manifest read or cache-invalidation logic of its own. **If `latest.watch`
     and `previous.watch` disagree** (the operator changed the watch list for this `id` between the
     two compared ticks), **`latest.watch` wins** unconditionally — the freshest observed intent
     governs, matching the freshness-gate convention already used one step up (step 2) and the
     "recompute fully fresh from `groups` on every call" discipline this function already commits to.
     A canary dropped from `watch` entirely between ticks simply stops being eligible to trip on the
     dropped attribute starting that tick — no special-casing needed, it falls out of the rule above.
   - `watch` includes `"atime"` and `latest.atime > previous.atime` → `trip_reason:
     "atime_advanced"`.
   - `watch` includes `"mtime"` and `latest.mtime !== previous.mtime` → `trip_reason:
     "mtime_changed"`.
   - `watch` includes `"executed"` and `latest.executed === "true" && previous.executed !==
     "true"` → `trip_reason: "executed"`.
   - A canary absent from `previous` or `latest` (permission blip, not-yet-established) is skipped
     this pair — never treated as a trip by omission.
   - Edge-triggered, K=1, same shape as `detectServiceDisappearances`: once the freshest-complete
     pointer moves past a pair, it naturally stops re-firing for that pair (no forever-firing
     candidate); a genuinely new access on a later tick produces a new attribute delta and fires
     again. No dedicated "resolved" bookkeeping needed — `alert-store.js`'s existing
     cooldown/recovery machinery (proven by every sibling) handles the rest.
5. Returns `[{ canary_id, kind, trip_reason, tripped_at_ts, last_seen_ts,
   complete_census_seen_count }]` — one entry per (canary, first-detected-reason) pair per tick,
   never more than one reason per canary per tick even if multiple watched attributes moved (pick
   the first match in `watch` order — deterministic, documented, not a correctness-critical choice
   since severity is unconditionally `critical` either way).

**`buildCanaryTrippedCandidates`** — mirrors `buildDisappearedCandidates` field-for-field:

```js
function hashCanaryId(canaryId) {
  return createHash("sha256").update(`canary.tripped:${canaryId}`).digest("hex").slice(0, 16);
}

export function buildCanaryTrippedCandidates(entries = []) {
  return entries.map((entry) => {
    const canaryIdHash = hashCanaryId(entry.canary_id);
    const canaryId = sanitizeIdentityString(entry.canary_id);
    const diagnostics = sanitizeDiagnostics({
      canary_id: canaryId,               // cleartext — the scoped exception (todo's own wording)
      canary_kind: entry.kind,
      trip_reason: entry.trip_reason,
      canary_id_hash: canaryIdHash,
      last_seen_ts: entry.last_seen_ts,
    });
    return {
      id: alertId(CANARY_TRIPPED_RULE_ID, canaryIdHash),
      rule_id: CANARY_TRIPPED_RULE_ID,
      fingerprint: canaryIdHash,          // HASHED — dedup/edge-trigger key, never the raw id
      severity: "critical",               // unconditional, no tiering — near-zero legitimate cause
      title: "Canary tripped",
      summary: "A decoy credential/persistence artifact was accessed or modified.",
      diagnostics,
      evidence_refs: ["canary-baseline"],
    };
  });
}
```

**`computeCanaryBaselineCandidates`** — structural copy of `computeServiceBaselineCandidates`:
`loadLearnedConfig(...).enabled` short-circuit to `[]` before any I/O; reads
`DEFAULT_BASELINE_FACT_WINDOW_MS` of fact history; groups; loads/writes the tiny
`canary-baseline.json` store (`last_folded_ts`, `skipped_partial_tick_count`,
`trip_event_count` — same fold-time-only increment discipline, same "candidate list rebuilt fresh
every call regardless of whether a store write happened" re-emission rule).

---

## 2. Exact wiring edits

### 2.1 `tools/descartes-cli/src/daemon.js`

- **`defaultDaemonProfile()`** (~line 61-87): add a seventh `structural.collectors` entry,
  `canary: { enabled: true }`, with a comment matching the `sessions`/`vpn-peer-status` precedent:
  safe/byte-identical for the existing installed base because (a) the outer
  `configDir/learned.json {enabled:false}` kill switch already gates the whole structural tick, and
  (b) an absent/empty `configDir/canaries.json` manifest makes the collector a genuine no-op (zero
  canaries → zero facts → zero candidates) — there is no *second* code-level default-off flag to
  add; the manifest itself is the opt-in surface.
- **`collectStructuralEvidence(structuralProfile, collectors)`** (~line 236-264): add
  `canary: collectors.canary ?? (() => collectCanaryEvidence([]))` to `activeCollectors`, and
  `if (structuralProfile.collectors?.canary?.enabled) evidence.push(await activeCollectors.canary());`
  — same shape as every sibling. The default (uninjected) collector reads an empty array, matching
  "no manifest configured yet" gracefully.
- **`runDaemonIteration`**, immediately before the existing `collectStructuralEvidence(...)` call
  inside the `if (structuralDue) { ... }` block (~line 440): load the manifest and bind it into a
  local collector closure, additive-only, never touching the existing `collectStructuralEvidence`
  signature:
  ```js
  let structuralCollectors = options.structuralCollectors;
  if (structuralProfile.collectors?.canary?.enabled) {
    const loadManifest = options.loadCanaryManifest ?? loadCanaryManifest;
    const { canaries } = await loadManifest(descartesPaths);
    structuralCollectors = {
      ...structuralCollectors,
      canary: structuralCollectors?.canary ?? (() => collectCanaryEvidence(canaries)),
    };
  }
  ```
  then pass `structuralCollectors` (not `options.structuralCollectors`) into
  `collectStructuralEvidence(structuralProfile, structuralCollectors, ...)`. This keeps
  `collectCanaryEvidence` pure/injectable (§1.1) and keeps all config I/O at the orchestration layer,
  exactly where `readStructuralCheckpoint`/`writeStructuralCheckpoint` already live.
- **Fact-point translation block** (~line 460-480): add
  `...factPointsFromCanaryEvidence(structuralEvidence, { ts }),` alongside the existing four
  `factPointsFrom*` calls — same "only reachable on a successful, non-timed-out structural tick"
  discipline as its siblings.
- **`extraCandidates` array** (~line 527-566): add an eighth entry,
  `...await computeCanaryBaselineCandidates(descartesPaths, { ...options, activeFreshnessMs }),`
  with a comment mirroring `service.disappeared`'s own: no new `execFile`/host I/O beyond the
  collector itself; gated identically by `computeCanaryBaselineCandidates`'s own
  `loadLearnedConfig(...).enabled` short-circuit; `canary.tripped` is `unknown_namespace` (no
  `classifyAlertNamespace` branch — see §2.2), so it can never reach the LLM adjudication path
  regardless of `enabled_namespaces`.
- New imports: `collectCanaryEvidence` from `./tools/canary.js`; `loadCanaryManifest` from
  `./canary-manifest.js`; `factPointsFromCanaryEvidence` from `./fact-translators.js` (added to the
  existing `factPointsFrom*` import block); `computeCanaryBaselineCandidates` from
  `./canary-baseline.js`.

### 2.2 `tools/descartes-cli/src/alert-intelligence.js`

- Import `CANARY_TRIPPED_RULE_ID` from `./canary-baseline.js`.
- Widen the locally-composed allowlist (~line 28-33):
  ```js
  const ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS = [
    ...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS,
    PEER_COUNT_SPIKE_RULE_ID,
    PEER_COUNT_DROP_RULE_ID,
    SERVICE_DISAPPEARED_RULE_ID,
    CANARY_TRIPPED_RULE_ID,
  ];
  ```
- Add a `buildSessionAlertNotificationDecision` branch (~after the `SERVICE_DISAPPEARED_RULE_ID`
  branch, line ~458-473) — same defensive-fallback shape as `service.disappeared`'s
  `displayServiceName` (guard against `sanitizeIdentityString`'s redaction-marker-object
  degradation, which would otherwise stringify to `"[object Object]"`):
  ```js
  if (alert?.rule_id === CANARY_TRIPPED_RULE_ID) {
    const displayCanaryId = typeof diagnostics.canary_id === "string" ? diagnostics.canary_id : `unknown (${diagnostics.canary_id_hash})`;
    return {
      notify: true,
      severity: "critical",   // unconditional — matches the candidate's own unconditional severity
      title: "Descartes: canary tripped",
      body: `Canary "${displayCanaryId}" (${diagnostics.canary_kind}) tripped: ${diagnostics.trip_reason}.`,
    };
  }
  ```
- **Deliberately NOT touching `classifyAlertNamespace`.** `canary.tripped` gets no new branch there
  — it stays `namespace: undefined` (fail-closed by omission from the closed map), exactly mirroring
  every other member of `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` today (`session.count_drop`,
  `session.churn`, `peer.count_spike`, `peer.count_drop`, `service.disappeared` — **none** of these
  use the `learned.`-style explicit `hardExcluded: true` branch; all rely on the closed-map
  omission). This is the proven, minimal-diff pattern — adding a new explicit hard-exclusion branch
  would also require widening `summarizeExclusions`' fixed-shape counts object
  (`{hard_excluded_learned, unknown_namespace, unregistered_template, not_consented}`), which is
  unnecessary churn for the same fail-closed guarantee. Flagged as an optional, non-blocking
  future hardening in §8's open questions — not required for v0.

### 2.3 `tools/descartes-cli/src/fact-translators.js`, `tools/descartes-cli/src/canary-baseline.js`,
`tools/descartes-cli/src/canary-manifest.js`, `tools/descartes-cli/src/tools/canary.js`

New/edited per §1 above. No other existing file needs an edit:

- **`calibration.js`: no edit.** `SERVICE_DISAPPEARED_RULE_ID` is itself absent from
  `CLOSED_RULE_IDS` (verified by reading the file — only `identity.*`/`session.*`/`peer.*`/
  `correlation.*` are calibrated in v0-of-that-slice). `canary.tripped` mirrors that precedent
  exactly and is likewise left out of `CLOSED_RULE_IDS` for this slice — no calibration/self-audit
  hookup for a first-cut deterministic, unconditional-severity alert. Revisit once there's enough
  fired-alert history to make a precision/recall proxy meaningful.
- **`alert-store.js`: no edit.** `["info", "warning", "critical"]` already accepts `"critical"`;
  `evaluateAndPersistAlerts`'s `extraCandidates` merge seam is generic over `rule_id`/`fingerprint`
  and needs no per-rule change.
- **`validateDaemonProfile`: no edit.** Already generic over `structural.collectors`'s object shape.

---

## 3. The atime-honesty caveat (addressed, not hand-waved)

Per the todo's explicit callout: `relatime`/`noatime` mounts blunt `atime` as a read signal (Linux
default is `relatime` on most modern distros — atime only advances once per day-ish, or not at all
under `noatime`). v0's resolution, following the research doc verbatim:

- **Detection is best-effort, stated as such.** A canary manifest entry using `watch: ["atime"]` on
  a `noatime` mount may simply never trip on a real read — this is a known, accepted, documented
  gap, not a silent failure. The manifest schema doc comment (§1.2) tells operators to pair
  `atime`-watched credential canaries with `mtime`-watched persistence canaries where possible, and
  to prefer `watch: ["mtime", "executed"]` canaries on `noatime` hosts.
- **Deception value is claimed unconditionally, independent of mount semantics.** The plan does not
  attempt to detect or work around `noatime`/`O_NOATIME` reads — an attacking agent has no way to
  know in advance whether Descartes' host mounts `atime`, so the credential canary's *decision-trap*
  value (the agent can't cheaply tell real from fake) holds regardless of whether the read gets
  caught. This is a documentation/framing decision, not a code change: no mount-detection logic is
  added in v0 (YAGNI — the collector doesn't need to know or care which mount semantics apply; it
  just observes whatever `atime` the filesystem actually reports, honestly, every tick).
- No `O_NOATIME`-defeat, no fanotify/eBPF, no privileged read path — all explicitly out of scope,
  matching §3.4 of the research doc ("it does not claim to catch a careful attacker who reads with
  `O_NOATIME` or on a `noatime` mount").

---

## 4. Test plan (fixture-driven, mirrors the named sibling test files)

This dev machine cannot run VMs — every test below is pure-function or uses real temp-directory
fixtures (real files written by the test, real `lstat` against them) or injected fakes, never a
platform-specific subprocess mock. `canary.js` is actually *easier* to test than `services.js`/
`scheduled-jobs.js` precisely because it has no `execFile` to mock — real fixture files suffice.

1. **`test/canary.test.js`** (new, mirrors `test/services.test.js`/`test/scheduled-jobs.test.js`):
   - Empty `canaries` array → `status: "ok"`, zero entries, `confidence` high.
   - A real fixture file (`fs.mkdtemp` + `fs.writeFile`) as a canary path → entry `status: "ok"`
     with `atime`/`mtime`/`ino`/`size` populated from the real `lstat`.
   - Nonexistent path → entry `status: "absent"`, envelope stays `"ok"` overall (not a failure).
   - Injected `options.lstat` throwing `EACCES` → entry `status: "unreadable"`, envelope degrades to
     `"warning"`, never throws out of the collector (uses `timedEnvelope`'s existing catch-all as
     the last-resort backstop, but the per-entry path should never need it).
   - `watch: ["executed"]` + `sentinel_path` present/absent (via injected `options.access`) →
     `executed: "true"`/`"false"`.
   - An `"ok"` entry's output `watch` field equals the manifest entry's own `watch` array, verbatim
     (round-trip, not re-derived) — this is what §1.3/§1.4 downstream rely on.
   - `MAX_CANARIES` bound: > 200 entries → `truncated: true`, only the first 200 processed.
   - No `execFile`/`child_process` import anywhere in `canary.js` — pin this with a static
     `ast-grep`/grep-based negative test or a code-review note (see §6), not just informally.

2. **`test/canary-manifest.test.js`** (new, mirrors `constraint-store.js`'s
   `loadLearnedConfig` tests / `provenance-elevated-config.js`'s own pattern):
   - `ENOENT` → `{ canaries: [] }`.
   - Corrupt JSON → `{ canaries: [], corrupt: true }`.
   - One invalid entry (missing `id`, missing `path`, unknown `kind`, unknown `watch` value) among
     otherwise-valid entries → the invalid entry is dropped, valid entries pass through unchanged
     (never throws, never drops the whole file for one bad record).

3. **`test/fact-translators.test.js`** (extend existing file): add
   `factPointsFromCanaryEvidence` cases mirroring `factPointsFromServiceEvidence`'s own tests —
   entity_key sanitization (cleartext, not hashed), an `"ok"` entry's `attributes` include both
   `executed` and `watch` (not just `atime`/`mtime`/`ino`/`size`/`kind` — pins the review fix that
   made the `"executed"` trip reason and the watch-list provenance rule implementable at all),
   census marker appended only when **both** `envelope.status === "ok" || "warning"` **and**
   `result.summary.total_count >= 1` (never on a missing/`"unable"` envelope, and — the regression
   fix — never on a genuinely empty/zero-canary manifest, even when the envelope status is
   `"ok"`), marker `confidence: 0`, an unresolvable/unsafe `canary_id` is dropped (never
   fabricated), `"absent"`/`"unreadable"` entries produce no presence fact that tick.

4. **`test/canary-baseline.test.js`** (new, structural mirror of
   `test/service-baseline.test.js`'s own layout — tick-grouping helper, detect helper, build helper,
   compute helper, store round-trip, in that order):
   - `groupCanaryFactsByTick`: strict three-way `censusState` match (`"complete"`/`"partial"`/
     `"unknown"`, never defaulting an unrecognized value to `"complete"`); the per-entity snapshot
     carries `executed` and `watch` through unchanged from the source fact (pins the review fix to
     this function's own shape).
   - `detectCanaryTrips`: atime-advance trigger; mtime-change trigger; executed-transition trigger;
     no trip when the watched attribute is unchanged between the two latest complete ticks; cold-
     start gate suppresses a canary observed fewer than `minEstablishedCount` times; freshness gate
     suppresses a stale-but-technically-complete latest tick-group; **watch-list provenance:** the
     attributes compared for a given canary are read from `latest.watch`, never from a freshly-loaded
     manifest (this function takes no manifest/config argument at all); **watch-list precedence:**
     when `latest.watch` and `previous.watch` disagree for the same `id` (operator edited
     `canaries.json` mid-window), `latest.watch` governs — assert this with a fixture where
     `previous.watch = ["atime"]`, `latest.watch = ["mtime"]`, and only the `mtime` delta is
     eligible to trip even though `previous` also had an eligible `atime` delta; a canary present in only one of
     the two compared tick-groups produces no trip (never a false trip from a permission blip);
     `watch` order determinism when multiple attributes move in the same tick.
   - `buildCanaryTrippedCandidates`: severity is unconditionally `"critical"`; `fingerprint`/`id`
     are hash-derived (never the raw `canary_id`); `diagnostics.canary_id` is cleartext-sanitized;
     `sanitizeDiagnostics` round-trips every field; an unsanitizable `canary_id` degrades to a
     redaction marker, never a raw string.
   - `computeCanaryBaselineCandidates`: `loadLearnedConfig(...).enabled === false` short-circuits to
     `[]` **before** any `readFactPoints`/store I/O (assert on a spy, not just the return value —
     mirrors the todo's own "checked before any I/O" convention); fold-time-only counter increments
     (a repeated call with no new tick-groups doesn't double-count); candidate list is rebuilt fresh
     every call regardless of whether a store write happened that tick.

5. **`test/daemon.test.js`** (extend existing file):
   - `canary` sub-collector participates in `collectStructuralEvidence` when
     `structuralProfile.collectors.canary.enabled` and produces `canary.presence`/`canary.census`
     facts via `factPointsFromCanaryEvidence`, persisted through `appendFactPoints`.
   - `computeCanaryBaselineCandidates`'s output lands in `evaluateAndPersistAlerts`'s
     `extraCandidates` array end-to-end (a fixture canary trip → a persisted `canary.tripped` alert
     record), mirroring however the existing `service.disappeared` daemon-level integration test is
     shaped.
   - **Regression-safety, load-bearing:** an absent/empty `configDir/canaries.json` manifest (the
     default for every existing installed base) produces **zero** `canary.*` facts and **zero**
     `canary.tripped` candidates — byte-identical to the pre-canary baseline. This is the same
     discipline every prior structural-tick addition in this file pins explicitly.
   - The manifest is loaded via the injected `options.loadCanaryManifest` in tests — no real
     `configDir/canaries.json` file needed to drive daemon-level tests deterministically.

6. **`test/alert-intelligence.test.js`** (extend existing file):
   - `classifyAlertNamespace("canary.tripped")` → `{ namespace: undefined, hardExcluded: false }`
     (fail-closed by omission — assert this explicitly, since it's the whole basis of the "never
     LLM-adjudicated" guarantee).
   - `classifyAlertEligibility` on a `canary.tripped` alert → `{ eligible: false, reason:
     "unknown_namespace" }` regardless of `enabled_namespaces` content (including a deliberately
     adversarial `enabled_namespaces` array that names `"canary"` explicitly — it still can't become
     eligible without a `PROMPT_TEMPLATES.canary` entry, which this plan never adds).
   - `emitSessionAlertSignals` delivers a due `canary.tripped` alert through the deterministic
     branch with the expected title/body, including the redaction-marker-object fallback path
     (mirrors `service.disappeared`'s own defensive test for `displayServiceName`).
   - `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` includes `CANARY_TRIPPED_RULE_ID` (a cheap
     membership assertion pinning the allowlist widening).

7. **Run the smallest relevant check per AGENTS.md** before finishing each module:
   `node --test tools/descartes-cli/test/canary*.test.js tools/descartes-cli/test/fact-translators.test.js`
   locally per-file while iterating, then the full `npm test` (or repo's equivalent) + lint gate
   before calling the slice done — per AGENTS.md's "run the smallest relevant check" +
   "tighten your feedback loop" conventions.

---

## 5. Safety invariants preserved (checklist)

- **Read-only.** `canary.js` calls only `lstat`/`access` — greppable: zero `fs.writeFile`,
  `fs.unlink`, `fs.mkdir`, or `fs.rename` calls anywhere in the collector. `canary-manifest.js` has
  a loader only, no writer, in v0.
- **fs-only, no `execFile`/shell.** Confirmed against every sibling collector (`services.js`,
  `scheduled-jobs.js` both use `execFile`; `canary.js` deliberately does not) — a strictly smaller
  surface than either, as the research doc requires.
- **Bounded.** `MAX_CANARIES = 200` hard cap, same convention as `scheduled-jobs.js`'s
  `job_limit`/`MAX_CRON_FILE_BYTES`.
- **Evidence-envelope-shaped.** Reuses `evidenceEnvelope`/`timedEnvelope` from `tools/envelope.js`
  verbatim — no new envelope schema.
- **Detectors default-OFF behind `learned.json`.** `computeCanaryBaselineCandidates` short-circuits
  on `loadLearnedConfig(...).enabled` before any I/O, identically to every sibling
  `compute*Candidates` function. The structural sub-collector flag defaults `true` (matching every
  sibling), but is inert by construction against an empty manifest (§2.1) and gated overall by the
  outer `learned.json` kill switch already governing the whole structural tick.
- **Deterministic, NO-LLM alert path.** `canary-baseline.js`'s header states it plainly (mirrors
  `service-baseline.js`'s own header); `detectCanaryTrips` is a pure function with no model call
  anywhere in its call graph.
- **Fail-closed alert namespace.** `canary.tripped` is unclassified in `classifyAlertNamespace`
  (never eligible for LLM adjudication under any `enabled_namespaces` configuration) while still
  reaching the operator deterministically via `emitSessionAlertSignals`'s allowlisted local-delivery
  branch (§2.2).
- **Degrade-not-fabricate.** Every read failure (ENOENT, EACCES, corrupt manifest, unsafe
  `canary_id`) degrades to "no claim"/dropped entry, never a fabricated trip or a crashed structural
  tick. Enumerated per-module in §1/§4.
- **No new privilege surface.** No new `execFile` allowlist entry anywhere (there is no `execFile`
  call to allowlist). No privilege escalation, no elevated-read mechanism touched
  (`provenance-elevated-config.js` is untouched by this plan).
- **Hash/bucket identity at source, with the one scoped, named exception.** `canary.presence`'s
  `entity_key` and `canary.tripped`'s `diagnostics.canary_id` are cleartext-sanitized (the
  2026-07-24 `service.disappeared` exception, extended here on the operator's own explicit
  reasoning: a canary_id is the entire operational point of a local notification, exactly like a
  service name). `fingerprint`/`id` — the dedup/edge-trigger keys, and the only fields any future
  federation layer should ever see — stay hashed, unconditionally, with no exception.

---

## 6. Decoy-placement doors-and-corners (per Slice 7 §(e) 7.1's own review note)

Addressed by scoping and documentation rather than new enforcement code, appropriate for a v0 whose
job is "collector reads metadata about operator-placed files," not "collector polices where an
operator is allowed to place files":

- **Any listening decoy socket is excluded from v0** (§0) — it is the one canary *kind* from the
  research doc's own gap table (§3.2, "decoy writable service / dead-drop") that cannot be
  fs-only-observed; standing one up is itself a mutating, new-surface action. Left as a named,
  explicit gap for a future slice with its own dedicated doors-and-corners pass, not silently
  dropped from the manifest schema (the `kind` enum in §1.2 simply has no entry for it, so a
  hand-authored manifest can't accidentally request it either).
- **Files in system locations are permitted by the manifest schema but are entirely an
  operator-setup responsibility, stated explicitly in the schema's own doc comment (§1.2).** The
  collector never creates, modifies, or removes anything at any manifest path, in any location,
  system or otherwise — its only operation is `lstat`/`access`. The risk this note exists to flag
  (a decoy that is *actually* parsed/executed by a real system loader, becoming non-inert) is a
  manifest-authoring risk, not a collector-code risk, and v0 resolves it by:
  1. Naming the invariant plainly ("MUST be inert to every real system parser") in the schema doc
     comment operators will read before hand-editing `canaries.json`.
  2. Using the research doc's own worked example (`~/.aws/credentials.bak`, not the live path) as
     the canonical pattern to imitate.
  3. **Not** building automated path-classification/rejection logic in v0 (e.g., refusing a
     manifest entry that literally names `/etc/sudoers`) — that is real, valuable, but genuinely
     separable hardening; noted as a Phase-2 idea in §8, not required to ship v0.
- **Least-privilege reads.** `lstat` (metadata only, never `readFile` of contents) is used
  everywhere except the optional `"executed"` sentinel check, which uses `access(..., F_OK)`
  (existence only) — the collector never reads the *contents* of any canary file, credential or
  otherwise, even though it could. This bounds what a compromised/buggy Descartes process itself
  could ever leak from a canary, independent of the manifest-authoring risk above.

---

## 7. Collision-with-shared-alert-pipeline — Phase-2 sequencing note

This is the one place this plan deliberately does **not** design ahead, and instead names the
future collision explicitly so whoever builds the federated/shared-alert-pipeline slice
(`docs/plans/2026-08-11-descartes-fleet-federated-topology.md` / the federated-immune-system vision)
does not discover it mid-implementation:

- **The cleartext `canary_id` in this alert's diagnostics is a scoped, LOCAL-notification-only
  exception** — the same 2026-07-24 operator decision that made `service.disappeared`'s
  `service_name` cleartext was explicit that this does **not** generalize to session/peer identity,
  "where the specific one is irrelevant and hashing loses nothing." A canary trip is exactly the
  kind of high-value, cross-host-corroboratable signal the federated-immune-system vision names as
  a first candidate for a "corroborated/ratified signature" — which means it is also exactly the
  kind of alert a future shared-alert-pipeline implementer will be tempted to forward off-host
  verbatim, diagnostics and all.
- **That must not happen with the cleartext field.** When a shared/federated alert-forwarding path
  is eventually built, it must carry only `canary_id_hash`/`fingerprint` (already hashed,
  domain-prefixed, unconditional) off-host — never `diagnostics.canary_id` — matching **`AGENTS.md`'s
  own privacy default (AGENTS.md:78, verbatim): "do not ship raw logs, usernames, file paths,
  hostnames, IPs, secrets, or stable host/user identifiers. Prefer local IDs, buckets, hashes with
  clear threat models, and opt-in federation."** *(Correction from review: an earlier draft of this
  paragraph attributed that quotation to
  `docs/research/2026-08-11-agentic-intrusion-defense.md`; the phrase does not appear anywhere in
  that file — verified by search. It is AGENTS.md's own line, quoted correctly above. The
  substantive requirement itself was never wrong: it matches
  `docs/plans/2026-08-11-descartes-fleet-federated-topology.md:178`'s own restatement of the same
  invariant for the Observation→Federation seam — "the only thing that crosses from a local
  instance to the fleet is a signature / incident fingerprint, never raw logs" — which that plan
  itself cites back to "the AGENTS.md privacy default." This plan's citation now matches that
  chain.)* This plan does not implement that redaction boundary (there is no federation code to
  redact from yet) — it names the requirement so the future slice's own plan inherits it as a
  stated constraint, not an afterthought discovered by a reviewer.
- **Sequencing implication:** any future federation/shared-pipeline plan touching `canary.tripped`
  should treat this plan's §1.4 (`buildCanaryTrippedCandidates`) as the canonical source of which
  fields are cleartext-by-design (`canary_id`, `canary_kind`, `trip_reason`) versus hash-only-by-design
  (`canary_id_hash`, `fingerprint`, `id`) — and should add an explicit host-local-only diagnostics
  allowlist at the federation boundary rather than assuming "whatever's in `diagnostics` is safe to
  forward" (which is true for every *other* namespace in this codebase today, and would silently
  stop being true the moment `canary.tripped`'s cleartext field crosses a host boundary unfiltered).

---

## 8. Open questions / non-blocking follow-ups

- Should `classifyAlertNamespace` eventually gain an explicit `canary.` → `hardExcluded: true`
  branch (like `learned.`) for extra defense-in-depth, given `canary.tripped`'s higher stakes
  (severity `critical`, direct intrusion signal) versus relying on closed-map omission like its
  siblings? Not required for v0 (§2.2) — flagged for a future hardening pass, would need
  `summarizeExclusions`' fixed-shape counts object widened too.
- Canary-deletion detection (§0) — cheap reuse of `detectServiceDisappearances`'s own shape against
  `canary.presence` entity_keys. Natural Phase-2 addendum once v0 has real-world signal.
  Historically this codebase treats a NEW alert rule_id (even a structurally-trivial one) as
  deserving its own tight review pass rather than folding it silently into this plan — deferred on
  purpose, not by oversight.
  Note that a canary that *disappears* could also just mean "operator hand-edited `canaries.json`
  to remove it" — that rule would need its own established/removed-from-manifest disambiguation the
  service.disappeared precedent didn't need to solve (services vanish from a live OS census; a
  canary vanishing from the manifest is an intentional operator edit, not itself signal). Worth
  scoping carefully, not rushing.
- Automated manifest path-classification/rejection (§6, "reject a manifest entry that names a known
  live-parsed system path") — real hardening, deliberately deferred rather than built speculatively
  against an enum of "known dangerous paths" that would need ongoing maintenance to stay accurate
  across platforms.
- No operator-facing `descartes canary status`/`list` CLI in v0 (§0) — worth adding once there's a
  real manifest in the wild to inspect; deliberately deferred to avoid building CLI ergonomics ahead
  of the underlying detector proving itself.

---

## Known v0 limitations (inherent host-local tamper — fleet-addressed)

**Addendum:** 2026-08-12 — recorded alongside the identity-binding fix (FIX-A, below) closing the
canary_id-reuse/path-edit fabrication gap and the delivery-abort fix (FIX-B) hardening
`emitSessionAlertSignals`'s notification loop.

A single, root-capable, host-local attacker who can already write both the canary files/manifest
**and** the daemon's own state (`canary-baseline.json`) can always defeat a host-local-only
detector — this is the same "the manifest is the attacker's own host-local file" class already
named in §5/§7 above, not a new gap. The residuals below are inherent to a v0 with no host-local
tamper-evidence primitive and no second, independent (fleet) observer; they are **not chased
further in this collector** because the correct fix is architectural (a fleet dead-man's-switch +
tamper-evidence design), not another local mitigation layered on top of a detector the attacker
already controls:

- **Per-entry manifest corruption.** `canary-manifest.js`'s `normalizeCanaryManifest` treats a
  single malformed row inside an otherwise-valid `canaries.json` (missing/wrong-typed `id`/`path`,
  an unrecognized `kind`, an empty/invalid `watch` array) as ordinary data-quality filtering —
  `schema_valid: true`, `read_ok: true` — and silently drops that one entry rather than raising
  `canary.tampered`. This is deliberate (§ the module's own `normalizeCanaryManifest` header
  comment distinguishes top-level shape failures, which DO raise `manifest_unreadable`, from
  per-entry drops, which don't) but means an attacker who can write `canaries.json` can
  surgically decommission ONE canary (rather than the whole manifest) with no alert at all — the
  same class as "the manifest is the attacker's own host-local file," just scoped to a single row
  instead of the whole document.
- **Delete a canary file AND its manifest entry together.** Indistinguishable from a legitimate
  operator decommission by design (`detectCanaryVanished`'s `currentCanaryIds` gate) — see the
  existing "legit decommission" test and §7's federation note; this is the intended,
  already-documented fail-safe behavior of the manifest-gate, not an oversight.
- **Delete `canaries.json` entirely.** Degrades to `ENOENT` → `{ canaries: [], read_ok: true }` (an
  authoritative empty manifest, not a tamper signal) — already the documented behavior of
  `loadCanaryManifest`'s ENOENT branch (distinct from a non-ENOENT read failure, which DOES raise
  `manifest_unreadable`).
- **Kill the daemon process itself.** No collector, no facts, no alert — outside any host-local
  detector's reach by construction; the daemon cannot observe its own absence.

**Defense:** all four residuals share the same root cause (a single host-local vantage point with
no independent corroborating observer and no tamper-evident local state) and the same fix —
`todos/2026-08-11-tamper-evidence-attestation-design.md`'s fleet/dead-man's-switch +
tamper-evidence design, which gives a second, harder-to-simultaneously-compromise observer (the
fleet) and a tamper-evident local attestation chain the attacker cannot silently roll back. Not
built here; named so the fleet slice inherits these four residuals as its acceptance bar rather
than rediscovering them.
