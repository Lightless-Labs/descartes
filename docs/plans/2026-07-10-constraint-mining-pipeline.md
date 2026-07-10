# Constraint Mining Pipeline — Layer A Slices S6a–S7 (Multi-Cadence Collection, Categorical Fact History, Deterministic Miner, Shadow Soak & Promotion Gate)

**Created:** 2026-07-10
**Reviewed:** 2026-07-10 (via two-lens design review — feasibility/daemon-safety + scope-guardian/safety) — findings applied below; disposition summarized in §0.1.
**Deepens:** `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` §0, §3.1, §3.3, §7, §8 (Slices 6a/6b/6c/7), §11, §12
**Origin:** Sonnet design+review workflow — a design pass that grounded every seam against shipped code (constraint-store.js, history-store.js, daemon.js, constraint-eval.js, diagnostics-sanitizer.js, the L0 collector tools), followed by a review pass. Operator-chosen build order: **Layer A (this plan) → Layer B provenance/witr → make it all live.**
**Status:** Proposed — implementation-ready. All four slices are independently shippable, TDD-first, atomic-commit-sized.

---

## 0. Grounding — what's already shipped (cite, don't duplicate)

- **`tools/descartes-cli/src/constraint-store.js`** — `resolveConstraintStorePaths()` (L7–14) puts state at `stateDir/learned/constraints.json`, config at `configDir/learned.json`. `validateConstraint()` (L34+), `CONSTRAINT_STATUSES = ["draft","shadow","review-ready","active","retired"]` (L5), atomic tmp+rename `writeConstraints`-style writers (0o600 files, 0o700 dirs via `ensureConstraintDir`/`ensureParent`), `loadLearnedConfig`/`writeLearnedConfig` gating everything behind `configDir/learned.json` `{enabled:false}` by default (L144–162), `SEED_CONSTRAINTS` (L171+) as the canonical example of the full constraint record shape (`id, kind, family, target, expected, status, confidence, provenance, fixtures, promotion_history, first_observed, last_verified, sensitivity, schema_version`).
- **`tools/descartes-cli/src/history-store.js`** — numeric metric-point schema. `normalizeMetricPoint` (L35–52) **throws** on `!Number.isFinite(value)` — this is *why* categorical facts need their own store, not reuse. `resolveHistoryStorePaths` (L8–15) → `stateDir/history/{metrics.jsonl,daemon-status.json}`. `readJsonLines`/per-line corrupt-tolerant parse (L54+), `enforceHistoryRetention` (L80–116, **not atomic** — direct `fs.writeFile`, no tmp+rename), `appendMetricPoints` (L118–127), `writeDaemonStatus`/`readDaemonStatus` (L235–254, direct `fs.writeFile`, no tmp+rename either).
- **`tools/descartes-cli/src/daemon.js`** — `defaultDaemonProfile()` (L19–34): one `interval_ms` (`DEFAULT_DAEMON_INTERVAL_MS = 60_000`), one `collectors: {system, processes, disks}` block. `collectDaemonEvidence` (L114–125) hardcodes exactly those 3 collectors. `runDaemonIteration` (L127–154): straight-line pipeline (evidence → `metricPointsFromEvidence` → `appendMetricPoints` → `writeDaemonStatus` → `evaluateAndPersistAlerts` → `adjudicateAlertNotifications`). `runForegroundDaemonLoop` (L546–558): one `do/while`, one `iterate()`, one `sleeper(intervalMs)` — no second timer exists. No `validateDaemonProfile` exists. No profile is ever loaded from disk today (`options.profile` is programmatic-only), so there is **no on-disk profile migration risk** to worry about for S6a.
- **`tools/descartes-cli/src/constraint-eval.js`** — `evaluateConstraints(activeConstraints, factLookup)` (bottom of file) only evaluates `status === "active"`, skips undefined facts, supports `expected` shapes `{comparator:"gte"|"lte"|"eq", value:<number>}` (numeric, `Number(factValue)` coerced) and `{pattern:"ends_with:<suffix>"}` (string). **Finding (load-bearing for the sanitization gate, §6 below): `buildViolationCandidate()` interpolates `constraint.id` and `constraint.target` directly into `title`/`summary`** (`` `Constraint violated: ${constraint.id}` ``, `` `...target "${constraint.target}"` ``) — only `diagnostics` is routed through `sanitizeDiagnostics()`. Title/summary are **not** sanitized today.
- **`tools/descartes-cli/src/diagnostics-sanitizer.js`** — `sanitizeDiagnostics()` allowlist: finite numbers, booleans, fixed-length hex hashes, and strings matching `SAFE_STRING_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/` and `≤ MAX_STRING_LENGTH (64)` chars. Anything else (paths, free text, over-length) is redacted. This is the pattern to extend, not reinvent.
- **`tools/descartes-cli/src/tools/envelope.js`** — `timedEnvelope()` (L19–34): on thrown error, sets `status:"unable"`, `confidence:0`, `review_hint:"missing_permission"` — the shipped "degrade, never fabricate" pattern.
- **Structural collector envelope ids** (confirmed by grep): `network.js` L260 `collectNetworkEvidence()` → envelope `id:"network-basics"` (L281); listening-socket parsers (`parseLinuxListeningSockets`, `parseMacLsofListeningSockets`, ~L129–156) produce `{protocol, local_address, local_port, ...}` — **note: the Linux parser has no pid/command/owner field at all**; only the macOS `lsof`-based parser resolves `command`/`pid`. `scheduled-jobs.js` L516 `collectScheduledJobsEvidence()` → envelope `id:"scheduled-jobs"`.
- **`services.js` result shape — confirmed to differ by manager, corrected from an earlier draft of this grounding section.** `collectServiceEvidence()` → envelope `id:"services"`, result `{manager: "systemd"|"launchd", status, summary, services:[...], truncated}`, but the `services[]` element shape is **not uniform across managers**: `parseSystemctlListUnits` (`services.js` ~L44–68, systemd branch) produces `{name, load, active, sub, description, failed, running:<boolean>, restarting}`; `parseLaunchctlList` (~L72–91, launchd/macOS branch) produces a **structurally different** `{label, pid, last_exit_status, state:"running"|"not_running", nonzero_exit}` — **no `name` key, no `running` boolean at all**. Any translator or downstream code consuming `services[]` must branch explicitly on `result.manager` (or equivalently, check for `name`/`label`) — a naive `service.running` read against launchd's shape is silently `undefined`. This matters concretely because this repo's own dev/CI host runs macOS (per project memory: "big-cabbage host").
- **`tools/descartes-cli/src/tools/scheduled-jobs.js`** — `collectLaunchdScheduledJobs` (~L421–447) scans candidate `.plist` files **sequentially**, each via its own `plutil -convert json` subprocess (`timeout:2500`ms). Its early-exit (`if (jobs.length >= limit) break`) only fires once a candidate has been successfully **parsed as a matching job** — a directory containing many non-matching or slow-to-stat plists (the common case: most LaunchAgents/LaunchDaemons have neither `StartInterval` nor `StartCalendarInterval`) does not trip the break and can serially accumulate many multi-second `plutil` timeouts. This is load-bearing for S6a's wall-time-budget requirement below (§2).
- **`tools/descartes-cli/src/paths.js`** — `resolveDescartesPaths()` (L14–31): `stateDir`/`configDir` join a **bare** subdirectory (no double-nesting); `assertNoPiOwnedPath()` (L33+) throws if any resolved path touches `.pi`.
- **CLI** — `tools/descartes-cli/src/index.js` `main()` dispatches on a flat `command` string (`login`, `triage`, `daemon`, `history`, `alerts`, …). There is **no `learned` subcommand today** — S6c introduces the first one (`descartes learned mine`), S7 adds `review`/`approve`/`reject`.
- **Roadmap terminology to preserve exactly:** `stateDir/learned/facts/*.jsonl` (fact-history, §3.1), `stateDir/learned/rollup/*.jsonl` (long-horizon store, **deferred** — only added if mining proves the window insufficient, §12), `stateDir/learned/shadow-violations.jsonl`, `stateDir/authority/promotions.json`, "minimum-fixture bar enforced at promotion", "shadow-precision floor", "deny-by-default".

### 0.1 Review disposition (round 2, this pass)

Every must-fix from the two-lens review is resolved in this revision unless explicitly marked "declined" below:

| Finding | Severity | Disposition |
|---|---|---|
| Service-presence translator spec assumed a uniform `{name,running,...}` shape; wrong for launchd (macOS) | major (must-fix) | **Fixed.** §0 grounding corrected above; §3 translator now branches explicitly on `result.manager`. |
| S6a's inline structural tick has no wall-time budget; `collectLaunchdScheduledJobs`'s sequential plist scan can serially block far longer than "occasional multi-second" | major (must-fix) | **Fixed.** §2 adds an explicit deadline wrapper around `collectStructuralEvidence`; §8 open question #2 rewritten to state the realistic worst case and the accepted tradeoff explicitly. |
| S7's shadow→review-ready gate needs "daily observation coverage" but no recurring mechanism generates it; in tension with keeping `soak` CLI-only | major (must-fix) | **Fixed.** §5 now wires `evaluateShadowConstraints`/`appendShadowRecords` (evaluation + logging only) into S6a's existing structural tick, kept structurally distinct from the human-invoked `descartes learned soak` promotion-check command, which remains CLI-only. §8 open question #3 rewritten accordingly. |
| `port-binding-identity` `entity_key = protocol:port` can collide across distinct sockets differing only by `local_address` | minor | **Fixed.** §3 `entity_key` now includes `local_address`. |
| `mineConstraintCandidates(factPoints, options)` narrows the roadmap's documented `(factHistory, snapshots, options)` signature without flagging it | minor | **Fixed.** §4 restores a reserved (unused in this slice) `snapshots` parameter with an explicit note on why it's unused for these two families. |
| Mined constraint `id` has no reserved namespace distinguishing it from hand-authored ids | minor | **Declined — already satisfied.** The emitted shape in §4 already constructs `id` as `` constraint.mined.${family}.${hash} `` — the `constraint.mined.` prefix is the reserved namespace. §4 now states this explicitly as an intentional, tested property rather than an incidental one. |
| `validateDaemonProfile` call site unspecified, risking dead code | minor | **Declined — already satisfied.** §2 already states it is "Called at the top of `runDaemonIteration`"; no drift found. Left unchanged. |
| Linux port-binding mining will practically always be `owner_known:"false"` (macOS-only in effect) | minor | **Fixed.** §3 adds an explicit one-line scope note under the network translator. |

---

## 1. Cross-slice conventions (apply uniformly — do not re-derive per slice)

1. **XDG-only, no double-nesting.** Every new path is resolved through a `resolveXStorePaths(descartesPaths)` function that joins a bare subdirectory onto `stateDir`/`configDir` (mirroring `resolveConstraintStorePaths`/`resolveHistoryStorePaths`). Every such function gets a test asserting `assertNoPiOwnedPath()` passes on its output.
2. **Atomic writes for anything that is read back to make a decision.** Whole-file JSON (constraints, profiles, promotions) → tmp+rename, `0o600`, exactly like `constraint-store.js`. Append-only JSONL (facts, shadow-violations) → `fs.appendFile` for the append path (matches `history-store.js`), but retention/compaction rewrites of JSONL use tmp+rename (a **deliberate deviation** from `history-store.js`'s non-atomic `enforceHistoryRetention` — justified because fact/shadow data feeds mining and promotion decisions, where partial-write corruption is more consequential than a dropped metric point).
3. **Corrupt-tolerant reads everywhere**, mirroring `history-store.js`'s per-line `JSON.parse` try/catch with a `corrupt_count`.
4. **Single kill switch.** All of S6a's structural collection, S6b's fact writing, S6c's mining, and S7's shadow evaluation/promotion machinery are gated behind the *already-shipped* `loadLearnedConfig(descartesPaths).enabled` (`configDir/learned.json`, default `false`). No new config file is introduced. Every slice's daemon-facing code checks this flag before doing any work; every slice's CLI-facing code still runs on-demand (mining/review/approve are explicit human-invoked actions and are not blocked by the flag — the flag gates *automatic/background* work only, matching Slice 1/2's existing precedent for `evaluateConstraints`/`evaluateAndPersistAlerts`).
5. **Read-only, no host mutation.** Every new collector call is an existing fixed-arg `execFile`-wrapped, `timedEnvelope`-wrapped function. Nothing in this plan adds a new collector *tool* — S6a only changes *when* the three already-shipped structural collectors (`collectServiceEvidence`, `collectNetworkEvidence`, `collectScheduledJobsEvidence`) run.
6. **No LLM anywhere in this plan.** Mining, shadow evaluation, and promotion gating are 100% hand-written deterministic JS. The only LLM touchpoint in the whole roadmap (`alert-intelligence.js` / `adjudicateAlertNotifications`) is untouched by this plan.
7. **TDD, atomic commits, small slices.** Each slice below is written as failing-tests-first. Sub-steps within a slice are separate atomic commits where natural (e.g., S6b's schema+store commit vs. its translators commit).
8. **Existing fast-path behavior is a hard invariant.** Any change to `daemon.js` must leave `collectDaemonEvidence`, `metricPointsFromEvidence`, and the existing fast-tick fields of `runDaemonIteration`'s return value/status write byte-identical when `profile.structural` is absent/disabled — regression-tested explicitly, not just "should still work."

---

## 2. Slice S6a — Multi-cadence collector scheduling in `daemon.js`

### Goal
Add a second, slower cadence (default hourly) that runs the three structural collectors (`services`, `network`, `scheduled-jobs`) independently of the existing 60s fast/metric cadence, with missed-tick handling and profile validation — **no mining logic, no fact translation yet** (that's S6b). Structural evidence collected this slice is discarded/logged only (or, if S6b has already landed, handed to S6b's translators — see "Sequencing" below); the acceptance bar for S6a alone is *scheduling correctness*, not fact storage.

### Sequencing note
S6a and S6b are logically parallel-shippable but S6a's `collectStructuralEvidence` is only *useful* once S6b's translators exist. Recommendation: land S6a first with structural evidence wired to a no-op/log-only sink (satisfies "no mining logic" and keeps the slice small), then land S6b, then a tiny follow-up commit within S6b wires `collectStructuralEvidence`'s output into `appendFactPoints`. This avoids S6a growing scope while still keeping both slices real and independently testable.

### Exact shapes / seam

**`defaultDaemonProfile()` (daemon.js L19–34), extended additively:**
```js
{
  interval_ms: DEFAULT_DAEMON_INTERVAL_MS,        // unchanged — fast/metric cadence
  collectors: { system: {enabled:true}, processes: {enabled:true, limit:5}, disks: {enabled:true} }, // unchanged
  structural: {
    interval_ms: DEFAULT_STRUCTURAL_INTERVAL_MS,  // new const, default 60*60*1000 (1h)
    collectors: {
      services: { enabled: true },
      network: { enabled: true },
      "scheduled-jobs": { enabled: true },
    },
  },
  safety: { read_only: true, background_llm_calls: false, telemetry: false, host_mutation: false }, // unchanged
}
```

**New `validateDaemonProfile(profile)`** (daemon.js): throws a descriptive `Error` if `profile.interval_ms` is not a positive finite number, `profile.collectors` is not an object, or (when `profile.structural` is present) `profile.structural.interval_ms` is not a positive finite number or `profile.structural.collectors` is not an object. A profile that simply *omits* `structural` entirely is valid (treated as "structural cadence disabled") — this preserves every existing caller/test that constructs a bare `{interval_ms, collectors}` profile literal. Called at the top of `runDaemonIteration` (throw-fast, same pattern as `validateConstraint`).

**New `collectStructuralEvidence(structuralProfile = {}, collectors = {})`**, sibling to `collectDaemonEvidence`, identical enabled-flag/injectable-collectors pattern:
```js
export async function collectStructuralEvidence(structuralProfile = {}, collectors = {}) {
  const activeCollectors = {
    services: collectors.services ?? collectServiceEvidence,
    network: collectors.network ?? collectNetworkEvidence,
    "scheduled-jobs": collectors["scheduled-jobs"] ?? collectScheduledJobsEvidence,
  };
  const evidence = [];
  if (structuralProfile.collectors?.services?.enabled) evidence.push(await activeCollectors.services());
  if (structuralProfile.collectors?.network?.enabled) evidence.push(await activeCollectors.network());
  if (structuralProfile.collectors?.["scheduled-jobs"]?.enabled) evidence.push(await activeCollectors["scheduled-jobs"]());
  return evidence;
}
```
`collectDaemonEvidence` itself is **not** touched — new imports (`collectServiceEvidence` from `./tools/services.js`, `collectNetworkEvidence` from `./tools/network.js`, `collectScheduledJobsEvidence` from `./tools/scheduled-jobs.js`) are added but only consumed by the new function.

**Explicit wall-time budget on the structural tick (must-fix, applied here).** Each individual collector already has its own per-command `execFile` timeout (2500–3500ms), but `scheduled-jobs.js`'s `collectLaunchdScheduledJobs` scans plist candidates **sequentially** and its early-exit only fires on a successfully-parsed match (§0 grounding) — a real macOS host's LaunchAgents/LaunchDaemons directories can serially accumulate many multi-second `plutil` timeouts with no per-tick ceiling today. `collectStructuralEvidence` is therefore wrapped in an overall deadline, independent of and in addition to each collector's own per-command timeout:
```js
const DEFAULT_STRUCTURAL_TICK_DEADLINE_MS = 45_000; // new const; generous relative to a 60s fast cadence, bounded relative to a 1h structural cadence

async function withDeadline(promise, deadlineMs, onTimeout) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), deadlineMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}
```
`runDaemonIteration` calls `collectStructuralEvidence` through `withDeadline(..., structuralProfile.deadline_ms ?? DEFAULT_STRUCTURAL_TICK_DEADLINE_MS, () => TIMED_OUT_SENTINEL)`. On timeout: the structural tick is abandoned for this iteration (partial results, if any, are **discarded**, not partially persisted — avoids inconsistent fact snapshots), `structural_collector_statuses` is written as `[{status:"unable", error:"structural_tick_deadline_exceeded"}]` so the timeout is observable in `daemon-status.json`, and — critically — `writeStructuralCheckpoint` is **still called** with the current `now`, so a repeatedly-slow host doesn't retry every fast tick (that would compound the very latency problem this budget exists to bound); it instead falls back to trying again at the next full structural interval. This makes the deadline a hard ceiling on how much any single iteration's fast/metric sample can be delayed by structural collection, independent of what any individual collector or the OS does.

`validateDaemonProfile` additionally validates `structural.deadline_ms`, when present, as a positive finite number (same rule as `interval_ms`).

**Wall-clock checkpoint, not a second timer.** `runForegroundDaemonLoop` keeps exactly one `sleeper(intervalMs)`. Inside `runDaemonIteration`, after the existing fast-path block, add:
```js
const structuralProfile = profile.structural;
const structuralDue = Boolean(
  structuralProfile?.interval_ms &&
  (options.now ?? Date.now()) - (checkpoint.lastStructuralRunMs ?? -Infinity) >= structuralProfile.interval_ms
);
```
This is wall-clock-compared (not tick-counted), so a missed tick (process down, slow iteration) is naturally handled — the next iteration whose wall clock has advanced past the threshold runs structural collection, no drift accumulation, no double-timer race.

**Checkpoint persistence:** a new small state file, **not** folded into `daemon-status.json` (avoids growing the object every consumer of `readDaemonStatus` round-trips, per the map's risk note) — `stateDir/daemon/structural-checkpoint.json`, written via the same atomic tmp+rename convention as `constraint-store.js` (deliberately atomic, unlike `writeDaemonStatus`'s direct write, because a torn checkpoint write could cause structural collection to run every tick forever, which is wasteful but not unsafe — atomic write is cheap insurance). Shape: `{ last_structural_run_ms: <number>, updated_at: <iso> }`. A tiny `readStructuralCheckpoint`/`writeStructuralCheckpoint` pair, ENOENT-tolerant (returns `{last_structural_run_ms: undefined}`), lives in `daemon.js` itself (not a new file — this is daemon-loop-internal state, not a learned artifact).

**`runDaemonIteration` wiring** (additive block after the existing fast-path, before the `return`):
```js
let structuralEvidence, structuralCheckpoint;
if (structuralDue) {
  structuralEvidence = await collectStructuralEvidence(structuralProfile, options.structuralCollectors);
  structuralCheckpoint = await writeStructuralCheckpoint(descartesPaths, { last_structural_run_ms: Number(ts_as_ms) });
}
```
`writeDaemonStatus`'s payload gains one additive, optional field: `structural_collector_statuses: structuralEvidence?.map(e => ({id: e.id, status: e.status, tool: e.trace?.tool}))` — omitted entirely (not `null`, not `[]`) when structural collection didn't run this tick, so existing exact-shape assertions on the fast path (no `structural` key present) are undisturbed. Return value gains `{ structuralEvidence }` (undefined when not due).

### TDD test list (failing first, in `test/daemon.test.js` unless noted)

1. `validateDaemonProfile` — accepts `defaultDaemonProfile()` unchanged; accepts a profile with `structural` omitted; throws on missing/non-numeric `interval_ms`; throws on non-object `collectors`; throws on `structural.interval_ms` non-numeric when `structural` is present; throws on `structural.collectors` non-object when present.
2. `collectStructuralEvidence` — with all three fake collectors injected, calls all three when all `enabled:true`; calls none when `structural` is `{}`/collectors all `enabled:false`; respects per-collector `enabled:false` for just one of the three; returns envelopes in a stable order (services, network, scheduled-jobs).
3. `collectDaemonEvidence`/`metricPointsFromEvidence` — **regression**: assert byte-identical behavior/output shape to pre-S6a fixtures when `profile.structural` is absent (proves the fast path is untouched).
4. Wall-clock due/not-due — `runDaemonIteration` with a fake checkpoint reader/writer: structural collection runs when `now - lastStructuralRunMs >= structural.interval_ms`; does **not** run when under threshold; runs exactly once even if called many times within the same sub-threshold window (checkpoint monotonically advances).
5. Missed-tick handling — simulate a large wall-clock gap (process "down" for 3× the structural interval) between two `runDaemonIteration` calls: structural collection runs exactly once on the next tick (not 3×), checkpoint advances to `now`, not to a backlog of missed slots.
6. Checkpoint persistence — `writeStructuralCheckpoint`/`readStructuralCheckpoint` round-trip; ENOENT read returns `{last_structural_run_ms: undefined}`; corrupt checkpoint file is tolerated (treated as never-run, does not throw) — mirrors `history-store.js`'s corrupt-tolerance philosophy even though this file uses atomic writes.
7. `writeDaemonStatus` shape — fast-only tick: no `structural_collector_statuses` key present (exact-key assertion, not just "doesn't throw"). Structural-due tick: `structural_collector_statuses` present with one entry per enabled structural collector, correct `{id, status, tool}` shape.
7a. **Wall-time budget (must-fix, new)** — inject a fake `scheduled-jobs` collector that never resolves (or resolves after a duration far exceeding the deadline): `runDaemonIteration` returns within `deadline_ms` regardless (assert via injected/fake clock plus a real short deadline in the test, not the 45s default); on timeout, `structural_collector_statuses` reflects `status:"unable"`/`error:"structural_tick_deadline_exceeded"`; the checkpoint still advances to `now` (proving the next attempt waits a full interval rather than retrying every fast tick); a non-timing-out structural tick is unaffected by the deadline machinery (regression).
8. Full-loop integration — `runForegroundDaemonLoop` with a fake `sleeper`/injected clock over N iterations spanning more than one structural interval: exactly the expected number of structural collections occur; fast-path point-count/status writes happen every iteration regardless.
9. `assertNoPiOwnedPath` on `resolveDescartesPaths(...)` plus the new checkpoint path (fold into an existing path-safety test if one exists, else add one).
10. Kill-switch — with `loadLearnedConfig(...).enabled === false` (default), structural collection is skipped entirely even when `structuralDue` would otherwise be true and `profile.structural` is configured (confirms convention #4 above holds at the daemon-loop level, not just at the mining/CLI level).

### Acceptance criteria
- All fast-path (`system`/`processes`/`disks`) tests pass unmodified; no existing assertion in `test/daemon.test.js` needs to change.
- A profile without `structural` behaves identically to today (no new files written, no new collectors called).
- Structural collectors run at the configured cadence, independent of the fast cadence, survive missed ticks without a backlog storm, and are gated by `configDir/learned.json`'s `enabled` flag.
- `npm test` green; new tests fail before the implementation and pass after (verify by running tests against a pre-implementation stash/diff during review).

### Safety notes
- Structural collectors are read-only but heavier (`network.js` does a live DNS lookup by default; `scheduled-jobs.js`'s `collectLaunchdScheduledJobs` can, in the worst case documented in §0, serially accumulate **tens of seconds to low minutes** of `plutil` timeouts on a real macOS host with many non-matching plists — this is a corrected, realistic worst case, not the "occasional multi-second" characterization an earlier draft of this plan used). Running structural collection inline in the same foreground loop means a slow structural tick can delay that iteration's fast sample **up to the explicit `DEFAULT_STRUCTURAL_TICK_DEADLINE_MS` (45s) ceiling** introduced above — this is now a bounded, tested, and consciously accepted worst case for v1, not an open-ended risk. This slice does **not** add concurrency/backgrounding (true architectural fix, out of scope here — revisit per §8 if the 45s ceiling itself proves too coarse in practice).
- No new mutating action, no new external collector, no new LLM touchpoint.

---

## 3. Slice S6b — Categorical fact-history schema + per-collector translators

### Goal
A new fact-point schema, distinct from `history-store.js`'s numeric metric-point schema (which `throw`s on non-finite values), plus translators from the S6a structural envelopes into that schema, stored at `stateDir/learned/facts/*.jsonl` with a retention cap. Mirrors `constraint-store.js`/`history-store.js` conventions.

### Exact shapes / paths

**New file `tools/descartes-cli/src/fact-store.js`.**

```js
export function resolveFactStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned", "facts");
  return { dir, factsFile: path.join(dir, "facts.jsonl") };
}
```
(Single file to start — a date-sharded layout is explicitly deferred; nothing in S6c requires sharding, and one JSONL file with time+size retention mirrors `history-store.js`'s `metrics.jsonl` exactly.)

**Fact-point schema** (roadmap §7, restated exactly):
```js
{
  ts: "<ISO8601>",
  fact_name: "<non-empty string>",          // e.g. "service.presence", "network.listening_port.owner"
  entity_key: "<non-empty string>",         // e.g. service name, "tcp:5432" — SANITIZED at emission (see §6)
  attributes: { /* bounded string/enum map, same normalizeDimensions-style coercion as history-store.js */ },
  source_envelope_id: "<string>",           // e.g. "services", "network-basics", "scheduled-jobs"
  source_tool: "<string>",                  // envelope.trace?.tool
  sensitivity: "operational" | "path" | ...,// defaults "operational"
}
```

`normalizeFactPoint(point, defaults)`:
- `fact_name`, `entity_key`: required non-empty strings (same requirement pattern as `metric_name`/constraint `id`), additionally run through the sanitization gate (§6) — truncate/allowlist, never pass a raw path through.
- `attributes`: reuse `history-store.js`'s `normalizeDimensions` pattern verbatim (stringify, cap at 160 chars per value, drop `undefined`/`null`, collapse non-object/array to `{}`) — **no `Number.isFinite` gate**, this is the entire reason facts can't live in `history-store.js`.
- `ts`: reuse `normalizeTimestamp`-equivalent (ISO validation via `new Date(ts)` NaN check).
- `source_envelope_id`/`source_tool`/`sensitivity`: same defaulting-from-caller pattern as `normalizeMetricPoint`.

**Storage mechanics:**
- `appendFactPoints(descartesPaths, factPoints, {ts, retentionMs, maxBytes, now})` — mirrors `appendMetricPoints`: `ensureFactDir` (`mkdir ... {recursive:true, mode:0o700}`) → normalize each point (throw propagates, no per-point catch, matching `appendMetricPoints`) → single `fs.appendFile` of all encoded lines (`mode:0o600`) → `enforceFactRetention`.
- `readFactPoints(descartesPaths, {windowMs})` — mirrors `readMetricPoints`: reuses a shared/duplicated `readJsonLines` (per-line corrupt-tolerant `JSON.parse`, `corrupt_count`), re-validates each record through `normalizeFactPoint` and **drops** (doesn't throw) any that fail — same "drop invalid, count corrupt separately" split as `history-store.js`.
- `enforceFactRetention` — own constants `DEFAULT_FACT_RETENTION_MS` (recommend 30 days — long enough to span S6c's default 7-day `minObservationDays` several times over) and `DEFAULT_FACT_MAX_BYTES` (recommend 5MB, matching `history-store.js`'s default), deliberately **not** reusing `DEFAULT_HISTORY_RETENTION_MS`/`DEFAULT_HISTORY_MAX_BYTES` (per convention #2, facts need a longer retention window than the 24h metric default, and must not accidentally couple to a constant other code may depend on). **Deviation from `history-store.js`:** the rewrite-on-retention pass uses tmp+rename (atomic), not `history-store.js`'s direct `fs.writeFile` — justified in convention #2.

**Translators** (same file or a `fact-translators.js` sibling — recommend sibling file to keep `fact-store.js` a pure storage module, mirroring how `constraint-eval.js` is separate from `constraint-store.js`):

**Must-fix, applied here: the translator branches explicitly on `result.manager`** — `services[]`'s element shape is *not* uniform across managers (§0 grounding, corrected from an earlier draft that assumed a single `{name,running,...}` shape): systemd services carry `name`/`running:<boolean>`; launchd services carry `label`/`state:"running"|"not_running"` and have **no** `name`/`running` keys at all. A single `service.running` read against a launchd result silently produces `undefined` — this must be a per-manager mapping, not a single field read.

```js
// factPointsFromServiceEvidence(evidence, {ts}) — models metricPointsFromEvidence's
// evidence.find(id, status==="ok") pattern (daemon.js L53-112).
function factPointsFromServiceEvidence(evidence, { ts }) {
  const envelope = evidence.find(e => e.id === "services" && e.status !== "unable");
  if (!envelope) return [];
  const services = envelope.result?.services ?? [];
  const manager = envelope.result?.manager;
  return services.map(service => {
    // Explicit per-manager field mapping (must-fix): systemd → name/running boolean;
    // launchd → label/state string, no name/running keys.
    const identity = manager === "launchd" ? service.label : service.name;
    const running = manager === "launchd" ? service.state === "running" : Boolean(service.running);
    return {
      ts,
      fact_name: "service.presence",
      entity_key: sanitizeEntityKey(identity),              // §6 gate
      attributes: { running: String(running), manager: String(manager) },
      source_envelope_id: envelope.id,
      source_tool: envelope.trace?.tool,
      sensitivity: "operational",
    };
  }).filter(point => point.entity_key); // defensively drop any entry whose identity field was missing/unsanitizable
}
```

`factPointsFromNetworkEvidence(evidence, {ts})` reads `envelope.id === "network-basics"`, `result.listening_sockets` (or whatever the actual field name is — **verify against `network.js`'s `collectNetworkEvidence` result shape before implementing**, the map's line numbers cite the *parser* functions, not the final aggregated `result` key, which must be confirmed in this slice's first commit). For each socket:
- **Minor fix, applied here:** `entity_key = sanitizeEntityKey(`${protocol}:${local_address}:${local_port}`)` — **includes `local_address`**, not just `protocol:port`. A bare `protocol:port` key would collide across genuinely distinct sockets that differ only by bind address (dual-stack `0.0.0.0:8080` vs `[::]:8080`, or a specific interface vs loopback on the same port) and would systematically discard legitimately-stable per-address facts once the miner's contradiction check saw the merged group "flip" between addresses. Folding `local_address` in keeps each physically distinct socket its own mining group.
- If the owning process can be resolved (macOS `lsof`-based parser only — the Linux parser has **no** pid/command field today, per the grounding above): `attributes: {owner: sanitizeEntityKey(command), owner_known: "true"}`.
- If it cannot be resolved (Linux today; or macOS `lsof` failure): **do not fabricate** — either omit the fact entirely, or emit `attributes: {owner_known: "false"}` with `sensitivity` unchanged and a `confidence:0`/`review_hint:"missing_permission"`-style marker mirroring `timedEnvelope`'s degrade pattern (folded into the fact point as an additive field, e.g. `confidence: 0`, since the fact schema doesn't otherwise carry the envelope's `confidence`/`review_hint`). **S6c's miner must treat `owner_known:"false"`/`confidence:0` facts as non-observations** — never counted as confirming or contradicting evidence (§6, §4).
- **Scope note (not a design change, flagged so it isn't mistaken for a bug):** given the current Linux collector's total lack of owner resolution, `port-binding-identity` mining will, in practice, produce essentially **zero** draft constraints on Linux hosts for v1 — every sample degrades to `owner_known:"false"` and is excluded from mining. This family is effectively macOS-only until a Linux owner-resolution path (e.g. `/proc/net/tcp` + `/proc/<pid>/fd` inode matching, itself a future slice) exists. `service-presence` mining is unaffected and works on both managers per the branching fix above.

`factPointsFromScheduledJobsEvidence` is **deferred** — the roadmap names only service-presence and port-binding as S6c's two mining families; a scheduled-jobs translator with no consumer is dead code. S6a still *collects* scheduled-jobs evidence (for future use / manual inspection); S6b does not need to translate it into facts yet. Document this explicitly as an intentional scope cut, not an oversight.

### TDD test list (new `test/fact-store.test.js`, `test/fact-translators.test.js`)

1. `resolveFactStorePaths` — correct path (`stateDir/learned/facts/facts.jsonl`), no double-nesting, `assertNoPiOwnedPath` passes.
2. `normalizeFactPoint` — required-field validation (empty `fact_name`/`entity_key` throw); `attributes` normalization drops `undefined`/`null`, stringifies, caps length; accepts a categorical/string `attributes` map that would `throw` if run through `normalizeMetricPoint` (explicit cross-check test proving the two schemas are genuinely distinct); defaults (`sensitivity`, `source_*`) apply correctly.
3. `appendFactPoints`/`readFactPoints` round-trip — write N points, read them back, verify shape; ENOENT read returns `{records:[], corrupt_count:0}`; corrupt lines are skipped and counted, not thrown; invalid-schema lines (e.g. a hand-edited file missing `entity_key`) are dropped on read, not counted as `corrupt_count` (mirrors the metric-point drop/`corrupt_count` split).
4. `enforceFactRetention` — points older than `retentionMs` are dropped; file stays under `maxBytes` (newest-first retained); rewrite is atomic (tmp file appears and is renamed — assert via a crash-simulation test if feasible: kill between tmp-write and rename, confirm original file is untouched).
5. `factPointsFromServiceEvidence` — **must-fix, both managers now covered:** systemd-style fixture envelope (`manager:"systemd"`, 3 services: 2 `running:true`, 1 `running:false`) → 3 fact points with correct `entity_key`/`attributes.running` read from `name`/`running`; **launchd-style fixture envelope** (`manager:"launchd"`, services shaped `{label,pid,state,...}`, no `name`/`running` keys) → fact points with `entity_key` read from `label` and `attributes.running` derived from `state==="running"`, proving the per-manager branch actually dispatches correctly rather than silently reading `undefined`; envelope with `status:"unable"` → `[]` (no fabrication); envelope missing entirely from evidence array → `[]`; a service entry missing its identity field entirely is dropped, not emitted with an empty `entity_key`.
6. `factPointsFromNetworkEvidence` — macOS-style envelope with resolvable owner → fact with `owner`/`owner_known:"true"`; Linux-style envelope (no pid/command) → fact with `owner_known:"false"`/`confidence:0`, **not** a fabricated owner; envelope with `status:"unable"` → `[]`; **must-fix:** two sockets sharing the same `protocol:port` but differing `local_address` (e.g. `0.0.0.0:8080` vs `[::]:8080`) produce **two distinct** `entity_key`s, not one merged/colliding key.
7. Sanitization at emission — a service name / process command containing a path-like or over-length string is truncated/redacted by `sanitizeEntityKey` **before** it reaches `entity_key`, verified by a fixture with a deliberately hostile input (e.g. `/usr/local/bin/../../etc/passwd`-shaped service name) — this is the first concrete test of the §6 gate, exercised end-to-end from raw collector shape to stored fact.
8. Config gate — `appendFactPoints`/translators are not invoked by daemon-loop code when `loadLearnedConfig(...).enabled === false` (integration-level, likely asserted in S6a's daemon.test.js once wired, cross-referenced here).

### Acceptance criteria
- `facts.jsonl` round-trips correctly, survives corruption, respects retention, and never throws on a categorical value the way `normalizeMetricPoint` would.
- Both translators (service-presence, port-binding) degrade to `owner_known:"false"`/`confidence:0` rather than fabricating on unprivileged/unresolvable input, provably by fixture test.
- No raw filesystem path or unbounded string reaches `entity_key`/`attributes` in any translator output — proven by an adversarial fixture, not just documentation.

### Safety notes
- This is the first slice where collected evidence is durably persisted outside `metrics.jsonl` — retention cap and atomic writes are mandatory, not optional, given facts feed S6c/S7 decisions.
- UID-scoping (§11 of the roadmap) is enforced entirely in the translators, at the earliest possible point — nothing downstream (miner, shadow evaluator) needs its own owner-resolution logic.

---

## 4. Slice S6c — Deterministic constraint miner

### Goal
`mineConstraintCandidates(factHistory, snapshots, options)` over S6b's `facts.jsonl`, for exactly two families — `service-presence` and `port-binding-identity` — emitting `status:"draft"` constraints (constraint-store.js shape) that are **inert**: never evaluated by `evaluateConstraints` (which only processes `status==="active"`), never shown to a user automatically, only reachable via the new on-demand `descartes learned mine` CLI command.

### Algorithm

**Input:** `factHistory` — either the array returned by `readFactPoints(descartesPaths, {windowMs})`, or (for pure-function testability) a plain array of already-normalized fact points passed directly. **Signature, corrected to match the roadmap's documented contract (minor fix, applied here):** `mineConstraintCandidates(factHistory, snapshots, options = {})`. Roadmap §3.2 documents a three-argument signature (`factHistory, snapshots, options`) to leave room for future families (e.g. process-ancestry, resource-ceiling) that need point-in-time snapshots rather than pure fact-history deltas. Neither of this slice's two families (`service-presence`, `port-binding-identity`) needs snapshot data — both are evaluated purely over the fact-history window — so S6c passes `snapshots = []` (or `undefined`) from its own CLI wrapper and the parameter is **accepted but unused** in this slice's implementation, with a one-line comment at the top of `mineConstraintCandidates` stating so explicitly. This keeps the exported signature stable for later families rather than silently narrowing it, while not inventing snapshot-consuming logic this slice doesn't need. A thin `descartes learned mine` CLI wrapper calls `readFactPoints` then `mineConstraintCandidates(factHistory, [], options)`. Keep the miner itself I/O-free (mirrors `evaluateConstraints`'s "pure, no I/O" doc comment).

**Options:** `{ minObservationDays = 7, minSamples = 3, now = Date.now() }`.

**Grouping:** group fact points by `(fact_name, entity_key)`. For each group:
1. Discard any fact point with `attributes.owner_known === "false"` or `confidence === 0` — **never used as either confirming or contradicting evidence** (this is where the port-binding translator's degrade-don't-fabricate marker gets honored downstream).
2. If the remaining group has `< minSamples` points, or the group's `(max(ts) - min(ts))` span is `< minObservationDays` days, skip — insufficient evidence.
3. Compute the set of distinct `attributes` values observed (for `service.presence`: distinct `attributes.running` values; for the port-binding family: distinct `attributes.owner` values). If the set has **more than one distinct value** (a contradiction — the fact changed), skip entirely — mining never emits a constraint over a fact that flipped, by design ("zero contradicting observations").
4. If the set has exactly one distinct value across `>= minSamples` samples spanning `>= minObservationDays`, emit one draft constraint.

**Emitted constraint shape** (constraint-store.js-compatible, `status:"draft"`):
```js
{
  id: `constraint.mined.${family}.${sanitizedHash(entity_key)}`,  // see §6 — never the raw entity_key
  kind: "constraint",
  family: "service-presence" | "port-binding-identity",
  target: sanitizeMinedTarget({fact_name, entity_key}),           // §6 gate, bounded
  expected: { comparator: "eq", value: <the single observed value, as a bounded string> },
  status: "draft",
  confidence: <fraction of non-degraded samples / total samples in window, 0..1>,
  provenance: {
    window: `${minObservationDays}d`,
    samples: <count>,
    source_collectors: [<distinct source_envelope_id values observed>],
    mined_at: <iso now>,
  },
  fixtures: [
    { input: { [fact_name]: <observed value> }, expect_match: true },
    { input: { [fact_name]: <a deliberately different value> }, expect_match: false },
  ],
  promotion_history: [],
  first_observed: <min ts in group>,
  last_verified: <max ts in group>,
  sensitivity: "operational",
  schema_version: SCHEMA_VERSION, // from constraint-store.js
}
```
The `constraint.mined.` id prefix (`` `constraint.mined.${family}.${sanitizedHash(entity_key)}` ``) is a deliberate, tested reserved namespace: mined ids are structurally distinguishable from hand-authored `SEED_CONSTRAINTS` ids (e.g. `constraint.daemon.interval_ms.min`) by prefix alone, not by a probabilistic hash-collision argument — a test asserts every mined id starts with `constraint.mined.` and that no `SEED_CONSTRAINTS` id does, so CLI/audit output can trivially discriminate provenance at a glance.

Note `expected: {comparator:"eq", value:<string>}` — this is a **categorical equality** shape, distinct from `constraint-eval.js`'s existing numeric `eq` (which does `Number(expected.value)`/`Number(factValue)` coercion and would misbehave against a string like `"true"`). **This plan explicitly does not modify `constraint-eval.js` in S6c** (draft constraints are never evaluated, so `evaluateExpected`'s behavior against this shape is moot for now) — but flags it as a required prerequisite fix **before S7 promotes anything past `shadow`**, since shadow *does* evaluate constraints against live facts. See §5 and §8 (open question).

`mineConstraintCandidates` does **not** write to `constraints.json` itself — it returns an array of candidate records. The CLI command (`descartes learned mine`) is responsible for merging them into the existing store via `constraint-store.js`'s writer, deduplicating by `id` (re-mining the same stable fact should update `last_verified`/`provenance`/`fixtures` on the existing draft, not create a duplicate — `id` is deterministic from `family`+`entity_key` precisely so re-mining is idempotent).

### Pre-mining sanitization gate (HARD GATE — detailed here, cross-referenced in §6)

Every mined constraint's `id`, `family`, and `target` must be bound/sanitized **before** the record is constructed, not after:
- `family` is drawn from a closed enum (`"service-presence"` | `"port-binding-identity"`) — never derived from raw data, so no sanitization needed, but validate it's one of the two known families defensively.
- `entity_key` arriving from S6b's `facts.jsonl` was **already** sanitized at the translator boundary (§3) — but the miner must not assume that invariant holds forever (facts.jsonl could in principle be hand-edited, or a future translator could regress). Re-apply the same `sanitizeEntityKey`/allowlist function to `entity_key` before it is embedded in `target`, as defense-in-depth.
- `target` is built as `` `${fact_name}.${sanitized_entity_key}` `` — bounded by construction to the same `SAFE_STRING_PATTERN`/length cap as `diagnostics-sanitizer.js`'s `isSafeEnumString`.
- `id` is built from a **hash** of `(family, entity_key)`, not the raw `entity_key` concatenated in — reuses `alert-store.js`'s `alertId()`-style hashing (same fixed-length hex-hash pattern `diagnostics-sanitizer.js` already treats as safe) so `id` is guaranteed to satisfy the sanitizer's `isFixedLengthHexHash` check regardless of what the source data looked like.
- **New shared function**, added to `diagnostics-sanitizer.js` (extends the existing module rather than duplicating its regex/length constants): `sanitizeIdentityString(value, {maxLength = MAX_STRING_LENGTH} = {})` → returns a bounded, allowlisted string or a fixed redaction marker, built from the exact same `SAFE_STRING_PATTERN`/`MAX_STRING_LENGTH` already exported. `sanitizeEntityKey` (fact-translators.js, S6b) and the miner's `target`/`id` construction (S6c) both call this one function — one implementation, two call sites, not two reimplementations.
- **Standing bug flagged, not silently fixed in this slice:** `constraint-eval.js`'s `buildViolationCandidate()` interpolates raw `constraint.id`/`constraint.target` into `title`/`summary` without sanitization (§0 grounding). Because S6c constraints stop at `status:"draft"` (never evaluated) and S7's shadow path writes to `shadow-violations.jsonl` (not through `buildViolationCandidate` at all — see §5), this bug is **not yet reachable** by mined data. It becomes reachable the moment any mined constraint reaches `status:"active"` (S7's final gate). **Required fix, scoped to S7, not S6c:** harden `buildViolationCandidate` to run `constraint.id`/`constraint.target` through `sanitizeIdentityString` before interpolating into `title`/`summary`, with a regression test proving hand-authored `SEED_CONSTRAINTS` (already-safe identifiers) render identically before/after. Tracked as an explicit S7 acceptance item, not an assumption.

### On-demand CLI

`descartes learned mine [--json] [--window <duration>]` — new `learned` command family in `index.js` (first `learned` subcommand; establishes the dispatch pattern S7 extends). Reads facts via `readFactPoints`, calls `mineConstraintCandidates`, merges into `constraints.json` via `constraint-store.js`'s writer, prints a summary (new/updated/unchanged draft counts). Does **not** require `configDir/learned.json` `enabled:true` (mining is an explicit, on-demand, read-only-of-facts action a human runs deliberately — consistent with convention #4's "flag gates automatic/background work only").

### TDD test list (new `test/constraint-miner.test.js`)

1. Stable fact, sufficient window/samples → exactly one draft constraint emitted, correct shape, `confidence` reflects the non-degraded sample fraction.
2. Fact with `< minSamples` → no constraint emitted.
3. Fact spanning `< minObservationDays` → no constraint emitted (even with many samples clustered in a short window).
4. Fact that flips (two distinct `attributes` values in the window) → no constraint emitted for that group, **and** other stable groups in the same input still mine correctly (one contradicting group doesn't poison the batch).
5. Degraded samples (`owner_known:"false"`/`confidence:0`) are excluded from both the sample count and the contradiction check — a group with 2 confirming + 5 degraded samples over the window does **not** mine (insufficient real samples), and a group with 5 confirming + 2 degraded-but-*different*-value samples still mines (degraded samples never count as contradicting).
6. Adversarial `entity_key`/service-name fixture (path-like, over-length, special characters) → mined `id`/`target` pass `diagnostics-sanitizer.js`'s allowlist checks directly (import and reuse `isSafeEnumString`/`isFixedLengthHexHash` in the test assertion, not a hand-rolled regex) — this is the concrete, automated proof of the HARD GATE, not just documentation.
7. Idempotent re-mining — mining the same stable fact twice produces the same `id`, with `last_verified`/`provenance.samples` updated on the second run rather than a duplicate record.
8. `descartes learned mine` CLI — merges into `constraints.json` without disturbing existing `SEED_CONSTRAINTS` or previously-mined drafts of unrelated families; `--json` output shape test.
9. Two families in one input (service-presence + port-binding facts mixed) → both mined independently and correctly, `family` field correctly discriminates.
10. `sanitizeIdentityString` (in `diagnostics-sanitizer.js`'s own test file) — unit tests for the new shared function in isolation (safe passthrough, redaction of unsafe input, length cap), before it's consumed by the miner.
11. Reserved id namespace — every mined `id` starts with `constraint.mined.`; no `SEED_CONSTRAINTS` id does (imports `SEED_CONSTRAINTS` directly rather than hardcoding a copy, so the assertion tracks the real seed list).
12. `mineConstraintCandidates(factHistory, snapshots, options)` — called with `snapshots` omitted/`[]`/`undefined` all behave identically (proves the reserved third parameter is truly inert for the two in-scope families, not silently required).

### Acceptance criteria
- Mined constraints are always `status:"draft"`, never directly `"active"`, provable by a test that scans every code path in `mineConstraintCandidates` for a hardcoded status.
- `evaluateConstraints` (already shipped, `status==="active"` only) is provably never invoked on a freshly-mined draft in any test or CLI path in this slice — regression test: mine against a fixture that would obviously violate its own constraint if evaluated, assert no alert candidate is ever produced end-to-end.
- Every mined `id`/`family`/`target` passes `diagnostics-sanitizer.js`'s existing allowlist functions, verified by direct reuse of those functions in tests (not reimplemented assertions).

### Safety notes
- No rollup/downsampled store is introduced in this slice (per roadmap §12 — resolve by attempting mining against the real S6b window first). If `minObservationDays=7` mining against `facts.jsonl`'s default 30-day retention proves insufficient in practice (e.g., retention needs to be longer than convenient for a single flat file), that's the trigger condition documented in §8's open questions — not a reason to add `rollup/*.jsonl` preemptively here.
- Miner is pure/no-I/O; all file access is isolated to the CLI wrapper, keeping the algorithm itself trivially unit-testable and audit-reviewable.

---

## 5. Slice S7 — Shadow soak, deterministic promotion gate, human approve

### Goal
`draft → shadow` → (soak window, fires only to `shadow-violations.jsonl`, never a real alert) → deterministic promotion check (zero shadow false-fires + minimum-fixture bar) → `review-ready` → **human-gated** `review`/`approve`/`reject` → `active`, recorded in `stateDir/authority/promotions.json` with nonce, expiry, deny-by-default, full audit trail. **No LLM anywhere.** Constraints never self-promote past `review-ready`.

### Prerequisite fix (must land first, own commit, own tests)
Per §4's flagged standing bug: extend `constraint-eval.js`'s `evaluateExpected()` with a **string-equality branch** so the categorical `{comparator:"eq", value:<string>}` shape S6c emits evaluates correctly (today, `Number("true")` is `NaN`, so a categorical constraint would evaluate as permanently-violated). Add: if `expected.comparator === "eq"` and `typeof expected.value === "string"`, do strict string equality against `String(factValue)` **without** the numeric coercion branch. Existing numeric `eq` behavior (`Number.isFinite(Number(expected.value))`) must remain byte-identical — test both paths side by side, plus a regression test that `SEED_CONSTRAINTS`' existing numeric-`eq`-shaped seeds (if any) evaluate unchanged. Also land the `buildViolationCandidate` sanitization hardening flagged in §4 here (harden `title`/`summary` construction to run `constraint.id`/`constraint.target` through the new `sanitizeIdentityString` before interpolation), with a regression test proving `SEED_CONSTRAINTS` render identically before/after.

### Exact shapes / paths

**Shadow evaluation is structurally separate from real alerting — not a flag, a different code path.** New file `tools/descartes-cli/src/shadow-store.js`:
```js
export function resolveShadowStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, shadowViolationsFile: path.join(dir, "shadow-violations.jsonl") };
}
```
New function in `constraint-eval.js` (or `shadow-store.js` — recommend `constraint-eval.js` since it's the natural sibling of `evaluateConstraints`, same pure/no-I/O contract): `evaluateShadowConstraints(shadowConstraints, factLookup)` — filters `status === "shadow"` (not `"active"`), reuses `evaluateExpected` internally, but returns a **distinct record shape**, never an alert-candidate:
```js
{ ts, constraint_id, family, target, expected, actual, fired: <bool> }
```
This is deliberately not routed anywhere near `alertId()`/`buildViolationCandidate`/`applyAlertCandidates` — the type signature itself makes "shadow fires can't accidentally become real alerts" a structural property, not a runtime check someone could get wrong. `appendShadowRecords(descartesPaths, records)` appends only `fired:true` records (or all records with `fired` recorded — recommend logging both fires and non-fires so the soak-window promotion check in the next step can distinguish "constraint has been observed with zero fires" from "constraint has never been observed at all") to `shadow-violations.jsonl`, JSONL append, same corrupt-tolerant read pattern as `facts.jsonl`.

**Draft → shadow transition.** Deterministic, automatic (does not require human action — shadow mode is observe-only, never reaches a real alert or a human's attention until promotion). Gate: a draft constraint is eligible for shadow once it has `fixtures.length >= MIN_FIXTURE_COUNT` (the "minimum-fixture bar enforced at promotion", roadmap wording — recommend `MIN_FIXTURE_COUNT = 2`, matching what S6c's miner already emits by construction, so in practice every S6c draft is immediately shadow-eligible; the bar exists as a schema-level enforcement point for *any* future constraint source, hand-authored or mined, not just today's miner). New function `promoteDraftsToShadow(constraints, {now})` — pure, returns updated constraint array with eligible drafts' `status` flipped to `"shadow"` and a `promotion_history` entry appended (`{ts, from:"draft", to:"shadow", actor:"deterministic-gate", note:"minimum-fixture bar met"}`).

**Shadow → review-ready transition.** Deterministic soak-window check: `checkShadowSoak(constraint, shadowRecords, {soakDays = 7, now})` — true iff the constraint has been in `status:"shadow"` for `>= soakDays` (via `promotion_history`'s `shadow` entry timestamp) **and** zero `shadow-violations.jsonl` records with `fired:true` exist for that `constraint_id` in the soak window **and** at least one non-fired observation exists per day of the window (proves the constraint was actually being checked, not silently idle — avoids "promoted because nobody looked" false confidence). `promoteShadowToReviewReady(constraints, shadowRecords, {soakDays, now})` — pure, same append-to-`promotion_history` pattern, flips eligible `shadow` constraints to `"review-ready"`.

**Must-fix, applied here: shadow *evaluation/logging* is split from the shadow→review-ready *promotion check*, and only the former is daemon-wired.** The soak gate's "daily observation coverage" requirement needs *something* to generate a coverage record roughly daily without requiring a human to remember to run a CLI command every day — but Open Question §8.3 (unchanged) is specifically about keeping the *promotion decision* CLI-only. These are different operations and can be split cleanly:

- **`evaluateAndLogShadowConstraints(descartesPaths, {now})` — new, additive, daemon-wired.** Reads `constraints.json`, filters `status==="shadow"`, calls `evaluateShadowConstraints` against the latest facts (`readFactPoints`), appends every result (fired and non-fired) via `appendShadowRecords`. This function is called from `runDaemonIteration`'s existing S6a structural-tick block (same `structuralDue` gate, same `withDeadline` wrapper, same `loadLearnedConfig(...).enabled` kill switch, same wall-clock cadence — no new timer, no new checkpoint), as one more additive step alongside `collectStructuralEvidence`. It is a **cheap no-op** whenever no constraint is in `status:"shadow"` (true for the entire lifetime of this plan until S7's own `promoteDraftsToShadow` first runs), so it adds negligible cost to the structural tick before there's anything to evaluate. This is the mechanism that makes "daily observation coverage" real: at the default hourly structural cadence, a shadow constraint accrues ~24 coverage records per day automatically, with no human action required — closing the gap the review flagged (§0.1).
- **`descartes learned soak [--json]` — unchanged in spirit, narrowed in scope, still purely on-demand/CLI, per Open Question §8.3.** Reads `constraints.json` and `shadow-violations.jsonl` (populated by the daemon-wired step above, or empty if `learned.enabled` is off / no structural tick has run yet — `soak` degrades to "nothing eligible" in that case, it never evaluates constraints itself), calls `promoteDraftsToShadow`, then `checkShadowSoak`/`promoteShadowToReviewReady` against the accumulated records, writes the updated constraint array back via `constraint-store.js`'s writer. `soak` no longer performs evaluation inline — it only ever makes **promotion decisions** off of already-logged data, keeping the human-invoked/CLI-only boundary exactly where §8.3 places it. This also means `soak`'s output is now deterministic given `shadow-violations.jsonl`'s contents, simplifying its tests (no fact-reading/evaluation mocking needed in `soak`'s own test file — that's covered by `evaluateAndLogShadowConstraints`'s tests instead).

This is the one place in this plan where S7 touches `daemon.js` (a single additive call inside S6a's already-reviewed structural-tick block) — noted explicitly here and in §9's blast-radius summary, since §9 originally described S6a as the *only* slice touching the daemon loop.

**Review-ready → active: strictly human-gated.** New file `tools/descartes-cli/src/promotion-store.js`:
```js
export function resolvePromotionStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "authority");
  return { dir, promotionsFile: path.join(dir, "promotions.json") };
}
```
Shape (`stateDir/authority/promotions.json`, atomic tmp+rename, `0o600`, mirrors `constraint-store.js`'s whole-file-array pattern exactly):
```js
{
  schema_version: 1,
  promotions: [
    {
      constraint_id, nonce, requested_at, expires_at,   // deny-by-default: no matching, unexpired nonce => denied
      actor: "human-cli",
      decision: "pending" | "approved" | "rejected",
      decided_at,
      note,
    },
  ],
}
```
- `descartes learned review [--json]` — lists all `status:"review-ready"` constraints with their `fixtures`, `provenance`, and shadow-soak history (read-only, no state change) — this is the human's inspection surface. Also mints a fresh `promotions.json` entry with `decision:"pending"`, a random `nonce`, and `expires_at` (recommend a short window, e.g. 24h) if one doesn't already exist for that constraint — this is what `approve`/`reject` will match against.
- `descartes learned approve <constraint-id> [--nonce <nonce>] [--json]` — requires the caller to supply the nonce shown by `review` (a simple confirm-you-looked-at-it friction, not cryptographic security — this is a local single-user CLI, the nonce's job is accidental-double-invocation/stale-review protection, not an attacker model). Fails (deny) if: no pending promotion record exists for that id, the nonce doesn't match, or `expires_at` has passed (expired reviews must be re-issued via `review` — **deny-by-default**, not "approve anyway"). On success: constraint flips `review-ready → active` in `constraints.json`, `promotion_history` gets `{ts, from:"review-ready", to:"active", actor:"human-cli", note}`, `promotions.json`'s record flips to `decision:"approved"`, `decided_at` set.
- `descartes learned reject <constraint-id> [--nonce <nonce>] [--note <text>] [--json]` — same matching rules; on success flips the constraint to `status:"retired"` (not back to `draft` — a rejected mined constraint should not silently re-mine and re-cycle without investigation; re-mining produces a **new** `id` only if the underlying fact changed, so a `retired` constraint naturally falls out of consideration unless the fact itself changes) and records `decision:"rejected"`.

### TDD test list (new `test/shadow-store.test.js`, `test/promotion-store.test.js`, extend `test/constraint-eval.test.js`)

1. `evaluateExpected` string-eq branch — categorical `{comparator:"eq", value:"true"}` against matching/non-matching string facts; numeric `eq` behavior unchanged (regression); malformed shapes still `{supported:false}`.
2. `buildViolationCandidate` sanitization hardening — adversarial `constraint.id`/`constraint.target` (path-like/over-length) no longer appears raw in `title`/`summary`; `SEED_CONSTRAINTS`-shaped safe identifiers render byte-identical before/after (regression).
3. `evaluateShadowConstraints` — filters strictly on `status==="shadow"` (ignores draft/active/review-ready/retired); returns `fired:true` on violation, `fired:false` on satisfied; unsupported `expected` shape and undefined-fact cases mirror `evaluateConstraints`'s skip semantics; **never** produces an object containing `rule_id`/`diagnostics`/anything resembling an alert-candidate shape (type-shape assertion, catches accidental cross-wiring).
4. `appendShadowRecords`/shadow-violations.jsonl round-trip, corrupt-tolerant read, `assertNoPiOwnedPath`.
4a. **`evaluateAndLogShadowConstraints` daemon wiring (must-fix, new)**, in `test/daemon.test.js` alongside S6a's structural-tick tests: no-op (no facts read, no file written) when zero constraints are `status:"shadow"`; with one shadow constraint and matching facts, appends exactly one record per structural tick to `shadow-violations.jsonl` via the existing structural cadence/checkpoint/deadline machinery (no second timer, no new checkpoint file); respects `loadLearnedConfig(...).enabled === false` (skipped, matching convention #4); over N simulated structural ticks spanning multiple days, produces one coverage record per tick — the concrete proof that "daily observation coverage" accrues automatically rather than requiring a human to run anything.
5. `promoteDraftsToShadow` — draft with `fixtures.length >= MIN_FIXTURE_COUNT` promotes; below-threshold draft does not; `promotion_history` entry appended correctly; non-draft statuses untouched (idempotent no-op on an already-`shadow` constraint).
6. `checkShadowSoak` — zero fires over full `soakDays` window with daily observation coverage → eligible; any `fired:true` record in the window → **not** eligible (even a single false-fire blocks promotion, per "zero shadow false-fires"); insufficient daily observation coverage (gap of missed soak checks) → not eligible even with zero fires (proves "nobody looked" doesn't count as "nothing happened"); `soakDays` not yet elapsed → not eligible.
7. `promoteShadowToReviewReady` — end-to-end with a fabricated shadow-violations fixture spanning a full clean soak window → constraint flips to `review-ready`; a fixture with one fire on day 3 → constraint stays `shadow` indefinitely (does not silently retry/reset without operator awareness — confirm the constraint remains inspectable/visible as "shadow, has fired" rather than disappearing).
8. `descartes learned review` — lists only `review-ready` constraints; read-only (no mutation to `constraints.json` on a bare `review` call beyond minting a pending `promotions.json` entry); shows fixtures/provenance/soak history in output.
9. `descartes learned approve` — correct nonce + unexpired → `active`, `promotions.json` updated, `promotion_history` updated; wrong nonce → denied, no state change; expired → denied, no state change; approving a constraint with no pending promotion record → denied (cannot skip `review`); approving twice → second call denied (already decided, not pending).
10. `descartes learned reject` — mirrors approve's matching rules; results in `status:"retired"`, not `"draft"`.
11. **Load-bearing safety regression** (mirrors Slice 2's precedent): assert that at no point in the `draft → shadow → review-ready` pipeline does a fixed-rule alert's behavior change, and that a shadow-fired constraint **never** appears in `alerts list`/`applyAlertCandidates` output — construct a fixture where a shadow constraint would obviously fire, run the full daemon-adjacent pipeline, assert zero alert candidates reference it.
12. End-to-end integration fixture: mine (S6c) → simulated structural ticks over a clean fact history (driving `evaluateAndLogShadowConstraints` to populate `shadow-violations.jsonl` with zero fires and full daily coverage, per item 4a) → `descartes learned soak` promotes to `review-ready` off that already-logged data → `review` → `approve` → constraint is `active` → **only now** does `evaluateConstraints` (already shipped) pick it up and, if violated, produce a real sanitized alert candidate through the existing Slice 2 `extraCandidates` merge — this is the one test in the whole plan that proves the full pipeline, including the daemon-wired evaluation step, connects end-to-end as designed.

### Acceptance criteria
- No constraint reaches `status:"active"` without an explicit, nonce-matched, unexpired `descartes learned approve` call — provable by exhaustively testing every other path (mine, soak, review, reject, expiry) never sets `status:"active"`.
- Shadow fires are structurally incapable of reaching `alerts list`/`applyAlertCandidates` — proven by type-shape tests and the end-to-end regression, not just by absence of a wiring call.
- `promotions.json` provides a full audit trail: every `approve`/`reject` (successful or denied) is attributable to a record with a timestamp; denied attempts do not silently disappear (recommend logging denied attempts too — an audit-trail append even on denial, distinct from the pending/approved/rejected `decision` field, e.g. a `denial_log` array or a `decision:"denied"` terminal state alongside `pending/approved/rejected` — pick one and test it explicitly).

### Safety notes
- This is the load-bearing safety slice of the whole plan. Every other slice produces data that is inert until this slice's human gate says otherwise.
- Deny-by-default is enforced at three independent points (no pending record, mismatched nonce, expired nonce) — any one of them failing closed is sufficient; the tests must exercise all three independently, not just one representative case.
- No LLM is invoked anywhere in `mine`/`soak`/`review`/`approve`/`reject`/`evaluateAndLogShadowConstraints` — grep-able absence of any `pi-harness.js`/`alert-intelligence.js` import in `constraint-miner.js`, `shadow-store.js`, `promotion-store.js` is itself a cheap regression check worth adding as a lint-style test (e.g., a test that reads each new file's source and asserts no forbidden import string appears).
- **Daemon touch, scoped and regression-tested (must-fix resolution).** S7's only change to `daemon.js` is the single additive `evaluateAndLogShadowConstraints` call inside S6a's existing structural-tick block (§5 above) — same cadence, same checkpoint, same deadline, same kill switch, no new timer. It writes only to `shadow-violations.jsonl` (never `constraints.json`, never real alert state) and is a no-op until a constraint first reaches `status:"shadow"`. Covered by the same byte-identical-fast-path regression discipline as S6a (convention #8): a fixture with zero shadow constraints must produce a structural tick identical to pre-S7 behavior.

---

## 6. Pre-mining sanitization gate — summary (cross-cutting, detailed in §4/§5 above)

Three independent, layered points of enforcement, not one:
1. **At fact emission (S6b):** `sanitizeEntityKey` (built on a new shared `sanitizeIdentityString` in `diagnostics-sanitizer.js`) bounds `entity_key`/attribute values the moment they leave a translator, before they're ever written to `facts.jsonl`.
2. **At mining (S6c):** the miner re-applies the same sanitizer to `entity_key` as defense-in-depth (never trusts that upstream data stayed clean), and constructs `id` from a hash rather than raw concatenation, guaranteeing `id`/`target`/`family` all pass `diagnostics-sanitizer.js`'s existing allowlist functions — proven by tests that literally import and call those functions against mined output, not by a parallel hand-rolled check.
3. **At evaluation (S7 prerequisite fix):** `constraint-eval.js`'s `buildViolationCandidate` is hardened to sanitize `constraint.id`/`constraint.target` before interpolating into `title`/`summary` (previously only `diagnostics` was sanitized) — this is the point where, absent the fix, a raw value could have reached a real alert's user-facing text. Fixed before any mined constraint can reach `status:"active"` and therefore before `evaluateConstraints` is ever exercised against mined data for real.

No slice ships mined data to a wider audience than the previous point in this chain without the corresponding gate already landed and tested.

---

## 7. Safety section (applies across all four slices)

- **All-deterministic, no LLM.** Zero LLM calls anywhere in `daemon.js`'s structural path, `fact-store.js`, `fact-translators.js`, `constraint-miner.js`, `shadow-store.js`, or `promotion-store.js`. The only LLM touchpoint in the entire roadmap (`alert-intelligence.js`) is untouched by this plan and remains gated by its own existing opt-in.
- **Read-only.** No new mutating host action is introduced. S6a only changes *scheduling* of already-shipped read-only collectors. No collector gains a new mutating flag.
- **XDG-only, no Pi paths.** Every new path (`stateDir/learned/facts/`, `stateDir/daemon/structural-checkpoint.json`, `stateDir/learned/shadow-violations.jsonl`, `stateDir/authority/promotions.json`) is resolved through `resolveDescartesPaths()`-derived helpers and checked with `assertNoPiOwnedPath()`. `~/.pi` is never touched, referenced, or read by any new code in this plan.
- **Single kill switch, honored uniformly.** `configDir/learned.json`'s `enabled` flag (default `false`) gates all *automatic/background* work across all four slices (structural collection, fact writing, and — per §0.1's must-fix resolution — S7's daemon-wired `evaluateAndLogShadowConstraints` evaluation/logging step). On-demand human-invoked CLI actions (`mine`, `soak`, `review`, `approve`, `reject`) are intentionally not blocked by this flag, matching the existing precedent that a human explicitly asking for something is a different trust boundary than background automation. The *promotion decision* (`soak`'s draft→shadow and shadow→review-ready transitions) remains CLI-only regardless of the flag — only the underlying evaluation/logging that promotion decisions read from is daemon-wired.
- **Deny-by-default promotion.** No constraint reaches `active` without an explicit, nonce-matched, unexpired human approval, recorded in a dedicated audit store separate from constraint state itself.
- **UID-scoping honesty.** Port-binding facts degrade to `owner_known:"false"`/`confidence:0` when unprivileged resolution fails (confirmed today: unconditionally true on Linux, conditionally true on macOS on `lsof` failure) — never fabricated, and structurally excluded from mining's confirming/contradicting evidence.
- **Fixed rules never weakened.** Nothing in this plan modifies `evaluateAndPersistAlerts`'s existing fixed-rule behavior; the only touch to `constraint-eval.js` is additive (new comparator branch, hardened sanitization on an already-shipped-but-not-yet-exercised code path).

---

## 8. Open questions

1. **Rollup store deferral (roadmap §12).** `stateDir/learned/rollup/*.jsonl` is explicitly **not** introduced by this plan. Resolve only after running `descartes learned mine` against real, accumulated `facts.jsonl` data and observing whether the default 30-day retention / 7-day `minObservationDays` combination actually yields stable mining results in practice. If retention needs to grow past what's comfortable for a single flat JSONL file (or read-time re-validation becomes slow), that's the trigger to design a downsampled rollup — not before.
2. **Structural collection cost inside the foreground loop (S6a) — revised per §0.1's must-fix resolution.** Running `network`/`scheduled-jobs` inline on the same thread as the fast tick is bounded by the new `DEFAULT_STRUCTURAL_TICK_DEADLINE_MS` (45s) wall-time budget (§2) — the realistic worst case, given `collectLaunchdScheduledJobs`'s sequential plist scan (§0), is **tens of seconds to low minutes without the deadline**, not "occasional multi-second" as an earlier draft of this plan characterized it; with the deadline, it is now a hard-capped, tested worst case. This plan accepts the capped tradeoff for v1 (matches the existing single-process, single-loop architecture) and does not add true concurrency/backgrounding. Revisit the 45s ceiling itself if soak testing on a real host shows it's too coarse (delays fast ticks noticeably even when bounded) or too tight (structural collection legitimately needs longer and gets needlessly abandoned).
3. **`descartes learned soak`'s promotion *decision* stays CLI-only; evaluation/logging is now daemon-wired (resolved per §0.1's must-fix).** Per the S7 design above, `evaluateAndLogShadowConstraints` (evaluation + append-to-`shadow-violations.jsonl` only) is wired into S6a's existing structural tick so daily coverage accrues automatically without a human running anything. `descartes learned soak` itself — the deterministic draft→shadow and shadow→review-ready *transition* logic — remains purely on-demand/CLI-invoked, unchanged from the original design intent: a human (or a future scheduled/cron invocation, out of scope here) still has to run `soak` to actually advance a constraint's status. This split is now explicit rather than an unresolved tension.
4. **Scheduled-jobs translator.** S6a collects `scheduled-jobs` evidence at the structural cadence; S6b does not translate it into facts (no consumer exists — S6c only mines `service-presence`/`port-binding-identity`). A `scheduled-job.presence`/`schedule-drift` family is a plausible future mining target but is out of scope here; flagging so the collected-but-unused evidence isn't mistaken for an oversight.
5. **`MIN_FIXTURE_COUNT` and `soakDays` defaults (2 and 7 respectively, recommended above).** These are the "minimum-fixture bar" and soak-window knobs the roadmap calls out as hard schema-level gates, not conventions — the exact numeric defaults are a judgment call this plan makes explicitly so review can push back on them before implementation, rather than leaving them undecided.
6. **Nonce/expiry window for `promotions.json` (24h recommended).** Single-user local CLI, so this is friction-against-mistakes rather than an attacker-model security boundary — flagged for review sign-off on the exact window rather than assumed silently.

---

## 9. Recommended implementation order

**S6a first.** Rationale: it is the slice that makes the first, primary touch to the already-shipped, safety-relevant `daemon.js` loop (revised note, per §0.1: S7 also makes one small *additional* additive touch to the same structural-tick block for `evaluateAndLogShadowConstraints`, but reuses S6a's cadence/checkpoint/deadline/kill-switch machinery wholesale rather than introducing new daemon-loop surface — S6a remains the slice that carries essentially all of this plan's daemon-loop risk). Every other slice (S6b's translators, S6c's miner, S7's soak/promotion) depends on structural evidence existing on a cadence at all. Landing S6a first, with its regression suite proving the existing fast path is byte-identical (now including the wall-time-deadline regression, §2), retires the highest-risk/highest-blast-radius change earliest, while S6b/S6c are purely additive new files with no existing-behavior regression risk of their own, and S7's one daemon-loop addition is small, reuses S6a's already-reviewed seam, and is independently regression-tested (§5's "byte-identical when zero shadow constraints exist" requirement). S6a's own scope is deliberately bounded (scheduling only, structural evidence discarded/log-only until S6b lands) so it ships small and fast, unblocking S6b immediately after.
