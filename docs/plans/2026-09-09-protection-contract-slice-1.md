# Protection-contract slice 1 — declare a job, get truthful coverage + assessment

**Date:** 2026-09-09
**Status:** PLAN
**Basis:** [`docs/architecture/2026-09-05-purpose-first-design.md`](../architecture/2026-09-05-purpose-first-design.md) §2 (the protection contract) / §9 (milestone 1); [`docs/reviews/2026-09-05-design-and-implementation-critique.md`](../reviews/2026-09-05-design-and-implementation-critique.md) §4 (the missing contract) + "What I would build next" #1.
**Roadmap:** HANDOFF "Path A", step 1 of 3 toward "one declared protection job end-to-end". This slice is step 1 only.
**Design input:** synthesized from three independent code-grounded passes — a structural draft (Sonnet), a coverage-mapping spine (Fable 5.1), and never-fabricate guardrails (gpt-6-astra). Where they diverged, the architectural calls are marked **[DECIDED — veto in play]** below.

---

## 1. Goal & scope

**Scope (one line):** declare a protected job and get a **truthful coverage + assessment view** for it, reusing existing collector evidence — **no new detectors, no actions, no LLM.**

Descartes has collectors, deterministic alert rules, and a learned subsystem, but no object that says "*this* matters, and here is what would tell me it's broken." This slice introduces that object — a `ProtectionContract` — and a command that answers honestly: can Descartes currently see the declared subject, and what state is it in?

### What this is NOT (deferred to later slices)
- **NOT incidents / episode identity / a delivery outbox** (critique's next milestone). Assessment is computed fresh per invocation; nothing is persisted as an episode and nothing is dispatched.
- **NOT actions/proposals/execution.** Purely observational (AGENTS.md "read-only by default").
- **NOT LLM investigation.** Deterministic arithmetic over existing evidence; zero calls into `pi-harness.js`/`alert-intelligence.js`.
- **NOT discovery / auto-suggestion of jobs.** The owner names the subject; discovery does not infer importance.
- **NOT the full tolerance/maintenance model** (no hysteresis, no maintenance windows).
- **NOT a "did the scheduled job succeed" signal** — a genuine evidence gap in the current codebase (§4), not a design choice.
- **NOT federation.**

---

## 2. Foundational ground truth (verified — it shapes the whole slice)

**No collector ever emits `status:"error"`.** `timedEnvelope` collapses *every* thrown exception (ENOENT, EACCES, timeout, parse failure) to `status:"unable"`, `confidence:0`, `review_hint:"missing_permission"` (`tools/envelope.js:19-34`). Consequently the daemon's own `collectorHasError` check — `evidence.some(status === "error")` (`daemon.js:870`) — is **unsatisfiable by any collector**; the daemon reaches `state:"error"` only on *persistence* failure (`daemon.js:876`). The daemon deliberately treats `unable` as benign for its own health (`daemon.js:856-858`).

**Implication (the slice's reason to exist):** "benign unsupported" vs. "a real coverage gap" is **not decidable from the evidence alone** — it becomes decidable only once **the contract declares the subject as *required*.** An `unable`/`unknown` on a collector a *declared* subject depends on is a coverage gap; the same status on an undeclared collector stays benign. The view derives this itself; it must **not** wait for or trust the daemon's own `state`.

Where "unsupported" vs. "ran-and-failed" *is* already separated (per collector, not globally): services map unsupported→`unknown`, command-failure→`unable`, systemd failed units→`warning` (`tools/services.js:252-257`); scheduled-jobs similarly (`tools/scheduled-jobs.js:495-504`); **disks/system have no such branch** — `ok` or `unable` only (`tools/disks.js:134-139`).

---

## 3. The key architectural decision — how the view gets its evidence  **[DECIDED — veto in play]**

Two honest designs were proposed. **Decision: fresh on-demand assessment + a persisted-evidence `daemon_watch` disclosure.**

- **Assessment = fresh collection at invocation time.** `protect coverage` calls `collectDiskEvidence()` / `collectServiceEvidence()` directly (`tools/disks.js`, `tools/services.js` — pure `execFile`, no state, **no `learned.json` check anywhere in those modules**). *Why:* this is the only design that satisfies the invariant **"deterministic protection monitoring must be usable without opting into the learned subsystem"** (critique §5) for *both* subjects — the daemon's own service collection is gated behind `learned.json` (`daemon.js:690-692`), so reading the *persisted* fact store would make service coverage require `learned enable`. A fresh collection is also a genuinely *successful, timestamped* observation (satisfying Astra guardrails #1/#4), and avoids a stale "healthy" outliving its evidence.
- **`daemon_watch` disclosure = read persisted daemon evidence.** Because a fresh probe answers "observable *right now, by me*", not "continuously *watched* by the daemon", every `coverage` output carries a `daemon_watch` block built from `readDaemonStatus` (`history-store.js:282-290`, read-only, `undefined` on ENOENT) so the reader is never misled (§7.4). **State it plainly in the command header: slice-1 coverage means "observable on demand," not "continuously watched"** — continuous watching + notification is slice 2.
- **The alternative (rejected for slice 1, worth revisiting):** read only the daemon's persisted evidence (Fable's design) — more literally "coverage = watched", no per-call `execFile` — but it makes service coverage require `learned enable` and depends on the daemon having run. Its precise persisted reads are reused *inside* `daemon_watch` (§7.4).

**Subject order: filesystem/disk FIRST, service SECOND** (Fable's call). Disk is the clean case — a *core* collector (60s, **no learned gate**, `daemon.js:129-136`), per-mount identity, existing thresholds, and a fully-consistent `daemon_watch:true` story. Service is included in the same slice but honestly discloses that the daemon only watches it when learned is enabled. **Scheduled-job is deferred** (§4).

---

## 4. The `ProtectionContract` data object

### Subject types this slice supports: `filesystem` (primary) and `service` (secondary). Scheduled-job deferred.

| Subject | Collector returns | Verdict |
|---|---|---|
| **filesystem** | per-mount `used_fraction`, `available_bytes`, `mount_point` (`tools/disks.js:47-73`) | **Richest & most reliable** — core collector, per-mount identity, reuses `alert-store.js`'s 0.90/0.95 thresholds. **Start here.** |
| **service** | per-unit `running`/`failed`/`restarting` (systemd) or `state`/`nonzero_exit` (launchd) (`tools/services.js:100-134`) | **Strong** current-state evidence, standalone. Costs to disclose: only a boolean `running` survives into facts; daemon watches it only when learned-on. |
| **scheduled-job** | inventory only — existence + parsed schedule; **no run history / exit code / last-success anywhere** (`tools/scheduled-jobs.js:477-493`) | **Deferred** — assessment would be structurally always `unknown`. A "did it succeed" signal is new-collector work (critique §3), out of scope. |

### Fields (slice 1, minimal)
```jsonc
{
  "schema_version": 1,
  "id": "protect_<16-hex>",                 // generated at declare, immutable
  "name": "<owner short name>",
  "subject_type": "filesystem" | "service", // closed set
  "subject": "<mount_point>" | "<systemd unit / launchd label>",
  "success_condition": {                    // DERIVED from subject_type (not free text this slice)
    "type": "used_fraction_below" | "service_running",
    "warn_fraction": 0.90, "critical_fraction": 0.95   // filesystem only; defaulted from alert-store
  },
  "expected_state": "running",              // service only; REQUIRED to assess "failing" (§7.3)
  "severity": "info" | "warning" | "critical",   // display/ordering only this slice (slice-2 compat)
  "notify": { "channel": "cli" },           // validated vs NOTIFICATION_CHANNELS; recorded, never dispatched
  "observation_permission": "granted",      // stub enum (one legal value); reserves the design's perm triad
  "maintenance_windows": [],                // reserved shape only, always empty
  "declared_at": "<iso>", "updated_at": "<iso>"
}
```
- **`success_condition` is derived, not owner-authored** — slice 1 evaluates exactly what existing evidence supports (`used_fraction_below`, `service_running`). Free-text conditions are future work.
- **`declare` touches no collector** — pure metadata write. An owner may declare a contract for a not-yet-installed service; coverage honestly reports `uncovered` until it appears. (Owner declares; discovery does not infer.)
- **`expected_state` is mandatory for services and load-bearing:** `running:false` alone is NOT `failing` — a systemd `Type=oneshot` unit is `active/exited` → `running:false` when healthy, and a launchd on-demand job is normally `not_running` (`tools/services.js:109`, `126-133`). Only when the owner declares `expected_state:"running"` does `running:false` become `failing`; otherwise it is `unknown` (§7.3).

---

## 5. The store — `tools/descartes-cli/src/protection-contract-store.js`

- **Location: `configDir`** (owner-declared *intent*, like `canary-manifest.js:18-20`), not `stateDir` (program-generated). `resolveProtectionContractPaths(descartesPaths) → { configFile: configDir/protection-contracts.json }`.
- **Idiom: mirror `promotion-store.js:75-165`** — `readJsonFile → {parsed, missing, corrupt}` (ENOENT→missing, bad JSON→corrupt, never throws); tolerant `loadProtectionContracts` (missing→`{contracts:[]}`, corrupt→`{contracts:[],corrupt_count:1}`, **per-record validation failures silently dropped** so one bad record never blinds the list); atomic tmp+rename `writeProtectionContracts` (0o600/0o700, every record re-validated before persist); `validateProtectionContract` throws on first invalid field.
- **Validation (fail-fast on write):** non-empty trimmed length-capped `id`/`name`/`subject` (a slice-local cap, self-contained per the codebase's own "duplicated rather than imported" convention, `fact-store.js:169-171`); `subject_type ∈ {filesystem,service}` with matching `success_condition.type` (cross-field); `severity ∈ {info,warning,critical}`; `notify.channel ∈ NOTIFICATION_CHANNELS` (`notification-delivery.js:10`); reject a duplicate `(subject_type, subject)` among live contracts.
- **CRUD:** `declareProtectionContract` / `listProtectionContracts` / `findProtectionContract(id)` / `removeProtectionContract(id)`.
- **Deliberately NOT stored: any coverage/assessment result.** Persisting `last_assessment` would reintroduce the exact bug this slice avoids (a stale "healthy" outliving its evidence). Coverage is always recomputed live.

---

## 6. The CLI surface — `tools/descartes-cli/src/protect.js`

New `index.js` dispatch branch, mirroring `containment`/`incident` (`index.js:226-249`): `if (command === "protect") { const { runProtect } = await import("./protect.js"); await runProtect(paths, args); return; }`. `runProtect(descartesPaths, args, runtime = {})` with `runtime.output ?? console.log` (testable, like `containment.js:40`). Arg parsing mirrors `alerts.js`'s `parseAlertsArgs`.

```
descartes protect declare --name <N> --subject-type filesystem|service --subject <ID>
                          [--warn <f> --critical <f> | --expected-state running]
                          [--severity …] [--notify-channel …] [--json]
descartes protect list [--json]                 # compact: name, subject, coverage, assessment (live-computed)
descartes protect coverage <contract-id> [--json]   # full detail (§7) + daemon_watch + basis
descartes protect remove <contract-id> [--json]
```
`list` and `coverage` are **live-computed every invocation** — with a handful of contracts this is cheap and, more importantly, there is no cache to go stale.

---

## 7. The coverage + assessment mapping (the heart)

### 7.0 The spine rule
**Assessment is forced `unknown` unless `coverage === "covered"`.** No stale, cached, partial, or last-known value may yield anything but `unknown` when coverage isn't established this invocation. Every non-unknown assessment carries a **`basis`** (the measurement + its `observed_at`) so the label never exceeds what was measured.

### 7.1 Coverage vocabulary (first branch = the collector envelope's own `status`)
```
coverage: "covered" | "partial" | "uncovered"
coverage_reason: null
  | "unsupported_platform"                 // envelope.status === "unknown" (platform doesn't apply — benign unless required)
  | "collector_failed"                     // envelope.status === "unable" (a REQUIRED, failing collector — a real gap; carry result.error verbatim, never interpret "missing_permission" as a permission diagnosis)
  | "subject_not_found_in_visible_scope"   // collector ok, named subject absent from what it returned
  | "presentation_truncated"               // subject found only in a lighter-detail projection
```
This reuses the collectors' existing `envelopeStatus()` (`tools/services.js:252-257`) rather than inventing a parallel vocabulary, and it is exactly the critique §1 distinction ("unsupported capability" vs "required-but-failing collector"). The `timedEnvelope` outer-catch folds into `collector_failed` too (both surface as `status:"unable"`).

### 7.2 Filesystem assessment (primary)
`collectDiskEvidence()` → `envelope.status`: `unable` → `uncovered:collector_failed`, `unknown`; `ok` → look up the declared `mount_point` in `result.filesystems`:
- **found → `covered`.** `used_fraction` vs the **same thresholds `alert-store.js:78-86` uses** for `disk.space.high_used_fraction` (0.90/0.95, duplicated-with-citing-comment or exported — open Q3): `<0.90`→`healthy`, `[0.90,0.95)`→`degraded`, `≥0.95`→`failing`. `basis:{metric:"used_fraction", value, observed_at}`.
- **not found → `uncovered:subject_not_found_in_visible_scope`, `unknown`** (unmounted / removable detached / typo — indistinguishable, so never `failing`).
- **Flagged divergence from daemon behavior:** the daemon *skips* `pressure_relevant:false` mounts (virtual/dev-image/APFS-system, `daemon.js:278`). This view does NOT apply that filter — an explicitly *declared* mount is assessed regardless of classification, because the owner declared it (owner-declaration outranks the daemon's default noise-reduction). Call this out in review.
- **Honesty caveat to surface:** `metrics.jsonl` has no completeness ledger (`history-store.js:4`), so a disk coverage claim is only ever "observed + fresh", never "provably continuous".

### 7.3 Service assessment (secondary)
`collectServiceEvidence({ serviceLimit: 200 })` (200 is the collector's hard ceiling, `services.js:81-83`) → `result.services` (full detail, ≤200) and `result.services_census` (light, ≤1000, **only `{name,running}` — no `failed`/`nonzero_exit`**). Match the declared `subject` (systemd unit / launchd label):
- **in `result.services` → `covered`.** Assessment from the success condition itself:
  - `running===true && !failed && !restarting` → `healthy`.
  - `restarting===true` → `degraded` (actively recovering).
  - otherwise (`running===false`, however cleanly) → **`failing` *only if* the contract declares `expected_state:"running"`; else `unknown`** (a healthy oneshot/on-demand unit is legitimately `running:false`). The raw state (`failed` vs cleanly `inactive`) rides in `detail` as annotation, never softening `failing` into something gentler.
- **only in `result.services_census` → `partial:presentation_truncated`.** Only the `running` boolean survives; sufficient for the binary condition (`running ? healthy : (expected_state ? failing : unknown)`), `detail:"state_detail_unavailable_at_presentation_tier"`.
- **in neither, envelope ok → `uncovered:subject_not_found_in_visible_scope`, `unknown` — never `failing`.** "Doesn't appear" is NOT strong evidence of "not running" here: `launchctl list` (non-root) sees the *user* domain only, and `systemctl list-units` is called with **no `--user`** (system manager only) (`services.js:167-174`, `214-215`). A system LaunchDaemon or a `systemd --user` unit is invisible — indistinguishable from uninstalled. Guessing "failing" would fabricate.
- **Read-only discipline (trap):** the view must use the *pure* `collectServiceEvidence` (and, for `daemon_watch`, the pure `groupServiceFactsByTick`) — **never** `computeServiceBaselineCandidates`, which *writes* its baseline store (`service-baseline.js:627`). Mirror how `alerts list` uses the non-persisting `evaluateAlerts` (`alerts.js:308-311`).

### 7.4 The `daemon_watch` disclosure (honesty patch for §3)
Built from `readDaemonStatus` (`undefined` if the daemon never ran → `{watched:false, reason:"the daemon has not run"}`):
- **filesystem** — core collector: check `status.collector_statuses[id==="disk-usage"]` (present every tick, `daemon.js:879`). ok/warning → `{watched:true, last_daemon_observation_ts: status.ts}`; else `{watched:false, reason:"daemon's last core collection did not report disk-usage"}`.
- **service** — `status.structural_collector_statuses` (present **only when learned is enabled and a structural tick completed**, `daemon.js:690-692`, `882`): absent → `{watched:false, reason:"structural (service) collection is gated behind the learned.json kill switch; this coverage view collected service evidence itself, independent of that gate"}`; present + `id==="services"` → `{watched:true, last_daemon_observation_ts}`.
  - Fable's precise reads apply here if the persisted census is consulted: look up via the **pure** `groupServiceFactsByTick`, filter to the latest **complete** tick, and match `entity_key === sanitizeEntityKey(declaredName)` (`fact-translators.js:14-16` — an unsanitized name never matches its own fact); do **not** reach for the `confidence:0` census marker through `buildShadowFactLookup`, which drops confidence:0 points (`shadow-store.js:184-186`).

### 7.5 Output shape (never persisted)
```jsonc
{ "contract_id":"…","name":"…","subject_type":"service","subject":"postgresql.service",
  "coverage":"covered|partial|uncovered", "coverage_reason":null|"…",
  "assessment":"healthy|degraded|failing|unknown",
  "basis":{ "measurement":"used_fraction|service_running", "value":0.42, "observed_at":"<iso, this invocation>" },
  "evidence_refs":["services"], "detail":{ "running":false, "failed":true },
  "daemon_watch":{ "watched":false, "reason":"…", "last_daemon_observation_ts":null } }
```

---

## 8. Never-fabricate guardrails (from the Astra pass — the invariants the mapper must satisfy)

1. **Never derive health/recovery from silence.** Empty/absent evidence can mean clear, disabled, failed, or unobserved — require a *successful, sufficiently fresh* assessment of the *specific* condition before reporting healthy; else `unknown` (and, in a future stateful slice, retain the prior problem as unresolved). `coveredRuleIds`/alert absence is not proof of coverage.
2. **Keep required-observation failures visible, distinct from confirmed non-support** (§2, §7.1). A required unsupported capability is still a coverage gap even when benign for daemon health; never read daemon-`ok` as job coverage.
3. **A disappeared subject must not disappear from the view.** Build the view from *declared contracts*, then attach evidence; missing evidence → `unknown`, still listed. Distinguish positively-established absence (found `running:false` / not in a *complete* census) from absence-in-a-partial/failed/stale inventory (`unknown`). Bind evidence to the *specific* subject — no host aggregates (never key by `metric_name` alone / `summarizeMetricPoints`, which erases the mount, `history-store.js:186`).
4. **Fresh daemon activity must not refresh stale job evidence.** Every assessment shows its `observed_at` + applicable freshness limit; expired/missing/invalid/future-dated evidence cannot support current health.
5. **History completeness ≠ coverage ≠ health.** `intact` (`fact-store-completeness.js:54`) means the history-trust check passed, not that the job was observed or healthy. Disclose `completeness.status` as a caveat, never as an assessment input; and incomplete history must not erase valid positive evidence of a problem.
6. **Never claim more than the evidence measures.** Inventory = presence, not successful execution / useful response / restorable backup. Expose every declared requirement, including unsupported/unevaluated; one passing check never hides another's gap.

**The precise user promise (state it in the command header):** *"Descartes records what I declared important, and shows which requirements existing evidence can assess, what that evidence establishes as of its observation time, and what remains unknown or uncovered."* Declaration alone enables no collector, establishes no continuous monitoring or delivery, and guarantees no job success. **Owner intent stays authoritative** — discovery may suggest a subject and baselines may describe behavior, but neither creates importance; "has always run here" ≠ "must be protected".

---

## 9. Sequencing (TDD)
| Phase | Deliverable | Tests |
|---|---|---|
| 0 | `protection-contract-store.js` (schema, validate, configDir paths, atomic load/write, duplicate rejection). | `protection-contract-store.test.js` — missing/corrupt/per-record-drop/duplicate/atomic (mirror `promotion-store.test.js`). |
| 1 | `protection-coverage.js` **pure** mappers `assessFilesystemContract(contract, diskEnvelope)` — every §7.2 branch against **fixture envelopes**. | `protection-coverage.test.js` — one test per branch. |
| 2 | `assessServiceContract(contract, serviceEnvelope)` — §7.3 branches incl. oneshot/`expected_state`, census-only, not-found, unable, unsupported. | same file. |
| 3 | `protect.js` CRUD (`declare`/`list`/`remove`) wired into `index.js` + `usage()`; `list` shows declared fields only. | `protect.test.js` — arg parsing, round-trip, `--json`. |
| 4 | `protect.js` orchestration: `coverage <id>` + live `list` via an **injectable collector seam** (`options.collectors.services ?? collectServiceEvidence`, mirroring `daemon.js:303-314`); add the `daemon_watch` read. | `protect.test.js` — every §7 branch via injected collector doubles; `daemon_watch` with/without status + structural entry. |
| 5 | Manual host demo (§10); README capabilities row; HANDOFF update. | Manual (the demo breaks a real unit — not CI). |

Run `npm test` after each phase.

---

## 10. Acceptance / demo
**Filesystem (fixture-driven, primary):** `assessFilesystemContract` unit tests cover the arc — `used_fraction 0.5`→healthy, `0.97`→failing, mount absent from `result.filesystems`→`uncovered:subject_not_found`/`unknown` — without filling a real disk.
**Service (live, primary human-facing demo):** declare a contract for a disposable **user**-scope unit (`systemctl --user` on Linux — note the collector's system-manager scope caveat, or a user `LaunchAgent` on macOS where `launchctl list` sees it) with `--expected-state running`; `coverage` → `covered`/`healthy`; stop it → `covered`/`failing` (`detail` shows real state); disable+remove → `uncovered:subject_not_found_in_visible_scope`/`unknown` — **not** `healthy`, not a crash, not a stale repeat of `failing`. Each step shows `basis.observed_at` and an honest `daemon_watch`.

---

## 11. Out of scope / deferred
Incidents + episode identity + delivery outbox (slice 2 reads `severity`/`notify` from here); actions/execution; LLM investigation; scheduled-job as a full subject (needs a run-outcome collector); free-text success conditions; per-contract configurable thresholds; tolerance/maintenance/hysteresis; notification dispatch; **decoupling the daemon's structural (service) tick from `learned.json`** (this slice works around the gate for on-demand queries but does not remove it); adding `failed`/`sub` to the `service.presence` fact for a `degraded` service tier (a schema change — first follow-up); federation.

---

## 12. Open questions / decisions for the operator
1. **Continuous watching is still blocked on `learned.json` (the big one).** On-demand coverage is decoupled here; a future daemon-driven "notify when a contract's assessment changes" (slice 2) needs service collection to run on a schedule *without* the `learnedConfig.enabled` gate (`daemon.js:690-692`) — either decouple that gate (non-trivial: it also protects the fact-store/mining pipeline) or add a *new*, protection-contract-specific collection domain independent of `structural`/`learned`. Decide before slice 2.
2. **§3 evidence-source decision** — fresh on-demand assessment + persisted `daemon_watch` (decided) vs. persisted-evidence-only (Fable's alternative: more literally "watched", no per-call `execFile`, but service coverage would require `learned enable`). Confirm or veto.
3. **Disk-threshold duplication vs. export** — duplicate `alert-store.js:78-86`'s 0.90/0.95 with a citing comment (self-contained-store convention) vs. a small additive export from `alert-store.js` (touches a file outside the slice). Also note the unreconciled `findings.js:48` 0.97 critical inconsistency (out of scope to fix).
4. **`services_census` lacks `failed`/`nonzero_exit`** — a declared unit beyond the top 200 is `partial` forever. Accept for slice 1, or make the census projection additive (`services.js:44-50`)?
5. **Success condition is derived, not owner-authored, this slice.** Confirm this narrowing of the design's fuller vision is intended for slice 1.
6. **Service demo platform** — user-scope LaunchAgent (macOS, visible to `launchctl list`) vs. root-required systemd system unit (the census collector doesn't query `--user`). Confirm the reference demo.
