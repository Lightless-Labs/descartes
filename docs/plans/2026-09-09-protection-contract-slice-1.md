# Protection Contract Slice 1 — Truthful Service and Filesystem Coverage and Assessment

> **⛔ SUPERSEDED / ABANDONED (2026-09-10).** The owner rejected this whole direction: an owner-declared "protect this service at this threshold, notify this channel" contract is "OTel + a local PagerDuty, done worse," and it walks away from the product's actual point — an agent that *discovers* what's running and *learns* to monitor it, rather than one you configure. Do NOT build from this plan (or its `-daybreak.md` variant). The replacement direction is **watch-by-default**: [`docs/plans/2026-09-10-watch-by-default-slice-1.md`](2026-09-10-watch-by-default-slice-1.md). Kept only as a record of the abandoned branch; its code-grounded collector findings remain useful reference.

**Date:** 2026-09-09
**Status:** SUPERSEDED (was: PLAN — reconciled canonical plan)

**Provenance:** This document merges two committed plans into the single canonical slice-1 plan, replacing both as the thing to build from.
- **Base (architecture, adopted verbatim in substance):** `docs/plans/2026-09-09-protection-contract-slice-1-daybreak.md` — the independent daybreak-blue plan. Its daemon-integrated contract-driven collection phase, 3-axis coverage model, freshness rules, and required-collector-failure → daemon `state:"error"` behavior are the adopted architecture.
- **Secondary (harvested pieces):** `docs/plans/2026-09-09-protection-contract-slice-1.md` — the earlier synthesized plan. Its filesystem-subject groundwork, never-fabricate guardrail phrasing, and several open questions are folded in below.
- **The one correction made here:** the daybreak plan deferred `filesystem` as a subject type (its §2.2), reasoning that resource-specific disk protection needed to "follow the resource-identity work." That was over-conservative — per-mount identity is already present in today's raw disk-collector output, and disk is a *core* collector that already runs, ungated, every tick. This plan restores `filesystem` as a co-equal first-class subject alongside `service`. Scheduled-job stays deferred, as both source plans agreed.

**Design basis:** [Purpose-first design](docs/architecture/2026-09-05-purpose-first-design.md) · [Design and implementation critique](docs/reviews/2026-09-05-design-and-implementation-critique.md)

---

## 1. Goal and scope

**Slice 1 = declare a protected job — a service or a filesystem mount — and get a truthful coverage + assessment view for it, reusing existing evidence — no new detectors, no actions, no LLM.**

The owner explicitly identifies an important long-running service, or a filesystem mount that must not fill up. Descartes observes it through the existing service or disk collector and reports two independent conclusions:

- **Coverage:** `covered | partial | uncovered`
- **Assessment:** `healthy | degraded | failing | unknown`

This supplies the explicit protection contract currently missing from the product (`docs/reviews/2026-09-05-design-and-implementation-critique.md:118-137`) and implements the first purpose-first milestone: seeing a protected subject with bounded, honest observations (`docs/architecture/2026-09-05-purpose-first-design.md:221-231`).

### What this is NOT

This slice does **not** implement:

- Incident or episode identity, incident transitions, recovery semantics, or a notification delivery outbox. Those form the next slice.
- Alert creation or notification delivery from protection assessments.
- Action proposals, approvals, remediation, containment, or execution.
- LLM investigation, explanation, or triage.
- Job discovery or automatic protection suggestions.
- Automatic conversion of baselines, previously observed services, or alerts into contracts.
- Scheduled-backup completion monitoring.
- Filesystem *dependency composition* — i.e. wiring a declared mount to the specific service/backup job that fills it. The filesystem *subject* itself ships in this slice (§2.1); the dependency edge does not.
- The full tolerance, maintenance-window, delay, or interruption-cost model.
- Per-contract notification transports.
- Federation, remote telemetry, or off-host witnessing.

Descartes remains observation-only. The repository's current framing likewise says no general host-action command exists and evidence collection is read-only (`README.md:3-9`, `README.md:404-425`).

---

## 2. Design decisions

### 2.1 Two subject types this slice supports: service and filesystem

Slice 1 supports exactly two subject types:

```text
subject.type = "service"
success_condition.type = "service_running"

subject.type = "filesystem"
success_condition.type = "used_fraction_below"
```

**Service.** The service subject is the smallest credible protected job because the existing collector already provides:

- Exact systemd unit names, `running`, `failed`, and `restarting` state (`tools/descartes-cli/src/tools/services.js:89-113`).
- Exact launchd labels, running state, and last exit status (`tools/descartes-cli/src/tools/services.js:116-134`).
- An authoritative census distinct from its 80-item presentation list, with explicit truncation (`tools/descartes-cli/src/tools/services.js:190-211`, `tools/descartes-cli/src/tools/services.js:231-249`).
- Structured distinctions among successful collection, collection failure, and unsupported platform (`tools/descartes-cli/src/tools/services.js:167-188`, `tools/descartes-cli/src/tools/services.js:252-300`).
- Existing `service.presence` facts carrying the service's running state and a census marker that distinguishes a genuine enumeration from no enumeration (`tools/descartes-cli/src/fact-translators.js:95-143`).
- Existing deterministic appearance/disappearance detectors, although these are historical novelty signals rather than current service-health checks (`tools/descartes-cli/src/service-baseline.js:1-33`, `tools/descartes-cli/src/service-baseline.js:308-372`).

The initial contract is deliberately limited to long-running services. A systemd oneshot unit in `active/exited` state does not satisfy `service_running`.

**Filesystem.** The filesystem subject belongs in slice 1 alongside service, not after it, because the existing evidence path already supports it today:

- Per-mount identity is already present in the raw disk collector output — `mount_point`, `used_fraction`, `available_bytes`, `filesystem`, and a `pressure_relevant`/`classification` tag — for every mounted filesystem the `df` invocation returns, not just a host-wide summary (`tools/descartes-cli/src/tools/disks.js:34-68`, `tools/descartes-cli/src/tools/disks.js:80-117`).
- That same per-mount identity survives into the persisted metric dimensions Descartes already writes every core tick: `metricPointsFromEvidence` stamps each `disk.used_fraction` point with `dimensions:{mount_point, filesystem, classification}` (`tools/descartes-cli/src/daemon.js:275-286`).
- What the daybreak-only plan correctly identified as unusable was a *different*, unused path: the host-wide disk *alert/summary*. `alert-store.js`'s `disk.space.high_used_fraction` rule reads the aggregate `disk.used_fraction` metric **name** across every pressure-relevant mount and reports only that "at least one" filesystem is pressured (`tools/descartes-cli/src/alert-store.js:164-174`); and `summarizeMetricPoints` groups by `metric_name` alone, which erases the `mount_point` dimension entirely (`tools/descartes-cli/src/history-store.js:186-227`). Filesystem assessment must never touch either of those — it reads the raw per-mount evidence directly (§6.5–§6.6, §7.1).
- Disk is a **core** collector — part of `collectDaemonEvidence`'s `{system, processes, disks}` set (`tools/descartes-cli/src/daemon.js:303-314`) — run every fast tick, **unconditionally, before any `learned.json` check** (`tools/descartes-cli/src/daemon.js:641-652`, gate at `tools/descartes-cli/src/daemon.js:677-692`). Service collection, by contrast, currently sits in the slower structural batch gated behind that same kill switch (`tools/descartes-cli/src/daemon.js:690-692`, `709`) — exactly why service protection needs a new, dedicated, ungated collection phase (§7.1). **Filesystem needs no such new phase**: the evidence it needs is already collected, every tick, by a collector Descartes already runs. Contract-driven filesystem assessment is a pure downstream read of that evidence, not a new I/O path — in this specific sense filesystem is *easier* to integrate than service, not harder, and deferring it was the one over-conservative call in the daybreak-only plan.
- No learned fact or baseline detector exists for filesystem at all — `fact-translators.js` has no disk/filesystem/mount-related translator — so, unlike service, there is no learned-subsystem entanglement to route around either (§6.8).

The filesystem subject is deliberately narrow, matching the service subject's narrowness: a `used_fraction_below` condition against one declared `mount_point`, no inode thresholds, no growth-rate projection, no composition with whatever service or scheduled job fills it (§11).

### 2.2 Defer only the scheduled-job subject

Do not expose a subject type the first slice cannot assess honestly:

- The scheduled-job collector inventories cron, systemd timer, and launchd definitions (`tools/descartes-cli/src/tools/scheduled-jobs.js:177-201`, `tools/descartes-cli/src/tools/scheduled-jobs.js:516-559`). Its current detector reports only a newly appeared definition (`tools/descartes-cli/src/persistence-baseline.js:225-283`). Neither establishes that work ran successfully or that a backup is restorable. The critique explicitly warns that inventory is not execution success (`docs/reviews/2026-09-05-design-and-implementation-critique.md:108-114`).

The motivating service → scheduled backup → filling disk scenario is now two-thirds established: slice 1 gives truthful protection for both the service and the destination filesystem. Only the "did the backup job actually run and succeed" leg remains, and it needs new collector work, not new contract plumbing (§11).

---

## 3. `ProtectionContract`

### 3.1 Stored shape

Service:

```json
{
  "id": "protection_550e8400-e29b-41d4-a716-446655440000",
  "name": "Primary PostgreSQL",
  "subject": {
    "type": "service",
    "manager": "systemd",
    "name": "postgresql.service"
  },
  "success_condition": {
    "type": "service_running"
  },
  "failure_severity": "critical",
  "notification_destination": {
    "type": "configured_default"
  },
  "observation_permission": "allowed"
}
```

Filesystem:

```json
{
  "id": "protection_6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "name": "Root filesystem",
  "subject": {
    "type": "filesystem",
    "mount_point": "/"
  },
  "success_condition": {
    "type": "used_fraction_below",
    "warn_fraction": 0.90,
    "critical_fraction": 0.95
  },
  "failure_severity": "critical",
  "notification_destination": {
    "type": "configured_default"
  },
  "observation_permission": "allowed"
}
```

Fields:

| Field | Slice-1 contract |
|---|---|
| `id` | Generated stable UUID prefixed with `protection_`; immutable. |
| `name` | Owner-provided display name. |
| `subject.type` | Exactly `service` or `filesystem`. |
| `subject.manager` | **Service only.** Exactly `systemd` or `launchd`; no ambiguous `auto` value is stored. |
| `subject.name` | **Service only.** Exact systemd unit or launchd label matched against collector output. |
| `subject.mount_point` | **Filesystem only.** Exact mount point matched against `result.filesystems[].mount_point` (`tools/descartes-cli/src/tools/disks.js:34-68`). No `manager` concept applies — the disk collector is platform-generic (§6.5). |
| `success_condition.type` | Exactly `service_running` (with `subject.type:"service"`) or `used_fraction_below` (with `subject.type:"filesystem"`). Derived from `subject.type`, not independently owner-chosen. |
| `success_condition.warn_fraction` / `.critical_fraction` | **Filesystem only.** Default `0.90` / `0.95`, the same values `alert-store.js` uses for `disk.space.high_used_fraction` (`tools/descartes-cli/src/alert-store.js:78-82`). Whether these are owner-overridable per contract or fixed for slice 1 is open (see OPEN QUESTIONS #3). |
| `failure_severity` | `info \| warning \| critical`; records owner importance for later incident work but does not itself send an alert. These values align with existing alert severity vocabulary (`tools/descartes-cli/src/alert-store.js:179-201`). |
| `notification_destination.type` | Exactly `configured_default`, referencing the existing global notification configuration. |
| `observation_permission` | `allowed \| denied`. Only `allowed` authorizes contract-driven collection and evaluation. |

### 3.2 Validation

`validateProtectionContract(record)` must reject:

- Non-object or array records.
- Unknown top-level or nested keys.
- Empty, overlong, control-character-containing IDs, names, service identities, or `mount_point` values.
- Unknown subject type, manager, success-condition, severity, destination, or permission enums.
- A systemd subject whose name does not end in `.service`.
- A `filesystem` subject carrying `manager`/`name` (service-only fields), or a `service` subject carrying `mount_point` (filesystem-only field) — fields are exclusive to their `subject.type`.
- `success_condition.type` that does not match `subject.type` (`service_running` only with `service`; `used_fraction_below` only with `filesystem`).
- A `used_fraction_below` condition whose `warn_fraction`/`critical_fraction` are not both numbers in `(0, 1]` with `critical_fraction > warn_fraction`.
- Duplicate IDs.
- Duplicate `(manager, subject.name)` service subjects, and duplicate `(subject.type, mount_point)` filesystem subjects.
- Duplicate owner-visible names, to avoid ambiguous CLI selection.

Validation runs both before writing and while loading, following the repository's validate-before-persist pattern (`tools/descartes-cli/src/constraint-store.js:95-147`, `tools/descartes-cli/src/constraint-store.js:191-206`).

Generate IDs through an injectable ID factory so tests remain deterministic.

### 3.3 Tolerance and maintenance

Do not store placeholder tolerance or maintenance fields in schema version 1, for either subject type. Their slice-1 semantics are:

- Assessment is immediate current-state assessment.
- No grace period or duration threshold is applied.
- No maintenance window suppresses or rewrites an assessment.

The CLI must disclose that the assessment is maintenance-unaware. Adding empty fields now would imply semantics the implementation does not yet possess.

---

## 4. Protection-contract store

Add:

```text
tools/descartes-cli/src/protection-contract-store.js
tools/descartes-cli/test/protection-contract-store.test.js
```

Store owner intent at:

```text
<configDir>/protection-contracts.json
```

Contracts belong in `configDir`, not `stateDir`: they are owner configuration, like the existing notification destination at `configDir/notifications.json` (`tools/descartes-cli/src/notification-delivery.js:10-16`). Derived assessments remain daemon state. Both subject types share the same store and array — no schema split by subject type beyond the record shape in §3.1.

### 4.1 Store API

Export:

```js
resolveProtectionContractStorePaths(descartesPaths)
validateProtectionContract(record)
loadProtectionContracts(descartesPaths)
writeProtectionContracts(descartesPaths, contracts)
addProtectionContract(descartesPaths, input, options)
```

File shape:

```json
{
  "schema_version": 1,
  "contracts": []
}
```

### 4.2 Persistence behavior

Mirror the existing store idiom:

1. Create the parent directory with mode `0700`.
2. Validate the complete proposed record set before touching the current file.
3. Serialize to `<file>.<pid>.tmp` with mode `0600`.
4. Rename atomically over the final file.

This directly mirrors `writeConstraints` (`tools/descartes-cli/src/constraint-store.js:191-206`) and notification configuration writes (`tools/descartes-cli/src/notification-delivery.js:62-69`).

A rejected write must leave the preceding file byte-for-byte unchanged, matching the existing tested store expectation (`tools/descartes-cli/test/constraint-store.test.js:235-247`).

### 4.3 Missing, corrupt, and invalid handling

`loadProtectionContracts` returns:

```js
{
  contracts: [],
  store_status: "missing" | "ok" | "degraded" | "corrupt",
  corrupt_count: 0,
  invalid_record_count: 0
}
```

Rules:

- Missing file: empty contract set, `store_status:"missing"`. This means no contracts have been declared.
- Malformed JSON, wrong schema version, or non-array `contracts`: empty set, `store_status:"corrupt"`.
- Valid wrapper containing invalid records: retain valid records, count rejected records, and return `store_status:"degraded"`.
- Non-`ENOENT` filesystem errors propagate to the caller.
- `addProtectionContract` refuses to rewrite a corrupt or degraded store. It must not turn unreadable owner intent into a new apparently clean file.
- CLI and daemon must surface corrupt/degraded state; they must never silently render it as "no protections configured."

This preserves the existing missing/corrupt reader idiom (`tools/descartes-cli/src/constraint-store.js:149-188`) while strengthening its operator-visible accounting for owner-declared protection.

The slice accepts the repository's current single-writer limitation. Atomic replacement prevents torn reads but does not solve two simultaneous CLI additions.

---

## 5. CLI surface

Add a top-level `protect` branch to the lazy dispatch in `index.js`, alongside `daemon`, `history`, and `alerts`. The existing dispatcher parses the top-level command at `tools/descartes-cli/src/index.js:91-107` and delegates to dedicated `runThing(paths,args)` modules at `tools/descartes-cli/src/index.js:109-133`.

Add:

```text
tools/descartes-cli/src/protect.js
tools/descartes-cli/test/protect.test.js
```

### 5.1 Commands

```bash
descartes protect add \
  --name "Primary PostgreSQL" \
  --subject-type service \
  --service postgresql.service \
  --manager systemd \
  --success running \
  --severity critical \
  --notify configured \
  --observation allowed \
  [--json]

descartes protect add \
  --name "Root filesystem" \
  --subject-type filesystem \
  --mount-point / \
  --success used-fraction-below \
  --severity critical \
  --notify configured \
  --observation allowed \
  [--json]

descartes protect list [--json]

descartes protect inspect <contract-id> [--json]
```

For launchd:

```bash
descartes protect add \
  --name "Local database" \
  --subject-type service \
  --service com.example.database \
  --manager launchd \
  --success running \
  --severity critical \
  --notify configured \
  --observation allowed
```

`--subject-type` is required and selects which of the remaining flags are legal: `protect add` rejects `--service`/`--manager` when `--subject-type filesystem`, and rejects `--mount-point` when `--subject-type service`. No aliases or positional inference should be added in slice 1. The explicit options prevent a user from accidentally protecting the wrong service manager, the wrong subject type, or believing unsupported success conditions exist.

### 5.2 Command behavior

`protect add`:

- Validates every argument, dispatching validation and success-condition defaults by `--subject-type`.
- Resolves `configured` to the stored `configured_default` reference.
- Rejects duplicate ID/name/subject.
- Writes only the Descartes-owned contract configuration.
- Prints the generated ID and a reminder that coverage remains `uncovered` and assessment `unknown` until a daemon cycle observes it — including for filesystem, even though the underlying disk collector already runs every tick regardless of contracts; the *contract's own* first daemon-status assessment still has to be produced once.

`protect list`:

- Lists all contracts, of both subject types.
- Joins each contract to the latest daemon protection snapshot.
- Shows `coverage` and `assessment` columns.
- If no current snapshot exists, prints `uncovered / unknown`; it never prints healthy from an empty alert list.
- Reports contract-store corruption before any rows.

`protect inspect`:

- Prints the complete contract.
- Prints capability, collection outcome, coverage, assessment, observation timestamp, freshness, and evidence source — rendering `subject.mount_point` for filesystem or `subject.manager`+`subject.name` for service.
- Resolves the existing notification config for display only: enabled/disabled and channel. Existing notification configuration supports `cli`, macOS desktop/native, Linux desktop, and syslog (`tools/descartes-cli/src/notification-delivery.js:10-49`).
- Does not send a notification.

### 5.3 JSON result

Service:

```json
{
  "contract": {},
  "coverage": {
    "status": "covered",
    "capability": "supported",
    "collection": "succeeded",
    "reasons": []
  },
  "assessment": {
    "status": "healthy",
    "reason": "subject_running",
    "observed_at": "2026-09-09T12:00:00.000Z",
    "evidence_refs": [
      {
        "envelope_id": "services",
        "source_tool": "collect_services"
      }
    ]
  },
  "notification_destination": {
    "type": "configured_default",
    "enabled": false,
    "channel": "cli",
    "readiness": "disabled"
  },
  "integrity_level": "unprotected_same_uid"
}
```

Filesystem:

```json
{
  "contract": {},
  "coverage": {
    "status": "covered",
    "capability": "supported",
    "collection": "succeeded",
    "reasons": []
  },
  "assessment": {
    "status": "degraded",
    "reason": "used_fraction_at_or_above_warn",
    "observed_at": "2026-09-09T12:00:00.000Z",
    "evidence_refs": [
      {
        "envelope_id": "disk-usage",
        "source_tool": "collect_disks"
      }
    ]
  },
  "notification_destination": {
    "type": "configured_default",
    "enabled": false,
    "channel": "cli",
    "readiness": "disabled"
  },
  "integrity_level": "unprotected_same_uid"
}
```

The envelope/tool references are locator metadata, not immutable observation IDs. The existing evidence envelope IDs are reused as `"services"` (`tools/descartes-cli/src/tools/services.js:291-300`) and `"disk-usage"` (`tools/descartes-cli/src/tools/disks.js:134-139`); occurrence-level citations belong with the later incident/evidence-identity slice.

---

## 6. Coverage and assessment mapping

Add:

```text
tools/descartes-cli/src/protection-assessment.js
tools/descartes-cli/test/protection-assessment.test.js
```

Export pure functions:

```js
assessServiceProtection(contract, serviceEnvelope, context)
assessFilesystemProtection(contract, diskEnvelope, context)
assessProtectionContracts(contracts, evidence, context)
materializeProtectionView(contract, daemonStatus, context)
```

### 6.1 Keep the axes separate

Coverage must preserve three different questions, identically for both subject types:

```json
{
  "status": "uncovered",
  "capability": "supported",
  "collection": "failed",
  "reasons": ["required_collector_unable"]
}
```

- `capability`: `supported | unsupported | unknown`
- `collection`: `succeeded | partial | failed | not_run`
- derived coverage `status`: `covered | partial | uncovered`

This makes unsupported capability visibly different from a supported collector that failed. Filesystem's value space within these axes is a strict subset of service's — see §6.5.

That separation is required because the shared envelope wrapper currently converts every thrown collector exception to `status:"unable"` and `review_hint:"missing_permission"`, regardless of the underlying cause (`tools/descartes-cli/src/tools/envelope.js:19-33`). The protection view must therefore say `collector_unable`; it must not assert "permission denied" unless a collector provides evidence for that narrower statement.

### 6.2 Current-cycle and freshness rules

A protection observation is current only if:

- It is present in the latest daemon status.
- Its cycle timestamp parses successfully.
- It is no older than:

```text
max(5 minutes, 3 × daemon profile.interval_ms)
```

This matches the existing daemon/sample staleness policy (`tools/descartes-cli/src/alert-store.js:75-92`, `tools/descartes-cli/src/alert-store.js:112-135`).

Because filesystem observation is folded into the existing core tick (§7.1) while service observation runs in the newly introduced, dedicated, ungated protection-collection phase (§7.1), `interval_ms` denotes the core interval for filesystem freshness and the protection phase's own interval for service freshness. Slice 1 gives the new phase the same interval as the core tick by default; if a future slice decouples them, the `3 × interval` bound must key off whichever interval actually governs the subject's own collection (see OPEN QUESTIONS #6).

When the daemon status is missing, unreadable, malformed, or stale:

```text
coverage.status     = uncovered
capability          = unknown
collection          = not_run
assessment.status   = unknown
reason              = daemon_status_missing | daemon_status_unreadable |
                      daemon_status_malformed | observation_stale
```

A stale stored `healthy`, `degraded`, or `failing` result may be displayed only as `last_known_assessment`; it cannot remain the current assessment. This applies identically to both subjects.

### 6.3 Service capability mapping

Given the current service collector envelope:

| Evidence | Capability | Collection | Coverage |
|---|---|---|---|
| Observation permission denied | `unknown` | `not_run` | `uncovered` |
| No `services` envelope this cycle | `unknown` | `not_run` | `uncovered` |
| `result.status:"unsupported"` / manager `"unsupported"` | `unsupported` | `not_run` | `uncovered` |
| Collector manager differs from contract manager | `unsupported` | `not_run` | `uncovered` |
| `result.status:"unable"` or envelope `status:"unable"` | `supported` on a matching Tier-1 manager | `failed` | `uncovered` |
| `result.status:"ok"` and `truncated:false` | `supported` | `succeeded` | `covered` |
| `result.status:"ok"` and `truncated:true` | `supported` | `partial` | `partial` |
| Malformed or contradictory result | `unknown` | `failed` | `uncovered` |

Do not interpret the envelope's top-level `warning` as collection failure. The collector emits `warning` when any systemd service is failed/restarting, even though enumeration succeeded (`tools/descartes-cli/src/tools/services.js:252-265`). Assessment must inspect the declared target only; an unrelated failed service cannot degrade the protected service.

### 6.4 Service assessment mapping

Search the authoritative `services_census` first, falling back to `services` only for legacy/test data. The collector deliberately separates its authoritative census from the presentation-limited list (`tools/descartes-cli/src/tools/services.js:8-27`, `tools/descartes-cli/src/fact-translators.js:95-109`).

| Target evidence | Assessment | Reason |
|---|---|---|
| Supported, successful current census; target running normally | `healthy` | `subject_running` |
| Target explicitly restarting | `degraded` | `subject_restarting` |
| Launchd target currently running but has a nonzero last exit | `degraded` | `subject_running_after_nonzero_exit` |
| Target explicitly failed, inactive, or not running | `failing` | `subject_not_running` |
| Target absent from a successful, non-truncated census | `failing` | `subject_absent` |
| Target absent from a truncated census | `unknown` | `partial_census_cannot_establish_absence` |
| Conflicting duplicate records or unrecognized target state | `unknown` | `ambiguous_subject_state` |
| Permission denied, unsupported, collector failure, missing cycle, or stale cycle | `unknown` | Corresponding coverage reason |

A partial census may still support a known assessment when the target itself appears with direct state:

```text
coverage = partial
assessment = healthy | degraded | failing
```

Partial coverage only forces `unknown` when the required conclusion depends on absence or otherwise missing state.

### 6.5 Filesystem capability mapping

Given the current disk collector envelope (`tools/descartes-cli/src/tools/disks.js:119-140`):

| Evidence | Capability | Collection | Coverage |
|---|---|---|---|
| Observation permission denied | `unknown` | `not_run` | `uncovered` |
| No `disk-usage` envelope this cycle | `unknown` | `not_run` | `uncovered` |
| `envelope.status:"unable"` (any thrown exception — ENOENT, EACCES, timeout, parse failure — collapsed identically by `timedEnvelope`, `tools/descartes-cli/src/tools/envelope.js:19-34`) | `supported` | `failed` | `uncovered` |
| `envelope.status:"ok"` and declared `mount_point` found in `result.filesystems` | `supported` | `succeeded` | `covered` |
| `envelope.status:"ok"` and declared `mount_point` NOT found in `result.filesystems` | `supported` | `succeeded` | `uncovered` (`subject_not_found_in_visible_scope`) |
| Malformed or contradictory result (e.g. two rows claiming the same `mount_point` with different `used_fraction`) | `unknown` | `failed` | `uncovered` |

Two structural differences from the service mapping (§6.3), both load-bearing:

1. **No `unsupported` row.** `disks.js` has no explicit unsupported-platform branch analogous to `services.js:279-289` (`if (process.platform === "linux") … ; else … error: "unsupported platform"`); it runs `df` unconditionally on any platform. A platform where `df` genuinely does not exist surfaces as `collector_unable` via the generic `timedEnvelope` catch, not as a distinct `unsupported` capability. Do not synthesize an `unsupported` value the collector itself does not report — that would fabricate a diagnosis the evidence does not support.
2. **No `partial` collection state.** `parseDf`/`parseDfInodes` return every row `df` prints; the collector never truncates (`tools/descartes-cli/src/tools/disks.js:70-78`). Filesystem coverage is therefore strictly binary — `covered` or `uncovered` — never `partial`, unlike service.

### 6.6 Filesystem assessment mapping

Match the declared `mount_point` against `result.filesystems[].mount_point`:

| Target evidence | Assessment | Reason |
|---|---|---|
| Found; `used_fraction < warn_fraction` (default `0.90`) | `healthy` | `used_fraction_below_warn` |
| Found; `warn_fraction ≤ used_fraction < critical_fraction` | `degraded` | `used_fraction_at_or_above_warn` |
| Found; `used_fraction ≥ critical_fraction` (default `0.95`) | `failing` | `used_fraction_at_or_above_critical` |
| Not found in `result.filesystems` (envelope `ok`) | `unknown` | `subject_not_found_in_visible_scope` — **never `failing`** |
| Permission denied, collector `unable`, missing cycle, or stale cycle | `unknown` | Corresponding coverage reason |
| Malformed or contradictory (duplicate `mount_point` rows) | `unknown` | `ambiguous_subject_state` |

**Mount absence is deliberately never `failing`** — a deliberate asymmetry with the service mapping (§6.4), not an oversight. For a service, a complete, non-truncated census gives an authoritative yes/no over the service manager's own inventory, so an owner's declaration ("this unit must be running") legitimately converts absence into `failing` (`subject_absent`). A single `df` snapshot has no equivalent signal: it cannot distinguish "this mount used to exist and is now gone" from "the owner declared a `mount_point` that never existed, or a removable volume that was deliberately unmounted." Absence therefore stays a coverage gap (`uncovered`/`unknown`), consistent with never-fabricate rule 5/6 (§6.7): a missing mount is evidence Descartes cannot currently see the subject, not evidence the subject failed.

**Pressure-relevant divergence (flag for operator awareness).** The daemon's own core-tick metric emission skips any filesystem with `pressure_relevant:false` — virtual filesystems, developer-runtime disk images, APFS system volumes (`tools/descartes-cli/src/tools/disks.js:80-117` classification; skipped at `tools/descartes-cli/src/daemon.js:278` and `daemon.js:289`) — as a default noise-reduction measure for its own ambient alerting. **Contract-driven filesystem assessment does not apply that filter.** An explicitly owner-declared `mount_point` is assessed regardless of its `pressure_relevant` classification: owner declaration outranks the daemon's default noise-reduction heuristic. A contract naming a `pressure_relevant:false` mount is honored, not silently dropped.

**Never read the aggregate.** Filesystem assessment must read the raw `disk-usage` envelope's `result.filesystems` directly (§7.1) — never `summarizeMetricPoints` (`tools/descartes-cli/src/history-store.js:186-227`), which groups solely by `metric_name` and so erases exactly the `mount_point` identity this mapping depends on; and never the `disk.space.high_used_fraction` alert rule's aggregate `disk.max` (`tools/descartes-cli/src/alert-store.js:164-174`), which answers "is *some* pressure-relevant mount hot" — a different, host-wide question — not "is *this declared* mount hot."

**Honesty caveat to surface.** `metrics.jsonl` carries no completeness ledger (unlike the learned fact store, `tools/descartes-cli/src/fact-store-completeness.js:50-90`), so a filesystem coverage claim is only ever "observed, and fresh" — never "provably continuously observed." Disclose this the same way service assessment discloses history-completeness limits (§6.7 rule 10).

### 6.7 Never-fabricate rules

These rules are mandatory, for both subjects:

1. `healthy` requires a fresh, positive observation of the declared subject — running (service) or under its warn threshold (filesystem).
2. "No relevant alert fired" is never evidence of health.
3. Empty candidate lists are never evidence of recovery or health.
4. A failed or skipped collector produces `unknown`, never `healthy`.
5. A subject missing from an incomplete/truncated enumeration produces `unknown`, never `failing` or `healthy` — service (§6.4, truncated census) or filesystem (§6.6, mount absent — the filesystem collector never truncates, but the same "absence is ambiguous" reasoning applies for the distinct reason given in §6.6).
6. A service missing from a fresh, complete census may be `failing` because the owner — not a learned baseline — declared that it should be running. A filesystem mount missing from a fresh evidence read is `unknown`, never `failing`: owner declaration alone does not convert filesystem absence into failure, because absence is not distinguishable evidence of that specific failure mode (§6.6).
7. A previously healthy contract whose evidence disappears becomes `unknown` on the next cycle.
8. A stopped daemon eventually makes every stored assessment `unknown` through freshness expiry.
9. Notification readiness does not alter coverage or assessment.
10. **History completeness ≠ coverage ≠ health.** Fact-history integrity does not downgrade a fresh direct service observation — it affects historical novelty claims (`service.disappeared`, §6.8), not the current `service_running` condition. `fact-store-completeness.js`'s `intact` means only that the trust check passed, not that the job is healthy or was even observed (`tools/descartes-cli/src/fact-store-integrity.js:550-602`, `tools/descartes-cli/src/fact-store-completeness.js:50-90`). Disclose completeness as a caveat on the assessment, never feed it in as an assessment input. The equivalent caveat for filesystem is `metrics.jsonl` having no completeness ledger at all (§6.6) — disclosed, not silently assumed away.
11. **Bind evidence to the specific declared subject — never a host aggregate.** An unrelated failed service cannot degrade a different protected service (§6.3); an unrelated hot mount cannot degrade a different declared mount, and the host-wide `disk.space.high_used_fraction` rule's "at least one filesystem" aggregate (`alert-store.js:164-174`) must never be read as if it were per-mount evidence (§6.6).
12. **A required unsupported capability is still a coverage gap.** The daemon's own health check deliberately treats a benign `unable` collector as non-fatal for its own `state` (§7.4); that leniency is for the daemon's ambient health, not for a contract that has declared the collector required. `capability:unsupported` and `capability:supported`/`collection:failed` both yield `coverage:uncovered` regardless of whether the daemon itself considers the underlying collector status benign.

The fact store models `intact`, `degraded`, and `unknown` explicitly and grants trust only on positive proof (`tools/descartes-cli/src/fact-store-integrity.js:550-602`, `tools/descartes-cli/src/fact-store-completeness.js:50-90`). The protection evaluator carries the same fail-closed posture for both subjects, without unnecessarily requiring history for a current-state condition.

### 6.8 Existing fact and detector outputs

For the service subject:

- **Status-bearing evidence:** the current `collectServiceEvidence` envelope, particularly its manager, result status, truncation, authoritative census, and target state.
- **Persisted facts:** `service.presence` with `attributes.running` and the `service.census` marker remain owned by the learned structural-history path (`tools/descartes-cli/src/fact-translators.js:119-143`). They are not sufficient by themselves to call the service currently healthy when no current protection cycle ran.
- **Existing detector:** `service.disappeared` is historical set-difference evidence over fresh, complete censuses (`tools/descartes-cli/src/service-baseline.js:308-372`). It may later be attached as related evidence, but slice 1 must not depend on it because the detector is disabled before any I/O when `learned.json` is off (`tools/descartes-cli/src/service-baseline.js:465-479`).
- **Alert store:** alert status values describe alert lifecycle (`active`, `recovered`, `acknowledged`, `suppressed`), not workload health (`tools/descartes-cli/src/alert-store.js:179-201`). Do not map a recovered alert directly to `healthy`.

For the filesystem subject:

- **Status-bearing evidence:** the current `collectDiskEvidence` envelope (`tools/descartes-cli/src/tools/disks.js:119-140`), specifically `result.filesystems[]` — `mount_point`, `used_fraction`, `available_bytes`, `classification`, `pressure_relevant`.
- **Persisted facts:** none. Unlike service, `fact-translators.js` has no disk/filesystem/mount translator — disk evidence never reaches the learned fact store. Contract-driven filesystem assessment therefore has no learned-subsystem entanglement to route around at all.
- **Existing detector:** none. There is no baseline/novelty detector over filesystems analogous to `service.disappeared`.
- **Alert store:** the `disk.space.high_used_fraction` rule (`tools/descartes-cli/src/alert-store.js:164-174`) is a host-wide aggregate over every pressure-relevant mount's `disk.used_fraction`, reporting only that at least one crossed the threshold. It answers a different question from "is *this* declared mount pressured" and must not be mapped to a per-contract assessment (§6.6, guardrail 11).

---

## 7. Daemon integration

The coverage view should use a durable latest daemon snapshot rather than silently collecting only when the user asks to inspect it.

### 7.1 Contract-driven collection and assessment phase

Within `runDaemonIteration`, this phase handles both subject types — but the two subjects need different amounts of new work.

**Filesystem — no new collection call.** The core `disks` collector already runs every tick, unconditionally, as part of `collectDaemonEvidence`'s `{system, processes, disks}` set (`tools/descartes-cli/src/daemon.js:303-314`), invoked at the very top of `runDaemonIteration` (`tools/descartes-cli/src/daemon.js:651`) — before the `learned.json` gate is even checked (`tools/descartes-cli/src/daemon.js:677-692`). Contract-driven filesystem assessment is therefore a pure downstream read:

1. Load the contract store.
2. Select contracts with `subject.type === "filesystem"` and `observation_permission === "allowed"`.
3. Locate the `disk-usage` envelope already present in this tick's `evidence` array (the same array `metricPointsFromEvidence` consumes, `tools/descartes-cli/src/daemon.js:651-652`) — **do not** issue a second `collectDiskEvidence()` call.
4. For each selected contract, look up its declared `mount_point` in the envelope's *raw*, unfiltered `result.filesystems` — not the `pressure_relevant`-filtered subset `metricPointsFromEvidence` builds for metrics (`tools/descartes-cli/src/daemon.js:277-278`), and never through `summarizeMetricPoints` (`tools/descartes-cli/src/history-store.js:186-227`).
5. Assess per §6.5/§6.6.

**Service — new, dedicated, ungated collection phase:**

1. Load the contract store before protection collection.
2. Select contracts with:
   - `subject.type === "service"`
   - `observation_permission === "allowed"`
3. If at least one exists, invoke the existing `collectServiceEvidence` exactly once for the cycle.
4. Share that one census across every allowed service contract.
5. Assess all service contracts through the pure assessment module.

No contracts, or only denied contracts, of a given subject type means no additional collector call for that type; filesystem assessment still runs against whatever the core tick already collected — it costs nothing extra either way.

6. Persist both subject types' projections together in the existing atomic `daemon-status.json` (§7.3).

The current fast collectors run in `collectDaemonEvidence` (`tools/descartes-cli/src/daemon.js:303-313`), while service collection currently sits in the slower structural batch (`tools/descartes-cli/src/daemon.js:316-354`, gated at `690-692`). Contract-driven service collection must be a distinct, named phase so it is not accidentally gated by learned monitoring; contract-driven filesystem assessment needs no equivalent new phase because it rides the collector that is already ungated (§2.1).

### 7.2 Reuse rather than duplicate

When learned monitoring is enabled and the slower structural batch is due, inject the already-collected service envelope as that batch's `services` collector result. The existing structural collector injection seam already accepts a replacement `services` function (`tools/descartes-cli/src/daemon.js:320-347`).

This preserves existing fact translation and baseline behavior while avoiding two service censuses in the same daemon cycle.

Filesystem has no equivalent duplication risk to manage: there is exactly one `disks` collection per tick today, contract-driven or not, so no injection seam is needed for it.

When learned monitoring is disabled:

- Do not write protection observations to the learned fact store.
- Do not run service baselines.
- Do persist the current per-contract assessment in daemon status, for both subject types.

### 7.3 Daemon status extension

Add:

```json
{
  "protection": {
    "contract_store": {
      "status": "ok",
      "corrupt_count": 0,
      "invalid_record_count": 0
    },
    "cycle_ts": "2026-09-09T12:00:00.000Z",
    "assessments": [
      { "contract_id": "protection_…", "subject_type": "service" },
      { "contract_id": "protection_…", "subject_type": "filesystem" }
    ],
    "required_collector_failures": []
  }
}
```

Each assessment contains only the bounded subject-state projection used for the decision, not the full host service census or the full host filesystem list.

`writeDaemonStatus` already uses atomic temporary-file replacement (`tools/descartes-cli/src/history-store.js:259-279`).

### 7.4 Required collector failure

The existing overall daemon state deliberately ignores generic `unable` envelopes because some can be benign platform limitations (`tools/descartes-cli/src/daemon.js:847-876`; `collectorHasError` at `870-871` checks only for a `status:"error"` that no collector ever emits — see the foundational ground truth below). A declared contract provides the missing context, for either subject:

- A matching supported service collector, or the disk collector, that is `unable` is a `required_collector_failure`.
- It sets the contract to `uncovered / unknown`.
- It is recorded in `protection.required_collector_failures`.
- It forces the current daemon status `state` to `error`.
- A known unsupported platform (service only — §6.5 notes the disk collector has no equivalent unsupported branch) remains separately represented as `unsupported`; it does not masquerade as a failed collection.

A corrupt/unreadable protection store also forces `state:"error"` because Descartes cannot establish which required observations exist.

This changes behavior only when owner-declared contracts exist.

**Foundational ground truth this section relies on:** no collector ever emits `status:"error"`. `timedEnvelope` collapses every thrown exception (ENOENT, EACCES, timeout, parse failure) to `status:"unable"`, `confidence:0`, `review_hint:"missing_permission"` (`tools/descartes-cli/src/tools/envelope.js:19-34`). Consequently the daemon's own `collectorHasError` check is unsatisfiable by any collector; the daemon reaches `state:"error"` on its own only via persistence failure. The daemon deliberately treats `unable` as benign for its own health. "Benign unsupported" vs. "a real coverage gap" is not decidable from the evidence alone — it becomes decidable only once a contract declares the subject *required*. This is exactly why the protection view must derive its own `required_collector_failure` signal rather than trusting the daemon's own `state`.

---

## 8. Build sequence

### Phase 1 — Contract schema and store

Write failing tests first for:

- Every valid and invalid contract field, for both subject types.
- Closed enums and closed object shapes.
- Stable ID creation.
- Duplicate subject/name rejection, including duplicate `(subject.type, mount_point)` for filesystem.
- Filesystem-specific field validation (`mount_point`, `warn_fraction`/`critical_fraction` ordering).
- Rejecting cross-type field contamination (`manager` on a filesystem subject, `mount_point` on a service subject).
- Missing, corrupt, degraded, and valid store results.
- Valid atomic round-trip with `0600` file and no remaining temporary file.
- Rejected writes preserving the prior file.
- Refusal to add over corrupt/degraded state.

Then implement `protection-contract-store.js`.

### Phase 2 — Pure coverage and assessment

Create actual service-envelope and disk-envelope fixtures matching both service collector managers and disk collector output.

Write the full matrix before implementation:

- Service: systemd running, restarting, failed, inactive, absent.
- Service: launchd running/zero exit, running/nonzero exit, not running, absent.
- Service: unrelated failed service does not degrade the protected subject.
- Service: complete versus truncated absence.
- Service: unsupported versus supported-but-unable.
- Filesystem: mount found at `0.5` / `0.90` / `0.94` / `0.95` / `0.99` used_fraction (healthy / degraded boundary / degraded / failing boundary / failing).
- Filesystem: declared mount absent from a full `result.filesystems` list → `uncovered/unknown`, **never** `failing`.
- Filesystem: `pressure_relevant:false` mount is still assessed when explicitly declared (the daemon's own filter is not applied).
- Filesystem: `envelope.status:"unable"` → `uncovered/unknown`, `required_collector_failure` candidate.
- Filesystem: malformed/duplicate `mount_point` rows → `unknown`/`ambiguous_subject_state`.
- Denied observation, for both subjects.
- Missing, malformed, contradictory, and stale evidence, for both subjects.
- Prior healthy followed by unavailable evidence yields unknown, for both subjects.
- No-alert and recovered-alert fixtures never create health, for both subjects.

Then implement `protection-assessment.js`.

### Phase 3 — Daemon wiring

Add daemon tests using existing dependency-injection conventions:

- Missing contract store adds no service collection.
- Denied contracts add no collection.
- One or many allowed service contracts cause exactly one census per cycle.
- Collection still runs with `learned.json` absent/disabled.
- No learned fact write occurs solely because a protection contract exists.
- A learned-enabled structural cycle reuses the protection census.
- Unsupported and unable paths remain distinct.
- Required collector failure and corrupt contract store affect daemon state, for both service and disk.
- A filesystem contract triggers zero additional collector calls in a tick — assessment is read from the same `evidence` array the core tick already produced.
- Filesystem assessment is unaffected by `learned.json` being absent/disabled/enabled — verify no behavioral difference across all three.
- A declared `pressure_relevant:false` mount is assessed in daemon output even though the core tick's own metric emission skipped it.
- Status contains bounded assessments for both subject types, both in memory and after reading `daemon-status.json`.
- A later unable cycle overwrites a prior healthy snapshot with unknown, for either subject.

Then modify `daemon.js`.

### Phase 4 — CLI and documentation

Add `protect.js`, the `index.js` branch, usage text, and README documentation.

Test:

- `add`, `list`, and `inspect` in human and JSON forms, for both subject types.
- `add` with `--subject-type filesystem` and `--subject-type service`, including rejecting cross-type flags.
- Inspection before the first daemon cycle.
- Unknown ID.
- Corrupt store.
- Corrupt/missing/stale daemon status.
- Disabled/unreadable notification configuration.
- Exit behavior for invalid CLI options.
- No imports or calls into Pi, triage, alert intelligence, notification delivery execution, containment, or action code.

Run:

```bash
node --test \
  tools/descartes-cli/test/protection-contract-store.test.js \
  tools/descartes-cli/test/protection-assessment.test.js \
  tools/descartes-cli/test/protect.test.js \
  tools/descartes-cli/test/daemon.test.js \
  tools/descartes-cli/test/index.test.js

npm test
npm run smoke:cli
```

---

## 9. Invariants preserved

### Never fabricate

The architecture separates collection outcome, observed fact, assessment, and urgency (`docs/architecture/2026-09-05-purpose-first-design.md:72-89`). Slice 1 preserves that separation in its output schema for both subject types. No fresh positive observation means `unknown`, not healthy — for a service or a filesystem mount alike.

### Observation-only

The service collector executes fixed read-only service-manager commands and records them as read-only (`tools/descartes-cli/src/tools/services.js:57-78`, `tools/descartes-cli/src/tools/services.js:167-174`). The disk collector is likewise fixed and read-only (`tools/descartes-cli/src/tools/disks.js:119-133`, recording `read_only: true` on its own command). Slice 1 adds no alert, proposal, approval, remediation, or executor.

The only writes are Descartes-owned contract configuration and the existing daemon-status snapshot.

### Independent of the learned kill switch

`learned.json` defaults disabled (`tools/descartes-cli/src/constraint-store.js:232-253`). Today that switch gates the structural collection block (`tools/descartes-cli/src/daemon.js:677-727`) and service-baseline evaluation (`tools/descartes-cli/src/service-baseline.js:465-479`) — service protection therefore needs the new dedicated phase of §7.1 to stay outside that gate. Filesystem protection was already outside it: the `disks` collector is a core collector with no learned dependency anywhere in its own module or in `fact-translators.js` (§6.8).

Enabling protection must not require `descartes learned enable`, for either subject; enabling protection must also not implicitly enable learning.

### Desired state comes from the owner

Only `descartes protect add` creates a contract, for either subject.

Service discovery, a longstanding baseline, `service.appeared`, `service.disappeared`, or an observed disk-usage pattern must never write the protection store. "Has always run here" / "has always had headroom" is observed normality; it is not owner-declared desired state (`docs/reviews/2026-09-05-design-and-implementation-critique.md:131-137`).

### Local-first and no LLM

The view is computed entirely from contract configuration and existing local evidence. It must work with no login, model, network access, or alert-intelligence configuration.

---

## 10. Acceptance and demo

### 10.1 Manual demonstration

**Service** (unchanged from the base plan). Use a disposable long-running user-owned test service; Descartes itself performs none of the state changes.

1. Configure the existing notification destination for future use:

   ```bash
   descartes alerts notifications setup --channel cli
   ```

2. Declare the service:

   ```bash
   descartes protect add \
     --name "Demo service" \
     --subject-type service \
     --service demo.service \
     --manager systemd \
     --success running \
     --severity critical \
     --notify configured \
     --observation allowed \
     --json
   ```

3. Before a daemon cycle:

   ```bash
   descartes protect inspect protection_<id>
   ```

   Expected:

   ```text
   Coverage: uncovered
   Assessment: unknown
   Reason: collector_not_run
   ```

4. Run one observation cycle while the service is running:

   ```bash
   descartes daemon run --foreground --once
   descartes protect inspect protection_<id>
   ```

   Expected:

   ```text
   Coverage: covered
   Assessment: healthy
   Evidence: services / collect_services
   ```

5. Stop the disposable service outside Descartes, then rerun the observation:

   ```bash
   descartes daemon run --foreground --once
   descartes protect inspect protection_<id>
   ```

   Expected:

   ```text
   Coverage: covered
   Assessment: failing
   Reason: subject_not_running
   ```

6. Restore the service outside Descartes, rerun, and verify a positive running observation returns `healthy`.

**Filesystem** (new).

1. Declare a mount already present on the host:

   ```bash
   descartes protect add \
     --name "Root filesystem" \
     --subject-type filesystem \
     --mount-point / \
     --success used-fraction-below \
     --severity warning \
     --notify configured \
     --observation allowed \
     --json
   ```

2. Run one observation cycle (filesystem needs no daemon cycle beyond whatever core tick already runs, but for parity with the service demo run one explicitly):

   ```bash
   descartes daemon run --foreground --once
   descartes protect inspect protection_<id>
   ```

   Expected (on a host with headroom):

   ```text
   Coverage: covered
   Assessment: healthy
   Evidence: disk-usage / collect_disks
   ```

3. Declare a second contract for a `mount_point` that does not exist on the host (e.g. `/does-not-exist`), rerun, and verify:

   ```text
   Coverage: uncovered
   Assessment: unknown
   Reason: subject_not_found_in_visible_scope
   ```

   — not `failing`.

No incident or notification is expected for either subject; this slice only updates the view.

### 10.2 Automated loss-of-observability demonstration

An integration test using temporary XDG directories and daemon dependency injection must execute this sequence:

1. Add a real stored service contract and a real stored filesystem contract through `runProtect`.
2. Run `runDaemonIteration` with a successful service envelope; inspect returns `covered / healthy`.
3. Run with a target-specific restarting envelope; inspect returns `covered / degraded`.
4. Run with a complete census where the target is absent; inspect returns `covered / failing`.
5. Run with an `unable` service envelope; inspect returns `capability:supported`, `collection:failed`, `coverage:uncovered`, `assessment:unknown`.
6. Run separately with an unsupported envelope; inspect returns `capability:unsupported`, `collection:not_run`, `coverage:uncovered`, `assessment:unknown`.
7. Run with a disk envelope where the declared mount is present at `used_fraction:0.5`; inspect the filesystem contract returns `covered / healthy`.
8. Run with the mount at `0.92`; inspect returns `covered / degraded`.
9. Run with the mount at `0.97`; inspect returns `covered / failing`.
10. Run with the mount absent from `result.filesystems`; inspect returns `uncovered / unknown` — assert explicitly this is never `failing`.
11. Run with an `unable` disk envelope; inspect returns `capability:supported`, `collection:failed`, `coverage:uncovered`, `assessment:unknown`, and assert `daemon-status.json`'s `state` is `"error"` (required collector failure) — same assertion for the equivalent unable-service case in step 5.
12. Advance the inspection clock beyond freshness without another daemon cycle; both the previously known service result and the previously known filesystem result become `uncovered / unknown`.

The test must explicitly assert that neither the unavailable nor stale nor mount-absent cases return `healthy`, and that mount-absent never returns `failing`.

---

## 11. Out of scope and deferred

Later slices should add, in order:

1. Resource-specific incident episodes and a delivery outbox.
2. Notification transitions for failing, uncertain, recovered, and worsening conditions.
3. Scheduled-job completion evidence — not merely job-definition inventory.
4. Dependencies connecting service, scheduled backup, and destination filesystem (the filesystem *subject* ships in this slice; the dependency *edge* linking it to a specific backup job does not).
5. Tolerance, consecutive-failure rules, grace periods, and maintenance windows.
6. Grounded investigation and optional LLM explanation.
7. Action proposals, authorization, execution, rollback, and postchecks.
8. Discovery suggestions that require explicit owner confirmation.
9. Observation identities and immutable evidence citations.
10. Federation and off-host assurance.
11. Inode-based filesystem thresholds (only `used_fraction`/space is assessed this slice, matching `alert-store.js`'s own scope).

---

# OPEN QUESTIONS / DECISIONS FOR THE OPERATOR

This reconciliation already resolves several questions both source plans raised — service-only vs. two-subject scope, fresh-on-demand vs. daemon-integrated evidence, and required-collector-failure → daemon `state:"error"` — those are not repeated below. What remains:

1. Confirm that slice 1 stores only a **reference to the existing global notification destination**, not a per-contract channel.
2. **Disk-threshold duplication vs. export.** Duplicate `alert-store.js:78-82`'s `0.90`/`0.95` into `protection-assessment.js` with a citing comment (matching the store layer's own "duplicated rather than imported" convention, `fact-store.js:169-171`) vs. a small additive export from `alert-store.js` (touches a file outside the slice's normal footprint). Also note the unreconciled `findings.js:48` `0.97`-critical inconsistency the earlier synthesized plan flagged — out of scope to fix here, but the chosen threshold source should not silently diverge from it further.
3. **Are filesystem `warn_fraction`/`critical_fraction` owner-configurable per contract, or fixed at the `alert-store.js` defaults for slice 1?** The stored shape (§3.1) carries both fields; whether `protect add` exposes flags to override them, or the CLI simply refuses any value other than the default pair, is undecided. Fixing them matches the service subject's fully-derived `success_condition`; exposing them earlier would be a small CLI-only addition.
4. **`services_census` lacks `failed`/`nonzero_exit`** (`tools/descartes-cli/src/tools/services.js` census projection) — a declared unit beyond the top-200 detail limit stays `partial` coverage forever, never reaching `covered`. Accept for slice 1, or make the census projection additive?
5. **Service demo platform.** A user-scope `systemctl --user` unit (Linux) or a user `LaunchAgent` (macOS, visible to non-root `launchctl list`) vs. a root-required systemd system unit — the census collector queries the system manager only, no `--user` (`tools/descartes-cli/src/tools/services.js:167-174`, `214-215`), so a `systemd --user` unit or a system-level macOS `LaunchDaemon` is invisible to it, indistinguishable from uninstalled. Confirm which platform/scope the reference demo (§10.1) should use, so the demo doesn't accidentally exercise the "invisible, not absent" case instead of a genuine positive observation.
6. **The new contract-driven service collection phase's own cadence (§7.1) is not fully specified.** As written it collects once per `runDaemonIteration` call whenever an allowed service contract exists — i.e. on the core tick's cadence, not the (typically slower) structural cadence service collection otherwise runs on. Confirm this is the intended frequency (more `systemctl`/`launchctl` invocations per unit time than today's structural cadence), or whether the phase should carry its own configurable interval closer to the structural cadence.
7. **Should the mount-absent → `unknown`-never-`failing` rule (§6.6) eventually gain a completeness signal** so a sufficiently corroborated absence could someday become `failing`, the way a complete service census can? Slice 1 deliberately does not build this (`df` never truncates today, so there is nothing to corroborate against) — noted for a later slice, not blocking this one.

---

# KEY CODE REFS

- CLI lazy dispatch: `tools/descartes-cli/src/index.js:91-133`
- Existing safety/CLI framing: `README.md:3-24`, `README.md:218-270`
- Learned kill switch default: `tools/descartes-cli/src/constraint-store.js:232-253`
- Learned-gated structural collection: `tools/descartes-cli/src/daemon.js:677-727` (gate check `690-692`, structural call `709`)
- Core (ungated) collector set `{system, processes, disks}`: `tools/descartes-cli/src/daemon.js:303-314`
- Core evidence collected at the top of `runDaemonIteration`, before the learned gate: `tools/descartes-cli/src/daemon.js:641-652`
- Envelope status collapse (`unable` on any exception; no collector ever emits `error`): `tools/descartes-cli/src/tools/envelope.js:19-34`
- Daemon `state` derivation ignoring benign `unable`: `tools/descartes-cli/src/daemon.js:847-892` (`collectorHasError` at `870-871`)
- Atomic daemon-status persistence: `tools/descartes-cli/src/history-store.js:259-289`
- Service evidence shapes: `tools/descartes-cli/src/tools/services.js:89-165`
- Service supported/unable/unsupported mapping, platform gate: `tools/descartes-cli/src/tools/services.js:167-300` (platform branch `279-289`)
- Authoritative service census facts: `tools/descartes-cli/src/fact-translators.js:95-143`
- Service baseline and learned gate: `tools/descartes-cli/src/service-baseline.js:308-372`, `tools/descartes-cli/src/service-baseline.js:465-479`
- Disk collector — per-mount `df` parse, classification, `pressure_relevant`, envelope: `tools/descartes-cli/src/tools/disks.js:34-68` (row parse), `tools/descartes-cli/src/tools/disks.js:80-117` (classification), `tools/descartes-cli/src/tools/disks.js:119-140` (`collectDiskEvidence`)
- Disk collector has no unsupported-platform branch, unlike `services.js:279-289`: `tools/descartes-cli/src/tools/disks.js` (whole file — no `process.platform` branch)
- Raw per-mount metric dimensions incl. `mount_point`, and the daemon's own `pressure_relevant` skip: `tools/descartes-cli/src/daemon.js:275-298` (skips at `278`, `289`)
- Host-wide disk alert aggregate (NOT per-mount; do not reuse for contract assessment): `tools/descartes-cli/src/alert-store.js:164-174`; thresholds at `tools/descartes-cli/src/alert-store.js:78-82`
- `summarizeMetricPoints` groups by `metric_name`, erases `mount_point` (NEVER use for filesystem assessment): `tools/descartes-cli/src/history-store.js:186-227`
- No learned fact/translator exists for disk/filesystem (verified absent): `tools/descartes-cli/src/fact-translators.js`
- Alert-record lifecycle shape: `tools/descartes-cli/src/alert-store.js:179-201`
- Existing recovery semantics: `tools/descartes-cli/src/alert-store.js:260-315`
- Fact completeness vocabulary: `tools/descartes-cli/src/fact-store-integrity.js:550-602`
- Fail-closed history trust: `tools/descartes-cli/src/fact-store-completeness.js:50-90`
- JSON-store read/write idiom: `tools/descartes-cli/src/constraint-store.js:149-206`
- Existing notification destination: `tools/descartes-cli/src/notification-delivery.js:10-69`
- Scheduled-job evidence limitation: `tools/descartes-cli/src/tools/scheduled-jobs.js:495-559`
- Scheduled-job detector scope: `tools/descartes-cli/src/persistence-baseline.js:225-297`
