> **Independent alternative — gpt-daybreak-blue-latest @ xhigh, 2026-09-09.** Produced from the 2026-09-05 design/critique + the code ONLY, explicitly NOT anchored to the synthesized plan (`docs/plans/2026-09-09-protection-contract-slice-1.md`). **Its architecture was ADOPTED as the spine of the canonical plan** (`docs/plans/2026-09-09-protection-contract-slice-1.md`) — daemon-integrated contract-driven collection, the 3-axis coverage model, freshness rules, and required-collector-failure → daemon `state:error`. The one reconciliation was restoring `filesystem` as a co-equal subject (this plan's §2.2 over-deferred it). Kept here for provenance / independent-derivation record; **build from the canonical plan, not this file.**

# Protection Contract Slice 1 — Truthful Service Coverage and Assessment

**Date:** 2026-09-09  
**Status:** PLAN  
**Design basis:** [Purpose-first design](docs/architecture/2026-09-05-purpose-first-design.md) · [Design and implementation critique](docs/reviews/2026-09-05-design-and-implementation-critique.md)

## 1. Goal and scope

**Slice 1 = declare a protected job and get a truthful coverage + assessment view for it, reusing existing evidence—no new detectors, no actions, no LLM.**

The owner explicitly identifies one important long-running service. Descartes observes it through the existing service collector and reports two independent conclusions:

- **Coverage:** `covered | partial | uncovered`
- **Assessment:** `healthy | degraded | failing | unknown`

This supplies the explicit protection contract currently missing from the product (`docs/reviews/2026-09-05-design-and-implementation-critique.md:118-137`) and implements the first purpose-first milestone: seeing a protected service with bounded, honest observations (`docs/architecture/2026-09-05-purpose-first-design.md:221-231`).

### What this is NOT

This slice does **not** implement:

- Incident or episode identity, incident transitions, recovery semantics, or a notification delivery outbox. Those form the next slice.
- Alert creation or notification delivery from protection assessments.
- Action proposals, approvals, remediation, containment, or execution.
- LLM investigation, explanation, or triage.
- Job discovery or automatic protection suggestions.
- Automatic conversion of baselines, previously observed services, or alerts into contracts.
- Scheduled-backup completion monitoring.
- Filesystem dependency composition.
- The full tolerance, maintenance-window, delay, or interruption-cost model.
- Per-contract notification transports.
- Federation, remote telemetry, or off-host witnessing.

Descartes remains observation-only. The repository’s current framing likewise says no general host-action command exists and evidence collection is read-only (`README.md:3-9`, `README.md:404-425`).

## 2. Design decisions

### 2.1 Start with one subject type: a long-running service

Slice 1 should support only:

```text
subject.type = "service"
success_condition.type = "service_running"
```

The service subject is the smallest credible protected job because the existing collector already provides:

- Exact systemd unit names, `running`, `failed`, and `restarting` state (`tools/descartes-cli/src/tools/services.js:89-113`).
- Exact launchd labels, running state, and last exit status (`tools/descartes-cli/src/tools/services.js:116-134`).
- An authoritative census distinct from its 80-item presentation list, with explicit truncation (`tools/descartes-cli/src/tools/services.js:190-211`, `tools/descartes-cli/src/tools/services.js:231-249`).
- Structured distinctions among successful collection, collection failure, and unsupported platform (`tools/descartes-cli/src/tools/services.js:167-188`, `tools/descartes-cli/src/tools/services.js:252-300`).
- Existing `service.presence` facts carrying the service’s running state and a census marker that distinguishes a genuine enumeration from no enumeration (`tools/descartes-cli/src/fact-translators.js:95-143`).
- Existing deterministic appearance/disappearance detectors, although these are historical novelty signals rather than current service-health checks (`tools/descartes-cli/src/service-baseline.js:1-33`, `tools/descartes-cli/src/service-baseline.js:308-372`).

The initial contract is deliberately limited to long-running services. A systemd oneshot unit in `active/exited` state does not satisfy `service_running`.

### 2.2 Defer filesystem and scheduled-job subjects

Do not expose subject types that the first slice cannot assess honestly:

- The disk collector supplies resource-specific mount measurements (`tools/descartes-cli/src/tools/disks.js:34-68`, `tools/descartes-cli/src/daemon.js:275-297`), but the current alert summary groups by metric name and the disk rule reports only that “at least one” filesystem is pressured (`tools/descartes-cli/src/history-store.js:186-205`, `tools/descartes-cli/src/alert-store.js:164-173`). Resource-specific disk protection should follow the resource-identity work.
- The scheduled-job collector inventories cron, systemd timer, and launchd definitions (`tools/descartes-cli/src/tools/scheduled-jobs.js:177-201`, `tools/descartes-cli/src/tools/scheduled-jobs.js:516-559`). Its current detector reports only a newly appeared definition (`tools/descartes-cli/src/persistence-baseline.js:225-283`). Neither establishes that work ran successfully or that a backup is restorable. The critique explicitly warns that inventory is not execution success (`docs/reviews/2026-09-05-design-and-implementation-critique.md:108-114`).

The motivating service → scheduled backup → filling disk scenario remains the direction, but slice 1 establishes only its first truthful protected object.

## 3. `ProtectionContract`

### 3.1 Stored shape

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

Fields:

| Field | Slice-1 contract |
|---|---|
| `id` | Generated stable UUID prefixed with `protection_`; immutable. |
| `name` | Owner-provided display name. |
| `subject.type` | Exactly `service`. |
| `subject.manager` | Exactly `systemd` or `launchd`; no ambiguous `auto` value is stored. |
| `subject.name` | Exact systemd unit or launchd label matched against collector output. |
| `success_condition.type` | Exactly `service_running`. |
| `failure_severity` | `info | warning | critical`; records owner importance for later incident work but does not itself send an alert. These values align with existing alert severity vocabulary (`tools/descartes-cli/src/alert-store.js:179-201`). |
| `notification_destination.type` | Exactly `configured_default`, referencing the existing global notification configuration. |
| `observation_permission` | `allowed | denied`. Only `allowed` authorizes contract-driven collection and evaluation. |

### 3.2 Validation

`validateProtectionContract(record)` must reject:

- Non-object or array records.
- Unknown top-level or nested keys.
- Empty, overlong, control-character-containing IDs, names, or service identities.
- Unknown subject, manager, success-condition, severity, destination, or permission enums.
- A systemd subject whose name does not end in `.service`.
- Duplicate IDs.
- Duplicate `(manager, subject.name)` subjects.
- Duplicate owner-visible names, to avoid ambiguous CLI selection.

Validation runs both before writing and while loading, following the repository’s validate-before-persist pattern (`tools/descartes-cli/src/constraint-store.js:95-147`, `tools/descartes-cli/src/constraint-store.js:191-206`).

Generate IDs through an injectable ID factory so tests remain deterministic.

### 3.3 Tolerance and maintenance

Do not store placeholder tolerance or maintenance fields in schema version 1. Their slice-1 semantics are:

- Assessment is immediate current-state assessment.
- No grace period or duration threshold is applied.
- No maintenance window suppresses or rewrites an assessment.

The CLI must disclose that the assessment is maintenance-unaware. Adding empty fields now would imply semantics the implementation does not yet possess.

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

Contracts belong in `configDir`, not `stateDir`: they are owner configuration, like the existing notification destination at `configDir/notifications.json` (`tools/descartes-cli/src/notification-delivery.js:10-16`). Derived assessments remain daemon state.

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
- CLI and daemon must surface corrupt/degraded state; they must never silently render it as “no protections configured.”

This preserves the existing missing/corrupt reader idiom (`tools/descartes-cli/src/constraint-store.js:149-188`) while strengthening its operator-visible accounting for owner-declared protection.

The slice accepts the repository’s current single-writer limitation. Atomic replacement prevents torn reads but does not solve two simultaneous CLI additions.

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
  --service postgresql.service \
  --manager systemd \
  --success running \
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
  --service com.example.database \
  --manager launchd \
  --success running \
  --severity critical \
  --notify configured \
  --observation allowed
```

No aliases or positional inference should be added in slice 1. The explicit options prevent a user from accidentally protecting the wrong service manager or believing unsupported success conditions exist.

### 5.2 Command behavior

`protect add`:

- Validates every argument.
- Resolves `configured` to the stored `configured_default` reference.
- Rejects duplicate ID/name/subject.
- Writes only the Descartes-owned contract configuration.
- Prints the generated ID and a reminder that coverage remains `uncovered` and assessment `unknown` until a daemon cycle observes it.

`protect list`:

- Lists all contracts.
- Joins each contract to the latest daemon protection snapshot.
- Shows `coverage` and `assessment` columns.
- If no current snapshot exists, prints `uncovered / unknown`; it never prints healthy from an empty alert list.
- Reports contract-store corruption before any rows.

`protect inspect`:

- Prints the complete contract.
- Prints capability, collection outcome, coverage, assessment, observation timestamp, freshness, and evidence source.
- Resolves the existing notification config for display only: enabled/disabled and channel. Existing notification configuration supports `cli`, macOS desktop/native, Linux desktop, and syslog (`tools/descartes-cli/src/notification-delivery.js:10-49`).
- Does not send a notification.

### 5.3 JSON result

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

The envelope/tool references are locator metadata, not immutable observation IDs. The current evidence envelope ID is reused as `"services"` (`tools/descartes-cli/src/tools/services.js:291-300`); occurrence-level citations belong with the later incident/evidence-identity slice.

## 6. Coverage and assessment mapping

Add:

```text
tools/descartes-cli/src/protection-assessment.js
tools/descartes-cli/test/protection-assessment.test.js
```

Export pure functions:

```js
assessServiceProtection(contract, serviceEnvelope, context)
assessProtectionContracts(contracts, evidence, context)
materializeProtectionView(contract, daemonStatus, context)
```

### 6.1 Keep the axes separate

Coverage must preserve three different questions:

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

This makes unsupported capability visibly different from a supported collector that failed.

That separation is required because the shared envelope wrapper currently converts every thrown collector exception to `status:"unable"` and `review_hint:"missing_permission"`, regardless of the underlying cause (`tools/descartes-cli/src/tools/envelope.js:19-33`). The protection view must therefore say `collector_unable`; it must not assert “permission denied” unless a collector provides evidence for that narrower statement.

### 6.2 Current-cycle and freshness rules

A protection observation is current only if:

- It is present in the latest daemon status.
- Its cycle timestamp parses successfully.
- It is no older than:

```text
max(5 minutes, 3 × daemon profile.interval_ms)
```

This matches the existing daemon/sample staleness policy (`tools/descartes-cli/src/alert-store.js:75-92`, `tools/descartes-cli/src/alert-store.js:112-135`).

When the daemon status is missing, unreadable, malformed, or stale:

```text
coverage.status     = uncovered
capability          = unknown
collection          = not_run
assessment.status   = unknown
reason              = daemon_status_missing | daemon_status_unreadable |
                      daemon_status_malformed | observation_stale
```

A stale stored `healthy`, `degraded`, or `failing` result may be displayed only as `last_known_assessment`; it cannot remain the current assessment.

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

Do not interpret the envelope’s top-level `warning` as collection failure. The collector emits `warning` when any systemd service is failed/restarting, even though enumeration succeeded (`tools/descartes-cli/src/tools/services.js:252-265`). Assessment must inspect the declared target only; an unrelated failed service cannot degrade the protected service.

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

### 6.5 Never-fabricate rules

These rules are mandatory:

1. `healthy` requires a fresh, positive observation of the declared subject in a running state.
2. “No relevant alert fired” is never evidence of health.
3. Empty candidate lists are never evidence of recovery or health.
4. A failed or skipped collector produces `unknown`, never `healthy`.
5. A service missing from an incomplete census produces `unknown`, never `failing` or `healthy`.
6. A service missing from a fresh, complete census may be `failing` because the owner—not a learned baseline—declared that it should be running.
7. A previously healthy contract whose evidence disappears becomes `unknown` on the next cycle.
8. A stopped daemon eventually makes every stored assessment `unknown` through freshness expiry.
9. Notification readiness does not alter coverage or assessment.
10. Fact-history integrity does not downgrade a fresh direct service observation. It affects historical novelty claims, not the current `service_running` condition.

The fact store models `intact`, `degraded`, and `unknown` explicitly and grants trust only on positive proof (`tools/descartes-cli/src/fact-store-integrity.js:550-602`, `tools/descartes-cli/src/fact-store-completeness.js:50-90`). The protection evaluator should carry the same fail-closed posture without unnecessarily requiring history for a current-state condition.

### 6.6 Existing fact and detector outputs

For the service subject:

- **Status-bearing evidence:** the current `collectServiceEvidence` envelope, particularly its manager, result status, truncation, authoritative census, and target state.
- **Persisted facts:** `service.presence` with `attributes.running` and the `service.census` marker remain owned by the learned structural-history path (`tools/descartes-cli/src/fact-translators.js:119-143`). They are not sufficient by themselves to call the service currently healthy when no current protection cycle ran.
- **Existing detector:** `service.disappeared` is historical set-difference evidence over fresh, complete censuses (`tools/descartes-cli/src/service-baseline.js:308-372`). It may later be attached as related evidence, but slice 1 must not depend on it because the detector is disabled before any I/O when `learned.json` is off (`tools/descartes-cli/src/service-baseline.js:465-479`).
- **Alert store:** alert status values describe alert lifecycle (`active`, `recovered`, `acknowledged`, `suppressed`), not workload health (`tools/descartes-cli/src/alert-store.js:179-201`). Do not map a recovered alert directly to `healthy`.

## 7. Daemon integration

The coverage view should use a durable latest daemon snapshot rather than silently collecting only when the user asks to inspect it.

### 7.1 Contract-driven service collection

Within `runDaemonIteration`:

1. Load the contract store before protection collection.
2. Select contracts with:
   - `subject.type === "service"`
   - `observation_permission === "allowed"`
3. If at least one exists, invoke the existing `collectServiceEvidence` exactly once for the cycle.
4. Share that one census across every allowed service contract.
5. Assess all contracts through the pure assessment module.
6. Persist the projections in the existing atomic `daemon-status.json`.

The current fast collectors run in `collectDaemonEvidence` (`tools/descartes-cli/src/daemon.js:303-313`), while service collection currently sits in the slower structural batch (`tools/descartes-cli/src/daemon.js:316-354`). Contract-driven collection should be a distinct, named phase so it is not accidentally gated by learned monitoring.

No contracts, or only denied contracts, means no additional collector call.

### 7.2 Reuse rather than duplicate

When learned monitoring is enabled and the slower structural batch is due, inject the already-collected service envelope as that batch’s `services` collector result. The existing structural collector injection seam already accepts a replacement `services` function (`tools/descartes-cli/src/daemon.js:320-347`).

This preserves existing fact translation and baseline behavior while avoiding two service censuses in the same daemon cycle.

When learned monitoring is disabled:

- Do not write protection observations to the learned fact store.
- Do not run service baselines.
- Do persist the current per-contract assessment in daemon status.

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
    "assessments": []
  }
}
```

Each assessment contains only the bounded subject-state projection used for the decision, not the full host service census.

`writeDaemonStatus` already uses atomic temporary-file replacement (`tools/descartes-cli/src/history-store.js:259-279`).

### 7.4 Required collector failure

The existing overall daemon state deliberately ignores generic `unable` envelopes because some can be benign platform limitations (`tools/descartes-cli/src/daemon.js:847-876`). A declared contract provides the missing context:

- A matching supported service collector that is `unable` is a `required_collector_failure`.
- It sets the contract to `uncovered / unknown`.
- It is recorded in `protection.required_collector_failures`.
- It forces the current daemon status `state` to `error`.
- A known unsupported platform remains separately represented as `unsupported`; it does not masquerade as a failed collection.

A corrupt/unreadable protection store also forces `state:"error"` because Descartes cannot establish which required observations exist.

This changes behavior only when owner-declared contracts exist.

## 8. Build sequence

### Phase 1 — Contract schema and store

Write failing tests first for:

- Every valid and invalid contract field.
- Closed enums and closed object shapes.
- Stable ID creation.
- Duplicate subject/name rejection.
- Missing, corrupt, degraded, and valid store results.
- Valid atomic round-trip with `0600` file and no remaining temporary file.
- Rejected writes preserving the prior file.
- Refusal to add over corrupt/degraded state.

Then implement `protection-contract-store.js`.

### Phase 2 — Pure coverage and assessment

Create actual service-envelope fixtures matching both collector managers.

Write the full matrix before implementation:

- systemd running, restarting, failed, inactive, absent.
- launchd running/zero exit, running/nonzero exit, not running, absent.
- Unrelated failed service does not degrade the protected subject.
- Complete versus truncated absence.
- Unsupported versus supported-but-unable.
- Denied observation.
- Missing, malformed, contradictory, and stale evidence.
- Prior healthy followed by unavailable evidence yields unknown.
- No-alert and recovered-alert fixtures never create health.

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
- Required collector failure and corrupt contract store affect daemon state.
- Status contains bounded assessments both in memory and after reading `daemon-status.json`.
- A later unable cycle overwrites a prior healthy snapshot with unknown.

Then modify `daemon.js`.

### Phase 4 — CLI and documentation

Add `protect.js`, the `index.js` branch, usage text, and README documentation.

Test:

- `add`, `list`, and `inspect` in human and JSON forms.
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

## 9. Invariants preserved

### Never fabricate

The architecture separates collection outcome, observed fact, assessment, and urgency (`docs/architecture/2026-09-05-purpose-first-design.md:72-89`). Slice 1 preserves that separation in its output schema.

No fresh positive observation means `unknown`, not healthy.

### Observation-only

The service collector executes fixed read-only service-manager commands and records them as read-only (`tools/descartes-cli/src/tools/services.js:57-78`, `tools/descartes-cli/src/tools/services.js:167-174`). Slice 1 adds no alert, proposal, approval, remediation, or executor.

The only writes are Descartes-owned contract configuration and the existing daemon-status snapshot.

### Independent of the learned kill switch

`learned.json` defaults disabled (`tools/descartes-cli/src/constraint-store.js:232-253`). Today that switch gates the structural collection block (`tools/descartes-cli/src/daemon.js:677-727`) and service-baseline evaluation (`tools/descartes-cli/src/service-baseline.js:465-479`).

Contract-driven observation must occur outside that gate. Enabling protection must not require `descartes learned enable`; enabling protection must also not implicitly enable learning.

### Desired state comes from the owner

Only `descartes protect add` creates a contract.

Service discovery, a longstanding baseline, `service.appeared`, or `service.disappeared` must never write the protection store. “Has always run here” is observed normality; it is not owner-declared desired state (`docs/reviews/2026-09-05-design-and-implementation-critique.md:131-137`).

### Local-first and no LLM

The view is computed entirely from contract configuration and existing local evidence. It must work with no login, model, network access, or alert-intelligence configuration.

## 10. Acceptance and demo

### 10.1 Manual demonstration

Use a disposable long-running user-owned test service; Descartes itself performs none of the state changes.

1. Configure the existing notification destination for future use:

   ```bash
   descartes alerts notifications setup --channel cli
   ```

2. Declare the service:

   ```bash
   descartes protect add \
     --name "Demo service" \
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

No incident or notification is expected; this slice only updates the view.

### 10.2 Automated loss-of-observability demonstration

An integration test using temporary XDG directories and daemon dependency injection must execute this sequence:

1. Add a real stored contract through `runProtect`.
2. Run `runDaemonIteration` with a successful service envelope; inspect returns `covered / healthy`.
3. Run with a target-specific restarting envelope; inspect returns `covered / degraded`.
4. Run with a complete census where the target is absent; inspect returns `covered / failing`.
5. Run with an `unable` service envelope; inspect returns:
   - `capability:supported`
   - `collection:failed`
   - `coverage:uncovered`
   - `assessment:unknown`
6. Run separately with an unsupported envelope; inspect returns:
   - `capability:unsupported`
   - `collection:not_run`
   - `coverage:uncovered`
   - `assessment:unknown`
7. Advance the inspection clock beyond freshness without another daemon cycle; the previously known result becomes `uncovered / unknown`.

The test must explicitly assert that neither the unavailable nor stale cases return `healthy`.

## 11. Out of scope and deferred

Later slices should add, in order:

1. Resource-specific incident episodes and a delivery outbox.
2. Notification transitions for failing, uncertain, recovered, and worsening conditions.
3. A filesystem subject with mount-specific identity and assessment.
4. Scheduled-job completion evidence—not merely job-definition inventory.
5. Dependencies connecting service, scheduled backup, and destination filesystem.
6. Tolerance, consecutive-failure rules, grace periods, and maintenance windows.
7. Grounded investigation and optional LLM explanation.
8. Action proposals, authorization, execution, rollback, and postchecks.
9. Discovery suggestions that require explicit owner confirmation.
10. Observation identities and immutable evidence citations.
11. Federation and off-host assurance.

# OPEN QUESTIONS / DECISIONS FOR THE ARCHITECT

- Confirm the recommended **service-only** subject scope; filesystem and scheduled-job contracts remain deferred.
- Confirm that a **supported required collector becoming unable forces daemon `state:"error"`**, while known unsupported capability remains separately `uncovered`.
- Confirm that slice 1 stores only a **reference to the existing global notification destination**, not a per-contract channel.
- Confirm the current-view freshness bound of **`max(5 minutes, 3 × daemon interval)`**.

# KEY CODE REFS VERIFIED

- CLI lazy dispatch: `tools/descartes-cli/src/index.js:91-133`
- Existing safety/CLI framing: `README.md:3-24`, `README.md:218-270`
- Learned kill switch default: `tools/descartes-cli/src/constraint-store.js:232-253`
- Learned-gated structural collection: `tools/descartes-cli/src/daemon.js:677-727`
- Fast collector and metric wiring: `tools/descartes-cli/src/daemon.js:242-313`
- Daemon status assembly: `tools/descartes-cli/src/daemon.js:847-910`
- Atomic daemon-status persistence: `tools/descartes-cli/src/history-store.js:259-289`
- Service evidence shapes: `tools/descartes-cli/src/tools/services.js:89-165`
- Service supported/unable/unsupported mapping: `tools/descartes-cli/src/tools/services.js:167-300`
- Authoritative service census facts: `tools/descartes-cli/src/fact-translators.js:95-143`
- Service baseline and learned gate: `tools/descartes-cli/src/service-baseline.js:308-372`, `tools/descartes-cli/src/service-baseline.js:465-479`
- Alert-record lifecycle shape: `tools/descartes-cli/src/alert-store.js:179-201`
- Existing recovery semantics: `tools/descartes-cli/src/alert-store.js:260-315`
- Fact completeness vocabulary: `tools/descartes-cli/src/fact-store-integrity.js:550-602`
- Fail-closed history trust: `tools/descartes-cli/src/fact-store-completeness.js:50-90`
- JSON-store read/write idiom: `tools/descartes-cli/src/constraint-store.js:149-206`
- Existing notification destination: `tools/descartes-cli/src/notification-delivery.js:10-69`
- Scheduled-job evidence limitation: `tools/descartes-cli/src/tools/scheduled-jobs.js:495-559`
- Scheduled-job detector scope: `tools/descartes-cli/src/persistence-baseline.js:225-297`