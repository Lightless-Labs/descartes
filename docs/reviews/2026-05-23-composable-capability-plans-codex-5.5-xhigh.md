## Overall verdict

The three 2026-05-23 plans are directionally well aligned with the intended Descartes architecture: they prioritize a reusable substrate over bespoke detectors, put history before intelligence, and frame executable-behavior tracking as a composability example rather than the core product.

Main concern: the plans need a clearer shared **fact/metric/entity catalog** boundary. The daemon/history plan currently stores metrics and compact evidence, while the derived transformation plan assumes facts already exist, and the sensor-toolkit plan defines the fact bridge later. To preserve the desired order, a minimal fact/entity/schema catalog should move earlier into the daemon/history or derived-transform layer.

Recommended order remains:

1. `docs/plans/2026-05-23-daemon-history-store.md`
2. `docs/plans/2026-05-23-derived-collector-transformation-engine.md`
3. `docs/plans/2026-05-23-agent-authored-sensor-toolkit.md`

## Strong alignment points

- **General substrate over bespoke logic:** All three plans explicitly avoid hand-authoring a giant signature library.
- **Good layering intent:** daemon/history first, pure derived transformations second, rule/model/sensor workbench third.
- **Read-only defaults:** No background LLM calls, no host mutation, no arbitrary shell/code execution.
- **Composable data plane:** Evidence envelopes → facts/metrics/history → transformations → rules/models/sensors is the right shape.
- **Promotion lifecycle:** Draft, fixture-tested, shadow, review, active, retired is well aligned with agent-authored artifacts.
- **Executable tracking example is mostly safe:** The postgres/executable behavior example demonstrates grouping, identity, windows, rollups, and provenance without requiring bespoke postgres logic.

## Priority gaps / misalignments

### P0 — Fact/entity catalog is in the wrong place

`derived-collector-transformation-engine.md` assumes inputs like `process_observation` and `process_parent_edge`, but the actual fact bridge is introduced in `agent-authored-sensor-toolkit.md`.

Move or duplicate a minimal substrate earlier:

- stable fact schema catalog
- metric catalog
- entity/identity model
- dimensions and units
- provenance model
- sensitivity labels
- schema versioning

Without this, the transformation engine has no well-defined input surface.

### P0 — Daemon/history needs stronger agent-facing query primitives

The daemon plan has good storage basics, but later agents will need more than raw metric rows and rollups.

Add explicit support for:

- bounded window queries
- sampled vs event observations
- state snapshots vs transitions/events
- missing-data semantics
- collection-run records
- query diagnostics: rows scanned, truncation, bounds hit
- stable metric/fact names and schema discovery
- artifact namespaces for future derived outputs

### P1 — Safety boundaries should be made uniform across all plans

The derived plan is strongest here. The daemon/history and sensor-toolkit plans should explicitly repeat:

- runtime limits
- memory limits
- row/window scan limits
- group/cardinality caps per artifact and per metric
- max output rows/findings
- storage quotas by data class
- no filesystem/process/network escape from workbench/evaluator tools
- provider-egress/privacy gates for `triage --use-history`
- audit trail for artifact creation, evaluation, promotion, rollback, and retirement

### P1 — Sensor toolkit todo could be misread as starting too early

`todos/2026-05-23-agent-authored-sensor-toolkit.md` includes local metric/history storage design and a rule-runner prototype in its “Initial Milestone.” That risks pulling implementation toward rules before daemon/history and transformations are done.

Recommend marking it explicitly as **blocked by** daemon/history and derived transformation foundations, with only design allowed until then.

### P1 — Rules, policy, and statistical models need sharper separation

The plans mention Prolog/Datalog/Casbin-like rules plus statistical models. That is viable, but risky if conflated.

Keep separate planes:

- **Datalog/logic:** operational facts/signatures/sensor derivations.
- **Statistical models:** scores, baselines, anomaly facts.
- **Casbin/policy:** authorization and promotion/activation decisions.

Do not let operational anomaly rules become authority rules.

## Missing abstractions/primitives

Add plan language for:

- **Entity identity layer:** process, executable, service, container, VM, certificate, mount, network endpoint.
- **Opaque/privacy-preserving identifiers:** stable enough for local joins, not raw/provider-leaky by default.
- **Observation/event/state model:** current snapshot, transition, metric point, derived fact, finding.
- **Schema evolution:** versioned facts/metrics/artifacts and migration behavior.
- **Artifact registry:** owner, version, lifecycle state, provenance, fixtures, evaluation results, approval record.
- **Replay/evaluation harness:** synthetic fixtures, scrubbed real fixtures, shadow replay, false-positive/false-negative capture.
- **Incremental/window semantics:** sliding/tumbling windows, watermarks, late/missing data, clock changes.
- **Resource accounting:** rows read, groups emitted, latency, memory, storage, dropped groups.
- **Privacy labels at field/dimension/output level**, not only artifact level.

## Recommendations for plan edits / next milestones

1. **Amend daemon/history plan** to include a minimal fact/metric/entity catalog and bounded query API.
2. **Amend derived transformation plan** to state its inputs are only cataloged facts/metrics from the daemon store, plus derived namespaces.
3. **Amend sensor-toolkit plan** to defer rule/model execution until after the transformation runner exists.
4. **Add a first implementation milestone:** storage schema + catalog + bounded query interface before daemon scheduling sophistication.
5. **Add artifact registry/promotion audit tables early**, even if promotion is manual-only at first.
6. **Make `triage --use-history` privacy behavior explicit:** bounded summaries only, sensitivity-aware, no raw logs/process history by default.

## Cautions on executable-tracking example

The example is useful, but keep it as a **worked composability test**, not a product detour.

Avoid:

- hardcoded postgres-specific logic
- bespoke executable watchers as the main abstraction
- manual libraries of process signatures
- custom one-off algorithms for command-shape drift

Prefer framing it as: “Can the substrate express identity grouping, bounded windows, derived metrics, provenance, and later sensor consumption?” If yes, the architecture is doing its job.
