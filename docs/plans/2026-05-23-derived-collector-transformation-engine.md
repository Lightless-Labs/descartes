# Derived Collector / Pure Transformation Engine

**Created:** 2026-05-23
**Status:** Proposed
**Depends on:** `docs/plans/2026-05-23-daemon-history-store.md`
**Feeds:** `docs/plans/2026-05-23-agent-authored-sensor-toolkit.md`

## Purpose

After the daemon can collect and persist bounded local history, Descartes needs a safe way for background agents to define new derived collectors, sensors, metrics, and algorithms over that stored data.

These artifacts are basically map/reduce/window transformations over Descartes-owned facts and metrics. They must not become arbitrary code execution. The agent can author transformations, but it cannot use them to execute commands, read arbitrary files, access the network, mutate host state, or escape the local data sandbox.

## Conceptual Shape

```text
daemon collectors
  -> evidence envelopes / facts / metric points
  -> local history store
  -> agent-authored pure transformations
       map/filter: evidence/facts/metrics -> derived facts/metrics
       reduce/window: time windows -> aggregates/baselines/anomalies
  -> derived collectors / sensors
  -> review and promotion gates
```

A derived collector is not a host collector. It is a deterministic data product derived from already-collected Descartes evidence/history.

## Artifact Types

### Derived collector

Produces derived facts or metrics from stored inputs.

Example:

```yaml
kind: derived_collector
name: sustained_process_cpu
version: 1
inputs:
  - metric: process.cpu_percent
window: 15m
group_by: [command]
transform:
  reduce:
    mean_cpu: mean(value)
    max_cpu: max(value)
    samples: count(value)
emit:
  fact: sustained_process_cpu(command, mean_cpu, max_cpu, samples)
bounds:
  max_groups: 50
  min_samples: 5
privacy:
  sensitivity: process_metadata
```

### Derived metric

Produces a metric series from facts or other metrics.

Examples:

- `process.cpu_percent.mean_15m{command}`
- `service.failed_count.delta_1h{scope}`
- `disk.free_bytes.min_24h{mount}`

### Derived sensor

Produces a finding/trigger candidate from derived facts or metrics.

Example:

```prolog
hot_process(Command) :-
  sustained_process_cpu(Command, Mean, Max, Samples),
  Samples >= 5,
  Mean > 80.
```

## Example Capability: Track One Executable Across Process Instances

A concrete end-state capability should be possible from the CLI:

```bash
descartes watch executable /usr/bin/postgres --name postgres-behavior
```

or, through the model-led CLI:

```bash
descartes triage "keep an eye on postgres and tell me if its behavior changes"
```

Descartes should be able to set up a derived collector/sensor that tracks one binary, executable identity, process name, bundle ID, container image entrypoint, or other stable executable identity across all process instances over time.

The daemon still only runs normal read-only process/system collectors. The derived collector groups process observations by stable executable identity and computes behavior metrics across all instances:

- instance count over time
- total and per-instance CPU
- total and per-instance RSS/memory
- parent/child lineage patterns
- command-line shape changes with redacted arguments
- user/UID distribution where available
- container/VM correlation where available
- listening ports / network role when network facts are available
- restart/churn rate
- first seen / last seen
- baseline windows and anomaly scores

Example artifact sketch:

```yaml
kind: derived_collector
name: postgres_behavior
version: 1
inputs:
  - fact: process_observation
  - fact: process_parent_edge
window: 24h
identity:
  executable_path: /usr/bin/postgres
group_by: [executable_identity]
transform:
  reduce:
    instances: distinct_count(pid)
    total_cpu: sum(cpu_percent)
    mean_cpu_per_instance: mean(cpu_percent)
    max_cpu_per_instance: max(cpu_percent)
    total_rss_bytes: sum(rss_bytes)
    max_rss_bytes: max(rss_bytes)
    restart_rate_1h: rate(new_pid_seen)
    command_shapes: distinct_count(redacted_command_shape)
emit:
  metric: executable.behavior
  dimensions: [executable_identity]
bounds:
  max_groups: 1
  max_window: 24h
  max_command_shapes: 25
privacy:
  sensitivity: process_metadata
```

A later sensor/model can consume this derived metric to detect behavior drift without the LLM watching raw process tables continuously.

## Transformation DSL Requirements

The DSL should be deliberately small and auditable.

Allowed primitives:

- select input facts/metrics by name and bounded time window
- project fields
- filter with typed predicates
- map to typed derived values
- group by bounded dimensions
- reduce with approved aggregations
- join only on explicitly allowed keys and bounded windows
- emit typed facts/metrics/findings

Approved aggregations:

- count
- min
- max
- mean
- median where feasible
- p95/p99 where enough samples exist
- sum
- last
- first
- rate
- delta
- distinct count with cardinality cap
- stddev where useful

Disallowed:

- arbitrary JavaScript/Rust/Python/shell
- filesystem reads/writes outside the history/artifact store
- network access
- process execution
- dynamic imports/modules
- unbounded loops/recursion
- unbounded joins/group cardinality
- mutation of source facts/metrics

## Execution Model

Transformations run in a local sandbox over Descartes-owned data:

1. Load artifact.
2. Validate schema, types, input names, windows, cardinality bounds, and output shape.
3. Build an execution plan.
4. Estimate cost/cardinality.
5. Execute against bounded history window.
6. Emit derived facts/metrics with provenance.
7. Record diagnostics: rows read, rows emitted, latency, dropped groups, missing data, bounds hit.

All outputs should preserve provenance back to source metric/fact windows and transformation artifact version.

## Agent Workbench Tools

The background LLM agent should get tools like:

- list available metrics/facts and schemas
- inspect bounded sample windows
- draft a derived collector artifact
- generate positive/negative fixtures
- run artifact against fixtures
- run artifact against bounded historical replay in shadow mode
- explain output provenance and aggregation path
- lint for privacy/bounds/cardinality/cost
- open promotion request

It should not get tools that execute arbitrary code or mutate host state.

## Promotion Lifecycle

1. draft
2. fixture-tested
3. shadow replay
4. human-reviewed
5. active derived collector/sensor
6. deprecated/retired

Promotion gates:

- schema-valid artifact
- bounded execution plan
- fixtures pass
- privacy labels present
- cardinality and retention limits set
- output provenance present
- human approval until a later policy explicitly allows narrower autonomous promotion

## Relationship To Logic Rules and Statistical Models

The transformation engine is the data plane that feeds both:

- Prolog/Datalog/Casbin-like logic rules over derived facts.
- Statistical model artifacts over derived metrics/windows.

In other words:

```text
history store -> pure transformations -> derived facts/metrics -> logic/statistical sensors
```

## Initial Milestones

### Milestone 1: Artifact schema and validator

- Define JSON/YAML schema for derived collector artifacts.
- Validate input metrics/facts, windows, group keys, aggregations, emit shape, and bounds.
- Add negative tests for forbidden operations and unbounded artifacts.

### Milestone 2: In-memory transformation runner

- Run map/filter/group/reduce over fixture metric rows.
- Emit derived facts/metrics with provenance and diagnostics.
- Enforce cardinality and row/window limits.

### Milestone 3: History-store integration

- Run transformations over daemon history windows.
- Write derived metrics/facts back to the store or an artifact namespace.
- Preserve artifact version/provenance.

### Milestone 4: Agent review packet

- Generate a review packet containing artifact source, fixtures, evaluation results, bounds, privacy labels, and sample outputs.

### Milestone 5: Shadow mode

- Run candidate transformations without affecting active CLI/triage outputs.
- Compare output stability over time.

## Non-Goals

- No arbitrary generated code execution.
- No host collection from derived collectors.
- No background LLM calls as part of transformation execution.
- No notifications or host actions.
- No autonomous activation before policy/authority support exists.

## Acceptance Criteria

- Agents can propose useful derived collectors as declarative artifacts.
- Runner can execute artifacts over fixtures without arbitrary code execution.
- Runtime enforces bounds, cardinality caps, and allowed operations.
- Outputs include provenance and diagnostics.
- Transformation artifacts can feed later rule/model/sensor layers.
