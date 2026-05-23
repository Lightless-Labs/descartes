---
title: Derived Collector / Pure Transformation Engine
created: 2026-05-23
status: open
priority: high
area: architecture
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-23-derived-collector-transformation-engine.md
  - docs/plans/2026-05-23-daemon-history-store.md
  - docs/plans/2026-05-23-agent-authored-sensor-toolkit.md
---

# TODO: Derived Collector / Pure Transformation Engine

## Summary

After daemon/history exists, let background agents define new derived collectors/sensors as pure declarative transformations over Descartes-owned facts and metrics.

This is map/filter/group/reduce/window over stored data, not arbitrary code execution and not host collection. The agent can author algorithms and transformations, but cannot use them to execute commands, read arbitrary files, access the network, or mutate host state.

## Initial Scope

- Artifact schema for derived collectors.
- Validator for inputs, windows, group keys, aggregations, emit shape, and bounds.
- In-memory transformation runner over fixtures.
- Approved aggregation primitives: count, min, max, mean, median/p95 where feasible, sum, last, first, rate, delta, distinct count with caps.
- Explicitly forbidden arbitrary JS/Rust/Python/shell, filesystem/network/process access, dynamic imports, unbounded loops, unbounded joins, and source mutation.
- Provenance and diagnostics for every output.

## Acceptance Criteria

- A candidate derived collector can be expressed as a declarative artifact.
- Runner executes it over fixture metric rows and emits derived facts/metrics.
- Runtime enforces row/window/cardinality limits.
- Forbidden operations are rejected by tests.
- Outputs include source metric/fact provenance, artifact version, and execution diagnostics.
- Candidate artifacts are not auto-activated; they produce review packets first.
