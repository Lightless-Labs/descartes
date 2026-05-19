---
title: Temporal Sampling Investigation Tools
created: 2026-05-19
status: open
priority: high
area: collectors
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-expand-local-investigation-tools.md
  - todos/2026-05-19-llm-driven-investigation-tools.md
---

# TODO: Temporal Sampling Investigation Tools

## Summary

Some operational facts require watching a dimension over time, not just taking one snapshot. Descartes should expose bounded, read-only temporal sampling tools that the LLM can request during triage.

Example: if CPU is high, the LLM may ask Descartes to sample top CPU processes every 2 seconds for 30 seconds, then return aggregate statistics.

## Goals

- Let the LLM choose a sampling dimension and duration within strict policy limits.
- Return aggregated results suitable for diagnosis.
- Optionally persist larger sample series to a Descartes-owned temp/cache file and return a path/reference for dedicated read/grep-style analysis tools.
- Keep all sampling read-only, bounded, auditable, and cancellable.

## Candidate Tool Shapes

### `sample_dimension`

Inputs:

- `dimension`: enum, for example:
  - `cpu_processes`
  - `memory_processes`
  - `load_memory_swap`
  - `disk_io` later
  - `network_io` later
  - `process:<pid>` later
- `duration_seconds`: number, capped by policy
- `interval_seconds`: number, capped/minimum by policy
- `top_n`: optional number for process dimensions
- `aggregation`: optional enum (`summary`, `timeseries`, `summary_and_timeseries_ref`)

Outputs:

- evidence envelope with:
  - sample count
  - elapsed time
  - min/max/mean/p95 where applicable
  - top contributors by average and peak
  - stability/flapping notes where deterministic
  - trace with requested duration, actual duration, and sampling interval

### `read_sampling_artifact`

Inputs:

- Descartes-owned artifact id/path returned by `sample_dimension`
- optional filter/query parameters

Outputs:

- bounded excerpt or derived aggregate from the stored sample series

This should not be a general file read tool. It should only read Descartes-owned sampling artifacts.

## Upper Limits / Policy

Initial suggested limits:

- max duration: 60 seconds
- min interval: 1 second
- max samples: 120
- max top processes per sample: 20
- max artifact size: bounded, e.g. 1–5 MB
- artifact lifetime: short-lived cache/state with clear cleanup behavior

The LLM may request lower values, but the tool must clamp or reject values above policy.

## Storage

If raw time series is too large for direct tool return:

- write JSONL or compact JSON to Descartes-owned cache/state/temp path
- return an artifact id and path/reference
- include sensitivity warning in the evidence envelope
- ensure path is under Descartes-owned XDG cache/state, not arbitrary temp or Pi-owned paths

## Safety / Privacy

- read-only only
- no arbitrary shell
- no unbounded monitoring
- no daemon/background persistence in v0
- explicit user-requested triage session only
- samples may contain process names, command lines, paths, and usernames; treat artifacts as sensitive diagnostic data

## Acceptance Criteria

This todo is complete when Descartes has at least one bounded temporal sampler for CPU/process or load/memory/swap pressure, with tests for clamping, aggregation, artifact writing, and Descartes-owned artifact paths.
