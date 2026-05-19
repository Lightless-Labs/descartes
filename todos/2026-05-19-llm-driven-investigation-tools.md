---
title: LLM-Driven Investigation Tools for Descartes Triage
created: 2026-05-19
status: open
priority: immediate
area: triage
kind: todo
owner: unassigned
---

# TODO: LLM-Driven Investigation Tools for Descartes Triage

## Summary

The current CLI path is stable but not yet the intended Descartes product loop.

Current behavior:

1. Descartes precollects a fixed first-slice evidence bundle.
2. It sends a compact evidence summary to the selected LLM.
3. The LLM performs a no-tool synthesis turn.

This gets an answer, but it is not enough. The point of Descartes is an LLM-backed local triage flow where the model can investigate by asking Descartes read-only tools for more evidence, while deterministic code remains the source of facts.

## Immediate Goal

Re-enable LLM-driven investigation with a safe, explicit tool surface:

- keep precollection as a guaranteed baseline
- provide the LLM with only Descartes read-only evidence tools
- do not expose Pi coding tools or arbitrary shell
- make tool availability and tool usage observable in JSON output
- keep fallback behavior, but treat fallback as degraded mode, not success

## Current Problem / Context

Earlier versions attempted an LLM tool-calling path but failed in practice:

- the model sometimes returned no final text
- in one version, evidence/tools were empty because no tools were called
- raw evidence sent to the model became too large/noisy
- provider/model selection also caused errors until fixed

The current no-tool synthesis path is a stabilizing bridge. The next iteration should restore the intended investigation loop carefully.

## Required Safety Boundaries

Allowed:

- Descartes-owned read-only evidence tools
- deterministic local collectors
- provider/network calls only for explicit `descartes triage ...`
- optional web/search tools only when explicitly designed as read-only information sources

Forbidden in v0 investigation:

- arbitrary shell
- Pi built-in coding tools (`bash`, `read`, `write`, `edit`, etc.)
- mutating host actions
- reading/importing/modifying user Pi setup
- background telemetry/federation
- unbounded local file/log exfiltration

## Near-Term Implementation Tasks

1. Add a two-phase triage flow:
   - Phase A: deterministic precollection and compact summary
   - Phase B: LLM synthesis with optional Descartes read-only tools enabled
2. Keep the prompt explicit:
   - facts come only from provided evidence or Descartes tools
   - no arbitrary commands
   - cite evidence IDs/tool traces
   - no actions were taken
3. Add JSON diagnostics:
   - selected provider/model/thinking level
   - active tool names
   - tool calls attempted
   - tool call results/errors
   - assistant stop reason / provider error when present
   - whether fallback was used
4. Add tests for active tools:
   - active tool names are exactly Descartes evidence tools when investigation is enabled
   - no Pi built-in tools are enabled
   - no arbitrary shell tool is available
5. Add tests for degraded behavior:
   - if no LLM text, fallback includes evidence and `llm_error` when available
   - fallback is clearly marked as fallback
6. Improve evidence compaction:
   - keep full evidence in JSON output
   - send compact evidence to the LLM
   - truncate long command lines and noisy mount lists in prompt context
7. Decide whether tool-calling should be default-on after validation, or hidden behind a temporary debug flag for one release.

## Initial Investigation Tool Set

Start with existing tools:

- `collect_system`
- `collect_processes`
- `collect_disks`
- `collect_triage_evidence`
- `derive_findings`

Potentially add next:

- `collect_network_basics`
- `collect_services` / `collect_launchd` / `collect_systemd`
- `collect_recent_logs` with strict limits and local-only privacy notes
- `inspect_process` for a specific PID/process name
- `inspect_parent_tree` for process ancestry
- `collect_containers` for Docker/Colima/Lima/Podman where available
- `collect_scheduled_jobs`
- `collect_certificates`
- `collect_time_sync`

## Closer-Future Web/Search Tools

Descartes should eventually be able to look up unknown programs, process names, error messages, or documentation via read-only web/search tools.

Possible sources:

- general web search
- Google/custom search
- Linkup
- Perplexity
- Context7
- DeepWiki
- vendor docs
- package registries / Homebrew / npm / crates.io / GitHub metadata

Design options:

1. User-provided search provider credentials.
2. A Lightless Labs proxy that performs search/retrieval.
3. Both, with the proxy optional.

If Lightless Labs provides a proxy, it can:

- cache by exact key
- cache semantically / by semantic proximity
- normalize process/package/docs metadata
- rate-limit and deduplicate external calls
- feed curated findings into a future process knowledge database

Privacy constraints:

- no raw logs or private paths by default
- query shaping should minimize sensitive local identifiers
- user should understand when external web/search is used
- web/search should remain explicit read-only investigation, not telemetry

## Future One Day: Federated Process Knowledge Database

Longer term, Descartes could maintain or contribute to a shared/federated database of processes and operational behavior.

Potential contents:

- process names and common executable paths
- what the process is for
- common parent/child process relationships
- normal CPU/memory/network/disk behavior patterns
- expected launch contexts
- package/application ownership
- known problematic versions
- known issue signatures
- safe investigation steps
- unsafe/remediation caveats
- links to authoritative docs

Examples:

- `WindowServer` on macOS: expected GUI compositor process; CPU spikes may correlate with external displays, screen recording, GPU-heavy apps.
- `dolt sql-server`: Dolt database server; high CPU may indicate active query, indexing, import, replication, or pathological query workload.
- simulator runtime mounts: often read-only/full by design and should not be reported as root disk pressure.

Federation/privacy defaults:

- no raw logs
- no usernames
- no full private paths
- no hostnames
- no stable host/user identifiers
- prefer local hashing/bucketing only with a clear threat model
- opt-in only

## Acceptance Criteria for This TODO

This TODO is complete when:

- LLM triage can ask at least the first-slice Descartes tools for more evidence.
- JSON output shows selected model, active tools, tool calls, and tool errors.
- Built-in Pi coding tools are demonstrably unavailable.
- The model produces a diagnosis from evidence on at least one real laptop using Anthropic and/or Codex subscription auth.
- Fallback remains available but is clearly degraded mode.
