---
title: LLM-Driven Investigation Tool Loop for Descartes Triage
created: 2026-05-19
status: completed
priority: immediate
area: triage
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-expand-local-investigation-tools.md
---

# TODO: LLM-Driven Investigation Tool Loop for Descartes Triage

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
- provide the LLM with only existing Descartes read-only evidence tools
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

Forbidden in v0 investigation:

- arbitrary shell
- Pi built-in coding tools (`bash`, `read`, `write`, `edit`, etc.)
- mutating host actions
- reading/importing/modifying user Pi setup
- background telemetry/federation
- unbounded local file/log exfiltration

## Existing Tool Set To Re-Expose

Start only with tools that already exist:

- `collect_system`
- `collect_processes`
- `collect_disks`
- `collect_triage_evidence`
- `derive_findings`

New local tools belong in `todos/2026-05-19-expand-local-investigation-tools.md`, not in this todo.

## Implementation Tasks

1. Add a two-phase triage flow:
   - Phase A: deterministic precollection and compact summary
   - Phase B: LLM synthesis with Descartes read-only tools enabled
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
   - active tool names are exactly existing Descartes evidence tools when investigation is enabled
   - no Pi built-in tools are enabled
   - no arbitrary shell tool is available
5. Add tests for degraded behavior:
   - if no LLM text, fallback includes evidence and `llm_error` when available
   - fallback is clearly marked as fallback
6. Preserve compact prompting:
   - keep full evidence in JSON output
   - send compact evidence to the LLM
   - truncate long command lines and noisy mount lists in prompt context
7. Decide whether tool-calling should be default-on after validation, or hidden behind a temporary debug flag for one release.

## Progress

2026-05-19:

- Implemented default-on tool-enabled investigation while keeping deterministic precollection.
- Added temporary `--no-investigate` escape hatch for the prior no-tool synthesis flow.
- Added explicit triage tool policy and runtime guard for exactly the existing Descartes read-only tools.
- Added JSON diagnostics for selected model metadata, thinking level, active tools, tool calls/results/errors, assistant stop reason, LLM error, and fallback state.
- Added tests for tool policy, diagnostics, and fallback degraded-mode marking.
- Validated end-to-end on a real macOS laptop with Anthropic Sonnet subscription auth: active tools were exactly the guarded Descartes tool set, the model called `collect_disks`, returned non-fallback diagnosis text, and JSON diagnostics/evidence/tool traces were populated.

## Completed

Completed 2026-05-19. Follow-up release-readiness work moved to `todos/2026-05-19-first-external-slice-validation.md`. New collector expansion remains in `todos/2026-05-19-expand-local-investigation-tools.md`.

## Acceptance Criteria

This TODO is complete when:

- LLM triage can ask at least the existing first-slice Descartes tools for more evidence.
- JSON output shows selected model, active tools, tool calls, and tool errors.
- Built-in Pi coding tools are demonstrably unavailable.
- The model produces a diagnosis from evidence on at least one real laptop using Anthropic and/or Codex subscription auth.
- Fallback remains available but is clearly degraded mode.
