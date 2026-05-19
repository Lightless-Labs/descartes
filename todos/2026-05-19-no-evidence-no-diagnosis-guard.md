---
title: No Evidence, No Diagnosis Guard
created: 2026-05-19
status: completed
priority: high
area: triage
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
  - todos/2026-05-19-first-external-slice-validation.md
---

# TODO: No Evidence, No Diagnosis Guard

**Completed:** 2026-05-19 — added an evidence guard for normal model-led triage: unsupported no-evidence assistant text triggers one explicit evidence-tool retry, then deterministic precollection fallback with JSON diagnostics if evidence is still absent. Package metadata bumped to v0.0.15.

## Summary

Normal `descartes triage` is model-led: the model must request local facts through guarded Descartes evidence tools instead of receiving unconditional precollected evidence. Add a runtime guard so normal investigation cannot silently succeed without evidence.

## Desired Behavior

When `investigation_enabled: true`:

- If the assistant returns a diagnosis with no tool calls and no collected evidence, do not accept it as a normal diagnosis.
- Prefer one retry with an explicit instruction to call `collect_triage_evidence` or relevant targeted tools before diagnosing.
- If retry still produces no evidence, fall back to deterministic precollection and mark the result as degraded/fallback.
- JSON diagnostics should expose the guard outcome, retry count, and fallback reason.

## Rationale

This preserves the product contract:

- models may decide what to inspect and synthesize explanations
- local system facts must come from auditable Descartes tools
- normal triage should not degrade into an unsupported freeform model answer

## Acceptance Criteria

- Test coverage for no-tool/no-evidence assistant output.
- Test coverage for retry or degraded fallback diagnostics.
- Human output remains explicit that no actions were taken.
- JSON output includes evidence/tool traces when fallback precollection is used.
