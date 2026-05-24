# Descartes Use-Case Library

This directory captures concrete future user-value examples for Descartes. These are **not implementation commitments**; they are product/architecture specimens that help evaluate whether collectors, history, rules, policy, privacy, and operator surfaces are pointing at useful operational behavior.

Use cases should stay specific enough to expose real requirements. Prefer:

- concrete machine/operator situations over generic assistant demos
- required vs optional capabilities/data sources/surfaces
- local-first evidence and explainability notes
- clear policy/authority gates for any interruptive or mutating behavior
- explicit false-positive and privacy boundaries

## Directory layout

```text
docs/use-cases/
  README.md
  examples/
    *.md
```

## Front matter schema

Each example starts with YAML front matter. Suggested fields:

```yaml
---
title: "Short descriptive title"
status: example
priority: p1
product_area: security | operations | maintenance | intent-ops | history | policy
summary: "One-sentence value proposition."
required_capabilities:
  - daemon_history
  - process_identity
required_data_sources:
  - process_table_snapshots
  - filesystem_activity_events
required_surfaces:
  - cli_status
  - proactive_notification
optional_improvements:
  capabilities: []
  data_sources: []
  surfaces: []
privacy:
  raw_data_boundary: "Raw evidence stays local unless explicitly included in a triage request."
  user_controls:
    - explain_why
    - delete_history
    - disable_detector
policy:
  interruption_threshold: "Only interrupt when evidence is actionable and confidence is high."
  action_authority: "recommend-only by default; mutating action requires explicit approval."
related_docs:
  - docs/plans/2026-05-23-daemon-history-store.md
---
```

## Evaluation questions

For each example, ask:

1. What useful thing can Descartes do that a generic LLM or stats dump would miss?
2. Which facts are deterministic local evidence, and which conclusions are derived rules/baselines?
3. What evidence would make the diagnosis or alert defensible?
4. What false positives would be dangerous or annoying?
5. What privacy boundary, correction surface, and policy gate are required before shipping it?
