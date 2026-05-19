# Descartes

Descartes is a Rust project for an AI-native operations agent: a maintenance agent, sysadmin assistant, and system operations gateway for computers.

It is named after the computer running the literal Blood Bank on the Moon in Philip Kerr's *The Second Angel*. The project goal is similarly operational: help keep machines alive, understandable, and manageable — whether they are headless servers, VM hosts, ephemeral VMs, developer machines, or future embedded/edge systems.

## Vision

Descartes should observe a machine, notify its user about meaningful events, diagnose problems from evidence, recommend remediations, and eventually act on the user's behalf under explicit guardrails.

The intended progression is:

```text
Observe → Notify → Diagnose → Recommend → Plan → Act → Learn
```

The important bit: Descartes should not start as a free-roaming autonomous root shell. It starts as a local-first, read-only, evidence-grounded observer. Autonomy comes later, behind policy, audit trails, and reversible action plans.

## Core Idea

Most routine operations work does not require a model to hallucinate wisdom. It requires good local facts, boring checks, signatures, baselines, and escalation when the boring machinery is not enough.

Descartes is therefore designed as a layered system:

| Layer | Purpose |
|---|---|
| **L0 Deterministic System Tools** | Gather factual evidence from logs, processes, services, disks, network, packages, containers, VMs, and platform APIs. |
| **L1 Monitoring / Rules / Signatures** | Detect thresholds, repeated failures, anomalies, drift, known issue patterns, and notification-worthy events. |
| **L2 Deliberative Agents** | Escalated diagnosis, incident correlation, explanation, recommendations, and tool/signature improvement proposals. |
| **L3 Federated Knowledge** | Optional future sharing of anonymized signatures, playbooks, incident fingerprints, and outcomes. |
| **Policy / Authority Plane** | Permissioning, approvals, action plans, audit logs, and autonomy boundaries. |

The model is a router, narrator, auditor, planner, and learning layer. It is not the source of truth. The source of truth is structured evidence from local tools.

## First External Slice

The current first slice is an installable, read-only, LLM-backed local triage CLI.

End-user install from GitHub, without cloning the repository (requires Node.js/npm 20.6+):

```bash
npm install -g github:Lightless-Labs/descartes
```

HTTPS tarball form if preferred:

```bash
npm install -g https://github.com/Lightless-Labs/descartes/tarball/main
```

Then run:

```bash
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
```

For subscription logins, Descartes picks a strong default rather than the provider registry's first model: highest available `openai-codex` GPT model by semantic version, or highest available Anthropic Sonnet. It uses high reasoning when available. You can override model selection:

```bash
descartes triage "my machine is slow" --model openai-codex/gpt-5.5 --thinking high
```

Descartes uses deterministic local tools to collect evidence for CPU/load, memory/swap, disks/inodes, and top processes. An LLM-backed private agent session interprets the user's complaint, decides which Descartes evidence tools to call, and produces an evidence-cited diagnosis with safe next checks.

Safety and privacy boundaries for v0:

- local evidence collection is read-only
- no host actions are taken
- no telemetry, background upload, or federation
- explicit triage requests may send collected evidence to the selected LLM provider
- saved reports/session state are sensitive diagnostic artifacts
- Descartes-owned config/state follows XDG paths such as `$XDG_CONFIG_HOME/descartes`
- Descartes may use an internal Pi SDK harness, but it must not require, read, import, reuse, or modify the user's personal Pi setup (`~/.pi`, project `.pi`, Pi sessions, settings, auth, skills, prompts, themes, or model config)

The initial scaffold lives under `tools/descartes-cli/`.

Later, once policy and audit foundations exist:

```bash
descartes plan fix postgres-restart-loop
descartes apply plan-123
```

## Evidence Envelopes

Tools should return structured evidence, not unstructured prose. A rough envelope:

```json
{
  "status": "ok | warning | critical | unknown | needs_input | unable",
  "layer": "L0",
  "source": "systemd | journal | procfs | sysfs | filesystem | network | package_manager | container | vm",
  "result": {},
  "confidence": 1.0,
  "review_hint": "none | threshold_crossed | repeated_failure | novel_pattern | missing_permission | ambiguous | out_of_range",
  "trace": {
    "tool": "inspect_systemd_unit",
    "target": "postgres.service",
    "latency_ms": 18,
    "ts": "2026-05-18T00:00:00Z"
  }
}
```

This makes later diagnosis, replay, testing, auditing, and signature extraction much easier.

## Safety Model

Descartes should be safe by construction:

- read-only by default
- local-first evidence collection
- explicit user opt-in for telemetry or federation
- no mutating action without a policy decision
- clear distinction between recommendations, plans, and executed actions
- audit log for every proposed and executed action
- prefer reversible, narrowly scoped, pre-tested actions
- compile confirmed learning back into deterministic rules/signatures where possible

## Implementation

Descartes will be written in Rust.

Early implementation priorities:

1. crate/workspace scaffold
2. typed evidence envelope
3. local system probes
4. CLI report path
5. rule/signature engine
6. local event store
7. notification abstraction
8. diagnosis and recommendation layer
9. policy-gated action planning

The wider Lightless Labs monorepo prefers Bazel. If Cargo is used initially, the project should remain Bazel-friendly: explicit manifests, reproducible tests, no hidden generation steps, and a clean crate graph.

## Repository Status

This repository is currently at the concept/scaffolding stage. See `AGENTS.md` for operating instructions for coding agents working on the project.
