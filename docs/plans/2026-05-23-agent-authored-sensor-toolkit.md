# Agent-Authored Sensor Toolkit / Reflex Workbench

**Created:** 2026-05-23
**Status:** Proposed

## Purpose

Do not hand-author deterministic findings and signatures for every process, runtime, service, or failure mode. Descartes needs a toolkit that lets a background LLM agent build, test, review, and promote its own deterministic tools, sensors, monitors, triggers, alarms, and statistical models.

The target is closer to a Casbin-style policy/evaluation engine plus a Prolog/Datalog-like fact/rule substrate than a growing pile of bespoke JavaScript `if` statements.

## Core Idea

Collectors produce structured evidence envelopes. A fact bridge reifies that evidence into typed facts. The agent authors declarative artifacts over those facts:

- logic rules / signatures over current evidence
- sensors over current or recent fact windows
- triggers and alarms with severity/confidence/review hints
- statistical feature definitions and baseline/anomaly/classification models
- tests, fixtures, and promotion metadata

The runtime executes these artifacts deterministically and cheaply. The LLM is used to create, explain, audit, and improve artifacts, not as the source of operational truth.

## Architecture Sketch

```text
L0 collectors
  -> evidence envelopes
  -> fact bridge / typed fact catalog
  -> logic engine (safe Prolog/Datalog-like rules)
  -> statistical model engine (features, baselines, classifiers)
  -> findings / triggers / alarms / recommendations
  -> agent workbench for proposal, tests, evaluation, promotion
```

## Artifact Types

### Fact schema

Defines stable relation names and fields derived from evidence envelopes, with provenance back to collector IDs and trace metadata.

Examples:

```prolog
process(Pid, Command, CpuPct, MemPct, RssBytes).
service(Unit, LoadState, ActiveState, SubState).
certificate(Source, Subject, NotAfter, DaysRemaining, OperationalRelevance).
container(Runtime, Name, Image, State).
vm(Runtime, Name, State).
```

### Logic rule / signature

Declarative, bounded, non-mutating rule over facts. Prefer a safe Datalog/stratified-Prolog subset for termination and auditability.

Includes:

- name and version
- required fact schemas
- rule text
- output finding/trigger schema
- severity/confidence mapping
- privacy notes
- positive/negative fixtures
- provenance and review history

### Statistical model artifact

A constrained model definition, not arbitrary code.

Includes:

- feature definitions over facts/time windows
- model family: threshold, EWMA, linear regression, logistic/classifier, clustering, anomaly score, etc.
- training window and inclusion/exclusion policy
- validation metrics
- drift/decay behavior
- output facts, such as `anomaly(metric, window, score, confidence)`
- fixtures and replay evaluations

### Sensor / trigger

Connects rule/model outputs to monitoring behavior:

- schedule/window
- debounce/flapping rules
- severity
- deduplication key
- notification policy target
- escalation criteria to L2 deliberative agent

## Background Agent Toolkit

The background LLM agent should receive tools for building tools, not host mutation:

- inspect fact catalog and example facts
- propose fact schema additions from collector envelopes
- author logic rules in the safe rule language
- author statistical feature/model definitions from approved model families
- generate synthetic fixtures and scrubbed regression fixtures
- run rule/model evaluation in a sandbox
- explain proofs and feature contributions
- compare candidate output against fixtures and previous artifacts
- lint for termination, privacy, bounds, and provenance
- open a candidate artifact for human review/promotion

## Promotion Gates

Artifacts move through explicit lifecycle states:

1. draft
2. test-only
3. shadow mode on live evidence
4. review-approved
5. active
6. deprecated/retired

Promotion requires:

- no host mutation
- bounded runtime and output
- allowed fact schemas only
- tests and fixtures
- privacy review
- explainability/provenance
- human approval until a later policy plane explicitly allows narrow autonomous promotion

## Initial Milestones

### Milestone 1: Fact bridge and tiny rule runner

- Define a minimal fact schema for existing system/process/disk/service/cert/time evidence.
- Convert existing evidence envelopes into facts with provenance.
- Add a safe rule-runner prototype with fixtures.
- Seed only 2-3 example rules to validate the substrate, not to build a full hand-authored rule library.

### Milestone 2: Agent workbench commands

- Let an agent inspect facts, propose a rule, generate fixtures, run evaluation, and produce a review packet.
- Keep outputs as candidate artifacts; do not auto-activate.

### Milestone 3: Statistical model artifact prototype

- Add simple feature definitions and approved model families such as threshold, EWMA, and linear/logistic models.
- Generate model-output facts that logic rules can consume.

### Milestone 4: Shadow-mode sensors

- Run selected candidate sensors against collected evidence without notifying or acting.
- Record false positives/negatives and confidence decay.

## Non-Goals For This Plan

- No arbitrary generated code execution.
- No mutating host actions.
- No attempt to enumerate all known process signatures manually.
- No autonomous artifact activation before policy/authority machinery exists.

## Open Design Questions

- Exact rule engine: embedded Prolog, Datalog, Datafrog, Soufflé-style offline compile, or a custom restricted rule DSL.
- Whether logic and statistical artifacts share one syntax or separate schemas.
- How much historical fact storage is required for useful baselines before a daemon exists.
- How to package artifacts for future Rust/Bazel-friendly execution while the current harness remains Node/Pi.
