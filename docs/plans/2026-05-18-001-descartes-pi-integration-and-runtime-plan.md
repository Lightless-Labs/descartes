# Descartes Pi Integration and Runtime Plan

**Created:** 2026-05-18  
**Corrected:** 2026-05-18 — Descartes should use agentic reasoning to build and refine L0/L1 as it goes, not wait until a complete Rust substrate exists before L2 exists.  
**Deferred:** 2026-05-18 — this is broader product direction, not the current first implementation slice. Start with `docs/plans/2026-05-18-003-first-external-slice-local-triage.md`.

## Decision

Use Pi early as a **bootstrap/workbench agent runtime** for Descartes, while keeping Descartes' durable operational substrate Rust-first.

The key correction: Descartes is not merely a Rust monitoring daemon that later receives an L2 reasoning adapter. Descartes should be the system that observes gaps, proposes new L0 probes and L1 rules/signatures, writes or updates them, tests them, and promotes them under policy.

Short version:

1. **Descartes learns by compiling experience downward.** New incidents should produce candidate probes, parsers, rules, signatures, playbooks, and tests.
2. **Pi can drive the bootstrap loop from day one.** Use Pi as the early agent harness for the builder/auditor loop, not only as a late optional diagnostician.
3. **Rust remains the durable execution substrate.** L0/L1 artifacts that Descartes learns should become Rust code, data files, rules, fixtures, tests, or signed signatures — not opaque chat history.
4. **Use adapters, not a fork.** Integrate Pi through SDK/RPC/extension surfaces where useful. Do not fork Pi as the product runtime unless later evidence forces it.
5. **Semport patterns selectively.** Track useful upstream agent-runtime ideas and port the semantics into Descartes-native Rust when they become durable product concepts.

## Core Product Loop

Descartes should continuously move knowledge down the stack:

```text
Observe machine state
  → detect known facts/events with current L0/L1
  → escalate novelty/ambiguity/high-impact cases
  → diagnose/recommend from evidence
  → identify missing probe/rule/signature/test
  → generate candidate artifact
  → validate against fixtures/history/sandbox
  → require review/policy promotion
  → compile into cheaper L0/L1 machinery
```

This is the central design principle:

> Reasoning is not the product endpoint. Reasoning is how Descartes manufactures better reflexes.

## Architecture Position

```text
Descartes Rust substrate
  ├─ L0 probes and evidence envelopes
  ├─ L1 rules, signatures, baselines, notifications
  ├─ local event/incident store
  ├─ candidate artifact store
  ├─ replay/validation harness
  ├─ policy and authority engine
  ├─ action-plan model
  └─ agent workbench adapters
        ├─ Pi SDK workbench        early/dev bootstrap
        ├─ Pi RPC adapter          Rust subprocess integration
        ├─ Pi extension bridge     dogfooding in Pi sessions
        ├─ local model adapter     future
        └─ no-agent mode           baseline deterministic operation
```

The important boundary is not "Pi later". The boundary is:

- Pi/LLMs may propose, edit, narrate, audit, and plan.
- Rust L0/L1 artifacts provide durable system facts and repeatable behavior.
- Promotion from candidate to active rule/tool/signature requires tests and policy.

## Integration Options Considered

### Option A — Pi SDK workbench

Use `@earendil-works/pi-coding-agent` from a small Node/TypeScript workbench that can run agent sessions, register Descartes tools, observe events, and manage candidate artifacts.

Pros:

- fastest route to a real Descartes builder loop
- direct access to Pi sessions, tools, events, extensions, and custom prompts
- good for development-time self-improvement workflows
- can orchestrate Rust CLI commands and file edits while Descartes is still small

Cons:

- TypeScript/Node dependency for the workbench
- should not become required for headless/minimal host operation
- risks coupling product semantics to Pi if boundaries are sloppy

Verdict: **Use early as a workbench, not as the shipped core daemon.**

### Option B — Pi RPC adapter

Rust spawns `pi --mode rpc --no-session`, sends JSONL commands, and consumes JSONL events.

Pros:

- clean Rust-to-agent boundary
- process isolation
- good future path for headless Descartes invoking Pi as an optional L2 backend
- avoids linking TypeScript SDK into Rust packages

Cons:

- weaker typing than SDK
- requires robust subprocess supervision and strict JSONL framing
- less convenient than SDK for rich workbench behavior

Verdict: **Use after the first workbench shape exists, especially for Rust-owned runtime integration.**

### Option C — Pi extension bridge

Expose Descartes commands and probes inside Pi as project-local extension tools.

Pros:

- excellent dogfooding loop inside the current Pi environment
- lets Pi call `descartes status --json`, inspect evidence, and propose artifacts
- useful for interactive development and demos

Cons:

- TypeScript extension code
- should remain bridge/dev UX, not product core

Verdict: **Build once the first Rust CLI commands exist.**

### Option D — Ongoing fork of Pi

Fork Pi and evolve it into Descartes.

Pros:

- maximum control over the harness

Cons:

- high maintenance burden
- wrong default language/runtime for Descartes core
- upstream merge pain
- product identity confusion

Verdict: **Avoid.** Reconsider only if Pi becomes indispensable and extension/SDK/RPC surfaces cannot support required changes.

### Option E — Semport selected Pi concepts into Rust

Continuously inspect Pi and other trusted agent runtimes for useful concepts, then re-express selected semantics in Rust.

Pros:

- keeps Descartes Rust-native
- lets the project benefit from upstream agent-runtime design
- avoids copying incidental complexity
- aligns with Descartes' own learning loop

Cons:

- requires a tracking/review discipline
- easy to over-port concepts before Descartes needs them

Verdict: **Use as the long-term strategy for durable runtime concepts.**

## Recommended Path

### Phase 0 — Define the self-building contract

Before much implementation, define the artifact lifecycle:

```text
observed gap
  → candidate artifact
  → generated tests/fixtures
  → replay/validation
  → human or policy review
  → active artifact
  → monitored outcome
```

Candidate artifact types:

- L0 probe
- parser
- evidence schema extension
- L1 rule
- signature
- baseline/anomaly check
- diagnostic playbook
- recommendation template
- notification policy
- regression fixture

Promotion requirements:

- every artifact has provenance
- every artifact has tests or replay evidence
- every artifact has a scope and rollback path
- mutating actions remain policy-gated

### Phase 1 — Minimal Rust kernel plus artifact model

Build just enough Rust substrate for Descartes to have something to improve:

- Cargo workspace
- `descartes-core` with evidence envelope, trace, event, incident, artifact, and promotion-status types
- `descartes-cli` with `status --json` stub and `artifacts` commands
- local artifact store, initially filesystem/JSONL or SQLite
- validation harness skeleton

This is not a full monitoring daemon yet. It is the seed crystal Descartes can grow.

### Phase 2 — Pi SDK workbench for the builder loop

Create an optional workbench package, likely under `tools/pi-workbench/`, that uses the Pi SDK to run Descartes-building sessions.

Responsibilities:

- load Descartes-specific system prompt/context
- register tools that call the Rust CLI
- register tools for candidate artifact creation/update
- register tools for running tests/replay validation
- capture Pi session events and link them to artifact provenance
- enforce that generated L0/L1 candidates start inactive

Initial workbench commands:

- inspect current Descartes status
- propose missing probe/rule/signature
- create candidate artifact
- generate fixture/test
- run validation
- summarize promotion readiness

### Phase 3 — First self-built L0 probes

Use the workbench to help implement and validate initial probes:

- OS/kernel/uptime
- memory/load
- disks/mounts
- process summary

Each probe should include:

- Rust implementation
- typed evidence result
- fixture or platform-guarded test
- status/report integration
- trace metadata

### Phase 4 — First self-built L1 rules/signatures

Use the same loop for rules:

- disk pressure
- memory pressure
- high load
- probe unavailable/missing permission
- simple service failure where supported

Each rule should include:

- inputs it consumes
- deterministic output
- severity
- notification hint
- recommendation text or next-check playbook
- tests against fixture evidence

### Phase 5 — Pi extension bridge

Once `descartes status --json` and artifact commands exist, add a project-local Pi extension bridge.

Purpose:

- let a Pi session call Descartes probes as tools
- let Descartes workbench behavior be used interactively
- dogfood the "agent builds better lower layers" workflow

Keep this optional and clearly outside the core product path.

### Phase 6 — Rust-owned Pi RPC adapter

After the builder loop exists, add a Rust Pi RPC adapter for headless/runtime usage.

Responsibilities:

- strict JSONL framing
- subprocess lifecycle supervision
- timeout/cancellation
- privacy filtering before sending packets
- structured prompts for incident analysis and artifact proposals
- structured outputs where possible

This adapter lets a running Descartes daemon escalate novelty to Pi without embedding Node in the daemon.

### Phase 7 — Semport ledger

Maintain a lightweight design ledger for upstream concepts worth semporting.

Candidate Pi concepts:

- session event stream shapes
- tool lifecycle events
- tool result truncation
- permission-gate hooks
- session branching/forking
- compaction/summarization
- extension/plugin boundaries
- RPC protocol design

Rules:

- semport semantics, not whole files
- write Descartes-native tests before adopting a pattern
- reject coding-agent-specific assumptions unless operations use cases need them
- do not fork Pi by default

## Near-Term Milestones

### Milestone 1 — Seed Rust workspace

Deliverables:

- Cargo workspace
- `descartes-core` evidence/event/artifact types
- `descartes-cli` with `status --json` stub
- artifact store skeleton
- validation harness skeleton
- fmt/test/clippy documented and passing

### Milestone 2 — Pi SDK workbench spike

Deliverables:

- optional `tools/pi-workbench/` package
- Pi SDK session creation
- Descartes-specific system prompt
- tool that runs `descartes status --json`
- tool that writes an inactive candidate artifact
- tool that runs validation
- no product runtime dependency on the workbench

### Milestone 3 — First probe grown through the loop

Deliverables:

- one real L0 probe implemented in Rust
- candidate/provenance record showing the workbench loop
- tests/fixtures
- promotion from candidate to active
- CLI output using the probe

### Milestone 4 — First rule grown through the loop

Deliverables:

- one L1 rule implemented in Rust or data config
- fixture evidence
- deterministic notification/recommendation result
- promotion record
- replay test

### Milestone 5 — Bridge and runtime adapter decision

Deliverables:

- decide whether Pi extension bridge or Rust RPC adapter is next based on actual workflow pain
- document observed coupling risks
- update plan with evidence

## Safety Invariants

- Generated probes/rules/signatures start inactive.
- Promotion requires tests/replay evidence and explicit review or policy.
- L0/L1 active artifacts must be inspectable and deterministic where feasible.
- No mutating host action is generated or executed without policy gates.
- Raw logs, usernames, hostnames, paths, IPs, and secrets must not leave the host without explicit privacy mode approval.
- Agent reasoning must link back to evidence trace IDs.
- Every self-improvement artifact has provenance and rollback notes.

## Open Questions

- Should candidate artifacts be stored as files, SQLite rows, or both?
- Should rules be Rust code, RON/TOML/YAML data, or a small DSL?
- What is the minimum fixture format for replaying evidence packets?
- How do we sign/promote active signatures later?
- What is the first privacy profile for Pi-backed reasoning?
- How much of the Pi workbench should be committed versus kept as local tooling?

## Non-Goals For Now

- autonomous remediation
- root/system mutation
- federated signature sharing
- permanent dependency on Pi for core operation
- ongoing fork of Pi
- unreviewed promotion of generated code/rules

## Final Recommendation

Use Pi now to bootstrap Descartes' self-building loop. Let Descartes generate and validate its own L0 probes and L1 rules/signatures as candidate artifacts, then promote them into a Rust-first substrate under tests and policy. Do not wait for a complete Rust monitor before introducing the agentic layer; the agentic layer is how the lower layers grow.
