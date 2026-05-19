# Descartes

## What it does

Descartes is a local-first operations triage CLI. Today it can answer questions like `descartes triage "my machine is slow"` by collecting read-only local evidence about CPU/load, memory/swap, disks/inodes, and top processes, then asking an LLM-backed private agent session to produce an evidence-cited diagnosis and safe next checks. No host actions are taken.

## Where it's going

Descartes is intended to become a stratified machine operations and defense agent: deterministic local tools and rules first, real-time behavior detection, an adaptive decision layer for ambiguity and tradeoffs, LLM-assisted diagnosis and planning when useful, a self-improvement loop that compiles confirmed learnings into cheaper probes/rules/signatures/tests, and eventually policy-gated actions with audit trails. The long-term goal is to recognize novel harmful behavior as it emerges — for example ransomware-like file activity or trojan-like persistence/network behavior — and interrupt it within explicit policy boundaries. It should also support intent-based operations: for example, if a user says “I need a quick Linux environment with npm”, Descartes should discover whether Docker, Colima, Podman, Tart, Lima, UTM, Multipass, Buildkite, another local option, or an authenticated remote/CI agent is available, recommend a plan, ask for scoped approval, execute or delegate only within that approval, verify the result, and clean up. The durable core is expected to move toward Rust, while the current first external slice is a Node.js/JavaScript CLI so it can ship quickly with the embedded Pi SDK agent harness and subscription login flow.

See `docs/ROADMAP.md` for the capability roadmap and policy-gated action direction.

## How to get started

Requires Node.js 22.19.0+ plus a writable npm global prefix:

```bash
npm install -g github:Lightless-Labs/descartes
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
```

Descartes may use Pi internally as a private harness, but it does not require, read, import, or modify the user's personal Pi setup.

It is named after the computer running the literal Blood Bank on the Moon in Philip Kerr's *The Second Angel*. The project is also inspired by the layered autonomic systems of lighthuggers in Alastair Reynolds' *Revelation Space* / *Absolution Gap*: machines with stratified reflexes, diagnostics, and higher-level reasoning rather than a single monolithic intelligence. The project goal is similarly operational: help keep machines alive, understandable, and manageable — whether they are headless servers, VM hosts, ephemeral VMs, developer machines, or future embedded/edge systems.

## Vision

Descartes should observe a machine, detect meaningful operational and security behavior in real time, notify its user, diagnose problems from evidence, recommend remediations, coordinate with other authenticated agents or execution environments when explicitly authorized, and eventually act on the user's behalf under explicit guardrails.

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

The model can route questions, synthesize evidence into explanations, make adaptive decisions about what to inspect next, audit gaps, plan next steps, and help drive self-improvement by compiling confirmed learnings downward into deterministic tools, probes, rules, signatures, and tests. It is not the source of truth. The source of truth is structured evidence from local tools.

## First External Slice

The current first slice is an installable, read-only, LLM-backed local triage CLI.

End-user install from GitHub, without cloning the repository (requires Node.js 22.19.0+):

```bash
npm install -g github:Lightless-Labs/descartes
```

HTTPS tarball form if preferred:

```bash
npm install -g https://github.com/Lightless-Labs/descartes/tarball/main
```

On Linux distributions that ship older Node.js/npm packages or a root-owned global prefix, install Node 22.19.0+ through your normal version manager and either configure a user-writable npm prefix or install with `npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes` and add `$HOME/.local/bin` to `PATH`.

Then run:

```bash
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
```

`descartes login` opens a browser for subscription OAuth when possible. If the browser callback cannot complete, rerun with `descartes login --no-open` and paste the final redirect URL or code.

For subscription logins, Descartes picks a strong default rather than the provider registry's first model: highest available `openai-codex` GPT model by semantic version, or highest available Anthropic Sonnet. It uses high reasoning when available. You can override model selection:

```bash
descartes triage "my machine is slow" --model openai-codex/gpt-5.5 --thinking high
```

`--json` returns the diagnosis, evidence envelopes, deterministic findings, diagnostics, tool traces, and `actions_taken: []` for replay/debugging.

Evidence collection policy for the current v0 path:

- normal `triage` is model-led: the agent must request local facts through guarded Descartes read-only tools
- Descartes does not precollect evidence before the normal LLM investigation turn
- `collect_triage_evidence` is available as the broad first-slice evidence bundle when the model wants the obvious first pass
- `--no-investigate` is a temporary degraded escape hatch that disables LLM-requested evidence tools and uses deterministic precollection for no-tool synthesis
- fallback output is marked as degraded if the model returns no final text

Descartes uses deterministic local tools to collect evidence for CPU/load, memory/swap, disks/inodes, and top processes. An LLM-backed private agent session interprets the user's complaint, decides which Descartes evidence tools to call, and produces an evidence-cited diagnosis with safe next checks.

Safety and privacy boundaries for v0:

- local evidence collection is read-only
- no host actions are taken
- no telemetry, background upload, or federation
- explicit triage requests may send collected evidence to the selected LLM provider
- saved reports/session state are sensitive diagnostic artifacts
- Descartes-owned config/state follows XDG paths such as `$XDG_CONFIG_HOME/descartes`
- Descartes may use an internal Pi SDK harness, but it must not require, read, import, reuse, or modify the user's personal Pi setup (`~/.pi`, project `.pi`, Pi sessions, settings, auth, skills, prompts, themes, or model config)

Supported platforms for the first slice:

- Tier 1: macOS Apple Silicon and Linux x86_64
- Best effort: macOS Intel and Linux ARM64
- Not supported initially: Windows, BSD, Android/Termux, remote hosts, and container-only introspection

Descartes-owned paths follow XDG Base Directory conventions:

| Purpose | Default |
|---|---|
| Config/auth | `$XDG_CONFIG_HOME/descartes` or `$HOME/.config/descartes` |
| Data | `$XDG_DATA_HOME/descartes` or `$HOME/.local/share/descartes` |
| State/session artifacts | `$XDG_STATE_HOME/descartes` or `$HOME/.local/state/descartes` |
| Cache | `$XDG_CACHE_HOME/descartes` or `$HOME/.cache/descartes` |
| Runtime | `$XDG_RUNTIME_DIR/descartes` when `XDG_RUNTIME_DIR` is set |

MVP limitations: no daemon, no background monitoring, no remote hosts, no service/log/container-specific collectors yet, no redacted export mode yet, and no mutating actions.

The initial scaffold lives under `tools/descartes-cli/`.

Later, once capability discovery, policy, and audit foundations exist:

```bash
descartes plan "create a temporary Linux environment with npm for this test"
descartes apply plan-123
```

Descartes should choose between available local options such as Docker/Colima containers, Tart/Lima/UTM/Multipass VMs, CI integrations, or authenticated delegated agents based on the user's goal, explain tradeoffs, request scoped approval, and audit what changed. Delegated work needs explicit agent identity, authentication, scoped authority, user validation when required, and end-to-end audit.

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
- no ambient trust between agents or delegated environments
- clear distinction between recommendations, plans, delegated work, and executed actions
- audit log for every proposed, delegated, and executed action
- prefer reversible, narrowly scoped, pre-tested actions
- compile confirmed learning back into deterministic rules/signatures where possible

## Implementation

The current installable first slice is a Node.js/JavaScript CLI under `tools/descartes-cli/`. It uses the Pi SDK as a private embedded agent harness, Descartes-owned XDG paths, and explicit read-only Descartes evidence tools.

Rust remains the intended direction for the durable core: collectors, typed evidence envelopes, rule/signature engines, local stores, policy/audit machinery, and future native CLIs. When Rust crates are introduced, keep them Bazel-friendly: explicit manifests, reproducible tests, no hidden generation steps, and a clean crate graph.

Early implementation priorities:

1. validated Node.js/JavaScript first-slice CLI with subscription login and LLM-backed triage
2. typed evidence envelope
3. local system probes
4. CLI report path
5. rule/signature engine
6. local event store
7. notification abstraction
8. diagnosis and recommendation layer
9. policy-gated action planning

The wider Lightless Labs monorepo prefers Bazel.

## Repository Status

This repository is currently at the concept/scaffolding stage. See `AGENTS.md` for operating instructions for coding agents working on the project.
