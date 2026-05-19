# Descartes Roadmap

**Created:** 2026-05-19

## Direction

Descartes starts as a read-only local triage CLI, but the long-term product is a local-first machine operations and defense agent. It should discover local capabilities, observe behavior, diagnose from evidence, recommend plans, coordinate with other authorized agents or execution environments when useful, and eventually act only through explicit policy/authority gates.

The core progression remains:

```text
Observe → Notify → Diagnose → Recommend → Plan → Act → Learn
```

## Guiding Use Case: Intent-Based Environment Provisioning

A representative future user request:

```text
I need a quick Linux environment to test a thing. It needs npm.
```

The user should not need to know or specify whether the machine has Docker, Colima, Podman, Tart, Lima, UTM, Multipass, Buildkite, another local option, or a trusted remote/CI agent. Descartes should discover local and delegated capabilities, compare viable strategies, recommend the safest fit, ask for approval on a concrete plan, execute only within that approval, verify the result, and clean up.

A mature interaction might look like:

```text
Descartes found three viable options:

1. Docker/Colima container
   Fastest. Good for npm/package tests. Not a full VM or systemd host.

2. Tart Linux VM
   Installed. Better isolation and a real VM boundary. Slower and uses more disk.

3. Buildkite validation job
   Available if CI credentials are configured. Best for repeatable release checks. Requires delegated authority scoped to this validation job.

Recommended: Docker/Colima unless you need a full VM.

Proposed plan:
- pull a Node Linux image if missing
- start a temporary container without host mounts
- verify node/npm
- run the requested test
- remove the container afterwards

This may download ~X MB. No host files will be mounted. No persistent changes except image cache.

Approve?
```

If the user says they need a real VM, Descartes replans around Tart/Lima/UTM/Multipass if available. If local options are unsuitable but an authenticated CI/remote agent is available, Descartes can propose delegation. If nothing suitable exists, it recommends an install option and explains tradeoffs before asking for approval.

## Required Capability Layers

### 1. Capability Discovery

Read-only tools answer:

- what OS/architecture is this?
- what package managers are available?
- what container runtimes are available?
- what VM runtimes are available?
- what CI/remote execution integrations are configured?
- what disk/network constraints apply?

Initial candidate tools:

- `collect_package_managers`
- `collect_container_runtimes`
- `collect_vm_runtimes`
- `collect_ci_integrations`

### 2. Process and Behavior Understanding

Before acting, Descartes needs better local facts about processes and provenance:

- process identity
- parent/child lineage
- executable location
- redacted command-line shape
- sustained behavior over time

Immediate next slice:

- shared redacted/bounded process args
- `inspect_process`
- `inspect_parent_tree`

Tracked in `todos/2026-05-19-process-identity-lineage-tools.md`.

### 3. Temporal Sampling

Many facts require watching over time rather than one snapshot:

- sustained CPU consumers
- repeated short-lived process bursts
- memory growth
- service flapping
- file/network bursts later

Tracked in `todos/2026-05-19-temporal-sampling-investigation-tools.md`.

### 4. Planning

Plans should be explicit objects, not prose-only suggestions:

- goal
- preflight checks
- proposed steps
- expected side effects
- risk level
- approval scope
- rollback/cleanup notes
- verification steps

### 5. Policy / Authority

No mutating action without explicit authorization. Approval must be scoped to a concrete plan. Every action needs an audit trail:

- proposed plan
- approval source/time/scope
- command/tool call
- pre-state
- result
- post-state
- rollback/cleanup notes

### 6. Inter-Agent Delegation / Identity

Descartes should eventually coordinate with other agents or execution environments, but never through ambient trust. Delegation needs explicit identity, authentication, capability scoping, policy checks, user validation, and end-to-end audit.

Examples:

- local Descartes delegates Linux validation to a Buildkite agent
- laptop Descartes asks a server-side Descartes instance to inspect that server locally
- a policy-approved remediation plan delegates one step to a temporary VM/container agent
- agents exchange evidence envelopes, plan fragments, approval records, and execution results

Required properties:

- every agent has an explicit identity
- every delegated request is authenticated
- delegated authority is scoped to a specific capability, target, expiry, and approval
- the receiving agent verifies caller identity, requested action, policy, and approval scope
- the initiating agent records why delegation was selected and what authority was granted
- delegated agents return structured evidence/results, not unverifiable prose
- user approval can be required before cross-agent delegation, sensitive evidence transfer, or mutation

A first design spike is tracked in `todos/2026-05-19-agent-delegation-identity-authority.md`.

### 7. Action Tools

Mutating tools should be narrow and policy-gated. Avoid exposing arbitrary shell as the default action surface. For the environment provisioning use case, future action tools might include:

- create temporary container
- remove temporary container
- create/launch temporary VM
- stop/remove temporary VM
- install package through approved package manager
- run approved command inside an approved disposable environment

### 8. Learning

Confirmed successful plans should compile downward into cheaper, auditable assets:

- deterministic probes
- reusable playbooks
- fixtures/tests
- signatures/rules
- CI validation jobs

## Near-Term Roadmap

### v0.0.x — Local read-only triage

Status: mostly validated on macOS.

- installable CLI
- subscription login
- model-led tool investigation
- read-only resource evidence
- JSON diagnostics/traces
- no host actions

Remaining/recently deferred:

- Linux x86_64 VM/container validation (`todos/2026-05-19-linux-ci-validation.md`)
- no-evidence/no-diagnosis guard (`todos/2026-05-19-no-evidence-no-diagnosis-guard.md`)

### Next — Process identity and lineage

Add redacted/bounded process evidence and process inspection tools. This is the highest-impact low-hanging fruit because it helps both today's triage and tomorrow's behavior/security detection.

Tracked in `todos/2026-05-19-process-identity-lineage-tools.md`.

### Then — Temporal sampling

Add bounded sampling so Descartes can distinguish transient snapshots from sustained behavior.

Tracked in `todos/2026-05-19-temporal-sampling-investigation-tools.md`.

### Then — Capability discovery

Add read-only discovery of package managers, container runtimes, VM runtimes, and CI integrations. This supports intent-based planning such as “I need a Linux environment with npm”.

### Later — Policy-gated action planning

Introduce explicit plan objects, approval scopes, audit trails, inter-agent delegation envelopes, and narrow mutating action tools. This is where Descartes can safely move from recommendation to action.

## Non-Negotiables

- read-only by default
- no arbitrary host mutation without policy approval
- no silent privilege escalation
- no ambient trust between agents
- evidence before reasoning
- model may adaptively decide what to inspect, but local facts come from tools
- every mutating action must be auditable and scoped
- every delegated action must be authenticated, authorized, scoped, and auditable
- prefer compiling repeated successful behavior into deterministic tools/rules/playbooks
