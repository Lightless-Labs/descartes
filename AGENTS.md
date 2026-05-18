# Descartes

Descartes is a Lightless Labs Rust project for an AI-native operations agent: a local-first maintenance agent, sysadmin assistant, and system operations gateway for machines.

The name comes from Philip Kerr's *The Second Angel*: Descartes is the computer running the literal Blood Bank on the Moon. This project borrows the idea of a machine entrusted with keeping critical infrastructure alive, but starts humbly: observe first, notify clearly, act only when explicitly allowed.

## Project Identity

Descartes is not "an LLM watching a server". It should become a stratified machine nervous system:

- cheap deterministic reflexes for common operational facts and failures
- statistical/baseline monitoring for behavior changes
- known-issue signatures and playbooks for repeatable diagnosis
- deliberative agent layers for escalation, ambiguity, synthesis, and learning
- a policy/authority plane for any action that changes the system

Core principle:

> Models may route, narrate, audit, plan, and learn. They are not the source of truth. System facts come from local tools, structured traces, and auditable evidence.

## Operational Lifecycle

Keep these lifecycle stages conceptually separate from architecture layers:

1. **Observe** — collect facts, logs, metrics, events, and machine state.
2. **Notify** — surface meaningful changes, risks, failures, and anomalies.
3. **Diagnose** — explain likely causes from grounded evidence.
4. **Recommend** — suggest remediations, tradeoffs, and next checks.
5. **Plan** — build auditable, reviewable action plans.
6. **Act** — execute only through explicit policy and authority gates.
7. **Learn** — compile confirmed findings back into cheaper rules, signatures, tests, and tools.

## Architecture Axes

Do not conflate lifecycle stages with implementation layers. A stage may involve several layers; a layer may support several stages.

### L-1 Interface / Privacy Gate

- Convert user intent into structured requests.
- Redact, bucket, or keep local sensitive data before external reasoning.
- Prefer local model/tool paths for raw logs, usernames, paths, hosts, IPs, and process details.

### L0 Deterministic System Tools

The factual core. Tools should be local-first, structured, testable, and auditable.

Initial domains:

- OS identity, kernel, uptime
- CPU, memory, swap, load, pressure
- disks, mounts, inode pressure, SMART/health where available
- process table and process trees
- services/daemons, especially systemd on Linux and launchd on macOS
- logs: journal, syslog, dmesg, platform equivalents
- network interfaces, routes, sockets, ports, DNS reachability
- package manager state and reboot-required signals
- containers and VMs where available
- backups, certificates, scheduled jobs, and time sync

L0 tools should return structured evidence envelopes, not prose blobs.

### L1 Monitoring / Rules / Signatures

- Thresholds and static rules.
- Stateful checks: flapping, repeated failures, missing heartbeats.
- Known-issue signatures and playbook matching.
- Statistical baselines and anomaly detection when useful.
- Notification routing and deduplication.

This layer should be capable of observing, notifying, diagnosing, and recommending for known/common cases without invoking an LLM.

### L2 Deliberative Diagnostic / Auditor Agents

- Escalated only for novelty, ambiguity, high impact, user queries, or review loops.
- Correlate lower-layer events into incidents.
- Ask L0 for more evidence rather than inventing facts.
- Produce hypotheses with confidence and missing evidence.
- Suggest new signatures, tools, thresholds, or tests.

### L3 Federated Knowledge Layer

Future/optional. Share anonymized signatures, playbooks, incident fingerprints, and outcome data.

Privacy default: do not ship raw logs, usernames, file paths, hostnames, IPs, secrets, or stable host/user identifiers. Prefer local IDs, buckets, hashes with clear threat models, and opt-in federation.

### Policy / Authority Plane

Any mutating action belongs behind explicit policy gates:

- read-only
- recommend-only
- approval-required
- policy-authorized low-risk action
- autonomous action for narrowly scoped, tested, reversible cases only

Every action needs an audit trail: proposed plan, approval source, command/tool call, pre-state, result, post-state, and rollback notes when possible.

## Rust Implementation Guidance

- Use Rust for core agents, collectors, tools, stores, and CLIs.
- Keep crates small and boundaries explicit.
- Prefer deterministic parsers and typed structs over ad-hoc strings.
- Use `Result` errors that fail early, fail fast, and fail clearly.
- Avoid shelling out unless a platform API is unavailable or unsafe to reimplement.
- When shelling out, capture command, arguments, exit status, stdout/stderr boundaries, timeout, and permissions.
- Design for Linux first if a choice is required, but keep platform abstractions open for macOS/BSD/Windows later.
- Parent repo prefers Bazel. If this repo starts with Cargo, keep it Bazel-friendly: no hidden build steps, checked-in manifests, reproducible tests, clear crate graph.

## Evidence Envelope Pattern

Use a common result shape for tool outputs. Exact Rust types may evolve, but preserve the idea:

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

## Development Process

- Start each session by reading `README.md`, this file, manifests, and `docs/HANDOFF.md`.
- Treat `docs/HANDOFF.md` as the current continuity document: update it before context compaction, before handing off to another agent, after completing milestones, and after important plan changes or discoveries.
- Keep changes scoped to Descartes unless the user explicitly asks for cross-project work.
- Use TDD for non-trivial behavior.
- Add or update tests with implementation changes.
- Run the smallest relevant check before finishing.
- For non-trivial milestones, create/update a plan under `docs/plans/`.
- When a plan is deepened, reviewed, completed, or amended, update its header with the date and reason.
- Document durable learnings in `docs/solutions/`.
- Keep generated artifacts, logs, and machine-local captures out of git unless explicitly curated and scrubbed.

## Quick Commands

This repository is not fully scaffolded yet. Once Rust manifests exist, prefer commands like:

```bash
cargo fmt
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

If/when Bazel is introduced, document equivalent build/test commands here and in `README.md`.

## Safety Invariants

- Read-only by default.
- Local evidence before model reasoning.
- No mutating action without policy authorization.
- No silent privilege escalation.
- No raw telemetry/federation without explicit user opt-in.
- Prefer compiling confirmed learning downward into deterministic rules/signatures over repeatedly relying on expensive reasoning.
