# Descartes First External Slice: LLM-Backed Local Triage CLI

**Created:** 2026-05-18  
**Revised:** 2026-05-18 — first slice must be LLM-backed, may use Pi internally as Descartes' private agent harness, must not touch the user's Pi setup, and should use XDG-style application paths.  
**Status:** In progress  
**Addendum:** 2026-05-18 — initial npm-style CLI scaffold added under `tools/descartes-cli/` with XDG path isolation tests, read-only resource evidence collectors, deterministic findings, and a private Pi SDK harness wrapper. Subscription login and real LLM triage still need end-to-end validation after dependency installation/auth.  
**Scope:** First functional end-to-end slice usable by external users and shippable quickly.

## Summary

Ship an installable CLI that answers an owner/operator's natural-language local operations question:

```bash
descartes triage "my machine is slow"
```

Descartes should:

1. accept the user's natural-language symptom,
2. use an LLM-backed agent harness to understand the request,
3. collect relevant local read-only evidence through deterministic Descartes tools,
4. ask the LLM to produce a grounded diagnosis and recommendations using only that evidence,
5. print a concise report with cited evidence and safe next checks.

The first slice is not a generic health report and not a deterministic `top`/`df` wrapper. The value is:

> I understand what you are asking, I inspected the machine, and the evidence suggests Docker is dominating CPU and memory while swap is active. Here is the evidence. Here is what to check next. No actions were taken.

## User Problem

A machine owner/operator feels that something is wrong and wants a quick, grounded first pass before digging through Activity Monitor, `top`, `df`, `journalctl`, `log`, Docker, service managers, and random web searches.

The first supported broad area is resource-pressure triage, but the user should be able to phrase the problem naturally:

- "my machine is slow"
- "why is everything sluggish?"
- "is Docker killing my laptop?"
- "something is eating all my CPU"
- "my dev box is unusable"

## Goals

- Provide useful LLM-backed local diagnosis on first run.
- Be installable by an external user.
- Support normal subscription-style auth as the primary path, not only developer API keys.
- Use Pi or another agent harness internally rather than reinventing model/tool/session machinery.
- Never require the user to preinstall or configure Pi.
- Never read, import, reuse, modify, or otherwise interact with the user's personal Pi setup.
- Work on at least macOS Apple Silicon and Linux x86_64 in a best-effort way.
- Gather specific local evidence visible to the owner/operator.
- Ground every conclusion in collected evidence.
- Take no mutating action.
- Send no telemetry.
- Send local evidence to the selected LLM provider only as part of the user-requested triage flow.
- Keep JSON/event shapes suitable for future replay, evaluation, and lower-layer rule evolution.

## Non-Goals

- No daemon.
- No background monitoring.
- No autonomous remediation.
- No remote host management.
- No dependency on an existing Pi installation or Pi configuration.
- No interaction with `~/.pi`, project `.pi`, Pi sessions, Pi auth, Pi extensions, Pi skills, Pi prompts, or Pi themes.
- No complete L0/L1/L2 artifact lifecycle.
- No generalized sysadmin chatbot beyond the local triage task.
- No attempt to diagnose every possible machine problem in v0.

## User Experience

### Install

Initial install mechanism is still an implementation choice, but it must produce a `descartes` command and include its private agent-harness dependency. Users should not separately install Pi.

Possible first install routes:

```bash
npm install -g @lightless-labs/descartes
```

or:

```bash
brew install lightless-labs/tap/descartes
```

or a GitHub Release binary/package once packaging exists.

A Cargo-only install is not sufficient if it cannot include the private Pi/agent harness needed for LLM-backed triage.

### Login

Primary path for normal users:

```bash
descartes login
```

The login flow should support subscription-backed providers where the underlying harness supports them, for example:

- Claude Pro / Max
- ChatGPT Plus / Pro
- GitHub Copilot

API keys are acceptable as an advanced/headless path, not the default user story.

### Primary command

```bash
descartes triage "my machine is slow"
```

Potential convenience alias after the primary command works:

```bash
descartes slow
```

### Example output

```text
Descartes triage: my machine is slow

Most likely cause
  Docker Desktop is consuming heavy CPU and memory while the system is under memory pressure.

Confidence
  High

Evidence
  - Load average is high for this machine: 14.2 over 10 CPU cores
  - Memory is 93% used
  - Swap is active: 6.1 GB used
  - Top CPU process: Docker Desktop, 388%
  - Top memory process: Docker Desktop, 7.4 GB
  - Root disk has adequate free space: 42 GB free

Safe next checks
  1. Check whether containers are rebuilding, stuck, or unexpectedly busy.
  2. Inspect Docker resource limits.
  3. Stop unused containers if you recognize them.

Avoid for now
  - Do not kill unknown system processes.
  - Do not reboot yet; the evidence points to a clear resource consumer.

No actions were taken.
```

### JSON / debug output

A structured output mode may exist for debugging/evaluation/replay, but it is not a no-LLM triage replacement. Natural-language triage requires an LLM.

```bash
descartes triage "my machine is slow" --json
```

Returns collected evidence, tool traces, and the LLM-backed diagnosis/recommendations.

## Pi / Agent Harness Boundary

Descartes may use Pi internally as an implementation dependency or embedded/private agent harness.

Descartes must never touch the user's personal Pi setup. This is a hard boundary, not an optional import feature.

Descartes must not read, import, reuse, modify, migrate, or inspect:

- `~/.pi/`
- `~/.pi/agent/`
- project `.pi/`
- Pi sessions
- Pi settings
- Pi auth
- Pi extensions
- Pi skills
- Pi prompts
- Pi themes
- Pi model configuration

If Pi SDK/RPC is used internally, it must be configured with:

- Descartes-owned config/auth/state/data directories
- explicit Descartes-owned resource loading
- explicit Descartes-owned tools only
- no default user/project Pi discovery
- no coding tools exposed to the triage agent by default
- read-only local evidence tools only

Pi is an internal harness choice, not part of the user contract.

## Application Paths

Use the XDG Base Directory pattern for Descartes-owned files.

On Unix-like systems:

| Purpose | Environment variable | Default |
|---|---|---|
| Config/auth | `XDG_CONFIG_HOME` | `$HOME/.config/descartes` |
| Data | `XDG_DATA_HOME` | `$HOME/.local/share/descartes` |
| State | `XDG_STATE_HOME` | `$HOME/.local/state/descartes` |
| Cache | `XDG_CACHE_HOME` | `$HOME/.cache/descartes` |
| Runtime | `XDG_RUNTIME_DIR` | `$XDG_RUNTIME_DIR/descartes` when set |

Suggested use:

- config/auth: provider login state, model/provider preferences, user settings
- data: bundled or downloaded Descartes prompts, schemas, local tool metadata
- state: Descartes sessions, triage history, audit/event records
- cache: temporary model/provider/cache artifacts, non-authoritative probe caches
- runtime: sockets, locks, short-lived process files

Do not use `~/.descartes` as the default unless needed as a compatibility fallback later. Do not use any Pi-owned path.

## Distribution

### Primary home

Initial public home:

```text
https://github.com/lightless-labs/descartes
```

The README should become the product surface for v0 and include:

- short product description
- installation command
- `descartes login`
- supported platforms
- example triage output
- clear statement that Descartes may use an internal agent harness but does not require or touch user Pi
- safety statement: local evidence collection is read-only, no telemetry by default
- explicit MVP limitations

### Later distribution

- npm package if the first CLI is TypeScript/Pi-SDK based
- Homebrew tap
- GitHub Releases with prebuilt binaries/packages
- Linux packages

## Supported Platforms

### Tier 1 for first slice

- macOS Apple Silicon
- Linux x86_64

### Tier 2 / best effort

- macOS Intel
- Linux ARM64

### Not supported initially

- Windows
- BSD
- Android/Termux
- remote hosts
- container-only introspection

## Capability Matrix

| Capability | macOS | Linux |
|---|---:|---:|
| Subscription login via private harness | spike | spike |
| LLM-backed local triage | yes | yes |
| OS/kernel/uptime | yes | yes |
| CPU/load | yes | yes |
| memory/swap | yes | yes |
| disks/mounts | yes | yes |
| top processes | yes | yes |
| process command lines | yes | yes |
| service manager diagnosis | later | later/systemd |
| recent system logs | later | later/journalctl |
| Docker/container diagnosis | later | later |

The first release can mention Docker only if process evidence shows Docker as a top resource consumer. It should not require Docker API integration.

## Privacy and Disclosure Model

Descartes v0 runs for the machine owner or authorized local user.

Local terminal output may include operationally useful machine identifiers and local evidence, including:

- hostname
- usernames where relevant
- process names
- process command lines
- mount points and paths
- listening process names if later added
- service names if later added
- local log excerpts if later added

The privacy boundary is not "do not show the local user their own machine." The privacy boundary is:

> Do not transmit sensitive local evidence except to the user-selected LLM provider for the explicit triage request, and do not send telemetry.

For v0:

- local evidence collection is read-only
- no telemetry
- no background upload
- no federation
- no external sharing except the LLM request required to answer `descartes triage ...`
- saved reports and session state should be treated as sensitive diagnostic artifacts

## Functional Design

### Pipeline

```text
User prompt
  -> private Descartes agent session
  -> LLM interprets symptom and requests evidence through allowed tools
  -> deterministic read-only tools collect local evidence
  -> LLM synthesizes diagnosis using only evidence returned by tools
  -> renderer prints human report or structured JSON
```

### Agent responsibilities

The LLM may:

- interpret the user's natural-language complaint
- decide which Descartes evidence tools to call
- ask follow-up questions if evidence is insufficient
- synthesize likely causes and confidence
- recommend safe next checks
- cite evidence IDs

The LLM may not:

- claim facts not present in evidence
- execute arbitrary shell commands
- mutate the system
- access coding tools
- browse or use unrelated local files
- interact with user Pi configuration

### Deterministic tool responsibilities

Descartes tools provide facts. They should be local, read-only, structured, and auditable.

Initial evidence tools:

- collect system identity and uptime
- collect CPU/load
- collect memory/swap
- collect disks/mount points usage
- collect top CPU processes
- collect top memory processes
- collect process names and command lines

Use a Rust system information component where practical. Shell out only when a platform API or crate support is insufficient, and capture command, args, exit status, stdout/stderr boundaries, timeout, and permissions.

### Findings and diagnosis

The first slice can include deterministic findings to help the LLM and to keep output grounded:

- `high_load_relative_to_cpu_count`
- `memory_pressure`
- `swap_pressure`
- `disk_pressure`
- `single_dominant_cpu_process`
- `single_dominant_memory_process`
- `multiple_resource_consumers`
- `insufficient_evidence`

The final diagnosis is LLM-authored but evidence-constrained.

## Data Model

Keep the model small but aligned with future evidence envelopes.

Suggested core shapes:

```rust
struct TriageSession {
    user_prompt: String,
    evidence: Vec<EvidenceEnvelope>,
    findings: Vec<Finding>,
    diagnosis: Diagnosis,
    actions_taken: Vec<ActionRecord>, // empty in v0
}
```

```rust
struct EvidenceEnvelope {
    id: String,
    status: EvidenceStatus,
    layer: Layer,
    source: EvidenceSource,
    result: serde_json::Value,
    confidence: f32,
    review_hint: ReviewHint,
    trace: Trace,
}
```

```rust
struct Finding {
    id: String,
    severity: Severity,
    summary: String,
    evidence_refs: Vec<String>,
}
```

```rust
struct Diagnosis {
    summary: String,
    confidence: ConfidenceLevel,
    explanation: String,
    evidence_refs: Vec<String>,
    next_checks: Vec<String>,
    avoid: Vec<String>,
}
```

## Implementation Plan

### Likely package layout

The exact implementation can be adjusted during the spike, but the first slice likely needs both:

1. a local evidence collector, preferably Rust-first
2. a CLI/agent harness layer that can use Pi SDK/RPC privately

Possible layout:

```text
Cargo.toml
crates/
  descartes-core/
  descartes-collector/

tools/descartes-cli/
  package.json
  src/
    index.ts
    paths.ts
    login.ts
    triage.ts
    pi-harness.ts
    tools/
      collect-system.ts
      collect-processes.ts
      collect-disks.ts
```

If a Rust-owned CLI can practically embed/spawn a private Pi RPC runtime with Descartes-owned paths, that is also acceptable. Do not hand-roll an agent harness just to keep the first binary Rust-only.

### Agent harness requirements

- uses Descartes-owned XDG paths
- custom/explicit resource loader
- no user Pi discovery
- no built-in coding edit/write/bash tools in the triage agent
- only Descartes read-only evidence tools
- subscription login support via Descartes-owned auth state
- structured final answer where possible

### CLI

```bash
descartes login
descartes triage <PROMPT> [--json]
descartes --version
```

### Tests / checks

Minimum tests:

- XDG path resolution honors env vars and defaults
- Pi/user setup boundary: no `~/.pi` or project `.pi` paths are read/written by Descartes path code
- evidence tool serialization
- memory pressure finding thresholds
- swap pressure finding thresholds
- disk pressure finding thresholds
- dominant process detection
- final report renderer includes diagnosis, evidence citations, next checks, and no-actions statement

## Acceptance Criteria

The first slice is shippable when:

- a user can install `descartes` without preinstalling Pi
- `descartes login` stores auth/config only in Descartes-owned XDG paths
- `descartes triage "my machine is slow"` runs an LLM-backed private agent session
- the private agent can collect local read-only evidence through Descartes tools
- the final answer cites evidence returned by those tools
- macOS Apple Silicon works
- Linux x86_64 is implemented or clearly best-effort with graceful unsupported evidence
- no mutating host actions are performed
- no telemetry is sent
- no user Pi files/config/session/auth/extensions/prompts/skills/themes are read or modified
- probe failures are represented as unavailable/unknown evidence rather than panics
- README documents install, login, platform support, example output, paths, Pi boundary, and limitations

## Risks and Mitigations

### Risk: We accidentally couple to user Pi state

Mitigation: explicit Descartes-owned XDG paths, custom resource loader, tests asserting no Pi-owned paths, and no import/reuse feature.

### Risk: We reinvent agent machinery

Mitigation: use Pi SDK/RPC internally as the harness where practical.

### Risk: Subscription login is harder to expose outside Pi's UI

Mitigation: make `descartes login` the first spike. If login APIs are not directly reusable, choose the least invasive private-harness path that still stores auth under Descartes-owned XDG paths.

### Risk: Output is still just a stats dump

Mitigation: require an LLM-authored diagnosis with evidence citations and safe next checks. Stats are evidence, not the product.

### Risk: Cross-platform metrics differ

Mitigation: best-effort probes and explicit `unknown`/`unable` evidence statuses.

### Risk: Process command lines expose sensitive data in copied reports

Mitigation: local output may show owner-visible details, but document saved reports/session state as sensitive. Add redacted export later.

### Risk: Scope creep into full monitoring

Mitigation: one command, one triage flow, no daemon.

## Future Slices

Possible next slices after this ships:

1. `descartes triage "postgres is down"` on Linux/systemd.
2. `descartes triage "why did my machine reboot?"` using local logs.
3. `descartes triage --from report.json` for replay/evaluation of a saved session.
4. Redacted export/share mode.
5. Candidate rule/probe generation once baseline user value exists.
