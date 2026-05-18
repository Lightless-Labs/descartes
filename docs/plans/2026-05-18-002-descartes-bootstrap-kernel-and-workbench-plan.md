# Descartes Bootstrap Kernel and Workbench Plan

**Created:** 2026-05-18  
**Superseded:** 2026-05-18 — this plan over-scoped the first slice before establishing a shippable external-user workflow. Use `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` for the current next implementation direction.  
**Source plan:** `docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md`  
**Scope:** Deepened execution plan for Milestones 1–2: the Rust seed kernel and the optional Pi workbench that helps grow L0/L1 artifacts.

## Planning Decision

Start by giving Descartes a small, typed Rust kernel that an L2 workbench can improve, not by building a complete monitor first.

The bootstrap target is:

```text
Rust kernel: evidence + artifact lifecycle + validation shape
Pi workbench: builder/auditor loop over inactive candidate artifacts
Promotion: explicit review + tests before candidate artifacts become active
```

## Milestone 1 — Rust Seed Kernel

### Repository Layout

Initial Cargo workspace:

```text
Cargo.toml
crates/
  descartes-core/
    Cargo.toml
    src/
      lib.rs
      evidence.rs
      artifact.rs
      event.rs
      validation.rs
      store.rs
  descartes-cli/
    Cargo.toml
    src/
      main.rs
      commands/
        mod.rs
        status.rs
        artifacts.rs
        validate.rs
```

Bazel-friendly constraints:

- keep all manifests checked in
- no hidden code generation
- no build scripts unless justified later
- keep crate graph small and explicit
- prefer stable JSON contracts that Bazel tests can exercise later

### Initial Dependencies

Keep dependencies boring and portable:

- `serde`, `serde_json` for JSON contracts
- `thiserror` for core errors
- `clap` for CLI parsing
- `anyhow` for CLI error reporting
- optional later: `time`, `uuid`, `camino`, `schemars`

Avoid introducing async runtimes, databases, daemon frameworks, or platform probing crates in Milestone 1.

### Core Type Model

#### EvidenceEnvelope

`descartes-core` should define the common evidence shape first:

```rust
pub struct EvidenceEnvelope<T = serde_json::Value> {
    pub status: EvidenceStatus,
    pub layer: Layer,
    pub source: EvidenceSource,
    pub result: T,
    pub confidence: Confidence,
    pub review_hint: ReviewHint,
    pub trace: Trace,
}
```

Supporting enums:

- `EvidenceStatus`: `Ok`, `Warning`, `Critical`, `Unknown`, `NeedsInput`, `Unable`
- `Layer`: `LMinus1`, `L0`, `L1`, `L2`, `L3`, `Policy`
- `EvidenceSource`: initially string-backed or enum-plus-`Other`; include `System`, `Procfs`, `Sysfs`, `Filesystem`, `Network`, `PackageManager`, `Container`, `Vm`, `Workbench`, `ArtifactStore`
- `ReviewHint`: `None`, `ThresholdCrossed`, `RepeatedFailure`, `NovelPattern`, `MissingPermission`, `Ambiguous`, `OutOfRange`, `ValidationRequired`

`Confidence` should be a small validated wrapper around `f32` or `f64` constrained to `0.0..=1.0`.

`Trace` fields:

- `tool`: stable tool/probe/rule name
- `target`: optional target string
- `latency_ms`: optional integer
- `ts`: timestamp string at boundaries; use a testable clock abstraction later
- `trace_id`: optional stable ID for cross-linking artifacts, evidence, and agent reasoning

#### Event and Incident Skeleton

Define small event/incident records without overfitting:

```rust
pub struct DescartesEvent {
    pub id: String,
    pub ts: String,
    pub source_trace_id: Option<String>,
    pub severity: Severity,
    pub summary: String,
    pub evidence_refs: Vec<String>,
}

pub struct IncidentCandidate {
    pub id: String,
    pub status: IncidentStatus,
    pub title: String,
    pub event_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub hypothesis_refs: Vec<String>,
}
```

Milestone 1 does not need incident correlation logic. It only needs serializable shapes.

### Artifact Lifecycle Model

Candidate artifacts are the unit the L2 loop proposes and validates.

```text
ObservedGap
  -> Candidate
  -> Validating
  -> ValidationFailed | ReviewReady
  -> Promoted | Rejected | Retired
```

Artifact kinds:

- `L0Probe`
- `Parser`
- `EvidenceSchemaExtension`
- `L1Rule`
- `Signature`
- `BaselineCheck`
- `DiagnosticPlaybook`
- `RecommendationTemplate`
- `NotificationPolicy`
- `RegressionFixture`

`ArtifactManifest` fields:

- `id`
- `kind`
- `name`
- `version`
- `status`
- `created_at`, `updated_at`
- `scope` — what machines/platforms/data this artifact is intended for
- `provenance` — actor, Pi session id/file when available, prompt digest, source trace IDs
- `files` — candidate files, fixture files, generated tests
- `validation` — latest report ID/status
- `promotion` — reviewer/policy, promoted-at, active target, rollback notes

Promotion invariants:

- generated artifacts start inactive
- promotion requires at least one validation report
- failed validation cannot be promoted
- promotion records who/what approved it
- active artifact location must be inspectable

### Artifact Store Skeleton

Use filesystem storage first; SQLite can come later.

Default local store:

```text
.descartes/
  artifacts/
    candidates/
      <artifact-id>/
        manifest.json
        files/
        fixtures/
        reports/
    active/
      <artifact-id>/
        manifest.json
    retired/
      <artifact-id>/
        manifest.json
  validation/
    reports/
```

Reasons:

- easy to inspect and diff
- easy for Pi/custom tools to write candidate artifacts safely
- easy to ignore or curate in git later
- does not force a database decision before the data model stabilizes

Repository policy question to settle before implementation: whether `.descartes/` is ignored wholesale, or whether curated artifacts/fixtures move into `crates/`/`fixtures/` after promotion. Initial default should be local-only `.descartes/` plus explicit curated promotion into source-controlled locations.

### Validation Harness Skeleton

Define validation types now; implement only no-op and cargo-test backed runners initially.

```rust
pub struct ValidationRequest {
    pub artifact_id: String,
    pub checks: Vec<ValidationCheck>,
}

pub struct ValidationReport {
    pub id: String,
    pub artifact_id: String,
    pub status: ValidationStatus,
    pub started_at: String,
    pub finished_at: String,
    pub checks: Vec<ValidationCheckResult>,
    pub evidence_refs: Vec<String>,
}
```

Validation check kinds:

- `ManifestWellFormed`
- `SerdeRoundTrip`
- `FixtureReplay`
- `CargoTest`
- `Clippy`
- `PolicyInvariant`

Milestone 1 runners:

1. `ManifestWellFormed`: verifies required manifest fields.
2. `SerdeRoundTrip`: verifies core types serialize/deserialize.
3. `CargoTest`: shell out to `cargo test` with captured command, args, status, stdout/stderr boundaries, and timeout.

### CLI Contract

Initial commands:

```bash
descartes status --json
descartes artifacts list --json
descartes artifacts show <id> --json
descartes artifacts create-candidate --kind <kind> --name <name> --json
descartes validate artifact <id> --json
```

`descartes status --json` should return a stable stub envelope, not prose:

```json
{
  "status": "unknown",
  "layer": "L0",
  "source": "system",
  "result": {
    "message": "Descartes Rust kernel initialized; no probes active yet",
    "active_probe_count": 0,
    "candidate_artifact_count": 0
  },
  "confidence": 1.0,
  "review_hint": "validation_required",
  "trace": {
    "tool": "descartes_status_stub",
    "target": null,
    "latency_ms": null,
    "ts": "...",
    "trace_id": "..."
  }
}
```

Human-readable output can come later; `--json` is the contract for the workbench.

### Milestone 1 Tests

Minimum tests before calling Milestone 1 done:

- evidence envelope serde roundtrip
- confidence rejects or clamps out-of-range values; choose one policy and test it
- status JSON includes all envelope fields
- artifact manifest serde roundtrip
- artifact store creates candidates inactive by default
- artifact store refuses promotion without passing validation metadata
- validation report serde roundtrip

Suggested commands:

```bash
cargo fmt
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Milestone 2 — Pi SDK Workbench Spike

### Placement

Optional package:

```text
tools/pi-workbench/
  package.json
  tsconfig.json
  src/
    index.ts
    prompts.ts
    tools/
      descartes-status.ts
      candidate-artifacts.ts
      validation.ts
```

This package is development tooling, not the shipped Descartes runtime.

### SDK Shape

Use Pi SDK directly for the first workbench because it gives typed access to sessions, tools, events, prompts, models, settings, and in-memory session control.

Initial SDK choices from Pi docs/examples:

- `createAgentSession(...)`
- `SessionManager.inMemory(...)` for early ephemeral workbench runs
- `DefaultResourceLoader` with `systemPromptOverride(...)` for Descartes-specific builder/auditor instructions
- explicit tools list or custom tools; use cwd-aware tool names/factories when needed
- `defineTool(...)` custom tools for Rust CLI and artifact-store operations
- subscribe to session events and persist relevant `toolCallId`, `turn_end`, `sessionId`, and optional `sessionFile` references in artifact provenance

### Workbench Tools

Register custom tools rather than asking the model to manipulate artifact-store files directly.

Initial custom tools:

1. `descartes_status`
   - runs `cargo run -p descartes-cli -- status --json` or the built binary
   - returns parsed JSON plus raw command trace

2. `create_candidate_artifact`
   - parameters: kind, name, scope, rationale, evidence_refs
   - creates inactive artifact manifest through the Rust CLI
   - returns artifact ID and manifest path

3. `write_candidate_file`
   - restricted to the candidate artifact directory
   - rejects absolute paths outside the artifact root
   - uses Pi file mutation queue semantics if implemented as an extension later

4. `run_artifact_validation`
   - invokes `descartes validate artifact <id> --json`
   - captures validation report path and status

5. `summarize_promotion_readiness`
   - pure/read-only helper over manifest + validation report
   - no promotion side effects

### Workbench Prompt Contract

The workbench system prompt should require the agent to:

- treat active Descartes behavior as Rust/data artifacts, not chat conclusions
- generate candidates inactive by default
- create or update tests/fixtures with candidates
- run validation before recommending promotion
- cite evidence trace IDs or explicitly say evidence is missing
- never run mutating host operations outside the repository/artifact store
- never include raw logs, usernames, hostnames, paths, IPs, or secrets in prompts sent to external models unless a privacy profile explicitly allows it

### Safety Gate

Initial workbench mode should be repository-scoped:

- no host system probing beyond the Rust CLI stub until explicit L0 probes exist
- no destructive shell commands
- no writes outside the repository root and candidate artifact directory
- no promotion tool in the first spike; promotion remains manual/reviewed

A later Pi extension bridge may implement interactive permission prompts, but the SDK spike should be safe without relying on UI prompts.

### Event/Provenance Capture

For each created artifact, store:

- Pi session ID
- Pi session file if persisted
- prompt digest or short prompt summary
- tool call IDs involved in candidate creation
- validation command trace
- model/provider name if available
- workbench version

Do not store raw chain-of-thought. Store assistant-visible rationale and structured provenance only.

### Milestone 2 Acceptance Criteria

- `tools/pi-workbench` can start a session with a Descartes-specific system prompt
- custom tool can call `descartes status --json`
- custom tool can create an inactive candidate artifact
- custom tool can run validation and attach/report the result
- candidate provenance includes at least session ID and tool call IDs
- no product runtime crate depends on Node/Pi

## Promotion Policy v0

Manual promotion process for early milestones:

1. Candidate exists and is inactive.
2. Candidate includes tests or fixture replay evidence.
3. `descartes validate artifact <id> --json` passes.
4. Human reviews manifest, code/data, tests, and rollback notes.
5. Human applies/promotes the artifact into active source-controlled code/data or `.descartes/artifacts/active` as appropriate.
6. Handoff and plan are updated with what was promoted and why.

No autonomous promotion in Milestones 1–4.

## Privacy Profiles v0

**Superseded note:** this section belongs to the older workbench/bootstrap plan and is not the current first-slice policy. The current first slice is LLM-backed local triage: provider calls are required for explicit `descartes triage ...` requests, while telemetry/background upload/federation are not allowed.

Future privacy profiles should distinguish:

- local terminal disclosure to the machine owner/operator
- evidence sent to the selected LLM provider for an explicit triage request
- redacted exports/reports intended for sharing
- telemetry/federation, which remains out of scope by default

## First Self-Built Artifact Candidates

Once Milestones 1–2 exist, good first candidates are:

1. L0 `os_identity_stub_to_real_probe`
   - reads OS/kernel/uptime through platform APIs or narrow read-only commands
   - has Linux-first implementation and non-Linux `unknown/unable` behavior

2. L1 `status_unknown_requires_probe_rule`
   - consumes the status stub/first probe envelope
   - emits a validation-required notification/recommendation

These are deliberately low-risk and testable.

## Open Decisions To Resolve During Implementation

- Whether `Confidence` rejects out-of-range values or clamps them. Prefer reject for correctness.
- Whether timestamps are strings in core types or typed internally with string serialization. Prefer typed internally if dependency cost is acceptable.
- Whether candidate artifacts under `.descartes/` are ignored by default or selectively committed. Prefer ignored local candidates, curated committed fixtures/artifacts.
- Whether initial rule artifacts are Rust code, JSON/TOML data, or a small DSL. Prefer Rust for the first rule, data format after patterns emerge.
- Whether validation reports live beside artifacts only or also in a global index. Prefer both eventually; beside artifact first.

## Done Definition For This Planning Slice

This plan is complete when Milestones 1–2 have enough detail that implementation can proceed without architectural guessing, while still leaving later probe/rule specifics to the self-building loop.
