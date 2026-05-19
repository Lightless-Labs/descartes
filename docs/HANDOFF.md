# Descartes Handoff

**Last updated:** 2026-05-19

## Current Status

Descartes has an initial first-slice CLI scaffold. The LLM-driven investigation loop has been validated on real macOS subscription-auth runs with Anthropic and ChatGPT/Codex. A release-readiness pass is effectively complete for macOS: packaging, local/GitHub install, XDG no-auth failure, API-key login storage, README/help drift, metadata drift, login UX, model-led tool use, and current-package human/JSON triage have been tightened/validated. Linux ARM64 best-effort validation now passes for public v0.0.11 install/help/version, ChatGPT/Codex `--no-open` login, model-led guarded triage, and system/process/disk evidence collection. Remaining platform gap is true Linux x86_64 validation/CI.

Current session update: Linux validation report showed the first Ubuntu attempt used unsupported Node v18.19.1/npm 9.2.0 and failed global install with `EACCES` on `/usr/local/lib/node_modules`; it did not reach Descartes runtime. A second run with `$HOME/.local` prefix installed public v0.0.8, completed ChatGPT/Codex `--no-open` login, and produced non-fallback model-led triage on Linux arm64 with guarded `collect_triage_evidence` and `actions_taken: []`; process collection failed because Linux procps rejected BSD-style `ps -axo ... -m`. v0.0.10 switched Linux process collection to `ps -eo ...` and sorts top CPU/memory in-process. v0.0.11 fixed npm-bin symlink entrypoint detection. Third Linux ARM64 validation with public v0.0.11 passed: install, symlinked `--version`/`--help`, ChatGPT/Codex `--no-open` login, non-fallback model-led triage, guarded `collect_triage_evidence`, and ok `collect_system`/`collect_processes`/`collect_disks` envelopes. That validation exposed raw process command lines before the current redaction/bounding work. v0.0.12 moves the embedded harness dependency from deprecated `@mariozechner/*` packages to `@earendil-works/pi-coding-agent` 0.75.3 and raises the runtime requirement to Node.js 22.19.0+. Fresh local tarball install no longer emits the `@mariozechner/*` deprecation warnings; one upstream `node-domexception` deprecation warning remains through `@google/genai`/Google auth transitive dependencies in Pi AI.

Current session update: normal `triage` is model-led and does not precollect evidence before the LLM turn. The model must request local facts through the guarded Descartes read-only tool surface. It now exposes `collect_system`, `collect_processes`, `collect_disks`, `inspect_process`, `inspect_parent_tree`, `collect_triage_evidence`, and `derive_findings`; a runtime guard rejects Pi coding/shell tools if they appear active. `--no-investigate` is available as a temporary degraded no-tool synthesis escape hatch and still uses deterministic precollection. JSON output includes selected model metadata, thinking level, active tools, tool calls/results/errors, assistant stop reason, LLM error, fallback state, evidence, findings, traces, and `actions_taken: []`. Fallback construction is testable and explicitly marked degraded mode.

Field validation update: a real macOS disk triage using Anthropic Sonnet succeeded end-to-end: `investigation_enabled: true`, active tools were exactly the guarded Descartes tool set, the model called `collect_disks`, and it returned a useful non-fallback diagnosis for large macOS "System Data" caused primarily by Xcode CoreSimulator runtime image mounts. This completes `todos/2026-05-19-llm-driven-investigation-tools.md`. The follow-up disk classification work is also complete: `/dev`, `map ... /home`, Linux/macOS pseudo filesystems, and macOS CoreSimulator/Cryptex developer runtime image mounts are classified as not pressure-relevant; runtime images now produce one aggregate notice instead of per-mount critical findings. Package metadata is bumped to v0.0.14.

Process identity/lineage update: `todos/2026-05-19-process-identity-lineage-tools.md` is complete. `collect_processes` now emits redacted/bounded command lines with redaction metadata, and the guarded triage surface includes `inspect_process` plus `inspect_parent_tree` for PID-level identity/provenance using fixed read-only `ps` snapshots and Linux `/proc` metadata where available. Package metadata is bumped to v0.0.13 for this slice. Linux x86_64 validation remains open for CI/true x86_64 coverage, but Linux ARM64 VM validation passed with v0.0.11. Roadmap note added: temporary VM/container cleanup and repeated-work playbook suggestions are framed as glimpses/capability biases enabled by intent preservation, lifecycle signals, structured memory, temporal confidence/decay, evidence-grounded recommendations, and policy-gated actions rather than as hardcoded workflows.

Conceptual update: Descartes no longer has a separate L-1 Interface / Privacy Gate layer. Privacy and provider-boundary behavior remain product/safety constraints, but architecture layers now start at L0 deterministic system tools.

Field report update: GitHub-installed triage on a real work laptop returned an empty diagnosis after login. `tools/descartes-cli/src/triage.js` now reads final assistant text from `session.messages` after `session.prompt()` instead of relying only on streaming `text_delta` events, and emits a deterministic fallback report if the model still returns no final text.

Second field report update: v0.0.1 still produced fallback with empty `evidence`, `findings`, and `tool_traces`, meaning the LLM session did not call any Descartes evidence tools. v0.0.2 precollects the first-slice read-only evidence bundle before invoking the model, injects that evidence into the prompt, and includes precollected evidence/traces in JSON output even when the model makes no tool calls.

Third field report update: v0.0.2 had evidence but still no LLM text. v0.0.3 changes synthesis to a no-tool LLM turn over a compact evidence summary, avoiding custom tool schemas and oversized raw evidence in the provider request. JSON fallback now includes `llm_error` when the assistant message records one.

Fourth field report update: v0.0.3 selected `openai-codex/gpt-5.1`, which ChatGPT subscription Codex rejected. v0.0.4 added explicit model selection and defaulted ChatGPT/Codex subscription auth to `openai-codex/gpt-5.5` with high reasoning when available. v0.0.5 replaces hardcoded Codex preferences with semantic-version "highest GPT model" selection per preferred subscription provider. v0.0.6 also avoids Anthropic registry-order Haiku defaults by selecting the highest available Anthropic Sonnet. v0.0.7 fixes Anthropic date parsing so release dates like `20250514` are not treated as version components ahead of `claude-sonnet-4-6`. v0.0.8 includes the login UX cleanup and temporary tool-forcing triage behavior. `--model` and `--thinking` are passed through to the harness.

Release-readiness update: README now starts with concrete "What it does", "Where it's going", and "How to get started" blocks, and frames the long-term goal as real-time operations/defense behavior detection with policy-bounded interruption of novel harmful behavior such as ransomware-like or trojan-like activity. CLI help now documents `--model`/`--thinking`; `--version` reads package metadata instead of a hardcoded string; root package contents exclude tests; root/nested package engine metadata is aligned; and `tools/descartes-cli/test/package-metadata.test.js` covers metadata/help/version drift.

Login UX fix: subscription OAuth login no longer starts an immediate manual paste `readline` prompt during normal browser-based login, because the Pi OAuth helper races that prompt against the localhost callback and leaves the terminal waiting for Enter after browser success. Normal `descartes login` now opens the browser and waits for callback; manual paste is available via `descartes login --no-open`. User re-test confirmed the flow is much better.

Current-package ChatGPT/Codex validation: GitHub-installed `descartes triage "my machine is slow"` returned a useful non-fallback human diagnosis citing system/process/disk evidence and ended with `No actions were taken.` Initial GitHub-installed JSON triage returned `fallback_used: false`, selected `openai-codex/gpt-5.5` with high thinking, active tools exactly `collect_system`, `collect_processes`, `collect_disks`, `collect_triage_evidence`, `derive_findings`, three ok precollected evidence envelopes, findings/tool traces, and `actions_taken: []`. The model made no additional tool calls because compact precollected evidence was sufficient; prior Anthropic validation covered explicit tool-call behavior. The JSON model output cited compact summary keys (`top_cpu`, `top_memory`) as evidence refs, so prompt instructions were tightened to require envelope IDs only.

Evidence collection policy decision: keep normal `triage` model-led rather than restoring unconditional precollection. The model must request local facts through the guarded Descartes tool surface; `collect_triage_evidence` is the broad first-pass tool. `--no-investigate` remains the degraded no-tool synthesis escape hatch and still precollects deterministic evidence. v0.0.8 GitHub-installed validation confirmed this works: JSON triage had `fallback_used: false`, selected `openai-codex/gpt-5.5`, active tools exactly matched the guarded Descartes tool set, the model called `collect_triage_evidence`, evidence refs were envelope IDs, and `actions_taken: []`. Future hardening: add a "no evidence, no diagnosis" guard that retries or degrades if normal investigation returns without tool calls/evidence.

Existing files:

- `README.md` — updated to describe the LLM-backed local triage first slice, Pi/XDG boundaries, and future intent-based policy-gated operations use cases.
- `AGENTS.md` — operating instructions for coding agents.
- `.gitignore` — excludes local reference material, logs, Rust build output, Node package output, and OS noise.
- `package.json` — root npm package so end users can install with `npm install -g github:Lightless-Labs/descartes` without cloning.
- `tools/descartes-cli/` — initial npm-style Descartes CLI scaffold.
  - `src/paths.js` resolves Descartes-owned XDG paths and rejects Pi-owned paths.
  - `src/tools/` contains read-only evidence collectors for system overview, top processes with redacted/bounded args, process identity/lineage inspection, disks, deterministic findings, and a combined triage bundle.
  - `src/pi-harness.js` wraps Pi SDK session creation with Descartes-owned auth/model paths, no default resource discovery, no built-in coding tools, and only explicit Descartes evidence tools.
  - `src/login.js` implements a first terminal OAuth/API-key login path storing under Descartes config.
  - `src/triage.js` implements human and JSON triage prompts around the private harness.
  - `test/` covers XDG path resolution, Pi-path guardrails, and deterministic finding thresholds.
- `docs/ROADMAP.md` — roadmap for capability discovery, process/behavior understanding, temporal sampling, planning, inter-agent delegation/identity, policy-gated action, and learning. Includes the guiding future use case: “I need a quick Linux environment with npm,” where Descartes discovers Docker/Colima/Podman/Tart/Lima/UTM/Multipass/Buildkite/authenticated delegated-agent options, recommends a plan, asks approval, executes or delegates within scoped authority, verifies, and cleans up.
- `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` — **current implementation plan**, now in progress.
- `todos/` — frontmatter-indexed work items for quick triage/sorting:
  - `2026-05-19-first-external-slice-validation.md` — **immediate next task, in progress**: validate install/login/triage/docs/platform readiness against the first external slice plan.
  - `2026-05-19-llm-driven-investigation-tools.md` — completed; safe LLM tool-driven local investigation restored and validated with Anthropic on macOS.
  - `2026-05-19-process-identity-lineage-tools.md` — completed; redacted/bounded process args, `inspect_process`, and `inspect_parent_tree` are implemented and exposed through the guarded triage tool surface.
  - `2026-05-19-expand-local-investigation-tools.md` — add more local read-only collectors; process identity/lineage is complete, with temporal sampling/network/services/logs/containers as later candidates.
  - `2026-05-19-temporal-sampling-investigation-tools.md` — bounded LLM-requested monitoring/sampling over time with aggregates/artifacts.
  - `2026-05-19-macos-disk-evidence-classification.md` — completed; classifies pseudo/runtime filesystems, fixes macOS map row parsing, and reduces disk finding noise.
  - `2026-05-19-linux-ci-validation.md` — future Buildkite Linux x86_64 validation, optionally with scoped CI credentials.
  - `2026-05-19-agent-delegation-identity-authority.md` — future design spike for inter-agent communication/delegation with identity, auth, scoped authority, policy, user validation, and audit.
  - `2026-05-19-no-evidence-no-diagnosis-guard.md` — future hardening for model-led triage: retry or degrade if normal investigation returns without tool calls/evidence.
  - `2026-05-19-web-search-retrieval-tools.md` — closer-future explicit web/search retrieval tools and optional proxy.
  - `2026-05-19-federated-process-knowledge-db.md` — future shared/federated process behavior knowledge database.
- `docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md` — deferred broader product direction.
- `docs/plans/2026-05-18-002-descartes-bootstrap-kernel-and-workbench-plan.md` — superseded; do not implement this first.

## Start Here In A New Session

1. Read `README.md`, `AGENTS.md`, and this handoff.
2. Treat `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` as the current source of truth.
3. Do **not** start with the artifact lifecycle, Pi workbench, deterministic-only triage, keyword matching, or a Cargo-only CLI unless the harness/package decision has been revisited.
4. Do not restore unconditional precollection as the normal triage path. Normal `triage` should remain model-led tool investigation; `--no-investigate` is the degraded precollection path.
5. Recommended next task: `todos/2026-05-19-no-evidence-no-diagnosis-guard.md`, or `todos/2026-05-19-temporal-sampling-investigation-tools.md` if expanding collector capability is preferred.

## Current First Slice

Ship an installable command:

```bash
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
```

This must be an **LLM-backed local triage flow**. The LLM interprets the user's natural-language complaint and decides which Descartes read-only evidence tools to call. Deterministic code gathers/structures evidence and computes optional findings for grounding; it does not pretend to understand arbitrary user intent by keyword matching.

The product value is not a stats dump. It is an evidence-cited operational diagnosis with confidence, safe next checks, and explicit no-action/audit language.

## Non-Negotiable Boundaries

### LLM and Auth

- Natural-language `triage` requires an LLM-backed agent harness.
- Normal users often have subscriptions, not API keys. `descartes login` should be the primary user path.
- API keys may be an advanced/headless fallback, not the main UX.
- LLM/provider network calls are expected for explicit `descartes triage ...` requests.
- Telemetry, background upload, and federation are not part of v0.

### Pi / Agent Harness

- Do not reinvent agent harness machinery if Pi SDK/RPC can provide model/provider/tool/session behavior.
- Descartes may use Pi internally as a private embedded harness.
- Users must **not** need to preinstall or configure Pi.
- Descartes must **never** read, import, reuse, modify, migrate, or inspect the user's personal Pi setup.
- No interaction with `~/.pi`, `~/.pi/agent`, project `.pi`, Pi sessions, Pi settings, Pi auth, Pi extensions, Pi skills, Pi prompts, Pi themes, or Pi model config.
- If Pi SDK/RPC is used, configure it with Descartes-owned paths, explicit resources, and Descartes read-only tools only.

### Local Evidence / Privacy

- Descartes runs for the machine owner or authorized local user.
- Local output may include operationally useful identifiers: hostname, usernames where relevant, process names, command lines, mount points, paths, service names, and later logs.
- The privacy boundary is not hiding the local machine from its owner. The boundary is not transmitting sensitive local evidence except to the selected LLM provider for the explicit triage request.
- Saved reports/session state are sensitive diagnostic artifacts.

### Safety

- Local evidence collection is read-only.
- No mutating host action in v0.
- No arbitrary shell/coding tools exposed to the triage agent by default.
- The LLM may ask for evidence through Descartes tools; it may not execute arbitrary commands or claim facts not present in evidence.

## Descartes-Owned Paths

Use XDG Base Directory conventions for Descartes-owned state on Unix-like systems:

| Purpose | Env var | Default |
|---|---|---|
| Config/auth | `XDG_CONFIG_HOME` | `$HOME/.config/descartes` |
| Data | `XDG_DATA_HOME` | `$HOME/.local/share/descartes` |
| State | `XDG_STATE_HOME` | `$HOME/.local/state/descartes` |
| Cache | `XDG_CACHE_HOME` | `$HOME/.cache/descartes` |
| Runtime | `XDG_RUNTIME_DIR` | `$XDG_RUNTIME_DIR/descartes` when set |

Do not default to `~/.descartes`. Do not use any Pi-owned path.

## Distribution Assumptions

Primary public home:

```text
https://github.com/lightless-labs/descartes
```

The first install mechanism is an implementation decision, but it must include/private-vendor the agent harness. A Cargo-only CLI is not sufficient if it cannot provide the LLM-backed private harness and subscription login flow.

Likely first distribution candidates:

```bash
npm install -g @lightless-labs/descartes
```

or:

```bash
brew install lightless-labs/tap/descartes
```

or a GitHub Release package/binary.

## Platform Scope

Tier 1 for first slice:

- macOS Apple Silicon
- Linux x86_64

Tier 2 / best effort:

- macOS Intel
- Linux ARM64

Not supported initially:

- Windows
- BSD
- Android/Termux
- remote hosts
- container-only introspection

## Implementation Direction

Likely architecture for the first slice:

```text
descartes CLI/package
  -> Descartes-owned XDG config/auth/state/cache paths
  -> private Pi SDK/RPC or equivalent harness
  -> explicit Descartes system prompt/resources
  -> Descartes read-only evidence tools
  -> Rust-first or native local collector components where useful
  -> LLM-authored, evidence-cited diagnosis
```

Possible repository shape from the current plan:

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

This shape is not mandatory. The mandatory part is the user-visible behavior and the path/Pi/safety boundaries.

## Suggested Next Action

Recommended next task: add the no-evidence/no-diagnosis retry-or-degrade guard from `todos/2026-05-19-no-evidence-no-diagnosis-guard.md` before expanding collectors further. If choosing a capability expansion instead, use `todos/2026-05-19-temporal-sampling-investigation-tools.md`.

The future capability-discovery/action/delegation direction is documented in `docs/ROADMAP.md`, including the “quick Linux environment with npm” use case and explicit inter-agent identity/auth/scoped-authority requirements. Linux x86_64 validation is deferred to future Buildkite CI and tracked separately in `todos/2026-05-19-linux-ci-validation.md`.

## Tests / Checks To Prioritize

- XDG path resolution honors environment variables and defaults.
- No Descartes path code references `~/.pi`, `.pi`, or Pi user config locations.
- Private harness starts with explicit Descartes resources/tools only.
- Evidence tools serialize structured evidence envelopes.
- Local evidence collection is read-only.
- Human renderer includes diagnosis, evidence citations, next checks, and "No actions were taken."
- JSON output includes evidence/tool traces and diagnosis.

## Broader Product Direction Later

After the first external slice exists, the broader L2 builder/auditor direction remains relevant: Descartes should learn by compiling experience down into durable probes, rules, signatures, fixtures, and tests. That is covered in the deferred plan `docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md`.

Do not implement that broader artifact lifecycle before the first LLM-backed local triage slice.

## Repository Notes

- This directory is now a git repository; `git status --short` works.
- Current checked command: `npm test` passes 42 Node test cases.
- Current checked command: direct local `collectProcessEvidence({ limit: 3 })` returns ok on macOS with `ps -axo ...`.
- Current checked command: `npm run pack:dry-run` includes README plus runtime `tools/descartes-cli/src` files and excludes tests/local artifacts for v0.0.12.
- Current checked command: local tarball install via `npm pack --pack-destination "$tmp"` + `npm install -g --prefix "$tmp/prefix" "$pkg"` works; installed `descartes --help` and `descartes --version` work.
- Current checked command: `npm install -g --prefix "$tmp" github:Lightless-Labs/descartes` installs from the public GitHub repo without cloning; installed `descartes --help` and `descartes --version` work.
- Current checked command: installed `descartes triage "my machine is slow" --json` reaches the expected "No configured model credentials" error with isolated XDG paths when no login exists and creates only `$XDG_CONFIG_HOME/descartes/auth.json`.
- Current checked command: installed `descartes login test-provider --api-key` with isolated XDG writes credentials to `$XDG_CONFIG_HOME/descartes/auth.json`.
- Current checked command: `npm test` and local tarball API-key login still pass after the login UX fix; user re-tested normal OAuth browser login and confirmed the extra-Enter issue is resolved.
- Current checked command: `node tools/descartes-cli/src/index.js --help` works without importing Pi dependencies and documents `--model`, `--thinking`, and `--no-investigate`.
- Current checked command: direct `collectAllEvidence()` invocation returns three ok evidence envelopes on the local macOS host.
- Current checked command: direct `collectProcessEvidence`, `inspectProcessEvidence`, and `inspectParentTreeEvidence` invocations return ok envelopes on the local macOS host with bounded process args.
- Current checked command: direct `collectDiskEvidence()` invocation returns classified filesystem envelopes on local macOS; `/dev`, `map auto_home`, CoreSimulator runtime mounts, and MetalToolchain Cryptex mounts are not pressure-relevant, and derived disk findings no longer include them as critical pressure.
- Current field validation: v0.0.8 GitHub-installed JSON triage with ChatGPT/Codex called `collect_triage_evidence`, returned `fallback_used: false`, cited envelope IDs, and left `actions_taken: []`.
- Remaining validation gap: true Linux x86_64 behavior/CI. Linux arm64 validation with `$HOME/.local` prefix passes on public v0.0.11: install, symlinked `descartes --version`/`--help`, ChatGPT/Codex `--no-open` login, model-led guarded triage, `fallback_used: false`, `collect_triage_evidence`, `actions_taken: []`, and ok system/process/disk envelopes. v0.0.12 updates the harness dependency to `@earendil-works/pi-coding-agent` 0.75.3 and now requires Node.js 22.19.0+; rerun Linux validation after push. Process args are now redacted/bounded by default, so rerun validation should confirm that behavior on Linux too. The Linux todo uses a writable `--prefix`; future Buildkite validation should use scoped CI secrets rather than personal credentials where possible.
- Completed implementation: process args redaction/bounding plus `inspect_process` / `inspect_parent_tree`, and disk filesystem classification/noise reduction. Recommended next implementation is the no-evidence/no-diagnosis guard or temporal sampling.
- `materials/` exists locally but is ignored and should not be referenced in committed project docs.
- `nohup.out` exists locally and is ignored.
- `lynx` is installed and can be used for web docs via `lynx -dump`.

## Update Discipline

Update this file:

- before context compaction
- before handing off to another agent
- after completing a milestone
- after changing the plan direction
- after discovering important constraints or gotchas
