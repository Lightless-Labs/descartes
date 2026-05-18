# Descartes Handoff

**Last updated:** 2026-05-18

## Current Status

Descartes has an initial first-slice CLI scaffold, but it is not yet end-to-end validated with installed dependencies and real auth.

Existing files:

- `README.md` — updated to describe the LLM-backed local triage first slice and Pi/XDG boundaries.
- `AGENTS.md` — operating instructions for coding agents.
- `.gitignore` — excludes local reference material, logs, Rust build output, Node package output, and OS noise.
- `package.json` — root npm package so end users can install with `npm install -g github:Lightless-Labs/descartes` without cloning.
- `tools/descartes-cli/` — initial npm-style Descartes CLI scaffold.
  - `src/paths.js` resolves Descartes-owned XDG paths and rejects Pi-owned paths.
  - `src/tools/` contains read-only evidence collectors for system overview, processes, disks, deterministic findings, and a combined triage bundle.
  - `src/pi-harness.js` wraps Pi SDK session creation with Descartes-owned auth/model paths, no default resource discovery, no built-in coding tools, and only explicit Descartes evidence tools.
  - `src/login.js` implements a first terminal OAuth/API-key login path storing under Descartes config.
  - `src/triage.js` implements human and JSON triage prompts around the private harness.
  - `test/` covers XDG path resolution, Pi-path guardrails, and deterministic finding thresholds.
- `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` — **current implementation plan**, now in progress.
- `docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md` — deferred broader product direction.
- `docs/plans/2026-05-18-002-descartes-bootstrap-kernel-and-workbench-plan.md` — superseded; do not implement this first.

## Start Here In A New Session

1. Read `README.md`, `AGENTS.md`, and this handoff.
2. Treat `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` as the current source of truth.
3. Do **not** start with the artifact lifecycle, Pi workbench, deterministic-only triage, keyword matching, or a Cargo-only CLI unless the harness/package decision has been revisited.
4. The immediate implementation question is: what is the smallest installable `descartes` CLI that can run an LLM-backed private agent session, collect local read-only evidence, and answer `descartes triage "my machine is slow"` without requiring or touching the user's Pi setup?

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

Continue the focused harness spike from the new `tools/descartes-cli/` scaffold:

1. Validate install from the public repo on a clean machine: `npm install -g github:Lightless-Labs/descartes`.
2. Validate that `descartes login` works with at least one subscription provider and writes only to `$XDG_CONFIG_HOME/descartes/auth.json` (or the default XDG config path).
3. Validate that `descartes triage "my machine is slow"` starts a private Pi SDK agent with only Descartes evidence tools and returns an evidence-cited answer.
4. Add an integration test or harness-level fake around `createPrivateTriageSession` to assert active tools are exactly Descartes evidence tools.
5. Improve JSON-mode robustness so final diagnosis is guaranteed structured, not merely prompt-requested JSON.
6. Add tests for renderer requirements: diagnosis, evidence citations, safe next checks, and `No actions were taken.`
7. Decide whether the first package stays JavaScript/Node, moves to TypeScript, or wraps a Rust collector component.
8. Update README with exact install command after packaging is chosen.
9. Update this handoff before stopping.

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
- Current checked command: `npm test` passes 7 Node test cases.
- Current checked command: `npm install -g --prefix "$tmp" github:Lightless-Labs/descartes` installs from the public GitHub repo without cloning; installed `descartes --help` and `descartes --version` work.
- Current checked command: GitHub-installed `descartes triage "my machine is slow" --json` reaches the expected "No configured model credentials" error with isolated XDG paths when no login exists.
- Current checked command: `node tools/descartes-cli/src/index.js --help` works without importing Pi dependencies.
- Current checked command: direct `collectAllEvidence()` invocation returns three ok evidence envelopes on the local macOS host.
- Full `descartes login` / `descartes triage` end-to-end flow has not been validated because local package dependencies/auth were not installed/configured in this repo.
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
