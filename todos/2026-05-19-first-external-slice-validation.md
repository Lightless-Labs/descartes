---
title: First External Slice Validation and Release Readiness
created: 2026-05-19
status: in_progress
priority: immediate
area: release
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
  - todos/2026-05-19-llm-driven-investigation-tools.md
---

# TODO: First External Slice Validation and Release Readiness

## Summary

The LLM-backed local triage loop has now worked in a real macOS Anthropic subscription-auth field test. The highest-impact next step is not adding more collectors; it is validating and tightening the first external slice against the current plan's shippability criteria.

This todo tracks the release-readiness pass for the installable `descartes` CLI.

## Why This Is Next

The current plan is explicitly about shipping the first installable LLM-backed local triage slice. New tools like process inspection and temporal sampling are valuable next product work, but the current slice should first be made reliably installable, documentable, and verifiable.

## Validation Checklist

### Packaging / install

- [x] Fresh install from GitHub works without cloning:
  - `npm install -g github:Lightless-Labs/descartes`
  - installed `descartes --help` works
  - installed `descartes --version` matches `package.json`
- [x] `npm pack --dry-run` includes expected runtime files and excludes local/generated artifacts.
- [x] Root package and nested CLI package metadata do not drift in version, engine requirements, or entrypoint semantics.

### Auth / paths / Pi boundary

- [x] With isolated XDG paths and no auth, `descartes triage ... --json` fails with the expected Descartes-owned "No configured model credentials" error.
- [x] `descartes login` stores auth/config only under Descartes-owned XDG paths. Validated with the API-key path; subscription OAuth was previously field-tested with Anthropic under Descartes-owned config.
- [x] No command reads, writes, imports, or relies on `~/.pi`, project `.pi`, Pi sessions, Pi settings, Pi auth, Pi skills, Pi prompts, Pi themes, or Pi model config. Covered by path tests and explicit private harness resource overrides.
- [x] Private harness starts with only explicit Descartes resources/tools.

### Triage behavior

- [x] `descartes triage "my machine is slow"` returns a human evidence-cited diagnosis and ends with "No actions were taken." Validated with current GitHub-installed package and ChatGPT/Codex subscription auth.
- [x] `descartes triage "my machine is slow" --json` returns diagnosis, evidence, findings, diagnostics, tool traces, and empty `actions_taken`. Validated with current GitHub-installed package and ChatGPT/Codex subscription auth.
- [x] JSON diagnostics include selected model, thinking level, active tools, tool calls/results/errors, assistant stop reason, LLM error when present, and fallback state.
- [x] Active tools are exactly the guarded Descartes read-only tool set.
- [x] `--no-investigate` remains a temporary degraded no-tool synthesis escape hatch and is documented as such if kept.
- [x] Fallback remains clearly marked degraded mode when no assistant text is returned.

### Platforms

- [x] macOS Apple Silicon passes the full validation flow with at least one subscription provider. Previously validated with Anthropic Sonnet and guarded Descartes tool calls.
- [ ] Linux x86_64 either passes the full validation flow or gracefully reports unsupported/unavailable evidence without panics.
- [x] macOS Intel and Linux ARM64 are documented as best effort.

### Documentation

- [x] README accurately describes the current Node.js/JavaScript first slice and long-term Rust direction.
- [x] README documents install, login, triage, JSON output, model/thinking overrides, `--no-investigate` if retained, supported platforms, limitations, safety, XDG paths, and Pi boundary.
- [x] Plan/handoff reflects that the LLM-driven tool loop is complete and release validation is the immediate next task.

## Validation Notes

2026-05-19 release-readiness pass:

- `npm test` passes 25 Node test cases, including package metadata drift and CLI help/version checks.
- `npm pack --dry-run` includes README plus runtime `tools/descartes-cli/src` files and excludes tests/local artifacts.
- Local tarball install via `npm pack` + `npm install -g --prefix "$tmp"` works; installed `descartes --help` and `descartes --version` work.
- GitHub install via `npm install -g github:Lightless-Labs/descartes` works for the currently published branch state; installed help/version work.
- Isolated-XDG no-auth triage from the installed tarball exits with the expected Descartes-owned credentials error and creates only `$XDG_CONFIG_HOME/descartes/auth.json`.
- `descartes login test-provider --api-key` with isolated XDG writes credentials to `$XDG_CONFIG_HOME/descartes/auth.json`.
- User field report found normal subscription OAuth left a pending manual paste prompt after browser success, requiring an extra Enter. Fixed by only enabling manual paste mode for `descartes login --no-open`; normal login now waits on browser callback and documents the `--no-open` fallback.
- Direct `collectAllEvidence()` invocation on local macOS returns ok envelopes for `system-overview`, `top-processes`, and `disk-usage`, with `actions_taken: []`.
- Current GitHub-installed `descartes triage "my machine is slow"` with ChatGPT/Codex subscription auth returned a useful non-fallback human diagnosis, cited local evidence, and ended with `No actions were taken.`
- Current GitHub-installed `descartes triage "my machine is slow" --json` returned `fallback_used: false`, selected `openai-codex/gpt-5.5` with high thinking, active tools exactly matching the guarded Descartes tool set, three ok precollected evidence envelopes, findings/tool traces, and `actions_taken: []`. The model did not make additional tool calls because the compact precollected evidence was sufficient; prior Anthropic validation covered the explicit tool-call path.
- Field output showed JSON `evidence_refs` could cite compact summary keys (`top_cpu`, `top_memory`) rather than envelope IDs. Prompt instructions were tightened to require only evidence envelope IDs.
- Temporary follow-up change: normal `triage` no longer precollects evidence before the LLM turn, forcing the model to use guarded Descartes evidence tools. `--no-investigate` still precollects deterministic evidence for degraded no-tool synthesis.

## Acceptance Criteria

This todo is complete when the first external slice can be considered shippable according to `docs/plans/2026-05-18-003-first-external-slice-local-triage.md`, with any remaining gaps explicitly documented as release blockers or known limitations.
