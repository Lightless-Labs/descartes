---
title: First External Slice Validation and Release Readiness
created: 2026-05-19
status: open
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

- [ ] Fresh install from GitHub works without cloning:
  - `npm install -g github:Lightless-Labs/descartes`
  - installed `descartes --help` works
  - installed `descartes --version` matches `package.json`
- [ ] `npm pack --dry-run` includes expected runtime files and excludes local/generated artifacts.
- [ ] Root package and nested CLI package metadata do not drift in version, engine requirements, or entrypoint semantics.

### Auth / paths / Pi boundary

- [ ] With isolated XDG paths and no auth, `descartes triage ... --json` fails with the expected Descartes-owned "No configured model credentials" error.
- [ ] `descartes login` stores auth/config only under Descartes-owned XDG paths.
- [ ] No command reads, writes, imports, or relies on `~/.pi`, project `.pi`, Pi sessions, Pi settings, Pi auth, Pi skills, Pi prompts, Pi themes, or Pi model config.
- [ ] Private harness starts with only explicit Descartes resources/tools.

### Triage behavior

- [ ] `descartes triage "my machine is slow"` returns a human evidence-cited diagnosis and ends with "No actions were taken."
- [ ] `descartes triage "my machine is slow" --json` returns diagnosis, evidence, findings, diagnostics, tool traces, and empty `actions_taken`.
- [ ] JSON diagnostics include selected model, thinking level, active tools, tool calls/results/errors, assistant stop reason, LLM error when present, and fallback state.
- [ ] Active tools are exactly the guarded Descartes read-only tool set.
- [ ] `--no-investigate` remains a temporary degraded no-tool synthesis escape hatch and is documented as such if kept.
- [ ] Fallback remains clearly marked degraded mode when no assistant text is returned.

### Platforms

- [ ] macOS Apple Silicon passes the full validation flow with at least one subscription provider.
- [ ] Linux x86_64 either passes the full validation flow or gracefully reports unsupported/unavailable evidence without panics.
- [ ] macOS Intel and Linux ARM64 are documented as best effort.

### Documentation

- [ ] README accurately describes the current Node.js/JavaScript first slice and long-term Rust direction.
- [ ] README documents install, login, triage, JSON output, model/thinking overrides, `--no-investigate` if retained, supported platforms, limitations, safety, XDG paths, and Pi boundary.
- [ ] Plan/handoff reflects that the LLM-driven tool loop is complete and release validation is the immediate next task.

## Acceptance Criteria

This todo is complete when the first external slice can be considered shippable according to `docs/plans/2026-05-18-003-first-external-slice-local-triage.md`, with any remaining gaps explicitly documented as release blockers or known limitations.
