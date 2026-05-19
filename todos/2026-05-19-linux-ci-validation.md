---
title: Linux x86_64 CI Validation
created: 2026-05-19
status: open
priority: high
area: release
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-first-external-slice-validation.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
---

# TODO: Linux x86_64 CI Validation

## Summary

No Linux x86_64 host is currently available for first-slice validation. Defer Linux validation to a future CI setup, likely Buildkite.

## Goals

Validate the first-slice CLI on Linux x86_64:

- install/package behavior
- `descartes --help`
- `descartes --version`
- isolated-XDG no-auth triage failure
- read-only evidence collectors for system, processes, disks
- optional credentialed `descartes triage ... --json` when safe CI credentials are available

## CI Credential Notes

Prefer CI secrets scoped to Descartes validation only. Avoid committing or printing credentials. If using provider credentials:

- prefer a revocable API key or dedicated test account over a personal subscription OAuth token
- store secrets in Buildkite secret management / agent environment hooks
- ensure JSON logs are scrubbed before artifact upload
- do not upload full process args, hostnames, usernames, or raw diagnostic reports unless redacted

## Acceptance Criteria

- Buildkite job runs on Linux x86_64.
- Job verifies package install/help/version.
- Job verifies isolated XDG paths and no-auth failure behavior.
- Job verifies local collectors return structured envelopes or graceful `unable` evidence.
- If credentialed validation is enabled, job confirms `fallback_used: false`, guarded active tools, at least one Descartes tool call, and `actions_taken: []`.
