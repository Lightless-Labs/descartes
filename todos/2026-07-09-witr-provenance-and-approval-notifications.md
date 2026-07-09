---
title: Witr-Inspired Provenance and Notification Approval Gates
created: 2026-07-09
status: open
priority: medium
area: provenance, approvals, notifications
kind: todo
owner: unassigned
related:
  - docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md
  - docs/plans/2026-05-30-native-macos-notifications.md
  - docs/plans/2026-05-18-003-first-external-slice-local-triage.md
  - todos/2026-07-08-macos-release-validation.md
---

# TODO: Witr-Inspired Provenance and Notification Approval Gates

## Summary

Research into `pranshuparmar/witr` is documented in
`docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md`. The plan has two
tracks:

1. Borrow Witr's process/port/container provenance patterns for Descartes L0/L1 tools.
2. Explore notifications as a user approval surface for risky actions, while keeping the
   authority in a persisted approval store with CLI/TUI fallback.

Do **not** add Witr as a hard library dependency yet: its useful implementation packages
are mostly Go `internal/...`. Realistic reuse is pattern borrowing, an optional bounded
`witr --json` shellout, or a fork/vendor path with Apache-2.0 attribution if future work
justifies it.

## Acceptance criteria

- [ ] **Provenance schema:** define a Descartes evidence-envelope shape for process,
      port, container, and service provenance, including source classification,
      warnings, missing-permission hints, and trace metadata.
- [ ] **Existing collector mapping:** map the schema to current collectors
      (`inspect_process`, `inspect_parent_tree`, `collect_network_basics`,
      `collect_services`, `collect_containers`, `collect_vms`) before adding new tools.
- [ ] **Listener-to-process prototype:** add or deepen a deterministic L0 path for
      `port -> process -> source` with fixture tests for Linux socket parsing and bounded
      macOS command fallback.
- [ ] **Source classifier:** implement deterministic classification for systemd,
      launchd, shell, SSH, cron/timer, supervisor, container, init, and unknown, with
      confidence/review hints.
- [ ] **Optional Witr shellout decision:** if used, treat Witr as third-party evidence:
      capture `witr --version`, command args, exit code, latency, bounded stdout/stderr;
      accept exit code 1 as warning-bearing JSON; parse tolerantly because Witr JSON has
      no schema/version wrapper.
- [ ] **Approval store design:** define persisted approval requests with id, nonce, risk
      class, requested action, bounded summary, evidence refs, expiry, deny-by-default,
      and append-only audit transitions.
- [ ] **Approval CLI fallback:** design or implement `descartes approvals
      list/show/respond <id> --nonce <nonce> --approve|--deny` before relying on
      notification responses.
- [ ] **Notification approval prompt:** send bounded approval notifications that point to
      the CLI/TUI fallback; never send raw logs, secrets, or unrestricted evidence blobs.
- [ ] **Native action spike:** only after real-host validation, prototype macOS action
      buttons/inline responses; callbacks may write approval decisions only after
      id/nonce validation, and executors must still read the authority store.
- [ ] **Risk-tier policy:** destructive or irreversible actions require explicit CLI/TUI
      confirmation; notification actions, if validated, are limited to reversible or
      lower-risk approvals.

## Notes

- Witr does not solve Wi-Fi/router diagnostics; keep that as a separate network-state
  collector track.
- Notifications are a convenience/attention surface, not proof that a user saw or
  approved anything.
- Missing notification permissions, focus mode, timeout, ambiguous response, stale nonce,
  or delivery failure must all resolve to no approval.
