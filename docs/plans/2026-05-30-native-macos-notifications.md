# Native macOS Notifications

**Created:** 2026-05-30
**Status:** In Progress
**Updated:** 2026-05-30 — initial native channel/config/adapter and Swift helper prototype implemented; real-host packaging/signing validation remains.

## Purpose

Move beyond the current macOS `osascript` notification adapter toward a native macOS notification helper that can eventually provide clearer branding, a stable bundle identity, and more predictable Notification Center permission behavior.

The current `osascript` path is acceptable as a conservative fallback, but permission attribution may attach to Terminal, the user's shell, or `osascript`. A native helper should make that platform caveat explicit and progressively replace the fallback where a packaged/signed helper is available.

## Safety Boundaries

- Notification delivery remains disabled by default.
- Native delivery must be explicitly selected/configured by the user.
- The helper receives only bounded notification payloads: title, body, severity, alert id, and rule id.
- No raw logs, process dumps, history dumps, credentials, or arbitrary evidence blobs are passed to the helper.
- No remediation/action authority.
- No arbitrary shell execution; the Node adapter may execute only a configured helper path with fixed arguments.
- Missing helper, permission denial, or platform errors must fail closed and produce local delivery audit records.

## Initial Implementation Slice

- Add a `macos-native` notification channel and CLI alias such as `--channel native`.
- Store an optional explicit helper path in Descartes notification config.
- Add fixed-argument Node adapter execution for the helper.
- Add local audit for missing-helper/unavailable/delivered/error outcomes.
- Add a checked-in Swift helper source prototype using `UserNotifications`.
- Keep `macos-desktop`/`osascript` as fallback until packaging/signing is solved.

## Future Packaging Work

- Decide packaging shape: signed helper app bundle, signed command-line helper, or LaunchServices-registered notification app.
- Determine bundle identifier and display name behavior for Notification Center.
- Add repeatable build/release packaging without hidden local build steps.
- Validate on real macOS hosts:
  - first-run permission prompt attribution;
  - Notification Center display name/icon;
  - behavior when notifications are denied;
  - behavior from daemon context vs interactive CLI context.

## Acceptance Criteria

- [x] Dedicated plan/todo exists before implementation.
- [x] `descartes alerts notifications setup --channel native --helper <path>` persists native helper config.
- [x] Native channel delivery uses a fixed executable path and fixed argument list.
- [x] Missing helper or non-macOS host fails closed with local audit, not daemon failure/spam.
- [x] Swift helper source prototype exists and accepts bounded fixed arguments.
- [x] Tests cover config normalization, CLI setup, missing-helper audit, and fixed native command invocation.
- [ ] Real-host macOS validation is documented before making native delivery the default macOS desktop channel.
