# macOS Notifier Real-Host Validation — TEMPLATE

Copy this file to `docs/reviews/YYYY-MM-DD-macos-notifier-real-host-validation.md` when running Part A from `macos-notifier-release-validation-brief.md`. Keep raw logs/screenshots out of git unless they are scrubbed and intentionally curated; summarize sensitive host details.

## Scope

Validation of the Homebrew-delivered, signed/notarized `DescartesNotifier.app` on a real macOS user session. This is the evidence record for first-run Notification Center/TCC behavior, daemon-context delivery, denied-permission behavior, and fallback delivery.

## Environment

- Date:
- Host model / macOS version:
- User session type: interactive console / remote desktop / other:
- Descartes formula/version:
- `command -v descartes`:
- `descartes --version`:
- Prior Descartes notifier grant? yes / no / reset before run:
- Bundle identifier: `com.bande-a-bonnot.lightless-labs.descartes.macos.notifier`

## Commands / Evidence

Record exact commands and summarized results. Prefer scrubbed relative paths or short summaries of local JSON/audit files over pasted raw logs or absolute user/machine-specific paths.

- Homebrew install or upgrade command:
- npm-global shim check / removal, if needed:
- Guided runner command, if used:
- Native setup command, if run manually:
- Helper path resolved:
- Code-signature validation result:
- Stapled-ticket validation result:
- Gatekeeper assessment result:
- Notification delivery audit file path or scrubbed summary:

## Checklist

### Helper identity and packaging

- [ ] `descartes` resolves to the Homebrew CLI, not an older npm-global shim.
- [ ] The installed version is `0.0.47` or newer.
- [ ] Native setup resolves the bundled helper with no `--helper` flag, or the guided runner derives the bundled helper for v0.0.47.
- [ ] Helper path is inside the Homebrew keg.
- [ ] `codesign --verify --deep --strict` succeeds for `DescartesNotifier.app`.
- [ ] `xcrun stapler validate` succeeds for `DescartesNotifier.app`.
- [ ] `spctl --assess --type execute` accepts `DescartesNotifier.app`.

### First-run Notification Center / TCC behavior

- [ ] TCC notification permission was reset or the host had no prior grant.
- [ ] First delivery attempt showed a Notification Center permission prompt.
- [ ] Prompt attribution was `DescartesNotifier`, not Terminal or osascript.
- [ ] After granting, the notification displayed with expected title/body/severity.
- [ ] A second delivery attempt in the same shell did not re-prompt.
- [ ] Grant persisted across a fresh CLI invocation from a new shell session.
- [ ] Host restart persistence result recorded, if tested.

### Daemon-context delivery

- [ ] Native delivery was exercised from a background/launchd context.
- [ ] Review states whether this was the full alert-intelligence daemon path or the guided runner's narrower `--daemon-test` LaunchAgent smoke.
- [ ] Daemon-context delivery displayed a notification.
- [ ] `notification-delivery.jsonl` records `delivery.status: "delivered"` for the daemon-context attempt.

### Denied-permission and fallback behavior

- [ ] Permission was reset and denied, or an equivalent denied state was confirmed.
- [ ] Native delivery failed closed when permission was denied.
- [ ] `notification-delivery.jsonl` records the denied/error result.
- [ ] The `osascript` / `macos-desktop` fallback channel still displayed a notification.

## Observations

### First-run prompt

- Prompt appeared? yes / no:
- Prompt attribution:
- Screenshot/reference, if curated:

### Notification display

- Interactive native display result:
- Second-run persistence result:
- Restart/new-shell persistence result:

### Daemon-context result

- Harness used: full alert-intelligence daemon / guided `--daemon-test` / other:
- Display result:
- Audit record summary:

### Denied path / fallback result

- Denied native result:
- Audit record summary:
- Fallback channel result:

## Conclusion

- [ ] Part A accepted: all required evidence above is present. Fill this only in the copied dated review, not in this template.
- [ ] Part A not accepted yet: gaps listed below. Fill this only in the copied dated review, not in this template.

Open gaps:

- TBD

Follow-ups:

- TBD
