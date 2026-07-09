# macOS Release Validation Blocker Audit — 2026-07-09

## Scope

Authoritative local stop-condition audit for the remaining macOS notifier release-validation work. This record exists to distinguish completed local implementation/evidence-capture work from external validation that cannot be proved from this checkout/session.

## Repo state at audit time

- Descartes app repo at audit input time: clean on `main...origin/main`; latest commit `2c42627` (`docs: add tap bump validation template`).
- Homebrew tap repo at audit input time: clean on `main...origin/main`; latest commit `75e886f` (`descartes: remove unused clipboard addons`).
- Latest Descartes tag visible locally: `v0.0.47`.
- Current shell credential check:
  - `GITHUB_TOKEN`: absent
  - `HOMEBREW_TAP_GITHUB_TOKEN`: absent
  - `DOPPLER_TOKEN`: absent

## Implemented / locally evidenced

- `v0.0.47` release pipeline reached signed/notarized/stapled GitHub Release publication.
- Homebrew install/linkage/helper packaging validation passed after tap commit `75e886f`; see `docs/reviews/2026-07-09-homebrew-notifier-install-validation.md`.
- Real-host Part A evidence template exists at `docs/reviews/macos-notifier-real-host-validation-template.md`.
- First-tag Part B/token evidence template exists at `docs/reviews/macos-notifier-first-tag-tap-bump-validation-template.md`.
- Guided native-helper validation tooling exists at `scripts/validate-macos-notifier-helper.sh`, including the optional `--daemon-test` smoke harness.
- Token preflight tooling exists at `scripts/check-homebrew-tap-token.sh`.

## Remaining unproved requirements

These are not local implementation tasks. They require external state/evidence before the release-validation todo or goal can be closed:

1. **Real-host helper / Part A:** run on a suitable Mac with no prior grant or after TCC reset; prove first-run Notification Center prompt attribution, display, persistence, daemon-context native delivery, denied-path fail-closed audit behavior, and fallback delivery. Record results in a copied dated Part A review.
2. **Token confirmation:** run `scripts/check-homebrew-tap-token.sh` from a trusted token-bearing environment and prove the effective token can read and push/write `Lightless-Labs/homebrew-tap` without recording token values.
3. **First-tag chain / Part B:** on the next `vX.Y.Z` tag, observe the first live Buildkite release → GitHub Release → Homebrew tap-bump run, verify the tap commit updates URL version plus both sha256 values, and verify Homebrew upgrade/install pulls the new CLI and helper. Record results in a copied dated Part B review.

## Local stop condition

If the app repo and tap repo are clean, the latest tag is still `v0.0.47`, and no credential-bearing environment or suitable real-host validation evidence is available, there is no further local work to execute for this HANDOFF item. Do not mark the goal complete; wait for the external evidence above.
