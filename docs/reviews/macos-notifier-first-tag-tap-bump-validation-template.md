# macOS Notifier First-Tag Tap-Bump Validation — TEMPLATE

Copy this file to `docs/reviews/YYYY-MM-DD-macos-notifier-first-tag-tap-bump-validation.md` when validating Part B and token confirmation from `macos-notifier-release-validation-brief.md`. Do not record token values, bearer headers, raw secrets, hostnames that are not already public CI identifiers, or unsanitized CI logs.

## Scope

Validation of the first live `vX.Y.Z` release after Homebrew tap auto-bump support landed. This is the evidence record for token preflight, Buildkite release execution, GitHub Release publication, Homebrew tap formula bump, and end-user Homebrew upgrade/install behavior.

## Environment

- Date:
- Release tag:
- Descartes commit for tag:
- `package.json` version:
- Buildkite build URL / number:
- Homebrew tap repo before commit:
- Homebrew tap repo after commit:
- Token source reported by preflight: `GITHUB_TOKEN` / `GITHUB_TOKEN from Doppler` / `HOMEBREW_TAP_GITHUB_TOKEN` / `HOMEBREW_TAP_GITHUB_TOKEN from Doppler` / other:
- Token source observed in the successful CI tap bump, if visible without exposing secrets:
- Validation host class/model/arch for end-user Homebrew check, no hostname:

## Commands / Evidence

Record exact commands and summarized results. Prefer public build/release/tap URLs plus scrubbed excerpts over pasted logs. Never paste token values.

- Version bump commit:
- Tag creation and push command:
- Token preflight command and OK/error summary:
- Buildkite release job URL:
- GitHub Release URL:
- Tap bump commit URL:
- Tap bump commit SHA:
- Formula diff URL:
- End-user Homebrew install/upgrade command:
- Brewed CLI path and version:
- Helper packaging/signature check, if repeated:

## Checklist

### Token preflight before tagging

- [ ] `scripts/check-homebrew-tap-token.sh` ran in a trusted token-bearing environment before the tag was pushed.
- [ ] The preflight reported that the effective token can read `Lightless-Labs/homebrew-tap/Formula/descartes.rb`.
- [ ] The preflight reported push/write permission on `Lightless-Labs/homebrew-tap`.
- [ ] The review records only the token source, never the token value.
- [ ] The successful CI tap bump reused `GITHUB_TOKEN` or `GITHUB_TOKEN from Doppler`; if a dedicated `HOMEBREW_TAP_GITHUB_TOKEN` was required instead, this review explicitly marks token confirmation as a gap or records the operator-approved deviation from the no-separate-secret acceptance path.
- [ ] Any preflight failure was resolved before tagging, or the release was intentionally blocked.

### Tag and Buildkite release chain

- [ ] `package.json` version matches the release tag.
- [ ] The `vX.Y.Z` tag points at the intended Descartes commit.
- [ ] Buildkite ran the tag-triggered `release-macos-notifier` job.
- [ ] The job built `DescartesNotifier.app` successfully.
- [ ] Code signing selected a valid Developer ID Application identity.
- [ ] Notarization completed with status `Accepted`.
- [ ] Stapling succeeded.
- [ ] Gatekeeper assessment reported a notarized Developer ID source.
- [ ] Buildkite uploaded `DescartesNotifier.app.zip` and `DescartesNotifier.app.zip.sha256` artifacts.
- [ ] GitHub Release for the tag was created or updated with both helper assets.

### Homebrew tap bump

- [ ] Release logs show the tap bump ran after GitHub Release publication.
- [ ] Release logs include the successful bump line for `Lightless-Labs/homebrew-tap/Formula/descartes.rb`.
- [ ] A `descartes: update to X.Y.Z` commit exists in `Lightless-Labs/homebrew-tap`.
- [ ] The exact tap commit SHA and formula diff URL are recorded.
- [ ] The formula source tarball URL was updated to the new tag.
- [ ] The formula helper zip URL was updated to the new tag.
- [ ] The formula source tarball sha256 changed to the new release checksum.
- [ ] The formula helper zip sha256 changed to the new helper checksum.
- [ ] No manual tap edit was needed; or, if manual fallback was used, this review clearly states why and records the manual commit.

### End-user Homebrew validation

- [ ] `brew update` plus `brew upgrade descartes`, or a fresh `brew install lightless-labs/tap/descartes`, pulled the new version.
- [ ] The validated executable was the brewed path, for example `/opt/homebrew/bin/descartes`, not an npm-global shim.
- [ ] `descartes --version` matched the release tag.
- [ ] The installed keg contains the version-matched `DescartesNotifier.app` helper.
- [ ] Helper signature/staple/Gatekeeper checks were repeated, or this review links to a same-version helper packaging validation record.

### Retag / draft-release hygiene, if applicable

- [ ] If the tag was deleted/recreated during validation, orphaned draft releases were checked and cleaned up.
- [ ] The final GitHub Release is the live release for the tag.

## Observations

### Token preflight

- Result:
- Token source reported by preflight, not value:
- Token source observed in CI tap bump, not value:
- Gaps, deviations, or remediation:

### Buildkite release

- Build result:
- Signing/notarization/stapling result:
- Artifact summary:

### GitHub Release

- Release URL:
- Asset summary:
- Draft/retag notes:

### Tap bump

- Tap commit:
- Formula diff URL:
- Formula URL/version changes:
- Formula checksum changes:
- Release log excerpt, scrubbed:

### End-user Homebrew check

- Install/upgrade result:
- Brewed CLI version:
- Helper packaging result:

## Conclusion

- [ ] Part B and token confirmation accepted: all required evidence above is present. Fill this only in the copied dated review, not in this template.
- [ ] Part B and/or token confirmation not accepted yet: gaps listed below. Fill this only in the copied dated review, not in this template.

Open gaps:

- TBD

Follow-ups:

- TBD
