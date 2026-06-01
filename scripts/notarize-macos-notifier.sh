#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${1:-${DESCARTES_MACOS_NOTIFIER_APP:-$ROOT_DIR/.build/macos-notifier/DescartesNotifier.app}}"
ARTIFACT_DIR="${DESCARTES_MACOS_NOTIFIER_ARTIFACT_DIR:-$ROOT_DIR/.build/macos-notifier/release}"
ZIP_PATH="$ARTIFACT_DIR/DescartesNotifier.app.zip"
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
CODESIGN_KEYCHAIN="${CODESIGN_KEYCHAIN:-}"
KEYCHAIN_PROFILE="${APPLE_NOTARY_KEYCHAIN_PROFILE:-}"
APPLE_NOTARY_KEY_PATH="${APPLE_NOTARY_KEY_PATH:-}"
APPLE_NOTARY_KEY_ID="${APPLE_NOTARY_KEY_ID:-}"
APPLE_NOTARY_ISSUER_ID="${APPLE_NOTARY_ISSUER_ID:-}"
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"

usage() {
  cat <<'EOF'
Usage:
  CODESIGN_IDENTITY="Developer ID Application: ..." \
  APPLE_NOTARY_KEYCHAIN_PROFILE="descartes-notary" \
  scripts/notarize-macos-notifier.sh [DescartesNotifier.app]

Preferred CI notary credentials:
  APPLE_NOTARY_KEY_PATH, APPLE_NOTARY_KEY_ID, APPLE_NOTARY_ISSUER_ID

Alternative notary credentials:
  APPLE_ID, APPLE_TEAM_ID, APPLE_APP_SPECIFIC_PASSWORD

The script signs with hardened runtime, zips the app, submits it with xcrun notarytool,
staples the ticket, and verifies the stapled app with Gatekeeper.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macOS notarization must run on macOS" >&2
  exit 2
fi

[[ -d "$APP_DIR" ]] || { echo "error: app bundle not found: $APP_DIR" >&2; exit 2; }
[[ -n "$CODESIGN_IDENTITY" ]] || { echo "error: CODESIGN_IDENTITY is required" >&2; exit 2; }
command -v codesign >/dev/null || { echo "error: codesign is required" >&2; exit 2; }
command -v xcrun >/dev/null || { echo "error: xcrun is required" >&2; exit 2; }
command -v spctl >/dev/null || { echo "error: spctl is required" >&2; exit 2; }
command -v ditto >/dev/null || { echo "error: ditto is required" >&2; exit 2; }

mkdir -p "$ARTIFACT_DIR"

codesign_args=(--force --timestamp --options runtime --sign "$CODESIGN_IDENTITY")
if [[ -n "$CODESIGN_KEYCHAIN" ]]; then
  codesign_args+=(--keychain "$CODESIGN_KEYCHAIN")
fi
codesign "${codesign_args[@]}" "$APP_DIR"
codesign --verify --deep --strict --verbose=2 "$APP_DIR"

rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP_DIR" "$ZIP_PATH"

if [[ -n "$APPLE_NOTARY_KEY_PATH" && -n "$APPLE_NOTARY_KEY_ID" && -n "$APPLE_NOTARY_ISSUER_ID" ]]; then
  xcrun notarytool submit "$ZIP_PATH" --key "$APPLE_NOTARY_KEY_PATH" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID" --wait
elif [[ -n "$KEYCHAIN_PROFILE" ]]; then
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$KEYCHAIN_PROFILE" --wait
elif [[ -n "$APPLE_ID" && -n "$APPLE_TEAM_ID" && -n "$APPLE_APP_SPECIFIC_PASSWORD" ]]; then
  xcrun notarytool submit "$ZIP_PATH" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" --wait
else
  echo "error: set APPLE_NOTARY_KEY_PATH/APPLE_NOTARY_KEY_ID/APPLE_NOTARY_ISSUER_ID, APPLE_NOTARY_KEYCHAIN_PROFILE, or APPLE_ID/APPLE_TEAM_ID/APPLE_APP_SPECIFIC_PASSWORD" >&2
  exit 2
fi

xcrun stapler staple "$APP_DIR"
xcrun stapler validate "$APP_DIR"
spctl --assess --type execute --verbose=4 "$APP_DIR"

# Publish the stapled app, not the pre-staple submission zip.
rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP_DIR" "$ZIP_PATH"

cat <<EOF
Notarized macOS notifier app:
  $APP_DIR
Stapled release artifact:
  $ZIP_PATH
EOF
