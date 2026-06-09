#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${DESCARTES_MACOS_NOTIFIER_BUILD_DIR:-$ROOT_DIR/.build/macos-notifier}"
RELEASE_DIR="$BUILD_ROOT/release"
APP_DIR="$BUILD_ROOT/DescartesNotifier.app"
ZIP_PATH="$RELEASE_DIR/DescartesNotifier.app.zip"
SHA_PATH="$ZIP_PATH.sha256"
TAG="${BUILDKITE_TAG:-}"
ALLOW_UNTAGGED="${DESCARTES_ALLOW_UNTAGGED_RELEASE:-}"

require_release_env() {
  local missing=()
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      missing+=("$name")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    printf 'error: missing required release environment variables:' >&2
    printf ' %s' "${missing[@]}" >&2
    printf '\n' >&2
    exit 2
  fi
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage:
  scripts/release-macos-notifier-buildkite.sh

Expected Buildkite secrets/environment:
  MACOS_DEVELOPER_ID_CERT_P12_BASE64
  MACOS_DEVELOPER_ID_CERT_PASSWORD
  APPLE_NOTARY_KEY_ID
  APPLE_NOTARY_ISSUER_ID
  APPLE_NOTARY_KEY_P8_BASE64

Optional override:
  CODESIGN_IDENTITY  Defaults to the first Developer ID Application identity imported from the p12.

Optional publication environment:
  GITHUB_TOKEN         Upload the zip/checksum to the matching GitHub Release when gh is installed.
  GITHUB_REPOSITORY    owner/repo override for gh, otherwise inferred from git remote.

This script is intended for tag-triggered Buildkite macOS jobs. It creates an
ephemeral keychain with a runtime-generated password, builds the notifier app,
signs/notarizes/staples/verifies it, writes a sha256 checksum, and uploads
Buildkite artifacts when buildkite-agent is available.
EOF
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macOS notifier releases must run on a macOS Buildkite agent" >&2
  exit 2
fi

if [[ -z "$TAG" && "$ALLOW_UNTAGGED" != "1" ]]; then
  echo "error: BUILDKITE_TAG is required for release builds; set DESCARTES_ALLOW_UNTAGGED_RELEASE=1 only for local dry runs" >&2
  exit 2
fi

if [[ -n "$TAG" && ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: release tag must look like vX.Y.Z: $TAG" >&2
  exit 2
fi

command -v node >/dev/null || { echo "error: node is required" >&2; exit 2; }
command -v base64 >/dev/null || { echo "error: base64 is required" >&2; exit 2; }
command -v security >/dev/null || { echo "error: security is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "error: openssl is required" >&2; exit 2; }
command -v shasum >/dev/null || { echo "error: shasum is required" >&2; exit 2; }

base64_decode() {
  if base64 --help 2>&1 | grep -q -- '--decode'; then
    base64 --decode
  else
    base64 -D
  fi
}

PACKAGE_VERSION="$(node -p "JSON.parse(require('fs').readFileSync('$ROOT_DIR/package.json', 'utf8')).version")"
if [[ -n "$TAG" && "${TAG#v}" != "$PACKAGE_VERSION" ]]; then
  echo "error: tag $TAG does not match package.json version $PACKAGE_VERSION" >&2
  exit 2
fi

require_release_env \
  MACOS_DEVELOPER_ID_CERT_P12_BASE64 \
  MACOS_DEVELOPER_ID_CERT_PASSWORD \
  APPLE_NOTARY_KEY_ID \
  APPLE_NOTARY_ISSUER_ID \
  APPLE_NOTARY_KEY_P8_BASE64

mkdir -p "$RELEASE_DIR"
KEYCHAIN_PATH="$BUILD_ROOT/descartes-signing.keychain-db"
CERT_PATH="$BUILD_ROOT/developer-id.p12"
NOTARY_KEY_PATH="$BUILD_ROOT/AuthKey_${APPLE_NOTARY_KEY_ID}.p8"
KEYCHAIN_PASSWORD="$(openssl rand -base64 48)"

cleanup() {
  security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
  rm -f "$CERT_PATH" "$NOTARY_KEY_PATH"
}
trap cleanup EXIT

printf '%s' "$MACOS_DEVELOPER_ID_CERT_P12_BASE64" | base64_decode > "$CERT_PATH"
printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | base64_decode > "$NOTARY_KEY_PATH"
chmod 0600 "$CERT_PATH" "$NOTARY_KEY_PATH"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security import "$CERT_PATH" -k "$KEYCHAIN_PATH" -P "$MACOS_DEVELOPER_ID_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

print_signing_diagnostics() {
  echo "Imported certificate names:" >&2
  security find-certificate -a -p "$KEYCHAIN_PATH" 2>/dev/null \
    | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null \
    | openssl pkcs7 -print_certs -noout -text 2>/dev/null \
    | sed -n 's/^ *Subject:.*CN=\([^,\/]*\).*/  - \1/p' >&2 || true
  echo "Codesigning identities visible to keychain:" >&2
  security find-identity -v -p codesigning "$KEYCHAIN_PATH" >&2 || true
}

if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
  CODESIGN_IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN_PATH" | sed -n 's/.*"\(Developer ID Application: .*\)".*/\1/p' | head -n 1)"
fi
if [[ -z "$CODESIGN_IDENTITY" ]]; then
  echo "error: no Developer ID Application signing identity found in imported p12" >&2
  echo "The p12 must contain both the Developer ID Application certificate and its private key; a downloaded .cer converted to p12 without the original private key will not work." >&2
  print_signing_diagnostics
  exit 2
fi

echo "Using codesign identity: $CODESIGN_IDENTITY"

DESCARTES_MACOS_NOTIFIER_BUILD_DIR="$BUILD_ROOT" \
DESCARTES_MACOS_NOTIFIER_VERSION="$PACKAGE_VERSION" \
"$ROOT_DIR/scripts/build-macos-notifier.sh"

CODESIGN_IDENTITY="$CODESIGN_IDENTITY" \
CODESIGN_KEYCHAIN="$KEYCHAIN_PATH" \
APPLE_NOTARY_KEY_PATH="$NOTARY_KEY_PATH" \
APPLE_NOTARY_KEY_ID="$APPLE_NOTARY_KEY_ID" \
APPLE_NOTARY_ISSUER_ID="$APPLE_NOTARY_ISSUER_ID" \
DESCARTES_MACOS_NOTIFIER_ARTIFACT_DIR="$RELEASE_DIR" \
"$ROOT_DIR/scripts/notarize-macos-notifier.sh" "$APP_DIR"

shasum -a 256 "$ZIP_PATH" > "$SHA_PATH"

if command -v buildkite-agent >/dev/null 2>&1; then
  buildkite-agent artifact upload "$ZIP_PATH"
  buildkite-agent artifact upload "$SHA_PATH"
fi

if [[ -n "${GITHUB_TOKEN:-}" && -n "$TAG" ]] && command -v gh >/dev/null 2>&1; then
  export GH_TOKEN="$GITHUB_TOKEN"
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    gh repo set-default "$GITHUB_REPOSITORY" >/dev/null
  fi
  gh release view "$TAG" >/dev/null 2>&1 || gh release create "$TAG" --title "$TAG" --notes "Descartes $TAG macOS notifier release"
  gh release upload "$TAG" "$ZIP_PATH" "$SHA_PATH" --clobber
fi

cat <<EOF
macOS notifier release artifact:
  $ZIP_PATH
sha256:
  $(cat "$SHA_PATH")
EOF
