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

Expected release environment, either already set or fetched from Doppler when DOPPLER_TOKEN is present:
  MACOS_DEVELOPER_ID_CERT_P12_BASE64
  MACOS_DEVELOPER_ID_CERT_PASSWORD
  APPLE_NOTARY_KEY_ID
  APPLE_NOTARY_ISSUER_ID
  APPLE_NOTARY_KEY_P8_BASE64

Doppler defaults used when DOPPLER_TOKEN is present:
  DOPPLER_PROJECT=lightless-labs-descartes
  DOPPLER_CONFIG=prd_notarisation

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

fetch_release_secret_from_doppler() {
  local name="$1"
  if [[ -z "${DOPPLER_TOKEN:-}" || -n "${!name:-}" ]]; then
    return 0
  fi
  command -v python3 >/dev/null || { echo "error: DOPPLER_TOKEN is set but python3 is unavailable for Doppler REST fetch" >&2; exit 2; }
  local project="${DOPPLER_PROJECT:-lightless-labs-descartes}"
  local config="${DOPPLER_CONFIG:-prd_notarisation}"
  local value
  if ! value="$(DOPPLER_BOOTSTRAP_TOKEN="$DOPPLER_TOKEN" DOPPLER_PROJECT_NAME="$project" DOPPLER_CONFIG_NAME="$config" DOPPLER_SECRET_NAME="$name" python3 <<'PY'
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

name = os.environ.get("DOPPLER_SECRET_NAME", "")
token = os.environ.get("DOPPLER_BOOTSTRAP_TOKEN", "")
project = os.environ.get("DOPPLER_PROJECT_NAME", "")
config = os.environ.get("DOPPLER_CONFIG_NAME", "")
if not name or not token or not project or not config:
    print("missing Doppler fetch environment", file=sys.stderr)
    sys.exit(2)

auth = base64.b64encode(f"{token}:".encode()).decode()
qs = urllib.parse.urlencode({"project": project, "config": config, "name": name})
req = urllib.request.Request(
    f"https://api.doppler.com/v3/configs/config/secret?{qs}",
    headers={
        "Authorization": f"Basic {auth}",
        "Accept": "application/json",
        "User-Agent": "descartes-macos-notifier-release/1",
    },
)
try:
    with urllib.request.urlopen(req, timeout=20) as res:
        payload = json.load(res)
except urllib.error.HTTPError as exc:
    body = exc.read(300).decode(errors="replace")
    print(f"Doppler read failed for {name}: HTTP {exc.code}: {body}", file=sys.stderr)
    sys.exit(2)
except Exception as exc:
    print(f"Doppler read failed for {name}: {exc}", file=sys.stderr)
    sys.exit(2)

value = payload.get("value", {})
if isinstance(value, dict):
    secret_value = value.get("computed") or value.get("raw") or value.get("value")
else:
    secret_value = value
if not isinstance(secret_value, str) or not secret_value:
    print(f"Doppler read returned no value for {name}", file=sys.stderr)
    sys.exit(2)
print(secret_value, end="")
PY
)"; then
    echo "error: failed to fetch Doppler release secret: $name" >&2
    exit 2
  fi
  if [[ -z "$value" ]]; then
    echo "error: Doppler release secret is empty: $name" >&2
    exit 2
  fi
  printf -v "$name" '%s' "$value"
  export "$name"
}

fetch_release_secrets_from_doppler() {
  fetch_release_secret_from_doppler MACOS_DEVELOPER_ID_CERT_P12_BASE64
  fetch_release_secret_from_doppler MACOS_DEVELOPER_ID_CERT_PASSWORD
  fetch_release_secret_from_doppler APPLE_NOTARY_KEY_ID
  fetch_release_secret_from_doppler APPLE_NOTARY_ISSUER_ID
  fetch_release_secret_from_doppler APPLE_NOTARY_KEY_P8_BASE64
  unset DOPPLER_TOKEN
}

base64_decode() {
  if base64 --help 2>&1 | grep -q -- '--decode'; then
    base64 --decode
  else
    base64 -D
  fi
}

sync_guest_clock() {
  echo "Guest UTC before time sync: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if command -v sntp >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    sudo -n sntp -sS time.apple.com >/dev/null 2>&1 || true
  fi
  if command -v systemsetup >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    sudo -n systemsetup -setusingnetworktime on >/dev/null 2>&1 || true
  fi
  echo "Guest UTC after time sync: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}

print_decoded_signing_certificate_diagnostics() {
  echo "Decoded Developer ID p12 sha256: $(shasum -a 256 "$CERT_PATH" | awk '{print $1}')"
  echo "Decoded Developer ID certificate diagnostics:"
  local cert_pem="$BUILD_ROOT/developer-id-cert.pem"
  local pass_file="$BUILD_ROOT/developer-id-cert-password.txt"
  printf '%s' "$MACOS_DEVELOPER_ID_CERT_PASSWORD" > "$pass_file"
  chmod 0600 "$pass_file"
  if openssl pkcs12 -in "$CERT_PATH" -passin "file:$pass_file" -nokeys -clcerts -out "$cert_pem" >/dev/null 2>&1; then
    openssl x509 -in "$cert_pem" -noout -subject -issuer -dates -fingerprint -sha1 || true
  else
    echo "warning: unable to extract decoded Developer ID certificate diagnostics" >&2
  fi
  rm -f "$cert_pem" "$pass_file"
}

PACKAGE_VERSION="$(node -p "JSON.parse(require('fs').readFileSync('$ROOT_DIR/package.json', 'utf8')).version")"
if [[ -n "$TAG" && "${TAG#v}" != "$PACKAGE_VERSION" ]]; then
  echo "error: tag $TAG does not match package.json version $PACKAGE_VERSION" >&2
  exit 2
fi

fetch_release_secrets_from_doppler

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
ORIGINAL_DEFAULT_KEYCHAIN="$(security default-keychain -d user 2>/dev/null | tr -d '"' || true)"
ORIGINAL_USER_KEYCHAINS="$(security list-keychains -d user 2>/dev/null | tr -d '"' || true)"

restore_user_keychain_settings() {
  if [[ -n "$ORIGINAL_DEFAULT_KEYCHAIN" ]]; then
    security default-keychain -d user -s "$ORIGINAL_DEFAULT_KEYCHAIN" >/dev/null 2>&1 || true
  fi
  if [[ -n "$ORIGINAL_USER_KEYCHAINS" ]]; then
    local keychains=()
    local keychain
    while IFS= read -r keychain; do
      [[ -n "$keychain" ]] && keychains+=("$keychain")
    done <<< "$ORIGINAL_USER_KEYCHAINS"
    if (( ${#keychains[@]} > 0 )); then
      security list-keychains -d user -s "${keychains[@]}" >/dev/null 2>&1 || true
    fi
  fi
}

cleanup() {
  restore_user_keychain_settings
  security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
  rm -f "$CERT_PATH" "$NOTARY_KEY_PATH"
}
trap cleanup EXIT

sync_guest_clock

printf '%s' "$MACOS_DEVELOPER_ID_CERT_P12_BASE64" | base64_decode > "$CERT_PATH"
printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | base64_decode > "$NOTARY_KEY_PATH"
chmod 0600 "$CERT_PATH" "$NOTARY_KEY_PATH"
print_decoded_signing_certificate_diagnostics

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
current_keychains=()
while IFS= read -r keychain; do
  [[ -n "$keychain" && "$keychain" != "$KEYCHAIN_PATH" ]] && current_keychains+=("$keychain")
done < <(security list-keychains -d user 2>/dev/null | tr -d '"' || true)
security list-keychains -d user -s "$KEYCHAIN_PATH" "${current_keychains[@]}"
security default-keychain -d user -s "$KEYCHAIN_PATH"
security import "$CERT_PATH" -k "$KEYCHAIN_PATH" -P "$MACOS_DEVELOPER_ID_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

print_signing_diagnostics() {
  echo "Imported certificate names:" >&2
  security find-certificate -a -p "$KEYCHAIN_PATH" 2>/dev/null \
    | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null \
    | openssl pkcs7 -print_certs -noout -text 2>/dev/null \
    | sed -n 's/^ *Subject:.*CN=\([^,\/]*\).*/  - \1/p' >&2 || true
  echo "Matching codesigning identities in keychain (including invalid):" >&2
  security find-identity -p codesigning "$KEYCHAIN_PATH" >&2 || true
  echo "Valid codesigning identities visible to keychain:" >&2
  security find-identity -v -p codesigning "$KEYCHAIN_PATH" >&2 || true
  echo "Private-key items visible in keychain:" >&2
  security dump-keychain "$KEYCHAIN_PATH" 2>/dev/null \
    | awk '/class: 0x00000010/ {show=1; n=0; print; next} /class: / && show {show=0} show && n++<32 {print}' >&2 || true
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
