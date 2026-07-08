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
  GITHUB_TOKEN         Upload the zip/checksum to the matching GitHub Release via the
                       GitHub REST API (no gh dependency). Also fetched from Doppler
                       when present there (optional secret).
  GITHUB_REPOSITORY    owner/repo override; otherwise inferred from the git remote or
                       package.json repository.url.
  HOMEBREW_TAP_GITHUB_TOKEN
                       Optional override for the Homebrew tap formula bump. By default
                       that bump reuses GITHUB_TOKEN (which must be able to write
                       Lightless-Labs/homebrew-tap); set this only to use a narrower
                       token. Also fetched from Doppler when present (optional secret).

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
  local optional="${2:-}"
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
    if [[ "$optional" == "optional" ]]; then
      echo "note: optional Doppler release secret not available: $name" >&2
      return 0
    fi
    echo "error: failed to fetch Doppler release secret: $name" >&2
    exit 2
  fi
  if [[ -z "$value" ]]; then
    if [[ "$optional" == "optional" ]]; then
      echo "note: optional Doppler release secret is empty: $name" >&2
      return 0
    fi
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
  # Optional: enables GitHub Release publication from inside the guest.
  fetch_release_secret_from_doppler GITHUB_TOKEN optional
  # Optional: enables the Homebrew tap formula bump after a published release.
  fetch_release_secret_from_doppler HOMEBREW_TAP_GITHUB_TOKEN optional
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
  local cert_bundle="$BUILD_ROOT/developer-id-certs.pem"
  if security find-certificate -a -p "$KEYCHAIN_PATH" > "$cert_bundle" 2>/dev/null && [[ -s "$cert_bundle" ]]; then
    python3 - "$cert_bundle" <<'PY'
import re, subprocess, sys
with open(sys.argv[1], "r") as f:
    pem = f.read()
certs = re.findall(r"-----BEGIN CERTIFICATE-----\n[\s\S]*?\n-----END CERTIFICATE-----", pem)
for cert in certs:
    try:
        subject = subprocess.check_output(
            ["openssl", "x509", "-noout", "-subject", "-nameopt", "sep_comma_plus_space"],
            input=cert.encode(), stderr=subprocess.DEVNULL,
        ).decode().strip()
        if "Developer ID Application" in subject:
            subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha1"],
                input=cert.encode(), check=False,
            )
            sys.exit(0)
    except Exception:
        continue
print("warning: no Developer ID Application certificate found in keychain")
PY
  else
    echo "warning: unable to extract decoded Developer ID certificate diagnostics from keychain" >&2
  fi
  rm -f "$cert_bundle"
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
INTERMEDIATE_PEM="$BUILD_ROOT/developer-id-intermediate.pem"
KEYCHAIN_PASSWORD="$(openssl rand -base64 48)"
ORIGINAL_USER_KEYCHAINS="$(security list-keychains -d user 2>/dev/null | tr -d '"' || true)"

restore_user_keychain_settings() {
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
  rm -f "$CERT_PATH" "$NOTARY_KEY_PATH" "$INTERMEDIATE_PEM"
}
trap cleanup EXIT

sync_guest_clock

printf '%s' "$MACOS_DEVELOPER_ID_CERT_P12_BASE64" | base64_decode > "$CERT_PATH"
printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | base64_decode > "$NOTARY_KEY_PATH"
chmod 0600 "$CERT_PATH" "$NOTARY_KEY_PATH"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

# Import the Developer ID Application p12. The private key must be present;
# a leaf certificate without its paired private key will not form a codesigning identity.
security import "$CERT_PATH" \
  -k "$KEYCHAIN_PATH" \
  -P "$MACOS_DEVELOPER_ID_CERT_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security \
  -T /usr/bin/productbuild \
  -T /usr/bin/productsign

# Print diagnostics after the p12 has been imported into the keychain.
print_decoded_signing_certificate_diagnostics

# Ensure the Apple Developer ID intermediate certificate that issued the leaf is
# present in the ephemeral keychain. Fresh CI macOS images do not ship Developer ID
# intermediates: the system stores carry only root certificates (plus the legacy G1
# Developer ID CA); it is Xcode/developer tooling that installs intermediates on
# developer machines. codesign builds its signing chain from the keychain search
# list without fetching missing issuers over the network, so the intermediate must
# sit next to the leaf. The chain terminates at the classic "Apple Root CA", which
# every genuine macOS image already ships and trusts; no root-store installation or
# trust-settings changes are needed.
#
# NOTE: `security find-certificate -a ... -p` exits 0 even when nothing matches, so
# certificate presence checks must inspect the output, never the exit status.

extract_leaf_cert_issuer() {
  local cert_bundle="$BUILD_ROOT/keychain-certs.pem"
  local issuer=""
  if security find-certificate -a -p "$KEYCHAIN_PATH" > "$cert_bundle" 2>/dev/null && [[ -s "$cert_bundle" ]]; then
    issuer="$(python3 - "$cert_bundle" <<'PY'
import re, subprocess, sys
with open(sys.argv[1], "r") as f:
    pem = f.read()
certs = re.findall(r"-----BEGIN CERTIFICATE-----\n[\s\S]*?\n-----END CERTIFICATE-----", pem)
for cert in certs:
    try:
        subject = subprocess.check_output(
            ["openssl", "x509", "-noout", "-subject", "-nameopt", "sep_comma_plus_space"],
            input=cert.encode(), stderr=subprocess.DEVNULL,
        ).decode().strip()
        if "Developer ID Application" in subject:
            issuer = subprocess.check_output(
                ["openssl", "x509", "-noout", "-issuer", "-nameopt", "sep_comma_plus_space"],
                input=cert.encode(), stderr=subprocess.DEVNULL,
            ).decode().strip()
            sys.stdout.write(issuer.replace("issuer=", "").strip())
            sys.exit(0)
    except Exception:
        continue
PY
)"
  fi
  rm -f "$cert_bundle"
  printf '%s' "$issuer"
}

keychain_contains_certificate_subject() {
  local cn_fragment="$1" ou_fragment="$2"
  local keychain="${3:-$KEYCHAIN_PATH}"
  local cert_bundle="$BUILD_ROOT/keychain-certs.pem"
  local result=1
  if security find-certificate -a -p "$keychain" > "$cert_bundle" 2>/dev/null && [[ -s "$cert_bundle" ]]; then
    if python3 - "$cert_bundle" "$cn_fragment" "$ou_fragment" <<'PY'
import re, subprocess, sys
path, cn, ou = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r") as f:
    pem = f.read()
certs = re.findall(r"-----BEGIN CERTIFICATE-----\n[\s\S]*?\n-----END CERTIFICATE-----", pem)
for cert in certs:
    try:
        subject = subprocess.check_output(
            ["openssl", "x509", "-noout", "-subject", "-nameopt", "sep_comma_plus_space"],
            input=cert.encode(), stderr=subprocess.DEVNULL,
        ).decode().strip()
        if cn in subject and ou in subject:
            sys.exit(0)
    except Exception:
        continue
sys.exit(1)
PY
    then
      result=0
    fi
  fi
  rm -f "$cert_bundle"
  return "$result"
}

import_developer_id_intermediate() {
  local issuer intermediate_ou intermediate_url subject
  local intermediate_der="$BUILD_ROOT/developer-id-intermediate.cer"
  issuer="$(extract_leaf_cert_issuer)"
  if [[ -z "$issuer" ]]; then
    echo "error: unable to read the issuer of the imported Developer ID Application certificate" >&2
    exit 2
  fi
  echo "Developer ID leaf issuer: $issuer"
  if [[ "$issuer" != *"CN=Developer ID Certification Authority"* ]]; then
    echo "error: unexpected Developer ID leaf issuer; cannot select an Apple intermediate: $issuer" >&2
    exit 2
  fi
  # Apple PKI publishes both generations of the Developer ID CA. Leaves issued
  # since ~2021 chain through the G2 intermediate (OU=G2); older ones through G1.
  if [[ "$issuer" == *"OU=G2"* ]]; then
    intermediate_ou="OU=G2"
    intermediate_url="https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer"
  else
    intermediate_ou="OU=Apple Certification Authority"
    intermediate_url="https://www.apple.com/certificateauthority/DeveloperIDCA.cer"
  fi
  if keychain_contains_certificate_subject "CN=Developer ID Certification Authority" "$intermediate_ou"; then
    echo "Developer ID intermediate already present in ephemeral keychain ($intermediate_ou)"
    return 0
  fi
  echo "Downloading Developer ID intermediate from Apple PKI: $intermediate_url"
  if ! curl -fsSL --max-time 30 "$intermediate_url" -o "$intermediate_der"; then
    echo "error: failed to download the Developer ID intermediate from $intermediate_url" >&2
    exit 2
  fi
  subject="$(openssl x509 -inform DER -in "$intermediate_der" -noout -subject -nameopt sep_comma_plus_space 2>/dev/null || true)"
  if [[ "$subject" != *"CN=Developer ID Certification Authority"* || "$subject" != *"$intermediate_ou"* ]]; then
    echo "error: downloaded intermediate does not match the leaf issuer: ${subject:-<unparseable>}" >&2
    exit 2
  fi
  security import "$intermediate_der" -k "$KEYCHAIN_PATH" -T /usr/bin/codesign
  if ! keychain_contains_certificate_subject "CN=Developer ID Certification Authority" "$intermediate_ou"; then
    echo "error: Developer ID intermediate import did not land in the ephemeral keychain" >&2
    exit 2
  fi
  echo "Imported Developer ID intermediate into ephemeral keychain ($intermediate_ou)"

  # Keep a PEM copy for chain diagnostics before signing.
  openssl x509 -inform DER -in "$intermediate_der" -out "$INTERMEDIATE_PEM" 2>/dev/null || true

  # codesign builds its signing chain through trustd, which is not guaranteed to
  # consult a session-modified custom keychain search list on a fresh CI image
  # (build #63 failed with "unable to build chain" despite the intermediate being
  # in the search-listed ephemeral keychain). Provisioned developer machines and
  # GitHub runner images both carry the Apple intermediates system-wide, so
  # mirror that: install the public intermediate certificate into the system
  # keychain. This adds a certificate only - no trust-settings changes.
  if keychain_contains_certificate_subject "CN=Developer ID Certification Authority" "$intermediate_ou" /Library/Keychains/System.keychain; then
    echo "Developer ID intermediate already present in system keychain ($intermediate_ou)"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    if sudo -n security add-certificates -k /Library/Keychains/System.keychain "$intermediate_der" 2>/dev/null && \
       keychain_contains_certificate_subject "CN=Developer ID Certification Authority" "$intermediate_ou" /Library/Keychains/System.keychain; then
      echo "Installed Developer ID intermediate into system keychain ($intermediate_ou)"
    else
      echo "warning: failed to install Developer ID intermediate into system keychain; codesign chain building may fail" >&2
    fi
  else
    echo "warning: passwordless sudo unavailable; Developer ID intermediate only in ephemeral keychain" >&2
  fi
  rm -f "$intermediate_der"
}
import_developer_id_intermediate

# Allow codesign to access the imported identity without an interactive prompt.
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

# Add the ephemeral keychain to the user search list. Do NOT make it the default keychain:
# certificate validity is evaluated against the default keychain's trust store, and a fresh
# ephemeral keychain lacks the Apple root/intermediate certificates needed to validate a
# Developer ID Application chain. This ordering matches the working GitHub Actions pattern.
current_keychains=()
while IFS= read -r keychain; do
  [[ -n "$keychain" && "$keychain" != "$KEYCHAIN_PATH" ]] && current_keychains+=("$keychain")
done < <(security list-keychains -d user 2>/dev/null | tr -d '"' || true)
security list-keychains -d user -s "$KEYCHAIN_PATH" "${current_keychains[@]}"

print_signing_diagnostics() {
  echo "Imported certificate names:" >&2
  security find-certificate -a -p "$KEYCHAIN_PATH" 2>/dev/null \
    | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null \
    | openssl pkcs7 -print_certs -noout -text 2>/dev/null \
    | sed -n 's/^ *Subject:.*CN=\([^,\/]*\).*/  - \1/p' >&2 || true
  echo "Matching codesigning identities in keychain (including invalid):" >&2
  security find-identity -p codesigning "$KEYCHAIN_PATH" >&2 || true
  echo "Valid codesigning identities visible in the full search list:" >&2
  security find-identity -v -p codesigning >&2 || true
  echo "Matching (including invalid) codesigning identities in the ephemeral keychain:" >&2
  security find-identity -p codesigning "$KEYCHAIN_PATH" >&2 || true
  echo "Private-key items visible in the ephemeral keychain:" >&2
  security dump-keychain "$KEYCHAIN_PATH" 2>/dev/null \
    | awk '/class: 0x00000010/ {show=1; n=0; print; next} /class: / && show {show=0} show && n++<32 {print}' >&2 || true
}

if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
  # Extract the exact identity name from the freshly imported p12 in the ephemeral keychain.
  # A brand-new ephemeral keychain may not contain the Apple CA/root chain needed for a
  # validity check, so do not require -v here. codesign will validate against the full
  # search list (which includes the system/login trust anchors) when it runs.
  CODESIGN_IDENTITY="$(security find-identity -p codesigning "$KEYCHAIN_PATH" | sed -n 's/.*"\(Developer ID Application: .*\)".*/\1/p' | head -n 1)"
fi
if [[ -z "$CODESIGN_IDENTITY" ]]; then
  echo "error: no Developer ID Application signing identity found in imported p12" >&2
  echo "The p12 must contain both the Developer ID Application certificate and its private key; a downloaded .cer converted to p12 without the original private key will not work." >&2
  print_signing_diagnostics
  exit 2
fi

echo "Using codesign identity: $CODESIGN_IDENTITY"

print_chain_diagnostics() {
  local leaf_pem="$BUILD_ROOT/leaf-diag.pem"
  echo "Chain diagnostics:" >&2
  echo "Keychain search list:" >&2
  security list-keychains >&2 || true
  if security find-certificate -c "Developer ID Application" -p "$KEYCHAIN_PATH" > "$leaf_pem" 2>/dev/null && grep -q "BEGIN CERTIFICATE" "$leaf_pem"; then
    if [[ -s "$INTERMEDIATE_PEM" ]]; then
      echo "verify-cert codeSign policy, local certs only (leaf + intermediate vs system anchors):" >&2
      security verify-cert -L -c "$leaf_pem" -c "$INTERMEDIATE_PEM" -p codeSign >&2 2>&1 || true
    fi
    echo "verify-cert codeSign policy, default resolution:" >&2
    security verify-cert -c "$leaf_pem" -p codeSign >&2 2>&1 || true
  else
    echo "warning: could not export leaf certificate for diagnostics" >&2
  fi
  rm -f "$leaf_pem"
  if security find-certificate -c "Apple Root CA" -p /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
    echo "Apple Root CA present in system root store" >&2
  else
    echo "warning: Apple Root CA NOT found in system root store" >&2
  fi
}

# Verify the selected identity is valid somewhere in the search list before signing.
if security find-identity -v -p codesigning | grep -F "$CODESIGN_IDENTITY" >/dev/null 2>&1; then
  echo "Identity reported valid in the full search list"
else
  echo "warning: $CODESIGN_IDENTITY was not reported as valid in the full search list" >&2
  print_chain_diagnostics
fi

DESCARTES_MACOS_NOTIFIER_BUILD_DIR="$BUILD_ROOT" \
DESCARTES_MACOS_NOTIFIER_VERSION="$PACKAGE_VERSION" \
"$ROOT_DIR/scripts/build-macos-notifier.sh"

CODESIGN_IDENTITY="$CODESIGN_IDENTITY" \
APPLE_NOTARY_KEY_PATH="$NOTARY_KEY_PATH" \
APPLE_NOTARY_KEY_ID="$APPLE_NOTARY_KEY_ID" \
APPLE_NOTARY_ISSUER_ID="$APPLE_NOTARY_ISSUER_ID" \
DESCARTES_MACOS_NOTIFIER_ARTIFACT_DIR="$RELEASE_DIR" \
"$ROOT_DIR/scripts/notarize-macos-notifier.sh" "$APP_DIR"

shasum -a 256 "$ZIP_PATH" > "$SHA_PATH"

# Upload directly only when running under a host-side Buildkite agent. Inside the
# Tart guest there is no agent access token; there the pipeline rsyncs the release
# directory back to the shared checkout and uploads via artifact_paths instead.
if command -v buildkite-agent >/dev/null 2>&1 && [[ -n "${BUILDKITE_AGENT_ACCESS_TOKEN:-}" ]]; then
  buildkite-agent artifact upload "$ZIP_PATH"
  buildkite-agent artifact upload "$SHA_PATH"
fi

github_release_repository() {
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    printf '%s' "$GITHUB_REPOSITORY"
    return 0
  fi
  local url
  url="$(git -C "$ROOT_DIR" remote get-url origin 2>/dev/null || true)"
  if [[ -z "$url" ]]; then
    # Tart guest checkouts are rsynced without .git; fall back to package metadata.
    url="$(node -p "(JSON.parse(require('fs').readFileSync('$ROOT_DIR/package.json','utf8')).repository||{}).url||''" 2>/dev/null || true)"
  fi
  url="${url%.git}"
  case "$url" in
    *github.com:*) printf '%s' "${url##*github.com:}" ;;
    *github.com/*) printf '%s' "${url##*github.com/}" ;;
    *) return 1 ;;
  esac
}

# Publish the stapled zip + checksum to the matching GitHub Release via the REST
# API (the vanilla guest image has no gh CLI). GITHUB_TOKEN arrives via Doppler
# when provisioned there; without it this step is skipped.
if [[ -n "${GITHUB_TOKEN:-}" && -n "$TAG" ]]; then
  if GH_RELEASE_REPO="$(github_release_repository)" && [[ -n "$GH_RELEASE_REPO" ]]; then
    echo "Publishing GitHub Release $TAG assets to $GH_RELEASE_REPO"
    GH_RELEASE_REPO="$GH_RELEASE_REPO" GH_RELEASE_TAG="$TAG" python3 - "$ZIP_PATH" "$SHA_PATH" <<'PY'
import json, os, sys, urllib.error, urllib.parse, urllib.request

token = os.environ["GITHUB_TOKEN"]
repo = os.environ["GH_RELEASE_REPO"]
tag = os.environ["GH_RELEASE_TAG"]
assets = sys.argv[1:]
API = "https://api.github.com"

def call(method, url, data=None, content_type="application/json"):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "descartes-macos-notifier-release/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as res:
        body = res.read()
    return json.loads(body) if body else {}

try:
    release = call("GET", f"{API}/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}")
except urllib.error.HTTPError as exc:
    if exc.code != 404:
        print(f"GitHub release lookup failed for {repo}@{tag}: HTTP {exc.code}", file=sys.stderr)
        sys.exit(2)
    payload = json.dumps({
        "tag_name": tag,
        "name": tag,
        "body": f"Descartes {tag} macOS notifier release",
    }).encode()
    release = call("POST", f"{API}/repos/{repo}/releases", payload)
    print(f"created GitHub release {tag}")

existing = {a["name"]: a["id"] for a in release.get("assets", [])}
upload_base = release["upload_url"].split("{")[0]
for path in assets:
    name = os.path.basename(path)
    if name in existing:
        call("DELETE", f"{API}/repos/{repo}/releases/assets/{existing[name]}")
    with open(path, "rb") as f:
        data = f.read()
    call("POST", f"{upload_base}?name={urllib.parse.quote(name)}", data, "application/octet-stream")
    print(f"uploaded {name}")
PY
    GITHUB_RELEASE_PUBLISHED=1
  else
    echo "warning: GITHUB_TOKEN set but repository could not be determined; skipping GitHub Release upload" >&2
  fi
fi

# Bump Formula/descartes.rb in the Homebrew tap to this release: tag tarball URL +
# sha256 and helper zip URL + sha256. Runs only after the GitHub Release actually
# published (otherwise the formula would point at assets that do not exist). Uses the
# GitHub Contents API so the guest needs no git clone or gh CLI. Transient failures
# (network, GitHub 5xx, rate limit) are retried with exponential backoff, and a
# concurrent-edit conflict (HTTP 409) re-reads and retries once against fresh content.
#
# Only if retries are exhausted does this fall through to best-effort: by then the
# signed/notarized artifacts and the GitHub Release are already out, so a hard failure
# would redden an otherwise-successful release AND skip the pipeline's artifact
# rsync-back. A stale tap is recoverable with a manual formula bump.
bump_homebrew_tap_formula() {
  local tap_repo="Lightless-Labs/homebrew-tap"
  local formula_path="Formula/descartes.rb"
  local formula_source_repo="Lightless-Labs/descartes"
  if [[ -z "$TAG" ]]; then
    return 0
  fi
  # Reuse the token that just published the release; it already writes to this org.
  # HOMEBREW_TAP_GITHUB_TOKEN is only needed to override with a narrower token (e.g.
  # if GITHUB_TOKEN is ever restricted to the descartes repo alone).
  local tap_token="${HOMEBREW_TAP_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
  if [[ -z "$tap_token" ]]; then
    echo "note: no GitHub token available (GITHUB_TOKEN / HOMEBREW_TAP_GITHUB_TOKEN); skipping Homebrew tap formula bump" >&2
    return 0
  fi
  if [[ "${GITHUB_RELEASE_PUBLISHED:-0}" != "1" ]]; then
    echo "warning: GitHub Release was not published this run; skipping Homebrew tap formula bump" >&2
    return 0
  fi
  # The formula's pinned URLs point at the canonical repo permanently; bumping its
  # checksums from a release published elsewhere (GITHUB_REPOSITORY override) would
  # produce sha256 values that cannot match the formula's own URLs.
  if [[ "${GH_RELEASE_REPO:-}" != "$formula_source_repo" ]]; then
    echo "warning: release published to ${GH_RELEASE_REPO:-<unknown>} rather than $formula_source_repo; skipping Homebrew tap formula bump" >&2
    return 0
  fi

  local zip_sha tarball_sha
  local tarball_path="$BUILD_ROOT/descartes-src-$TAG.tar.gz"
  zip_sha="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
  # curl retries transient network/5xx itself (GitHub sometimes lags generating a
  # freshly-pushed tag's archive) before we fall through to the manual-bump note.
  if ! curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --max-time 180 "https://github.com/$formula_source_repo/archive/refs/tags/$TAG.tar.gz" -o "$tarball_path"; then
    echo "warning: could not download the $TAG source tarball to compute its checksum; skipping Homebrew tap formula bump" >&2
    echo "warning: bump manually: url version + tarball sha256 + helper zip sha256 ($zip_sha) in https://github.com/$tap_repo/blob/main/$formula_path" >&2
    return 0
  fi
  tarball_sha="$(shasum -a 256 "$tarball_path" | awk '{print $1}')"
  rm -f "$tarball_path"

  echo "Bumping $tap_repo $formula_path to $TAG"
  if ! TAP_TOKEN="$tap_token" TAP_REPO="$tap_repo" FORMULA_PATH="$formula_path" RELEASE_TAG="$TAG" \
    TARBALL_SHA256="$tarball_sha" HELPER_SHA256="$zip_sha" \
    python3 <<'PY'
import base64, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request

token = os.environ["TAP_TOKEN"]
repo = os.environ["TAP_REPO"]
path = os.environ["FORMULA_PATH"]
tag = os.environ["RELEASE_TAG"]
version = tag.lstrip("v")
tarball_sha = os.environ["TARBALL_SHA256"]
helper_sha = os.environ["HELPER_SHA256"]
API = "https://api.github.com"

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4

def _http_retryable(exc):
    if exc.code in RETRYABLE_STATUS:
        return True
    # Primary/secondary rate limits surface as 403 with a rate-limit signal.
    return exc.code == 403 and (
        exc.headers.get("Retry-After") is not None
        or exc.headers.get("X-RateLimit-Remaining") == "0"
    )

def _backoff_seconds(exc, attempt):
    if isinstance(exc, urllib.error.HTTPError):
        after = exc.headers.get("Retry-After")
        if after and after.isdigit():
            return min(int(after), 30)
    return min(2 ** attempt, 30)

def call(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "descartes-macos-notifier-release/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(url, method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as res:
                return json.loads(res.read())
        except urllib.error.HTTPError as exc:
            # 409 is a genuine edit conflict; the caller re-reads and retries it.
            if exc.code != 409 and _http_retryable(exc) and attempt < MAX_ATTEMPTS - 1:
                time.sleep(_backoff_seconds(exc, attempt))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(_backoff_seconds(exc, attempt))
                continue
            raise

def rewrite(text):
    changed = re.sub(
        r"(archive/refs/tags/v)[0-9][0-9A-Za-z.\-]*(\.tar\.gz)",
        rf"\g<1>{version}\g<2>",
        text,
    )
    changed = re.sub(
        r"(releases/download/v)[0-9][0-9A-Za-z.\-]*(/DescartesNotifier\.app\.zip)",
        rf"\g<1>{version}\g<2>",
        changed,
    )
    # Each pinned URL line is followed by its sha256 line; replace pairwise so the
    # tarball and helper checksums cannot be swapped.
    lines = changed.split("\n")
    pending = None
    for i, line in enumerate(lines):
        if "archive/refs/tags/" in line:
            if pending:
                break
            pending = tarball_sha
        elif "DescartesNotifier.app.zip" in line and "releases/download/" in line:
            if pending:
                break
            pending = helper_sha
        elif pending and re.search(r'sha256 "[0-9a-f]{64}"', line):
            lines[i] = re.sub(r'sha256 "[0-9a-f]{64}"', f'sha256 "{pending}"', line)
            pending = None
    if pending:
        raise RuntimeError("unexpected formula shape (pinned URL without a following sha256); not bumping")
    return "\n".join(lines)

def bump():
    for attempt in range(2):
        current = call("GET", f"{API}/repos/{repo}/contents/{urllib.parse.quote(path)}")
        text = base64.b64decode(current["content"]).decode()
        updated = rewrite(text)
        if updated == text:
            print(f"tap formula already current for {tag}; no bump needed")
            return
        payload = {
            "message": f"descartes: update to {version}",
            "content": base64.b64encode(updated.encode()).decode(),
            "sha": current["sha"],
        }
        try:
            result = call("PUT", f"{API}/repos/{repo}/contents/{urllib.parse.quote(path)}", payload)
        except urllib.error.HTTPError as exc:
            if exc.code == 409 and attempt == 0:
                print("warning: tap formula changed concurrently; retrying once with fresh content", file=sys.stderr)
                continue
            raise
        print(f"bumped {repo}/{path} to {version}: {result['commit']['sha'][:9]}")
        return
    raise RuntimeError("tap formula update conflicted twice")

# Any failure exits nonzero; the calling shell treats that as a loud warning, never
# a release failure — the artifacts and GitHub Release are already published.
try:
    bump()
except Exception as exc:
    print(f"error: tap formula bump failed: {exc}", file=sys.stderr)
    sys.exit(3)
PY
  then
    echo "warning: Homebrew tap formula bump FAILED; the tap is stale for $TAG (release artifacts are unaffected)" >&2
    echo "warning: bump manually: url version + tarball sha256 ($tarball_sha) + helper zip sha256 ($zip_sha) in https://github.com/$tap_repo/blob/main/$formula_path" >&2
    return 0
  fi
}
bump_homebrew_tap_formula

cat <<EOF
macOS notifier release artifact:
  $ZIP_PATH
sha256:
  $(cat "$SHA_PATH")
EOF
