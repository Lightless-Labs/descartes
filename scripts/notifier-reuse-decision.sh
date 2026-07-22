#!/usr/bin/env bash
set -euo pipefail

# Decides whether the macOS notifier release step should REUSE a prior
# release's already-notarized+stapled DescartesNotifier.app.zip instead of
# rebuilding+signing+notarizing. Every uncertainty resolves to "build" — this
# script never crashes the caller under `set -euo pipefail`: on any failure
# (network, parsing, integrity, identity, notarization) it prints "build" to
# stdout and exits 0. Only genuinely unexpected internal errors exit nonzero;
# callers must still treat any stdout other than exactly "reuse <tag>" as build.
#
# Stdout contract (exactly one line):
#   reuse <prior_tag>   the verified zip is now at $OUT_ZIP; reuse it as-is
#   build               rebuild+notarize as usual
#
# Required environment:
#   SOURCE_DIGEST      current notifier source digest (scripts/notifier-source-digest.sh)
#   GH_RELEASE_REPO    owner/repo of the GitHub release history to scan
#   GITHUB_TOKEN       token with read access to GH_RELEASE_REPO
#   CURRENT_TAG        this release's tag, e.g. v0.0.50
#   OUT_ZIP            path to place the reused zip at, on success
#
# Optional environment:
#   EXPECTED_TEAM_ID              if set, the reused app's codesign TeamIdentifier
#                                 must match exactly; if unset, a Developer ID
#                                 signature (any team) is still required
#   DESCARTES_NOTIFIER_FORCE_REBUILD=1   short-circuits straight to "build"
#   DESCARTES_GITHUB_API_URL      default https://api.github.com (tests override)
#   DESCARTES_GITHUB_DOWNLOAD_URL default https://github.com (tests override)

EXPECTED_BUNDLE_ID="com.bande-a-bonnot.lightless-labs.descartes.macos.notifier"
EXPECTED_BUNDLE_EXECUTABLE="DescartesNotifier"
ZIP_ASSET_NAME="DescartesNotifier.app.zip"
REUSE_ASSET_NAME="notifier-reuse.json"

API_URL="${DESCARTES_GITHUB_API_URL:-https://api.github.com}"
DOWNLOAD_URL="${DESCARTES_GITHUB_DOWNLOAD_URL:-https://github.com}"
SOURCE_DIGEST="${SOURCE_DIGEST:-}"
GH_RELEASE_REPO="${GH_RELEASE_REPO:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
CURRENT_TAG="${CURRENT_TAG:-}"
OUT_ZIP="${OUT_ZIP:-}"
EXPECTED_TEAM_ID="${EXPECTED_TEAM_ID:-}"

usage() {
  cat <<'EOF'
Usage: scripts/notifier-reuse-decision.sh

Decides whether to reuse a prior release's already-notarized+stapled
DescartesNotifier.app.zip instead of rebuilding it. See the top of this file
for the full environment variable contract. Prints exactly one line to
stdout: "reuse <prior_tag>" or "build".
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

WORK_DIR=""
cleanup() {
  # Must never itself fail/return false under `set -e`: a false status here
  # would become the script's exit code, clobbering an earlier `exit 0`.
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

# Prints "build" plus a diagnostic reason to stderr, then exits 0. Every
# not-safe-to-reuse path in this script funnels through here.
build() {
  echo "notifier-reuse-decision: build (${1:-no reason given})" >&2
  echo "build"
  exit 0
}

if [[ "${DESCARTES_NOTIFIER_FORCE_REBUILD:-0}" == "1" ]]; then
  build "DESCARTES_NOTIFIER_FORCE_REBUILD=1"
fi
if [[ -z "$GITHUB_TOKEN" ]]; then
  build "GITHUB_TOKEN not set"
fi
if [[ -z "$GH_RELEASE_REPO" ]]; then
  build "GH_RELEASE_REPO not set"
fi
if [[ -z "$SOURCE_DIGEST" ]]; then
  build "SOURCE_DIGEST not set"
fi
if [[ -z "$CURRENT_TAG" ]]; then
  build "CURRENT_TAG not set"
fi
if [[ -z "$OUT_ZIP" ]]; then
  build "OUT_ZIP not set"
fi

for tool in curl python3 shasum unzip plutil codesign stapler spctl; do
  command -v "$tool" >/dev/null 2>&1 || build "required tool not found: $tool"
done

# --- Step 1: list prior releases, pick the highest eligible semver candidate
#     that carries both assets, then fetch+validate its reuse attestation. ---
if ! PY_OUT="$(API_URL="$API_URL" DOWNLOAD_URL="$DOWNLOAD_URL" GH_RELEASE_REPO="$GH_RELEASE_REPO" \
  GITHUB_TOKEN="$GITHUB_TOKEN" CURRENT_TAG="$CURRENT_TAG" SOURCE_DIGEST="$SOURCE_DIGEST" \
  ZIP_ASSET_NAME="$ZIP_ASSET_NAME" REUSE_ASSET_NAME="$REUSE_ASSET_NAME" python3 <<'PY'
import json
import os
import re
import sys
import urllib.error
import urllib.request

api = os.environ["API_URL"].rstrip("/")
download_base = os.environ["DOWNLOAD_URL"].rstrip("/")
repo = os.environ["GH_RELEASE_REPO"]
token = os.environ["GITHUB_TOKEN"]
current_tag = os.environ["CURRENT_TAG"]
source_digest = os.environ["SOURCE_DIGEST"]
zip_asset_name = os.environ["ZIP_ASSET_NAME"]
reuse_asset_name = os.environ["REUSE_ASSET_NAME"]

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def build(reason):
    print(reason, file=sys.stderr)
    print("build")
    sys.exit(0)


def semver_tuple(tag):
    m = TAG_RE.match(tag)
    return tuple(int(x) for x in m.groups()) if m else None


def request(url, timeout):
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "descartes-notifier-reuse-decision/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.read()


current_semver = semver_tuple(current_tag)
if current_semver is None:
    build(f"current tag is not semver: {current_tag}")

try:
    raw = request(f"{api}/repos/{repo}/releases?per_page=30", timeout=25)
    releases = json.loads(raw)
except Exception as exc:
    build(f"list releases failed: {exc}")

if not isinstance(releases, list):
    build("releases list response was not a JSON array")

candidates = []
for r in releases:
    if not isinstance(r, dict):
        continue
    tag = r.get("tag_name") or ""
    if r.get("draft") or r.get("prerelease"):
        continue
    if tag == current_tag:
        continue
    sv = semver_tuple(tag)
    if sv is None or sv >= current_semver:
        continue
    asset_names = {a.get("name") for a in (r.get("assets") or []) if isinstance(a, dict)}
    if zip_asset_name not in asset_names or reuse_asset_name not in asset_names:
        continue
    candidates.append((sv, tag))

if not candidates:
    build("no eligible prior release carries both reuse assets")

candidates.sort()
best_tag = candidates[-1][1]

reuse_json_url = f"{download_base}/{repo}/releases/download/{best_tag}/{reuse_asset_name}"
try:
    attestation_raw = request(reuse_json_url, timeout=25)
except Exception as exc:
    build(f"fetch {reuse_asset_name} failed for {best_tag}: {exc}")

try:
    attestation = json.loads(attestation_raw)
except Exception as exc:
    build(f"unparsable {reuse_asset_name} for {best_tag}: {exc}")

if not isinstance(attestation, dict):
    build(f"{reuse_asset_name} for {best_tag} was not a JSON object")

att_digest = attestation.get("source_digest")
att_zip_sha256 = attestation.get("zip_sha256")
if not isinstance(att_digest, str) or not att_digest:
    build(f"{reuse_asset_name} for {best_tag} missing source_digest")
if not isinstance(att_zip_sha256, str) or not att_zip_sha256:
    build(f"{reuse_asset_name} for {best_tag} missing zip_sha256")

if att_digest != source_digest:
    build(f"source digest mismatch against candidate {best_tag}")

att_source_version = attestation.get("source_version")
if not isinstance(att_source_version, str):
    att_source_version = ""

zip_url = f"{download_base}/{repo}/releases/download/{best_tag}/{zip_asset_name}"
print(f"CANDIDATE {best_tag} {zip_url} {att_zip_sha256} {att_source_version}")
PY
)"; then
  build "notifier-reuse-decision candidate scan crashed unexpectedly"
fi

if [[ "$PY_OUT" == "build" ]]; then
  build "candidate scan found nothing reusable"
fi

read -r -a CANDIDATE_FIELDS <<< "$PY_OUT"
if [[ "${CANDIDATE_FIELDS[0]:-}" != "CANDIDATE" || "${#CANDIDATE_FIELDS[@]}" -lt 4 ]]; then
  build "unexpected candidate-scan output: $PY_OUT"
fi
CANDIDATE_TAG="${CANDIDATE_FIELDS[1]}"
ZIP_URL="${CANDIDATE_FIELDS[2]}"
ATT_ZIP_SHA256="${CANDIDATE_FIELDS[3]}"
ATT_SOURCE_VERSION="${CANDIDATE_FIELDS[4]:-}"

# --- Step 2: download the candidate zip and verify integrity + identity +
#     notarization. Any failure anywhere in here falls through to build. ---
mkdir -p "$(dirname "$OUT_ZIP")"
rm -f "$OUT_ZIP"
if ! curl -fsSL --max-time 60 -o "$OUT_ZIP" "$ZIP_URL"; then
  rm -f "$OUT_ZIP"
  build "download of $ZIP_ASSET_NAME failed for $CANDIDATE_TAG"
fi

if ! ACTUAL_ZIP_SHA256="$(shasum -a 256 "$OUT_ZIP" 2>/dev/null | awk '{ print $1 }')"; then
  rm -f "$OUT_ZIP"
  build "shasum of downloaded zip failed"
fi
if [[ "$ACTUAL_ZIP_SHA256" != "$ATT_ZIP_SHA256" ]]; then
  rm -f "$OUT_ZIP"
  build "zip sha256 mismatch: attestation says $ATT_ZIP_SHA256, downloaded is $ACTUAL_ZIP_SHA256"
fi

WORK_DIR="$(mktemp -d 2>/dev/null || true)"
if [[ -z "$WORK_DIR" || ! -d "$WORK_DIR" ]]; then
  rm -f "$OUT_ZIP"
  build "mktemp failed"
fi

if ! unzip -q -o "$OUT_ZIP" -d "$WORK_DIR" >/dev/null 2>&1; then
  rm -f "$OUT_ZIP"
  build "unzip of downloaded zip failed"
fi

APP_DIR="$WORK_DIR/DescartesNotifier.app"
if [[ ! -d "$APP_DIR" ]]; then
  rm -f "$OUT_ZIP"
  build "downloaded zip did not contain DescartesNotifier.app"
fi

INFO_PLIST="$APP_DIR/Contents/Info.plist"
if [[ ! -f "$INFO_PLIST" ]]; then
  rm -f "$OUT_ZIP"
  build "Info.plist missing in downloaded app bundle"
fi

if ! BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$INFO_PLIST" 2>/dev/null)"; then
  rm -f "$OUT_ZIP"
  build "unable to read CFBundleIdentifier"
fi
if [[ "$BUNDLE_ID" != "$EXPECTED_BUNDLE_ID" ]]; then
  rm -f "$OUT_ZIP"
  build "unexpected CFBundleIdentifier: $BUNDLE_ID"
fi

if ! BUNDLE_EXECUTABLE="$(plutil -extract CFBundleExecutable raw -o - "$INFO_PLIST" 2>/dev/null)"; then
  rm -f "$OUT_ZIP"
  build "unable to read CFBundleExecutable"
fi
if [[ "$BUNDLE_EXECUTABLE" != "$EXPECTED_BUNDLE_EXECUTABLE" ]]; then
  rm -f "$OUT_ZIP"
  build "unexpected CFBundleExecutable: $BUNDLE_EXECUTABLE"
fi

if ! codesign --verify --deep --strict "$APP_DIR" >/dev/null 2>&1; then
  rm -f "$OUT_ZIP"
  build "codesign --verify --deep --strict failed"
fi

if ! CODESIGN_DVV_LOG="$(codesign -dvv "$APP_DIR" 2>&1 1>/dev/null)"; then
  rm -f "$OUT_ZIP"
  build "codesign -dvv failed"
fi
TEAM_ID="$(printf '%s\n' "$CODESIGN_DVV_LOG" | sed -n 's/^TeamIdentifier=//p' | head -n 1)"
if [[ -z "$TEAM_ID" || "$TEAM_ID" == "not set" ]]; then
  rm -f "$OUT_ZIP"
  build "app is not signed by a Developer ID (TeamIdentifier not set)"
fi
if [[ -n "$EXPECTED_TEAM_ID" && "$TEAM_ID" != "$EXPECTED_TEAM_ID" ]]; then
  rm -f "$OUT_ZIP"
  build "codesign TeamIdentifier ($TEAM_ID) does not match EXPECTED_TEAM_ID"
fi

if ! stapler validate "$APP_DIR" >/dev/null 2>&1; then
  rm -f "$OUT_ZIP"
  build "stapler validate failed"
fi

if ! spctl --assess --type execute --verbose=4 "$APP_DIR" >/dev/null 2>&1; then
  rm -f "$OUT_ZIP"
  build "spctl --assess --type execute failed"
fi

echo "notifier-reuse-decision: reusing notifier from $CANDIDATE_TAG (source unchanged); embedded version ${ATT_SOURCE_VERSION:-unknown} lags this release's CLI version" >&2
echo "reuse $CANDIDATE_TAG"
