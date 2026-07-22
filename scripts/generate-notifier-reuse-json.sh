#!/usr/bin/env bash
set -euo pipefail

# Writes the notifier-reuse.json attestation asset that lets a LATER release
# decide whether it can reuse THIS release's DescartesNotifier.app.zip:
#   {"source_digest","zip_sha256","source_version"}
#
# source_version is read from the zip's OWN embedded Info.plist
# (CFBundleShortVersionString), not passed in separately: on a fresh build
# that is this release's version; on a reused zip it is whatever version was
# baked in at the original build, which is exactly the "last real build"
# value the reuse chain needs to stay honest (see plan §4 - the embedded
# version intentionally lags on a reused zip).
#
# Required environment:
#   SOURCE_DIGEST   this release's notifier source digest
#   ZIP_PATH        path to the DescartesNotifier.app.zip to attest (built or reused)
#   OUT_JSON        path to write notifier-reuse.json to

usage() {
  cat <<'EOF'
Usage: SOURCE_DIGEST=<hex> ZIP_PATH=<path> OUT_JSON=<path> \
  scripts/generate-notifier-reuse-json.sh
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

SOURCE_DIGEST="${SOURCE_DIGEST:-}"
ZIP_PATH="${ZIP_PATH:-}"
OUT_JSON="${OUT_JSON:-}"

[[ -n "$SOURCE_DIGEST" ]] || { echo "error: SOURCE_DIGEST is required" >&2; exit 2; }
[[ -n "$ZIP_PATH" ]] || { echo "error: ZIP_PATH is required" >&2; exit 2; }
[[ -f "$ZIP_PATH" ]] || { echo "error: ZIP_PATH does not exist: $ZIP_PATH" >&2; exit 2; }
[[ -n "$OUT_JSON" ]] || { echo "error: OUT_JSON is required" >&2; exit 2; }

command -v shasum >/dev/null || { echo "error: shasum is required" >&2; exit 2; }
command -v unzip >/dev/null || { echo "error: unzip is required" >&2; exit 2; }
command -v plutil >/dev/null || { echo "error: plutil is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "error: python3 is required" >&2; exit 2; }

ZIP_SHA256="$(shasum -a 256 "$ZIP_PATH" | awk '{ print $1 }')"

WORK_DIR="$(mktemp -d)"
cleanup() {
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

unzip -q -o "$ZIP_PATH" -d "$WORK_DIR"
INFO_PLIST="$WORK_DIR/DescartesNotifier.app/Contents/Info.plist"
[[ -f "$INFO_PLIST" ]] || { echo "error: Info.plist not found in $ZIP_PATH" >&2; exit 2; }

SOURCE_VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$INFO_PLIST")"

mkdir -p "$(dirname "$OUT_JSON")"
SOURCE_DIGEST="$SOURCE_DIGEST" ZIP_SHA256="$ZIP_SHA256" SOURCE_VERSION="$SOURCE_VERSION" OUT_JSON="$OUT_JSON" python3 <<'PY'
import json
import os

out_path = os.environ["OUT_JSON"]
payload = {
    "source_digest": os.environ["SOURCE_DIGEST"],
    "zip_sha256": os.environ["ZIP_SHA256"],
    "source_version": os.environ["SOURCE_VERSION"],
}
with open(out_path, "w") as f:
    json.dump(payload, f)
    f.write("\n")
PY

cat "$OUT_JSON"
