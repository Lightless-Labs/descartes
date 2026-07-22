#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage: scripts/notifier-source-digest.sh [--root <dir>]

Prints a stable sha256 digest over the files that determine the BEHAVIOR of the
built DescartesNotifier.app:
  - every file under tools/descartes-cli/native/macos/ (the .swift, the
    Info.plist TEMPLATE with __DESCARTES_VERSION__/__DESCARTES_BUILD__
    placeholders intact, and any future resource)
  - scripts/build-macos-notifier.sh
  - scripts/notarize-macos-notifier.sh

The digest is sha256 over the sorted set of "<sha256>  <relpath>" lines for
those files, so it is order-independent and pure bash + shasum (no network).

The Info.plist TEMPLATE is hashed, never a version-substituted copy, so a pure
version/build-number bump does not change the digest.

--root overrides the directory the paths above are resolved against (relative
to it); tests point this at a fixture tree that mirrors the real layout.
Defaults to this repo's root.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ -n "${2:-}" ]] || { echo "error: --root requires a directory argument" >&2; exit 2; }
      ROOT="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v shasum >/dev/null || { echo "error: shasum is required" >&2; exit 2; }

[[ -d "$ROOT" ]] || { echo "error: --root directory not found: $ROOT" >&2; exit 2; }

NATIVE_RELDIR="tools/descartes-cli/native/macos"
NATIVE_DIR="$ROOT/$NATIVE_RELDIR"
[[ -d "$NATIVE_DIR" ]] || { echo "error: notifier native source dir not found: $NATIVE_DIR" >&2; exit 2; }

EXTRA_FILES=(
  "scripts/build-macos-notifier.sh"
  "scripts/notarize-macos-notifier.sh"
)

NATIVE_FILES=()
while IFS= read -r relpath; do
  [[ -n "$relpath" ]] && NATIVE_FILES+=("$relpath")
done < <(cd "$NATIVE_DIR" && find . -type f | sed 's#^\./##' | LC_ALL=C sort | sed "s#^#$NATIVE_RELDIR/#")

ALL_FILES=("${NATIVE_FILES[@]}" "${EXTRA_FILES[@]}")

if (( ${#ALL_FILES[@]} == 0 )); then
  echo "error: no digest input files found under $NATIVE_RELDIR" >&2
  exit 2
fi

for relpath in "${ALL_FILES[@]}"; do
  [[ -f "$ROOT/$relpath" ]] || { echo "error: digest input file missing: $relpath" >&2; exit 2; }
done

digest_lines() {
  for relpath in "${ALL_FILES[@]}"; do
    shasum -a 256 "$ROOT/$relpath" | awk -v rel="$relpath" '{ print $1 "  " rel }'
  done
}

digest_lines | LC_ALL=C sort | shasum -a 256 | awk '{ print $1 }'
