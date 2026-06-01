#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FILE="$ROOT_DIR/tools/descartes-cli/native/macos/DescartesNotifier.swift"
INFO_PLIST_TEMPLATE="$ROOT_DIR/tools/descartes-cli/native/macos/DescartesNotifier-Info.plist"
BUILD_ROOT="${DESCARTES_MACOS_NOTIFIER_BUILD_DIR:-$ROOT_DIR/.build/macos-notifier}"
APP_NAME="DescartesNotifier.app"
APP_DIR="$BUILD_ROOT/$APP_NAME"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
BINARY_PATH="$MACOS_DIR/DescartesNotifier"
INFO_PLIST_PATH="$CONTENTS_DIR/Info.plist"
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
CODESIGN_KEYCHAIN="${CODESIGN_KEYCHAIN:-}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macOS notifier app bundles must be built on macOS" >&2
  exit 2
fi

command -v swiftc >/dev/null || { echo "error: swiftc is required" >&2; exit 2; }
command -v node >/dev/null || { echo "error: node is required to read package metadata" >&2; exit 2; }

VERSION="${DESCARTES_MACOS_NOTIFIER_VERSION:-$(node -p "JSON.parse(require('fs').readFileSync('$ROOT_DIR/package.json', 'utf8')).version")}"
BUILD_NUMBER="${DESCARTES_MACOS_NOTIFIER_BUILD:-${VERSION//[^0-9]/}}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR"

swiftc \
  -O \
  -framework Foundation \
  -framework UserNotifications \
  "$SOURCE_FILE" \
  -o "$BINARY_PATH"
chmod 0755 "$BINARY_PATH"

sed \
  -e "s/__DESCARTES_VERSION__/$VERSION/g" \
  -e "s/__DESCARTES_BUILD__/$BUILD_NUMBER/g" \
  "$INFO_PLIST_TEMPLATE" > "$INFO_PLIST_PATH"

if [[ -n "$CODESIGN_IDENTITY" ]]; then
  codesign_args=(--force --timestamp --options runtime --sign "$CODESIGN_IDENTITY")
  if [[ -n "$CODESIGN_KEYCHAIN" ]]; then
    codesign_args+=(--keychain "$CODESIGN_KEYCHAIN")
  fi
  codesign "${codesign_args[@]}" "$APP_DIR"
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
fi

cat <<EOF
Built macOS notifier app:
  $APP_DIR
Bundle identifier:
  com.bande-a-bonnot.lightless-labs.descartes.macos.notifier
EOF
