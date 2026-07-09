#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ID="com.bande-a-bonnot.lightless-labs.descartes.macos.notifier"
DESCARTES_BIN="${DESCARTES_BIN:-descartes}"
NODE_BIN="${NODE_BIN:-node}"
SKIP_TEST=0
YES=0
RESET_TCC=0
DAEMON_TEST=0

usage() {
  cat <<'EOF'
Usage: scripts/validate-macos-notifier-helper.sh [--yes] [--skip-test] [--reset-tcc] [--daemon-test]

Real-host validation helper for the Homebrew-installed Descartes native macOS
notification helper. Run on a macOS host after:

  brew install lightless-labs/tap/descartes

The script:
  1. runs native notification setup without an explicit helper override;
  2. verifies setup resolved an executable bundled helper;
  3. verifies the helper app signature/staple/Gatekeeper assessment when tools exist;
  4. optionally triggers a test notification for the operator to observe TCC attribution;
  5. optionally runs a one-shot user LaunchAgent notification test for daemon-context smoke validation.

Descartes config/state/cache are isolated under a temporary XDG root by default, so this
helper does not overwrite the user's real notification configuration. TCC/Notification
Center permission state is system/user state and is affected only when --reset-tcc is
confirmed or when the optional notification test is triggered.

Options:
  --yes        Do not pause before resetting TCC or triggering the test notification.
  --skip-test    Verify helper resolution/signature only; do not send a notification.
  --reset-tcc    Prompt to reset Notification Center permission for the Descartes notifier bundle first.
  --daemon-test  After the interactive test, prompt before running a one-shot user LaunchAgent test.

Set DESCARTES_BIN=/path/to/descartes to validate a specific installed CLI.
Set NODE_BIN=/path/to/node if the brewed CLI should run with a specific node executable.
Set DESCARTES_VALIDATION_XDG_ROOT=/path to preserve/use a specific validation state root.
The script refuses DESCARTES_MACOS_NOTIFICATION_HELPER because validation is intended
for no-override Homebrew bundled-helper resolution.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --yes) YES=1 ;;
    --skip-test) SKIP_TEST=1 ;;
    --reset-tcc) RESET_TCC=1 ;;
    --daemon-test) DAEMON_TEST=1 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if (( SKIP_TEST && DAEMON_TEST )); then
  echo "error: --daemon-test cannot be combined with --skip-test" >&2
  exit 2
fi

if [[ -n "${DESCARTES_MACOS_NOTIFICATION_HELPER:-}" ]]; then
  echo "error: DESCARTES_MACOS_NOTIFICATION_HELPER is set; unset it to validate bundled Homebrew helper resolution" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: native macOS notifier validation must run on macOS" >&2
  exit 2
fi

if ! command -v "$DESCARTES_BIN" >/dev/null 2>&1; then
  echo "error: descartes CLI not found: $DESCARTES_BIN" >&2
  exit 2
fi
if ! command -v "$NODE_BIN" >/dev/null 2>&1; then
  echo "error: node executable not found: $NODE_BIN" >&2
  exit 2
fi
resolved_node_path="$(command -v "$NODE_BIN")"
case "$resolved_node_path" in
  /*) ;;
  *) resolved_node_path="$(pwd -P)/$resolved_node_path" ;;
esac

json_get() {
  local file="$1" expr="$2"
  "$resolved_node_path" -e '
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const parts = process.argv[2].split(".");
let value = data;
for (const part of parts) value = value == null ? undefined : value[part];
if (value === undefined || value === null) process.exit(3);
if (typeof value === "object") console.log(JSON.stringify(value));
else console.log(String(value));
' "$file" "$expr"
}

derive_bundled_helper_path() {
  local cli_path="$1"
  "$resolved_node_path" -e '
const fs = require("fs");
const path = require("path");
const cliPath = process.argv[1];
const candidates = [];
let realCliPath;
try {
  realCliPath = fs.realpathSync(cliPath);
} catch {
  realCliPath = cliPath;
}
if (realCliPath.endsWith("/tools/descartes-cli/src/index.js")) {
  candidates.push(path.join(
    path.dirname(realCliPath),
    "..",
    "native",
    "macos",
    "DescartesNotifier.app",
    "Contents",
    "MacOS",
    "DescartesNotifier",
  ));
}
if (realCliPath.endsWith("/bin/descartes")) {
  candidates.push(path.join(
    path.dirname(realCliPath),
    "..",
    "lib",
    "node_modules",
    "@lightless-labs",
    "descartes",
    "tools",
    "descartes-cli",
    "native",
    "macos",
    "DescartesNotifier.app",
    "Contents",
    "MacOS",
    "DescartesNotifier",
  ));
}
for (const candidate of candidates) {
  if (fs.existsSync(candidate)) {
    console.log(candidate);
    process.exit(0);
  }
}
process.exit(3);
' "$cli_path"
}

write_daemon_test_plist() {
  local plist_file="$1" label="$2" node_path="$3" cli_path="$4" stdout_file="$5" stderr_file="$6"
  "$resolved_node_path" -e '
const fs = require("fs");
const [plistFile, label, nodePath, cliPath, stdoutFile, stderrFile, validationRoot] = process.argv.slice(1);
const xml = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll("\"", "&quot;")
  .replaceAll(String.fromCharCode(39), "&apos;");
const args = [nodePath, cliPath, "alerts", "notifications", "test", "--json"];
const env = {
  XDG_CONFIG_HOME: `${validationRoot}/config`,
  XDG_DATA_HOME: `${validationRoot}/data`,
  XDG_STATE_HOME: `${validationRoot}/state`,
  XDG_CACHE_HOME: `${validationRoot}/cache`,
};
const argXml = args.map((arg) => `\t\t<string>${xml(arg)}</string>`).join("\n");
const envXml = Object.entries(env).map(([key, value]) => `\t\t<key>${xml(key)}</key>\n\t\t<string>${xml(value)}</string>`).join("\n");
fs.writeFileSync(plistFile, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xml(label)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argXml}
\t</array>
\t<key>EnvironmentVariables</key>
\t<dict>
${envXml}
\t</dict>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>StandardOutPath</key>
\t<string>${xml(stdoutFile)}</string>
\t<key>StandardErrorPath</key>
\t<string>${xml(stderrFile)}</string>
</dict>
</plist>
`);
' "$plist_file" "$label" "$node_path" "$cli_path" "$stdout_file" "$stderr_file" "$VALIDATION_ROOT"
}

run_daemon_context_test() {
  local daemon_dir="$VALIDATION_ROOT/daemon-context"
  mkdir -p "$daemon_dir"
  local label="com.lightless-labs.descartes.notifier-validation.$$"
  local plist_file="$daemon_dir/$label.plist"
  local stdout_file="$daemon_dir/stdout.json"
  local stderr_file="$daemon_dir/stderr.log"
  local domain="gui/$(id -u)"

  : > "$stdout_file"
  : > "$stderr_file"
  write_daemon_test_plist "$plist_file" "$label" "$resolved_node_path" "$resolved_cli_path" "$stdout_file" "$stderr_file"

  echo "Running daemon-context notification smoke via one-shot user LaunchAgent..."
  echo "LaunchAgent label: $label"
  echo "LaunchAgent plist: $plist_file"
  launchctl bootout "$domain/$label" >/dev/null 2>&1 || true
  if ! launchctl bootstrap "$domain" "$plist_file"; then
    echo "error: failed to bootstrap daemon-context LaunchAgent" >&2
    return 1
  fi

  for _ in $(seq 1 40); do
    if [[ -s "$stdout_file" ]]; then
      break
    fi
    sleep 0.25
  done
  launchctl bootout "$domain/$label" >/dev/null 2>&1 || true

  echo "Daemon-context stdout: $stdout_file"
  if [[ -s "$stdout_file" ]]; then
    cat "$stdout_file"
  else
    echo "error: daemon-context notification test produced no stdout" >&2
    if [[ -s "$stderr_file" ]]; then
      echo "Daemon-context stderr:"
      cat "$stderr_file"
    fi
    return 1
  fi
  if [[ -s "$stderr_file" ]]; then
    echo "Daemon-context stderr:"
    cat "$stderr_file"
  fi

  local daemon_delivery_status
  daemon_delivery_status="$(json_get "$stdout_file" delivery.status 2>/dev/null || true)"
  if [[ -n "$daemon_delivery_status" ]]; then
    echo "Daemon-context delivery status: $daemon_delivery_status"
  fi
  echo "Daemon-context delivery audit: $VALIDATION_ROOT/state/alerts/notification-delivery.jsonl"
  if [[ "$daemon_delivery_status" != "delivered" ]]; then
    echo "error: daemon-context notification smoke did not report delivered status" >&2
    return 1
  fi
}

VALIDATION_ROOT="${DESCARTES_VALIDATION_XDG_ROOT:-$(mktemp -d -t descartes-notifier-validation.XXXXXX)}"
mkdir -p "$VALIDATION_ROOT/config" "$VALIDATION_ROOT/data" "$VALIDATION_ROOT/state" "$VALIDATION_ROOT/cache"

run_descartes() {
  XDG_CONFIG_HOME="$VALIDATION_ROOT/config" \
  XDG_DATA_HOME="$VALIDATION_ROOT/data" \
  XDG_STATE_HOME="$VALIDATION_ROOT/state" \
  XDG_CACHE_HOME="$VALIDATION_ROOT/cache" \
    "$DESCARTES_BIN" "$@"
}

resolved_cli_path="$(command -v "$DESCARTES_BIN")"
case "$resolved_cli_path" in
  /*) ;;
  *) resolved_cli_path="$(pwd -P)/$resolved_cli_path" ;;
esac

echo "Descartes native macOS notifier validation"
echo "CLI: $resolved_cli_path"
echo "Node: $resolved_node_path"
echo "Version: $(run_descartes --version)"
echo "Bundle ID: $BUNDLE_ID"
echo "Validation XDG root: $VALIDATION_ROOT"

if (( RESET_TCC )); then
  if (( ! YES )); then
    if [[ ! -t 0 ]]; then
      RESET_TCC=0
      echo "Skipping TCC reset because stdin is not interactive; pass --yes to reset non-interactively."
    else
      cat <<EOF

--reset-tcc will remove the current Notification Center permission grant for:
  $BUNDLE_ID
This is useful for observing the first-run prompt, but it mutates real per-user TCC state.
Type "reset" to continue, or press Enter to skip the reset.
EOF
      read -r reset_reply || reset_reply=""
      if [[ "$reset_reply" != "reset" ]]; then
        RESET_TCC=0
        echo "Skipping TCC reset."
      fi
    fi
  fi
  if (( RESET_TCC )); then
    echo "Resetting Notification Center permission for $BUNDLE_ID"
    tccutil reset Notifications "$BUNDLE_ID" || true
  fi
fi

setup_json_file="$(mktemp)"
status_json_file="$(mktemp)"
test_json_file="$(mktemp)"
cleanup() {
  rm -f "$setup_json_file" "$status_json_file" "$test_json_file"
}
trap cleanup EXIT

echo "Running native notification setup without an explicit helper override..."
run_descartes alerts notifications setup --channel native --json > "$setup_json_file"
cat "$setup_json_file"

available="$(json_get "$setup_json_file" resolution.macos_native_helper_available 2>/dev/null || true)"
source="$(json_get "$setup_json_file" resolution.macos_native_helper_source 2>/dev/null || true)"
helper_path="$(json_get "$setup_json_file" resolution.resolved_macos_native_helper_path 2>/dev/null || true)"

if [[ -z "$available" || -z "$source" || -z "$helper_path" ]]; then
  echo "Setup JSON did not include native helper resolution; deriving bundled helper path from CLI location..."
  helper_path="$(derive_bundled_helper_path "$resolved_cli_path" 2>/dev/null || true)"
  source="bundled"
  if [[ -n "$helper_path" && -x "$helper_path" ]]; then
    available="true"
  else
    available="false"
  fi
fi

if [[ "$available" != "true" ]]; then
  echo "error: native helper did not resolve as available" >&2
  exit 1
fi
if [[ "$source" != "bundled" ]]; then
  echo "error: expected bundled Homebrew helper source, got: $source" >&2
  exit 1
fi
if [[ ! -x "$helper_path" ]]; then
  echo "error: resolved helper is not executable: $helper_path" >&2
  exit 1
fi

echo "Resolved bundled helper: $helper_path"

app_dir=""
case "$helper_path" in
  *.app/Contents/MacOS/DescartesNotifier)
    app_dir="${helper_path%/Contents/MacOS/DescartesNotifier}"
    ;;
  *)
    echo "error: bundled helper path is not inside a .app bundle: $helper_path" >&2
    exit 1
    ;;
esac

echo "Helper app: $app_dir"

if command -v codesign >/dev/null 2>&1; then
  echo "Verifying code signature..."
  codesign --verify --deep --strict --verbose=2 "$app_dir"
fi
if command -v xcrun >/dev/null 2>&1; then
  echo "Validating stapled notarization ticket..."
  xcrun stapler validate "$app_dir"
fi
if command -v spctl >/dev/null 2>&1; then
  echo "Assessing Gatekeeper acceptance..."
  spctl --assess --type execute --verbose=4 "$app_dir"
fi

run_descartes alerts notifications status --json > "$status_json_file"
echo "Current notification status:"
cat "$status_json_file"

if (( SKIP_TEST )); then
  echo "Skipping notification test by request."
  exit 0
fi

if (( ! YES )); then
  if [[ ! -t 0 ]]; then
    echo "error: refusing to trigger a notification without interactive stdin; pass --yes or --skip-test" >&2
    exit 2
  fi
  cat <<EOF

About to run: $DESCARTES_BIN alerts notifications test --json
Watch for the first-run Notification Center permission prompt.
Expected attribution: DescartesNotifier, not Terminal or osascript.
Press Enter to trigger the test notification, or Ctrl-C to stop.
EOF
  read -r _ || true
fi

run_descartes alerts notifications test --json > "$test_json_file"
echo "Test delivery result:"
cat "$test_json_file"

delivery_status="$(json_get "$test_json_file" delivery.status || true)"
if [[ -n "$delivery_status" ]]; then
  echo "Delivery status: $delivery_status"
fi

if (( DAEMON_TEST )); then
  if (( ! YES )); then
    if [[ ! -t 0 ]]; then
      echo "error: refusing to trigger daemon-context notification test without interactive stdin; pass --yes or omit --daemon-test" >&2
      exit 2
    fi
    cat <<EOF

About to run a one-shot user LaunchAgent that invokes:
  $DESCARTES_BIN alerts notifications test --json
This is a daemon-context smoke test, not a full alert-intelligence daemon run.
Watch whether the notification displays from the background context.
Press Enter to trigger the daemon-context test, or Ctrl-C to stop.
EOF
    read -r _ || true
  fi
  run_daemon_context_test
fi

cat <<EOF

Manual observations to record in docs/reviews/:
- Did the first-run prompt appear? yes/no
- Prompt attribution: DescartesNotifier / Terminal / osascript / other
- Did the notification display with the expected title/body? yes/no
- Did a second test avoid re-prompting? yes/no
- Does the grant persist in a new shell? yes/no
- Daemon-context smoke: did a LaunchAgent-triggered native delivery display and record an audit status? yes/no
- Denied path: after resetting/denying, does delivery fail closed with an audit record? yes/no

Validation state/audit root preserved at:
  $VALIDATION_ROOT

To reset for a clean retest:
  tccutil reset Notifications $BUNDLE_ID
EOF
