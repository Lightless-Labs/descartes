#!/usr/bin/env bash
# S3-priv Slice 6 -- the FIRST privileged CI step for descartes-root-helper. Runs ONLY inside a
# disposable Tart Linux VM (never a developer machine, never a long-lived host): it setcaps
# cap_sys_ptrace,cap_dac_read_search=ep on the built release helper and proves cross-UID /proc
# provenance resolution end to end -- the unprivileged Node path degrades (status "partial"), the
# elevated path upgrades (status "ok") -- both against the SAME listening socket, in ONE job, so
# they can't drift apart.
#
# TWO-CAP GRANT (empirically corrected, 2026-07-12): an earlier real privileged run of this exact
# job proved cap_sys_ptrace ALONE is INSUFFICIENT for cross-UID PORT resolution -- the elevated
# assertion below failed while a root-run resolve of the same port succeeded, isolating the gap to
# the file-capability grant, not the resolution logic. `resolve_port` (proc_linux.rs) enumerates
# `/proc/<pid>/fd` (mode 0500, owner = the target uid) to match a listening socket's inode to its
# owning pid. The fd DIRECTORY's kernel permission hook (`proc_fd_permission`) is DAC/
# same-thread-group gated -- NOT `ptrace_may_access` -- so *enumerating* another user's fd table
# needs `cap_dac_read_search`; `cap_sys_ptrace` alone only covers the subsequent `readlinkat` of
# the fd targets and of `/exe`. The minimal sufficient set, confirmed by testing an escalating
# series of grants in that same privileged run, is the UNION of both --
# `cap_sys_ptrace,cap_dac_read_search=ep` -- with `cap_dac_override` confirmed NOT needed.
# (Cross-UID `--resolve-pid` alone needs only `cap_sys_ptrace`, since `status`/`cmdline` are
# world-readable -- but a single file-capability grant is per-binary, so it must always carry the
# union.) See docs/plans/2026-07-11-s3-priv-elevated-read-path.md's and
# docs/plans/2026-07-10-layer-b-provenance.md's 2026-07-12 addenda for the full writeup, and
# crates/descartes-root-helper/src/proc_linux.rs's module doc for the code-level explanation. NO
# seccomp/allowlist change was needed or made: the newly-succeeding syscalls (openat/getdents64/
# readlinkat) were already allowlisted (hardening.rs) -- the capability grant only changes their
# return value from EACCES to success.
#
# This is the ONLY place in the whole S3-priv plan that grants a real Linux capability. See
# docs/plans/2026-07-11-s3-priv-elevated-read-path.md Slice 6, docs/operator/
# linux-elevated-provenance-setup.md (the manual grant this mirrors), and
# crates/descartes-root-helper/scripts/verify-install.sh (the read-only checks this also runs).
#
# Self-contained like scripts/probe-linux-ci-capability.sh: .buildkite/pipeline.yml just calls
# `bash scripts/ci-elevated-provenance.sh`, no inline YAML, no $$-escaping.
#
# CANNOT be validated on a macOS dev machine (no Linux root, no cap_sys_ptrace/cap_dac_read_search)
# -- this script's own first green Buildkite run IS the validation. See this file's own header
# comment in the repo history / the plan doc for why every assertion below is pinned against the
# real code rather than assumed.

set -euo pipefail

# ------------------------------------------------------------------------------------------------
# Fixed configuration.
# ------------------------------------------------------------------------------------------------

readonly GROUP_NAME="descartes-provenance"
readonly XUID_USER="descartes-xuid"
# Must match DEFAULT_HELPER_PATH in tools/descartes-cli/src/tools/provenance-elevated.js exactly --
# the daemon never looks anywhere else.
readonly HELPER_INSTALL_PATH="/usr/local/libexec/descartes/descartes-root-helper"
readonly NODE_VERSION="22.21.1"

# ------------------------------------------------------------------------------------------------
# Teardown. Idempotent, never fails the trap -- every cleanup command is best-effort (`|| true`).
# Order matters: kill the listener BEFORE userdel (userdel fails on a user with a live process).
# ------------------------------------------------------------------------------------------------

LISTENER_PID=""
LISTENER_WRAPPER_PID=""
INSTALLED_HELPER=""

cleanup() {
  local status=$?
  if [ -n "${LISTENER_PID:-}" ]; then
    sudo kill "$LISTENER_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "${LISTENER_WRAPPER_PID:-}" ]; then
    sudo kill "$LISTENER_WRAPPER_PID" >/dev/null 2>&1 || true
  fi
  if id "$XUID_USER" >/dev/null 2>&1; then
    sudo userdel "$XUID_USER" >/dev/null 2>&1 || true
  fi
  if [ -n "${INSTALLED_HELPER:-}" ] && [ -e "$INSTALLED_HELPER" ]; then
    sudo rm -f "$INSTALLED_HELPER" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "ci-elevated-provenance: FAIL: $1" >&2
  exit 1
}

info() {
  echo "ci-elevated-provenance: $1"
}

# ------------------------------------------------------------------------------------------------
# Pre-flight. Fail LOUD with an actionable message on any miss -- never a silent skip.
# ------------------------------------------------------------------------------------------------

preflight() {
  sudo -n true 2>/dev/null || fail "passwordless sudo is not available for $(id -un) -- this step needs root to build/install/setcap the helper and create a second UID; confirm the CI image grants NOPASSWD sudo (probe #123 confirmed this on ci-linux-arm64-rust-bazel; if this regressed, the image changed)"

  if [ "$(id -u)" -eq 0 ]; then
    fail "this script must run as a NON-ROOT CI user (got uid 0) -- the entire cross-UID premise requires the Node harness to run unprivileged; if node ran as root the unprivileged baseline would already be status:\"ok\" and there would be nothing to prove"
  fi

  local required_cmds=(cargo setcap getcap useradd groupadd setpriv ss sg sudo)
  local missing=()
  local cmd
  for cmd in "${required_cmds[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    fail "missing required CI-guest binaries: ${missing[*]} -- probe #123 confirmed cargo/sudo/setcap/getcap/useradd/groupadd/setpriv/runuser on this image; if this regressed, the tart-ci Linux image changed and Slice 6 needs to be re-triaged"
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    info "python3 not found (probe #123 did not check for it) -- installing"
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3
    command -v python3 >/dev/null 2>&1 || fail "python3 install attempted via apt-get but is still not on PATH"
  fi
}

# ------------------------------------------------------------------------------------------------
# Node + checkout (mirrors the existing :linux: job's install_node/prepare_guest_checkout).
# ------------------------------------------------------------------------------------------------

install_node() {
  local uname_s uname_m node_platform archive_ext archive_url node_dir tmp_archive
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"

  case "$uname_s-$uname_m" in
    Linux-aarch64 | Linux-arm64)
      node_platform="linux-arm64"
      archive_ext="tar.xz"
      ;;
    *)
      fail "unsupported Linux Node.js platform: $uname_s $uname_m"
      ;;
  esac

  node_dir="$HOME/.local/node-v$NODE_VERSION-$node_platform"
  if [ ! -x "$node_dir/bin/node" ]; then
    mkdir -p "$node_dir"
    tmp_archive="$(mktemp)"
    archive_url="https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-$node_platform.$archive_ext"
    curl --proto '=https' --tlsv1.2 -fsSL "$archive_url" -o "$tmp_archive"
    tar -xJf "$tmp_archive" -C "$node_dir" --strip-components=1
    rm -f "$tmp_archive"
  fi
  export PATH="$node_dir/bin:$PATH"
}

WORK_DIR=""

prepare_guest_checkout() {
  local source_dir
  source_dir="$(pwd)"
  WORK_DIR="$HOME/descartes-elevated-checkout"
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  rsync -a --delete --exclude node_modules --exclude .git "$source_dir/" "$WORK_DIR/"
  cd "$WORK_DIR"
}

# ------------------------------------------------------------------------------------------------
# Grant dance (must-fix 4): root-created install dirs via `install -D`, matching the operator doc's
# exact command so verify-install.sh's ancestor-chain check (every dir root-owned) passes.
# ------------------------------------------------------------------------------------------------

grant_capability() {
  sudo groupadd --system "$GROUP_NAME" || getent group "$GROUP_NAME" >/dev/null 2>&1 || fail "groupadd $GROUP_NAME failed and the group still does not exist"

  sudo install -D -m 0750 -o root -g "$GROUP_NAME" \
    target/release/descartes-root-helper \
    "$HELPER_INSTALL_PATH"
  INSTALLED_HELPER="$HELPER_INSTALL_PATH"

  # 2-cap union (2026-07-12 fix) -- see this file's header comment for why cap_sys_ptrace alone is
  # insufficient for cross-UID PORT resolution.
  sudo setcap "cap_sys_ptrace,cap_dac_read_search=ep" "$HELPER_INSTALL_PATH"

  # MUST-FIX 1: this adds the group to /etc/group only -- it does NOT change the supplementary
  # group list of THIS already-running shell/script process. The elevated Node run below is
  # `sg`-wrapped specifically because of this.
  sudo usermod -aG "$GROUP_NAME" "$(id -un)"
}

# ------------------------------------------------------------------------------------------------
# Second UID + listener (must-fix 2). A FULL uid/gid switch via `sudo setpriv` (not `sudo -u`, so
# this only relies on the already-confirmed plain root-defaulting `sudo -n true`, not on a sudoers
# Runas_Spec covering arbitrary target users/groups) so BOTH the socket uid (/proc/net/tcp) and
# /proc/<pid>/status Uid equal the 2nd uid -- the uid-agreement guard in resolveCrossUidPortResult
# (tools/descartes-cli/src/tools/provenance.js) degrades the upgrade otherwise.
# ------------------------------------------------------------------------------------------------

setup_second_uid() {
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$XUID_USER" || id "$XUID_USER" >/dev/null 2>&1 || fail "useradd $XUID_USER failed and the user still does not exist"
  XUID="$(id -u "$XUID_USER")"
  XGID="$(id -g "$XUID_USER")"
}

start_listener() {
  local listener_log="$WORK_DIR/.ci-elevated-listener.log"

  # Inline the listener via `python3 -c`, NOT a script FILE. A prior run failed with
  # "python3: can't open file '$WORK_DIR/.ci-elevated-listener.py': [Errno 13] Permission denied":
  # $WORK_DIR is under the CI user's home (/home/admin), which the 2nd uid (999) cannot traverse or
  # read, so a script file there is unreadable to it. Passing the code as an argv string sidesteps
  # file access entirely. (The LOG below is fine: the CI user opens its fd via the redirect, and the
  # child inherits that fd, so uid 999 never opens the log path itself.)
  local listener_py
  listener_py="$(cat <<'PYEOF'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
s.listen(1)
# Unambiguous marker: the parser greps the WHOLE log for LISTENER_PORT=<n>, so a sudo/setpriv
# warning line (merged via 2>&1) can never be mistaken for the port (a prior run parsed a phantom
# "313" out of such noise via head -n1|tr, then ss found no socket on it).
print("LISTENER_PORT=%d" % s.getsockname()[1], flush=True)
sys.stdout.flush()
while True:
    s.accept()
PYEOF
)"

  : >"$listener_log"

  # `sudo setpriv --reuid --regid --clear-groups` -- run as root (plain sudo, already confirmed),
  # THEN drop to the 2nd uid/gid inside setpriv. --clear-groups so the child never inherits the
  # invoking root process's own supplementary groups (setpriv's own documented footgun otherwise).
  # The listener code is passed via `-c` so the unreadable-script-file problem above cannot recur.
  # shellcheck disable=SC2024 # deliberate: the redirect must be opened by THIS (unprivileged) CI
  # user, not by sudo/root, so the log stays readable without sudo below; the child inherits the
  # already-open fd regardless of its own uid.
  sudo setpriv --reuid="$XUID" --regid="$XGID" --clear-groups python3 -c "$listener_py" >"$listener_log" 2>&1 &
  LISTENER_WRAPPER_PID=$!

  PORT=""
  local candidate
  for _ in $(seq 1 50); do
    # Grep the WHOLE log for the marker (NOT head -n1|tr): a warning line before python's output
    # must not be parsed as the port. Absent marker after the timeout -> the dump below shows why.
    candidate="$(grep -oE 'LISTENER_PORT=[0-9]+' "$listener_log" 2>/dev/null | head -n1 | cut -d= -f2 || true)"
    if [ -n "$candidate" ]; then
      PORT="$candidate"
      break
    fi
    sleep 0.2
  done

  if [ -z "${PORT:-}" ]; then
    cat "$listener_log" >&2 || true
    fail "listener did not print a port within the timeout -- see log above (python3/setpriv on this guest may differ from what was assumed)"
  fi
  info "listener bound 127.0.0.1:$PORT as uid=$XUID"

  # MUST-FIX 2: the REAL listener pid, via `ss`, NEVER `$!` -- `$!` here is `sudo`'s own pid (sudo
  # forks/monitors, and setpriv execs into python3 without forking again, so the real pid is
  # several layers removed from the backgrounded wrapper). Asserting resolved.pid === $! would
  # false-fail every single run.
  local ss_output
  ss_output="$(sudo ss -ltnpH "sport = :$PORT" || true)"
  if [ -z "$ss_output" ]; then
    info "--- listener log (diagnostic) ---"
    cat "$listener_log" >&2 || true
    info "--- all LISTEN sockets (diagnostic) ---"
    sudo ss -ltnp >&2 || true
    fail "ss reported no LISTEN socket on port $PORT (see listener log + socket table above)"
  fi
  # `|| true` on the pipeline: under `set -o pipefail`, a no-match `grep` would otherwise abort the
  # whole script right here (via `set -e`) with a bare "exit 1" and none of this function's own
  # diagnostics -- neutralize that so the explicit check on the next line produces the real message.
  LISTENER_PID="$(printf '%s\n' "$ss_output" | grep -oE 'pid=[0-9]+' | head -n1 | cut -d= -f2 || true)"
  [ -n "${LISTENER_PID:-}" ] || fail "could not parse a listener pid out of ss output: $ss_output"
  info "listener real pid (via ss) = $LISTENER_PID (background wrapper \$! was $LISTENER_WRAPPER_PID -- NOT used for any assertion)"
}

verify_uid_agreement() {
  local port="$1" pid="$2" expected_uid="$3"
  local port_hex socket_uid proc_uid

  port_hex="$(printf '%04X' "$port")"
  socket_uid="$(awk -v want=":$port_hex" '$4 == "0A" && $2 ~ want"$" {print $8; exit}' /proc/net/tcp)"
  [ "$socket_uid" = "$expected_uid" ] || fail "socket uid mismatch: /proc/net/tcp reports uid=$socket_uid for LISTEN port $port, expected $expected_uid -- the elevated upgrade's cross-UID premise requires the two to differ from the CI user AND agree with each other"

  proc_uid="$(sudo awk '/^Uid:/{print $2; exit}' "/proc/$pid/status")"
  [ "$proc_uid" = "$expected_uid" ] || fail "process uid mismatch: /proc/$pid/status reports Uid=$proc_uid for pid $pid, expected $expected_uid"

  info "uid agreement confirmed: socket uid ($socket_uid) and /proc/$pid/status Uid ($proc_uid) both equal $expected_uid"
}

log_ptrace_scope() {
  local scope
  if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
    scope="$(cat /proc/sys/kernel/yama/ptrace_scope)"
  else
    scope="unreadable"
  fi
  # A finding to record, not a failure: PTRACE_MODE_READ (what resolve_port needs) is exempt from
  # Yama scope 2 in most configurations, and scope 3 disables ptrace even for capable processes.
  # Probe #123 confirmed this guest is scope=1; the elevated-envelope assertion below hard-asserts
  # "1" for exactly that reason -- if a future guest image changes this, that assertion (not this
  # log line) is what will need revisiting.
  info "guest /proc/sys/kernel/yama/ptrace_scope = $scope"
}

# ------------------------------------------------------------------------------------------------
# Envelope assertions (must-fix 5/6). Grounded against the real code, not the plan's prose:
#   - envelope-level status/confidence/review_hint: computeProvenanceEnvelopeFields,
#     tools/descartes-cli/src/tools/provenance.js:458-463 (partial -> 0.4/missing_permission;
#     ok+non-unknown-source -> 1/none), applied in resolveProvenance at :886-887.
#   - envelope.result.resolved.*: the record nested under `.result` by finalizeProvenanceResult,
#     provenance.js:515-529; the baseline shape is resolveCrossUidPortResult's unprivilegedCore,
#     provenance.js:689-699 (status "partial", pid left undefined, user.uid the free/confident
#     owning-uid fact, reason "cross_uid_or_unresolved_pid"); the elevated shape is upgradedCore,
#     provenance.js:750-769 (status "ok", pid/executable_path from the verified helper response,
#     user.uid always primary.uid -- never the helper's self-report, per the trust-model comment at
#     :739-744).
#   - envelope.result.privilege.*: computePrivilege, provenance.js:475-485, with the elevated
#     success path calling it as computePrivilege({ mechanism: upgrade.mechanism,
#     elevatedAvailable: true, elevatedUsed: true }) at provenance.js:774; ptrace_scope is attached
#     by resolveCrossUidPortResult's withPtraceScopeDiagnostic, provenance.js:727-737, gated on
#     config.elevated.enabled===true (true here, since provenance.json sets it explicitly below).
#   - mechanism "cap_sys_ptrace" explicit (not "auto"): provenance-elevated-config.js's
#     PROVENANCE_MECHANISMS enum includes it verbatim (line 18); resolveElevated,
#     tools/descartes-cli/src/tools/provenance-elevated.js:240-264, threads the CONFIGURED
#     mechanism straight through as `attemptedMechanism` whenever it is not "auto" -- so the
#     result's privilege.mechanism is exactly the string this script writes into
#     configDir/provenance.json below.
#   - Real-code test precedent for this exact shape: tools/descartes-cli/test/
#     provenance-elevated.test.js:120-134 (baseline) and :152-176 (elevated upgrade).
# ------------------------------------------------------------------------------------------------

assert_baseline_envelope() {
  local envelope_json="$1" expected_uid="$2"
  ENVELOPE_JSON="$envelope_json" EXPECTED_UID="$expected_uid" node <<'NODE_EOF' || fail "baseline (unprivileged) envelope assertions failed -- see node output above; envelope was: $envelope_json"
const envelope = JSON.parse(process.env.ENVELOPE_JSON);
const expectedUid = Number(process.env.EXPECTED_UID);
const resolved = envelope?.result?.resolved ?? {};
const checks = [
  ["envelope.status", envelope.status, "partial"],
  ["envelope.confidence", envelope.confidence, 0.4],
  ["envelope.review_hint", envelope.review_hint, "missing_permission"],
  ["envelope.result.resolved.pid", resolved.pid, undefined],
  ["envelope.result.resolved.user.uid", resolved.user?.uid, expectedUid],
  ["envelope.result.resolved.reason", resolved.reason, "cross_uid_or_unresolved_pid"],
];
let ok = true;
for (const [label, actual, expected] of checks) {
  if (actual !== expected) {
    ok = false;
    console.error(`BASELINE ASSERTION FAILED: ${label} = ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
}
if (!ok) process.exit(1);
console.error("baseline envelope assertions: OK (status partial / confidence 0.4 / review_hint missing_permission / resolved.pid undefined / resolved.user.uid matches / resolved.reason cross_uid_or_unresolved_pid)");
NODE_EOF
}

assert_elevated_envelope() {
  local envelope_json="$1" expected_uid="$2" expected_pid="$3" expected_mechanism="$4"
  ENVELOPE_JSON="$envelope_json" EXPECTED_UID="$expected_uid" EXPECTED_PID="$expected_pid" EXPECTED_MECHANISM="$expected_mechanism" \
    node <<'NODE_EOF' || fail "elevated envelope assertions failed -- see node output above; envelope was: $envelope_json"
const envelope = JSON.parse(process.env.ENVELOPE_JSON);
const expectedUid = Number(process.env.EXPECTED_UID);
const expectedPid = Number(process.env.EXPECTED_PID);
const expectedMechanism = process.env.EXPECTED_MECHANISM;
const resolved = envelope?.result?.resolved ?? {};
const privilege = envelope?.result?.privilege ?? {};
const checks = [
  ["envelope.status", envelope.status, "ok"],
  ["envelope.confidence", envelope.confidence, 1],
  ["envelope.result.resolved.pid", resolved.pid, expectedPid],
  ["envelope.result.resolved.user.uid", resolved.user?.uid, expectedUid],
  ["envelope.result.privilege.elevated_used", privilege.elevated_used, true],
  ["envelope.result.privilege.mechanism", privilege.mechanism, expectedMechanism],
  ["envelope.result.privilege.ptrace_scope", privilege.ptrace_scope, "1"],
];
let ok = true;
for (const [label, actual, expected] of checks) {
  if (actual !== expected) {
    ok = false;
    console.error(`ELEVATED ASSERTION FAILED: ${label} = ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
}
if (typeof resolved.executable_path !== "string" || resolved.executable_path.length === 0) {
  ok = false;
  console.error(`ELEVATED ASSERTION FAILED: envelope.result.resolved.executable_path not populated: ${JSON.stringify(resolved.executable_path)}`);
}
if (!ok) process.exit(1);
console.error("elevated envelope assertions: OK (status ok / confidence 1 / resolved.pid matches real listener pid / resolved.user.uid matches / executable_path populated / privilege.elevated_used true / privilege.mechanism matches / privilege.ptrace_scope \"1\")");
NODE_EOF
}

# ------------------------------------------------------------------------------------------------
# Main.
# ------------------------------------------------------------------------------------------------

if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ]; then
  export HOME=/home/admin
fi

preflight
install_node
prepare_guest_checkout

node --version
npm --version
cargo --version

# Only the release build/test here (Slice-5-deferred coverage). The existing :linux: job already
# runs `cargo test --workspace --locked` (debug) plus the full npm suite -- do not repeat either;
# zero new signal, double cold-build cost.
cargo build --release -p descartes-root-helper
cargo test --workspace --locked --release

grant_capability

# verify-install.sh's getcap-POSITIVE + install checks against the REAL grant just made. It does
# NOT do a functional smoke (that's this step, below) -- see its own header comment.
bash crates/descartes-root-helper/scripts/verify-install.sh "$HELPER_INSTALL_PATH"

setup_second_uid
start_listener
verify_uid_agreement "$PORT" "$LISTENER_PID" "$XUID"
log_ptrace_scope

HARNESS_PATH="$WORK_DIR/tools/descartes-cli/scripts/ci-elevated-smoke.mjs"
NODE_BIN="$(command -v node)"

# --- Unprivileged baseline run: config disabled (no provenance.json at all), no group needed. ---
BASELINE_XDG_CONFIG_HOME="$WORK_DIR/.ci-elevated-xdg-baseline"
mkdir -p "$BASELINE_XDG_CONFIG_HOME"
# `if ! VAR=...; then` (not a bare `VAR="$(...)"`) so a harness crash under `set -e` hits this
# script's own `fail` with an actionable message instead of aborting silently with a bare bash
# "command failed" error -- the if-condition context is exempt from `set -e`'s abort-on-failure.
if ! BASELINE_JSON="$(XDG_CONFIG_HOME="$BASELINE_XDG_CONFIG_HOME" "$NODE_BIN" "$HARNESS_PATH" "$PORT")"; then
  fail "baseline (unprivileged) harness crashed -- ci-elevated-smoke.mjs exited non-zero instead of printing its one JSON line; see node's stderr above this message"
fi
info "baseline envelope: $BASELINE_JSON"
assert_baseline_envelope "$BASELINE_JSON" "$XUID"

# --- Elevated run: config enabled with the explicit mechanism, `sg`-wrapped (must-fix 1) so the
# group added to /etc/group above is actually active for THIS process. ---
ELEVATED_XDG_CONFIG_HOME="$WORK_DIR/.ci-elevated-xdg-elevated"
mkdir -p "$ELEVATED_XDG_CONFIG_HOME/descartes"
cat >"$ELEVATED_XDG_CONFIG_HOME/descartes/provenance.json" <<'JSONEOF'
{
  "elevated": {
    "enabled": true,
    "mechanism": "cap_sys_ptrace"
  }
}
JSONEOF

# Same `if ! VAR=...; then fail ...` guard as the baseline capture above -- an `sg`-wrapped
# harness crash under `set -e` would otherwise abort with a bare bash error instead of a plain
# (uninformative) bash failure.
if ! ELEVATED_JSON="$(sg "$GROUP_NAME" -c "XDG_CONFIG_HOME=$ELEVATED_XDG_CONFIG_HOME $NODE_BIN $HARNESS_PATH $PORT")"; then
  fail "elevated harness crashed (see stderr above) -- ci-elevated-smoke.mjs exited non-zero under \`sg $GROUP_NAME\` instead of printing its one JSON line"
fi
info "elevated envelope: $ELEVATED_JSON"
assert_elevated_envelope "$ELEVATED_JSON" "$XUID" "$LISTENER_PID" "cap_sys_ptrace"

info "PASS -- unprivileged baseline degraded to partial/0.4/missing_permission; elevated path upgraded to ok/1 and resolved cross-UID pid $LISTENER_PID (uid $XUID) via mechanism cap_sys_ptrace (file-cap grant: cap_sys_ptrace,cap_dac_read_search=ep)"
