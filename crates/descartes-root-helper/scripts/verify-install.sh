#!/usr/bin/env bash
# S3-priv Slice 5 Phase 2 Part D — read-only installer verifier for the descartes-root-helper
# capability grant. Never mutates anything: every check is a stat/getcap/findmnt/systemctl read.
# See docs/operator/linux-elevated-provenance-setup.md for the manual grant this checks, and
# docs/plans/2026-07-11-s3-priv-elevated-read-path.md (Slice 5) for the acceptance criteria.
#
# Usage:
#   verify-install.sh [helper_path] [config_file] [systemd_service_unit] [systemd_socket_unit]
#
#   helper_path            default: /usr/local/libexec/descartes/descartes-root-helper -- this
#                           MUST match DEFAULT_HELPER_PATH in
#                           tools/descartes-cli/src/tools/provenance-elevated.js exactly. The
#                           daemon does not yet honor a custom config.elevated.helper_path (see
#                           the operator doc); a helper installed anywhere else is never invoked.
#   config_file             optional: configDir/provenance.json. If omitted, the config-writability
#                           check is skipped (documented below as a separate operator check).
#   systemd_service_unit    optional: only checked when BOTH unit names are given -- the named
#   systemd_socket_unit     root_helper/systemd fallback is opt-in, not the default mechanism.
#
# Exit status: 0 only if every applicable check passes. Nonzero, with a specific
# operator-facing message on stderr, on the FIRST check that fails (fail-fast).
#
# Deferred to Slice 6 (needs a real `setcap` grant, i.e. root, in CI): the getcap POSITIVE case
# (this script validates getcap's OUTPUT SHAPE once a grant exists; it cannot itself grant one)
# and a functional smoke run of the helper as the daemon user under the real capability. Both
# require root to set up in the first place -- exercised in Slice 6's privileged CI job, not here.

set -euo pipefail

readonly EXPECTED_OWNER="root"
readonly EXPECTED_GROUP="descartes-provenance"
readonly EXPECTED_MODE="750"
readonly EXPECTED_CAP_LINE="cap_sys_ptrace=ep"
readonly WRITABLE_MASK=$((8#022)) # group- or world-writable bits.

HELPER_PATH="${1:-/usr/local/libexec/descartes/descartes-root-helper}"
CONFIG_FILE="${2:-}"
SYSTEMD_SERVICE_UNIT="${3:-}"
SYSTEMD_SOCKET_UNIT="${4:-}"

fail() {
  echo "verify-install: FAIL: $1" >&2
  exit 1
}

info() {
  echo "verify-install: $1"
}

# Fails closed if $1 (a mode as reported by `stat -c %a`, e.g. "750" or "0755") has any
# group/world-write bit set. Compares by bitmask, not by mask-of-permitted-chars, so this cannot
# be fooled by unusual digit counts.
is_group_or_world_writable() {
  local mode_octal="$1"
  local mode_dec=$((8#$mode_octal))
  [ "$((mode_dec & WRITABLE_MASK))" -ne 0 ]
}

# --- 0. Platform guard -----------------------------------------------------------------------
# Every check below (getcap, findmnt, GNU `stat -c`) is Linux-only; running this on macOS/BSD
# would either error confusingly (no getcap/findmnt) or silently mis-parse BSD stat's different
# flag surface (BSD stat has no `-c`).
UNAME_S="$(uname -s)"
if [ "$UNAME_S" != "Linux" ]; then
  fail "this script only runs on Linux (it shells out to getcap/findmnt/GNU stat, none of which are assumed present or POSIX-compatible elsewhere) -- detected '$UNAME_S'"
fi

case "$HELPER_PATH" in
  /*) ;;
  *) fail "helper_path must be an absolute path (got '$HELPER_PATH') -- pass the exact configured/installed path, matching DEFAULT_HELPER_PATH" ;;
esac

# --- 1. Existence, not-a-symlink, canonicalization -------------------------------------------
if [ ! -e "$HELPER_PATH" ]; then
  fail "helper not found at $HELPER_PATH -- install it first (see docs/operator/linux-elevated-provenance-setup.md)"
fi
if [ -L "$HELPER_PATH" ]; then
  fail "helper at $HELPER_PATH is a symlink -- install the real binary at this exact path, never a link to it"
fi
if [ ! -f "$HELPER_PATH" ]; then
  fail "helper at $HELPER_PATH exists but is not a regular file"
fi

if ! CANONICAL_PATH="$(realpath -e "$HELPER_PATH" 2>/dev/null)"; then
  fail "realpath could not resolve $HELPER_PATH"
fi
if [ "$CANONICAL_PATH" != "$HELPER_PATH" ]; then
  fail "helper's canonical path ($CANONICAL_PATH) does not match the configured path ($HELPER_PATH) -- an ancestor directory is a symlink that moves the real target outside the checked chain"
fi

# Every subsequent check runs against the canonical path. At this point TARGET is byte-identical
# to HELPER_PATH (the check above already rejected any divergence) -- kept as its own variable
# for readability/documentation, not because the two can differ past this line.
TARGET="$CANONICAL_PATH"

# --- 2. Owner / group --------------------------------------------------------------------------
OWNER="$(stat -c '%U' "$TARGET")"
GROUP="$(stat -c '%G' "$TARGET")"
if [ "$OWNER" != "$EXPECTED_OWNER" ]; then
  fail "helper at $TARGET is owned by '$OWNER', expected '$EXPECTED_OWNER'"
fi
if [ "$GROUP" != "$EXPECTED_GROUP" ]; then
  fail "helper at $TARGET has group '$GROUP', expected '$EXPECTED_GROUP' (a dedicated group -- see docs/operator/linux-elevated-provenance-setup.md step 1)"
fi

# --- 3. Mode: EXACTLY 750, string-equality (never a mask) ------------------------------------
# A "not group/world-writable" MASK would let setuid/setgid/sticky bits (or an unexpectedly
# narrower/broader-but-still-non-writable mode) slip through silently. Exact string equality
# against "750" rejects all of that in one comparison -- e.g. a setuid 4750 helper reports mode
# "4750" via `stat -c %a`, which fails this check immediately.
MODE="$(stat -c '%a' "$TARGET")"
if [ "$MODE" != "$EXPECTED_MODE" ]; then
  fail "helper at $TARGET has mode '$MODE', expected exactly '$EXPECTED_MODE' (not world-executable/readable, no setuid/setgid/sticky bit, not group-writable)"
fi
# NOTE (residual risk): `stat -c %a` reports only the classic owner/group/other permission bits --
# it cannot see POSIX ACL entries (`setfacl`), which could grant broader effective access than the
# mode above shows. This is largely mitigated by check 4 below (every ancestor directory is
# confirmed root-owned, and adding an ACL to a root-owned path already requires root), but see the
# defense-in-depth ACL check just below it for a direct check rather than relying on that
# inference alone.

# --- 3b. POSIX ACL residual (defense-in-depth only; getfacl may not be installed) -------------
if command -v getfacl >/dev/null 2>&1; then
  for ACL_TARGET in "$TARGET" "$(dirname "$TARGET")"; do
    if getfacl -c "$ACL_TARGET" 2>/dev/null | grep -Eq '^(user|group):[^:]+:|^mask::'; then
      fail "$ACL_TARGET has extended POSIX ACL entries beyond the base owner/group/other bits -- remove them (setfacl -b $ACL_TARGET); they can grant broader access than the mode bits show"
    fi
  done
else
  info "getfacl not found -- skipping the POSIX ACL defense-in-depth check (optional, unlike getcap/findmnt which are hard requirements); operators should ensure no ACLs are set on the install path"
fi

# --- 4. Ancestor directory chain: root-owned, not group/world-writable, not a symlink ---------
# (dir-hijack guard) -- walk from the immediate parent up to and including '/'. This mirrors
# provenance-elevated.js's verifyTrustBoundary ancestor walk in spirit: write access to any
# CONTAINING directory lets a local user swap the binary regardless of the leaf's own bits.
DIR="$(dirname "$TARGET")"
while true; do
  if [ -L "$DIR" ]; then
    fail "ancestor directory $DIR is a symlink -- reject the whole chain (dir-hijack vector)"
  fi
  DIR_OWNER="$(stat -c '%U' "$DIR")"
  if [ "$DIR_OWNER" != "root" ]; then
    fail "ancestor directory $DIR is owned by '$DIR_OWNER', expected 'root'"
  fi
  DIR_MODE="$(stat -c '%a' "$DIR")"
  if is_group_or_world_writable "$DIR_MODE"; then
    fail "ancestor directory $DIR (mode $DIR_MODE) is group- or world-writable -- dir-hijack vector"
  fi
  if [ "$DIR" = "/" ]; then
    break
  fi
  DIR="$(dirname "$DIR")"
done

# --- 5. getcap: MUST be present (hard fail, never a silent skip) -----------------------------
if ! command -v getcap >/dev/null 2>&1; then
  fail "getcap not found -- install libcap2-bin (or your distro's equivalent) to verify the capability grant; this is a hard requirement, never silently skipped"
fi

CAP_OUTPUT="$(getcap "$TARGET" 2>/dev/null || true)"
if [ -z "$CAP_OUTPUT" ]; then
  fail "getcap reported no capabilities on $TARGET -- the cap_sys_ptrace grant is missing (run: setcap cap_sys_ptrace=ep $TARGET)"
fi

# libcap's `getcap` has shipped two output formats across versions:
#   older:  "<path> = cap_sys_ptrace+ep"
#   newer:  "<path> cap_sys_ptrace=ep"
# Strip the leading "<path>" (and, for the older format, the " = "), normalize the older format's
# '+' (add-to-existing at grant time) to '=' for comparison purposes, then require the REMAINDER
# to be exactly "cap_sys_ptrace=ep". Any broader capability set, any other capability name, or an
# unparseable/unexpected line fails this comparison (the prefix-strip is a no-op when it doesn't
# match, which correctly leaves the comparison failing rather than silently accepting garbage).
CAP_REMAINDER="${CAP_OUTPUT#"$TARGET"}"
CAP_REMAINDER="${CAP_REMAINDER# }"
CAP_REMAINDER="${CAP_REMAINDER#= }"
CAP_REMAINDER="${CAP_REMAINDER//+/=}"
CAP_REMAINDER="$(printf '%s' "$CAP_REMAINDER" | tr -d '[:space:]')"

if [ "$CAP_REMAINDER" != "$EXPECTED_CAP_LINE" ]; then
  fail "getcap output for $TARGET is '$CAP_OUTPUT', expected exactly '$EXPECTED_CAP_LINE' and nothing broader (parsed remainder: '$CAP_REMAINDER')"
fi

# --- 6. nosuid mount check ---------------------------------------------------------------------
# A nosuid mount silently voids the file capability: setcap still writes the xattr, getcap still
# reports it correctly (checks 5 above would still pass), but the kernel ignores the capability
# at exec time. This is the single easiest-to-miss failure mode in the whole grant.
if ! command -v findmnt >/dev/null 2>&1; then
  fail "findmnt not found -- cannot verify the filesystem containing $TARGET is not mounted nosuid; failing closed rather than silently skipping"
fi

MOUNT_OPTIONS="$(findmnt -no OPTIONS --target "$TARGET" 2>/dev/null || true)"
if [ -z "$MOUNT_OPTIONS" ]; then
  fail "findmnt could not determine mount options for $TARGET"
fi
case ",$MOUNT_OPTIONS," in
  *,nosuid,*)
    fail "the filesystem containing $TARGET is mounted 'nosuid' -- this silently voids the file capability at exec (setcap/getcap look correct, but the kernel ignores the cap); reinstall on a non-nosuid filesystem"
    ;;
esac

# --- 7. Config file + parent dir: not group/world-writable (optional; only if provided) -------
if [ -n "$CONFIG_FILE" ]; then
  CONFIG_DIR="$(dirname "$CONFIG_FILE")"
  if [ -e "$CONFIG_FILE" ]; then
    CONFIG_MODE="$(stat -c '%a' "$CONFIG_FILE")"
    if is_group_or_world_writable "$CONFIG_MODE"; then
      fail "config file $CONFIG_FILE (mode $CONFIG_MODE) is group- or world-writable"
    fi
  fi
  if [ -e "$CONFIG_DIR" ]; then
    CONFIG_DIR_MODE="$(stat -c '%a' "$CONFIG_DIR")"
    if is_group_or_world_writable "$CONFIG_DIR_MODE"; then
      fail "config directory $CONFIG_DIR (mode $CONFIG_DIR_MODE) is group- or world-writable"
    fi
  fi
else
  info "no config_file argument given -- skipping the config-file writability check (verify configDir/provenance.json and its parent directory separately: neither should be group/world-writable)"
fi

# --- 8. Named systemd fallback (guarded: only when actually configured) -----------------------
if [ -n "$SYSTEMD_SERVICE_UNIT" ] && [ -n "$SYSTEMD_SOCKET_UNIT" ]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemd fallback units were named ($SYSTEMD_SERVICE_UNIT / $SYSTEMD_SOCKET_UNIT) but systemctl is not available to verify them"
  fi

  # `systemctl show` is authoritative (it sees drop-ins) -- never a text parse of the unit file,
  # which could miss an override.
  SERVICE_USER="$(systemctl show -p User --value "$SYSTEMD_SERVICE_UNIT" 2>/dev/null || true)"
  SERVICE_CAPS="$(systemctl show -p CapabilityBoundingSet --value "$SYSTEMD_SERVICE_UNIT" 2>/dev/null || true)"
  SERVICE_NNP="$(systemctl show -p NoNewPrivileges --value "$SYSTEMD_SERVICE_UNIT" 2>/dev/null || true)"
  SERVICE_PROTECT_SYSTEM="$(systemctl show -p ProtectSystem --value "$SYSTEMD_SERVICE_UNIT" 2>/dev/null || true)"

  if [ "$SERVICE_USER" != "root" ]; then
    fail "systemd unit $SYSTEMD_SERVICE_UNIT has User='$SERVICE_USER', expected 'root'"
  fi
  # systemd's --value output for CapabilityBoundingSet is a space-separated cap-name list;
  # require it to be exactly the single CAP_SYS_PTRACE entry (collapse repeated separators first
  # so trivial whitespace differences never cause a false FAIL/PASS).
  SERVICE_CAPS_NORMALIZED="$(printf '%s' "$SERVICE_CAPS" | tr -s '[:space:]' ' ')"
  SERVICE_CAPS_NORMALIZED="${SERVICE_CAPS_NORMALIZED# }"
  SERVICE_CAPS_NORMALIZED="${SERVICE_CAPS_NORMALIZED% }"
  if [ "$SERVICE_CAPS_NORMALIZED" != "CAP_SYS_PTRACE" ]; then
    fail "systemd unit $SYSTEMD_SERVICE_UNIT has CapabilityBoundingSet='$SERVICE_CAPS', expected exactly 'CAP_SYS_PTRACE'"
  fi
  if [ "$SERVICE_NNP" != "yes" ]; then
    fail "systemd unit $SYSTEMD_SERVICE_UNIT has NoNewPrivileges='$SERVICE_NNP', expected 'yes'"
  fi
  # Required alongside NoNewPrivileges (docs/operator/linux-elevated-provenance-setup.md): this
  # mechanism runs the helper as literal root, so ProtectSystem=strict is not optional hardening.
  if [ "$SERVICE_PROTECT_SYSTEM" != "strict" ]; then
    fail "systemd unit $SYSTEMD_SERVICE_UNIT has ProtectSystem='$SERVICE_PROTECT_SYSTEM', expected 'strict' (required alongside NoNewPrivileges)"
  fi

  SOCKET_MODE="$(systemctl show -p SocketMode --value "$SYSTEMD_SOCKET_UNIT" 2>/dev/null || true)"
  SOCKET_USER="$(systemctl show -p SocketUser --value "$SYSTEMD_SOCKET_UNIT" 2>/dev/null || true)"
  SOCKET_GROUP="$(systemctl show -p SocketGroup --value "$SYSTEMD_SOCKET_UNIT" 2>/dev/null || true)"

  if [ "$SOCKET_MODE" != "0660" ]; then
    fail "systemd unit $SYSTEMD_SOCKET_UNIT has SocketMode='$SOCKET_MODE', expected '0660'"
  fi
  if [ "$SOCKET_USER" != "root" ]; then
    fail "systemd unit $SYSTEMD_SOCKET_UNIT has SocketUser='$SOCKET_USER', expected 'root'"
  fi
  if [ "$SOCKET_GROUP" != "$EXPECTED_GROUP" ]; then
    fail "systemd unit $SYSTEMD_SOCKET_UNIT has SocketGroup='$SOCKET_GROUP', expected '$EXPECTED_GROUP'"
  fi
else
  info "no systemd fallback units named -- skipping the named root_helper/systemd checks (only relevant if that fallback mechanism is actually configured)"
fi

info "PASS: $TARGET is correctly scoped (existence/symlink/owner/group/mode/ancestor-chain/getcap-shape/mount all verified)"
info "NOTE (deferred to Slice 6): a real capability grant + functional smoke test as the daemon user still needs root to set up and is exercised in privileged CI, not by this script."
exit 0
