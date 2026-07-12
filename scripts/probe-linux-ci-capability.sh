#!/usr/bin/env bash
# One-off, READ-ONLY probe of the Linux CI guest's capabilities for the S3-priv elevated
# read path (docs/plans/2026-07-11-s3-priv-elevated-read-path.md, pre-flight checklist).
#
# It answers: does the CI Linux guest have a Rust toolchain, passwordless sudo, and the
# sysadmin binaries (setcap/useradd/...) needed to grant the cap_sys_ptrace,cap_dac_read_search
# file-capability UNION (2026-07-12 fix: cap_sys_ptrace alone is insufficient for cross-UID PORT
# resolution -- see scripts/ci-elevated-provenance.sh's header comment) and spawn a second UID for
# the Slice 6 cross-UID validation? Mutates nothing. Safe to run anywhere.
#
# HOW TO RUN: add a temporary, non-blocking Buildkite step (paste the snippet in the
# S3-priv plan / the PR that adds this), or SSH into a tart-ci Linux guest and run it.
# Read the log; delete the temporary step afterwards. Then record the answers in the plan.
set -u

echo "===== descartes S3-priv CI capability probe ====="
echo "----- host / arch / identity -----"
uname -a || true
echo "arch: $(uname -m)   (S3-priv Tier-1 target is x86_64; CI is expected linux-arm64)"
id || true
echo "user: $(whoami 2>/dev/null || echo '?')"

echo "----- Rust toolchain (S3/S4 need this) -----"
if command -v cargo >/dev/null && command -v rustc >/dev/null; then
  echo "RUST: present"; cargo --version; rustc --version
else
  echo "RUST: MISSING (cargo/rustc not on PATH) -> S3/S4 blocked until the image ships a toolchain"
fi

echo "----- passwordless sudo (S5 grant / S6 setcap+useradd need this) -----"
if sudo -n true 2>/dev/null; then
  echo "SUDO: passwordless sudo AVAILABLE"
else
  echo "SUDO: NO passwordless sudo -> cannot setcap or create a 2nd user non-interactively in CI"
fi

echo "----- sysadmin binaries (S5/S6) -----"
for b in setcap getcap capsh useradd groupadd setpriv runuser; do
  if command -v "$b" >/dev/null; then echo "  $b: $(command -v "$b")"; else echo "  $b: MISSING"; fi
done

echo "----- Yama ptrace_scope (affects whether CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH actually work) -----"
if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
  ps="$(cat /proc/sys/kernel/yama/ptrace_scope)"
  echo "  ptrace_scope=$ps  (0=classic,1=restricted-but-capable-ok,2=admin-only,3=disabled-even-for-capable)"
else
  echo "  ptrace_scope: not present (no Yama LSM) -> classic ptrace rules"
fi

echo "----- verdict -----"
have_rust=$(command -v cargo >/dev/null && command -v rustc >/dev/null && echo 1 || echo 0)
have_sudo=$(sudo -n true 2>/dev/null && echo 1 || echo 0)
have_setcap=$(command -v setcap >/dev/null && echo 1 || echo 0)
have_useradd=$(command -v useradd >/dev/null && echo 1 || echo 0)
echo "  rust=$have_rust sudo=$have_sudo setcap=$have_setcap useradd=$have_useradd"
if [ "$have_rust$have_sudo$have_setcap$have_useradd" = "1111" ]; then
  echo "  => CI can build + grant + validate S3-priv (pending ptrace_scope != 2/3)."
else
  echo "  => CI is MISSING at least one prerequisite. S6 validation needs the tart-ci Linux"
  echo "     image extended (Rust toolchain and/or passwordless sudo + libcap2-bin/shadow-utils)"
  echo "     by the Lightless-Labs/tart-ci image owner before S3-priv can be CI-validated."
fi
echo "===== end probe ====="
