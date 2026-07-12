# Linux Elevated Provenance — Manual Setup

**Audience:** operators installing Descartes on Linux who want cross-UID runtime provenance
(resolving the pid/executable/command owning a listening port when it runs under a **different**
UID than the Descartes daemon).
**Status:** v1 is a documented **manual** grant, checked by a read-only verifier. There is no
automated installer for this step — see `docs/plans/2026-07-11-s3-priv-elevated-read-path.md`
Slice 5 for why (no Linux packaging pipeline exists in this repo today, and an automated
root-requiring installer is explicitly out of scope for v1).

## Why this is opt-in and manual

Without this setup, Descartes's runtime provenance collector (`inspect_runtime_provenance`)
already resolves everything it can unprivileged. For a listening socket owned by the daemon's own
UID, that's a full resolution. For a socket owned by a **different** UID, the unprivileged path
correctly reports the owning UID (a free, confident fact from `/proc/net/tcp`) but cannot resolve
the pid/executable/command — it returns `status:"partial"`, `confidence:0.4`,
`review_hint:"missing_permission"`. This is graceful and safe; nothing is broken if you skip this
document.

The elevated read path closes that gap by using a tiny, purpose-built helper binary
(`crates/descartes-root-helper`) that holds **only the minimal capability union
`CAP_SYS_PTRACE,CAP_DAC_READ_SEARCH`** (never full root, unless you explicitly choose the named
systemd fallback below) and does nothing but resolve a pid or port to
`{pid, uid, executable_path, command}` on a fixed, bounded argv. (Both capabilities are required —
see Step 4 below for why `CAP_SYS_PTRACE` alone is insufficient.) It is gated behind **two
independent opt-ins**, both required:

1. **This document's OS-level grant** (out-of-code, manual, one-time).
2. **`configDir/provenance.json`'s `elevated.enabled:true`** (Descartes's own config, Slice 1).

Either absent, the feature degrades silently back to the unprivileged `partial`/`0.4` baseline
above. Nothing in the daemon/provenance runtime's own code path (`tools/descartes-cli/src/**/*.js`)
ever escalates privilege or shells out to `sudo`, `pkexec`, `setcap`, or any other
privilege-escalation mechanism — that invariant is enforced by
`tools/descartes-cli/test/escalation-lint.test.js`, a standing lint that scans that source tree for
escalation shell-outs and macOS privileged-helper API references (comment- and string-safe, so it
does not false-positive on prose describing the invariant) and runs as part of `npm test` on every
build and every local run. This document is the **only** place a human runs those commands.

## Prerequisites

- The helper binary built from a revision of this repo that includes the PID-reuse fix (Slice 5A,
  merged as part of `crates/descartes-root-helper`'s `procfs.rs` module — a `/proc/<pid>` dirfd
  pin-then-verify that closes the recycled-pid window). There is no `--version` flag on the
  helper; confirm by building from a commit where `crates/descartes-root-helper/src/procfs.rs`
  exists and is used by `resolve_pid`/`resolve_port` in `crates/descartes-root-helper/src/lib.rs`.
  Do not grant capability to a helper built from an older revision.
- `setcap`/`getcap` (from `libcap2-bin` or your distro's equivalent), `groupadd`, root or `sudo`
  access, and — for the verifier — `findmnt` and GNU `stat`.
- A filesystem for the install path that is **not** mounted `nosuid` (see the warning below).

## The exact manual sequence

Run these as root (or via `sudo`) on the host running the Descartes daemon.

### 1. Create a dedicated group

```bash
groupadd --system descartes-provenance
```

This is a **dedicated** group scoped to exactly this capability, not a general admin/`sudo`/`wheel`
group. Anyone added to it can invoke the helper (Step 5); keep membership tight.

### 2. Install the built, hardened, release helper at the fixed path

```bash
install -D -m 0750 -o root -g descartes-provenance \
  target/release/descartes-root-helper \
  /usr/local/libexec/descartes/descartes-root-helper
```

**This exact path — `/usr/local/libexec/descartes/descartes-root-helper` — is not a suggestion.**
It is the literal value of `DEFAULT_HELPER_PATH` in
`tools/descartes-cli/src/tools/provenance-elevated.js`, and it is where the daemon will actually
look for the helper.

> **Decision, stated plainly so you don't `setcap` a path the daemon never invokes:**
> `provenance.json`'s config schema (Slice 1) already has a `elevated.helper_path` field, but
> `resolveElevated` does not yet honor it — the real call is
> `options.helperPath ?? DEFAULT_HELPER_PATH`, and `options.helperPath` is only ever supplied by
> tests, never by the daemon's own config-loading path today. **Wiring a custom `helper_path`
> through would widen the trust surface (an attacker who can rewrite config could redirect the
> daemon to a different binary) and has been deliberately deferred.** Until that changes, the
> helper **must** live at the fixed `DEFAULT_HELPER_PATH` above, or the daemon will never find it
> (the elevated path will silently, harmlessly degrade back to the unprivileged baseline — it will
> not error loudly).

### 3. Confirm ownership and mode

```bash
chown root:descartes-provenance /usr/local/libexec/descartes/descartes-root-helper
chmod 0750 /usr/local/libexec/descartes/descartes-root-helper
```

(The `install -D -m -o -g` above already does this; these are here as an explicit, idempotent
double-check, and as the two commands you'll re-run after every upgrade — see below.) Mode
**exactly** `0750`: owner read/write/execute, group read/execute, **nothing** for other. Not
world-executable, not world-readable. `verify-install.sh` (below) checks this as an exact string
match, not a "not group/world-writable" mask — a mask would let a stray setuid/setgid/sticky bit
slip through undetected.

### 4. Grant the capability

```bash
setcap "cap_sys_ptrace,cap_dac_read_search=ep" /usr/local/libexec/descartes/descartes-root-helper
```

This is the **primary** mechanism, and it is a **union of two capabilities, both required**. A
real privileged CI run (2026-07-12) proved `cap_sys_ptrace` **alone is insufficient** for cross-UID
**port** resolution: `--resolve-port` enumerates `/proc/<pid>/fd` (mode `0500`, owner = the target
uid) to match a listening socket's inode to its owning pid. The fd **directory's** kernel
permission check (`proc_fd_permission`) is DAC/same-thread-group gated — **not**
`ptrace_may_access` — so *enumerating* another user's fd table needs `cap_dac_read_search`;
`cap_sys_ptrace` only covers the subsequent `readlink` of the fd targets and of `/exe`. (Cross-UID
`--resolve-pid` alone needs only `cap_sys_ptrace`, since `status`/`cmdline` are world-readable —
but the file-capability grant is per-binary, so it must always carry the union.) `cap_dac_override`
was tested and confirmed **not** needed. `ep` = Effective + Permitted (both capabilities are active
on exec, not merely inheritable). Do **not** grant a broader capability set —
`verify-install.sh` below rejects anything except exactly this 2-capability set with `ep` flags —
and do **not** leave a narrower one in place (e.g. the stale single-cap `cap_sys_ptrace=ep` grant
from before 2026-07-12): see the upgrade warning below.

### 5. Add the daemon's account to the group

```bash
usermod -a -G descartes-provenance <account-the-descartes-daemon-runs-as>
```

The daemon must run under an account that is a member of `descartes-provenance` (directly or via
its primary group) to be permitted to execute the `0750` helper binary at all. Group membership
changes typically require a new login session (or `newgrp`/service restart) to take effect for
already-running processes.

### 6. Enable the elevated path in Descartes's own config

Edit `configDir/provenance.json` (see `tools/descartes-cli/src/provenance-elevated-config.js` for
the exact path resolution — `configDir` follows the daemon's normal XDG config resolution):

```json
{
  "elevated": {
    "enabled": true,
    "mechanism": "auto"
  }
}
```

`mechanism` may be:

- `"auto"` — probes and uses `cap_sys_ptrace`-class mechanisms only. **`"auto"` never
  auto-selects `root_helper`** (the systemd fallback below), even if a probe reports it as
  available — that mechanism must be named explicitly.
- `"root_helper"` — named explicitly, only if you have deliberately set up the systemd fallback
  in the next section instead of (or in addition to) the capability grant above.

This is the **second, independent** opt-in condition. Both this and Steps 1–5 above must be true;
either alone leaves the feature inert.

## Re-run after every upgrade

**After every helper binary upgrade, re-run Step 4 (`setcap`) and `verify-install.sh`.** A
replaced binary is a **new inode** — file capabilities are stored as an extended attribute on the
inode, and that xattr does **not** survive a file replacement (a fresh `install`/`cp`/deployment
step, even to the identical path). Skipping this after an upgrade is a **silent degrade**: the
daemon will simply stop being able to invoke the helper's elevated path (or the helper will exec
fine but the capability-requiring syscalls will fail), with no loud error — it just falls back to
the unprivileged baseline. Re-running `verify-install.sh` after every upgrade is how you catch
this before it becomes a surprise.

**If this host still carries the OLD single-capability grant (`cap_sys_ptrace=ep`, from before
2026-07-12), that is also a silent degrade — and a more insidious one than a missing grant.**
`--probe` (what the daemon uses to decide `elevated_available`) only checks that the helper is
invocable at all, not what a specific cross-UID resolution actually needs — so a host on the old
grant reports `available:true` and *looks* healthy from Descartes's own perspective. But any
cross-UID **port** resolution silently falls back to the unprivileged `partial`/`0.4`/
`missing_permission` baseline, with no loud error anywhere in the daemon's own logs.
`verify-install.sh` is what catches this (it fails closed on the old single-cap grant — see Step
4). **Action: on every host set up before 2026-07-12, re-run Step 4's `setcap` with the
2-capability set above, then re-run `verify-install.sh`, and confirm it reports PASS before
trusting cross-UID port resolutions from that host.**

## `nosuid` mounts silently void the grant

If `/usr/local` (or wherever you install the helper) is mounted `nosuid`, `setcap` will still
succeed, the xattr will still be written, and `getcap` will still report
`cap_dac_read_search,cap_sys_ptrace=ep` correctly — **but the kernel ignores the capability at exec
time on a `nosuid` mount.** This is a
classic, easy-to-miss trap: everything *looks* correctly configured, and only a live invocation
would reveal the capability isn't actually active. Install the helper on a filesystem that is
**not** mounted `nosuid`. `verify-install.sh` checks this via `findmnt` and fails loudly if the
target mount has `nosuid` set.

## Verifying the install

```bash
crates/descartes-root-helper/scripts/verify-install.sh \
  /usr/local/libexec/descartes/descartes-root-helper
```

Run this after the initial setup, after every upgrade (see above), and any time you want to
confirm the grant is still correctly scoped. It is entirely read-only — it never mutates
anything — and exits nonzero with a specific, operator-facing message on the first thing that's
wrong: missing/symlinked binary, wrong owner/group, wrong mode, a writable or symlinked ancestor
directory anywhere in the path (a classic local-privesc "dir-hijack" vector — an attacker who can
write to `/usr/local/libexec` or `/usr/local/libexec/descartes`, even with the binary itself
correctly locked down, could otherwise swap in their own binary), missing `getcap`, wrong/broader
`getcap` output, or a `nosuid` mount. See the script's own header comment for the full check list.

POSIX ACLs (`setfacl`) are invisible to the mode bits the script checks, so the script also runs a
best-effort `getfacl`-based defense-in-depth check (skipped, not failed, if `getfacl` isn't
installed) confirming the helper and its parent directory carry no extended ACL entries. This is
largely mitigated already by the root-owned-ancestor check above, but operators should still treat
"no ACLs on the install path" as their own responsibility, independent of whether `getfacl` happens
to be present on a given host.

One thing it deliberately does **not** verify unprivileged: that the capability actually,
functionally works end-to-end as the daemon's own user (that needs a real invocation under a real
grant, which needs root to set up in the first place — this is exercised in this repo's Linux CI
elevated-path job, not by the local verifier).

## Named systemd fallback (explicitly separate from `mechanism:"auto"`)

If `cap_sys_ptrace`-via-`setcap` is unavailable or unsuitable for your environment, a named
systemd socket-activated root service is documented as an alternative — **never** auto-selected;
it must be named explicitly as `mechanism:"root_helper"` in Step 6 above.

This mechanism runs the helper as literal **root** (not merely `CAP_SYS_PTRACE`), so it must be
scoped at least as tightly as the primary capability binary's `0750 root:descartes-provenance`:

**`descartes-root-helper.service`:**

```ini
[Service]
Type=simple
User=root
ExecStart=/usr/local/libexec/descartes/descartes-root-helper
NoNewPrivileges=yes
ProtectSystem=strict
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
```

`CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE` — **exactly this set, no more** — bounds
what the root-running process could ever gain, even though it starts as root. Both capabilities are
required for the same reason the primary file-capability grant is a union (see Step 4): a
process's *effective* capabilities are bounded by its capability bounding set even when it runs as
literal root, so a bounding set restricted to `CAP_SYS_PTRACE` alone reproduces the **exact same**
cross-UID `/proc/<pid>/fd`-enumeration failure the stale single-cap file-capability grant does —
plain, unrestricted root "just works" here only because it isn't bounding-set-restricted at all,
which is precisely what this hardening deliberately narrows away. This is not optional hardening,
it's the whole point of choosing this fallback instead of granting broader root access.
`NoNewPrivileges=yes` and `ProtectSystem=strict` are required alongside it.

**`descartes-root-helper.socket`** (audience-scoped — **this is the load-bearing hardening for
this mechanism**, equivalent to the primary binary's `0750` mode):

```ini
[Socket]
ListenStream=/run/descartes/root-helper.sock
SocketMode=0660
SocketUser=root
SocketGroup=descartes-provenance
```

`SocketMode=0660`, `SocketUser=root`, `SocketGroup=descartes-provenance` — **exactly**. Since this
mechanism runs the helper as literal root, an unscoped activation socket would let *any* local
process reaching it trigger a root-run invocation, regardless of Descartes's own config opt-in.
`verify-install.sh` checks these three properties, plus the `.service` unit's `User`,
`CapabilityBoundingSet`, `NoNewPrivileges`, and `ProtectSystem` (via `systemctl show`, the
authoritative source that also sees drop-ins — never by parsing unit-file text) whenever systemd
unit names are passed to it.

## Summary checklist

- [ ] `groupadd --system descartes-provenance` (dedicated group)
- [ ] Helper installed at exactly `/usr/local/libexec/descartes/descartes-root-helper`
- [ ] `chown root:descartes-provenance` + `chmod 0750` on that exact path
- [ ] `setcap "cap_sys_ptrace,cap_dac_read_search=ep"` on that exact path (both capabilities — see
      Step 4)
- [ ] Install target is **not** on a `nosuid` mount
- [ ] Daemon's account is a member of `descartes-provenance`
- [ ] `configDir/provenance.json`: `elevated.enabled:true`, `mechanism` set explicitly
- [ ] `verify-install.sh` reports PASS
- [ ] (If using the named systemd fallback instead) both units' hardening matches the section
      above, `mechanism:"root_helper"` named explicitly (never `"auto"`)
- [ ] Calendar reminder: re-run `setcap` + `verify-install.sh` after every helper upgrade
