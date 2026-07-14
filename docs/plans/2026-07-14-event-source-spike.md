# Event-Source Spike — Real-Time exec/file/network/login Collection (Slice 5 go/no-go)

**Created:** 2026-07-14
**Status:** COMPLETE — time-boxed spike, decision recorded (§5). Zero daemon-loop code shipped from this document, per the parent plan's Definition of Done for Slice 5.
**Parent plan:** `docs/plans/2026-07-13-observed-incident-collectors.md`, Slice 5 ("Real-time event-source spike (TIME-BOXED, decision-aid only)").
**Mirrors structure of:** `docs/plans/2026-07-11-s3-priv-elevated-read-path.md` §3 ("macOS go/no-go spike") — a real prerequisites assessment ending in a written decision, not a hardened POC. Same spike guardrail applies: "skip it / gap too narrow" is a valid, successful outcome (see memory note "spikes stay time-boxed").
**Time-box used:** one investigation session — read-only macOS probing on this dev machine + targeted research (WebSearch, via a research subagent) for the Linux half and for macOS entitlement/ES-architecture facts that can't be verified locally.

**Reviewed:** 2026-07-14 (via Fable subagent) — **ENDORSE-WITH-CHANGES**. Corrections folded in below: fanotify's `FAN_OPEN_EXEC`/`FAN_OPEN_EXEC_PERM` exec event type (present since Linux 5.0; the original claim of "no exec event type at any privilege level" was factually wrong — drawn from `fanotify_init(2)` alone rather than `fanotify_mark(2)`/`fanotify(7)` — the DECLINE holds, but on corrected grounds: a weak signal, dominated by the other branches); the macOS network DECLINE reframed from an absolute "architecturally impossible" to "zero achievable via any **supported** path," with an explicit revisit trigger added for macOS 26.4; the macOS `eslogger` DEFER is now trigger-gated (§5) rather than an open-ended "someday" item; the Linux auditd group-readable-log open question is resolved (§1b finding 1). The eBPF characterization (finding 2, §1b) was independently confirmed accurate — no change. **No branch verdict flips.**

---

## 0. What this spike does NOT do

- Does not write, wire, or stub any collector, daemon-loop code, config schema, or CI job. Its only artifact is this document plus the Slice 5 status update in the parent plan.
- Does not configure any Linux audit rules (mutating — out of scope for a read-only agent), does not install a macOS system extension, and does not run any privileged capture (`sudo eslogger ...`, `auditctl -a ...`) itself. Per the parent plan's safety checks for this slice: "read-only investigation only... do not configure new audit rules or install a system extension during the spike."
- Does not spin up a Linux VM or a disposable Linux CI probe (the `scripts/probe-linux-ci-capability.sh` precedent). Judged not warranted this pass: that precedent exists because "does this specific CI guest have passwordless sudo" was a genuinely unverifiable host-specific fact. The Linux-side questions this spike needed answered — which capability gates `auditctl -l` vs passive audit-log consumption, whether `CAP_BPF` alone suffices for tracing programs, whether fanotify has a usable unprivileged mode — are stable kernel/tool documentation facts, not host-specific unknowns. A CI probe becomes worth spending on a *specific target host* only after a "proceed" decision, not during the initial feasibility read.
- Does not re-litigate Slices 0–4/6 of the parent plan. Slice 6 (L2 correlation) is explicitly documented there as **not** depending on this spike's outcome — that remains true regardless of what's decided below.

---

## 1. Grounding

### 1a. macOS — confirmed directly, read-only, on this dev machine

Host: macOS 26.2 (build 25C56), unprivileged user (`uid=502`, no elevated shell used at any point).

```
$ which eslogger
/usr/bin/eslogger
$ eslogger --list-events        # exits 0, unprivileged, no capture started
[104 event short-names listed]
```

Confirmed present in the unprivileged `--list-events` output (this enumerates *supported* event types — it does not require, and does not start, a live capture):
- **Process/exec:** `exec`, `fork`, `exit`, `clone`, `signal`.
- **Login/auth:** `login_login`, `login_logout`, `lw_session_login`, `lw_session_logout`, `openssh_login`, `openssh_logout`, `authentication`, `authorization_judgement`, `authorization_petition`, `su`, `sudo`.
- **IPC (not IP networking):** `uipc_bind`, `uipc_connect` — per the Endpoint Security API these are Unix-domain-socket bind/connect only.
- **Not present anywhere in the 104-entry list:** any generic AF_INET/AF_INET6 socket-connect or network-send event.

`man eslogger` (read directly, no capture run) states explicitly:
> "eslogger must be run as super-user and requires the responsible process to have TCC Full Disk Access authorization... IMPORTANT: eslogger is NOT API in any sense. Do NOT rely on the structure or information emitted for ANY reason. It may change from release to release without warning."

So on this machine, **today, unprivileged**: `eslogger`'s existence, its event catalog, and its documented privilege requirement are all confirmed facts, not assumptions. No `sudo`, no capture, no system-extension install was performed.

### 1b. Linux + macOS-entitlement facts — researched (no local VM; WebSearch via a research subagent, citations preserved)

| # | Question | Finding | Confidence |
|---|---|---|---|
| 1 | Does `auditctl -l` need `CAP_AUDIT_CONTROL`? Is there a lower-privilege passive-read path? | Yes, `auditctl -l` (rule listing) needs `CAP_AUDIT_CONTROL`. A **distinct**, narrower capability, `CAP_AUDIT_READ` (kernel 3.16+), gates joining the `AUDIT_NLGRP_READLOG` multicast group for passive consumption of audit *event records* — independent of rule-control privilege. It is real and usable today, not merely theoretical (added specifically so services like `systemd-journald` could consume audit events without rule-control rights). **Resolved (Fable review 2026-07-14):** upstream `auditd.conf` defaults `log_group=root`, so `/var/log/audit/audit.log` is root-only unless the operator deliberately loosens it — a group-readable file-tail path is therefore an **additional, opportunistic** route (available only where an operator has configured `log_group` to a readable group), **not a default one**. This does not change the existing verdict (§2/§4/§5: DEFER, low priority, opportunistic) — it slots into it. | High — `capabilities(7)`, `auditctl(8)`, LKML patch series, `auditd.conf(5)` |
| 2 | Does `CAP_BPF` alone (5.8+) suffice for exec/network-tracing eBPF programs? | No. `CAP_BPF` alone covers map creation/basic ops. **Tracing programs (kprobe/tracepoint/raw_tracepoint)** — the program types needed for exec/network event capture — additionally need `CAP_PERFMON`. Network programs (TC/XDP) additionally need `CAP_NET_ADMIN`. Separately, `kernel.unprivileged_bpf_disabled` defaults to **closed** on Ubuntu (since 21.10 / 20.04.4 HWE), and is disabled/restricted by default on recent Debian and RHEL — so on mainstream distros, an unprivileged process gets no benefit from `CAP_BPF` alone regardless. | High (CAP_BPF/CAP_PERFMON split, Ubuntu default); Medium (Debian/RHEL specifics) |
| 3 | Does `fanotify_init()` need `CAP_SYS_ADMIN`? Is there a usable unprivileged mode? | Host-wide/mount-wide monitoring needs `CAP_SYS_ADMIN`. An unprivileged mode exists since Linux 5.13, but is restricted to `FAN_REPORT_FID`, **individually-marked inodes only** (no `FAN_MARK_MOUNT`/`FAN_MARK_FILESYSTEM`), no permission/blocking events, no unlimited queue/marks. **Not sufficient for host-wide monitoring of any kind.** **Corrected (Fable review 2026-07-14):** the earlier claim that fanotify "has no exec event type at all" was factually wrong — it was drawn from reading `fanotify_init(2)` alone, not `fanotify_mark(2)`/`fanotify(7)`. fanotify **does** have an exec event type, `FAN_OPEN_EXEC`/`FAN_OPEN_EXEC_PERM` (since Linux 5.0), used in production by RHEL's `fapolicyd`. It is nonetheless a **weak** exec signal: file-open-for-exec only, with no argv/process-ancestry context, and blind to interpreter/script reads (e.g. `python script.py` surfaces only the `python` binary's open, not `script.py`). fanotify still has **zero** network event types at any privilege level — that half of the original claim holds. | High — `fanotify_mark(2)`, `fanotify(7)`, `fapolicyd` docs |
| 4 | Is `com.apple.developer.endpoint-security.client` still Apple-approval-gated? | Yes — apply via Apple's System Extensions Request Form, wait for Apple's manual email approval; not self-grantable in Xcode/the developer portal. Must ship as a System Extension (not a plain daemon): code signing, notarization, and explicit end-user approval in System Settings > Privacy & Security to activate. | High on mechanism; Medium on 2026-specific freshness (no 2026-dated primary source found, nothing suggests it changed) |
| 5 | Does Apple's EndpointSecurity expose a generic IP network-connect event (for a custom ES client, not just `eslogger`)? | No, via any **supported** path — confirmed as a widely-corroborated limitation, not an `eslogger`-specific gap. ES's only network-adjacent events are Unix-domain-socket (`uipc_bind`/`uipc_connect`). Real IP-level visibility requires an entirely different mechanism — NetworkExtension (`NEFilterDataProvider` content filter, or `NEPacketTunnelProvider`) — a different entitlement and architecture, not an extension of the ES entitlement. Corroborated by Elastic, Objective-See, and Outflank EDR-internals writeups plus Apple's own forums. **Updated (Fable review 2026-07-14):** the macOS 26.4 rumor is upgraded from "not reliable" to **corroborated but undocumented** — reportedly new `ES_EVENT_TYPE_RESERVED_*` network events, gated to entitlement-holding custom ES clients only, explicitly not published API. **REVISIT TRIGGER:** if Apple documents these 26.4 ES network events as real, published API (not a reserved/undocumented placeholder), re-open this DECLINE — that would close the "no supported path" gap this finding currently rests on. | High on the core gap (no supported path today); Medium on the 26.4 rumor's existence; Low on its API stability/timeline |

---

## 2. Doors-and-corners — prerequisites table per source

| Source | Mechanism | Privilege/entitlement prerequisite | exec | network | login | Verdict |
|---|---|---|---|---|---|---|
| **macOS custom ES client** | Own System Extension + `com.apple.developer.endpoint-security.client` | Apple-approval-gated entitlement (apply, wait for Apple); System Extension packaging; notarization; end-user approval prompt; elevated launch context. **Large, multi-week-class lift**, not self-serve. | ✓ (same ES event set as `eslogger`, plus AUTH/blocking events `eslogger` doesn't expose) | ✗ — no supported path, same as `eslogger` (finding 5) | ✓ | **DECLINE.** No network-coverage win over `eslogger` to justify the entitlement-approval dependency and packaging lift. **Revisit trigger:** Apple documents macOS 26.4's rumored ES network events as real, published API. |
| **macOS `eslogger`** | Apple-shipped ES-backed CLI, already carries Apple's own ES entitlement | **Root (super-user) + Full Disk Access (TCC)** for the invoking process. **No new entitlement** (the binary is Apple-signed and already carries it) — this is the key structural advantage over a custom client. No system extension, no notarization, no user-approval flow *of your own* to build. | ✓ confirmed (`exec`/`fork`/`exit`) | ✗ confirmed — no supported path, only Unix-domain IPC (finding 5, §1a) | ✓ confirmed, strong (`login_login`/`logout`, `openssh_login`/`logout`, `authentication`, `su`, `sudo`) | **DEFER, trigger-gated** — lowest-lift real option for exec+login; still needs a standing elevated grant (root+FDA), addressed in §4/§5. |
| **Linux auditd (passive read)** | `AUDIT_NLGRP_READLOG` multicast consumption vs `AUDIT_LIST` control | `CAP_AUDIT_READ` (narrower than `CAP_AUDIT_CONTROL`/root) suffices for passive consumption — a real, scoped, non-root capability. Still a capability grant, not zero-privilege; a non-root operator with neither grant sees `unable`/permission-denied, exactly the plan's anticipated degrade case. | contingent — only if the operator's *own*, pre-existing auditd rules already log `execve` (Descartes cannot add rules; mutating is out of scope) | contingent — same caveat, for `connect` rules | often present by default (PAM-triggered `USER_LOGIN`/`USER_AUTH` records) | **DEFER, low priority** — an "if already configured" opportunistic source, not urgent, no new privilege-model design needed (degrade-not-fabricate already covers the unconfigured/unprivileged case). |
| **Linux eBPF (tracing programs)** | `BPF_PROG_LOAD` of kprobe/tracepoint/raw_tracepoint | `CAP_BPF` alone insufficient for tracing programs — needs `CAP_BPF + CAP_PERFMON`; `unprivileged_bpf_disabled` defaults closed on Ubuntu/Debian/RHEL, closing the unprivileged path entirely on mainstream distros in practice. | ✓ (in principle, richest option) | ✓ (in principle) | via process/login-adjacent tracepoints, not as directly as ES/auditd | **DECLINE for now** — "privileged elevated path" territory at least as large as the whole S3-priv effort (its own verifier-safe programs, ring-buffer plumbing, hardening, CI validation); disproportionate to a milestone-scoped spike. |
| **Linux fanotify** | `fanotify_mark()` (host-wide marks) | Host-wide monitoring needs `CAP_SYS_ADMIN`. Unprivileged mode (5.13+) exists but is restricted to individually-marked inodes only — not host-wide. | △ weak — `FAN_OPEN_EXEC`/`FAN_OPEN_EXEC_PERM` (5.0+) exists and is used in production (RHEL `fapolicyd`), but is file-open-for-exec only: no argv, no process-ancestry, blind to interpreter/script reads | ✗ — no network event type at any privilege level | ✗ | **DECLINE** — weak exec signal at high privilege cost (`CAP_SYS_ADMIN` for host-wide marks), zero network; **strictly dominated** by auditd/eBPF at similar-or-lower privilege, not a scope mismatch independent of privilege. |

---

## 3. Decision criteria (per the parent plan's Slice 5 time-box)

**(a) Does `eslogger`/passive-auditd-read already cover the incident's actual gap (exec + network + login) WITHOUT new entitlements/privilege?**

No, on both platforms, for different reasons:
- **macOS `eslogger`** clears the *entitlement* bar (none needed — the Apple-signed binary already carries it) but **not** the *privilege* bar (root + Full Disk Access is a real, standing elevated grant). Event coverage is strong for exec+login and structurally zero for network — this is an ES architecture limit, not a privilege or "not-yet-built" gap, so it is **zero achievable via any supported path** today (see the macOS 26.4 revisit trigger in §1b finding 5 / §5).
- **Linux passive auditd read** needs `CAP_AUDIT_READ` (new privilege, though narrower than root/`CAP_AUDIT_CONTROL`), and even granted, exec/network coverage is contingent on the operator's own pre-existing rule configuration, which Descartes cannot create (mutating, out of scope). Login coverage is more often present by default (PAM-triggered records) than exec/network are.

**(b) Operational cost vs marginal forensic value over Slices 1–4's polling:**

- **Cost:** A continuous `eslogger` capture means a standing root+FDA daemon (unlike S3-priv's `root_helper`, which holds elevated capability only for a per-call scoping window, a continuous capture would hold it for the daemon's entire lifetime) plus real log volume (every exec on the host) needing its own retention/rotation design distinct from `fact-store.js`'s existing 30-day/5MB cap. Linux eBPF/fanotify would mean building an entirely new privileged Rust subsystem at least on the scale of the whole S3-priv effort (Slices 3–4's crate, hardening, CI validation), for a mechanism (fanotify) that turns out to be scope-mismatched anyway.
- **Value:** Real and specific for macOS exec+login — sub-tick-resolution process ancestry and exact login/command ordering would fully answer "was this the AI agent's own remote shell, and in what order did the kill-then-resurrect happen," which Slices 1–4/6's tick-resolution polling can only approximate (Slice 1's `created_at_fingerprint` churn detection already catches same-tick kill-then-resurrect as attribute churn, just not its exact order or the responsible process). Value for network is zero on macOS (architectural dead end) and uncertain/contingent on Linux.
- **Given Slices 1–4/6 already substantially narrow the practical version of the *same* incident shape (mass session drop, unattributed peer login, statistical anomaly, cross-stream correlation) without any new privilege at all**, the cost/value ratio for a continuously-running, always-privileged collector does not clear the bar today.

**(c) Explicit recommendation:** **DEFER** the event-source-collector line of work as a whole. See §5 for the per-branch disposition and the narrowest viable next step if a future revisit happens.

---

## 4. Operational-cost-vs-value summary (compact)

| Branch | Standing cost if built as a continuous daemon | Marginal value over Slices 1–4/6 | Verdict |
|---|---|---|---|
| macOS `eslogger` (exec+login) | Root + FDA held for the daemon's full lifetime; real event volume needing its own bounded retention | Real: sub-tick ordering + process ancestry the polling model cannot produce | DEFER; redesign as bounded/triggered before reconsidering (§5) |
| macOS `eslogger`/custom ES client (network) | N/A — no supported path can deliver this today | None — zero achievable via any supported path | DECLINE — revisit if Apple documents macOS 26.4's rumored ES network events as real API |
| Linux auditd passive-read | Low (single narrow capability, if the operator already configured rules) | Contingent on pre-existing, Descartes-uncontrolled config | DEFER, low priority, opportunistic only |
| Linux eBPF (tracing) | Very high — new privileged subsystem, S3-priv-scale effort | High in principle, but disproportionate to this milestone's scope | DECLINE for now |
| Linux fanotify | High (`CAP_SYS_ADMIN` for host-wide marks) | Weak — `FAN_OPEN_EXEC` gives file-open-for-exec only, no argv/ancestry; zero network | DECLINE — dominated by auditd/eBPF at similar-or-lower privilege |

---

## 5. Recommendation

**Overall: DEFER.** Do not schedule a Slice 5b build in this plan's current cycle. Slices 1–4/6 already meaningfully close the practical version of the incident's retrospective-reconstruction gap (tick-resolution polling + `created_at_fingerprint` churn detection + peer/VPN baseline + statistical anomaly + cross-stream correlation) without any new privilege. The event-source family's genuine remaining value is concentrated in one branch (macOS `eslogger`, exec+login only), whose operational-cost profile doesn't yet have a cheap design, and whose network-half of the incident's own gap cannot be closed by *any* researched option on macOS, and only contingently on Linux.

**Per-branch disposition:**
- **DECLINE outright:** macOS custom ES client (no coverage win over `eslogger`, much bigger lift); network-connect coverage via any ES-based mechanism on macOS (zero achievable via any supported path today, confirmed independently — **revisit trigger:** Apple documents macOS 26.4's rumored ES network events as real, published API); Linux eBPF (disproportionate lift for this milestone); Linux fanotify (weak exec signal — `FAN_OPEN_EXEC` is file-open-only, no argv/ancestry — at high privilege cost and zero network, dominated by auditd/eBPF).
- **DEFER, revisitable:** macOS `eslogger` for exec+login only. **REVISIT TRIGGERS (Fable review 2026-07-14, resolves flagged question 1 below) — this DEFER only becomes actionable once ONE of these fires, and is otherwise dormant:**
  (a) a real incident where Slices 1–4/6's tick-resolution reconstruction demonstrably **failed** to answer the question that mattered (the polling/fact-history/correlation model genuinely couldn't reconstruct what happened — not merely that it was slower or coarser than sub-tick capture would have been); OR
  (b) an operator explicitly **requests** sub-tick forensics for a specific need AND **accepts** the bounded standing root+Full-Disk-Access grant this would require.
  **With these triggers in place, DEFER is functionally "DECLINE-until-triggered"** — nothing about this branch proceeds absent (a) or (b), and the "DEFER" label is cosmetic (it signals "the value case is real, revisit if triggered" rather than "dead, never reconsider"). Without an explicit trigger condition this would be the wrong posture — DEFER risks becoming a perpetually-open "someday" item; the trigger-gating above is what keeps it honest.

  **Narrowest viable next step, if triggered** (not scheduled now): 
  1. An **operator-run**, manual, time-boxed validation — not Descartes code — to concretely measure event volume/signal quality before any build commitment. Recommended command, for the operator to run via `!` on this machine if they want to sharpen this further (not run by this spike):
     ```
     sudo eslogger exec fork exit login_login login_logout openssh_login openssh_logout authentication su sudo | jq .
     ```
     run for a short bounded window while rehearsing the incident's own shape (SSH in, kill a tmux session, resurrect it) — the same rehearsal shape Slice 1's kill-then-resurrect fixture already models synthetically, but for real.
  2. If that validation looks good, any actual build is its **own** dedicated plan (this document does not pre-author it), sequenced exactly like S3-priv: Node plumbing against a mock helper contract first, then the real invocation. It **must**:
     - Redesign the capture as **bounded and alert-triggered** (extending Slice 2's evidence-freeze model — start a short `eslogger` window when Slice 4/6 raises a correlation candidate, capture, stop, bundle — never a continuous background daemon), which is what would actually make the operational-cost side of criterion (b) acceptable.
     - **Reuse the S3-priv opt-in/audience-scoped/deny-by-default model verbatim** for the root+FDA grant — no new privilege mechanism, per the parent plan's own safety spine ("the only acceptable model is the already-shipped S3-priv... mechanism").
     - Get its **own** fresh `doors-and-corners` pass and adversarial review at actual implementation time, not a reuse of this spike's planning-time pass (mirrors the S3-priv macOS spike's own stated requirement).
- **DEFER, low priority, opportunistic:** Linux auditd passive-read as an "if the operator already configured it" future collector idea — not scheduled, not urgent, requires no new privilege-model design if ever picked up (degrade-not-fabricate already covers the unconfigured/unprivileged case cleanly).

**Flagged for reviewer (Fable) sanity-check — all three RESOLVED in the 2026-07-14 review:**
1. **RESOLVED.** Is DEFER (vs. a flat DECLINE of the whole family) the right call, given that `eslogger`'s exec+login value is real but the bounded/triggered redesign that would make its cost acceptable doesn't exist yet — or should this be recorded as DECLINE-until-a-concrete-incident-shows-polling-insufficient, to avoid this becoming a perpetually-open "someday" item? **Answer: DEFER, but explicitly trigger-gated** — see the REVISIT TRIGGERS block above. With triggers ((a) a real incident where tick-resolution reconstruction demonstrably failed, or (b) an operator request plus acceptance of the standing root+FDA grant), DEFER is functionally "DECLINE-until-triggered," which resolves the "perpetually-open someday item" risk without needing a harder DECLINE label.
2. **RESOLVED.** Double-check the `CAP_AUDIT_READ` characterization (§1b, finding 1) against a real Linux host if this is ever revisited — worth confirming whether common distro configurations additionally expose `/var/log/audit/audit.log` to a group-readable path (e.g. an `adm`-equivalent group) that would make passive consumption *more* available in practice than the capability-only analysis here suggests. **Answer: the `CAP_AUDIT_READ` characterization is fair; one addition folded in** — upstream `auditd.conf` defaults `log_group=root`, so `/var/log/audit/audit.log` is root-only unless an operator deliberately loosens it. A group-readable path is therefore an **additional opportunistic route**, not a default one, and does not change the DEFER/low-priority/opportunistic verdict.
3. **RESOLVED.** Sanity-check the fanotify "wrong mechanism regardless of privilege" claim (§2) — this is a stronger, more dismissive characterization than the parent plan's own framing (which treated fanotify as a viable-but-privileged option). Confirmed via `fanotify_init(2)` directly, but worth a second look given it changes fanotify from "defer, privileged" to "decline, scope-mismatched." **Answer: the claim was factually wrong, not merely overstated** — it was drawn from `fanotify_init(2)` alone. fanotify does have `FAN_OPEN_EXEC`/`FAN_OPEN_EXEC_PERM` (5.0+, used in production by RHEL's `fapolicyd`). The DECLINE still holds, but on corrected grounds: a weak exec-only signal (no argv/ancestry, blind to interpreter/script reads) at high privilege cost (`CAP_SYS_ADMIN`) and zero network — dominated by auditd/eBPF at similar-or-lower privilege, not "scope-mismatched regardless of privilege." See §1b finding 3, §2, §4 for the corrected text.

---

## 6. Sources (from the research pass)

- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html), LKML `CAP_AUDIT_READ` patch series.
- [Introduction to CAP_BPF](https://www.mdaverde.com/posts/cap-bpf/), [LWN: Introduce CAP_BPF](https://lwn.net/Articles/820560/), [LWN: A crop of new capabilities](https://lwn.net/Articles/822362/), [Ubuntu Discourse: unprivileged eBPF disabled by default](https://discourse.ubuntu.com/t/unprivileged-ebpf-disabled-by-default-for-ubuntu-20-04-lts-18-04-lts-16-04-esm/27047).
- [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html), [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html), [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html) — corrected citation set (Fable review 2026-07-14): the original finding cited only `fanotify_init(2)`, which does not cover event-mask flags like `FAN_OPEN_EXEC`; `fanotify_mark(2)`/`fanotify(7)` are the correct references for fanotify's exec event type.
- [`com.apple.developer.endpoint-security.client` entitlement docs](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client), [Apple Developer Forums thread 655467](https://developer.apple.com/forums/thread/655467).
- [Elastic: Mac system extensions for threat detection, Part 1](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-1), [Objective-See blog_0x86](https://objective-see.org/blog/blog_0x86.html), [Apple Developer Forums thread 748407](https://developer.apple.com/forums/thread/748407), [Outflank: EDR Internals for macOS and Linux](https://www.outflank.nl/blog/2024/06/03/edr-internals-macos-linux/).
- `man eslogger`, `eslogger --list-events`, `eslogger --help`, `sw_vers` — all run directly, read-only, on this dev machine.
