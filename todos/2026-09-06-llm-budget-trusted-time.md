# LLM-budget hardening: write-ahead audit + trusted monotonic time

**Created:** 2026-09-06 (daybreak re-gate round 3 → A5 disposition)
**Status:** deferred (scoped, operator-authorized disposition of a residual daybreak NOT READY)
**Area:** `tools/descartes-cli/src/alert-intelligence.js` — the trailing-hour LLM-adjudication budget
**Severity:** low–medium — a bounded *over-call* of an opt-in, rate-limited, audited, no-tools LLM
path; never a fabrication of monitoring data, a suppression of a real alert, or an authority bypass.
The attacker capability required (step the system wall clock, or race the audit file) is roughly the
same local-privilege actor the trusted-same-user-state boundary already defers off-host.

## Why this is one slice, not three scattered findings

daybreak's action-and-llm-surface re-gate surfaced three residuals that share a single root cause —
**the budget mixes a persisted wall-clock record `ts` with process-local timing, and reads the audit
after it has already acted.** Patching any one in isolation just moves the seam:

- **A3 — deliver-before-durable-audit.** A call can be delivered before its audit record is durably
  appended; a crash/kill in that window loses the record and frees budget that was really spent.
- **A4 — concurrent TOCTOU.** Two ticks (or two processes) read the same trailing-hour audit, both
  see budget, both admit — the read→decide→append sequence is not serialized.
- **A5 — wall-clock manipulation.** Three distinct vectors across three re-gate rounds
  (forward-jump → per-tick accumulation → backward-step-then-restore), each freeing budget the
  clock hadn't earned. An in-process `process.hrtime` monotonic anchor was tried and **reverted**
  (2026-09-06): on Linux (Tier 1) `CLOCK_MONOTONIC` pauses across suspend, so after a laptop sleep
  the bounded clock lagged real wall, records read as future-dated, and the fail-closed future-ts
  clamp counted them in-window *indefinitely* — silently darkening the LLM route until restart.
  Forward-jump protection and suspend robustness are indistinguishable without an external time
  source, which is the proof this is a redesign and not a patch.

## Target design (to be planned before implementing)

1. **Write-ahead the intent, then act, then finalize.** Append a `reserved` record *before* the LLM
   call, finalize/annotate it after — so a crash leaves budget consumed (fail-closed), never freed.
2. **Serialize read→decide→append** across ticks and processes (advisory lock / single-writer /
   compare-and-swap on a sequence), closing the TOCTOU.
3. **A trusted monotonic sequence in the audit records** (monotonic counter + boot-id continuity),
   so budget windowing no longer trusts the raw wall clock. Wall `ts` stays for human/audit reading;
   the *budget* decision keys off the trusted sequence.

## Acceptance

- The three vectors above are covered by tests that a raw-wall-clock implementation fails and the
  new one passes, **without** reintroducing the suspend-darkening regression (add an explicit
  suspend/`CLOCK_MONOTONIC`-pause test — the fixture that caught the reverted anchor).
- daybreak re-gate of action-and-llm-surface reaches READY with no new same-interplay residual.
- Ordinary aging-out (a genuinely-elapsed hour frees the budget) still holds.

## Current state (what shipped instead)

The budget window uses the **raw wall clock** (`now`) directly — see the `REVERTED` tombstone above
`boundBudgetNow`'s former location in `alert-intelligence.js`. This is the correct default until a
trusted time source exists: it has no suspend regression, and the backward-clock-step case stays
covered fail-closed by `isWithinTrailingHour`'s future-ts clamp. The confirmed A1/A2/A6 fabrication
findings from the same re-gate were fixed and shipped; only this budget-clock class is deferred.

Related: [[descartes-autonomy-doctrine-no-uac-gate]] (reversibility×corroboration), the trusted-state
threat model (`docs/design/state-integrity-threat-model.md`), and the trusted-state step-① plan.
