# Session/peer detector tuning (from 2026-10-05 real-host calibration)

**Created:** 2026-10-06
**Status:** PARTLY DECIDED — R6 decided; R3/R4/R5/R7/R9/R10 awaiting operator answers (explained in plain terms 2026-10-06).
**Origin:** real-host calibration workflow (2026-10-05) ranked list R1–R10. R8 (Tailscale peers do not move the peer count) shipped in `fix/watch-fabrication-2026-10`.

## Decided

- **R6 — reboot awareness (operator, 2026-10-06): option 1.** When a reboot is detected (uptime < gap since the previous structural tick):
  - `session.churn`: suppressed and NOT reported as evaluated (an existing alert freezes; it never falsely recovers).
  - `session.count_drop`: recorded but non-notifying.
  - **Follow-up note (operator):** make this more context-aware later — e.g. distinguish a planned/clean reboot from an unexpected one (shutdown cause, uptime pattern, who/what initiated it), and do not blanket-suppress when other signals in the same window look suspicious (peer spike, new service, canary, correlation).

## Awaiting operator decision

- **R3** notify once per active alert (activation + severity escalation), instead of re-notifying every 15-minute cooldown. Note: the S7 soak showed the post-upgrade `daemon.fact_history.horizon_short` alert would send ~480 notifications over ~5 days under current re-notify behaviour.
- **R4** stddev floor 0.5 → 0.75 (session + peer).
- **R5** score session/peer over 14 days instead of 31 (via `baselineFactWindowMs`, not the shared constant).
- **R7** session CRITICAL guard (≥4 sessions AND ≥75% of mean), or cap at warning.
- **R9** wake grace: after sleep, score only spikes on the first structural tick.
- **R10** lone `session.churn` notifies or is record-only.
