# Session/peer noise → context the learner can use (from 2026-10-05 real-host calibration)

**Created:** 2026-10-06
**Status:** REFRAMED by the operator (2026-10-06). Most of the calibration's ranked tuning list (R4–R10) consisted of hand-written behaviour rules (thresholds, suppressions, severity guards). The operator **rejected that approach**: Descartes must *learn and adapt*, and it needs **data, context awareness and the ability to learn**, not an expert-system rule forest. R8 (Tailscale peers do not move the peer count) already shipped in `fix/watch-fabrication-2026-10`.

## Decisions (operator, 2026-10-06)

| Item | Decision |
|---|---|
| R3 notify once per active alert (activation + severity escalation), not every 15-min cooldown | **ACCEPTED.** Delivery policy, not detection. The S7 soak showed the post-upgrade `daemon.fact_history.horizon_short` alert would otherwise send ~480 notifications over ~5 days. |
| R4 stddev floor 0.5 → 0.75 | **REJECTED.** Hard-coded rule. |
| R5 31 → 14-day window | **REJECTED.** Real attacks unfold over days; a short memory is easy to fool. Keep 31 days. |
| R6 / R7 reboot suppression and CRITICAL guard | **REFRAMED.** Descartes must know what a reboot is and when it happened, and integrate that into what it learns. |
| R9 wake grace | **REFRAMED.** Descartes should learn that this host is usually on a VPN / tailnet, and learn what is normal when connected and when disconnected. |
| R10 lone-churn rule | **REFRAMED.** Same principle. |

## The real work: context as observed, learned data

Replace the rule proposals with **context observations** that the stratified models condition on (fits `docs/plans/2026-07-09-self-learning-stratified-monitoring.md`):

- **Host lifecycle events as facts:** boot time (from uptime / boot-time), shutdown and reboot, sleep and wake transitions, daemon gaps. These are recorded as first-class facts with timestamps, not as suppression switches.
- **Network context as facts:** VPN connected/disconnected, tailnet connected/disconnected and peer reachability, interface changes.
- **Session context as facts:** session origin (local, ssh, tmux, terminal app), creator process lineage where available.
- **Context-conditioned baselines:** session/peer models learn "normal" per context stratum (for example right-after-boot, just-woke, VPN-up vs VPN-down, weekday hour) and when transitions between strata happen. A reboot then reads as "a known event with its learned aftermath", and an anomaly is a deviation *given* the context.
- **Long memory stays** (31 days and the first/last-seen set) so slow, multi-day attacks remain visible.
- **Never-fabricate gates stay.** Freshness, trust and coverage are invariants, not behaviour rules.

Next step: a plan (`docs/plans/`) for context facts + context-conditioned session/peer baselines, gated like the rest. R3 can ship independently as a delivery change.
