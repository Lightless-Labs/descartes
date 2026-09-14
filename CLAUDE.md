# Descartes

Agent instructions for this repo live in **`AGENTS.md`** — read it first (architecture, lifecycle, safety invariants, conventions).

The current continuity / handoff document is **`docs/HANDOFF.md`**. Start every session by reading `README.md`, `AGENTS.md`, and `docs/HANDOFF.md` — see the **"RESUME HERE"** block at the top of its Current Status for the live state and next action. The active tracking todo is under `todos/` (currently `todos/2026-09-14-watch-by-default-implementation.md`; broader initiative: `todos/2026-07-09-self-learning-stratified-monitoring.md`).

Per `AGENTS.md`: update `docs/HANDOFF.md` before context compaction, before handing off, after milestones, and after plan changes/discoveries.

**Multi-model review & planning:** for planning depth, adversarial review, or a second opinion, use the external-model roster (daybreak-blue / Astra via codex, Fable via the Agent tool, Sonnet/ultracode) per **`docs/solutions/2026-09-14-multi-model-review-and-planning-playbook.md`** (also referenced in `AGENTS.md` §Development Process). It carries the codex invocation discipline (esp. `--approve-for-me` so file reads don't hang), the planning patterns, and the direction-before-execution / verify-don't-worship / gate-every-green disciplines. Reserve a **daybreak-blue re-gate for security-critical code before shipping**.
