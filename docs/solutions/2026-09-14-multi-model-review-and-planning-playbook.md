---
title: Multi-model review & planning playbook
date: 2026-09-14
tags: [process, workflow, review, planning, multi-model, codex, daybreak, astra, fable, ultracode]
summary: How to use the external-model roster (daybreak-blue, Astra, Fable, codex/ultracode) for planning and adversarial review on Descartes — validated across the 2026-09 security-hardening and watch-by-default sessions.
---

# Multi-model review & planning playbook

Reusable workflow reference. These patterns were validated on Descartes across September 2026
(the trusted-state / never-fabricate hardening, the daybreak security sweep, and the
protection-contract → watch-by-default planning). Read this when a task needs planning depth,
adversarial review, or a second opinion — before spinning anything up.

## The model roster — who to use for what

| Model | How to reach it | Use it for |
|---|---|---|
| **`gpt-daybreak-blue-latest`** | codex (see invocation below) | **Frontier defensive-cyber adversarial review.** The strongest security reviewer here — it caught real fabrication BLOCKERs that the Sonnet-implement + 3-lens-verify pipeline passed, TWICE (the trusted-state re-gate, the watch-by-default gate-split hazard). Use as the **final gate before shipping security-critical code**, and for an **independent unbiased plan** on a consequential design. |
| **`gpt-6-astra`** | codex | **Reliability / goal-alignment review.** Honest-behavior guardrails, never-fabricate audits, "what can this fabricate or hide" failure-mode enumeration. |
| **Fable 5.1** | Agent tool, `model: "fable"` | **Code-grounded design + adversarial verification.** Reads the repo NATIVELY (no codex sandbox friction) and can run simulations. Excellent for the coverage/mapping spine of a plan and for grounded verification (it empirically confirmed the +364-day suspend blind). |
| **Sonnet** | Agent / Workflow, `model: "sonnet"` | **The workhorse** — drafting and implementing against a tight directive. Delegate here by default (cheaper than the Opus main loop); reserve daybreak for the gate. |

Verify-don't-worship applies to ALL of them: every finding is a claim to check against the actual
code before acting. This session, a "clean sign-off" from an ungrounded pass was overturned by a
grounded one; a verifier's "just remove the gate" fix was itself incomplete (broke a "no-I/O" test).

## codex dispatch discipline (load-bearing)

The `codex-cli` skill (`~/.claude/skills/codex-cli`) is the authority; the traps that cost real time:

- **File reads HANG on `-s read-only`.** With `approval_policy = "on-request"`, a read-only sandbox
  makes codex's file-read tool-calls wait for approval that never comes in non-interactive `exec` →
  "the tool host repeatedly timed out before executing any file reads" → an **ungrounded** answer.
  **Fix: use `--approve-for-me`** (auto-approves, workspace-write sandbox). Then `git status` after —
  workspace-write *could* write; this session it never did, but check.
- **Lead the prompt with a no-skills directive** — `DIRECT TASK — do not invoke skills, agents, or
  meta-workflows. …` — or codex auto-activates its `adversarial-reviewer` skill and runs 30+ min silently.
- **Capture with `-o out.md --json > events.jsonl 2> err.log`**, not a pipe (a pipe leaves the file at
  0 bytes until exit). Redirect stderr to its own file — an arg error exits 0 and looks like success.
- **Model ids are `gpt-<version>-<codename>`; do not guess.** `gpt-6-astra` works; `gpt-6-terra` is
  rejected. Recover the real id: `grep '^model' ~/.codex/config.toml`, then probe once at
  `model_reasoning_effort="low"` before a fleet.
- **Reasoning effort:** `high` for most review/plan; `xhigh` for a hard independent plan. Never escape
  the `-c` quotes. Run in the background; set the Bash timeout to 600000.

Canonical invocation:
```bash
codex exec "$(cat directive.txt brief.md)" \
  -m gpt-daybreak-blue-latest -c 'model_reasoning_effort="high"' \
  --approve-for-me --skip-git-repo-check -C "$REPO" \
  -o out.md --json > events.jsonl 2> err.log
```
Output can duplicate its final answer — extract the verdict via grep and take the **last** occurrence.
For a large transcript, extract the final message with a small node script (find the longest string
containing the title marker; unescape `&lt;`/`&gt;`/`&amp;`) rather than reading it into context.

## Planning patterns

- **Committee-then-synthesize.** Decide the scope + section skeleton YOURSELF (non-delegable), then
  give N models the SAME bounded scope, each a DISTINCT angle (structure / coverage-mapping /
  never-fabricate guardrails). Synthesize + gate. Tell each "stay focused — do NOT widen the slice."
- **Independent unbiased second opinion.** For a consequential design, run ONE strong model
  (daybreak @ xhigh) told explicitly to **ignore the existing plans and design from scratch**, then
  COMPARE: convergence = validation; divergence = attention. This session the independent plan's
  architecture beat the synthesized one — worth the run.
- **Reconcile via a merge agent** given a tight directive (which parts of each plan to take, and the
  one correction to make). Then gate the merge yourself.
- Extract a delegated plan/patch from the agent transcript programmatically; don't retype it.

## The ultracode implement → verify workflow

For substantive implementation (only when the user opts into ultracode / a workflow):
1. **One implementer** (Sonnet, TDD) edits the working tree against the plan's spec.
2. **A 3-lens adversarial verify** in parallel — `fail-open / never-fabricate hunt`, `spec-conformance`,
   `test-adequacy` — each **re-runs the tests itself** and **red/green-checks its own findings**, and
   returns the corrected records, not just a critique.
3. **You (architect) gate:** run the FULL suite yourself (an agent's "green" is a claim), review the
   diff (especially any *modified existing tests* — a yellow flag), then the **daybreak re-gate**, then
   commit. Cap re-gate rounds at ~3; escalate a stubborn same-interplay residual as a scoped deferred
   item rather than whack-a-mole.

## Disciplines / hard-won lessons

- **Direction before execution (the biggest one).** Do NOT run an expensive multi-model committee on a
  strategically-misdirected slice. When a plan concretizes into something that resembles a commodity
  tool or contradicts the product's own differentiator, **surface that doubt to the user before
  investing further** — this session a full protection-contract plan (committee + daybreak xhigh +
  merge) was built and then abandoned because it reinvented "OTel + local PagerDuty."
- **Verify-don't-worship** (above) — check findings against the code; grounded beats ungrounded.
- **Gate every green yourself** — full suite + diff review; don't trust an agent's or verifier's claim.
- **Atomic commits, commit+push as you go.** One logical change per commit; daybreak provenance in the
  message. Set `SSH_AUTH_SOCK` + `ssh-add --apple-load-keychain` before any git auth op (never ask the
  user to). On a concurrent-push rejection, `git pull --rebase` and resolve (HANDOFF top-of-file
  entries collide predictably — keep all entries, newest first).
- **Proportionality.** One grounding+draft agent is enough for a well-scoped plan; reserve the full
  committee + frontier gate for genuinely consequential or security-critical work.

## Related durable knowledge (agent memory)

- `daybreak-blue-security-reviewer` — the reviewer, its track record, verify-don't-worship.
- `delegate-cheaper-models-over-opus-main-loop` — favour Sonnet > Opus > Fable; commit+push as you go.
- `spikes-stay-timeboxed-decision-aids` — a spike ends in a written go/no-go, not a hardened prototype.

## Where these were used (worked examples in-repo)
- `docs/reviews/2026-09-04-daybreak-security-sweep.md` + its 2026-09-06 re-gate section.
- `docs/reviews/2026-09-06-trusted-state-step1-grounded-review.md` (2× Astra + Fable, one with sims).
- `docs/plans/2026-09-09-protection-contract-slice-1{,-daybreak}.md` (committee + independent + merge — then abandoned).
- `docs/plans/2026-09-10-watch-by-default-slice-1.md` (proportionate: one grounding pass; caught its own Fix-3 tie-in).
