# DECISION-AID: Should Descartes move its agent interface to ACP / acpx?

**Type:** Time-boxed decision aid (go / no-go). **Not** a migration plan — it deliberately stops at a written recommendation and does not design the move.
**Created:** 2026-08-11
**Status:** Complete — recommendation below.
**Scope discipline:** Per the "spikes stay time-boxed" convention, "skip it — the gap is too narrow / no trigger yet" is a *successful* outcome, not a failure. This document commits to a recommendation rather than spawning a prototype.

**Headline recommendation: NO-GO (now), across all three interpretations.** Keep the embedded Pi harness. The one future-worthy sliver is documented with an explicit revisit-trigger, but it is not "acpx" and has no trigger today.

---

## 1. What ACP / acpx actually is

### 1.1 Agent Client Protocol (ACP)

ACP (agentclientprotocol.com, originally Zed Industries, now the independent `agentclientprotocol` GitHub org with GOVERNANCE.md/MAINTAINERS.md) standardizes how a **Client** (typically a code editor/IDE) drives a coding **Agent** (an AI program that autonomously modifies code). Key shape:

- **Wire:** JSON-RPC 2.0, UTF-8, newline-delimited. **Primary transport is stdio** — the Client launches the Agent as a *subprocess* and speaks JSON-RPC over stdin/stdout. (Streamable HTTP is still a *draft* transport.)
- **Roles are inverted from intuition:** the Agent is the JSON-RPC "server" but runs as a child process; the channel is bidirectional (the Agent calls back into the Client for `fs/read_text_file`, `fs/write_text_file`, `terminal/*`, and `session/request_permission`).
- **Lifecycle:** `initialize` → optional `authenticate` → `session/new | session/load | session/resume` → a `session/prompt` loop that streams `session/update` notifications (plan/message/thought chunks, `tool_call`/`tool_call_update`, usage), optionally interrupted by `session/request_permission` and `session/cancel`, ending with a `StopReason`.
- **Permission model is push-based:** the Agent *requests* permission (`session/request_permission` with `allow_once`/`allow_always`/`reject_once`/`reject_always` options); the Client grants or denies. This is a **runtime grant/deny gate, not a construction-time "this session has no tools" guarantee** — a distinction that matters enormously below.
- **Auth is an opaque envelope, not an implementation.** ACP only standardizes "advertise `authMethods`, call `authenticate(methodId)`, maybe `logout`." What happens inside `authenticate` (browser OAuth, API-key prompt, SSO) is entirely the Agent binary's business. This is the single most consequential fact for Descartes (§3.1).
- **Maturity:** broad, fast-growing, multi-vendor adoption (Zed, JetBrains, VS Code extensions, Neovim/Emacs, dozens of agents: Gemini CLI, Codex CLI adapter, Claude Agent SDK adapter, Copilot CLI, etc.). Official SDKs in Rust/TS/Kotlin/Java/Python. **Protocol v2 is still in draft** alongside stable v1.

The **official Rust surface** is a two-repo split: `agent-client-protocol-schema` (low-level wire types) and `agent-client-protocol` (higher-level Client/Agent/Proxy/Conductor runtime, MSRV 1.88.0, Apache-2.0), in `agentclientprotocol/rust-sdk`. This is the *only* Rust-aligned ACP artifact — and, critically, it is **not** what "acpx" names.

### 1.2 acpx — a name that points at two unrelated projects

This is a disambiguation the operator needs before anything else:

| | **openclaw/acpx** | **docs.rs/acpx = imumesh18/acpx** |
|---|---|---|
| Kind | Application (CLI) | Library (Rust crate) |
| Language | TypeScript (npm `acpx`, bin → `dist/cli.js`) | Rust (edition 2024, MSRV 1.85.0) |
| What it is | "Headless CLI client for stateful ACP sessions" — wraps Codex/Claude/Gemini/custom ACP agents behind one CLI | "Thin Rust client for launching ACP agent subprocesses via the official SDK" |
| Maturity | pre-1.0, **v0.13.0**, Node ≥22.13, 3,120★, MIT, actively pushed | pre-1.0, **v0.1.0**, 3★, 381 downloads, pins `agent-client-protocol` **0.10.2**, MIT (per Cargo.toml) |
| Official? | Independent app on ACP | Its own README: "**not an official ACP project**" |

They share only the name. **docs.rs/acpx does NOT document openclaw/acpx.** Neither is the official Rust SDK. Worth flagging: the three links that seeded this investigation point at two openclaw/acpx artifacts *plus* the unrelated imumesh18 crate that merely shares the package name.

### 1.3 The acpx "flows" feature (openclaw/acpx only)

A **flow** is a TypeScript module (`defineFlow` from `acpx/flows`) that the acpx runtime executes as a topologically-ordered graph, persisting state to `~/.acpx/flows/runs/<runId>/`. Node kinds: `acp` (a model turn), `action` (deterministic shell/HTTP), `compute` (pure local fn), `decision` (constrained-choice ACP branch + `decisionEdge()`), `checkpoint` (pause for human/external input). Run via `acpx flow run ./f.ts`. Explicitly **"an experimental, opt-in surface."** Elevated flows must pass `--approve-all` or acpx fails fast. Completed runs are immutable and feed a read-only browser replay viewer (React Flow graph, per-node status, rewind/scrub).

Flows are acpx's lightweight code-defined DAG/pipeline layer over ACP sessions — deterministic branch + non-agent steps + human-in-loop checkpoints + replay. Conceptually adjacent to what Descartes' L2 / self-audit / provenance vision wants (§2C).

---

## 2. Three interpretations of "move the agents interface to acpx"

The phrase is genuinely ambiguous. The three readings diverge sharply in what they cost and buy. **This is the primary operator question** (carried into the structured output).

### (A) Descartes-as-ACP-*server*
Descartes exposes *itself* as an ACP Agent so editors (Zed, JetBrains, …) can drive it via `session/prompt`.
- **Fit: poor / role-inverted.** Descartes is a read-only ops-triage/monitoring daemon, not a coding agent. ACP is built around editor UX — code diffs, terminals, file writes — none of which Descartes does.
- **Cost:** opens a *new external entry surface* into the safety-critical daemon (the gated-wakeup/namespace-consent/audit machinery is all internal today; an ACP server surface would be a fresh attack/authz boundary).
- **Verdict: almost certainly not what's meant, and the highest-risk reading.**

### (B) acpx-as-*client* replacing the Pi harness  ← most likely
Descartes swaps its embedded in-process Pi harness (`createAgentSession`) for an ACP *client* (acpx CLI, or an ACP client crate) that drives an **external ACP agent subprocess** (claude-agent-acp / gemini-cli / codex-acp / …).
- **Fit: the literal reading of "agents interface → acpx."** "agents interface" = the seam by which Descartes reaches the LLM; that seam is `pi-harness.js`. This is the interpretation the gap analysis (§3) is built around.
- **Verdict: the case to actually adjudicate.** It is where the real regressions live.

### (C) Adopt acpx *flows* for Descartes' own L2 multi-agent orchestration
Use flows (`defineFlow` DAG of acp/action/compute/decision/checkpoint) as the substrate for Descartes' future L2 / federated-immune-system multi-agent work.
- **Fit: a different axis** — not the triage/alert LLM seam at all, but multi-step workflow composition. The DAG + checkpoint + immutable-replay + provenance model is a genuine *pattern* match for the self-learning/self-audit vision.
- **Cost:** flows are TypeScript-only, "experimental", and drag in acpx's whole runtime + external agent binaries; Descartes already owns its daemon tick / rate-budget / audit-JSONL machinery that flows would duplicate or fight.
- **Verdict: worth mining as a design reference, not adopting as a dependency.**

**Most likely intended: (B).** But "flows" appearing in the seed research suggests the operator may also be probing (C). (A) is unlikely. The recommendation below holds NO-GO under *all three* — which is why it is safe to commit before the operator disambiguates — but the *reasoning* and the *revisit-trigger* differ per interpretation, so the disambiguation still matters.

---

## 3. Gap analysis vs. the current Pi harness

**The seam is narrow at the file level, deep at the contract level.** Exactly one file — `tools/descartes-cli/src/pi-harness.js` — imports the Pi constructors; `login.js` additionally uses `AuthStorage`. Every other call site already talks to two abstracted factory functions (`createPrivateTriageSession` / `createPrivateAlertSession`) and a thin session object (`.prompt`, `.subscribe`, `.messages`, `.dispose`, `.getActiveToolNames`). So the *plumbing* is swap-friendly. The hard part is that the **safety and behavior contract falls directly out of Pi's specific embedding API**, and ACP does not offer equivalents. (Dependency today: single in-process `@earendil-works/pi-coding-agent` ^0.75.3, Node ≥22.19 — `package.json`.)

### 3.1 Subscription-OAuth login + model selection — the deal-breaker for (B)
- `descartes login` drives Pi's `AuthStorage.create(paths.authFile).login(...)` — a full subscription-OAuth flow (`onAuth`/`onPrompt`/`onSelect`/`onManualCodeInput`), credentials stored at a **Descartes-owned XDG path**, never Pi's `~/.pi` (`assertNoPiOwnedPath`).
- **ACP does not cover this ground at all.** ACP drives an *already-authenticated* agent; auth is opaque per agent binary. And the ecosystem evidence is adverse: Zed's `claude-agent-acp` (built on the Claude Agent SDK) historically **required a raw Anthropic API key and rejected claude.ai subscription tokens** (openclaw/openclaw #53456); even after adding a `claude-ai-login` method, a `--hide-claude-auth` flag can force API-key-only mode (claude-agent-acp #517); JetBrains reportedly can't do Claude OAuth "due to Anthropic's current policies" (YouTrack LLM-24706). A community wrapper (`claude-code-acp`) exists *specifically* to shell out to the real `claude` CLI to reuse a Pro/Max session — evidence this is a live, unsolved friction point.
- **Consequence:** under (B), Descartes would likely have to **keep Pi's `AuthStorage` + `ModelRegistry` anyway** (for `descartes login` and for `model-selection.js`'s highest-gpt/highest-sonnet policy, which assumes Pi's `{provider,id,name,reasoning}` descriptor). Moving execution to ACP does **not** let Descartes shed Pi — it adds ACP *on top of* Pi's auth/model layer, or regresses subscription auth to API-key-only. Either way the "move" is not a clean replacement.

### 3.2 Safety invariants — weakened, not preserved, under ACP (interpretation B)
Verified in-code today:
- **Gated wakeup is structurally tool-free.** `createPrivateAlertSession` passes `enableTools: false` unconditionally (`pi-harness.js:481`), which sets `noTools: "all"` (`:460`) — the alert LLM has *zero tools registered by construction*, not merely denied at runtime.
- **Triage tools are a proven allowlist.** `enableTools` (default `false`, `:448`) gates a frozen 20-name `TRIAGE_TOOL_NAMES` allowlist; post-creation, `assertSafeTriageToolNames(session.getActiveToolNames())` (`:466`, `tool-policy.js`) throws if *anything* outside the allowlist — or in the `bash/read/write/edit/grep/find/ls` denylist — is active. This audits Pi's **actual reported tool surface**, not the requested config.
- **Ambient-context suppression:** `noExtensions/noSkills` + `systemPromptOverride` + `SessionManager.inMemory()`/`SettingsManager.inMemory()` (`:420–457`) guarantee no AGENTS.md/skills/themes leak and zero disk/cross-session bleed.

**ACP's model cannot reproduce these cleanly.** ACP tool access is *push-based permission grant/deny*, so the alert path's "no tool can ever be reached" would degrade to "we deny every permission request" — a **weaker, runtime guarantee** that depends on an agent binary Descartes does not control, versus today's construction-time "no tools exist." Likewise, `getActiveToolNames()`'s structural post-hoc proof and the "blank agent, only my prompt + my tools, nothing ambient" contract have **no ACP equivalent** — ACP is designed for editor-integration UX (permissions/diffs/terminals), not headless "give me a sterile agent." The gated wakeup's surrounding gates (namespace consent with hard-excluded `learned.*`, per-hour budget with critical reservation, fail-closed audit JSONL with sha256 prompt hash) are Descartes-internal and would survive — but they wrap a *weaker* core than they do today. **This is the load-bearing reason (B) is a regression, not a lateral move.**

### 3.3 Rust re-anchoring alignment — acpx does not help
Descartes lives in a Rust/Bazel monorepo with a stated Rust direction. One might hope an ACP move advances that. It does not, *as posed*:
- openclaw/**acpx is TypeScript** (adds a Node CLI dependency, not Rust).
- imumesh18/**acpx is a v0.1.0, 3-star toy** pinning ACP SDK 0.10.2 — not production-viable.
- The only Rust-aligned path is the **official `agent-client-protocol` crate** — which is *not* "acpx." So "move to acpx" specifically pulls *away* from Rust re-anchoring (TS CLI) or toward an unmaintained crate. If Rust re-anchoring is the real motive, the artifact to evaluate is the official SDK, not acpx — and even then §3.1/§3.2 still bite.

### 3.4 Distribution / licensing — heavier, more processes, more supply chain
- Today: one in-process npm dep. Under (B) via acpx: a **multi-process stack** — the acpx TS CLI (Node ≥22.13) *plus an external agent binary* it drives (claude-agent-acp / gemini / codex), each with its own auth, update cadence, and CVE surface. Descartes would ship/manage/tolerate **an external agent subprocess it does not author**. That is a materially larger install and threat surface for a safety-critical daemon whose current guarantee is "the LLM is embedded, sterile, and read-only."
- Licensing is permissive (ACP Apache-2.0; both acpx projects MIT) — not a blocker — but note GitHub couldn't auto-detect imumesh18/acpx's LICENSE (Cargo.toml is authoritative).

### 3.5 acpx pre-1.0 / naming risk
- openclaw/acpx v0.13.0, README warns "treat CLI and runtime interfaces as evolving." imumesh18/acpx v0.1.0. ACP **protocol v2 still draft**. Building a safety-critical seam on a pre-1.0, actively-churning surface with a still-evolving protocol is exactly the fragility the time-box discipline warns against.
- The **name collides** across two unrelated projects — an ongoing documentation/onboarding hazard.

---

## 4. Recommendation

### NO-GO (now) — keep the embedded Pi harness.

Under the most-likely interpretation (B), moving the agent interface to acpx is a **strict regression** on the three things that matter most to Descartes:
1. It **cannot** re-express `descartes login`'s subscription OAuth (ACP is auth-agnostic; the Claude ACP adapter forces/prefers API-key-only), so Pi's auth+model layer stays anyway — no clean replacement.
2. It **weakens** the load-bearing safety guarantees: the alert path's construction-time "zero tools" becomes runtime "deny every request," and the ambient-context-suppression + post-hoc tool audit have no ACP equivalent.
3. It **does not advance Rust re-anchoring** (acpx-the-CLI is TypeScript; acpx-the-crate is a toy) while **enlarging** distribution/supply-chain surface with an external agent subprocess.

(A) is a role-inverted new attack surface. (C) is a good *design reference* but a TS, experimental *dependency* that duplicates machinery Descartes already owns. None clears the bar today, and there is **no present trigger** — Pi works, is one file, and the migration would *add* cost while *subtracting* safety.

### Recommended scope (the deferred sliver, with an explicit revisit-trigger)
Do **not** adopt acpx (TS CLI or the v0.1.0 crate) in any interpretation. The current one-file Pi seam stays. The **only** future-worthy variant is: *if and only if* a real trigger fires later —
- (i) Rust re-anchoring of the CLI evicts the Node/Pi dependency, **or**
- (ii) a concrete L2 multi-agent need materializes (federated-immune-system work) that Descartes' own orchestration cannot cover —

then evaluate a **Rust-native ACP client via the official `agent-client-protocol` crate (not acpx)**, gated on it reconstructing the full contract (§3.2). For (C) specifically: harvest the flows *DAG/checkpoint/immutable-replay/provenance pattern* as inspiration for Descartes' own L2 layer, without taking the acpx runtime as a dependency. Until a trigger fires, this is a documented "revisit-when," not scheduled work.

---

## 5. Minimal next-step spike (only if a §4 trigger fires)
A **≤1-day, read-only, throwaway** spike — reusing existing tooling, no new infra, per the time-box discipline:

- **Substrate:** the official `agent-client-protocol` Rust crate (explicitly *not* acpx), driving **one already-installed** ACP agent subprocess.
- **Single success question:** can it reconstruct, cleanly, all three of —
  1. **zero ambient context** (no AGENTS.md/skills/themes leak; only Descartes' fixed system prompt),
  2. a **provably tool-free** session for the alert path (structural, not "deny at runtime"), with a post-hoc active-tool audit equivalent to `getActiveToolNames()`, and
  3. the **mandatory audit hook** (sha256 prompt-hash JSONL before the call completes) —
  **without regressing subscription auth?**
- **Stop rule:** if *any* of the three can't be met cleanly (esp. #2, given ACP's push-based permission model, and auth given §3.1), **stop and keep Pi.** "Gap too wide / no clean contract" is a successful spike outcome.

---

## 6. Honesty ledger — what the research could NOT verify (open questions)

Carried forward, not papered over:

**Blocking-for-(B), verify first if ever revisited:**
- **Does `claude-agent-acp` support claude.ai subscription OAuth by default, or is API-key-only the practical reality?** Inferred from a closed issue (#53456) + an open one (#517), *not* read from current adapter source. This single unknown determines whether (B) can preserve Descartes' current subscription-auth UX at all.

**General unverifieds (from the seed research):**
- crates.io download/version counts for the ACP crates were inconsistent across snapshots (direction "very active" is solid; exact numbers are approximate).
- Which ACP protocol version (v1 vs draft v2) each listed client/agent actually implements is not individually verified; v2 is still draft with no inspected timeline.
- Streamable HTTP transport is "draft" per the spec doc; no PR/timeline inspected.
- `zed.dev/acp/agent/claude-agent` could not be fetched directly (WebSearch-synthesized only).
- openclaw/acpx v0.13.0 and imumesh18/acpx v0.1.0 are as-of 2026-08-11; npm/crates.io move fast.
- imumesh18/acpx's linked flow-architecture design docs were not fetched; GitHub license auto-detection 404'd (Cargo.toml `MIT` is authoritative).
- No evidence the two acpx projects are meant to be used together; openclaw/acpx has no observed Rust footprint.

---

## Sources
- **ACP:** agentclientprotocol.com; `agentclientprotocol/agent-client-protocol` (protocol v1 docs: transports, initialization, authentication, session-setup, prompt-turn, tool-calls); `agentclientprotocol/rust-sdk` (crate split, MSRV 1.88.0, Apache-2.0); crates.io `agent-client-protocol` / `agent-client-protocol-schema`.
- **Auth divergence:** openclaw/openclaw #53456; `agentclientprotocol/claude-agent-acp` #517 (`--hide-claude-auth`, `claude-ai-login`); `harukitosa/claude-code-acp`; gemini-cli #7549/#12042/#10855/#28439; JetBrains YouTrack LLM-24706.
- **acpx:** `github.com/openclaw/acpx` (README, `docs/flows.md`, package.json — fetched 2026-08-11, v0.13.0); `github.com/imumesh18/acpx` + crates.io/docs.rs `acpx` (v0.1.0, Cargo.toml).
- **Descartes current seam (verified in-repo, 2026-08-11):** `tools/descartes-cli/src/pi-harness.js` (`:448` enableTools default false, `:460` `noTools:"all"`, `:466` audit, `:481` alert `enableTools:false`, `:420–457` in-memory + ambient suppression); `tools/descartes-cli/src/tool-policy.js` (frozen allowlist/denylist + `assertSafeTriageToolNames`); `tools/descartes-cli/src/{login,model-selection,alert-intelligence,paths,evidence-freeze,daemon,index}.js`; `tools/descartes-cli/package.json` (`@earendil-works/pi-coding-agent` ^0.75.3).
