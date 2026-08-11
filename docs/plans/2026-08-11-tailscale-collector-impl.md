# Tailscale / tailnet collector — implementation plan

**Created:** 2026-08-11
**Status:** Draft (not yet reviewed/implemented)
**Todo:** [todos/2026-08-11-tailscale-collector.md](../../todos/2026-08-11-tailscale-collector.md)
**Reviewed:** 2026-08-11 (Fable + gpt-5.6-sol) — Fable GO_WITH_CHANGES (2 must-fixes, both folded
in below: the Go zero-time handshake sentinel now maps to `0` not `undefined`, and section 6
documents + tests the tailscale-only `peer.count_drop` blind spot); sol UNAVAILABLE (no findings
to fold — this run has no sol input).

## Purpose

Add a read-only Tailscale/tailnet collector, sibling to `tools/vpn-peer-status.js`, that reads
local `tailscaled` state via a fixed-argv allowlist and feeds Tailscale peers into the existing
`peer.presence` fact stream (`peer-signature-store.js`'s hash scheme, `peer-baseline.js`'s
`peer.count_spike`/`peer.count_drop` detectors, `incident-correlation.js`'s
`correlation.login_kill_proximity`). v1 emits **zero new alert rule_ids** and reads **only local
daemon state** (`tailscale status --json`) — no admin-API/control-plane calls, no
`netcheck`/`whois`, no mutation surface.

All file paths below are relative to `tools/descartes-cli/` unless stated otherwise.

## 1. New module

**`src/tools/tailscale-status.js`** (new file, sibling to `src/tools/vpn-peer-status.js`, same
`timedEnvelope`/`evidenceEnvelope` discipline from `src/tools/envelope.js`).

Exports:
- `collectTailscaleStatusEvidence(options)` — the L0 collector, envelope `id: "tailscale-status"`,
  `source: "tailscale_status"`, `tool: "collect_tailscale_status"`.
- `DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT = 200` — own constant, not imported from
  `vpn-peer-status.js` (mirrors the codebase convention of each collector/baseline module owning
  its own tunables, e.g. `peer-baseline.js` vs `session-baseline.js`).
- `parseTailscaleStatusJson(stdout)` — pure parser, no I/O.
- Small local `runFixedExecFile`/`isPermissionDenied` helpers, **duplicated** (not imported) from
  `vpn-peer-status.js` — these are file-private there today; keep the two collectors independent
  rather than introducing a shared-helper coupling that doesn't exist yet.

### Fixed-argv allowlist (closed, exactly one construct)

```js
runExec("tailscale", ["status", "--json"], { timeout, maxBuffer });
```

This is the **complete, pinned set** of `tailscale` invocations this file may ever construct —
mirror `vpn-peer-status.js`'s WireGuard-allowlist comment block verbatim, adapted:

> NEVER add a second `tailscale` invocation here. In particular NEVER: `tailscale up`, `down`,
> `set`, `logout`, `login`, `switch`, `configure`, `serve`, `funnel`, `file`, `ssh`, `lock`,
> `cert`, `web`, `debug` — any subcommand that mutates daemon/tailnet state, authenticates,
> exposes a service, or touches certificates/keys. `status --json` is read-only and prints no
> private key or auth material.

`execFile` (not `exec`/shell) throughout — no shell parsing, no argv injection surface.

### Degrade-not-fabricate status ladder

Mirrors `vpn-peer-status.js`'s WireGuard ladder, adapted for Tailscale's own failure shapes:

| Condition | `status` | Notes |
|---|---|---|
| `ENOENT` | `"absent"` | binary genuinely not installed |
| exit 0, JSON parses, `BackendState` ∈ `{"NeedsLogin","NoState","Stopped"}` | `"logged_out"` | **real, distinguishable zero** — daemon told us truthfully it isn't logged in; never conflated with `"unable"` |
| exit 0, JSON parses, `BackendState === "Running"` | `"ok"` | includes the genuine zero-peer case |
| exit 0 but JSON fails to parse | `"unable"` | malformed output — never partially trusted |
| nonzero exit, permission-denied text/code (mirrors `isPermissionDenied`) | `"missing_permission"` | `elevation_candidate: true`, same pure-documentation marker as WireGuard — this collector never escalates |
| nonzero exit, other | `"unable"` | |

Envelope `status: "ok"` (outer `evidenceEnvelope`) iff internal status is `"ok"`; `"absent"` /
`"logged_out"` / `"missing_permission"` / `"unable"` all map to outer `"unable"`, confidence 0 —
matches `vpn-peer-status.js`'s `any_source_available` convention (a single-source collector, so
this is simpler than the 5-source VPN case, not a departure from it).

**Open item (flagged, not resolved here):** confirm against real `tailscale status --json` output
whether a logged-out/stopped daemon exits 0 or nonzero, and the exact `BackendState` enum values,
before finalizing the parser — see Open Questions below. Treat `BackendState` from parsed JSON as
authoritative over stderr text-sniffing wherever both are available.

### Bounds

- `timeout` default 3000ms, `maxBuffer` default 512KB (verbose JSON; larger than
  `vpn-peer-status.js`'s 256KB default for `wg`/`who`/`last`), both options-overridable.
- Per-tick peer cap `DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT = 200`: same `truncated`/`total_count`
  discipline as `vpn-peer-status.js` — entities are capped, never silently dropped without a
  marker.

### Parsed peer shape (in-memory only, never persisted raw)

From each `Peer` map entry:

```js
{
  source_type: "tailscale",
  presence_state: peer.Online ? "observed_active" : "observed_historical",
  node_public_key: peer.PublicKey,               // raw, in-memory only — hashed at the translator
  is_exit_node_active: Boolean(peer.ExitNode),         // this peer IS our current exit node
  is_exit_node_option: Boolean(peer.ExitNodeOption),   // this peer offers exit-node capability
  latest_handshake_epoch_seconds: <derived from peer.LastHandshake RFC3339 string;
                                    `0` if the field is the Go zero-time sentinel
                                    ("0001-01-01T00:00:00Z") — WireGuard's own
                                    never-handshaked convention, so bucketHandshakeAge
                                    (fact-translators.js:478, `epochSeconds === 0 ->
                                    "never"`) maps it correctly; `undefined` only if
                                    the field is genuinely absent from the JSON, which
                                    bucketHandshakeAge maps to "unknown" (distinct from
                                    "never" — a missing field is not a truthful zero)>,
}
```

**Review fix (Fable must-fix, 2026-08-11):** the shape note above previously said the zero-time
sentinel maps to `undefined`. That was wrong: `bucketHandshakeAge` (section 2, `buildPeerFactPoint`)
returns `"never"` only for `epochSeconds === 0`, and `"unknown"` for any non-finite
(`undefined`/`NaN`) value — so mapping the sentinel to `undefined` would have made the planned
golden-fixture assertion ("Go zero-time → never handshaked") unreachable, and would have silently
conflated a real, distinguishable "never handshaked" peer with "unknown" (a degrade-not-fabricate
violation: the collector *does* know this peer has never handshaked — Tailscale told it so via the
zero-time convention — collapsing that to "unknown" throws away real information). The parser must
special-case the exact string `"0001-01-01T00:00:00Z"` → `0` before the general RFC3339 → epoch
conversion; only a field that is missing/null/unparseable-and-not-the-sentinel produces `undefined`.

**Deliberately NOT captured in v1** (YAGNI — not needed for the four named signals): raw
Tailscale IP (`100.x`), MagicDNS hostname, tailnet name, per-user login/email, tags, `Self`
node's own attributes. Identity = node public key only (WireGuard-style — Tailscale *is*
WireGuard, so this reuses the existing identity/attribute split from
`peer-signature-store.js` exactly, no new split to design). If a future slice needs
tailnet/user/hostname context, it must hash/bucket at this same source layer — do not persist
raw.

## 2. Fact/marker consumed and produced

No new fact_name. Tailscale peers feed the **existing** `peer.presence` fact_name
(`fact-translators.js`'s `PEER_FACT_NAME`), so `peer-baseline.js`'s tick-grouping/count logic and
`incident-correlation.js` pick them up automatically — they aggregate by `fact_name`/`ts`, not by
`source_type`.

### `src/fact-translators.js` edits

1. `CLOSED_PEER_SOURCE_TYPES`: `new Set(["wireguard", "ssh", "vpn_service", "tailscale"])`.
2. `peerEntityKey(peer)`: extend the `peerIdentifier` ternary — for `sourceType === "tailscale"`,
   `peerIdentifier: peer.node_public_key` (identity = pubkey only, same branch shape as
   `wireguard`'s `peer.public_key`; `remoteUser`/`remoteHost` stay unset, exactly like WireGuard).
   Produces `entity_key: "peer.tailscale.<hash>"` via the unchanged
   `computePeerIdentitySignature`.
3. `buildPeerFactPoint(peer, envelope, ts)`:
   - `handshake_age_bucket`: widen the existing ternary to
     `sourceType === "wireguard" || sourceType === "tailscale" ? bucketHandshakeAge(...) : "n/a"`
     — reuses `bucketHandshakeAge` unchanged (Tailscale's handshake age is the same
     WireGuard-underlying concept, just sourced from an RFC3339 string instead of a raw epoch —
     the epoch conversion happens in the collector, not here).
   - New closed-enum attribute `exit_node_role`, added to `attributes` for **every** peer fact
     (uniform attribute-key set across all peer facts, matching the existing
     `handshake_age_bucket`/`"n/a"` convention):
     ```js
     function bucketExitNodeRole(peer, sourceType) {
       if (sourceType !== "tailscale") return "n/a";
       if (peer.is_exit_node_active) return "in_use";
       if (peer.is_exit_node_option) return "advertised_unused";
       return "none";
     }
     ```
     This is the entire "exit-node usage change" signal surface for v1 — the fact makes the
     current exit-node role observable per tick; a detector that diffs it tick-to-tick is future
     work (see Open Questions / todo's own deferred items), not part of this plan.
4. New exported translator, mirroring `factPointsFromVpnPeerEvidence` shape exactly:
   ```js
   export function factPointsFromTailscaleStatusEvidence(evidence, { ts } = {}) {
     const envelope = (evidence ?? []).find((e) => e.id === "tailscale-status" && e.status !== "unable");
     if (!envelope) return [];
     const peers = envelope.result?.peers ?? [];
     const points = peers.map((peer) => buildPeerFactPoint(peer, envelope, ts));
     if (envelope.result?.truncated) {
       points.push(buildPeerOverflowMarkerFactPoint(envelope.result, envelope, ts));
     }
     return points;
   }
   ```
   **Deliberately does NOT append a `PEER_CENSUS_MARKER_ENTITY_KEY` point** — see the collision
   note in section 6. It DOES reuse `PEER_OVERFLOW_ENTITY_KEY` (safe — see section 6) when its own
   `result.truncated` is true, using the existing `buildPeerOverflowMarkerFactPoint` unchanged.
5. `peer-signature-store.js`: **documentation-only** edit — extend the module header and
   `computePeerIdentitySignature`'s docstring's identity-vs-attribute enumeration to record
   `tailscale` as a fourth source kind, identity = node public key only (reuses the WireGuard
   branch's reasoning verbatim; no new code path, `computePeerIdentitySignature` itself is already
   fully generic over `sourceType`). The store stays **unwired** from `daemon.js` for Tailscale
   too — same SCOPE NOTE as WireGuard/SSH/vpn_service today; nothing in this plan calls
   `reconcilePeerSignatures`/`writePeerSignatureStore`.

## 3. Exact alert(s) — none new

v1 adds **zero** new `rule_id`s and **zero** new `extraCandidates` entries. It feeds two
already-shipped, already-reviewed deterministic detectors purely by widening the `peer.presence`
fact stream they already consume:

- `peer.count_spike` / `peer.count_drop` (`src/peer-baseline.js`) — severity hardcoded
  `"warning"` (never escalates), unchanged by this plan. Tailscale peers count toward
  `groupPeerFactsByTick`'s per-tick `count` like any other `peer.presence` point.
- `correlation.login_kill_proximity` (`src/incident-correlation.js`) — unchanged, already
  `source_type`-agnostic (`peerSourceType = point.attributes?.source_type ?? "unknown"`, purely
  reported into diagnostics, not branched on).

No `alerts.js`/`alert-store.js`/`calibration.js`/`alert-intelligence.js` edits are required:
`classifyAlertNamespace` is unaffected (no new rule_id prefix); `peer.*` stays `unknown_namespace`
(permanently un-consentable to the LLM, fail-closed, unchanged);
`ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (`src/alert-intelligence.js`) already covers
`PEER_COUNT_SPIKE_RULE_ID`/`PEER_COUNT_DROP_RULE_ID` and needs no widening.

## 4. Exact wiring edits, by file

### `src/daemon.js`

1. Imports: add
   ```js
   import { collectTailscaleStatusEvidence } from "./tools/tailscale-status.js";
   ```
   and add `factPointsFromTailscaleStatusEvidence` to the existing
   `fact-translators.js` named-import block.
2. `defaultDaemonProfile()` — add to `structural.collectors`, after `"vpn-peer-status"`:
   ```js
   "tailscale-status": { enabled: true },
   ```
   with a comment mirroring the `"vpn-peer-status"` entry's own: default true, safe/byte-identical
   for any operator who hasn't opted into learned features (outer `learned.json` kill switch gates
   the whole structural tick first); pure read-only L0 fact source; **no** `extraCandidates`
   addition paired with it.
3. `collectStructuralEvidence()` — add to `activeCollectors`:
   ```js
   "tailscale-status": collectors["tailscale-status"] ?? collectTailscaleStatusEvidence,
   ```
   and to the evidence-push sequence, **after** the existing `"vpn-peer-status"` push (preserves
   the "same `ts` for every peer fact this iteration" invariant `peer-baseline.js` already relies
   on — ordering within one iteration doesn't affect `ts`, but keep it adjacent to its sibling for
   readability):
   ```js
   if (structuralProfile.collectors?.["tailscale-status"]?.enabled) evidence.push(await activeCollectors["tailscale-status"]());
   ```
4. `runDaemonIteration()`'s structural `factPoints` array — add, immediately after the existing
   `...factPointsFromVpnPeerEvidence(structuralEvidence, { ts }),` line:
   ```js
   ...factPointsFromTailscaleStatusEvidence(structuralEvidence, { ts }),
   ```
   Comment mirrors the `vpn-peer-status` line's own: pure L0 fact source, only reachable on a
   successful (non-timed-out) structural tick, deliberately **not** paired with any
   `extraCandidates` addition — feeds `peer.count_spike`/`peer.count_drop`/
   `correlation.login_kill_proximity` automatically since those aggregate the shared
   `peer.presence` stream by tick, not by `source_type`.

No `extraCandidates` array edit (section 3).

### `src/pi-harness.js` (L2 model-visible tool registration)

Add a `defineTool` entry mirroring `collect_vpn_peer_status`'s exactly, after it:
```js
defineTool({
  name: "collect_tailscale_status",
  label: "Collect Tailscale/tailnet status",
  description: "Collect a read-only baseline of Tailscale/tailnet peer identity from local daemon state (`tailscale status --json`): node presence, exit-node role, handshake recency. No traffic content is inspected, no admin/control-plane API is called, no privilege is escalated, and no host actions are taken.",
  parameters: Type.Object({ peer_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 500 })) }),
  executionMode: "parallel",
  execute: async (_id, params) => jsonToolResult(await collectTailscaleStatusEvidence({ peerLimit: params.peer_limit ?? DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT })),
}),
```
Add `collectTailscaleStatusEvidence, DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT` to the existing
`tools/tailscale-status.js`-sourced import (new import line, mirrors the `vpn-peer-status.js`
import at line 24).

### `src/tool-policy.js`

Add `"collect_tailscale_status"` to `TRIAGE_TOOL_NAMES`, immediately after
`"collect_vpn_peer_status"`. (`test/pi-harness.test.js` and `test/tool-policy.test.js` both assert
this array against the live tool registry — see section 5.)

### `docs/reference/collectors.md`

Add a `### \`collect_tailscale_status\`` entry mirroring the existing
`### \`collect_vpn_peer_status\`` entry's shape/tone (operator-facing catalog, per the repo's own
"Development Process" convention of documenting durable surfaces). This entry must include the
operator-facing dependency note from section 6 (Fable must-fix, 2026-08-11): **`peer.count_drop`
(peer drop-to-zero detection) requires the `"vpn-peer-status"` collector to also be enabled** — a
Tailscale-only configuration (`"vpn-peer-status"` disabled) gets `peer.count_spike` coverage but
not `peer.count_drop` coverage, because only `vpn-peer-status.js`'s translator emits the census
marker `peer.count_drop`'s regime key depends on.

### No edit needed (verified, not assumed)

- **`src/incident-correlation.js`** — already `source_type`-agnostic (confirmed by direct read;
  `peerSourceType` is read from the attribute and reported, never branched on).
- **`src/constraint-miner.js`** — `FAMILY_BY_FACT_NAME` has no entry for `peer.presence`; miner
  inertness is keyed on `fact_name`, not `source_type`, so it's unaffected by construction.
- **`src/alert-intelligence.js` / `src/calibration.js`** — no new rule_id, no namespace change
  (section 3).
- **`test/escalation-lint.test.js`** — scans `src/` recursively (`readdirSync`); the new file is
  automatically covered with zero edits. Verify it passes (trivial: the only argv literal is
  `["status", "--json"]`, no `sudo`/`setcap`/`pkexec`/`doas` token anywhere).

## 5. Test plan (fixture-driven, TDD, mirrors the named siblings)

This dev machine cannot run VMs/real `tailscaled` — every test below is fixture-driven against
injected `runFixedExecFile`/collector fakes, exactly like `vpn-peer-status.test.js`'s DI
convention. Write tests before implementation.

### `test/tailscale-status.test.js` (new — mirrors `test/vpn-peer-status.test.js`)

- fakeExec DI harness, argv-keyed script map (same convention as
  `vpn-peer-status.test.js`'s `fakeExec`).
- **Allowlist negative test**: read `src/tools/tailscale-status.js`'s own source and assert
  exactly one `execFile`/`runExec`-shaped call with argv `["status", "--json"]`, and that no other
  `tailscale` subcommand token (`up`/`down`/`set`/`logout`/`login`/`switch`/`configure`/`serve`/
  `funnel`/`lock`/`ssh`/`cert`) appears in real (non-comment) code — mirrors
  `vpn-peer-status.test.js`'s own `wg` allowlist test.
- Degrade-not-fabricate fixtures: `ENOENT` → `absent`; `BackendState:"NeedsLogin"` (exit 0) →
  `logged_out`, zero peers, confidence 0; `BackendState:"Stopped"` variant; permission-denied
  stderr → `missing_permission`, `elevation_candidate:true`; malformed/truncated JSON stdout →
  `unable`, never partially parsed.
- Golden `BackendState:"Running"` fixture, 3 peers (one online + currently our exit node, one
  online plain peer, one offline/historical peer) → asserts exact parsed peer shape including the
  Go zero-time (`"0001-01-01T00:00:00Z"`) → `latest_handshake_epoch_seconds: 0` → (downstream, in
  `fact-translators.test.js`) `handshake_age_bucket: "never"` special case. Also assert a genuinely
  *absent* `LastHandshake` field parses to `latest_handshake_epoch_seconds: undefined` →
  `handshake_age_bucket: "unknown"` — the two cases must stay distinguishable end-to-end (must-fix,
  Fable review 2026-08-11).
- Per-tick entity cap / `truncated`+`total_count` test (mirrors `vpn-peer-status.js`'s must-fix-3
  precedent).
- `timeout`/`maxBuffer` option-plumbing test.

### `test/fact-translators.test.js` (extend existing Slice-3 peer block)

- `factPointsFromTailscaleStatusEvidence` returns `[]` when no `"tailscale-status"` envelope is
  present, and when `envelope.status === "unable"` (mirrors `factPointsFromVpnPeerEvidence`'s own
  tests).
- Golden entity_key hash test: reproduces
  `computePeerIdentitySignature({ sourceType: "tailscale", peerIdentifier: <pubkey> })` exactly,
  pinned before shipping.
- `exit_node_role` bucket test: `"in_use"` / `"advertised_unused"` / `"none"` for tailscale peers;
  **regression guard** — `"n/a"` still holds for wireguard/ssh/vpn_service peers (existing source
  types unaffected).
- `handshake_age_bucket` now resolves for tailscale peers (reuses `bucketHandshakeAge`
  unchanged); still `"n/a"` for ssh/vpn_service.
- Overflow-marker test: tailscale's own `result.truncated:true` → `PEER_OVERFLOW_ENTITY_KEY` point
  emitted with the correct `total_count_bucket`.
- **Pinned negative test** (regression guard for the section-6 design decision): assert
  `factPointsFromTailscaleStatusEvidence` **never** emits a `PEER_CENSUS_MARKER_ENTITY_KEY` point,
  under any fixture.

### `test/peer-baseline.test.js` (extend)

- Combined-stream test: `vpn-peer-status` points + `tailscale-status` points sharing one `ts`
  correctly sum into one `groupPeerFactsByTick` tick-group count — proves "feeds
  `peer.count_spike`/`peer.count_drop` automatically" as a behavior, not just an assertion about
  wiring.
- **Tailscale-only markerless test (Fable must-fix, 2026-08-11 — documents the section-6 blind
  spot as a pinned regression, not just prose):** build tick-groups from
  `factPointsFromTailscaleStatusEvidence` output alone (no `vpn-peer-status` points, so no
  `PEER_CENSUS_MARKER_ENTITY_KEY` point exists in the stream) and assert
  `dropTickGroupDisposition`-driven behavior end-to-end: `groupPeerFactsByTick` produces
  `availabilitySignature: undefined` for every group, and
  `computeWindowedPeerDropStats(...).confidence_state` stays `"provisional"` (never
  `"established"`) even after ≥ `DEFAULT_PEER_MIN_SAMPLE_COUNT` tailscale-only ticks — pins the
  "drop detection is silently inert in a tailscale-only configuration" claim as a test, not just a
  plan assertion. Also assert `computeWindowedPeerStats` (the spike path) DOES reach
  `confidence_state: "established"` on the same fixture, confirming the spike/drop asymmetry.

### `test/peer-signature-store.test.js` (extend)

- Add a fourth golden fixture: `computePeerIdentitySignature` for a tailscale peer (identity =
  pubkey only, `remoteUser`/`remoteHost` unset) — same pinned-hash discipline as the existing
  wireguard/ssh/vpn_service fixtures.

### `test/daemon.test.js` (extend)

- `collectStructuralEvidence` respects `structuralProfile.collectors["tailscale-status"].enabled`
  gating (mirrors the existing `vpn-peer-status` gating test).
- `defaultDaemonProfile()` includes `"tailscale-status": { enabled: true }` (shape test).
- Extend the existing Slice-3 "store-separation" test (~line 1737) to also assert a
  tailscale-only tick never writes `signatures.json`/`peer-signatures.json`.
- Full `runDaemonIteration` integration test: inject a fake `collectTailscaleStatusEvidence`
  returning a realistic `Running` + peers envelope → assert `structuralFacts`/fact-history gains
  `peer.presence` points with `source_type:"tailscale"`, and assert the alerts array gains no
  rule_id beyond what `peer.count_spike`/`peer.count_drop` already produce (i.e., no accidental
  new alert family).

### `test/pi-harness.test.js` / `test/tool-policy.test.js`

- Existing exact-parity assertions (`TRIAGE_TOOL_NAMES` vs. live tool registry) will fail until
  both files are updated together — this is the existing regression guard, not new test code.

### `test/constraint-miner.test.js` (optional, cheap insurance)

- One redundant assertion: mine a fact-history containing a tailscale-sourced `peer.presence`
  point, confirm zero drafts. (Already covered transitively by `fact_name`-keyed inertness; this
  makes it explicit rather than relying on that transitive coverage.)

### `test/incident-correlation.test.js` (optional, confirmatory)

- One fixture-driven test: a tailscale-sourced `peer.presence` point participates in
  `correlation.login_kill_proximity` exactly like a WireGuard/SSH one
  (`diagnostics.peer_source_type === "tailscale"`). Not load-bearing (zero code change there), but
  closes the loop on the "feeds incident-correlation" claim end-to-end.

## 6. COLLISION WITH SHARED ALERT PIPELINE — Phase-2 sequencing note

**The collision:** `vpn-peer-status.js`'s translator (`factPointsFromVpnPeerEvidence`) already
emits an **unconditional per-tick `PEER_CENSUS_MARKER_ENTITY_KEY` point** carrying a single
`availability_signature` string (Decision 1, `fact-translators.js`) — a closed-enum bucket built
from its own 5 sources' statuses. `peer-baseline.js`'s `groupPeerFactsByTick` treats this marker
as **one value per tick-group** (`group.availabilitySignature = ...`, an overwrite, not a merge),
and `peer.count_drop`'s regime-keyed fold depends on that single value accurately representing
"which peer sources were degraded this tick."

If a naive implementation of the Tailscale translator mirrored `vpn-peer-status.js`'s marker
emission verbatim — emitting its **own** `PEER_CENSUS_MARKER_ENTITY_KEY` point, on the same `ts`,
with its own 1-source signature — the two collectors' marker points would collide on the same
tick-group. Whichever translator's point lands last in the `factPoints` concatenation order in
`daemon.js` would **silently overwrite** the other's `availability_signature`, corrupting
`peer.count_drop`'s regime key for every tick where both collectors ran (i.e., always, once both
are enabled) — a real, silent correctness bug, not a cosmetic one.

**This plan's resolution (Phase 1, this plan):** the Tailscale translator does **not** emit its
own census marker at all. The zero-tick-anchor / regime-key responsibility for the shared
`peer.presence` stream stays **solely** with `vpn-peer-status.js`'s marker, exactly as it is
today. Tailscale peers still contribute to `group.count` (real, non-marker `peer.presence` points
are always counted), and Tailscale's own overflow (`result.truncated`) still safely reuses
`PEER_OVERFLOW_ENTITY_KEY` — that marker is **safe to multiplex** because `groupPeerFactsByTick`
only ever sets `group.hasOverflow = true` (an OR, never a reset), so multiple collectors' overflow
markers on the same tick compose correctly without collision. Only the single-value
`availability_signature` field is unsafe to multiplex, which is exactly the field this plan avoids
producing a second copy of.

**Accepted v1 limitation (document, don't fix here):** because Tailscale's own source-availability
degradation (e.g., `tailscaled` installed but stopped, or logged out) is invisible to the regime
key, a Tailscale-logout-driven change in total peer count is scored by `peer.count_spike`/
`peer.count_drop` as ordinary baseline variance under the *same* regime as before — which is
actually correct/desired for a genuine count change, but means a **flapping** Tailscale daemon
(repeated stop/start) does not get isolated into its own regime the way a flapping WireGuard/SSH
source already does. Revisit only if this proves noisy in practice.

**Second accepted v1 limitation — tailscale-only-collector blind spot (Fable must-fix,
2026-08-11):** the `PEER_CENSUS_MARKER_ENTITY_KEY` point is emitted **only** by
`factPointsFromVpnPeerEvidence` (`vpn-peer-status.js`'s translator), never by
`factPointsFromTailscaleStatusEvidence` (deliberately, per the resolution above). This creates a
real operator-configuration dependency: **if the `"vpn-peer-status"` collector is disabled while
`"tailscale-status"` stays enabled, no census-marker point is ever emitted at all**, because
Tailscale peer facts are the only `peer.presence` points in that tick-group. Per
`dropTickGroupDisposition` (`peer-baseline.js`), any tick-group with `availabilitySignature ===
undefined` is `"markerless"`, and `computeWindowedPeerDropStats`'s `eligibleGroups` filter requires
`dropTickGroupDisposition(group) === "complete"` — so every tick-group is excluded from both the
fold (the persisted mean/variance/EWMA never advances) and the score (no `last_observation` is ever
produced). Concretely: **`peer.count_drop` is silently inert in a tailscale-only configuration** —
`confidence_state` stays `"provisional"` forever (mirrors the documented pre-Slice-4c cold-start
gate, `peer-baseline.js:420-426`), so a Tailscale-only drop-to-zero is never detected, not even as
a low-confidence signal. This is a real, permanent blind spot for that configuration, not a
transient cold-start — it does not resolve itself by waiting longer.

`peer.count_spike` is **not** affected the same way: `tickGroupDisposition` (the spike-only,
non-Slice-4c disposition function) only distinguishes `"overflow"`/`"complete"` and has no
`"markerless"` concept, so a tailscale-only tick-group folds and scores normally under
`computeWindowedPeerStats` — a Tailscale-only peer-count **spike** is still detected. Only the
*drop* direction is lost.

**Operator-facing consequence to document (`docs/reference/collectors.md`, section 4 of this
plan):** Tailscale drop-direction coverage (`peer.count_drop`) requires the `"vpn-peer-status"`
collector to also be enabled (even if its own 5 WireGuard/SSH/session sources are all `"absent"` on
that host — the collector still runs and still emits its unconditional per-tick census marker,
which is all `peer.count_drop` needs to stop being markerless). A Tailscale-only deployment (
`"vpn-peer-status"` disabled, `"tailscale-status"` enabled) gets spike detection but not drop
detection on the shared `peer.presence` stream. Not fixed in this plan — fixing it for real requires
the Phase-2 multi-collector signature schema change already described immediately above (a Phase-1
partial fix, e.g. having the Tailscale translator emit the marker only when
`vpn-peer-status`'s own envelope is absent from that tick, was considered and rejected: it would
silently reintroduce the exact overwrite-collision this section exists to prevent the moment both
collectors are enabled together and race on emission order, trading one silent bug for another).

**Phase 2 (explicitly out of scope for this plan):** if a future slice needs Tailscale's own
degradation state folded into the regime key, it needs a real, reviewed schema change — e.g. a
combined multi-collector signature (concatenating each active peer-source collector's own status
bucket into one ordered string, versioned as `v2`) or a peer-source-scoped marker entity_key
convention (`peer.census-marker.tailscale.v1` alongside a redesigned
`computeWindowedPeerStats`/`computeWindowedPeerDropStats` that merges per-source regime keys). Do
not let a future collector "naively copy `vpn-peer-status.js`'s marker-emission pattern" without
first re-reading this section — that is exactly the bug this plan avoids introducing today.

## 7. Safety invariants preserved

- **Read-only.** Single fixed-argv allowlist entry (`["status", "--json"]`), `execFile` only (no
  shell), no dynamic subcommand construction — a static source read is sufficient to confirm the
  complete argv surface (pinned by the allowlist negative test).
- **Structurally incapable of mutation.** No `tailscale up/down/set/logout/switch/configure/
  serve/funnel/lock/ssh/cert` — these tokens cannot appear in a constructible argv because the
  file contains exactly one hardcoded argv array literal.
- **Bounded.** Per-tick peer cap (200, `truncated`+`total_count` never silently dropped), bounded
  `timeout`/`maxBuffer`, structural-tick deadline already enforced generically by `daemon.js`'s
  `withDeadline`/`DEFAULT_STRUCTURAL_TICK_DEADLINE_MS` (no new deadline logic needed).
- **Evidence-envelope-shaped.** Reuses `evidenceEnvelope`/`timedEnvelope` from
  `tools/envelope.js`, identical `id`/`source`/`tool`/`confidence`/`review_hint` discipline.
- **Detectors default-OFF behind `learned.json`.** The collector itself has no detector logic; the
  only detectors that read its facts (`peer.count_spike`/`peer.count_drop`,
  `correlation.login_kill_proximity`) are already gated behind
  `loadLearnedConfig(...).enabled`, unchanged by this plan.
- **Deterministic NO-LLM alert path.** Zero new rule_ids, zero new `extraCandidates` entries — the
  entire new fact stream is consumed by already-shipped, already-reviewed deterministic
  detectors.
- **Fail-closed alert namespace.** No new rule_id means no new `classifyAlertNamespace` branch;
  `peer.*` remains `unknown_namespace` (permanently un-consentable to LLM adjudication), unchanged
  by this plan.
- **Degrade-not-fabricate.** Full status ladder (`absent`/`logged_out`/`missing_permission`/
  `unable`/`ok`); a genuinely logged-out Tailscale is a real, distinguishable zero, never
  conflated with an error.
- **Hash/bucket identity at source.** `entity_key` is `computePeerIdentitySignature`'s hash (node
  public key only); every persisted attribute (`source_type`, `presence_state`,
  `login_hour_bucket`, `handshake_age_bucket`, `exit_node_role`) is a closed-enum literal/bucket —
  no raw pubkey, IP, hostname, tailnet name, or user identity ever reaches `fact-store.js` (whose
  attribute sanitization is only a 160-char truncate — hashing/bucketing at the translator is the
  only real control, per `fact-translators.js`'s own documented hard requirement).
- **No new raw telemetry/federation.** `peer-signature-store.js` stays unwired from the daemon
  loop for Tailscale, exactly as it already is for WireGuard/SSH/vpn_service.

## 8. Open questions

1. Exact `tailscale status --json` field names/shapes (`Self`, `Peer` map, `CurrentTailnet`,
   `BackendState` enum values, `ExitNode`/`ExitNodeOption` booleans, `LastHandshake` RFC3339 +
   Go-zero-time sentinel) need confirmation against real output or Tailscale's published
   `ipn/ipnstate` struct docs before the parser is finalized — this dev machine cannot run
   `tailscaled`/VMs, so fixtures must be hand-built and carefully cross-checked, exactly flagged
   in-code the way `vpn-peer-status.js` flags its own `wg`/`who`/`last` shape assumptions.
2. Does `tailscale status --json` ever require elevated privileges on any platform (unlike
   `wg show`, which commonly does)? If so, mirror the existing `elevation_candidate`
   documentation-only marker convention (the S3-priv opt-in path already shipped would be the
   place to add an elevated read later — this collector itself never escalates).
3. Exact stderr phrasing for a logged-out/stopped daemon likely varies by Tailscale version and
   platform — prefer `BackendState` from parsed JSON over stderr text-sniffing wherever both are
   available; the stderr-based fallback should stay conservative (narrow, specific phrases only,
   defaulting to `"unable"` rather than guessing `"logged_out"`).
4. Deferred to Phase 2 (not this plan): folding Tailscale's own degradation into the
   `peer.count_drop` regime key (section 6); whether new-device/odd-hour/exit-node-change ever
   warrant their **own** new alert rule_ids beyond just widening `peer.count_spike`/
   `peer.count_drop`'s input; whether `tailscale netcheck`/`whois` are ever worth adding to the
   allowlist for richer signal (both explicitly deferred by the todo).
