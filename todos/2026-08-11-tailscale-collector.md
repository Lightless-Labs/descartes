---
title: Collector candidate — Tailscale / tailnet (network-identity + traffic patterns)
created: 2026-08-11
status: pending
priority: medium
area: collectors
kind: todo
owner: unassigned
related:
  - docs/research/2026-08-11-agentic-intrusion-defense.md
  - todos/2026-08-11-agent-intrusion-detection-gaps.md
  - todos/2026-08-11-apple-container-collector.md
  - todos/2026-07-09-self-learning-stratified-monitoring.md
---

# Collector candidate: Tailscale / tailnet (network-identity + traffic patterns)

**Created:** 2026-08-11
**Status:** Candidate / not scheduled — extends the existing peer-identity baseline; moderate scope.
**Origin:** A Tailscale engineer starred the repo (network-identity is landing with the right audience) + the agent-intrusion material (below) makes network identity a prime detection surface.

## Why

Slice 3 already ships `collect_vpn_peer_status` (`tools/descartes-cli/src/tools/vpn-peer-status.js`) + `peer-signature-store.js`, reading **WireGuard** via a fixed-argv allowlist and baselining peer identity (feeds `peer.presence` → Slice 4b `peer.count_spike`, Slice 6 incident-correlation). Tailscale is WireGuard-based with a *much* richer, directly-readable control plane — so it's the natural next peer source, and the one where the observed-incident signature **"unattributed odd-hour peer login"** actually manifests in the real world.

## Scope (sibling to the WireGuard collector — reuse Slice 3/4b machinery, don't reinvent)

- **Read-only, fixed-argv allowlist** mirroring the `wg show` allowlist discipline: `tailscale status --json` (device/peer inventory, online state, exit-node, tailnet name), optionally `tailscale netcheck` and `tailscale whois`. Structurally incapable of mutating state (no `tailscale up/down/set/logout`).
- **Feed the existing `peer-signature-store.js` baseline** — extend `peer.presence` facts with tailnet peers; hash/bucket every identity **at source** (node pubkeys, Tailscale IPs/`100.x`, MagicDNS hostnames, tailnet/org name, user) using the existing `descartes.peer.v1`-style scheme. Degrade-not-fabricate when `tailscale` is absent/logged-out.

## Signatures it unlocks (map directly onto shipped/planned detectors)

- **new device joins the tailnet** → new-peer / `new_public_bind`-style identity signal.
- **peer online at an odd hour** → already the incident-correlation (Slice 6) login-side anchor; Tailscale is where it's observable.
- **exit-node usage change** (traffic suddenly egressing via a new/unexpected node) → a genuine "traffic pattern" signal Livio flagged.
- **device-count spike** → `peer.count_spike` already exists (Slice 4b); **count_drop** (Slice 4c) too.
- **ACL / tag drift, tailnet-lock key change, new Tailscale-SSH session** → identity-drift-class signals.

## Open items to verify at implementation time

- Exact `tailscale status --json` field shape + which fields are stable across versions; whether per-flow **traffic** data is accessible read-only (likely limited — device/peer/exit-node *state* is the reliable surface; true flow-level traffic may need `tailscale bugreport`/metrics or is out of scope).
- Privacy: a tailnet is strongly org-identifying — hash/bucket at source, same discipline as the existing peer scheme; nothing raw persisted or federated.
- Local vs control-plane: `tailscale status` is local-daemon state; a tailnet-wide view (admin API) is a separate, auth'd, opt-in surface — keep v1 to the local daemon.

## Effort

Moderate — a new collector + translator extending the shipped peer scheme + baseline; larger than a standalone container collector because it feeds the identity/anomaly baseline, but it reuses Slice 3/4b/6 machinery rather than adding new alert plumbing.
