---
title: Inter-Agent Delegation, Identity, and Authority
created: 2026-05-19
status: open
priority: medium
area: architecture
kind: todo
owner: unassigned
related:
  - docs/ROADMAP.md
  - docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md
---

# TODO: Inter-Agent Delegation, Identity, and Authority

## Summary

Long-term Descartes should be able to delegate work to other agents or execution environments, but only through explicit identity, authentication, policy, and user-validation boundaries.

Examples:

- local Descartes asks a CI agent to run Linux validation
- laptop Descartes delegates a check to a server-side Descartes instance
- a user-approved remediation plan delegates one step to a VM/container agent
- agents exchange evidence envelopes, plans, approvals, and audit records

## Design Goals

- Every agent has an explicit identity.
- Every delegated request is authenticated.
- Every delegated action has a scoped authority token/capability, not ambient trust.
- The receiving agent verifies caller identity, requested capability, policy, and approval scope.
- The initiating agent records why delegation was chosen and what authority was granted.
- The user can validate/approve cross-agent delegation before mutating or sensitive actions.
- Delegated agents return structured evidence/results, not unverifiable prose.
- All delegation is auditable end-to-end.

## Open Questions

- What is the initial identity primitive? Local keypair, workload identity, CI OIDC, SSH cert, mTLS, signed JWT/PASETO, or something else?
- How are capabilities represented and scoped?
- How does user approval bind to a delegated action?
- How are revocation, expiry, replay protection, and nonce/challenge handled?
- How do agents prove what environment they executed in?
- What evidence is safe to transmit between agents by default?

## Acceptance Criteria For A First Design Spike

- Document agent identity and capability-token model.
- Define a delegated request/response envelope.
- Define audit fields for delegated actions.
- Define policy checks for caller, callee, action, scope, expiry, and user approval.
- Identify one narrow first use case, likely CI/Linux validation, before generalizing.
