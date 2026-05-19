---
title: Federated Process Knowledge Database
created: 2026-05-19
status: open
priority: future
area: knowledge
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-web-search-retrieval-tools.md
---

# TODO: Federated Process Knowledge Database

## Summary

Longer term, Descartes could maintain or contribute to a shared/federated database of processes and operational behavior.

This is future work. It should not block the first local triage product.

## Potential Contents

- process names and common executable paths
- what the process is for
- common parent/child process relationships
- normal CPU/memory/network/disk behavior patterns
- expected launch contexts
- package/application ownership
- known problematic versions
- known issue signatures
- safe investigation steps
- unsafe/remediation caveats
- links to authoritative docs

## Example Entries

- `WindowServer` on macOS:
  - expected GUI compositor process
  - CPU spikes may correlate with external displays, screen recording, GPU-heavy apps, or display driver issues
- `dolt sql-server`:
  - Dolt database server
  - high CPU may indicate active query, indexing, import, replication, or pathological query workload
- simulator runtime mounts:
  - often read-only/full by design
  - should not be treated the same as root/data disk pressure

## Federation / Privacy Defaults

- opt-in only
- no raw logs
- no usernames
- no full private paths
- no hostnames
- no stable host/user identifiers
- prefer local hashing/bucketing only with a clear threat model
- separate local knowledge from federated/shared knowledge

## Relationship To Web/Search Proxy

A Lightless-owned web/search proxy could feed this database by normalizing retrieved process/package/docs information, caching lookup results, and turning repeated confirmed findings into structured entries.

## Acceptance Criteria

This todo is complete when there is a concrete data model, privacy model, local/offline behavior, opt-in federation protocol, and at least a small curated seed database used by Descartes diagnosis.
