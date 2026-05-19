---
title: Web Search and Retrieval Tools for Descartes Investigation
created: 2026-05-19
status: open
priority: medium
area: knowledge
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-federated-process-knowledge-db.md
---

# TODO: Web Search and Retrieval Tools for Descartes Investigation

## Summary

Descartes should eventually be able to look up unknown programs, process names, error messages, and documentation via explicit read-only web/search tools.

This is closer-future work, not the immediate local triage tool loop.

## Use Cases

- Identify what a process/program is.
- Find vendor documentation for a daemon or service.
- Look up common failure modes for a package/process/version.
- Resolve ambiguous local evidence with external context.

## Possible Sources

- general web search
- Google/custom search
- Linkup
- Perplexity
- Context7
- DeepWiki
- vendor docs
- package registries / Homebrew / npm / crates.io / GitHub metadata

## Design Options

1. User-provided search provider credentials.
2. A Lightless Labs proxy that performs search/retrieval.
3. Both, with the proxy optional.

## Lightless Proxy Possibility

If Lightless Labs provides a proxy, it can:

- cache by exact key
- cache semantically / by semantic proximity
- normalize process/package/docs metadata
- rate-limit and deduplicate external calls
- feed curated findings into the future process knowledge database

## Privacy Constraints

- no raw logs by default
- no private paths by default
- no usernames/hostnames by default
- query shaping should minimize sensitive local identifiers
- user should understand when external web/search is used
- web/search should remain explicit read-only investigation, not telemetry

## Acceptance Criteria

This todo is complete when Descartes has a documented and implemented read-only search/retrieval abstraction with at least one provider, privacy-preserving query shaping, and clear JSON traces for external lookups.
