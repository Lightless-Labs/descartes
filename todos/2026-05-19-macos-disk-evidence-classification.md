---
title: macOS Disk Evidence Classification and Redaction Improvements
created: 2026-05-19
status: completed
priority: high
area: triage
kind: todo
owner: unassigned
related:
  - todos/2026-05-19-expand-local-investigation-tools.md
  - todos/2026-05-19-llm-driven-investigation-tools.md
---

# TODO: macOS Disk Evidence Classification and Redaction Improvements

**Completed:** 2026-05-19 — added disk filesystem classification, fixed macOS `map ... 100% /path` parsing, excluded virtual and CoreSimulator/Cryptex developer runtime image mounts from disk-pressure findings, added aggregate runtime-image notice, and bumped package metadata to v0.0.14.

## Summary

A real macOS disk triage field test worked well end-to-end: Anthropic Sonnet used the guarded Descartes tool surface, called `collect_disks`, and produced a useful evidence-cited diagnosis for large macOS "System Data" attributed mostly to mounted Xcode CoreSimulator runtime images.

The same test exposed deterministic evidence-quality gaps that should be fixed below LLM synthesis.

## Field Report Highlights

Prompt:

```text
How is my disk doing? Ignore simulator images volumes. Why do I have 300GB+ of 'System Data'?
```

Observed good behavior:

- LLM tool loop worked with `investigation_enabled: true`.
- Active tools were exactly the Descartes read-only tool set.
- The model called `collect_disks` and returned non-fallback diagnosis text.
- The diagnosis correctly recognized APFS shared free space and CoreSimulator runtimes as a likely major "System Data" contributor.

Observed gaps:

- `derive_findings` flagged `/dev` (`devfs`) as critical disk pressure, even though it is a virtual pseudo-filesystem and should be ignored or classified separately.
- `derive_findings` flagged every mounted CoreSimulator runtime image as critical/warning because those fixed-size read-only-ish images are intentionally nearly full.
- Historical JSON output included full process command lines; default process evidence now emits redacted/bounded args with metadata, but a future explicit local-only/full vs share-safe export policy still needs design.
- The model handled the user's "Ignore simulator image volumes" instruction semantically, but deterministic findings still surfaced simulator image pressure as actionable-looking critical findings.

## Implementation Tasks

1. Add filesystem classification for macOS disk evidence:
   - `virtual`: `devfs`, synthetic maps, pseudo filesystems.
   - `apfs_system`: sealed system/preboot/update/vm/support volumes.
   - `apfs_data`: primary Data volume.
   - `developer_runtime_image`: CoreSimulator runtime/cryptex mounts.
   - `external_or_other`: fallback.
2. Update disk-pressure findings to ignore or downgrade expected-full pseudo/runtime-image mounts.
3. Add separate informational findings for large mounted simulator runtime images, with aggregate total bytes rather than one critical finding per mount.
4. Fix `df` parsing for odd macOS `map ... /System/Volumes/Data/home` rows so mount points are not stored as `"100% /path"`.
5. Add tests with fixture rows for:
   - `devfs` at 100% should not produce critical disk pressure.
   - CoreSimulator runtime images at 98% should not produce critical disk pressure.
   - Data volume at high utilization should still produce real disk pressure.
6. Plan explicit report/export policy for process command lines now that default JSON is bounded/redacted:
   - keep default `--json` safe enough for routine debugging, and
   - reserve any future raw local-only detail behind an explicit flag and clear sensitivity warning.

## Acceptance Criteria

- macOS `/dev` no longer appears as critical disk pressure.
- CoreSimulator runtime image mounts no longer appear as individual critical disk-pressure findings.
- A disk triage JSON report still includes enough evidence for the LLM to explain large simulator storage when relevant.
- Tests cover virtual filesystems, simulator images, and real full Data/root filesystems.
