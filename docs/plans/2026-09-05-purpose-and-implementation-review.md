---
title: Purpose-first design and current implementation review
date: 2026-09-05
updated: 2026-09-05
update_reason: Both requested documents completed; source references and selected regression suites verified
status: completed
---

# Purpose-first design and current implementation review

The user requested two saved documents, in order: an independent account of how Descartes should work from its stated purpose, followed by an evidence-based critique of its current design, implementation, and choices.

## Method

1. Read the supplied project identity and README introduction; defer implementation-bearing startup documents to preserve the requested order.
2. Write and save the independent proposal before reading current design or code. **Complete:** `docs/architecture/2026-09-05-purpose-first-design.md`. Preserve this baseline during review.
3. Read manifests, current handoff, roadmap, relevant design plans, and the implemented observation, alert, investigation, learning, and authority boundaries. Trace claims to source; account for the September 4 fixes. **Complete.**
4. Save a separate critique distinguishing confirmed implementation limitations, architectural judgments, and incomplete future work. Include what to retain, what to change, and a practical sequence with observable acceptance criteria. **Complete:** `docs/reviews/2026-09-05-design-and-implementation-critique.md`.
5. Verify documentation references and the smallest useful relevant checks; update HANDOFF.md with the deliverables and scope. Do not change runtime behavior or existing design decisions as part of this review. **Complete:** 280 selected Node tests passed; links and baseline hash verified; handoff updated; no runtime edits by this review. Concurrent alert-intelligence edits were left intact and recorded in the critique's scope note.

## Review questions

- Which operating jobs does the current product complete, and where does it stop?
- Do model use, temporal state, notification delivery, and learning serve those jobs?
- Are source facts, causal judgments, evidence integrity, and authority kept distinct?
- Does the next planned investment follow demonstrated operational need?
- Which differences from the independent proposal reflect newly discovered operator intent rather than implementation mistakes?
