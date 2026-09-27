# Correlation recovery-coverage (deferred from the detector-reported-recovery-coverage slice)

**Created:** 2026-09-27
**Status:** DEFERRED — correlation coverage is currently safe-frozen (never fabricates); this is the follow-up to restore genuine recovery.
**Origin:** `todos/2026-09-20-detector-reported-recovery-coverage.md` (that slice deferred correlation after 3 daybreak rounds).

## State
`incident-correlation.js` `computeCorrelationCandidates` reports `evaluatedAlertKeys: []` on every path (commit `52ad5cc`) → every persisted `correlation.login_kill_proximity` alert FREEZES (never auto-recovers, never fabricates). Detection logic is unchanged. Correlation is AUTHOR-tier (learned-gated, default-off), so this affects only opted-in-authoring users; freezing a high-severity intrusion-correlation signal until manually acknowledged is acceptable/arguably-good.

## Why deferred (daybreak found 3 progressively-deeper fabrication edges)
Correlation's fingerprint is compound and data-dependent (`<anchor.fingerprint>__<winning-peer>`), so exact identity coverage is hard, and it interacts with the alert-store's malformed-row quarantine:
1. **Orphan/expiry** (`7f812b8`): "no live anchor prefix" wrongly treated as expiry → recovered on missing/future/quarantined source anchors. Fixed to require present+unique+valid-non-future+age>lookback.
2. **Both-branch prefix matching** (`82eab31`): the LIVE branch (and the expiry cross-check) still used bare fingerprint-prefix matching without verifying source-anchor identity (diagnostic-fingerprint mismatch, ambiguous duplicates, unrelated live anchor sharing a prefix). Unified: resolve to exactly one source anchor (complete diagnostics + prefix consistency + unique row) before either branch.
3. **Malformed-duplicate quarantine** (open): `readAlertRecords` silently quarantines malformed rows, so the uniqueness check can see a false "exactly one match" when a valid + a malformed-duplicate anchor share `(rule_id, fingerprint)` → fabricated recovery. daybreak's prescribed fix: preserve quarantined source identities for resolution and count matching malformed rows as invalid/ambiguous (freeze); add valid-plus-malformed-duplicate regressions (expiry + live).

## To do (the proper coverage slice)
Restore genuine correlation recovery coverage: resolve each persisted correlation to its unique source anchor INCLUDING visibility of quarantined/malformed rows (so a shadowed duplicate → ambiguous → freeze); classify live/expired/future/invalid; recover expired directly and live only after trusted+ready peer evaluation; freeze everything unresolved. Then a daybreak re-gate. Consider whether alert-store should expose quarantined rows for identity-conflict detection generally.
