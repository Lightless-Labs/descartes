# Daybreak gate — Linux ACL fallback (fix/linux-acl-fallback-2026-11)

Reviewer: gpt-daybreak-blue-latest via codex. Date: 2026-11-03.

## Round 1

BLOCKER — [binary-resolver.js:422](tools/descartes-cli/src/tools/binary-resolver.js:422) rejects only a realpath basename exactly equal to `busybox`; it does not establish GNU semantics. Toybox, renamed BusyBox, or a BusyBox hardlink emits a valid 10-character mode without inspecting ACLs, which [the parser](tools/descartes-cli/src/tools/binary-resolver.js:404) reports as `absent`. Toybox’s implementation prints `mode_to_string()` without an ACL marker ([source](https://github.com/gfto/toybox/blob/master/toys/posix/ls.c)). Reproduced: resolved `/usr/bin/toybox` plus plain output returns `absent` for an ACL-bearing target.

BLOCKER — [binary-resolver.js:414](tools/descartes-cli/src/tools/binary-resolver.js:414) uses `ls` as a trust oracle after only realpath/absolute-path checks; its file and component chain are never ownership-, mode-, or ACL-checked. An ACL-authorized attacker can replace `/bin/ls`, or redirect it to an attacker-controlled absolute executable, and emit a plain mode for every probe. The target’s mode/ownership phase passes and all ACL-bearing components are then accepted. Reproduced with `/bin/ls → /opt/attacker/ls`: current code returns `absent`.

VERDICT: NEEDS-REWORK (2 blockers)
## Round 2

BLOCKER — [`binary-resolver.js:687`](tools/descartes-cli/src/tools/binary-resolver.js:687) records `acl_evidence: "unverified"`, but common collectors discard it. For example, [`processes.js:190`](tools/descartes-cli/src/tools/processes.js:190) retains only parsed processes and command metadata. The daemon scanner only recognizes an emitted `binary_provenance` object at [`daemon.js:115`](tools/descartes-cli/src/daemon.js:115). Scenario: Linux lacks trusted `getfattr` and GNU `ls`; `ps` is accepted with unverified ACL evidence, but `top-processes`, daemon status, and facts contain no marker—externally indistinguishable from verified absence. The test at [`daemon.test.js:186`](tools/descartes-cli/test/daemon.test.js:186) manually injects provenance and therefore misses the real collector path.

HIGH — None.

MEDIUM — None.

LOW — None.

Prior blockers are otherwise closed: [`binary-resolver.js:457`](tools/descartes-cli/src/tools/binary-resolver.js:457) trust-checks the helper chain before execution, and [`binary-resolver.js:458`](tools/descartes-cli/src/tools/binary-resolver.js:458) requires GNU-coreutils version evidence before parsing `ls`. Non-GNU `ls` yields `acl_unverified`, and untrusted `ls` is never executed. Mode/ownership and macOS behavior show no regression; the focused hermetic suite passed 280/280.

VERDICT: NEEDS-REWORK (1 blockers)
## Round 3

BLOCKER — None. The original Linux scenario is closed: the resolver records `unverified` ([binary-resolver.js:698](tools/descartes-cli/src/tools/binary-resolver.js:698)), the real `ps` collector preserves it ([processes.js:193](tools/descartes-cli/src/tools/processes.js:193)), daemon status and `collector_statuses` surface it ([daemon.js:2178](tools/descartes-cli/src/daemon.js:2178)), and fast evidence now feeds `collector.binary_state` facts ([daemon.js:1590](tools/descartes-cli/src/daemon.js:1590), [context-translators.js:590](tools/descartes-cli/src/context-translators.js:590)). The real-path regression test covers all three surfaces ([linux-acl-fallback-regate.test.js:101](tools/descartes-cli/test/linux-acl-fallback-regate.test.js:101)). All resolver-backed collector paths retain provenance.

HIGH — None. macOS returns `not_applicable`, and daemon emission is Linux-gated ([binary-resolver.js:490](tools/descartes-cli/src/tools/binary-resolver.js:490), [daemon.js:126](tools/descartes-cli/src/daemon.js:126)). Verified, unverified, unknown, and absent remain distinct; facts map missing ACL provenance to `unknown`, never `absent` ([context-translators.js:616](tools/descartes-cli/src/context-translators.js:616)).

MEDIUM — None. The earlier helper-chain blockers remain closed: helper mode/ownership is checked before execution, and `ls` must identify as GNU coreutils ([binary-resolver.js:457](tools/descartes-cli/src/tools/binary-resolver.js:457), [binary-resolver.js:467](tools/descartes-cli/src/tools/binary-resolver.js:467)).

LOW — None. Focused hermetic suite passed 259/259; worktree remained unchanged.

VERDICT: READY