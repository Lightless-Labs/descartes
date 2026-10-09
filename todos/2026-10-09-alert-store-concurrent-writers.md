# Alert-store concurrent writers

Status: deferred separate slice (2026-10-09)

The alert store still performs unlocked read-modify-write updates. Detection persistence rereads the
latest snapshot before writing, and acknowledgement, delivery confirmation, delivery failure, and
adjudication each write a whole alert snapshot. Two concurrent daemons are therefore unsupported;
this slice removes the daemon singleton and does not attempt to make the store multi-writer safe.

Evidence from the daybreak round-4 reports in the notify-once prompt:

- singleton ownership could be lost through stale-owner reclamation and separate runtime/state roots;
- the command queue added a second crash-replay surface and was removed;
- the underlying alert-store lost-update read-modify-write race was identified as pre-existing on
  `main`, rather than being a notify-once representation defect.

With first-class per-incident confirmation, a lost confirmation write can cause a duplicate delivery
on replay, but cannot cause silence. `notify-once.test.js` simulates that lost write and asserts the
redelivery. A future writer-safety slice should choose and test an atomic protocol (for example an
OS lock or versioned compare-and-swap), define recovery after interrupted writes, and cover detection,
acknowledgement, confirmation, failure, and adjudication writers together.
