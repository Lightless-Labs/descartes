// S3-priv Slice 6 — the cross-UID functional smoke run itself. Deliberately tiny: this is the
// harness the privileged CI step (scripts/ci-elevated-provenance.sh) execs twice against the same
// listening port -- once unprivileged, once sg-wrapped into the descartes-provenance group -- to
// prove the elevated /proc read path actually upgrades a real cross-UID resolution. See
// docs/plans/2026-07-11-s3-priv-elevated-read-path.md Slice 6 and
// tools/descartes-cli/src/tools/provenance.js's resolveCrossUidPortResult (the code this exercises).
//
// No deps beyond the two local ESM imports (both node-builtins + local-ESM only, per
// tools/descartes-cli/src/tools/provenance.js's own import graph), no side effects beyond the one
// console.log below, no privilege-escalation terms anywhere in this file -- it never shells out,
// never invokes sudo/setcap/pkexec, and never touches the helper binary directly. It only ever
// calls the same unprivileged Node entry point (`resolveProvenance`) every other Descartes caller
// uses; whatever privilege is in effect for THIS process (none, or the descartes-provenance group
// via the caller's `sg`/`sudo -g` wrap) is entirely the CALLER's doing, not this file's.
//
// Runs identically on macOS (takes resolveByPortMac's code path) so it can be `node --check`'d and
// dry-run'd on a dev machine with no Linux root -- see this repo's Slice 6 definition of done.

import { resolveProvenance } from "../src/tools/provenance.js";
import { resolveDescartesPaths } from "../src/paths.js";

const port = Number(process.argv[2]);

// `process.env`, not a filtered subset: the caller sets XDG_CONFIG_HOME (and, for the elevated
// run, wraps this process under `sg descartes-provenance`) before exec'ing this file specifically
// so that env reaches resolveDescartesPaths unmodified.
const env = process.env;
const paths = resolveDescartesPaths(env);

const envelope = await resolveProvenance({ port }, { paths });

console.log(JSON.stringify(envelope));
