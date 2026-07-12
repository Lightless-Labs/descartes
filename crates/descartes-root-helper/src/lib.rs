//! Library crate for descartes-root-helper: exposes `hardening`, the kernel-level
//! privilege-confinement module (S3-priv Slice 4), to both the production binary (`src/main.rs`)
//! and the out-of-process test probe (`src/bin/hardening-probe.rs`) -- one source of truth for
//! what `engage()`/`drop_capabilities()` actually do, so the probe's behavior under test can never
//! drift from what ships. Also exposes `procfs` (S3-priv Slice 5 Part A), the `/proc/<pid>`
//! dirfd-pinning primitives `src/proc_linux.rs` (a separate, `bin`-crate module) builds its
//! PID-reuse-safe resolution on.
//!
//! `unsafe` is denied at the crate root and re-enabled ONLY for `hardening` and `procfs`, which
//! are where every raw syscall in this crate's production path lives -- see each module's doc
//! comment.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(unsafe_code)]
pub mod hardening;

/// `/proc/<pid>` dirfd-pinning primitives (S3-priv Slice 5 Part A) -- INTERNAL CONTRACT, NO
/// EXTERNAL CONSUMER. `pub` (not `pub(crate)`) purely because `src/main.rs` + `src/proc_linux.rs`
/// (the `bin` crate) and this `lib` crate are SEPARATE crates -- `proc_linux.rs` calls into this
/// module exactly like it already depends on `hardening`. Linux-only: `/proc/<pid>` dirfd pinning
/// has no meaning on a platform without `/proc`.
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[allow(unsafe_code)]
pub mod procfs;
