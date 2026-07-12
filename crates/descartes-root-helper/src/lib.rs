//! Library crate for descartes-root-helper: exposes `hardening`, the kernel-level
//! privilege-confinement module (S3-priv Slice 4), to both the production binary (`src/main.rs`)
//! and the out-of-process test probe (`src/bin/hardening-probe.rs`) -- one source of truth for
//! what `engage()`/`drop_capabilities()` actually do, so the probe's behavior under test can never
//! drift from what ships.
//!
//! `unsafe` is denied at the crate root and re-enabled ONLY for `hardening`, which is where every
//! raw syscall (seccomp/prctl/capset) in this crate's production path lives -- see that module's
//! doc comment.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(unsafe_code)]
pub mod hardening;
