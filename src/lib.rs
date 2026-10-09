//! sentinel-guard library surface.
//!
//! The crate is a binary first: `src/main.rs` is the CLI. This library target
//! exists so the fuzz targets under `fuzz/` and the integration tests under
//! `tests/` can drive the parsers and the policy pipeline directly, without
//! spawning the binary. The module tree is the same one the binary uses; no
//! API stability is promised across versions.

pub mod audit;
pub mod audit_mcp;
pub mod audit_trail;
pub mod check;
pub mod cli;
pub mod common;
pub mod corpus;
pub mod doctor;
pub mod evaluate;
pub mod install;
pub mod lint;
pub mod policy;
pub mod policy_diff;
pub mod policy_migrate;
pub mod post_evaluate;
pub mod preflight;
pub mod selfprotect;
pub mod verify;
pub mod why;
