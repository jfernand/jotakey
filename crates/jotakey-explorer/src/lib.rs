// (c) Javier Fernandez @ JotaSoft 2026
//! jotakey-explorer: find the FIDO security keys attached to this computer and show what
//! each one reports about itself. Works with any FIDO key on Linux (hidraw), including a
//! Jotakey behind `jotakey-bridge`. It only asks questions; see [`report`] for exactly which.

#![forbid(unsafe_code)]

pub mod app;
pub mod cbor;
pub mod ctaphid;
pub mod discover;
pub mod report;
