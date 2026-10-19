// (c) Javier Fernandez @ JotaSoft 2026
//! Jotakey authenticator core.
//!
//! Everything that interprets bytes from the host lives here: CBOR, the CTAP2 command
//! layer, CTAPHID and BLE framing, credential wrapping and the power-on self tests. The
//! crate is `no_std`, does not allocate, and contains no `unsafe`. Hardware is reached only
//! through the [`platform::Platform`] trait so the whole core runs and is tested on the host.
//!
//! The security invariants this crate upholds are listed in `AGENTS.md` §2.

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::todo,
        clippy::unimplemented,
    )
)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod authdata;
pub mod cbor;
pub mod credential;
pub mod crypto;
pub mod ctap;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod pin_protocol;
pub mod platform;
pub mod selftest;
pub mod status;
pub mod storage;
pub mod transport;

/// Largest CTAP request or response this authenticator accepts or emits, in bytes.
///
/// Advertised to the platform as `maxMsgSize` in `authenticatorGetInfo`. It bounds every
/// buffer in the core and in both transports.
pub const MAX_MSG_SIZE: usize = 1200;

/// AAGUID reported by this authenticator model.
///
/// Self-attestation does not identify the model cryptographically. The AAGUID is
/// informational only.
pub const AAGUID: [u8; 16] = [
    0x6a, 0x6f, 0x74, 0x61, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x30, 0x31, 0x2d, 0x63, 0x36, 0x00, 0x01,
];
