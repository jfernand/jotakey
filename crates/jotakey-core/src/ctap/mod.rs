//! CTAP2 command layer (CTAP 2.0 §5) as a resumable state machine.
//!
//! [`Authenticator::process`] parses and validates a request. Commands that need the user's
//! touch return [`Outcome::NeedsUserPresence`] and park their validated parameters in
//! [`Pending`]. The caller waits for the button, sending keepalives meanwhile, and then calls
//! [`Authenticator::complete`] with the [`PresenceResult`].
//!
//! **Invariant 1** is structural: the only code paths that call [`crate::crypto::sign`] are
//! inside `complete`, and only under `PresenceResult::Confirmed`. `formal/Jotakey/Authenticator.lean`
//! models this state machine and proves the property over all command traces.

mod get_assertion;
mod get_info;
mod make_credential;
mod parse;
mod reset;

use zeroize::Zeroizing;

use crate::MAX_MSG_SIZE;
use crate::cbor::{CborError, Encoder};
use crate::credential::{CRED_ID_LEN, NONCE_LEN};
use crate::platform::{Platform, SecretLabel, PresenceResult};
use crate::status::Status;

/// CTAP2 command bytes.
pub mod command {
    /// authenticatorMakeCredential
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    /// authenticatorGetAssertion
    pub const GET_ASSERTION: u8 = 0x02;
    /// authenticatorGetInfo
    pub const GET_INFO: u8 = 0x04;
    /// authenticatorClientPIN (not supported in the MVP)
    pub const CLIENT_PIN: u8 = 0x06;
    /// authenticatorReset
    pub const RESET: u8 = 0x07;
}

/// How long `authenticatorReset` stays available after power-up (CTAP 2.0 §5.6).
pub const RESET_WINDOW_MS: u64 = 10_000;

/// Advertised `maxCredentialCountInList`.
pub const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 8;

/// A response buffer: status byte followed by optional CBOR.
pub type Response = [u8; MAX_MSG_SIZE];

/// What the caller must do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A complete response of this many bytes is in the output buffer.
    Response(usize),
    /// Wait for user presence, then call [`Authenticator::complete`].
    NeedsUserPresence,
}

/// Validated parameters of a command that is waiting for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pending {
    /// Nothing is waiting.
    Idle,
    /// makeCredential that will mint a new credential.
    MakeCredential {
        /// SHA-256 of the RP ID.
        rp_id_hash: [u8; 32],
        /// Hash of the WebAuthn client data.
        client_data_hash: [u8; 32],
    },
    /// getAssertion for an already-authenticated credential.
    GetAssertion {
        /// SHA-256 of the RP ID.
        rp_id_hash: [u8; 32],
        /// Hash of the WebAuthn client data.
        client_data_hash: [u8; 32],
        /// Credential ID exactly as presented (and verified).
        cred_id: [u8; CRED_ID_LEN],
        /// Nonce recovered from the credential ID.
        nonce: [u8; NONCE_LEN],
    },
    /// makeCredential hit the exclude list: after the touch, report `CREDENTIAL_EXCLUDED`.
    Excluded,
    /// Zero-length pinAuth ("which device?" probe): after the touch, report `PIN_NOT_SET`.
    PinProbe,
    /// authenticatorReset within the power-up window.
    Reset,
}

/// The authenticator state.
#[derive(Debug)]
pub struct Authenticator {
    pending: Pending,
    faulted: bool,
    aaguid: [u8; 16],
}

impl Authenticator {
    /// A fresh authenticator. Call only after the power-on self tests passed.
    #[must_use]
    pub const fn new(aaguid: [u8; 16]) -> Self {
        Self { pending: Pending::Idle, faulted: false, aaguid }
    }

    /// Enter the permanent fault state (invariant 7): every later command fails.
    pub fn fault(&mut self) {
        self.faulted = true;
        self.pending = Pending::Idle;
    }

    /// Whether the authenticator is in the fault state.
    #[must_use]
    pub const fn is_faulted(&self) -> bool {
        self.faulted
    }

    /// The command currently waiting for user presence.
    #[must_use]
    pub const fn pending(&self) -> &Pending {
        &self.pending
    }

    /// Drop any pending command (transport reset, channel resync, timeout).
    pub fn abort(&mut self) {
        self.pending = Pending::Idle;
    }

    /// Handle one CTAP2 request (`command byte ‖ CBOR parameters`).
    pub fn process<P: Platform>(&mut self, platform: &mut P, request: &[u8], out: &mut Response) -> Outcome {
        // A new request always supersedes a parked one.
        self.pending = Pending::Idle;
        if self.faulted {
            return Outcome::Response(write_status(out, Status::Other));
        }
        let Some((&cmd, params)) = request.split_first() else {
            return Outcome::Response(write_status(out, Status::InvalidLength));
        };
        let parked = match cmd {
            command::GET_INFO => {
                return Outcome::Response(if params.is_empty() {
                    get_info::run(&self.aaguid, out).unwrap_or_else(|s| write_status(out, s))
                } else {
                    write_status(out, Status::InvalidLength)
                });
            }
            command::MAKE_CREDENTIAL => make_credential::process(platform, params),
            command::GET_ASSERTION => get_assertion::process(platform, params),
            command::RESET => reset::process(platform, params),
            _ => Err(Status::InvalidCommand),
        };
        match parked {
            Ok(p) => {
                self.pending = p;
                Outcome::NeedsUserPresence
            }
            Err(s) => Outcome::Response(write_status(out, s)),
        }
    }

    /// Finish the pending command with the result of the presence check. Returns the
    /// response length. With nothing pending this answers `CTAP1_ERR_OTHER`.
    pub fn complete<P: Platform>(&mut self, platform: &mut P, presence: PresenceResult, out: &mut Response) -> usize {
        let pending = core::mem::replace(&mut self.pending, Pending::Idle);
        if self.faulted || pending == Pending::Idle {
            return write_status(out, Status::Other);
        }
        match presence {
            PresenceResult::Timeout => return write_status(out, Status::UserActionTimeout),
            PresenceResult::Cancelled => return write_status(out, Status::KeepaliveCancel),
            PresenceResult::Confirmed => {}
        }
        let result = match pending {
            Pending::Idle => Err(Status::Other),
            Pending::Excluded => Err(Status::CredentialExcluded),
            Pending::PinProbe => Err(Status::PinNotSet),
            Pending::Reset => reset::complete(platform, out),
            Pending::MakeCredential { rp_id_hash, client_data_hash } => {
                make_credential::complete(platform, &self.aaguid, &rp_id_hash, &client_data_hash, out)
            }
            Pending::GetAssertion { rp_id_hash, client_data_hash, cred_id, nonce } => {
                get_assertion::complete(platform, &rp_id_hash, &client_data_hash, &cred_id, &nonce, out)
            }
        };
        match result {
            Ok(n) => n,
            Err(s) => write_status(out, s),
        }
    }
}

/// Write a bare status byte and return the response length.
pub(crate) fn write_status(out: &mut Response, s: Status) -> usize {
    if let Some(b) = out.first_mut() {
        *b = s.code();
    }
    1
}

/// Write `Success` followed by CBOR produced by `f`; returns the response length.
pub(crate) fn write_success(
    out: &mut Response,
    f: impl FnOnce(&mut Encoder<'_>) -> Result<(), CborError>,
) -> Result<usize, Status> {
    let (status, body) = out.split_first_mut().ok_or(Status::Other)?;
    *status = Status::Success.code();
    let mut e = Encoder::new(body);
    f(&mut e).map_err(|_| Status::Other)?;
    e.len().checked_add(1).ok_or(Status::Other)
}

/// Derive a root secret for this operation; zeroized when dropped.
pub(crate) fn derive<P: Platform>(platform: &mut P, label: SecretLabel) -> Result<Zeroizing<[u8; 32]>, Status> {
    let mut k = Zeroizing::new([0u8; 32]);
    platform.derive_secret(label, &mut k).map_err(|_| Status::Other)?;
    Ok(k)
}

impl From<CborError> for Status {
    fn from(e: CborError) -> Self {
        match e {
            CborError::UnexpectedType | CborError::BadKeyType => Self::CborUnexpectedType,
            _ => Self::InvalidCbor,
        }
    }
}
