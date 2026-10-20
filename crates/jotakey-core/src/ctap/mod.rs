// (c) Javier Fernandez @ JotaSoft 2026
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

pub mod client_pin;
mod get_assertion;
mod get_info;
mod make_credential;
mod parse;
mod reset;

use zeroize::Zeroizing;

use crate::MAX_MSG_SIZE;
use crate::cbor::{CborError, Encoder};
use crate::credential::{self, CRED_ID_LEN, NONCE_LEN};
use crate::platform::{PinRecord, Platform, PresenceResult, SecretLabel};
use crate::status::Status;
pub use client_pin::PinSession;

/// CTAP2 command bytes.
pub mod command {
    /// authenticatorMakeCredential
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    /// authenticatorGetAssertion
    pub const GET_ASSERTION: u8 = 0x02;
    /// authenticatorGetInfo
    pub const GET_INFO: u8 = 0x04;
    /// authenticatorClientPIN
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
        /// A pinUvAuthToken authorized the request: sign with the UV flag.
        user_verified: bool,
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
        /// A pinUvAuthToken authorized the request: sign with the UV flag.
        user_verified: bool,
    },
    /// makeCredential hit the exclude list: after the touch, report `CREDENTIAL_EXCLUDED`.
    Excluded,
    /// Zero-length pinAuth ("which device?" probe): after the touch, report `PIN_INVALID` if
    /// a PIN is set and `PIN_NOT_SET` if not.
    PinProbe,
    /// authenticatorReset within the power-up window.
    Reset,
}

/// What validating a request leads to: a command parked for a touch, or a silent
/// getAssertion (`up: false`) to sign at once without the UP flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingOrSilent {
    /// Park and ask for user presence.
    Pending(Pending),
    /// Sign now, UP flag clear. Always a [`Pending::GetAssertion`].
    Silent(Pending),
}

/// The authenticator state.
#[derive(Debug)]
pub struct Authenticator {
    pending: Pending,
    faulted: bool,
    aaguid: [u8; 16],
    pin: PinSession,
}

impl Authenticator {
    /// A fresh authenticator. Call only after the power-on self tests passed.
    #[must_use]
    pub const fn new(aaguid: [u8; 16]) -> Self {
        Self { pending: Pending::Idle, faulted: false, aaguid, pin: PinSession::new() }
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

    /// The clientPIN state of this power cycle.
    #[must_use]
    pub const fn pin_session(&self) -> &PinSession {
        &self.pin
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
                if !params.is_empty() {
                    return Outcome::Response(write_status(out, Status::InvalidLength));
                }
                let result = platform
                    .load_pin()
                    .map_err(|_| Status::Other)
                    .and_then(|pin| get_info::run(&self.aaguid, pin.verifier.is_some(), out));
                return Outcome::Response(result.unwrap_or_else(|s| write_status(out, s)));
            }
            command::CLIENT_PIN => {
                let result = client_pin::process(platform, &mut self.pin, params, out);
                return Outcome::Response(result.unwrap_or_else(|s| write_status(out, s)));
            }
            command::MAKE_CREDENTIAL => make_credential::process(platform, &mut self.pin, params),
            command::GET_ASSERTION => match get_assertion::process(platform, &mut self.pin, params) {
                Ok(PendingOrSilent::Pending(p)) => Ok(p),
                Ok(PendingOrSilent::Silent(Pending::GetAssertion {
                    rp_id_hash,
                    client_data_hash,
                    cred_id,
                    nonce,
                    user_verified,
                })) => {
                    // A silent assertion: signed now, with the UP flag clear (invariant 1).
                    let flags = get_assertion::Flags { user_present: false, user_verified };
                    let result =
                        get_assertion::sign(platform, &rp_id_hash, &client_data_hash, &cred_id, &nonce, flags, out);
                    return Outcome::Response(result.unwrap_or_else(|s| write_status(out, s)));
                }
                Ok(PendingOrSilent::Silent(_)) => Err(Status::Other),
                Err(s) => Err(s),
            },
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
            Pending::PinProbe => match platform.load_pin() {
                Ok(PinRecord { verifier: Some(_), .. }) => Err(Status::PinInvalid),
                Ok(PinRecord { verifier: None, .. }) => Err(Status::PinNotSet),
                Err(_) => Err(Status::Other),
            },
            Pending::Reset => {
                // Every PIN state of this power cycle goes with the PIN itself.
                self.pin = PinSession::new();
                reset::complete(platform, out)
            }
            Pending::MakeCredential { rp_id_hash, client_data_hash, user_verified } => {
                if user_verified {
                    self.pin.spend_token();
                }
                make_credential::complete(platform, &self.aaguid, &rp_id_hash, &client_data_hash, user_verified, out)
            }
            Pending::GetAssertion { rp_id_hash, client_data_hash, cred_id, nonce, user_verified } => {
                if user_verified {
                    self.pin.spend_token();
                }
                let flags = get_assertion::Flags { user_present: true, user_verified };
                get_assertion::sign(platform, &rp_id_hash, &client_data_hash, &cred_id, &nonce, flags, out)
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

/// Credential tags from the platform's hardware key store (`AGENTS.md` §3).
pub(crate) struct PlatformTagger<'p, P: Platform>(pub(crate) &'p mut P);

impl<P: Platform> credential::Tagger for PlatformTagger<'_, P> {
    fn mac(&mut self, input: &[u8; credential::TAG_INPUT_LEN]) -> Result<[u8; 32], credential::TagError> {
        let mut t = [0u8; 32];
        self.0.derive_secret(SecretLabel::CredentialTag, input, &mut t).map_err(|_| credential::TagError)?;
        Ok(t)
    }
}

/// The private-key seed of the credential with `nonce` at `rp_id_hash`; zeroized when dropped.
pub(crate) fn credential_seed<P: Platform>(
    platform: &mut P,
    rp_id_hash: &[u8; 32],
    nonce: &[u8; credential::NONCE_LEN],
) -> Result<Zeroizing<[u8; 32]>, Status> {
    let mut context = [0u8; 32 + credential::NONCE_LEN];
    let (rp, n) = context.split_at_mut(32);
    rp.copy_from_slice(rp_id_hash);
    n.copy_from_slice(nonce);
    let mut k = Zeroizing::new([0u8; 32]);
    platform.derive_secret(SecretLabel::CredentialSeed, &context, &mut k).map_err(|_| Status::Other)?;
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
