// (c) Javier Fernandez @ JotaSoft 2026
//! CTAP status codes (CTAP 2.0 §6.3) used by this authenticator.

/// A CTAP status code. `Success` is the only non-error value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Status {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    UnsupportedOption = 0x2B,
    InvalidOption = 0x2C,
    KeepaliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinAuthInvalid = 0x33,
    PinNotSet = 0x35,
    RequestTooLarge = 0x39,
    Other = 0x7F,
}

impl Status {
    /// The wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}
