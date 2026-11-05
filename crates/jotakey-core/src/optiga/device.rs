// (c) Javier Fernandez @ JotaSoft 2026
//! The OPTIGA as the key's platform sees it: open, establish a live shielded session, then
//! derive secrets from `K_root`, advance and read the counter, draw random bytes.
//!
//! Every operation that returns something the key relies on goes through
//! [`Optiga::command`], which protects the command, accepts the response only under the
//! rule of [`shielded::Session::accept`] *in a live session*, and drops the session on any
//! failure. A dropped session is re-established by the caller (`Optiga::establish`), which
//! runs the handshake and then the live-session check again.
//!
//! **Counter.** [`Optiga::increment_counter`] counts the OPTIGA's monotonic counter up by one
//! and then reads it back through the session. The value it returns is persisted in the
//! OPTIGA before the caller sees it (invariant 2), and it is refused unless it exceeds every
//! value returned before it since power-up: `formal/Jotakey/Shielded.lean` proves that the
//! values released strictly increase.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::apdu::{self, Apdu, OID_COUNTER, OID_FRESHNESS};
use super::frame::FRAME_SIZE;
use super::link::{self, Link, PCTR_PRESENTATION};
use super::shielded::{self, Handshake, Purpose, SECRET_LEN, Session};
use super::{I2c, OptigaError, physical};
use crate::crypto::tls_prf_sha256;

/// The derivation label of the live-session check.
pub const FRESHNESS_LABEL: &[u8] = b"jotakey/fresh/v1";
/// The live-session check's nonce length.
pub const NONCE_LEN: usize = 32;

/// The OPTIGA behind its bus.
pub struct Optiga<B: I2c> {
    bus: B,
    link: Link,
    /// The presentation layer has been switched on since the last reset: from then on every
    /// packet must carry it (IFX I2C protocol §6).
    presentation: bool,
    session: Option<Session>,
    /// The highest counter value released since power-up.
    last_counter: Option<u32>,
}

impl<B: I2c> Optiga<B> {
    /// Wrap the bus. Nothing is sent yet.
    pub fn new(bus: B) -> Self {
        Self { bus, link: Link::new(FRAME_SIZE), presentation: false, session: None, last_counter: None }
    }

    /// The bus (to reset the OPTIGA through its reset line, or in tests).
    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }

    /// Whether a live session is established.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.session.as_ref().is_some_and(Session::is_fresh)
    }

    /// Start talking to a freshly reset OPTIGA: agree on the frame size and open the
    /// authentication application (unprotected: the OPTIGA has not enabled its presentation
    /// layer yet). The caller resets the OPTIGA first (its reset line), which also resets its
    /// frame counters to where [`Link::new`] starts ours; like Infineon's host library, the
    /// driver sends no resync frame then.
    ///
    /// # Errors
    /// Any bus, link or status error.
    pub fn open(&mut self) -> Result<(), OptigaError> {
        self.session = None;
        self.presentation = false;
        let frame_size = physical::negotiate_frame_size(&mut self.bus)?;
        self.link = Link::new(frame_size);
        let mut out = [0u8; 0];
        let n = self.command_plain(&apdu::open_application()?, &mut out)?;
        if n != 0 {
            return Err(OptigaError::Malformed);
        }
        Ok(())
    }

    /// Send one packet and return the body of the answer, checking its presentation flag.
    fn exchange<'a>(
        &mut self,
        presentation: bool,
        body: &[u8],
        resp: &'a mut [u8; FRAME_SIZE],
    ) -> Result<&'a mut [u8], OptigaError> {
        let mut packet = [0u8; FRAME_SIZE];
        let end = body.len().checked_add(1).ok_or(OptigaError::Length)?;
        packet.get_mut(1..end).ok_or(OptigaError::Length)?.copy_from_slice(body);
        packet[0] = if presentation { PCTR_PRESENTATION } else { 0 };
        let n = self.link.transceive(&mut self.bus, packet.get(..end).ok_or(OptigaError::Length)?, resp)?;
        let got = resp.get_mut(..n).ok_or(OptigaError::Malformed)?;
        let (flag, _) = link::split_packet(got)?;
        if flag != presentation {
            return Err(OptigaError::Malformed);
        }
        got.get_mut(1..).ok_or(OptigaError::Malformed)
    }

    /// Run a command without protection: only before the presentation layer is on
    /// (opening the application; pairing at provisioning). Copies the response data into
    /// `out` and returns its length.
    ///
    /// # Errors
    /// [`OptigaError::Integrity`] once the presentation layer is on; any bus, link or status
    /// error; [`OptigaError::Length`] if the data does not fit `out`.
    pub fn command_plain(&mut self, cmd: &Apdu, out: &mut [u8]) -> Result<usize, OptigaError> {
        if self.presentation {
            return Err(OptigaError::Integrity);
        }
        let mut resp = [0u8; FRAME_SIZE];
        let body = self.exchange(false, cmd.as_bytes(), &mut resp)?;
        let data = apdu::parse_response(body)?;
        out.get_mut(..data.len()).ok_or(OptigaError::Length)?.copy_from_slice(data);
        Ok(data.len())
    }

    /// Run the handshake with `binding`, then the live-session check: derive
    /// `PRF(freshness secret, FRESHNESS_LABEL ‖ nonce)` in the OPTIGA through the new session
    /// and compare it with the same value computed here. `nonce` must be fresh random bytes
    /// from the MCU. Only then is the session live.
    ///
    /// # Errors
    /// [`OptigaError::Integrity`] if the handshake fails; [`OptigaError::NotFresh`] if the
    /// check's answer is wrong; any bus, link or status error. The session is dropped.
    pub fn establish(
        &mut self,
        binding: &[u8; SECRET_LEN],
        freshness: &[u8; SECRET_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), OptigaError> {
        self.session = None;
        let result = self.handshake_and_check(binding, freshness, nonce);
        if result.is_err() {
            self.session = None;
        }
        result
    }

    fn handshake_and_check(
        &mut self,
        binding: &[u8; SECRET_LEN],
        freshness: &[u8; SECRET_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), OptigaError> {
        self.presentation = true;
        let mut resp = [0u8; FRAME_SIZE];
        let hello = self.exchange(true, &shielded::master_hello(), &mut resp)?;
        let hs = Handshake::start(binding, hello)?;
        let fin = hs.master_finished()?;
        let slave_fin = self.exchange(true, &fin, &mut resp)?;
        self.session = Some(hs.finish(slave_fin)?);

        let mut expected = Zeroizing::new([0u8; 32]);
        tls_prf_sha256(freshness, &[FRESHNESS_LABEL, nonce], expected.as_mut()).map_err(|_| OptigaError::NotFresh)?;
        let mut got = Zeroizing::new([0u8; 32]);
        let cmd = apdu::derive_key(OID_FRESHNESS, &[FRESHNESS_LABEL, nonce], 32)?;
        let n = self.protected(&cmd, got.as_mut(), Purpose::Freshness)?;
        if n != 32 || !bool::from(got.ct_eq(expected.as_ref())) {
            return Err(OptigaError::NotFresh);
        }
        self.session.as_mut().ok_or(OptigaError::NoSession)?.mark_fresh();
        Ok(())
    }

    fn protected(&mut self, cmd: &Apdu, out: &mut [u8], purpose: Purpose) -> Result<usize, OptigaError> {
        let result = self.protected_inner(cmd, out, purpose);
        if result.is_err() {
            // Any failure ends the session: a lost, forged or refused message leaves the two
            // sides' sequence numbers in doubt, and a new handshake settles them.
            self.session = None;
        }
        result
    }

    fn protected_inner(&mut self, cmd: &Apdu, out: &mut [u8], purpose: Purpose) -> Result<usize, OptigaError> {
        let mut record = [0u8; FRAME_SIZE];
        let session = self.session.as_mut().ok_or(OptigaError::NoSession)?;
        if purpose == Purpose::Use && !session.is_fresh() {
            return Err(OptigaError::NotFresh);
        }
        let n = session.protect(cmd.as_bytes(), &mut record)?;
        let mut resp = Zeroizing::new([0u8; FRAME_SIZE]);
        let body = self.exchange(true, record.get(..n).ok_or(OptigaError::Length)?, &mut resp)?;
        let session = self.session.as_mut().ok_or(OptigaError::NoSession)?;
        let plain = session.accept(body, purpose)?;
        let data = apdu::parse_response(plain)?;
        out.get_mut(..data.len()).ok_or(OptigaError::Length)?.copy_from_slice(data);
        Ok(data.len())
    }

    /// Run a command through the live session; copy the response data into `out` and
    /// return its length.
    ///
    /// # Errors
    /// [`OptigaError::NoSession`] or [`OptigaError::NotFresh`] without a live session; any
    /// error of the exchange (the session is then dropped).
    pub fn command(&mut self, cmd: &Apdu, out: &mut [u8]) -> Result<usize, OptigaError> {
        self.protected(cmd, out, Purpose::Use)
    }

    /// `out = F(K_root-like secret in oid, parts…)`: the OPTIGA's TLS PRF over the
    /// concatenated derivation data, 32 bytes.
    ///
    /// # Errors
    /// As [`Optiga::command`]; [`OptigaError::Malformed`] unless exactly 32 bytes come back.
    pub fn derive(&mut self, oid: u16, parts: &[&[u8]], out: &mut [u8; 32]) -> Result<(), OptigaError> {
        let cmd = apdu::derive_key(oid, parts, 32)?;
        let mut buf = Zeroizing::new([0u8; 32]);
        let n = self.command(&cmd, buf.as_mut())?;
        if n != 32 {
            out.fill(0);
            return Err(OptigaError::Malformed);
        }
        out.copy_from_slice(buf.as_ref());
        Ok(())
    }

    /// Fill `out` (8–256 bytes) from the OPTIGA's TRNG through the live session.
    ///
    /// # Errors
    /// As [`Optiga::command`]; [`OptigaError::Malformed`] if the length is wrong.
    pub fn random(&mut self, out: &mut [u8]) -> Result<(), OptigaError> {
        let cmd = apdu::get_random(out.len())?;
        let n = self.command(&cmd, out)?;
        if n != out.len() {
            out.fill(0);
            return Err(OptigaError::Malformed);
        }
        Ok(())
    }

    /// Count the signature counter up by one and return its new value, which the OPTIGA has
    /// stored before this returns. Refused unless it exceeds every value this function
    /// returned since power-up.
    ///
    /// # Errors
    /// As [`Optiga::command`] (an exhausted counter answers with an error status);
    /// [`OptigaError::Malformed`] for a counter object of the wrong size;
    /// [`OptigaError::CounterNotIncreasing`] as above.
    pub fn increment_counter(&mut self) -> Result<u32, OptigaError> {
        let mut none = [0u8; 0];
        if self.command(&apdu::count(OID_COUNTER, 1)?, &mut none)? != 0 {
            return Err(OptigaError::Malformed);
        }
        let mut obj = [0u8; 8];
        if self.command(&apdu::get_data(OID_COUNTER, false)?, &mut obj)? != 8 {
            return Err(OptigaError::Malformed);
        }
        let value = u32::from_be_bytes([obj[0], obj[1], obj[2], obj[3]]);
        let (released, ok) = release_counter(self.last_counter, value);
        self.last_counter = released;
        if ok { Ok(value) } else { Err(OptigaError::CounterNotIncreasing) }
    }

    /// The highest counter value released since power-up.
    #[must_use]
    pub fn last_counter(&self) -> Option<u32> {
        self.last_counter
    }
}

/// The counter release rule (`formal/Jotakey/Shielded.lean`, `release`): a value read back
/// is released only if it exceeds the last one released; returns the new high-water mark
/// and whether `value` is released.
#[must_use]
pub fn release_counter(last: Option<u32>, value: u32) -> (Option<u32>, bool) {
    match last {
        Some(l) if value <= l => (Some(l), false),
        _ => (Some(value), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_release_rule() {
        assert_eq!(release_counter(None, 0), (Some(0), true));
        assert_eq!(release_counter(Some(5), 6), (Some(6), true));
        assert_eq!(release_counter(Some(5), 5), (Some(5), false));
        assert_eq!(release_counter(Some(5), 4), (Some(5), false));
        assert_eq!(release_counter(Some(u32::MAX - 1), u32::MAX), (Some(u32::MAX), true));
    }
    // End-to-end tests against the simulated OPTIGA are in `sim::tests`.
}
