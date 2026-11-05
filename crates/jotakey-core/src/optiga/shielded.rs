// (c) Javier Fernandez @ JotaSoft 2026
//! The shielded connection: the IFX I2C presentation layer, protocol version 1 (pre-shared
//! secret, TLS PRF SHA256, AES-128-CCM-8), master side (IFX I2C protocol §6).
//!
//! **Handshake.** The master sends `Hello` (`SCTR 0x00 ‖ PVER`); the OPTIGA answers
//! `0x00 ‖ PVER ‖ RND[32] ‖ SSEQ[4]`. Both sides derive 40 bytes of session keys,
//! `PRF(binding secret, "Platform Binding" ‖ RND)`, laid out as
//! `MasterEncKey[16] ‖ MasterDecKey[16] ‖ MasterEncNonce[4] ‖ MasterDecNonce[4]`. The master
//! sends `Finished`: `0x08 ‖ SSEQ ‖ CCM(MasterEncKey, MasterEncNonce ‖ SSEQ, RND ‖ SSEQ)`, and
//! the OPTIGA answers `0x08 ‖ MSEQ ‖ CCM(its key, MasterDecNonce ‖ MSEQ, RND ‖ MSEQ)`, which
//! the master decrypts and checks. CCM's associated data is always
//! `SCTR ‖ SEQ[4] ‖ PVER ‖ plaintext length[2]` (big-endian).
//!
//! **Records.** With full protection (`SCTR 0x23`) the master sends `0x23 ‖ MSEQ ‖ CCM(APDU)`
//! with MSEQ one more than the last it used (the first is the Finished MSEQ + 1); the OPTIGA
//! answers `0x23 ‖ SSEQ ‖ CCM(APDU)`. The layout follows Infineon's host library.
//!
//! **Acceptance rule** ([`Session::accept`], modelled in `formal/Jotakey/Shielded.lean`): a
//! response is used only if
//!
//! 1. the session has passed the live-session check, unless the response *is* that check
//!    ([`Purpose::Freshness`]);
//! 2. its SCTR is `0x23` (an alert, or anything else, ends the session);
//! 3. its SSEQ is in the window `(last, last + 3]` (`TRANS_REPEAT`);
//! 4. its tag verifies;
//!
//! and only then does `last` become its SSEQ. Infineon's library moves the window before the
//! tag is checked, so a forged message can push it; here only an authentic one can. The
//! device layer drops the session after any failure, so in one session accepted SSEQs
//! strictly increase and each request gets exactly one accepted response.
//!
//! **Why the live-session check.** The handshake has no challenge from the master: the
//! OPTIGA alone picks `RND`, and the master's `Finished` is a function of `RND` and `SSEQ`.
//! Someone on the bus who recorded an old session can replay the OPTIGA's half of it, and
//! the master would accept the old session keys and then old responses, among them an old
//! (lower) counter value (Solution Reference Manual §6.6, "the shielded connection does not
//! provide an option to add random challenge/nonce from the host"). So right after the
//! handshake the master sends a fresh nonce through the session and checks the OPTIGA's
//! answer (`device::Optiga::establish`): an old recording cannot contain it.

use aes::Aes128;
use ccm::aead::AeadInOut;
use ccm::consts::U8;
use ccm::{Ccm, KeyInit};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::OptigaError;
use crate::crypto::tls_prf_sha256;

/// Protocol version 1: pre-shared secret.
pub const PVER: u8 = 0x01;
/// The PRF label of the session key derivation.
pub const LABEL: &[u8] = b"Platform Binding";
/// The platform binding secret's length.
pub const SECRET_LEN: usize = 64;
/// `RND`'s length.
pub const RND_LEN: usize = 32;
/// The CCM-8 tag length.
pub const TAG_LEN: usize = 8;
/// `SCTR ‖ SEQ`.
pub const RECORD_HEADER: usize = 5;
/// A protected record's bytes beyond its APDU.
pub const RECORD_OVERHEAD: usize = RECORD_HEADER + TAG_LEN;
/// The acceptance window above the last accepted SSEQ (`TRANS_REPEAT`).
pub const SEQ_WINDOW: u32 = 3;
/// Sequence numbers above this end the session (`PRL_SEQUENCE_THRESHOLD`); a new handshake
/// starts them afresh.
pub const SEQ_LIMIT: u32 = 0xFFFF_FFF0;

/// `Handshake.Hello`.
pub const SCTR_HELLO: u8 = 0x00;
/// `Handshake.Finished`.
pub const SCTR_FINISHED: u8 = 0x08;
/// `Record Exchange`, master and slave payloads protected.
pub const SCTR_RECORD: u8 = 0x23;

/// The OPTIGA's `Hello`: `SCTR ‖ PVER ‖ RND ‖ SSEQ`.
pub const SLAVE_HELLO_LEN: usize = 2 + RND_LEN + 4;
/// `Finished` in either direction: `SCTR ‖ SEQ ‖ CCM(RND ‖ SEQ)`.
pub const FINISHED_LEN: usize = RECORD_HEADER + RND_LEN + 4 + TAG_LEN;
const FINISHED_PLAIN: usize = RND_LEN + 4;

type Cipher = Ccm<Aes128, U8, U8>;

/// The 40 bytes of session keys and nonces. Zeroized on drop.
pub struct SessionKeys(Zeroizing<[u8; 40]>);

impl SessionKeys {
    /// `PRF(binding, "Platform Binding" ‖ rnd)[..40]`.
    ///
    /// # Errors
    /// Never in practice (the PRF output is short).
    pub fn derive(binding: &[u8; SECRET_LEN], rnd: &[u8; RND_LEN]) -> Result<Self, OptigaError> {
        let mut k = Zeroizing::new([0u8; 40]);
        tls_prf_sha256(binding, &[LABEL, rnd], k.as_mut()).map_err(|_| OptigaError::Integrity)?;
        Ok(Self(k))
    }

    fn part<const N: usize>(&self, at: usize) -> Result<[u8; N], OptigaError> {
        let end = at.checked_add(N).ok_or(OptigaError::Integrity)?;
        self.0.get(at..end).and_then(|s| s.try_into().ok()).ok_or(OptigaError::Integrity)
    }

    /// The key and nonce prefix the master encrypts with.
    fn encrypt(&self) -> Result<(Zeroizing<[u8; 16]>, [u8; 4]), OptigaError> {
        Ok((Zeroizing::new(self.part::<16>(0)?), self.part::<4>(32)?))
    }

    /// The key and nonce prefix the master decrypts with (the OPTIGA's encryption pair).
    fn decrypt(&self) -> Result<(Zeroizing<[u8; 16]>, [u8; 4]), OptigaError> {
        Ok((Zeroizing::new(self.part::<16>(16)?), self.part::<4>(36)?))
    }
}

/// `SCTR ‖ SEQ ‖ PVER ‖ length`.
fn associated_data(sctr: u8, seq: u32, len: usize) -> Result<[u8; 8], OptigaError> {
    let l = u16::try_from(len).map_err(|_| OptigaError::Length)?.to_be_bytes();
    let s = seq.to_be_bytes();
    Ok([sctr, s[0], s[1], s[2], s[3], PVER, l[0], l[1]])
}

fn nonce(prefix: [u8; 4], seq: u32) -> ccm::Nonce<U8> {
    let s = seq.to_be_bytes();
    ccm::Nonce::<U8>::from([prefix[0], prefix[1], prefix[2], prefix[3], s[0], s[1], s[2], s[3]])
}

/// Encrypt `buf` in place; return the tag.
fn seal(
    pair: (Zeroizing<[u8; 16]>, [u8; 4]),
    sctr: u8,
    seq: u32,
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], OptigaError> {
    let cipher = Cipher::new_from_slice(pair.0.as_ref()).map_err(|_| OptigaError::Integrity)?;
    let ad = associated_data(sctr, seq, buf.len())?;
    let tag =
        cipher.encrypt_inout_detached(&nonce(pair.1, seq), &ad, buf.into()).map_err(|_| OptigaError::Integrity)?;
    Ok(tag.into())
}

/// Decrypt `buf` in place if `tag` verifies; on failure `buf` is zeroed.
fn open(
    pair: (Zeroizing<[u8; 16]>, [u8; 4]),
    sctr: u8,
    seq: u32,
    buf: &mut [u8],
    tag: [u8; TAG_LEN],
) -> Result<(), OptigaError> {
    let cipher = Cipher::new_from_slice(pair.0.as_ref()).map_err(|_| OptigaError::Integrity)?;
    let ad = associated_data(sctr, seq, buf.len())?;
    let ok = cipher.decrypt_inout_detached(&nonce(pair.1, seq), &ad, (&mut *buf).into(), &tag.into()).is_ok();
    if ok {
        Ok(())
    } else {
        buf.fill(0);
        Err(OptigaError::Integrity)
    }
}

/// `Handshake.Hello` from the master.
#[must_use]
pub const fn master_hello() -> [u8; 2] {
    [SCTR_HELLO, PVER]
}

/// Whether `seq` may follow `last`: `last < seq ≤ last + SEQ_WINDOW`, and below
/// [`SEQ_LIMIT`]. The rule `formal/Jotakey/Shielded.lean` calls `inWindow`.
#[must_use]
pub fn in_window(last: u32, seq: u32) -> bool {
    seq > last && seq <= last.saturating_add(SEQ_WINDOW) && seq <= SEQ_LIMIT
}

/// A handshake between the OPTIGA's `Hello` and its `Finished`.
pub struct Handshake {
    keys: SessionKeys,
    rnd: [u8; RND_LEN],
    sseq: u32,
}

impl Handshake {
    /// Read the OPTIGA's `Hello` and derive the session keys.
    ///
    /// # Errors
    /// [`OptigaError::Integrity`] if the message is not a version-1 `Hello` (an alert, a
    /// wrong length or version), or SSEQ leaves no room below [`SEQ_LIMIT`].
    pub fn start(binding: &[u8; SECRET_LEN], slave_hello: &[u8]) -> Result<Self, OptigaError> {
        if slave_hello.len() != SLAVE_HELLO_LEN {
            return Err(OptigaError::Integrity);
        }
        let (head, rest) = slave_hello.split_at_checked(2).ok_or(OptigaError::Integrity)?;
        if head != [SCTR_HELLO, PVER] {
            return Err(OptigaError::Integrity);
        }
        let (rnd, sseq) = rest.split_at_checked(RND_LEN).ok_or(OptigaError::Integrity)?;
        let rnd: [u8; RND_LEN] = rnd.try_into().map_err(|_| OptigaError::Integrity)?;
        let sseq = u32::from_be_bytes(sseq.try_into().map_err(|_| OptigaError::Integrity)?);
        if sseq >= SEQ_LIMIT {
            return Err(OptigaError::Integrity);
        }
        let keys = SessionKeys::derive(binding, &rnd)?;
        Ok(Self { keys, rnd, sseq })
    }

    /// The master's `Finished`.
    ///
    /// # Errors
    /// Never in practice.
    pub fn master_finished(&self) -> Result<[u8; FINISHED_LEN], OptigaError> {
        let mut out = [0u8; FINISHED_LEN];
        let s = self.sseq.to_be_bytes();
        let mut plain = [0u8; FINISHED_PLAIN];
        plain.get_mut(..RND_LEN).ok_or(OptigaError::Integrity)?.copy_from_slice(&self.rnd);
        plain.get_mut(RND_LEN..).ok_or(OptigaError::Integrity)?.copy_from_slice(&s);
        let tag = seal(self.keys.encrypt()?, SCTR_FINISHED, self.sseq, &mut plain)?;
        out[0] = SCTR_FINISHED;
        out.get_mut(1..RECORD_HEADER).ok_or(OptigaError::Integrity)?.copy_from_slice(&s);
        let ct_end = RECORD_HEADER + FINISHED_PLAIN;
        out.get_mut(RECORD_HEADER..ct_end).ok_or(OptigaError::Integrity)?.copy_from_slice(&plain);
        out.get_mut(ct_end..).ok_or(OptigaError::Integrity)?.copy_from_slice(&tag);
        Ok(out)
    }

    /// Check the OPTIGA's `Finished` and open the session. The session is not yet live
    /// ([`Session::is_fresh`] is false).
    ///
    /// # Errors
    /// [`OptigaError::Integrity`] unless it is a `Finished` whose tag verifies and whose
    /// plaintext is `RND ‖ MSEQ`.
    pub fn finish(self, slave_finished: &[u8]) -> Result<Session, OptigaError> {
        if slave_finished.len() != FINISHED_LEN || slave_finished.first() != Some(&SCTR_FINISHED) {
            return Err(OptigaError::Integrity);
        }
        let seq_bytes: [u8; 4] =
            slave_finished.get(1..RECORD_HEADER).and_then(|s| s.try_into().ok()).ok_or(OptigaError::Integrity)?;
        let mseq = u32::from_be_bytes(seq_bytes);
        let ct_end = RECORD_HEADER + FINISHED_PLAIN;
        let mut plain: [u8; FINISHED_PLAIN] =
            slave_finished.get(RECORD_HEADER..ct_end).and_then(|s| s.try_into().ok()).ok_or(OptigaError::Integrity)?;
        let tag: [u8; TAG_LEN] =
            slave_finished.get(ct_end..).and_then(|s| s.try_into().ok()).ok_or(OptigaError::Integrity)?;
        open(self.keys.decrypt()?, SCTR_FINISHED, mseq, &mut plain, tag)?;
        let (rnd, echoed) = plain.split_at(RND_LEN);
        let ok = rnd.ct_eq(&self.rnd) & echoed.ct_eq(&seq_bytes);
        if !bool::from(ok) || mseq >= SEQ_LIMIT {
            return Err(OptigaError::Integrity);
        }
        Ok(Session { keys: self.keys, mseq, last_sseq: self.sseq, fresh: false })
    }
}

/// What a response is accepted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// The answer to the live-session check: allowed before the session is live.
    Freshness,
    /// Anything else: only in a live session.
    Use,
}

/// An established shielded session.
pub struct Session {
    keys: SessionKeys,
    /// The last MSEQ used (the Finished MSEQ before the first record).
    mseq: u32,
    /// The last SSEQ accepted (the Hello SSEQ before the first record).
    last_sseq: u32,
    /// The live-session check passed.
    fresh: bool,
}

impl Session {
    /// Whether the live-session check has passed.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// Record that the live-session check passed (`device::Optiga::establish` only).
    pub fn mark_fresh(&mut self) {
        self.fresh = true;
    }

    /// The last SSEQ accepted.
    #[must_use]
    pub fn last_sseq(&self) -> u32 {
        self.last_sseq
    }

    /// Protect `apdu` into `out` (`0x23 ‖ MSEQ ‖ ciphertext ‖ tag`); return the length.
    ///
    /// # Errors
    /// [`OptigaError::Exhausted`] when MSEQ would pass [`SEQ_LIMIT`];
    /// [`OptigaError::Length`] if `out` is too short.
    pub fn protect(&mut self, apdu: &[u8], out: &mut [u8]) -> Result<usize, OptigaError> {
        let mseq = self.mseq.checked_add(1).filter(|&m| m <= SEQ_LIMIT).ok_or(OptigaError::Exhausted)?;
        let ct_end = apdu.len().checked_add(RECORD_HEADER).ok_or(OptigaError::Length)?;
        let total = ct_end.checked_add(TAG_LEN).ok_or(OptigaError::Length)?;
        let ct = out.get_mut(RECORD_HEADER..ct_end).ok_or(OptigaError::Length)?;
        ct.copy_from_slice(apdu);
        let tag = seal(self.keys.encrypt()?, SCTR_RECORD, mseq, ct)?;
        out.get_mut(ct_end..total).ok_or(OptigaError::Length)?.copy_from_slice(&tag);
        out.get_mut(1..RECORD_HEADER).ok_or(OptigaError::Length)?.copy_from_slice(&mseq.to_be_bytes());
        *out.first_mut().ok_or(OptigaError::Length)? = SCTR_RECORD;
        self.mseq = mseq;
        Ok(total)
    }

    /// Authenticate and decrypt a response in place; return the APDU inside it.
    ///
    /// # Errors
    /// [`OptigaError::NotFresh`] for [`Purpose::Use`] before the live-session check;
    /// [`OptigaError::Integrity`] for an alert or any other SCTR, a short message, an SSEQ
    /// outside the window, or a tag that does not verify. `last_sseq` changes only on success.
    pub fn accept<'a>(&mut self, msg: &'a mut [u8], purpose: Purpose) -> Result<&'a [u8], OptigaError> {
        if purpose == Purpose::Use && !self.fresh {
            return Err(OptigaError::NotFresh);
        }
        if msg.len() <= RECORD_OVERHEAD || msg.first() != Some(&SCTR_RECORD) {
            return Err(OptigaError::Integrity);
        }
        let seq_bytes: [u8; 4] =
            msg.get(1..RECORD_HEADER).and_then(|s| s.try_into().ok()).ok_or(OptigaError::Integrity)?;
        let sseq = u32::from_be_bytes(seq_bytes);
        if !in_window(self.last_sseq, sseq) {
            return Err(OptigaError::Integrity);
        }
        let ct_end = msg.len().checked_sub(TAG_LEN).ok_or(OptigaError::Integrity)?;
        let (body, tag) = msg.split_at_mut(ct_end);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().map_err(|_| OptigaError::Integrity)?;
        let ct = body.get_mut(RECORD_HEADER..).ok_or(OptigaError::Integrity)?;
        open(self.keys.decrypt()?, SCTR_RECORD, sseq, ct, tag)?;
        self.last_sseq = sseq;
        Ok(ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The OPTIGA's side of a session, written independently of the master code above from
    /// the protocol specification's figures 6-2 to 6-5: it encrypts with the master's
    /// decryption pair and decrypts with its encryption pair.
    pub(crate) fn slave_seal(keys: &[u8; 40], sctr: u8, seq: u32, plain: &[u8]) -> std::vec::Vec<u8> {
        let cipher = Cipher::new_from_slice(&keys[16..32]).unwrap();
        let mut n = [0u8; 8];
        n[..4].copy_from_slice(&keys[36..40]);
        n[4..].copy_from_slice(&seq.to_be_bytes());
        let mut ad = std::vec![sctr];
        ad.extend_from_slice(&seq.to_be_bytes());
        ad.push(PVER);
        ad.extend_from_slice(&u16::try_from(plain.len()).unwrap().to_be_bytes());
        let mut buf = plain.to_vec();
        let tag = cipher.encrypt_inout_detached(&ccm::Nonce::<U8>::from(n), &ad, buf.as_mut_slice().into()).unwrap();
        let mut out = std::vec![sctr];
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        out
    }

    fn keys_of(binding: &[u8; 64], rnd: &[u8; 32]) -> [u8; 40] {
        let mut k = [0u8; 40];
        tls_prf_sha256(binding, &[b"Platform Binding", rnd], &mut k).unwrap();
        k
    }

    fn hello(rnd: &[u8; 32], sseq: u32) -> std::vec::Vec<u8> {
        let mut v = std::vec![0x00, 0x01];
        v.extend_from_slice(rnd);
        v.extend_from_slice(&sseq.to_be_bytes());
        v
    }

    fn established(binding: &[u8; 64], rnd: &[u8; 32], sseq: u32, mseq: u32) -> Session {
        let hs = Handshake::start(binding, &hello(rnd, sseq)).unwrap();
        let mut plain = rnd.to_vec();
        plain.extend_from_slice(&mseq.to_be_bytes());
        hs.finish(&slave_seal(&keys_of(binding, rnd), SCTR_FINISHED, mseq, &plain)).unwrap()
    }

    /// AES-128-CCM with an 8-byte tag and an 8-byte nonce, checked against Python's
    /// `cryptography` (`AESCCM(key, tag_length=8).encrypt(nonce, data, aad)`) for
    /// key 00..0f, nonce 10..17, aad 20..27, plaintext 30..3f.
    #[test]
    fn ccm8_known_answer() {
        let key: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let n: [u8; 8] = core::array::from_fn(|i| 0x10 + u8::try_from(i).unwrap());
        let ad: [u8; 8] = core::array::from_fn(|i| 0x20 + u8::try_from(i).unwrap());
        let mut buf: [u8; 16] = core::array::from_fn(|i| 0x30 + u8::try_from(i).unwrap());
        let cipher = Cipher::new_from_slice(&key).unwrap();
        let tag = cipher.encrypt_inout_detached(&ccm::Nonce::<U8>::from(n), &ad, buf.as_mut_slice().into()).unwrap();
        let mut got = buf.to_vec();
        got.extend_from_slice(&tag);
        assert_eq!(got, hex_literal::hex!("205554588121a2be73bbd2105353210c1efce347239ac046"));
    }

    #[test]
    fn handshake_and_records() {
        let binding = [7u8; 64];
        let rnd = [9u8; 32];
        let keys = keys_of(&binding, &rnd);
        let hs = Handshake::start(&binding, &hello(&rnd, 100)).unwrap();
        // The master's Finished decrypts, with the master's encryption pair, to RND ‖ SSEQ.
        let fin = hs.master_finished().unwrap();
        assert_eq!(fin[0], SCTR_FINISHED);
        assert_eq!(&fin[1..5], &100u32.to_be_bytes());
        {
            let cipher = Cipher::new_from_slice(&keys[0..16]).unwrap();
            let mut n = [0u8; 8];
            n[..4].copy_from_slice(&keys[32..36]);
            n[4..].copy_from_slice(&100u32.to_be_bytes());
            let ad = [0x08, 0, 0, 0, 100, 0x01, 0x00, 0x24];
            let mut ct = fin[5..41].to_vec();
            let tag: [u8; 8] = fin[41..].try_into().unwrap();
            cipher
                .decrypt_inout_detached(&ccm::Nonce::<U8>::from(n), &ad, ct.as_mut_slice().into(), &tag.into())
                .unwrap();
            assert_eq!(&ct[..32], &rnd);
            assert_eq!(&ct[32..], &100u32.to_be_bytes());
        }
        let mut s = established(&binding, &rnd, 100, 500);
        assert!(!s.is_fresh());
        // Master records start at MSEQ + 1.
        let mut out = [0u8; 64];
        let n = s.protect(&[0x81, 0x00, 0x00, 0x02, 0xE1, 0x20], &mut out).unwrap();
        assert_eq!(n, 6 + RECORD_OVERHEAD);
        assert_eq!(&out[..5], &[0x23, 0, 0, 0x01, 0xF5]);
        // A response: usable for the freshness check before the session is live, then only
        // after it.
        let mut r = slave_seal(&keys, SCTR_RECORD, 101, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(s.accept(&mut r.clone(), Purpose::Use), Err(OptigaError::NotFresh));
        assert_eq!(s.accept(&mut r, Purpose::Freshness).unwrap(), &[0, 0, 0, 0]);
        assert_eq!(s.last_sseq(), 101);
        s.mark_fresh();
        let mut r = slave_seal(&keys, SCTR_RECORD, 104, &[0x00, 0x00, 0x00, 0x01, 0x55]);
        assert_eq!(s.accept(&mut r, Purpose::Use).unwrap(), &[0, 0, 0, 1, 0x55]);
        assert_eq!(s.last_sseq(), 104);
    }

    #[test]
    fn replays_forgeries_and_alerts_are_refused() {
        let binding = [1u8; 64];
        let rnd = [2u8; 32];
        let keys = keys_of(&binding, &rnd);
        let mut s = established(&binding, &rnd, 10, 20);
        s.mark_fresh();
        let first = slave_seal(&keys, SCTR_RECORD, 11, &[0, 0, 0, 0]);
        assert!(s.accept(&mut first.clone(), Purpose::Use).is_ok());
        // The same response again.
        assert_eq!(s.accept(&mut first.clone(), Purpose::Use), Err(OptigaError::Integrity));
        // Too far ahead.
        let far = slave_seal(&keys, SCTR_RECORD, 15, &[0, 0, 0, 0]);
        assert_eq!(s.accept(&mut far.clone(), Purpose::Use), Err(OptigaError::Integrity));
        // A forged tag inside the window does not move it.
        let mut forged = slave_seal(&keys, SCTR_RECORD, 14, &[0, 0, 0, 0]);
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(s.accept(&mut forged, Purpose::Use), Err(OptigaError::Integrity));
        assert_eq!(s.last_sseq(), 11);
        let next = slave_seal(&keys, SCTR_RECORD, 12, &[0, 0, 0, 0]);
        assert!(s.accept(&mut next.clone(), Purpose::Use).is_ok());
        // A response from another session (other RND) does not verify.
        let other = slave_seal(&keys_of(&binding, &[3u8; 32]), SCTR_RECORD, 13, &[0, 0, 0, 0]);
        assert_eq!(s.accept(&mut other.clone(), Purpose::Use), Err(OptigaError::Integrity));
        // Alerts, other SCTRs, and short messages.
        assert_eq!(s.accept(&mut [0x40], Purpose::Use), Err(OptigaError::Integrity));
        assert_eq!(s.accept(&mut [0x44], Purpose::Use), Err(OptigaError::Integrity));
        let mut wrong = slave_seal(&keys, 0x22, 13, &[0, 0, 0, 0]);
        assert_eq!(s.accept(&mut wrong, Purpose::Use), Err(OptigaError::Integrity));
        let mut empty = slave_seal(&keys, SCTR_RECORD, 13, &[]);
        assert_eq!(s.accept(&mut empty, Purpose::Use), Err(OptigaError::Integrity));
        // The plaintext of a message that failed is not left behind.
        let mut tampered = slave_seal(&keys, SCTR_RECORD, 13, &[0xAA; 8]);
        tampered[6] ^= 0x80;
        assert!(s.accept(&mut tampered, Purpose::Use).is_err());
        assert_eq!(s.last_sseq(), 12);
    }

    #[test]
    fn handshake_refusals() {
        let binding = [1u8; 64];
        let rnd = [2u8; 32];
        assert!(Handshake::start(&binding, &hello(&rnd, 0)).is_ok());
        let mut h = hello(&rnd, 0);
        h[1] = 0x02;
        assert!(Handshake::start(&binding, &h).is_err(), "version 2");
        assert!(Handshake::start(&binding, &[0x40]).is_err(), "alert");
        assert!(Handshake::start(&binding, &hello(&rnd, 0)[..37]).is_err(), "short");
        assert!(Handshake::start(&binding, &hello(&rnd, SEQ_LIMIT)).is_err(), "no room");
        let keys = keys_of(&binding, &rnd);
        let finish = |plain: &[u8], seq: u32, k: &[u8; 40]| {
            Handshake::start(&binding, &hello(&rnd, 5)).unwrap().finish(&slave_seal(k, SCTR_FINISHED, seq, plain))
        };
        let mut good = rnd.to_vec();
        good.extend_from_slice(&9u32.to_be_bytes());
        assert!(finish(&good, 9, &keys).is_ok());
        assert!(finish(&good, 10, &keys).is_err(), "MSEQ outside disagrees with MSEQ inside");
        let mut bad_rnd = good.clone();
        bad_rnd[0] ^= 1;
        assert!(finish(&bad_rnd, 9, &keys).is_err(), "wrong RND");
        assert!(finish(&good, 9, &keys_of(&[0u8; 64], &rnd)).is_err(), "wrong binding secret");
        let mut limit = rnd.to_vec();
        limit.extend_from_slice(&SEQ_LIMIT.to_be_bytes());
        assert!(finish(&limit, SEQ_LIMIT, &keys).is_err(), "no room for records");
        let hs = Handshake::start(&binding, &hello(&rnd, 5)).unwrap();
        let mut f = slave_seal(&keys, SCTR_FINISHED, 9, &good);
        f[0] = 0x00;
        assert!(hs.finish(&f).is_err(), "wrong SCTR");
    }

    #[test]
    fn sequence_numbers_run_out() {
        let binding = [1u8; 64];
        let rnd = [2u8; 32];
        let mut s = established(&binding, &rnd, 0, SEQ_LIMIT - 1);
        let mut out = [0u8; 32];
        assert!(s.protect(&[1], &mut out).is_ok());
        assert_eq!(s.protect(&[1], &mut out), Err(OptigaError::Exhausted));
        assert_eq!(s.protect(&[1; 32], &mut out), Err(OptigaError::Exhausted));
        let mut s = established(&binding, &rnd, 0, 0);
        assert_eq!(s.protect(&[1; 32], &mut out), Err(OptigaError::Length));
    }

    #[test]
    fn window_edges() {
        assert!(!in_window(10, 10));
        assert!(in_window(10, 11));
        assert!(in_window(10, 13));
        assert!(!in_window(10, 14));
        assert!(!in_window(10, 9));
        assert!(in_window(SEQ_LIMIT - 1, SEQ_LIMIT));
        assert!(!in_window(SEQ_LIMIT, SEQ_LIMIT + 1));
        assert!(!in_window(u32::MAX - 1, u32::MAX));
    }

    proptest! {
        /// Accepted SSEQs strictly increase, and never by more than the window.
        #[test]
        fn accepted_sequence_numbers_increase(seqs in proptest::collection::vec(0u32..40, 0..60)) {
            let binding = [5u8; 64];
            let rnd = [6u8; 32];
            let keys = keys_of(&binding, &rnd);
            let mut s = established(&binding, &rnd, 3, 0);
            s.mark_fresh();
            let mut last = 3u32;
            for q in seqs {
                let mut m = slave_seal(&keys, SCTR_RECORD, q, &[0, 0, 0, 0]);
                match s.accept(&mut m, Purpose::Use) {
                    Ok(_) => {
                        prop_assert!(q > last && q <= last + SEQ_WINDOW);
                        last = q;
                    }
                    Err(_) => prop_assert!(!(q > last && q <= last + SEQ_WINDOW)),
                }
                prop_assert_eq!(s.last_sseq(), last);
            }
        }

        #[test]
        fn accept_is_total(mut bytes in proptest::collection::vec(any::<u8>(), 0..80), fresh in any::<bool>()) {
            let binding = [5u8; 64];
            let rnd = [6u8; 32];
            let mut s = established(&binding, &rnd, 3, 0);
            if fresh { s.mark_fresh(); }
            let _ = s.accept(&mut bytes, Purpose::Use);
            prop_assert_eq!(s.last_sseq(), 3, "random bytes never authenticate");
        }

        #[test]
        fn handshake_parsers_are_total(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            let binding = [5u8; 64];
            let _ = Handshake::start(&binding, &bytes);
            let hs = Handshake::start(&binding, &hello(&[6u8; 32], 3)).unwrap();
            prop_assert!(hs.finish(&bytes).is_err());
        }
    }
}
