// (c) Javier Fernandez @ JotaSoft 2026
//! Provisioning a jotakey key's OPTIGA, on the device, started by a human (AGENTS.md §3a).
//!
//! [`provision`] pairs the MCU with the OPTIGA and creates the secrets:
//!
//! 1. the **pairing secret** `P = SHA-512(OPTIGA TRNG(64) ‖ MCU RNG(64))`, which the MCU keeps
//!    in flash, and from it the **binding secret** (`0xE140`, keys the shielded connection)
//!    and the **freshness secret** (`0xF1D1`, the live-session check), each
//!    `HKDF-SHA256(P, label)` over 64 bytes. Both go to the OPTIGA unprotected: there is no
//!    shielded connection before them (as in Infineon's own pairing);
//! 2. `K_root = SHA-512(OPTIGA TRNG(64) ‖ MCU RNG(64))`, written to `0xF1D0` through the new
//!    live session, so it never crosses the bus in clear;
//! 3. the access conditions: `K_root` and the freshness secret are pre-shared secrets that
//!    can never be read or changed and are used only through the shielded connection; the
//!    binding secret can never be read or changed; the
//!    counter starts at 0 with threshold [`COUNTER_THRESHOLD`], counts only through the
//!    shielded connection and can never be rewritten;
//! 4. a check that the root derives.
//!
//! Every step is **reversible** while the objects' life cycle state is below operational:
//! the OPTIGA lets their metadata change, so provisioning can run again (it first opens the
//! change conditions it closed last time). What makes the conditions final is [`lock`], the
//! one irreversible step: it sets each object's life cycle to operational. A unit is only
//! secure once locked: before that, someone on the bus can open the conditions again, read
//! `K_root` and rewrite the counter. AGENTS.md §4: automation never runs [`lock`].

use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use super::apdu::{self, OID_BINDING, OID_COUNTER, OID_FRESHNESS, OID_ROOT, metadata};
use super::device::Optiga;
use super::shielded::SECRET_LEN;
use super::{I2c, OptigaError};

/// The counter's threshold: the OPTIGA's rated endurance (AGENTS.md §3). At the threshold it
/// freezes and the key refuses to sign.
pub const COUNTER_THRESHOLD: u32 = 600_000;
/// HKDF label of the binding secret.
pub const BINDING_LABEL: &[u8] = b"jotakey/optiga-binding/v1";
/// HKDF label of the freshness secret.
pub const FRESHNESS_SECRET_LABEL: &[u8] = b"jotakey/optiga-fresh/v1";
/// MCU random bytes [`provision`] needs: 64 for `P`, 64 for `K_root`, 32 for the nonce.
pub const MCU_RANDOM_LEN: usize = 160;

/// The pairing secret, kept in MCU flash. Zeroized on drop.
pub struct Pairing(Zeroizing<[u8; SECRET_LEN]>);

impl Pairing {
    /// From its stored bytes.
    #[must_use]
    pub fn from_bytes(b: &[u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(*b))
    }

    /// The bytes to store.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    fn expand(&self, label: &[u8]) -> Result<Zeroizing<[u8; SECRET_LEN]>, OptigaError> {
        let mut out = Zeroizing::new([0u8; SECRET_LEN]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, self.0.as_ref())
            .expand(label, out.as_mut())
            .map_err(|_| OptigaError::Length)?;
        Ok(out)
    }

    /// The binding secret (`0xE140`).
    ///
    /// # Errors
    /// Never in practice.
    pub fn binding(&self) -> Result<Zeroizing<[u8; SECRET_LEN]>, OptigaError> {
        self.expand(BINDING_LABEL)
    }

    /// The freshness secret (`0xF1D1`).
    ///
    /// # Errors
    /// Never in practice.
    pub fn freshness(&self) -> Result<Zeroizing<[u8; SECRET_LEN]>, OptigaError> {
        self.expand(FRESHNESS_SECRET_LABEL)
    }
}

/// `SHA-512(a ‖ b)`: both chips' randomness, so neither alone decides the secret.
fn mix(a: &[u8], b: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha512::new();
    h.update(a);
    h.update(b);
    Zeroizing::new(h.finalize().into())
}

/// Why provisioning stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionError {
    /// The OPTIGA is already locked: provisioning would change nothing (or break the key).
    AlreadyLocked,
    /// An OPTIGA operation failed.
    Optiga(OptigaError),
}

impl From<OptigaError> for ProvisionError {
    fn from(e: OptigaError) -> Self {
        Self::Optiga(e)
    }
}

/// The metadata that makes a pre-shared secret final: type PRESSEC, used only over the
/// shielded connection, never read, never changed.
#[rustfmt::skip]
const SECRET_METADATA: [u8; 14] = [
    metadata::DATA_TYPE, 1, metadata::TYPE_PRESSEC,
    metadata::EXECUTE, 3, metadata::CONF, 0xE1, 0x40,
    metadata::READ, 1, metadata::NEV,
    metadata::CHANGE, 1, metadata::NEV,
];

/// Open the change condition again (allowed while the life cycle is below operational).
const REOPEN: [u8; 3] = [metadata::CHANGE, 1, metadata::ALW];

/// The binding secret: never read, never changed (AGENTS.md §3).
const BINDING_METADATA: [u8; 6] = [metadata::READ, 1, metadata::NEV, metadata::CHANGE, 1, metadata::NEV];

/// The counter: counted only over the shielded connection, never rewritten.
const COUNTER_METADATA: [u8; 8] =
    [metadata::EXECUTE, 3, metadata::CONF, 0xE1, 0x40, metadata::CHANGE, 1, metadata::NEV];

/// Whether the metadata TLV (`0x20 len tags…`) says life cycle operational or later.
fn is_locked(md: &[u8]) -> Result<bool, OptigaError> {
    let (head, tags) = md.split_first_chunk::<2>().ok_or(OptigaError::Malformed)?;
    let [tag, len] = *head;
    if tag != 0x20 || usize::from(len) != tags.len() {
        return Err(OptigaError::Malformed);
    }
    let mut rest = tags;
    while let Some((&[t, l], after)) = rest.split_first_chunk::<2>() {
        let (value, next) = after.split_at_checked(usize::from(l)).ok_or(OptigaError::Malformed)?;
        if t == metadata::LCSO {
            return Ok(value.first().is_some_and(|&v| v >= metadata::LCS_OPERATIONAL));
        }
        rest = next;
    }
    if rest.is_empty() { Ok(false) } else { Err(OptigaError::Malformed) }
}

/// Provision a freshly reset OPTIGA. `mcu_random` must be fresh MCU RNG output. Returns the
/// pairing secret for the caller to store in flash (the key cannot reach its root without
/// it), **after** the OPTIGA holds everything, so that an interruption leaves a state from
/// which provisioning can simply run again.
///
/// # Errors
/// [`ProvisionError::AlreadyLocked`] if `K_root`'s object is already operational; any OPTIGA
/// error.
pub fn provision<B: I2c>(o: &mut Optiga<B>, mcu_random: &[u8; MCU_RANDOM_LEN]) -> Result<Pairing, ProvisionError> {
    let (p_mcu, rest) = mcu_random.split_at(64);
    let (root_mcu, nonce) = rest.split_at(64);
    let nonce: &[u8; 32] = nonce.try_into().map_err(|_| OptigaError::Length)?;

    o.open()?;
    let mut md = [0u8; 64];
    let n = o.command_plain(&apdu::get_data(OID_ROOT, true)?, &mut md)?;
    if is_locked(md.get(..n).ok_or(OptigaError::Malformed)?)? {
        return Err(ProvisionError::AlreadyLocked);
    }

    // 1. Pairing, unprotected.
    let mut r = Zeroizing::new([0u8; 64]);
    if o.command_plain(&apdu::get_random(64)?, r.as_mut())? != 64 {
        return Err(OptigaError::Malformed.into());
    }
    let pairing = Pairing(mix(r.as_ref(), p_mcu));
    let binding = pairing.binding()?;
    let freshness = pairing.freshness()?;
    let mut none = [0u8; 0];
    o.command_plain(&apdu::set_metadata(OID_BINDING, &REOPEN)?, &mut none)?;
    o.command_plain(&apdu::set_data(OID_BINDING, binding.as_ref())?, &mut none)?;
    o.command_plain(&apdu::set_metadata(OID_BINDING, &BINDING_METADATA)?, &mut none)?;
    o.command_plain(&apdu::set_metadata(OID_FRESHNESS, &REOPEN)?, &mut none)?;
    o.command_plain(&apdu::set_data(OID_FRESHNESS, freshness.as_ref())?, &mut none)?;
    o.command_plain(&apdu::set_metadata(OID_FRESHNESS, &SECRET_METADATA)?, &mut none)?;

    // 2. The live session, then K_root through it.
    o.establish(&binding, &freshness, nonce)?;
    o.random(r.as_mut())?;
    let root = mix(r.as_ref(), root_mcu);
    o.command(&apdu::set_metadata(OID_ROOT, &REOPEN)?, &mut none)?;
    o.command(&apdu::set_data(OID_ROOT, root.as_ref())?, &mut none)?;
    o.command(&apdu::set_metadata(OID_ROOT, &SECRET_METADATA)?, &mut none)?;

    // 3. The counter: 0, threshold 600 000.
    let mut counter = [0u8; 8];
    counter.get_mut(4..).ok_or(OptigaError::Length)?.copy_from_slice(&COUNTER_THRESHOLD.to_be_bytes());
    o.command(&apdu::set_metadata(OID_COUNTER, &REOPEN)?, &mut none)?;
    o.command(&apdu::set_data(OID_COUNTER, &counter)?, &mut none)?;
    o.command(&apdu::set_metadata(OID_COUNTER, &COUNTER_METADATA)?, &mut none)?;

    // 4. The root derives.
    let mut check = Zeroizing::new([0u8; 32]);
    o.derive(OID_ROOT, &[b"jotakey/provision-check/v1"], &mut check)?;
    Ok(pairing)
}

/// **IRREVERSIBLE.** Set the life cycle of `K_root`, the freshness secret, the counter and
/// the binding secret to operational, which freezes their access conditions for good.
/// Requires a live session. Run only by a human, on a unit that passed provisioning
/// (`provision-lock` firmware feature, AGENTS.md §4); never from automation.
///
/// # Errors
/// Any OPTIGA error (objects locked before the failure stay locked).
pub fn lock<B: I2c>(o: &mut Optiga<B>) -> Result<(), OptigaError> {
    let mut none = [0u8; 0];
    for oid in [OID_ROOT, OID_FRESHNESS, OID_COUNTER, OID_BINDING] {
        o.command(&apdu::set_metadata(oid, &[metadata::LCSO, 1, metadata::LCS_OPERATIONAL])?, &mut none)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls_prf_sha256;
    use crate::optiga::sim::{Ac, SimOptiga};

    fn mcu(seed: u8) -> [u8; MCU_RANDOM_LEN] {
        core::array::from_fn(|i| seed ^ u8::try_from(i % 251).unwrap())
    }

    #[test]
    fn provisioning_then_use() {
        let mut o = Optiga::new(SimOptiga::new(1));
        let pairing = provision(&mut o, &mcu(1)).unwrap();
        let sim = o.bus_mut();
        // The OPTIGA holds the derived secrets and the final conditions.
        assert_eq!(&sim.binding.data[..64], pairing.binding().unwrap().as_ref());
        assert_eq!(&sim.freshness.data[..64], pairing.freshness().unwrap().as_ref());
        for obj in [&sim.root, &sim.freshness] {
            assert!(obj.pressec);
            assert_eq!((obj.read, obj.change, obj.execute), (Ac::Never, Ac::Never, Ac::Shielded));
        }
        assert_eq!((sim.counter.change, sim.counter.execute), (Ac::Never, Ac::Shielded));
        assert_eq!(sim.counter_value(), 0);
        assert_eq!(&sim.counter.data[4..8], &COUNTER_THRESHOLD.to_be_bytes());
        // K_root mixes both chips' randomness and is not the pairing secret.
        let root: [u8; 64] = sim.root.data[..64].try_into().unwrap();
        assert_ne!(&root, pairing.as_bytes());
        assert_eq!((sim.binding.read, sim.binding.change), (Ac::Never, Ac::Never));
        // Only the pairing steps went unprotected: open, metadata read, random, and three
        // writes (reopen, data, final metadata) for each of the binding and freshness secrets.
        assert_eq!(sim.plain_commands, 9);

        // After a reset, the stored pairing secret is all the key needs.
        sim.reset();
        let stored = Pairing::from_bytes(pairing.as_bytes());
        o.open().unwrap();
        o.establish(&stored.binding().unwrap(), &stored.freshness().unwrap(), &[3; 32]).unwrap();
        let mut out = [0u8; 32];
        o.derive(OID_ROOT, &[b"x".as_slice(); 8], &mut out).unwrap();
        let mut want = [0u8; 32];
        tls_prf_sha256(&root, &[b"xxxxxxxx"], &mut want).unwrap();
        assert_eq!(out, want);
        assert_eq!(o.increment_counter(), Ok(1));
    }

    #[test]
    fn provisioning_can_run_again_until_locked() {
        let mut o = Optiga::new(SimOptiga::new(2));
        let first = provision(&mut o, &mcu(2)).unwrap();
        o.bus_mut().reset();
        let second = provision(&mut o, &mcu(3)).unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        // Lock (on the simulator only), then provisioning refuses.
        lock(&mut o).unwrap();
        assert!(o.bus_mut().root.lcs >= metadata::LCS_OPERATIONAL);
        o.bus_mut().reset();
        assert_eq!(provision(&mut o, &mcu(4)).err(), Some(ProvisionError::AlreadyLocked));
        // A locked unit still works with its pairing secret, and its conditions are frozen.
        o.bus_mut().reset();
        o.open().unwrap();
        o.establish(&second.binding().unwrap(), &second.freshness().unwrap(), &[1; 32]).unwrap();
        let mut none = [0u8; 0];
        assert_eq!(o.command(&apdu::set_metadata(OID_ROOT, &REOPEN).unwrap(), &mut none), Err(OptigaError::Status));
    }

    #[test]
    fn interrupted_provisioning_can_be_resumed() {
        // Interrupt at every exchange in turn: a reset, then provisioning again, succeeds.
        for cut in 1..40u32 {
            let mut o = Optiga::new(SimOptiga::new(5));
            o.bus_mut().cut_after = Some(cut);
            let _ = provision(&mut o, &mcu(5));
            o.bus_mut().cut_after = None;
            o.bus_mut().reset();
            let p = provision(&mut o, &mcu(6)).unwrap();
            o.bus_mut().reset();
            o.open().unwrap();
            o.establish(&p.binding().unwrap(), &p.freshness().unwrap(), &[9; 32]).unwrap();
        }
    }

    /// Known answers computed independently with Python's `cryptography` (HKDF-SHA256, no
    /// salt, 64 bytes) and `hashlib` (SHA-512).
    #[test]
    fn secrets_known_answers() {
        use hex_literal::hex;
        let p = Pairing::from_bytes(&[0x42; 64]);
        assert_eq!(
            p.binding().unwrap().as_ref(),
            &hex!(
                "b515ce382e7c80c370516073d40af0c466fb78fc040f18220bfa3208a2612558e79a34962f49cda671805742a91ff877425d99e2dcef2bdee7c7f13da7592923"
            )
        );
        assert_eq!(
            p.freshness().unwrap().as_ref(),
            &hex!(
                "44953296ce78053d992a7a84226887325b7fc4ccd8ea00fbd3e0e0c33850c1fe77e6d6c62f995453680aa3a2948ca69221e0ebcba510b2221582af4b3a5b52cc"
            )
        );
        assert_eq!(
            mix(&[1; 64], &[2; 64]).as_ref(),
            &hex!(
                "a9146d787915a360bf0bcf22b7117f6da14f2fe2f8d7fc70b820179a5653d706a08fa97ddae68d8ec9783534d35c0871f056e25433d27909d7147f6e7c217612"
            )
        );
    }

    #[test]
    fn locked_metadata_detection() {
        assert_eq!(is_locked(&[0x20, 3, 0xC0, 1, 0x07]), Ok(true));
        assert_eq!(is_locked(&[0x20, 3, 0xC0, 1, 0x0F]), Ok(true));
        assert_eq!(is_locked(&[0x20, 3, 0xC0, 1, 0x03]), Ok(false));
        assert_eq!(is_locked(&[0x20, 6, 0xD0, 1, 0xFF, 0xC0, 1, 0x07]), Ok(true));
        assert_eq!(is_locked(&[0x20, 3, 0xD0, 1, 0xFF]), Ok(false));
        assert_eq!(is_locked(&[0x20, 0]), Ok(false));
        assert!(is_locked(&[0x20, 4, 0xD0, 1, 0xFF]).is_err());
        assert!(is_locked(&[0x20, 2, 0xD0, 5]).is_err());
        assert!(is_locked(&[0x21, 0]).is_err());
        assert!(is_locked(&[0x20]).is_err());
        assert!(is_locked(&[0x20, 1, 0xD0]).is_err());
    }
}
