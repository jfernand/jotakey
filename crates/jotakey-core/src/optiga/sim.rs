// (c) Javier Fernandez @ JotaSoft 2026
//! A software OPTIGA Trust M for tests and fuzzing: the slave side of every layer the driver
//! speaks, behind the [`I2c`] trait. **Never in firmware** (`mock` feature).
//!
//! It implements what the driver uses and what provisioning sets up: the registers, the data
//! link (one frame window, retransmission of its last data frame on a repeated frame or a
//! NAK), the presentation layer version 1 (slave side, written from the protocol
//! specification), `OpenApplication`, `GetDataObject`, `SetDataObject` (data, metadata,
//! count), `GetRandom` and `DeriveKey` (TLS PRF SHA256). Access conditions are modelled for
//! the objects the key uses (`0xE120`, `0xE140`, `0xF1D0`, `0xF1D1`): `ALW`, `NEV` and
//! `Conf(0xE140)`, and life cycle `op` freezing the metadata. Its random numbers are a hash
//! chain, so every run is reproducible.
//!
//! Fault switches make it NACK, damage or drop frames, so the tests can drive the driver's
//! error paths. It is test code: it indexes and does arithmetic directly (the panics it could
//! raise would be bugs in the simulator, found by the tests and the fuzzer that use it).
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects, missing_docs)]

use aes::Aes128;
use ccm::aead::AeadInOut;
use ccm::consts::U8;
use ccm::{Ccm, KeyInit};

use super::apdu::{OID_BINDING, OID_COUNTER, OID_FRESHNESS, OID_ROOT, metadata};
use super::frame::{self, Ack, FRAME_SIZE, Frame};
use super::link::PCTR_PRESENTATION;
use super::physical::{REG_DATA, REG_DATA_REG_LEN, REG_I2C_STATE};
use super::shielded::{LABEL, PVER, SCTR_FINISHED, SCTR_HELLO, SCTR_RECORD, SEQ_WINDOW};
use super::{BusError, I2c};
use crate::crypto::{sha256, tls_prf_sha256};

type Cipher = Ccm<Aes128, U8, U8>;

/// An access condition, as far as the simulator models them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ac {
    Always,
    Never,
    /// Only over the shielded connection.
    Shielded,
}

/// One modelled data object.
#[derive(Clone, Debug)]
pub struct Object {
    pub data: [u8; 140],
    pub used: usize,
    pub lcs: u8,
    pub change: Ac,
    pub read: Ac,
    pub execute: Ac,
    pub pressec: bool,
}

impl Object {
    fn new(change: Ac, read: Ac, execute: Ac, lcs: u8) -> Self {
        Self { data: [0; 140], used: 0, lcs, change, read, execute, pressec: false }
    }
    fn bytes(&self) -> &[u8] {
        &self.data[..self.used]
    }
}

const LCS_CREATION: u8 = 0x01;
const LCS_INITIALIZATION: u8 = 0x03;
const STATUS_ERROR: u8 = 0xFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handshake {
    None,
    HelloSent,
    Established,
}

/// The simulated OPTIGA.
#[derive(Clone)]
pub struct SimOptiga {
    // Physical layer.
    read_reg: u8,
    data_reg_len: u16,
    queue: [([u8; FRAME_SIZE], usize); 2],
    queued: usize,
    // Data link.
    tx: u8,
    rx: u8,
    last_data: ([u8; FRAME_SIZE], usize),
    // Presentation layer.
    presentation: bool,
    hs: Handshake,
    rnd: [u8; 32],
    keys: [u8; 40],
    sseq: u32,
    master_last: u32,
    // Application.
    app_open: bool,
    pub counter: Object,
    pub binding: Object,
    pub root: Object,
    pub freshness: Object,
    rng: [u8; 32],
    rng_ctr: u64,
    // Statistics and fault switches.
    /// `DeriveKey` operations on a persistent secret (security events).
    pub derivations: u32,
    /// Unprotected commands executed.
    pub plain_commands: u32,
    /// The next this many transactions are not acknowledged.
    pub nacks: u32,
    /// Flip a bit in the next frame sent.
    pub corrupt_next: bool,
    /// Lose the next frame sent.
    pub drop_next: bool,
    /// Never answer.
    pub silent: bool,
    /// Stop answering after this many accepted data frames (a power cut, as the master sees it).
    pub cut_after: Option<u32>,
    exchanges: u32,
}

impl SimOptiga {
    /// A chip as delivered: binding secret writable, counter in initialization, arbitrary
    /// data objects in creation with `ALW` conditions.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        let mut counter = Object::new(Ac::Always, Ac::Always, Ac::Always, LCS_INITIALIZATION);
        counter.used = 8;
        counter.data[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        Self {
            read_reg: 0,
            data_reg_len: 0x40,
            queue: [([0; FRAME_SIZE], 0), ([0; FRAME_SIZE], 0)],
            queued: 0,
            tx: 3,
            rx: 3,
            last_data: ([0; FRAME_SIZE], 0),
            presentation: false,
            hs: Handshake::None,
            rnd: [0; 32],
            keys: [0; 40],
            sseq: 0,
            master_last: 0,
            app_open: false,
            counter,
            binding: Object::new(Ac::Always, Ac::Always, Ac::Always, LCS_CREATION),
            root: Object::new(Ac::Always, Ac::Always, Ac::Always, LCS_CREATION),
            freshness: Object::new(Ac::Always, Ac::Always, Ac::Always, LCS_CREATION),
            rng: sha256(&[b"jotakey sim", &[seed]]),
            rng_ctr: 0,
            derivations: 0,
            plain_commands: 0,
            nacks: 0,
            corrupt_next: false,
            drop_next: false,
            silent: false,
            cut_after: None,
            exchanges: 0,
        }
    }

    /// A chip as provisioning leaves it (`optiga::provision`), set up directly.
    #[must_use]
    pub fn provisioned(seed: u8, binding: &[u8; 64], freshness: &[u8; 64], root: &[u8; 64]) -> Self {
        let mut s = Self::new(seed);
        s.binding.data[..64].copy_from_slice(binding);
        s.binding.used = 64;
        s.binding.read = Ac::Never;
        s.binding.change = Ac::Never;
        for (obj, v) in [(&mut s.root, root), (&mut s.freshness, freshness)] {
            obj.data[..64].copy_from_slice(v);
            obj.used = 64;
            obj.pressec = true;
            obj.read = Ac::Never;
            obj.change = Ac::Never;
            obj.execute = Ac::Shielded;
        }
        s.counter.data[..8].copy_from_slice(&[0, 0, 0, 0, 0, 0x09, 0x27, 0xC0]);
        s.counter.execute = Ac::Shielded;
        s.counter.change = Ac::Never;
        s
    }

    /// The reset line: everything volatile is lost.
    pub fn reset(&mut self) {
        self.queued = 0;
        self.tx = 3;
        self.rx = 3;
        self.last_data.1 = 0;
        self.presentation = false;
        self.hs = Handshake::None;
        self.app_open = false;
        self.data_reg_len = 0x40;
    }

    fn cut(&self) -> bool {
        self.cut_after.is_some_and(|c| self.exchanges >= c)
    }

    /// The counter's value.
    #[must_use]
    pub fn counter_value(&self) -> u32 {
        u32::from_be_bytes(self.counter.data[..4].try_into().unwrap_or([0; 4]))
    }

    fn random(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            self.rng_ctr += 1;
            let b = sha256(&[&self.rng, &self.rng_ctr.to_le_bytes()]);
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }

    fn enqueue(&mut self, f: &[u8]) {
        if self.drop_next {
            self.drop_next = false;
            return;
        }
        if self.queued >= self.queue.len() {
            return;
        }
        let slot = &mut self.queue[self.queued];
        slot.0[..f.len()].copy_from_slice(f);
        if self.corrupt_next {
            self.corrupt_next = false;
            slot.0[f.len() - 1] ^= 0x01;
        }
        slot.1 = f.len();
        self.queued += 1;
    }

    fn dequeue(&mut self, buf: &mut [u8]) {
        if self.queued == 0 {
            buf.fill(0xFF);
            return;
        }
        let (f, n) = self.queue[0];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = if i < n { f[i] } else { 0xFF };
        }
        self.queue[0] = self.queue[1];
        self.queued -= 1;
    }

    fn on_frame(&mut self, bytes: &[u8]) {
        match frame::decode(bytes) {
            Err(_) => {
                let nak = frame::encode_control((self.rx + 1) & 3, Ack::Nak);
                self.enqueue(&nak);
            }
            Ok(Frame::Resync) => {
                self.tx = 3;
                self.rx = 3;
                self.queued = 0;
                self.last_data.1 = 0;
            }
            Ok(Frame::Control { ack_number, ack }) => {
                if ack_number == self.tx {
                    match ack {
                        Ack::Ack => self.last_data.1 = 0,
                        Ack::Nak => self.resend(),
                    }
                }
            }
            Ok(Frame::Data { number, packet, .. }) => {
                if number == ((self.rx + 1) & 3) {
                    self.rx = number;
                    self.exchanges += 1;
                    let mut resp = [0u8; FRAME_SIZE];
                    let n = self.on_packet(packet, &mut resp);
                    if n == 0 {
                        return;
                    }
                    self.tx = (self.tx + 1) & 3;
                    let mut out = [0u8; FRAME_SIZE];
                    if let Ok(len) = frame::encode_data(self.tx, self.rx, &resp[..n], &mut out) {
                        self.last_data.0 = out;
                        self.last_data.1 = len;
                        self.enqueue(&out[..len]);
                    }
                } else if number == self.rx {
                    // The master did not get our answer and sent its frame again.
                    self.resend();
                }
            }
        }
    }

    fn resend(&mut self) {
        let (f, n) = self.last_data;
        if n > 0 {
            self.enqueue(&f[..n]);
        }
    }

    /// Answer one packet; returns the answer's length (0: no answer).
    fn on_packet(&mut self, packet: &[u8], out: &mut [u8; FRAME_SIZE]) -> usize {
        let pctr = packet[0];
        let body = &packet[1..];
        if pctr & !PCTR_PRESENTATION != 0 {
            return 0;
        }
        if pctr & PCTR_PRESENTATION == 0 {
            if self.presentation {
                return 0;
            }
            self.plain_commands += 1;
            out[0] = 0;
            let n = self.on_apdu(body, false, &mut out[1..]);
            return n + 1;
        }
        self.presentation = true;
        out[0] = PCTR_PRESENTATION;
        let n = self.on_secure(body, &mut out[1..]);
        if n == 0 { 0 } else { n + 1 }
    }

    fn alert(out: &mut [u8], code: u8) -> usize {
        out[0] = code;
        1
    }

    fn on_secure(&mut self, msg: &[u8], out: &mut [u8]) -> usize {
        let Some(&sctr) = msg.first() else { return 0 };
        match sctr {
            SCTR_HELLO => {
                if msg.len() != 2 || msg[1] & PVER == 0 || self.binding.used != 64 {
                    self.hs = Handshake::None;
                    return Self::alert(out, 0x40);
                }
                let mut rnd = [0u8; 32];
                self.random(&mut rnd);
                let mut s = [0u8; 4];
                self.random(&mut s);
                self.rnd = rnd;
                self.sseq = u32::from_be_bytes(s) & 0xFFFF;
                let binding: [u8; 64] = self.binding.data[..64].try_into().unwrap_or([0; 64]);
                let _ = tls_prf_sha256(&binding, &[LABEL, &rnd], &mut self.keys);
                self.hs = Handshake::HelloSent;
                out[0] = SCTR_HELLO;
                out[1] = PVER;
                out[2..34].copy_from_slice(&rnd);
                out[34..38].copy_from_slice(&self.sseq.to_be_bytes());
                38
            }
            SCTR_FINISHED => {
                if self.hs != Handshake::HelloSent || msg.len() != 49 {
                    self.hs = Handshake::None;
                    return Self::alert(out, 0x40);
                }
                let seq = u32::from_be_bytes(msg[1..5].try_into().unwrap_or([0; 4]));
                let mut plain = [0u8; 36];
                plain.copy_from_slice(&msg[5..41]);
                let tag: [u8; 8] = msg[41..49].try_into().unwrap_or([0; 8]);
                let ok = seq == self.sseq
                    && self.open_from_master(SCTR_FINISHED, seq, &mut plain, tag)
                    && plain[..32] == self.rnd
                    && plain[32..] == seq.to_be_bytes();
                if !ok {
                    self.hs = Handshake::None;
                    return Self::alert(out, 0x40);
                }
                let mut m = [0u8; 4];
                self.random(&mut m);
                let mseq = u32::from_be_bytes(m) & 0xFFFF;
                self.master_last = mseq;
                let mut p = [0u8; 36];
                p[..32].copy_from_slice(&self.rnd);
                p[32..].copy_from_slice(&mseq.to_be_bytes());
                let tag = self.seal_to_master(SCTR_FINISHED, mseq, &mut p);
                out[0] = SCTR_FINISHED;
                out[1..5].copy_from_slice(&mseq.to_be_bytes());
                out[5..41].copy_from_slice(&p);
                out[41..49].copy_from_slice(&tag);
                self.hs = Handshake::Established;
                49
            }
            SCTR_RECORD => {
                if self.hs != Handshake::Established || msg.len() <= 13 {
                    return Self::alert(out, 0x40);
                }
                let mseq = u32::from_be_bytes(msg[1..5].try_into().unwrap_or([0; 4]));
                let ct_end = msg.len() - 8;
                let mut apdu = [0u8; FRAME_SIZE];
                let alen = ct_end - 5;
                apdu[..alen].copy_from_slice(&msg[5..ct_end]);
                let tag: [u8; 8] = msg[ct_end..].try_into().unwrap_or([0; 8]);
                let in_window = mseq > self.master_last && mseq <= self.master_last.saturating_add(SEQ_WINDOW);
                if !in_window || !self.open_from_master(SCTR_RECORD, mseq, &mut apdu[..alen], tag) {
                    return Self::alert(out, 0x44);
                }
                self.master_last = mseq;
                let mut resp = [0u8; FRAME_SIZE];
                let rlen = self.on_apdu(&apdu[..alen], true, &mut resp);
                self.sseq += 1;
                let seq = self.sseq;
                let tag = self.seal_to_master(SCTR_RECORD, seq, &mut resp[..rlen]);
                out[0] = SCTR_RECORD;
                out[1..5].copy_from_slice(&seq.to_be_bytes());
                out[5..5 + rlen].copy_from_slice(&resp[..rlen]);
                out[5 + rlen..13 + rlen].copy_from_slice(&tag);
                13 + rlen
            }
            _ => Self::alert(out, 0x40),
        }
    }

    fn ad(sctr: u8, seq: u32, len: usize) -> [u8; 8] {
        let s = seq.to_be_bytes();
        let l = u16::try_from(len).unwrap_or(0).to_be_bytes();
        [sctr, s[0], s[1], s[2], s[3], PVER, l[0], l[1]]
    }

    fn nonce(prefix: &[u8], seq: u32) -> ccm::Nonce<U8> {
        let mut n = [0u8; 8];
        n[..4].copy_from_slice(prefix);
        n[4..].copy_from_slice(&seq.to_be_bytes());
        ccm::Nonce::<U8>::from(n)
    }

    /// Decrypt with the master's encryption pair.
    fn open_from_master(&self, sctr: u8, seq: u32, buf: &mut [u8], tag: [u8; 8]) -> bool {
        let Ok(c) = Cipher::new_from_slice(&self.keys[..16]) else { return false };
        c.decrypt_inout_detached(
            &Self::nonce(&self.keys[32..36], seq),
            &Self::ad(sctr, seq, buf.len()),
            buf.into(),
            &tag.into(),
        )
        .is_ok()
    }

    /// Encrypt with the master's decryption pair.
    fn seal_to_master(&self, sctr: u8, seq: u32, buf: &mut [u8]) -> [u8; 8] {
        seal_with(&self.keys, sctr, seq, buf)
    }

    fn object(&mut self, oid: u16) -> Option<&mut Object> {
        match oid {
            OID_COUNTER => Some(&mut self.counter),
            OID_BINDING => Some(&mut self.binding),
            OID_ROOT => Some(&mut self.root),
            OID_FRESHNESS => Some(&mut self.freshness),
            _ => None,
        }
    }

    fn allowed(ac: Ac, shielded: bool) -> bool {
        match ac {
            Ac::Always => true,
            Ac::Never => false,
            Ac::Shielded => shielded,
        }
    }

    fn ok(out: &mut [u8], data: &[u8]) -> usize {
        out[0] = 0;
        out[1] = 0;
        out[2..4].copy_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        out[4..4 + data.len()].copy_from_slice(data);
        4 + data.len()
    }

    fn error(out: &mut [u8]) -> usize {
        out[..4].copy_from_slice(&[STATUS_ERROR, 0, 0, 0]);
        4
    }

    fn on_apdu(&mut self, apdu: &[u8], shielded: bool, out: &mut [u8]) -> usize {
        if apdu.len() < 4 {
            return Self::error(out);
        }
        let (cmd, param) = (apdu[0] & 0x7F, apdu[1]);
        let len = usize::from(u16::from_be_bytes([apdu[2], apdu[3]]));
        if len != apdu.len() - 4 {
            return Self::error(out);
        }
        let data = &apdu[4..];
        if cmd == 0x70 {
            if data == super::apdu::APPLICATION_ID {
                self.app_open = true;
                return Self::ok(out, &[]);
            }
            return Self::error(out);
        }
        if !self.app_open {
            return Self::error(out);
        }
        match cmd {
            0x01 => self.get_data_object(param, data, shielded, out),
            0x02 => self.set_data_object(param, data, shielded, out),
            0x0C => {
                if param != 0 || data.len() != 2 {
                    return Self::error(out);
                }
                let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
                if !(8..=256).contains(&n) {
                    return Self::error(out);
                }
                let mut r = [0u8; 256];
                self.random(&mut r[..n]);
                Self::ok(out, &r[..n])
            }
            0x34 => self.derive_key(param, data, shielded, out),
            _ => Self::error(out),
        }
    }

    fn get_data_object(&mut self, param: u8, data: &[u8], shielded: bool, out: &mut [u8]) -> usize {
        if data.len() != 2 {
            return Self::error(out);
        }
        let oid = u16::from_be_bytes([data[0], data[1]]);
        let Some(obj) = self.object(oid) else { return Self::error(out) };
        let obj = obj.clone();
        match param {
            0x00 if Self::allowed(obj.read, shielded)
                && !(oid == OID_BINDING && obj.lcs >= metadata::LCS_OPERATIONAL) =>
            {
                Self::ok(out, obj.bytes())
            }
            0x01 => {
                let ac = |a: Ac| match a {
                    Ac::Always => [1u8, metadata::ALW, 0, 0],
                    Ac::Never => [1, metadata::NEV, 0, 0],
                    Ac::Shielded => [3, metadata::CONF, 0xE1, 0x40],
                };
                let mut md = [0u8; 40];
                let mut n = 2;
                md[n..n + 3].copy_from_slice(&[metadata::LCSO, 1, obj.lcs]);
                n += 3;
                for (tag, a) in
                    [(metadata::CHANGE, obj.change), (metadata::READ, obj.read), (metadata::EXECUTE, obj.execute)]
                {
                    let enc = ac(a);
                    let l = usize::from(enc[0]);
                    md[n] = tag;
                    md[n + 1..n + 2 + l].copy_from_slice(&enc[..1 + l]);
                    n += 2 + l;
                }
                if obj.pressec {
                    md[n..n + 3].copy_from_slice(&[metadata::DATA_TYPE, 1, metadata::TYPE_PRESSEC]);
                    n += 3;
                }
                md[0] = 0x20;
                md[1] = u8::try_from(n - 2).unwrap_or(0);
                Self::ok(out, &md[..n])
            }
            _ => Self::error(out),
        }
    }

    fn set_data_object(&mut self, param: u8, data: &[u8], shielded: bool, out: &mut [u8]) -> usize {
        if data.len() < 4 || data[2..4] != [0, 0] {
            return Self::error(out);
        }
        let oid = u16::from_be_bytes([data[0], data[1]]);
        let value = &data[4..];
        let Some(obj) = self.object(oid) else { return Self::error(out) };
        match param {
            0x00 | 0x40 => {
                // The binding secret's default change condition is "LcsO < op || Conf(E140)".
                let may = if oid == OID_BINDING {
                    match obj.change {
                        Ac::Never => false,
                        Ac::Shielded => shielded,
                        Ac::Always => obj.lcs < metadata::LCS_OPERATIONAL || shielded,
                    }
                } else {
                    Self::allowed(obj.change, shielded)
                        || (oid == OID_COUNTER && obj.lcs < metadata::LCS_OPERATIONAL && obj.change != Ac::Never)
                };
                let fits = if oid == OID_COUNTER {
                    value.len() == 8
                } else {
                    value.len() <= obj.data.len() && !value.is_empty()
                };
                if !may || !fits {
                    return Self::error(out);
                }
                obj.data[..value.len()].copy_from_slice(value);
                obj.used = value.len();
                Self::ok(out, &[])
            }
            0x01 => {
                if obj.lcs >= metadata::LCS_OPERATIONAL
                    || value.len() < 2
                    || value[0] != 0x20
                    || usize::from(value[1]) != value.len() - 2
                {
                    return Self::error(out);
                }
                let mut new = obj.clone();
                let mut i = 2;
                while i < value.len() {
                    if i + 2 > value.len() {
                        return Self::error(out);
                    }
                    let (tag, l) = (value[i], usize::from(value[i + 1]));
                    if i + 2 + l > value.len() {
                        return Self::error(out);
                    }
                    let v = &value[i + 2..i + 2 + l];
                    let ac = match v {
                        [metadata::ALW] => Some(Ac::Always),
                        [metadata::NEV] => Some(Ac::Never),
                        [metadata::CONF, 0xE1, 0x40] => Some(Ac::Shielded),
                        _ => None,
                    };
                    match (tag, ac) {
                        (metadata::LCSO, _) if l == 1 && v[0] >= new.lcs => new.lcs = v[0],
                        (metadata::CHANGE, Some(a)) => new.change = a,
                        (metadata::READ, Some(a)) => new.read = a,
                        (metadata::EXECUTE, Some(a)) => new.execute = a,
                        (metadata::DATA_TYPE, _) if v == [metadata::TYPE_PRESSEC] => new.pressec = true,
                        _ => return Self::error(out),
                    }
                    i += 2 + l;
                }
                *obj = new;
                Self::ok(out, &[])
            }
            0x02 => {
                if oid != OID_COUNTER || value.len() != 1 || value[0] == 0 || !Self::allowed(obj.execute, shielded) {
                    return Self::error(out);
                }
                let v = u32::from_be_bytes(obj.data[..4].try_into().unwrap_or([0; 4]));
                let t = u32::from_be_bytes(obj.data[4..8].try_into().unwrap_or([0; 4]));
                if v >= t {
                    return Self::error(out);
                }
                let nv = v.saturating_add(u32::from(value[0])).min(t);
                obj.data[..4].copy_from_slice(&nv.to_be_bytes());
                Self::ok(out, &[])
            }
            _ => Self::error(out),
        }
    }

    fn derive_key(&mut self, param: u8, data: &[u8], shielded: bool, out: &mut [u8]) -> usize {
        if param != 0x01 {
            return Self::error(out);
        }
        let (mut oid, mut olen, mut ddata, mut export) = (None, None, None, false);
        let mut i = 0;
        while i < data.len() {
            if i + 3 > data.len() {
                return Self::error(out);
            }
            let tag = data[i];
            let l = usize::from(u16::from_be_bytes([data[i + 1], data[i + 2]]));
            if i + 3 + l > data.len() {
                return Self::error(out);
            }
            let v = &data[i + 3..i + 3 + l];
            match (tag, l) {
                (0x01, 2) => oid = Some(u16::from_be_bytes([v[0], v[1]])),
                (0x03, 2) => olen = Some(usize::from(u16::from_be_bytes([v[0], v[1]]))),
                (0x02, 8..=1024) => ddata = Some(v),
                (0x07, 0) => export = true,
                _ => return Self::error(out),
            }
            i += 3 + l;
        }
        let (Some(oid), Some(olen), Some(ddata), true) = (oid, olen, ddata, export) else { return Self::error(out) };
        if !(16..=256).contains(&olen) {
            return Self::error(out);
        }
        let Some(obj) = self.object(oid) else { return Self::error(out) };
        if !obj.pressec || obj.used == 0 || obj.used > 64 || !Self::allowed(obj.execute, shielded) {
            return Self::error(out);
        }
        let secret = obj.bytes().to_vec_array();
        let mut r = [0u8; 256];
        if tls_prf_sha256(&secret.0[..secret.1], &[ddata], &mut r[..olen]).is_err() {
            return Self::error(out);
        }
        self.derivations += 1;
        Self::ok(out, &r[..olen])
    }
}

/// Encrypt `buf` in place as the OPTIGA does (with the master's decryption pair of the 40
/// session key bytes `keys`); return the tag.
fn seal_with(keys: &[u8; 40], sctr: u8, seq: u32, buf: &mut [u8]) -> [u8; 8] {
    let Ok(c) = Cipher::new_from_slice(&keys[16..32]) else { return [0; 8] };
    c.encrypt_inout_detached(&SimOptiga::nonce(&keys[36..40], seq), &SimOptiga::ad(sctr, seq, buf.len()), buf.into())
        .map(Into::into)
        .unwrap_or([0; 8])
}

/// The OPTIGA's half of a session with sequence numbers chosen by a test
/// (`tests/differential.rs`).
pub struct SlaveSession {
    keys: [u8; 40],
    rnd: [u8; 32],
}

impl SlaveSession {
    /// Session keys for `binding` and `rnd`.
    #[must_use]
    pub fn new(binding: &[u8; 64], rnd: [u8; 32]) -> Self {
        let mut keys = [0u8; 40];
        let _ = tls_prf_sha256(binding, &[LABEL, &rnd], &mut keys);
        Self { keys, rnd }
    }

    /// The OPTIGA's `Hello` with SSEQ `sseq`.
    #[must_use]
    pub fn hello(&self, sseq: u32) -> [u8; 38] {
        let mut h = [0u8; 38];
        h[0] = SCTR_HELLO;
        h[1] = PVER;
        h[2..34].copy_from_slice(&self.rnd);
        h[34..].copy_from_slice(&sseq.to_be_bytes());
        h
    }

    /// The OPTIGA's `Finished` with MSEQ `mseq`.
    #[must_use]
    pub fn finished(&self, mseq: u32) -> [u8; 49] {
        let mut p = [0u8; 36];
        p[..32].copy_from_slice(&self.rnd);
        p[32..].copy_from_slice(&mseq.to_be_bytes());
        let tag = seal_with(&self.keys, SCTR_FINISHED, mseq, &mut p);
        let mut f = [0u8; 49];
        f[0] = SCTR_FINISHED;
        f[1..5].copy_from_slice(&mseq.to_be_bytes());
        f[5..41].copy_from_slice(&p);
        f[41..].copy_from_slice(&tag);
        f
    }

    /// A record `sctr ‖ seq ‖ CCM(plain)`, its tag damaged unless `authentic`; returns the
    /// buffer and its length.
    #[must_use]
    pub fn record(&self, sctr: u8, seq: u32, plain: &[u8], authentic: bool) -> ([u8; FRAME_SIZE], usize) {
        let mut out = [0u8; FRAME_SIZE];
        let n = plain.len();
        out[0] = sctr;
        out[1..5].copy_from_slice(&seq.to_be_bytes());
        out[5..5 + n].copy_from_slice(plain);
        let tag = seal_with(&self.keys, sctr, seq, &mut out[5..5 + n]);
        out[5 + n..13 + n].copy_from_slice(&tag);
        if !authentic {
            out[12 + n] ^= 0x01;
        }
        (out, 13 + n)
    }
}

/// A copy of a slice into a fixed array (the simulator has no allocator either).
trait ToArray {
    fn to_vec_array(&self) -> ([u8; 140], usize);
}

impl ToArray for [u8] {
    fn to_vec_array(&self) -> ([u8; 140], usize) {
        let mut a = [0u8; 140];
        let n = self.len().min(140);
        a[..n].copy_from_slice(&self[..n]);
        (a, n)
    }
}

impl I2c for SimOptiga {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BusError> {
        if self.nacks > 0 {
            self.nacks -= 1;
            return Err(BusError::Nack);
        }
        let Some((&reg, data)) = bytes.split_first() else { return Err(BusError::Other) };
        if data.is_empty() {
            self.read_reg = reg;
            return Ok(());
        }
        match reg {
            REG_DATA_REG_LEN if data.len() == 2 => {
                let want = u16::from_be_bytes([data[0], data[1]]);
                self.data_reg_len = want.min(u16::try_from(FRAME_SIZE).unwrap_or(0));
            }
            REG_DATA if !self.silent && !self.cut() && data.len() <= usize::from(self.data_reg_len) => {
                self.on_frame(data)
            }
            _ => {}
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
        if self.nacks > 0 {
            self.nacks -= 1;
            return Err(BusError::Nack);
        }
        match self.read_reg {
            REG_I2C_STATE => {
                let len = if self.queued > 0 { self.queue[0].1 } else { 0 };
                let l = u16::try_from(len).unwrap_or(0).to_be_bytes();
                let st = [if self.queued > 0 { 0x40 } else { 0x00 }, 0x00, l[0], l[1]];
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = st.get(i).copied().unwrap_or(0xFF);
                }
            }
            REG_DATA_REG_LEN => {
                let v = self.data_reg_len.to_be_bytes();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = v.get(i).copied().unwrap_or(0xFF);
                }
            }
            REG_DATA => self.dequeue(buf),
            _ => buf.fill(0xFF),
        }
        Ok(())
    }

    fn delay_us(&mut self, _us: u32) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optiga::OptigaError;
    use crate::optiga::device::{FRESHNESS_LABEL, Optiga};

    const BINDING: [u8; 64] = [0x11; 64];
    const FRESH: [u8; 64] = [0x22; 64];
    const ROOT: [u8; 64] = [0x33; 64];

    fn live(seed: u8) -> Optiga<SimOptiga> {
        let mut o = Optiga::new(SimOptiga::provisioned(seed, &BINDING, &FRESH, &ROOT));
        o.open().unwrap();
        o.establish(&BINDING, &FRESH, &[seed; 32]).unwrap();
        o
    }

    fn prf32(secret: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut o = [0u8; 32];
        tls_prf_sha256(secret, parts, &mut o).unwrap();
        o
    }

    #[test]
    fn derive_counter_random_end_to_end() {
        let mut o = live(1);
        assert!(o.is_live());
        let mut out = [0u8; 32];
        o.derive(OID_ROOT, &[b"jotakey/tag/v1", &[7; 32], &[1], &[9; 32]], &mut out).unwrap();
        assert_eq!(out, prf32(&ROOT, &[b"jotakey/tag/v1", &[7; 32], &[1], &[9; 32]]));
        assert_eq!(o.increment_counter(), Ok(1));
        assert_eq!(o.increment_counter(), Ok(2));
        assert_eq!(o.bus_mut().counter_value(), 2);
        let mut r = [0u8; 64];
        o.random(&mut r).unwrap();
        assert_ne!(r, [0u8; 64]);
        // Two derivations: the check and the one above (security events).
        assert_eq!(o.bus_mut().derivations, 2);
        // Only OpenApplication went unprotected.
        assert_eq!(o.bus_mut().plain_commands, 1);
    }

    #[test]
    fn nothing_is_used_before_the_session_is_live() {
        let mut o = Optiga::new(SimOptiga::provisioned(2, &BINDING, &FRESH, &ROOT));
        o.open().unwrap();
        let mut out = [0u8; 32];
        assert_eq!(o.derive(OID_ROOT, &[&[0; 32]], &mut out), Err(OptigaError::NoSession));
        assert_eq!(o.increment_counter(), Err(OptigaError::NoSession));
        // A wrong freshness secret: the handshake succeeds, the check fails, nothing is live.
        assert_eq!(o.establish(&BINDING, &[0x99; 64], &[1; 32]), Err(OptigaError::NotFresh));
        assert!(!o.is_live());
        assert_eq!(o.increment_counter(), Err(OptigaError::NoSession));
        // A wrong binding secret: the OPTIGA's Finished does not verify.
        assert_eq!(o.establish(&[0x98; 64], &FRESH, &[1; 32]), Err(OptigaError::Integrity));
        assert!(o.establish(&BINDING, &FRESH, &[1; 32]).is_ok());
        assert_eq!(o.increment_counter(), Ok(1));
    }

    #[test]
    fn the_link_recovers_from_damaged_lost_and_busy_frames() {
        let mut o = live(3);
        o.bus_mut().corrupt_next = true;
        assert_eq!(o.increment_counter(), Ok(1));
        o.bus_mut().drop_next = true;
        assert_eq!(o.increment_counter(), Ok(2));
        o.bus_mut().nacks = 50;
        assert_eq!(o.increment_counter(), Ok(3));
        o.bus_mut().silent = true;
        assert_eq!(o.increment_counter(), Err(OptigaError::Timeout));
        assert!(!o.is_live(), "any failure drops the session");
        o.bus_mut().silent = false;
        assert_eq!(o.increment_counter(), Err(OptigaError::NoSession));
    }

    #[test]
    fn after_a_reset_the_session_is_rebuilt() {
        let mut o = live(4);
        assert_eq!(o.increment_counter(), Ok(1));
        o.bus_mut().reset();
        assert!(o.increment_counter().is_err());
        o.open().unwrap();
        o.establish(&BINDING, &FRESH, &[5; 32]).unwrap();
        assert_eq!(o.increment_counter(), Ok(2));
        assert_eq!(o.last_counter(), Some(2));
    }

    #[test]
    fn a_counter_that_goes_back_is_refused() {
        let mut o = live(5);
        assert_eq!(o.increment_counter(), Ok(1));
        assert_eq!(o.increment_counter(), Ok(2));
        // Rewritten behind the key's back (possible only on an unlocked chip).
        o.bus_mut().counter.data[..4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(o.increment_counter(), Err(OptigaError::CounterNotIncreasing));
        assert_eq!(o.last_counter(), Some(2));
        // At the threshold the OPTIGA refuses to count.
        let t = 10u32;
        o.bus_mut().counter.data[..8].copy_from_slice(&[0, 0, 0, 9, 0, 0, 0, 10]);
        assert_eq!(o.increment_counter(), Ok(t));
        assert!(o.establish(&BINDING, &FRESH, &[6; 32]).is_ok());
        assert_eq!(o.increment_counter(), Err(OptigaError::Status));
    }

    /// A bus attacker who recorded a whole session replays the OPTIGA's half of it: the
    /// handshake goes through (the master's half is the same), but the live-session check
    /// fails, because the recording does not contain the answer for the new nonce.
    #[test]
    fn a_replayed_session_is_not_live() {
        struct Recorder {
            sim: SimOptiga,
            reads: std::vec::Vec<std::vec::Vec<u8>>,
        }
        impl I2c for Recorder {
            fn write(&mut self, b: &[u8]) -> Result<(), BusError> {
                self.sim.write(b)
            }
            fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
                let r = self.sim.read(buf);
                self.reads.push(buf.to_vec());
                r
            }
            fn delay_us(&mut self, _: u32) {}
        }
        struct Replayer {
            reads: std::vec::Vec<std::vec::Vec<u8>>,
            at: usize,
        }
        impl I2c for Replayer {
            fn write(&mut self, _: &[u8]) -> Result<(), BusError> {
                Ok(())
            }
            fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
                let r = self.reads.get(self.at).cloned().unwrap_or_default();
                self.at += 1;
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = r.get(i).copied().unwrap_or(0xFF);
                }
                Ok(())
            }
            fn delay_us(&mut self, _: u32) {}
        }
        let mut o =
            Optiga::new(Recorder { sim: SimOptiga::provisioned(6, &BINDING, &FRESH, &ROOT), reads: std::vec![] });
        o.open().unwrap();
        o.establish(&BINDING, &FRESH, &[1; 32]).unwrap();
        assert_eq!(o.increment_counter(), Ok(1));
        let reads = core::mem::take(&mut o.bus_mut().reads);

        // The same nonce would pass: the recording is a faithful replay.
        let mut same = Optiga::new(Replayer { reads: reads.clone(), at: 0 });
        same.open().unwrap();
        assert_eq!(same.establish(&BINDING, &FRESH, &[1; 32]), Ok(()));
        // A fresh nonce does not.
        let mut fresh = Optiga::new(Replayer { reads, at: 0 });
        fresh.open().unwrap();
        assert_eq!(fresh.establish(&BINDING, &FRESH, &[2; 32]), Err(OptigaError::NotFresh));
        assert_eq!(fresh.increment_counter(), Err(OptigaError::NoSession));
        let _ = FRESHNESS_LABEL;
    }

    #[test]
    fn access_conditions_hold() {
        let mut o = live(7);
        // K_root cannot be read, even through the session.
        let mut buf = [0u8; 140];
        assert_eq!(
            o.command(&crate::optiga::apdu::get_data(OID_ROOT, false).unwrap(), &mut buf),
            Err(OptigaError::Status)
        );
        // Nor overwritten.
        assert!(o.establish(&BINDING, &FRESH, &[8; 32]).is_ok());
        assert_eq!(
            o.command(&crate::optiga::apdu::set_data(OID_ROOT, &[0; 64]).unwrap(), &mut buf),
            Err(OptigaError::Status)
        );
        // Without the session, DeriveKey on K_root is refused (EXE = Conf(E140)).
        let mut plain = Optiga::new(SimOptiga::provisioned(7, &BINDING, &FRESH, &ROOT));
        plain.open().unwrap();
        let cmd = crate::optiga::apdu::derive_key(OID_ROOT, &[&[0; 32]], 32).unwrap();
        assert_eq!(plain.command_plain(&cmd, &mut buf), Err(OptigaError::Status));
    }
}
