//! A small, independent CBOR value type for the relying-party side of the tests.
//!
//! Deliberately not shared with the device code: if the device's codec were wrong in a way
//! that is symmetric with its own encoder, a shared codec would hide it.

/// A CBOR value (the subset CTAP uses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Integer (both major types 0 and 1).
    Int(i128),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string.
    Text(String),
    /// Array.
    Array(Vec<Value>),
    /// Map, in canonical order once encoded.
    Map(Vec<(Value, Value)>),
    /// Boolean.
    Bool(bool),
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xFF => out.extend([m | 24, arg as u8]),
        0x100..=0xFFFF => {
            out.push(m | 25);
            out.extend((arg as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(m | 26);
            out.extend((arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend(arg.to_be_bytes());
        }
    }
}

impl Value {
    /// Shorthand for text.
    pub fn t(s: &str) -> Self {
        Self::Text(s.into())
    }

    /// Canonical encoding (map keys sorted length-first, then bytewise).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(i) if *i >= 0 => head(out, 0, *i as u64),
            Self::Int(i) => head(out, 1, (-1 - *i) as u64),
            Self::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend(b);
            }
            Self::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend(t.as_bytes());
            }
            Self::Array(a) => {
                head(out, 4, a.len() as u64);
                a.iter().for_each(|v| v.encode_into(out));
            }
            Self::Map(m) => {
                let mut kv: Vec<(Vec<u8>, Vec<u8>)> = m.iter().map(|(k, v)| (k.encode(), v.encode())).collect();
                kv.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
                head(out, 5, kv.len() as u64);
                for (k, v) in kv {
                    out.extend(k);
                    out.extend(v);
                }
            }
            Self::Bool(b) => out.push(if *b { 0xF5 } else { 0xF4 }),
        }
    }

    /// Decode one value; returns it and the bytes consumed.
    pub fn decode(d: &[u8]) -> Option<(Self, usize)> {
        let ib = *d.first()?;
        let (major, info) = (ib >> 5, ib & 0x1F);
        let (arg, mut p): (u64, usize) = match info {
            0..=23 => (u64::from(info), 1),
            24 => (u64::from(*d.get(1)?), 2),
            25 => (u64::from(u16::from_be_bytes(d.get(1..3)?.try_into().ok()?)), 3),
            26 => (u64::from(u32::from_be_bytes(d.get(1..5)?.try_into().ok()?)), 5),
            27 => (u64::from_be_bytes(d.get(1..9)?.try_into().ok()?), 9),
            _ => return None,
        };
        let v = match major {
            0 => Self::Int(i128::from(arg)),
            1 => Self::Int(-1 - i128::from(arg)),
            2 | 3 => {
                let n = usize::try_from(arg).ok()?;
                let b = d.get(p..p + n)?.to_vec();
                p += n;
                if major == 2 { Self::Bytes(b) } else { Self::Text(String::from_utf8(b).ok()?) }
            }
            4 => {
                let mut a = Vec::new();
                for _ in 0..arg {
                    let (v, n) = Self::decode(d.get(p..)?)?;
                    p += n;
                    a.push(v);
                }
                Self::Array(a)
            }
            5 => {
                let mut m = Vec::new();
                for _ in 0..arg {
                    let (k, n) = Self::decode(d.get(p..)?)?;
                    p += n;
                    let (v, n) = Self::decode(d.get(p..)?)?;
                    p += n;
                    m.push((k, v));
                }
                Self::Map(m)
            }
            7 if info == 20 || info == 21 => Self::Bool(info == 21),
            _ => return None,
        };
        Some((v, p))
    }

    /// Map lookup.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Self::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Byte-string contents.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }
}
