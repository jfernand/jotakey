// (c) Javier Fernandez @ JotaSoft 2026
//! A small CBOR decoder for what FIDO keys send back.
//!
//! The explorer talks to devices it knows nothing about, so their replies are untrusted
//! input: lengths are checked against the bytes actually present before anything is
//! allocated, and nesting is limited. Unlike the device's decoder this one is lenient
//! about canonical form: it is for displaying what a key says, not for verifying it.

/// Deepest nesting accepted (getInfo needs 3).
const MAX_DEPTH: usize = 16;

/// A decoded CBOR value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Integer (major types 0 and 1).
    Int(i128),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string.
    Text(String),
    /// Array.
    Array(Vec<Value>),
    /// Map, in the order received.
    Map(Vec<(Value, Value)>),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// A tagged value (tag number, content).
    Tag(u64, Box<Value>),
    /// Any other simple value, or a float (shown as its raw bits).
    Simple(u64),
}

impl Value {
    /// Decode exactly one value from `data`; trailing bytes are an error.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let (v, n) = decode_at(data, 0)?;
        (n == data.len()).then_some(v)
    }

    /// Look up `key` in a map.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Self::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Look up an integer key in a map.
    pub fn get_int(&self, key: i128) -> Option<&Value> {
        self.get(&Value::Int(key))
    }

    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The text, if this is a text string.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The bytes, if this is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The entries, if this is a map.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
}

impl std::fmt::Display for Value {
    /// CBOR diagnostic notation (RFC 8949 §8), compact.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(i) => write!(f, "{i}"),
            Self::Bytes(b) => write!(f, "h'{}'", hex(b)),
            Self::Text(t) => write!(f, "{t:?}"),
            Self::Array(a) => {
                f.write_str("[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Self::Map(m) => {
                f.write_str("{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                f.write_str("}")
            }
            Self::Bool(b) => write!(f, "{b}"),
            Self::Null => f.write_str("null"),
            Self::Tag(t, v) => write!(f, "{t}({v})"),
            Self::Simple(s) => write!(f, "simple({s})"),
        }
    }
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_at(d: &[u8], depth: usize) -> Option<(Value, usize)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let ib = *d.first()?;
    let (major, info) = (ib >> 5, ib & 0x1F);
    let (arg, mut p): (u64, usize) = match info {
        0..=23 => (u64::from(info), 1),
        24 => (u64::from(*d.get(1)?), 2),
        25 => (u64::from(u16::from_be_bytes(d.get(1..3)?.try_into().ok()?)), 3),
        26 => (u64::from(u32::from_be_bytes(d.get(1..5)?.try_into().ok()?)), 5),
        27 => (u64::from_be_bytes(d.get(1..9)?.try_into().ok()?), 9),
        _ => return None, // indefinite lengths and reserved values
    };
    let v = match major {
        0 => Value::Int(i128::from(arg)),
        1 => Value::Int(-1 - i128::from(arg)),
        2 | 3 => {
            let n = usize::try_from(arg).ok()?;
            let b = d.get(p..p.checked_add(n)?)?.to_vec();
            p += n;
            if major == 2 { Value::Bytes(b) } else { Value::Text(String::from_utf8(b).ok()?) }
        }
        4 | 5 => {
            // Each element takes at least one byte: a count beyond what is left is a lie,
            // and is rejected before anything is reserved.
            let count = usize::try_from(arg).ok()?;
            if count > d.len().saturating_sub(p) {
                return None;
            }
            let mut items = Vec::new();
            for _ in 0..count * if major == 4 { 1 } else { 2 } {
                let (v, n) = decode_at(d.get(p..)?, depth + 1)?;
                p += n;
                items.push(v);
            }
            if major == 4 {
                Value::Array(items)
            } else {
                let mut it = items.into_iter();
                let mut m = Vec::with_capacity(count);
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    m.push((k, v));
                }
                Value::Map(m)
            }
        }
        6 => {
            let (v, n) = decode_at(d.get(p..)?, depth + 1)?;
            p += n;
            Value::Tag(arg, Box::new(v))
        }
        _ => match (info, arg) {
            (20 | 21, _) => Value::Bool(info == 21),
            (22, _) => Value::Null,
            _ => Value::Simple(arg),
        },
    };
    Some((v, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_get_info_shaped_map() {
        // {1: ["FIDO_2_0"], 3: h'00..', 4: {"rk": false, "up": true}, 5: 1200}
        let mut d = vec![0xA4, 0x01, 0x81, 0x68];
        d.extend(b"FIDO_2_0");
        d.extend([0x03, 0x50]);
        d.extend([0u8; 16]);
        d.extend([0x04, 0xA2, 0x62, b'r', b'k', 0xF4, 0x62, b'u', b'p', 0xF5]);
        d.extend([0x05, 0x19, 0x04, 0xB0]);
        let v = Value::decode(&d).unwrap();
        assert_eq!(v.get_int(1).unwrap().as_array().unwrap()[0].as_text(), Some("FIDO_2_0"));
        assert_eq!(v.get_int(3).unwrap().as_bytes().unwrap().len(), 16);
        assert_eq!(v.get_int(4).unwrap().get(&Value::Text("up".into())), Some(&Value::Bool(true)));
        assert_eq!(v.get_int(5).unwrap().as_int(), Some(1200));
    }

    #[test]
    fn negative_integers_and_diagnostic_notation() {
        let v = Value::decode(&[0x82, 0x26, 0x39, 0x01, 0x00]).unwrap(); // [-7, -257]
        assert_eq!(v.to_string(), "[-7, -257]");
    }

    #[test]
    fn lying_lengths_and_deep_nesting_are_rejected_without_allocating() {
        // A byte string announcing 2^64-1 bytes, and an array announcing 2^32 elements.
        assert!(Value::decode(&[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_none());
        assert!(Value::decode(&[0x9A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]).is_none());
        // 100 nested one-element arrays.
        let mut deep = vec![0x81; 100];
        deep.push(0x00);
        assert!(Value::decode(&deep).is_none());
    }

    #[test]
    fn trailing_bytes_and_truncation_are_rejected() {
        assert!(Value::decode(&[0x01, 0x02]).is_none());
        assert!(Value::decode(&[0x62, b'a']).is_none());
        assert!(Value::decode(&[]).is_none());
    }
}
