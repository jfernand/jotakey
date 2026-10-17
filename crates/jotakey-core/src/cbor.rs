// (c) Javier Fernandez @ JotaSoft 2026
//! Strict, zero-copy CBOR codec for the subset CTAP2 uses.
//!
//! The decoder accepts only **CTAP2 canonical CBOR** (CTAP 2.0 §6):
//! - integer, length and count arguments use the shortest encoding;
//! - lengths are definite (no indefinite-length items);
//! - map keys are strictly increasing in canonical order (shorter encoded key first, then
//!   bytewise), which also rules out duplicate keys;
//! - tags, floats, `undefined` and other simple values are rejected;
//! - nesting depth is bounded by [`MAX_DEPTH`].
//!
//! Strictness removes parser ambiguity. Two parsers cannot disagree about a message that only
//! has one valid reading. Every function is total: malformed input yields a [`CborError`],
//! never a panic. The executable Lean model in `formal/Jotakey/Cbor/` mirrors
//! [`Decoder::head`] and [`Encoder::head`] (`Heads.lean`) and [`Decoder::skip`] (`Cbor.lean`).

/// Maximum nesting depth of arrays and maps accepted by the decoder.
pub const MAX_DEPTH: u8 = 4;

/// Decoding or encoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    /// Input ended in the middle of an item.
    Truncated,
    /// An argument was not encoded in its shortest form.
    NonMinimal,
    /// Indefinite-length item or stray "break".
    Indefinite,
    /// Reserved additional-information value (28–30).
    Malformed,
    /// Tag, float or simple value outside `false`/`true`/`null`.
    Unsupported,
    /// Text string is not valid UTF-8.
    InvalidUtf8,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Map keys not strictly increasing in canonical order (includes duplicates).
    NonCanonicalMap,
    /// Map key of a type CTAP never uses (only integers and text are allowed).
    BadKeyType,
    /// An item had a different type than required.
    UnexpectedType,
    /// Bytes left over after the top-level item.
    TrailingBytes,
    /// Encoder output buffer is full.
    BufferFull,
}

/// CBOR major types.
mod major {
    pub const UNSIGNED: u8 = 0;
    pub const NEGATIVE: u8 = 1;
    pub const BYTES: u8 = 2;
    pub const TEXT: u8 = 3;
    pub const ARRAY: u8 = 4;
    pub const MAP: u8 = 5;
    pub const TAG: u8 = 6;
    pub const SIMPLE: u8 = 7;
}

/// One decoded data item. Containers carry their element count; their contents follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3, validated UTF-8.
    Text(&'a str),
    /// Major type 4 with element count.
    Array(u64),
    /// Major type 5 with pair count.
    Map(u64),
    /// Simple values 20/21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

/// A CTAP map key: either an integer or a text string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key<'a> {
    /// Integer key (CTAP command parameters, COSE labels).
    Int(i64),
    /// Text key (WebAuthn dictionary members).
    Text(&'a str),
}

/// Zero-copy decoder over an input slice.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

/// Iteration state for one map, enforcing canonical key order.
#[derive(Clone, Copy, Debug)]
pub struct MapState<'a> {
    remaining: u64,
    prev_key: Option<&'a [u8]>,
}

/// Canonical CTAP2 key order: shorter encoding first, then bytewise lexicographic.
fn canonical_lt(a: &[u8], b: &[u8]) -> bool {
    a.len() < b.len() || (a.len() == b.len() && a < b)
}

impl<'a> Decoder<'a> {
    /// Start decoding `input` from its first byte.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Offset of the next unread byte.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Fail unless all input has been consumed.
    ///
    /// # Errors
    /// [`CborError::TrailingBytes`] if bytes remain.
    pub const fn finish(&self) -> Result<(), CborError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(CborError::TrailingBytes)
        }
    }

    fn read_u8(&mut self) -> Result<u8, CborError> {
        let b = *self.input.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos = self.pos.checked_add(1).ok_or(CborError::Truncated)?;
        Ok(b)
    }

    fn read_slice(&mut self, len: u64) -> Result<&'a [u8], CborError> {
        let len = usize::try_from(len).map_err(|_| CborError::Truncated)?;
        let end = self.pos.checked_add(len).ok_or(CborError::Truncated)?;
        let s = self.input.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn read_be(&mut self, n: u64) -> Result<u64, CborError> {
        let bytes = self.read_slice(n)?;
        let mut v: u64 = 0;
        for &b in bytes {
            v = (v << 8) | u64::from(b);
        }
        Ok(v)
    }

    /// Decode one item head: `(major type, argument)`. Enforces shortest-form arguments and
    /// rejects indefinite lengths. For major type 7 the argument is the simple value.
    ///
    /// # Errors
    /// Any [`CborError`] describing why the head is not canonical.
    pub fn head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1F;
        // Floats and extended simple values (major 7, info 24..=27) are not in the subset.
        if major == major::SIMPLE && (24..=27).contains(&info) {
            return Err(CborError::Unsupported);
        }
        let arg = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = self.read_be(1)?;
                if v < 24 {
                    return Err(CborError::NonMinimal);
                }
                v
            }
            25 => {
                let v = self.read_be(2)?;
                if v <= 0xFF {
                    return Err(CborError::NonMinimal);
                }
                v
            }
            26 => {
                let v = self.read_be(4)?;
                if v <= 0xFFFF {
                    return Err(CborError::NonMinimal);
                }
                v
            }
            27 => {
                let v = self.read_be(8)?;
                if v <= 0xFFFF_FFFF {
                    return Err(CborError::NonMinimal);
                }
                v
            }
            28..=30 => return Err(CborError::Malformed),
            _ => return Err(CborError::Indefinite),
        };
        Ok((major, arg))
    }

    /// Decode the next item. Container contents are not consumed.
    ///
    /// # Errors
    /// Any [`CborError`].
    pub fn item(&mut self) -> Result<Item<'a>, CborError> {
        let (major, arg) = self.head()?;
        match major {
            major::UNSIGNED => Ok(Item::Unsigned(arg)),
            major::NEGATIVE => Ok(Item::Negative(arg)),
            major::BYTES => Ok(Item::Bytes(self.read_slice(arg)?)),
            major::TEXT => {
                let raw = self.read_slice(arg)?;
                core::str::from_utf8(raw)
                    .map(Item::Text)
                    .map_err(|_| CborError::InvalidUtf8)
            }
            major::ARRAY => Ok(Item::Array(arg)),
            major::MAP => Ok(Item::Map(arg)),
            major::SIMPLE => match arg {
                20 => Ok(Item::Bool(false)),
                21 => Ok(Item::Bool(true)),
                22 => Ok(Item::Null),
                _ => Err(CborError::Unsupported),
            },
            // major::TAG and anything else: tags are not part of the subset.
            _ => Err(CborError::Unsupported),
        }
    }

    /// Consume one complete value (including container contents) at nesting `depth`,
    /// validating it exactly as strictly as a typed read would.
    ///
    /// # Errors
    /// Any [`CborError`]; [`CborError::TooDeep`] beyond [`MAX_DEPTH`].
    pub fn skip(&mut self, depth: u8) -> Result<(), CborError> {
        match self.item()? {
            Item::Array(n) => {
                let inner = Self::deeper(depth)?;
                for _ in 0..n {
                    self.skip(inner)?;
                }
                Ok(())
            }
            Item::Map(n) => {
                let inner = Self::deeper(depth)?;
                let mut st = MapState { remaining: n, prev_key: None };
                while self.next_key(&mut st)?.is_some() {
                    self.skip(inner)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Consume one complete value and return its raw encoding.
    ///
    /// # Errors
    /// As [`Decoder::skip`].
    pub fn raw_value(&mut self, depth: u8) -> Result<&'a [u8], CborError> {
        let start = self.pos;
        self.skip(depth)?;
        self.input.get(start..self.pos).ok_or(CborError::Truncated)
    }

    fn deeper(depth: u8) -> Result<u8, CborError> {
        let d = depth.checked_add(1).ok_or(CborError::TooDeep)?;
        if d > MAX_DEPTH { Err(CborError::TooDeep) } else { Ok(d) }
    }

    /// Read a map head and return the iteration state for its pairs.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] if the next item is not a map.
    pub fn map(&mut self) -> Result<MapState<'a>, CborError> {
        match self.item()? {
            Item::Map(n) => Ok(MapState { remaining: n, prev_key: None }),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Read the next key of a map, or `None` when all pairs are read. The caller must
    /// consume exactly one value after each returned key.
    ///
    /// # Errors
    /// [`CborError::NonCanonicalMap`] if keys are out of order or repeated,
    /// [`CborError::BadKeyType`] for keys that are neither integers nor text.
    pub fn next_key(&mut self, st: &mut MapState<'a>) -> Result<Option<Key<'a>>, CborError> {
        if st.remaining == 0 {
            return Ok(None);
        }
        st.remaining = st.remaining.saturating_sub(1);
        let start = self.pos;
        let key = match self.item()? {
            Item::Unsigned(n) => Key::Int(i64::try_from(n).map_err(|_| CborError::BadKeyType)?),
            Item::Negative(n) => {
                let n = i64::try_from(n).map_err(|_| CborError::BadKeyType)?;
                // -1 - n cannot overflow for n in 0..=i64::MAX.
                Key::Int((-1i64).checked_sub(n).ok_or(CborError::BadKeyType)?)
            }
            Item::Text(t) => Key::Text(t),
            _ => return Err(CborError::BadKeyType),
        };
        let raw = self.input.get(start..self.pos).ok_or(CborError::Truncated)?;
        if let Some(prev) = st.prev_key
            && !canonical_lt(prev, raw)
        {
            return Err(CborError::NonCanonicalMap);
        }
        st.prev_key = Some(raw);
        Ok(Some(key))
    }

    /// Read an array head and return its element count.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] if the next item is not an array.
    pub fn array(&mut self) -> Result<u64, CborError> {
        match self.item()? {
            Item::Array(n) => Ok(n),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Read a byte string.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] on any other type.
    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        match self.item()? {
            Item::Bytes(b) => Ok(b),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Read a text string.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] on any other type.
    pub fn text(&mut self) -> Result<&'a str, CborError> {
        match self.item()? {
            Item::Text(t) => Ok(t),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Read an unsigned integer.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] on any other type.
    pub fn unsigned(&mut self) -> Result<u64, CborError> {
        match self.item()? {
            Item::Unsigned(n) => Ok(n),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Read a signed integer that fits in `i64`.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] on any other type or if out of range.
    pub fn int(&mut self) -> Result<i64, CborError> {
        match self.item()? {
            Item::Unsigned(n) => i64::try_from(n).map_err(|_| CborError::UnexpectedType),
            Item::Negative(n) => {
                let n = i64::try_from(n).map_err(|_| CborError::UnexpectedType)?;
                (-1i64).checked_sub(n).ok_or(CborError::UnexpectedType)
            }
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Read a boolean.
    ///
    /// # Errors
    /// [`CborError::UnexpectedType`] on any other type.
    pub fn boolean(&mut self) -> Result<bool, CborError> {
        match self.item()? {
            Item::Bool(b) => Ok(b),
            _ => Err(CborError::UnexpectedType),
        }
    }
}

/// Canonical CBOR encoder into a fixed buffer.
///
/// Heads are always shortest-form. The caller must emit map keys in canonical order; the
/// unit tests decode every response with the strict [`Decoder`] to check this.
#[derive(Debug)]
pub struct Encoder<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> Encoder<'b> {
    /// Encode into `buf` starting at offset 0.
    pub const fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// True if nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Append raw bytes (already-encoded CBOR or a non-CBOR prefix).
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn raw(&mut self, data: &[u8]) -> Result<(), CborError> {
        let end = self.pos.checked_add(data.len()).ok_or(CborError::BufferFull)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(CborError::BufferFull)?;
        dst.copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    /// Emit a shortest-form head for `major` with argument `arg`.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn head(&mut self, major: u8, arg: u64) -> Result<(), CborError> {
        let m = major << 5;
        let be = arg.to_be_bytes();
        match arg {
            0..=23 => self.raw(&[m | (be[7] & 0x1F)]),
            24..=0xFF => self.raw(&[m | 24, be[7]]),
            0x100..=0xFFFF => self.raw(&[m | 25, be[6], be[7]]),
            0x1_0000..=0xFFFF_FFFF => self.raw(&[m | 26, be[4], be[5], be[6], be[7]]),
            _ => {
                self.raw(&[m | 27])?;
                self.raw(&be)
            }
        }
    }

    /// Emit an unsigned integer.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn unsigned(&mut self, v: u64) -> Result<(), CborError> {
        self.head(major::UNSIGNED, v)
    }

    /// Emit a signed integer.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        if v >= 0 {
            self.head(major::UNSIGNED, v.unsigned_abs())
        } else {
            // -1 - v == |v| - 1 for negative v, which never overflows.
            self.head(major::NEGATIVE, v.unsigned_abs().saturating_sub(1))
        }
    }

    /// Emit a byte string.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        self.head(major::BYTES, b.len() as u64)?;
        self.raw(b)
    }

    /// Emit a text string.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn text(&mut self, t: &str) -> Result<(), CborError> {
        self.head(major::TEXT, t.len() as u64)?;
        self.raw(t.as_bytes())
    }

    /// Emit an array head.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn array(&mut self, n: u64) -> Result<(), CborError> {
        self.head(major::ARRAY, n)
    }

    /// Emit a map head.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn map(&mut self, n: u64) -> Result<(), CborError> {
        self.head(major::MAP, n)
    }

    /// Emit a boolean.
    ///
    /// # Errors
    /// [`CborError::BufferFull`].
    pub fn boolean(&mut self, b: bool) -> Result<(), CborError> {
        self.head(major::SIMPLE, if b { 21 } else { 20 })
    }
}

// Keep the unused major constants referenced so the table above stays complete.
const _: [u8; 2] = [major::TAG, major::SIMPLE];

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    fn enc<F: FnOnce(&mut Encoder<'_>) -> Result<(), CborError>>(f: F) -> ([u8; 64], usize) {
        let mut buf = [0u8; 64];
        let mut e = Encoder::new(&mut buf);
        f(&mut e).unwrap();
        let n = e.len();
        (buf, n)
    }

    #[test]
    fn rfc8949_appendix_a_integers() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (10, &[0x0a]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (25, &[0x18, 0x19]),
            (100, &[0x18, 0x64]),
            (1000, &[0x19, 0x03, 0xe8]),
            (1_000_000, &[0x1a, 0x00, 0x0f, 0x42, 0x40]),
            (1_000_000_000_000, &[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]),
            (-1, &[0x20]),
            (-10, &[0x29]),
            (-100, &[0x38, 0x63]),
            (-1000, &[0x39, 0x03, 0xe7]),
            (-7, &[0x26]),
        ];
        for &(v, want) in cases {
            let (buf, n) = enc(|e| e.int(v));
            assert_eq!(&buf[..n], want, "encode {v}");
            let mut d = Decoder::new(want);
            assert_eq!(d.int().unwrap(), v, "decode {v}");
            d.finish().unwrap();
        }
    }

    #[test]
    fn rejects_non_minimal_heads() {
        for bad in [&[0x18, 0x17][..], &[0x19, 0x00, 0xff], &[0x1a, 0, 0, 0xff, 0xff], &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]] {
            assert_eq!(Decoder::new(bad).item(), Err(CborError::NonMinimal), "{bad:x?}");
        }
    }

    #[test]
    fn rejects_indefinite_tags_floats_undefined() {
        assert_eq!(Decoder::new(&[0x5f]).item(), Err(CborError::Indefinite));
        assert_eq!(Decoder::new(&[0xff]).item(), Err(CborError::Indefinite));
        assert_eq!(Decoder::new(&[0xc0, 0x00]).item(), Err(CborError::Unsupported));
        assert_eq!(Decoder::new(&[0xf9, 0x3c, 0x00]).item(), Err(CborError::Unsupported));
        assert_eq!(Decoder::new(&[0xf7]).item(), Err(CborError::Unsupported));
        assert_eq!(Decoder::new(&[0x1c]).item(), Err(CborError::Malformed));
    }

    #[test]
    fn simple_values() {
        assert_eq!(Decoder::new(&[0xf4]).item(), Ok(Item::Bool(false)));
        assert_eq!(Decoder::new(&[0xf5]).item(), Ok(Item::Bool(true)));
        assert_eq!(Decoder::new(&[0xf6]).item(), Ok(Item::Null));
    }

    #[test]
    fn map_key_order_is_enforced() {
        // {1: 0, 2: 0} ok; {2: 0, 1: 0} and {1: 0, 1: 0} rejected.
        let ok = [0xa2, 0x01, 0x00, 0x02, 0x00];
        Decoder::new(&ok).skip(0).unwrap();
        let unordered = [0xa2, 0x02, 0x00, 0x01, 0x00];
        assert_eq!(Decoder::new(&unordered).skip(0), Err(CborError::NonCanonicalMap));
        let dup = [0xa2, 0x01, 0x00, 0x01, 0x00];
        assert_eq!(Decoder::new(&dup).skip(0), Err(CborError::NonCanonicalMap));
        // Text keys: "id" < "name" < "displayName" (length first).
        let mut buf = [0u8; 64];
        let mut e = Encoder::new(&mut buf);
        e.map(3).unwrap();
        for k in ["id", "name", "displayName"] {
            e.text(k).unwrap();
            e.unsigned(0).unwrap();
        }
        let n = e.len();
        Decoder::new(&buf[..n]).skip(0).unwrap();
        // Integer keys sort before text keys, negative ints after positive ones.
        let mixed = [0xa3, 0x01, 0x00, 0x20, 0x00, 0x61, 0x61, 0x00];
        Decoder::new(&mixed).skip(0).unwrap();
    }

    #[test]
    fn depth_is_bounded() {
        let ok = [0x81, 0x81, 0x81, 0x81, 0x00]; // 4 nested arrays
        Decoder::new(&ok).skip(0).unwrap();
        let deep = [0x81, 0x81, 0x81, 0x81, 0x81, 0x00];
        assert_eq!(Decoder::new(&deep).skip(0), Err(CborError::TooDeep));
    }

    #[test]
    fn huge_counts_do_not_loop_forever() {
        // Array claiming 2^64-1 elements with no content: fails fast on truncation.
        let bad = [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Decoder::new(&bad).skip(0), Err(CborError::Truncated));
        let bad = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Decoder::new(&bad).item(), Err(CborError::Truncated));
    }

    #[test]
    fn invalid_utf8_rejected() {
        assert_eq!(Decoder::new(&[0x62, 0xc3, 0x28]).item(), Err(CborError::InvalidUtf8));
    }

    #[test]
    fn negative_map_keys_and_typed_reads() {
        // {-1: 5, -2: 0} — COSE-style negative labels decode to the right integers.
        let data = [0xa2, 0x20, 0x05, 0x21, 0x00];
        let mut d = Decoder::new(&data);
        let mut m = d.map().unwrap();
        assert_eq!(d.next_key(&mut m).unwrap(), Some(Key::Int(-1)));
        assert_eq!(d.unsigned().unwrap(), 5);
        assert_eq!(d.next_key(&mut m).unwrap(), Some(Key::Int(-2)));
        assert_eq!(d.unsigned().unwrap(), 0);
        assert_eq!(d.next_key(&mut m).unwrap(), None);
        assert_eq!(Decoder::new(&[0x19, 0x01, 0x00]).unsigned(), Ok(256));
        assert_eq!(Decoder::new(&[0x20]).unsigned(), Err(CborError::UnexpectedType));
    }

    #[test]
    fn encoder_len_and_is_empty() {
        let mut buf = [0u8; 4];
        let mut e = Encoder::new(&mut buf);
        assert!(e.is_empty());
        e.unsigned(1).unwrap();
        assert!(!e.is_empty());
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn encoder_reports_full_buffer() {
        let mut buf = [0u8; 3];
        let mut e = Encoder::new(&mut buf);
        assert_eq!(e.bytes(&[1, 2, 3]), Err(CborError::BufferFull));
    }

    proptest! {
        #[test]
        fn head_roundtrip(major in 0u8..=5, arg: u64) {
            let mut buf = [0u8; 9];
            let mut e = Encoder::new(&mut buf);
            e.head(major, arg).unwrap();
            let n = e.len();
            let mut d = Decoder::new(&buf[..n]);
            prop_assert_eq!(d.head().unwrap(), (major, arg));
            prop_assert!(d.finish().is_ok());
        }

        #[test]
        fn int_roundtrip(v: i64) {
            let (buf, n) = enc(|e| e.int(v));
            let mut d = Decoder::new(&buf[..n]);
            prop_assert_eq!(d.int().unwrap(), v);
        }

        #[test]
        fn decoder_never_panics(data: Vec<u8>) {
            let _ = Decoder::new(&data).skip(0);
        }

        #[test]
        fn accepted_heads_are_canonical(data: Vec<u8>) {
            // Whatever the decoder accepts re-encodes to exactly the same bytes.
            let mut d = Decoder::new(&data);
            if let Ok((major, arg)) = d.head()
                && major <= 5 {
                    let used = d.position();
                    let mut buf = [0u8; 9];
                    let mut e = Encoder::new(&mut buf);
                    e.head(major, arg).unwrap();
                    let n = e.len();
                    prop_assert_eq!(&buf[..n], &data[..used]);
                }
        }
    }
}
