// (c) Javier Fernandez @ JotaSoft 2026
//! CBOR decoder: never panics, and anything it accepts is canonical. Re-encoding the
//! decoded items reproduces the input exactly, so no message has two encodings.

#![no_main]

use jotakey_core::cbor::{Decoder, Encoder, Item};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut d = Decoder::new(data);
    if d.skip(0).is_err() {
        return;
    }
    let consumed = d.position();

    // Accepted: walk the same bytes item by item and re-encode them.
    let mut out = vec![0u8; consumed];
    let mut e = Encoder::new(&mut out);
    let mut walk = Decoder::new(&data[..consumed]);
    while walk.position() < consumed {
        let item = walk.item().expect("item inside an accepted value must decode");
        match item {
            Item::Unsigned(n) => e.unsigned(n),
            Item::Negative(n) => e.head(1, n),
            Item::Bytes(b) => e.bytes(b),
            Item::Text(t) => e.text(t),
            Item::Array(n) => e.array(n),
            Item::Map(n) => e.map(n),
            Item::Bool(b) => e.boolean(b),
            Item::Null => e.raw(&[0xf6]),
        }
        .expect("re-encoding fits in the original length");
    }
    let n = e.len();
    assert_eq!(&out[..n], &data[..consumed], "accepted CBOR is not canonical");
});
