// (c) Javier Fernandez @ JotaSoft 2026
//! Parsing helpers shared by the CTAP2 commands.
//!
//! Every helper validates the *type* of every member it sees, including members it does not
//! use. A malformed field anywhere in a request rejects the request.

use crate::cbor::{Decoder, Key};
use crate::status::Status;

/// Depth of values nested directly inside the top-level parameter map.
pub const PARAM_DEPTH: u8 = 1;

/// `PublicKeyCredentialDescriptor` (WebAuthn §5.10.3).
#[derive(Clone, Copy, Debug)]
pub struct Descriptor<'a> {
    /// Credential ID bytes.
    pub id: &'a [u8],
    /// True iff `type == "public-key"`.
    pub is_public_key: bool,
}

/// Parse a descriptor map at `depth`: `{"id": bytes, "type": text, ?"transports": [text]}`.
pub fn descriptor<'a>(d: &mut Decoder<'a>, depth: u8) -> Result<Descriptor<'a>, Status> {
    let mut m = d.map()?;
    let mut id = None;
    let mut ty = None;
    while let Some(k) = d.next_key(&mut m)? {
        match k {
            Key::Text("id") => id = Some(d.bytes()?),
            Key::Text("type") => ty = Some(d.text()?),
            Key::Text("transports") => {
                let n = d.array()?;
                for _ in 0..n {
                    d.text()?;
                }
            }
            _ => d.skip(depth.saturating_add(1))?,
        }
    }
    let (Some(id), Some(ty)) = (id, ty) else {
        return Err(Status::MissingParameter);
    };
    Ok(Descriptor { id, is_public_key: ty == "public-key" })
}

/// Validate a descriptor list and return its raw encoding for a later second pass.
pub fn descriptor_list<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8], Status> {
    let start = d.clone();
    let n = d.array()?;
    for _ in 0..n {
        descriptor(d, PARAM_DEPTH.saturating_add(1))?;
    }
    let mut probe = start;
    Ok(probe.raw_value(PARAM_DEPTH)?)
}

/// Iterate a list previously validated by [`descriptor_list`], calling `f` on each
/// descriptor until it returns `Some`.
pub fn find_in_list<'a, T>(
    raw: &'a [u8],
    mut f: impl FnMut(&Descriptor<'a>) -> Option<T>,
) -> Result<Option<T>, Status> {
    let mut d = Decoder::new(raw);
    let n = d.array()?;
    for _ in 0..n {
        let desc = descriptor(&mut d, PARAM_DEPTH.saturating_add(1))?;
        if let Some(t) = f(&desc) {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// The `options` map. Absent keys are `None`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Resident key requested.
    pub rk: Option<bool>,
    /// User presence requested.
    pub up: Option<bool>,
    /// User verification requested.
    pub uv: Option<bool>,
}

/// Parse `{?"rk": bool, ?"up": bool, ?"uv": bool, ...}`; unknown options must still be bools.
pub fn options(d: &mut Decoder<'_>) -> Result<Options, Status> {
    let mut m = d.map()?;
    let mut o = Options::default();
    while let Some(k) = d.next_key(&mut m)? {
        let v = d.boolean()?;
        match k {
            Key::Text("rk") => o.rk = Some(v),
            Key::Text("up") => o.up = Some(v),
            Key::Text("uv") => o.uv = Some(v),
            _ => {}
        }
    }
    Ok(o)
}

/// Read a byte string that must be exactly 32 bytes long (clientDataHash).
pub fn hash32(d: &mut Decoder<'_>) -> Result<[u8; 32], Status> {
    d.bytes()?.try_into().map_err(|_| Status::InvalidLength)
}

/// Read and check a map of text members; `user`/`rp` entities. Returns the `id` member raw.
pub enum EntityId<'a> {
    /// `rp.id` (text).
    Text(&'a str),
    /// `user.id` (bytes).
    Bytes(&'a [u8]),
}

/// Parse an entity map where `id` has the given expected kind and every other known member
/// is text. Unknown members are skipped (after validation).
pub fn entity<'a>(d: &mut Decoder<'a>, id_is_bytes: bool) -> Result<EntityId<'a>, Status> {
    let mut m = d.map()?;
    let mut id = None;
    while let Some(k) = d.next_key(&mut m)? {
        match k {
            Key::Text("id") => {
                id = Some(if id_is_bytes { EntityId::Bytes(d.bytes()?) } else { EntityId::Text(d.text()?) });
            }
            Key::Text("name" | "displayName" | "icon") => {
                d.text()?;
            }
            _ => d.skip(PARAM_DEPTH.saturating_add(1))?,
        }
    }
    id.ok_or(Status::MissingParameter)
}

/// Validate and ignore an extensions map (no extensions are supported in the MVP).
pub fn extensions(d: &mut Decoder<'_>) -> Result<(), Status> {
    let raw = d.raw_value(PARAM_DEPTH)?;
    Decoder::new(raw).map()?;
    Ok(())
}
