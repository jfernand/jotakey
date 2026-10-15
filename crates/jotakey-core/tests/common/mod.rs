//! Test-side helpers: an owned CBOR value with a canonical encoder, request builders and a
//! response decoder. Independent of the crate's own encoder on purpose, so a bug there
//! cannot hide itself.

#![allow(dead_code)]

use jotakey_core::ctap::{Authenticator, Outcome, Response};
use jotakey_core::mock::MockPlatform;
use jotakey_core::platform::UpResult;
use jotakey_core::{AAGUID, MAX_MSG_SIZE};

#[derive(Clone, Debug, PartialEq)]
pub enum V {
    U(u64),
    N(i64),
    B(Vec<u8>),
    T(String),
    A(Vec<V>),
    M(Vec<(V, V)>),
    Bool(bool),
    Null,
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xFF {
        out.extend([m | 24, arg as u8]);
    } else if arg <= 0xFFFF {
        out.push(m | 25);
        out.extend((arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(m | 26);
        out.extend((arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(arg.to_be_bytes());
    }
}

impl V {
    pub fn t(s: &str) -> V {
        V::T(s.to_string())
    }

    pub fn int(i: i64) -> V {
        if i >= 0 { V::U(i as u64) } else { V::N(i) }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            V::U(u) => head(out, 0, *u),
            V::N(n) => head(out, 1, (-1 - *n) as u64),
            V::B(b) => {
                head(out, 2, b.len() as u64);
                out.extend(b);
            }
            V::T(t) => {
                head(out, 3, t.len() as u64);
                out.extend(t.as_bytes());
            }
            V::A(a) => {
                head(out, 4, a.len() as u64);
                for v in a {
                    v.encode_into(out);
                }
            }
            V::M(m) => {
                let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = m.iter().map(|(k, v)| (k.encode(), v.encode())).collect();
                pairs.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
                head(out, 5, pairs.len() as u64);
                for (k, v) in pairs {
                    out.extend(k);
                    out.extend(v);
                }
            }
            V::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            V::Null => out.push(0xf6),
        }
    }

    /// Decode with a permissive reference decoder (used to inspect responses).
    pub fn decode(data: &[u8]) -> (V, usize) {
        let ib = data[0];
        let major = ib >> 5;
        let info = ib & 0x1f;
        let (arg, mut pos) = match info {
            0..=23 => (info as u64, 1),
            24 => (data[1] as u64, 2),
            25 => (u16::from_be_bytes(data[1..3].try_into().unwrap()) as u64, 3),
            26 => (u32::from_be_bytes(data[1..5].try_into().unwrap()) as u64, 5),
            27 => (u64::from_be_bytes(data[1..9].try_into().unwrap()), 9),
            _ => panic!("unsupported"),
        };
        let v = match major {
            0 => V::U(arg),
            1 => V::N(-1 - arg as i64),
            2 => {
                let b = data[pos..pos + arg as usize].to_vec();
                pos += arg as usize;
                V::B(b)
            }
            3 => {
                let t = String::from_utf8(data[pos..pos + arg as usize].to_vec()).unwrap();
                pos += arg as usize;
                V::T(t)
            }
            4 => {
                let mut a = Vec::new();
                for _ in 0..arg {
                    let (v, n) = V::decode(&data[pos..]);
                    pos += n;
                    a.push(v);
                }
                V::A(a)
            }
            5 => {
                let mut m = Vec::new();
                for _ in 0..arg {
                    let (k, n) = V::decode(&data[pos..]);
                    pos += n;
                    let (v, n) = V::decode(&data[pos..]);
                    pos += n;
                    m.push((k, v));
                }
                V::M(m)
            }
            7 => match info {
                20 => V::Bool(false),
                21 => V::Bool(true),
                22 => V::Null,
                _ => panic!("simple"),
            },
            _ => panic!("major"),
        };
        (v, pos)
    }

    pub fn get(&self, key: &V) -> Option<&V> {
        match self {
            V::M(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            V::B(b) => b,
            other => panic!("not bytes: {other:?}"),
        }
    }
}

pub const RP: &str = "example.com";
pub const CDH: [u8; 32] = [0xCD; 32];

pub fn descriptor(id: &[u8]) -> V {
    V::M(vec![(V::t("id"), V::B(id.to_vec())), (V::t("type"), V::t("public-key"))])
}

pub fn make_credential_params(rp: &str) -> Vec<(V, V)> {
    vec![
        (V::U(1), V::B(CDH.to_vec())),
        (V::U(2), V::M(vec![(V::t("id"), V::t(rp)), (V::t("name"), V::t("Example"))])),
        (
            V::U(3),
            V::M(vec![
                (V::t("id"), V::B(vec![1, 2, 3, 4])),
                (V::t("name"), V::t("alice")),
                (V::t("displayName"), V::t("Alice")),
            ]),
        ),
        (
            V::U(4),
            V::A(vec![V::M(vec![(V::t("alg"), V::int(-7)), (V::t("type"), V::t("public-key"))])]),
        ),
    ]
}

pub fn get_assertion_params(rp: &str, allow: &[&[u8]]) -> Vec<(V, V)> {
    vec![
        (V::U(1), V::t(rp)),
        (V::U(2), V::B(CDH.to_vec())),
        (V::U(3), V::A(allow.iter().map(|id| descriptor(id)).collect())),
    ]
}

pub fn request(cmd: u8, params: Vec<(V, V)>) -> Vec<u8> {
    let mut r = vec![cmd];
    r.extend(V::M(params).encode());
    r
}

pub struct Harness {
    pub auth: Authenticator,
    pub platform: MockPlatform,
    pub out: Box<Response>,
}

impl Harness {
    pub fn new() -> Self {
        Self { auth: Authenticator::new(AAGUID), platform: MockPlatform::new(1), out: Box::new([0u8; MAX_MSG_SIZE]) }
    }

    /// Process a request; if presence is needed, answer with `up`. Returns (status, body).
    pub fn run(&mut self, req: &[u8], up: UpResult) -> (u8, Vec<u8>) {
        let n = match self.auth.process(&mut self.platform, req, &mut self.out) {
            Outcome::Response(n) => n,
            Outcome::NeedsUserPresence => self.auth.complete(&mut self.platform, up, &mut self.out),
        };
        (self.out[0], self.out[1..n].to_vec())
    }

    pub fn status(&mut self, req: &[u8]) -> u8 {
        self.run(req, UpResult::Confirmed).0
    }
}
