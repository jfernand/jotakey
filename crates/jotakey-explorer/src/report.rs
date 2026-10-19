// (c) Javier Fernandez @ JotaSoft 2026
//! Ask a device what it is, and lay the answers out as labelled sections.
//!
//! **Read-only by construction.** The only requests sent are CTAPHID INIT, CTAP2
//! `authenticatorGetInfo`, `authenticatorClientPIN` getPINRetries/getUVRetries (when the
//! key says it has a PIN or built-in UV), and the U2F `VERSION` APDU. None of them needs a
//! touch, creates or uses a credential, or changes any state on the key; the retry
//! counters are read, never spent. WINK (the `w` key) only blinks the device.

use crate::cbor::{Value, hex};
use crate::ctaphid::{Client, Error, InitInfo, Transport, capability};
use crate::discover::Device;

/// `authenticatorGetInfo`.
pub const GET_INFO: u8 = 0x04;
/// `authenticatorClientPIN`.
pub const CLIENT_PIN: u8 = 0x06;
/// The AAGUID the Jotakey firmware reports (`jotakey_core::AAGUID`; a test keeps them equal).
pub const JOTAKEY_AAGUID: [u8; 16] = *b"jotakey-v01-c6\x00\x01";

/// One labelled value. `note` explains it in a few words.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// Left column.
    pub label: String,
    /// Right column.
    pub value: String,
    /// Optional explanation, shown dimmed.
    pub note: Option<String>,
}

/// A titled group of rows.
#[derive(Clone, Debug, PartialEq)]
pub struct Section {
    /// Heading.
    pub title: String,
    /// Content.
    pub rows: Vec<Row>,
}

/// Everything learnt about one device.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Report {
    /// Sections in display order.
    pub sections: Vec<Section>,
    /// The raw getInfo reply, if there was one.
    pub raw_get_info: Option<Vec<u8>>,
    /// Problems worth showing (the device still may have answered other questions).
    pub problems: Vec<String>,
}

fn row(label: impl Into<String>, value: impl Into<String>) -> Row {
    Row { label: label.into(), value: value.into(), note: None }
}

fn row_note(label: impl Into<String>, value: impl Into<String>, note: impl Into<String>) -> Row {
    Row { label: label.into(), value: value.into(), note: Some(note.into()) }
}

/// What sysfs says, before any I/O.
pub fn device_section(d: &Device) -> Section {
    let mut rows = vec![
        row("Node", d.path.display().to_string()),
        row("Bus", if d.virtual_device { format!("{} (virtual, uhid)", d.bus) } else { d.bus.to_string() }),
        Row {
            label: "VID:PID".into(),
            value: format!("{:04x}:{:04x}", d.vendor_id, d.product_id),
            note: d.vendor_name().map(str::to_owned),
        },
        row("Kernel name", d.name.clone()),
    ];
    if !d.phys.is_empty() {
        rows.push(row("Physical path", d.phys.clone()));
    }
    if let Some(u) = &d.usb {
        let fields = [
            ("Manufacturer", &u.manufacturer),
            ("Product", &u.product),
            ("Serial", &u.serial),
            ("Release", &u.release),
        ];
        for (label, v) in fields {
            if let Some(v) = v {
                rows.push(row(label, v.clone()));
            }
        }
        if let Some(s) = &u.speed {
            rows.push(row("USB speed", format!("{s} Mbit/s")));
        }
    }
    Section { title: "Device".into(), rows }
}

/// Query a device over `io` and describe it.
pub fn query<T: Transport>(device: &Device, io: T) -> Report {
    let mut report = Report { sections: vec![device_section(device)], ..Report::default() };
    let (mut client, init) = match Client::connect(io) {
        Ok(c) => c,
        Err(e) => {
            report.problems.push(format!("CTAPHID INIT failed: {e}"));
            return report;
        }
    };
    report.sections.push(init_section(&init));

    let mut options = None;
    if init.capabilities & capability::CBOR != 0 {
        match client.cbor(GET_INFO, &[]) {
            Ok((0, body)) => match Value::decode(&body) {
                Some(info) => {
                    report.sections.push(get_info_section(&info));
                    options = info.get_int(4).cloned();
                    report.raw_get_info = Some(body);
                }
                None => report.problems.push(format!("getInfo reply is not valid CBOR: {}", hex(&body))),
            },
            Ok((status, _)) => report.problems.push(format!("getInfo failed: {}", ctap_status(status))),
            Err(e) => report.problems.push(format!("getInfo failed: {e}")),
        }
    }

    if let Some(opts) = &options {
        let mut rows = Vec::new();
        if opts.get(&Value::Text("clientPin".into())) == Some(&Value::Bool(true)) {
            rows.push(retries(&mut client, 0x01, 3, "PIN retries", "wrong PINs left before the key locks"));
        }
        if opts.get(&Value::Text("uv".into())) == Some(&Value::Bool(true)) {
            rows.push(retries(&mut client, 0x07, 5, "UV retries", "failed fingerprints left before falling back to the PIN"));
        }
        if !rows.is_empty() {
            report.sections.push(Section { title: "Verification".into(), rows });
        }
    }

    if init.capabilities & capability::NMSG == 0 {
        // U2F_VERSION: CLA 00, INS 03, P1 00, P2 00, extended Le 00 00 00.
        let row = match client.msg(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]) {
            Ok(r) if r.ends_with(&[0x90, 0x00]) => row_note(
                "VERSION",
                String::from_utf8_lossy(&r[..r.len() - 2]).into_owned(),
                "the key also speaks the older U2F protocol",
            ),
            Ok(r) => row("VERSION", format!("status word {}", hex(&r[r.len().saturating_sub(2)..]))),
            Err(e) => row("VERSION", format!("failed: {e}")),
        };
        report.sections.push(Section { title: "U2F (CTAP1)".into(), rows: vec![row] });
    }
    report
}

/// clientPIN getPINRetries (0x01, answer key 3) or getUVRetries (0x07, answer key 5).
fn retries<T: Transport>(client: &mut Client<T>, sub: u8, answer_key: i128, label: &str, note: &str) -> Row {
    // {1: pinUvAuthProtocol 1, 2: subCommand}
    let params = [0xA2, 0x01, 0x01, 0x02, sub];
    match client.cbor(CLIENT_PIN, &params) {
        Ok((0, body)) => match Value::decode(&body).as_ref().and_then(|v| v.get_int(answer_key)).and_then(Value::as_int) {
            Some(n) => row_note(label, n.to_string(), note),
            None => row(label, "reply without a count"),
        },
        Ok((status, _)) => row(label, ctap_status(status)),
        Err(e) => row(label, format!("failed: {e}")),
    }
}

fn init_section(init: &InitInfo) -> Section {
    let caps = init.capabilities;
    let mut names = Vec::new();
    if caps & capability::WINK != 0 {
        names.push("WINK");
    }
    if caps & capability::CBOR != 0 {
        names.push("CBOR (CTAP2)");
    }
    if caps & capability::NMSG != 0 {
        names.push("NMSG (no U2F)");
    } else {
        names.push("MSG (U2F)");
    }
    let (major, minor, build) = init.device_version;
    Section {
        title: "CTAPHID".into(),
        rows: vec![
            row("Protocol version", init.protocol_version.to_string()),
            row_note("Device version", format!("{major}.{minor}.{build}"), "vendor-defined"),
            row("Capabilities", format!("{caps:#04x}  {}", names.join(", "))),
            row_note("Channel", format!("{:#010x}", init.channel), "allocated for this session"),
        ],
    }
}

/// Lay out a getInfo map: known members by name, unknown ones as raw CBOR.
pub fn get_info_section(info: &Value) -> Section {
    let mut rows = Vec::new();
    let Some(entries) = info.as_map() else {
        return Section { title: "CTAP2 getInfo".into(), rows: vec![row("Reply", info.to_string())] };
    };
    for (key, value) in entries {
        let Some(k) = key.as_int() else {
            rows.push(row(key.to_string(), value.to_string()));
            continue;
        };
        match k {
            0x03 => rows.push(aaguid_row(value)),
            0x04 => {
                rows.push(row("options", ""));
                for (name, v) in value.as_map().unwrap_or_default() {
                    let name = name.as_text().map_or_else(|| name.to_string(), str::to_owned);
                    let note = option_note(&name, v);
                    rows.push(Row { label: format!("  {name}"), value: v.to_string(), note });
                }
            }
            0x0A => {
                let algs: Vec<String> = value
                    .as_array()
                    .unwrap_or_default()
                    .iter()
                    .map(|a| {
                        let alg = a.get(&Value::Text("alg".into())).and_then(Value::as_int);
                        match alg {
                            Some(n) => match cose_alg_name(n) {
                                Some(name) => format!("{name} ({n})"),
                                None => n.to_string(),
                            },
                            None => a.to_string(),
                        }
                    })
                    .collect();
                rows.push(row("algorithms", algs.join(", ")));
            }
            _ => {
                let (label, note) = get_info_member(k);
                let shown = match value {
                    Value::Array(a) if a.iter().all(|v| v.as_text().is_some()) => {
                        a.iter().filter_map(Value::as_text).collect::<Vec<_>>().join(", ")
                    }
                    other => other.to_string(),
                };
                rows.push(Row { label, value: shown, note: note.map(str::to_owned) });
            }
        }
    }
    Section { title: "CTAP2 getInfo".into(), rows }
}

fn aaguid_row(value: &Value) -> Row {
    let Some(b) = value.as_bytes().filter(|b| b.len() == 16) else { return row("aaguid", value.to_string()) };
    let h = hex(b);
    let uuid = format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]);
    let note = if b == JOTAKEY_AAGUID {
        Some("Jotakey".to_owned())
    } else if b.iter().all(|&x| x == 0) {
        Some("all zero: the key does not identify its model".to_owned())
    } else {
        Some("model ID; look it up in the FIDO Metadata Service".to_owned())
    };
    Row { label: "aaguid".into(), value: uuid, note }
}

/// Name and explanation of getInfo member `key` (CTAP 2.1 §6.4, CTAP 2.2).
fn get_info_member(key: i128) -> (String, Option<&'static str>) {
    let (name, note) = match key {
        0x01 => ("versions", Some("protocol versions spoken")),
        0x02 => ("extensions", None),
        0x05 => ("maxMsgSize", Some("largest request, in bytes")),
        0x06 => ("pinUvAuthProtocols", None),
        0x07 => ("maxCredentialCountInList", Some("credential IDs per allow/exclude list")),
        0x08 => ("maxCredentialIdLength", None),
        0x09 => ("transports", None),
        0x0B => ("maxSerializedLargeBlobArray", None),
        0x0C => ("forcePINChange", None),
        0x0D => ("minPINLength", None),
        0x0E => ("firmwareVersion", None),
        0x0F => ("maxCredBlobLength", None),
        0x10 => ("maxRPIDsForSetMinPINLength", None),
        0x11 => ("preferredPlatformUvAttempts", None),
        0x12 => ("uvModality", Some("bit field of built-in verification methods")),
        0x13 => ("certifications", None),
        0x14 => ("remainingDiscoverableCredentials", Some("free passkey slots")),
        0x15 => ("vendorPrototypeConfigCommands", None),
        0x16 => ("attestationFormats", None),
        0x17 => ("uvCountSinceLastPinEntry", None),
        0x18 => ("longTouchForReset", None),
        _ => return (format!("member {key:#04x}"), Some("not known to this explorer")),
    };
    (name.to_owned(), note)
}

fn option_note(name: &str, v: &Value) -> Option<String> {
    let on = *v == Value::Bool(true);
    let s = match (name, on) {
        ("rk", true) => "stores discoverable credentials (passkeys)",
        ("rk", false) => "no discoverable credentials: sites must send credential IDs",
        ("up", true) => "can test user presence (a touch)",
        ("uv", true) => "built-in user verification (e.g. fingerprint) is set up",
        ("uv", false) => "built-in user verification exists but is not set up",
        ("plat", true) => "built into the computer, not removable",
        ("plat", false) => "a removable (roaming) authenticator",
        ("clientPin", true) => "a PIN is set",
        ("clientPin", false) => "PINs supported, none set yet",
        ("pinUvAuthToken", true) => "CTAP 2.1 PIN/UV tokens with permissions",
        ("credMgmt" | "credentialMgmtPreview", true) => "can list and delete stored passkeys",
        ("bioEnroll" | "userVerificationMgmtPreview", true) => "fingerprints enrolled",
        ("bioEnroll" | "userVerificationMgmtPreview", false) => "fingerprint sensor, nothing enrolled",
        ("largeBlobs", true) => "stores large blobs for relying parties",
        ("ep", _) => "enterprise attestation",
        ("alwaysUv", true) => "always asks for the PIN or fingerprint",
        ("makeCredUvNotRqd", true) => "registration without UV allowed for non-discoverable credentials",
        ("setMinPINLength", true) => "minimum PIN length can be raised",
        ("authnrCfg", true) => "supports authenticatorConfig",
        _ => return None,
    };
    Some(s.to_owned())
}

/// COSE algorithm names (IANA registry) for the identifiers keys commonly list.
pub fn cose_alg_name(alg: i128) -> Option<&'static str> {
    Some(match alg {
        -7 => "ES256",
        -8 => "EdDSA",
        -9 => "ESP256",
        -35 => "ES384",
        -36 => "ES512",
        -37 => "PS256",
        -47 => "ES256K",
        -257 => "RS256",
        _ => return None,
    })
}

/// CTAP status code names for the codes these queries can produce.
pub fn ctap_status(status: u8) -> String {
    let name = match status {
        0x01 => "invalid command",
        0x02 => "invalid parameter",
        0x03 => "invalid length",
        0x11 => "CBOR unexpected type",
        0x12 => "invalid CBOR",
        0x2B => "unsupported option",
        0x31 => "PIN invalid",
        0x32 => "PIN blocked",
        0x35 => "PIN not set",
        0x7F => "other",
        _ => "unknown",
    };
    format!("CTAP status {status:#04x} ({name})")
}

/// Blink the device, if it can.
pub fn wink<T: Transport>(io: T) -> Result<(), Error> {
    let (mut client, init) = Client::connect(io)?;
    if init.capabilities & capability::WINK == 0 {
        return Err(Error::Protocol("this device does not support WINK".into()));
    }
    client.wink()
}
