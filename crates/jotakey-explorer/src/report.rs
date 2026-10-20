// (c) Javier Fernandez @ JotaSoft 2026
//! Ask a device what it is, and lay the answers out as labelled sections.
//!
//! **Read-only by construction.** The only requests sent are CTAPHID INIT, CTAP2
//! `authenticatorGetInfo`, `authenticatorClientPIN` getPINRetries/getUVRetries (when the
//! key says it has a PIN or built-in UV), and the U2F `VERSION` APDU. None of them needs a
//! touch, creates or uses a credential, or changes any state on the key; the retry
//! counters are read, never spent. WINK (the `w` key) only blinks the device. The USB and
//! HID descriptors come from sysfs, without any I/O to the device.

use crate::cbor::{Value, hex};
use crate::ctaphid::{Client, Error, InitInfo, Transport, capability};
use crate::discover::{Device, UsbInfo};
use crate::hid;

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
    }
    Section { title: "Device".into(), rows }
}

/// Everything sysfs says, before any I/O: the device, its USB descriptors and its HID
/// report descriptor. Shown while a query runs and when the device cannot be opened.
pub fn local_sections(d: &Device) -> Vec<Section> {
    vec![device_section(d), usb_section(d), hid_section(d)]
}

/// The USB device, configuration, interface and endpoint descriptors.
pub fn usb_section(d: &Device) -> Section {
    let title = "USB".to_owned();
    let Some(u) = &d.usb else {
        let note = if d.virtual_device {
            if (d.vendor_id, d.product_id) == (0x1209, 0x0001) {
                "a virtual HID device made through /dev/uhid by jotakey-bridge; the C6 itself enumerates as a USB serial device"
            } else {
                "a virtual HID device made through /dev/uhid: there is no USB device behind it"
            }
        } else {
            "not on a USB bus"
        };
        return Section { title, rows: vec![row_note("Descriptors", "none", note)] };
    };
    let mut rows = Vec::new();
    if let Some(v) = &u.usb_version {
        rows.push(row_note("USB version", v.clone(), "bcdUSB: the version the device claims"));
    }
    if let Some(s) = &u.speed {
        let name = match s.as_str() {
            "1.5" => Some("low speed"),
            "12" => Some("full speed, as most security keys"),
            "480" => Some("high speed"),
            "5000" | "10000" | "20000" => Some("SuperSpeed"),
            _ => None,
        };
        rows.push(Row { label: "Speed".into(), value: format!("{s} Mbit/s"), note: name.map(str::to_owned) });
    }
    if let Some((bus, dev)) = &u.address {
        rows.push(row_note("Address", format!("bus {bus}, device {dev}"), "as lsusb shows it"));
    }
    if let Some((class, sub, proto)) = &u.device_class {
        let note = match class.as_str() {
            "00" => "defined per interface",
            "ef" => "miscellaneous: a composite device with interface associations",
            "ff" => "vendor-specific",
            _ => "bDeviceClass/SubClass/Protocol",
        };
        rows.push(row_note("Device class", format!("{class}/{sub}/{proto}"), note));
    }
    if let Some(m) = &u.max_packet_size0 {
        rows.push(row_note("Control endpoint", format!("{m} bytes"), "bMaxPacketSize0 of endpoint 0"));
    }
    if let (Some(active), Some(count)) = (&u.configuration, &u.configurations) {
        rows.push(row_note(
            "Configuration",
            format!("{active} of {count}"),
            "bConfigurationValue of bNumConfigurations",
        ));
    }
    if let Some(p) = &u.max_power {
        let note = u.attributes.map(power_note).unwrap_or_default();
        rows.push(Row { label: "Max power".into(), value: p.clone(), note: (!note.is_empty()).then_some(note) });
    }
    if let Some(n) = &u.interfaces {
        rows.push(row_note("Interfaces", n.clone(), "a FIDO key with OTP or smart-card functions has several"));
    }
    if let Some(r) = &u.removable {
        rows.push(row("Port", r.clone()));
    }
    rows.extend(interface_rows(u));
    Section { title, rows }
}

/// bmAttributes of a configuration, in words.
fn power_note(attributes: u8) -> String {
    let mut parts = vec![if attributes & 0x40 != 0 { "self-powered" } else { "bus-powered" }];
    if attributes & 0x20 != 0 {
        parts.push("remote wakeup");
    }
    format!("{} (bmAttributes {attributes:#04x})", parts.join(", "))
}

fn interface_rows(u: &UsbInfo) -> Vec<Row> {
    let Some(i) = &u.interface else { return Vec::new() };
    let mut rows = Vec::new();
    let number = i.number.clone().unwrap_or_else(|| "?".into());
    match &i.class {
        Some((class, sub, proto)) => {
            let note = match (class.as_str(), sub.as_str(), proto.as_str()) {
                ("03", "00", _) => "HID, no boot protocol: how FIDO keys present themselves",
                ("03", "01", "01") => "HID boot keyboard (an OTP function typing codes)",
                ("03", _, _) => "HID",
                _ => "bInterfaceClass/SubClass/Protocol",
            };
            rows.push(row_note("HID interface", format!("#{number}, class {class}/{sub}/{proto}"), note));
        }
        None => rows.push(row("HID interface", format!("#{number}"))),
    }
    if let Some(n) = &i.name {
        rows.push(row("Interface name", n.clone()));
    }
    if let Some(drv) = &i.driver {
        rows.push(row_note("Driver", drv.clone(), "the kernel driver bound to the interface"));
    }
    for e in &i.endpoints {
        let dir = match e.direction.as_deref() {
            Some("in") => "IN (device to host)",
            Some("out") => "OUT (host to device)",
            Some(other) => other,
            None => "?",
        };
        let mut value = format!("{} {dir}", e.kind.as_deref().unwrap_or("?"));
        if let Some(m) = e.max_packet_size {
            value.push_str(&format!(", {m} bytes"));
        }
        if let Some(t) = &e.interval {
            value.push_str(&format!(", every {t}"));
        }
        let note = (e.max_packet_size == Some(64)).then(|| "one 64-byte CTAPHID packet per transfer".to_owned());
        rows.push(Row { label: format!("Endpoint 0x{}", e.address), value, note });
    }
    rows
}

/// The HID report descriptor: report lengths, then every item with its bytes.
pub fn hid_section(d: &Device) -> Section {
    let title = "HID report descriptor".to_owned();
    let bytes = &d.report_descriptor;
    if bytes.is_empty() {
        return Section { title, rows: vec![row("Descriptor", "not available")] };
    }
    let decoded = hid::decode(bytes);
    let mut rows = vec![row("Length", format!("{} bytes", bytes.len()))];
    for ((kind, id), bits) in &decoded.reports {
        let label = if *id == 0 { format!("{kind} report") } else { format!("{kind} report {id}") };
        let value = if bits % 8 == 0 { format!("{} bytes", bits / 8) } else { format!("{bits} bits") };
        let note = match (*id, *bits) {
            (0, 512) => Some("the CTAPHID packet size".to_owned()),
            (0, _) => None,
            _ => Some("plus the report ID byte on the wire".to_owned()),
        };
        rows.push(Row { label, value, note });
    }
    if let Some(e) = &decoded.error {
        rows.push(row_note("Problem", e.clone(), "decoding stopped here"));
    }
    for item in &decoded.items {
        let hex: Vec<String> = item.bytes.iter().map(|b| format!("{b:02x}")).collect();
        rows.push(row(
            format!("{:04x}  {}", item.offset, hex.join(" ")),
            format!("{}{}", "  ".repeat(item.depth), item.text),
        ));
    }
    Section { title, rows }
}

/// Query a device over `io` and describe it.
pub fn query<T: Transport>(device: &Device, io: T) -> Report {
    let mut report = Report { sections: vec![device_section(device), usb_section(device)], ..Report::default() };
    let (mut client, init) = match Client::connect(io) {
        Ok(c) => c,
        Err(e) => {
            report.problems.push(format!("CTAPHID INIT failed: {e}"));
            report.sections.push(hid_section(device));
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
            rows.push(retries(
                &mut client,
                0x07,
                5,
                "UV retries",
                "failed fingerprints left before falling back to the PIN",
            ));
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
    report.sections.push(hid_section(device));
    report
}

/// clientPIN getPINRetries (0x01, answer key 3) or getUVRetries (0x07, answer key 5).
fn retries<T: Transport>(client: &mut Client<T>, sub: u8, answer_key: i128, label: &str, note: &str) -> Row {
    // {1: pinUvAuthProtocol 1, 2: subCommand}
    let params = [0xA2, 0x01, 0x01, 0x02, sub];
    match client.cbor(CLIENT_PIN, &params) {
        Ok((0, body)) => {
            match Value::decode(&body).as_ref().and_then(|v| v.get_int(answer_key)).and_then(Value::as_int) {
                Some(n) => row_note(label, n.to_string(), note),
                None => row(label, "reply without a count"),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{Bus, UsbEndpoint, UsbInterface};

    fn yubikey() -> Device {
        Device {
            path: "/dev/hidraw7".into(),
            bus: Bus::Usb,
            vendor_id: 0x1050,
            product_id: 0x0407,
            name: "Yubico YubiKey OTP+FIDO+CCID".into(),
            phys: "usb-0000:00:14.0-2/input1".into(),
            usb: Some(UsbInfo {
                manufacturer: Some("Yubico".into()),
                product: Some("YubiKey OTP+FIDO+CCID".into()),
                release: Some("5.43".into()),
                speed: Some("12".into()),
                usb_version: Some("2.00".into()),
                address: Some(("3".into(), "9".into())),
                device_class: Some(("00".into(), "00".into(), "00".into())),
                max_packet_size0: Some("64".into()),
                configurations: Some("1".into()),
                configuration: Some("1".into()),
                max_power: Some("30mA".into()),
                attributes: Some(0xA0),
                interfaces: Some("3".into()),
                interface: Some(UsbInterface {
                    number: Some("01".into()),
                    class: Some(("03".into(), "00".into(), "00".into())),
                    driver: Some("usbhid".into()),
                    endpoints: vec![UsbEndpoint {
                        address: "84".into(),
                        kind: Some("Interrupt".into()),
                        direction: Some("in".into()),
                        max_packet_size: Some(64),
                        interval: Some("2ms".into()),
                    }],
                    ..UsbInterface::default()
                }),
                ..UsbInfo::default()
            }),
            virtual_device: false,
            report_descriptor: vec![
                0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x03, 0x75, 0x08, 0x95, 0x3F, 0x81, 0x02, 0xC0,
            ],
        }
    }

    fn find<'a>(s: &'a Section, label: &str) -> &'a Row {
        s.rows.iter().find(|r| r.label == label).unwrap_or_else(|| panic!("no row {label:?} in {s:?}"))
    }

    #[test]
    fn usb_section_describes_a_real_key() {
        let s = usb_section(&yubikey());
        assert_eq!(find(&s, "Speed").value, "12 Mbit/s");
        assert_eq!(find(&s, "Address").value, "bus 3, device 9");
        assert_eq!(find(&s, "Configuration").value, "1 of 1");
        assert_eq!(find(&s, "Max power").note.as_deref(), Some("bus-powered, remote wakeup (bmAttributes 0xa0)"));
        assert_eq!(find(&s, "HID interface").value, "#01, class 03/00/00");
        assert_eq!(find(&s, "Driver").value, "usbhid");
        assert_eq!(find(&s, "Endpoint 0x84").value, "Interrupt IN (device to host), 64 bytes, every 2ms");
        assert_eq!(power_note(0xC0), "self-powered (bmAttributes 0xc0)");
    }

    #[test]
    fn hid_section_sizes_reports_with_ids() {
        let s = hid_section(&yubikey());
        assert_eq!(find(&s, "Input report 3").value, "63 bytes");
        assert_eq!(find(&s, "Input report 3").note.as_deref(), Some("plus the report ID byte on the wire"));
        assert_eq!(find(&s, "0007  85 03").value, "  Report ID (3)");
        let mut broken = yubikey();
        broken.report_descriptor.truncate(15);
        assert_eq!(find(&hid_section(&broken), "Problem").value, "1 collection(s) left open");
        broken.report_descriptor.clear();
        assert_eq!(find(&hid_section(&broken), "Descriptor").value, "not available");
    }

    #[test]
    fn virtual_devices_have_no_usb_descriptors() {
        let mut d = yubikey();
        d.usb = None;
        d.virtual_device = true;
        assert!(find(&usb_section(&d), "Descriptors").note.as_deref().unwrap().contains("no USB device behind it"));
        d.vendor_id = 0x1209;
        d.product_id = 0x0001;
        assert!(find(&usb_section(&d), "Descriptors").note.as_deref().unwrap().contains("jotakey-bridge"));
    }
}
