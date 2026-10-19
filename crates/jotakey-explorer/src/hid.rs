// (c) Javier Fernandez @ JotaSoft 2026
//! HID report descriptors (USB HID 1.11 §6.2.2), decoded item by item.
//!
//! A report descriptor is a little program the device hands the host: a stream of short
//! items (one prefix byte, then 0, 1, 2 or 4 data bytes) that set up state (*global* and
//! *local* items) and then declare a report field or a collection (*main* items). This
//! module prints each item the way `hid-decode` or the USB-IF's HID Descriptor Tool would,
//! and adds up how long each report is. The descriptor comes from the device, so it is
//! untrusted: every read is bounds-checked and a malformed tail is reported, not trusted.

use std::collections::BTreeMap;

/// One decoded item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Offset of the prefix byte in the descriptor.
    pub offset: usize,
    /// The item's bytes, prefix included.
    pub bytes: Vec<u8>,
    /// Collection nesting depth at this item (for indentation).
    pub depth: usize,
    /// Human-readable form, e.g. `Usage Page (FIDO Alliance)`.
    pub text: String,
}

/// Input, output or feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportKind {
    /// Device to host.
    Input,
    /// Host to device.
    Output,
    /// Read and written with control transfers.
    Feature,
}

impl std::fmt::Display for ReportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Input => "Input",
            Self::Output => "Output",
            Self::Feature => "Feature",
        })
    }
}

/// A decoded descriptor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    /// Every item, in order.
    pub items: Vec<Item>,
    /// Length in bits of each report, by (kind, report ID; 0 when the device uses none).
    pub reports: BTreeMap<(ReportKind, u8), u32>,
    /// Why decoding stopped early, if it did.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Default)]
struct Globals {
    usage_page: u32,
    report_size: u32,
    report_count: u32,
    report_id: u8,
}

/// Decode `bytes`.
pub fn decode(bytes: &[u8]) -> Descriptor {
    let mut d = Descriptor::default();
    let mut globals = Globals::default();
    let mut stack: Vec<Globals> = Vec::new();
    let mut depth = 0usize;
    let mut i = 0usize;
    while let Some(&prefix) = bytes.get(i) {
        if prefix == 0xFE {
            // Long item: bDataSize, bLongItemTag, data. None are defined; show and skip.
            let Some(&size) = bytes.get(i + 1) else {
                d.error = Some(format!("long item at {i:#06x} is truncated"));
                break;
            };
            let end = i + 3 + usize::from(size);
            let Some(raw) = bytes.get(i..end) else {
                d.error = Some(format!("long item at {i:#06x} is truncated"));
                break;
            };
            d.items.push(Item { offset: i, bytes: raw.to_vec(), depth, text: format!("Long Item ({size} bytes)") });
            i = end;
            continue;
        }
        let size = [0, 1, 2, 4][usize::from(prefix & 0x03)];
        let Some(raw) = bytes.get(i..i + 1 + size) else {
            d.error = Some(format!("item at {i:#06x} needs {size} data bytes, {} left", bytes.len() - i - 1));
            break;
        };
        let data = raw[1..].iter().rev().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
        let signed = sign_extend(data, size);
        let tag = prefix >> 4;
        let mut item_depth = depth;
        let text = match (prefix >> 2) & 0x03 {
            0 => match tag {
                0x8 | 0x9 | 0xB => {
                    let kind = match tag {
                        0x8 => ReportKind::Input,
                        0x9 => ReportKind::Output,
                        _ => ReportKind::Feature,
                    };
                    let bits = globals.report_size.saturating_mul(globals.report_count);
                    let total = d.reports.entry((kind, globals.report_id)).or_insert(0);
                    *total = total.saturating_add(bits);
                    format!("{kind} ({})", main_flags(data, kind))
                }
                0xA => {
                    depth += 1;
                    format!("Collection ({})", collection_name(data))
                }
                0xC => {
                    depth = depth.saturating_sub(1);
                    item_depth = depth;
                    "End Collection".to_owned()
                }
                t => format!("Main item {t:#x} ({data:#x})"),
            },
            1 => match tag {
                0x0 => {
                    globals.usage_page = data;
                    format!("Usage Page ({})", usage_page_name(data))
                }
                0x1 => format!("Logical Minimum ({signed})"),
                0x2 => format!("Logical Maximum ({signed})"),
                0x3 => format!("Physical Minimum ({signed})"),
                0x4 => format!("Physical Maximum ({signed})"),
                0x5 => format!("Unit Exponent ({signed})"),
                0x6 => format!("Unit ({data:#x})"),
                0x7 => {
                    globals.report_size = data;
                    format!("Report Size ({data})")
                }
                0x8 => {
                    globals.report_id = u8::try_from(data).unwrap_or(u8::MAX);
                    format!("Report ID ({data})")
                }
                0x9 => {
                    globals.report_count = data;
                    format!("Report Count ({data})")
                }
                0xA => {
                    stack.push(globals);
                    "Push".to_owned()
                }
                0xB => {
                    globals = stack.pop().unwrap_or_default();
                    "Pop".to_owned()
                }
                t => format!("Global item {t:#x} ({data:#x})"),
            },
            2 => match tag {
                0x0 => format!("Usage ({})", usage_name(globals.usage_page, data, size)),
                0x1 => format!("Usage Minimum ({})", usage_name(globals.usage_page, data, size)),
                0x2 => format!("Usage Maximum ({})", usage_name(globals.usage_page, data, size)),
                0x3 => format!("Designator Index ({data})"),
                0x4 => format!("Designator Minimum ({data})"),
                0x5 => format!("Designator Maximum ({data})"),
                0x7 => format!("String Index ({data})"),
                0x8 => format!("String Minimum ({data})"),
                0x9 => format!("String Maximum ({data})"),
                0xA => format!("Delimiter ({data})"),
                t => format!("Local item {t:#x} ({data:#x})"),
            },
            _ => format!("Reserved item {prefix:#04x}"),
        };
        d.items.push(Item { offset: i, bytes: raw.to_vec(), depth: item_depth, text });
        i += 1 + size;
    }
    if d.error.is_none() && depth != 0 {
        d.error = Some(format!("{depth} collection(s) left open"));
    }
    d
}

fn sign_extend(data: u32, size: usize) -> i64 {
    match size {
        1 => i64::from(data as u8 as i8),
        2 => i64::from(data as u16 as i16),
        4 => i64::from(data as i32),
        _ => 0,
    }
}

fn main_flags(data: u32, kind: ReportKind) -> String {
    let bit = |n: u32| data & (1 << n) != 0;
    let mut f = vec![
        if bit(0) { "Const" } else { "Data" },
        if bit(1) { "Var" } else { "Array" },
        if bit(2) { "Rel" } else { "Abs" },
    ];
    let extra: [(u32, &str); 5] = [(3, "Wrap"), (4, "NonLinear"), (5, "NoPreferred"), (6, "Null"), (8, "Buffered")];
    for (n, name) in extra {
        if bit(n) {
            f.push(name);
        }
    }
    if kind != ReportKind::Input && bit(7) {
        f.push("Volatile");
    }
    f.join(", ")
}

fn collection_name(data: u32) -> String {
    match data {
        0x00 => "Physical".into(),
        0x01 => "Application".into(),
        0x02 => "Logical".into(),
        0x03 => "Report".into(),
        0x04 => "Named Array".into(),
        0x05 => "Usage Switch".into(),
        0x06 => "Usage Modifier".into(),
        0x80..=0xFF => format!("vendor {data:#04x}"),
        _ => format!("reserved {data:#04x}"),
    }
}

/// Names of the usage pages FIDO keys and their composite siblings use (HID Usage Tables).
pub fn usage_page_name(page: u32) -> String {
    let name = match page {
        0x01 => "Generic Desktop",
        0x07 => "Keyboard/Keypad",
        0x08 => "LEDs",
        0x09 => "Button",
        0x0C => "Consumer",
        0x0D => "Digitizers",
        0x0F => "Physical Input Device",
        0xF1D0 => "FIDO Alliance",
        0xFF00..=0xFFFF => return format!("Vendor {page:#06x}"),
        _ => return format!("{page:#06x}"),
    };
    name.to_owned()
}

/// A usage's name on its page; a 4-byte usage carries its own page in the high half.
fn usage_name(page: u32, data: u32, size: usize) -> String {
    let (page, id) = if size == 4 { (data >> 16, data & 0xFFFF) } else { (page, data) };
    let known = match (page, id) {
        (0xF1D0, 0x01) => Some("CTAPHID"),
        (0xF1D0, 0x20) => Some("Input Report Data"),
        (0xF1D0, 0x21) => Some("Output Report Data"),
        (0x01, 0x02) => Some("Mouse"),
        (0x01, 0x06) => Some("Keyboard"),
        (0x01, 0x30) => Some("X"),
        (0x01, 0x31) => Some("Y"),
        (0x01, 0x38) => Some("Wheel"),
        (0x0C, 0x01) => Some("Consumer Control"),
        _ => None,
    };
    let base = match known {
        Some(n) => n.to_owned(),
        None => format!("{id:#04x}"),
    };
    if size == 4 { format!("{}: {base}", usage_page_name(page)) } else { base }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// jotakey-bridge's descriptor, which is also what most FIDO keys send.
    const FIDO: &[u8] = &[
        0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
        0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
        0x02, 0xC0,
    ];

    #[test]
    fn decodes_the_fido_descriptor() {
        let d = decode(FIDO);
        assert_eq!(d.error, None);
        let texts: Vec<(usize, &str)> = d.items.iter().map(|i| (i.depth, i.text.as_str())).collect();
        assert_eq!(
            texts,
            [
                (0, "Usage Page (FIDO Alliance)"),
                (0, "Usage (CTAPHID)"),
                (0, "Collection (Application)"),
                (1, "Usage (Input Report Data)"),
                (1, "Logical Minimum (0)"),
                (1, "Logical Maximum (255)"),
                (1, "Report Size (8)"),
                (1, "Report Count (64)"),
                (1, "Input (Data, Var, Abs)"),
                (1, "Usage (Output Report Data)"),
                (1, "Logical Minimum (0)"),
                (1, "Logical Maximum (255)"),
                (1, "Report Size (8)"),
                (1, "Report Count (64)"),
                (1, "Output (Data, Var, Abs)"),
                (0, "End Collection"),
            ]
        );
        assert_eq!(d.items[0].offset, 0);
        assert_eq!(d.items[0].bytes, [0x06, 0xD0, 0xF1]);
        assert_eq!(d.items[15].offset, 33);
        assert_eq!(d.reports, BTreeMap::from([((ReportKind::Input, 0), 512), ((ReportKind::Output, 0), 512)]));
    }

    #[test]
    fn report_ids_push_pop_and_signed_values() {
        // Report ID 2, 8 x 1-bit buttons and a signed 8-bit axis; Push/Pop restores the size.
        let d = decode(&[
            0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x02, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xA4, 0x75,
            0x08, 0x95, 0x01, 0x15, 0x81, 0x25, 0x7F, 0x81, 0x06, 0xB4, 0x95, 0x02, 0xB1, 0x03, 0xC0,
        ]);
        assert_eq!(d.error, None);
        assert!(d.items.iter().any(|i| i.text == "Logical Minimum (-127)"));
        assert!(d.items.iter().any(|i| i.text == "Input (Data, Var, Rel)"));
        assert!(d.items.iter().any(|i| i.text == "Feature (Const, Var, Abs)"));
        // Input: 8 + 8 bits; Feature: after Pop, size 1 again, count 2.
        assert_eq!(d.reports[&(ReportKind::Input, 2)], 16);
        assert_eq!(d.reports[&(ReportKind::Feature, 2)], 2);
    }

    #[test]
    fn malformed_descriptors_are_reported_not_trusted() {
        assert_eq!(decode(&FIDO[..2]).error.as_deref(), Some("item at 0x0000 needs 2 data bytes, 1 left"));
        assert_eq!(decode(&FIDO[..20]).error.as_deref(), Some("1 collection(s) left open"));
        assert!(decode(&[0xFE, 0x05, 0x00, 1]).error.unwrap().contains("long item"));
        let long = decode(&[0xFE, 0x01, 0x10, 0xAA]);
        assert_eq!((long.items[0].text.as_str(), long.error), ("Long Item (1 bytes)", None));
        assert_eq!(decode(&[0xC0, 0xC0]).items[1].depth, 0, "stray End Collection does not underflow");
        assert_eq!(decode(&[]), Descriptor::default());
        // A 4-byte usage names its own page.
        assert_eq!(decode(&[0x0B, 0x01, 0x00, 0xD0, 0xF1]).items[0].text, "Usage (FIDO Alliance: CTAPHID)");
        assert_eq!(usage_page_name(0xFF31), "Vendor 0xff31");
    }
}
