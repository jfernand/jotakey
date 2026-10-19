// (c) Javier Fernandez @ JotaSoft 2026
//! Find FIDO devices among the hidraw nodes, using sysfs only (no device I/O).
//!
//! A HID device is a FIDO authenticator when its report descriptor has a top-level
//! application collection with usage page `0xF1D0` and usage `0x01` (CTAP 2.1 §11.2.1).
//! That works for USB keys, Bluetooth HID keys and virtual ones such as the device
//! `jotakey-bridge` creates through `/dev/uhid`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The FIDO Alliance's HID usage page.
pub const FIDO_USAGE_PAGE: u32 = 0xF1D0;
/// "CTAPHID" usage within it.
pub const FIDO_USAGE_CTAPHID: u32 = 0x01;

/// How the device is attached, from the HID bus number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bus {
    /// USB (also used by `/dev/uhid` devices that claim to be USB, such as the bridge).
    Usb,
    /// Bluetooth (classic HID or HID over GATT).
    Bluetooth,
    /// I²C, virtual, or anything else: the raw bus number.
    Other(u16),
}

impl std::fmt::Display for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usb => f.write_str("USB"),
            Self::Bluetooth => f.write_str("Bluetooth"),
            Self::Other(n) => write!(f, "bus {n:#06x}"),
        }
    }
}

/// One FIDO HID device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// Device node, e.g. `/dev/hidraw3`.
    pub path: PathBuf,
    /// How it is attached.
    pub bus: Bus,
    /// USB vendor ID.
    pub vendor_id: u16,
    /// USB product ID.
    pub product_id: u16,
    /// The kernel's name for it (`HID_NAME`): usually "manufacturer product".
    pub name: String,
    /// Physical location (`HID_PHYS`): USB port path or Bluetooth address.
    pub phys: String,
    /// USB descriptor strings and release number, when the device is on a real USB bus.
    pub usb: Option<UsbStrings>,
    /// Whether the kernel's sysfs path says the device is virtual (uhid).
    pub virtual_device: bool,
}

/// What the USB device descriptor says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsbStrings {
    /// iManufacturer.
    pub manufacturer: Option<String>,
    /// iProduct.
    pub product: Option<String>,
    /// iSerialNumber.
    pub serial: Option<String>,
    /// bcdDevice, the device release number.
    pub release: Option<String>,
    /// Negotiated speed in Mbit/s.
    pub speed: Option<String>,
}

impl Device {
    /// A short label for lists: the product name, or the kernel's name.
    pub fn label(&self) -> String {
        let product = self.usb.as_ref().and_then(|u| u.product.clone());
        let name = product.unwrap_or_else(|| self.name.clone());
        if name.is_empty() { format!("{:04x}:{:04x}", self.vendor_id, self.product_id) } else { name }
    }

    /// The device node's file name, e.g. `hidraw3`.
    pub fn node(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    /// Who the vendor ID belongs to, for the IDs FIDO keys commonly use.
    pub fn vendor_name(&self) -> Option<&'static str> {
        vendor_name(self.vendor_id, self.product_id)
    }
}

/// Owners of some vendor IDs seen on FIDO keys.
pub fn vendor_name(vendor_id: u16, product_id: u16) -> Option<&'static str> {
    Some(match (vendor_id, product_id) {
        (0x1209, 0x0001) => "Jotakey through jotakey-bridge (pid.codes test ID)",
        (0x1209, _) => "pid.codes (open-source hardware)",
        (0x1050, _) => "Yubico",
        (0x096e, _) => "Feitian",
        (0x18d1, _) => "Google",
        (0x20a0, _) => "Nitrokey (Clay Logic)",
        _ => return None,
    })
}

/// All FIDO devices, sorted by node name.
pub fn scan() -> io::Result<Vec<Device>> {
    scan_in(Path::new("/sys/class/hidraw"), Path::new("/dev"))
}

/// [`scan`] over a given sysfs class directory and device directory (for tests).
pub fn scan_in(class_dir: &Path, dev_dir: &Path) -> io::Result<Vec<Device>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(class_dir)? {
        let entry = entry?;
        let hid = entry.path().join("device");
        let Ok(descriptor) = fs::read(hid.join("report_descriptor")) else { continue };
        if !is_fido(&descriptor) {
            continue;
        }
        let uevent = fs::read_to_string(hid.join("uevent")).unwrap_or_default();
        let field = |key: &str| {
            uevent.lines().find_map(|l| l.strip_prefix(key)).map(str::to_owned).unwrap_or_default()
        };
        let (bus, vendor_id, product_id) = parse_hid_id(&field("HID_ID=")).unwrap_or((Bus::Other(0), 0, 0));
        let real = fs::canonicalize(&hid).unwrap_or_else(|_| hid.clone());
        found.push(Device {
            path: dev_dir.join(entry.file_name()),
            bus,
            vendor_id,
            product_id,
            name: field("HID_NAME="),
            phys: field("HID_PHYS="),
            usb: usb_strings(&real),
            virtual_device: real.components().any(|c| c.as_os_str() == "virtual"),
        });
    }
    found.sort_by_key(|d| node_number(&d.path));
    Ok(found)
}

fn node_number(path: &Path) -> (u64, String) {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let digits: String = name.chars().filter(char::is_ascii_digit).collect();
    (digits.parse().unwrap_or(u64::MAX), name)
}

/// `HID_ID=0003:00001209:00000001` → (USB, 0x1209, 0x0001).
fn parse_hid_id(s: &str) -> Option<(Bus, u16, u16)> {
    let mut it = s.split(':');
    let bus = u16::from_str_radix(it.next()?, 16).ok()?;
    let vendor = u32::from_str_radix(it.next()?, 16).ok()?;
    let product = u32::from_str_radix(it.next()?, 16).ok()?;
    let bus = match bus {
        0x03 => Bus::Usb,
        0x05 => Bus::Bluetooth,
        n => Bus::Other(n),
    };
    Some((bus, u16::try_from(vendor).ok()?, u16::try_from(product).ok()?))
}

/// The USB device above a HID device in sysfs: the first ancestor with `idVendor`.
fn usb_strings(hid: &Path) -> Option<UsbStrings> {
    let usb = hid.ancestors().skip(1).take(4).find(|p| p.join("idVendor").is_file())?;
    let read = |f: &str| fs::read_to_string(usb.join(f)).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    Some(UsbStrings {
        manufacturer: read("manufacturer"),
        product: read("product"),
        serial: read("serial"),
        release: read("bcdDevice").map(|b| {
            // BCD "0543" → "5.43"
            let b = b.trim_start_matches('0');
            if b.len() > 2 { format!("{}.{}", &b[..b.len() - 2], &b[b.len() - 2..]) } else { format!("0.{b:0>2}") }
        }),
        speed: read("speed"),
    })
}

/// Whether a HID report descriptor declares a FIDO CTAPHID application collection.
pub fn is_fido(descriptor: &[u8]) -> bool {
    let mut usage_page = 0u32;
    let mut usages: Vec<u32> = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(&prefix) = descriptor.get(i) {
        if prefix == 0xFE {
            // Long item: size in the next byte, tag after it.
            let size = usize::from(*descriptor.get(i + 1).unwrap_or(&0));
            i += 3 + size;
            continue;
        }
        let size = [0, 1, 2, 4][usize::from(prefix & 0x03)];
        let Some(bytes) = descriptor.get(i + 1..i + 1 + size) else { return false };
        let data = bytes.iter().rev().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
        i += 1 + size;
        match (prefix >> 2) & 0x03 {
            // Main items.
            0 => {
                match prefix >> 4 {
                    0xA => {
                        // Collection: Application (0x01) at the top level.
                        let application = data == 0x01 && depth == 0;
                        let fido = usages.iter().any(|&u| {
                            let page = if u > 0xFFFF { u >> 16 } else { usage_page };
                            page == FIDO_USAGE_PAGE && (u & 0xFFFF) == FIDO_USAGE_CTAPHID
                        });
                        if application && fido {
                            return true;
                        }
                        depth += 1;
                    }
                    0xC => depth = depth.saturating_sub(1), // End Collection
                    _ => {}
                }
                usages.clear(); // local items last until the next main item
            }
            // Global: Usage Page.
            1 if prefix >> 4 == 0x0 => usage_page = data,
            // Local: Usage (4-byte usages carry their own page).
            2 if prefix >> 4 == 0x0 => usages.push(if size == 4 { data } else { data & 0xFFFF }),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor jotakey-bridge registers (and most FIDO keys use): usage page F1D0,
    /// usage 01, application collection, 64-byte input and output reports.
    const FIDO: &[u8] = &[
        0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
        0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
        0x02, 0xC0,
    ];
    /// A boot keyboard's first items: generic desktop page, keyboard usage.
    const KEYBOARD: &[u8] = &[0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0xC0];

    #[test]
    fn recognises_fido_descriptors_only() {
        assert!(is_fido(FIDO));
        assert!(!is_fido(KEYBOARD));
        // A YubiKey-style composite device: keyboard collection first, then FIDO.
        assert!(is_fido(&[KEYBOARD, FIDO].concat()));
        // A 4-byte usage carrying the FIDO page itself.
        assert!(is_fido(&[0x05, 0x01, 0x0B, 0x01, 0x00, 0xD0, 0xF1, 0xA1, 0x01, 0xC0]));
        // FIDO usage on a nested (non-top-level) collection does not count.
        assert!(!is_fido(&[0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0xC0, 0xC0]));
        // Truncated input is simply not FIDO.
        assert!(!is_fido(&FIDO[..2]));
        assert!(!is_fido(&[]));
    }

    #[test]
    fn hid_ids_parse() {
        assert_eq!(parse_hid_id("0003:00001209:00000001"), Some((Bus::Usb, 0x1209, 0x0001)));
        assert_eq!(parse_hid_id("0005:0000046D:0000B031"), Some((Bus::Bluetooth, 0x046D, 0xB031)));
        assert_eq!(parse_hid_id("garbage"), None);
    }

    #[test]
    fn scans_a_fake_sysfs_tree() {
        let root = std::env::temp_dir().join(format!("jotakey-explorer-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let add = |node: &str, descriptor: &[u8], hid_id: &str, name: &str| {
            let dev = root.join("class").join(node).join("device");
            fs::create_dir_all(&dev).unwrap();
            fs::write(dev.join("report_descriptor"), descriptor).unwrap();
            fs::write(dev.join("uevent"), format!("HID_ID={hid_id}\nHID_NAME={name}\nHID_PHYS=usb-1/input1\n")).unwrap();
        };
        add("hidraw10", FIDO, "0003:00001209:00000001", "Jotakey");
        add("hidraw2", KEYBOARD, "0003:0000046D:0000C31C", "Keyboard");
        add("hidraw3", FIDO, "0003:00001050:00000407", "Yubico YubiKey OTP+FIDO+CCID");
        let found = scan_in(&root.join("class"), Path::new("/dev")).unwrap();
        fs::remove_dir_all(&root).unwrap();

        let nodes: Vec<String> = found.iter().map(Device::node).collect();
        assert_eq!(nodes, ["hidraw3", "hidraw10"], "FIDO only, in numeric order");
        assert_eq!(found[0].vendor_name(), Some("Yubico"));
        assert_eq!(found[1].label(), "Jotakey");
        assert_eq!(found[1].path, Path::new("/dev/hidraw10"));
    }
}
