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
    /// USB descriptors, when the device is on a real USB bus.
    pub usb: Option<UsbInfo>,
    /// Whether the kernel's sysfs path says the device is virtual (uhid).
    pub virtual_device: bool,
    /// The HID report descriptor, exactly as the device sent it.
    pub report_descriptor: Vec<u8>,
}

/// What the USB device, configuration, interface and endpoint descriptors say, as the
/// kernel exposes them in sysfs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsbInfo {
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
    /// bcdUSB, the USB version the device claims (e.g. "2.00").
    pub usb_version: Option<String>,
    /// Bus and device number, as `lsusb` shows them.
    pub address: Option<(String, String)>,
    /// bDeviceClass, bDeviceSubClass, bDeviceProtocol (hex).
    pub device_class: Option<(String, String, String)>,
    /// bMaxPacketSize0: the control endpoint's packet size.
    pub max_packet_size0: Option<String>,
    /// bNumConfigurations and the active bConfigurationValue.
    pub configurations: Option<String>,
    /// The active configuration.
    pub configuration: Option<String>,
    /// bMaxPower of the active configuration (e.g. "100mA").
    pub max_power: Option<String>,
    /// bmAttributes of the active configuration.
    pub attributes: Option<u8>,
    /// bNumInterfaces of the active configuration.
    pub interfaces: Option<String>,
    /// Whether the port says the device can be unplugged.
    pub removable: Option<String>,
    /// The HID interface itself.
    pub interface: Option<UsbInterface>,
}

/// A USB interface descriptor and its endpoints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsbInterface {
    /// bInterfaceNumber.
    pub number: Option<String>,
    /// bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol (hex).
    pub class: Option<(String, String, String)>,
    /// iInterface, if the device names it.
    pub name: Option<String>,
    /// The kernel driver bound to it (`usbhid`).
    pub driver: Option<String>,
    /// Endpoints other than endpoint 0, sorted by address.
    pub endpoints: Vec<UsbEndpoint>,
}

/// A USB endpoint descriptor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsbEndpoint {
    /// bEndpointAddress (hex), e.g. "81" (endpoint 1, IN).
    pub address: String,
    /// Transfer type: "Interrupt", "Bulk", …
    pub kind: Option<String>,
    /// "in" (device to host) or "out".
    pub direction: Option<String>,
    /// wMaxPacketSize in bytes.
    pub max_packet_size: Option<u16>,
    /// The polling interval, as the kernel computed it (e.g. "5ms").
    pub interval: Option<String>,
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
            usb: usb_info(&real),
            virtual_device: real.components().any(|c| c.as_os_str() == "virtual"),
            report_descriptor: descriptor,
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

fn read_attr(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// The USB device above a HID device in sysfs (the first ancestor with `idVendor`) and the
/// interface the HID device hangs off (its parent, which has `bInterfaceClass`).
fn usb_info(hid: &Path) -> Option<UsbInfo> {
    let usb = hid.ancestors().skip(1).take(4).find(|p| p.join("idVendor").is_file())?;
    let read = |f: &str| read_attr(usb, f);
    let triple = |dir: &Path, a: &str, b: &str, c: &str| Some((read_attr(dir, a)?, read_attr(dir, b)?, read_attr(dir, c)?));
    let interface = hid.parent().filter(|p| p.join("bInterfaceClass").is_file()).map(|dir| UsbInterface {
        number: read_attr(dir, "bInterfaceNumber"),
        class: triple(dir, "bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol"),
        name: read_attr(dir, "interface"),
        driver: fs::read_link(dir.join("driver"))
            .ok()
            .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned())),
        endpoints: endpoints(dir),
    });
    Some(UsbInfo {
        manufacturer: read("manufacturer"),
        product: read("product"),
        serial: read("serial"),
        release: read("bcdDevice").map(|b| bcd(&b)),
        speed: read("speed"),
        usb_version: read("version"),
        address: read("busnum").zip(read("devnum")),
        device_class: triple(usb, "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol"),
        max_packet_size0: read("bMaxPacketSize0"),
        configurations: read("bNumConfigurations"),
        configuration: read("bConfigurationValue"),
        max_power: read("bMaxPower"),
        attributes: read("bmAttributes").and_then(|a| u8::from_str_radix(&a, 16).ok()),
        interfaces: read("bNumInterfaces"),
        removable: read("removable"),
        interface,
    })
}

/// BCD "0543" → "5.43".
fn bcd(b: &str) -> String {
    let b = b.trim_start_matches('0');
    if b.len() > 2 { format!("{}.{}", &b[..b.len() - 2], &b[b.len() - 2..]) } else { format!("0.{b:0>2}") }
}

/// The `ep_XX` directories of an interface.
fn endpoints(interface: &Path) -> Vec<UsbEndpoint> {
    let Ok(entries) = fs::read_dir(interface) else { return Vec::new() };
    let mut found: Vec<UsbEndpoint> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("ep_"))
        .filter_map(|e| {
            let dir = e.path();
            Some(UsbEndpoint {
                address: read_attr(&dir, "bEndpointAddress")?,
                kind: read_attr(&dir, "type"),
                direction: read_attr(&dir, "direction"),
                max_packet_size: read_attr(&dir, "wMaxPacketSize").and_then(|m| u16::from_str_radix(&m, 16).ok()),
                interval: read_attr(&dir, "interval"),
            })
        })
        .collect();
    found.sort_by(|a, b| a.address.cmp(&b.address));
    found
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
        assert_eq!(found[1].report_descriptor, FIDO);
        assert_eq!(found[1].usb, None, "no USB device above it");
    }

    #[test]
    fn reads_usb_descriptors_from_sysfs() {
        // usb device 3-2 → interface 3-2:1.0 (with ep_81, ep_02) → HID device.
        let root = std::env::temp_dir().join(format!("jotakey-explorer-usb-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let usb = root.join("3-2");
        let interface = usb.join("3-2:1.0");
        let hid = interface.join("0003:1050:0407.0005");
        fs::create_dir_all(&hid).unwrap();
        let write = |dir: &Path, name: &str, value: &str| fs::write(dir.join(name), format!("{value}\n")).unwrap();
        for (name, value) in [
            ("idVendor", "1050"), ("manufacturer", "Yubico"), ("product", "YubiKey OTP+FIDO+CCID"),
            ("bcdDevice", "0543"), ("speed", "12"), ("version", " 2.00"), ("busnum", "3"), ("devnum", "9"),
            ("bDeviceClass", "00"), ("bDeviceSubClass", "00"), ("bDeviceProtocol", "00"),
            ("bMaxPacketSize0", "64"), ("bNumConfigurations", "1"), ("bConfigurationValue", "1"),
            ("bMaxPower", "30mA"), ("bmAttributes", "80"), ("bNumInterfaces", " 3"), ("removable", "removable"),
        ] {
            write(&usb, name, value);
        }
        for (name, value) in [
            ("bInterfaceNumber", "01"), ("bInterfaceClass", "03"), ("bInterfaceSubClass", "00"),
            ("bInterfaceProtocol", "00"),
        ] {
            write(&interface, name, value);
        }
        for (ep, dir, size) in [("ep_81", "in", "0040"), ("ep_02", "out", "0040")] {
            let e = interface.join(ep);
            fs::create_dir_all(&e).unwrap();
            write(&e, "bEndpointAddress", &ep[3..]);
            write(&e, "type", "Interrupt");
            write(&e, "direction", dir);
            write(&e, "wMaxPacketSize", size);
            write(&e, "interval", "5ms");
        }
        let info = usb_info(&hid).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(info.release.as_deref(), Some("5.43"));
        assert_eq!(info.usb_version.as_deref(), Some("2.00"));
        assert_eq!(info.address, Some(("3".into(), "9".into())));
        assert_eq!(info.attributes, Some(0x80));
        assert_eq!(info.interfaces.as_deref(), Some("3"));
        let i = info.interface.unwrap();
        assert_eq!(i.class, Some(("03".into(), "00".into(), "00".into())));
        assert_eq!(i.driver, None);
        let eps: Vec<(&str, Option<u16>)> = i.endpoints.iter().map(|e| (e.address.as_str(), e.max_packet_size)).collect();
        assert_eq!(eps, [("02", Some(64)), ("81", Some(64))]);
        assert_eq!(bcd("0100"), "1.00");
        assert_eq!(bcd("0001"), "0.01");
    }
}
