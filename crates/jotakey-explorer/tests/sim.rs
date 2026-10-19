// (c) Javier Fernandez @ JotaSoft 2026
//! The explorer against the in-process Jotakey (serial framing, CTAPHID, authenticator).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use jotakey_explorer::app::{App, Entry};
use jotakey_explorer::ctaphid::{Packet, Transport};
use jotakey_explorer::discover::{Bus, Device};
use jotakey_explorer::report::{self, JOTAKEY_AAGUID, Report};
use jotakey_host_tests::{ReportIo, SimDevice, User};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

/// The simulator behind the explorer's transport trait.
struct Sim<'a>(&'a mut SimDevice);

impl Transport for Sim<'_> {
    fn send(&mut self, packet: &Packet) -> io::Result<()> {
        self.0.send(packet)
    }
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Packet>> {
        match self.0.recv(timeout) {
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(None),
            other => other,
        }
    }
}

/// The report descriptor jotakey-bridge registers (`REPORT_DESCRIPTOR` in its main.rs).
const BRIDGE_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95,
    0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0,
];

fn device() -> Device {
    Device {
        path: PathBuf::from("/dev/hidraw-sim"),
        bus: Bus::Usb,
        vendor_id: 0x1209,
        product_id: 0x0001,
        name: "Jotakey (simulated)".into(),
        phys: String::new(),
        usb: None,
        virtual_device: true,
        report_descriptor: BRIDGE_DESCRIPTOR.to_vec(),
    }
}

fn value<'a>(r: &'a Report, section: &str, label: &str) -> Option<&'a str> {
    let s = r.sections.iter().find(|s| s.title == section)?;
    s.rows.iter().find(|row| row.label.trim() == label).map(|row| row.value.as_str())
}

#[test]
fn aaguid_matches_the_firmware() {
    assert_eq!(JOTAKEY_AAGUID, jotakey_core::AAGUID);
}

#[test]
fn a_jotakey_reports_itself_without_a_touch_and_without_changing_state() {
    let mut sim = SimDevice::new(1);
    sim.user = User::Absent; // nobody touches: every query must still complete
    let counter = sim.platform.counter;
    let epoch = sim.platform.epoch;

    let r = report::query(&device(), Sim(&mut sim));
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    let titles: Vec<&str> = r.sections.iter().map(|s| s.title.as_str()).collect();
    assert_eq!(
        titles,
        ["Device", "USB", "CTAPHID", "CTAP2 getInfo", "HID report descriptor"],
        "no U2F, no PIN set: no further sections"
    );
    assert_eq!(value(&r, "USB", "Descriptors"), Some("none"));
    assert_eq!(value(&r, "HID report descriptor", "Length"), Some("34 bytes"));
    assert_eq!(value(&r, "HID report descriptor", "Input report"), Some("64 bytes"));
    assert_eq!(value(&r, "HID report descriptor", "Output report"), Some("64 bytes"));
    assert_eq!(value(&r, "HID report descriptor", "0000  06 d0 f1"), Some("Usage Page (FIDO Alliance)"));
    assert_eq!(value(&r, "HID report descriptor", "0021  c0"), Some("End Collection"));

    assert_eq!(value(&r, "CTAPHID", "Protocol version"), Some("2"));
    assert!(value(&r, "CTAPHID", "Capabilities").unwrap().contains("NMSG"));
    assert_eq!(value(&r, "CTAP2 getInfo", "versions"), Some("FIDO_2_0"));
    assert_eq!(value(&r, "CTAP2 getInfo", "maxMsgSize"), Some("1200"));
    assert_eq!(value(&r, "CTAP2 getInfo", "rk"), Some("false"));
    let aaguid = r.sections[3].rows.iter().find(|row| row.label == "aaguid").unwrap();
    assert_eq!(aaguid.note.as_deref(), Some("Jotakey"));
    assert!(r.raw_get_info.is_some());

    assert_eq!(sim.platform.counter, counter, "the signature counter moved");
    assert_eq!(sim.platform.epoch, epoch, "the epoch changed");
}

#[test]
fn wink_reaches_the_device() {
    let mut sim = SimDevice::new(2);
    report::wink(Sim(&mut sim)).unwrap();
}

#[test]
fn the_details_pane_renders_a_report() {
    let mut sim = SimDevice::new(3);
    let r = report::query(&device(), Sim(&mut sim));
    let mut app = App::new();
    app.devices = vec![device()];
    app.list.select(Some(0));
    app.entries.insert(device().path, Entry::Done(r));
    app.raw = true;

    let mut terminal = Terminal::new(TestBackend::new(140, 50)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let screen: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    for needle in ["jotakey-explorer", "Devices (1)", "hidraw-sim", "CTAP2 getInfo", "FIDO_2_0", "Jotakey", "HID report descriptor"] {
        assert!(screen.contains(needle), "{needle:?} not on screen");
    }
}
