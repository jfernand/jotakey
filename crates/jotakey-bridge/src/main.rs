//! `jotakey-bridge`: makes a Jotakey on a serial port look like a USB FIDO security key.
//!
//! The ESP32-C6 cannot enumerate as a USB HID device. Its firmware therefore tunnels
//! 64-byte CTAPHID reports over the USB-Serial/JTAG port, framed with COBS + CRC-32
//! (`jotakey_core::transport::serial`). This daemon creates a virtual HID device with the
//! FIDO usage page through Linux `/dev/uhid` and copies reports in both directions.
//!
//! The bridge is outside the security boundary. It sees only what any USB host sees: CTAP
//! requests and responses, never key material. User presence is confirmed on the device.
//!
//! Usage: `jotakey-bridge [/dev/ttyACM0]` (needs write access to `/dev/uhid`; see
//! `scripts/99-jotakey.rules`).

use std::io::{self, ErrorKind};
use std::time::Duration;

use jotakey_core::transport::ctaphid::PACKET_SIZE;
use jotakey_core::transport::serial::{Deframer, encode};
mod uhid;

use uhid::{Device, Event, Identity};

/// FIDO HID report descriptor (CTAP 2.0 §8.1.8.2): usage page 0xF1D0, 64-byte in/out reports.
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Var, Abs)
    0x09, 0x21, //         Usage (Output Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Var, Abs)
    0xC0, //             End Collection
];

/// pid.codes open-source VID with its test PID (development use).
const VENDOR: u32 = 0x1209;
const PRODUCT: u32 = 0x0001;

fn create_device() -> io::Result<Device> {
    Device::create(&Identity {
        name: "Jotakey FIDO2 (bridge)",
        vendor: VENDOR,
        product: PRODUCT,
        version: 0x0100,
        report_descriptor: &REPORT_DESCRIPTOR,
    })
}

fn open_serial(path: &str) -> io::Result<Box<dyn serialport::SerialPort>> {
    let mut port = serialport::new(path, 115_200)
        .timeout(Duration::from_millis(5))
        // Toggling DTR/RTS on the ESP32-C6 USB-Serial/JTAG port can reset the chip.
        .dtr_on_open(false)
        .open()
        .map_err(io::Error::other)?;
    let _ = port.write_request_to_send(false);
    Ok(port)
}

/// Copy reports until the serial port fails (unplugged); then return to reconnect.
fn pump(dev: &mut Device, port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    let mut deframer = Deframer::new();
    let mut buf = [0u8; 256];
    loop {
        // Host → device.
        while let Some(event) = dev.poll()? {
            match event {
                Event::Output(data) => {
                    // Unnumbered reports may arrive with a leading report-ID byte of 0.
                    let report = match data.len() {
                        n if n == PACKET_SIZE + 1 => &data[1..],
                        n if n == PACKET_SIZE => &data[..],
                        _ => continue,
                    };
                    let mut r = [0u8; PACKET_SIZE];
                    r.copy_from_slice(report);
                    let (frame, n) = encode(&r);
                    port.write_all(&frame[..n])?;
                }
                Event::Other => {}
            }
        }
        // Device → host.
        match port.read(&mut buf) {
            Ok(n) => {
                for &b in &buf[..n] {
                    if let Some(report) = deframer.push(b) {
                        dev.send(&report)?;
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/dev/ttyACM0".into());
    let mut dev = match create_device() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot open /dev/uhid: {e} (see scripts/99-jotakey.rules or run as root)");
            std::process::exit(1);
        }
    };
    eprintln!("jotakey-bridge: virtual FIDO device created; waiting for {path}");
    loop {
        match open_serial(&path) {
            Ok(mut port) => {
                eprintln!("jotakey-bridge: connected to {path}");
                if let Err(e) = pump(&mut dev, port.as_mut()) {
                    eprintln!("jotakey-bridge: link lost: {e}");
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}
