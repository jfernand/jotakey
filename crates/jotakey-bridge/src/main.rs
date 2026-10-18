// (c) Javier Fernandez @ JotaSoft 2026
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

use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use jotakey_core::transport::ctaphid::PACKET_SIZE;
use jotakey_core::transport::serial::{Deframer, encode};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, poll};
use serialport::{SerialPort, TTYPort};
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

/// How long a write to the serial port may block before the link counts as lost.
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

fn create_device() -> io::Result<Device> {
    Device::create(&Identity {
        name: "Jotakey FIDO2 (bridge)",
        vendor: VENDOR,
        product: PRODUCT,
        version: 0x0100,
        report_descriptor: &REPORT_DESCRIPTOR,
    })
}

fn open_serial(path: &str) -> io::Result<TTYPort> {
    let mut port = serialport::new(path, 115_200)
        .timeout(WRITE_TIMEOUT)
        // Toggling DTR/RTS on the ESP32-C6 USB-Serial/JTAG port can reset the chip.
        .dtr_on_open(false)
        .open_native()
        .map_err(io::Error::other)?;
    let _ = port.write_request_to_send(false);
    Ok(port)
}

/// Copy reports until the serial port fails (unplugged); then return to reconnect.
///
/// Sleeps in `poll(2)` until the kernel has a uhid event or the serial port has bytes, so an
/// idle bridge uses no CPU and every report is forwarded as soon as it arrives. There is no
/// timeout: the bridge has no timers of its own (CTAPHID timeouts live on the device).
fn pump(dev: &mut Device, port: &mut TTYPort) -> io::Result<()> {
    let mut deframer = Deframer::new();
    let mut buf = [0u8; 256];
    let gone = PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL;
    loop {
        let mut fds =
            [PollFd::new(dev.as_raw_fd(), PollFlags::POLLIN), PollFd::new(port.as_raw_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, -1) {
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
        let uhid_ready = fds[0].revents().unwrap_or(PollFlags::empty());
        let serial_ready = fds[1].revents().unwrap_or(PollFlags::empty());

        if uhid_ready.intersects(gone) {
            return Err(io::Error::other("/dev/uhid failed"));
        }
        // Host → device.
        if uhid_ready.contains(PollFlags::POLLIN) {
            while let Some(event) = dev.next_event()? {
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
        }
        // Device → host.
        if serial_ready.contains(PollFlags::POLLIN) {
            let n = port.read(&mut buf)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "serial port closed"));
            }
            for &b in &buf[..n] {
                if let Some(report) = deframer.push(b) {
                    dev.send(&report)?;
                }
            }
        } else if serial_ready.intersects(gone) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "serial port hung up"));
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
                if let Err(e) = pump(&mut dev, &mut port) {
                    eprintln!("jotakey-bridge: link lost: {e}");
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;
    use std::sync::mpsc;
    use std::time::Instant;

    /// Context switches of one thread so far (voluntary + involuntary), from `/proc`.
    fn context_switches(task: &std::path::Path) -> u64 {
        let status = std::fs::read_to_string(task.join("status")).unwrap();
        status
            .lines()
            .filter(|l| l.starts_with("voluntary_ctxt_switches") || l.starts_with("nonvoluntary_ctxt_switches"))
            .map(|l| l.split_whitespace().last().unwrap().parse::<u64>().unwrap())
            .sum()
    }

    /// One complete frame as sent: the leading delimiter, the body, the trailing delimiter.
    fn read_frame(port: &mut TTYPort) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut frame = Vec::new();
        let mut b = [0u8; 1];
        while frame.len() < 2 || frame.last() != Some(&0) {
            assert!(Instant::now() < deadline, "no frame from the bridge");
            if port.read(&mut b).is_ok_and(|n| n == 1) {
                frame.push(b[0]);
            }
        }
        frame
    }

    /// The real `pump` between a fake uhid (a datagram socket pair keeps event boundaries,
    /// like `/dev/uhid`) and a pseudo-terminal standing in for the serial port.
    #[test]
    fn pump_forwards_both_ways_sleeps_when_idle_and_stops_on_hangup() {
        let (bridge_end, kernel) = UnixDatagram::pair().unwrap();
        bridge_end.set_nonblocking(true).unwrap();
        kernel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut dev = Device::from_file(File::from(OwnedFd::from(bridge_end)));
        let (mut board, mut serial) = TTYPort::pair().unwrap();

        let (task_tx, task_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            task_tx.send(std::fs::read_link("/proc/thread-self").unwrap()).unwrap();
            done_tx.send(pump(&mut dev, &mut serial)).unwrap();
        });
        let task = std::path::Path::new("/proc").join(task_rx.recv().unwrap());

        // Host → device: an output report (with the optional leading report-ID byte) comes
        // out of the serial port as exactly one frame.
        let mut report = [0u8; PACKET_SIZE];
        report[..7].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08]);
        let mut with_id = vec![0u8];
        with_id.extend_from_slice(&report);
        kernel.send(&uhid::output_event(&with_id)).unwrap();
        let (frame, n) = encode(&report);
        assert_eq!(read_frame(&mut board), &frame[..n]);

        // Device → host: a frame from the board becomes one UHID_INPUT2 event.
        let reply = [0x5au8; PACKET_SIZE];
        let (frame, n) = encode(&reply);
        board.write_all(&frame[..n]).unwrap();
        let mut ev = vec![0u8; uhid::EVENT_SIZE];
        let len = kernel.recv(&mut ev).unwrap();
        assert_eq!(uhid::input2_report(&ev[..len]), Some(reply.to_vec()));

        // Idle: the pump sleeps in poll(2). The old 5 ms polling loop woke about 60 times here.
        let before = context_switches(&task);
        std::thread::sleep(Duration::from_millis(300));
        let wakeups = context_switches(&task) - before;
        assert!(wakeups <= 2, "idle bridge woke {wakeups} times in 300 ms");

        // Unplug: the serial side hangs up and the pump returns so main() can reconnect.
        drop(board);
        let result = done_rx.recv_timeout(Duration::from_secs(2)).expect("pump did not notice the hangup");
        assert!(result.is_err());
    }
}
