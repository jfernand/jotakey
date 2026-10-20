// (c) Javier Fernandez @ JotaSoft 2026
//! CTAPHID and BLE framing: unit scenarios plus property tests over arbitrary input.

use jotakey_core::MAX_MSG_SIZE;
use jotakey_core::transport::ble::{self, BleEvent, BleFramer, MAX_FRAGMENT};
use jotakey_core::transport::ctaphid::{self, BROADCAST_CID, CtapHid, HidEvent, Packet, ReceiveState, cmd, err};
use proptest::prelude::*;

// ---------- draining what the device sends ----------

/// More packets than any response needs (a 1200-byte message is 21 CTAPHID packets, or 64
/// BLE fragments of 20 bytes). A framer that sends more never stops: fail, rather than
/// hang until a test timeout (cargo mutants counts a hang as a timeout, not a kill).
const MAX_PACKETS: usize = 1_000;

/// Every packet the device has queued, in order.
fn hid_packets(h: &mut CtapHid) -> Vec<Packet> {
    let mut out = Vec::new();
    while let Some(p) = h.next_packet() {
        out.push(p);
        assert!(out.len() <= MAX_PACKETS, "the CTAPHID framer never stops sending");
    }
    out
}

/// Every notification the device has queued, in order.
fn ble_notifications(b: &mut BleFramer) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_FRAGMENT];
    while let Some(n) = b.next_notification(&mut buf) {
        out.push(buf[..n].to_vec());
        assert!(out.len() <= MAX_PACKETS, "the BLE framer never stops sending");
    }
    out
}

// ---------- host-side CTAPHID helpers ----------

fn init_packet(channel: u32, command: u8, total: usize, data: &[u8]) -> Packet {
    let mut p = [0u8; 64];
    p[..4].copy_from_slice(&channel.to_be_bytes());
    p[4] = command | 0x80;
    p[5..7].copy_from_slice(&(total as u16).to_be_bytes());
    p[7..7 + data.len()].copy_from_slice(data);
    p
}

fn fragment(channel: u32, command: u8, msg: &[u8]) -> Vec<Packet> {
    let mut out = vec![init_packet(channel, command, msg.len(), &msg[..msg.len().min(57)])];
    for (seq, chunk) in msg.get(57..).unwrap_or(&[]).chunks(59).enumerate() {
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&channel.to_be_bytes());
        p[4] = seq as u8;
        p[5..5 + chunk.len()].copy_from_slice(chunk);
        out.push(p);
    }
    out
}

/// Drain and reassemble everything the device sends: Vec of (channel, command, payload).
fn drain(h: &mut CtapHid) -> Vec<(u32, u8, Vec<u8>)> {
    let mut msgs: Vec<(u32, u8, Vec<u8>)> = Vec::new();
    let mut want: Option<usize> = None;
    for p in hid_packets(h) {
        let channel = u32::from_be_bytes(p[..4].try_into().unwrap());
        if p[4] & 0x80 != 0 {
            let total = u16::from_be_bytes([p[5], p[6]]) as usize;
            msgs.push((channel, p[4] & 0x7f, p[7..7 + total.min(57)].to_vec()));
            want = Some(total);
        } else {
            let last = msgs.last_mut().expect("cont before init");
            let total = want.unwrap();
            let n = (total - last.2.len()).min(59);
            last.2.extend_from_slice(&p[5..5 + n]);
        }
    }
    msgs
}

fn alloc(h: &mut CtapHid) -> u32 {
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(h.handle_packet(&init_packet(BROADCAST_CID, cmd::INIT, 8, &nonce), 0), HidEvent::None);
    let msgs = drain(h);
    assert_eq!(msgs.len(), 1);
    let (channel, c, data) = &msgs[0];
    assert_eq!((*channel, *c), (BROADCAST_CID, cmd::INIT));
    assert_eq!(&data[..8], &nonce);
    assert_eq!(data.len(), 17);
    assert_eq!(data[12], 2, "protocol version");
    assert_eq!(data[16], ctaphid::CAPABILITIES);
    u32::from_be_bytes(data[8..12].try_into().unwrap())
}

fn send(h: &mut CtapHid, channel: u32, command: u8, msg: &[u8], now: u64) -> HidEvent {
    let mut ev = HidEvent::None;
    for p in fragment(channel, command, msg) {
        ev = h.handle_packet(&p, now);
    }
    ev
}

#[test]
fn init_allocates_distinct_channels() {
    let mut h = CtapHid::new();
    let a = alloc(&mut h);
    let b = alloc(&mut h);
    assert_ne!(a, b);
    assert!(a != 0 && a != BROADCAST_CID);
}

#[test]
fn cbor_request_roundtrip_at_every_size_boundary() {
    let mut h = CtapHid::new();
    let channel = alloc(&mut h);
    for len in [1usize, 56, 57, 58, 116, 117, 118, 500, MAX_MSG_SIZE] {
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        assert_eq!(send(&mut h, channel, cmd::CBOR, &msg, 0), HidEvent::Request { channel });
        assert_eq!(h.request(), &msg[..]);
        let resp: Vec<u8> = msg.iter().rev().copied().collect();
        h.respond(channel, &resp);
        assert_eq!(drain(&mut h), vec![(channel, cmd::CBOR, resp)]);
        assert_eq!(h.receive_state(), ReceiveState::Idle);
    }
}

#[test]
fn ping_echoes() {
    let mut h = CtapHid::new();
    let channel = alloc(&mut h);
    let msg = vec![0xAB; 300];
    assert_eq!(send(&mut h, channel, cmd::PING, &msg, 0), HidEvent::None);
    assert_eq!(drain(&mut h), vec![(channel, cmd::PING, msg)]);
}

#[test]
fn other_channel_gets_busy_and_owner_is_untouched() {
    let mut h = CtapHid::new();
    let a = alloc(&mut h);
    let b = alloc(&mut h);
    let msg = vec![7u8; 200];
    let pkts = fragment(a, cmd::CBOR, &msg);
    h.handle_packet(&pkts[0], 0);
    // B tries to start a transaction mid-way.
    h.handle_packet(&init_packet(b, cmd::CBOR, 1, &[4]), 0);
    assert_eq!(drain(&mut h), vec![(b, cmd::ERROR, vec![err::CHANNEL_BUSY])]);
    // B sends a stray continuation packet: ignored.
    let mut stray = pkts[1];
    stray[..4].copy_from_slice(&b.to_be_bytes());
    assert_eq!(h.handle_packet(&stray, 0), HidEvent::None);
    for p in &pkts[1..] {
        h.handle_packet(p, 0);
    }
    assert_eq!(h.receive_state(), ReceiveState::Busy { channel: a });
    assert_eq!(h.request(), &msg[..]);
    // B is still refused while A is busy; B's CANCEL does not cancel A.
    assert_eq!(h.handle_packet(&init_packet(b, cmd::CANCEL, 0, &[]), 0), HidEvent::None);
    assert_eq!(h.handle_packet(&init_packet(a, cmd::CANCEL, 0, &[]), 0), HidEvent::Cancel { channel: a });
}

#[test]
fn sequence_errors_timeouts_and_bad_channels() {
    let mut h = CtapHid::new();
    let channel = alloc(&mut h);
    let pkts = fragment(channel, cmd::CBOR, &[1u8; 200]);
    h.handle_packet(&pkts[0], 0);
    h.handle_packet(&pkts[2], 0); // skipped seq 0
    assert_eq!(drain(&mut h), vec![(channel, cmd::ERROR, vec![err::INVALID_SEQ])]);
    assert_eq!(h.receive_state(), ReceiveState::Idle);

    h.handle_packet(&pkts[0], 1000);
    h.poll_timeout(1000 + ctaphid::PACKET_TIMEOUT_MS);
    assert!(matches!(h.receive_state(), ReceiveState::Receiving { .. }));
    h.poll_timeout(1001 + ctaphid::PACKET_TIMEOUT_MS);
    assert_eq!(drain(&mut h), vec![(channel, cmd::ERROR, vec![err::MSG_TIMEOUT])]);

    h.handle_packet(&init_packet(0x1234_5678, cmd::CBOR, 1, &[4]), 0);
    assert_eq!(drain(&mut h), vec![(0x1234_5678, cmd::ERROR, vec![err::INVALID_CHANNEL])]);
    h.handle_packet(&init_packet(BROADCAST_CID, cmd::CBOR, 1, &[4]), 0);
    assert_eq!(drain(&mut h), vec![(BROADCAST_CID, cmd::ERROR, vec![err::INVALID_CHANNEL])]);
    h.handle_packet(&init_packet(channel, cmd::CBOR, MAX_MSG_SIZE + 1, &[]), 0);
    assert_eq!(drain(&mut h), vec![(channel, cmd::ERROR, vec![err::INVALID_LEN])]);
    h.handle_packet(&init_packet(channel, cmd::MSG, 1, &[0]), 0);
    assert_eq!(drain(&mut h), vec![(channel, cmd::ERROR, vec![err::INVALID_CMD])]);
    h.handle_packet(&init_packet(channel, cmd::CBOR, 0, &[]), 0);
    assert_eq!(drain(&mut h), vec![(channel, cmd::ERROR, vec![err::INVALID_LEN])]);
}

#[test]
fn init_resync_aborts_own_request() {
    let mut h = CtapHid::new();
    let channel = alloc(&mut h);
    assert_eq!(send(&mut h, channel, cmd::CBOR, &[4], 0), HidEvent::Request { channel });
    let ev = h.handle_packet(&init_packet(channel, cmd::INIT, 8, &[9; 8]), 0);
    assert_eq!(ev, HidEvent::Abort { channel });
    assert_eq!(h.receive_state(), ReceiveState::Idle);
    let msgs = drain(&mut h);
    assert_eq!(msgs[0].0, channel);
    // A late response for the aborted request is dropped.
    h.respond(channel, &[0, 1, 2]);
    assert!(drain(&mut h).is_empty());
}

#[test]
fn wink_and_keepalive() {
    let mut h = CtapHid::new();
    let channel = alloc(&mut h);
    assert_eq!(send(&mut h, channel, cmd::WINK, &[], 0), HidEvent::Wink);
    assert_eq!(drain(&mut h), vec![(channel, cmd::WINK, vec![])]);
    h.keepalive(ctaphid::keepalive::UP_NEEDED);
    assert!(drain(&mut h).is_empty(), "no keepalive when idle");
    send(&mut h, channel, cmd::CBOR, &[4], 0);
    h.keepalive(ctaphid::keepalive::UP_NEEDED);
    assert_eq!(drain(&mut h), vec![(channel, cmd::KEEPALIVE, vec![2])]);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn hid_roundtrip_any_payload(msg in proptest::collection::vec(any::<u8>(), 1..=MAX_MSG_SIZE)) {
        let mut h = CtapHid::new();
        let channel = alloc(&mut h);
        prop_assert_eq!(send(&mut h, channel, cmd::CBOR, &msg, 0), HidEvent::Request { channel });
        prop_assert_eq!(h.request(), &msg[..]);
        h.respond(channel, &msg);
        prop_assert_eq!(drain(&mut h), vec![(channel, cmd::CBOR, msg)]);
    }

    /// Arbitrary packet streams never panic and keep the receive state well-formed.
    #[test]
    fn hid_arbitrary_streams(pkts in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 0..64),
                             channels in proptest::collection::vec(0u32..4, 0..64)) {
        let mut h = CtapHid::new();
        let _ = alloc(&mut h);
        let _ = alloc(&mut h);
        for (i, half) in pkts.iter().enumerate() {
            let mut p = [0u8; 64];
            p[..32].copy_from_slice(half);
            p[32..].copy_from_slice(half);
            // Bias CIDs toward valid ones so deeper states are reached.
            let channel = match channels.get(i).copied().unwrap_or(0) { 0 => 1, 1 => 2, 2 => BROADCAST_CID, _ => u32::from_be_bytes([p[0], p[1], p[2], p[3]]) };
            p[..4].copy_from_slice(&channel.to_be_bytes());
            let _ = h.handle_packet(&p, i as u64);
            match h.receive_state() {
                ReceiveState::Receiving { received, total, .. } => prop_assert!(received <= total && total <= MAX_MSG_SIZE),
                ReceiveState::Busy { .. } => prop_assert!(!h.request().is_empty() && h.request().len() <= MAX_MSG_SIZE),
                ReceiveState::Idle => {}
            }
            hid_packets(&mut h);
        }
    }
}

// ---------- BLE ----------

fn ble_frames(command: u8, msg: &[u8], frag: usize) -> Vec<Vec<u8>> {
    let mut v = vec![{
        let mut f = vec![command, (msg.len() >> 8) as u8, msg.len() as u8];
        f.extend_from_slice(&msg[..msg.len().min(frag - 3)]);
        f
    }];
    let mut seq = 0u8;
    for chunk in msg.get(frag - 3..).unwrap_or(&[]).chunks(frag - 1) {
        let mut f = vec![seq];
        f.extend_from_slice(chunk);
        v.push(f);
        seq = if seq == 0x7f { 0 } else { seq + 1 };
    }
    v
}

fn ble_drain(b: &mut BleFramer) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for f in ble_notifications(b) {
        let f = &f[..];
        if f[0] & 0x80 != 0 {
            total = u16::from_be_bytes([f[1], f[2]]) as usize;
            out.push((f[0], f[3..].to_vec()));
        } else {
            out.last_mut().unwrap().1.extend_from_slice(&f[1..]);
        }
        assert!(out.last().unwrap().1.len() <= total);
    }
    out
}

#[test]
fn ble_scenarios() {
    let mut b = BleFramer::new(20);
    let msg: Vec<u8> = (0..300).map(|i| i as u8).collect();
    let mut ev = BleEvent::None;
    for f in ble_frames(ble::cmd::MSG, &msg, 20) {
        ev = b.handle_write(&f, 0);
    }
    assert_eq!(ev, BleEvent::Request);
    assert_eq!(b.request(), &msg[..]);
    // Busy: a new message is refused, CANCEL is reported.
    assert_eq!(b.handle_write(&[ble::cmd::MSG, 0, 1, 4], 0), BleEvent::None);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::BUSY])]);
    assert_eq!(b.handle_write(&[ble::cmd::CANCEL, 0, 0], 0), BleEvent::Cancel);
    b.keepalive(ble::keepalive::UP_NEEDED);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::KEEPALIVE, vec![2])]);
    b.respond(&msg);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::MSG, msg.clone())]);

    // Oversized write, bad command, bad sequence, too long, timeout.
    assert_eq!(b.handle_write(&[0u8; 21], 0), BleEvent::None);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::INVALID_LEN])]);
    b.handle_write(&[0x85, 0, 0], 0);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::INVALID_CMD])]);
    b.handle_write(&[ble::cmd::MSG, 0, 40, 1], 0);
    b.handle_write(&[3, 1], 0);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::INVALID_SEQ])]);
    b.handle_write(&[ble::cmd::MSG, 0x04, 0xB1], 0);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::INVALID_LEN])]);
    b.handle_write(&[ble::cmd::MSG, 0, 40, 1], 0);
    b.poll_timeout(ble::FRAGMENT_TIMEOUT_MS + 1);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::REQ_TIMEOUT])]);
    // PING echoes.
    b.handle_write(&[ble::cmd::PING, 0, 3, 7, 8, 9], 0);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::PING, vec![7, 8, 9])]);
}

proptest! {
    #[test]
    fn ble_roundtrip(msg in proptest::collection::vec(any::<u8>(), 1..=MAX_MSG_SIZE), frag in 20usize..=512) {
        let mut b = BleFramer::new(frag);
        let mut ev = BleEvent::None;
        for f in ble_frames(ble::cmd::MSG, &msg, frag) {
            ev = b.handle_write(&f, 0);
        }
        prop_assert_eq!(ev, BleEvent::Request);
        prop_assert_eq!(b.request(), &msg[..]);
        b.respond(&msg);
        prop_assert_eq!(ble_drain(&mut b), vec![(ble::cmd::MSG, msg)]);
    }

    #[test]
    fn ble_arbitrary_writes(writes in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..64)) {
        let mut b = BleFramer::new(20);
        for (i, w) in writes.iter().enumerate() {
            let _ = b.handle_write(w, i as u64);
            prop_assert!(b.request().len() <= MAX_MSG_SIZE);
            ble_notifications(&mut b);
        }
    }
}

// ---------- Tests driven by mutation testing ----------

#[test]
fn hid_capabilities_literal() {
    // WINK | CBOR | NMSG, from CTAP 2.0 §8.1.9.1.3.
    assert_eq!(ctaphid::CAPABILITIES, 0x0D);
}

#[test]
fn hid_next_unallocated_channel_is_invalid() {
    let mut h = CtapHid::new();
    let a = alloc(&mut h);
    h.handle_packet(&init_packet(a + 1, cmd::CBOR, 1, &[4]), 0);
    assert_eq!(drain(&mut h), vec![(a + 1, cmd::ERROR, vec![err::INVALID_CHANNEL])]);
    assert_eq!(send(&mut h, a, cmd::CBOR, &[4], 0), HidEvent::Request { channel: a });
}

#[test]
fn hid_new_init_on_own_channel_mid_message_is_invalid_seq() {
    let mut h = CtapHid::new();
    let a = alloc(&mut h);
    let pkts = fragment(a, cmd::CBOR, &[1u8; 200]);
    h.handle_packet(&pkts[0], 0);
    h.handle_packet(&init_packet(a, cmd::CBOR, 1, &[4]), 0);
    assert_eq!(drain(&mut h), vec![(a, cmd::ERROR, vec![err::INVALID_SEQ])]);
    assert_eq!(h.receive_state(), ReceiveState::Idle);
}

#[test]
fn hid_init_resync_only_touches_its_own_channel() {
    let mut h = CtapHid::new();
    let a = alloc(&mut h);
    let b = alloc(&mut h);
    // A is busy; B resynchronises: A must stay busy and no Abort is reported.
    assert_eq!(send(&mut h, a, cmd::CBOR, &[4], 0), HidEvent::Request { channel: a });
    assert_eq!(h.handle_packet(&init_packet(b, cmd::INIT, 8, &[3; 8]), 0), HidEvent::None);
    assert_eq!(h.receive_state(), ReceiveState::Busy { channel: a });
    drain(&mut h);
    h.respond(a, &[0]);
    drain(&mut h);
    // A is mid-message; B resynchronises: A keeps receiving.
    let pkts = fragment(a, cmd::CBOR, &[1u8; 200]);
    h.handle_packet(&pkts[0], 0);
    h.handle_packet(&init_packet(b, cmd::INIT, 8, &[3; 8]), 0);
    assert!(matches!(h.receive_state(), ReceiveState::Receiving { channel, .. } if channel == a));
    // A resynchronises itself mid-message: back to idle.
    h.handle_packet(&init_packet(a, cmd::INIT, 8, &[3; 8]), 0);
    assert_eq!(h.receive_state(), ReceiveState::Idle);
}

#[test]
fn hid_init_requires_eight_byte_nonce() {
    let mut h = CtapHid::new();
    h.handle_packet(&init_packet(BROADCAST_CID, cmd::INIT, 7, &[1; 7]), 0);
    assert_eq!(drain(&mut h), vec![(BROADCAST_CID, cmd::ERROR, vec![err::INVALID_LEN])]);
}

#[test]
fn hid_response_sequence_numbers() {
    let mut h = CtapHid::new();
    let a = alloc(&mut h);
    send(&mut h, a, cmd::CBOR, &[4], 0);
    h.respond(a, &[0x55; MAX_MSG_SIZE]);
    let mut seqs = Vec::new();
    for p in hid_packets(&mut h) {
        if p[4] & 0x80 == 0 {
            seqs.push(p[4]);
        }
    }
    assert_eq!(seqs, (0..seqs.len() as u8).collect::<Vec<_>>());
}

#[test]
fn ble_boundaries() {
    let mut b = BleFramer::new(20);
    assert_eq!(b.fragment_size(), 20);
    assert_eq!(BleFramer::new(5).fragment_size(), 20);
    assert_eq!(BleFramer::new(9999).fragment_size(), 512);
    // A write of exactly fragment_size bytes is fine.
    let mut w = vec![ble::cmd::MSG, 0, 17];
    w.extend_from_slice(&[1; 17]);
    assert_eq!(b.handle_write(&w, 0), BleEvent::Request);
    // Continuation while busy: ignored, no error.
    assert_eq!(b.handle_write(&[0, 1], 0), BleEvent::None);
    assert!(ble_drain(&mut b).is_empty());
    b.respond(&[0]);
    ble_drain(&mut b);
    // Continuation while idle: INVALID_SEQ.
    b.handle_write(&[0, 1], 0);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::INVALID_SEQ])]);
    // Timeout boundary: exactly FRAGMENT_TIMEOUT_MS is not yet a timeout.
    b.handle_write(&[ble::cmd::MSG, 0, 40, 1], 100);
    b.poll_timeout(100 + ble::FRAGMENT_TIMEOUT_MS);
    assert!(ble_drain(&mut b).is_empty());
    // reset() starts over with the new fragment size and drops the partial message.
    b.reset(64);
    assert_eq!(b.fragment_size(), 64);
    b.handle_write(&[0, 1], 0);
    assert_eq!(ble_drain(&mut b), vec![(ble::cmd::ERROR, vec![ble::err::INVALID_SEQ])]);
}

#[test]
fn ble_notification_sequence_numbers() {
    let mut b = BleFramer::new(20);
    b.handle_write(&[ble::cmd::MSG, 0, 1, 4], 0);
    b.respond(&[0x55; MAX_MSG_SIZE]);
    let mut seqs = Vec::new();
    let mut first = true;
    for f in ble_notifications(&mut b) {
        assert!(f.len() <= 20);
        if !first {
            seqs.push(f[0]);
        }
        first = false;
    }
    let want: Vec<u8> = (0..seqs.len()).map(|i| (i % 0x80) as u8).collect();
    assert_eq!(seqs, want);
}

#[test]
fn ble_max_size_message_is_accepted() {
    let msg = vec![0x42u8; MAX_MSG_SIZE];
    let mut b = BleFramer::new(512);
    let mut ev = BleEvent::None;
    for f in ble_frames(ble::cmd::MSG, &msg, 512) {
        ev = b.handle_write(&f, 0);
    }
    assert_eq!(ev, BleEvent::Request);
    assert_eq!(b.request().len(), MAX_MSG_SIZE);
}
