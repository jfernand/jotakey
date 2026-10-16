//! Full USB path: 64-byte CTAPHID packets → reassembly → authenticator → fragmentation.
//!
//! Input: a sequence of 65-byte records `[flags, packet(64)]`. `flags` low bits pick the
//! CID (biased toward allocated channels), bit 6 advances the clock past the packet
//! timeout, and bit 7 answers a pending touch with Timeout instead of Confirmed.

#![no_main]

use jotakey_core::ctap::{Authenticator, Outcome};
use jotakey_core::mock::MockPlatform;
use jotakey_core::platform::PresenceResult;
use jotakey_core::transport::ctaphid::{BROADCAST_CID, CtapHid, HidEvent, PACKET_SIZE, ReceiveState};
use jotakey_core::{AAGUID, MAX_MSG_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut hid = CtapHid::new();
    let mut auth = Authenticator::new(AAGUID);
    let mut platform = MockPlatform::new(3);
    let mut out = Box::new([0u8; MAX_MSG_SIZE]);
    let mut now = 0u64;

    for rec in data.chunks_exact(PACKET_SIZE + 1) {
        let flags = rec[0];
        let mut p = [0u8; PACKET_SIZE];
        p.copy_from_slice(&rec[1..]);
        let cid = match flags & 0x3 {
            0 => BROADCAST_CID,
            1 => 1,
            2 => 2,
            _ => u32::from_be_bytes([p[0], p[1], p[2], p[3]]),
        };
        p[..4].copy_from_slice(&cid.to_be_bytes());
        if flags & 0x40 != 0 {
            now += 1_000;
            hid.poll_timeout(now);
        }

        match hid.handle_packet(&p, now) {
            HidEvent::Request { channel: cid } => {
                let req = hid.request().to_vec();
                assert!(!req.is_empty() && req.len() <= MAX_MSG_SIZE);
                let n = match auth.process(&mut platform, &req, &mut out) {
                    Outcome::Response(n) => n,
                    Outcome::NeedsUserPresence => {
                        let up = if flags & 0x80 != 0 { PresenceResult::Timeout } else { PresenceResult::Confirmed };
                        auth.complete(&mut platform, up, &mut out)
                    }
                };
                hid.respond(cid, &out[..n]);
            }
            HidEvent::Abort { .. } | HidEvent::Cancel { .. } => auth.abort(),
            HidEvent::Wink | HidEvent::None => {}
        }
        match hid.receive_state() {
            ReceiveState::Receiving { received, total, .. } => assert!(received <= total && total <= MAX_MSG_SIZE),
            ReceiveState::Busy { .. } => panic!("request left unanswered"),
            ReceiveState::Idle => {}
        }
        let mut guard = 0;
        while hid.next_packet().is_some() {
            guard += 1;
            assert!(guard <= 1 + MAX_MSG_SIZE / 57 + 2, "runaway output");
        }
    }
});
