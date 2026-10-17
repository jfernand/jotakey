// (c) Javier Fernandez @ JotaSoft 2026
//! BLE framing with the authenticator behind it.
//!
//! Input: `[fragment_size_byte, (len, bytes[len])*]` — each record is one GATT write.

#![no_main]

use jotakey_core::ctap::{Authenticator, Outcome};
use jotakey_core::mock::MockPlatform;
use jotakey_core::platform::PresenceResult;
use jotakey_core::transport::ble::{BleEvent, BleFramer, MAX_FRAGMENT};
use jotakey_core::{AAGUID, MAX_MSG_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&frag, mut rest)) = data.split_first() else { return };
    let mut ble = BleFramer::new(usize::from(frag) * 2);
    let mut auth = Authenticator::new(AAGUID);
    let mut platform = MockPlatform::new(4);
    let mut out = Box::new([0u8; MAX_MSG_SIZE]);
    let mut note = [0u8; MAX_FRAGMENT];
    let mut now = 0u64;

    while let Some((&len, tail)) = rest.split_first() {
        let n = usize::from(len).min(tail.len());
        let (write, next) = tail.split_at(n);
        rest = next;
        now += u64::from(len & 0x0F) * 100;
        ble.poll_timeout(now);
        match ble.handle_write(write, now) {
            BleEvent::Request => {
                let req = ble.request().to_vec();
                let n = match auth.process(&mut platform, &req, &mut out) {
                    Outcome::Response(n) => n,
                    Outcome::NeedsUserPresence => auth.complete(&mut platform, PresenceResult::Confirmed, &mut out),
                };
                ble.respond(&out[..n]);
            }
            BleEvent::Cancel => auth.abort(),
            BleEvent::None => {}
        }
        while let Some(len) = ble.next_notification(&mut note) {
            assert!(len <= ble.fragment_size().max(4));
        }
    }
});
