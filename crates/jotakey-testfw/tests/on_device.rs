// (c) Javier Fernandez @ JotaSoft 2026
//! On-device tests (run on the ESP32-C6 itself).
//!
//! ```sh
//! cd crates/jotakey-testfw
//! cargo test                         # automatic tests
//! cargo test --features interactive  # + button test (press BOOT when asked)
//! ```
//!
//! probe-rs flashes each test, resets the chip, runs it, and reports pass/fail through
//! semihosting. Output arrives over RTT (defmt).

#![no_std]
#![no_main]

use jotakey_testfw as _;

#[embedded_test::tests(default_timeout = 60)]
mod tests {
    use esp_hal::clock::CpuClock;
    use esp_hal::peripherals::Peripherals;
    use esp_hal::rng::{Trng, TrngSource};
    use esp_hal::time::Instant;
    use jotakey_core::cbor::Encoder;
    use jotakey_core::credential::CRED_ID_LEN;
    use jotakey_core::ctap::{Authenticator, Outcome, command};
    use jotakey_core::platform::PresenceResult;
    use jotakey_core::selftest::{self, RngHealth, SelfTestError};
    use jotakey_core::storage::{Flash, RecordLog, SECTOR_SIZE};
    use jotakey_core::{AAGUID, MAX_MSG_SIZE, crypto};
    use jotakey_testfw::{Scratch, TargetPlatform};

    #[init]
    fn init() -> Peripherals {
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()))
    }

    // ---------------------------------------------------------------- crypto

    #[test]
    fn known_answer_tests_pass_on_target() {
        selftest::run_kats(None).unwrap();
    }

    #[test]
    fn injected_faults_are_detected_on_target() {
        use SelfTestError::*;
        for t in [Sha256, Hmac, Hkdf, Ecdsa, Credential] {
            assert_eq!(selftest::run_kats(Some(t)), Err(t));
        }
    }

    #[test]
    fn ecdsa_timing_budget(_p: Peripherals) {
        let sk = crypto::derive_credential_key(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        let start = Instant::now();
        const N: u64 = 10;
        for i in 0..N {
            let sig = crypto::sign(&sk, &[b"authenticator data", &i.to_le_bytes()], &[7; 32]).unwrap();
            assert!(crypto::verify(&sk.public_key(), &[b"authenticator data", &i.to_le_bytes()], sig.as_bytes()));
        }
        let per_op = start.elapsed().as_millis() / N;
        defmt::info!("sign+verify: {} ms per operation", per_op);
        // A touch already takes ~300 ms of human time; 400 ms of compute keeps the
        // interaction snappy.
        assert!(per_op < 400, "ECDSA too slow: {} ms", per_op);
    }

    // ---------------------------------------------------------------- entropy

    #[test]
    fn trng_health_and_statistics(p: Peripherals) {
        let _source = TrngSource::new(p.RNG, p.ADC1);
        let trng = Trng::try_new().unwrap();

        let mut startup = [0u8; selftest::STARTUP_SAMPLES];
        trng.read(&mut startup);
        selftest::startup_rng_test(&startup).unwrap();

        // 64 KiB through the continuous tests, with a byte histogram and a bit count.
        let mut health = RngHealth::new();
        let mut hist = [0u32; 256];
        let mut ones = 0u64;
        let mut buf = [0u8; 1024];
        for _ in 0..64 {
            trng.read(&mut buf);
            health.feed_all(&buf).unwrap();
            for &b in &buf {
                hist[usize::from(b)] += 1;
                ones += u64::from(b.count_ones());
            }
        }
        // Chi-square, 255 degrees of freedom: mean 255, σ ≈ 22.6. Accept ±6σ.
        let expected = 65_536.0f64 / 256.0;
        let chi2: f64 = hist.iter().map(|&o| (f64::from(o) - expected) * (f64::from(o) - expected) / expected).sum();
        defmt::info!("TRNG chi-square = {}", chi2);
        assert!((120.0..390.0).contains(&chi2), "byte distribution is not uniform");
        // Monobit over 524 288 bits: mean 262 144, σ ≈ 362. Accept ±6σ.
        let dev = ones.abs_diff(262_144);
        defmt::info!("TRNG ones = {} (deviation {})", ones, dev);
        assert!(dev < 2_200, "bit bias");
    }

    // ---------------------------------------------------------------- HMAC / eFuse key

    #[test]
    fn efuse_root_key_hmac(p: Peripherals) {
        use esp_hal::hmac::{Hmac, HmacPurpose, KeyId};
        let mut hmac = Hmac::new(p.HMAC);
        let mut run = |msg: &[u8]| -> Option<[u8; 32]> {
            hmac.init();
            nb::block!(hmac.configure(HmacPurpose::ToUser, KeyId::Key0)).ok()?;
            let mut rest = msg;
            while !rest.is_empty() {
                rest = nb::block!(hmac.update(rest)).ok()?;
            }
            let mut out = [0u8; 32];
            nb::block!(hmac.finalize(&mut out)).ok()?;
            Some(out)
        };
        let Some(a1) = run(b"jotakey/mac/v1") else {
            defmt::warn!("SKIPPED: eFuse KEY0 is not provisioned with purpose HMAC_UP (see scripts/provision.sh)");
            return;
        };
        let a2 = run(b"jotakey/mac/v1").unwrap();
        let b = run(b"jotakey/seed/v1").unwrap();
        assert_eq!(a1, a2, "HMAC must be deterministic");
        assert_ne!(a1, b, "labels must separate keys");
        assert_ne!(a1, [0u8; 32]);
    }

    // ---------------------------------------------------------------- storage

    #[test]
    fn record_log_on_real_flash(p: Peripherals) {
        let mut f = Scratch { storage: esp_storage::FlashStorage::new(p.FLASH) };
        for s in 0..2 {
            f.erase(s * SECTOR_SIZE).unwrap();
        }
        let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        assert!(log.latest().is_none());
        // 600 records cross the sector boundary twice (256 records per sector).
        for i in 1..=600u32 {
            assert_eq!(log.append(&mut f, &i.to_le_bytes()).unwrap(), i);
        }
        let log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        assert_eq!(log.latest().map(|l| l.0), Some(600));

        // Torn write: only the first half of the next record reaches flash.
        let mut probe = [0u8; 16];
        let mut slot = 0;
        for i in 0..256u32 {
            let off = (600 / 256 % 2) as u32 * SECTOR_SIZE + i * 16;
            f.read(off, &mut probe).unwrap();
            if probe.iter().all(|&b| b == 0xFF) {
                slot = off;
                break;
            }
        }
        f.write(slot, b"JKR1\x59\x02\x00\x00").unwrap();
        let mut log = RecordLog::<4>::mount(&mut f, 0).unwrap();
        assert_eq!(log.latest().map(|l| l.0), Some(600), "torn record must be ignored");
        assert_eq!(log.append(&mut f, &601u32.to_le_bytes()).unwrap(), 601);
        assert_eq!(RecordLog::<4>::mount(&mut f, 0).unwrap().latest().map(|l| l.0), Some(601));

        for s in 0..2 {
            f.erase(s * SECTOR_SIZE).unwrap();
        }
    }

    // ---------------------------------------------------------------- CTAP on silicon

    fn make_credential_request(buf: &mut [u8]) -> usize {
        let mut e = Encoder::new(buf);
        e.raw(&[command::MAKE_CREDENTIAL]).unwrap();
        e.map(4).unwrap();
        e.unsigned(1).unwrap();
        e.bytes(&[0xCD; 32]).unwrap();
        e.unsigned(2).unwrap();
        e.map(1).unwrap();
        e.text("id").unwrap();
        e.text("jotakey.test").unwrap();
        e.unsigned(3).unwrap();
        e.map(1).unwrap();
        e.text("id").unwrap();
        e.bytes(b"user").unwrap();
        e.unsigned(4).unwrap();
        e.array(1).unwrap();
        e.map(2).unwrap();
        e.text("alg").unwrap();
        e.int(-7).unwrap();
        e.text("type").unwrap();
        e.text("public-key").unwrap();
        e.len()
    }

    fn get_assertion_request(buf: &mut [u8], cred_id: &[u8]) -> usize {
        let mut e = Encoder::new(buf);
        e.raw(&[command::GET_ASSERTION]).unwrap();
        e.map(3).unwrap();
        e.unsigned(1).unwrap();
        e.text("jotakey.test").unwrap();
        e.unsigned(2).unwrap();
        e.bytes(&[0xCD; 32]).unwrap();
        e.unsigned(3).unwrap();
        e.array(1).unwrap();
        e.map(2).unwrap();
        e.text("id").unwrap();
        e.bytes(cred_id).unwrap();
        e.text("type").unwrap();
        e.text("public-key").unwrap();
        e.len()
    }

    /// Find `needle` in `hay` and return what follows it.
    fn after<'a>(hay: &'a [u8], needle: &[u8]) -> &'a [u8] {
        let i = hay.windows(needle.len()).position(|w| w == needle).unwrap();
        &hay[i + needle.len()..]
    }

    #[test]
    fn ctap_register_and_authenticate_on_target(p: Peripherals) {
        let _source = TrngSource::new(p.RNG, p.ADC1);
        let mut platform = TargetPlatform::new(Trng::try_new().unwrap());
        let mut auth = Authenticator::new(AAGUID);
        let mut out = [0u8; MAX_MSG_SIZE];
        let mut req = [0u8; 256];

        let n = make_credential_request(&mut req);
        assert_eq!(auth.process(&mut platform, &req[..n], &mut out), Outcome::NeedsUserPresence);
        let len = auth.complete(&mut platform, PresenceResult::Confirmed, &mut out);
        assert_eq!(out[0], 0);
        // authData follows map key 2 and a one-byte-length byte-string head (0x58 len).
        let ad = after(&out[1..len], &[0x02, 0x58]);
        let ad = &ad[1..1 + usize::from(ad[0])];
        let mut cred_id = [0u8; CRED_ID_LEN];
        cred_id.copy_from_slice(&ad[55..55 + CRED_ID_LEN]);
        let cose = &ad[55 + CRED_ID_LEN..];
        let x = &after(cose, &[0x21, 0x58, 0x20])[..32];
        let y = &after(cose, &[0x22, 0x58, 0x20])[..32];
        let mut sec1 = [4u8; 65];
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        let pk = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();

        let n = get_assertion_request(&mut req, &cred_id);
        assert_eq!(auth.process(&mut platform, &req[..n], &mut out), Outcome::NeedsUserPresence);
        let len = auth.complete(&mut platform, PresenceResult::Confirmed, &mut out);
        assert_eq!(out[0], 0);
        let ad = &after(&out[1..len], &[0x02, 0x58, 37])[..37];
        let sig_field = after(&out[1..len], &[0x03, 0x58]);
        let sig = &sig_field[1..1 + usize::from(sig_field[0])];
        assert!(crypto::verify(&pk, &[ad, &[0xCD; 32]], sig), "assertion signature must verify");
        assert_eq!(&ad[33..37], &2u32.to_be_bytes(), "counter after register + assert");

        // No touch, no signature.
        let n = get_assertion_request(&mut req, &cred_id);
        let _ = auth.process(&mut platform, &req[..n], &mut out);
        let len = auth.complete(&mut platform, PresenceResult::Timeout, &mut out);
        assert_eq!((len, out[0]), (1, 0x2F));
        assert_eq!(platform.counter, 2);
    }

    // ---------------------------------------------------------------- peripherals

    #[test]
    fn status_led_accepts_frames(p: Peripherals) {
        use esp_hal::gpio::Level;
        use esp_hal::rmt::{PulseCode, Rmt, TxChannelConfig, TxChannelCreator};
        use esp_hal::time::Rate;
        let rmt = Rmt::new(p.RMT, Rate::from_mhz(80)).unwrap();
        let mut ch = rmt
            .channel0
            .configure_tx(&TxChannelConfig::default().with_clk_divider(1))
            .unwrap()
            .with_pin(p.GPIO8);
        let one = PulseCode::new(Level::High, 64, Level::Low, 36);
        let zero = PulseCode::new(Level::High, 32, Level::Low, 68);
        for color in [0x00_10_00u32, 0] {
            let mut frame = [PulseCode::end_marker(); 25];
            for (i, slot) in frame.iter_mut().take(24).enumerate() {
                *slot = if (color >> (23 - i)) & 1 == 1 { one } else { zero };
            }
            let tx = ch.transmit(&frame).map_err(|(e, _)| e).unwrap();
            ch = tx.wait().map_err(|(e, _)| e).unwrap();
        }
    }

    #[cfg(feature = "interactive")]
    #[test]
    fn user_presence_button(p: Peripherals) {
        use esp_hal::gpio::{Input, InputConfig, Pull};
        let button = Input::new(p.GPIO9, InputConfig::default().with_pull(Pull::Up));
        defmt::info!(">>> press the BOOT button within 30 s");
        let start = Instant::now();
        while button.is_high() {
            assert!(start.elapsed().as_secs() < 30, "no button press seen");
        }
        defmt::info!("button press detected after {} ms", start.elapsed().as_millis());
    }
}
