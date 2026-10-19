// (c) Javier Fernandez @ JotaSoft 2026
//! Jotakey firmware for the ESP32-C6 DevKit.
//!
//! Boot sequence (fail closed at every step, invariant 7):
//! 1. Clocks, heap, scheduler; logs go to the UART port only.
//! 2. TRNG start-up health test (SP 800-90B) and cryptographic known-answer tests.
//! 3. Root key check: the eFuse HMAC key must be provisioned (or the INSECURE `dev-key`
//!    feature is on, which the LED announces at every boot).
//! 4. Mount the counter/epoch logs.
//! 5. Start the USB tunnel, BLE (on demand) and the authenticator loop.
//!
//! Any failure leaves the authenticator in its permanent fault state: every request gets
//! `CTAP1_ERR_OTHER`, and the LED is solid red.

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod ble;
mod led;
mod link;
mod platform;
mod presence;
mod usb;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Pull};
#[cfg(not(feature = "dev-key"))]
use esp_hal::hmac::Hmac;
use esp_hal::rmt::{Rmt, TxChannelConfig, TxChannelCreator};
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb::usb_serial_jtag::UsbSerialJtag;
use esp_radio::ble::controller::BleConnector;
use esp_storage::FlashStorage;
use jotakey_core::ctap::{Authenticator, Outcome, Response};
use jotakey_core::platform::Platform;
use jotakey_core::selftest::{self, STARTUP_SAMPLES};
use jotakey_core::transport::ctaphid::keepalive;
use jotakey_core::{AAGUID, MAX_MSG_SIZE};
use static_cell::StaticCell;
use trouble_host::prelude::ExternalController;

use crate::link::{LED, LedState, REQUESTS, Transport};
use crate::platform::{EspPlatform, Region, RootKey};

esp_bootloader_esp_idf::esp_app_desc!();

/// Hold time that turns BLE on.
const BLE_HOLD: Duration = Duration::from_secs(3);

static OUT: StaticCell<Response> = StaticCell::new();

#[esp_hal::main]
async fn main(spawner: Spawner) {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 72 * 1024);
    let timg0 = TimerGroup::new(p.TIMG0);
    esp_rtos::start(timg0.timer0, p.FROM_CPU_INTR0);
    log::info!("jotakey {} booting", env!("CARGO_PKG_VERSION"));

    // LED first, so faults are visible.
    let led_ch = Rmt::new(p.RMT, Rate::from_mhz(80))
        .ok()
        .map(|rmt| rmt.into_async())
        .and_then(|rmt| rmt.channel0.configure_tx(&TxChannelConfig::default().with_clk_divider(1)).ok())
        .map(|ch| ch.with_pin(p.GPIO8));
    if let Some(ch) = led_ch
        && let Ok(t) = led::led_task(ch) {
            spawner.spawn(t);
        }

    let mut auth = Authenticator::new(AAGUID);
    let out = OUT.init([0u8; MAX_MSG_SIZE]);

    // Entropy: the TRNG needs the SAR ADC (and the radio once BLE runs) as noise sources.
    let _trng_source = TrngSource::new(p.RNG, p.ADC1);
    let trng = Trng::try_new();

    // Root key.
    #[cfg(not(feature = "dev-key"))]
    let root = RootKey::Efuse(Hmac::new(p.HMAC));
    #[cfg(feature = "dev-key")]
    let root = {
        let _ = p.HMAC;
        log::warn!("INSECURE dev-key build: root key derived from the MAC address");
        LED.signal(LedState::DevKey);
        let mac = esp_hal::efuse::base_mac_address();
        RootKey::Insecure(zeroize::Zeroizing::new(jotakey_core::crypto::sha256(&[
            b"jotakey/INSECURE-dev-key/v1",
            mac.as_bytes(),
        ])))
    };

    let platform = match trng {
        Ok(trng) => EspPlatform::new(trng, root, Region::new(FlashStorage::new(p.FLASH))).ok(),
        Err(_) => None,
    };
    let mut platform = match platform {
        Some(pl) => pl,
        None => {
            log::error!("platform init failed (TRNG or flash)");
            fault_forever(&mut auth, out).await
        }
    };

    // Power-on self tests (invariant 7).
    let mut samples = [0u8; STARTUP_SAMPLES];
    platform.raw_samples(&mut samples);
    if let Err(e) = selftest::startup_rng_test(&samples).and_then(|()| selftest::run_kats(None)) {
        log::error!("self test failed: {e:?}");
        fault_forever(&mut auth, out).await
    }
    // The root key must work (unprovisioned eFuse → HMAC peripheral refuses).
    let mut probe = zeroize::Zeroizing::new([0u8; 32]);
    if platform.derive_secret(jotakey_core::platform::SecretLabel::CredentialTag, &[], &mut probe).is_err() {
        log::error!("root key unavailable: provision the eFuse HMAC key (scripts/provision.sh)");
        fault_forever(&mut auth, out).await
    }
    drop(probe);
    log::info!("self tests passed; counter = {}", platform.counter_value());

    // Transports.
    let usb = UsbSerialJtag::new(p.USB_DEVICE).into_async();
    if let Ok(t) = usb::usb_task(usb) {
        spawner.spawn(t);
    }
    match BleConnector::new(p.BT, Default::default()) {
        Ok(connector) => {
            let controller: ExternalController<_, 1> = ExternalController::new(connector);
            let mac = esp_hal::efuse::base_mac_address();
            let mut addr = [0u8; 6];
            addr.copy_from_slice(mac.as_bytes());
            addr[5] |= 0xC0; // static random address: top two bits set
            if let Ok(t) = ble_task(controller, addr) {
                spawner.spawn(t);
            }
        }
        Err(_) => log::warn!("BLE controller unavailable; USB only"),
    }

    let mut button = Input::new(p.GPIO9, InputConfig::default().with_pull(Pull::Up));
    authenticator_loop(&mut auth, &mut platform, &mut button, out).await
}

#[embassy_executor::task]
async fn ble_task(controller: ExternalController<BleConnector<'static>, 1>, addr: [u8; 6]) {
    ble::run(controller, addr).await;
}

/// Serve requests forever. While idle, a 3 s button hold enables BLE.
async fn authenticator_loop(
    auth: &mut Authenticator,
    platform: &mut EspPlatform<'_>,
    button: &mut Input<'_>,
    out: &mut Response,
) -> ! {
    loop {
        let req = match select(REQUESTS.receive(), watch_long_press(button)).await {
            Either::First(req) => req,
            Either::Second(()) => {
                log::info!("BLE enabled for {} s", ble::BLE_WINDOW.as_secs());
                ble::BLE_ENABLE.signal(());
                continue;
            }
        };
        link::CANCEL.reset();
        let n = match auth.process(platform, &req.data, out) {
            Outcome::Response(n) => n,
            Outcome::NeedsUserPresence => {
                LED.signal(LedState::Touch);
                let status = match req.transport {
                    Transport::Usb => keepalive::UP_NEEDED,
                    Transport::Ble => jotakey_core::transport::ble::keepalive::UP_NEEDED,
                };
                let up = presence::wait(button, req.transport, status).await;
                LED.signal(LedState::Idle);
                auth.complete(platform, up, out)
            }
        };
        link::reply(req.transport, out.get(..n).unwrap_or(&[]));
    }
}

/// Resolve after the button has been held continuously for [`BLE_HOLD`].
async fn watch_long_press(button: &mut Input<'_>) {
    let mut since: Option<Instant> = None;
    loop {
        if button.is_low() {
            let t = *since.get_or_insert_with(Instant::now);
            if Instant::now() - t >= BLE_HOLD {
                // Wait for release so the same hold cannot confirm a later request.
                while button.is_low() {
                    Timer::after_millis(20).await;
                }
                return;
            }
        } else {
            since = None;
        }
        Timer::after_millis(50).await;
    }
}

/// Permanent fault: answer every request with `CTAP1_ERR_OTHER`, LED solid red.
async fn fault_forever(auth: &mut Authenticator, out: &mut Response) -> ! {
    auth.fault();
    LED.signal(LedState::Fault);
    loop {
        let req = REQUESTS.receive().await;
        // `process` in the fault state touches no hardware; any platform type works.
        let n = match auth.process(&mut NoPlatform, &req.data, out) {
            Outcome::Response(n) => n,
            Outcome::NeedsUserPresence => auth.complete(&mut NoPlatform, jotakey_core::platform::PresenceResult::Timeout, out),
        };
        link::reply(req.transport, out.get(..n).unwrap_or(&[]));
    }
}

/// A platform that refuses everything (used only in the fault state).
struct NoPlatform;

impl Platform for NoPlatform {
    fn random_bytes(&mut self, _: &mut [u8]) -> Result<(), jotakey_core::platform::PlatformError> {
        Err(jotakey_core::platform::PlatformError)
    }
    fn derive_secret(
        &mut self,
        _: jotakey_core::platform::SecretLabel,
        _: &[u8],
        _: &mut [u8; 32],
    ) -> Result<(), jotakey_core::platform::PlatformError> {
        Err(jotakey_core::platform::PlatformError)
    }
    fn increment_counter(&mut self) -> Result<u32, jotakey_core::platform::PlatformError> {
        Err(jotakey_core::platform::PlatformError)
    }
    fn rotate_epoch(&mut self) -> Result<(), jotakey_core::platform::PlatformError> {
        Err(jotakey_core::platform::PlatformError)
    }
    fn load_pin(&mut self) -> Result<jotakey_core::platform::PinRecord, jotakey_core::platform::PlatformError> {
        Err(jotakey_core::platform::PlatformError)
    }
    fn store_pin(&mut self, _: &jotakey_core::platform::PinRecord) -> Result<(), jotakey_core::platform::PlatformError> {
        Err(jotakey_core::platform::PlatformError)
    }
    fn uptime_ms(&self) -> u64 {
        u64::MAX
    }
}
