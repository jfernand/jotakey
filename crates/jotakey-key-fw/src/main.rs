// (c) Javier Fernandez @ JotaSoft 2026
//! Jotakey firmware for the jotakey key (STM32L432KC + OPTIGA Trust M V1).
//!
//! Milestone 2: native USB CTAPHID, touch, LED, RNG and flash storage, and the OPTIGA Trust M
//! over its shielded connection: `K_root` and the signature counter live in the OPTIGA. A unit
//! that is not provisioned has no root and stays in the fault state. The INSECURE `dev-key`
//! build keeps a software root and never drives the OPTIGA. The human-run `provision` and
//! `provision-lock` builds set the OPTIGA up (`provision.rs`).
//!
//! Boot sequence (fail closed at every step, invariant 7):
//! 1. Clocks: HSI16 → PLL → 80 MHz system clock; HSI48 for USB and the RNG, trimmed by the
//!    clock recovery system from USB start-of-frame (no crystal, HARDWARE.md §2).
//! 2. LED first, so faults are visible.
//! 3. RNG start-up health test (SP 800-90B) and cryptographic known-answer tests.
//! 4. Mount the record logs; reset the OPTIGA, establish a live shielded session with the
//!    pairing secret from flash, and check that the root key derives.
//! 5. Calibrate the touch sensor, start USB and the authenticator loop.
//!
//! Any failure leaves the authenticator in its permanent fault state: every request gets
//! `CTAP1_ERR_OTHER`, and the LED is solid on. The log goes over SWD (defmt RTT), never USB.

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(all(feature = "dev-key", any(feature = "provision", feature = "provision-lock")))]
compile_error!("the provisioning images talk to the OPTIGA; they cannot be dev-key builds");
#[cfg(all(feature = "provision", feature = "provision-lock"))]
compile_error!("provision and provision-lock are separate images: provision first, lock later");

mod flash;
mod led;
mod link;
// The dev-key build never drives the OPTIGA.
#[cfg_attr(feature = "dev-key", allow(dead_code))]
mod optiga;
mod platform;
mod presence;
#[cfg(any(feature = "provision", feature = "provision-lock"))]
mod provision;
mod usb;

use defmt_rtt as _;
use embassy_executor::{InterruptExecutor, Spawner};
use embassy_stm32::flash::Flash;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::interrupt::{self, InterruptExt, Priority};
use embassy_stm32::peripherals;
use embassy_stm32::rng::{self, Rng};
use embassy_stm32::tsc::{self, Tsc};
use embassy_stm32::{Config, bind_interrupts, usb as stm_usb};
use jotakey_core::ctap::{Authenticator, Outcome, Response};
use jotakey_core::platform::{PinRecord, Platform, PlatformError, PresenceResult, SecretLabel};
use jotakey_core::selftest::{self, STARTUP_SAMPLES};
use jotakey_core::transport::ctaphid::keepalive;
use jotakey_core::{AAGUID, MAX_MSG_SIZE};
use panic_probe as _;
use static_cell::StaticCell;

use crate::link::{LED, LedState, REQUESTS};
use crate::platform::{KeyPlatform, RootKey, TrueRng};
use crate::presence::TouchSensor;

bind_interrupts!(struct Irqs {
    USB => stm_usb::InterruptHandler<peripherals::USB>;
    RNG => rng::InterruptHandler<peripherals::RNG>;
});

static OUT: StaticCell<Response> = StaticCell::new();

/// USB runs here, above the thread-mode executor of the authenticator, so that blocking work
/// in a request (an OPTIGA derivation of about 50 ms each, a flash erase) never stalls the USB
/// device or CTAPHID framing.
static USB_EXECUTOR: InterruptExecutor = InterruptExecutor::new();

/// SPI3 is unused on the key; its interrupt drives [`USB_EXECUTOR`].
#[embassy_stm32::interrupt]
unsafe fn SPI3() {
    // SAFETY: called only from this interrupt, the one `USB_EXECUTOR` was started on.
    unsafe { USB_EXECUTOR.on_interrupt() }
}

fn clocks() -> Config {
    use embassy_stm32::rcc::{Hsi48Config, Pll, PllMul, PllPreDiv, PllRDiv, PllSource, Sysclk, mux};
    let mut config = Config::default();
    config.rcc.hsi = true;
    config.rcc.pll = Some(Pll {
        source: PllSource::HSI,
        prediv: PllPreDiv::DIV1,
        mul: PllMul::MUL10,
        divp: None,
        divq: None,
        divr: Some(PllRDiv::DIV2), // 16 MHz × 10 / 2 = 80 MHz
    });
    config.rcc.sys = Sysclk::PLL1_R;
    config.rcc.hsi48 = Some(Hsi48Config { sync_from_usb: true });
    config.rcc.mux.clk48sel = mux::Clk48sel::HSI48;
    config
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(clocks());
    defmt::info!("jotakey key {} booting", env!("CARGO_PKG_VERSION"));

    // LED first, so faults are visible.
    let led = Output::new(p.PA3, Level::Low, Speed::Low);
    if let Ok(t) = led::led_task(led) {
        spawner.spawn(t);
    }

    let mut auth = Authenticator::new(AAGUID);
    let out = OUT.init([0u8; MAX_MSG_SIZE]);

    // USB starts early so that a faulty key still enumerates and answers CTAP1_ERR_OTHER.
    let driver = stm_usb::Driver::new(p.USB, Irqs, p.PA12, p.PA11);
    interrupt::SPI3.set_priority(Priority::P6);
    let usb_spawner = USB_EXECUTOR.start(interrupt::SPI3);
    if let Ok(t) = usb::usb_task(driver) {
        usb_spawner.spawn(t);
    }

    // Root key: the OPTIGA on I2C1, its reset on PA5.
    #[cfg(not(feature = "dev-key"))]
    let root = {
        let mut i2c_config = embassy_stm32::i2c::Config::default();
        i2c_config.frequency = embassy_stm32::time::Hertz(optiga::I2C_HZ);
        let i2c = embassy_stm32::i2c::I2c::new_blocking(p.I2C1, p.PA9, p.PA10, i2c_config);
        let reset = Output::new(p.PA5, Level::Low, Speed::Low);
        RootKey::Optiga(optiga::SecureElement::new(optiga::OptigaBus::new(i2c), reset))
    };
    // The dev-key build never drives the OPTIGA: its reset line stays low, so that with the
    // bring-up link R7 open nothing back-powers the secure element (HARDWARE.md §1).
    #[cfg(feature = "dev-key")]
    let _optiga_reset = Output::new(p.PA5, Level::Low, Speed::Low);
    #[cfg(feature = "dev-key")]
    let root = {
        defmt::warn!("INSECURE dev-key build: root key derived from the STM32 unique ID");
        LED.signal(LedState::DevKey);
        RootKey::Insecure(zeroize::Zeroizing::new(jotakey_core::crypto::sha256(&[
            b"jotakey/INSECURE-dev-key/v1",
            &embassy_stm32::uid::uid(),
        ])))
    };

    let rng = TrueRng::new(Rng::new(p.RNG, Irqs));
    let region = flash::Region::new(Flash::new_blocking(p.FLASH));
    let mut platform = match KeyPlatform::new(rng, root, region) {
        Ok(pl) => pl,
        Err(PlatformError) => {
            defmt::error!("platform init failed (RNG or flash)");
            fault_forever(&mut auth, out).await
        }
    };

    // Power-on self tests (invariant 7).
    let mut samples = [0u8; STARTUP_SAMPLES];
    let tested = platform
        .raw_samples(&mut samples)
        // A peripheral error is an RNG health failure as much as a failed statistical test.
        .map_err(|_| selftest::SelfTestError::RngRepetition)
        .and_then(|()| selftest::startup_rng_test(&samples))
        .and_then(|()| selftest::run_kats(None));
    if tested.is_err() {
        defmt::error!("self test failed");
        fault_forever(&mut auth, out).await
    }
    // The root key must work: a live session with the OPTIGA and one derivation (invariant 7).
    // The provisioning images skip this: they exist to create the root.
    #[cfg(not(any(feature = "provision", feature = "provision-lock")))]
    {
        if platform.uses_optiga() && !platform.is_provisioned() {
            defmt::error!("not provisioned: no pairing secret in flash (run the provision image)");
            fault_forever(&mut auth, out).await
        }
        let mut probe = zeroize::Zeroizing::new([0u8; 32]);
        if platform.derive_secret(SecretLabel::CredentialTag, &[], &mut probe).is_err() {
            defmt::error!("root key unavailable (OPTIGA unreachable or its session refused)");
            fault_forever(&mut auth, out).await
        }
    }
    defmt::info!("self tests passed");

    // Touch sensor: TSC group 2, PB4 sampling capacitor, PB5 electrode.
    let mut g2: tsc::pin_groups::PinGroupWithRoles<peripherals::TSC, tsc::pin_groups::G2> =
        tsc::pin_groups::PinGroupWithRoles::default();
    g2.set_io1::<tsc::pin_groups::pin_roles::Sample>(p.PB4);
    let electrode = g2.set_io2::<tsc::pin_groups::pin_roles::Channel>(p.PB5);
    let groups = tsc::pin_groups::PinGroups { g2: Some(g2.pin_group), ..Default::default() };
    let mut sensor = match Tsc::new_blocking(p.TSC, groups, tsc::Config::default()) {
        Ok(t) => TouchSensor::new(t, electrode.pin),
        Err(_) => {
            defmt::error!("touch controller init failed");
            fault_forever(&mut auth, out).await
        }
    };
    sensor.calibrate().await;

    #[cfg(feature = "provision")]
    provision::run_provision(&mut platform, &mut sensor).await;
    #[cfg(feature = "provision-lock")]
    provision::run_lock(&mut platform, &mut sensor).await;

    #[cfg_attr(any(feature = "provision", feature = "provision-lock"), allow(unreachable_code))]
    authenticator_loop(&mut auth, &mut platform, &mut sensor, out).await
}

/// Serve requests forever.
async fn authenticator_loop(
    auth: &mut Authenticator,
    platform: &mut KeyPlatform<'_>,
    sensor: &mut TouchSensor,
    out: &mut Response,
) -> ! {
    loop {
        let req = REQUESTS.receive().await;
        link::CANCEL.reset();
        // The command byte only: request data is never logged.
        defmt::info!("request: command {:#04x}", req.first().copied().unwrap_or(0));
        let n = match auth.process(platform, &req, out) {
            Outcome::Response(n) => n,
            Outcome::NeedsUserPresence => {
                LED.signal(LedState::Touch);
                let up = presence::wait(sensor, keepalive::UP_NEEDED).await;
                defmt::info!("user presence: {}", defmt::Debug2Format(&up));
                LED.signal(LedState::Idle);
                auth.complete(platform, up, out)
            }
        };
        link::reply(out.get(..n).unwrap_or(&[]));
    }
}

/// Permanent fault: answer every request with `CTAP1_ERR_OTHER`, LED solid on.
async fn fault_forever(auth: &mut Authenticator, out: &mut Response) -> ! {
    auth.fault();
    LED.signal(LedState::Fault);
    loop {
        let req = REQUESTS.receive().await;
        // `process` in the fault state touches no hardware; any platform type works.
        let n = match auth.process(&mut NoPlatform, &req, out) {
            Outcome::Response(n) => n,
            Outcome::NeedsUserPresence => auth.complete(&mut NoPlatform, PresenceResult::Timeout, out),
        };
        link::reply(out.get(..n).unwrap_or(&[]));
    }
}

/// A platform that refuses everything (used only in the fault state).
struct NoPlatform;

impl Platform for NoPlatform {
    fn random_bytes(&mut self, _: &mut [u8]) -> Result<(), PlatformError> {
        Err(PlatformError)
    }
    fn derive_secret(&mut self, _: SecretLabel, _: &[u8], _: &mut [u8; 32]) -> Result<(), PlatformError> {
        Err(PlatformError)
    }
    fn increment_counter(&mut self) -> Result<u32, PlatformError> {
        Err(PlatformError)
    }
    fn rotate_epoch(&mut self) -> Result<(), PlatformError> {
        Err(PlatformError)
    }
    fn load_pin(&mut self) -> Result<PinRecord, PlatformError> {
        Err(PlatformError)
    }
    fn store_pin(&mut self, _: &PinRecord) -> Result<(), PlatformError> {
        Err(PlatformError)
    }
    fn uptime_ms(&self) -> u64 {
        u64::MAX
    }
}
