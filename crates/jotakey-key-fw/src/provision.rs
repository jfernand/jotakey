// (c) Javier Fernandez @ JotaSoft 2026
//! The human-run provisioning images (AGENTS.md §3a, §4). Neither is ever flashed or run by
//! automation (building them, as CI does, changes nothing).
//!
//! - `--features provision`: pair the OPTIGA and create `K_root`, the freshness secret and the
//!   counter (`jotakey_core::optiga::provision::provision`). Every step can be undone while the
//!   OPTIGA's objects are below life cycle operational, and provisioning may run again; it
//!   refuses if this unit's flash already holds a pairing secret (erase the storage region with
//!   probe-rs to start over). A unit provisioned but not locked is a development unit: someone
//!   on its bus can reopen the access conditions.
//! - `--features provision-lock`: **IRREVERSIBLE.** Set the OPTIGA objects' life cycle to
//!   operational (`jotakey_core::optiga::provision::lock`), freezing their access conditions:
//!   `K_root` can then never be read or changed, and the counter never rewritten.
//!
//! Each waits for the touch pad to be held (3 s to provision, 10 s to lock) before acting,
//! with the LED blinking slowly, and reports over SWD. Afterwards the LED blinks fast if it
//! worked and stays solid on if it failed (the log says why).

use embassy_time::{Duration, Timer};

use crate::link::{LED, LedState};
use crate::platform::KeyPlatform;
use crate::presence::TouchSensor;

const POLL: Duration = Duration::from_millis(20);

/// Wait until the pad has been touched continuously for `ms` milliseconds.
async fn wait_hold(sensor: &mut TouchSensor, ms: u64) {
    let mut held: u64 = 0;
    while held < ms {
        Timer::after(POLL).await;
        held = if sensor.touched() { held.saturating_add(POLL.as_millis()) } else { 0 };
    }
}

async fn park(ok: bool) -> ! {
    LED.signal(if ok { LedState::Wink } else { LedState::Fault });
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}

/// The `provision` image.
#[cfg(feature = "provision")]
pub async fn run_provision(platform: &mut KeyPlatform<'_>, sensor: &mut TouchSensor) -> ! {
    if platform.is_provisioned() {
        defmt::error!("already provisioned: erase the storage region (0x0803_8000, 32 KB) to start over");
        park(false).await
    }
    defmt::warn!("PROVISIONING: hold the touch pad for 3 s to pair the OPTIGA and create the root key");
    LED.signal(LedState::Touch);
    wait_hold(sensor, 3_000).await;
    LED.signal(LedState::Idle);
    match platform.provision() {
        Ok(()) => {
            defmt::info!("provisioned (not locked); flash the normal firmware, or provision-lock to lock");
            park(true).await
        }
        Err(e) => {
            defmt::error!("provisioning failed: {}", defmt::Debug2Format(&e));
            park(false).await
        }
    }
}

/// The `provision-lock` image.
#[cfg(feature = "provision-lock")]
pub async fn run_lock(platform: &mut KeyPlatform<'_>, sensor: &mut TouchSensor) -> ! {
    if !platform.is_provisioned() {
        defmt::error!("not provisioned: run the provision image first");
        park(false).await
    }
    defmt::warn!("IRREVERSIBLE: hold the touch pad for 10 s to lock the OPTIGA (life cycle operational)");
    LED.signal(LedState::Touch);
    wait_hold(sensor, 10_000).await;
    LED.signal(LedState::Idle);
    match platform.lock() {
        Ok(()) => {
            defmt::info!("locked; flash the normal firmware");
            park(true).await
        }
        Err(_) => {
            defmt::error!("locking failed (objects locked before the failure stay locked)");
            park(false).await
        }
    }
}
