//! Transports that carry CTAP2 messages between host and core.
//!
//! Both are pure state machines over byte buffers. The firmware moves bytes between
//! them and the hardware (USB-Serial/JTAG for CTAPHID via the bridge, GATT for BLE).

pub mod ble;
pub mod ctaphid;
pub mod serial;
