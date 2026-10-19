// (c) Javier Fernandez @ JotaSoft 2026
//! The explorer against whatever FIDO keys are plugged in. Ignored by default:
//!
//! ```sh
//! cargo test -p jotakey-explorer --test device -- --ignored --nocapture
//! ```
//!
//! No touch is needed; the keys blink once (WINK) if they can.

use jotakey_explorer::ctaphid::Hidraw;
use jotakey_explorer::{discover, report};

#[test]
#[ignore = "needs at least one FIDO key (or jotakey-bridge)"]
fn every_attached_key_answers_and_winks() {
    let devices = discover::scan().expect("sysfs");
    assert!(!devices.is_empty(), "no FIDO devices attached");
    for d in &devices {
        let r = report::query(d, Hidraw::open(&d.path).expect("open"));
        eprintln!("{}: {} sections, problems {:?}", d.path.display(), r.sections.len(), r.problems);
        assert!(r.problems.is_empty(), "{}: {:?}", d.path.display(), r.problems);
        let caps = r.sections.iter().find(|s| s.title == "CTAPHID").expect("INIT answered");
        let winks = caps.rows.iter().any(|row| row.value.contains("WINK"));
        if winks {
            report::wink(Hidraw::open(&d.path).expect("open")).expect("wink");
        }
    }
}
