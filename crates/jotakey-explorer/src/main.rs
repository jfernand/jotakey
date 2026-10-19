// (c) Javier Fernandez @ JotaSoft 2026
//! Terminal explorer for FIDO security keys.
//!
//!     jotakey-explorer          interactive; q quits
//!     jotakey-explorer --dump   print every device's report as plain text and exit

use std::time::Duration;

use jotakey_explorer::app::App;
use jotakey_explorer::ctaphid::{Error, Hidraw};
use jotakey_explorer::discover;
use jotakey_explorer::report::{self, Report};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

fn main() -> std::io::Result<()> {
    match std::env::args().nth(1).as_deref() {
        None => interactive(),
        Some("--dump") => dump(),
        Some(_) => {
            eprintln!("usage: jotakey-explorer [--dump]");
            std::process::exit(2);
        }
    }
}

fn interactive() -> std::io::Result<()> {
    let mut app = App::new();
    ratatui::run(|terminal| {
        while !app.quit {
            app.tick();
            terminal.draw(|frame| app.draw(frame))?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                app.on_key(key);
            }
        }
        Ok(())
    })
}

fn dump() -> std::io::Result<()> {
    let devices = discover::scan()?;
    if devices.is_empty() {
        println!("No FIDO devices found.");
    }
    for d in &devices {
        let r = match Hidraw::open(&d.path) {
            Ok(io) => report::query(d, io),
            Err(e) => Report {
                sections: report::local_sections(d),
                problems: vec![format!("cannot open {}: {}", d.path.display(), Error::Io(e))],
                ..Report::default()
            },
        };
        println!("== {} ({})", d.label(), d.path.display());
        for p in &r.problems {
            println!("! {p}");
        }
        for s in &r.sections {
            println!("{}", s.title);
            for row in &s.rows {
                let note = row.note.as_deref().map(|n| format!("   ({n})")).unwrap_or_default();
                println!("  {:<32} {}{note}", row.label, row.value);
            }
        }
        println!();
    }
    Ok(())
}
