// (c) Javier Fernandez @ JotaSoft 2026
//! The explorer's state, key handling and drawing.
//!
//! Device I/O runs on worker threads so a slow or silent key never freezes the screen;
//! results come back over a channel and are cached per device node. The device list is
//! rescanned from sysfs every two seconds, so keys can be plugged and unplugged freely.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph, Wrap};

use crate::cbor::{Value, hex};
use crate::ctaphid::Hidraw;
use crate::discover::{self, Device};
use crate::report::{self, Report};

const ACCENT: Color = Color::Rgb(0xF5, 0xB8, 0x00);
const RESCAN_EVERY: Duration = Duration::from_secs(2);

/// Which pane the arrow keys move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// The device list.
    Devices,
    /// The details pane (scrolling).
    Details,
}

/// What is known about one device node.
#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    /// A query is running.
    Querying,
    /// The query finished.
    Done(Report),
}

enum Msg {
    Report(PathBuf, Report),
    Wink(PathBuf, Result<(), String>),
}

/// The application.
pub struct App {
    /// FIDO devices, in node order.
    pub devices: Vec<Device>,
    /// Selection in the device list.
    pub list: ListState,
    /// Query results by device node.
    pub entries: HashMap<PathBuf, Entry>,
    /// Pane with the keyboard focus.
    pub focus: Focus,
    /// Details scroll offset, in lines.
    pub scroll: u16,
    /// Show the raw getInfo bytes.
    pub raw: bool,
    /// One-line message for the footer.
    pub status: String,
    /// Set when the user asked to leave.
    pub quit: bool,
    scan_error: Option<String>,
    last_scan: Option<Instant>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// An empty explorer; call [`App::rescan`] to fill it.
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            devices: Vec::new(),
            list: ListState::default(),
            entries: HashMap::new(),
            focus: Focus::Devices,
            scroll: 0,
            raw: false,
            status: String::new(),
            quit: false,
            scan_error: None,
            last_scan: None,
            tx,
            rx,
        }
    }

    /// The selected device.
    pub fn selected(&self) -> Option<&Device> {
        self.list.selected().and_then(|i| self.devices.get(i))
    }

    /// Re-read the device list from sysfs, keeping the selection on the same node.
    pub fn rescan(&mut self) {
        self.last_scan = Some(Instant::now());
        match discover::scan() {
            Ok(devices) => {
                self.scan_error = None;
                self.set_devices(devices);
            }
            Err(e) => self.scan_error = Some(format!("cannot read /sys/class/hidraw: {e}")),
        }
    }

    /// Replace the device list (from a scan, or from a test).
    pub fn set_devices(&mut self, devices: Vec<Device>) {
        let keep = self.selected().map(|d| d.path.clone());
        self.entries.retain(|path, _| devices.iter().any(|d| &d.path == path));
        self.devices = devices;
        let index = keep.and_then(|p| self.devices.iter().position(|d| d.path == p));
        self.list.select(index.or(if self.devices.is_empty() { None } else { Some(0) }));
        self.query_selected(false);
    }

    /// Start a query of the selected device unless one is cached (or `force`).
    pub fn query_selected(&mut self, force: bool) {
        let Some(device) = self.selected().cloned() else { return };
        match self.entries.get(&device.path) {
            Some(Entry::Querying) => return,
            Some(Entry::Done(_)) if !force => return,
            _ => {}
        }
        self.entries.insert(device.path.clone(), Entry::Querying);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let report = match Hidraw::open(&device.path) {
                Ok(io) => report::query(&device, io),
                Err(e) => Report {
                    sections: vec![report::device_section(&device)],
                    problems: vec![format!("cannot open {}: {}", device.path.display(), crate::ctaphid::Error::Io(e))],
                    ..Report::default()
                },
            };
            let _ = tx.send(Msg::Report(device.path, report));
        });
    }

    fn wink_selected(&mut self) {
        let Some(device) = self.selected().cloned() else { return };
        self.status = format!("winking {}…", device.node());
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = Hidraw::open(&device.path)
                .map_err(|e| crate::ctaphid::Error::Io(e).to_string())
                .and_then(|io| report::wink(io).map_err(|e| e.to_string()));
            let _ = tx.send(Msg::Wink(device.path, result));
        });
    }

    /// Collect finished work and rescan when due. Call once per frame.
    pub fn tick(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Report(path, report) => {
                    if self.devices.iter().any(|d| d.path == path) {
                        self.entries.insert(path, Entry::Done(report));
                    }
                }
                Msg::Wink(path, Ok(())) => self.status = format!("{} winked", path.display()),
                Msg::Wink(path, Err(e)) => self.status = format!("wink {}: {e}", path.display()),
            }
        }
        if self.last_scan.is_none_or(|t| t.elapsed() >= RESCAN_EVERY) {
            self.rescan();
        }
    }

    fn select(&mut self, delta: isize) {
        if self.devices.is_empty() {
            return;
        }
        let last = self.devices.len() - 1;
        let current = self.list.selected().unwrap_or(0);
        let next = current.saturating_add_signed(delta).min(last);
        if next != current {
            self.list.select(Some(next));
            self.scroll = 0;
            self.query_selected(false);
        }
    }

    fn scroll_by(&mut self, delta: i32) {
        self.scroll = u16::try_from((i32::from(self.scroll) + delta).max(0)).unwrap_or(u16::MAX);
    }

    /// Handle one key press.
    pub fn on_key(&mut self, key: KeyEvent) {
        let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            _ if ctrl_c => self.quit = true,
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = if self.focus == Focus::Devices { Focus::Details } else { Focus::Devices };
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.focus = Focus::Details,
            KeyCode::Left | KeyCode::Char('h') => self.focus = Focus::Devices,
            KeyCode::Up | KeyCode::Char('k') => match self.focus {
                Focus::Devices => self.select(-1),
                Focus::Details => self.scroll_by(-1),
            },
            KeyCode::Down | KeyCode::Char('j') => match self.focus {
                Focus::Devices => self.select(1),
                Focus::Details => self.scroll_by(1),
            },
            KeyCode::PageUp => self.scroll_by(-10),
            KeyCode::PageDown => self.scroll_by(10),
            KeyCode::Home | KeyCode::Char('g') => self.scroll = 0,
            KeyCode::Char('r') => {
                self.rescan();
                self.query_selected(true);
                self.status = "rescanned".into();
            }
            KeyCode::Char('w') => self.wink_selected(),
            KeyCode::Char('x') => self.raw = !self.raw,
            _ => {}
        }
    }

    /// Draw the whole screen.
    pub fn draw(&mut self, frame: &mut Frame<'_>) {
        let [header, body, footer] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]).areas(frame.area());
        frame.render_widget(
            Line::from(vec![
                Span::styled(" jotakey-explorer ", Style::new().fg(Color::Black).bg(ACCENT).bold()),
                Span::raw("  FIDO security keys on this computer (read-only)"),
            ]),
            header,
        );
        let [left, right] = Layout::horizontal([Constraint::Percentage(34), Constraint::Fill(1)]).areas(body);
        self.draw_devices(frame, left);
        self.draw_details(frame, right);
        let help = "↑↓/jk select or scroll · Tab/Enter switch pane · PgUp/PgDn · r rescan · w wink · x raw · q quit";
        let line = if self.status.is_empty() {
            Line::from(Span::styled(help, Style::new().dark_gray()))
        } else {
            Line::from(vec![Span::styled(format!("{}  ", self.status), Style::new().fg(ACCENT)), Span::styled(help, Style::new().dark_gray())])
        };
        frame.render_widget(line, footer);
    }

    fn pane(&self, title: &str, focus: Focus) -> Block<'static> {
        let style = if self.focus == focus { Style::new().fg(ACCENT) } else { Style::new().dark_gray() };
        Block::bordered().border_type(BorderType::Rounded).border_style(style).title(format!(" {title} "))
    }

    fn draw_devices(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let block = self.pane(&format!("Devices ({})", self.devices.len()), Focus::Devices);
        if self.devices.is_empty() {
            let msg = self.scan_error.clone().unwrap_or_else(|| {
                "No FIDO devices found.\n\nPlug in a security key, or start jotakey-bridge for a C6 DevKit. The list refreshes by itself.".into()
            });
            frame.render_widget(Paragraph::new(msg).wrap(Wrap { trim: true }).block(block), area);
            return;
        }
        let items: Vec<ListItem> = self
            .devices
            .iter()
            .map(|d| {
                let state = match self.entries.get(&d.path) {
                    Some(Entry::Querying) => Span::styled(" …", Style::new().dark_gray()),
                    Some(Entry::Done(r)) if r.problems.is_empty() => Span::styled(" ●", Style::new().green()),
                    Some(Entry::Done(_)) => Span::styled(" ●", Style::new().red()),
                    None => Span::raw(""),
                };
                ListItem::new(Text::from(vec![
                    Line::from(vec![Span::styled(d.label(), Style::new().bold()), state]),
                    Line::from(Span::styled(
                        format!("{}  {:04x}:{:04x}  {}{}", d.node(), d.vendor_id, d.product_id, d.bus, if d.virtual_device { " (virtual)" } else { "" }),
                        Style::new().dark_gray(),
                    )),
                ]))
            })
            .collect();
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::new().bg(Color::Rgb(0x3A, 0x3A, 0x3A)))
            .highlight_symbol("▌ ");
        frame.render_stateful_widget(list, area, &mut self.list);
    }

    fn draw_details(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let Some(device) = self.selected().cloned() else {
            frame.render_widget(Paragraph::new("").block(self.pane("Details", Focus::Details)), area);
            return;
        };
        let lines = match self.entries.get(&device.path) {
            Some(Entry::Done(report)) => report_lines(report, self.raw),
            _ => {
                let mut lines = section_lines(&report::device_section(&device));
                lines.push(Line::from(Span::styled("Querying the device…", Style::new().fg(ACCENT))));
                lines
            }
        };
        // Keep at least one line on screen however far the user scrolled.
        let max = u16::try_from(lines.len().saturating_sub(1)).unwrap_or(u16::MAX);
        self.scroll = self.scroll.min(max);
        let block = self.pane(&device.label(), Focus::Details);
        frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }).scroll((self.scroll, 0)), area);
    }
}

fn section_lines(section: &report::Section) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(section.title.clone(), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)))];
    let width = section.rows.iter().map(|r| r.label.chars().count()).max().unwrap_or(0).min(32);
    for r in &section.rows {
        let mut spans = vec![
            Span::styled(format!("  {:<width$}  ", r.label), Style::new().dark_gray()),
            Span::raw(r.value.clone()),
        ];
        if let Some(note) = &r.note {
            spans.push(Span::styled(format!("  {note}"), Style::new().dark_gray().italic()));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    lines
}

/// The details pane's text for a finished report.
pub fn report_lines(report: &Report, raw: bool) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for p in &report.problems {
        lines.push(Line::from(Span::styled(format!("⚠ {p}"), Style::new().red())));
    }
    if !report.problems.is_empty() {
        lines.push(Line::raw(""));
    }
    for s in &report.sections {
        lines.extend(section_lines(s));
    }
    match (&report.raw_get_info, raw) {
        (Some(bytes), true) => {
            lines.push(Line::from(Span::styled(
                format!("Raw getInfo ({} bytes)", bytes.len()),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            )));
            for chunk in bytes.chunks(24) {
                lines.push(Line::from(Span::styled(format!("  {}", hex(chunk)), Style::new().dark_gray())));
            }
            if let Some(v) = Value::decode(bytes) {
                lines.push(Line::raw(""));
                lines.push(Line::raw(format!("  {v}")));
            }
        }
        (Some(_), false) => lines.push(Line::from(Span::styled("x shows the raw getInfo reply", Style::new().dark_gray()))),
        _ => {}
    }
    lines
}
