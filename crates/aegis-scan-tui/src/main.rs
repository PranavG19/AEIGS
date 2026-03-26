mod app;
mod event;
mod scan_runner;
mod ui;
mod detail_view;
mod stats_view;
mod exporter;

use std::io;
use std::time::Duration;

use clap::Parser;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;

use app::{ActiveView, App, ScanProfile};
use event::{Action, handle_action, map_key, poll_key};

/// AEGIS Scan TUI — Real-time attack dashboard.
#[derive(Parser, Debug)]
#[command(name = "aegis-scan-tui", about = "Real-time AEGIS scan dashboard")]
struct Cli {
    /// Target URL to scan.
    #[arg(long)]
    target: String,

    /// Scan profile: quick, standard, deep, stealth.
    #[arg(long, default_value = "standard")]
    profile: String,

    /// Demo mode: generate realistic fake events instead of a real scan.
    #[arg(long)]
    demo: bool,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let profile: ScanProfile = cli.profile.parse().unwrap_or(ScanProfile::Standard);
    let mut app = App::new(cli.target.clone(), profile);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, rx) = std::sync::mpsc::channel();
    let _scan_handle = scan_runner::spawn_scan(
        cli.target,
        profile,
        cli.demo,
        tx,
    );

    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|frame| match app.active_view {
            ActiveView::Dashboard => ui::render_dashboard(frame, &app),
            ActiveView::FindingDetail => detail_view::render_detail(frame, &app),
            ActiveView::Stats => stats_view::render_stats(frame, &app),
        })?;

        if let Some(key) = poll_key(tick_rate) {
            let action = map_key(key);

            if action == Action::Export {
                let _ = exporter::export_findings(&app);
            }

            if !handle_action(&mut app, action) {
                break;
            }
        }

        while let Ok(evt) = rx.try_recv() {
            if !app.is_paused {
                app.apply_event(evt);
            }
        }

        app.apply_event(event::TuiEvent::Tick);

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
