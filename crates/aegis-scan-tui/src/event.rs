use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

use crate::app::{ActiveView, AttackChain, Finding, LogLevel, ScanPhase};

/// Events that flow from the scan runner or user input into the App.
#[derive(Debug, Clone)]
pub enum TuiEvent {
    PhaseChanged { phase: ScanPhase, progress: f64 },
    PhaseProgress { phase: ScanPhase, progress: f64 },
    EndpointDiscovered { endpoint: String, method: String },
    FindingConfirmed(Box<Finding>),
    ChainDiscovered(AttackChain),
    ModuleStarted { name: String },
    ModuleStopped { name: String },
    RequestMade,
    StealthUpdate { score: u8 },
    Log { level: LogLevel, message: String },
    ScanComplete,
    Tick,
}

/// User-triggered action from keyboard input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    Pause,
    Filter,
    ScrollUp,
    ScrollDown,
    SelectNext,
    SelectPrev,
    Enter,
    Escape,
    ShowStats,
    Export,
    None,
}

/// Map a key event to an action.
pub fn map_key(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
        KeyCode::Char('p') => Action::Pause,
        KeyCode::Char('f') => Action::Filter,
        KeyCode::Char('s') => Action::ShowStats,
        KeyCode::Char('e') => Action::Export,
        KeyCode::Up | KeyCode::Char('k') => Action::ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => Action::ScrollDown,
        KeyCode::Tab => Action::SelectNext,
        KeyCode::BackTab => Action::SelectPrev,
        KeyCode::Enter => Action::Enter,
        KeyCode::Esc => Action::Escape,
        _ => Action::None,
    }
}

/// Handle a user action by mutating app state. Returns true if the event loop
/// should continue processing (false = quit).
pub fn handle_action(app: &mut crate::app::App, action: Action) -> bool {
    match action {
        Action::Quit => {
            app.should_quit = true;
            return false;
        }
        Action::Pause => {
            app.is_paused = !app.is_paused;
        }
        Action::Enter => {
            if app.active_view == ActiveView::Dashboard && !app.findings.is_empty() {
                app.active_view = ActiveView::FindingDetail;
            }
        }
        Action::Escape => {
            if app.active_view != ActiveView::Dashboard {
                app.active_view = ActiveView::Dashboard;
            }
        }
        Action::ShowStats => {
            app.active_view = if app.active_view == ActiveView::Stats {
                ActiveView::Dashboard
            } else {
                ActiveView::Stats
            };
        }
        Action::ScrollUp => {
            if app.active_view == ActiveView::FindingDetail {
                app.selected_finding = app.selected_finding.saturating_sub(1);
            } else {
                app.findings_scroll_offset = app.findings_scroll_offset.saturating_sub(1);
            }
        }
        Action::ScrollDown => {
            if app.active_view == ActiveView::FindingDetail {
                if app.selected_finding + 1 < app.findings.len() {
                    app.selected_finding += 1;
                }
            } else if app.findings_scroll_offset + 1 < app.findings.len() {
                app.findings_scroll_offset += 1;
            }
        }
        Action::SelectNext => {
            if app.selected_finding + 1 < app.findings.len() {
                app.selected_finding += 1;
            }
        }
        Action::SelectPrev => {
            app.selected_finding = app.selected_finding.saturating_sub(1);
        }
        Action::Export | Action::Filter | Action::None => {}
    }
    true
}

/// Poll terminal for a key event within the given timeout.
pub fn poll_key(timeout: Duration) -> Option<KeyEvent> {
    if event::poll(timeout).unwrap_or(false)
        && let Ok(Event::Key(key)) = event::read()
    {
        return Some(key);
    }
    None
}

#[cfg(test)]
#[path = "event_test.rs"]
mod event_test;
