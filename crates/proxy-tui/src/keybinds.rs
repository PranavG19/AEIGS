use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Application-level actions triggered by key presses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    SwitchTab(usize),
    ToggleHelp,
    NavUp,
    NavDown,
    NavLeft,
    NavRight,
    Search,
    Enter,
    Escape,
    SendToRepeater,
    SendToIntruder,
    Save,
    None,
}

/// Map a crossterm KeyEvent to an Action.
pub fn key_to_action(event: KeyEvent) -> Action {
    match (event.code, event.modifiers) {
        (KeyCode::Char('q'), KeyModifiers::NONE) => Action::Quit,
        (KeyCode::Char('1'), KeyModifiers::NONE) => Action::SwitchTab(0),
        (KeyCode::Char('2'), KeyModifiers::NONE) => Action::SwitchTab(1),
        (KeyCode::Char('3'), KeyModifiers::NONE) => Action::SwitchTab(2),
        (KeyCode::Char('4'), KeyModifiers::NONE) => Action::SwitchTab(3),
        (KeyCode::Char('5'), KeyModifiers::NONE) => Action::SwitchTab(4),
        (KeyCode::Char('6'), KeyModifiers::NONE) => Action::SwitchTab(5),
        (KeyCode::Char('?'), KeyModifiers::NONE) => Action::ToggleHelp,
        (KeyCode::Char('k') | KeyCode::Up, KeyModifiers::NONE) => Action::NavUp,
        (KeyCode::Char('j') | KeyCode::Down, KeyModifiers::NONE) => Action::NavDown,
        (KeyCode::Char('h') | KeyCode::Left, KeyModifiers::NONE) => Action::NavLeft,
        (KeyCode::Char('l') | KeyCode::Right, KeyModifiers::NONE) => Action::NavRight,
        (KeyCode::Char('/'), KeyModifiers::NONE) => Action::Search,
        (KeyCode::Enter, KeyModifiers::NONE) => Action::Enter,
        (KeyCode::Esc, KeyModifiers::NONE) => Action::Escape,
        (KeyCode::Char('r'), KeyModifiers::NONE) => Action::SendToRepeater,
        (KeyCode::Char('i'), KeyModifiers::NONE) => Action::SendToIntruder,
        (KeyCode::Char('s'), KeyModifiers::NONE) => Action::Save,
        _ => Action::None,
    }
}

#[cfg(test)]
#[path = "keybinds_test.rs"]
mod keybinds_test;
