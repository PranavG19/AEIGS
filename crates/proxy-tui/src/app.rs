use crate::keybinds::{Action, key_to_action};
use crossterm::event::KeyEvent;

/// The 6 TUI tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Proxy,
    Repeater,
    Intruder,
    Scope,
    Payloads,
    Comparer,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Proxy,
        Tab::Repeater,
        Tab::Intruder,
        Tab::Scope,
        Tab::Payloads,
        Tab::Comparer,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Proxy => "1:Proxy",
            Tab::Repeater => "2:Repeater",
            Tab::Intruder => "3:Intruder",
            Tab::Scope => "4:Scope",
            Tab::Payloads => "5:Payloads",
            Tab::Comparer => "6:Comparer",
        }
    }
}

/// Top-level application state.
pub struct App {
    pub active_tab: Tab,
    pub should_quit: bool,
    pub show_help: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            active_tab: Tab::Proxy,
            should_quit: false,
            show_help: false,
        }
    }

    /// Handle a key event, returning the derived action.
    pub fn handle_key(&mut self, event: KeyEvent) -> Action {
        let action = key_to_action(event);
        match action {
            Action::Quit => self.should_quit = true,
            Action::SwitchTab(idx) => {
                if let Some(&tab) = Tab::ALL.get(idx) {
                    self.active_tab = tab;
                }
            }
            Action::ToggleHelp => self.show_help = !self.show_help,
            _ => {}
        }
        action
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "app_test.rs"]
mod app_test;
