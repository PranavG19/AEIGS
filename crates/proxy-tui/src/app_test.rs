use crossterm::event::{KeyCode, KeyModifiers};

use super::*;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn starts_on_proxy_tab() {
    let app = App::new();
    assert_eq!(app.active_tab, Tab::Proxy);
    assert!(!app.should_quit);
    assert!(!app.show_help);
}

#[test]
fn quit_sets_flag() {
    let mut app = App::new();
    app.handle_key(key(KeyCode::Char('q')));
    assert!(app.should_quit);
}

#[test]
fn tab_switching_all_tabs() {
    let mut app = App::new();
    for (i, &tab) in Tab::ALL.iter().enumerate() {
        let digit = char::from_digit(i as u32 + 1, 10).unwrap();
        app.handle_key(key(KeyCode::Char(digit)));
        assert_eq!(app.active_tab, tab);
    }
}

#[test]
fn help_toggle() {
    let mut app = App::new();
    assert!(!app.show_help);
    app.handle_key(key(KeyCode::Char('?')));
    assert!(app.show_help);
    app.handle_key(key(KeyCode::Char('?')));
    assert!(!app.show_help);
}

#[test]
fn tab_titles() {
    assert_eq!(Tab::Proxy.title(), "1:Proxy");
    assert_eq!(Tab::Comparer.title(), "6:Comparer");
}
