use super::*;

#[test]
fn quit_key() {
    let event = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
    assert_eq!(key_to_action(event), Action::Quit);
}

#[test]
fn tab_switching() {
    for i in 0..6 {
        let code = KeyCode::Char(char::from_digit(i as u32 + 1, 10).unwrap());
        let event = KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(key_to_action(event), Action::SwitchTab(i));
    }
}

#[test]
fn vim_navigation() {
    let cases = [
        (KeyCode::Char('j'), Action::NavDown),
        (KeyCode::Char('k'), Action::NavUp),
        (KeyCode::Char('h'), Action::NavLeft),
        (KeyCode::Char('l'), Action::NavRight),
    ];
    for (code, expected) in cases {
        let event = KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(key_to_action(event), expected);
    }
}

#[test]
fn arrow_navigation() {
    let cases = [
        (KeyCode::Down, Action::NavDown),
        (KeyCode::Up, Action::NavUp),
    ];
    for (code, expected) in cases {
        let event = KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(key_to_action(event), expected);
    }
}

#[test]
fn unknown_key_is_none() {
    let event = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE);
    assert_eq!(key_to_action(event), Action::None);
}
