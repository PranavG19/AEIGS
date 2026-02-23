use super::{ProxyStatus, StatusBarState};

#[test]
fn stopped_status_default() {
    let state = StatusBarState::new("127.0.0.1:8080".to_string());
    assert_eq!(state.proxy_status, ProxyStatus::Stopped);
    assert!(state.status_line().starts_with("[STOPPED]"));
}

#[test]
fn running_status_line() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.proxy_status = ProxyStatus::Running;
    assert!(state.status_line().starts_with("[RUNNING]"));
}

#[test]
fn singular_request() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.exchange_count = 1;
    assert!(state.status_line().contains("1 request"));
    assert!(!state.status_line().contains("1 requests"));
}

#[test]
fn plural_requests() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.exchange_count = 5;
    assert!(state.status_line().contains("5 requests"));
}

#[test]
fn scope_on_shows_count() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.scope_enabled = true;
    state.in_scope_count = 42;
    assert!(state.status_line().contains("Scope: ON (42 in-scope)"));
}

#[test]
fn scope_off_not_shown() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.scope_enabled = false;
    assert!(!state.status_line().contains("Scope"));
}

#[test]
fn filter_active_shows_text() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.filter_active = true;
    state.filter_text = Some("test".to_string());
    assert!(state.status_line().contains("Filter: test"));
}

#[test]
fn filter_active_no_text() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.filter_active = true;
    state.filter_text = None;
    assert!(state.status_line().contains("Filter: active"));
}

#[test]
fn filter_inactive_not_shown() {
    let mut state = StatusBarState::new("127.0.0.1:8080".to_string());
    state.filter_active = false;
    state.filter_text = Some("ignored".to_string());
    assert!(!state.status_line().contains("Filter"));
}
