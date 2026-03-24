use super::*;

#[test]
fn new_session_starts_empty() {
    let manager = SessionManager::new(50);
    assert_eq!(manager.session_id(), 0);
    assert_eq!(manager.requests_in_session(), 0);
    assert!(manager.last_url().is_none());
    assert!(manager.session_headers().is_empty());
}

#[test]
fn record_request_adds_to_history() {
    let mut manager = SessionManager::new(50);
    manager.record_request("https://example.com/page1");
    manager.record_request("https://example.com/page2");
    assert_eq!(manager.requests_in_session(), 2);
}

#[test]
fn last_url_returns_most_recent() {
    let mut manager = SessionManager::new(50);
    manager.record_request("https://example.com/first");
    manager.record_request("https://example.com/second");
    assert_eq!(manager.last_url(), Some("https://example.com/second"));
}

#[test]
fn process_set_cookie_stores_cookie() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("session=abc123; Path=/; HttpOnly");
    let headers = manager.session_headers();
    let cookie_header = headers.iter().find(|(k, _)| k == "Cookie");
    assert!(cookie_header.is_some());
    assert_eq!(cookie_header.unwrap().1, "session=abc123");
}

#[test]
fn session_headers_returns_cookie_when_cookies_exist() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("token=xyz");
    let headers = manager.session_headers();
    assert!(headers.iter().any(|(k, _)| k == "Cookie"));
}

#[test]
fn session_headers_returns_referer_from_last_url() {
    let mut manager = SessionManager::new(50);
    manager.record_request("https://example.com/origin");
    let headers = manager.session_headers();
    let referer = headers.iter().find(|(k, _)| k == "Referer");
    assert!(referer.is_some());
    assert_eq!(referer.unwrap().1, "https://example.com/origin");
}

#[test]
fn session_headers_empty_when_no_state() {
    let manager = SessionManager::new(50);
    assert!(manager.session_headers().is_empty());
}

#[test]
fn auto_rotation_at_threshold() {
    let mut manager = SessionManager::new(3);
    manager.record_request("https://example.com/1");
    manager.record_request("https://example.com/2");
    assert_eq!(manager.session_id(), 0);
    manager.record_request("https://example.com/3");
    assert_eq!(manager.session_id(), 1);
    assert_eq!(manager.requests_in_session(), 0);
    assert!(manager.last_url().is_none());
}

#[test]
fn manual_rotate_clears_state() {
    let mut manager = SessionManager::new(50);
    manager.record_request("https://example.com/page");
    manager.process_set_cookie("key=val");
    manager.rotate_session();
    assert_eq!(manager.session_id(), 1);
    assert_eq!(manager.requests_in_session(), 0);
    assert!(manager.last_url().is_none());
    assert!(manager.session_headers().is_empty());
}

#[test]
fn multiple_cookies_combined_in_header() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("name1=val1");
    manager.process_set_cookie("name2=val2");
    let headers = manager.session_headers();
    let cookie_header = headers.iter().find(|(k, _)| k == "Cookie").unwrap();
    let parts: Vec<&str> = cookie_header.1.split("; ").collect();
    assert_eq!(parts.len(), 2);
    assert!(parts.contains(&"name1=val1"));
    assert!(parts.contains(&"name2=val2"));
}

#[test]
fn process_set_cookie_overwrites_same_name() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("session=old_value");
    manager.process_set_cookie("session=new_value");
    let headers = manager.session_headers();
    let cookie_header = headers.iter().find(|(k, _)| k == "Cookie").unwrap();
    assert_eq!(cookie_header.1, "session=new_value");
}

#[test]
fn default_creates_manager_with_50_max() {
    let manager = SessionManager::default();
    assert_eq!(manager.session_id(), 0);
    assert_eq!(manager.requests_in_session(), 0);
}

#[test]
fn process_set_cookie_ignores_empty_name() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("=value_only");
    assert!(manager.session_headers().is_empty());
}

#[test]
fn process_set_cookie_ignores_no_equals() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("no-equals-sign");
    assert!(manager.session_headers().is_empty());
}

#[test]
fn process_set_cookie_trims_whitespace() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("  name  =  value  ; Path=/");
    let headers = manager.session_headers();
    let cookie = headers.iter().find(|(k, _)| k == "Cookie").unwrap();
    assert_eq!(cookie.1, "name=value");
}

#[test]
fn max_requests_one_rotates_every_request() {
    let mut manager = SessionManager::new(1);
    manager.record_request("https://example.com/a");
    assert_eq!(manager.session_id(), 1);
    manager.record_request("https://example.com/b");
    assert_eq!(manager.session_id(), 2);
    manager.record_request("https://example.com/c");
    assert_eq!(manager.session_id(), 3);
}

#[test]
fn cookie_with_equals_in_value() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("token=abc=def=ghi; Path=/");
    let headers = manager.session_headers();
    let cookie = headers.iter().find(|(k, _)| k == "Cookie").unwrap();
    assert_eq!(cookie.1, "token=abc=def=ghi");
}

#[test]
fn rotation_clears_cookies_but_increments_id() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("session=abc");
    manager.process_set_cookie("token=xyz");
    assert_eq!(manager.session_id(), 0);
    manager.rotate_session();
    assert_eq!(manager.session_id(), 1);
    assert!(manager.session_headers().is_empty());
}

#[test]
fn multiple_rotations_increment_session_id() {
    let mut manager = SessionManager::new(50);
    for i in 0..10 {
        assert_eq!(manager.session_id(), i as u64);
        manager.rotate_session();
    }
    assert_eq!(manager.session_id(), 10);
}

#[test]
fn referer_and_cookie_together_in_headers() {
    let mut manager = SessionManager::new(50);
    manager.record_request("https://example.com/origin");
    manager.process_set_cookie("session=abc");
    let headers = manager.session_headers();
    assert!(headers.iter().any(|(k, _)| k == "Cookie"));
    assert!(headers.iter().any(|(k, _)| k == "Referer"));
    assert_eq!(headers.len(), 2);
}

#[test]
fn process_set_cookie_empty_string() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie("");
    assert!(manager.session_headers().is_empty());
}

#[test]
fn process_set_cookie_only_semicolons() {
    let mut manager = SessionManager::new(50);
    manager.process_set_cookie(";;;");
    assert!(manager.session_headers().is_empty());
}

#[test]
fn auto_rotation_clears_cookies() {
    let mut manager = SessionManager::new(2);
    manager.process_set_cookie("session=abc");
    manager.record_request("https://example.com/1");
    let headers = manager.session_headers();
    assert!(headers.iter().any(|(k, _)| k == "Cookie"));
    manager.record_request("https://example.com/2");
    assert_eq!(manager.session_id(), 1);
    assert!(manager.session_headers().is_empty());
}
