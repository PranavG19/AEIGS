use super::*;

#[test]
fn is_localhost_api_url_accepts_localhost() {
    assert!(is_localhost_api_url("http://localhost:3000/api/data"));
}

#[test]
fn is_localhost_api_url_accepts_127_0_0_1() {
    assert!(is_localhost_api_url("http://127.0.0.1:8080/api/users"));
}

#[test]
fn is_localhost_api_url_accepts_ipv6_loopback() {
    assert!(is_localhost_api_url("http://[::1]:3000/api/data"));
}

#[test]
fn is_localhost_api_url_rejects_remote() {
    assert!(!is_localhost_api_url("https://api.example.com/v1/data"));
}

#[test]
fn is_localhost_api_url_rejects_invalid_url() {
    assert!(!is_localhost_api_url("not-a-url"));
}

#[test]
fn is_localhost_api_url_rejects_empty() {
    assert!(!is_localhost_api_url(""));
}

#[test]
fn is_localhost_api_url_accepts_localhost_no_port() {
    assert!(is_localhost_api_url("http://localhost/api"));
}
