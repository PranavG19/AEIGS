use super::*;

#[test]
fn new_jar_is_empty() {
    let jar = SessionJar::new();
    assert!(jar.cookies().is_empty());
    assert!(jar.auto_update);
}

#[test]
fn update_from_set_cookie_header() {
    let mut jar = SessionJar::new();
    let headers = vec![(
        "Set-Cookie".to_string(),
        "session_id=abc123; Path=/; Domain=.example.com".to_string(),
    )];
    jar.update_from_response("http://example.com/", &headers);
    assert_eq!(jar.cookies().len(), 1);
    assert_eq!(jar.cookies()[0].name, "session_id");
    assert_eq!(jar.cookies()[0].value, "abc123");
    assert_eq!(jar.cookies()[0].domain, "example.com");
    assert_eq!(jar.cookies()[0].path, "/");
}

#[test]
fn update_from_multiple_set_cookie() {
    let mut jar = SessionJar::new();
    let headers = vec![
        ("Set-Cookie".to_string(), "a=1; Path=/".to_string()),
        ("Set-Cookie".to_string(), "b=2; Path=/api".to_string()),
        ("Set-Cookie".to_string(), "c=3; Path=/".to_string()),
    ];
    jar.update_from_response("http://example.com/", &headers);
    assert_eq!(jar.cookies().len(), 3);
    let names: Vec<&str> = jar.cookies().iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
    assert!(names.contains(&"c"));
}

#[test]
fn cookies_for_url_matches_domain() {
    let mut jar = SessionJar::new();
    let headers = vec![
        (
            "Set-Cookie".to_string(),
            "a=1; Domain=example.com".to_string(),
        ),
        (
            "Set-Cookie".to_string(),
            "b=2; Domain=other.com".to_string(),
        ),
    ];
    jar.update_from_response("http://example.com/", &headers);
    let matched = jar.cookies_for_url("http://example.com/page");
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].name, "a");
}

#[test]
fn cookies_for_url_matches_path() {
    let mut jar = SessionJar::new();
    let headers = vec![
        ("Set-Cookie".to_string(), "root=1; Path=/".to_string()),
        ("Set-Cookie".to_string(), "api=2; Path=/api".to_string()),
    ];
    jar.update_from_response("http://example.com/", &headers);

    let root_match = jar.cookies_for_url("http://example.com/");
    assert_eq!(root_match.len(), 1);
    assert_eq!(root_match[0].name, "root");

    let api_match = jar.cookies_for_url("http://example.com/api/users");
    assert_eq!(api_match.len(), 2);
    let names: Vec<&str> = api_match.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"root"));
    assert!(names.contains(&"api"));
}

#[test]
fn inject_cookies_formats_header() {
    let mut jar = SessionJar::new();
    let headers = vec![
        ("Set-Cookie".to_string(), "a=1; Path=/".to_string()),
        ("Set-Cookie".to_string(), "b=2; Path=/".to_string()),
    ];
    jar.update_from_response("http://example.com/", &headers);
    let result = jar.inject_cookies("http://example.com/page");
    assert!(result.is_some());
    let (name, value) = result.unwrap();
    assert_eq!(name, "cookie");
    assert!(value.contains("a=1"));
    assert!(value.contains("b=2"));
    assert!(value.contains("; "));
}

#[test]
fn inject_cookies_empty_when_no_match() {
    let mut jar = SessionJar::new();
    let headers = vec![(
        "Set-Cookie".to_string(),
        "a=1; Domain=example.com; Path=/".to_string(),
    )];
    jar.update_from_response("http://example.com/", &headers);
    let result = jar.inject_cookies("http://other.com/page");
    assert!(result.is_none());
}

#[test]
fn is_session_cookie_detects_patterns() {
    assert!(SessionJar::is_session_cookie("session_id"));
    assert!(SessionJar::is_session_cookie("token"));
    assert!(SessionJar::is_session_cookie("auth_key"));
    assert!(SessionJar::is_session_cookie("JSESSIONID"));
    assert!(SessionJar::is_session_cookie("jwt_token"));
    assert!(SessionJar::is_session_cookie("csrf_token"));
    assert!(SessionJar::is_session_cookie("SID"));
    assert!(SessionJar::is_session_cookie("TOKEN_v2"));
}

#[test]
fn is_session_cookie_rejects_normal() {
    assert!(!SessionJar::is_session_cookie("color"));
    assert!(!SessionJar::is_session_cookie("language"));
    assert!(!SessionJar::is_session_cookie("theme"));
    assert!(!SessionJar::is_session_cookie("preference"));
}

#[test]
fn clear_empties_jar() {
    let mut jar = SessionJar::new();
    let headers = vec![("Set-Cookie".to_string(), "a=1; Path=/".to_string())];
    jar.update_from_response("http://example.com/", &headers);
    assert_eq!(jar.cookies().len(), 1);
    jar.clear();
    assert!(jar.cookies().is_empty());
}

#[test]
fn update_replaces_existing() {
    let mut jar = SessionJar::new();
    let headers1 = vec![(
        "Set-Cookie".to_string(),
        "token=old_val; Path=/; Domain=example.com".to_string(),
    )];
    jar.update_from_response("http://example.com/", &headers1);
    assert_eq!(jar.cookies()[0].value, "old_val");

    let headers2 = vec![(
        "Set-Cookie".to_string(),
        "token=new_val; Path=/; Domain=example.com".to_string(),
    )];
    jar.update_from_response("http://example.com/", &headers2);
    assert_eq!(jar.cookies().len(), 1);
    assert_eq!(jar.cookies()[0].value, "new_val");
}

#[test]
fn auto_update_disabled_ignores_headers() {
    let mut jar = SessionJar::with_auto_update(false);
    let headers = vec![("Set-Cookie".to_string(), "a=1; Path=/".to_string())];
    jar.update_from_response("http://example.com/", &headers);
    assert!(jar.cookies().is_empty());
}

#[test]
fn secure_cookie_attributes_parsed() {
    let mut jar = SessionJar::new();
    let headers = vec![(
        "Set-Cookie".to_string(),
        "tok=val; Path=/; Secure; HttpOnly".to_string(),
    )];
    jar.update_from_response("http://example.com/", &headers);
    assert_eq!(jar.cookies().len(), 1);
    assert!(jar.cookies()[0].secure);
    assert!(jar.cookies()[0].http_only);
}
