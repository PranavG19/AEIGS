use super::*;

#[test]
fn modify_request_header_value() {
    let rule = ModificationRule {
        id: 1,
        enabled: true,
        match_target: MatchTarget::RequestHeader,
        match_pattern: r"User-Agent: .+".to_string(),
        replace_with: "User-Agent: AegisScanner/1.0".to_string(),
    };
    let mut headers = vec![
        ("Host".to_string(), "localhost".to_string()),
        ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
    ];
    let mut body = Vec::new();
    apply_request_modifications(&[rule], &mut headers, &mut body);
    assert_eq!(headers[1].0, "User-Agent");
    assert_eq!(headers[1].1, "AegisScanner/1.0");
    assert_eq!(headers[0].0, "Host");
}

#[test]
fn modify_response_header_removes() {
    let rule = ModificationRule {
        id: 1,
        enabled: true,
        match_target: MatchTarget::ResponseHeader,
        match_pattern: r"X-Frame-Options: .+".to_string(),
        replace_with: String::new(),
    };
    let mut headers = vec![
        ("Content-Type".to_string(), "text/html".to_string()),
        ("X-Frame-Options".to_string(), "DENY".to_string()),
    ];
    let mut body = Vec::new();
    apply_response_modifications(&[rule], &mut headers, &mut body);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, "Content-Type");
}

#[test]
fn modify_request_body_regex() {
    let rule = ModificationRule {
        id: 1,
        enabled: true,
        match_target: MatchTarget::RequestBody,
        match_pattern: r#""role"\s*:\s*"user""#.to_string(),
        replace_with: r#""role": "admin""#.to_string(),
    };
    let mut headers = Vec::new();
    let mut body = br#"{"name":"test","role": "user"}"#.to_vec();
    apply_request_modifications(&[rule], &mut headers, &mut body);
    let result = String::from_utf8(body).unwrap();
    assert!(result.contains(r#""role": "admin""#));
    assert!(!result.contains(r#""role": "user""#));
}

#[test]
fn modify_response_body() {
    let rule = ModificationRule {
        id: 1,
        enabled: true,
        match_target: MatchTarget::ResponseBody,
        match_pattern: r"secret-token-[a-f0-9]+".to_string(),
        replace_with: "REDACTED".to_string(),
    };
    let mut headers = Vec::new();
    let mut body = b"data: secret-token-abc123 end".to_vec();
    apply_response_modifications(&[rule], &mut headers, &mut body);
    assert_eq!(String::from_utf8(body).unwrap(), "data: REDACTED end");
}

#[test]
fn disabled_rule_skipped() {
    let rule = ModificationRule {
        id: 1,
        enabled: false,
        match_target: MatchTarget::RequestBody,
        match_pattern: r"original".to_string(),
        replace_with: "replaced".to_string(),
    };
    let mut headers = Vec::new();
    let mut body = b"original content".to_vec();
    apply_request_modifications(&[rule], &mut headers, &mut body);
    assert_eq!(String::from_utf8(body).unwrap(), "original content");
}

#[test]
fn non_matching_rule_no_change() {
    let rule = ModificationRule {
        id: 1,
        enabled: true,
        match_target: MatchTarget::RequestBody,
        match_pattern: r"xyz_no_match".to_string(),
        replace_with: "replaced".to_string(),
    };
    let mut headers = Vec::new();
    let mut body = b"original content".to_vec();
    apply_request_modifications(&[rule], &mut headers, &mut body);
    assert_eq!(String::from_utf8(body).unwrap(), "original content");
}

#[test]
fn multiple_rules_applied_in_order() {
    let rules = vec![
        ModificationRule {
            id: 1,
            enabled: true,
            match_target: MatchTarget::RequestBody,
            match_pattern: r"alpha".to_string(),
            replace_with: "beta".to_string(),
        },
        ModificationRule {
            id: 2,
            enabled: true,
            match_target: MatchTarget::RequestBody,
            match_pattern: r"beta".to_string(),
            replace_with: "gamma".to_string(),
        },
    ];
    let mut headers = Vec::new();
    let mut body = b"alpha".to_vec();
    apply_request_modifications(&rules, &mut headers, &mut body);
    assert_eq!(String::from_utf8(body).unwrap(), "gamma");
}

#[test]
fn capture_group_replacement() {
    let rule = ModificationRule {
        id: 1,
        enabled: true,
        match_target: MatchTarget::RequestBody,
        match_pattern: r"id=(\d+)&token=(\w+)".to_string(),
        replace_with: "id=$1&token=MASKED".to_string(),
    };
    let mut headers = Vec::new();
    let mut body = b"id=42&token=secret123".to_vec();
    apply_request_modifications(&[rule], &mut headers, &mut body);
    assert_eq!(String::from_utf8(body).unwrap(), "id=42&token=MASKED");
}

#[test]
fn invalid_regex_returns_error() {
    let mut engine = ModificationEngine::new();
    let result = engine.add_rule(MatchTarget::RequestBody, r"[invalid(", "replacement");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("invalid modification pattern"));
}

#[test]
fn add_remove_toggle_rules() {
    let mut engine = ModificationEngine::new();
    let id1 = engine
        .add_rule(MatchTarget::RequestHeader, "foo", "bar")
        .unwrap();
    let id2 = engine
        .add_rule(MatchTarget::ResponseBody, "baz", "qux")
        .unwrap();
    assert_eq!(engine.rules().len(), 2);
    assert!(engine.rules()[0].enabled);

    assert!(engine.toggle_rule(id1));
    assert!(!engine.rules()[0].enabled);
    assert!(engine.toggle_rule(id1));
    assert!(engine.rules()[0].enabled);

    assert!(!engine.toggle_rule(999));
    assert!(!engine.remove_rule(999));

    assert!(engine.remove_rule(id1));
    assert_eq!(engine.rules().len(), 1);
    assert_eq!(engine.rules()[0].id, id2);
}

#[test]
fn request_rules_ignore_response_targets() {
    let rules = vec![
        ModificationRule {
            id: 1,
            enabled: true,
            match_target: MatchTarget::RequestHeader,
            match_pattern: r"Host: .+".to_string(),
            replace_with: "Host: injected".to_string(),
        },
        ModificationRule {
            id: 2,
            enabled: true,
            match_target: MatchTarget::ResponseHeader,
            match_pattern: r"Server: .+".to_string(),
            replace_with: String::new(),
        },
    ];
    let mut headers = vec![
        ("Host".to_string(), "original".to_string()),
        ("Server".to_string(), "nginx".to_string()),
    ];
    let mut body = Vec::new();
    apply_request_modifications(&rules, &mut headers, &mut body);
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].1, "injected");
    assert_eq!(headers[1].0, "Server");
    assert_eq!(headers[1].1, "nginx");
}

#[test]
fn strip_security_header_real_world() {
    let mut engine = ModificationEngine::new();
    engine
        .add_rule(MatchTarget::ResponseHeader, r"X-Frame-Options: .+", "")
        .unwrap();
    engine
        .add_rule(
            MatchTarget::ResponseHeader,
            r"X-Content-Type-Options: .+",
            "",
        )
        .unwrap();
    let mut headers = vec![
        ("Content-Type".to_string(), "text/html".to_string()),
        ("X-Frame-Options".to_string(), "SAMEORIGIN".to_string()),
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ("Cache-Control".to_string(), "no-cache".to_string()),
    ];
    let mut body = Vec::new();
    apply_response_modifications(engine.rules(), &mut headers, &mut body);
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].0, "Content-Type");
    assert_eq!(headers[1].0, "Cache-Control");
}
