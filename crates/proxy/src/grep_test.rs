use super::*;

fn sample_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-Request-Id".to_string(), "abc-123".to_string()),
    ]
}

#[test]
fn grep_match_finds_pattern_in_body() {
    let matchers = vec![GrepMatch {
        pattern: "success".to_string(),
        search_in: SearchTarget::Body,
        negate: false,
    }];
    let body = b"operation was a success";
    let result = apply_grep_matches(&matchers, 200, &[], body).unwrap();
    assert_eq!(result, vec!["success"]);
}

#[test]
fn grep_match_finds_pattern_in_headers() {
    let matchers = vec![GrepMatch {
        pattern: "json".to_string(),
        search_in: SearchTarget::Headers,
        negate: false,
    }];
    let result = apply_grep_matches(&matchers, 200, &sample_headers(), b"").unwrap();
    assert_eq!(result, vec!["json"]);
}

#[test]
fn grep_match_searches_both() {
    let body_matcher = GrepMatch {
        pattern: "success".to_string(),
        search_in: SearchTarget::Both,
        negate: false,
    };
    let header_matcher = GrepMatch {
        pattern: "abc-123".to_string(),
        search_in: SearchTarget::Both,
        negate: false,
    };
    let body = b"success";
    let headers = sample_headers();
    let result = apply_grep_matches(&[body_matcher, header_matcher], 200, &headers, body).unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.contains(&"success".to_string()));
    assert!(result.contains(&"abc-123".to_string()));
}

#[test]
fn grep_match_negate_flags_absence() {
    let matchers = vec![GrepMatch {
        pattern: "error".to_string(),
        search_in: SearchTarget::Body,
        negate: true,
    }];
    let body = b"everything is fine";
    let result = apply_grep_matches(&matchers, 200, &[], body).unwrap();
    assert_eq!(result, vec!["error"]);
}

#[test]
fn grep_match_negate_excludes_presence() {
    let matchers = vec![GrepMatch {
        pattern: "error".to_string(),
        search_in: SearchTarget::Body,
        negate: true,
    }];
    let body = b"an error occurred";
    let result = apply_grep_matches(&matchers, 200, &[], body).unwrap();
    assert!(result.is_empty());
}

#[test]
fn grep_match_no_match_returns_empty() {
    let matchers = vec![GrepMatch {
        pattern: "notfound".to_string(),
        search_in: SearchTarget::Body,
        negate: false,
    }];
    let body = b"hello world";
    let result = apply_grep_matches(&matchers, 200, &[], body).unwrap();
    assert!(result.is_empty());
}

#[test]
fn grep_extract_captures_group() {
    let extracts = vec![GrepExtract {
        pattern: r#"token":"([^"]+)"#.to_string(),
        group: 1,
        search_in: SearchTarget::Body,
    }];
    let body = br#"{"token":"secret_abc_123","status":"ok"}"#;
    let result = apply_grep_extracts(&extracts, &[], body).unwrap();
    assert_eq!(result, vec!["secret_abc_123"]);
}

#[test]
fn grep_extract_from_headers() {
    let extracts = vec![GrepExtract {
        pattern: r"X-Request-Id: (.+)".to_string(),
        group: 1,
        search_in: SearchTarget::Headers,
    }];
    let result = apply_grep_extracts(&extracts, &sample_headers(), b"").unwrap();
    assert_eq!(result, vec!["abc-123"]);
}

#[test]
fn grep_extract_group_zero_full_match() {
    let extracts = vec![GrepExtract {
        pattern: r"\d{3}".to_string(),
        group: 0,
        search_in: SearchTarget::Body,
    }];
    let body = b"status code 200 returned";
    let result = apply_grep_extracts(&extracts, &[], body).unwrap();
    assert_eq!(result, vec!["200"]);
}

#[test]
fn grep_extract_no_match_skips() {
    let extracts = vec![GrepExtract {
        pattern: r"token: (.+)".to_string(),
        group: 1,
        search_in: SearchTarget::Body,
    }];
    let body = b"no tokens here";
    let result = apply_grep_extracts(&extracts, &[], body).unwrap();
    assert!(result.is_empty());
}

#[test]
fn grep_invalid_regex_returns_error() {
    let matchers = vec![GrepMatch {
        pattern: "[".to_string(),
        search_in: SearchTarget::Body,
        negate: false,
    }];
    let result = apply_grep_matches(&matchers, 200, &[], b"test");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, GrepError::InvalidPattern(_)));

    let extracts = vec![GrepExtract {
        pattern: "[".to_string(),
        group: 0,
        search_in: SearchTarget::Body,
    }];
    let result = apply_grep_extracts(&extracts, &[], b"test");
    assert!(result.is_err());
}

#[test]
fn grep_multiple_matchers() {
    let matchers = vec![
        GrepMatch {
            pattern: "ok".to_string(),
            search_in: SearchTarget::Body,
            negate: false,
        },
        GrepMatch {
            pattern: "fail".to_string(),
            search_in: SearchTarget::Body,
            negate: false,
        },
        GrepMatch {
            pattern: "json".to_string(),
            search_in: SearchTarget::Headers,
            negate: false,
        },
    ];
    let headers = sample_headers();
    let body = b"result: ok";
    let result = apply_grep_matches(&matchers, 200, &headers, body).unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.contains(&"ok".to_string()));
    assert!(result.contains(&"json".to_string()));
}

#[test]
fn grep_binary_body_handled() {
    let matchers = vec![GrepMatch {
        pattern: "test".to_string(),
        search_in: SearchTarget::Body,
        negate: false,
    }];
    let body: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x80, 0xC0];
    let result = apply_grep_matches(&matchers, 200, &[], &body).unwrap();
    assert!(result.is_empty());

    let extracts = vec![GrepExtract {
        pattern: r"\w+".to_string(),
        group: 0,
        search_in: SearchTarget::Body,
    }];
    let result = apply_grep_extracts(&extracts, &[], &body);
    assert!(result.is_ok());
}
