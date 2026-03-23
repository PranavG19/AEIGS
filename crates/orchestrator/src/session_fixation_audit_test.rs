use crate::session_fixation_audit::*;

#[test]
fn no_session_cookies_returns_empty() {
    let issues = analyze_session_fixation("https://example.com/page", &[], "");
    assert!(issues.is_empty());
}

#[test]
fn non_session_cookie_ignored() {
    let cookies = vec!["theme=dark; Path=/".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.is_empty());
}

#[test]
fn session_id_in_url_detected() {
    let issues =
        analyze_session_fixation("https://example.com/page?sessionid=abc123def456", &[], "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::SessionIdInUrl { param } if param == "sessionid"
    )));
}

#[test]
fn phpsessid_in_url_detected() {
    let issues = analyze_session_fixation("https://example.com/?PHPSESSID=abc123&foo=bar", &[], "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::SessionIdInUrl { param } if param == "PHPSESSID"
    )));
}

#[test]
fn jsessionid_in_url_case_insensitive() {
    let issues = analyze_session_fixation("https://example.com/?jsessionid=xyz789", &[], "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::SessionIdInUrl { param } if param == "jsessionid"
    )));
}

#[test]
fn token_param_in_url_detected() {
    let issues = analyze_session_fixation("https://example.com/api?token=secret123", &[], "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::SessionIdInUrl { param } if param == "token"
    )));
}

#[test]
fn missing_httponly_detected() {
    let cookies = vec!["sessionid=abc123def456; Path=/; Secure; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionCookieNoHttpOnly { .. }))
    );
}

#[test]
fn missing_secure_detected() {
    let cookies = vec!["sessionid=abc123def456; Path=/; HttpOnly; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionCookieNoSecure { .. }))
    );
}

#[test]
fn missing_samesite_detected() {
    let cookies = vec!["sessionid=abc123def456; Path=/; HttpOnly; Secure".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionCookieNoSameSite { .. }))
    );
}

#[test]
fn long_expiry_detected() {
    let cookies = vec![
        "sessionid=abc123def456; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800"
            .to_string(),
    ];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::SessionCookieLongExpiry { max_age_secs, .. } if *max_age_secs == 604800
    )));
}

#[test]
fn safe_max_age_not_flagged() {
    let cookies = vec![
        "sessionid=abc123def456; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600"
            .to_string(),
    ];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionCookieLongExpiry { .. }))
    );
}

#[test]
fn predictable_short_session_detected() {
    let cookies = vec!["sessionid=1234; Path=/; HttpOnly; Secure; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::PredictableSessionId { pattern, .. } if pattern == "too_short"
    )));
}

#[test]
fn predictable_numeric_session_detected() {
    let cookies =
        vec!["sessionid=123456789012; Path=/; HttpOnly; Secure; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::PredictableSessionId { pattern, .. } if pattern == "numeric_only"
    )));
}

#[test]
fn insufficient_length_detected() {
    let cookies =
        vec!["sessionid=abcd1234xyz; Path=/; HttpOnly; Secure; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::PredictableSessionId { pattern, .. } if pattern == "insufficient_length"
    )));
}

#[test]
fn low_entropy_detected() {
    let cookies =
        vec!["sessionid=aaaaaaaaaaaaaaaa; Path=/; HttpOnly; Secure; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::PredictableSessionId { pattern, .. } if pattern == "low_entropy"
    )));
}

#[test]
fn lowercase_only_detected() {
    let cookies =
        vec!["sessionid=abcdefghijklmnop; Path=/; HttpOnly; Secure; SameSite=Strict".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::PredictableSessionId { pattern, .. } if pattern == "lowercase_only"
    )));
}

#[test]
fn strong_session_id_not_predictable() {
    let cookies = vec![
        "sessionid=a8f3b2c1d9e4f5067890abcdef123456; Path=/; HttpOnly; Secure; SameSite=Strict"
            .to_string(),
    ];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::PredictableSessionId { .. }))
    );
}

#[test]
fn session_acceptance_from_url_detected() {
    let body = r#"
        const params = new URLSearchParams(window.location.search);
        const sessionid = params.get('sessionid');
        document.cookie = 'sessionid=' + sessionid;
    "#;
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionAcceptanceFromUrl))
    );
}

#[test]
fn session_acceptance_location_search_detected() {
    let body = r#"
        const sid = location.search.split('sid=')[1];
        document.cookie = 'sid=' + sid;
    "#;
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionAcceptanceFromUrl))
    );
}

#[test]
fn session_acceptance_php_get_detected() {
    let body = r#"
        <?php
        $sid = $_GET['sessionid'];
        setcookie('sessionid', $sid);
        ?>
    "#;
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionAcceptanceFromUrl))
    );
}

#[test]
fn cross_subdomain_session_sharing_detected() {
    let cookies = vec![
        "sessionid=abc123def456; Path=/; HttpOnly; Secure; SameSite=Strict; Domain=.example.com"
            .to_string(),
    ];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        SessionFixationIssue::CrossSubdomainSessionSharing { domain, .. } if domain == ".example.com"
    )));
}

#[test]
fn no_session_regeneration_on_login_detected() {
    let body = r#"
        function login(username, password) {
            if (authenticate(username, password)) {
                // No session regeneration here
                return true;
            }
        }
    "#;
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::NoSessionRegenerationOnLogin))
    );
}

#[test]
fn session_regeneration_present_not_flagged() {
    let body = r#"
        function login(username, password) {
            if (authenticate(username, password)) {
                session.regenerate();
                return true;
            }
        }
    "#;
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::NoSessionRegenerationOnLogin))
    );
}

#[test]
fn session_id_in_referer_detected() {
    let body = r#"
        const referer = document.referrer;
        const sessionid = extractParam(referer, 'sessionid');
    "#;
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionIdInReferer))
    );
}

#[test]
fn fully_secure_cookie_only_flags_nothing_extra() {
    let cookies = vec![
        "sessionid=a8f3b2c1d9e4f5067890abcdef123456; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600"
            .to_string(),
    ];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(issues.is_empty());
}

#[test]
fn jsessionid_cookie_recognized() {
    let cookies = vec!["JSESSIONID=short; Path=/".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(!issues.is_empty());
}

#[test]
fn connect_sid_cookie_recognized() {
    let cookies = vec!["connect.sid=abc; Path=/".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(!issues.is_empty());
}

#[test]
fn aspsessionid_cookie_recognized() {
    let cookies = vec!["ASPSESSIONID=xyz123; Path=/".to_string()];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    assert!(!issues.is_empty());
}

#[test]
fn multiple_session_cookies_all_checked() {
    let cookies = vec![
        "sessionid=short; Path=/".to_string(),
        "sid=12345678; Path=/".to_string(),
    ];
    let issues = analyze_session_fixation("https://example.com", &cookies, "");
    let httponly_count = issues
        .iter()
        .filter(|i| matches!(i, SessionFixationIssue::SessionCookieNoHttpOnly { .. }))
        .count();
    assert!(httponly_count >= 2);
}

#[test]
fn session_fixation_severity_ordering() {
    assert!(
        session_fixation_severity(&SessionFixationIssue::SessionAcceptanceFromUrl)
            > session_fixation_severity(&SessionFixationIssue::SessionIdInUrl {
                param: "sid".into()
            })
    );
    assert!(
        session_fixation_severity(&SessionFixationIssue::PredictableSessionId {
            cookie_name: "sid".into(),
            pattern: "numeric_only".into()
        }) > session_fixation_severity(&SessionFixationIssue::SessionCookieNoHttpOnly {
            cookie_name: "sid".into()
        })
    );
    assert!(
        session_fixation_severity(&SessionFixationIssue::NoSessionRegenerationOnLogin)
            > session_fixation_severity(&SessionFixationIssue::SessionCookieNoSameSite {
                cookie_name: "sid".into()
            })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        SessionFixationIssue::SessionIdInUrl {
            param: "sid".into(),
        },
        SessionFixationIssue::SessionCookieNoHttpOnly {
            cookie_name: "sessionid".into(),
        },
    ];
    let mut seq = 100;
    let ops = session_fixation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

#[test]
fn display_variants() {
    let issue = SessionFixationIssue::SessionIdInUrl {
        param: "sid".into(),
    };
    assert_eq!(issue.to_string(), "session_id_in_url:sid");

    let issue = SessionFixationIssue::SessionCookieLongExpiry {
        cookie_name: "sess".into(),
        max_age_secs: 604800,
    };
    assert_eq!(issue.to_string(), "session_long_expiry:sess:604800s");

    let issue = SessionFixationIssue::SessionAcceptanceFromUrl;
    assert_eq!(issue.to_string(), "session_acceptance_from_url");

    let issue = SessionFixationIssue::CrossSubdomainSessionSharing {
        cookie_name: "sid".into(),
        domain: ".example.com".into(),
    };
    assert_eq!(
        issue.to_string(),
        "cross_subdomain_session:sid:.example.com"
    );
}

#[test]
fn empty_url_no_issues() {
    let issues = analyze_session_fixation("https://example.com", &[], "");
    assert!(issues.is_empty());
}

#[test]
fn cookie_setter_without_url_params_no_issue() {
    let body = "document.cookie = 'theme=dark';";
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionAcceptanceFromUrl))
    );
}

#[test]
fn url_params_without_cookie_setter_no_issue() {
    let body = "const sid = new URLSearchParams(location.search).get('sid');";
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionAcceptanceFromUrl))
    );
}

#[test]
fn referer_without_session_param_no_issue() {
    let body = "const ref = document.referrer; console.log(ref);";
    let issues = analyze_session_fixation("https://example.com", &[], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SessionFixationIssue::SessionIdInReferer))
    );
}
