use crate::www_authenticate_audit::*;

// --- BasicOverHttp / BasicOverHttps ---

#[test]
fn no_header_no_issues() {
    let issues = analyze_www_authenticate(&[], true);
    assert!(issues.is_empty());
}

#[test]
fn empty_string_no_issues() {
    let vals = vec!["".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.is_empty());
}

#[test]
fn basic_over_http_detected() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, false);
    assert!(issues.contains(&WwwAuthIssue::BasicOverHttp));
    assert!(!issues.contains(&WwwAuthIssue::BasicOverHttps));
}

#[test]
fn basic_over_https_detected() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.contains(&WwwAuthIssue::BasicOverHttps));
    assert!(!issues.contains(&WwwAuthIssue::BasicOverHttp));
}

#[test]
fn basic_over_http_severity_higher_than_https() {
    assert!(
        www_auth_severity(&WwwAuthIssue::BasicOverHttp)
            > www_auth_severity(&WwwAuthIssue::BasicOverHttps)
    );
}

#[test]
fn basic_case_insensitive() {
    let vals = vec!["BASIC realm=\"x\"".to_string()];
    let issues = analyze_www_authenticate(&vals, false);
    assert!(issues.contains(&WwwAuthIssue::BasicOverHttp));
}

// --- DigestWithoutQop ---

#[test]
fn digest_without_qop_flagged() {
    let vals = vec!["Digest realm=\"test\", nonce=\"abc123\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.contains(&WwwAuthIssue::DigestWithoutQop));
}

#[test]
fn digest_with_qop_not_flagged() {
    let vals = vec!["Digest realm=\"test\", nonce=\"abc\", qop=\"auth\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(!issues.contains(&WwwAuthIssue::DigestWithoutQop));
}

// --- DigestWeakAlgorithm ---

#[test]
fn digest_md5_detected() {
    let vals =
        vec!["Digest realm=\"test\", nonce=\"abc\", qop=\"auth\", algorithm=MD5".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.iter().any(
        |i| matches!(i, WwwAuthIssue::DigestWeakAlgorithm { algorithm } if algorithm == "MD5")
    ));
}

#[test]
fn digest_md5_sess_detected() {
    let vals =
        vec!["Digest realm=\"test\", nonce=\"abc\", qop=\"auth\", algorithm=MD5-sess".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.iter().any(
        |i| matches!(i, WwwAuthIssue::DigestWeakAlgorithm { algorithm } if algorithm == "MD5-sess")
    ));
}

#[test]
fn digest_sha256_not_weak() {
    let vals =
        vec!["Digest realm=\"test\", nonce=\"abc\", qop=\"auth\", algorithm=SHA-256".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::DigestWeakAlgorithm { .. }))
    );
}

#[test]
fn digest_weak_algorithm_severity() {
    let sev = www_auth_severity(&WwwAuthIssue::DigestWeakAlgorithm {
        algorithm: "MD5".into(),
    });
    assert!(sev > 0.0);
    assert!(sev < www_auth_severity(&WwwAuthIssue::DigestWithoutQop));
}

// --- NTLM ---

#[test]
fn ntlm_detected() {
    let vals = vec!["NTLM".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.contains(&WwwAuthIssue::NtlmAuth));
}

#[test]
fn ntlm_case_insensitive() {
    let vals = vec!["ntlm".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.contains(&WwwAuthIssue::NtlmAuth));
}

#[test]
fn ntlm_severity_high() {
    assert!(www_auth_severity(&WwwAuthIssue::NtlmAuth) >= 5.0);
}

// --- Negotiate ---

#[test]
fn negotiate_detected() {
    let vals = vec!["Negotiate".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.contains(&WwwAuthIssue::NegotiateAuth));
}

#[test]
fn negotiate_case_insensitive() {
    let vals = vec!["NEGOTIATE".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.contains(&WwwAuthIssue::NegotiateAuth));
}

// --- Realm info leak ---

#[test]
fn realm_admin_leak() {
    let vals = vec!["Basic realm=\"Admin Panel\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { realm } if realm == "Admin Panel"))
    );
}

#[test]
fn realm_internal_leak() {
    let vals = vec!["Basic realm=\"internal-api\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

#[test]
fn realm_staging_leak() {
    let vals = vec!["Basic realm=\"staging-api\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

#[test]
fn realm_debug_leak() {
    let vals = vec!["Digest realm=\"debug-endpoint\", nonce=\"x\", qop=\"auth\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

#[test]
fn realm_test_leak() {
    let vals = vec!["Basic realm=\"test-server\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

#[test]
fn realm_dev_leak() {
    let vals = vec!["Basic realm=\"dev server\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

#[test]
fn realm_generic_no_leak() {
    let vals = vec!["Basic realm=\"Restricted\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

// --- Realm path leak ---

#[test]
fn realm_forward_slash_path_leak() {
    let vals = vec!["Basic realm=\"/etc/passwd\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmPathLeak { .. }))
    );
}

#[test]
fn realm_backslash_path_leak() {
    let vals = vec!["Basic realm=\"C:\\Users\\admin\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmPathLeak { .. }))
    );
}

#[test]
fn realm_windows_drive_path_leak() {
    let vals = vec!["Basic realm=\"C:\\inetpub\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmPathLeak { realm } if realm.contains("C:")))
    );
}

#[test]
fn realm_no_path_no_leak() {
    let vals = vec!["Basic realm=\"MyApp\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmPathLeak { .. }))
    );
}

// --- Custom/unknown scheme ---

#[test]
fn custom_scheme_detected() {
    let vals = vec!["CustomAuth realm=\"x\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::CustomScheme { scheme } if scheme == "customauth"))
    );
}

#[test]
fn bearer_not_custom() {
    let vals = vec!["Bearer".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::CustomScheme { .. }))
    );
}

#[test]
fn bearer_no_issues() {
    let vals = vec!["Bearer".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(!issues.contains(&WwwAuthIssue::BasicOverHttp));
    assert!(!issues.contains(&WwwAuthIssue::BasicOverHttps));
    assert!(!issues.contains(&WwwAuthIssue::NtlmAuth));
}

// --- Missing realm quotes ---

#[test]
fn unquoted_realm_detected() {
    let vals = vec!["Basic realm=Login".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::MissingRealmQuotes { .. }))
    );
}

#[test]
fn quoted_realm_not_flagged() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::MissingRealmQuotes { .. }))
    );
}

// --- Multiple schemes ---

#[test]
fn multiple_schemes_in_single_header() {
    let vals = vec!["Basic realm=\"x\", Digest realm=\"y\", nonce=\"z\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::MultipleSchemes { count } if *count > 1))
    );
}

#[test]
fn single_scheme_no_multiple_flag() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::MultipleSchemes { .. }))
    );
}

// --- Edge cases ---

#[test]
fn multiple_headers_all_analyzed() {
    let vals = vec![
        "Basic realm=\"internal-admin\"".to_string(),
        "Digest realm=\"api\", nonce=\"xyz\"".to_string(),
    ];
    let issues = analyze_www_authenticate(&vals, false);
    assert!(issues.contains(&WwwAuthIssue::BasicOverHttp));
    assert!(issues.contains(&WwwAuthIssue::DigestWithoutQop));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WwwAuthIssue::RealmInfoLeak { .. }))
    );
}

#[test]
fn empty_vec_no_issues() {
    let issues = analyze_www_authenticate(&[], false);
    assert!(issues.is_empty());
}

#[test]
fn whitespace_only_no_crash() {
    let vals = vec!["   ".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(!issues.contains(&WwwAuthIssue::BasicOverHttp));
}

// --- Severity ordering ---

#[test]
fn severity_basic_http_highest() {
    assert!(www_auth_severity(&WwwAuthIssue::BasicOverHttp) >= 7.0);
}

#[test]
fn severity_ntlm_above_negotiate() {
    assert!(
        www_auth_severity(&WwwAuthIssue::NtlmAuth)
            > www_auth_severity(&WwwAuthIssue::NegotiateAuth)
    );
}

#[test]
fn severity_digest_qop_above_weak_algo() {
    assert!(
        www_auth_severity(&WwwAuthIssue::DigestWithoutQop)
            > www_auth_severity(&WwwAuthIssue::DigestWeakAlgorithm {
                algorithm: "MD5".into()
            })
    );
}

#[test]
fn severity_realm_path_above_realm_info() {
    assert!(
        www_auth_severity(&WwwAuthIssue::RealmPathLeak {
            realm: "/etc".into()
        }) > www_auth_severity(&WwwAuthIssue::RealmInfoLeak {
            realm: "admin".into()
        })
    );
}

#[test]
fn severity_missing_quotes_lowest_category() {
    let quote_sev = www_auth_severity(&WwwAuthIssue::MissingRealmQuotes {
        scheme: "basic".into(),
    });
    assert!(quote_sev < www_auth_severity(&WwwAuthIssue::MultipleSchemes { count: 2 }));
}

#[test]
fn severity_all_positive() {
    let all_issues = vec![
        WwwAuthIssue::BasicOverHttp,
        WwwAuthIssue::BasicOverHttps,
        WwwAuthIssue::DigestWithoutQop,
        WwwAuthIssue::DigestWeakAlgorithm {
            algorithm: "MD5".into(),
        },
        WwwAuthIssue::RealmInfoLeak {
            realm: "admin".into(),
        },
        WwwAuthIssue::RealmPathLeak {
            realm: "/tmp".into(),
        },
        WwwAuthIssue::NtlmAuth,
        WwwAuthIssue::NegotiateAuth,
        WwwAuthIssue::MultipleSchemes { count: 3 },
        WwwAuthIssue::CustomScheme { scheme: "x".into() },
        WwwAuthIssue::MissingRealmQuotes {
            scheme: "basic".into(),
        },
    ];
    for issue in &all_issues {
        assert!(
            www_auth_severity(issue) > 0.0,
            "severity must be positive for {issue}"
        );
    }
}

// --- Display ---

#[test]
fn display_basic_over_http() {
    assert_eq!(WwwAuthIssue::BasicOverHttp.to_string(), "basic_over_http");
}

#[test]
fn display_basic_over_https() {
    assert_eq!(WwwAuthIssue::BasicOverHttps.to_string(), "basic_over_https");
}

#[test]
fn display_digest_without_qop() {
    assert_eq!(
        WwwAuthIssue::DigestWithoutQop.to_string(),
        "digest_without_qop"
    );
}

#[test]
fn display_digest_weak_algorithm() {
    let d = WwwAuthIssue::DigestWeakAlgorithm {
        algorithm: "MD5".into(),
    };
    assert_eq!(d.to_string(), "digest_weak_algorithm: MD5");
}

#[test]
fn display_realm_info_leak() {
    let d = WwwAuthIssue::RealmInfoLeak {
        realm: "admin".into(),
    };
    assert_eq!(d.to_string(), "realm_info_leak: admin");
}

#[test]
fn display_realm_path_leak() {
    let d = WwwAuthIssue::RealmPathLeak {
        realm: "/etc".into(),
    };
    assert_eq!(d.to_string(), "realm_path_leak: /etc");
}

#[test]
fn display_ntlm() {
    assert_eq!(WwwAuthIssue::NtlmAuth.to_string(), "ntlm_auth");
}

#[test]
fn display_negotiate() {
    assert_eq!(WwwAuthIssue::NegotiateAuth.to_string(), "negotiate_auth");
}

#[test]
fn display_multiple_schemes() {
    let d = WwwAuthIssue::MultipleSchemes { count: 3 };
    assert_eq!(d.to_string(), "multiple_schemes: 3");
}

#[test]
fn display_custom_scheme() {
    let d = WwwAuthIssue::CustomScheme {
        scheme: "xauth".into(),
    };
    assert_eq!(d.to_string(), "custom_scheme: xauth");
}

#[test]
fn display_missing_realm_quotes() {
    let d = WwwAuthIssue::MissingRealmQuotes {
        scheme: "digest".into(),
    };
    assert_eq!(d.to_string(), "missing_realm_quotes: digest");
}

// --- extract_realm ---

#[test]
fn extract_realm_quoted() {
    let realm = extract_realm("Basic realm=\"MyApp\"");
    assert_eq!(realm.as_deref(), Some("MyApp"));
}

#[test]
fn extract_realm_unquoted() {
    let realm = extract_realm("Basic realm=MyApp");
    assert_eq!(realm.as_deref(), Some("MyApp"));
}

#[test]
fn extract_realm_no_realm() {
    let realm = extract_realm("Bearer");
    assert_eq!(realm, None);
}

#[test]
fn extract_realm_empty_quoted() {
    let realm = extract_realm("Basic realm=\"\"");
    assert_eq!(realm.as_deref(), Some(""));
}

// --- Operations ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = www_auth_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![WwwAuthIssue::BasicOverHttp, WwwAuthIssue::NtlmAuth];
    let mut seq = 0;
    let ops = www_auth_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_seq_increments_from_nonzero() {
    let issues = vec![WwwAuthIssue::BasicOverHttps];
    let mut seq = 10;
    let ops = www_auth_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn operations_backward_compat_wrapper() {
    let issues = vec![WwwAuthIssue::DigestWithoutQop];
    let mut seq1 = 0;
    let mut seq2 = 0;
    let ops1 = www_auth_to_operations(&issues, &mut seq1);
    let ops2 = www_authenticate_to_operations(&issues, &mut seq2);
    assert_eq!(ops1.len(), ops2.len());
    assert_eq!(seq1, seq2);
}

#[test]
fn operations_multiple_issues_from_analysis() {
    let vals = vec![
        "Basic realm=\"internal-admin\"".to_string(),
        "NTLM".to_string(),
    ];
    let issues = analyze_www_authenticate(&vals, false);
    let mut seq = 0;
    let ops = www_auth_to_operations(&issues, &mut seq);
    assert!(ops.len() >= 3);
    assert_eq!(seq as usize, ops.len());
}
