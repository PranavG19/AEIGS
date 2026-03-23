use crate::tls_scanner::*;

#[test]
fn parse_hsts_max_age_standard() {
    assert_eq!(parse_hsts_max_age("max-age=31536000"), Some(31536000));
}

#[test]
fn parse_hsts_max_age_with_directives() {
    assert_eq!(
        parse_hsts_max_age("max-age=31536000; includeSubDomains; preload"),
        Some(31536000)
    );
}

#[test]
fn parse_hsts_max_age_short() {
    assert_eq!(parse_hsts_max_age("max-age=3600"), Some(3600));
}

#[test]
fn parse_hsts_max_age_zero() {
    assert_eq!(parse_hsts_max_age("max-age=0"), Some(0));
}

#[test]
fn parse_hsts_max_age_missing() {
    assert_eq!(parse_hsts_max_age("includeSubDomains; preload"), None);
}

#[test]
fn parse_hsts_max_age_invalid() {
    assert_eq!(parse_hsts_max_age("max-age=notanumber"), None);
}

#[test]
fn parse_hsts_max_age_case_insensitive() {
    assert_eq!(parse_hsts_max_age("Max-Age=86400"), Some(86400));
}

#[test]
fn tls_findings_to_operations_no_https() {
    let findings = vec![TlsFinding {
        issue: TlsIssue::NoHttps,
        detail: "test".to_string(),
    }];
    let mut seq = 0;
    let ops = tls_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::WeakCryptography
            );
            assert!((severity - 7.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn tls_findings_to_operations_missing_hsts() {
    let findings = vec![TlsFinding {
        issue: TlsIssue::MissingHsts,
        detail: "test".to_string(),
    }];
    let mut seq = 0;
    let ops = tls_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn tls_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = tls_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn tls_findings_to_operations_multiple() {
    let findings = vec![
        TlsFinding {
            issue: TlsIssue::MissingHsts,
            detail: "test".to_string(),
        },
        TlsFinding {
            issue: TlsIssue::InsecureRedirect,
            detail: "test".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tls_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn scan_tls_skips_localhost() {
    let findings = scan_tls("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_tls_skips_loopback() {
    let findings = scan_tls("http://127.0.0.1:3000");
    assert!(findings.is_empty());
}

// New TLS Security Analysis Tests

#[test]
fn analyze_tls_headers_missing_strict_transport() {
    let headers = [("content-type", "text/html")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::MissingStrictTransport));
}

#[test]
fn analyze_tls_headers_has_strict_transport() {
    let headers = [("strict-transport-security", "max-age=31536000")];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingStrictTransport));
}

#[test]
fn analyze_tls_headers_short_max_age() {
    let headers = [("strict-transport-security", "max-age=3600")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::ShortMaxAge));
}

#[test]
fn analyze_tls_headers_sufficient_max_age() {
    let headers = [("strict-transport-security", "max-age=31536000")];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::ShortMaxAge));
}

#[test]
fn analyze_tls_headers_missing_include_subdomains() {
    let headers = [("strict-transport-security", "max-age=31536000")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::MissingIncludeSubDomains));
}

#[test]
fn analyze_tls_headers_has_include_subdomains() {
    let headers = [(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingIncludeSubDomains));
}

#[test]
fn analyze_tls_headers_missing_preload() {
    let headers = [(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::MissingPreload));
}

#[test]
fn analyze_tls_headers_has_preload() {
    let headers = [(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingPreload));
}

#[test]
fn analyze_tls_headers_missing_upgrade_insecure_requests() {
    let headers = [("content-type", "text/html")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::InsecureUpgradeInsecureRequests));
}

#[test]
fn analyze_tls_headers_has_upgrade_insecure_requests() {
    let headers = [(
        "content-security-policy",
        "default-src 'self'; upgrade-insecure-requests",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::InsecureUpgradeInsecureRequests));
}

#[test]
fn analyze_tls_headers_missing_mixed_content_block() {
    let headers = [("content-security-policy", "default-src 'self'")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::MixedContentRisk));
}

#[test]
fn analyze_tls_headers_has_mixed_content_block() {
    let headers = [(
        "content-security-policy",
        "default-src 'self'; block-all-mixed-content",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MixedContentRisk));
}

#[test]
fn analyze_tls_headers_weak_cipher_rc4() {
    let headers = [("server", "nginx/1.14.0 (TLS1.0, RC4-SHA)")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_weak_cipher_des() {
    let headers = [("server", "Apache/2.4.1 (3DES-EDE-CBC-SHA)")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_weak_cipher_md5() {
    let headers = [("server", "OpenSSL/1.0.1 (MD5)")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_weak_cipher_ssl() {
    let headers = [("server", "IIS/7.5 (SSL3.0)")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_weak_cipher_tls10() {
    let headers = [("server", "nginx (TLS1.0)")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_weak_cipher_tls11() {
    let headers = [("server", "Apache (TLS1.1)")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_strong_cipher() {
    let headers = [("server", "nginx/1.18.0 (TLS1.3, AES256-GCM-SHA384)")];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::WeakCipherIndication));
}

#[test]
fn analyze_tls_headers_missing_expect_ct() {
    let headers = [("content-type", "text/html")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::CertificateTransparency));
}

#[test]
fn analyze_tls_headers_has_expect_ct() {
    let headers = [("expect-ct", "max-age=86400, enforce")];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::CertificateTransparency));
}

#[test]
fn analyze_tls_headers_missing_public_key_pins() {
    let headers = [("content-type", "text/html")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::MissingPublicKeyPins));
}

#[test]
fn analyze_tls_headers_has_public_key_pins() {
    let headers = [(
        "public-key-pins",
        "pin-sha256=\"base64==\"; max-age=5184000",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingPublicKeyPins));
}

#[test]
fn analyze_tls_headers_has_public_key_pins_report_only() {
    let headers = [(
        "public-key-pins-report-only",
        "pin-sha256=\"base64==\"; max-age=5184000",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingPublicKeyPins));
}

#[test]
fn analyze_tls_headers_insecure_cookie() {
    let headers = [("set-cookie", "session=abc123; HttpOnly")];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::InsecureCookieTransmission));
}

#[test]
fn analyze_tls_headers_secure_cookie() {
    let headers = [("set-cookie", "session=abc123; Secure; HttpOnly")];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::InsecureCookieTransmission));
}

#[test]
fn analyze_tls_headers_multiple_cookies_one_insecure() {
    let headers = [
        ("set-cookie", "session=abc123; Secure"),
        ("set-cookie", "tracking=xyz; HttpOnly"),
    ];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.contains(&TlsSecurityIssue::InsecureCookieTransmission));
}

#[test]
fn analyze_tls_headers_empty() {
    let headers = [];
    let issues = analyze_tls_headers(&headers);
    // With no headers, we get: MissingStrictTransport, InsecureUpgradeInsecureRequests,
    // MixedContentRisk, CertificateTransparency, MissingPublicKeyPins = 5 issues
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&TlsSecurityIssue::MissingStrictTransport));
    assert!(issues.contains(&TlsSecurityIssue::InsecureUpgradeInsecureRequests));
    assert!(issues.contains(&TlsSecurityIssue::MixedContentRisk));
    assert!(issues.contains(&TlsSecurityIssue::CertificateTransparency));
    assert!(issues.contains(&TlsSecurityIssue::MissingPublicKeyPins));
}

#[test]
fn analyze_tls_headers_case_insensitive() {
    let headers = [
        ("STRICT-TRANSPORT-SECURITY", "MAX-AGE=31536000"),
        ("Content-Security-Policy", "UPGRADE-INSECURE-REQUESTS"),
    ];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingStrictTransport));
    assert!(!issues.contains(&TlsSecurityIssue::InsecureUpgradeInsecureRequests));
}

#[test]
fn tls_security_issue_display_missing_strict_transport() {
    assert_eq!(
        TlsSecurityIssue::MissingStrictTransport.to_string(),
        "Missing Strict-Transport-Security header"
    );
}

#[test]
fn tls_security_issue_display_short_max_age() {
    assert_eq!(
        TlsSecurityIssue::ShortMaxAge.to_string(),
        "HSTS max-age below recommended threshold"
    );
}

#[test]
fn tls_security_issue_display_missing_include_subdomains() {
    assert_eq!(
        TlsSecurityIssue::MissingIncludeSubDomains.to_string(),
        "HSTS missing includeSubDomains directive"
    );
}

#[test]
fn tls_security_issue_display_missing_preload() {
    assert_eq!(
        TlsSecurityIssue::MissingPreload.to_string(),
        "HSTS missing preload directive"
    );
}

#[test]
fn tls_security_issue_display_insecure_upgrade() {
    assert_eq!(
        TlsSecurityIssue::InsecureUpgradeInsecureRequests.to_string(),
        "Missing upgrade-insecure-requests directive"
    );
}

#[test]
fn tls_security_issue_display_mixed_content() {
    assert_eq!(
        TlsSecurityIssue::MixedContentRisk.to_string(),
        "Content-Security-Policy missing block-all-mixed-content"
    );
}

#[test]
fn tls_security_issue_display_weak_cipher() {
    assert_eq!(
        TlsSecurityIssue::WeakCipherIndication.to_string(),
        "Server header indicates weak cipher suite"
    );
}

#[test]
fn tls_security_issue_display_certificate_transparency() {
    assert_eq!(
        TlsSecurityIssue::CertificateTransparency.to_string(),
        "Missing Expect-CT header"
    );
}

#[test]
fn tls_security_issue_display_missing_pkp() {
    assert_eq!(
        TlsSecurityIssue::MissingPublicKeyPins.to_string(),
        "Missing Public-Key-Pins header (deprecated but informational)"
    );
}

#[test]
fn tls_security_issue_display_insecure_cookie() {
    assert_eq!(
        TlsSecurityIssue::InsecureCookieTransmission.to_string(),
        "Set-Cookie without Secure flag in response"
    );
}

#[test]
fn tls_security_severity_missing_strict_transport() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::MissingStrictTransport),
        6.0
    );
}

#[test]
fn tls_security_severity_short_max_age() {
    assert_eq!(tls_security_severity(&TlsSecurityIssue::ShortMaxAge), 4.0);
}

#[test]
fn tls_security_severity_missing_include_subdomains() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::MissingIncludeSubDomains),
        3.0
    );
}

#[test]
fn tls_security_severity_missing_preload() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::MissingPreload),
        2.0
    );
}

#[test]
fn tls_security_severity_insecure_upgrade() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::InsecureUpgradeInsecureRequests),
        5.0
    );
}

#[test]
fn tls_security_severity_mixed_content() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::MixedContentRisk),
        5.5
    );
}

#[test]
fn tls_security_severity_weak_cipher() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::WeakCipherIndication),
        7.0
    );
}

#[test]
fn tls_security_severity_certificate_transparency() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::CertificateTransparency),
        3.5
    );
}

#[test]
fn tls_security_severity_missing_pkp() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::MissingPublicKeyPins),
        2.0
    );
}

#[test]
fn tls_security_severity_insecure_cookie() {
    assert_eq!(
        tls_security_severity(&TlsSecurityIssue::InsecureCookieTransmission),
        6.5
    );
}

#[test]
fn tls_security_to_operations_single_issue() {
    let issues = vec![TlsSecurityIssue::MissingStrictTransport];
    let mut seq = 0;
    let ops = tls_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::WeakCryptography
            );
            assert!((severity - 6.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn tls_security_to_operations_multiple_issues() {
    let issues = vec![
        TlsSecurityIssue::MissingStrictTransport,
        TlsSecurityIssue::WeakCipherIndication,
        TlsSecurityIssue::InsecureCookieTransmission,
    ];
    let mut seq = 5;
    let ops = tls_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn tls_security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 10;
    let ops = tls_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn tls_security_to_operations_confidence_is_half() {
    let issues = vec![TlsSecurityIssue::ShortMaxAge];
    let mut seq = 0;
    let ops = tls_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn analyze_tls_headers_full_secure_config() {
    let headers = [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains; preload",
        ),
        (
            "content-security-policy",
            "default-src 'self'; upgrade-insecure-requests; block-all-mixed-content",
        ),
        ("expect-ct", "max-age=86400, enforce"),
        (
            "public-key-pins",
            "pin-sha256=\"base64==\"; max-age=5184000",
        ),
        ("set-cookie", "session=abc; Secure; HttpOnly"),
        ("server", "nginx/1.20.0 (TLS1.3)"),
    ];
    let issues = analyze_tls_headers(&headers);
    assert!(issues.is_empty());
}

#[test]
fn analyze_tls_headers_partial_hsts_config() {
    let headers = [(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingStrictTransport));
    assert!(!issues.contains(&TlsSecurityIssue::ShortMaxAge));
    assert!(!issues.contains(&TlsSecurityIssue::MissingIncludeSubDomains));
    assert!(issues.contains(&TlsSecurityIssue::MissingPreload));
}

#[test]
fn analyze_tls_headers_hsts_without_max_age() {
    let headers = [("strict-transport-security", "includeSubDomains; preload")];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::MissingStrictTransport));
    assert!(!issues.contains(&TlsSecurityIssue::ShortMaxAge));
}

#[test]
fn analyze_tls_headers_csp_both_directives() {
    let headers = [(
        "content-security-policy",
        "upgrade-insecure-requests; block-all-mixed-content",
    )];
    let issues = analyze_tls_headers(&headers);
    assert!(!issues.contains(&TlsSecurityIssue::InsecureUpgradeInsecureRequests));
    assert!(!issues.contains(&TlsSecurityIssue::MixedContentRisk));
}

#[test]
fn tls_security_issue_debug_format() {
    let issue = TlsSecurityIssue::WeakCipherIndication;
    let debug_str = format!("{:?}", issue);
    assert!(debug_str.contains("WeakCipherIndication"));
}

#[test]
fn tls_security_issue_clone_and_equality() {
    let issue1 = TlsSecurityIssue::MissingPreload;
    let issue2 = issue1.clone();
    assert_eq!(issue1, issue2);
}
