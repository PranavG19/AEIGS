use crate::deprecated_header_audit::*;

// --- Detection tests ---

#[test]
fn detects_expect_ct() {
    let headers = [("expect-ct", "max-age=86400")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::ExpectCt));
}

#[test]
fn detects_feature_policy() {
    let headers = [("feature-policy", "microphone 'none'")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::FeaturePolicy));
}

#[test]
fn detects_public_key_pins() {
    let headers = [("public-key-pins", "pin-sha256=abc; max-age=5184000")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::PublicKeyPins));
}

#[test]
fn detects_public_key_pins_report_only() {
    let headers = [("public-key-pins-report-only", "pin-sha256=abc")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::PublicKeyPinsReportOnly));
}

#[test]
fn detects_xxss_protection() {
    let headers = [("x-xss-protection", "1; mode=block")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::XxssProtection));
}

#[test]
fn detects_x_frame_options() {
    let headers = [("x-frame-options", "DENY")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::XFrameOptions));
}

#[test]
fn detects_x_content_type_options_non_nosniff() {
    let headers = [("x-content-type-options", "nosnif")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(
        issues.contains(&DeprecatedHeaderIssue::XContentTypeOptions {
            value: "nosnif".to_string(),
        })
    );
}

#[test]
fn x_content_type_options_nosniff_not_flagged() {
    let headers = [("x-content-type-options", "nosniff")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeprecatedHeaderIssue::XContentTypeOptions { .. }))
    );
}

#[test]
fn x_content_type_options_nosniff_case_insensitive() {
    let headers = [("x-content-type-options", "NoSniff")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeprecatedHeaderIssue::XContentTypeOptions { .. }))
    );
}

#[test]
fn x_content_type_options_nosniff_trimmed() {
    let headers = [("x-content-type-options", "  nosniff  ")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeprecatedHeaderIssue::XContentTypeOptions { .. }))
    );
}

#[test]
fn x_content_type_options_empty_value_flagged() {
    let headers = [("x-content-type-options", "")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(
        issues.contains(&DeprecatedHeaderIssue::XContentTypeOptions {
            value: "".to_string(),
        })
    );
}

#[test]
fn detects_pragma() {
    let headers = [("pragma", "no-cache")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::PragmaHttp2));
}

#[test]
fn detects_p3p() {
    let headers = [("p3p", "CP=\"NOI DSP COR\"")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::P3p));
}

#[test]
fn detects_x_webkit_csp() {
    let headers = [("x-webkit-csp", "default-src 'self'")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::XWebkitCsp));
}

#[test]
fn detects_x_content_security_policy() {
    let headers = [("x-content-security-policy", "default-src 'self'")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::XContentSecurityPolicy));
}

// --- Case sensitivity ---

#[test]
fn header_name_case_insensitive() {
    let headers = [("Expect-CT", "max-age=0")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::ExpectCt));
}

#[test]
fn header_name_all_caps() {
    let headers = [("PUBLIC-KEY-PINS", "pin-sha256=abc")];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.contains(&DeprecatedHeaderIssue::PublicKeyPins));
}

// --- Edge cases ---

#[test]
fn empty_headers() {
    let issues = analyze_deprecated_headers(&[]);
    assert!(issues.is_empty());
}

#[test]
fn only_modern_headers() {
    let headers = [
        ("content-security-policy", "default-src 'self'"),
        ("permissions-policy", "geolocation=()"),
        ("strict-transport-security", "max-age=31536000"),
    ];
    let issues = analyze_deprecated_headers(&headers);
    assert!(issues.is_empty());
}

#[test]
fn all_deprecated_present() {
    let headers = [
        ("expect-ct", "max-age=0"),
        ("feature-policy", "microphone 'none'"),
        ("public-key-pins", "pin-sha256=abc"),
        ("public-key-pins-report-only", "pin-sha256=abc"),
        ("x-xss-protection", "1"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "wrong"),
        ("pragma", "no-cache"),
        ("p3p", "CP=\"NOI\""),
        ("x-webkit-csp", "default-src 'self'"),
        ("x-content-security-policy", "default-src 'self'"),
    ];
    let issues = analyze_deprecated_headers(&headers);
    assert_eq!(issues.len(), 11);
}

#[test]
fn multiple_deprecated_subset() {
    let headers = [
        ("expect-ct", "max-age=0"),
        ("feature-policy", "microphone 'none'"),
        ("x-xss-protection", "1; mode=block"),
    ];
    let issues = analyze_deprecated_headers(&headers);
    assert_eq!(issues.len(), 3);
    assert!(issues.contains(&DeprecatedHeaderIssue::ExpectCt));
    assert!(issues.contains(&DeprecatedHeaderIssue::FeaturePolicy));
    assert!(issues.contains(&DeprecatedHeaderIssue::XxssProtection));
}

#[test]
fn mixed_modern_and_deprecated() {
    let headers = [
        ("content-security-policy", "default-src 'self'"),
        ("x-webkit-csp", "default-src 'self'"),
        ("permissions-policy", "geolocation=()"),
        ("feature-policy", "microphone 'none'"),
    ];
    let issues = analyze_deprecated_headers(&headers);
    assert_eq!(issues.len(), 2);
    assert!(issues.contains(&DeprecatedHeaderIssue::XWebkitCsp));
    assert!(issues.contains(&DeprecatedHeaderIssue::FeaturePolicy));
}

// --- Display tests ---

#[test]
fn display_expect_ct() {
    assert_eq!(format!("{}", DeprecatedHeaderIssue::ExpectCt), "expect_ct");
}

#[test]
fn display_feature_policy() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::FeaturePolicy),
        "feature_policy"
    );
}

#[test]
fn display_public_key_pins() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::PublicKeyPins),
        "public_key_pins"
    );
}

#[test]
fn display_public_key_pins_report_only() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::PublicKeyPinsReportOnly),
        "public_key_pins_report_only"
    );
}

#[test]
fn display_xxss_protection() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::XxssProtection),
        "xxss_protection"
    );
}

#[test]
fn display_x_frame_options() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::XFrameOptions),
        "x_frame_options"
    );
}

#[test]
fn display_x_content_type_options() {
    let issue = DeprecatedHeaderIssue::XContentTypeOptions {
        value: "wrong".to_string(),
    };
    assert_eq!(format!("{issue}"), "x_content_type_options:wrong");
}

#[test]
fn display_pragma_http2() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::PragmaHttp2),
        "pragma_http2"
    );
}

#[test]
fn display_p3p() {
    assert_eq!(format!("{}", DeprecatedHeaderIssue::P3p), "p3p");
}

#[test]
fn display_x_webkit_csp() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::XWebkitCsp),
        "x_webkit_csp"
    );
}

#[test]
fn display_x_content_security_policy() {
    assert_eq!(
        format!("{}", DeprecatedHeaderIssue::XContentSecurityPolicy),
        "x_content_security_policy"
    );
}

// --- Severity tests ---

#[test]
fn severity_expect_ct() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::ExpectCt) - 1.5).abs() < f64::EPSILON
    );
}

#[test]
fn severity_feature_policy() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::FeaturePolicy) - 2.0).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_public_key_pins() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::PublicKeyPins) - 3.0).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_public_key_pins_report_only() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::PublicKeyPinsReportOnly) - 2.0).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_xxss_protection() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::XxssProtection) - 2.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_x_frame_options() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::XFrameOptions) - 1.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_x_content_type_options() {
    let issue = DeprecatedHeaderIssue::XContentTypeOptions {
        value: "bad".to_string(),
    };
    assert!((deprecated_header_severity(&issue) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_pragma_http2() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::PragmaHttp2) - 1.0).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_p3p() {
    assert!((deprecated_header_severity(&DeprecatedHeaderIssue::P3p) - 1.5).abs() < f64::EPSILON);
}

#[test]
fn severity_x_webkit_csp() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::XWebkitCsp) - 2.5).abs() < f64::EPSILON
    );
}

#[test]
fn severity_x_content_security_policy() {
    assert!(
        (deprecated_header_severity(&DeprecatedHeaderIssue::XContentSecurityPolicy) - 2.5).abs()
            < f64::EPSILON
    );
}

// --- Operations tests ---

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = deprecated_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        DeprecatedHeaderIssue::ExpectCt,
        DeprecatedHeaderIssue::FeaturePolicy,
        DeprecatedHeaderIssue::PublicKeyPins,
    ];
    let mut seq = 0;
    let ops = deprecated_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        DeprecatedHeaderIssue::XxssProtection,
        DeprecatedHeaderIssue::P3p,
    ];
    let mut seq = 10;
    let ops = deprecated_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
}

#[test]
fn operations_single_issue() {
    let issues = vec![DeprecatedHeaderIssue::PublicKeyPins];
    let mut seq = 0;
    let ops = deprecated_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_all_eleven_issues() {
    let issues = vec![
        DeprecatedHeaderIssue::ExpectCt,
        DeprecatedHeaderIssue::FeaturePolicy,
        DeprecatedHeaderIssue::PublicKeyPins,
        DeprecatedHeaderIssue::PublicKeyPinsReportOnly,
        DeprecatedHeaderIssue::XxssProtection,
        DeprecatedHeaderIssue::XFrameOptions,
        DeprecatedHeaderIssue::XContentTypeOptions {
            value: "bad".to_string(),
        },
        DeprecatedHeaderIssue::PragmaHttp2,
        DeprecatedHeaderIssue::P3p,
        DeprecatedHeaderIssue::XWebkitCsp,
        DeprecatedHeaderIssue::XContentSecurityPolicy,
    ];
    let mut seq = 0;
    let ops = deprecated_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 11);
    assert_eq!(seq, 11);
}
