use crate::csp_nonce_audit::*;

#[test]
fn empty_csp_returns_no_issues() {
    assert!(analyze_csp_nonces("").is_empty());
}

#[test]
fn no_nonces_returns_no_issues() {
    let csp = "default-src 'self'; script-src 'self' https://cdn.example.com";
    assert!(analyze_csp_nonces(csp).is_empty());
}

#[test]
fn valid_long_nonce_no_issues_except_strict_dynamic() {
    let csp = "script-src 'nonce-abc123def456ghi789jkl012' 'strict-dynamic'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues.is_empty());
}

#[test]
fn short_nonce_detected() {
    let csp = "script-src 'nonce-abc123'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues.iter().any(|i| matches!(i, CspNonceIssue::ShortNonce { length, .. } if *length == 6)));
}

#[test]
fn duplicate_nonce_detected() {
    let csp = "script-src 'nonce-abcdef1234567890'; style-src 'nonce-abcdef1234567890'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::DuplicateNonce { .. })));
}

#[test]
fn nonce_with_unsafe_inline_detected() {
    let csp = "script-src 'nonce-abcdef1234567890' 'unsafe-inline'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::NonceWithUnsafeInline)));
}

#[test]
fn weak_sha1_hash_detected() {
    let csp = "script-src 'sha1-abc123def456' 'nonce-abcdef1234567890'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues.iter().any(
        |i| matches!(i, CspNonceIssue::WeakHashAlgorithm { algorithm } if algorithm == "sha1")
    ));
}

#[test]
fn weak_md5_hash_detected() {
    let csp = "script-src 'md5-abc123def456' 'nonce-abcdef1234567890'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues.iter().any(
        |i| matches!(i, CspNonceIssue::WeakHashAlgorithm { algorithm } if algorithm == "md5")
    ));
}

#[test]
fn sha256_hash_not_flagged_as_weak() {
    let csp = "script-src 'sha256-abcdef1234567890abcdef1234567890'";
    let issues = analyze_csp_nonces(csp);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::WeakHashAlgorithm { .. })));
}

#[test]
fn missing_strict_dynamic_detected() {
    let csp = "script-src 'nonce-abcdef1234567890'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::MissingStrictDynamic)));
}

#[test]
fn strict_dynamic_present_no_issue() {
    let csp = "script-src 'nonce-abcdef1234567890' 'strict-dynamic'";
    let issues = analyze_csp_nonces(csp);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::MissingStrictDynamic)));
}

#[test]
fn nonce_in_default_src_detected() {
    let csp = "default-src 'nonce-ab' 'strict-dynamic'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::ShortNonce { .. })));
}

#[test]
fn nonce_in_style_src_detected() {
    let csp = "style-src 'nonce-xy' 'strict-dynamic'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::ShortNonce { .. })));
}

#[test]
fn nonce_in_img_src_ignored() {
    let csp = "img-src 'nonce-ab'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues_combined() {
    let csp = "script-src 'nonce-abc' 'unsafe-inline' 'sha1-xyz123'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::ShortNonce { .. })));
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::NonceWithUnsafeInline)));
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::WeakHashAlgorithm { .. })));
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::MissingStrictDynamic)));
}

#[test]
fn severity_ordering() {
    assert!(csp_nonce_severity(&CspNonceIssue::DuplicateNonce {
        nonce: "x".into()
    }) > csp_nonce_severity(&CspNonceIssue::NonceWithUnsafeInline));
    assert!(
        csp_nonce_severity(&CspNonceIssue::NonceWithUnsafeInline)
            > csp_nonce_severity(&CspNonceIssue::MissingStrictDynamic)
    );
}

#[test]
fn display_format() {
    let issue = CspNonceIssue::ShortNonce {
        nonce: "abc".into(),
        length: 3,
    };
    assert_eq!(issue.to_string(), "short_csp_nonce:3:abc");

    let issue = CspNonceIssue::NonceWithUnsafeInline;
    assert_eq!(issue.to_string(), "nonce_with_unsafe_inline");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        CspNonceIssue::ShortNonce {
            nonce: "abc".into(),
            length: 3,
        },
        CspNonceIssue::NonceWithUnsafeInline,
    ];
    let mut seq = 0;
    let ops = csp_nonce_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn static_base64_nonce_detected() {
    let csp = "script-src 'nonce-aaaaaaaabbbbbbbb' 'strict-dynamic'";
    let issues = analyze_csp_nonces(csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::Base64Nonce { .. })));
}

#[test]
fn high_entropy_nonce_not_flagged_as_base64() {
    let csp = "script-src 'nonce-x7Kf9mPqR2sLwN3v' 'strict-dynamic'";
    let issues = analyze_csp_nonces(csp);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, CspNonceIssue::Base64Nonce { .. })));
}
