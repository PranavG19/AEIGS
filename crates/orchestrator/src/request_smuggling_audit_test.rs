use crate::request_smuggling_audit::*;

#[test]
fn te_and_cl_both_present() {
    let issues = analyze_smuggling_headers(true, true, &["chunked"], false);
    assert!(issues
        .iter()
        .any(|i| *i == SmugglingIssue::TransferEncodingAndContentLength));
}

#[test]
fn te_only_clean() {
    let issues = analyze_smuggling_headers(true, false, &["chunked"], false);
    assert!(!issues
        .iter()
        .any(|i| *i == SmugglingIssue::TransferEncodingAndContentLength));
}

#[test]
fn cl_only_clean() {
    let issues = analyze_smuggling_headers(false, true, &[], false);
    assert!(issues.is_empty());
}

#[test]
fn dual_transfer_encoding() {
    let issues = analyze_smuggling_headers(true, false, &["chunked", "identity"], false);
    assert!(issues
        .iter()
        .any(|i| *i == SmugglingIssue::DualTransferEncoding));
}

#[test]
fn obfuscated_te_detected() {
    let issues = analyze_smuggling_headers(true, false, &["chunked ", " chunked"], false);
    assert!(issues
        .iter()
        .any(|i| matches!(i, SmugglingIssue::ObfuscatedTransferEncoding { .. })));
}

#[test]
fn normal_te_values_clean() {
    let issues = analyze_smuggling_headers(true, false, &["chunked"], false);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, SmugglingIssue::ObfuscatedTransferEncoding { .. })));
}

#[test]
fn gzip_te_clean() {
    let issues = analyze_smuggling_headers(true, false, &["gzip"], false);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, SmugglingIssue::ObfuscatedTransferEncoding { .. })));
}

#[test]
fn invalid_host_accepted() {
    let issues = analyze_smuggling_headers(false, false, &[], true);
    assert!(issues
        .iter()
        .any(|i| *i == SmugglingIssue::Http11WithoutHostValidation));
}

#[test]
fn invalid_host_rejected_clean() {
    let issues = analyze_smuggling_headers(false, false, &[], false);
    assert!(issues.is_empty());
}

#[test]
fn combined_issues() {
    let issues = analyze_smuggling_headers(true, true, &["chunked", " chunked"], true);
    assert!(issues.len() >= 3);
}

#[test]
fn severity_ordering() {
    assert!(
        smuggling_severity(&SmugglingIssue::DualTransferEncoding)
            > smuggling_severity(&SmugglingIssue::TransferEncodingAndContentLength)
    );
    assert!(
        smuggling_severity(&SmugglingIssue::TransferEncodingAndContentLength)
            > smuggling_severity(&SmugglingIssue::ObfuscatedTransferEncoding {
                variant: "x".to_string()
            })
    );
    assert!(
        smuggling_severity(&SmugglingIssue::ObfuscatedTransferEncoding {
            variant: "x".to_string()
        }) > smuggling_severity(&SmugglingIssue::Http11WithoutHostValidation)
    );
}

#[test]
fn operations_generated() {
    let issues = vec![
        SmugglingIssue::DualTransferEncoding,
        SmugglingIssue::Http11WithoutHostValidation,
    ];
    let mut seq = 0;
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = smuggling_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        SmugglingIssue::DualTransferEncoding.to_string(),
        "dual_transfer_encoding"
    );
    assert_eq!(
        SmugglingIssue::TransferEncodingAndContentLength.to_string(),
        "te_and_cl_both_present"
    );
    assert_eq!(
        SmugglingIssue::ObfuscatedTransferEncoding {
            variant: "chunked ".to_string()
        }
        .to_string(),
        "obfuscated_te:chunked "
    );
    assert_eq!(
        SmugglingIssue::Http11WithoutHostValidation.to_string(),
        "http11_no_host_validation"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_request_smuggling("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_request_smuggling("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn obfuscated_variants() {
    for variant in &["xchunked", "chunked\t", "CHUNKED"] {
        let issues = analyze_smuggling_headers(true, false, &[variant], false);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, SmugglingIssue::ObfuscatedTransferEncoding { .. })),
            "Should detect obfuscated TE: {variant}"
        );
    }
}
