use crate::ssrf_redirect_audit::*;

#[test]
fn external_redirect_not_flagged() {
    let result = analyze_redirect_location("https://example.com/page", "localhost");
    assert!(result.is_none());
}

#[test]
fn localhost_redirect_detected() {
    let result = analyze_redirect_location("http://127.0.0.1/admin", "localhost");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToLocalhost { .. })
    ));
}

#[test]
fn localhost_name_redirect_detected() {
    let result = analyze_redirect_location("http://localhost/secret", "localhost");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToLocalhost { .. })
    ));
}

#[test]
fn ipv6_localhost_detected() {
    let result = analyze_redirect_location("http://[::1]/api", "localhost");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToLocalhost { .. })
    ));
}

#[test]
fn aws_metadata_detected() {
    let result = analyze_redirect_location(
        "http://169.254.169.254/latest/meta-data/iam/info",
        "metadata",
    );
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToMetadata { .. })
    ));
}

#[test]
fn gcp_metadata_detected() {
    let result =
        analyze_redirect_location("http://metadata.google.internal/computeMetadata", "metadata");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToMetadata { .. })
    ));
}

#[test]
fn private_ip_10_detected() {
    let result = analyze_redirect_location("http://10.0.0.1/internal", "private");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToPrivateIp { .. })
    ));
}

#[test]
fn private_ip_192_detected() {
    let result = analyze_redirect_location("http://192.168.1.100/admin", "private");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToPrivateIp { .. })
    ));
}

#[test]
fn private_ip_172_detected() {
    let result = analyze_redirect_location("http://172.16.0.50/secret", "private");
    assert!(matches!(
        result,
        Some(SsrfRedirectIssue::RedirectToPrivateIp { .. })
    ));
}

#[test]
fn is_internal_covers_all_ranges() {
    assert!(is_internal_target("http://127.0.0.1/"));
    assert!(is_internal_target("http://localhost/"));
    assert!(is_internal_target("http://[::1]/"));
    assert!(is_internal_target("http://169.254.169.254/"));
    assert!(is_internal_target("http://metadata.google.internal/"));
    assert!(is_internal_target("http://10.0.0.1/"));
    assert!(is_internal_target("http://192.168.0.1/"));
    assert!(is_internal_target("http://172.16.0.1/"));
    assert!(!is_internal_target("http://example.com/"));
}

#[test]
fn invalid_kind_returns_none() {
    let result = analyze_redirect_location("http://127.0.0.1/", "unknown");
    assert!(result.is_none());
}

#[test]
fn severity_metadata_highest() {
    assert!(
        ssrf_redirect_severity(&SsrfRedirectIssue::RedirectToMetadata {
            location: "x".to_string()
        }) > ssrf_redirect_severity(&SsrfRedirectIssue::RedirectToLocalhost {
            location: "x".to_string()
        })
    );
}

#[test]
fn severity_localhost_higher_than_private() {
    assert!(
        ssrf_redirect_severity(&SsrfRedirectIssue::RedirectToLocalhost {
            location: "x".to_string()
        }) > ssrf_redirect_severity(&SsrfRedirectIssue::RedirectToPrivateIp {
            location: "x".to_string()
        })
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = ssrf_redirect_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![SsrfRedirectIssue::RedirectToMetadata {
        location: "http://169.254.169.254/".to_string(),
    }];
    let mut seq = 0;
    let ops = ssrf_redirect_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert_eq!(
        SsrfRedirectIssue::RedirectToPrivateIp {
            location: "http://10.0.0.1/".to_string()
        }
        .to_string(),
        "ssrf_redirect_private_ip:http://10.0.0.1/"
    );
    assert_eq!(
        SsrfRedirectIssue::RedirectToLocalhost {
            location: "http://localhost/".to_string()
        }
        .to_string(),
        "ssrf_redirect_localhost:http://localhost/"
    );
    assert_eq!(
        SsrfRedirectIssue::RedirectToMetadata {
            location: "http://169.254.169.254/".to_string()
        }
        .to_string(),
        "ssrf_redirect_metadata:http://169.254.169.254/"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_ssrf_redirect("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_ssrf_redirect("http://127.0.0.1");
    assert!(issues.is_empty());
}
