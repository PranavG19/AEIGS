use crate::request_smuggling_audit::*;

#[test]
fn dual_content_length_detected() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::DualContentLength];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn dual_transfer_encoding_detected() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::DualTransferEncoding];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn te_and_cl_both_present() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::TransferEncodingAndContentLength];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn obfuscated_te_variant() {
    let issue = RequestSmugglingIssue::ObfuscatedTransferEncoding {
        variant: "chunked ".to_string(),
    };
    assert_eq!(issue.to_string(), "obfuscated_te:chunked ");
}

#[test]
fn http2_downgrade_detected() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::Http2Downgrade];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn invalid_host_accepted() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::InvalidHostAccepted];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn connection_upgrade_present() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::ConnectionUpgradePresent];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn proxy_header_manipulation() {
    let issue = RequestSmugglingIssue::ProxyHeaderManipulation {
        header: "X-Forwarded-For".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "proxy_header_manipulation:X-Forwarded-For"
    );
}

#[test]
fn content_length_in_js_code() {
    let body = "xhr.setRequestHeader('Content-Length', '100');";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::ContentLengthInJsCode)
    );
}

#[test]
fn transfer_encoding_in_js_code() {
    let body = "xhr.setRequestHeader('Transfer-Encoding', 'chunked');";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::TransferEncodingInJsCode)
    );
}

#[test]
fn chunked_encoding_reference() {
    let body = "const encoding = 'chunked';";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::ChunkedEncodingReference)
    );
}

#[test]
fn h2c_upgrade_indicator() {
    let body = "Upgrade: h2c\r\nConnection: Upgrade";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::H2cUpgradeIndicator)
    );
}

#[test]
fn frontend_backend_desync() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::FrontendBackendDesync];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn websocket_upgrade_vulnerable() {
    let mut seq = 0u64;
    let issues = vec![RequestSmugglingIssue::WebsocketUpgradeVulnerable];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn severity_ordering_critical() {
    assert!(
        request_smuggling_severity(&RequestSmugglingIssue::DualContentLength)
            > request_smuggling_severity(&RequestSmugglingIssue::TransferEncodingAndContentLength)
    );
}

#[test]
fn severity_ordering_high() {
    assert!(
        request_smuggling_severity(&RequestSmugglingIssue::FrontendBackendDesync)
            > request_smuggling_severity(&RequestSmugglingIssue::DualTransferEncoding)
    );
}

#[test]
fn severity_ordering_medium() {
    assert!(
        request_smuggling_severity(&RequestSmugglingIssue::Http2Downgrade)
            > request_smuggling_severity(&RequestSmugglingIssue::ProxyHeaderManipulation {
                header: "test".to_string()
            })
    );
}

#[test]
fn severity_ordering_low() {
    assert!(
        request_smuggling_severity(&RequestSmugglingIssue::ChunkedEncodingReference)
            > request_smuggling_severity(&RequestSmugglingIssue::ContentLengthInJsCode)
    );
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0u64;
    let ops = smuggling_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn multiple_issues_generate_multiple_ops() {
    let mut seq = 0u64;
    let issues = vec![
        RequestSmugglingIssue::DualContentLength,
        RequestSmugglingIssue::DualTransferEncoding,
        RequestSmugglingIssue::Http2Downgrade,
    ];
    let ops = smuggling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn display_dual_content_length() {
    assert_eq!(
        RequestSmugglingIssue::DualContentLength.to_string(),
        "dual_content_length"
    );
}

#[test]
fn display_dual_transfer_encoding() {
    assert_eq!(
        RequestSmugglingIssue::DualTransferEncoding.to_string(),
        "dual_transfer_encoding"
    );
}

#[test]
fn display_te_and_cl() {
    assert_eq!(
        RequestSmugglingIssue::TransferEncodingAndContentLength.to_string(),
        "te_and_cl_both_present"
    );
}

#[test]
fn display_http2_downgrade() {
    assert_eq!(
        RequestSmugglingIssue::Http2Downgrade.to_string(),
        "http2_downgrade"
    );
}

#[test]
fn display_invalid_host() {
    assert_eq!(
        RequestSmugglingIssue::InvalidHostAccepted.to_string(),
        "invalid_host_accepted"
    );
}

#[test]
fn display_connection_upgrade() {
    assert_eq!(
        RequestSmugglingIssue::ConnectionUpgradePresent.to_string(),
        "connection_upgrade_present"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_request_smuggling("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback_ipv4() {
    let issues = audit_request_smuggling("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback_ipv6() {
    let issues = audit_request_smuggling("http://[::1]");
    assert!(issues.is_empty());
}

#[test]
fn content_length_double_quote() {
    let body = r#"xhr.setRequestHeader("Content-Length", "100");"#;
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::ContentLengthInJsCode)
    );
}

#[test]
fn transfer_encoding_property() {
    let body = "request.transferEncoding = 'chunked';";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::TransferEncodingInJsCode)
    );
}

#[test]
fn h2c_in_protocol_field() {
    let body = "const protocol: 'h2c'";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::H2cUpgradeIndicator)
    );
}

#[test]
fn http2_protocol_indicator() {
    let body = "supports HTTP/2 protocol";
    let issues = analyze_request_smuggling(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == RequestSmugglingIssue::H2cUpgradeIndicator)
    );
}

#[test]
fn clean_body_no_issues() {
    let body = "<!DOCTYPE html><html><body>Hello World</body></html>";
    let issues = analyze_request_smuggling(body);
    assert!(issues.is_empty());
}

#[test]
fn multiple_patterns_detected() {
    let body = r#"
        xhr.setRequestHeader('Content-Length', '100');
        xhr.setRequestHeader('Transfer-Encoding', 'chunked');
        protocol: 'h2c'
    "#;
    let issues = analyze_request_smuggling(body);
    assert!(issues.len() >= 3);
}
