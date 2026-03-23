use crate::content_type_confusion_audit::*;

#[test]
fn both_success_detects_xml_acceptance() {
    let issues = analyze_content_type_confusion(200, 200, "<root/>", "/api/data");
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson { .. }
    )));
}

#[test]
fn json_ok_xml_rejected_no_issue() {
    let issues = analyze_content_type_confusion(200, 415, "", "/api/data");
    assert!(issues.is_empty());
}

#[test]
fn both_rejected_no_issue() {
    let issues = analyze_content_type_confusion(405, 405, "", "/api/data");
    assert!(issues.is_empty());
}

#[test]
fn xxe_file_content_detected() {
    let issues = analyze_content_type_confusion(
        200,
        200,
        "<response>root:x:0:0:root:/root:/bin/bash</response>",
        "/api/data",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::XxeIndicator { indicator, .. } if indicator == "file_content_leak"
    )));
}

#[test]
fn xxe_metadata_detected() {
    let issues = analyze_content_type_confusion(
        200,
        200,
        "<response>169.254.169.254 metadata</response>",
        "/api/data",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::XxeIndicator { indicator, .. } if indicator == "ssrf_metadata_leak"
    )));
}

#[test]
fn no_xxe_in_normal_xml_response() {
    let issues = analyze_content_type_confusion(200, 200, "<response>ok</response>", "/api/data");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::XxeIndicator { .. }))
    );
}

#[test]
fn xxe_not_checked_when_xml_rejected() {
    let issues =
        analyze_content_type_confusion(200, 415, "root:x:0:0:root:/root:/bin/bash", "/api/data");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::XxeIndicator { .. }))
    );
}

#[test]
fn json_to_xml_response_mismatch() {
    let result = analyze_response_type_mismatch("application/json", "application/xml");
    assert!(result.is_some());
    assert!(matches!(
        result.unwrap(),
        ContentTypeConfusionIssue::MismatchedResponseType { .. }
    ));
}

#[test]
fn xml_to_json_response_mismatch() {
    let result = analyze_response_type_mismatch("text/xml", "application/json; charset=utf-8");
    assert!(result.is_some());
}

#[test]
fn same_type_no_mismatch() {
    let result = analyze_response_type_mismatch("application/json", "application/json");
    assert!(result.is_none());
}

#[test]
fn html_to_html_no_mismatch() {
    let result = analyze_response_type_mismatch("text/html", "text/html");
    assert!(result.is_none());
}

#[test]
fn severity_ordering() {
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::XxeIndicator {
            endpoint: "/api".into(),
            indicator: "file_read".into()
        }) > content_type_confusion_severity(
            &ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
                endpoint: "/api".into()
            }
        )
    );
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
            endpoint: "/api".into()
        }) > content_type_confusion_severity(&ContentTypeConfusionIssue::MismatchedResponseType {
            request_ct: "json".into(),
            response_ct: "xml".into()
        })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
            endpoint: "/api".into(),
        },
        ContentTypeConfusionIssue::XxeIndicator {
            endpoint: "/api".into(),
            indicator: "file_read".into(),
        },
    ];
    let mut seq = 20;
    let ops = content_type_confusion_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 22);
}

#[test]
fn display_variants() {
    let issue = ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
        endpoint: "/api".into(),
    };
    assert_eq!(issue.to_string(), "accepts_xml_for_json:/api");

    let issue = ContentTypeConfusionIssue::XxeIndicator {
        endpoint: "/api".into(),
        indicator: "file_read".into(),
    };
    assert_eq!(issue.to_string(), "xxe_indicator:/api:file_read");

    let issue = ContentTypeConfusionIssue::MismatchedResponseType {
        request_ct: "json".into(),
        response_ct: "xml".into(),
    };
    assert_eq!(issue.to_string(), "ct_mismatch:json->xml");
}

// PolyglotPayload tests
#[test]
fn test_polyglot_pdf_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html"),
        &[],
        "%PDF-1.4\n%âãÏÓ\n<html><script>alert(1)</script></html>",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

#[test]
fn test_polyglot_gif_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/plain"),
        &[],
        "GIF89a<script>alert(1)</script>",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

#[test]
fn test_polyglot_gif87a_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("application/json"),
        &[],
        "GIF87a{\"evil\": true}",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

#[test]
fn test_polyglot_script_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("application/json"),
        &[],
        "<script>alert(document.cookie)</script>",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

#[test]
fn test_no_polyglot_for_correct_type() {
    let issues =
        analyze_content_type_confusion_advanced(Some("application/pdf"), &[], "%PDF-1.4\ncontent");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

#[test]
fn test_no_polyglot_for_gif_with_image_type() {
    let issues = analyze_content_type_confusion_advanced(Some("image/gif"), &[], "GIF89acontent");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

#[test]
fn test_no_polyglot_for_script_in_html() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html"),
        &[],
        "<script>alert(1)</script>",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
}

// ContentTypeHeaderInjection tests
#[test]
fn test_crlf_injection_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html\r\nX-Evil: injected"),
        &[("Content-Type", "text/html\r\nX-Evil: injected")],
        "",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::ContentTypeHeaderInjection { .. }
    )));
}

#[test]
fn test_url_encoded_crlf_injection_detected() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Content-Type", "text/html%0d%0aX-Evil: injected")],
        "",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::ContentTypeHeaderInjection { .. }
    )));
}

#[test]
fn test_uppercase_encoded_crlf_injection_detected() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Content-Type", "text/html%0D%0AX-Evil: injected")],
        "",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::ContentTypeHeaderInjection { .. }
    )));
}

#[test]
fn test_no_crlf_injection_in_normal_header() {
    let issues =
        analyze_content_type_confusion_advanced(None, &[("Content-Type", "text/html")], "");
    assert!(!issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::ContentTypeHeaderInjection { .. }
    )));
}

// MultipartBoundaryConfusion tests
#[test]
fn test_multipart_boundary_confusion_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("multipart/form-data; boundary=----WebKitFormBoundary"),
        &[],
        "--different-boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::MultipartBoundaryConfusion))
    );
}

#[test]
fn test_no_boundary_confusion_with_correct_boundary() {
    let issues = analyze_content_type_confusion_advanced(
        Some("multipart/form-data; boundary=----WebKitFormBoundary"),
        &[],
        "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::MultipartBoundaryConfusion))
    );
}

#[test]
fn test_no_boundary_confusion_without_multipart() {
    let issues = analyze_content_type_confusion_advanced(
        Some("application/json"),
        &[],
        "--some-dashes-in-body",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::MultipartBoundaryConfusion))
    );
}

// CharsetOverride tests
#[test]
fn test_charset_override_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; charset=utf-8"),
        &[],
        "<html><head><meta charset=\"iso-8859-1\"></head></html>",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::CharsetOverride { .. }))
    );
}

#[test]
fn test_no_charset_override_with_matching_charsets() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; charset=utf-8"),
        &[],
        "<html><head><meta charset=\"utf-8\"></head></html>",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::CharsetOverride { .. }))
    );
}

#[test]
fn test_no_charset_override_without_meta_tag() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; charset=utf-8"),
        &[],
        "<html><body>content</body></html>",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::CharsetOverride { .. }))
    );
}

// NullByteInContentType tests
#[test]
fn test_null_byte_percent_encoded_detected() {
    let issues = analyze_content_type_confusion_advanced(Some("text/html%00.jpg"), &[], "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::NullByteInContentType))
    );
}

#[test]
fn test_null_byte_literal_detected() {
    let issues = analyze_content_type_confusion_advanced(Some("text/html\0.jpg"), &[], "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::NullByteInContentType))
    );
}

#[test]
fn test_no_null_byte_in_normal_content_type() {
    let issues = analyze_content_type_confusion_advanced(Some("text/html"), &[], "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::NullByteInContentType))
    );
}

// WildcardAcceptHeader tests
#[test]
fn test_wildcard_accept_with_negotiation_detected() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Accept", "*/*"), ("Accept-Language", "en-US,en;q=0.9")],
        "",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::WildcardAcceptHeader))
    );
}

#[test]
fn test_wildcard_accept_with_encoding_negotiation() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Accept", "*/*"), ("Accept-Encoding", "gzip, deflate")],
        "",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::WildcardAcceptHeader))
    );
}

#[test]
fn test_no_wildcard_accept_without_negotiation() {
    let issues = analyze_content_type_confusion_advanced(None, &[("Accept", "*/*")], "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::WildcardAcceptHeader))
    );
}

#[test]
fn test_no_wildcard_accept_with_specific_type() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Accept", "application/json"), ("Accept-Language", "en-US")],
        "",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::WildcardAcceptHeader))
    );
}

// ContentTypeParameterPollution tests
#[test]
fn test_parameter_pollution_detected() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; charset=utf-8; charset=iso-8859-1"),
        &[],
        "",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeParameterPollution))
    );
}

#[test]
fn test_parameter_pollution_case_insensitive() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; CHARSET=utf-8; charset=iso-8859-1"),
        &[],
        "",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeParameterPollution))
    );
}

#[test]
fn test_no_parameter_pollution_with_unique_params() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; charset=utf-8; boundary=----WebKit"),
        &[],
        "",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeParameterPollution))
    );
}

// DoubleContentTypeHeader tests
#[test]
fn test_double_content_type_header_detected() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[
            ("Content-Type", "text/html"),
            ("Content-Type", "application/json"),
        ],
        "",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::DoubleContentTypeHeader))
    );
}

#[test]
fn test_no_double_content_type_with_single_header() {
    let issues =
        analyze_content_type_confusion_advanced(None, &[("Content-Type", "text/html")], "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::DoubleContentTypeHeader))
    );
}

#[test]
fn test_no_double_content_type_without_content_type() {
    let issues = analyze_content_type_confusion_advanced(None, &[("Accept", "text/html")], "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::DoubleContentTypeHeader))
    );
}

// ContentTypeCaseSensitivity tests
#[test]
fn test_case_sensitivity_application_detected() {
    let issues = analyze_content_type_confusion_advanced(Some("Application/JSON"), &[], "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeCaseSensitivity))
    );
}

#[test]
fn test_case_sensitivity_text_detected() {
    let issues = analyze_content_type_confusion_advanced(Some("Text/HTML"), &[], "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeCaseSensitivity))
    );
}

#[test]
fn test_case_sensitivity_json_detected() {
    let issues = analyze_content_type_confusion_advanced(Some("application/JSON"), &[], "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeCaseSensitivity))
    );
}

#[test]
fn test_no_case_sensitivity_with_lowercase() {
    let issues = analyze_content_type_confusion_advanced(Some("application/json"), &[], "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeCaseSensitivity))
    );
}

// ContentLengthMismatch tests
#[test]
fn test_content_length_mismatch_detected() {
    let issues =
        analyze_content_type_confusion_advanced(None, &[("Content-Length", "100")], "short");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentLengthMismatch))
    );
}

#[test]
fn test_content_length_mismatch_body_longer() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Content-Length", "5")],
        "this is a much longer body than declared",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentLengthMismatch))
    );
}

#[test]
fn test_no_content_length_mismatch_with_correct_length() {
    let body = "exact body";
    let issues = analyze_content_type_confusion_advanced(None, &[("Content-Length", "10")], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentLengthMismatch))
    );
}

#[test]
fn test_no_content_length_mismatch_within_tolerance() {
    let issues = analyze_content_type_confusion_advanced(
        None,
        &[("Content-Length", "105")],
        &"x".repeat(100),
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentLengthMismatch))
    );
}

// Combined detection tests
#[test]
fn test_multiple_issues_detected_together() {
    let issues = analyze_content_type_confusion_advanced(
        Some("Application/JSON; charset=utf-8"),
        &[
            ("Content-Type", "Application/JSON; charset=utf-8"),
            ("Content-Type", "text/html"),
        ],
        "%PDF-1.4\ncontent",
    );
    assert!(issues.len() >= 3);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::PolyglotPayload { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::DoubleContentTypeHeader))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeCaseSensitivity))
    );
}

#[test]
fn test_empty_inputs_no_issues() {
    let issues = analyze_content_type_confusion_advanced(None, &[], "");
    assert!(issues.is_empty());
}

#[test]
fn test_minimal_valid_input_no_issues() {
    let issues = analyze_content_type_confusion_advanced(Some("text/plain"), &[], "normal content");
    assert!(issues.is_empty());
}

// Edge case tests
#[test]
fn test_content_type_with_spaces() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html ; charset=utf-8 ; boundary=abc"),
        &[],
        "",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::ContentTypeParameterPollution))
    );
}

#[test]
fn test_boundary_confusion_no_boundary_param() {
    let issues = analyze_content_type_confusion_advanced(
        Some("multipart/form-data"),
        &[],
        "--some-boundary\r\ndata",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::MultipartBoundaryConfusion))
    );
}

#[test]
fn test_charset_override_with_single_quotes() {
    let issues = analyze_content_type_confusion_advanced(
        Some("text/html; charset=utf-8"),
        &[],
        "<html><head><meta charset='iso-8859-1'></head></html>",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ContentTypeConfusionIssue::CharsetOverride { .. }))
    );
}

// Severity tests for new variants
#[test]
fn test_new_variants_severity_ordering() {
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::ContentTypeHeaderInjection {
            header: "test".into()
        }) > content_type_confusion_severity(&ContentTypeConfusionIssue::PolyglotPayload {
            content_type: "test".into()
        })
    );
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::PolyglotPayload {
            content_type: "test".into()
        }) > content_type_confusion_severity(&ContentTypeConfusionIssue::NullByteInContentType)
    );
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::NullByteInContentType)
            > content_type_confusion_severity(
                &ContentTypeConfusionIssue::ContentTypeParameterPollution
            )
    );
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::ContentTypeParameterPollution)
            > content_type_confusion_severity(
                &ContentTypeConfusionIssue::MultipartBoundaryConfusion
            )
    );
}

// Display tests for new variants
#[test]
fn test_display_new_variants() {
    let issue = ContentTypeConfusionIssue::PolyglotPayload {
        content_type: "text/html".into(),
    };
    assert_eq!(issue.to_string(), "polyglot_payload:text/html");

    let issue = ContentTypeConfusionIssue::ContentTypeHeaderInjection {
        header: "evil%0d%0a".into(),
    };
    assert_eq!(issue.to_string(), "ct_header_injection:evil%0d%0a");

    let issue = ContentTypeConfusionIssue::MultipartBoundaryConfusion;
    assert_eq!(issue.to_string(), "multipart_boundary_confusion");

    let issue = ContentTypeConfusionIssue::CharsetOverride {
        declared: "utf-8".into(),
        actual: "iso-8859-1".into(),
    };
    assert_eq!(issue.to_string(), "charset_override:utf-8->iso-8859-1");

    let issue = ContentTypeConfusionIssue::NullByteInContentType;
    assert_eq!(issue.to_string(), "null_byte_in_content_type");

    let issue = ContentTypeConfusionIssue::WildcardAcceptHeader;
    assert_eq!(issue.to_string(), "wildcard_accept_header");

    let issue = ContentTypeConfusionIssue::ContentTypeParameterPollution;
    assert_eq!(issue.to_string(), "content_type_parameter_pollution");

    let issue = ContentTypeConfusionIssue::DoubleContentTypeHeader;
    assert_eq!(issue.to_string(), "double_content_type_header");

    let issue = ContentTypeConfusionIssue::ContentTypeCaseSensitivity;
    assert_eq!(issue.to_string(), "content_type_case_sensitivity");

    let issue = ContentTypeConfusionIssue::ContentLengthMismatch;
    assert_eq!(issue.to_string(), "content_length_mismatch");
}
