use crate::content_type_audit::{
    ContentTypeIssueKind, ContentTypeSecurityIssue, analyze_content_type,
    analyze_content_type_security, content_type_security_severity,
    content_type_security_to_operations, content_type_to_operations,
};

#[test]
fn proper_headers_no_issues() {
    let issues = analyze_content_type(Some("nosniff"), Some("text/html; charset=utf-8"));
    assert!(issues.is_empty());
}

#[test]
fn missing_nosniff() {
    let issues = analyze_content_type(None, Some("text/html; charset=utf-8"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, ContentTypeIssueKind::MissingNosniff);
}

#[test]
fn wrong_nosniff_value() {
    let issues = analyze_content_type(Some("none"), Some("text/html; charset=utf-8"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ContentTypeIssueKind::MissingNosniff)
    );
}

#[test]
fn nosniff_case_insensitive() {
    let issues = analyze_content_type(Some("NOSNIFF"), Some("text/html; charset=utf-8"));
    assert!(issues.is_empty());
}

#[test]
fn missing_content_type() {
    let issues = analyze_content_type(Some("nosniff"), None);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ContentTypeIssueKind::MissingContentType)
    );
}

#[test]
fn octet_stream_flagged() {
    let issues = analyze_content_type(Some("nosniff"), Some("application/octet-stream"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ContentTypeIssueKind::OctetStreamForHtml)
    );
}

#[test]
fn text_without_charset() {
    let issues = analyze_content_type(Some("nosniff"), Some("text/html"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ContentTypeIssueKind::CharsetMissing)
    );
}

#[test]
fn text_with_charset_ok() {
    let issues = analyze_content_type(Some("nosniff"), Some("text/plain; charset=utf-8"));
    assert!(issues.is_empty());
}

#[test]
fn application_json_no_charset_ok() {
    let issues = analyze_content_type(Some("nosniff"), Some("application/json"));
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues() {
    let issues = analyze_content_type(None, Some("application/octet-stream"));
    assert!(issues.len() >= 2);
}

#[test]
fn both_missing() {
    let issues = analyze_content_type(None, None);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ContentTypeIssueKind::MissingNosniff)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ContentTypeIssueKind::MissingContentType)
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = content_type_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_content_type(None, None);
    let mut seq = 0;
    let ops = content_type_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", ContentTypeIssueKind::MissingNosniff).is_empty());
    assert!(!format!("{}", ContentTypeIssueKind::MissingContentType).is_empty());
    assert!(!format!("{}", ContentTypeIssueKind::OctetStreamForHtml).is_empty());
    assert!(!format!("{}", ContentTypeIssueKind::CharsetMissing).is_empty());
}

// ============================================================
// ContentTypeSecurityIssue Tests
// ============================================================

// 1. MimeSniffingVulnerable tests
#[test]
fn mime_sniffing_vulnerable_detected() {
    let body = "<!DOCTYPE html><html><head></head><body>test</body></html>";
    let issues = analyze_content_type_security(Some("text/plain"), None, body);
    assert!(issues.contains(&ContentTypeSecurityIssue::MimeSniffingVulnerable));
}

#[test]
fn mime_sniffing_not_vulnerable_with_nosniff() {
    let body = "<!DOCTYPE html><html><head></head><body>test</body></html>";
    let issues = analyze_content_type_security(Some("text/plain"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::MimeSniffingVulnerable));
}

#[test]
fn mime_sniffing_not_vulnerable_correct_type() {
    let body = "<!DOCTYPE html><html><head></head><body>test</body></html>";
    let issues = analyze_content_type_security(Some("text/html"), None, body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::MimeSniffingVulnerable));
}

#[test]
fn mime_sniffing_not_vulnerable_no_html() {
    let body = "plain text content without any html";
    let issues = analyze_content_type_security(Some("text/plain"), None, body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::MimeSniffingVulnerable));
}

// 2. JsonWithHtmlContent tests
#[test]
fn json_with_html_content_detected() {
    let body = r#"{"data": "<div>malicious</div>"}"#;
    let issues = analyze_content_type_security(Some("application/json"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::JsonWithHtmlContent));
}

#[test]
fn json_with_html_content_negative() {
    let body = r#"{"data": "normal text content"}"#;
    let issues = analyze_content_type_security(Some("application/json"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::JsonWithHtmlContent));
}

#[test]
fn json_with_script_tag() {
    let body = r#"{"data": "<script>alert(1)</script>"}"#;
    let issues = analyze_content_type_security(Some("application/json"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::JsonWithHtmlContent));
}

// 3. XmlWithScript tests
#[test]
fn xml_with_script_detected() {
    let body = r#"<?xml version="1.0"?><root><script>alert(1)</script></root>"#;
    let issues = analyze_content_type_security(Some("application/xml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::XmlWithScript));
}

#[test]
fn xml_with_script_text_xml() {
    let body = r#"<root><script>alert(1)</script></root>"#;
    let issues = analyze_content_type_security(Some("text/xml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::XmlWithScript));
}

#[test]
fn xml_with_script_negative() {
    let body = r#"<?xml version="1.0"?><root><data>content</data></root>"#;
    let issues = analyze_content_type_security(Some("application/xml"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::XmlWithScript));
}

#[test]
fn xml_with_javascript_protocol() {
    let body = r#"<root><a href="javascript:alert(1)">link</a></root>"#;
    let issues = analyze_content_type_security(Some("application/xml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::XmlWithScript));
}

// 4. SvgWithScript tests
#[test]
fn svg_with_script_detected() {
    let body = r#"<svg><script>alert(1)</script></svg>"#;
    let issues = analyze_content_type_security(Some("image/svg+xml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::SvgWithScript));
}

#[test]
fn svg_with_script_negative() {
    let body = r#"<svg><circle cx="50" cy="50" r="40"/></svg>"#;
    let issues = analyze_content_type_security(Some("image/svg+xml"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::SvgWithScript));
}

#[test]
fn svg_with_javascript_event() {
    let body = r#"<svg><rect onclick="javascript:alert(1)"/></svg>"#;
    let issues = analyze_content_type_security(Some("image/svg+xml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::SvgWithScript));
}

// 5. CsvInjection tests
#[test]
fn csv_injection_equals_formula() {
    let body = "name,value\n=1+1,data";
    let issues = analyze_content_type_security(Some("text/csv"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CsvInjection));
}

#[test]
fn csv_injection_plus_formula() {
    let body = "name,value\n+1+1,data";
    let issues = analyze_content_type_security(Some("text/csv"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CsvInjection));
}

#[test]
fn csv_injection_minus_formula() {
    let body = "name,value\n-1,data";
    let issues = analyze_content_type_security(Some("text/csv"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CsvInjection));
}

#[test]
fn csv_injection_at_formula() {
    let body = "name,value\n@SUM(A1:A2),data";
    let issues = analyze_content_type_security(Some("text/csv"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CsvInjection));
}

#[test]
fn csv_injection_negative() {
    let body = "name,value\nnormal,data";
    let issues = analyze_content_type_security(Some("text/csv"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::CsvInjection));
}

// 6. TextPlainWithHtml tests
#[test]
fn text_plain_with_html_doctype() {
    let body = "<!DOCTYPE html><html><body>content</body></html>";
    let issues = analyze_content_type_security(Some("text/plain"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::TextPlainWithHtml));
}

#[test]
fn text_plain_with_html_tag() {
    let body = "<html><body>content</body></html>";
    let issues = analyze_content_type_security(Some("text/plain"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::TextPlainWithHtml));
}

#[test]
fn text_plain_with_html_negative() {
    let body = "just plain text content";
    let issues = analyze_content_type_security(Some("text/plain"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::TextPlainWithHtml));
}

#[test]
fn text_plain_with_html_uppercase() {
    let body = "<HTML><BODY>content</BODY></HTML>";
    let issues = analyze_content_type_security(Some("text/plain"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::TextPlainWithHtml));
}

// 7. MultipartBoundaryExposed tests
#[test]
fn multipart_boundary_exposed() {
    let body = "--boundary123\r\nContent-Disposition: form-data\r\n\r\ndata";
    let issues = analyze_content_type_security(
        Some("multipart/form-data; boundary=boundary123"),
        Some("nosniff"),
        body,
    );
    assert!(issues.contains(&ContentTypeSecurityIssue::MultipartBoundaryExposed));
}

#[test]
fn multipart_boundary_exposed_quoted() {
    let body = "--myboundary\r\nContent-Disposition: form-data\r\n\r\ndata";
    let issues = analyze_content_type_security(
        Some("multipart/form-data; boundary=\"myboundary\""),
        Some("nosniff"),
        body,
    );
    assert!(issues.contains(&ContentTypeSecurityIssue::MultipartBoundaryExposed));
}

#[test]
fn multipart_boundary_not_exposed() {
    let body = "some data without boundary";
    let issues = analyze_content_type_security(
        Some("multipart/form-data; boundary=boundary123"),
        Some("nosniff"),
        body,
    );
    assert!(!issues.contains(&ContentTypeSecurityIssue::MultipartBoundaryExposed));
}

// 8. CharsetMismatch tests
#[test]
fn charset_mismatch_bom() {
    let body = "\u{FEFF}content with BOM";
    let issues =
        analyze_content_type_security(Some("text/html; charset=iso-8859-1"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CharsetMismatch));
}

#[test]
fn charset_mismatch_meta_tag() {
    let body = r#"<html><head><meta charset="utf-8"></head></html>"#;
    let issues =
        analyze_content_type_security(Some("text/html; charset=iso-8859-1"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CharsetMismatch));
}

#[test]
fn charset_mismatch_negative() {
    let body = r#"<html><head><meta charset="utf-8"></head></html>"#;
    let issues =
        analyze_content_type_security(Some("text/html; charset=utf-8"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::CharsetMismatch));
}

#[test]
fn charset_mismatch_no_declared_charset() {
    let body = "\u{FEFF}content with BOM";
    let issues = analyze_content_type_security(Some("text/html"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::CharsetMismatch));
}

// 9. ContentTypeDoubleEncoded tests
#[test]
fn content_type_double_encoded_percent() {
    let body = "content";
    let issues = analyze_content_type_security(Some("text%2Fhtml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::ContentTypeDoubleEncoded));
}

#[test]
fn content_type_double_encoded_hex() {
    let body = "content";
    let issues = analyze_content_type_security(Some("text\\x2Fhtml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::ContentTypeDoubleEncoded));
}

#[test]
fn content_type_double_encoded_negative() {
    let body = "content";
    let issues = analyze_content_type_security(Some("text/html"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::ContentTypeDoubleEncoded));
}

// 10. InconsistentMimeType tests
#[test]
fn inconsistent_mime_type_json() {
    let body = "not a json object";
    let issues = analyze_content_type_security(Some("application/json"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

#[test]
fn inconsistent_mime_type_json_negative() {
    let body = r#"{"key": "value"}"#;
    let issues = analyze_content_type_security(Some("application/json"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

#[test]
fn inconsistent_mime_type_json_array() {
    let body = r#"[1, 2, 3]"#;
    let issues = analyze_content_type_security(Some("application/json"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

#[test]
fn inconsistent_mime_type_html() {
    let body = "plain text without html";
    let issues = analyze_content_type_security(Some("text/html"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

#[test]
fn inconsistent_mime_type_html_negative() {
    let body = "<html><body>content</body></html>";
    let issues = analyze_content_type_security(Some("text/html"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

#[test]
fn inconsistent_mime_type_xml() {
    let body = "plain text content";
    let issues = analyze_content_type_security(Some("application/xml"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

#[test]
fn inconsistent_mime_type_xml_negative() {
    let body = r#"<?xml version="1.0"?><root/>"#;
    let issues = analyze_content_type_security(Some("application/xml"), Some("nosniff"), body);
    assert!(!issues.contains(&ContentTypeSecurityIssue::InconsistentMimeType));
}

// Display tests
#[test]
fn display_security_issue_variants() {
    assert!(!format!("{}", ContentTypeSecurityIssue::MimeSniffingVulnerable).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::JsonWithHtmlContent).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::XmlWithScript).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::SvgWithScript).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::CsvInjection).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::TextPlainWithHtml).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::MultipartBoundaryExposed).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::CharsetMismatch).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::ContentTypeDoubleEncoded).is_empty());
    assert!(!format!("{}", ContentTypeSecurityIssue::InconsistentMimeType).is_empty());
}

// Severity tests
#[test]
fn severity_all_variants() {
    assert!(
        content_type_security_severity(&ContentTypeSecurityIssue::MimeSniffingVulnerable) > 0.0
    );
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::JsonWithHtmlContent) > 0.0);
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::XmlWithScript) > 0.0);
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::SvgWithScript) > 0.0);
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::CsvInjection) > 0.0);
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::TextPlainWithHtml) > 0.0);
    assert!(
        content_type_security_severity(&ContentTypeSecurityIssue::MultipartBoundaryExposed) > 0.0
    );
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::CharsetMismatch) > 0.0);
    assert!(
        content_type_security_severity(&ContentTypeSecurityIssue::ContentTypeDoubleEncoded) > 0.0
    );
    assert!(content_type_security_severity(&ContentTypeSecurityIssue::InconsistentMimeType) > 0.0);
}

#[test]
fn severity_relative_ordering() {
    let svg_severity = content_type_security_severity(&ContentTypeSecurityIssue::SvgWithScript);
    let boundary_severity =
        content_type_security_severity(&ContentTypeSecurityIssue::MultipartBoundaryExposed);
    assert!(svg_severity > boundary_severity);
}

// Operations tests
#[test]
fn operations_empty_when_no_security_issues() {
    let mut seq = 0;
    let ops = content_type_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_for_single_issue() {
    let issues = vec![ContentTypeSecurityIssue::MimeSniffingVulnerable];
    let mut seq = 0;
    let ops = content_type_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_produced_for_multiple_issues() {
    let issues = vec![
        ContentTypeSecurityIssue::MimeSniffingVulnerable,
        ContentTypeSecurityIssue::JsonWithHtmlContent,
        ContentTypeSecurityIssue::SvgWithScript,
    ];
    let mut seq = 0;
    let ops = content_type_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn operations_sequence_increments_correctly() {
    let issues = vec![
        ContentTypeSecurityIssue::XmlWithScript,
        ContentTypeSecurityIssue::CsvInjection,
    ];
    let mut seq = 100;
    let ops = content_type_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

// Edge case tests
#[test]
fn empty_body_no_issues() {
    let issues = analyze_content_type_security(Some("text/html"), Some("nosniff"), "");
    assert!(issues.is_empty());
}

#[test]
fn none_content_type_no_crash() {
    let body = "<html><body>test</body></html>";
    let issues = analyze_content_type_security(None, Some("nosniff"), body);
    assert!(issues.is_empty());
}

#[test]
fn whitespace_only_body() {
    let issues = analyze_content_type_security(Some("text/html"), Some("nosniff"), "   \n\t  ");
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_content_type() {
    let body = r#"{"data": "<script>alert(1)</script>"}"#;
    let issues = analyze_content_type_security(Some("APPLICATION/JSON"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::JsonWithHtmlContent));
}

#[test]
fn multiple_issues_detected() {
    let body = "<html><script>alert(1)</script></html>";
    let issues = analyze_content_type_security(Some("text/plain"), None, body);
    assert!(issues.len() >= 2);
    assert!(issues.contains(&ContentTypeSecurityIssue::MimeSniffingVulnerable));
    assert!(issues.contains(&ContentTypeSecurityIssue::TextPlainWithHtml));
}

#[test]
fn csv_injection_at_line_boundary() {
    let body = "header1,header2\nnormal,data\n=1+1,injection";
    let issues = analyze_content_type_security(Some("text/csv"), Some("nosniff"), body);
    assert!(issues.contains(&ContentTypeSecurityIssue::CsvInjection));
}

#[test]
fn boundary_with_semicolon_delimiter() {
    let body = "--mybound\r\ndata";
    let issues = analyze_content_type_security(
        Some("multipart/form-data; boundary=mybound; charset=utf-8"),
        Some("nosniff"),
        body,
    );
    assert!(issues.contains(&ContentTypeSecurityIssue::MultipartBoundaryExposed));
}
