use std::time::Duration;

use crate::smuggling_detector::{
    SmugglingDetector, SmugglingType, build_clte_probe, build_te_obfuscation_variants,
    build_tecl_probe, interpret_timing, parse_status_code, send_raw_request,
};

#[test]
fn clte_probe_contains_conflicting_headers() {
    let (probe, label) = build_clte_probe("localhost:3000", "/api");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.contains("Content-Length: 6"));
    assert!(text.contains("Transfer-Encoding: chunked"));
    assert!(text.contains("POST /api HTTP/1.1"));
    assert!(text.contains("Host: localhost:3000"));
    assert!(text.contains("0\r\n\r\nX"));
    assert_eq!(label, "CL.TE");
}

#[test]
fn clte_probe_body_length_matches_content_length() {
    let (probe, _) = build_clte_probe("localhost", "/");
    let text = String::from_utf8(probe).unwrap();
    let body_start = text.find("\r\n\r\n").unwrap() + 4;
    let body = &text[body_start..];
    assert_eq!(
        body.len(),
        6,
        "CL.TE body must be exactly 6 bytes: '0\\r\\n\\r\\nX'"
    );
}

#[test]
fn tecl_probe_contains_conflicting_headers() {
    let (probe, label) = build_tecl_probe("localhost:3000", "/api");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.contains("Content-Length: 3"));
    assert!(text.contains("Transfer-Encoding: chunked"));
    assert!(text.contains("POST /api HTTP/1.1"));
    assert!(text.contains("Host: localhost:3000"));
    assert!(text.contains("SMUGGLED"));
    assert_eq!(label, "TE.CL");
}

#[test]
fn tecl_probe_has_valid_chunked_body() {
    let (probe, _) = build_tecl_probe("localhost", "/");
    let text = String::from_utf8(probe).unwrap();
    let body_start = text.find("\r\n\r\n").unwrap() + 4;
    let body = &text[body_start..];
    assert!(body.starts_with("8\r\nSMUGGLED\r\n0\r\n\r\n"));
}

#[test]
fn te_obfuscation_variants_returns_four_variants() {
    let variants = build_te_obfuscation_variants();
    assert_eq!(variants.len(), 4);
}

#[test]
fn te_obfuscation_xchunked_variant() {
    let variants = build_te_obfuscation_variants();
    let (header, label) = &variants[0];
    assert_eq!(header, "Transfer-Encoding: xchunked");
    assert_eq!(*label, "xchunked");
}

#[test]
fn te_obfuscation_space_before_colon_variant() {
    let variants = build_te_obfuscation_variants();
    let (header, label) = &variants[1];
    assert_eq!(header, "Transfer-Encoding : chunked");
    assert_eq!(*label, "space-before-colon");
}

#[test]
fn te_obfuscation_duplicate_different_case_variant() {
    let variants = build_te_obfuscation_variants();
    let (header, label) = &variants[2];
    assert!(header.contains("Transfer-Encoding: chunked"));
    assert!(header.contains("Transfer-encoding: x"));
    assert_eq!(*label, "duplicate-different-case");
}

#[test]
fn te_obfuscation_tab_before_value_variant() {
    let variants = build_te_obfuscation_variants();
    let (header, label) = &variants[3];
    assert!(header.contains("Transfer-Encoding:\t"));
    assert!(header.contains("chunked"));
    assert_eq!(*label, "tab-before-value");
}

#[test]
fn smuggling_type_display_clte() {
    assert_eq!(SmugglingType::ClTe.to_string(), "CL.TE");
}

#[test]
fn smuggling_type_display_tecl() {
    assert_eq!(SmugglingType::TeCl.to_string(), "TE.CL");
}

#[test]
fn smuggling_type_display_tete() {
    assert_eq!(SmugglingType::TeTe.to_string(), "TE.TE");
}

#[test]
fn interpret_timing_below_threshold_returns_none() {
    let result = interpret_timing(
        "http://127.0.0.1:3000/api",
        SmugglingType::ClTe,
        Duration::from_secs(3),
        "",
    );
    assert!(result.is_none());
}

#[test]
fn interpret_timing_at_threshold_returns_finding() {
    let result = interpret_timing(
        "http://127.0.0.1:3000/api",
        SmugglingType::ClTe,
        Duration::from_secs(5),
        "",
    );
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.smuggling_type, SmugglingType::ClTe);
    assert!((f.severity - 8.5).abs() < f64::EPSILON);
    assert!(f.evidence.contains("CL.TE"));
    assert!(f.evidence.contains("5.0s"));
}

#[test]
fn interpret_timing_above_threshold_returns_finding() {
    let result = interpret_timing(
        "http://127.0.0.1:3000/api",
        SmugglingType::TeCl,
        Duration::from_secs(7),
        "",
    );
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.smuggling_type, SmugglingType::TeCl);
    assert!((f.severity - 8.5).abs() < f64::EPSILON);
    assert!(f.evidence.contains("TE.CL"));
}

#[test]
fn interpret_timing_tete_includes_label() {
    let result = interpret_timing(
        "http://127.0.0.1:3000/api",
        SmugglingType::TeTe,
        Duration::from_secs(6),
        "xchunked",
    );
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.smuggling_type, SmugglingType::TeTe);
    assert!(f.evidence.contains("xchunked"));
}

#[test]
fn interpret_timing_preserves_endpoint() {
    let result = interpret_timing(
        "http://127.0.0.1:8080/vulnerable",
        SmugglingType::ClTe,
        Duration::from_secs(10),
        "",
    );
    assert_eq!(result.unwrap().endpoint, "http://127.0.0.1:8080/vulnerable");
}

#[test]
fn parse_status_code_extracts_200() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(parse_status_code(response), 200);
}

#[test]
fn parse_status_code_extracts_400() {
    let response = b"HTTP/1.1 400 Bad Request\r\n\r\n";
    assert_eq!(parse_status_code(response), 400);
}

#[test]
fn parse_status_code_extracts_500() {
    let response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n";
    assert_eq!(parse_status_code(response), 500);
}

#[test]
fn parse_status_code_returns_zero_for_garbage() {
    let response = b"not an http response";
    assert_eq!(parse_status_code(response), 0);
}

#[test]
fn parse_status_code_returns_zero_for_empty() {
    assert_eq!(parse_status_code(b""), 0);
}

#[test]
fn detector_rejects_non_localhost() {
    let detector = SmugglingDetector::new();
    let findings = detector.test_smuggling("http://example.com/api");
    assert!(findings.is_empty());
}

#[test]
fn detector_rejects_empty_endpoint() {
    let detector = SmugglingDetector::new();
    let findings = detector.test_smuggling("");
    assert!(findings.is_empty());
}

#[test]
fn detector_rejects_invalid_url() {
    let detector = SmugglingDetector::new();
    let findings = detector.test_smuggling("not a url");
    assert!(findings.is_empty());
}

#[test]
fn detector_default_timeout_is_ten_seconds() {
    let detector = SmugglingDetector::new();
    assert_eq!(detector.timeout(), Duration::from_secs(10));
}

#[test]
fn detector_with_timeout_sets_value() {
    let detector = SmugglingDetector::new().with_timeout(Duration::from_secs(30));
    assert_eq!(detector.timeout(), Duration::from_secs(30));
}

#[test]
fn detector_default_impl_matches_new() {
    let d1 = SmugglingDetector::new();
    let d2 = SmugglingDetector::default();
    assert_eq!(d1.timeout(), d2.timeout());
}

#[test]
fn send_raw_request_fails_on_invalid_addr() {
    let result = send_raw_request(
        "not_an_address",
        b"GET / HTTP/1.1\r\n\r\n",
        Duration::from_secs(1),
    );
    assert!(result.is_err());
}

#[test]
fn send_raw_request_fails_on_connection_refused() {
    let result = send_raw_request(
        "127.0.0.1:1",
        b"GET / HTTP/1.1\r\n\r\n",
        Duration::from_secs(1),
    );
    assert!(result.is_err());
}

#[test]
fn clte_probe_uses_post_method() {
    let (probe, _) = build_clte_probe("localhost", "/test");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.starts_with("POST /test HTTP/1.1\r\n"));
}

#[test]
fn tecl_probe_uses_post_method() {
    let (probe, _) = build_tecl_probe("localhost", "/test");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.starts_with("POST /test HTTP/1.1\r\n"));
}

#[test]
fn clte_probe_includes_connection_close() {
    let (probe, _) = build_clte_probe("localhost", "/");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.contains("Connection: close"));
}

#[test]
fn tecl_probe_includes_connection_close() {
    let (probe, _) = build_tecl_probe("localhost", "/");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.contains("Connection: close"));
}

#[test]
fn smuggling_type_equality() {
    assert_eq!(SmugglingType::ClTe, SmugglingType::ClTe);
    assert_ne!(SmugglingType::ClTe, SmugglingType::TeCl);
    assert_ne!(SmugglingType::TeCl, SmugglingType::TeTe);
}

#[test]
fn clte_probe_with_different_paths() {
    let (probe, _) = build_clte_probe("127.0.0.1:8080", "/api/v2/users");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.contains("POST /api/v2/users HTTP/1.1"));
    assert!(text.contains("Host: 127.0.0.1:8080"));
}

#[test]
fn tecl_probe_with_different_paths() {
    let (probe, _) = build_tecl_probe("127.0.0.1:8080", "/api/v2/users");
    let text = String::from_utf8(probe).unwrap();
    assert!(text.contains("POST /api/v2/users HTTP/1.1"));
    assert!(text.contains("Host: 127.0.0.1:8080"));
}

#[test]
fn interpret_timing_just_below_threshold_returns_none() {
    let result = interpret_timing(
        "http://127.0.0.1:3000/api",
        SmugglingType::ClTe,
        Duration::from_millis(4999),
        "",
    );
    assert!(result.is_none());
}

#[test]
fn interpret_timing_severity_is_consistent() {
    for st in [
        SmugglingType::ClTe,
        SmugglingType::TeCl,
        SmugglingType::TeTe,
    ] {
        let f =
            interpret_timing("http://127.0.0.1:3000/", st, Duration::from_secs(6), "test").unwrap();
        assert!(
            (f.severity - 8.5).abs() < f64::EPSILON,
            "severity should be 8.5 for {st}"
        );
    }
}

#[test]
fn finding_fields_populated_correctly() {
    let f = interpret_timing(
        "http://127.0.0.1:3000/target",
        SmugglingType::TeCl,
        Duration::from_secs(8),
        "",
    )
    .unwrap();
    assert_eq!(f.endpoint, "http://127.0.0.1:3000/target");
    assert_eq!(f.smuggling_type, SmugglingType::TeCl);
    assert!((f.severity - 8.5).abs() < f64::EPSILON);
    assert!(!f.evidence.is_empty());
}
