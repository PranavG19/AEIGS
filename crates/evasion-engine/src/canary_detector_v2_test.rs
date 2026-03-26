use super::canary_detector_v2::*;

#[test]
fn empty_response_is_safe() {
    let detector = CanaryDetector::with_defaults();
    let result = detector.scan_response("", &[], "https://example.com");
    assert!(result.is_safe);
    assert!(result.canaries_found.is_empty());
}

#[test]
fn detects_aws_access_key_pattern() {
    let detector = CanaryDetector::with_defaults();
    let body = "config: AKIAIOSFODNN7EXAMPLE secret: wJalrXUtnFEMI";
    let result = detector.scan_response(body, &[], "");
    assert!(!result.canaries_found.is_empty());
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::AwsAccessKey));
}

#[test]
fn aws_key_has_critical_severity() {
    let detector = CanaryDetector::with_defaults();
    let body = "key=AKIAIOSFODNN7EXAMPLE";
    let result = detector.scan_response(body, &[], "");
    let canary = result
        .canaries_found
        .iter()
        .find(|c| c.canary_type == CanaryType::AwsAccessKey)
        .unwrap();
    assert_eq!(canary.severity, CanarySeverity::Critical);
}

#[test]
fn detects_canarytokens_domain() {
    let detector = CanaryDetector::with_defaults();
    let body = r#"<img src="https://canarytokens.com/abc123/pixel.gif">"#;
    let result = detector.scan_response(body, &[], "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::TrackingPixel));
}

#[test]
fn detects_interact_sh_domain() {
    let detector = CanaryDetector::with_defaults();
    let body = "callback: https://abc.interact.sh/test";
    let result = detector.scan_response(body, &[], "");
    assert!(!result.canaries_found.is_empty());
}

#[test]
fn detects_1x1_tracking_pixel() {
    let detector = CanaryDetector::with_defaults();
    let body = r#"<img src="/track" width="1" height="1">"#;
    let result = detector.scan_response(body, &[], "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::TrackingPixel));
}

#[test]
fn detects_honeydoc_marker() {
    let detector = CanaryDetector::with_defaults();
    let body = "This document is powered by thinkst canary platform.";
    let result = detector.scan_response(body, &[], "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::HoneydocMarker));
}

#[test]
fn detects_dns_canary_in_body() {
    let detector = CanaryDetector::with_defaults();
    let body = "resolve: abc123.canarytokens.com";
    let result = detector.scan_response(body, &[], "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::DnsCanary));
}

#[test]
fn detects_dns_canary_in_url() {
    let detector = CanaryDetector::with_defaults();
    let result = detector.scan_response("", &[], "https://x.dnslog.cn/test");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::DnsCanary));
}

#[test]
fn detects_canary_header() {
    let detector = CanaryDetector::with_defaults();
    let headers = vec![("X-Canary-Token", "abc123")];
    let result = detector.scan_response("", &headers, "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::WebBug));
}

#[test]
fn detects_hidden_honeypot_field() {
    let detector = CanaryDetector::with_defaults();
    let body = r#"<input type="hidden" name="honeypot" value="">"#;
    let result = detector.scan_response(body, &[], "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::HiddenFormField));
}

#[test]
fn detects_js_beacon_pattern() {
    let detector = CanaryDetector::with_defaults();
    let body = r#"<script>new Image().src="https://evil.com/track?id=123";</script>"#;
    let result = detector.scan_response(body, &[], "");
    assert!(result
        .canaries_found
        .iter()
        .any(|c| c.canary_type == CanaryType::JavaScriptBeacon));
}

#[test]
fn risk_score_reflects_highest_confidence() {
    let detector = CanaryDetector::with_defaults();
    let body = "AKIAIOSFODNN7EXAMPLE some text .canarytokens.com";
    let result = detector.scan_response(body, &[], "");
    assert!(result.risk_score >= 0.9);
}

#[test]
fn abort_threshold_marks_unsafe() {
    let detector = CanaryDetector::new(CanaryDetectorConfig {
        abort_risk_threshold: 0.5,
        ..Default::default()
    });
    let body = "<!-- canary token here -->";
    let result = detector.scan_response(body, &[], "");
    assert!(!result.is_safe);
}

#[test]
fn has_canaries_quick_check() {
    let detector = CanaryDetector::with_defaults();
    assert!(!detector.has_canaries("normal content"));
    assert!(detector.has_canaries("resolve: x.canarytokens.com"));
}

#[test]
fn canary_type_display() {
    assert_eq!(format!("{}", CanaryType::AwsAccessKey), "aws-access-key");
    assert_eq!(format!("{}", CanaryType::DnsCanary), "dns-canary");
    assert_eq!(format!("{}", CanaryType::TrackingPixel), "tracking-pixel");
}

#[test]
fn multiple_canaries_in_one_response() {
    let detector = CanaryDetector::with_defaults();
    let body = r#"
        key=AKIAIOSFODNN7EXAMPLE
        <img src="https://canarytokens.com/pixel.gif">
        <input type="hidden" name="honeypot" value="">
    "#;
    let result = detector.scan_response(body, &[], "");
    assert!(result.canaries_found.len() >= 3);
}
