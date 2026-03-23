use crate::payment_request_audit::*;

#[test]
fn no_payment_api_no_issues() {
    assert!(analyze_payment_request("<html></html>", true).is_empty());
}

#[test]
fn detects_api_usage() {
    let body = r#"<script>new PaymentRequest(methods, details)</script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(issues.contains(&PaymentRequestIssue::ApiDetected));
}

#[test]
fn detects_insecure_context() {
    let body = r#"<script>new PaymentRequest(methods, details)</script>"#;
    let issues = analyze_payment_request(body, false);
    assert!(issues.contains(&PaymentRequestIssue::InsecureContext));
}

#[test]
fn no_insecure_on_https() {
    let body = r#"<script>new PaymentRequest(methods, details)</script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(!issues.contains(&PaymentRequestIssue::InsecureContext));
}

#[test]
fn detects_can_make_payment_fingerprint() {
    let body = r#"<script>
        const req = new PaymentRequest(methods, details);
        req.canMakePayment().then(result => { track(result); });
    </script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(issues.contains(&PaymentRequestIssue::CanMakePaymentFingerprint));
}

#[test]
fn detects_third_party_method() {
    let body = r#"<script>
        const methods = [{supportedMethods: "https://apple.com/apple-pay"}];
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(issues.contains(&PaymentRequestIssue::ThirdPartyPaymentMethod));
}

#[test]
fn no_third_party_without_known_urls() {
    let body = r#"<script>
        const methods = [{supportedMethods: "basic-card"}];
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(!issues.contains(&PaymentRequestIssue::ThirdPartyPaymentMethod));
}

#[test]
fn detects_no_input_validation() {
    let body = r#"<script>new PaymentRequest(methods, details).show()</script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(issues.contains(&PaymentRequestIssue::NoInputValidation));
}

#[test]
fn no_validation_issue_with_event_listener() {
    let body = r#"<script>
        const req = new PaymentRequest(methods, details);
        req.addEventListener("paymentmethodchange", handler);
    </script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(!issues.contains(&PaymentRequestIssue::NoInputValidation));
}

#[test]
fn detects_multiple_methods() {
    let body = r#"<script>
        const methods = [
            {supportedMethods: "basic-card"},
            {supportedMethods: "apple-pay"},
            {supportedMethods: "google-pay"},
            {supportedMethods: "samsung-pay"},
        ];
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(issues.contains(&PaymentRequestIssue::MultiplePaymentMethods));
}

#[test]
fn no_multiple_with_one_method() {
    let body = r#"<script>
        const methods = [{supportedMethods: "basic-card"}];
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_request(body, true);
    assert!(!issues.contains(&PaymentRequestIssue::MultiplePaymentMethods));
}

#[test]
fn severity_insecure_highest() {
    assert_eq!(
        payment_request_severity(&PaymentRequestIssue::InsecureContext),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        payment_request_severity(&PaymentRequestIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        PaymentRequestIssue::ApiDetected,
        PaymentRequestIssue::InsecureContext,
    ];
    let mut seq = 0;
    let ops = payment_request_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PaymentRequestIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        PaymentRequestIssue::CanMakePaymentFingerprint.to_string(),
        "can_make_payment_fingerprint"
    );
    assert_eq!(
        PaymentRequestIssue::InsecureContext.to_string(),
        "insecure_context"
    );
    assert_eq!(
        PaymentRequestIssue::ThirdPartyPaymentMethod.to_string(),
        "third_party_payment_method"
    );
    assert_eq!(
        PaymentRequestIssue::NoInputValidation.to_string(),
        "no_input_validation"
    );
    assert_eq!(
        PaymentRequestIssue::MultiplePaymentMethods.to_string(),
        "multiple_payment_methods"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_payment_request("", true).is_empty());
}
