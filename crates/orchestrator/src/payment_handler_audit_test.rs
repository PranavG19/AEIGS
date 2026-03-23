use crate::payment_handler_audit::*;

#[test]
fn no_payment_handler_no_issues() {
    assert!(analyze_payment_handler("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_payment_handler() {
    let body = r#"<script>if (window.PaymentHandler) {}</script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::ApiDetected));
}

#[test]
fn detects_api_payment_manager() {
    let body = r#"<script>const pm = reg.paymentManager;</script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::ApiDetected));
}

#[test]
fn detects_custom_handler() {
    let body = r#"<script>const pm = reg.paymentManager;</script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::CustomHandler));
}

#[test]
fn detects_data_interception() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            fetch("/log", {body: JSON.stringify(e.methodData)});
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::DataInterception));
}

#[test]
fn no_interception_without_fetch() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            e.respondWith(new PaymentResponse());
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(!issues.contains(&PaymentHandlerIssue::DataInterception));
}

#[test]
fn detects_instrument_enumeration() {
    let body = r#"<script>
        const pm = reg.paymentManager;
        const all = await pm.instruments.getAll();
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::InstrumentEnumeration));
}

#[test]
fn no_enumeration_without_getall() {
    let body = r#"<script>
        const pm = reg.paymentManager;
        await pm.instruments.set("card", {name: "Visa"});
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(!issues.contains(&PaymentHandlerIssue::InstrumentEnumeration));
}

#[test]
fn detects_no_origin_validation() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            const pm = reg.paymentManager;
            e.respondWith(handlePayment(e));
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::NoOriginValidation));
}

#[test]
fn no_origin_issue_with_check() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            const pm = reg.paymentManager;
            if (e.topOrigin === "https://shop.example") { }
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(!issues.contains(&PaymentHandlerIssue::NoOriginValidation));
}

#[test]
fn severity_interception_highest() {
    assert_eq!(payment_handler_severity(&PaymentHandlerIssue::DataInterception), 8.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(payment_handler_severity(&PaymentHandlerIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![PaymentHandlerIssue::ApiDetected, PaymentHandlerIssue::CustomHandler];
    let mut seq = 0;
    let ops = payment_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PaymentHandlerIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(PaymentHandlerIssue::CustomHandler.to_string(), "custom_handler");
    assert_eq!(PaymentHandlerIssue::DataInterception.to_string(), "data_interception");
    assert_eq!(PaymentHandlerIssue::InstrumentEnumeration.to_string(), "instrument_enumeration");
    assert_eq!(PaymentHandlerIssue::NoOriginValidation.to_string(), "no_origin_validation");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_payment_handler("").is_empty());
}
