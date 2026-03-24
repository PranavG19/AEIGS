use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentRequestIssue {
    ApiDetected,
    CanMakePaymentFingerprint,
    InsecureContext,
    ThirdPartyPaymentMethod,
    NoInputValidation,
    MultiplePaymentMethods,
}

impl std::fmt::Display for PaymentRequestIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CanMakePaymentFingerprint => write!(f, "can_make_payment_fingerprint"),
            Self::InsecureContext => write!(f, "insecure_context"),
            Self::ThirdPartyPaymentMethod => write!(f, "third_party_payment_method"),
            Self::NoInputValidation => write!(f, "no_input_validation"),
            Self::MultiplePaymentMethods => write!(f, "multiple_payment_methods"),
        }
    }
}

pub fn audit_payment_request(target: &str) -> Vec<PaymentRequestIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let is_https = target.starts_with("https://");
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_payment_request(&body, is_https)
}

pub fn analyze_payment_request(body: &str, is_https: bool) -> Vec<PaymentRequestIssue> {
    if !body.contains("PaymentRequest") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(PaymentRequestIssue::ApiDetected);

    if !is_https {
        issues.push(PaymentRequestIssue::InsecureContext);
    }

    if body.contains("canMakePayment") {
        issues.push(PaymentRequestIssue::CanMakePaymentFingerprint);
    }

    if body.contains("https://") && has_third_party_method(body) {
        issues.push(PaymentRequestIssue::ThirdPartyPaymentMethod);
    }

    if !body.contains("addEventListener") && !body.contains("onpaymentmethodchange") {
        issues.push(PaymentRequestIssue::NoInputValidation);
    }

    let method_count = count_payment_methods(body);
    if method_count > 3 {
        issues.push(PaymentRequestIssue::MultiplePaymentMethods);
    }

    issues
}

fn has_third_party_method(body: &str) -> bool {
    let markers = [
        "https://apple.com/apple-pay",
        "https://google.com/pay",
        "https://play.google.com/billing",
    ];
    markers.iter().any(|m| body.contains(m))
}

fn count_payment_methods(body: &str) -> usize {
    let known = [
        "basic-card",
        "apple-pay",
        "google-pay",
        "samsung-pay",
        "secure-payment-confirmation",
    ];
    known.iter().filter(|m| body.contains(**m)).count()
}

pub fn payment_request_severity(issue: &PaymentRequestIssue) -> f64 {
    match issue {
        PaymentRequestIssue::InsecureContext => 7.0,
        PaymentRequestIssue::ThirdPartyPaymentMethod => 5.5,
        PaymentRequestIssue::CanMakePaymentFingerprint => 5.0,
        PaymentRequestIssue::NoInputValidation => 4.5,
        PaymentRequestIssue::MultiplePaymentMethods => 4.0,
        PaymentRequestIssue::ApiDetected => 3.0,
    }
}

pub fn payment_request_to_operations(
    issues: &[PaymentRequestIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                payment_request_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentRequestSecurityIssue {
    PaymentDataExfiltration,
    PaymentWithoutHttps,
    PaymentPhishing,
    PaymentCrossOrigin,
    PaymentPersistence,
    PaymentWithoutValidation,
    PaymentInIframe,
    ExcessivePaymentData,
    PaymentMethodEnumeration,
    PaymentTokenExposure,
}

impl std::fmt::Display for PaymentRequestSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaymentDataExfiltration => write!(f, "payment_data_exfiltration"),
            Self::PaymentWithoutHttps => write!(f, "payment_without_https"),
            Self::PaymentPhishing => write!(f, "payment_phishing"),
            Self::PaymentCrossOrigin => write!(f, "payment_cross_origin"),
            Self::PaymentPersistence => write!(f, "payment_persistence"),
            Self::PaymentWithoutValidation => write!(f, "payment_without_validation"),
            Self::PaymentInIframe => write!(f, "payment_in_iframe"),
            Self::ExcessivePaymentData => write!(f, "excessive_payment_data"),
            Self::PaymentMethodEnumeration => write!(f, "payment_method_enumeration"),
            Self::PaymentTokenExposure => write!(f, "payment_token_exposure"),
        }
    }
}

pub fn analyze_payment_security(body: &str, is_https: bool) -> Vec<PaymentRequestSecurityIssue> {
    if !body.contains("PaymentRequest") && !body.contains("PaymentResponse") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_payment_exfiltration(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentDataExfiltration);
    }

    if !is_https && body.contains("PaymentRequest") {
        issues.push(PaymentRequestSecurityIssue::PaymentWithoutHttps);
    }

    if has_payment_phishing(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentPhishing);
    }

    if has_payment_cross_origin(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentCrossOrigin);
    }

    if has_payment_persistence(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentPersistence);
    }

    if has_payment_without_validation(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentWithoutValidation);
    }

    if has_payment_in_iframe(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentInIframe);
    }

    if has_excessive_payment_data(body) {
        issues.push(PaymentRequestSecurityIssue::ExcessivePaymentData);
    }

    if has_payment_method_enumeration(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentMethodEnumeration);
    }

    if has_payment_token_exposure(body) {
        issues.push(PaymentRequestSecurityIssue::PaymentTokenExposure);
    }

    issues
}

fn has_payment_exfiltration(body: &str) -> bool {
    (body.contains("PaymentResponse") || body.contains("response.details"))
        && (body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains("navigator.sendBeacon"))
}

fn has_payment_phishing(body: &str) -> bool {
    body.contains("PaymentRequest")
        && (body.contains("displayName:") || body.contains("displayName ="))
        && (body.contains("urgent") || body.contains("verify") || body.contains("suspended"))
}

fn has_payment_cross_origin(body: &str) -> bool {
    (body.contains("PaymentResponse") || body.contains("response.details"))
        && body.contains("postMessage")
}

fn has_payment_persistence(body: &str) -> bool {
    (body.contains("PaymentResponse") || body.contains("response.details"))
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB"))
}

fn has_payment_without_validation(body: &str) -> bool {
    body.contains(".show()")
        && body.contains("then(response")
        && !body.contains("response.details")
        && !body.contains("response.requestId")
}

fn has_payment_in_iframe(body: &str) -> bool {
    body.contains("PaymentRequest")
        && (body.contains("window.parent")
            || body.contains("window.top")
            || body.contains("!== window.self"))
}

fn has_excessive_payment_data(body: &str) -> bool {
    body.contains("PaymentRequest")
        && body.contains("requestShipping")
        && (body.contains("requestPayerName")
            || body.contains("requestPayerEmail")
            || body.contains("requestPayerPhone"))
}

fn has_payment_method_enumeration(body: &str) -> bool {
    let count = body.matches("canMakePayment").count();
    count >= 3
}

fn has_payment_token_exposure(body: &str) -> bool {
    (body.contains("paymentToken") || body.contains("nonce") || body.contains("transactionId"))
        && (body.contains("console.log")
            || body.contains("localStorage")
            || body.contains("sessionStorage"))
}

pub fn payment_security_severity(issue: &PaymentRequestSecurityIssue) -> f64 {
    match issue {
        PaymentRequestSecurityIssue::PaymentDataExfiltration => 9.0,
        PaymentRequestSecurityIssue::PaymentTokenExposure => 8.5,
        PaymentRequestSecurityIssue::PaymentPhishing => 8.0,
        PaymentRequestSecurityIssue::PaymentPersistence => 7.5,
        PaymentRequestSecurityIssue::PaymentWithoutHttps => 7.0,
        PaymentRequestSecurityIssue::PaymentCrossOrigin => 6.5,
        PaymentRequestSecurityIssue::PaymentInIframe => 6.0,
        PaymentRequestSecurityIssue::PaymentWithoutValidation => 5.5,
        PaymentRequestSecurityIssue::ExcessivePaymentData => 4.5,
        PaymentRequestSecurityIssue::PaymentMethodEnumeration => 3.0,
    }
}

pub fn payment_security_to_operations(
    issues: &[PaymentRequestSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                payment_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
