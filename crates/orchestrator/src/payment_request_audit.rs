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
