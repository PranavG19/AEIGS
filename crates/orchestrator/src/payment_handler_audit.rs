use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentHandlerIssue {
    ApiDetected,
    CustomHandler,
    DataInterception,
    InstrumentEnumeration,
    NoOriginValidation,
}

impl std::fmt::Display for PaymentHandlerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CustomHandler => write!(f, "custom_handler"),
            Self::DataInterception => write!(f, "data_interception"),
            Self::InstrumentEnumeration => write!(f, "instrument_enumeration"),
            Self::NoOriginValidation => write!(f, "no_origin_validation"),
        }
    }
}

pub fn audit_payment_handler(target: &str) -> Vec<PaymentHandlerIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_payment_handler(&body)
}

pub fn analyze_payment_handler(body: &str) -> Vec<PaymentHandlerIssue> {
    if !body.contains("PaymentHandler")
        && !body.contains("paymentManager")
        && !body.contains("PaymentInstruments")
        && !body.contains("PaymentRequestEvent")
        && !body.contains("paymentrequest")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(PaymentHandlerIssue::ApiDetected);

    if body.contains("paymentManager") || body.contains("PaymentHandler") {
        issues.push(PaymentHandlerIssue::CustomHandler);
    }

    if (body.contains("paymentrequest") || body.contains("PaymentRequestEvent"))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(PaymentHandlerIssue::DataInterception);
    }

    if body.contains("instruments") && (body.contains("getAll") || body.contains("keys(")) {
        issues.push(PaymentHandlerIssue::InstrumentEnumeration);
    }

    if (body.contains("PaymentRequestEvent") || body.contains("paymentManager"))
        && !body.contains("origin")
        && !body.contains("topOrigin")
    {
        issues.push(PaymentHandlerIssue::NoOriginValidation);
    }

    issues
}

pub fn payment_handler_severity(issue: &PaymentHandlerIssue) -> f64 {
    match issue {
        PaymentHandlerIssue::DataInterception => 8.0,
        PaymentHandlerIssue::NoOriginValidation => 7.0,
        PaymentHandlerIssue::InstrumentEnumeration => 6.0,
        PaymentHandlerIssue::CustomHandler => 5.0,
        PaymentHandlerIssue::ApiDetected => 3.0,
    }
}

pub fn payment_handler_to_operations(
    issues: &[PaymentHandlerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                payment_handler_severity(issue),
                0.6,
            )
        })
        .collect()
}
