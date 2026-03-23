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

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentHandlerSecurityIssue {
    PaymentDataExfiltration,
    InsecurePaymentEndpoint,
    PaymentWithoutCSP,
    CardDataInLocalStorage,
    PaymentInIframe,
    PaymentWithoutIntegrity,
    PaymentFormAutoComplete,
    PaymentWithoutSSL,
    PaymentRedirectOpen,
    PaymentDataInUrl,
}

impl std::fmt::Display for PaymentHandlerSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaymentDataExfiltration => write!(f, "payment_data_exfiltration"),
            Self::InsecurePaymentEndpoint => write!(f, "insecure_payment_endpoint"),
            Self::PaymentWithoutCSP => write!(f, "payment_without_csp"),
            Self::CardDataInLocalStorage => write!(f, "card_data_in_localstorage"),
            Self::PaymentInIframe => write!(f, "payment_in_iframe"),
            Self::PaymentWithoutIntegrity => write!(f, "payment_without_integrity"),
            Self::PaymentFormAutoComplete => write!(f, "payment_form_autocomplete"),
            Self::PaymentWithoutSSL => write!(f, "payment_without_ssl"),
            Self::PaymentRedirectOpen => write!(f, "payment_redirect_open"),
            Self::PaymentDataInUrl => write!(f, "payment_data_in_url"),
        }
    }
}

pub fn analyze_payment_handler_security(body: &str) -> Vec<PaymentHandlerSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    // Check for payment data exfiltration to third-party
    if (lower.contains("payment") || lower.contains("card") || lower.contains("cvv"))
        && (lower.contains("analytics") || lower.contains("tracker") || lower.contains("beacon"))
        && (lower.contains("fetch(")
            || lower.contains("xmlhttprequest")
            || lower.contains("sendbeacon"))
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentDataExfiltration);
    }

    // Check for insecure HTTP payment endpoint
    if (lower.contains("payment") || lower.contains("checkout"))
        && (lower.contains("http://") && !lower.contains("https://"))
        && (lower.contains("action=") || lower.contains("fetch(") || lower.contains("ajax"))
    {
        issues.push(PaymentHandlerSecurityIssue::InsecurePaymentEndpoint);
    }

    // Check for payment page without CSP
    if (lower.contains("payment") || lower.contains("checkout") || lower.contains("billing"))
        && !lower.contains("content-security-policy")
        && !lower.contains("csp")
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentWithoutCSP);
    }

    // Check for card data in localStorage
    if (lower.contains("localstorage") || lower.contains("sessionstorage"))
        && (lower.contains("card")
            || lower.contains("cvv")
            || lower.contains("cardnumber")
            || lower.contains("ccv"))
    {
        issues.push(PaymentHandlerSecurityIssue::CardDataInLocalStorage);
    }

    // Check for payment form in iframe
    if lower.contains("<iframe")
        && (lower.contains("payment") || lower.contains("checkout") || lower.contains("billing"))
        && !lower.contains("sandbox")
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentInIframe);
    }

    // Check for payment scripts without SRI
    if lower.contains("<script")
        && (lower.contains("payment")
            || lower.contains("stripe")
            || lower.contains("paypal")
            || lower.contains("square"))
        && !lower.contains("integrity=")
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentWithoutIntegrity);
    }

    // Check for autocomplete on card fields
    if (lower.contains("type=\"text\"")
        || lower.contains("type='text'")
        || lower.contains("<input"))
        && (lower.contains("card") || lower.contains("cvv") || lower.contains("ccv"))
        && !lower.contains("autocomplete=\"off\"")
        && !lower.contains("autocomplete='off'")
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentFormAutoComplete);
    }

    // Check for payment cookies without secure attribute
    if (lower.contains("setcookie")
        || lower.contains("set-cookie")
        || lower.contains("document.cookie"))
        && (lower.contains("payment") || lower.contains("session") || lower.contains("token"))
        && !lower.contains("secure")
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentWithoutSSL);
    }

    // Check for open redirect after payment
    if (lower.contains("payment") || lower.contains("checkout"))
        && (lower.contains("redirect") || lower.contains("location"))
        && (lower.contains("?url=")
            || lower.contains("?redirect=")
            || lower.contains("?return=")
            || lower.contains(".get('url')")
            || lower.contains(".get('redirect')")
            || lower.contains(".get('return')"))
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentRedirectOpen);
    }

    // Check for payment data in URL
    if lower.contains("?")
        && (lower.contains("card=")
            || lower.contains("cvv=")
            || (lower.contains("amount=") && lower.contains("payment")))
    {
        issues.push(PaymentHandlerSecurityIssue::PaymentDataInUrl);
    }

    issues
}

pub fn payment_handler_security_severity(issue: &PaymentHandlerSecurityIssue) -> f64 {
    match issue {
        PaymentHandlerSecurityIssue::CardDataInLocalStorage => 9.5,
        PaymentHandlerSecurityIssue::PaymentDataExfiltration => 9.0,
        PaymentHandlerSecurityIssue::InsecurePaymentEndpoint => 8.5,
        PaymentHandlerSecurityIssue::PaymentDataInUrl => 8.0,
        PaymentHandlerSecurityIssue::PaymentWithoutSSL => 7.5,
        PaymentHandlerSecurityIssue::PaymentRedirectOpen => 7.0,
        PaymentHandlerSecurityIssue::PaymentFormAutoComplete => 6.5,
        PaymentHandlerSecurityIssue::PaymentWithoutIntegrity => 6.0,
        PaymentHandlerSecurityIssue::PaymentInIframe => 5.5,
        PaymentHandlerSecurityIssue::PaymentWithoutCSP => 5.0,
    }
}

pub fn payment_handler_security_to_operations(
    issues: &[PaymentHandlerSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                payment_handler_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
