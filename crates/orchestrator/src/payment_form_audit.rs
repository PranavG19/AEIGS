use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentFormIssue {
    PaymentFormOverHttp,
    MissingAutocompleteOnCardField,
    CardDataInHiddenField,
    InlineCardProcessing,
    ExternalPaymentScript { domain: String },
    CardNumberMaxlengthMissing,
    NoPaymentIframe,
}

impl std::fmt::Display for PaymentFormIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaymentFormOverHttp => write!(f, "payment_over_http"),
            Self::MissingAutocompleteOnCardField => write!(f, "missing_cc_autocomplete"),
            Self::CardDataInHiddenField => write!(f, "card_hidden_field"),
            Self::InlineCardProcessing => write!(f, "inline_card_processing"),
            Self::ExternalPaymentScript { domain } => {
                write!(f, "external_payment_script:{domain}")
            }
            Self::CardNumberMaxlengthMissing => write!(f, "card_no_maxlength"),
            Self::NoPaymentIframe => write!(f, "no_payment_iframe"),
        }
    }
}

const CARD_INPUT_PATTERNS: &[&str] = &[
    "name=\"cc",
    "name=\"card",
    "name=\"credit",
    "name=\"cardnumber",
    "name=\"card_number",
    "name=\"cc_number",
    "name=\"ccnumber",
    "name=\"pan",
    "autocomplete=\"cc-number",
    "autocomplete=\"cc-name",
    "autocomplete=\"cc-exp",
    "autocomplete=\"cc-csc",
];

const CVV_PATTERNS: &[&str] = &[
    "name=\"cvv",
    "name=\"cvc",
    "name=\"csc",
    "name=\"security_code",
    "name=\"card_code",
];

const PAYMENT_PROCESSORS: &[&str] = &[
    "js.stripe.com",
    "js.braintreegateway.com",
    "checkout.stripe.com",
    "www.paypal.com",
    "pay.google.com",
    "applepay.cdn-apple.com",
    "js.squareup.com",
    "secure.authorize.net",
];

pub fn audit_payment_forms(target: &str) -> Vec<PaymentFormIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_payment_forms(&body, target.starts_with("https://"))
}

pub fn analyze_payment_forms(body: &str, is_https: bool) -> Vec<PaymentFormIssue> {
    let lower = body.to_ascii_lowercase();
    if !has_payment_indicators(&lower) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if !is_https {
        issues.push(PaymentFormIssue::PaymentFormOverHttp);
    }

    check_card_fields(&lower, &mut issues);
    check_hidden_card_data(&lower, &mut issues);
    check_inline_processing(body, &mut issues);
    check_external_payment_scripts(&lower, &mut issues);
    check_payment_iframe(&lower, &mut issues);

    issues
}

fn has_payment_indicators(lower: &str) -> bool {
    CARD_INPUT_PATTERNS.iter().any(|p| lower.contains(p))
        || CVV_PATTERNS.iter().any(|p| lower.contains(p))
        || lower.contains("type=\"payment")
        || lower.contains("id=\"payment")
        || lower.contains("class=\"payment")
}

fn check_card_fields(lower: &str, issues: &mut Vec<PaymentFormIssue>) {
    let has_card_input = lower.contains("name=\"card") || lower.contains("name=\"cc");
    if !has_card_input {
        return;
    }

    let has_autocomplete = lower.contains("autocomplete=\"cc-number")
        || lower.contains("autocomplete=\"cc-name")
        || lower.contains("autocomplete=\"cc-exp")
        || lower.contains("autocomplete=\"cc-csc");

    if !has_autocomplete {
        issues.push(PaymentFormIssue::MissingAutocompleteOnCardField);
    }

    if (lower.contains("name=\"card_number") || lower.contains("name=\"cardnumber"))
        && !lower.contains("maxlength=")
    {
        issues.push(PaymentFormIssue::CardNumberMaxlengthMissing);
    }
}

fn check_hidden_card_data(lower: &str, issues: &mut Vec<PaymentFormIssue>) {
    if !lower.contains("type=\"hidden") {
        return;
    }
    let card_hidden = CARD_INPUT_PATTERNS
        .iter()
        .chain(CVV_PATTERNS.iter())
        .any(|p| {
            if let Some(idx) = lower.find(*p) {
                let start = idx.saturating_sub(100);
                let ctx = &lower[start..idx];
                ctx.contains("type=\"hidden")
            } else {
                false
            }
        });
    if card_hidden {
        issues.push(PaymentFormIssue::CardDataInHiddenField);
    }
}

fn check_inline_processing(body: &str, issues: &mut Vec<PaymentFormIssue>) {
    let inline_indicators = [
        "XMLHttpRequest",
        "fetch(",
        "$.ajax",
        "axios.post",
    ];
    let card_js_patterns = [
        "cardNumber",
        "card_number",
        "ccNumber",
        "creditCard",
    ];
    let has_inline = inline_indicators.iter().any(|i| body.contains(i));
    let has_card_js = card_js_patterns.iter().any(|p| body.contains(p));
    if has_inline && has_card_js {
        issues.push(PaymentFormIssue::InlineCardProcessing);
    }
}

fn check_external_payment_scripts(lower: &str, issues: &mut Vec<PaymentFormIssue>) {
    for processor in PAYMENT_PROCESSORS {
        if lower.contains(processor) {
            return;
        }
    }
    let has_card = lower.contains("name=\"card") || lower.contains("name=\"cc");
    let has_form = lower.contains("<form");
    if has_card && has_form {
        issues.push(PaymentFormIssue::NoPaymentIframe);
    }
}

fn check_payment_iframe(lower: &str, issues: &mut Vec<PaymentFormIssue>) {
    if !lower.contains("<iframe") {
        return;
    }
    for processor in PAYMENT_PROCESSORS {
        if lower.contains(processor) {
            return;
        }
    }
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<iframe") {
        let abs = pos + idx;
        let tag_end = lower[abs..].find('>').unwrap_or(lower.len() - abs);
        let tag = &lower[abs..abs + tag_end];
        if tag.contains("payment") || tag.contains("checkout") || tag.contains("card") {
            let src_start = tag.find("src=");
            if let Some(si) = src_start {
                let src_rest = &tag[si + 4..];
                let src_val = src_rest.trim_start_matches(['"', '\'']);
                let end = src_val
                    .find(['"', '\'', '>', ' '])
                    .unwrap_or(src_val.len());
                let domain = &src_val[..end];
                if domain.starts_with("http") {
                    issues.push(PaymentFormIssue::ExternalPaymentScript {
                        domain: domain.to_string(),
                    });
                    return;
                }
            }
        }
        pos = abs + tag_end;
    }
}

pub fn payment_form_severity(issue: &PaymentFormIssue) -> f64 {
    match issue {
        PaymentFormIssue::PaymentFormOverHttp => 9.0,
        PaymentFormIssue::CardDataInHiddenField => 8.0,
        PaymentFormIssue::InlineCardProcessing => 7.0,
        PaymentFormIssue::ExternalPaymentScript { .. } => 5.0,
        PaymentFormIssue::NoPaymentIframe => 5.0,
        PaymentFormIssue::MissingAutocompleteOnCardField => 4.0,
        PaymentFormIssue::CardNumberMaxlengthMissing => 3.0,
    }
}

pub fn payment_form_to_operations(
    issues: &[PaymentFormIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                payment_form_severity(issue),
                0.8,
            )
        })
        .collect()
}
