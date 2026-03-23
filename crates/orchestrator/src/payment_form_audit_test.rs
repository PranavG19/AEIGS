use crate::payment_form_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_payment_forms("", true);
    assert!(issues.is_empty());
}

#[test]
fn no_payment_indicators() {
    let body = "<html><body><form><input type='text'></form></body></html>";
    let issues = analyze_payment_forms(body, true);
    assert!(issues.is_empty());
}

#[test]
fn detects_payment_over_http() {
    let body = r#"<form><input name="card_number" type="text"></form>"#;
    let issues = analyze_payment_forms(body, false);
    assert!(issues.contains(&PaymentFormIssue::PaymentFormOverHttp));
}

#[test]
fn https_no_http_issue() {
    let body = r#"<form><input name="card_number" type="text"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(!issues.contains(&PaymentFormIssue::PaymentFormOverHttp));
}

#[test]
fn detects_missing_autocomplete() {
    let body = r#"<form><input name="card_number" type="text"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(issues.contains(&PaymentFormIssue::MissingAutocompleteOnCardField));
}

#[test]
fn autocomplete_present_no_issue() {
    let body = r#"<form><input name="card_number" autocomplete="cc-number" type="text"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(!issues.contains(&PaymentFormIssue::MissingAutocompleteOnCardField));
}

#[test]
fn detects_card_number_no_maxlength() {
    let body = r#"<form><input name="card_number" type="text"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(issues.contains(&PaymentFormIssue::CardNumberMaxlengthMissing));
}

#[test]
fn maxlength_present_no_issue() {
    let body = r#"<form><input name="card_number" type="text" maxlength="19"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(!issues.contains(&PaymentFormIssue::CardNumberMaxlengthMissing));
}

#[test]
fn detects_hidden_card_field() {
    let body = r#"<form><input type="hidden" name="cc_number" value=""></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(issues.contains(&PaymentFormIssue::CardDataInHiddenField));
}

#[test]
fn detects_hidden_cvv_field() {
    let body = r#"<form><input type="hidden" name="cvv" value="123"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(issues.contains(&PaymentFormIssue::CardDataInHiddenField));
}

#[test]
fn detects_inline_card_processing() {
    let body = r#"
        <form><input name="cc_number" type="text"></form>
        <script>
            var cardNumber = document.getElementById('cc');
            fetch('/api/charge', { body: JSON.stringify({cardNumber}) });
        </script>
    "#;
    let issues = analyze_payment_forms(body, true);
    assert!(issues.contains(&PaymentFormIssue::InlineCardProcessing));
}

#[test]
fn no_inline_processing_without_card_js() {
    let body = r#"
        <form><input name="cc_number" type="text"></form>
        <script>fetch('/api/data');</script>
    "#;
    let issues = analyze_payment_forms(body, true);
    assert!(!issues.contains(&PaymentFormIssue::InlineCardProcessing));
}

#[test]
fn no_payment_iframe_when_no_processor() {
    let body = r#"<form><input name="card_number" type="text"></form>"#;
    let issues = analyze_payment_forms(body, true);
    assert!(issues.contains(&PaymentFormIssue::NoPaymentIframe));
}

#[test]
fn stripe_present_no_missing_iframe() {
    let body = r#"
        <form><input name="card_number" type="text"></form>
        <script src="https://js.stripe.com/v3/"></script>
    "#;
    let issues = analyze_payment_forms(body, true);
    assert!(!issues.contains(&PaymentFormIssue::NoPaymentIframe));
}

#[test]
fn severity_http_highest() {
    assert_eq!(
        payment_form_severity(&PaymentFormIssue::PaymentFormOverHttp),
        9.0
    );
}

#[test]
fn severity_hidden_card_high() {
    assert_eq!(
        payment_form_severity(&PaymentFormIssue::CardDataInHiddenField),
        8.0
    );
}

#[test]
fn severity_maxlength_low() {
    assert_eq!(
        payment_form_severity(&PaymentFormIssue::CardNumberMaxlengthMissing),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        PaymentFormIssue::PaymentFormOverHttp,
        PaymentFormIssue::CardDataInHiddenField,
    ];
    let mut seq = 0;
    let ops = payment_form_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        PaymentFormIssue::PaymentFormOverHttp.to_string(),
        "payment_over_http"
    );
    assert_eq!(
        PaymentFormIssue::MissingAutocompleteOnCardField.to_string(),
        "missing_cc_autocomplete"
    );
    assert_eq!(
        PaymentFormIssue::CardDataInHiddenField.to_string(),
        "card_hidden_field"
    );
    assert_eq!(
        PaymentFormIssue::InlineCardProcessing.to_string(),
        "inline_card_processing"
    );
    assert_eq!(
        PaymentFormIssue::CardNumberMaxlengthMissing.to_string(),
        "card_no_maxlength"
    );
    assert_eq!(
        PaymentFormIssue::NoPaymentIframe.to_string(),
        "no_payment_iframe"
    );
}

#[test]
fn external_payment_script_display() {
    let issue = PaymentFormIssue::ExternalPaymentScript {
        domain: "https://evil.com/pay".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "external_payment_script:https://evil.com/pay"
    );
}
