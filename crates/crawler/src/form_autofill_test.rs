use crate::form_autofill::*;
use crate::types::DiscoveredForm;
use crate::types::FormInput;

fn make_input(name: &str, input_type: &str) -> FormInput {
    FormInput {
        name: name.to_string(),
        input_type: input_type.to_string(),
        value: None,
    }
}

#[test]
fn detect_email_from_type() {
    let input = make_input("user_email", "email");
    assert_eq!(detect_field_type(&input), FieldType::Email);
}

#[test]
fn detect_email_from_name() {
    let input = make_input("email", "text");
    assert_eq!(detect_field_type(&input), FieldType::Email);
}

#[test]
fn detect_phone_from_type() {
    let input = make_input("contact", "tel");
    assert_eq!(detect_field_type(&input), FieldType::Phone);
}

#[test]
fn detect_phone_from_name() {
    let input = make_input("phone_number", "text");
    assert_eq!(detect_field_type(&input), FieldType::Phone);
}

#[test]
fn detect_password() {
    let input = make_input("user_password", "password");
    assert_eq!(detect_field_type(&input), FieldType::Password);
}

#[test]
fn detect_username() {
    let input = make_input("username", "text");
    assert_eq!(detect_field_type(&input), FieldType::Username);
}

#[test]
fn detect_firstname() {
    let input = make_input("first_name", "text");
    assert_eq!(detect_field_type(&input), FieldType::FirstName);
}

#[test]
fn detect_lastname() {
    let input = make_input("last_name", "text");
    assert_eq!(detect_field_type(&input), FieldType::LastName);
}

#[test]
fn detect_fullname() {
    let input = make_input("name", "text");
    assert_eq!(detect_field_type(&input), FieldType::FullName);
}

#[test]
fn detect_address() {
    let input = make_input("street_address", "text");
    assert_eq!(detect_field_type(&input), FieldType::Address);
}

#[test]
fn detect_city() {
    let input = make_input("city", "text");
    assert_eq!(detect_field_type(&input), FieldType::City);
}

#[test]
fn detect_zipcode() {
    let input = make_input("zip_code", "text");
    assert_eq!(detect_field_type(&input), FieldType::ZipCode);
}

#[test]
fn detect_country() {
    let input = make_input("country", "text");
    assert_eq!(detect_field_type(&input), FieldType::Country);
}

#[test]
fn detect_credit_card() {
    let input = make_input("credit_card_number", "text");
    assert_eq!(detect_field_type(&input), FieldType::CreditCard);
}

#[test]
fn detect_cvv() {
    let input = make_input("cvv", "text");
    assert_eq!(detect_field_type(&input), FieldType::Cvv);
}

#[test]
fn detect_file_upload() {
    let input = make_input("document", "file");
    assert_eq!(detect_field_type(&input), FieldType::FileUpload);
}

#[test]
fn detect_hidden_field() {
    let input = make_input("tracking_id", "hidden");
    assert_eq!(detect_field_type(&input), FieldType::Hidden);
}

#[test]
fn detect_csrf_token() {
    let input = make_input("csrf_token", "hidden");
    assert_eq!(detect_field_type(&input), FieldType::CsrfToken);
}

#[test]
fn detect_captcha_field() {
    let input = make_input("g-recaptcha-response", "text");
    assert_eq!(detect_field_type(&input), FieldType::Captcha);
}

#[test]
fn detect_checkbox() {
    let input = make_input("agree_terms", "checkbox");
    assert_eq!(detect_field_type(&input), FieldType::Checkbox);
}

#[test]
fn detect_radio() {
    let input = make_input("gender", "radio");
    assert_eq!(detect_field_type(&input), FieldType::Radio);
}

#[test]
fn detect_url_field() {
    let input = make_input("website", "url");
    assert_eq!(detect_field_type(&input), FieldType::Url);
}

#[test]
fn detect_date_field() {
    let input = make_input("birthday", "date");
    assert_eq!(detect_field_type(&input), FieldType::Date);
}

#[test]
fn detect_search_field() {
    let input = make_input("q", "search");
    assert_eq!(detect_field_type(&input), FieldType::Search);
}

#[test]
fn generate_email_value() {
    let config = AutofillConfig::default();
    let val = generate_fill_value(FieldType::Email, &config);
    assert!(val.contains("@"));
    assert!(val.contains("test.aegis.local"));
}

#[test]
fn generate_phone_value() {
    let config = AutofillConfig::default();
    let val = generate_fill_value(FieldType::Phone, &config);
    assert!(val.starts_with("+1555"));
}

#[test]
fn generate_password_value() {
    let config = AutofillConfig::default();
    let val = generate_fill_value(FieldType::Password, &config);
    assert!(!val.is_empty());
    assert!(val.contains('!') || val.contains('#'));
}

#[test]
fn custom_values_override_defaults() {
    let config = AutofillConfig::default().with_custom_value("email", "custom@example.com");
    assert_eq!(
        config.custom_values.get("email").unwrap(),
        "custom@example.com"
    );
}

#[test]
fn analyze_login_form() {
    let form = DiscoveredForm {
        action: "/login".to_string(),
        method: "POST".to_string(),
        inputs: vec![
            FormInput {
                name: "username".to_string(),
                input_type: "text".to_string(),
                value: None,
            },
            FormInput {
                name: "password".to_string(),
                input_type: "password".to_string(),
                value: None,
            },
            FormInput {
                name: "csrf_token".to_string(),
                input_type: "hidden".to_string(),
                value: Some("abc123".to_string()),
            },
        ],
    };

    let config = AutofillConfig::default();
    let analysis = analyze_form(&form, &config);

    assert_eq!(analysis.action, "/login");
    assert_eq!(analysis.method, "POST");
    assert_eq!(analysis.fields.len(), 3);
    assert!(analysis.has_csrf_token);
    assert_eq!(analysis.csrf_token_name.as_deref(), Some("csrf_token"));
    assert_eq!(analysis.csrf_token_value.as_deref(), Some("abc123"));
    assert!(!analysis.has_captcha);

    let username_field = analysis
        .fields
        .iter()
        .find(|f| f.name == "username")
        .unwrap();
    assert_eq!(username_field.detected_field_type, FieldType::Username);
    assert!(!username_field.fill_value.is_empty());
}

#[test]
fn analyze_registration_form() {
    let form = DiscoveredForm {
        action: "/register".to_string(),
        method: "POST".to_string(),
        inputs: vec![
            FormInput {
                name: "email".to_string(),
                input_type: "email".to_string(),
                value: None,
            },
            FormInput {
                name: "first_name".to_string(),
                input_type: "text".to_string(),
                value: None,
            },
            FormInput {
                name: "last_name".to_string(),
                input_type: "text".to_string(),
                value: None,
            },
            FormInput {
                name: "password".to_string(),
                input_type: "password".to_string(),
                value: None,
            },
            FormInput {
                name: "phone".to_string(),
                input_type: "tel".to_string(),
                value: None,
            },
            FormInput {
                name: "document".to_string(),
                input_type: "file".to_string(),
                value: None,
            },
        ],
    };

    let config = AutofillConfig::default();
    let analysis = analyze_form(&form, &config);

    assert_eq!(analysis.fields.len(), 6);
    assert!(analysis.has_file_upload);
    assert!(!analysis.has_captcha);

    let email_field = analysis.fields.iter().find(|f| f.name == "email").unwrap();
    assert_eq!(email_field.detected_field_type, FieldType::Email);
    assert!(email_field.fill_value.contains("@"));
}

#[test]
fn analyze_form_with_captcha() {
    let form = DiscoveredForm {
        action: "/submit".to_string(),
        method: "POST".to_string(),
        inputs: vec![
            FormInput {
                name: "name".to_string(),
                input_type: "text".to_string(),
                value: None,
            },
            FormInput {
                name: "g-recaptcha-response".to_string(),
                input_type: "text".to_string(),
                value: None,
            },
        ],
    };

    let config = AutofillConfig::default();
    let analysis = analyze_form(&form, &config);
    assert!(analysis.has_captcha);
}

#[test]
fn detect_multi_step_with_wizard_class() {
    let html = r#"
        <div class="wizard-step" data-step="1">Step 1</div>
        <div class="wizard-step" data-step="2">Step 2</div>
        <div class="wizard-step" data-step="3">Step 3</div>
        <button>Next</button>
        <button>Previous</button>
    "#;
    let steps = detect_multi_step_form(html);
    assert_eq!(steps, Some(3));
}

#[test]
fn detect_multi_step_with_next_prev_buttons() {
    let html = r#"
        <form>
            <div class="step-1">Name</div>
            <div class="step-2">Address</div>
            <button type="button">Next</button>
            <button type="button">Previous</button>
        </form>
    "#;
    let steps = detect_multi_step_form(html);
    assert!(steps.is_some());
    assert!(steps.unwrap() >= 2);
}

#[test]
fn no_multi_step_for_simple_form() {
    let html = r#"
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Login</button>
        </form>
    "#;
    assert_eq!(detect_multi_step_form(html), None);
}

#[test]
fn generate_png_test_file() {
    let (name, content_type, bytes) = generate_test_file(Some("image/png"));
    assert_eq!(name, "test.png");
    assert_eq!(content_type, "image/png");
    assert_eq!(&bytes[..4], &[0x89, 0x50, 0x4E, 0x47]);
}

#[test]
fn generate_pdf_test_file() {
    let (name, content_type, bytes) = generate_test_file(Some("application/pdf"));
    assert_eq!(name, "test.pdf");
    assert_eq!(content_type, "application/pdf");
    assert!(String::from_utf8_lossy(&bytes).starts_with("%PDF"));
}

#[test]
fn generate_xml_test_file() {
    let (name, content_type, bytes) = generate_test_file(Some("text/xml"));
    assert_eq!(name, "test.xml");
    assert_eq!(content_type, "text/xml");
    assert!(String::from_utf8_lossy(&bytes).contains("<?xml"));
}

#[test]
fn generate_default_test_file() {
    let (name, content_type, _bytes) = generate_test_file(None);
    assert_eq!(name, "test.txt");
    assert_eq!(content_type, "text/plain");
}

#[test]
fn extract_csrf_from_hidden_input() {
    let html = r#"<input type="hidden" name="csrf_token" value="abc123def456" />"#;
    let tokens = extract_csrf_tokens(html);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "csrf_token");
    assert_eq!(tokens[0].1, "abc123def456");
}

#[test]
fn extract_csrf_from_meta_tag() {
    let html = r#"<meta name="csrf-token" content="meta-token-xyz" />"#;
    let tokens = extract_csrf_tokens(html);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].1, "meta-token-xyz");
}

#[test]
fn extract_django_csrf() {
    let html = r#"<input type="hidden" name="csrfmiddlewaretoken" value="django-csrf-value" />"#;
    let tokens = extract_csrf_tokens(html);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "csrfmiddlewaretoken");
}

#[test]
fn extract_rails_authenticity_token() {
    let html = r#"<input type="hidden" name="authenticity_token" value="rails-auth-token" />"#;
    let tokens = extract_csrf_tokens(html);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "authenticity_token");
}

#[test]
fn no_csrf_in_plain_form() {
    let html = r#"<input type="text" name="username" value="admin" />"#;
    let tokens = extract_csrf_tokens(html);
    assert!(tokens.is_empty());
}

#[test]
fn autofill_config_builder() {
    let config = AutofillConfig::default()
        .with_email_domain("custom.com")
        .with_phone_prefix("+44")
        .with_default_password("Custom!Pass1");
    assert_eq!(config.email_domain, "custom.com");
    assert_eq!(config.phone_prefix, "+44");
    assert_eq!(config.default_password, "Custom!Pass1");
}

#[test]
fn custom_value_overrides_in_analyze() {
    let form = DiscoveredForm {
        action: "/api/submit".to_string(),
        method: "POST".to_string(),
        inputs: vec![FormInput {
            name: "email".to_string(),
            input_type: "email".to_string(),
            value: None,
        }],
    };

    let config = AutofillConfig::default().with_custom_value("email", "override@example.com");
    let analysis = analyze_form(&form, &config);

    assert_eq!(analysis.fields[0].fill_value, "override@example.com");
}

#[test]
fn field_selector_uses_name_attribute() {
    let form = DiscoveredForm {
        action: "/test".to_string(),
        method: "GET".to_string(),
        inputs: vec![FormInput {
            name: "query".to_string(),
            input_type: "text".to_string(),
            value: None,
        }],
    };

    let config = AutofillConfig::default();
    let analysis = analyze_form(&form, &config);
    assert_eq!(analysis.fields[0].selector, "[name=\"query\"]");
}
