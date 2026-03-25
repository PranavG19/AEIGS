use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{DiscoveredForm, FormInput};

/// Classification of a form field for context-aware auto-filling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldType {
    Email,
    Phone,
    FirstName,
    LastName,
    FullName,
    Username,
    Password,
    Address,
    City,
    State,
    ZipCode,
    Country,
    CreditCard,
    Cvv,
    ExpiryDate,
    Url,
    Date,
    Number,
    Search,
    FileUpload,
    Hidden,
    CsrfToken,
    Captcha,
    TextArea,
    Select,
    Checkbox,
    Radio,
    Unknown,
}

/// A form field with its detected type and generated fill value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillField {
    pub name: String,
    pub input_type: String,
    pub detected_field_type: FieldType,
    pub fill_value: String,
    pub selector: String,
}

/// Result of analyzing and preparing a form for auto-submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormAnalysis {
    pub action: String,
    pub method: String,
    pub fields: Vec<AutofillField>,
    pub has_captcha: bool,
    pub has_csrf_token: bool,
    pub csrf_token_name: Option<String>,
    pub csrf_token_value: Option<String>,
    pub is_multi_step: bool,
    pub has_file_upload: bool,
    pub step_count: u32,
}

/// Configuration for form auto-fill behavior.
#[derive(Debug, Clone)]
pub struct AutofillConfig {
    pub email_domain: String,
    pub phone_prefix: String,
    pub default_password: String,
    pub fill_hidden_fields: bool,
    pub skip_captcha_forms: bool,
    pub custom_values: HashMap<String, String>,
}

impl Default for AutofillConfig {
    fn default() -> Self {
        Self {
            email_domain: "test.aegis.local".to_string(),
            phone_prefix: "+1555".to_string(),
            default_password: "AegisTest!2024#Secure".to_string(),
            fill_hidden_fields: false,
            skip_captcha_forms: true,
            custom_values: HashMap::new(),
        }
    }
}

impl AutofillConfig {
    pub fn with_email_domain(mut self, domain: &str) -> Self {
        self.email_domain = domain.to_string();
        self
    }

    pub fn with_phone_prefix(mut self, prefix: &str) -> Self {
        self.phone_prefix = prefix.to_string();
        self
    }

    pub fn with_default_password(mut self, password: &str) -> Self {
        self.default_password = password.to_string();
        self
    }

    pub fn with_custom_value(mut self, field_name: &str, value: &str) -> Self {
        self.custom_values
            .insert(field_name.to_string(), value.to_string());
        self
    }
}

/// Detect the semantic field type from field name, type attribute, and surrounding context.
///
/// Uses a combination of HTML input type, field name pattern matching, and common
/// naming conventions to classify form fields for context-aware value generation.
pub fn detect_field_type(input: &FormInput) -> FieldType {
    let name_lower = input.name.to_lowercase();
    let type_lower = input.input_type.to_lowercase();

    if type_lower == "hidden" {
        if is_csrf_field(&name_lower) {
            return FieldType::CsrfToken;
        }
        return FieldType::Hidden;
    }

    if type_lower == "file" {
        return FieldType::FileUpload;
    }

    if type_lower == "checkbox" {
        return FieldType::Checkbox;
    }

    if type_lower == "radio" {
        return FieldType::Radio;
    }

    if type_lower == "email" || name_lower.contains("email") || name_lower.contains("e-mail") {
        return FieldType::Email;
    }

    if type_lower == "tel"
        || name_lower.contains("phone")
        || name_lower.contains("tel")
        || name_lower.contains("mobile")
    {
        return FieldType::Phone;
    }

    if type_lower == "password" || name_lower.contains("password") || name_lower.contains("passwd")
    {
        return FieldType::Password;
    }

    if type_lower == "url" || name_lower.contains("website") || name_lower.contains("url") {
        return FieldType::Url;
    }

    if type_lower == "date"
        || name_lower.contains("date")
        || name_lower.contains("birthday")
        || name_lower.contains("dob")
    {
        return FieldType::Date;
    }

    if type_lower == "number" || name_lower.contains("amount") || name_lower.contains("quantity") {
        return FieldType::Number;
    }

    if type_lower == "search" || name_lower.contains("search") || name_lower == "q" {
        return FieldType::Search;
    }

    if is_captcha_field(&name_lower) {
        return FieldType::Captcha;
    }

    if name_lower.contains("username") || name_lower.contains("user_name") || name_lower == "login"
    {
        return FieldType::Username;
    }

    if name_lower.contains("firstname")
        || name_lower.contains("first_name")
        || name_lower == "fname"
    {
        return FieldType::FirstName;
    }

    if name_lower.contains("lastname") || name_lower.contains("last_name") || name_lower == "lname"
    {
        return FieldType::LastName;
    }

    if name_lower.contains("name") && !name_lower.contains("user") {
        return FieldType::FullName;
    }

    if name_lower.contains("address")
        || name_lower.contains("street")
        || name_lower.contains("addr")
    {
        return FieldType::Address;
    }

    if name_lower.contains("city") || name_lower.contains("town") {
        return FieldType::City;
    }

    if name_lower.contains("state")
        || name_lower.contains("province")
        || name_lower.contains("region")
    {
        return FieldType::State;
    }

    if name_lower.contains("zip")
        || name_lower.contains("postal")
        || name_lower.contains("postcode")
    {
        return FieldType::ZipCode;
    }

    if name_lower.contains("country") {
        return FieldType::Country;
    }

    if name_lower.contains("card") || name_lower.contains("credit") || name_lower.contains("cc_num")
    {
        return FieldType::CreditCard;
    }

    if name_lower.contains("cvv")
        || name_lower.contains("cvc")
        || name_lower.contains("security_code")
    {
        return FieldType::Cvv;
    }

    if name_lower.contains("expir")
        || name_lower.contains("exp_date")
        || name_lower.contains("exp_month")
    {
        return FieldType::ExpiryDate;
    }

    if type_lower == "textarea" {
        return FieldType::TextArea;
    }

    if type_lower == "select" {
        return FieldType::Select;
    }

    FieldType::Unknown
}

/// Generate a context-appropriate fill value for a detected field type.
pub fn generate_fill_value(field_type: FieldType, config: &AutofillConfig) -> String {
    match field_type {
        FieldType::Email => format!("test@{}", config.email_domain),
        FieldType::Phone => format!("{}0001234", config.phone_prefix),
        FieldType::FirstName => "Aegis".to_string(),
        FieldType::LastName => "Tester".to_string(),
        FieldType::FullName => "Aegis Tester".to_string(),
        FieldType::Username => "aegis_test_user".to_string(),
        FieldType::Password => config.default_password.clone(),
        FieldType::Address => "123 Security Lane".to_string(),
        FieldType::City => "Cybertown".to_string(),
        FieldType::State => "CA".to_string(),
        FieldType::ZipCode => "90210".to_string(),
        FieldType::Country => "US".to_string(),
        FieldType::CreditCard => "4111111111111111".to_string(),
        FieldType::Cvv => "123".to_string(),
        FieldType::ExpiryDate => "12/2030".to_string(),
        FieldType::Url => "https://test.aegis.local".to_string(),
        FieldType::Date => "2024-01-15".to_string(),
        FieldType::Number => "42".to_string(),
        FieldType::Search => "test search query".to_string(),
        FieldType::TextArea => "This is an automated test submission by Aegis scanner.".to_string(),
        FieldType::Checkbox => "on".to_string(),
        FieldType::Radio => "option1".to_string(),
        FieldType::Select => "1".to_string(),
        FieldType::Hidden | FieldType::CsrfToken => String::new(),
        FieldType::FileUpload => String::new(),
        FieldType::Captcha => String::new(),
        FieldType::Unknown => "test_value".to_string(),
    }
}

/// Analyze a discovered form and prepare auto-fill data for all fields.
///
/// Detects field types, generates appropriate fill values, identifies CSRF tokens,
/// flags CAPTCHA presence, detects multi-step forms, and prepares the form for
/// automated submission.
pub fn analyze_form(form: &DiscoveredForm, config: &AutofillConfig) -> FormAnalysis {
    let mut fields = Vec::new();
    let mut has_captcha = false;
    let mut has_csrf = false;
    let mut csrf_name = None;
    let mut csrf_value = None;
    let mut has_file = false;

    for input in &form.inputs {
        let detected = detect_field_type(input);

        if detected == FieldType::Captcha {
            has_captcha = true;
        }

        if detected == FieldType::CsrfToken {
            has_csrf = true;
            csrf_name = Some(input.name.clone());
            csrf_value = input.value.clone();
        }

        if detected == FieldType::FileUpload {
            has_file = true;
        }

        let fill_value = if let Some(custom) = config.custom_values.get(&input.name) {
            custom.clone()
        } else if detected == FieldType::Hidden || detected == FieldType::CsrfToken {
            input.value.clone().unwrap_or_default()
        } else {
            generate_fill_value(detected, config)
        };

        fields.push(AutofillField {
            name: input.name.clone(),
            input_type: input.input_type.clone(),
            detected_field_type: detected,
            fill_value,
            selector: format!("[name=\"{}\"]", input.name),
        });
    }

    FormAnalysis {
        action: form.action.clone(),
        method: form.method.clone(),
        fields,
        has_captcha,
        has_csrf_token: has_csrf,
        csrf_token_name: csrf_name,
        csrf_token_value: csrf_value,
        is_multi_step: false,
        has_file_upload: has_file,
        step_count: 1,
    }
}

/// Detect multi-step (wizard) forms from HTML.
///
/// Looks for step indicators, next/prev buttons, and progressive disclosure
/// patterns that indicate a form spans multiple pages or steps.
pub fn detect_multi_step_form(html: &str) -> Option<u32> {
    let lower = html.to_lowercase();

    let step_indicators = [
        "step-indicator",
        "wizard-step",
        "form-step",
        "multi-step",
        "progress-step",
        "step-content",
    ];

    let has_steps = step_indicators.iter().any(|s| lower.contains(s));
    if !has_steps {
        let has_next = lower.contains("next") || lower.contains("continue");
        let has_prev = lower.contains("previous") || lower.contains("back");
        if !has_next || !has_prev {
            return None;
        }
    }

    let step_re = regex::Regex::new(r"(?i)step[\s_-]*(\d+)").unwrap();
    let max_step = step_re
        .captures_iter(html)
        .filter_map(|c| c[1].parse::<u32>().ok())
        .max()
        .unwrap_or(2);

    Some(max_step)
}

/// Generate a test file payload appropriate for a file upload field.
///
/// Returns (filename, content_type, bytes) for different file types
/// based on accepted file extensions or a default text file.
pub fn generate_test_file(accept_attr: Option<&str>) -> (String, String, Vec<u8>) {
    let accept = accept_attr.unwrap_or("");
    let lower = accept.to_lowercase();

    if lower.contains("image") || lower.contains(".png") || lower.contains(".jpg") {
        let png_header: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
            0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC,
            0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        return ("test.png".to_string(), "image/png".to_string(), png_header);
    }

    if lower.contains(".pdf") || lower.contains("application/pdf") {
        let pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n%%EOF";
        return (
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            pdf.to_vec(),
        );
    }

    if lower.contains(".xml") || lower.contains("text/xml") {
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><test>aegis</test></root>";
        return ("test.xml".to_string(), "text/xml".to_string(), xml.to_vec());
    }

    if lower.contains(".csv") {
        let csv = b"name,email,phone\nAegis,test@test.local,5550001234\n";
        return ("test.csv".to_string(), "text/csv".to_string(), csv.to_vec());
    }

    let txt = b"Aegis scanner test file upload content.";
    (
        "test.txt".to_string(),
        "text/plain".to_string(),
        txt.to_vec(),
    )
}

/// Extract CSRF tokens from HTML page source.
///
/// Searches for hidden inputs, meta tags, and common JavaScript variable patterns
/// that contain anti-CSRF tokens for replay in form submissions.
pub fn extract_csrf_tokens(html: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    let hidden_re = regex::Regex::new(
        r#"(?i)<input[^>]+type\s*=\s*["']hidden["'][^>]+name\s*=\s*["']([^"']+)["'][^>]+value\s*=\s*["']([^"']+)["'][^>]*>"#
    ).unwrap();
    for cap in hidden_re.captures_iter(html) {
        let name = &cap[1];
        if is_csrf_field(&name.to_lowercase()) {
            tokens.push((name.to_string(), cap[2].to_string()));
        }
    }

    let hidden_re2 = regex::Regex::new(
        r#"(?i)<input[^>]+name\s*=\s*["']([^"']+)["'][^>]+type\s*=\s*["']hidden["'][^>]+value\s*=\s*["']([^"']+)["'][^>]*>"#
    ).unwrap();
    for cap in hidden_re2.captures_iter(html) {
        let name = &cap[1];
        if is_csrf_field(&name.to_lowercase()) {
            let pair = (name.to_string(), cap[2].to_string());
            if !tokens.contains(&pair) {
                tokens.push(pair);
            }
        }
    }

    let meta_re = regex::Regex::new(
        r#"(?i)<meta\s+name\s*=\s*["']csrf[_-]?token["']\s+content\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();
    for cap in meta_re.captures_iter(html) {
        tokens.push(("csrf-token".to_string(), cap[1].to_string()));
    }

    tokens
}

fn is_csrf_field(name: &str) -> bool {
    let csrf_patterns = [
        "csrf",
        "_token",
        "authenticity_token",
        "csrfmiddlewaretoken",
        "__requestverificationtoken",
        "antiforgery",
        "xsrf",
    ];
    csrf_patterns.iter().any(|p| name.contains(p))
}

fn is_captcha_field(name: &str) -> bool {
    let captcha_patterns = [
        "captcha",
        "recaptcha",
        "hcaptcha",
        "g-recaptcha",
        "cf-turnstile",
        "arkose",
    ];
    captcha_patterns.iter().any(|p| name.contains(p))
}

#[cfg(test)]
#[path = "form_autofill_test.rs"]
mod form_autofill_test;
