use std::fmt;

use once_cell::sync::Lazy;
use regex::Regex;

/// Category of sensitive data detected in an HTTP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveDataCategory {
    Pii,
    Financial,
    Medical,
    Authentication,
    InternalInfrastructure,
    ApiKeyOrSecret,
    Geolocation,
    PersonalContact,
}

impl fmt::Display for SensitiveDataCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pii => write!(f, "Personally Identifiable Information"),
            Self::Financial => write!(f, "Financial Data"),
            Self::Medical => write!(f, "Medical Data"),
            Self::Authentication => write!(f, "Authentication Data"),
            Self::InternalInfrastructure => write!(f, "Internal Infrastructure"),
            Self::ApiKeyOrSecret => write!(f, "API Key or Secret"),
            Self::Geolocation => write!(f, "Geolocation Data"),
            Self::PersonalContact => write!(f, "Personal Contact Information"),
        }
    }
}

/// Specific type of sensitive data within a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveDataKind {
    Ssn,
    CreditCard,
    PhoneNumber,
    EmailAddress,
    BankAccountNumber,
    RoutingNumber,
    Iban,
    Icd10Code,
    PrescriptionPattern,
    PasswordInUrl,
    TokenInError,
    SessionIdInLog,
    PrivateIpAddress,
    Hostname,
    FilePath,
    StackTrace,
    AwsAccessKey,
    AwsSecretKey,
    GenericApiKey,
    DatabaseConnectionString,
    GpsCoordinates,
    StreetAddress,
}

impl fmt::Display for SensitiveDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssn => write!(f, "Social Security Number"),
            Self::CreditCard => write!(f, "Credit Card Number"),
            Self::PhoneNumber => write!(f, "Phone Number"),
            Self::EmailAddress => write!(f, "Email Address"),
            Self::BankAccountNumber => write!(f, "Bank Account Number"),
            Self::RoutingNumber => write!(f, "Routing Number"),
            Self::Iban => write!(f, "IBAN"),
            Self::Icd10Code => write!(f, "ICD-10 Diagnosis Code"),
            Self::PrescriptionPattern => write!(f, "Prescription Information"),
            Self::PasswordInUrl => write!(f, "Password in URL"),
            Self::TokenInError => write!(f, "Token in Error Message"),
            Self::SessionIdInLog => write!(f, "Session ID in Log"),
            Self::PrivateIpAddress => write!(f, "Private IP Address"),
            Self::Hostname => write!(f, "Internal Hostname"),
            Self::FilePath => write!(f, "File Path"),
            Self::StackTrace => write!(f, "Stack Trace"),
            Self::AwsAccessKey => write!(f, "AWS Access Key"),
            Self::AwsSecretKey => write!(f, "AWS Secret Key"),
            Self::GenericApiKey => write!(f, "Generic API Key"),
            Self::DatabaseConnectionString => write!(f, "Database Connection String"),
            Self::GpsCoordinates => write!(f, "GPS Coordinates"),
            Self::StreetAddress => write!(f, "Street Address"),
        }
    }
}

/// Regulatory framework reference for a sensitive data finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegulatoryMapping {
    pub gdpr: Option<String>,
    pub pci_dss: Option<String>,
    pub hipaa: Option<String>,
}

/// A single sensitive data finding within an HTTP response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveDataFinding {
    pub category: SensitiveDataCategory,
    pub kind: SensitiveDataKind,
    pub matched_text: String,
    pub offset: usize,
    pub regulatory: RegulatoryMapping,
}

/// Scans an HTTP response body for sensitive data exposure.
///
/// Returns all findings with category, kind, matched text, byte offset,
/// and regulatory mapping. Applies false-positive filters to exclude
/// test data, documentation examples, and placeholder values.
pub fn detect_sensitive_data(response_body: &str) -> Vec<SensitiveDataFinding> {
    let mut findings = Vec::new();

    if is_likely_test_or_doc_content(response_body) {
        return findings;
    }

    detect_ssn(response_body, &mut findings);
    detect_credit_card(response_body, &mut findings);
    detect_phone_number(response_body, &mut findings);
    detect_email(response_body, &mut findings);
    detect_bank_account(response_body, &mut findings);
    detect_routing_number(response_body, &mut findings);
    detect_iban(response_body, &mut findings);
    detect_icd10(response_body, &mut findings);
    detect_prescription(response_body, &mut findings);
    detect_password_in_url(response_body, &mut findings);
    detect_token_in_error(response_body, &mut findings);
    detect_session_id_in_log(response_body, &mut findings);
    detect_private_ip(response_body, &mut findings);
    detect_hostname(response_body, &mut findings);
    detect_file_path(response_body, &mut findings);
    detect_stack_trace(response_body, &mut findings);
    detect_aws_access_key(response_body, &mut findings);
    detect_aws_secret_key(response_body, &mut findings);
    detect_generic_api_key(response_body, &mut findings);
    detect_database_connection_string(response_body, &mut findings);
    detect_gps_coordinates(response_body, &mut findings);
    detect_street_address(response_body, &mut findings);

    findings
}

fn regulatory_for(kind: SensitiveDataKind) -> RegulatoryMapping {
    match kind {
        SensitiveDataKind::Ssn => RegulatoryMapping {
            gdpr: Some("Art. 9 — Special categories of personal data".into()),
            pci_dss: None,
            hipaa: Some("§164.514 — De-identification standard".into()),
        },
        SensitiveDataKind::CreditCard => RegulatoryMapping {
            gdpr: Some("Art. 6 — Lawfulness of processing".into()),
            pci_dss: Some("Req 3.4 — Render PAN unreadable".into()),
            hipaa: None,
        },
        SensitiveDataKind::PhoneNumber | SensitiveDataKind::EmailAddress => RegulatoryMapping {
            gdpr: Some("Art. 5(1)(f) — Integrity and confidentiality".into()),
            pci_dss: None,
            hipaa: Some("§164.502 — Uses and disclosures".into()),
        },
        SensitiveDataKind::BankAccountNumber
        | SensitiveDataKind::RoutingNumber
        | SensitiveDataKind::Iban => RegulatoryMapping {
            gdpr: Some("Art. 6 — Lawfulness of processing".into()),
            pci_dss: Some("Req 3 — Protect stored cardholder data".into()),
            hipaa: None,
        },
        SensitiveDataKind::Icd10Code | SensitiveDataKind::PrescriptionPattern => {
            RegulatoryMapping {
                gdpr: Some("Art. 9 — Special categories of personal data".into()),
                pci_dss: None,
                hipaa: Some("§164.502 — Uses and disclosures".into()),
            }
        }
        SensitiveDataKind::PasswordInUrl
        | SensitiveDataKind::TokenInError
        | SensitiveDataKind::SessionIdInLog => RegulatoryMapping {
            gdpr: Some("Art. 32 — Security of processing".into()),
            pci_dss: Some("Req 8.2 — Authentication credentials".into()),
            hipaa: Some("§164.312(d) — Authentication".into()),
        },
        SensitiveDataKind::PrivateIpAddress
        | SensitiveDataKind::Hostname
        | SensitiveDataKind::FilePath
        | SensitiveDataKind::StackTrace => RegulatoryMapping {
            gdpr: None,
            pci_dss: Some("Req 6.5.5 — Improper error handling".into()),
            hipaa: None,
        },
        SensitiveDataKind::AwsAccessKey
        | SensitiveDataKind::AwsSecretKey
        | SensitiveDataKind::GenericApiKey
        | SensitiveDataKind::DatabaseConnectionString => RegulatoryMapping {
            gdpr: Some("Art. 32 — Security of processing".into()),
            pci_dss: Some("Req 2.1 — Change vendor defaults".into()),
            hipaa: Some("§164.312(a)(1) — Access control".into()),
        },
        SensitiveDataKind::GpsCoordinates | SensitiveDataKind::StreetAddress => RegulatoryMapping {
            gdpr: Some("Art. 5(1)(c) — Data minimisation".into()),
            pci_dss: None,
            hipaa: Some("§164.514 — De-identification standard".into()),
        },
    }
}

fn is_likely_test_or_doc_content(body: &str) -> bool {
    static TEST_MARKERS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)(this is a test|example\.com|test data|lorem ipsum|sample response|documentation example|placeholder value)")
            .expect("valid regex")
    });
    let lower = body.to_lowercase();
    let marker_count = TEST_MARKERS.find_iter(&lower).count();
    let line_count = body.lines().count().max(1);
    marker_count > 0 && (marker_count * 10) > line_count
}

fn is_false_positive_context(body: &str, offset: usize) -> bool {
    let start = offset.saturating_sub(60);
    let end = (offset + 80).min(body.len());
    let context = &body[start..end].to_lowercase();
    context.contains("example")
        || context.contains("test")
        || context.contains("fake")
        || context.contains("placeholder")
        || context.contains("dummy")
        || context.contains("sample")
        || context.contains("xxxx")
}

fn push_finding(
    findings: &mut Vec<SensitiveDataFinding>,
    body: &str,
    category: SensitiveDataCategory,
    kind: SensitiveDataKind,
    matched_text: &str,
    offset: usize,
) {
    if is_false_positive_context(body, offset) {
        return;
    }
    findings.push(SensitiveDataFinding {
        category,
        kind,
        matched_text: matched_text.to_string(),
        offset,
        regulatory: regulatory_for(kind),
    });
}

/// Luhn algorithm validation for credit card numbers.
pub fn luhn_validate(digits: &str) -> bool {
    let cleaned: Vec<u8> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();
    if cleaned.len() < 13 || cleaned.len() > 19 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &d in cleaned.iter().rev() {
        let mut val = d as u32;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum.is_multiple_of(10)
}

static SSN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{3}-\d{2}-\d{4})\b").expect("valid regex"));

fn detect_ssn(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in SSN_RE.find_iter(body) {
        let text = cap.as_str();
        let first_three: u16 = text[..3].parse().unwrap_or(0);
        if first_three == 0 || first_three == 666 || first_three >= 900 {
            continue;
        }
        let middle: u8 = text[4..6].parse().unwrap_or(0);
        let last: u16 = text[7..].parse().unwrap_or(0);
        if middle == 0 || last == 0 {
            continue;
        }
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Pii,
            SensitiveDataKind::Ssn,
            text,
            cap.start(),
        );
    }
}

static CC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4})\b").expect("valid regex")
});

fn detect_credit_card(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in CC_RE.find_iter(body) {
        let text = cap.as_str();
        if luhn_validate(text) {
            push_finding(
                findings,
                body,
                SensitiveDataCategory::Pii,
                SensitiveDataKind::CreditCard,
                text,
                cap.start(),
            );
        }
    }
}

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b").expect("valid regex")
});

fn detect_phone_number(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in PHONE_RE.find_iter(body) {
        let text = cap.as_str();
        let digit_count = text.chars().filter(|c| c.is_ascii_digit()).count();
        if !(10..=11).contains(&digit_count) {
            continue;
        }
        push_finding(
            findings,
            body,
            SensitiveDataCategory::PersonalContact,
            SensitiveDataKind::PhoneNumber,
            text,
            cap.start(),
        );
    }
}

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b").expect("valid regex")
});

fn detect_email(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in EMAIL_RE.find_iter(body) {
        let text = cap.as_str();
        if text.contains("example.com") || text.contains("test.com") || text.contains("noreply") {
            continue;
        }
        push_finding(
            findings,
            body,
            SensitiveDataCategory::PersonalContact,
            SensitiveDataKind::EmailAddress,
            text,
            cap.start(),
        );
    }
}

static BANK_ACCT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:account|acct)[\s#:]*(\d{8,17})\b").expect("valid regex"));

fn detect_bank_account(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in BANK_ACCT_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let num = cap.get(1).unwrap().as_str();
        if num.chars().all(|c| c == '0') {
            continue;
        }
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Financial,
            SensitiveDataKind::BankAccountNumber,
            num,
            full.start(),
        );
    }
}

static ROUTING_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:routing|aba|rtn)[\s#:]*(\d{9})\b").expect("valid regex"));

fn detect_routing_number(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in ROUTING_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let num = cap.get(1).unwrap().as_str();
        if validate_aba_routing(num) {
            push_finding(
                findings,
                body,
                SensitiveDataCategory::Financial,
                SensitiveDataKind::RoutingNumber,
                num,
                full.start(),
            );
        }
    }
}

fn validate_aba_routing(digits: &str) -> bool {
    if digits.len() != 9 {
        return false;
    }
    let d: Vec<u32> = digits.chars().map(|c| c as u32 - '0' as u32).collect();
    let checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
    checksum.is_multiple_of(10)
}

static IBAN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b").expect("valid regex"));

fn detect_iban(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in IBAN_RE.find_iter(body) {
        let text = cap.as_str();
        if validate_iban_checksum(text) {
            push_finding(
                findings,
                body,
                SensitiveDataCategory::Financial,
                SensitiveDataKind::Iban,
                text,
                cap.start(),
            );
        }
    }
}

fn validate_iban_checksum(iban: &str) -> bool {
    if iban.len() < 15 || iban.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    let mut numeric = String::with_capacity(rearranged.len() * 2);
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            numeric.push(ch);
        } else if ch.is_ascii_uppercase() {
            let val = ch as u32 - 'A' as u32 + 10;
            numeric.push_str(&val.to_string());
        } else {
            return false;
        }
    }
    mod97(&numeric) == 1
}

fn mod97(digits: &str) -> u32 {
    let mut remainder: u32 = 0;
    for ch in digits.chars() {
        let d = ch as u32 - '0' as u32;
        remainder = (remainder * 10 + d) % 97;
    }
    remainder
}

static ICD10_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:diagnosis|icd|dx)[\s:]*([A-Z]\d{2}(?:\.\d{1,4})?)\b").expect("valid regex")
});

fn detect_icd10(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in ICD10_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let code = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Medical,
            SensitiveDataKind::Icd10Code,
            code,
            full.start(),
        );
    }
}

static PRESCRIPTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:rx|prescri(?:ption|bed)|medication)[\s:]+(\w+\s+\d+\s*mg(?:\s+\w+)*)")
        .expect("valid regex")
});

fn detect_prescription(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in PRESCRIPTION_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let med = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Medical,
            SensitiveDataKind::PrescriptionPattern,
            med,
            full.start(),
        );
    }
}

static PASSWORD_URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:password|passwd|pwd)=([^\s&]{3,})").expect("valid regex"));

fn detect_password_in_url(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in PASSWORD_URL_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Authentication,
            SensitiveDataKind::PasswordInUrl,
            full.as_str(),
            full.start(),
        );
    }
}

static TOKEN_ERROR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:error|exception|fail(?:ed|ure))[^}]{0,100}(?:token|bearer|jwt|api[_-]?key)[\s=:]+([A-Za-z0-9._\-]{16,})")
        .expect("valid regex")
});

fn detect_token_in_error(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in TOKEN_ERROR_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let token = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Authentication,
            SensitiveDataKind::TokenInError,
            token,
            full.start(),
        );
    }
}

static SESSION_LOG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:session[_-]?id|sid|jsessionid|phpsessid)[\s=:]+([A-Za-z0-9]{16,64})")
        .expect("valid regex")
});

fn detect_session_id_in_log(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in SESSION_LOG_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let sid = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Authentication,
            SensitiveDataKind::SessionIdInLog,
            sid,
            full.start(),
        );
    }
}

static PRIVATE_IP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )
    .expect("valid regex")
});

fn detect_private_ip(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in PRIVATE_IP_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::InternalInfrastructure,
            SensitiveDataKind::PrivateIpAddress,
            cap.as_str(),
            cap.start(),
        );
    }
}

static HOSTNAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-z][a-z0-9\-]+\.(?:internal|local|corp|intranet|priv|lan))\b")
        .expect("valid regex")
});

fn detect_hostname(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in HOSTNAME_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::InternalInfrastructure,
            SensitiveDataKind::Hostname,
            cap.as_str(),
            cap.start(),
        );
    }
}

static FILE_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:/(?:home|var|etc|usr|opt|tmp|root|srv)/[^\s:"'<>]{3,}|[A-Z]:\\(?:Users|Windows|Program Files)[^\s:"'<>]{3,})"#
    )
    .expect("valid regex")
});

fn detect_file_path(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in FILE_PATH_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::InternalInfrastructure,
            SensitiveDataKind::FilePath,
            cap.as_str(),
            cap.start(),
        );
    }
}

static STACK_TRACE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:at\s+[\w$.]+\([\w]+\.(?:java|kt|scala):\d+\)|File\s+"[^"]+",\s+line\s+\d+|\.rs:\d+:\d+|Traceback \(most recent call last\))"#
    )
    .expect("valid regex")
});

fn detect_stack_trace(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in STACK_TRACE_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::InternalInfrastructure,
            SensitiveDataKind::StackTrace,
            cap.as_str(),
            cap.start(),
        );
    }
}

static AWS_ACCESS_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").expect("valid regex"));

fn detect_aws_access_key(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in AWS_ACCESS_KEY_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::ApiKeyOrSecret,
            SensitiveDataKind::AwsAccessKey,
            cap.as_str(),
            cap.start(),
        );
    }
}

static AWS_SECRET_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)[\s=:]+([A-Za-z0-9/+=]{40})",
    )
    .expect("valid regex")
});

fn detect_aws_secret_key(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in AWS_SECRET_KEY_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let secret = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::ApiKeyOrSecret,
            SensitiveDataKind::AwsSecretKey,
            secret,
            full.start(),
        );
    }
}

static GENERIC_API_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:api[_-]?key|apikey|x-api-key)[\s=:]+([A-Za-z0-9\-_.]{20,})")
        .expect("valid regex")
});

fn detect_generic_api_key(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in GENERIC_API_KEY_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let key = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::ApiKeyOrSecret,
            SensitiveDataKind::GenericApiKey,
            key,
            full.start(),
        );
    }
}

static DB_CONN_STRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s]{10,}")
        .expect("valid regex")
});

fn detect_database_connection_string(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in DB_CONN_STRING_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::ApiKeyOrSecret,
            SensitiveDataKind::DatabaseConnectionString,
            cap.as_str(),
            cap.start(),
        );
    }
}

static GPS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:lat(?:itude)?|lng|lon(?:gitude)?|coords?|gps)["'\s=:]+(-?\d{1,3}\.\d{4,})"#,
    )
    .expect("valid regex")
});

fn detect_gps_coordinates(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in GPS_RE.captures_iter(body) {
        let full = cap.get(0).unwrap();
        let coord = cap.get(1).unwrap().as_str();
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Geolocation,
            SensitiveDataKind::GpsCoordinates,
            coord,
            full.start(),
        );
    }
}

static STREET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Road|Rd|Court|Ct|Place|Pl|Way))\b"
    )
    .expect("valid regex")
});

fn detect_street_address(body: &str, findings: &mut Vec<SensitiveDataFinding>) {
    for cap in STREET_RE.find_iter(body) {
        push_finding(
            findings,
            body,
            SensitiveDataCategory::Geolocation,
            SensitiveDataKind::StreetAddress,
            cap.as_str(),
            cap.start(),
        );
    }
}
