use std::collections::HashMap;
use std::fmt;

use regex::Regex;

/// Email validation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailValidationStatus {
    Valid,
    Invalid,
    CatchAll,
    Greylisted,
    Timeout,
    Refused,
    Unknown,
}

impl fmt::Display for EmailValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Invalid => write!(f, "Invalid"),
            Self::CatchAll => write!(f, "Catch-All"),
            Self::Greylisted => write!(f, "Greylisted"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Refused => write!(f, "Refused"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Confidence level for validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ValidationConfidence {
    Low,
    Medium,
    High,
    Definitive,
}

impl fmt::Display for ValidationConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Definitive => write!(f, "Definitive"),
        }
    }
}

/// SMTP response code parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct SmtpResponse {
    pub code: u16,
    pub enhanced_code: Option<String>,
    pub message: String,
    pub is_positive: bool,
    pub is_temporary: bool,
}

/// Timing analysis for SMTP response.
#[derive(Debug, Clone, PartialEq)]
pub struct SmtpTimingProfile {
    pub rcpt_to_response_ms: u64,
    pub valid_addr_avg_ms: Option<u64>,
    pub invalid_addr_avg_ms: Option<u64>,
    pub timing_delta_ms: Option<i64>,
    pub is_timing_vulnerable: bool,
}

/// Catch-all detection result.
#[derive(Debug, Clone, PartialEq)]
pub struct CatchAllResult {
    pub domain: String,
    pub is_catch_all: bool,
    pub test_addresses_tried: usize,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub confidence: ValidationConfidence,
    pub mx_records: Vec<String>,
}

/// Greylisting detection result.
#[derive(Debug, Clone, PartialEq)]
pub struct GreylistResult {
    pub domain: String,
    pub is_greylisting: bool,
    pub first_response: Option<SmtpResponse>,
    pub retry_response: Option<SmtpResponse>,
    pub retry_delay_seconds: u64,
    pub confidence: ValidationConfidence,
}

/// Single email validation result.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailValidationResult {
    pub email: String,
    pub status: EmailValidationStatus,
    pub confidence: ValidationConfidence,
    pub smtp_response: Option<SmtpResponse>,
    pub catch_all: Option<CatchAllResult>,
    pub greylist: Option<GreylistResult>,
    pub timing_profile: Option<SmtpTimingProfile>,
    pub mx_server: Option<String>,
    pub validation_methods: Vec<String>,
}

/// Batch validation report.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailValidationReport {
    pub domain: String,
    pub results: Vec<EmailValidationResult>,
    pub catch_all_status: Option<CatchAllResult>,
    pub greylist_status: Option<GreylistResult>,
    pub total_checked: usize,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub unknown_count: usize,
    pub status_distribution: HashMap<EmailValidationStatus, usize>,
}

/// Parses an SMTP response string.
pub fn parse_smtp_response(response: &str) -> SmtpResponse {
    let code_re = Regex::new(r"^(\d{3})[\s\-]").expect("valid smtp regex");
    let enhanced_re = Regex::new(r"(\d\.\d\.\d)").expect("valid enhanced regex");

    let code = code_re
        .captures(response)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok())
        .unwrap_or(0);

    let enhanced_code = enhanced_re
        .captures(response)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());

    let message = response.trim().to_string();
    let is_positive = code >= 200 && code < 300;
    let is_temporary = code >= 400 && code < 500;

    SmtpResponse {
        code,
        enhanced_code,
        message,
        is_positive,
        is_temporary,
    }
}

/// Determines email validity from an SMTP RCPT TO response code.
pub fn classify_smtp_response(code: u16) -> EmailValidationStatus {
    match code {
        250 | 251 => EmailValidationStatus::Valid,
        550 | 551 | 553 | 554 => EmailValidationStatus::Invalid,
        450 | 451 | 452 => EmailValidationStatus::Greylisted,
        421 => EmailValidationStatus::Refused,
        0 => EmailValidationStatus::Timeout,
        _ => EmailValidationStatus::Unknown,
    }
}

/// Detects catch-all behavior by testing random addresses.
pub fn detect_catch_all(
    domain: &str,
    test_responses: &[(String, u16)],
    mx_records: Vec<String>,
) -> CatchAllResult {
    let total = test_responses.len();
    let accepted = test_responses
        .iter()
        .filter(|(_, code)| *code == 250 || *code == 251)
        .count();
    let rejected = test_responses
        .iter()
        .filter(|(_, code)| *code >= 550 && *code < 560)
        .count();

    let is_catch_all = total > 0 && accepted == total;
    let confidence = if total >= 5 && is_catch_all {
        ValidationConfidence::High
    } else if total >= 3 && is_catch_all {
        ValidationConfidence::Medium
    } else if total >= 1 && is_catch_all {
        ValidationConfidence::Low
    } else if rejected > 0 {
        ValidationConfidence::High
    } else {
        ValidationConfidence::Low
    };

    CatchAllResult {
        domain: domain.to_string(),
        is_catch_all,
        test_addresses_tried: total,
        accepted_count: accepted,
        rejected_count: rejected,
        confidence,
        mx_records,
    }
}

/// Analyzes SMTP timing for timing-based enumeration.
pub fn analyze_smtp_timing(
    valid_timings_ms: &[u64],
    invalid_timings_ms: &[u64],
    current_rcpt_ms: u64,
) -> SmtpTimingProfile {
    let valid_avg = if !valid_timings_ms.is_empty() {
        Some(valid_timings_ms.iter().sum::<u64>() / valid_timings_ms.len() as u64)
    } else {
        None
    };

    let invalid_avg = if !invalid_timings_ms.is_empty() {
        Some(invalid_timings_ms.iter().sum::<u64>() / invalid_timings_ms.len() as u64)
    } else {
        None
    };

    let timing_delta = match (valid_avg, invalid_avg) {
        (Some(v), Some(i)) => Some(v as i64 - i as i64),
        _ => None,
    };

    let is_timing_vulnerable = timing_delta.map(|delta| delta.abs() > 100).unwrap_or(false);

    SmtpTimingProfile {
        rcpt_to_response_ms: current_rcpt_ms,
        valid_addr_avg_ms: valid_avg,
        invalid_addr_avg_ms: invalid_avg,
        timing_delta_ms: timing_delta,
        is_timing_vulnerable,
    }
}

/// Detects greylisting from SMTP responses.
pub fn detect_greylisting(
    domain: &str,
    first_code: u16,
    first_response: &str,
    retry_code: Option<u16>,
    retry_response: Option<&str>,
    retry_delay_seconds: u64,
) -> GreylistResult {
    let first = parse_smtp_response(first_response);
    let retry = retry_response.map(|r| parse_smtp_response(r));

    let is_greylisting =
        first.is_temporary && retry.as_ref().map(|r| r.is_positive).unwrap_or(false);

    let confidence = if is_greylisting {
        if retry_delay_seconds >= 300 {
            ValidationConfidence::High
        } else {
            ValidationConfidence::Medium
        }
    } else if first.is_temporary {
        ValidationConfidence::Low
    } else {
        ValidationConfidence::Definitive
    };

    GreylistResult {
        domain: domain.to_string(),
        is_greylisting,
        first_response: Some(first),
        retry_response: retry,
        retry_delay_seconds,
        confidence,
    }
}

/// Validates a single email address combining all techniques.
pub fn validate_email(
    email: &str,
    smtp_code: u16,
    smtp_response: &str,
    catch_all: Option<&CatchAllResult>,
    greylist: Option<&GreylistResult>,
    timing: Option<SmtpTimingProfile>,
) -> EmailValidationResult {
    let parsed = parse_smtp_response(smtp_response);
    let base_status = classify_smtp_response(smtp_code);

    let (status, confidence) = if let Some(ca) = catch_all {
        if ca.is_catch_all && base_status == EmailValidationStatus::Valid {
            (
                EmailValidationStatus::CatchAll,
                ValidationConfidence::Medium,
            )
        } else {
            (base_status, derive_confidence(base_status))
        }
    } else {
        (base_status, derive_confidence(base_status))
    };

    let mut methods = vec!["SMTP RCPT TO".to_string()];
    if catch_all.is_some() {
        methods.push("Catch-all detection".to_string());
    }
    if greylist.is_some() {
        methods.push("Greylist bypass".to_string());
    }
    if timing.is_some() {
        methods.push("Timing analysis".to_string());
    }

    let domain = email.split('@').nth(1).unwrap_or("").to_string();

    EmailValidationResult {
        email: email.to_string(),
        status,
        confidence,
        smtp_response: Some(parsed),
        catch_all: catch_all.cloned(),
        greylist: greylist.cloned(),
        timing_profile: timing,
        mx_server: None,
        validation_methods: methods,
    }
}

fn derive_confidence(status: EmailValidationStatus) -> ValidationConfidence {
    match status {
        EmailValidationStatus::Valid => ValidationConfidence::High,
        EmailValidationStatus::Invalid => ValidationConfidence::Definitive,
        EmailValidationStatus::CatchAll => ValidationConfidence::Low,
        EmailValidationStatus::Greylisted => ValidationConfidence::Low,
        _ => ValidationConfidence::Low,
    }
}

/// Generates random test email addresses for catch-all detection.
pub fn generate_catch_all_test_addresses(domain: &str, count: usize) -> Vec<String> {
    let prefixes = [
        "xq7kz9m2", "j3bfw8p1", "n5cty6r4", "v0dhg3x8", "z2mkl7q5", "w4npf9s1", "u6arj2e7",
        "i8gxo5c3", "l1hvb4d9", "y9etm6w0",
    ];
    prefixes
        .iter()
        .take(count)
        .map(|p| format!("{}@{}", p, domain))
        .collect()
}

/// Builds a batch validation report.
pub fn build_validation_report(
    domain: &str,
    results: Vec<EmailValidationResult>,
    catch_all: Option<CatchAllResult>,
    greylist: Option<GreylistResult>,
) -> EmailValidationReport {
    let total_checked = results.len();
    let valid_count = results
        .iter()
        .filter(|r| r.status == EmailValidationStatus::Valid)
        .count();
    let invalid_count = results
        .iter()
        .filter(|r| r.status == EmailValidationStatus::Invalid)
        .count();
    let unknown_count = results
        .iter()
        .filter(|r| r.status == EmailValidationStatus::Unknown)
        .count();

    let mut status_dist: HashMap<EmailValidationStatus, usize> = HashMap::new();
    for r in &results {
        *status_dist.entry(r.status).or_insert(0) += 1;
    }

    EmailValidationReport {
        domain: domain.to_string(),
        results,
        catch_all_status: catch_all,
        greylist_status: greylist,
        total_checked,
        valid_count,
        invalid_count,
        unknown_count,
        status_distribution: status_dist,
    }
}
