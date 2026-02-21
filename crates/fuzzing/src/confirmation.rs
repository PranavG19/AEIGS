use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use aegis_protocol::finding::VulnerabilityClass;
use regex::Regex;

use crate::executor::FuzzResponse;
use crate::oracle::{BaselineProfile, normalize_body, simhash, simhash_similarity};

/// Evidence produced by a per-vulnerability-class confirmation function.
/// Captures what type of evidence was observed, how confident the function
/// is in the finding, and a human-readable description of the observation.
///
/// `confidence` must be in `0.0..=1.0`.
#[derive(Debug, Clone)]
pub struct ConfirmationEvidence {
    pub evidence_type: EvidenceType,
    pub confidence: f64,
    pub description: String,
}

/// Classifies the kind of observable behavior that confirms a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    SqlErrorMessage,
    TimeBasedDelay,
    ReflectedPayload,
    StatusCodeChange,
    InformationDisclosure,
    BehaviorDifference,
    TemplateEvaluation,
    CommandOutput,
    PathContents,
    RedirectToExternal,
    DeserializationMarker,
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SqlErrorMessage => "sql-error-message",
            Self::TimeBasedDelay => "time-based-delay",
            Self::ReflectedPayload => "reflected-payload",
            Self::StatusCodeChange => "status-code-change",
            Self::InformationDisclosure => "information-disclosure",
            Self::BehaviorDifference => "behavior-difference",
            Self::TemplateEvaluation => "template-evaluation",
            Self::CommandOutput => "command-output",
            Self::PathContents => "path-contents",
            Self::RedirectToExternal => "redirect-to-external",
            Self::DeserializationMarker => "deserialization-marker",
        };
        write!(f, "{label}")
    }
}

/// Confirmation function signature: given a treatment response, a control
/// response, the payload that was sent, and a baseline profile for the
/// endpoint, returns evidence if the vulnerability is confirmed.
pub type ConfirmFn =
    fn(&FuzzResponse, &FuzzResponse, &str, &BaselineProfile) -> Option<ConfirmationEvidence>;

/// Builds a registry mapping each vulnerability class to its ordered list
/// of confirmation functions. Functions are tried in order; the first to
/// return Some wins.
pub fn build_confirmation_registry() -> HashMap<VulnerabilityClass, Vec<ConfirmFn>> {
    let mut registry: HashMap<VulnerabilityClass, Vec<ConfirmFn>> = HashMap::new();

    registry.insert(
        VulnerabilityClass::SqlInjection,
        vec![
            confirm_sql_error_message,
            confirm_sql_time_delay,
            confirm_sql_boolean_diff,
            confirm_sql_union_column_count,
        ],
    );

    registry
}

static SQL_ERROR_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)you have an error in your sql syntax",
        r"(?i)ORA-\d{5}",
        r"(?i)PostgreSQL.*ERROR",
        r"(?i)SQLSTATE\[",
        r"sqlite3\.OperationalError",
        r"(?i)Microsoft OLE DB",
        r"(?i)unclosed quotation mark",
        r"(?i)quoted string not properly terminated",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

static SQL_TIME_KEYWORDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(sleep|waitfor|pg_sleep|benchmark)\s*\(\s*(\d+)").unwrap());

static SQL_UNION_SELECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)UNION\s+(ALL\s+)?SELECT\s+").unwrap());

fn body_matches_sql_error(body: &str) -> bool {
    SQL_ERROR_PATTERNS.iter().any(|re| re.is_match(body))
}

pub fn confirm_sql_error_message(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    _payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let matched_pattern = SQL_ERROR_PATTERNS
        .iter()
        .find(|re| re.is_match(&treatment.body))?;

    if matched_pattern.is_match(&control.body) {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::SqlErrorMessage,
        confidence: 0.95,
        description: format!(
            "SQL error pattern '{}' found in treatment but not in control",
            matched_pattern.as_str()
        ),
    })
}

pub fn confirm_sql_time_delay(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let captures = SQL_TIME_KEYWORDS.captures(payload)?;
    let expected_delay_secs: f64 = captures.get(2)?.as_str().parse().ok()?;
    let threshold_secs = expected_delay_secs * 0.8;

    let delta = treatment.response_time.as_secs_f64() - control.response_time.as_secs_f64();

    if delta < threshold_secs {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::TimeBasedDelay,
        confidence: 0.90,
        description: format!(
            "treatment took {:.2}s longer than control (expected delay: {expected_delay_secs}s)",
            delta
        ),
    })
}

pub fn confirm_sql_boolean_diff(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    _payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    if treatment.status_code != control.status_code {
        return None;
    }

    let treatment_hash = simhash(&normalize_body(&treatment.body));
    let control_hash = simhash(&normalize_body(&control.body));
    let similarity = simhash_similarity(treatment_hash, control_hash);

    if similarity >= 0.85 {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::BehaviorDifference,
        confidence: 0.85,
        description: format!(
            "same status {} but body similarity {similarity:.3} indicates boolean-based blind SQLi",
            treatment.status_code
        ),
    })
}

pub fn confirm_sql_union_column_count(
    treatment: &FuzzResponse,
    _control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    if !SQL_UNION_SELECT.is_match(payload) {
        return None;
    }

    if body_matches_sql_error(&treatment.body) {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::BehaviorDifference,
        confidence: 0.80,
        description: "UNION SELECT did not produce SQL error, column count likely matched"
            .to_string(),
    })
}
