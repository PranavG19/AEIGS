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

    registry.insert(
        VulnerabilityClass::CrossSiteScripting,
        vec![
            confirm_xss_reflection_in_html_context,
            confirm_xss_reflection_in_attribute,
            confirm_xss_reflection_in_js_context,
        ],
    );

    registry.insert(
        VulnerabilityClass::ServerSideTemplateInjection,
        vec![confirm_ssti_evaluation],
    );

    registry.insert(
        VulnerabilityClass::CommandInjection,
        vec![confirm_cmd_output_patterns, confirm_cmd_time_delay],
    );

    registry.insert(
        VulnerabilityClass::PathTraversal,
        vec![confirm_path_traversal_file_contents],
    );

    registry.insert(
        VulnerabilityClass::OpenRedirect,
        vec![confirm_redirect_to_payload_domain],
    );

    registry.insert(
        VulnerabilityClass::InsecureDeserialization,
        vec![confirm_deserialization_error_pattern],
    );

    registry.insert(
        VulnerabilityClass::ServerSideRequestForgery,
        vec![confirm_ssrf_internal_content],
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

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

static XSS_ATTRIBUTE_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(href|src|onclick|onload|onerror|onmouseover|action|formaction|data|style|value)\s*=\s*["']([^"']*)["']"#).unwrap()
});

static XSS_SCRIPT_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap());

pub fn confirm_xss_reflection_in_html_context(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    if payload.len() < 4 {
        return None;
    }

    if !treatment.body.contains(payload) {
        return None;
    }

    if control.body.contains(payload) {
        return None;
    }

    let encoded = html_encode(payload);
    if encoded != payload && treatment.body.contains(&encoded) && !treatment.body.contains(payload)
    {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::ReflectedPayload,
        confidence: 0.90,
        description: format!(
            "XSS payload reflected unencoded in HTML context ({} chars)",
            payload.len()
        ),
    })
}

pub fn confirm_xss_reflection_in_attribute(
    treatment: &FuzzResponse,
    _control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    for captures in XSS_ATTRIBUTE_CONTEXT.captures_iter(&treatment.body) {
        let attr_value = captures.get(2)?;
        if attr_value.as_str().contains(payload) {
            let attr_name = captures.get(1)?.as_str();
            return Some(ConfirmationEvidence {
                evidence_type: EvidenceType::ReflectedPayload,
                confidence: 0.88,
                description: format!("XSS payload reflected inside '{attr_name}' attribute value"),
            });
        }
    }
    None
}

pub fn confirm_xss_reflection_in_js_context(
    treatment: &FuzzResponse,
    _control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    for captures in XSS_SCRIPT_BLOCK.captures_iter(&treatment.body) {
        let script_content = captures.get(1)?;
        if script_content.as_str().contains(payload) {
            return Some(ConfirmationEvidence {
                evidence_type: EvidenceType::ReflectedPayload,
                confidence: 0.92,
                description: "XSS payload reflected inside <script> block".to_string(),
            });
        }
    }
    None
}

static SSTI_PROBES: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
    ]
});

pub fn confirm_ssti_evaluation(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    for (probe, expected) in SSTI_PROBES.iter() {
        if !payload.contains(probe) {
            continue;
        }

        if treatment.body.contains(expected) && !control.body.contains(expected) {
            return Some(ConfirmationEvidence {
                evidence_type: EvidenceType::TemplateEvaluation,
                confidence: 0.95,
                description: format!(
                    "SSTI probe '{probe}' evaluated to '{expected}' in treatment but not control"
                ),
            });
        }
    }
    None
}

static CMD_OUTPUT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"uid=\d+\(.*?\)\s+gid=\d+",
        r"root:.*:0:0:",
        r"total \d+\n.*rwx",
        r"(?i)Windows IP Configuration",
        r"PRETTY_NAME=",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

static CMD_TIME_KEYWORDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(sleep|ping|timeout)\s+(\d+)").unwrap());

pub fn confirm_cmd_output_patterns(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    _payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let matched_pattern = CMD_OUTPUT_PATTERNS
        .iter()
        .find(|re| re.is_match(&treatment.body))?;

    if matched_pattern.is_match(&control.body) {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::CommandOutput,
        confidence: 0.95,
        description: format!(
            "OS command output pattern '{}' found in treatment but not control",
            matched_pattern.as_str()
        ),
    })
}

pub fn confirm_cmd_time_delay(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let captures = CMD_TIME_KEYWORDS.captures(payload)?;
    let expected_delay_secs: f64 = captures.get(2)?.as_str().parse().ok()?;
    let threshold_secs = expected_delay_secs * 0.8;

    let delta = treatment.response_time.as_secs_f64() - control.response_time.as_secs_f64();

    if delta < threshold_secs {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::TimeBasedDelay,
        confidence: 0.88,
        description: format!(
            "command delay: treatment took {delta:.2}s longer than control (expected: {expected_delay_secs}s)"
        ),
    })
}

static PATH_TRAVERSAL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [r"root:.*:0:0:", r"\[boot loader\]", r"\[extensions\]"]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
});

pub fn confirm_path_traversal_file_contents(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    _payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let matched_pattern = PATH_TRAVERSAL_PATTERNS
        .iter()
        .find(|re| re.is_match(&treatment.body))?;

    if matched_pattern.is_match(&control.body) {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::PathContents,
        confidence: 0.92,
        description: format!(
            "file content pattern '{}' found in treatment but not control",
            matched_pattern.as_str()
        ),
    })
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn is_redirect_status(status: u16) -> bool {
    (300..400).contains(&status)
}

pub fn confirm_redirect_to_payload_domain(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    if let Some(location) = find_header(&treatment.headers, "location") {
        let has_evil = location.contains("evil.com");
        let has_protocol_relative = location.starts_with("//");
        let has_payload_domain = !payload.is_empty() && location.contains(payload);

        if has_evil || has_protocol_relative || has_payload_domain {
            return Some(ConfirmationEvidence {
                evidence_type: EvidenceType::RedirectToExternal,
                confidence: 0.90,
                description: format!("Location header redirects to external: {location}"),
            });
        }
    }

    if is_redirect_status(treatment.status_code) && !is_redirect_status(control.status_code) {
        return Some(ConfirmationEvidence {
            evidence_type: EvidenceType::RedirectToExternal,
            confidence: 0.80,
            description: format!(
                "treatment returned redirect status {} while control returned {}",
                treatment.status_code, control.status_code
            ),
        });
    }

    None
}

static DESERIALIZATION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)ClassNotFoundException",
        r"java\.io\.ObjectInputStream",
        r"unserialize\(\)",
        r"pickle\.loads",
        r"node-serialize",
        r"(?i)marshalling error",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

pub fn confirm_deserialization_error_pattern(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    _payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let matched_pattern = DESERIALIZATION_PATTERNS
        .iter()
        .find(|re| re.is_match(&treatment.body))?;

    if matched_pattern.is_match(&control.body) {
        return None;
    }

    Some(ConfirmationEvidence {
        evidence_type: EvidenceType::DeserializationMarker,
        confidence: 0.85,
        description: format!(
            "deserialization pattern '{}' found in treatment but not control",
            matched_pattern.as_str()
        ),
    })
}

static SSRF_INTERNAL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"instance-identity",
        r"meta-data",
        r"169\.254\.169\.254",
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

pub fn confirm_ssrf_internal_content(
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    _payload: &str,
    _baseline: &BaselineProfile,
) -> Option<ConfirmationEvidence> {
    let matched_pattern = SSRF_INTERNAL_PATTERNS
        .iter()
        .find(|re| re.is_match(&treatment.body) && !re.is_match(&control.body));

    if let Some(pattern) = matched_pattern {
        return Some(ConfirmationEvidence {
            evidence_type: EvidenceType::InformationDisclosure,
            confidence: 0.88,
            description: format!(
                "internal service pattern '{}' found in treatment but not control",
                pattern.as_str()
            ),
        });
    }

    if control.body_size_bytes > 0 && treatment.body_size_bytes > control.body_size_bytes * 2 {
        return Some(ConfirmationEvidence {
            evidence_type: EvidenceType::InformationDisclosure,
            confidence: 0.88,
            description: format!(
                "treatment body ({} bytes) is >2x control body ({} bytes)",
                treatment.body_size_bytes, control.body_size_bytes
            ),
        });
    }

    None
}
