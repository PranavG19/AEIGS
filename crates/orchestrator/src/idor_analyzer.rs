use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;

/// Detected ID format in a path segment or parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdFormat {
    SequentialInteger,
    Uuid,
    Slug,
    Encoded,
}

impl std::fmt::Display for IdFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequentialInteger => write!(f, "sequential integer"),
            Self::Uuid => write!(f, "UUID"),
            Self::Slug => write!(f, "slug"),
            Self::Encoded => write!(f, "encoded"),
        }
    }
}

/// A candidate endpoint for Insecure Direct Object Reference testing.
///
/// Produced by heuristic analysis of endpoint patterns, parameter names,
/// and HTTP methods. The `likelihood` score reflects how probable it is
/// that the endpoint is vulnerable to IDOR, ranging from 0.0 to 1.0.
#[derive(Debug, Clone)]
pub struct IdorTestCase {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub id_format: IdFormat,
    pub likelihood: f64,
    pub reasoning: String,
}

/// Heuristic IDOR analysis engine.
///
/// Analyzes API endpoint patterns to identify likely Insecure Direct Object
/// Reference targets without requiring an LLM. Generates test cases, XML
/// context for LLM prompts, and natural-language test descriptions.
pub struct IdorAnalyzer;

const HIGH_LIKELIHOOD_ID_PARAMS: &[&str] = &[
    "id",
    "user_id",
    "account_id",
    "order_id",
    "userId",
    "accountId",
    "orderId",
    "invoice_id",
    "document_id",
    "file_id",
    "report_id",
];

const MEDIUM_LIKELIHOOD_ID_PARAMS: &[&str] = &["ref", "code", "token", "slug", "key", "handle"];

const USER_SPECIFIC_SEGMENTS: &[&str] = &[
    "user", "account", "profile", "order", "invoice", "document", "file", "report",
];

impl IdorAnalyzer {
    /// Analyzes endpoints to identify IDOR candidates using heuristic rules.
    ///
    /// Input: slice of `(path, method, parameter_names)` tuples.
    /// Returns test cases sorted by likelihood descending.
    pub fn analyze_endpoints(endpoints: &[(String, String, Vec<String>)]) -> Vec<IdorTestCase> {
        let mut cases: Vec<IdorTestCase> = endpoints
            .iter()
            .flat_map(|(path, method, params)| analyze_single(path, method, params))
            .collect();
        cases.sort_by(|a, b| {
            b.likelihood
                .partial_cmp(&a.likelihood)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        cases
    }

    /// Builds XML context for LLM prompts combining IDOR analysis with existing findings.
    pub fn build_idor_context(
        endpoints: &[(String, String, Vec<String>)],
        findings: &[(VulnerabilityClass, String)],
    ) -> String {
        let cases = Self::analyze_endpoints(endpoints);
        let endpoints_xml = format_endpoints_xml(&cases);
        let findings_xml = format_findings_xml(findings);
        format!(
            "<idor_analysis>\n\
             \x20   <endpoints>\n\
             {endpoints_xml}\
             \x20   </endpoints>\n\
             \x20   <existing_findings>\n\
             {findings_xml}\
             \x20   </existing_findings>\n\
             </idor_analysis>"
        )
    }

    /// Generates natural-language test descriptions for IDOR test cases.
    pub fn suggest_idor_tests(test_cases: &[IdorTestCase]) -> Vec<String> {
        test_cases.iter().map(describe_test).collect()
    }
}

fn analyze_single(path: &str, method: &str, params: &[String]) -> Vec<IdorTestCase> {
    let mut cases = Vec::new();
    check_path_segments(path, method, &mut cases);
    check_parameter_names(path, method, params, &mut cases);
    check_user_specific_get(path, method, &mut cases);
    check_state_changing_methods(path, method, &mut cases);
    deduplicate_by_highest_likelihood(&mut cases);
    cases
}

fn check_path_segments(path: &str, method: &str, cases: &mut Vec<IdorTestCase>) {
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        if segment.chars().all(|c| c.is_ascii_digit()) {
            cases.push(IdorTestCase {
                endpoint: path.to_string(),
                method: method.to_string(),
                parameter: segment.to_string(),
                id_format: IdFormat::SequentialInteger,
                likelihood: 0.9,
                reasoning: format!("Numeric ID segment '{segment}' in path, likely enumerable"),
            });
        } else if looks_like_uuid(segment) {
            cases.push(IdorTestCase {
                endpoint: path.to_string(),
                method: method.to_string(),
                parameter: segment.to_string(),
                id_format: IdFormat::Uuid,
                likelihood: 0.6,
                reasoning: "UUID in path, harder to enumerate but IDOR possible if UUIDs leak"
                    .to_string(),
            });
        }
    }
}

fn check_parameter_names(
    path: &str,
    method: &str,
    params: &[String],
    cases: &mut Vec<IdorTestCase>,
) {
    for param in params {
        let lower = param.to_lowercase();
        if is_high_likelihood_param(&lower) {
            cases.push(IdorTestCase {
                endpoint: path.to_string(),
                method: method.to_string(),
                parameter: param.clone(),
                id_format: infer_format_from_param(&lower),
                likelihood: 0.85,
                reasoning: format!(
                    "Parameter '{param}' is a direct object reference on {method} {path}"
                ),
            });
        } else if is_medium_likelihood_param(&lower) {
            cases.push(IdorTestCase {
                endpoint: path.to_string(),
                method: method.to_string(),
                parameter: param.clone(),
                id_format: infer_format_from_param(&lower),
                likelihood: 0.5,
                reasoning: format!(
                    "Parameter '{param}' may reference an object indirectly on {method} {path}"
                ),
            });
        }
    }
}

fn check_user_specific_get(path: &str, method: &str, cases: &mut Vec<IdorTestCase>) {
    if !method.eq_ignore_ascii_case("GET") {
        return;
    }
    if !path_contains_user_segment(path) {
        return;
    }
    cases.push(IdorTestCase {
        endpoint: path.to_string(),
        method: method.to_string(),
        parameter: String::new(),
        id_format: IdFormat::SequentialInteger,
        likelihood: 0.8,
        reasoning: format!("GET endpoint returning user-specific data at {path}"),
    });
}

fn check_state_changing_methods(path: &str, method: &str, cases: &mut Vec<IdorTestCase>) {
    let upper = method.to_uppercase();
    if !matches!(upper.as_str(), "PUT" | "PATCH" | "DELETE") {
        return;
    }
    if !path_has_resource_id_pattern(path) {
        return;
    }
    cases.push(IdorTestCase {
        endpoint: path.to_string(),
        method: method.to_string(),
        parameter: String::new(),
        id_format: IdFormat::SequentialInteger,
        likelihood: 0.85,
        reasoning: format!(
            "{upper} on resource endpoint {path}, state-changing on specific resources"
        ),
    });
}

fn is_high_likelihood_param(lower: &str) -> bool {
    HIGH_LIKELIHOOD_ID_PARAMS
        .iter()
        .any(|p| p.to_lowercase() == *lower)
}

fn is_medium_likelihood_param(lower: &str) -> bool {
    MEDIUM_LIKELIHOOD_ID_PARAMS
        .iter()
        .any(|p| p.to_lowercase() == *lower)
}

fn path_contains_user_segment(path: &str) -> bool {
    let lower = path.to_lowercase();
    USER_SPECIFIC_SEGMENTS.iter().any(|seg| lower.contains(seg))
}

fn path_has_resource_id_pattern(path: &str) -> bool {
    path.split('/').filter(|s| !s.is_empty()).any(|s| {
        s.starts_with(':')
            || s.starts_with('{')
            || s.chars().all(|c| c.is_ascii_digit())
            || looks_like_uuid(s)
    })
}

fn infer_format_from_param(lower_param: &str) -> IdFormat {
    if lower_param.contains("uuid") || lower_param.contains("guid") {
        return IdFormat::Uuid;
    }
    if lower_param.contains("slug") || lower_param == "handle" {
        return IdFormat::Slug;
    }
    if lower_param.contains("token") || lower_param.contains("code") || lower_param == "ref" {
        return IdFormat::Encoded;
    }
    IdFormat::SequentialInteger
}

fn deduplicate_by_highest_likelihood(cases: &mut Vec<IdorTestCase>) {
    cases.sort_by(|a, b| {
        b.likelihood
            .partial_cmp(&a.likelihood)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut seen = HashSet::new();
    cases.retain(|c| {
        let key = (c.endpoint.clone(), c.parameter.clone());
        seen.insert(key)
    });
}

fn format_endpoints_xml(cases: &[IdorTestCase]) -> String {
    cases.iter().map(format_single_endpoint_xml).collect()
}

fn format_single_endpoint_xml(c: &IdorTestCase) -> String {
    let param_attr = if c.parameter.is_empty() {
        String::new()
    } else {
        format!(" params=\"{}\"", xml_escape(&c.parameter))
    };
    format!(
        "        <endpoint path=\"{path}\" method=\"{method}\"{param_attr}>\n\
         \x20           <idor_likelihood>{likelihood}</idor_likelihood>\n\
         \x20           <reasoning>{reasoning}</reasoning>\n\
         \x20       </endpoint>\n",
        path = xml_escape(&c.endpoint),
        method = xml_escape(&c.method),
        likelihood = c.likelihood,
        reasoning = xml_escape(&c.reasoning),
    )
}

fn format_findings_xml(findings: &[(VulnerabilityClass, String)]) -> String {
    findings
        .iter()
        .map(|(class, endpoint)| {
            format!(
                "        <finding class=\"{class}\" endpoint=\"{ep}\"/>\n",
                ep = xml_escape(endpoint),
            )
        })
        .collect()
}

fn describe_test(case: &IdorTestCase) -> String {
    match case.id_format {
        IdFormat::SequentialInteger => {
            format!(
                "Test IDOR on {method} {endpoint}: try incrementing the numeric ID to access other users' resources",
                method = case.method,
                endpoint = case.endpoint,
            )
        }
        IdFormat::Uuid => {
            format!(
                "Test IDOR on {method} {endpoint}: if another user's UUID is available, try accessing their resource",
                method = case.method,
                endpoint = case.endpoint,
            )
        }
        IdFormat::Slug => {
            format!(
                "Test IDOR on {method} {endpoint}: enumerate or guess slugs for parameter '{param}'",
                method = case.method,
                endpoint = case.endpoint,
                param = case.parameter,
            )
        }
        IdFormat::Encoded => {
            format!(
                "Test IDOR on {method} {endpoint}: decode or manipulate encoded parameter '{param}' to reference other objects",
                method = case.method,
                endpoint = case.endpoint,
                param = case.parameter,
            )
        }
    }
}

fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
