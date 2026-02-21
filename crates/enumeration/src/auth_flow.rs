use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// A single step in a multi-step authentication flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlowStep {
    pub step_id: String,
    pub endpoint: String,
    pub method: String,
    pub body_template: Option<String>,
    pub extract_from_response: Vec<ResponseExtraction>,
    pub expected_status: u16,
}

/// Describes how to extract a value from an HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseExtraction {
    pub variable_name: String,
    pub source: ExtractionSource,
}

/// Where to extract a value from in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionSource {
    Header(String),
    JsonPath(String),
    Cookie(String),
    StatusCode,
}

/// An ordered multi-step authentication flow definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlow {
    pub name: String,
    pub steps: Vec<AuthFlowStep>,
    pub required_inputs: Vec<String>,
}

/// Runtime state accumulated while executing an auth flow.
#[derive(Debug, Clone)]
pub struct AuthFlowState {
    pub variables: HashMap<String, String>,
    pub completed_steps: Vec<String>,
    pub is_authenticated: bool,
}

/// Errors that occur during auth flow validation or execution.
#[derive(Debug)]
pub enum AuthFlowError {
    MissingVariable(String),
    StepFailed {
        step_id: String,
        expected_status: u16,
        actual_status: u16,
    },
    ExtractionFailed {
        step_id: String,
        variable_name: String,
    },
    InvalidJsonPath(String),
}

impl fmt::Display for AuthFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVariable(name) => {
                write!(f, "missing variable: {name}")
            }
            Self::StepFailed {
                step_id,
                expected_status,
                actual_status,
            } => {
                write!(
                    f,
                    "step '{step_id}' failed: expected status {expected_status}, got {actual_status}"
                )
            }
            Self::ExtractionFailed {
                step_id,
                variable_name,
            } => {
                write!(
                    f,
                    "extraction failed in step '{step_id}': could not extract '{variable_name}'"
                )
            }
            Self::InvalidJsonPath(path) => {
                write!(f, "invalid json path: {path}")
            }
        }
    }
}

impl std::error::Error for AuthFlowError {}

/// Authentication vulnerability types discoverable through flow analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthFlowVulnerability {
    SessionFixation,
    TokenReuseAfterLogout,
    MissingTokenRotation,
    WeakSessionId,
    InsecureCookieAttributes,
}

impl fmt::Display for AuthFlowVulnerability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SessionFixation => "session-fixation",
            Self::TokenReuseAfterLogout => "token-reuse-after-logout",
            Self::MissingTokenRotation => "missing-token-rotation",
            Self::WeakSessionId => "weak-session-id",
            Self::InsecureCookieAttributes => "insecure-cookie-attributes",
        };
        write!(f, "{label}")
    }
}

/// A concrete finding from auth flow vulnerability detection.
#[derive(Debug, Clone)]
pub struct AuthFlowFinding {
    pub vulnerability: AuthFlowVulnerability,
    pub flow_name: String,
    pub affected_step: String,
    pub description: String,
    pub evidence: String,
}

/// Replace `{{variable_name}}` placeholders in a template with values from the map.
pub fn render_template(
    template: &str,
    variables: &HashMap<String, String>,
) -> Result<String, AuthFlowError> {
    let mut result = template.to_string();
    let mut start = 0;

    while let Some(open) = result[start..].find("{{") {
        let open_abs = start + open;
        let after_open = open_abs + 2;
        let Some(close) = result[after_open..].find("}}") else {
            break;
        };
        let close_abs = after_open + close;
        let var_name = &result[after_open..close_abs];
        let value = variables
            .get(var_name)
            .ok_or_else(|| AuthFlowError::MissingVariable(var_name.to_string()))?;
        result.replace_range(open_abs..close_abs + 2, value);
        start = open_abs + value.len();
    }

    Ok(result)
}

/// Extract a value from a simulated HTTP response based on the extraction source.
pub fn extract_value(
    source: &ExtractionSource,
    status_code: u16,
    headers: &[(String, String)],
    body: &str,
) -> Option<String> {
    match source {
        ExtractionSource::Header(name) => {
            let lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == lower)
                .map(|(_, v)| v.clone())
        }
        ExtractionSource::JsonPath(path) => extract_json_path(body, path),
        ExtractionSource::Cookie(name) => extract_cookie_value(headers, name),
        ExtractionSource::StatusCode => Some(status_code.to_string()),
    }
}

fn extract_json_path(body: &str, path: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut current = &parsed;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        current = current.get(segment)?;
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn extract_cookie_value(headers: &[(String, String)], cookie_name: &str) -> Option<String> {
    for (key, value) in headers {
        if key.to_lowercase() != "set-cookie" {
            continue;
        }
        let cookie_part = value.split(';').next()?;
        if let Some((name, val)) = cookie_part.split_once('=')
            && name.trim() == cookie_name
        {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Validate an auth flow definition for structural correctness.
pub fn validate_auth_flow(flow: &AuthFlow) -> Result<(), AuthFlowError> {
    let mut seen_ids = HashSet::new();
    let mut available_vars: HashSet<&str> =
        flow.required_inputs.iter().map(|s| s.as_str()).collect();

    for input in &flow.required_inputs {
        if input.is_empty() {
            return Err(AuthFlowError::MissingVariable(
                "empty required_input".to_string(),
            ));
        }
    }

    for step in &flow.steps {
        if step.step_id.is_empty() {
            return Err(AuthFlowError::MissingVariable("empty step_id".to_string()));
        }
        if step.endpoint.is_empty() {
            return Err(AuthFlowError::MissingVariable("empty endpoint".to_string()));
        }
        if step.method.is_empty() {
            return Err(AuthFlowError::MissingVariable("empty method".to_string()));
        }
        if !seen_ids.insert(&step.step_id) {
            return Err(AuthFlowError::MissingVariable(format!(
                "duplicate step_id: {}",
                step.step_id
            )));
        }

        if let Some(ref tmpl) = step.body_template {
            check_template_vars(tmpl, &available_vars)?;
        }

        for extraction in &step.extract_from_response {
            available_vars.insert(&extraction.variable_name);
        }
    }

    Ok(())
}

fn check_template_vars(template: &str, available: &HashSet<&str>) -> Result<(), AuthFlowError> {
    let mut start = 0;
    while let Some(open) = template[start..].find("{{") {
        let open_abs = start + open;
        let after_open = open_abs + 2;
        let Some(close) = template[after_open..].find("}}") else {
            break;
        };
        let close_abs = after_open + close;
        let var_name = &template[after_open..close_abs];
        if !available.contains(var_name) {
            return Err(AuthFlowError::MissingVariable(var_name.to_string()));
        }
        start = close_abs + 2;
    }
    Ok(())
}

/// Detect session fixation: session ID unchanged after login.
pub fn detect_session_fixation(
    pre_login_session: Option<&str>,
    post_login_session: Option<&str>,
) -> Option<AuthFlowFinding> {
    let (pre, post) = (pre_login_session?, post_login_session?);
    if pre == post {
        Some(AuthFlowFinding {
            vulnerability: AuthFlowVulnerability::SessionFixation,
            flow_name: String::new(),
            affected_step: "login".to_string(),
            description: "session ID did not change after authentication".to_string(),
            evidence: format!("pre-login and post-login session ID both: {pre}"),
        })
    } else {
        None
    }
}

const MIN_SESSION_ID_LENGTH: usize = 16;

/// Detect weak session IDs based on length and character composition.
pub fn detect_weak_session_id(session_id: &str) -> Option<AuthFlowFinding> {
    if session_id.len() < MIN_SESSION_ID_LENGTH {
        return Some(AuthFlowFinding {
            vulnerability: AuthFlowVulnerability::WeakSessionId,
            flow_name: String::new(),
            affected_step: "login".to_string(),
            description: "session ID is too short".to_string(),
            evidence: format!(
                "length {} < minimum {}",
                session_id.len(),
                MIN_SESSION_ID_LENGTH
            ),
        });
    }

    if session_id.chars().all(|c| c.is_ascii_digit()) {
        return Some(AuthFlowFinding {
            vulnerability: AuthFlowVulnerability::WeakSessionId,
            flow_name: String::new(),
            affected_step: "login".to_string(),
            description: "session ID contains only digits".to_string(),
            evidence: format!("all-digit session ID: {session_id}"),
        });
    }

    None
}

/// Detect insecure cookie attributes from a Set-Cookie header value.
pub fn detect_insecure_cookie(set_cookie_header: &str) -> Vec<AuthFlowVulnerability> {
    let lower = set_cookie_header.to_lowercase();
    let mut issues = Vec::new();

    if !lower.contains("secure") {
        issues.push(AuthFlowVulnerability::InsecureCookieAttributes);
    }
    if !lower.contains("httponly") {
        issues.push(AuthFlowVulnerability::InsecureCookieAttributes);
    }
    if !lower.contains("samesite") {
        issues.push(AuthFlowVulnerability::InsecureCookieAttributes);
    }

    issues
}

/// Return predefined common authentication flow templates.
pub fn common_auth_flows() -> Vec<AuthFlow> {
    vec![
        AuthFlow {
            name: "Basic Login".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "login".to_string(),
                endpoint: "/login".to_string(),
                method: "POST".to_string(),
                body_template: Some(
                    r#"{"username":"{{username}}","password":"{{password}}"}"#.to_string(),
                ),
                extract_from_response: vec![ResponseExtraction {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::JsonPath("token".to_string()),
                }],
                expected_status: 200,
            }],
            required_inputs: vec!["username".to_string(), "password".to_string()],
        },
        AuthFlow {
            name: "Bearer Token".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "get_token".to_string(),
                endpoint: "/auth/token".to_string(),
                method: "POST".to_string(),
                body_template: Some(
                    r#"{"username":"{{username}}","password":"{{password}}"}"#.to_string(),
                ),
                extract_from_response: vec![
                    ResponseExtraction {
                        variable_name: "access_token".to_string(),
                        source: ExtractionSource::JsonPath("access_token".to_string()),
                    },
                    ResponseExtraction {
                        variable_name: "refresh_token".to_string(),
                        source: ExtractionSource::JsonPath("refresh_token".to_string()),
                    },
                ],
                expected_status: 200,
            }],
            required_inputs: vec!["username".to_string(), "password".to_string()],
        },
        AuthFlow {
            name: "Cookie Session".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "login".to_string(),
                endpoint: "/login".to_string(),
                method: "POST".to_string(),
                body_template: Some(
                    r#"{"username":"{{username}}","password":"{{password}}"}"#.to_string(),
                ),
                extract_from_response: vec![ResponseExtraction {
                    variable_name: "session_id".to_string(),
                    source: ExtractionSource::Cookie("session".to_string()),
                }],
                expected_status: 200,
            }],
            required_inputs: vec!["username".to_string(), "password".to_string()],
        },
    ]
}
