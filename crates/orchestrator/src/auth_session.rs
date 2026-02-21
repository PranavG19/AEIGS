use std::collections::HashMap;
use std::fmt;

use aegis_enumeration::auth_flow::{
    AuthFlow, AuthFlowState, ExtractionSource, extract_value, render_template, validate_auth_flow,
};
use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};

use crate::phase_fuzz::FuzzTransport;

/// A session established by executing an authentication flow against a live target.
///
/// Contains extracted tokens, cookies, and headers ready for injection into
/// subsequent fuzz requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub variables: HashMap<String, String>,
    pub cookies: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub is_valid: bool,
}

/// Errors that can occur during auth session establishment.
#[derive(Debug)]
pub enum AuthSessionError {
    ValidationFailed(String),
    StepFailed {
        step_id: String,
        expected_status: u16,
        actual_status: u16,
    },
    ExtractionFailed {
        step_id: String,
        variable_name: String,
    },
    TransportError(String),
}

impl fmt::Display for AuthSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed(msg) => write!(f, "auth flow validation failed: {msg}"),
            Self::StepFailed {
                step_id,
                expected_status,
                actual_status,
            } => write!(
                f,
                "step '{step_id}' failed: expected status {expected_status}, got {actual_status}"
            ),
            Self::ExtractionFailed {
                step_id,
                variable_name,
            } => write!(
                f,
                "extraction failed in step '{step_id}': could not extract '{variable_name}'"
            ),
            Self::TransportError(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

impl std::error::Error for AuthSessionError {}

/// Execute an authentication flow against a live target, returning an authenticated session.
///
/// Validates the flow definition, then executes each step sequentially,
/// extracting variables from responses and accumulating session state.
pub async fn execute_auth_flow<T: FuzzTransport>(
    flow: &AuthFlow,
    transport: &mut T,
    inputs: &HashMap<String, String>,
    target_base: &str,
) -> Result<AuthenticatedSession, AuthSessionError> {
    validate_auth_flow(flow).map_err(|e| AuthSessionError::ValidationFailed(e.to_string()))?;

    let mut state = AuthFlowState {
        variables: inputs.clone(),
        completed_steps: Vec::new(),
        is_authenticated: false,
    };

    for step in &flow.steps {
        let body = render_step_body(&step.body_template, &state.variables)?;
        let request = build_step_request(target_base, &step.endpoint, &step.method, &body);
        let response = send_step_request(transport, &request).await?;

        verify_status_code(&step.step_id, step.expected_status, response.status_code)?;
        extract_step_variables(&step.step_id, step, &response, &mut state.variables)?;
        state.completed_steps.push(step.step_id.clone());
    }

    state.is_authenticated = true;
    Ok(build_authenticated_session(&state.variables, flow))
}

/// Inject authentication headers and cookies into a fuzz request.
pub fn inject_auth_into_request(request: &mut FuzzRequest, session: &AuthenticatedSession) {
    for (name, value) in &session.headers {
        request.headers.push((name.clone(), value.clone()));
    }
    for (name, value) in &session.cookies {
        request
            .headers
            .push(("Cookie".to_string(), format!("{name}={value}")));
    }
}

const BEARER_TOKEN_VARIABLE_NAMES: [&str; 3] = ["token", "access_token", "bearer_token"];

fn build_authenticated_session(
    variables: &HashMap<String, String>,
    flow: &AuthFlow,
) -> AuthenticatedSession {
    let mut headers = Vec::new();
    for name in &BEARER_TOKEN_VARIABLE_NAMES {
        if let Some(value) = variables.get(*name) {
            headers.push(("Authorization".to_string(), format!("Bearer {value}")));
            break;
        }
    }

    let mut cookies = Vec::new();
    for step in &flow.steps {
        for extraction in &step.extract_from_response {
            if let ExtractionSource::Cookie(cookie_name) = &extraction.source
                && let Some(value) = variables.get(&extraction.variable_name)
            {
                cookies.push((cookie_name.clone(), value.clone()));
            }
        }
    }

    AuthenticatedSession {
        variables: variables.clone(),
        cookies,
        headers,
        is_valid: true,
    }
}

fn render_step_body(
    body_template: &Option<String>,
    variables: &HashMap<String, String>,
) -> Result<String, AuthSessionError> {
    match body_template {
        Some(tmpl) => render_template(tmpl, variables)
            .map_err(|e| AuthSessionError::TransportError(e.to_string())),
        None => Ok(String::new()),
    }
}

fn build_step_request(target_base: &str, endpoint: &str, method: &str, body: &str) -> FuzzRequest {
    let mut headers = Vec::new();
    if !body.is_empty() {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    FuzzRequest {
        request_id: 0,
        endpoint: format!("{target_base}{endpoint}"),
        method: method.to_string(),
        parameter_name: String::new(),
        parameter_location: ParameterLocation::Body,
        payload: body.to_string(),
        headers,
    }
}

async fn send_step_request<T: FuzzTransport>(
    transport: &mut T,
    request: &FuzzRequest,
) -> Result<FuzzResponse, AuthSessionError> {
    transport
        .send(request)
        .await
        .map_err(AuthSessionError::TransportError)
}

fn verify_status_code(
    step_id: &str,
    expected_status: u16,
    actual_status: u16,
) -> Result<(), AuthSessionError> {
    if actual_status != expected_status {
        return Err(AuthSessionError::StepFailed {
            step_id: step_id.to_string(),
            expected_status,
            actual_status,
        });
    }
    Ok(())
}

fn extract_step_variables(
    step_id: &str,
    step: &aegis_enumeration::auth_flow::AuthFlowStep,
    response: &FuzzResponse,
    variables: &mut HashMap<String, String>,
) -> Result<(), AuthSessionError> {
    for extraction in &step.extract_from_response {
        let value = extract_value(
            &extraction.source,
            response.status_code,
            &response.headers,
            &response.body,
        )
        .ok_or_else(|| AuthSessionError::ExtractionFailed {
            step_id: step_id.to_string(),
            variable_name: extraction.variable_name.clone(),
        })?;
        variables.insert(extraction.variable_name.clone(), value);
    }
    Ok(())
}
