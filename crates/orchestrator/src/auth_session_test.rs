use std::collections::HashMap;

use aegis_enumeration::auth_flow::{AuthFlow, AuthFlowStep, ExtractionSource, ResponseExtraction};
use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};

use super::auth_session::*;
use super::phase_fuzz::FuzzTransport;

struct MockAuthTransport {
    responses: std::collections::VecDeque<(u16, String, Vec<(String, String)>)>,
}

impl MockAuthTransport {
    fn new(responses: Vec<(u16, String, Vec<(String, String)>)>) -> Self {
        Self {
            responses: responses.into(),
        }
    }
}

impl FuzzTransport for MockAuthTransport {
    async fn send(&mut self, _request: &FuzzRequest) -> Result<FuzzResponse, String> {
        let (status, body, headers) = self
            .responses
            .pop_front()
            .ok_or_else(|| "no more mock responses".to_string())?;
        Ok(FuzzResponse {
            request_id: 0,
            status_code: status,
            body,
            headers,
            response_time: std::time::Duration::from_millis(10),
            body_size_bytes: 0,
        })
    }
}

struct FailingAuthTransport;

impl FuzzTransport for FailingAuthTransport {
    async fn send(&mut self, _request: &FuzzRequest) -> Result<FuzzResponse, String> {
        Err("connection refused".to_string())
    }
}

fn single_step_login_flow() -> AuthFlow {
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
    }
}

fn login_inputs() -> HashMap<String, String> {
    let mut inputs = HashMap::new();
    inputs.insert("username".to_string(), "admin".to_string());
    inputs.insert("password".to_string(), "secret".to_string());
    inputs
}

#[tokio::test]
async fn execute_auth_flow_single_step_login() {
    let flow = single_step_login_flow();
    let mut transport = MockAuthTransport::new(vec![(
        200,
        r#"{"token":"jwt-abc-123"}"#.to_string(),
        vec![],
    )]);

    let session = execute_auth_flow(
        &flow,
        &mut transport,
        &login_inputs(),
        "http://localhost:3000",
    )
    .await
    .unwrap();

    assert!(session.is_valid);
    assert_eq!(session.variables.get("token").unwrap(), "jwt-abc-123");
    assert_eq!(session.headers.len(), 1);
    assert_eq!(session.headers[0].0, "Authorization");
    assert_eq!(session.headers[0].1, "Bearer jwt-abc-123");
}

#[tokio::test]
async fn execute_auth_flow_multi_step() {
    let flow = AuthFlow {
        name: "CSRF Login".to_string(),
        steps: vec![
            AuthFlowStep {
                step_id: "get_csrf".to_string(),
                endpoint: "/csrf".to_string(),
                method: "GET".to_string(),
                body_template: None,
                extract_from_response: vec![ResponseExtraction {
                    variable_name: "csrf_token".to_string(),
                    source: ExtractionSource::Header("X-CSRF-Token".to_string()),
                }],
                expected_status: 200,
            },
            AuthFlowStep {
                step_id: "login".to_string(),
                endpoint: "/login".to_string(),
                method: "POST".to_string(),
                body_template: Some(
                    r#"{"username":"{{username}}","csrf":"{{csrf_token}}"}"#.to_string(),
                ),
                extract_from_response: vec![ResponseExtraction {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::JsonPath("token".to_string()),
                }],
                expected_status: 200,
            },
        ],
        required_inputs: vec!["username".to_string()],
    };

    let mut transport = MockAuthTransport::new(vec![
        (
            200,
            String::new(),
            vec![("X-CSRF-Token".to_string(), "csrf-xyz-789".to_string())],
        ),
        (200, r#"{"token":"jwt-after-csrf"}"#.to_string(), vec![]),
    ]);

    let mut inputs = HashMap::new();
    inputs.insert("username".to_string(), "admin".to_string());

    let session = execute_auth_flow(&flow, &mut transport, &inputs, "http://localhost:3000")
        .await
        .unwrap();

    assert!(session.is_valid);
    assert_eq!(session.variables.get("csrf_token").unwrap(), "csrf-xyz-789");
    assert_eq!(session.variables.get("token").unwrap(), "jwt-after-csrf");
    assert_eq!(session.headers[0].1, "Bearer jwt-after-csrf");
}

#[tokio::test]
async fn execute_auth_flow_cookie_extraction() {
    let flow = AuthFlow {
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
    };

    let mut transport = MockAuthTransport::new(vec![(
        200,
        String::new(),
        vec![(
            "Set-Cookie".to_string(),
            "session=abc123def456; HttpOnly; Secure".to_string(),
        )],
    )]);

    let session = execute_auth_flow(
        &flow,
        &mut transport,
        &login_inputs(),
        "http://localhost:3000",
    )
    .await
    .unwrap();

    assert!(session.is_valid);
    assert_eq!(session.cookies.len(), 1);
    assert_eq!(session.cookies[0].0, "session");
    assert_eq!(session.cookies[0].1, "abc123def456");
    assert!(session.headers.is_empty());
}

#[tokio::test]
async fn execute_auth_flow_step_fails_with_wrong_status() {
    let flow = single_step_login_flow();
    let mut transport = MockAuthTransport::new(vec![(403, "Forbidden".to_string(), vec![])]);

    let err = execute_auth_flow(
        &flow,
        &mut transport,
        &login_inputs(),
        "http://localhost:3000",
    )
    .await
    .unwrap_err();

    match err {
        AuthSessionError::StepFailed {
            step_id,
            expected_status,
            actual_status,
        } => {
            assert_eq!(step_id, "login");
            assert_eq!(expected_status, 200);
            assert_eq!(actual_status, 403);
        }
        other => panic!("expected StepFailed, got: {other}"),
    }
}

#[tokio::test]
async fn execute_auth_flow_extraction_fails() {
    let flow = single_step_login_flow();
    let mut transport = MockAuthTransport::new(vec![(
        200,
        r#"{"no_token_here": true}"#.to_string(),
        vec![],
    )]);

    let err = execute_auth_flow(
        &flow,
        &mut transport,
        &login_inputs(),
        "http://localhost:3000",
    )
    .await
    .unwrap_err();

    match err {
        AuthSessionError::ExtractionFailed {
            step_id,
            variable_name,
        } => {
            assert_eq!(step_id, "login");
            assert_eq!(variable_name, "token");
        }
        other => panic!("expected ExtractionFailed, got: {other}"),
    }
}

#[tokio::test]
async fn execute_auth_flow_transport_error() {
    let flow = single_step_login_flow();
    let mut transport = FailingAuthTransport;

    let err = execute_auth_flow(
        &flow,
        &mut transport,
        &login_inputs(),
        "http://localhost:3000",
    )
    .await
    .unwrap_err();

    match err {
        AuthSessionError::TransportError(msg) => {
            assert!(msg.contains("connection refused"));
        }
        other => panic!("expected TransportError, got: {other}"),
    }
}

#[test]
fn inject_auth_adds_headers_and_cookies() {
    let session = AuthenticatedSession {
        variables: HashMap::new(),
        cookies: vec![("session".to_string(), "abc123".to_string())],
        headers: vec![("Authorization".to_string(), "Bearer jwt-xyz".to_string())],
        is_valid: true,
    };

    let mut request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:3000/api/users".to_string(),
        method: "GET".to_string(),
        parameter_name: "id".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "1".to_string(),
        headers: vec![],
    };

    inject_auth_into_request(&mut request, &session);

    assert_eq!(request.headers.len(), 2);
    assert_eq!(request.headers[0].0, "Authorization");
    assert_eq!(request.headers[0].1, "Bearer jwt-xyz");
    assert_eq!(request.headers[1].0, "Cookie");
    assert_eq!(request.headers[1].1, "session=abc123");
}

#[tokio::test]
async fn execute_auth_flow_validates_flow_first() {
    let flow = AuthFlow {
        name: "Invalid Flow".to_string(),
        steps: vec![AuthFlowStep {
            step_id: String::new(),
            endpoint: "/login".to_string(),
            method: "POST".to_string(),
            body_template: None,
            extract_from_response: vec![],
            expected_status: 200,
        }],
        required_inputs: vec![],
    };

    let mut transport = MockAuthTransport::new(vec![(200, String::new(), vec![])]);
    let err = execute_auth_flow(
        &flow,
        &mut transport,
        &HashMap::new(),
        "http://localhost:3000",
    )
    .await
    .unwrap_err();

    match err {
        AuthSessionError::ValidationFailed(msg) => {
            assert!(msg.contains("empty step_id"), "got: {msg}");
        }
        other => panic!("expected ValidationFailed, got: {other}"),
    }
}

#[tokio::test]
async fn execute_auth_flow_missing_input_variable() {
    let flow = single_step_login_flow();
    let mut incomplete_inputs = HashMap::new();
    incomplete_inputs.insert("username".to_string(), "admin".to_string());

    let mut transport =
        MockAuthTransport::new(vec![(200, r#"{"token":"jwt-abc"}"#.to_string(), vec![])]);

    let err = execute_auth_flow(
        &flow,
        &mut transport,
        &incomplete_inputs,
        "http://localhost:3000",
    )
    .await
    .unwrap_err();

    match err {
        AuthSessionError::TransportError(msg) => {
            assert!(msg.contains("password"), "got: {msg}");
        }
        other => panic!("expected TransportError from render_template, got: {other}"),
    }
}

#[tokio::test]
async fn build_session_bearer_token_from_access_token() {
    let flow = AuthFlow {
        name: "Bearer Token".to_string(),
        steps: vec![AuthFlowStep {
            step_id: "get_token".to_string(),
            endpoint: "/auth/token".to_string(),
            method: "POST".to_string(),
            body_template: Some(
                r#"{"username":"{{username}}","password":"{{password}}"}"#.to_string(),
            ),
            extract_from_response: vec![ResponseExtraction {
                variable_name: "access_token".to_string(),
                source: ExtractionSource::JsonPath("access_token".to_string()),
            }],
            expected_status: 200,
        }],
        required_inputs: vec!["username".to_string(), "password".to_string()],
    };

    let mut transport = MockAuthTransport::new(vec![(
        200,
        r#"{"access_token":"at-9876"}"#.to_string(),
        vec![],
    )]);

    let session = execute_auth_flow(
        &flow,
        &mut transport,
        &login_inputs(),
        "http://localhost:3000",
    )
    .await
    .unwrap();

    assert!(session.is_valid);
    assert_eq!(session.headers.len(), 1);
    assert_eq!(session.headers[0].0, "Authorization");
    assert_eq!(session.headers[0].1, "Bearer at-9876");
    assert_eq!(session.variables.get("access_token").unwrap(), "at-9876");
}

#[test]
fn auth_session_error_display_variants() {
    let validation_err = AuthSessionError::ValidationFailed("bad flow".to_string());
    assert_eq!(
        validation_err.to_string(),
        "auth flow validation failed: bad flow"
    );

    let step_err = AuthSessionError::StepFailed {
        step_id: "login".to_string(),
        expected_status: 200,
        actual_status: 500,
    };
    assert_eq!(
        step_err.to_string(),
        "step 'login' failed: expected status 200, got 500"
    );

    let extraction_err = AuthSessionError::ExtractionFailed {
        step_id: "login".to_string(),
        variable_name: "token".to_string(),
    };
    assert_eq!(
        extraction_err.to_string(),
        "extraction failed in step 'login': could not extract 'token'"
    );

    let transport_err = AuthSessionError::TransportError("timeout".to_string());
    assert_eq!(transport_err.to_string(), "transport error: timeout");
}
