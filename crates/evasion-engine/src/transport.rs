use std::time::{Duration, Instant};

use reqwest::Client;

use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};
use aegis_protocol::scope_attestation::SignedScopeAttestation;

use crate::header_transformer::HeaderTransformer;
use crate::http2_fingerprint::{Http2Fingerprint, h2_fingerprint_for_persona};
use crate::persona::Persona;
use crate::session_manager::SessionManager;
use crate::timing_controller::TimingController;

#[derive(Debug)]
pub enum TransportError {
    NetworkError(String),
    Timeout(String),
    BuildError(String),
    TargetNotAllowed(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::BuildError(msg) => write!(f, "build error: {msg}"),
            Self::TargetNotAllowed(msg) => write!(f, "target not allowed: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

pub struct EvasionTransport {
    client: Client,
    header_transformer: HeaderTransformer,
    timing: TimingController,
    session: SessionManager,
    persona: Persona,
    persona_catalog: Vec<Persona>,
    current_persona_index: usize,
    persona_rotation_interval: Option<u32>,
    sessions_since_rotation: u32,
    scope_attestation: Option<SignedScopeAttestation>,
    operator_authorized: bool,
    h2_fingerprint: Http2Fingerprint,
}

impl EvasionTransport {
    pub fn builder() -> EvasionTransportBuilder {
        EvasionTransportBuilder {
            persona: None,
            persona_catalog_path: None,
            max_requests_per_session: 50,
            timing_seed: 0,
            persona_rotation_interval: None,
            accept_self_signed: false,
            scope_attestation: None,
            operator_authorized: false,
        }
    }

    pub async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, TransportError> {
        aegis_protocol::target_validation::validate_target_with_override(
            &request.endpoint,
            self.scope_attestation.as_ref(),
            self.operator_authorized,
        )
        .map_err(|e| TransportError::TargetNotAllowed(e.to_string()))?;

        let delay_ms = self.timing.compute_delay_ms();
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let session_headers = self.session.session_headers();
        let all_headers = merge_headers(&request.headers, &session_headers);
        let transformed = self.transform_headers(&all_headers);
        let reqwest_request = self.build_reqwest_request(request, &transformed)?;

        let start = Instant::now();
        let response = self.execute_request(reqwest_request).await?;
        let response_time = start.elapsed();

        self.timing.record_request();
        let session_before = self.session.session_id();
        self.session.record_request(&request.endpoint);
        let session_rotated = self.session.session_id() != session_before;

        if session_rotated {
            self.maybe_rotate_persona();
        }

        self.process_response_cookies(&response);
        map_response(response, request.request_id, response_time).await
    }

    pub fn persona_id(&self) -> crate::persona::PersonaId {
        self.persona.id
    }

    pub fn session_id(&self) -> u64 {
        self.session.session_id()
    }

    pub fn reset_session(&mut self) {
        self.session.rotate_session();
    }

    /// Returns the HTTP/2 fingerprint currently in use by this transport.
    ///
    /// The fingerprint matches the active persona's browser identity and
    /// contains SETTINGS, WINDOW_UPDATE, PRIORITY, and pseudo-header ordering
    /// parameters that should be applied at the HTTP/2 connection level.
    pub fn h2_fingerprint(&self) -> &Http2Fingerprint {
        &self.h2_fingerprint
    }

    fn maybe_rotate_persona(&mut self) {
        if let Some(interval) = self.persona_rotation_interval {
            self.sessions_since_rotation += 1;
            if self.sessions_since_rotation >= interval {
                self.sessions_since_rotation = 0;
                self.current_persona_index =
                    (self.current_persona_index + 1) % self.persona_catalog.len();
                self.persona = self.persona_catalog[self.current_persona_index].clone();
                self.header_transformer = HeaderTransformer::new();
                self.timing = TimingController::from_persona(&self.persona, 0);
                self.h2_fingerprint = h2_fingerprint_for_persona(self.persona.id);
            }
        }
    }

    fn transform_headers(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        if let Some(referer) = self.session.last_url() {
            self.header_transformer
                .transform_with_referer(headers, &self.persona, referer)
                .headers
        } else {
            self.header_transformer
                .transform(headers, &self.persona)
                .headers
        }
    }

    fn build_reqwest_request(
        &self,
        request: &FuzzRequest,
        transformed_headers: &[(String, String)],
    ) -> Result<reqwest::Request, TransportError> {
        let method = parse_method(&request.method)?;
        let (url, body, extra_headers) = resolve_parameter_injection(request);
        let mut builder = self.client.request(method, &url);

        for (key, value) in transformed_headers {
            builder = builder.header(key, value);
        }
        for (key, value) in &extra_headers {
            builder = builder.header(key, value);
        }
        if let Some(body_str) = body {
            builder = builder.body(body_str);
        }

        builder
            .build()
            .map_err(|e| TransportError::BuildError(e.to_string()))
    }

    async fn execute_request(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, TransportError> {
        self.client.execute(request).await.map_err(|e| {
            if e.is_timeout() {
                TransportError::Timeout(e.to_string())
            } else {
                TransportError::NetworkError(e.to_string())
            }
        })
    }

    fn process_response_cookies(&mut self, response: &reqwest::Response) {
        for value in response.headers().get_all("set-cookie") {
            if let Ok(cookie_str) = value.to_str() {
                self.session.process_set_cookie(cookie_str);
            }
        }
    }
}

fn resolve_parameter_injection(
    request: &FuzzRequest,
) -> (String, Option<String>, Vec<(String, String)>) {
    match request.parameter_location {
        ParameterLocation::Query => {
            let url = if request.parameter_name.is_empty() {
                request.endpoint.clone()
            } else {
                format!(
                    "{}?{}={}",
                    request.endpoint, request.parameter_name, request.payload
                )
            };
            (url, None, vec![])
        }
        ParameterLocation::Body => {
            let body = if request.parameter_name.is_empty() {
                request.payload.clone()
            } else {
                serde_json::json!({ &request.parameter_name: &request.payload }).to_string()
            };
            (
                request.endpoint.clone(),
                Some(body),
                vec![("Content-Type".to_string(), "application/json".to_string())],
            )
        }
        ParameterLocation::Path => {
            let url = request
                .endpoint
                .replace(&format!("{{{}}}", request.parameter_name), &request.payload);
            (url, None, vec![])
        }
        ParameterLocation::Header => {
            let extra = vec![(request.parameter_name.clone(), request.payload.clone())];
            (request.endpoint.clone(), None, extra)
        }
        ParameterLocation::Cookie => {
            let extra = vec![(
                "Cookie".to_string(),
                format!("{}={}", request.parameter_name, request.payload),
            )];
            (request.endpoint.clone(), None, extra)
        }
    }
}

async fn map_response(
    response: reqwest::Response,
    request_id: u64,
    response_time: Duration,
) -> Result<FuzzResponse, TransportError> {
    let status_code = response.status().as_u16();
    let headers = extract_response_headers(&response);
    let body = response
        .text()
        .await
        .map_err(|e| TransportError::NetworkError(e.to_string()))?;
    let body_size_bytes = body.len();

    Ok(FuzzResponse {
        request_id,
        status_code,
        body,
        headers,
        response_time,
        body_size_bytes,
    })
}

fn extract_response_headers(response: &reqwest::Response) -> Vec<(String, String)> {
    response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

fn merge_headers(
    request_headers: &[(String, String)],
    session_headers: &[(String, String)],
) -> Vec<(String, String)> {
    let mut merged = request_headers.to_vec();
    for header in session_headers {
        let already_present = merged
            .iter()
            .any(|(k, _)| k.to_lowercase() == header.0.to_lowercase());
        if !already_present {
            merged.push(header.clone());
        }
    }
    merged
}

fn parse_method(method: &str) -> Result<reqwest::Method, TransportError> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        other => Err(TransportError::BuildError(format!(
            "unsupported HTTP method: {other}"
        ))),
    }
}

#[cfg(test)]
#[path = "transport_test.rs"]
mod transport_test;

pub struct EvasionTransportBuilder {
    persona: Option<Persona>,
    persona_catalog_path: Option<std::path::PathBuf>,
    max_requests_per_session: u32,
    timing_seed: u64,
    persona_rotation_interval: Option<u32>,
    accept_self_signed: bool,
    scope_attestation: Option<SignedScopeAttestation>,
    operator_authorized: bool,
}

impl EvasionTransportBuilder {
    pub fn with_persona(mut self, persona: &Persona) -> Self {
        self.persona = Some(persona.clone());
        self
    }

    pub fn with_max_requests_per_session(mut self, n: u32) -> Self {
        self.max_requests_per_session = n;
        self
    }

    pub fn with_timing_seed(mut self, seed: u64) -> Self {
        self.timing_seed = seed;
        self
    }

    pub fn with_persona_rotation(mut self, interval: u32) -> Self {
        self.persona_rotation_interval = Some(interval);
        self
    }

    /// Accept invalid TLS certificates (e.g. self-signed) when connecting.
    /// Only safe because `send()` enforces target validation via `validate_target`.
    pub fn with_accept_self_signed(mut self, accept: bool) -> Self {
        self.accept_self_signed = accept;
        self
    }

    /// Attach a signed scope attestation for remote target validation.
    /// When set, `send()` will allow non-localhost targets that match the attestation.
    pub fn with_scope_attestation(mut self, attestation: SignedScopeAttestation) -> Self {
        self.scope_attestation = Some(attestation);
        self
    }

    /// Load personas from a custom JSON catalog file instead of the embedded default.
    pub fn with_persona_catalog(mut self, path: &std::path::Path) -> Self {
        self.persona_catalog_path = Some(path.to_path_buf());
        self
    }

    /// Allow remote (non-localhost) targets via operator self-authorization.
    /// When set, `send()` skips the localhost check if no attestation is present.
    pub fn with_operator_authorized(mut self, authorized: bool) -> Self {
        self.operator_authorized = authorized;
        self
    }

    pub fn build(self) -> EvasionTransport {
        let catalog = crate::persona::load_persona_catalog(self.persona_catalog_path.as_deref())
            .expect("persona catalog must be valid");
        let persona = self.persona.unwrap_or_else(|| catalog[0].clone());

        let timing = TimingController::from_persona(&persona, self.timing_seed);
        let h2_fingerprint = h2_fingerprint_for_persona(persona.id);

        let client = Client::builder()
            .danger_accept_invalid_certs(self.accept_self_signed)
            .build()
            .expect("failed to build reqwest client");

        EvasionTransport {
            client,
            header_transformer: HeaderTransformer::new(),
            timing,
            session: SessionManager::new(self.max_requests_per_session),
            persona,
            persona_catalog: catalog,
            current_persona_index: 0,
            persona_rotation_interval: self.persona_rotation_interval,
            sessions_since_rotation: 0,
            scope_attestation: self.scope_attestation,
            operator_authorized: self.operator_authorized,
            h2_fingerprint,
        }
    }
}
