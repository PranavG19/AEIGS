use std::time::{Duration, Instant};

use reqwest::Client;

use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};
use aegis_protocol::scope_attestation::SignedScopeAttestation;

use crate::header_transformer::HeaderTransformer;
use crate::http2_fingerprint::{Http2Fingerprint, h2_fingerprint_for_persona};
use crate::identity_rotation::{IdentityRotationConfig, IdentityRotationEngine};
use crate::persona::Persona;
use crate::proxy_chain::{ProxyChainConfig, ProxyChainManager, ProxyChainPath};
use crate::rate_adaptive_throttle::{RateAdaptiveThrottle, RateLimitSignal, AdaptiveThrottleConfig};
use crate::session_compartment::{SessionCompartment, SessionCompartmentConfig, SessionIdentity};
use crate::session_manager::SessionManager;
use crate::timing_controller::TimingController;
use crate::traffic_shaper::{TrafficShaper, TrafficShaperConfig};

/// Errors that can occur during evasion transport request execution.
#[derive(Debug)]
pub enum TransportError {
    NetworkError(String),
    Timeout(String),
    BuildError(String),
    TargetNotAllowed(String),
    ProxyExhausted(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::BuildError(msg) => write!(f, "build error: {msg}"),
            Self::TargetNotAllowed(msg) => write!(f, "target not allowed: {msg}"),
            Self::ProxyExhausted(msg) => write!(f, "proxy exhausted: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// HTTP transport layer with integrated evasion capabilities.
///
/// Wraps a `reqwest::Client` with persona-based header transformation,
/// timing jitter, session management, cookie tracking, persona rotation,
/// HTTP/2 fingerprint matching, and target validation (localhost-only by
/// default, remote via scope attestation or operator authorization).
/// Construct via `EvasionTransport::builder()`.
pub struct EvasionTransport {
    client: Client,
    header_transformer: HeaderTransformer,
    timing: TimingController,
    traffic_shaper: TrafficShaper,
    rate_throttle: RateAdaptiveThrottle,
    session: SessionManager,
    persona: Persona,
    persona_catalog: Vec<Persona>,
    current_persona_index: usize,
    persona_rotation_interval: Option<u32>,
    sessions_since_rotation: u32,
    scope_attestation: Option<SignedScopeAttestation>,
    operator_authorized: bool,
    h2_fingerprint: Http2Fingerprint,
    proxy_manager: Option<ProxyChainManager>,
    active_proxy_chain: Option<ProxyChainPath>,
    accept_self_signed: bool,
    session_compartment: SessionCompartment,
    identity_engine: Option<IdentityRotationEngine>,
    active_session_identity: Option<SessionIdentity>,
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
            proxy_manager: None,
            traffic_shaper_config: None,
            throttle_config: None,
            identity_rotation_config: None,
            session_compartment_config: None,
        }
    }

    pub async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, TransportError> {
        aegis_protocol::target_validation::validate_target_with_override(
            &request.endpoint,
            self.scope_attestation.as_ref(),
            self.operator_authorized,
        )
        .map_err(|e| TransportError::TargetNotAllowed(e.to_string()))?;

        let shaper_delay = self.traffic_shaper.next_delay_ms();
        let throttle_delay = self.rate_throttle.delay_ms(&request.endpoint);
        let timing_delay = self.timing.compute_delay_ms();
        let delay_ms = shaper_delay.max(throttle_delay).max(timing_delay);
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
        let status_code = response.status().as_u16();

        let signal = match status_code {
            429 => RateLimitSignal::HardLimit,
            403 => RateLimitSignal::SoftLimit,
            _ if status_code >= 200 && status_code < 400 => RateLimitSignal::Ok,
            _ => RateLimitSignal::Ok,
        };
        self.rate_throttle.report(&request.endpoint, signal);

        if ProxyChainManager::should_rotate_on_status(status_code) {
            self.rotate_proxy_chain(&request.endpoint);
        }

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

    /// Sends cover traffic requests to mask attack patterns.
    /// Generates benign requests interleaved with actual scan traffic.
    pub async fn send_cover_traffic(&mut self, base_url: &str, count: usize) -> Vec<Result<FuzzResponse, TransportError>> {
        let cover_requests = self.traffic_shaper.generate_cover_traffic(base_url, count);
        let mut results = Vec::with_capacity(cover_requests.len());
        for cover in &cover_requests {
            let fuzz_request = FuzzRequest {
                request_id: 0,
                endpoint: cover.url.clone(),
                method: "GET".to_string(),
                parameter_name: String::new(),
                parameter_location: ParameterLocation::Query,
                payload: String::new(),
                headers: cover.referer.as_ref().map(|r| vec![("Referer".to_string(), r.clone())]).unwrap_or_default(),
            };
            results.push(self.send(&fuzz_request).await);
        }
        results
    }

    /// Returns the number of cover requests needed before the next attack request.
    pub fn cover_requests_needed(&self) -> usize {
        self.traffic_shaper.cover_requests_needed()
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

                if let Some(ref mut engine) = self.identity_engine {
                    engine.record_use();
                }

                let new_identity = self.session_compartment.create_session();
                self.active_session_identity = Some(new_identity);

                self.rebuild_client();
            }
        }
    }

    /// Rotate the proxy chain for the given target, burning the current exit node.
    fn rotate_proxy_chain(&mut self, target: &str) {
        if let Some(ref mut manager) = self.proxy_manager {
            if let Some(ref current_chain) = self.active_proxy_chain.take() {
                let new_chain = manager.rotate_on_detection(target, current_chain);
                self.active_proxy_chain = new_chain;
            } else {
                let new_chain = manager.build_chain(target);
                self.active_proxy_chain = new_chain;
            }
            self.rebuild_client();
        }
    }

    /// Rebuild the reqwest Client with current proxy settings.
    fn rebuild_client(&mut self) {
        let mut builder = Client::builder()
            .danger_accept_invalid_certs(self.accept_self_signed);

        if let (Some(manager), Some(chain)) = (&self.proxy_manager, &self.active_proxy_chain) {
            if let Some(proxy) = manager.build_reqwest_proxy(chain) {
                builder = builder.proxy(proxy);
            }
        }

        if let Ok(new_client) = builder.build() {
            self.client = new_client;
        }
    }

    /// Returns a reference to the proxy chain manager, if configured.
    pub fn proxy_manager(&self) -> Option<&ProxyChainManager> {
        self.proxy_manager.as_ref()
    }

    /// Returns a mutable reference to the proxy chain manager.
    pub fn proxy_manager_mut(&mut self) -> Option<&mut ProxyChainManager> {
        self.proxy_manager.as_mut()
    }

    /// Returns the active proxy chain path, if any.
    pub fn active_proxy_chain(&self) -> Option<&ProxyChainPath> {
        self.active_proxy_chain.as_ref()
    }

    /// Returns a reference to the rate adaptive throttle.
    pub fn rate_throttle(&self) -> &RateAdaptiveThrottle {
        &self.rate_throttle
    }

    /// Returns a reference to the traffic shaper.
    pub fn traffic_shaper(&self) -> &TrafficShaper {
        &self.traffic_shaper
    }

    /// Returns the active compartmented session identity, if any.
    pub fn active_session_identity(&self) -> Option<&SessionIdentity> {
        self.active_session_identity.as_ref()
    }

    /// Returns a reference to the session compartment manager.
    pub fn session_compartment(&self) -> &SessionCompartment {
        &self.session_compartment
    }

    /// Returns a reference to the identity rotation engine, if configured.
    pub fn identity_engine(&self) -> Option<&IdentityRotationEngine> {
        self.identity_engine.as_ref()
    }

    /// Explicitly rotates the identity, destroying the current session
    /// and rebuilding the client with a fresh fingerprint.
    pub fn rotate_identity(&mut self) {
        if let Some(ref id) = self.active_session_identity.take() {
            self.session_compartment.destroy_session(&id.session_id);
        }
        if let Some(ref mut engine) = self.identity_engine {
            engine.rotate();
        }
        let new_identity = self.session_compartment.create_session();
        self.active_session_identity = Some(new_identity);
        self.session.rotate_session();
        self.rebuild_client();
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

/// Builder for `EvasionTransport` with `with_*` configuration methods.
///
/// Defaults to the first persona in the embedded catalog, 50 requests per
/// session, no persona rotation, strict TLS validation, and localhost-only
/// target restriction.
pub struct EvasionTransportBuilder {
    persona: Option<Persona>,
    persona_catalog_path: Option<std::path::PathBuf>,
    max_requests_per_session: u32,
    timing_seed: u64,
    persona_rotation_interval: Option<u32>,
    accept_self_signed: bool,
    scope_attestation: Option<SignedScopeAttestation>,
    operator_authorized: bool,
    proxy_manager: Option<ProxyChainManager>,
    traffic_shaper_config: Option<TrafficShaperConfig>,
    throttle_config: Option<AdaptiveThrottleConfig>,
    identity_rotation_config: Option<IdentityRotationConfig>,
    session_compartment_config: Option<SessionCompartmentConfig>,
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

    /// Attach a pre-configured proxy chain manager for proxy rotation.
    pub fn with_proxy_manager(mut self, manager: ProxyChainManager) -> Self {
        self.proxy_manager = Some(manager);
        self
    }

    /// Set traffic shaper configuration for human-like timing.
    pub fn with_traffic_shaper(mut self, config: TrafficShaperConfig) -> Self {
        self.traffic_shaper_config = Some(config);
        self
    }

    /// Set adaptive rate throttle configuration.
    pub fn with_rate_throttle(mut self, config: AdaptiveThrottleConfig) -> Self {
        self.throttle_config = Some(config);
        self
    }

    /// Enable identity rotation with the given configuration.
    pub fn with_identity_rotation(mut self, config: IdentityRotationConfig) -> Self {
        self.identity_rotation_config = Some(config);
        self
    }

    /// Set session compartmentalization configuration.
    pub fn with_session_compartment(mut self, config: SessionCompartmentConfig) -> Self {
        self.session_compartment_config = Some(config);
        self
    }

    pub fn build(self) -> EvasionTransport {
        let catalog = crate::persona::load_persona_catalog(self.persona_catalog_path.as_deref())
            .expect("persona catalog must be valid");
        let persona = self.persona.unwrap_or_else(|| catalog[0].clone());

        let timing = TimingController::from_persona(&persona, self.timing_seed);
        let h2_fingerprint = h2_fingerprint_for_persona(persona.id);

        let traffic_shaper = match self.traffic_shaper_config {
            Some(config) => TrafficShaper::with_seed(config, self.timing_seed),
            None => TrafficShaper::with_seed(TrafficShaperConfig::default(), self.timing_seed),
        };

        let rate_throttle = match self.throttle_config {
            Some(config) => RateAdaptiveThrottle::new(config),
            None => RateAdaptiveThrottle::with_defaults(),
        };

        let mut session_compartment = match self.session_compartment_config {
            Some(config) => SessionCompartment::new(config),
            None => SessionCompartment::with_defaults(),
        };

        let identity_engine = self.identity_rotation_config.map(|config| {
            let mut engine = IdentityRotationEngine::with_seed(config, self.timing_seed);
            engine.generate_pool();
            engine.activate_next();
            engine
        });

        let initial_identity = session_compartment.create_session();

        let client = Client::builder()
            .danger_accept_invalid_certs(self.accept_self_signed)
            .build()
            .expect("failed to build reqwest client");

        EvasionTransport {
            client,
            header_transformer: HeaderTransformer::new(),
            timing,
            traffic_shaper,
            rate_throttle,
            session: SessionManager::new(self.max_requests_per_session),
            persona,
            persona_catalog: catalog,
            current_persona_index: 0,
            persona_rotation_interval: self.persona_rotation_interval,
            sessions_since_rotation: 0,
            scope_attestation: self.scope_attestation,
            operator_authorized: self.operator_authorized,
            h2_fingerprint,
            proxy_manager: self.proxy_manager,
            active_proxy_chain: None,
            accept_self_signed: self.accept_self_signed,
            session_compartment,
            identity_engine,
            active_session_identity: Some(initial_identity),
        }
    }
}
