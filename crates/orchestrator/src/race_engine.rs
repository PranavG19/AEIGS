use std::fmt;
use std::time::Duration;

/// Race condition attack targets — categories of state-dependent operations
/// that are vulnerable to TOCTOU (Time-Of-Check-To-Time-Of-Use) attacks.
///
/// Each variant represents a distinct business logic pattern where parallel
/// requests can corrupt shared state. The Brain selects the target type
/// based on endpoint behavior analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RaceTarget {
    /// Coupon/promo code redemption — redeem twice before decrement
    CouponRedemption,
    /// Balance transfer/withdrawal — drain more than available
    BalanceTransfer,
    /// Rate limit counter — bypass by arriving before counter increments
    RateLimitBypass,
    /// Inventory check — purchase more than stock allows
    InventoryCheck,
    /// Account creation — create duplicates of unique-constrained resources
    DuplicateCreation,
    /// Vote/like manipulation — increment counter multiple times
    VoteManipulation,
    /// File upload — overwrite or double-upload race
    FileUploadRace,
    /// Session state — login/logout race for session fixation
    SessionStateRace,
    /// Email verification — use token multiple times
    TokenReuse,
    /// Database sequence — exploit auto-increment prediction
    SequencePrediction,
}

impl fmt::Display for RaceTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CouponRedemption => write!(f, "coupon_redemption"),
            Self::BalanceTransfer => write!(f, "balance_transfer"),
            Self::RateLimitBypass => write!(f, "rate_limit_bypass"),
            Self::InventoryCheck => write!(f, "inventory_check"),
            Self::DuplicateCreation => write!(f, "duplicate_creation"),
            Self::VoteManipulation => write!(f, "vote_manipulation"),
            Self::FileUploadRace => write!(f, "file_upload_race"),
            Self::SessionStateRace => write!(f, "session_state_race"),
            Self::TokenReuse => write!(f, "token_reuse"),
            Self::SequencePrediction => write!(f, "sequence_prediction"),
        }
    }
}

/// Delivery strategy for race condition requests.
///
/// The key insight: network jitter dominates. To achieve true simultaneous
/// delivery, we must minimize the time window between the first and last
/// request reaching the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStrategy {
    /// Single-packet attack: pack multiple HTTP requests into one TCP segment.
    /// Requires all requests to fit in one MSS (~1460 bytes for Ethernet).
    /// Achieves sub-microsecond delivery differential at the server.
    SinglePacket,
    /// Last-byte synchronization: send all requests except the final byte,
    /// then burst the final bytes simultaneously. ~1ms window.
    LastByte,
    /// Parallel connection burst: open N connections, hold them ready,
    /// release all simultaneously. ~5-10ms window.
    ParallelBurst,
    /// Pipelined requests on a single HTTP/1.1 keep-alive connection.
    /// Server processes sequentially but without connection overhead.
    Pipelined,
}

impl fmt::Display for DeliveryStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SinglePacket => write!(f, "single_packet"),
            Self::LastByte => write!(f, "last_byte"),
            Self::ParallelBurst => write!(f, "parallel_burst"),
            Self::Pipelined => write!(f, "pipelined"),
        }
    }
}

/// Configuration for a race condition attack.
#[derive(Debug, Clone)]
pub struct RaceConfig {
    pub target_type: RaceTarget,
    pub strategy: DeliveryStrategy,
    pub burst_size: u32,
    pub endpoint: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub warmup_rounds: u32,
    pub verification_delay: Duration,
    pub max_retries: u32,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            target_type: RaceTarget::CouponRedemption,
            strategy: DeliveryStrategy::ParallelBurst,
            burst_size: 10,
            endpoint: String::new(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: None,
            warmup_rounds: 2,
            verification_delay: Duration::from_millis(500),
            max_retries: 3,
        }
    }
}

/// A single request in a race burst.
#[derive(Debug, Clone)]
pub struct RaceRequest {
    pub index: u32,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// The raw HTTP/1.1 bytes for a request, suitable for TCP-level injection.
///
/// Used by SinglePacket and LastByte strategies where we need to control
/// exact byte boundaries in the TCP stream.
#[derive(Debug, Clone)]
pub struct RawHttpRequest {
    pub bytes: Vec<u8>,
    pub boundary_offset: usize,
}

/// Result of a single race burst.
#[derive(Debug, Clone)]
pub struct RaceBurstResult {
    pub burst_index: u32,
    pub strategy: DeliveryStrategy,
    pub request_count: u32,
    pub success_count: u32,
    pub response_statuses: Vec<u16>,
    pub timing_spread_us: u64,
    pub anomalies: Vec<RaceAnomaly>,
}

/// An anomaly detected during race testing.
#[derive(Debug, Clone)]
pub enum RaceAnomaly {
    /// Multiple requests succeeded where only one should have
    MultipleSuccesses { expected_max: u32, actual: u32 },
    /// State inconsistency detected (e.g., negative balance, over-limit stock)
    StateInconsistency { description: String },
    /// Response divergence — identical requests got different responses
    ResponseDivergence { status_a: u16, status_b: u16 },
    /// Timing anomaly — one request took significantly longer (lock contention)
    LockContention { fast_ms: u64, slow_ms: u64 },
}

impl fmt::Display for RaceAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultipleSuccesses {
                expected_max,
                actual,
            } => {
                write!(
                    f,
                    "multiple successes: expected max {expected_max}, got {actual}"
                )
            }
            Self::StateInconsistency { description } => {
                write!(f, "state inconsistency: {description}")
            }
            Self::ResponseDivergence { status_a, status_b } => {
                write!(f, "response divergence: {status_a} vs {status_b}")
            }
            Self::LockContention { fast_ms, slow_ms } => {
                write!(f, "lock contention: {fast_ms}ms vs {slow_ms}ms")
            }
        }
    }
}

/// Build a batch of identical race requests from a config.
pub fn build_race_batch(config: &RaceConfig) -> Vec<RaceRequest> {
    (0..config.burst_size)
        .map(|i| RaceRequest {
            index: i,
            method: config.method.clone(),
            path: config.endpoint.clone(),
            headers: config.headers.clone(),
            body: config.body.clone(),
        })
        .collect()
}

/// Serialize a race request into raw HTTP/1.1 bytes.
///
/// The `boundary_offset` marks where to split for last-byte sync:
/// everything before this offset is sent in advance, the final byte
/// is held until the synchronized release.
pub fn serialize_http11(request: &RaceRequest, host: &str) -> RawHttpRequest {
    let mut buf = Vec::with_capacity(512);

    let request_line = format!("{} {} HTTP/1.1\r\n", request.method, request.path);
    buf.extend_from_slice(request_line.as_bytes());
    buf.extend_from_slice(format!("Host: {}\r\n", host).as_bytes());

    for (key, value) in &request.headers {
        buf.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }

    if let Some(body) = &request.body {
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(body);
    } else {
        buf.extend_from_slice(b"\r\n");
    }

    let boundary = buf.len().saturating_sub(1);

    RawHttpRequest {
        bytes: buf,
        boundary_offset: boundary,
    }
}

/// Build a single-packet payload: concatenate multiple HTTP requests into
/// one TCP-sendable buffer. For this to work, the total must fit in one
/// MSS (typically 1460 bytes on Ethernet, 1220 on many WANs).
pub fn build_single_packet(requests: &[RawHttpRequest]) -> Option<Vec<u8>> {
    let total: usize = requests.iter().map(|r| r.bytes.len()).sum();
    if total > MAX_SINGLE_PACKET_SIZE {
        return None;
    }

    let mut packet = Vec::with_capacity(total);
    for req in requests {
        packet.extend_from_slice(&req.bytes);
    }
    Some(packet)
}

/// Maximum bytes for single-packet attack (conservative Ethernet MSS).
const MAX_SINGLE_PACKET_SIZE: usize = 1400;

/// Recommend the best delivery strategy for a given configuration.
///
/// Single-packet is best but requires small requests. Last-byte is the
/// universal fallback with good precision. Parallel burst is simplest
/// but has the widest delivery window.
pub fn recommend_strategy(request_size: usize, burst_size: u32) -> DeliveryStrategy {
    let total_size = request_size * burst_size as usize;
    if total_size <= MAX_SINGLE_PACKET_SIZE {
        DeliveryStrategy::SinglePacket
    } else if burst_size <= 20 {
        DeliveryStrategy::LastByte
    } else {
        DeliveryStrategy::ParallelBurst
    }
}

/// Analyze burst results for race condition anomalies.
///
/// The key detection: if N identical requests are sent and M > 1 succeed
/// where at most 1 should succeed, the operation is not atomic.
pub fn detect_anomalies(
    results: &RaceBurstResult,
    expected_max_successes: u32,
) -> Vec<RaceAnomaly> {
    let mut anomalies = Vec::new();

    if results.success_count > expected_max_successes {
        anomalies.push(RaceAnomaly::MultipleSuccesses {
            expected_max: expected_max_successes,
            actual: results.success_count,
        });
    }

    let unique_statuses: std::collections::HashSet<u16> =
        results.response_statuses.iter().copied().collect();
    if unique_statuses.len() > 1 {
        let statuses: Vec<u16> = unique_statuses.into_iter().collect();
        if statuses.len() >= 2 {
            anomalies.push(RaceAnomaly::ResponseDivergence {
                status_a: statuses[0],
                status_b: statuses[1],
            });
        }
    }

    anomalies
}

/// Compute severity for a race condition finding based on target type.
pub fn race_severity(target: RaceTarget) -> f64 {
    match target {
        RaceTarget::BalanceTransfer => 9.5,
        RaceTarget::CouponRedemption => 8.0,
        RaceTarget::TokenReuse => 8.5,
        RaceTarget::InventoryCheck => 7.5,
        RaceTarget::RateLimitBypass => 6.0,
        RaceTarget::DuplicateCreation => 7.0,
        RaceTarget::VoteManipulation => 5.5,
        RaceTarget::FileUploadRace => 7.0,
        RaceTarget::SessionStateRace => 8.0,
        RaceTarget::SequencePrediction => 6.5,
    }
}

/// Estimate whether a race condition is likely exploitable based on
/// the target type and observed infrastructure characteristics.
pub fn estimate_exploitability(
    target: RaceTarget,
    has_rate_limit: bool,
    response_time_ms: u64,
) -> f64 {
    let base: f64 = match target {
        RaceTarget::BalanceTransfer => 0.8,
        RaceTarget::CouponRedemption => 0.7,
        RaceTarget::TokenReuse => 0.6,
        RaceTarget::InventoryCheck => 0.6,
        RaceTarget::RateLimitBypass => 0.5,
        RaceTarget::DuplicateCreation => 0.5,
        RaceTarget::VoteManipulation => 0.4,
        RaceTarget::FileUploadRace => 0.3,
        RaceTarget::SessionStateRace => 0.4,
        RaceTarget::SequencePrediction => 0.3,
    };

    let rate_limit_factor = if has_rate_limit { 0.7 } else { 1.0 };

    let timing_factor = if response_time_ms < 50 {
        1.2
    } else if response_time_ms < 200 {
        1.0
    } else {
        0.6
    };

    (base * rate_limit_factor * timing_factor).clamp(0.0, 1.0)
}

#[cfg(test)]
#[path = "race_engine_test.rs"]
mod race_engine_test;
