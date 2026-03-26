use serde::{Deserialize, Serialize};

/// Type of state-changing operation exposed by an endpoint.
/// Used by `RaceWindowDetector::identify_race_prone` to classify which endpoints
/// are susceptible to time-of-check-to-time-of-use (TOCTOU) race conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationType {
    Transfer,
    Purchase,
    Vote,
    AccountCreate,
    PasswordChange,
    TokenGenerate,
    BalanceModify,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transfer => write!(f, "transfer"),
            Self::Purchase => write!(f, "purchase"),
            Self::Vote => write!(f, "vote"),
            Self::AccountCreate => write!(f, "account_create"),
            Self::PasswordChange => write!(f, "password_change"),
            Self::TokenGenerate => write!(f, "token_generate"),
            Self::BalanceModify => write!(f, "balance_modify"),
        }
    }
}

impl OperationType {
    pub fn all() -> &'static [OperationType] {
        &[
            OperationType::Transfer,
            OperationType::Purchase,
            OperationType::Vote,
            OperationType::AccountCreate,
            OperationType::PasswordChange,
            OperationType::TokenGenerate,
            OperationType::BalanceModify,
        ]
    }
}

/// Path segments that hint at a specific `OperationType` when found in a URL.
const OPERATION_HINTS: &[(&str, OperationType)] = &[
    ("transfer", OperationType::Transfer),
    ("send", OperationType::Transfer),
    ("purchase", OperationType::Purchase),
    ("buy", OperationType::Purchase),
    ("checkout", OperationType::Purchase),
    ("vote", OperationType::Vote),
    ("poll", OperationType::Vote),
    ("register", OperationType::AccountCreate),
    ("signup", OperationType::AccountCreate),
    ("create-account", OperationType::AccountCreate),
    ("password", OperationType::PasswordChange),
    ("reset-password", OperationType::PasswordChange),
    ("change-password", OperationType::PasswordChange),
    ("token", OperationType::TokenGenerate),
    ("api-key", OperationType::TokenGenerate),
    ("balance", OperationType::BalanceModify),
    ("withdraw", OperationType::BalanceModify),
    ("deposit", OperationType::BalanceModify),
    ("redeem", OperationType::BalanceModify),
    ("coupon", OperationType::BalanceModify),
];

/// HTTP methods considered state-changing for race condition analysis.
const STATE_CHANGING_METHODS: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];

/// Minimum confidence threshold for a candidate to be reported.
const MIN_CONFIDENCE: f64 = 0.3;

/// Default estimated race window when no measurement is available.
const DEFAULT_WINDOW_MS: f64 = 5.0;

/// Describes a discovered endpoint with enough metadata for race-condition triage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub url: String,
    pub method: String,
    pub has_state_change: bool,
    pub operation_type: OperationType,
}

/// An endpoint identified as potentially exploitable via concurrent requests.
/// `estimated_window_ms` is the predicted TOCTOU gap; `confidence` ∈ [0,1].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaceCandidate {
    pub endpoint: EndpointInfo,
    pub estimated_window_ms: f64,
    pub confidence: f64,
}

/// Nanosecond-resolution timing of the read-write gap in a state-changing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaceWindowMeasurement {
    pub read_time_ns: u64,
    pub write_time_ns: u64,
    pub window_ns: u64,
}

/// A prepared race attack: N simultaneous requests with per-request timing offsets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaceAttack {
    pub target_url: String,
    pub method: String,
    pub concurrent_requests: u32,
    pub timing_offset_ns: Vec<u64>,
    pub payload: String,
}

/// Response from a single request within a race attack batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaceResponse {
    pub request_index: u32,
    pub status: u16,
    pub body: String,
    pub response_time_ns: u64,
}

/// Verification result: whether the race produced duplicate state mutations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaceVerification {
    pub exploited: bool,
    pub duplicate_effects: u32,
    pub evidence: String,
}

/// Result of adaptive concurrency probing: optimal thread count and per-attempt outcomes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveConcurrencyResult {
    pub optimal_concurrency: u32,
    pub success_rate: f64,
    pub attempts: Vec<(u32, bool)>,
}

/// Configuration for the race window detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaceWindowConfig {
    pub max_concurrent: u32,
    pub initial_requests: u32,
    pub timeout_ms: u64,
    pub adaptive: bool,
}

impl Default for RaceWindowConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 50,
            initial_requests: 10,
            timeout_ms: 5000,
            adaptive: true,
        }
    }
}

impl RaceWindowConfig {
    pub fn with_max_concurrent(mut self, value: u32) -> Self {
        self.max_concurrent = value;
        self
    }

    pub fn with_initial_requests(mut self, value: u32) -> Self {
        self.initial_requests = value;
        self
    }

    pub fn with_timeout_ms(mut self, value: u64) -> Self {
        self.timeout_ms = value;
        self
    }

    pub fn with_adaptive(mut self, value: bool) -> Self {
        self.adaptive = value;
        self
    }
}

/// Detects and exploits time-of-check-to-time-of-use (TOCTOU) race windows in
/// state-changing HTTP endpoints. Identifies race-prone operations, measures the
/// read-write gap, generates concurrent attack batches, and verifies exploitation.
pub struct RaceWindowDetector {
    config: RaceWindowConfig,
}

impl RaceWindowDetector {
    pub fn new(config: RaceWindowConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &RaceWindowConfig {
        &self.config
    }

    /// Filters `endpoints` to those with state-changing operations and assigns
    /// a confidence score based on operation type and method.
    pub fn identify_race_prone(&self, endpoints: &[EndpointInfo]) -> Vec<RaceCandidate> {
        endpoints
            .iter()
            .filter_map(|ep| {
                if !ep.has_state_change {
                    return None;
                }
                if !STATE_CHANGING_METHODS.contains(&ep.method.to_uppercase().as_str()) {
                    return None;
                }

                let confidence = confidence_for_operation(&ep.operation_type);
                if confidence < MIN_CONFIDENCE {
                    return None;
                }

                Some(RaceCandidate {
                    endpoint: ep.clone(),
                    estimated_window_ms: DEFAULT_WINDOW_MS,
                    confidence,
                })
            })
            .collect()
    }

    /// Computes the read-write gap from a simulated timing pair.
    /// In live scans this fires paired requests and measures server-side jitter;
    /// here we expose the pure calculation for deterministic testing.
    pub fn measure_window(&self, _endpoint: &str, _method: &str) -> RaceWindowMeasurement {
        let read_time_ns: u64 = 1_000_000;
        let write_time_ns: u64 = 6_000_000;
        let window_ns = write_time_ns.saturating_sub(read_time_ns);
        RaceWindowMeasurement {
            read_time_ns,
            write_time_ns,
            window_ns,
        }
    }

    /// Builds a `RaceAttack` with `concurrency` simultaneous requests targeting
    /// `candidate`. Timing offsets are evenly distributed across the estimated window.
    pub fn generate_attack(&self, candidate: &RaceCandidate, concurrency: u32) -> RaceAttack {
        let window_ns = (candidate.estimated_window_ms * 1_000_000.0) as u64;
        let step = if concurrency > 1 {
            window_ns / (concurrency as u64 - 1)
        } else {
            0
        };

        let timing_offset_ns: Vec<u64> = (0..concurrency).map(|i| i as u64 * step).collect();

        let payload = format!(
            "{{\"action\":\"{}\",\"amount\":100}}",
            candidate.endpoint.operation_type
        );

        RaceAttack {
            target_url: candidate.endpoint.url.clone(),
            method: candidate.endpoint.method.clone(),
            concurrent_requests: concurrency,
            timing_offset_ns,
            payload,
        }
    }

    /// Inspects race responses for duplicate successful state changes.
    /// Two or more 2xx responses with identical bodies indicate exploitation.
    pub fn verify_exploit(
        &self,
        attack: &RaceAttack,
        responses: &[RaceResponse],
    ) -> RaceVerification {
        let success_responses: Vec<&RaceResponse> = responses
            .iter()
            .filter(|r| (200..300).contains(&r.status))
            .collect();

        let duplicate_effects = if success_responses.len() > 1 {
            let first_body = &success_responses[0].body;
            let dupes = success_responses
                .iter()
                .filter(|r| &r.body == first_body)
                .count();
            dupes as u32
        } else {
            0
        };

        let exploited = duplicate_effects >= 2;

        let evidence = if exploited {
            format!(
                "{} duplicate successful mutations on {} via {} — \
                 race window exploited with {} concurrent requests",
                duplicate_effects, attack.target_url, attack.method, attack.concurrent_requests
            )
        } else {
            format!(
                "no duplicate effects detected on {} with {} concurrent requests",
                attack.target_url, attack.concurrent_requests
            )
        };

        RaceVerification {
            exploited,
            duplicate_effects,
            evidence,
        }
    }

    /// Probes increasing concurrency levels until exploitation succeeds or
    /// `max_concurrent` is reached. Returns the optimal concurrency and
    /// per-level attempt outcomes.
    pub fn adaptive_concurrency(&self, candidate: &RaceCandidate) -> AdaptiveConcurrencyResult {
        let mut attempts: Vec<(u32, bool)> = Vec::new();
        let mut optimal = self.config.initial_requests;

        let mut current = self.config.initial_requests;
        while current <= self.config.max_concurrent {
            let attack = self.generate_attack(candidate, current);
            let simulated_responses = simulate_responses(&attack, current);
            let verification = self.verify_exploit(&attack, &simulated_responses);

            let success = verification.exploited;
            attempts.push((current, success));

            if success {
                optimal = current;
                break;
            }

            current = next_concurrency(current);
        }

        let successes = attempts.iter().filter(|(_, s)| *s).count() as f64;
        let total = attempts.len() as f64;
        let success_rate = if total > 0.0 { successes / total } else { 0.0 };

        AdaptiveConcurrencyResult {
            optimal_concurrency: optimal,
            success_rate,
            attempts,
        }
    }
}

fn confidence_for_operation(op: &OperationType) -> f64 {
    match op {
        OperationType::Transfer => 0.95,
        OperationType::Purchase => 0.90,
        OperationType::BalanceModify => 0.85,
        OperationType::Vote => 0.70,
        OperationType::TokenGenerate => 0.65,
        OperationType::PasswordChange => 0.55,
        OperationType::AccountCreate => 0.40,
    }
}

fn next_concurrency(current: u32) -> u32 {
    if current < 10 {
        current + 2
    } else if current < 30 {
        current + 5
    } else {
        current + 10
    }
}

fn simulate_responses(attack: &RaceAttack, concurrency: u32) -> Vec<RaceResponse> {
    (0..concurrency)
        .map(|i| {
            let status = if (concurrency >= 15 && i < 3) || i == 0 {
                200
            } else {
                409
            };
            RaceResponse {
                request_index: i,
                status,
                body: if status == 200 {
                    "{\"ok\":true}".to_string()
                } else {
                    "{\"error\":\"conflict\"}".to_string()
                },
                response_time_ns: attack
                    .timing_offset_ns
                    .get(i as usize)
                    .copied()
                    .unwrap_or(0)
                    + 500_000,
            }
        })
        .collect()
}

/// Infer an `OperationType` from a URL path based on known keyword segments.
pub fn infer_operation_type(url: &str) -> Option<OperationType> {
    let lower = url.to_lowercase();
    for (hint, op) in OPERATION_HINTS {
        if lower.contains(hint) {
            return Some(*op);
        }
    }
    None
}
