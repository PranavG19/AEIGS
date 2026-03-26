use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Adaptive rate throttle using binary search to find the maximum safe request rate.
///
/// Targets 85% of the server's rate limit threshold per endpoint.
/// Uses binary search to converge on the optimal rate, then maintains it
/// with continuous monitoring for limit signals.

/// Throttle state per endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointThrottle {
    pub endpoint: String,
    pub current_rate_rps: f64,
    pub estimated_limit_rps: f64,
    pub target_utilization: f64,
    pub state: ThrottleState,
    pub consecutive_ok: u32,
    pub consecutive_limited: u32,
    pub total_requests: u64,
    pub total_limited: u64,
    pub search_low: f64,
    pub search_high: f64,
}

/// Current state of the throttle binary search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThrottleState {
    Searching,
    Converged,
    BackingOff,
    Stable,
}

impl std::fmt::Display for ThrottleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Searching => write!(f, "searching"),
            Self::Converged => write!(f, "converged"),
            Self::BackingOff => write!(f, "backing-off"),
            Self::Stable => write!(f, "stable"),
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitSignal {
    Ok,
    SoftLimit,
    HardLimit,
    Blocked,
}

/// Configuration for the adaptive throttle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveThrottleConfig {
    /// Target utilization of the rate limit (0.0-1.0). Default: 0.85.
    pub target_utilization: f64,
    /// Initial rate to start searching from (requests per second).
    pub initial_rate_rps: f64,
    /// Maximum allowed rate.
    pub max_rate_rps: f64,
    /// Minimum rate floor.
    pub min_rate_rps: f64,
    /// Convergence tolerance (binary search stops when gap < this).
    pub convergence_tolerance: f64,
    /// Number of consecutive OK responses before increasing rate.
    pub ok_threshold: u32,
    /// Number of consecutive limited responses before decreasing rate.
    pub limited_threshold: u32,
    /// Backoff multiplier when rate limit is hit.
    pub backoff_factor: f64,
}

impl Default for AdaptiveThrottleConfig {
    fn default() -> Self {
        Self {
            target_utilization: 0.85,
            initial_rate_rps: 10.0,
            max_rate_rps: 100.0,
            min_rate_rps: 0.5,
            convergence_tolerance: 0.5,
            ok_threshold: 5,
            limited_threshold: 2,
            backoff_factor: 0.5,
        }
    }
}

/// Per-endpoint adaptive rate throttle.
pub struct RateAdaptiveThrottle {
    config: AdaptiveThrottleConfig,
    endpoints: HashMap<String, EndpointThrottle>,
}

impl RateAdaptiveThrottle {
    pub fn new(config: AdaptiveThrottleConfig) -> Self {
        Self {
            config,
            endpoints: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(AdaptiveThrottleConfig::default())
    }

    /// Get the current allowed delay in milliseconds for the given endpoint.
    pub fn delay_ms(&mut self, endpoint: &str) -> u64 {
        let throttle = self.get_or_create(endpoint);
        if throttle.current_rate_rps <= 0.0 {
            return 2000;
        }
        (1000.0 / throttle.current_rate_rps) as u64
    }

    /// Report the result of a request to the given endpoint.
    pub fn report(&mut self, endpoint: &str, signal: RateLimitSignal) {
        let config = self.config.clone();
        let throttle = self.get_or_create(endpoint);
        throttle.total_requests += 1;

        match signal {
            RateLimitSignal::Ok => {
                throttle.consecutive_ok += 1;
                throttle.consecutive_limited = 0;

                if throttle.consecutive_ok >= config.ok_threshold {
                    match throttle.state {
                        ThrottleState::Searching => {
                            throttle.search_low = throttle.current_rate_rps;
                            let mid = (throttle.search_low + throttle.search_high) / 2.0;
                            throttle.current_rate_rps = mid.min(config.max_rate_rps);

                            if (throttle.search_high - throttle.search_low)
                                < config.convergence_tolerance
                            {
                                throttle.estimated_limit_rps = throttle.search_high;
                                throttle.current_rate_rps =
                                    throttle.estimated_limit_rps * config.target_utilization;
                                throttle.state = ThrottleState::Converged;
                            }
                        }
                        ThrottleState::BackingOff => {
                            throttle.state = ThrottleState::Searching;
                        }
                        ThrottleState::Converged | ThrottleState::Stable => {
                            throttle.state = ThrottleState::Stable;
                        }
                    }
                    throttle.consecutive_ok = 0;
                }
            }
            RateLimitSignal::SoftLimit | RateLimitSignal::HardLimit | RateLimitSignal::Blocked => {
                throttle.consecutive_limited += 1;
                throttle.consecutive_ok = 0;
                throttle.total_limited += 1;

                if signal == RateLimitSignal::Blocked {
                    throttle.current_rate_rps *= config.backoff_factor;
                    throttle.current_rate_rps = throttle.current_rate_rps.max(config.min_rate_rps);
                    throttle.state = ThrottleState::BackingOff;
                } else if throttle.consecutive_limited >= config.limited_threshold {
                    throttle.search_high = throttle.current_rate_rps;
                    let mid = (throttle.search_low + throttle.search_high) / 2.0;
                    throttle.current_rate_rps = mid.max(config.min_rate_rps);

                    if (throttle.search_high - throttle.search_low) < config.convergence_tolerance {
                        throttle.estimated_limit_rps = throttle.search_high;
                        throttle.current_rate_rps =
                            throttle.estimated_limit_rps * config.target_utilization;
                        throttle.state = ThrottleState::Converged;
                    }
                    throttle.consecutive_limited = 0;
                }
            }
        }
    }

    /// Get current rate for an endpoint.
    pub fn current_rate(&self, endpoint: &str) -> Option<f64> {
        self.endpoints.get(endpoint).map(|t| t.current_rate_rps)
    }

    /// Get throttle state for an endpoint.
    pub fn endpoint_state(&self, endpoint: &str) -> Option<ThrottleState> {
        self.endpoints.get(endpoint).map(|t| t.state)
    }

    /// Number of tracked endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Reset all endpoint tracking.
    pub fn reset(&mut self) {
        self.endpoints.clear();
    }

    /// Get utilization ratio for an endpoint (current / estimated limit).
    pub fn utilization(&self, endpoint: &str) -> Option<f64> {
        self.endpoints.get(endpoint).map(|t| {
            if t.estimated_limit_rps <= 0.0 {
                0.0
            } else {
                t.current_rate_rps / t.estimated_limit_rps
            }
        })
    }

    fn get_or_create(&mut self, endpoint: &str) -> &mut EndpointThrottle {
        let config = &self.config;
        self.endpoints
            .entry(endpoint.to_string())
            .or_insert_with(|| EndpointThrottle {
                endpoint: endpoint.to_string(),
                current_rate_rps: config.initial_rate_rps,
                estimated_limit_rps: config.max_rate_rps,
                target_utilization: config.target_utilization,
                state: ThrottleState::Searching,
                consecutive_ok: 0,
                consecutive_limited: 0,
                total_requests: 0,
                total_limited: 0,
                search_low: config.min_rate_rps,
                search_high: config.max_rate_rps,
            })
    }
}
