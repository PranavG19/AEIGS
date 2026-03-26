use serde::{Deserialize, Serialize};

/// Pareto-distributed request timing controller with burst dampening.
///
/// Models inter-request delays using a Pareto distribution (heavy-tailed),
/// which more closely matches real human browsing patterns than uniform
/// or exponential distributions. Includes burst detection and dampening
/// to avoid triggering rate-limit heuristics.
pub struct JitterController {
    config: JitterConfig,
    state: JitterState,
}

/// Configuration for the Pareto jitter controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterConfig {
    /// Pareto shape parameter (alpha). Lower = heavier tail. Typical: 1.5-3.0.
    pub pareto_alpha: f64,
    /// Minimum delay in milliseconds (Pareto scale parameter).
    pub min_delay_ms: u64,
    /// Maximum delay cap to prevent unreasonably long waits.
    pub max_delay_ms: u64,
    /// Number of recent requests to track for burst detection.
    pub burst_window_size: usize,
    /// If more than this fraction of the window is below min_delay * 2, dampen.
    pub burst_threshold: f64,
    /// Multiplier applied to delay during burst dampening.
    pub burst_dampen_factor: f64,
    /// Session-level timing bias (added to all delays for this session).
    pub session_bias_ms: u64,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            pareto_alpha: 2.0,
            min_delay_ms: 200,
            max_delay_ms: 30_000,
            burst_window_size: 10,
            burst_threshold: 0.6,
            burst_dampen_factor: 3.0,
            session_bias_ms: 0,
        }
    }
}

/// Internal state tracking for burst detection and session consistency.
#[derive(Debug, Clone)]
struct JitterState {
    recent_delays: Vec<u64>,
    total_requests: u64,
    rng_state: u64,
    dampening_active: bool,
}

/// Timing profile summary for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingProfile {
    pub total_requests: u64,
    pub mean_delay_ms: f64,
    pub min_observed_ms: u64,
    pub max_observed_ms: u64,
    pub burst_dampen_count: u64,
    pub pareto_alpha: f64,
}

impl JitterController {
    pub fn new(config: JitterConfig) -> Self {
        Self {
            state: JitterState {
                recent_delays: Vec::with_capacity(config.burst_window_size),
                total_requests: 0,
                rng_state: 0xdeadbeef12345678,
                dampening_active: false,
            },
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(JitterConfig::default())
    }

    /// Create a controller with a specific seed for reproducible timing.
    pub fn with_seed(config: JitterConfig, seed: u64) -> Self {
        let mut ctrl = Self::new(config);
        ctrl.state.rng_state = if seed == 0 { 0xdeadbeef12345678 } else { seed };
        ctrl
    }

    /// Compute the next inter-request delay in milliseconds.
    ///
    /// Draws from a Pareto distribution, applies burst dampening if triggered,
    /// and adds the session-level bias.
    pub fn next_delay_ms(&mut self) -> u64 {
        self.state.rng_state = xorshift64(self.state.rng_state);
        let u = uniform_01(self.state.rng_state);

        let pareto_sample =
            pareto_inverse_cdf(u, self.config.pareto_alpha, self.config.min_delay_ms as f64);
        let mut delay = (pareto_sample as u64).min(self.config.max_delay_ms);

        if self.is_burst_detected() {
            delay = ((delay as f64) * self.config.burst_dampen_factor) as u64;
            delay = delay.min(self.config.max_delay_ms);
            self.state.dampening_active = true;
        } else {
            self.state.dampening_active = false;
        }

        delay += self.config.session_bias_ms;
        delay = delay.min(self.config.max_delay_ms);

        self.record_delay(delay);
        delay
    }

    /// Check if current request pattern looks like a burst.
    fn is_burst_detected(&self) -> bool {
        if self.state.recent_delays.len() < self.config.burst_window_size {
            return false;
        }

        let fast_threshold = self.config.min_delay_ms * 2;
        let fast_count = self
            .state
            .recent_delays
            .iter()
            .filter(|&&d| d < fast_threshold)
            .count();
        let ratio = fast_count as f64 / self.state.recent_delays.len() as f64;
        ratio >= self.config.burst_threshold
    }

    fn record_delay(&mut self, delay: u64) {
        self.state.total_requests += 1;
        self.state.recent_delays.push(delay);
        if self.state.recent_delays.len() > self.config.burst_window_size {
            self.state.recent_delays.remove(0);
        }
    }

    /// Get the current timing profile summary.
    pub fn timing_profile(&self) -> TimingProfile {
        let (mean, min_obs, max_obs) = if self.state.recent_delays.is_empty() {
            (0.0, 0, 0)
        } else {
            let sum: u64 = self.state.recent_delays.iter().sum();
            let mean = sum as f64 / self.state.recent_delays.len() as f64;
            let min_obs = *self.state.recent_delays.iter().min().unwrap();
            let max_obs = *self.state.recent_delays.iter().max().unwrap();
            (mean, min_obs, max_obs)
        };

        TimingProfile {
            total_requests: self.state.total_requests,
            mean_delay_ms: mean,
            min_observed_ms: min_obs,
            max_observed_ms: max_obs,
            burst_dampen_count: 0,
            pareto_alpha: self.config.pareto_alpha,
        }
    }

    /// Whether burst dampening is currently active.
    pub fn is_dampening_active(&self) -> bool {
        self.state.dampening_active
    }

    /// Reset timing state (new session).
    pub fn reset(&mut self) {
        self.state.recent_delays.clear();
        self.state.total_requests = 0;
        self.state.dampening_active = false;
    }

    /// Total requests tracked in this session.
    pub fn total_requests(&self) -> u64 {
        self.state.total_requests
    }
}

/// Pareto inverse CDF: x = scale / (1 - u)^(1/alpha)
fn pareto_inverse_cdf(u: f64, alpha: f64, scale: f64) -> f64 {
    let clamped = u.max(0.001).min(0.999);
    scale / (1.0 - clamped).powf(1.0 / alpha)
}

/// Map u64 to [0, 1) range.
fn uniform_01(x: u64) -> f64 {
    (x >> 11) as f64 / (1u64 << 53) as f64
}

fn xorshift64(mut state: u64) -> u64 {
    if state == 0 {
        state = 0xdeadbeefcafe1234;
    }
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}
