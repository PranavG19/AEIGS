use std::time::{Duration, Instant};

use crate::stealth_config::StealthConfig;
use aegis_protocol::target_validation;

pub use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};

#[derive(Debug)]
pub enum ExecutorError {
    NetworkError(String),
    Timeout(String),
    RateLimited,
    TargetNotAllowed(String),
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::TargetNotAllowed(msg) => write!(f, "target not allowed: {msg}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

pub struct RateLimiter {
    max_requests_per_second: u32,
    request_timestamps: Vec<Instant>,
}

impl RateLimiter {
    pub fn new(max_rps: u32) -> Self {
        Self {
            max_requests_per_second: max_rps,
            request_timestamps: Vec::new(),
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let one_second_ago = now - Duration::from_secs(1);

        self.request_timestamps.retain(|&ts| ts > one_second_ago);

        if self.request_timestamps.len() < self.max_requests_per_second as usize {
            self.request_timestamps.push(now);
            true
        } else {
            false
        }
    }

    pub fn current_rate(&self) -> usize {
        let now = Instant::now();
        let one_second_ago = now - Duration::from_secs(1);
        self.request_timestamps
            .iter()
            .filter(|&&ts| ts > one_second_ago)
            .count()
    }

    pub fn max_rps(&self) -> u32 {
        self.max_requests_per_second
    }
}

pub struct RequestExecutor {
    base_url: String,
    rate_limiter: RateLimiter,
    timeout: Duration,
    default_headers: Vec<(String, String)>,
    next_request_id: u64,
    total_requests: u64,
    total_errors: u64,
    stealth_config: Option<StealthConfig>,
}

pub(crate) fn browser_default_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()),
        ("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".to_string()),
        ("Accept-Language".to_string(), "en-US,en;q=0.5".to_string()),
        ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
    ]
}

impl RequestExecutor {
    pub fn new(base_url: String, max_rps: u32, timeout: Duration) -> Result<Self, ExecutorError> {
        target_validation::validate_target_is_localhost(&base_url)
            .map_err(|e| ExecutorError::TargetNotAllowed(e.to_string()))?;

        Ok(Self {
            base_url,
            rate_limiter: RateLimiter::new(max_rps),
            timeout,
            default_headers: browser_default_headers(),
            next_request_id: 1,
            total_requests: 0,
            total_errors: 0,
            stealth_config: None,
        })
    }

    pub fn with_default_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.default_headers = headers;
        self
    }

    pub fn with_stealth_config(mut self, config: StealthConfig) -> Self {
        self.stealth_config = Some(config);
        self
    }

    pub fn build_request(
        &mut self,
        endpoint: &str,
        method: &str,
        parameter_name: &str,
        payload: &str,
    ) -> FuzzRequest {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        FuzzRequest {
            request_id,
            endpoint: format!("{}{}", self.base_url, endpoint),
            method: method.to_string(),
            parameter_name: parameter_name.to_string(),
            parameter_location: ParameterLocation::Query,
            payload: payload.to_string(),
            headers: self.default_headers.clone(),
        }
    }

    pub fn try_acquire_rate_limit(&mut self) -> bool {
        self.rate_limiter.try_acquire()
    }

    pub fn record_success(&mut self) {
        self.total_requests += 1;
    }

    pub fn record_error(&mut self) {
        self.total_requests += 1;
        self.total_errors += 1;
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn total_errors(&self) -> u64 {
        self.total_errors
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.total_errors as f64 / self.total_requests as f64
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn stealth_config(&self) -> Option<&StealthConfig> {
        self.stealth_config.as_ref()
    }
}
