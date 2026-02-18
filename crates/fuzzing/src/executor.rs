use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct FuzzRequest {
    pub request_id: u64,
    pub endpoint: String,
    pub method: String,
    pub parameter_name: String,
    pub payload: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct FuzzResponse {
    pub request_id: u64,
    pub status_code: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub response_time: Duration,
    pub body_size_bytes: usize,
}

#[derive(Debug)]
pub enum ExecutorError {
    NetworkError(String),
    Timeout(String),
    RateLimited,
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::RateLimited => write!(f, "rate limited"),
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
    next_request_id: u64,
    total_requests: u64,
    total_errors: u64,
}

impl RequestExecutor {
    pub fn new(base_url: String, max_rps: u32, timeout: Duration) -> Self {
        Self {
            base_url,
            rate_limiter: RateLimiter::new(max_rps),
            timeout,
            next_request_id: 1,
            total_requests: 0,
            total_errors: 0,
        }
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
            payload: payload.to_string(),
            headers: Vec::new(),
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
}
