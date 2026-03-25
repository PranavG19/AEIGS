use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Token bucket for a single entity (worker or global).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    pub capacity: u64,
    pub tokens: u64,
    pub refill_rate_per_sec: f64,
    pub last_refill_ms: u64,
}

impl TokenBucket {
    /// Creates a full bucket with the given capacity and refill rate.
    pub fn new(capacity: u64, refill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate_per_sec,
            last_refill_ms: crate::util::timestamp_ms(),
        }
    }

    /// Refills tokens based on elapsed time since last refill.
    pub fn refill(&mut self, current_time_ms: u64) {
        let elapsed_ms = current_time_ms.saturating_sub(self.last_refill_ms);
        let elapsed_secs = elapsed_ms as f64 / 1000.0;
        let new_tokens = (elapsed_secs * self.refill_rate_per_sec) as u64;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill_ms = current_time_ms;
        }
    }

    /// Attempts to consume `n` tokens. Returns `true` if successful.
    pub fn try_consume(&mut self, n: u64, current_time_ms: u64) -> bool {
        self.refill(current_time_ms);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Returns the number of available tokens (after refill).
    pub fn available(&mut self, current_time_ms: u64) -> u64 {
        self.refill(current_time_ms);
        self.tokens
    }

    /// Returns the fraction of capacity currently available.
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        1.0 - (self.tokens as f64 / self.capacity as f64)
    }
}

/// Errors from rate limiter operations.
#[derive(Debug)]
pub enum RateLimitError {
    WorkerNotRegistered(String),
    GlobalLimitExhausted,
    WorkerLimitExhausted(String),
    InvalidConfig(String),
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerNotRegistered(id) => write!(f, "worker not registered: {id}"),
            Self::GlobalLimitExhausted => write!(f, "global rate limit exhausted"),
            Self::WorkerLimitExhausted(id) => write!(f, "rate limit exhausted for worker: {id}"),
            Self::InvalidConfig(msg) => write!(f, "invalid rate limit config: {msg}"),
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Configuration for the distributed rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub global_capacity: u64,
    pub global_refill_rate: f64,
    pub per_worker_capacity: u64,
    pub per_worker_refill_rate: f64,
    pub adaptive: bool,
    pub backoff_factor: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_capacity: 1000,
            global_refill_rate: 100.0,
            per_worker_capacity: 200,
            per_worker_refill_rate: 20.0,
            adaptive: true,
            backoff_factor: 0.5,
        }
    }
}

/// Coordinates rate limiting across all workers hitting a shared target.
pub struct DistributedRateLimiter {
    global_bucket: TokenBucket,
    worker_buckets: HashMap<String, TokenBucket>,
    config: RateLimitConfig,
    rate_limit_detections: u64,
}

impl DistributedRateLimiter {
    /// Creates a new distributed rate limiter from configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = TokenBucket::new(config.global_capacity, config.global_refill_rate);
        Self {
            global_bucket,
            worker_buckets: HashMap::new(),
            config,
            rate_limit_detections: 0,
        }
    }

    /// Registers a worker with its own token bucket.
    pub fn register_worker(&mut self, worker_id: &str) {
        let bucket = TokenBucket::new(
            self.config.per_worker_capacity,
            self.config.per_worker_refill_rate,
        );
        self.worker_buckets.insert(worker_id.to_string(), bucket);
    }

    /// Removes a worker's bucket, returning its remaining tokens to the global pool.
    pub fn deregister_worker(&mut self, worker_id: &str) -> Result<(), RateLimitError> {
        let bucket = self
            .worker_buckets
            .remove(worker_id)
            .ok_or_else(|| RateLimitError::WorkerNotRegistered(worker_id.to_string()))?;
        let return_tokens = bucket
            .tokens
            .min(self.global_bucket.capacity - self.global_bucket.tokens);
        self.global_bucket.tokens += return_tokens;
        Ok(())
    }

    /// Requests `n` tokens for a worker. Checks both global and per-worker limits.
    pub fn request_tokens(
        &mut self,
        worker_id: &str,
        n: u64,
        current_time_ms: u64,
    ) -> Result<(), RateLimitError> {
        if !self.worker_buckets.contains_key(worker_id) {
            return Err(RateLimitError::WorkerNotRegistered(worker_id.to_string()));
        }
        if !self.global_bucket.try_consume(n, current_time_ms) {
            return Err(RateLimitError::GlobalLimitExhausted);
        }
        let worker_bucket = self.worker_buckets.get_mut(worker_id).unwrap();
        if !worker_bucket.try_consume(n, current_time_ms) {
            // Return tokens to global since worker can't use them
            self.global_bucket.tokens =
                (self.global_bucket.tokens + n).min(self.global_bucket.capacity);
            return Err(RateLimitError::WorkerLimitExhausted(worker_id.to_string()));
        }
        Ok(())
    }

    /// Signals that rate limiting was detected from the target, triggering adaptive backoff.
    pub fn signal_rate_limited(&mut self, current_time_ms: u64) {
        self.rate_limit_detections += 1;
        if !self.config.adaptive {
            return;
        }
        let factor = self.config.backoff_factor;
        self.global_bucket.refill_rate_per_sec *= factor;
        for bucket in self.worker_buckets.values_mut() {
            bucket.refill_rate_per_sec *= factor;
            bucket.refill(current_time_ms);
        }
    }

    /// Redistributes budget from a deregistered/failed worker across remaining workers.
    pub fn redistribute_budget(&mut self, _failed_worker_id: &str) {
        let active_count = self.worker_buckets.len();
        if active_count == 0 {
            return;
        }
        let bonus_per_worker = self.config.per_worker_capacity / active_count as u64;
        for bucket in self.worker_buckets.values_mut() {
            bucket.tokens = (bucket.tokens + bonus_per_worker).min(bucket.capacity);
        }
    }

    /// Returns the global bucket utilization (0.0 = empty, 1.0 = fully consumed).
    pub fn global_utilization(&self) -> f64 {
        self.global_bucket.utilization()
    }

    /// Returns available tokens for a worker after refill.
    pub fn worker_available(
        &mut self,
        worker_id: &str,
        current_time_ms: u64,
    ) -> Result<u64, RateLimitError> {
        let bucket = self
            .worker_buckets
            .get_mut(worker_id)
            .ok_or_else(|| RateLimitError::WorkerNotRegistered(worker_id.to_string()))?;
        Ok(bucket.available(current_time_ms))
    }

    /// Returns total rate limit detections since creation.
    pub fn detection_count(&self) -> u64 {
        self.rate_limit_detections
    }

    /// Returns the number of registered workers.
    pub fn worker_count(&self) -> usize {
        self.worker_buckets.len()
    }
}
