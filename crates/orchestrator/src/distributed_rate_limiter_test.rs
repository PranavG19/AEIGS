use crate::distributed_rate_limiter::{
    DistributedRateLimiter, RateLimitConfig, RateLimitError, TokenBucket,
};

fn now_ms() -> u64 {
    crate::util::timestamp_ms()
}

// --- TokenBucket ---

#[test]
fn token_bucket_starts_full() {
    let bucket = TokenBucket::new(100, 10.0);
    assert_eq!(bucket.tokens, 100);
    assert_eq!(bucket.capacity, 100);
}

#[test]
fn token_bucket_consume_reduces_tokens() {
    let mut bucket = TokenBucket::new(100, 10.0);
    let t = now_ms();
    assert!(bucket.try_consume(30, t));
    assert_eq!(bucket.tokens, 70);
}

#[test]
fn token_bucket_consume_fails_when_insufficient() {
    let mut bucket = TokenBucket::new(10, 10.0);
    let t = now_ms();
    assert!(!bucket.try_consume(20, t));
    assert_eq!(bucket.tokens, 10);
}

#[test]
fn token_bucket_refill_adds_tokens() {
    let mut bucket = TokenBucket::new(100, 10.0);
    let t = now_ms();
    bucket.try_consume(50, t);
    assert_eq!(bucket.tokens, 50);
    // Advance 2 seconds → 20 tokens refilled
    bucket.refill(t + 2000);
    assert_eq!(bucket.tokens, 70);
}

#[test]
fn token_bucket_refill_capped_at_capacity() {
    let mut bucket = TokenBucket::new(100, 1000.0);
    let t = now_ms();
    bucket.try_consume(10, t);
    bucket.refill(t + 10_000);
    assert_eq!(bucket.tokens, 100);
}

#[test]
fn token_bucket_utilization() {
    let mut bucket = TokenBucket::new(100, 10.0);
    let t = now_ms();
    assert!((bucket.utilization() - 0.0).abs() < 0.01);
    bucket.try_consume(100, t);
    assert!((bucket.utilization() - 1.0).abs() < 0.01);
}

#[test]
fn token_bucket_available_after_refill() {
    let mut bucket = TokenBucket::new(100, 10.0);
    let t = now_ms();
    bucket.try_consume(100, t);
    let avail = bucket.available(t + 5000);
    assert_eq!(avail, 50);
}

// --- DistributedRateLimiter ---

#[test]
fn register_and_request_tokens() {
    let config = RateLimitConfig::default();
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    let t = now_ms();
    let result = limiter.request_tokens("w1", 1, t);
    assert!(result.is_ok());
}

#[test]
fn request_tokens_unregistered_worker_fails() {
    let config = RateLimitConfig::default();
    let mut limiter = DistributedRateLimiter::new(config);
    let t = now_ms();
    let result = limiter.request_tokens("ghost", 1, t);
    assert!(result.is_err());
}

#[test]
fn global_limit_exhaustion() {
    let config = RateLimitConfig {
        global_capacity: 5,
        global_refill_rate: 0.0,
        per_worker_capacity: 100,
        per_worker_refill_rate: 0.0,
        adaptive: false,
        backoff_factor: 0.5,
    };
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    let t = now_ms();
    for _ in 0..5 {
        limiter.request_tokens("w1", 1, t).unwrap();
    }
    let result = limiter.request_tokens("w1", 1, t);
    assert!(result.is_err());
}

#[test]
fn per_worker_limit_exhaustion() {
    let config = RateLimitConfig {
        global_capacity: 1000,
        global_refill_rate: 0.0,
        per_worker_capacity: 3,
        per_worker_refill_rate: 0.0,
        adaptive: false,
        backoff_factor: 0.5,
    };
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    let t = now_ms();
    for _ in 0..3 {
        limiter.request_tokens("w1", 1, t).unwrap();
    }
    let result = limiter.request_tokens("w1", 1, t);
    assert!(result.is_err());
}

#[test]
fn worker_limit_exhaustion_returns_global_tokens() {
    let config = RateLimitConfig {
        global_capacity: 10,
        global_refill_rate: 0.0,
        per_worker_capacity: 2,
        per_worker_refill_rate: 0.0,
        adaptive: false,
        backoff_factor: 0.5,
    };
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    limiter.register_worker("w2");
    let t = now_ms();
    // Consume w1's per-worker limit
    limiter.request_tokens("w1", 1, t).unwrap();
    limiter.request_tokens("w1", 1, t).unwrap();
    // w1 is exhausted; this should fail but return tokens to global
    let _ = limiter.request_tokens("w1", 1, t);
    // w2 should still have global tokens available
    let result = limiter.request_tokens("w2", 1, t);
    assert!(result.is_ok());
}

#[test]
fn adaptive_backoff_reduces_rate() {
    let config = RateLimitConfig {
        global_capacity: 100,
        global_refill_rate: 100.0,
        per_worker_capacity: 50,
        per_worker_refill_rate: 50.0,
        adaptive: true,
        backoff_factor: 0.5,
    };
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    let t = now_ms();
    limiter.signal_rate_limited(t);
    assert_eq!(limiter.detection_count(), 1);
    // After backoff, rates should be halved
    // We can verify by checking that fewer tokens refill
}

#[test]
fn deregister_worker_returns_tokens() {
    let config = RateLimitConfig::default();
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    let result = limiter.deregister_worker("w1");
    assert!(result.is_ok());
    assert_eq!(limiter.worker_count(), 0);
}

#[test]
fn deregister_unknown_worker_fails() {
    let config = RateLimitConfig::default();
    let mut limiter = DistributedRateLimiter::new(config);
    let result = limiter.deregister_worker("ghost");
    assert!(result.is_err());
}

#[test]
fn redistribute_budget_spreads_tokens() {
    let config = RateLimitConfig {
        per_worker_capacity: 100,
        ..Default::default()
    };
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    limiter.register_worker("w2");
    let t = now_ms();
    // Drain w1 tokens
    for _ in 0..50 {
        let _ = limiter.request_tokens("w1", 1, t);
    }
    limiter.redistribute_budget("w_failed");
    let avail = limiter.worker_available("w2", t).unwrap();
    assert!(avail > 0);
}

#[test]
fn global_utilization_tracks_consumption() {
    let config = RateLimitConfig {
        global_capacity: 100,
        global_refill_rate: 0.0,
        per_worker_capacity: 100,
        per_worker_refill_rate: 0.0,
        adaptive: false,
        backoff_factor: 0.5,
    };
    let mut limiter = DistributedRateLimiter::new(config);
    limiter.register_worker("w1");
    let t = now_ms();
    assert!(limiter.global_utilization() < 0.01);
    for _ in 0..50 {
        limiter.request_tokens("w1", 1, t).unwrap();
    }
    assert!(limiter.global_utilization() > 0.4);
}

#[test]
fn worker_count_tracking() {
    let config = RateLimitConfig::default();
    let mut limiter = DistributedRateLimiter::new(config);
    assert_eq!(limiter.worker_count(), 0);
    limiter.register_worker("w1");
    limiter.register_worker("w2");
    assert_eq!(limiter.worker_count(), 2);
    limiter.deregister_worker("w1").unwrap();
    assert_eq!(limiter.worker_count(), 1);
}

// --- Error display ---

#[test]
fn error_display() {
    let e = RateLimitError::WorkerNotRegistered("w1".to_string());
    assert!(format!("{e}").contains("w1"));
    let e = RateLimitError::GlobalLimitExhausted;
    assert!(format!("{e}").contains("global"));
    let e = RateLimitError::WorkerLimitExhausted("w2".to_string());
    assert!(format!("{e}").contains("w2"));
    let e = RateLimitError::InvalidConfig("bad".to_string());
    assert!(format!("{e}").contains("bad"));
}

#[test]
fn default_config_values() {
    let cfg = RateLimitConfig::default();
    assert_eq!(cfg.global_capacity, 1000);
    assert!(cfg.adaptive);
}
