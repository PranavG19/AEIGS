#[cfg(test)]
mod tests {
    use crate::executor::{ExecutorError, RateLimiter, RequestExecutor};
    use std::time::Duration;

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(10);
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn rate_limiter_reports_current_rate() {
        let mut limiter = RateLimiter::new(100);
        for _ in 0..3 {
            limiter.try_acquire();
        }
        assert_eq!(limiter.current_rate(), 3);
    }

    #[test]
    fn rate_limiter_max_rps() {
        let limiter = RateLimiter::new(42);
        assert_eq!(limiter.max_rps(), 42);
    }

    #[test]
    fn executor_builds_request() {
        let mut executor = RequestExecutor::new(
            "http://localhost:8080".to_string(),
            100,
            Duration::from_secs(30),
        );

        let req = executor.build_request("/users", "GET", "id", "1");
        assert_eq!(req.endpoint, "http://localhost:8080/users");
        assert_eq!(req.method, "GET");
        assert_eq!(req.parameter_name, "id");
        assert_eq!(req.payload, "1");
        assert_eq!(req.request_id, 1);

        let req2 = executor.build_request("/items", "POST", "name", "test");
        assert_eq!(req2.request_id, 2);
    }

    #[test]
    fn executor_tracks_requests_and_errors() {
        let mut executor =
            RequestExecutor::new("http://localhost".to_string(), 100, Duration::from_secs(30));

        assert_eq!(executor.total_requests(), 0);
        assert_eq!(executor.total_errors(), 0);
        assert_eq!(executor.error_rate(), 0.0);

        executor.record_success();
        executor.record_success();
        executor.record_error();

        assert_eq!(executor.total_requests(), 3);
        assert_eq!(executor.total_errors(), 1);
        assert!((executor.error_rate() - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn executor_rate_limiting() {
        let mut executor =
            RequestExecutor::new("http://localhost".to_string(), 2, Duration::from_secs(30));

        assert!(executor.try_acquire_rate_limit());
        assert!(executor.try_acquire_rate_limit());
        assert!(!executor.try_acquire_rate_limit());
    }

    #[test]
    fn executor_base_url_and_timeout() {
        let executor = RequestExecutor::new(
            "http://example.com".to_string(),
            100,
            Duration::from_secs(60),
        );
        assert_eq!(executor.base_url(), "http://example.com");
        assert_eq!(executor.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = ExecutorError::NetworkError("connection refused".to_string());
        assert!(err.to_string().contains("network error"));

        let err = ExecutorError::Timeout("30s exceeded".to_string());
        assert!(err.to_string().contains("timeout"));

        let err = ExecutorError::RateLimited;
        assert!(err.to_string().contains("rate limited"));
    }
}
