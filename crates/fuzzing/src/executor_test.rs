#[cfg(test)]
mod tests {
    use crate::executor::{ExecutorError, RateLimiter, RequestExecutor, browser_default_headers};
    use crate::stealth_config::StealthConfig;
    use aegis_protocol::scope_attestation::{
        ScopeDocument, SignedScopeAttestation, sign_scope_document,
    };
    use ed25519_dalek::SigningKey;
    use std::time::Duration;

    fn make_attestation(target: &str, valid_until: &str) -> SignedScopeAttestation {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let doc = ScopeDocument {
            target: target.to_string(),
            authorized_by: "test-admin".to_string(),
            valid_until: valid_until.to_string(),
            scope_id: "test-scope-001".to_string(),
        };
        sign_scope_document(&doc, &signing_key)
    }

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
            None,
        )
        .unwrap();

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
        let mut executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap();

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
        let mut executor = RequestExecutor::new(
            "http://localhost".to_string(),
            2,
            Duration::from_secs(30),
            None,
        )
        .unwrap();

        assert!(executor.try_acquire_rate_limit());
        assert!(executor.try_acquire_rate_limit());
        assert!(!executor.try_acquire_rate_limit());
    }

    #[test]
    fn executor_base_url_and_timeout() {
        let executor = RequestExecutor::new(
            "http://localhost:9090".to_string(),
            100,
            Duration::from_secs(60),
            None,
        )
        .unwrap();
        assert_eq!(executor.base_url(), "http://localhost:9090");
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

        let err = ExecutorError::TargetNotAllowed("host is remote".to_string());
        assert!(err.to_string().contains("target not allowed"));
    }

    #[test]
    fn browser_default_headers_returns_five_entries() {
        let headers = browser_default_headers();
        assert_eq!(headers.len(), 5);
    }

    #[test]
    fn build_request_includes_all_default_headers() {
        let mut executor = RequestExecutor::new(
            "http://localhost:8080".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap();

        let req = executor.build_request("/api", "GET", "q", "test");
        assert_eq!(req.headers.len(), 5);

        let header_names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(header_names.contains(&"User-Agent"));
        assert!(header_names.contains(&"Accept"));
        assert!(header_names.contains(&"Accept-Language"));
        assert!(header_names.contains(&"Accept-Encoding"));
        assert!(header_names.contains(&"Connection"));
    }

    #[test]
    fn with_default_headers_replaces_defaults() {
        let custom_headers = vec![
            ("X-Custom".to_string(), "value1".to_string()),
            ("Authorization".to_string(), "Bearer token".to_string()),
        ];

        let mut executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap()
        .with_default_headers(custom_headers);

        let req = executor.build_request("/test", "POST", "body", "data");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].0, "X-Custom");
        assert_eq!(req.headers[0].1, "value1");
        assert_eq!(req.headers[1].0, "Authorization");
        assert_eq!(req.headers[1].1, "Bearer token");
    }

    #[test]
    fn default_headers_present_without_additional_headers() {
        let mut executor = RequestExecutor::new(
            "http://localhost:3000".to_string(),
            50,
            Duration::from_secs(10),
            None,
        )
        .unwrap();

        let req = executor.build_request("/health", "GET", "", "");
        assert_eq!(req.headers.len(), 5);

        let defaults = browser_default_headers();
        for (i, (key, value)) in defaults.iter().enumerate() {
            assert_eq!(&req.headers[i].0, key);
            assert_eq!(&req.headers[i].1, value);
        }
    }

    #[test]
    fn stealth_config_none_by_default() {
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap();
        assert!(executor.stealth_config().is_none());
    }

    #[test]
    fn with_stealth_config_sets_config() {
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap()
        .with_stealth_config(StealthConfig::default());
        assert!(executor.stealth_config().is_some());
    }

    #[test]
    fn with_stealth_config_default() {
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap()
        .with_stealth_config(StealthConfig::default());
        let config = executor.stealth_config().unwrap();
        assert_eq!(*config, StealthConfig::default());
    }

    #[test]
    fn with_stealth_config_aggressive() {
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap()
        .with_stealth_config(StealthConfig::aggressive());
        let config = executor.stealth_config().unwrap();
        assert_eq!(*config, StealthConfig::aggressive());
    }

    #[test]
    fn with_stealth_config_paranoid() {
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap()
        .with_stealth_config(StealthConfig::paranoid());
        let config = executor.stealth_config().unwrap();
        assert_eq!(*config, StealthConfig::paranoid());
    }

    #[test]
    fn stealth_config_preserves_values() {
        let custom = StealthConfig::default().with_max_requests_per_second(42.0);
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap()
        .with_stealth_config(custom);
        let config = executor.stealth_config().unwrap();
        assert!((config.max_requests_per_second - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn new_rejects_non_localhost_target() {
        let result = RequestExecutor::new(
            "http://example.com".to_string(),
            100,
            Duration::from_secs(30),
            None,
        );
        let Err(err) = result else {
            panic!("expected error for non-localhost target");
        };
        assert!(matches!(err, ExecutorError::TargetNotAllowed(_)));
        assert!(err.to_string().contains("not localhost"));
    }

    #[test]
    fn new_rejects_remote_ip_target() {
        let result = RequestExecutor::new(
            "http://192.168.1.1:8080".to_string(),
            100,
            Duration::from_secs(30),
            None,
        );
        let Err(err) = result else {
            panic!("expected error for non-localhost target");
        };
        assert!(matches!(err, ExecutorError::TargetNotAllowed(_)));
    }

    #[test]
    fn new_accepts_localhost_url() {
        let result = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn new_accepts_localhost_with_port() {
        let result = RequestExecutor::new(
            "http://localhost:8080".to_string(),
            100,
            Duration::from_secs(30),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn new_accepts_127_0_0_1() {
        let result = RequestExecutor::new(
            "http://127.0.0.1:3000".to_string(),
            100,
            Duration::from_secs(30),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn new_accepts_ipv6_loopback() {
        let result = RequestExecutor::new(
            "http://[::1]:9090".to_string(),
            100,
            Duration::from_secs(30),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn new_accepts_remote_target_with_valid_attestation() {
        let attestation = make_attestation("http://example.com:8080", "2099-12-31");
        let result = RequestExecutor::new(
            "http://example.com:8080".to_string(),
            100,
            Duration::from_secs(30),
            Some(attestation),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn new_rejects_remote_target_with_mismatched_attestation() {
        let attestation = make_attestation("http://other.com", "2099-12-31");
        let result = RequestExecutor::new(
            "http://example.com:8080".to_string(),
            100,
            Duration::from_secs(30),
            Some(attestation),
        );
        let Err(err) = result else {
            panic!("expected error for mismatched attestation");
        };
        assert!(matches!(err, ExecutorError::TargetNotAllowed(_)));
    }

    #[test]
    fn new_rejects_remote_target_with_expired_attestation() {
        let attestation = make_attestation("http://example.com", "2020-01-01");
        let result = RequestExecutor::new(
            "http://example.com".to_string(),
            100,
            Duration::from_secs(30),
            Some(attestation),
        );
        let Err(err) = result else {
            panic!("expected error for expired attestation");
        };
        assert!(matches!(err, ExecutorError::TargetNotAllowed(_)));
    }

    #[test]
    fn scope_attestation_none_by_default() {
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            None,
        )
        .unwrap();
        assert!(executor.scope_attestation().is_none());
    }

    #[test]
    fn scope_attestation_stored_when_provided() {
        let attestation = make_attestation("http://localhost", "2099-12-31");
        let executor = RequestExecutor::new(
            "http://localhost".to_string(),
            100,
            Duration::from_secs(30),
            Some(attestation),
        )
        .unwrap();
        assert!(executor.scope_attestation().is_some());
    }
}
