#[cfg(test)]
mod tests {
    use crate::rate_limit_detector::{
        BurstProbeResult, RateLimitProbeResult, WindowProbeResult, build_rate_limit_profile,
        detect_burst_allowance, detect_limit_response_code, detect_limit_window, detect_rate_limit,
    };

    fn probe(rate: f64, total: u32, limited: u32, code: Option<u16>) -> RateLimitProbeResult {
        RateLimitProbeResult {
            request_rate: rate,
            total_sent: total,
            limited_count: limited,
            limit_status_code: code,
        }
    }

    fn window(wait: u32, recovered: bool) -> WindowProbeResult {
        WindowProbeResult {
            wait_seconds: wait,
            recovered,
        }
    }

    #[test]
    fn detect_rate_limit_empty_input() {
        assert!(detect_rate_limit(&[]).is_none());
    }

    #[test]
    fn detect_rate_limit_no_probes_meet_threshold() {
        let probes = vec![
            probe(10.0, 100, 10, Some(429)),
            probe(20.0, 100, 49, Some(429)),
        ];
        assert!(detect_rate_limit(&probes).is_none());
    }

    #[test]
    fn detect_rate_limit_single_match() {
        let probes = vec![probe(50.0, 100, 51, Some(429))];
        assert_eq!(detect_rate_limit(&probes), Some(50.0));
    }

    #[test]
    fn detect_rate_limit_multiple_matches_returns_lowest_rate() {
        let probes = vec![
            probe(100.0, 100, 80, Some(429)),
            probe(50.0, 100, 60, Some(429)),
            probe(75.0, 100, 70, Some(429)),
        ];
        assert_eq!(detect_rate_limit(&probes), Some(50.0));
    }

    #[test]
    fn detect_rate_limit_excludes_zero_total_sent() {
        let probes = vec![probe(10.0, 0, 0, Some(429))];
        assert!(detect_rate_limit(&probes).is_none());
    }

    #[test]
    fn detect_rate_limit_threshold_boundary_exactly_half() {
        let probes = vec![probe(30.0, 100, 50, Some(429))];
        assert!(detect_rate_limit(&probes).is_none());
    }

    #[test]
    fn detect_rate_limit_threshold_boundary_just_over_half() {
        let probes = vec![probe(30.0, 100, 51, Some(429))];
        assert_eq!(detect_rate_limit(&probes), Some(30.0));
    }

    #[test]
    fn detect_rate_limit_mixed_qualifying_and_not() {
        let probes = vec![
            probe(10.0, 100, 10, Some(429)),
            probe(25.0, 100, 80, Some(429)),
            probe(50.0, 100, 90, Some(429)),
        ];
        assert_eq!(detect_rate_limit(&probes), Some(25.0));
    }

    #[test]
    fn detect_burst_allowance_some() {
        let burst = BurstProbeResult {
            total_sent: 100,
            first_limited_at: Some(42),
            limit_status_code: Some(429),
        };
        assert_eq!(detect_burst_allowance(&burst), Some(42));
    }

    #[test]
    fn detect_burst_allowance_none() {
        let burst = BurstProbeResult {
            total_sent: 100,
            first_limited_at: None,
            limit_status_code: None,
        };
        assert!(detect_burst_allowance(&burst).is_none());
    }

    #[test]
    fn detect_limit_window_empty_input() {
        assert!(detect_limit_window(&[]).is_none());
    }

    #[test]
    fn detect_limit_window_none_recovered() {
        let probes = vec![window(30, false), window(60, false)];
        assert!(detect_limit_window(&probes).is_none());
    }

    #[test]
    fn detect_limit_window_single_recovery() {
        let probes = vec![window(30, false), window(60, true)];
        assert_eq!(detect_limit_window(&probes), Some(60));
    }

    #[test]
    fn detect_limit_window_multiple_recoveries_returns_min() {
        let probes = vec![window(30, true), window(60, true), window(120, true)];
        assert_eq!(detect_limit_window(&probes), Some(30));
    }

    #[test]
    fn detect_limit_window_mixed_recovered_and_not() {
        let probes = vec![
            window(10, false),
            window(60, true),
            window(30, true),
            window(90, false),
        ];
        assert_eq!(detect_limit_window(&probes), Some(30));
    }

    #[test]
    fn detect_limit_response_code_empty_defaults_429() {
        assert_eq!(detect_limit_response_code(&[]), 429);
    }

    #[test]
    fn detect_limit_response_code_single_code() {
        let probes = vec![probe(10.0, 100, 80, Some(503))];
        assert_eq!(detect_limit_response_code(&probes), 503);
    }

    #[test]
    fn detect_limit_response_code_most_common_wins() {
        let probes = vec![
            probe(10.0, 100, 80, Some(429)),
            probe(20.0, 100, 80, Some(503)),
            probe(30.0, 100, 80, Some(429)),
            probe(40.0, 100, 80, Some(429)),
        ];
        assert_eq!(detect_limit_response_code(&probes), 429);
    }

    #[test]
    fn detect_limit_response_code_all_none_defaults_429() {
        let probes = vec![probe(10.0, 100, 80, None), probe(20.0, 100, 80, None)];
        assert_eq!(detect_limit_response_code(&probes), 429);
    }

    #[test]
    fn detect_limit_response_code_ignores_none_entries() {
        let probes = vec![
            probe(10.0, 100, 80, None),
            probe(20.0, 100, 80, Some(503)),
            probe(30.0, 100, 80, None),
        ];
        assert_eq!(detect_limit_response_code(&probes), 503);
    }

    #[test]
    fn build_rate_limit_profile_returns_none_when_no_limit_detected() {
        let probes = vec![probe(10.0, 100, 10, Some(429))];
        let result = build_rate_limit_profile(&probes, None, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn build_rate_limit_profile_returns_none_for_empty_probes() {
        let result = build_rate_limit_profile(&[], None, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn build_rate_limit_profile_full_profile() {
        let probes = vec![
            probe(50.0, 100, 80, Some(429)),
            probe(100.0, 100, 90, Some(429)),
        ];
        let burst = BurstProbeResult {
            total_sent: 200,
            first_limited_at: Some(75),
            limit_status_code: Some(429),
        };
        let windows = vec![window(30, false), window(60, true)];

        let profile = build_rate_limit_profile(&probes, Some(&burst), &windows).unwrap();

        assert_eq!(profile.requests_per_second, Some(50.0));
        assert_eq!(profile.burst_allowance, Some(75));
        assert_eq!(profile.limit_response_code, 429);
        assert_eq!(profile.limit_window_seconds, Some(60));
    }

    #[test]
    fn build_rate_limit_profile_no_burst() {
        let probes = vec![probe(50.0, 100, 80, Some(429))];
        let windows = vec![window(30, true)];

        let profile = build_rate_limit_profile(&probes, None, &windows).unwrap();

        assert_eq!(profile.requests_per_second, Some(50.0));
        assert!(profile.burst_allowance.is_none());
        assert_eq!(profile.limit_response_code, 429);
        assert_eq!(profile.limit_window_seconds, Some(30));
    }

    #[test]
    fn build_rate_limit_profile_no_window() {
        let probes = vec![probe(50.0, 100, 80, Some(503))];
        let burst = BurstProbeResult {
            total_sent: 100,
            first_limited_at: Some(20),
            limit_status_code: Some(503),
        };

        let profile = build_rate_limit_profile(&probes, Some(&burst), &[]).unwrap();

        assert_eq!(profile.requests_per_second, Some(50.0));
        assert_eq!(profile.burst_allowance, Some(20));
        assert_eq!(profile.limit_response_code, 503);
        assert!(profile.limit_window_seconds.is_none());
    }

    #[test]
    fn build_rate_limit_profile_burst_with_no_first_limited() {
        let probes = vec![probe(50.0, 100, 80, Some(429))];
        let burst = BurstProbeResult {
            total_sent: 100,
            first_limited_at: None,
            limit_status_code: None,
        };

        let profile = build_rate_limit_profile(&probes, Some(&burst), &[]).unwrap();

        assert_eq!(profile.requests_per_second, Some(50.0));
        assert!(profile.burst_allowance.is_none());
    }

    #[test]
    fn serde_roundtrip_rate_limit_probe_result() {
        let original = probe(42.5, 200, 150, Some(429));
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: RateLimitProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_rate, 42.5);
        assert_eq!(deserialized.total_sent, 200);
        assert_eq!(deserialized.limited_count, 150);
        assert_eq!(deserialized.limit_status_code, Some(429));
    }

    #[test]
    fn serde_roundtrip_rate_limit_probe_result_none_code() {
        let original = probe(10.0, 50, 25, None);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: RateLimitProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_rate, 10.0);
        assert_eq!(deserialized.total_sent, 50);
        assert_eq!(deserialized.limited_count, 25);
        assert!(deserialized.limit_status_code.is_none());
    }

    #[test]
    fn serde_roundtrip_burst_probe_result() {
        let original = BurstProbeResult {
            total_sent: 500,
            first_limited_at: Some(100),
            limit_status_code: Some(503),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: BurstProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_sent, 500);
        assert_eq!(deserialized.first_limited_at, Some(100));
        assert_eq!(deserialized.limit_status_code, Some(503));
    }

    #[test]
    fn serde_roundtrip_burst_probe_result_none_fields() {
        let original = BurstProbeResult {
            total_sent: 50,
            first_limited_at: None,
            limit_status_code: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: BurstProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_sent, 50);
        assert!(deserialized.first_limited_at.is_none());
        assert!(deserialized.limit_status_code.is_none());
    }

    #[test]
    fn serde_roundtrip_window_probe_result() {
        let original = window(120, true);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: WindowProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.wait_seconds, 120);
        assert!(deserialized.recovered);
    }

    #[test]
    fn serde_roundtrip_window_probe_result_not_recovered() {
        let original = window(30, false);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: WindowProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.wait_seconds, 30);
        assert!(!deserialized.recovered);
    }
}
