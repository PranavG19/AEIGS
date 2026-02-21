#[cfg(test)]
mod tests {
    use crate::request_patterns::{
        BrowsingPattern, COMMON_SUBRESOURCES, CoverTrafficConfig, DEFAULT_INTER_BATCH_DELAY_MS,
        MAX_BATCH_SIZE, NavigationStep, PatternError, build_burst_batch, build_navigation_chain,
        build_parallel_resources_batch, build_sequential_batch, estimate_batch_duration_ms,
        inject_cover_traffic, plan_timing,
    };

    #[test]
    fn browsing_pattern_display_sequential() {
        assert_eq!(BrowsingPattern::Sequential.to_string(), "Sequential");
    }

    #[test]
    fn browsing_pattern_display_burst_then_pause() {
        assert_eq!(
            BrowsingPattern::BurstThenPause.to_string(),
            "Burst Then Pause"
        );
    }

    #[test]
    fn browsing_pattern_display_parallel_resources() {
        assert_eq!(
            BrowsingPattern::ParallelResources.to_string(),
            "Parallel Resources"
        );
    }

    #[test]
    fn browsing_pattern_display_navigation_chain() {
        assert_eq!(
            BrowsingPattern::NavigationChain.to_string(),
            "Navigation Chain"
        );
    }

    #[test]
    fn browsing_pattern_equality() {
        assert_eq!(BrowsingPattern::Sequential, BrowsingPattern::Sequential);
        assert_ne!(BrowsingPattern::Sequential, BrowsingPattern::BurstThenPause);
    }

    #[test]
    fn build_sequential_batch_creates_correct_count() {
        let batch = build_sequential_batch(&["/a", "/b", "/c"], "GET", 100).unwrap();
        assert_eq!(batch.requests.len(), 3);
        assert_eq!(batch.pattern, BrowsingPattern::Sequential);
    }

    #[test]
    fn build_sequential_batch_applies_delay() {
        let batch = build_sequential_batch(&["/a", "/b"], "POST", 250).unwrap();
        for req in &batch.requests {
            assert_eq!(req.delay_before_ms, 250);
        }
    }

    #[test]
    fn build_sequential_batch_sets_method() {
        let batch = build_sequential_batch(&["/x"], "PUT", 0).unwrap();
        assert_eq!(batch.requests[0].method, "PUT");
    }

    #[test]
    fn build_sequential_batch_empty_endpoints_errors() {
        let result = build_sequential_batch(&[], "GET", 100);
        assert_eq!(result.unwrap_err(), PatternError::EmptyBatch);
    }

    #[test]
    fn build_sequential_batch_oversized_errors() {
        let endpoints: Vec<&str> = (0..65).map(|_| "/x").collect();
        let result = build_sequential_batch(&endpoints, "GET", 0);
        assert!(matches!(
            result.unwrap_err(),
            PatternError::TooManyRequests(65)
        ));
    }

    #[test]
    fn build_sequential_batch_default_inter_batch_delay() {
        let batch = build_sequential_batch(&["/a"], "GET", 0).unwrap();
        assert_eq!(batch.inter_batch_delay_ms, DEFAULT_INTER_BATCH_DELAY_MS);
    }

    #[test]
    fn build_burst_batch_creates_burst_pattern() {
        let batch = build_burst_batch(&["/a", "/b"], "GET", 5, 2000).unwrap();
        assert_eq!(batch.pattern, BrowsingPattern::BurstThenPause);
    }

    #[test]
    fn build_burst_batch_applies_inter_batch_delay() {
        let batch = build_burst_batch(&["/a"], "GET", 5, 3000).unwrap();
        assert_eq!(batch.inter_batch_delay_ms, 3000);
    }

    #[test]
    fn build_burst_batch_applies_burst_delay() {
        let batch = build_burst_batch(&["/a", "/b", "/c"], "GET", 10, 2000).unwrap();
        for req in &batch.requests {
            assert_eq!(req.delay_before_ms, 10);
        }
    }

    #[test]
    fn build_burst_batch_empty_errors() {
        let result = build_burst_batch(&[], "GET", 5, 2000);
        assert_eq!(result.unwrap_err(), PatternError::EmptyBatch);
    }

    #[test]
    fn build_parallel_resources_batch_first_request_is_page() {
        let batch = build_parallel_resources_batch("/index.html", &["/style.css"]).unwrap();
        assert_eq!(batch.requests[0].endpoint, "/index.html");
        assert_eq!(batch.requests[0].delay_before_ms, 0);
        assert_eq!(batch.requests[0].priority, 0);
    }

    #[test]
    fn build_parallel_resources_batch_subresources_have_referer() {
        let batch = build_parallel_resources_batch("/page", &["/style.css", "/app.js"]).unwrap();
        for req in &batch.requests[1..] {
            assert_eq!(req.referer.as_deref(), Some("/page"));
        }
    }

    #[test]
    fn build_parallel_resources_batch_subresources_have_priority_one() {
        let batch =
            build_parallel_resources_batch("/page", &["/a.css", "/b.js", "/c.png"]).unwrap();
        for req in &batch.requests[1..] {
            assert_eq!(req.priority, 1);
        }
    }

    #[test]
    fn build_parallel_resources_batch_subresource_delays_in_range() {
        let batch =
            build_parallel_resources_batch("/page", &["/a", "/b", "/c", "/d", "/e"]).unwrap();
        for req in &batch.requests[1..] {
            assert!(req.delay_before_ms >= 10);
            assert!(req.delay_before_ms <= 50);
        }
    }

    #[test]
    fn build_parallel_resources_batch_pattern_is_parallel() {
        let batch = build_parallel_resources_batch("/p", &["/s"]).unwrap();
        assert_eq!(batch.pattern, BrowsingPattern::ParallelResources);
    }

    #[test]
    fn build_navigation_chain_single_step() {
        let steps = vec![NavigationStep {
            page_url: "/home".to_string(),
            subresources: vec!["/style.css".to_string()],
            api_calls: vec!["/api/user".to_string()],
        }];
        let batches = build_navigation_chain(&steps).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].requests.len(), 3);
        assert_eq!(batches[0].pattern, BrowsingPattern::NavigationChain);
    }

    #[test]
    fn build_navigation_chain_multiple_steps() {
        let steps = vec![
            NavigationStep {
                page_url: "/home".to_string(),
                subresources: vec![],
                api_calls: vec![],
            },
            NavigationStep {
                page_url: "/about".to_string(),
                subresources: vec!["/about.css".to_string()],
                api_calls: vec![],
            },
        ];
        let batches = build_navigation_chain(&steps).unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].requests.len(), 1);
        assert_eq!(batches[1].requests.len(), 2);
    }

    #[test]
    fn build_navigation_chain_empty_steps_errors() {
        let result = build_navigation_chain(&[]);
        assert_eq!(result.unwrap_err(), PatternError::EmptyBatch);
    }

    #[test]
    fn build_navigation_chain_inter_batch_delay_is_1000() {
        let steps = vec![NavigationStep {
            page_url: "/p".to_string(),
            subresources: vec![],
            api_calls: vec![],
        }];
        let batches = build_navigation_chain(&steps).unwrap();
        assert_eq!(batches[0].inter_batch_delay_ms, 1000);
    }

    #[test]
    fn build_navigation_chain_api_calls_have_priority_two() {
        let steps = vec![NavigationStep {
            page_url: "/p".to_string(),
            subresources: vec!["/s".to_string()],
            api_calls: vec!["/api/data".to_string()],
        }];
        let batches = build_navigation_chain(&steps).unwrap();
        let api_req = &batches[0].requests[2];
        assert_eq!(api_req.priority, 2);
        assert_eq!(api_req.endpoint, "/api/data");
    }

    #[test]
    fn inject_cover_traffic_adds_correct_count() {
        let batch = build_sequential_batch(&["/real"], "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/health".to_string()],
            cover_ratio: 3.0,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config).unwrap();
        assert_eq!(result.requests.len(), 4);
    }

    #[test]
    fn inject_cover_traffic_marks_cover_as_cover_traffic() {
        let batch = build_sequential_batch(&["/real"], "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/decoy".to_string()],
            cover_ratio: 2.0,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config).unwrap();
        assert!(!result.requests[0].is_cover_traffic);
        assert!(result.requests[1].is_cover_traffic);
        assert!(result.requests[2].is_cover_traffic);
    }

    #[test]
    fn inject_cover_traffic_invalid_ratio_errors() {
        let batch = build_sequential_batch(&["/a"], "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/x".to_string()],
            cover_ratio: -1.0,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config);
        assert!(matches!(
            result.unwrap_err(),
            PatternError::InvalidCoverRatio(_)
        ));
    }

    #[test]
    fn inject_cover_traffic_nan_ratio_errors() {
        let batch = build_sequential_batch(&["/a"], "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/x".to_string()],
            cover_ratio: f64::NAN,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config);
        assert!(matches!(
            result.unwrap_err(),
            PatternError::InvalidCoverRatio(_)
        ));
    }

    #[test]
    fn inject_cover_traffic_respects_max_batch_size() {
        let endpoints: Vec<&str> = (0..32).map(|_| "/r").collect();
        let batch = build_sequential_batch(&endpoints, "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/c".to_string()],
            cover_ratio: 2.0,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config);
        assert!(matches!(
            result.unwrap_err(),
            PatternError::TooManyRequests(_)
        ));
    }

    #[test]
    fn inject_cover_traffic_randomize_reorders() {
        let batch = build_sequential_batch(&["/r1", "/r2"], "GET", 0).unwrap();
        let config_ordered = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/c1".to_string(), "/c2".to_string()],
            cover_ratio: 2.0,
            randomize_order: false,
        };
        let config_shuffled = CoverTrafficConfig {
            randomize_order: true,
            ..config_ordered.clone()
        };
        let ordered = inject_cover_traffic(&batch, &config_ordered).unwrap();
        let shuffled = inject_cover_traffic(&batch, &config_shuffled).unwrap();
        let ordered_eps: Vec<&str> = ordered
            .requests
            .iter()
            .map(|r| r.endpoint.as_str())
            .collect();
        let shuffled_eps: Vec<&str> = shuffled
            .requests
            .iter()
            .map(|r| r.endpoint.as_str())
            .collect();
        assert_ne!(ordered_eps, shuffled_eps);
    }

    #[test]
    fn inject_cover_traffic_disabled_returns_clone() {
        let batch = build_sequential_batch(&["/a"], "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: false,
            cover_endpoints: vec!["/c".to_string()],
            cover_ratio: 5.0,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config).unwrap();
        assert_eq!(result.requests.len(), 1);
    }

    #[test]
    fn plan_timing_sequential_ordering() {
        let batch = build_sequential_batch(&["/a", "/b", "/c"], "GET", 100).unwrap();
        let timing = plan_timing(&batch, 0);
        assert_eq!(timing.len(), 3);
        assert_eq!(timing[0].0, 0);
        assert_eq!(timing[1].0, 1);
        assert_eq!(timing[2].0, 2);
    }

    #[test]
    fn plan_timing_respects_priority() {
        let batch = build_parallel_resources_batch("/page", &["/style.css", "/app.js"]).unwrap();
        let timing = plan_timing(&batch, 0);
        assert_eq!(timing[0].0, 0);
    }

    #[test]
    fn plan_timing_cumulative_delays() {
        let batch = build_sequential_batch(&["/a", "/b"], "GET", 100).unwrap();
        let timing = plan_timing(&batch, 0);
        assert_eq!(timing[0].1, 100);
        assert_eq!(timing[1].1, 200);
    }

    #[test]
    fn plan_timing_with_jitter_adds_variation() {
        let batch = build_sequential_batch(&["/a", "/b", "/c"], "GET", 50).unwrap();
        let timing_no_jitter = plan_timing(&batch, 0);
        let timing_with_jitter = plan_timing(&batch, 10);
        assert_ne!(timing_no_jitter[2].1, timing_with_jitter[2].1);
    }

    #[test]
    fn estimate_batch_duration_includes_delays() {
        let batch = build_sequential_batch(&["/a", "/b"], "GET", 100).unwrap();
        let duration = estimate_batch_duration_ms(&batch, 0);
        assert!(duration >= 200);
    }

    #[test]
    fn estimate_batch_duration_includes_inter_batch_delay() {
        let batch = build_burst_batch(&["/a"], "GET", 10, 5000).unwrap();
        let duration = estimate_batch_duration_ms(&batch, 0);
        assert!(duration >= 5000);
    }

    #[test]
    fn pattern_error_display_empty_batch() {
        let err = PatternError::EmptyBatch;
        assert_eq!(err.to_string(), "batch has no requests");
    }

    #[test]
    fn pattern_error_display_invalid_cover_ratio() {
        let err = PatternError::InvalidCoverRatio("-1".to_string());
        assert!(err.to_string().contains("invalid cover ratio"));
    }

    #[test]
    fn pattern_error_display_too_many_requests() {
        let err = PatternError::TooManyRequests(100);
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("64"));
    }

    #[test]
    fn common_subresources_is_non_empty() {
        assert!(!COMMON_SUBRESOURCES.is_empty());
        assert_eq!(COMMON_SUBRESOURCES.len(), 6);
    }

    #[test]
    fn planned_request_default_cover_traffic_is_false() {
        let batch = build_sequential_batch(&["/a"], "GET", 0).unwrap();
        assert!(!batch.requests[0].is_cover_traffic);
    }

    #[test]
    fn browsing_pattern_serde_roundtrip() {
        let pattern = BrowsingPattern::ParallelResources;
        let json = serde_json::to_string(&pattern).unwrap();
        let deserialized: BrowsingPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern, deserialized);
    }

    #[test]
    fn planned_request_serde_roundtrip() {
        let batch = build_sequential_batch(&["/test"], "POST", 50).unwrap();
        let json = serde_json::to_string(&batch.requests[0]).unwrap();
        let deserialized: crate::request_patterns::PlannedRequest =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.endpoint, "/test");
        assert_eq!(deserialized.method, "POST");
        assert_eq!(deserialized.delay_before_ms, 50);
    }

    #[test]
    fn build_parallel_resources_batch_no_subresources() {
        let batch = build_parallel_resources_batch("/page", &[]).unwrap();
        assert_eq!(batch.requests.len(), 1);
        assert_eq!(batch.requests[0].endpoint, "/page");
    }

    #[test]
    fn max_batch_size_exactly_accepted() {
        let endpoints: Vec<&str> = (0..MAX_BATCH_SIZE).map(|_| "/x").collect();
        let result = build_sequential_batch(&endpoints, "GET", 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().requests.len(), MAX_BATCH_SIZE);
    }

    #[test]
    fn navigation_chain_subresources_have_referer() {
        let steps = vec![NavigationStep {
            page_url: "/home".to_string(),
            subresources: vec!["/home.css".to_string()],
            api_calls: vec![],
        }];
        let batches = build_navigation_chain(&steps).unwrap();
        assert_eq!(batches[0].requests[1].referer.as_deref(), Some("/home"));
    }

    #[test]
    fn inject_cover_traffic_cycles_cover_endpoints() {
        let batch = build_sequential_batch(&["/real"], "GET", 0).unwrap();
        let config = CoverTrafficConfig {
            enabled: true,
            cover_endpoints: vec!["/c1".to_string(), "/c2".to_string()],
            cover_ratio: 4.0,
            randomize_order: false,
        };
        let result = inject_cover_traffic(&batch, &config).unwrap();
        let cover_eps: Vec<&str> = result.requests[1..]
            .iter()
            .map(|r| r.endpoint.as_str())
            .collect();
        assert_eq!(cover_eps, vec!["/c1", "/c2", "/c1", "/c2"]);
    }
}
