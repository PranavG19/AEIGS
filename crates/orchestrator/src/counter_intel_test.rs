use super::*;

#[test]
fn detection_type_display() {
    assert_eq!(DetectionType::Honeypot.to_string(), "Honeypot");
    assert_eq!(
        DetectionType::ResponseTampering.to_string(),
        "Response Tampering"
    );
    assert_eq!(DetectionType::MitmPresence.to_string(), "MITM Presence");
    assert_eq!(DetectionType::TrackingCanary.to_string(), "Tracking Canary");
    assert_eq!(
        DetectionType::AdaptiveDefense.to_string(),
        "Adaptive Defense"
    );
}

#[test]
fn alert_severity_ordering() {
    assert!(AlertSeverity::Info < AlertSeverity::Warning);
    assert!(AlertSeverity::Warning < AlertSeverity::Critical);
    assert!(AlertSeverity::Critical < AlertSeverity::Emergency);
}

#[test]
fn recommended_action_display() {
    assert_eq!(RecommendedAction::Continue.to_string(), "Continue");
    assert_eq!(RecommendedAction::PauseScan.to_string(), "Pause Scan");
    assert_eq!(RecommendedAction::AbortScan.to_string(), "Abort Scan");
    assert_eq!(RecommendedAction::SwitchProxy.to_string(), "Switch Proxy");
}

#[test]
fn honeypot_indicators_score_none() {
    let indicators = HoneypotIndicators {
        too_many_open_ports: false,
        fake_service_banners: false,
        suspiciously_vulnerable: false,
        known_honeypot_fingerprint: false,
        inconsistent_stack: false,
        deceptive_headers: false,
    };
    assert_eq!(indicators.score(), 0.0);
    assert!(!indicators.is_likely_honeypot());
}

#[test]
fn honeypot_indicators_score_all() {
    let indicators = HoneypotIndicators {
        too_many_open_ports: true,
        fake_service_banners: true,
        suspiciously_vulnerable: true,
        known_honeypot_fingerprint: true,
        inconsistent_stack: true,
        deceptive_headers: true,
    };
    assert_eq!(indicators.score(), 1.0);
    assert!(indicators.is_likely_honeypot());
}

#[test]
fn honeypot_known_fingerprint_triggers() {
    let indicators = HoneypotIndicators {
        too_many_open_ports: false,
        fake_service_banners: false,
        suspiciously_vulnerable: false,
        known_honeypot_fingerprint: true,
        inconsistent_stack: false,
        deceptive_headers: false,
    };
    assert!(indicators.is_likely_honeypot());
}

#[test]
fn honeypot_half_score_triggers() {
    let indicators = HoneypotIndicators {
        too_many_open_ports: true,
        fake_service_banners: true,
        suspiciously_vulnerable: true,
        known_honeypot_fingerprint: false,
        inconsistent_stack: false,
        deceptive_headers: false,
    };
    assert_eq!(indicators.score(), 0.5);
    assert!(indicators.is_likely_honeypot());
}

#[test]
fn check_honeypot_headers_match() {
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "Cowrie SSH".to_string());
    let matches = check_honeypot_headers(&headers);
    assert_eq!(matches.len(), 1);
    assert!(matches[0].contains("Cowrie"));
}

#[test]
fn check_honeypot_headers_no_match() {
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "nginx/1.24.0".to_string());
    let matches = check_honeypot_headers(&headers);
    assert!(matches.is_empty());
}

#[test]
fn check_honeypot_headers_multiple_matches() {
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "Dionaea".to_string());
    headers.insert("X-Powered-By".to_string(), "HoneyTrap 2.0".to_string());
    let matches = check_honeypot_headers(&headers);
    assert_eq!(matches.len(), 2);
}

#[test]
fn tampering_analysis_clean() {
    let headers = HashMap::new();
    let analysis = analyze_response_tampering(200, 200, &headers, "OK");
    assert!(!analysis.is_tampered());
}

#[test]
fn tampering_analysis_status_mismatch() {
    let headers = HashMap::new();
    let analysis = analyze_response_tampering(200, 403, &headers, "Forbidden");
    assert!(analysis.status_code_inconsistent);
    assert!(analysis.is_tampered());
}

#[test]
fn tampering_analysis_content_injection() {
    let headers = HashMap::new();
    let body = "<html><div class=\"captcha-container\">verify</div></html>";
    let analysis = analyze_response_tampering(200, 200, &headers, body);
    assert!(analysis.content_injected);
    assert!(analysis.is_tampered());
}

#[test]
fn tampering_analysis_redirect_to_captcha() {
    let mut headers = HashMap::new();
    headers.insert(
        "location".to_string(),
        "https://target.com/captcha".to_string(),
    );
    let analysis = analyze_response_tampering(200, 302, &mut headers, "");
    assert!(analysis.redirect_to_captcha);
}

#[test]
fn tampering_analysis_tracking_headers() {
    let mut headers = HashMap::new();
    headers.insert("x-security-token".to_string(), "abc123".to_string());
    headers.insert("x-visitor-id".to_string(), "track-456".to_string());
    let analysis = analyze_response_tampering(200, 200, &headers, "OK");
    assert_eq!(analysis.unexpected_headers_added.len(), 2);
    assert!(analysis.is_tampered());
}

#[test]
fn latency_profile_empty_samples() {
    let profile = analyze_latency(&[], 2.0);
    assert_eq!(profile.mean_ms, 0.0);
    assert_eq!(profile.anomaly_count, 0);
}

#[test]
fn latency_profile_normal_traffic() {
    let samples = vec![50.0, 52.0, 48.0, 51.0, 49.0, 50.0, 53.0, 47.0];
    let profile = analyze_latency(&samples, 2.0);
    assert!((profile.mean_ms - 50.0).abs() < 2.0);
    assert!(profile.stddev_ms < 5.0);
    assert_eq!(profile.anomaly_count, 0);
}

#[test]
fn latency_profile_with_mitm_spike() {
    let samples = vec![50.0, 52.0, 48.0, 200.0, 51.0, 49.0, 195.0, 50.0];
    let profile = analyze_latency(&samples, 2.0);
    assert!(profile.anomaly_count >= 1);
}

#[test]
fn detect_canary_tokens_in_body() {
    let body = "Normal content with <img src='http://canarytokens.com/track/abc'>";
    let headers = HashMap::new();
    let detected = detect_canary_tokens(body, &headers);
    assert_eq!(detected.len(), 1);
    assert!(detected[0].contains("canarytokens.com"));
}

#[test]
fn detect_canary_tokens_in_headers() {
    let mut headers = HashMap::new();
    headers.insert(
        "X-Callback".to_string(),
        "https://interact.sh/abc".to_string(),
    );
    let detected = detect_canary_tokens("clean body", &headers);
    assert_eq!(detected.len(), 1);
    assert!(detected[0].contains("interact.sh"));
}

#[test]
fn detect_canary_tokens_none() {
    let headers = HashMap::new();
    let detected = detect_canary_tokens("perfectly normal response", &headers);
    assert!(detected.is_empty());
}

#[test]
fn adaptive_defense_no_adaptation() {
    let error_rates = vec![0.05, 0.04, 0.06, 0.05, 0.04];
    let response_times = vec![50.0, 52.0, 48.0, 51.0, 49.0];
    let profile = detect_adaptive_defense(&error_rates, &response_times);
    assert!(!profile.error_rate_increasing);
    assert!(!profile.response_times_increasing);
    assert_eq!(profile.threat_score(), 0.0);
}

#[test]
fn adaptive_defense_escalating_errors() {
    let error_rates = vec![0.05, 0.06, 0.10, 0.30, 0.60, 0.80];
    let response_times = vec![50.0, 52.0, 55.0, 60.0, 80.0, 120.0];
    let profile = detect_adaptive_defense(&error_rates, &response_times);
    assert!(profile.error_rate_increasing);
    assert!(profile.response_times_increasing);
    assert!(profile.blocking_threshold_lowering);
    assert!(profile.threat_score() > 0.0);
}

#[test]
fn adaptive_defense_too_few_samples() {
    let profile = detect_adaptive_defense(&[0.1, 0.5], &[50.0, 100.0]);
    assert!(!profile.error_rate_increasing);
    assert!(!profile.response_times_increasing);
}

#[test]
fn counter_intel_engine_empty() {
    let engine = CounterIntelEngine::new();
    assert_eq!(engine.alert_count(), 0);
    assert_eq!(engine.overall_threat_score(), 0.0);
    assert_eq!(engine.recommended_action(), RecommendedAction::Continue);
    assert!(!engine.should_pause());
    assert!(engine.max_severity().is_none());
}

#[test]
fn counter_intel_engine_low_threat() {
    let mut engine = CounterIntelEngine::new();
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::TrackingCanary,
        severity: AlertSeverity::Info,
        description: "Minor canary detected".to_string(),
        evidence: vec!["Found interact.sh".to_string()],
        confidence: 0.5,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::Continue,
    });
    assert_eq!(engine.alert_count(), 1);
    assert!(engine.overall_threat_score() < 0.3);
    assert_eq!(engine.recommended_action(), RecommendedAction::Continue);
}

#[test]
fn counter_intel_engine_high_threat() {
    let mut engine = CounterIntelEngine::new();
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::Honeypot,
        severity: AlertSeverity::Emergency,
        description: "Target is a honeypot".to_string(),
        evidence: vec!["Cowrie detected".to_string()],
        confidence: 0.95,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::AbortScan,
    });
    assert!(engine.overall_threat_score() >= 0.9);
    assert_eq!(engine.recommended_action(), RecommendedAction::AbortScan);
    assert!(engine.should_pause());
}

#[test]
fn counter_intel_engine_medium_threat() {
    let mut engine = CounterIntelEngine::new().with_thresholds(0.5, 0.8);
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::ResponseTampering,
        severity: AlertSeverity::Critical,
        description: "WAF injecting content".to_string(),
        evidence: vec!["Captcha container found".to_string()],
        confidence: 0.8,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::ReduceAggression,
    });
    let score = engine.overall_threat_score();
    assert!(score >= 0.5);
    assert!(score < 0.8);
    assert_eq!(engine.recommended_action(), RecommendedAction::PauseScan);
}

#[test]
fn counter_intel_engine_max_severity() {
    let mut engine = CounterIntelEngine::new();
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::TrackingCanary,
        severity: AlertSeverity::Info,
        description: "canary".to_string(),
        evidence: vec![],
        confidence: 0.5,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::Continue,
    });
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::MitmPresence,
        severity: AlertSeverity::Critical,
        description: "mitm".to_string(),
        evidence: vec![],
        confidence: 0.8,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::SwitchProxy,
    });
    assert_eq!(engine.max_severity(), Some(AlertSeverity::Critical));
}

#[test]
fn counter_intel_engine_summary() {
    let mut engine = CounterIntelEngine::new();
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::Honeypot,
        severity: AlertSeverity::Warning,
        description: "Possible honeypot".to_string(),
        evidence: vec!["Unusual ports".to_string()],
        confidence: 0.6,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::ReduceAggression,
    });
    engine.add_alert(CounterIntelAlert {
        detection_type: DetectionType::TrackingCanary,
        severity: AlertSeverity::Info,
        description: "Canary token".to_string(),
        evidence: vec!["ceye.io".to_string()],
        confidence: 0.4,
        timestamp_ms: 1000,
        recommended_action: RecommendedAction::Continue,
    });
    let summary = engine.generate_summary();
    assert_eq!(summary.total_alerts, 2);
    assert!(summary.threat_score > 0.0);
    assert!(summary.alerts_by_type.contains_key("Honeypot"));
    assert!(summary.alerts_by_type.contains_key("Tracking Canary"));
    assert!(summary.generated_at_ms > 0);
}

#[test]
fn is_trend_increasing_flat() {
    assert!(!is_trend_increasing(&[1.0, 1.0, 1.0, 1.0, 1.0]));
}

#[test]
fn is_trend_increasing_ascending() {
    assert!(is_trend_increasing(&[1.0, 2.0, 3.0, 5.0, 8.0, 12.0]));
}

#[test]
fn is_trend_increasing_descending() {
    assert!(!is_trend_increasing(&[10.0, 8.0, 6.0, 4.0, 2.0]));
}

#[test]
fn is_trend_increasing_too_few() {
    assert!(!is_trend_increasing(&[1.0, 5.0]));
}
