use super::*;

fn stealthy_metrics() -> ScanMetrics {
    ScanMetrics {
        total_requests: 500,
        blocked_requests: 5,
        unique_ips_used: 25,
        requests_per_second: 2.0,
        typical_traffic_rps: 10.0,
        fingerprint_changes: 5,
        fingerprint_consistency_score: 0.95,
        cover_traffic_ratio: 0.3,
        scanner_signatures_detected: 0,
        has_proxy_chain: true,
        geo_regions_used: 4,
        session_duration_secs: 3600,
    }
}

fn exposed_metrics() -> ScanMetrics {
    ScanMetrics {
        total_requests: 1000,
        blocked_requests: 800,
        unique_ips_used: 1,
        requests_per_second: 100.0,
        typical_traffic_rps: 10.0,
        fingerprint_changes: 0,
        fingerprint_consistency_score: 0.1,
        cover_traffic_ratio: 0.0,
        scanner_signatures_detected: 5,
        has_proxy_chain: false,
        geo_regions_used: 1,
        session_duration_secs: 60,
    }
}

#[test]
fn stealthy_scan_scores_high() {
    let report = DetectionScorer::score(&stealthy_metrics());
    assert!(report.overall_score >= 75.0);
    assert!(matches!(
        report.grade,
        StealthGrade::Stealthy | StealthGrade::Undetectable
    ));
}

#[test]
fn exposed_scan_scores_low() {
    let report = DetectionScorer::score(&exposed_metrics());
    assert!(report.overall_score < 50.0);
    assert!(matches!(
        report.grade,
        StealthGrade::Exposed | StealthGrade::Risky
    ));
}

#[test]
fn factors_all_present() {
    let report = DetectionScorer::score(&stealthy_metrics());
    let factor_names: Vec<&str> = report.factors.iter().map(|f| f.name.as_str()).collect();
    assert!(factor_names.contains(&"IP Diversity"));
    assert!(factor_names.contains(&"Request Rate"));
    assert!(factor_names.contains(&"Fingerprint Consistency"));
    assert!(factor_names.contains(&"WAF Trigger Rate"));
    assert!(factor_names.contains(&"Cover Traffic"));
    assert!(factor_names.contains(&"Scanner Signatures"));
    assert!(factor_names.contains(&"Proxy Usage"));
    assert!(factor_names.contains(&"Geographic Diversity"));
    assert_eq!(report.factors.len(), 8);
}

#[test]
fn score_clamped_0_to_100() {
    let report = DetectionScorer::score(&stealthy_metrics());
    assert!(report.overall_score >= 0.0);
    assert!(report.overall_score <= 100.0);
    for factor in &report.factors {
        assert!(factor.score >= 0.0);
        assert!(factor.score <= 100.0);
    }
}

#[test]
fn exposed_scan_generates_recommendations() {
    let report = DetectionScorer::score(&exposed_metrics());
    assert!(!report.recommendations.is_empty());
}

#[test]
fn stealthy_scan_has_few_recommendations() {
    let report = DetectionScorer::score(&stealthy_metrics());
    assert!(report.recommendations.len() <= 2);
}

#[test]
fn recommendations_sorted_by_priority() {
    let report = DetectionScorer::score(&exposed_metrics());
    for i in 1..report.recommendations.len() {
        assert!(report.recommendations[i].priority >= report.recommendations[i - 1].priority);
    }
}

#[test]
fn high_ip_diversity_scores_well() {
    let metrics = ScanMetrics {
        unique_ips_used: 50,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let ip_factor = report
        .factors
        .iter()
        .find(|f| f.name == "IP Diversity")
        .unwrap();
    assert!(ip_factor.score >= 90.0);
}

#[test]
fn single_ip_scores_poorly() {
    let metrics = ScanMetrics {
        unique_ips_used: 1,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let ip_factor = report
        .factors
        .iter()
        .find(|f| f.name == "IP Diversity")
        .unwrap();
    assert!(ip_factor.score <= 25.0);
}

#[test]
fn low_request_rate_scores_well() {
    let metrics = ScanMetrics {
        requests_per_second: 1.0,
        typical_traffic_rps: 10.0,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let rate_factor = report
        .factors
        .iter()
        .find(|f| f.name == "Request Rate")
        .unwrap();
    assert!(rate_factor.score >= 80.0);
}

#[test]
fn high_request_rate_scores_poorly() {
    let metrics = ScanMetrics {
        requests_per_second: 100.0,
        typical_traffic_rps: 10.0,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let rate_factor = report
        .factors
        .iter()
        .find(|f| f.name == "Request Rate")
        .unwrap();
    assert!(rate_factor.score <= 25.0);
}

#[test]
fn no_blocks_scores_waf_well() {
    let metrics = ScanMetrics {
        total_requests: 100,
        blocked_requests: 0,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let waf_factor = report
        .factors
        .iter()
        .find(|f| f.name == "WAF Trigger Rate")
        .unwrap();
    assert_eq!(waf_factor.score, 100.0);
}

#[test]
fn all_blocked_scores_waf_zero() {
    let metrics = ScanMetrics {
        total_requests: 100,
        blocked_requests: 100,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let waf_factor = report
        .factors
        .iter()
        .find(|f| f.name == "WAF Trigger Rate")
        .unwrap();
    assert_eq!(waf_factor.score, 0.0);
}

#[test]
fn zero_scanner_signatures_perfect_score() {
    let metrics = ScanMetrics {
        scanner_signatures_detected: 0,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let sig_factor = report
        .factors
        .iter()
        .find(|f| f.name == "Scanner Signatures")
        .unwrap();
    assert_eq!(sig_factor.score, 100.0);
}

#[test]
fn proxy_chain_improves_score() {
    let metrics_with = ScanMetrics {
        has_proxy_chain: true,
        ..Default::default()
    };
    let metrics_without = ScanMetrics {
        has_proxy_chain: false,
        ..Default::default()
    };
    let report_with = DetectionScorer::score(&metrics_with);
    let report_without = DetectionScorer::score(&metrics_without);
    let proxy_with = report_with
        .factors
        .iter()
        .find(|f| f.name == "Proxy Usage")
        .unwrap();
    let proxy_without = report_without
        .factors
        .iter()
        .find(|f| f.name == "Proxy Usage")
        .unwrap();
    assert!(proxy_with.score > proxy_without.score);
}

#[test]
fn grade_display() {
    assert_eq!(format!("{}", StealthGrade::Undetectable), "Undetectable");
    assert_eq!(format!("{}", StealthGrade::Stealthy), "Stealthy");
    assert_eq!(format!("{}", StealthGrade::Moderate), "Moderate");
    assert_eq!(format!("{}", StealthGrade::Risky), "Risky");
    assert_eq!(format!("{}", StealthGrade::Exposed), "Exposed");
}

#[test]
fn priority_display() {
    assert_eq!(format!("{}", RecommendationPriority::Critical), "CRITICAL");
    assert_eq!(format!("{}", RecommendationPriority::High), "HIGH");
    assert_eq!(format!("{}", RecommendationPriority::Medium), "MEDIUM");
    assert_eq!(format!("{}", RecommendationPriority::Low), "LOW");
}

#[test]
fn default_metrics_produce_report() {
    let report = DetectionScorer::score(&ScanMetrics::default());
    assert!(report.overall_score >= 0.0);
    assert!(!report.factors.is_empty());
}

#[test]
fn cover_traffic_high_ratio_scores_well() {
    let metrics = ScanMetrics {
        cover_traffic_ratio: 0.5,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let ct_factor = report
        .factors
        .iter()
        .find(|f| f.name == "Cover Traffic")
        .unwrap();
    assert!(ct_factor.score >= 90.0);
}

#[test]
fn geo_diversity_many_regions_scores_well() {
    let metrics = ScanMetrics {
        geo_regions_used: 7,
        ..Default::default()
    };
    let report = DetectionScorer::score(&metrics);
    let geo_factor = report
        .factors
        .iter()
        .find(|f| f.name == "Geographic Diversity")
        .unwrap();
    assert!(geo_factor.score >= 90.0);
}
