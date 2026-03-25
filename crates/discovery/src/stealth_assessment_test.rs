use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::stealth_assessment::*;

fn make_profile() -> ScanProfile {
    ScanProfile::default()
}

#[test]
fn assessor_builds_without_panic() {
    let _assessor = StealthAssessor::new();
}

#[test]
fn empty_profile_scores_well() {
    let assessor = StealthAssessor::new();
    let mut profile = make_profile();
    profile.source_ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    ];
    let result = assessor.assess(&profile);
    assert!(
        result.overall_score >= 0.5,
        "empty profile should score reasonably: {}",
        result.overall_score
    );
}

#[test]
fn aggressive_scan_scores_poorly() {
    let assessor = StealthAssessor::new();
    let profile = ScanProfile {
        request_timestamps: vec![
            Duration::from_millis(0),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ],
        user_agents_used: vec!["sqlmap/1.7".to_string()],
        payloads_sent: vec![
            "' OR '1'='1".to_string(),
            "<script>alert(1)</script>".to_string(),
            "../../etc/passwd".to_string(),
        ],
        source_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        headers_sent: HashMap::new(),
        total_requests: 500,
        requests_per_second: 200.0,
        unique_paths_hit: 490,
    };
    let result = assessor.assess(&profile);
    assert!(
        result.overall_score < 0.5,
        "aggressive scan should score poorly: {}",
        result.overall_score
    );
    assert!(
        result.grade == StealthGrade::Poor || result.grade == StealthGrade::Compromised,
        "grade should be Poor or Compromised: {:?}",
        result.grade
    );
    assert!(
        !result.recommendations.is_empty(),
        "should have recommendations"
    );
}

#[test]
fn stealthy_scan_scores_well() {
    let assessor = StealthAssessor::new();
    let profile = ScanProfile {
        request_timestamps: vec![
            Duration::from_millis(0),
            Duration::from_millis(342),
            Duration::from_millis(891),
            Duration::from_millis(1103),
            Duration::from_millis(1876),
        ],
        user_agents_used: vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        ],
        payloads_sent: vec!["search_query".to_string(), "page=2".to_string()],
        source_ips: vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        ],
        headers_sent: HashMap::from([
            ("Accept".to_string(), "text/html".to_string()),
            ("Accept-Language".to_string(), "en-US".to_string()),
        ]),
        total_requests: 50,
        requests_per_second: 3.0,
        unique_paths_hit: 20,
    };
    let result = assessor.assess(&profile);
    assert!(
        result.overall_score >= 0.7,
        "stealthy scan should score well: {}",
        result.overall_score
    );
}

#[test]
fn scanner_user_agent_detected() {
    let assessor = StealthAssessor::new();
    let mut profile = make_profile();
    profile.user_agents_used = vec!["Nikto/2.1.6".to_string()];
    profile.source_ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
    ];
    let result = assessor.assess(&profile);
    let ua_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.category == StealthCategory::HeaderStealth && f.severity == StealthSeverity::Critical
        })
        .collect();
    assert!(!ua_findings.is_empty(), "should flag scanner UA");
}

#[test]
fn high_rps_flagged() {
    let assessor = StealthAssessor::new();
    let mut profile = make_profile();
    profile.requests_per_second = 150.0;
    profile.source_ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
    ];
    let result = assessor.assess(&profile);
    let timing_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == StealthCategory::TimingAnalysis)
        .collect();
    assert!(!timing_findings.is_empty(), "should flag high RPS");
}

#[test]
fn single_ip_flagged() {
    let assessor = StealthAssessor::new();
    let mut profile = make_profile();
    profile.source_ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
    let result = assessor.assess(&profile);
    let ip_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == StealthCategory::IpDiversity)
        .collect();
    assert!(!ip_findings.is_empty(), "should flag single IP");
}

#[test]
fn known_payload_signatures_flagged() {
    let assessor = StealthAssessor::new();
    let mut profile = make_profile();
    profile.payloads_sent = vec![
        "' OR '1'='1".to_string(),
        "UNION SELECT * FROM users".to_string(),
    ];
    profile.source_ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
    ];
    let result = assessor.assess(&profile);
    let payload_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == StealthCategory::PayloadDetection)
        .collect();
    assert!(!payload_findings.is_empty(), "should flag known payloads");
}

#[test]
fn score_to_grade_thresholds() {
    assert_eq!(score_to_grade(0.90), StealthGrade::Excellent);
    assert_eq!(score_to_grade(0.85), StealthGrade::Excellent);
    assert_eq!(score_to_grade(0.75), StealthGrade::Good);
    assert_eq!(score_to_grade(0.55), StealthGrade::Fair);
    assert_eq!(score_to_grade(0.35), StealthGrade::Poor);
    assert_eq!(score_to_grade(0.10), StealthGrade::Compromised);
}

#[test]
fn grade_display() {
    assert_eq!(format!("{}", StealthGrade::Excellent), "Excellent");
    assert_eq!(format!("{}", StealthGrade::Compromised), "Compromised");
}

#[test]
fn category_display() {
    assert_eq!(
        format!("{}", StealthCategory::RequestPattern),
        "Request Pattern"
    );
    assert_eq!(
        format!("{}", StealthCategory::TimingAnalysis),
        "Timing Analysis"
    );
}

#[test]
fn severity_display() {
    assert_eq!(format!("{}", StealthSeverity::Info), "Info");
    assert_eq!(format!("{}", StealthSeverity::Critical), "Critical");
}

#[test]
fn priority_display() {
    assert_eq!(format!("{}", RecommendationPriority::Low), "Low");
    assert_eq!(format!("{}", RecommendationPriority::Critical), "Critical");
}

#[test]
fn priority_ordering() {
    assert!(RecommendationPriority::Low < RecommendationPriority::Medium);
    assert!(RecommendationPriority::Medium < RecommendationPriority::High);
    assert!(RecommendationPriority::High < RecommendationPriority::Critical);
}

#[test]
fn compute_regularity_uniform_intervals() {
    let intervals = vec![100.0, 100.0, 100.0, 100.0];
    let regularity = compute_regularity(&intervals).unwrap();
    assert!(
        regularity > 0.95,
        "uniform intervals should be highly regular: {regularity}"
    );
}

#[test]
fn compute_regularity_random_intervals() {
    let intervals = vec![50.0, 200.0, 10.0, 500.0, 30.0];
    let regularity = compute_regularity(&intervals).unwrap();
    assert!(
        regularity < 0.5,
        "random intervals should have low regularity: {regularity}"
    );
}

#[test]
fn compute_regularity_insufficient_data() {
    assert!(compute_regularity(&[]).is_none());
    assert!(compute_regularity(&[100.0]).is_none());
}

#[test]
fn compute_subnet_diversity_same_subnet() {
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    ];
    let diversity = compute_subnet_diversity(&ips);
    assert!(
        diversity < 0.5,
        "same /24 should have low diversity: {diversity}"
    );
}

#[test]
fn compute_subnet_diversity_different_subnets() {
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    ];
    let diversity = compute_subnet_diversity(&ips);
    assert_eq!(diversity, 1.0, "all different subnets: {diversity}");
}

#[test]
fn compute_subnet_diversity_single_ip() {
    let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
    let diversity = compute_subnet_diversity(&ips);
    assert_eq!(diversity, 0.0);
}

#[test]
fn recommendations_sorted_by_priority() {
    let assessor = StealthAssessor::new();
    let profile = ScanProfile {
        request_timestamps: vec![
            Duration::from_millis(0),
            Duration::from_millis(10),
            Duration::from_millis(20),
        ],
        user_agents_used: vec!["sqlmap/1.7".to_string()],
        payloads_sent: vec!["' OR '1'='1".to_string()],
        source_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        headers_sent: HashMap::new(),
        total_requests: 200,
        requests_per_second: 150.0,
        unique_paths_hit: 195,
    };
    let result = assessor.assess(&profile);
    for i in 1..result.recommendations.len() {
        assert!(
            result.recommendations[i - 1].priority >= result.recommendations[i].priority,
            "recommendations should be sorted by priority descending"
        );
    }
}

#[test]
fn missing_headers_noted() {
    let assessor = StealthAssessor::new();
    let mut profile = make_profile();
    profile.headers_sent = HashMap::new();
    profile.source_ips = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
    ];
    let result = assessor.assess(&profile);
    let header_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.category == StealthCategory::HeaderStealth && f.description.contains("Missing")
        })
        .collect();
    assert!(
        header_findings.len() >= 2,
        "should note missing Accept and Accept-Language headers"
    );
}

#[test]
fn scan_profile_default() {
    let profile = ScanProfile::default();
    assert_eq!(profile.total_requests, 0);
    assert_eq!(profile.requests_per_second, 0.0);
    assert!(profile.payloads_sent.is_empty());
    assert!(profile.source_ips.is_empty());
}

#[test]
fn overall_score_always_bounded() {
    let assessor = StealthAssessor::new();
    let profile = ScanProfile {
        request_timestamps: vec![],
        user_agents_used: vec![
            "sqlmap".to_string(),
            "nikto".to_string(),
            "nmap".to_string(),
        ],
        payloads_sent: (0..50).map(|_| "' OR '1'='1".to_string()).collect(),
        source_ips: vec![],
        headers_sent: HashMap::new(),
        total_requests: 10000,
        requests_per_second: 1000.0,
        unique_paths_hit: 9999,
    };
    let result = assessor.assess(&profile);
    assert!(result.overall_score >= 0.0, "score >= 0");
    assert!(result.overall_score <= 1.0, "score <= 1");
}
