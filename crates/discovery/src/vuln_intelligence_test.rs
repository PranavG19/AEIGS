use super::vuln_intelligence::*;

fn make_cve(id: &str, product: &str, versions: &[&str], cvss: f64) -> CveEntry {
    CveEntry {
        cve_id: id.to_string(),
        description: format!("Test CVE for {}", product),
        cvss_score: Some(cvss),
        cvss_vector: None,
        published_date: Some("2024-01-01".to_string()),
        affected_product: product.to_string(),
        affected_versions: versions.iter().map(|v| v.to_string()).collect(),
        cwe_ids: vec![],
    }
}

fn make_epss(cve_id: &str, probability: f64, percentile: f64) -> EpssScore {
    EpssScore {
        cve_id: cve_id.to_string(),
        probability,
        percentile,
        last_updated: Some("2024-06-01".to_string()),
    }
}

fn make_exploit(cve_id: &str, weaponized: bool, maturity: ExploitMaturity) -> ExploitAvailability {
    ExploitAvailability {
        cve_id: cve_id.to_string(),
        public_exploit: true,
        exploit_sources: vec![ExploitSource {
            name: "test-source".to_string(),
            url: Some("https://example.com/exploit".to_string()),
            source_type: ExploitSourceType::GitHub,
            reliability: 0.8,
        }],
        exploit_maturity: maturity,
        weaponized,
    }
}

fn make_threat_actor(name: &str, technologies: &[&str], level: ThreatLevel) -> ThreatActor {
    ThreatActor {
        name: name.to_string(),
        aliases: vec![],
        targeted_sectors: vec!["technology".to_string()],
        targeted_technologies: technologies.iter().map(|t| t.to_string()).collect(),
        ttps: vec!["T1190".to_string()],
        risk_level: level,
        description: format!("Threat actor {}", name),
    }
}

// ─── match_cves ───────────────────────────────────────────────────────────────

#[test]
fn test_match_cves_exact_product() {
    let cves = vec![make_cve("CVE-2024-0001", "nginx", &[], 7.5)];
    let software = vec![("nginx", None)];
    let matches = match_cves(&software, &cves);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].cve.cve_id, "CVE-2024-0001");
    assert_eq!(matches[0].asset_identifier, "nginx");
}

#[test]
fn test_match_cves_case_insensitive() {
    let cves = vec![make_cve("CVE-2024-0002", "Nginx", &[], 6.0)];
    let software = vec![("NGINX", None)];
    let matches = match_cves(&software, &cves);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].cve.cve_id, "CVE-2024-0002");
}

#[test]
fn test_match_cves_partial_product_discovered_contains_cve() {
    let cves = vec![make_cve("CVE-2024-0003", "express", &[], 5.5)];
    let software = vec![("express-server", None)];
    let matches = match_cves(&software, &cves);
    assert_eq!(
        matches.len(),
        1,
        "discovered 'express-server' should contain CVE product 'express'"
    );
}

#[test]
fn test_match_cves_partial_product_cve_contains_discovered() {
    let cves = vec![make_cve("CVE-2024-0004", "apache-tomcat", &[], 8.0)];
    let software = vec![("tomcat", None)];
    let matches = match_cves(&software, &cves);
    assert_eq!(
        matches.len(),
        1,
        "CVE product 'apache-tomcat' should contain discovered 'tomcat'"
    );
}

#[test]
fn test_match_cves_no_match() {
    let cves = vec![make_cve("CVE-2024-0005", "postgresql", &[], 9.0)];
    let software = vec![("redis", None)];
    let matches = match_cves(&software, &cves);
    assert!(matches.is_empty());
}

#[test]
fn test_match_cves_version_exact_match() {
    let cves = vec![make_cve("CVE-2024-0006", "nginx", &["1.18.0"], 7.0)];
    let software = vec![("nginx", Some("1.18.0"))];
    let matches = match_cves(&software, &cves);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].asset_version.as_deref(), Some("1.18.0"));
}

#[test]
fn test_match_cves_version_no_match() {
    let cves = vec![make_cve("CVE-2024-0007", "nginx", &["1.18.0"], 7.0)];
    let software = vec![("nginx", Some("1.20.0"))];
    let matches = match_cves(&software, &cves);
    assert!(
        matches.is_empty(),
        "version 1.20.0 should not match exact affected 1.18.0"
    );
}

#[test]
fn test_match_cves_wildcard_version() {
    let cves = vec![make_cve("CVE-2024-0008", "nginx", &["*"], 6.5)];
    let software = vec![("nginx", Some("99.99.99"))];
    let matches = match_cves(&software, &cves);
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_match_cves_version_range_prefix() {
    let cves = vec![make_cve("CVE-2024-0009", "nginx", &["1.18.*"], 7.0)];

    let hit = match_cves(&[("nginx", Some("1.18.3"))], &cves);
    assert_eq!(hit.len(), 1);

    let miss = match_cves(&[("nginx", Some("1.19.0"))], &cves);
    assert!(miss.is_empty());
}

#[test]
fn test_match_cves_version_less_than() {
    let cves = vec![make_cve("CVE-2024-0010", "nginx", &["<2.0.0"], 8.5)];
    let hit = match_cves(&[("nginx", Some("1.99.9"))], &cves);
    assert_eq!(hit.len(), 1);

    let miss = match_cves(&[("nginx", Some("2.0.0"))], &cves);
    assert!(miss.is_empty());
}

#[test]
fn test_match_cves_version_less_equal() {
    let cves = vec![make_cve("CVE-2024-0011", "nginx", &["<=1.18.0"], 7.0)];
    let hit_eq = match_cves(&[("nginx", Some("1.18.0"))], &cves);
    assert_eq!(hit_eq.len(), 1);

    let hit_lt = match_cves(&[("nginx", Some("1.17.9"))], &cves);
    assert_eq!(hit_lt.len(), 1);

    let miss = match_cves(&[("nginx", Some("1.18.1"))], &cves);
    assert!(miss.is_empty());
}

#[test]
fn test_match_cves_version_greater_than() {
    let cves = vec![make_cve("CVE-2024-0012", "nginx", &[">1.0.0"], 6.0)];
    let hit = match_cves(&[("nginx", Some("1.0.1"))], &cves);
    assert_eq!(hit.len(), 1);

    let miss = match_cves(&[("nginx", Some("1.0.0"))], &cves);
    assert!(miss.is_empty());
}

#[test]
fn test_match_cves_no_discovered_version_matches_any() {
    let cves = vec![make_cve("CVE-2024-0013", "nginx", &["1.18.0"], 7.0)];
    let software = vec![("nginx", None)];
    let matches = match_cves(&software, &cves);
    assert_eq!(
        matches.len(),
        1,
        "None version should match any affected_versions"
    );
}

#[test]
fn test_match_cves_empty_affected_versions_matches_any() {
    let cves = vec![make_cve("CVE-2024-0014", "nginx", &[], 7.0)];
    let software = vec![("nginx", Some("99.0.0"))];
    let matches = match_cves(&software, &cves);
    assert_eq!(
        matches.len(),
        1,
        "empty affected_versions should match any discovered version"
    );
}

#[test]
fn test_match_cves_multiple_software_multiple_cves() {
    let cves = vec![
        make_cve("CVE-2024-1000", "nginx", &[], 7.5),
        make_cve("CVE-2024-1001", "openssl", &[], 9.8),
        make_cve("CVE-2024-1002", "redis", &[], 5.0),
    ];
    let software = vec![("nginx", None), ("openssl", Some("3.0.1"))];
    let matches = match_cves(&software, &cves);
    assert_eq!(matches.len(), 2);
    let ids: Vec<&str> = matches.iter().map(|m| m.cve.cve_id.as_str()).collect();
    assert!(ids.contains(&"CVE-2024-1000"));
    assert!(ids.contains(&"CVE-2024-1001"));
}

// ─── enrich_with_epss ─────────────────────────────────────────────────────────

#[test]
fn test_enrich_with_epss_updates_matching_cve() {
    let cves = vec![make_cve("CVE-2024-2000", "nginx", &[], 7.5)];
    let mut matches = match_cves(&[("nginx", None)], &cves);
    assert!(matches[0].epss.is_none());

    let epss = vec![make_epss("CVE-2024-2000", 0.85, 0.97)];
    enrich_with_epss(&mut matches, &epss);

    assert!(matches[0].epss.is_some());
    let epss_result = matches[0].epss.as_ref().unwrap();
    assert!((epss_result.probability - 0.85).abs() < f64::EPSILON);
    assert!((epss_result.percentile - 0.97).abs() < f64::EPSILON);
}

#[test]
fn test_enrich_with_epss_recalculates_priority() {
    let cves = vec![make_cve("CVE-2024-2001", "nginx", &[], 7.5)];
    let mut matches = match_cves(&[("nginx", None)], &cves);
    let priority_before = matches[0].priority_score;

    let epss = vec![make_epss("CVE-2024-2001", 0.95, 0.99)];
    enrich_with_epss(&mut matches, &epss);

    assert!(
        matches[0].priority_score > priority_before,
        "priority should increase after EPSS enrichment with high probability"
    );
}

#[test]
fn test_enrich_with_epss_no_matching_cve() {
    let cves = vec![make_cve("CVE-2024-2002", "nginx", &[], 7.5)];
    let mut matches = match_cves(&[("nginx", None)], &cves);

    let epss = vec![make_epss("CVE-2024-9999", 0.5, 0.5)];
    enrich_with_epss(&mut matches, &epss);

    assert!(
        matches[0].epss.is_none(),
        "non-matching CVE should not be enriched"
    );
}

// ─── enrich_with_exploits ─────────────────────────────────────────────────────

#[test]
fn test_enrich_with_exploits_attaches_exploit_data() {
    let cves = vec![make_cve("CVE-2024-3000", "nginx", &[], 9.0)];
    let mut matches = match_cves(&[("nginx", None)], &cves);
    assert!(matches[0].exploits.is_empty());

    let exploits = vec![make_exploit(
        "CVE-2024-3000",
        false,
        ExploitMaturity::ProofOfConcept,
    )];
    enrich_with_exploits(&mut matches, &exploits);

    assert_eq!(matches[0].exploits.len(), 1);
    assert!(!matches[0].exploits[0].weaponized);
    assert_eq!(
        matches[0].exploits[0].exploit_maturity,
        ExploitMaturity::ProofOfConcept
    );
}

#[test]
fn test_enrich_with_exploits_weaponized_increases_priority() {
    let cves = vec![make_cve("CVE-2024-3001", "nginx", &[], 9.0)];
    let mut matches_no_weapon = match_cves(&[("nginx", None)], &cves);
    let mut matches_weapon = match_cves(&[("nginx", None)], &cves);

    let exploits_normal = vec![make_exploit(
        "CVE-2024-3001",
        false,
        ExploitMaturity::FunctionalExploit,
    )];
    let exploits_weaponized = vec![make_exploit(
        "CVE-2024-3001",
        true,
        ExploitMaturity::Weaponized,
    )];

    enrich_with_exploits(&mut matches_no_weapon, &exploits_normal);
    enrich_with_exploits(&mut matches_weapon, &exploits_weaponized);

    assert!(
        matches_weapon[0].priority_score > matches_no_weapon[0].priority_score,
        "weaponized exploit should yield higher priority"
    );
}

#[test]
fn test_enrich_with_exploits_no_matching_cve() {
    let cves = vec![make_cve("CVE-2024-3002", "nginx", &[], 7.0)];
    let mut matches = match_cves(&[("nginx", None)], &cves);

    let exploits = vec![make_exploit(
        "CVE-2024-XXXX",
        true,
        ExploitMaturity::Weaponized,
    )];
    enrich_with_exploits(&mut matches, &exploits);

    assert!(matches[0].exploits.is_empty());
}

// ─── correlate_threat_actors ──────────────────────────────────────────────────

#[test]
fn test_correlate_threat_actors_matches_technology() {
    let actors = vec![
        make_threat_actor("APT-Nginx-Group", &["nginx", "apache"], ThreatLevel::High),
        make_threat_actor("APT-Redis-Gang", &["redis"], ThreatLevel::Medium),
    ];
    let tech_stack = vec!["nginx"];
    let result = correlate_threat_actors(&tech_stack, &actors);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "APT-Nginx-Group");
}

#[test]
fn test_correlate_threat_actors_case_insensitive() {
    let actors = vec![make_threat_actor(
        "CaseTester",
        &["Apache"],
        ThreatLevel::Low,
    )];
    let tech_stack = vec!["apache"];
    let result = correlate_threat_actors(&tech_stack, &actors);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_correlate_threat_actors_no_match() {
    let actors = vec![make_threat_actor(
        "APT-ICS",
        &["scada", "plc"],
        ThreatLevel::Critical,
    )];
    let tech_stack = vec!["nginx", "express"];
    let result = correlate_threat_actors(&tech_stack, &actors);
    assert!(result.is_empty());
}

#[test]
fn test_correlate_threat_actors_multiple_matches() {
    let actors = vec![
        make_threat_actor("Group-A", &["nginx"], ThreatLevel::High),
        make_threat_actor("Group-B", &["nginx", "redis"], ThreatLevel::Critical),
        make_threat_actor("Group-C", &["postgres"], ThreatLevel::Medium),
    ];
    let tech_stack = vec!["nginx"];
    let result = correlate_threat_actors(&tech_stack, &actors);
    assert_eq!(result.len(), 2);
    let names: Vec<&str> = result.iter().map(|a| a.name.as_str()).collect();
    assert!(names.contains(&"Group-A"));
    assert!(names.contains(&"Group-B"));
}

// ─── detect_zero_day_indicators ───────────────────────────────────────────────

#[test]
fn test_detect_zero_day_indicators_basic() {
    let anomalies: Vec<(&str, &str, f64, &[&str])> = vec![(
        "unknown_crash",
        "Segfault in nginx/worker",
        0.85,
        &["core dump at 0xdeadbeef", "stack trace captured"],
    )];
    let indicators = detect_zero_day_indicators(&anomalies);
    assert_eq!(indicators.len(), 1);
    assert_eq!(indicators[0].indicator_type, ZeroDayType::UnknownCrash);
    assert!((indicators[0].confidence - 0.85).abs() < f64::EPSILON);
    assert_eq!(indicators[0].evidence.len(), 2);
}

#[test]
fn test_detect_zero_day_indicators_filters_zero_confidence() {
    let anomalies: Vec<(&str, &str, f64, &[&str])> = vec![
        ("anomalous_behavior", "Something weird", 0.0, &["evidence"]),
        ("unknown_crash", "Real crash", 0.5, &["evidence"]),
    ];
    let indicators = detect_zero_day_indicators(&anomalies);
    assert_eq!(
        indicators.len(),
        1,
        "zero confidence anomalies should be filtered"
    );
    assert_eq!(indicators[0].indicator_type, ZeroDayType::UnknownCrash);
}

#[test]
fn test_detect_zero_day_indicators_clamps_confidence() {
    let anomalies: Vec<(&str, &str, f64, &[&str])> = vec![(
        "memory_corruption",
        "Heap overflow in parser",
        5.0,
        &["evidence"],
    )];
    let indicators = detect_zero_day_indicators(&anomalies);
    assert_eq!(indicators.len(), 1);
    assert!(
        indicators[0].confidence <= 1.0,
        "confidence should be clamped to [0,1]"
    );
}

#[test]
fn test_detect_zero_day_indicators_extracts_affected_component() {
    let anomalies: Vec<(&str, &str, f64, &[&str])> = vec![(
        "timing_anomaly",
        "Timing anomaly in auth-handler module",
        0.7,
        &[],
    )];
    let indicators = detect_zero_day_indicators(&anomalies);
    assert_eq!(indicators[0].affected_component, "auth-handler");
}

#[test]
fn test_detect_zero_day_indicators_all_types() {
    let type_map = vec![
        ("anomalous_behavior", ZeroDayType::AnomalousBehavior),
        ("unknown_crash", ZeroDayType::UnknownCrash),
        ("memory_corruption", ZeroDayType::MemoryCorruption),
        ("unexpected_output", ZeroDayType::UnexpectedOutput),
        ("timing_anomaly", ZeroDayType::TimingAnomaly),
        ("resource_exhaustion", ZeroDayType::ResourceExhaustion),
    ];
    for (type_str, expected) in &type_map {
        let anomalies: Vec<(&str, &str, f64, &[&str])> = vec![(type_str, "desc", 0.5, &[])];
        let indicators = detect_zero_day_indicators(&anomalies);
        assert_eq!(
            indicators[0].indicator_type, *expected,
            "type string '{}' should map correctly",
            type_str
        );
    }
}

#[test]
fn test_detect_zero_day_indicators_unknown_type_defaults() {
    let anomalies: Vec<(&str, &str, f64, &[&str])> =
        vec![("totally_invented_type", "Something", 0.3, &[])];
    let indicators = detect_zero_day_indicators(&anomalies);
    assert_eq!(
        indicators[0].indicator_type,
        ZeroDayType::AnomalousBehavior,
        "unknown type string should default to AnomalousBehavior"
    );
}

// ─── calculate_priority_score ─────────────────────────────────────────────────

#[test]
fn test_calculate_priority_score_cvss_only() {
    let cve = make_cve("CVE-2024-4000", "test", &[], 10.0);
    let score = calculate_priority_score(&cve, None, false, false);
    // 0.30 * 10.0 = 3.0
    assert!((score - 3.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_priority_score_all_factors_max() {
    let cve = make_cve("CVE-2024-4001", "test", &[], 10.0);
    let epss = make_epss("CVE-2024-4001", 1.0, 1.0);
    let score = calculate_priority_score(&cve, Some(&epss), true, true);
    // 0.30*10 + 0.30*10 + 0.25*10 + 0.15*10 = 10.0
    assert!((score - 10.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_priority_score_no_cvss() {
    let mut cve = make_cve("CVE-2024-4002", "test", &[], 0.0);
    cve.cvss_score = None;
    let score = calculate_priority_score(&cve, None, false, false);
    assert!((score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_priority_score_exploit_without_weaponized() {
    let cve = make_cve("CVE-2024-4003", "test", &[], 5.0);
    let score = calculate_priority_score(&cve, None, true, false);
    // 0.30*5 + 0.25*10 = 1.5 + 2.5 = 4.0
    assert!((score - 4.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_priority_score_clamps_to_ten() {
    // Even with absurd CVSS (clamped internally), the result should not exceed 10.0.
    let mut cve = make_cve("CVE-2024-4004", "test", &[], 100.0);
    cve.cvss_score = Some(100.0);
    let epss = make_epss("CVE-2024-4004", 5.0, 1.0);
    let score = calculate_priority_score(&cve, Some(&epss), true, true);
    assert!(score <= 10.0, "priority score must be clamped to 10.0");
}

// ─── calculate_risk_score ─────────────────────────────────────────────────────

#[test]
fn test_calculate_risk_score_empty_report() {
    let report = VulnIntelReport {
        target: "test".to_string(),
        matches: vec![],
        zero_day_indicators: vec![],
        threat_actors: vec![],
        total_cves: 0,
        critical_count: 0,
        exploitable_count: 0,
        risk_score: 0.0,
    };
    let score = calculate_risk_score(&report);
    assert!((score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_risk_score_all_critical_exploitable() {
    let report = VulnIntelReport {
        target: "test".to_string(),
        matches: vec![],
        zero_day_indicators: vec![],
        threat_actors: vec![],
        total_cves: 10,
        critical_count: 10,
        exploitable_count: 10,
        risk_score: 0.0,
    };
    let score = calculate_risk_score(&report);
    // critical_ratio=1.0, exploit_ratio=1.0, actor=0, zero_day=0
    // 1.0*0.35 + 1.0*0.30 = 0.65
    assert!((score - 0.65).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_risk_score_with_threat_actors() {
    let report = VulnIntelReport {
        target: "test".to_string(),
        matches: vec![],
        zero_day_indicators: vec![],
        threat_actors: vec![
            make_threat_actor("A", &["x"], ThreatLevel::High),
            make_threat_actor("B", &["y"], ThreatLevel::Critical),
            make_threat_actor("C", &["z"], ThreatLevel::Medium),
        ],
        total_cves: 0,
        critical_count: 0,
        exploitable_count: 0,
        risk_score: 0.0,
    };
    let score = calculate_risk_score(&report);
    // actor_signal = min(3*0.2, 1.0) = 0.6
    // raw = 0.6*0.15 = 0.09
    assert!((score - 0.09).abs() < 1e-9);
}

#[test]
fn test_calculate_risk_score_with_zero_days() {
    let report = VulnIntelReport {
        target: "test".to_string(),
        matches: vec![],
        zero_day_indicators: vec![ZeroDayIndicator {
            indicator_type: ZeroDayType::MemoryCorruption,
            description: "heap overflow".to_string(),
            confidence: 0.9,
            evidence: vec![],
            affected_component: "parser".to_string(),
        }],
        threat_actors: vec![],
        total_cves: 0,
        critical_count: 0,
        exploitable_count: 0,
        risk_score: 0.0,
    };
    let score = calculate_risk_score(&report);
    // zero_day_signal = 0.9, raw = 0.9*0.20 = 0.18
    assert!((score - 0.18).abs() < 1e-9);
}

#[test]
fn test_calculate_risk_score_actor_signal_capped_at_one() {
    let actors: Vec<ThreatActor> = (0..10)
        .map(|i| make_threat_actor(&format!("Actor-{}", i), &["x"], ThreatLevel::High))
        .collect();
    let report = VulnIntelReport {
        target: "test".to_string(),
        matches: vec![],
        zero_day_indicators: vec![],
        threat_actors: actors,
        total_cves: 0,
        critical_count: 0,
        exploitable_count: 0,
        risk_score: 0.0,
    };
    let score = calculate_risk_score(&report);
    // actor_signal = min(10*0.2, 1.0) = 1.0, raw = 1.0*0.15 = 0.15
    assert!((score - 0.15).abs() < 1e-9);
}

// ─── correlate_vulnerabilities (full pipeline) ────────────────────────────────

#[test]
fn test_correlate_vulnerabilities_full_pipeline() {
    let cve_db = vec![
        make_cve("CVE-2024-5000", "nginx", &["<=1.20.0"], 9.5),
        make_cve("CVE-2024-5001", "express", &[], 6.0),
    ];
    let epss = vec![
        make_epss("CVE-2024-5000", 0.92, 0.98),
        make_epss("CVE-2024-5001", 0.10, 0.30),
    ];
    let exploits = vec![make_exploit(
        "CVE-2024-5000",
        true,
        ExploitMaturity::Weaponized,
    )];
    let actors = vec![make_threat_actor(
        "APT-Web",
        &["nginx"],
        ThreatLevel::Critical,
    )];
    let anomalies: Vec<(&str, &str, f64, &[&str])> = vec![(
        "memory_corruption",
        "Heap corruption in nginx/parser",
        0.75,
        &["coredump.bin"],
    )];
    let software = vec![("nginx", Some("1.18.0")), ("express", Some("4.18.2"))];
    let tech_stack = vec!["nginx"];

    let report = correlate_vulnerabilities(
        "https://example.com",
        &software,
        &cve_db,
        &epss,
        &exploits,
        &actors,
        &anomalies,
        &tech_stack,
    );

    assert_eq!(report.target, "https://example.com");
    assert_eq!(report.total_cves, 2);
    assert_eq!(report.critical_count, 1, "one CVE has cvss >= 9.0");
    assert_eq!(report.exploitable_count, 1, "one CVE has exploit data");
    assert_eq!(report.threat_actors.len(), 1);
    assert_eq!(report.zero_day_indicators.len(), 1);
    assert!(report.risk_score > 0.0);

    let nginx_match = report
        .matches
        .iter()
        .find(|m| m.cve.cve_id == "CVE-2024-5000")
        .expect("nginx CVE should be present");
    assert!(nginx_match.epss.is_some());
    assert_eq!(nginx_match.exploits.len(), 1);
    assert!(!nginx_match.threat_actors.is_empty());
}

#[test]
fn test_correlate_vulnerabilities_empty_inputs() {
    let report = correlate_vulnerabilities("https://empty.test", &[], &[], &[], &[], &[], &[], &[]);
    assert_eq!(report.total_cves, 0);
    assert!(report.matches.is_empty());
    assert!(report.zero_day_indicators.is_empty());
    assert!(report.threat_actors.is_empty());
    assert!((report.risk_score - 0.0).abs() < f64::EPSILON);
}

// ─── Display impls ────────────────────────────────────────────────────────────

#[test]
fn test_threat_level_display() {
    assert_eq!(ThreatLevel::Critical.to_string(), "CRITICAL");
    assert_eq!(ThreatLevel::High.to_string(), "HIGH");
    assert_eq!(ThreatLevel::Medium.to_string(), "MEDIUM");
    assert_eq!(ThreatLevel::Low.to_string(), "LOW");
    assert_eq!(ThreatLevel::Unknown.to_string(), "UNKNOWN");
}

#[test]
fn test_zero_day_type_display() {
    assert_eq!(
        ZeroDayType::AnomalousBehavior.to_string(),
        "Anomalous Behavior"
    );
    assert_eq!(ZeroDayType::UnknownCrash.to_string(), "Unknown Crash");
    assert_eq!(
        ZeroDayType::MemoryCorruption.to_string(),
        "Memory Corruption"
    );
    assert_eq!(
        ZeroDayType::UnexpectedOutput.to_string(),
        "Unexpected Output"
    );
    assert_eq!(ZeroDayType::TimingAnomaly.to_string(), "Timing Anomaly");
    assert_eq!(
        ZeroDayType::ResourceExhaustion.to_string(),
        "Resource Exhaustion"
    );
}

#[test]
fn test_exploit_source_type_display() {
    assert_eq!(ExploitSourceType::ExploitDb.to_string(), "Exploit-DB");
    assert_eq!(ExploitSourceType::GitHub.to_string(), "GitHub");
    assert_eq!(ExploitSourceType::Metasploit.to_string(), "Metasploit");
    assert_eq!(
        ExploitSourceType::NucleiTemplate.to_string(),
        "Nuclei Template"
    );
    assert_eq!(ExploitSourceType::PacketStorm.to_string(), "Packet Storm");
    assert_eq!(
        ExploitSourceType::Custom("Shodan".to_string()).to_string(),
        "Custom(Shodan)"
    );
}

#[test]
fn test_exploit_maturity_display_and_ordering() {
    assert_eq!(ExploitMaturity::Unproven.to_string(), "Unproven");
    assert_eq!(
        ExploitMaturity::ProofOfConcept.to_string(),
        "Proof of Concept"
    );
    assert_eq!(
        ExploitMaturity::FunctionalExploit.to_string(),
        "Functional Exploit"
    );
    assert_eq!(ExploitMaturity::Weaponized.to_string(), "Weaponized");
    assert!(ExploitMaturity::Unproven < ExploitMaturity::Weaponized);
}
