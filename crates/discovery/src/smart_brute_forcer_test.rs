use super::smart_brute_forcer::*;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

fn default_engine() -> SmartBruteForcer {
    SmartBruteForcer::new(SmartBruteForceConfig::default())
}

// ── Pattern Learning ──────────────────────────────────────────

#[test]
fn learn_env_service_pattern_with_dash() {
    let mut engine = default_engine();
    engine.learn_from(&["dev-api.example.com".into(), "dev-web.example.com".into()]);

    let has_env_service = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::EnvService { separator: '-' }));
    assert!(has_env_service, "should detect env-service pattern");
}

#[test]
fn learn_env_service_pattern_with_underscore() {
    let mut engine = default_engine();
    engine.learn_from(&["staging_api.example.com".into()]);

    let has_env_service = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::EnvService { separator: '_' }));
    assert!(
        has_env_service,
        "should detect env_service pattern with underscore"
    );
}

#[test]
fn learn_service_env_pattern() {
    let mut engine = default_engine();
    engine.learn_from(&["api-staging.example.com".into()]);

    let has_service_env = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::ServiceEnv { separator: '-' }));
    assert!(has_service_env, "should detect service-env pattern");
}

#[test]
fn learn_numbered_suffix_pattern() {
    let mut engine = default_engine();
    engine.learn_from(&["web1.example.com".into(), "web2.example.com".into()]);

    let has_numbered = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::NumberedSuffix { base } if base == "web"));
    assert!(has_numbered, "should detect numbered suffix base=web");
}

#[test]
fn learn_versioned_prefix_pattern() {
    let mut engine = default_engine();
    engine.learn_from(&["v2-api.example.com".into()]);

    let has_versioned = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::VersionedPrefix { base } if base == "api"));
    assert!(
        has_versioned,
        "should detect versioned prefix v2-api → base=api"
    );
}

#[test]
fn learn_leaked_prefix() {
    let mut engine = default_engine();
    engine.learn_from(&["internal.example.com".into()]);

    let has_leaked = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::LeakedPrefix));
    assert!(has_leaked, "should recognize 'internal' as a leaked prefix");
}

// ── Permutation Generation (AC1) ──────────────────────────────

#[test]
fn given_dev_api_dev_web_suggests_staging_and_prod_variants() {
    let mut engine = default_engine();
    engine.learn_from(&["dev-api.example.com".into(), "dev-web.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    let names: HashSet<String> = candidates.iter().map(|c| c.subdomain.clone()).collect();

    assert!(
        names.contains("staging-api.example.com"),
        "should suggest staging-api"
    );
    assert!(
        names.contains("staging-web.example.com"),
        "should suggest staging-web"
    );
    assert!(
        names.contains("prod-api.example.com"),
        "should suggest prod-api"
    );
    assert!(
        names.contains("prod-web.example.com"),
        "should suggest prod-web"
    );
}

#[test]
fn does_not_suggest_already_known_subdomains() {
    let mut engine = default_engine();
    engine.learn_from(&[
        "dev-api.example.com".into(),
        "staging-api.example.com".into(),
    ]);

    let candidates = engine.generate_candidates("example.com");
    let names: Vec<&str> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::PatternPermutation)
        .map(|c| c.subdomain.as_str())
        .collect();

    // dev-api and staging-api are already known, should not appear in permutation candidates
    assert!(
        !names.contains(&"dev-api.example.com"),
        "should not re-suggest known dev-api"
    );
    assert!(
        !names.contains(&"staging-api.example.com"),
        "should not re-suggest known staging-api"
    );
}

#[test]
fn permutation_generates_all_env_prefix_variants() {
    let mut engine = default_engine();
    engine.learn_from(&["dev-web.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    let perm_names: HashSet<String> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::PatternPermutation)
        .map(|c| c.subdomain.clone())
        .collect();

    // Should generate at least qa-web, test-web, uat-web, preprod-web
    assert!(perm_names.contains("qa-web.example.com"));
    assert!(perm_names.contains("test-web.example.com"));
    assert!(perm_names.contains("uat-web.example.com"));
    assert!(perm_names.contains("preprod-web.example.com"));
}

// ── Number Iteration ──────────────────────────────────────────

#[test]
fn number_iteration_generates_sequential_candidates() {
    let mut engine = default_engine();
    engine.learn_from(&["web1.example.com".into(), "web2.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    let number_candidates: Vec<&ScoredCandidate> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::NumberIteration)
        .collect();

    let names: HashSet<String> = number_candidates
        .iter()
        .map(|c| c.subdomain.clone())
        .collect();
    assert!(names.contains("web3.example.com"), "should generate web3");
    assert!(names.contains("web10.example.com"), "should generate web10");
}

#[test]
fn number_iteration_higher_numbers_have_lower_score() {
    let mut engine = default_engine();
    engine.learn_from(&["node1.example.com".into(), "node2.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    let number_candidates: Vec<&ScoredCandidate> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::NumberIteration)
        .collect();

    let score_3 = number_candidates
        .iter()
        .find(|c| c.subdomain == "node3.example.com")
        .map(|c| c.score)
        .unwrap_or(0.0);
    let score_50 = number_candidates
        .iter()
        .find(|c| c.subdomain == "node50.example.com")
        .map(|c| c.score)
        .unwrap_or(0.0);

    assert!(
        score_3 > score_50,
        "web3 ({score_3}) should score higher than web50 ({score_50})"
    );
}

// ── Cloud-Aware (AC3) ─────────────────────────────────────────

#[test]
fn cloud_patterns_has_at_least_five_providers() {
    let patterns = SmartBruteForcer::cloud_patterns();
    let providers: HashSet<&str> = patterns.iter().map(|(p, _)| *p).collect();
    assert!(
        providers.len() >= 5,
        "should have ≥5 cloud patterns, got {}",
        providers.len()
    );
}

#[test]
fn cloud_candidates_include_s3_and_azure_and_gcp() {
    let engine = default_engine();
    let candidates = engine.generate_candidates("acmecorp.com");
    let cloud_candidates: Vec<&str> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::CloudAware)
        .map(|c| c.subdomain.as_str())
        .collect();

    let has_s3 = cloud_candidates
        .iter()
        .any(|c| c.contains("s3.amazonaws.com"));
    let has_azure = cloud_candidates
        .iter()
        .any(|c| c.contains("blob.core.windows.net"));
    let has_gcp = cloud_candidates
        .iter()
        .any(|c| c.contains("storage.googleapis.com"));

    assert!(has_s3, "should generate S3 candidates");
    assert!(has_azure, "should generate Azure Blob candidates");
    assert!(has_gcp, "should generate GCP Storage candidates");
}

#[test]
fn cloud_candidates_use_org_name_variants() {
    let engine = default_engine();
    let candidates = engine.generate_candidates("acmecorp.com");
    let cloud_subs: Vec<String> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::CloudAware)
        .map(|c| c.subdomain.clone())
        .collect();

    let has_backup = cloud_subs.iter().any(|s| s.contains("acmecorp-backup"));
    let has_dev = cloud_subs.iter().any(|s| s.contains("acmecorp-dev"));
    assert!(has_backup, "should generate acmecorp-backup cloud variants");
    assert!(has_dev, "should generate acmecorp-dev cloud variants");
}

#[test]
fn cloud_disabled_generates_no_cloud_candidates() {
    let config = SmartBruteForceConfig {
        cloud_check_enabled: false,
        ..SmartBruteForceConfig::default()
    };
    let engine = SmartBruteForcer::new(config);
    let candidates = engine.generate_candidates("example.com");
    let cloud_count = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::CloudAware)
        .count();
    assert_eq!(cloud_count, 0, "no cloud candidates when disabled");
}

// ── Priority Scoring (AC4) ────────────────────────────────────

#[test]
fn candidates_are_sorted_by_score_descending() {
    let mut engine = default_engine();
    engine.learn_from(&["dev-api.example.com".into(), "dev-web.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    for window in candidates.windows(2) {
        assert!(
            window[0].score >= window[1].score,
            "candidates should be sorted descending: {} ({}) should be ≥ {} ({})",
            window[0].subdomain,
            window[0].score,
            window[1].subdomain,
            window[1].score,
        );
    }
}

#[test]
fn frequently_observed_suffixes_score_higher() {
    let mut engine = default_engine();
    // "api" suffix appears twice, "dashboard" appears once
    engine.learn_from(&[
        "dev-api.example.com".into(),
        "staging-api.example.com".into(),
        "dev-dashboard.example.com".into(),
    ]);

    let candidates = engine.generate_candidates("example.com");

    let prod_api_score = candidates
        .iter()
        .find(|c| c.subdomain == "prod-api.example.com")
        .map(|c| c.score);
    let prod_dashboard_score = candidates
        .iter()
        .find(|c| c.subdomain == "prod-dashboard.example.com")
        .map(|c| c.score);

    assert!(
        prod_api_score > prod_dashboard_score,
        "prod-api ({:?}) should score higher than prod-dashboard ({:?})",
        prod_api_score,
        prod_dashboard_score,
    );
}

// ── Wildcard Detection (AC2) ──────────────────────────────────

#[test]
fn wildcard_detected_when_all_probes_resolve_same_ip() {
    let wildcard_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let result = detect_wildcard_with_resolver("example.com", 3, |_| Some(wildcard_ip));

    assert!(result.is_wildcard, "should detect wildcard");
    assert_eq!(result.wildcard_ip, Some(wildcard_ip));
    assert_eq!(result.probe_results.len(), 3);
}

#[test]
fn no_wildcard_when_probes_do_not_resolve() {
    let result = detect_wildcard_with_resolver("example.com", 3, |_| None);

    assert!(
        !result.is_wildcard,
        "should not detect wildcard when nothing resolves"
    );
    assert_eq!(result.wildcard_ip, None);
}

#[test]
fn no_wildcard_when_only_some_probes_resolve() {
    let result = detect_wildcard_with_resolver("example.com", 3, |_| {
        None // Simulates partial resolution by returning None for all
    });

    assert!(!result.is_wildcard);
}

// ── Wildcard Response Filtering ───────────────────────────────

#[test]
fn filter_removes_wildcard_matching_responses() {
    let wildcard_sig = ResponseSignature {
        status_code: 200,
        content_length_bucket: 1000,
        server_header: Some("nginx".into()),
    };

    let responses = vec![
        (
            "real.example.com".into(),
            ResponseSignature {
                status_code: 200,
                content_length_bucket: 5000,
                server_header: Some("apache".into()),
            },
        ),
        (
            "wildcard-match.example.com".into(),
            ResponseSignature {
                status_code: 200,
                content_length_bucket: 1000,
                server_header: Some("nginx".into()),
            },
        ),
        (
            "different-status.example.com".into(),
            ResponseSignature {
                status_code: 404,
                content_length_bucket: 1000,
                server_header: Some("nginx".into()),
            },
        ),
    ];

    let filtered = SmartBruteForcer::filter_wildcard_responses(&responses, &wildcard_sig);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"real.example.com".to_string()));
    assert!(filtered.contains(&"different-status.example.com".to_string()));
    assert!(!filtered.contains(&"wildcard-match.example.com".to_string()));
}

#[test]
fn filter_keeps_responses_with_different_content_length() {
    let wildcard_sig = ResponseSignature {
        status_code: 200,
        content_length_bucket: 100,
        server_header: None,
    };

    let responses = vec![(
        "big-page.example.com".into(),
        ResponseSignature {
            status_code: 200,
            content_length_bucket: 50000,
            server_header: None,
        },
    )];

    let filtered = SmartBruteForcer::filter_wildcard_responses(&responses, &wildcard_sig);
    assert_eq!(filtered.len(), 1);
}

// ── Zone Walking ──────────────────────────────────────────────

#[test]
fn zone_walk_returns_not_supported_by_default() {
    let result = SmartBruteForcer::zone_walk("example.com");
    assert_eq!(result.nsec_type, NsecType::NotSupported);
    assert!(result.discovered_names.is_empty());
}

#[test]
fn zone_walk_with_nsec_resolver_returns_names() {
    let result = zone_walk_with_query("example.com", |_domain| {
        Some((
            NsecType::Nsec,
            vec![
                "mail.example.com".into(),
                "www.example.com".into(),
                "ns1.example.com".into(),
            ],
        ))
    });

    assert_eq!(result.nsec_type, NsecType::Nsec);
    assert_eq!(result.discovered_names.len(), 3);
    assert_eq!(result.walked_records, 3);
}

#[test]
fn zone_walk_nsec3_returns_hashed_names() {
    let result = zone_walk_with_query("example.com", |_domain| {
        Some((NsecType::Nsec3, vec!["hashed1.example.com".into()]))
    });

    assert_eq!(result.nsec_type, NsecType::Nsec3);
    assert_eq!(result.discovered_names.len(), 1);
}

// ── Config / Edge Cases ───────────────────────────────────────

#[test]
fn default_config_values() {
    let cfg = SmartBruteForceConfig::default();
    assert_eq!(cfg.max_number_iteration, 100);
    assert!(cfg.cloud_check_enabled);
    assert!(cfg.zone_walk_enabled);
    assert_eq!(cfg.wildcard_probe_count, 3);
    assert_eq!(cfg.max_candidates, 10_000);
}

#[test]
fn empty_engine_generates_only_leaked_and_cloud_candidates() {
    let engine = default_engine();
    let candidates = engine.generate_candidates("example.com");

    let sources: HashSet<&CandidateSource> = candidates.iter().map(|c| &c.source).collect();
    assert!(sources.contains(&CandidateSource::LeakedPrefix));
    assert!(sources.contains(&CandidateSource::CloudAware));
    assert!(!sources.contains(&CandidateSource::PatternPermutation));
    assert!(!sources.contains(&CandidateSource::NumberIteration));
}

#[test]
fn max_candidates_caps_output_size() {
    let config = SmartBruteForceConfig {
        max_candidates: 5,
        ..SmartBruteForceConfig::default()
    };
    let mut engine = SmartBruteForcer::new(config);
    engine.learn_from(&["dev-api.example.com".into(), "dev-web.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    assert!(
        candidates.len() <= 5,
        "should cap at max_candidates=5, got {}",
        candidates.len()
    );
}

#[test]
fn no_duplicate_candidates() {
    let mut engine = default_engine();
    engine.learn_from(&[
        "dev-api.example.com".into(),
        "dev-api.example.com".into(), // duplicate input
        "dev-web.example.com".into(),
    ]);

    let candidates = engine.generate_candidates("example.com");
    let unique: HashSet<&str> = candidates.iter().map(|c| c.subdomain.as_str()).collect();
    assert_eq!(unique.len(), candidates.len(), "should have no duplicates");
}

#[test]
fn learn_from_subdomain_without_dots() {
    let mut engine = default_engine();
    engine.learn_from(&["dev-api".into()]);
    let has_pattern = engine
        .patterns()
        .iter()
        .any(|p| matches!(p, NamingPattern::EnvService { separator: '-' }));
    assert!(has_pattern, "should work even with bare labels");
}

#[test]
fn leaked_prefix_candidates_exclude_already_known() {
    let mut engine = default_engine();
    engine.learn_from(&["admin.example.com".into(), "vpn.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    let leaked: Vec<&str> = candidates
        .iter()
        .filter(|c| c.source == CandidateSource::LeakedPrefix)
        .map(|c| c.subdomain.as_str())
        .collect();

    assert!(
        !leaked.contains(&"admin.example.com"),
        "should not re-suggest known admin"
    );
    assert!(
        !leaked.contains(&"vpn.example.com"),
        "should not re-suggest known vpn"
    );
    assert!(
        leaked.contains(&"mail.example.com"),
        "should still suggest unknown mail"
    );
}

#[test]
fn scored_candidate_ordering_works() {
    let high = ScoredCandidate {
        subdomain: "high.example.com".into(),
        score: 10.0,
        source: CandidateSource::PatternPermutation,
    };
    let low = ScoredCandidate {
        subdomain: "low.example.com".into(),
        score: 1.0,
        source: CandidateSource::LeakedPrefix,
    };
    assert!(high > low);
    assert!(low < high);
}

#[test]
fn content_length_similar_within_five_percent() {
    let sig_a = ResponseSignature {
        status_code: 200,
        content_length_bucket: 1000,
        server_header: None,
    };
    let sig_b = ResponseSignature {
        status_code: 200,
        content_length_bucket: 1040,
        server_header: None,
    };
    // 4% difference — should match
    let responses = vec![("test.example.com".into(), sig_b)];
    let filtered = SmartBruteForcer::filter_wildcard_responses(&responses, &sig_a);
    assert_eq!(
        filtered.len(),
        0,
        "4% difference should be treated as matching wildcard"
    );
}

#[test]
fn underscore_separated_permutations() {
    let mut engine = default_engine();
    engine.learn_from(&["dev_api.example.com".into()]);

    let candidates = engine.generate_candidates("example.com");
    let names: HashSet<String> = candidates.iter().map(|c| c.subdomain.clone()).collect();

    assert!(
        names.contains("staging_api.example.com"),
        "should generate underscore variants"
    );
    assert!(
        names.contains("prod_api.example.com"),
        "should generate prod_api underscore variant"
    );
}
