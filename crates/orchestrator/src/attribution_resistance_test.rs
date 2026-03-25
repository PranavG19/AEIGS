use super::*;

#[test]
fn proxy_layer_display() {
    assert_eq!(
        ProxyLayer::ResidentialProxy.to_string(),
        "Residential Proxy"
    );
    assert_eq!(ProxyLayer::Vpn.to_string(), "VPN");
    assert_eq!(ProxyLayer::Tor.to_string(), "Tor");
    assert_eq!(ProxyLayer::Socks5.to_string(), "SOCKS5");
    assert_eq!(ProxyLayer::CloudFunction.to_string(), "Cloud Function");
    assert_eq!(ProxyLayer::SshTunnel.to_string(), "SSH Tunnel");
}

#[test]
fn proxy_chain_new_empty() {
    let chain = ProxyChain::new();
    assert_eq!(chain.hop_count(), 0);
    assert_eq!(chain.total_latency_ms, 0);
    assert_eq!(chain.overall_anonymity_score, 1.0);
    assert!(chain.countries_traversed.is_empty());
}

#[test]
fn proxy_chain_add_links() {
    let mut chain = ProxyChain::new();
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::Vpn,
        address: "vpn.example.com".to_string(),
        port: 1194,
        country_code: Some("DE".to_string()),
        estimated_latency_ms: 50,
        anonymity_score: 0.9,
    });
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::Tor,
        address: "127.0.0.1".to_string(),
        port: 9050,
        country_code: None,
        estimated_latency_ms: 300,
        anonymity_score: 0.95,
    });
    assert_eq!(chain.hop_count(), 2);
    assert_eq!(chain.total_latency_ms, 350);
    assert!((chain.overall_anonymity_score - 0.855).abs() < 0.001);
    assert_eq!(chain.countries_traversed, vec!["DE"]);
}

#[test]
fn proxy_chain_deduplicates_countries() {
    let mut chain = ProxyChain::new();
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::Socks5,
        address: "a".to_string(),
        port: 1080,
        country_code: Some("US".to_string()),
        estimated_latency_ms: 10,
        anonymity_score: 0.8,
    });
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::HttpProxy,
        address: "b".to_string(),
        port: 8080,
        country_code: Some("US".to_string()),
        estimated_latency_ms: 10,
        anonymity_score: 0.8,
    });
    assert_eq!(chain.countries_traversed.len(), 1);
}

#[test]
fn build_recommended_chain_structure() {
    let chain = build_recommended_chain();
    assert_eq!(chain.hop_count(), 3);
    assert_eq!(chain.links[0].layer, ProxyLayer::ResidentialProxy);
    assert_eq!(chain.links[1].layer, ProxyLayer::Vpn);
    assert_eq!(chain.links[2].layer, ProxyLayer::Tor);
    assert!(chain.total_latency_ms > 0);
    assert!(chain.overall_anonymity_score > 0.0);
    assert!(chain.overall_anonymity_score < 1.0);
}

#[test]
fn traffic_mix_profile_default() {
    let profile = TrafficMixProfile::default();
    assert!(!profile.cover_sites.is_empty());
    assert!(profile.scan_to_cover_ratio > 0.0);
    assert!(profile.scan_to_cover_ratio < 1.0);
    assert_eq!(profile.cover_request_pattern, RequestPattern::HumanLike);
    assert!(profile.user_agent.contains("Mozilla"));
}

#[test]
fn generate_mixed_schedule_includes_both_types() {
    let scan_urls = vec![
        "https://target.com/api".to_string(),
        "https://target.com/login".to_string(),
    ];
    let profile = TrafficMixProfile::default();
    let schedule = generate_mixed_schedule(&scan_urls, &profile);
    assert!(!schedule.is_empty());
    let scan_count = schedule.iter().filter(|r| !r.is_cover_traffic).count();
    let cover_count = schedule.iter().filter(|r| r.is_cover_traffic).count();
    assert!(scan_count > 0);
    assert!(cover_count > 0);
}

#[test]
fn generate_mixed_schedule_empty_scan_urls() {
    let profile = TrafficMixProfile::default();
    let schedule = generate_mixed_schedule(&[], &profile);
    assert!(schedule.is_empty());
}

#[test]
fn cloud_provider_display() {
    assert_eq!(CloudProvider::Aws.to_string(), "AWS");
    assert_eq!(CloudProvider::Gcp.to_string(), "GCP");
    assert_eq!(CloudProvider::Azure.to_string(), "Azure");
    assert_eq!(CloudProvider::DigitalOcean.to_string(), "DigitalOcean");
}

#[test]
fn infrastructure_plan_default() {
    let plan = InfrastructurePlan::default();
    assert!(plan.ephemeral);
    assert!(plan.auto_destroy);
    assert!(plan.phase_assignments.contains_key("recon"));
    assert!(plan.phase_assignments.contains_key("fuzz"));
    assert_eq!(plan.max_instance_lifetime_secs, 3600);
}

#[test]
fn opsec_checklist_all_categories() {
    let checks = generate_opsec_checklist();
    assert!(checks.len() >= 8);
    let categories: std::collections::HashSet<OpsecCategory> =
        checks.iter().map(|c| c.category).collect();
    assert!(categories.contains(&OpsecCategory::Network));
    assert!(categories.contains(&OpsecCategory::Identity));
    assert!(categories.contains(&OpsecCategory::Infrastructure));
    assert!(categories.contains(&OpsecCategory::DataHandling));
}

#[test]
fn opsec_checklist_has_critical_items() {
    let checks = generate_opsec_checklist();
    let critical_count = checks
        .iter()
        .filter(|c| c.severity == OpsecSeverity::Critical)
        .count();
    assert!(critical_count >= 3);
}

#[test]
fn evaluate_opsec_all_unchecked() {
    let checks = generate_opsec_checklist();
    let eval = evaluate_opsec(&checks);
    assert_eq!(eval.passed, 0);
    assert_eq!(eval.failed, 0);
    assert_eq!(eval.unchecked, checks.len());
    assert!(eval.safe_to_proceed);
}

#[test]
fn evaluate_opsec_all_passed() {
    let mut checks = generate_opsec_checklist();
    for check in &mut checks {
        check.passed = Some(true);
    }
    let eval = evaluate_opsec(&checks);
    assert_eq!(eval.passed, checks.len());
    assert_eq!(eval.failed, 0);
    assert!(eval.safe_to_proceed);
}

#[test]
fn evaluate_opsec_critical_failure_blocks() {
    let mut checks = generate_opsec_checklist();
    for check in &mut checks {
        check.passed = Some(true);
    }
    checks[0].passed = Some(false);
    checks[0].severity = OpsecSeverity::Critical;
    let eval = evaluate_opsec(&checks);
    assert_eq!(eval.critical_failures, 1);
    assert!(!eval.safe_to_proceed);
}

#[test]
fn evaluate_opsec_many_non_critical_failures() {
    let mut checks = generate_opsec_checklist();
    let mut fail_count = 0;
    for check in &mut checks {
        if check.severity != OpsecSeverity::Critical && fail_count < 3 {
            check.passed = Some(false);
            fail_count += 1;
        } else {
            check.passed = Some(true);
        }
    }
    let eval = evaluate_opsec(&checks);
    assert!(!eval.safe_to_proceed);
}

#[test]
fn opsec_category_display() {
    assert_eq!(OpsecCategory::Network.to_string(), "Network");
    assert_eq!(OpsecCategory::Identity.to_string(), "Identity");
    assert_eq!(OpsecCategory::DataHandling.to_string(), "Data Handling");
    assert_eq!(OpsecCategory::Forensics.to_string(), "Forensics");
}

#[test]
fn opsec_severity_ordering() {
    assert!(OpsecSeverity::Advisory < OpsecSeverity::Warning);
    assert!(OpsecSeverity::Warning < OpsecSeverity::Critical);
}

#[test]
fn decoy_config_default() {
    let cfg = DecoyConfig::default();
    assert!(!cfg.decoy_targets.is_empty());
    assert_eq!(cfg.decoy_ratio, 0.5);
    assert!(cfg.mimic_real_scan);
    assert!(cfg.randomize_order);
}

#[test]
fn generate_blended_targets_ratio() {
    let real = vec![
        "https://target1.com".to_string(),
        "https://target2.com".to_string(),
        "https://target3.com".to_string(),
        "https://target4.com".to_string(),
    ];
    let config = DecoyConfig::default();
    let blended = generate_blended_targets(&real, &config);
    let real_count = blended.iter().filter(|t| !t.is_decoy).count();
    let decoy_count = blended.iter().filter(|t| t.is_decoy).count();
    assert_eq!(real_count, 4);
    assert_eq!(decoy_count, 2);
}

#[test]
fn generate_blended_targets_empty() {
    let config = DecoyConfig::default();
    let blended = generate_blended_targets(&[], &config);
    assert!(blended.is_empty());
}
