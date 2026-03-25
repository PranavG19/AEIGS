use super::ip_reputation::*;
use std::net::Ipv4Addr;

fn make_checker_with_ips() -> IpReputationChecker {
    let mut checker = IpReputationChecker::new();
    checker.track_ip(
        Ipv4Addr::new(1, 1, 1, 1),
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.track_ip(
        Ipv4Addr::new(2, 2, 2, 2),
        IspClassification::CloudHosting,
        IpGeoRegion::Europe,
    );
    checker.track_ip(
        Ipv4Addr::new(3, 3, 3, 3),
        IspClassification::BudgetVps,
        IpGeoRegion::AsiaPacific,
    );
    checker.track_ip(
        Ipv4Addr::new(4, 4, 4, 4),
        IspClassification::TorExit,
        IpGeoRegion::Europe,
    );
    checker
}

#[test]
fn track_ip_registers_new_address() {
    let mut checker = IpReputationChecker::new();
    checker.track_ip(
        Ipv4Addr::new(10, 0, 0, 1),
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );

    assert_eq!(checker.all_tracked().len(), 1);
    let ip = &checker.all_tracked()[0];
    assert_eq!(ip.address, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ip.isp, IspClassification::Residential);
    assert_eq!(ip.region, IpGeoRegion::NorthAmerica);
    assert_eq!(ip.burn_status, BurnStatus::Clean);
    assert!((ip.reputation_score - 0.95).abs() < 0.001);
}

#[test]
fn track_ip_deduplicates() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.track_ip(addr, IspClassification::CloudHosting, IpGeoRegion::Europe);

    assert_eq!(checker.all_tracked().len(), 1);
    assert_eq!(checker.all_tracked()[0].isp, IspClassification::Residential);
}

#[test]
fn record_requests_updates_counts() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.record_requests(addr, 100, 5);

    let ip = &checker.all_tracked()[0];
    assert_eq!(ip.total_requests_sent, 100);
    assert_eq!(ip.total_blocks_received, 5);
    assert!((ip.block_rate() - 0.05).abs() < 0.001);
}

#[test]
fn block_rate_zero_when_no_requests() {
    let checker = make_checker_with_ips();
    let ip = &checker.all_tracked()[0];
    assert!((ip.block_rate() - 0.0).abs() < 0.001);
}

#[test]
fn burn_status_transitions_warm() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.record_requests(addr, 100, 12);

    let ip = &checker.all_tracked()[0];
    assert_eq!(ip.burn_status, BurnStatus::Warm);
}

#[test]
fn burn_status_transitions_hot() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.record_requests(addr, 100, 30);

    let ip = &checker.all_tracked()[0];
    assert_eq!(ip.burn_status, BurnStatus::Hot);
}

#[test]
fn burn_status_transitions_burned() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.record_requests(addr, 100, 55);

    let ip = &checker.all_tracked()[0];
    assert_eq!(ip.burn_status, BurnStatus::Burned);
}

#[test]
fn blocklist_hits_cause_burn() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );

    for i in 0..5 {
        checker.record_blocklist_hit(
            addr,
            BlocklistHit {
                list_name: format!("blocklist_{i}"),
                category: BlocklistCategory::WebAttack,
                first_seen_epoch: 1000,
                last_seen_epoch: 2000,
                severity: 8,
            },
        );
    }

    let ip = &checker.all_tracked()[0];
    assert_eq!(ip.burn_status, BurnStatus::Burned);
}

#[test]
fn reputation_score_penalized_by_blocks() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );

    let initial_score = checker.all_tracked()[0].reputation_score;
    checker.record_requests(addr, 100, 20);
    let penalized_score = checker.all_tracked()[0].reputation_score;

    assert!(penalized_score < initial_score);
}

#[test]
fn rotation_recommendation_clean() {
    let checker = make_checker_with_ips();
    let rec = checker
        .rotation_recommendation(Ipv4Addr::new(1, 1, 1, 1))
        .unwrap();

    assert_eq!(rec.action, RotationAction::Continue);
    assert!(rec.replacement_criteria.is_empty());
}

#[test]
fn rotation_recommendation_burned() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(5, 5, 5, 5);
    checker.track_ip(addr, IspClassification::CloudHosting, IpGeoRegion::Europe);
    checker.record_requests(addr, 100, 60);

    let rec = checker.rotation_recommendation(addr).unwrap();
    assert_eq!(rec.action, RotationAction::Retire);
    assert!(!rec.replacement_criteria.is_empty());
}

#[test]
fn rotation_recommendation_hot() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(6, 6, 6, 6);
    checker.track_ip(addr, IspClassification::BudgetVps, IpGeoRegion::AsiaPacific);
    checker.record_requests(addr, 100, 30);

    let rec = checker.rotation_recommendation(addr).unwrap();
    assert_eq!(rec.action, RotationAction::RotateNow);
    assert!(rec.suggested_cooldown.is_some());
}

#[test]
fn rotation_recommendation_nonexistent_ip() {
    let checker = IpReputationChecker::new();
    assert!(checker
        .rotation_recommendation(Ipv4Addr::new(99, 99, 99, 99))
        .is_none());
}

#[test]
fn geo_diversity_score_empty_pool() {
    let checker = IpReputationChecker::new();
    let score = checker.geo_diversity_score();

    assert_eq!(score.total_ips, 0);
    assert_eq!(score.regions_covered, 0);
    assert!((score.diversity_score - 0.0).abs() < 0.001);
}

#[test]
fn geo_diversity_score_multi_region() {
    let checker = make_checker_with_ips();
    let score = checker.geo_diversity_score();

    assert_eq!(score.total_ips, 4);
    assert_eq!(score.regions_covered, 3);
    assert!(score.diversity_score > 0.0);
    assert!(score
        .region_distribution
        .contains_key(&IpGeoRegion::NorthAmerica));
    assert!(score.region_distribution.contains_key(&IpGeoRegion::Europe));
    assert!(score
        .region_distribution
        .contains_key(&IpGeoRegion::AsiaPacific));
}

#[test]
fn geo_diversity_recommends_missing_regions() {
    let checker = make_checker_with_ips();
    let score = checker.geo_diversity_score();

    assert!(!score.recommendations.is_empty());
    assert!(score
        .recommendations
        .iter()
        .any(|r| r.contains("South America")));
    assert!(score.recommendations.iter().any(|r| r.contains("Africa")));
}

#[test]
fn isp_distribution() {
    let checker = make_checker_with_ips();
    let dist = checker.isp_distribution();

    assert_eq!(dist[&IspClassification::Residential], 1);
    assert_eq!(dist[&IspClassification::CloudHosting], 1);
    assert_eq!(dist[&IspClassification::BudgetVps], 1);
    assert_eq!(dist[&IspClassification::TorExit], 1);
}

#[test]
fn ranked_ips_sorted_by_reputation() {
    let checker = make_checker_with_ips();
    let ranked = checker.ranked_ips();

    assert_eq!(ranked.len(), 4);
    assert_eq!(ranked[0].isp, IspClassification::Residential);
    assert_eq!(ranked[ranked.len() - 1].isp, IspClassification::TorExit);
    for w in ranked.windows(2) {
        assert!(w[0].reputation_score >= w[1].reputation_score);
    }
}

#[test]
fn usable_ips_excludes_burned() {
    let mut checker = make_checker_with_ips();
    let addr = Ipv4Addr::new(4, 4, 4, 4);
    checker.record_requests(addr, 100, 60);

    let usable = checker.usable_ips();
    assert!(usable.iter().all(|ip| ip.burn_status != BurnStatus::Burned));
    assert_eq!(usable.len(), 3);
}

#[test]
fn burned_ips_list() {
    let mut checker = make_checker_with_ips();
    checker.record_requests(Ipv4Addr::new(4, 4, 4, 4), 100, 60);

    let burned = checker.burned_ips();
    assert_eq!(burned.len(), 1);
    assert_eq!(burned[0].address, Ipv4Addr::new(4, 4, 4, 4));
}

#[test]
fn pool_health_summary() {
    let mut checker = make_checker_with_ips();
    checker.record_requests(Ipv4Addr::new(3, 3, 3, 3), 100, 12);
    checker.record_requests(Ipv4Addr::new(4, 4, 4, 4), 100, 55);

    let summary = checker.pool_health_summary();
    assert_eq!(summary.total_ips, 4);
    assert_eq!(summary.clean_count, 2);
    assert_eq!(summary.warm_count, 1);
    assert_eq!(summary.burned_count, 1);
    assert!(summary.average_reputation > 0.0);
    assert!((summary.usable_percentage - 75.0).abs() < 0.1);
}

#[test]
fn isp_base_reputation_ordering() {
    assert!(
        IspClassification::Residential.base_reputation()
            > IspClassification::CloudHosting.base_reputation()
    );
    assert!(
        IspClassification::CloudHosting.base_reputation()
            > IspClassification::TorExit.base_reputation()
    );
    assert!(
        IspClassification::Mobile.base_reputation()
            > IspClassification::BudgetVps.base_reputation()
    );
}

#[test]
fn burn_status_display() {
    assert_eq!(BurnStatus::Clean.to_string(), "Clean");
    assert_eq!(BurnStatus::Warm.to_string(), "Warm");
    assert_eq!(BurnStatus::Hot.to_string(), "Hot");
    assert_eq!(BurnStatus::Burned.to_string(), "Burned");
}

#[test]
fn burn_status_ordering() {
    assert!(BurnStatus::Clean < BurnStatus::Warm);
    assert!(BurnStatus::Warm < BurnStatus::Hot);
    assert!(BurnStatus::Hot < BurnStatus::Burned);
}

#[test]
fn isp_classification_display() {
    assert_eq!(IspClassification::Residential.to_string(), "Residential");
    assert_eq!(IspClassification::CloudHosting.to_string(), "Cloud Hosting");
    assert_eq!(IspClassification::TorExit.to_string(), "Tor Exit");
}

#[test]
fn geo_region_display() {
    assert_eq!(IpGeoRegion::NorthAmerica.to_string(), "North America");
    assert_eq!(IpGeoRegion::AsiaPacific.to_string(), "Asia-Pacific");
}

#[test]
fn blocklist_category_display() {
    assert_eq!(BlocklistCategory::WebAttack.to_string(), "Web Attack");
    assert_eq!(BlocklistCategory::BotnetC2.to_string(), "Botnet C2");
}

#[test]
fn rotation_action_display() {
    assert_eq!(RotationAction::Continue.to_string(), "Continue");
    assert_eq!(RotationAction::Retire.to_string(), "Retire");
    assert_eq!(RotationAction::RotateNow.to_string(), "Rotate Now");
}

#[test]
fn isp_all_has_10_entries() {
    assert_eq!(IspClassification::all().len(), 10);
}

#[test]
fn geo_region_all_has_7_entries() {
    assert_eq!(IpGeoRegion::all().len(), 7);
}

#[test]
fn custom_burn_threshold() {
    let mut checker = IpReputationChecker::new().with_burn_threshold(0.30);
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(
        addr,
        IspClassification::Residential,
        IpGeoRegion::NorthAmerica,
    );
    checker.record_requests(addr, 100, 35);

    assert_eq!(checker.all_tracked()[0].burn_status, BurnStatus::Burned);
}

#[test]
fn default_checker() {
    let checker = IpReputationChecker::default();
    assert_eq!(checker.all_tracked().len(), 0);
}

#[test]
fn reputation_score_clamped() {
    let mut checker = IpReputationChecker::new();
    let addr = Ipv4Addr::new(10, 0, 0, 1);
    checker.track_ip(addr, IspClassification::TorExit, IpGeoRegion::Europe);

    for i in 0..10 {
        checker.record_blocklist_hit(
            addr,
            BlocklistHit {
                list_name: format!("list_{i}"),
                category: BlocklistCategory::Malware,
                first_seen_epoch: 1000,
                last_seen_epoch: 2000,
                severity: 10,
            },
        );
    }
    checker.record_requests(addr, 100, 99);

    let ip = &checker.all_tracked()[0];
    assert!(ip.reputation_score >= 0.0);
    assert!(ip.reputation_score <= 1.0);
}
