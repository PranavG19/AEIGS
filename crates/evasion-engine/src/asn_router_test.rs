use super::asn_router::*;

fn make_router() -> AsnRouter {
    AsnRouter::with_seed(RouteConfig::default(), 42)
}

#[test]
fn default_database_is_populated() {
    let router = make_router();
    assert!(router.database_size() >= 10);
    assert!(router.get_asn(3356).is_some());
    assert!(router.get_asn(8708).is_some());
    assert!(router.get_asn(24940).is_some());
    assert!(router.get_asn(200019).is_some());
}

#[test]
fn five_eyes_countries_correctly_identified() {
    assert!(AsnRouter::is_five_eyes("US"));
    assert!(AsnRouter::is_five_eyes("GB"));
    assert!(AsnRouter::is_five_eyes("CA"));
    assert!(AsnRouter::is_five_eyes("AU"));
    assert!(AsnRouter::is_five_eyes("NZ"));
    assert!(!AsnRouter::is_five_eyes("DE"));
    assert!(!AsnRouter::is_five_eyes("RO"));
    assert!(!AsnRouter::is_five_eyes("BR"));
    assert!(!AsnRouter::is_five_eyes("RU"));
}

#[test]
fn nine_eyes_includes_five_eyes_plus_four() {
    for code in &["US", "GB", "CA", "AU", "NZ", "DK", "FR", "NL", "NO"] {
        assert!(AsnRouter::is_nine_eyes(code), "{code} should be Nine Eyes");
    }
    assert!(!AsnRouter::is_nine_eyes("DE"));
    assert!(!AsnRouter::is_nine_eyes("RO"));
}

#[test]
fn fourteen_eyes_includes_nine_eyes_plus_five() {
    for code in &["DE", "BE", "IT", "SE", "ES"] {
        assert!(
            AsnRouter::is_fourteen_eyes(code),
            "{code} should be Fourteen Eyes"
        );
    }
    assert!(AsnRouter::is_fourteen_eyes("US"));
    assert!(!AsnRouter::is_fourteen_eyes("RO"));
    assert!(!AsnRouter::is_fourteen_eyes("BR"));
}

#[test]
fn scoring_prefers_residential_over_datacenter() {
    let router = make_router();
    let residential_asn = 8708;
    let datacenter_asn = 24940;

    let residential_score = router.score_asn(residential_asn);
    let datacenter_score = router.score_asn(datacenter_asn);

    assert!(
        residential_score > datacenter_score,
        "Residential ({residential_score:.3}) should score higher than Datacenter ({datacenter_score:.3})"
    );
}

#[test]
fn scoring_penalizes_five_eyes_jurisdiction() {
    let router = make_router();
    let us_tier1 = router.score_asn(3356);
    let ro_residential = router.score_asn(8708);

    assert!(
        ro_residential > us_tier1,
        "RO Residential ({ro_residential:.3}) should score higher than US Tier-1 ({us_tier1:.3})"
    );
}

#[test]
fn scoring_returns_zero_for_unknown_asn() {
    let router = make_router();
    assert_eq!(router.score_asn(999999), 0.0);
}

#[test]
fn bulletproof_scores_lower_than_residential() {
    let router = make_router();
    let bulletproof_score = router.score_asn(200019);
    let residential_score = router.score_asn(8708);

    assert!(
        residential_score > bulletproof_score,
        "Residential ({residential_score:.3}) should beat Bulletproof ({bulletproof_score:.3}) on tier alone"
    );
}

#[test]
fn route_selection_avoids_five_eyes() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(true)
            .with_min_hops(3),
        42,
    );
    let route = router.select_route().unwrap();

    for &asn in &route.hops {
        let entry = router.get_asn(asn).unwrap();
        assert!(
            !AsnRouter::is_five_eyes(&entry.country),
            "AS{} in {} should not be Five Eyes",
            entry.asn_number,
            entry.country
        );
    }
}

#[test]
fn route_selection_avoids_fourteen_eyes() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(true)
            .with_avoid_fourteen_eyes(true)
            .with_min_hops(2),
        42,
    );
    let route = router.select_route().unwrap();

    for &asn in &route.hops {
        let entry = router.get_asn(asn).unwrap();
        assert!(
            !AsnRouter::is_fourteen_eyes(&entry.country),
            "AS{} in {} should not be Fourteen Eyes",
            entry.asn_number,
            entry.country
        );
    }
}

#[test]
fn path_diversity_enforces_different_consecutive_countries() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(false)
            .with_min_hops(4)
            .with_max_hops(6),
        7,
    );
    let route = router.select_route().unwrap();

    for window in route.countries.windows(2) {
        assert_ne!(
            window[0], window[1],
            "Consecutive hops should use different countries, got {} -> {}",
            window[0], window[1]
        );
    }
}

#[test]
fn path_diversity_no_duplicate_asns() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(false)
            .with_min_hops(4),
        99,
    );
    let route = router.select_route().unwrap();

    let mut seen = std::collections::HashSet::new();
    for &asn in &route.hops {
        assert!(seen.insert(asn), "ASN {asn} appeared twice in route");
    }
}

#[test]
fn jurisdiction_risk_classification() {
    let router = make_router();

    assert_eq!(
        router.classify_jurisdiction("US"),
        JurisdictionRisk::FiveEyes
    );
    assert_eq!(
        router.classify_jurisdiction("GB"),
        JurisdictionRisk::FiveEyes
    );
    assert_eq!(
        router.classify_jurisdiction("FR"),
        JurisdictionRisk::NineEyes
    );
    assert_eq!(
        router.classify_jurisdiction("DE"),
        JurisdictionRisk::FourteenEyes
    );
    assert_eq!(
        router.classify_jurisdiction("JP"),
        JurisdictionRisk::MlatPartner
    );
    assert_eq!(
        router.classify_jurisdiction("RO"),
        JurisdictionRisk::Neutral
    );
    assert_eq!(
        router.classify_jurisdiction("PA"),
        JurisdictionRisk::Favorable
    );
    assert_eq!(
        router.classify_jurisdiction("XX"),
        JurisdictionRisk::Neutral
    );
}

#[test]
fn best_exit_nodes_ranked_by_score() {
    let router = make_router();
    let exits = router.best_exit_nodes(5);

    assert!(!exits.is_empty());
    let scores: Vec<f64> = exits
        .iter()
        .map(|e| router.score_asn(e.asn_number))
        .collect();

    for window in scores.windows(2) {
        assert!(
            window[0] >= window[1],
            "Exit nodes should be sorted descending: {:.3} should >= {:.3}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn best_exit_nodes_respects_limit() {
    let router = make_router();
    let exits = router.best_exit_nodes(3);
    assert!(exits.len() <= 3);
}

#[test]
fn best_exit_nodes_excludes_five_eyes_when_configured() {
    let router = AsnRouter::with_seed(RouteConfig::default().with_avoid_five_eyes(true), 42);
    let exits = router.best_exit_nodes(10);

    for entry in &exits {
        assert!(
            !AsnRouter::is_five_eyes(&entry.country),
            "Exit node AS{} in {} should not be Five Eyes",
            entry.asn_number,
            entry.country
        );
    }
}

#[test]
fn custom_asn_addition() {
    let mut router = make_router();
    let initial_size = router.database_size();

    router.add_asn(AsnEntry {
        asn_number: 999999,
        name: "Custom Test Network".to_string(),
        tier: AsnTier::Residential,
        country: "CH".to_string(),
        jurisdiction: JurisdictionInfo {
            country_code: "CH".to_string(),
            risk: JurisdictionRisk::Neutral,
            has_mlat_with_us: false,
            has_data_retention_laws: false,
        },
    });

    assert_eq!(router.database_size(), initial_size + 1);
    let entry = router.get_asn(999999).unwrap();
    assert_eq!(entry.name, "Custom Test Network");
    assert_eq!(entry.tier, AsnTier::Residential);
    assert_eq!(entry.country, "CH");
}

#[test]
fn custom_asn_participates_in_scoring() {
    let mut router = make_router();
    router.add_asn(AsnEntry {
        asn_number: 111111,
        name: "Swiss Residential ISP".to_string(),
        tier: AsnTier::Residential,
        country: "CH".to_string(),
        jurisdiction: JurisdictionInfo {
            country_code: "CH".to_string(),
            risk: JurisdictionRisk::Neutral,
            has_mlat_with_us: false,
            has_data_retention_laws: false,
        },
    });

    let score = router.score_asn(111111);
    assert!(
        score > 0.8,
        "Swiss residential should score high: {score:.3}"
    );
}

#[test]
fn route_total_score_is_sum_of_hop_scores() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(false)
            .with_min_hops(2)
            .with_max_hops(3),
        42,
    );
    let route = router.select_route().unwrap();
    let expected: f64 = route.hops.iter().map(|asn| router.score_asn(*asn)).sum();

    assert!(
        (route.total_score - expected).abs() < 1e-10,
        "Total score {:.6} should equal sum of hop scores {:.6}",
        route.total_score,
        expected
    );
}

#[test]
fn route_countries_match_hop_entries() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(false)
            .with_min_hops(3),
        42,
    );
    let route = router.select_route().unwrap();

    assert_eq!(route.hops.len(), route.countries.len());
    for (i, &asn) in route.hops.iter().enumerate() {
        let entry = router.get_asn(asn).unwrap();
        assert_eq!(
            entry.country, route.countries[i],
            "Country mismatch at hop {i}"
        );
    }
}

#[test]
fn asn_tier_stealth_scores_ordered() {
    assert!(AsnTier::Residential.stealth_score() > AsnTier::Academic.stealth_score());
    assert!(AsnTier::Academic.stealth_score() > AsnTier::Tier1.stealth_score());
    assert!(AsnTier::Tier1.stealth_score() > AsnTier::Government.stealth_score());
    assert!(AsnTier::Government.stealth_score() > AsnTier::Datacenter.stealth_score());
    assert!(AsnTier::Datacenter.stealth_score() > AsnTier::Bulletproof.stealth_score());
}

#[test]
fn jurisdiction_risk_penalties_ordered() {
    assert!(JurisdictionRisk::FiveEyes.penalty() > JurisdictionRisk::NineEyes.penalty());
    assert!(JurisdictionRisk::NineEyes.penalty() > JurisdictionRisk::FourteenEyes.penalty());
    assert!(JurisdictionRisk::FourteenEyes.penalty() > JurisdictionRisk::MlatPartner.penalty());
    assert!(JurisdictionRisk::MlatPartner.penalty() > JurisdictionRisk::Neutral.penalty());
    assert!(JurisdictionRisk::Neutral.penalty() > JurisdictionRisk::Favorable.penalty());
    assert_eq!(JurisdictionRisk::Favorable.penalty(), 0.0);
}

#[test]
fn asn_entry_display() {
    let router = make_router();
    let entry = router.get_asn(8708).unwrap();
    let display = format!("{entry}");
    assert!(display.contains("AS8708"));
    assert!(display.contains("RCS & RDS"));
    assert!(display.contains("Residential"));
    assert!(display.contains("RO"));
}

#[test]
fn asn_tier_display_variants() {
    assert_eq!(format!("{}", AsnTier::Tier1), "Tier-1");
    assert_eq!(format!("{}", AsnTier::Residential), "Residential");
    assert_eq!(format!("{}", AsnTier::Datacenter), "Datacenter");
    assert_eq!(format!("{}", AsnTier::Bulletproof), "Bulletproof");
    assert_eq!(format!("{}", AsnTier::Government), "Government");
    assert_eq!(format!("{}", AsnTier::Academic), "Academic");
}

#[test]
fn jurisdiction_risk_display_variants() {
    assert_eq!(format!("{}", JurisdictionRisk::FiveEyes), "Five Eyes");
    assert_eq!(format!("{}", JurisdictionRisk::NineEyes), "Nine Eyes");
    assert_eq!(
        format!("{}", JurisdictionRisk::FourteenEyes),
        "Fourteen Eyes"
    );
    assert_eq!(format!("{}", JurisdictionRisk::MlatPartner), "MLAT Partner");
    assert_eq!(format!("{}", JurisdictionRisk::Neutral), "Neutral");
    assert_eq!(format!("{}", JurisdictionRisk::Favorable), "Favorable");
}

#[test]
fn all_entries_returns_full_database() {
    let router = make_router();
    let entries = router.all_entries();
    assert_eq!(entries.len(), router.database_size());
}

#[test]
fn empty_router_select_route_returns_none() {
    let mut router = AsnRouter::with_seed(
        RouteConfig::default()
            .with_avoid_five_eyes(false)
            .with_min_hops(1),
        42,
    );
    router.clear_database();
    assert!(router.select_route().is_none());
}
