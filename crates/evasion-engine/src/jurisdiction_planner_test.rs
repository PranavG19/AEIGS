use super::jurisdiction_planner::*;

#[test]
fn us_is_five_eyes() {
    let planner = JurisdictionPlanner::with_defaults();
    assert!(planner.is_five_eyes("US"));
    assert!(planner.is_five_eyes("GB"));
    assert!(planner.is_five_eyes("AU"));
}

#[test]
fn switzerland_is_not_five_eyes() {
    let planner = JurisdictionPlanner::with_defaults();
    assert!(!planner.is_five_eyes("CH"));
}

#[test]
fn germany_is_fourteen_eyes() {
    let planner = JurisdictionPlanner::with_defaults();
    assert!(planner.is_fourteen_eyes("DE"));
    assert!(planner.is_fourteen_eyes("US"));
    assert!(planner.is_fourteen_eyes("FR"));
}

#[test]
fn panama_is_not_fourteen_eyes() {
    let planner = JurisdictionPlanner::with_defaults();
    assert!(!planner.is_fourteen_eyes("PA"));
}

#[test]
fn five_eyes_countries_have_high_risk() {
    let planner = JurisdictionPlanner::with_defaults();
    let risk = planner.country_risk("US").unwrap();
    assert!(risk >= 0.8, "US risk should be >= 0.8, got {risk}");
}

#[test]
fn switzerland_has_low_risk() {
    let planner = JurisdictionPlanner::with_defaults();
    let risk = planner.country_risk("CH").unwrap();
    assert!(risk <= 0.3, "CH risk should be <= 0.3, got {risk}");
}

#[test]
fn mlat_active_between_five_eyes() {
    let planner = JurisdictionPlanner::with_defaults();
    let status = planner.mlat_status("US", "GB");
    assert_eq!(status, MlatStatus::Active);
}

#[test]
fn mlat_limited_cross_alliance() {
    let planner = JurisdictionPlanner::with_defaults();
    let status = planner.mlat_status("US", "CH");
    assert_eq!(status, MlatStatus::Limited);
}

#[test]
fn recommend_route_avoids_five_eyes_by_default() {
    let planner = JurisdictionPlanner::with_defaults();
    let rec = planner.recommend_route();
    for hop in &rec.recommended_path {
        assert!(
            !planner.is_five_eyes(hop),
            "route should not include Five Eyes country: {hop}"
        );
    }
}

#[test]
fn recommend_route_respects_max_hops() {
    let config = JurisdictionPlannerConfig {
        max_hops: 2,
        ..Default::default()
    };
    let planner = JurisdictionPlanner::new(config);
    let rec = planner.recommend_route();
    assert!(rec.recommended_path.len() <= 2);
}

#[test]
fn recommend_route_has_low_total_risk() {
    let planner = JurisdictionPlanner::with_defaults();
    let rec = planner.recommend_route();
    let per_hop_avg = if rec.recommended_path.is_empty() {
        0.0
    } else {
        rec.total_risk_score / rec.recommended_path.len() as f64
    };
    assert!(
        per_hop_avg <= 0.5,
        "avg hop risk should be low, got {per_hop_avg}"
    );
}

#[test]
fn avoided_countries_includes_five_eyes() {
    let planner = JurisdictionPlanner::with_defaults();
    let rec = planner.recommend_route();
    assert!(rec.avoided_countries.contains(&"US".to_string()));
    assert!(rec.avoided_countries.contains(&"GB".to_string()));
}

#[test]
fn privacy_friendly_countries_exist() {
    let planner = JurisdictionPlanner::with_defaults();
    let friendly = planner.privacy_friendly_countries();
    assert!(!friendly.is_empty());
    for country in &friendly {
        assert!(country.risk_score <= 0.3);
        assert!(!country.has_data_retention_laws);
    }
}

#[test]
fn profile_count_nonzero() {
    let planner = JurisdictionPlanner::with_defaults();
    assert!(planner.profile_count() > 10);
}

#[test]
fn alliance_display_formatting() {
    assert_eq!(format!("{}", Alliance::FiveEyes), "Five Eyes");
    assert_eq!(format!("{}", Alliance::NineEyes), "Nine Eyes");
    assert_eq!(format!("{}", Alliance::FourteenEyes), "Fourteen Eyes");
    assert_eq!(format!("{}", Alliance::None), "None");
}

#[test]
fn risk_level_display() {
    assert_eq!(format!("{}", RiskLevel::Low), "low");
    assert_eq!(format!("{}", RiskLevel::Critical), "critical");
}

#[test]
fn avoid_fourteen_eyes_config() {
    let config = JurisdictionPlannerConfig {
        avoid_five_eyes: true,
        avoid_fourteen_eyes: true,
        ..Default::default()
    };
    let planner = JurisdictionPlanner::new(config);
    let rec = planner.recommend_route();
    for hop in &rec.recommended_path {
        assert!(
            !planner.is_fourteen_eyes(hop),
            "route should not include 14-eyes country: {hop}"
        );
    }
}
