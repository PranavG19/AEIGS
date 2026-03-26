use super::cover_traffic_v2::*;

#[test]
fn default_generator_has_sites() {
    let generator = CoverTrafficGenerator::with_defaults();
    assert!(generator.site_count() > 0);
}

#[test]
fn generate_session_produces_actions() {
    let generator = CoverTrafficGenerator::with_defaults();
    let actions = generator.generate_session(42);
    assert!(!actions.is_empty());
}

#[test]
fn session_has_page_load_actions() {
    let generator = CoverTrafficGenerator::with_defaults();
    let actions = generator.generate_session(42);
    let page_loads = actions
        .iter()
        .filter(|a| a.action_type == ClickType::PageLoad)
        .count();
    assert!(page_loads > 0);
}

#[test]
fn session_has_varied_action_types() {
    let generator = CoverTrafficGenerator::with_defaults();
    let actions = generator.generate_session(42);
    let types: std::collections::HashSet<_> = actions
        .iter()
        .map(|a| std::mem::discriminant(&a.action_type))
        .collect();
    assert!(types.len() >= 2, "expected multiple action types");
}

#[test]
fn all_actions_have_nonzero_delay() {
    let generator = CoverTrafficGenerator::with_defaults();
    let actions = generator.generate_session(42);
    for action in &actions {
        assert!(action.delay_ms > 0, "delay should be > 0");
    }
}

#[test]
fn all_actions_have_urls() {
    let generator = CoverTrafficGenerator::with_defaults();
    let actions = generator.generate_session(42);
    for action in &actions {
        assert!(!action.url.is_empty());
    }
}

#[test]
fn compute_attack_ratio_correct() {
    let generator = CoverTrafficGenerator::with_defaults();
    let ratio = generator.compute_attack_ratio(30, 70);
    assert!((ratio - 0.3).abs() < 0.001);
}

#[test]
fn compute_attack_ratio_zero_total() {
    let generator = CoverTrafficGenerator::with_defaults();
    assert_eq!(generator.compute_attack_ratio(0, 0), 0.0);
}

#[test]
fn cover_requests_needed_for_30_percent_ratio() {
    let generator = CoverTrafficGenerator::new(CoverTrafficConfig {
        attack_to_cover_ratio: 0.3,
        ..Default::default()
    });
    let needed = generator.cover_requests_needed(30);
    assert!(
        needed >= 65,
        "need ~70 cover for 30 attack at 0.3 ratio, got {needed}"
    );
}

#[test]
fn cover_requests_needed_respects_minimum() {
    let generator = CoverTrafficGenerator::new(CoverTrafficConfig {
        attack_to_cover_ratio: 0.9,
        min_cover_requests: 10,
        ..Default::default()
    });
    let needed = generator.cover_requests_needed(1);
    assert!(needed >= 10);
}

#[test]
fn category_distribution_covers_multiple() {
    let generator = CoverTrafficGenerator::with_defaults();
    let dist = generator.category_distribution();
    assert!(
        dist.len() >= 5,
        "should have at least 5 categories, got {}",
        dist.len()
    );
}

#[test]
fn different_seeds_produce_different_sessions() {
    let generator = CoverTrafficGenerator::with_defaults();
    let s1 = generator.generate_session(1);
    let s2 = generator.generate_session(2);
    let urls1: Vec<_> = s1.iter().map(|a| &a.url).collect();
    let urls2: Vec<_> = s2.iter().map(|a| &a.url).collect();
    assert_ne!(urls1, urls2);
}

#[test]
fn resource_ratios_sum_to_100() {
    let r = ResourceRatios::default();
    let sum = r.navigation_pct + r.resource_pct + r.xhr_pct;
    assert!((sum - 100.0).abs() < 0.001);
}

#[test]
fn session_count_within_config_bounds() {
    let config = CoverTrafficConfig {
        min_cover_requests: 3,
        max_cover_requests: 10,
        click_depth_min: 0,
        click_depth_max: 0,
        enable_media_interactions: false,
        ..Default::default()
    };
    let generator = CoverTrafficGenerator::new(config);
    for seed in 0..20 {
        let actions = generator.generate_session(seed);
        let page_loads = actions
            .iter()
            .filter(|a| a.action_type == ClickType::PageLoad)
            .count();
        assert!(
            page_loads >= 3 && page_loads <= 10,
            "page_loads={page_loads} not in [3,10]"
        );
    }
}
