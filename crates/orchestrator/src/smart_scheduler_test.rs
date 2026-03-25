use super::*;

fn default_scheduler() -> SmartScheduler {
    SmartScheduler::with_default_config()
}

fn scheduler_with_config(config: SmartSchedulerConfig) -> SmartScheduler {
    SmartScheduler::new(config)
}

#[test]
fn default_config_has_expected_values() {
    let config = SmartSchedulerConfig::default();

    assert!((config.weights.category_weight - 0.4).abs() < f64::EPSILON);
    assert!((config.weights.tech_risk_weight - 0.25).abs() < f64::EPSILON);
    assert!((config.weights.vuln_history_weight - 0.2).abs() < f64::EPSILON);
    assert!((config.weights.business_crit_weight - 0.15).abs() < f64::EPSILON);
    assert!(config.skip_static_assets);
    assert!(config.skip_cdn_resources);
    assert!(config.known_safe_patterns.is_empty());
    assert_eq!(config.max_queue_size, 10_000);
    assert_eq!(config.category_base_scores.len(), 8);
}

#[test]
fn builder_pattern_chains_correctly() {
    let weights = SchedulerWeights {
        category_weight: 0.5,
        tech_risk_weight: 0.2,
        vuln_history_weight: 0.2,
        business_crit_weight: 0.1,
    };

    let config = SmartSchedulerConfig::default()
        .with_weights(weights.clone())
        .with_skip_static(false)
        .with_skip_cdn(false)
        .with_safe_pattern("healthcheck".to_string())
        .with_safe_pattern("status".to_string())
        .with_max_queue_size(500);

    assert!((config.weights.category_weight - 0.5).abs() < f64::EPSILON);
    assert!(!config.skip_static_assets);
    assert!(!config.skip_cdn_resources);
    assert_eq!(config.known_safe_patterns.len(), 2);
    assert_eq!(config.max_queue_size, 500);
}

#[test]
fn classify_auth_endpoints() {
    let auth_urls = [
        "https://app.com/auth/callback",
        "https://app.com/login",
        "https://app.com/api/signin",
        "https://app.com/oauth/authorize",
        "https://app.com/token/refresh",
        "https://app.com/session/new",
        "https://app.com/register",
        "https://app.com/signup",
        "https://app.com/password/reset",
        "https://app.com/2fa/verify",
        "https://app.com/mfa/setup",
    ];

    for url in &auth_urls {
        assert_eq!(
            SmartScheduler::classify_endpoint(url, "POST"),
            EndpointCategory::Authentication,
            "expected Authentication for {url}"
        );
    }
}

#[test]
fn classify_admin_endpoints() {
    let admin_urls = [
        "https://app.com/admin/users",
        "https://app.com/dashboard",
        "https://app.com/manage/settings",
        "https://app.com/control/deployments",
        "https://app.com/panel/overview",
    ];

    for url in &admin_urls {
        assert_eq!(
            SmartScheduler::classify_endpoint(url, "GET"),
            EndpointCategory::AdminPanel,
            "expected AdminPanel for {url}"
        );
    }
}

#[test]
fn classify_api_endpoints() {
    let api_urls = [
        "https://app.com/api/users",
        "https://app.com/v1/products",
        "https://app.com/v2/orders",
        "https://app.com/v3/metrics",
        "https://app.com/graphql",
        "https://app.com/rest/items",
    ];

    for url in &api_urls {
        assert_eq!(
            SmartScheduler::classify_endpoint(url, "GET"),
            EndpointCategory::ApiEndpoint,
            "expected ApiEndpoint for {url}"
        );
    }
}

#[test]
fn classify_static_assets() {
    let static_urls = [
        "https://app.com/bundle.js",
        "https://app.com/style.css",
        "https://app.com/logo.png",
        "https://app.com/photo.jpg",
        "https://app.com/icon.gif",
        "https://app.com/diagram.svg",
        "https://app.com/font.woff",
        "https://app.com/favicon.ico",
        "https://app.com/bundle.js.map",
    ];

    for url in &static_urls {
        assert_eq!(
            SmartScheduler::classify_endpoint(url, "GET"),
            EndpointCategory::StaticAsset,
            "expected StaticAsset for {url}"
        );
    }
}

#[test]
fn classify_cdn_resources() {
    let cdn_urls = [
        "https://cdn.example.com/lib.js",
        "https://static.example.com/image.png",
        "https://assets.example.com/font.woff",
        "https://app.com/static/main.css",
        "https://app.com/assets/logo.png",
        "https://app.com/dist/bundle.js",
        "https://app.com/bundle/vendor.js",
    ];

    for url in &cdn_urls {
        let category = SmartScheduler::classify_endpoint(url, "GET");
        let is_cdn_or_static =
            category == EndpointCategory::CdnResource || category == EndpointCategory::StaticAsset;
        assert!(
            is_cdn_or_static,
            "expected CdnResource or StaticAsset for {url}, got {category:?}"
        );
    }
}

#[test]
fn classify_dynamic_content() {
    let dynamic_urls = [
        "https://app.com/page.php",
        "https://app.com/index.asp",
        "https://app.com/handler.jsp",
        "https://app.com/view.py",
        "https://app.com/search?q=test",
        "https://app.com/items?page=2&sort=name",
    ];

    for url in &dynamic_urls {
        assert_eq!(
            SmartScheduler::classify_endpoint(url, "GET"),
            EndpointCategory::DynamicContent,
            "expected DynamicContent for {url}"
        );
    }
}

#[test]
fn classify_unknown_fallback() {
    let url = "https://app.com/about";
    assert_eq!(
        SmartScheduler::classify_endpoint(url, "GET"),
        EndpointCategory::Unknown
    );
}

#[test]
fn add_endpoint_computes_priority() {
    let mut scheduler = default_scheduler();
    let target = scheduler.add_endpoint("https://app.com/auth/login", "POST");

    assert_eq!(target.category, EndpointCategory::Authentication);
    assert!(target.priority_score > 0.0);
    assert!(!target.skipped);
    assert!(target.skip_reason.is_none());
    assert_eq!(target.method, "POST");
}

#[test]
fn prioritize_sorts_by_score_descending() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/about", "GET");
    scheduler.add_endpoint("https://app.com/auth/login", "POST");
    scheduler.add_endpoint("https://app.com/api/v1/users", "GET");
    scheduler.add_endpoint("https://app.com/admin/settings", "GET");

    scheduler.prioritize();

    let targets = scheduler.targets();
    for window in targets.windows(2) {
        let current_effective = if window[0].skipped {
            -1.0
        } else {
            window[0].priority_score
        };
        let next_effective = if window[1].skipped {
            -1.0
        } else {
            window[1].priority_score
        };
        assert!(
            current_effective >= next_effective,
            "targets not sorted: {} ({}) should be >= {} ({})",
            window[0].url,
            current_effective,
            window[1].url,
            next_effective
        );
    }
}

#[test]
fn skip_static_assets_when_configured() {
    let mut scheduler = default_scheduler();
    let target = scheduler.add_endpoint("https://app.com/bundle.js", "GET");

    assert!(target.skipped);
    assert_eq!(target.skip_reason.as_deref(), Some("static asset"));
}

#[test]
fn skip_cdn_resources_when_configured() {
    let mut scheduler = default_scheduler();
    let target = scheduler.add_endpoint("https://cdn.example.com/lib.woff", "GET");

    assert!(target.skipped);
}

#[test]
fn no_skip_static_when_disabled() {
    let config = SmartSchedulerConfig::default().with_skip_static(false);
    let mut scheduler = scheduler_with_config(config);
    let target = scheduler.add_endpoint("https://app.com/bundle.js", "GET");

    assert!(!target.skipped);
}

#[test]
fn next_target_returns_highest_priority() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/about", "GET");
    scheduler.add_endpoint("https://app.com/auth/login", "POST");
    scheduler.add_endpoint("https://app.com/page.php", "GET");

    let first = scheduler.next_target().expect("should have targets");
    assert_eq!(first.category, EndpointCategory::Authentication);

    let second = scheduler.next_target().expect("should have targets");
    assert_eq!(second.category, EndpointCategory::DynamicContent);
}

#[test]
fn next_target_skips_skipped_targets() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/bundle.js", "GET");
    scheduler.add_endpoint("https://app.com/about", "GET");

    let target = scheduler.next_target().expect("should have active target");
    assert_eq!(target.category, EndpointCategory::Unknown);
    assert!(!target.skipped);
}

#[test]
fn tech_risk_affects_score() {
    let mut baseline = default_scheduler();
    baseline.add_endpoint("https://app.com/about", "GET");
    let baseline_score = baseline.targets()[0].priority_score;

    let mut boosted = default_scheduler();
    boosted.set_tech_risk("app.com", 0.9);
    boosted.add_endpoint("https://app.com/about", "GET");
    let boosted_score = boosted.targets()[0].priority_score;

    assert!(
        boosted_score > baseline_score,
        "tech risk should increase priority: {boosted_score} > {baseline_score}"
    );
}

#[test]
fn vuln_history_affects_score() {
    let mut baseline = default_scheduler();
    baseline.add_endpoint("https://app.com/about", "GET");
    let baseline_score = baseline.targets()[0].priority_score;

    let mut boosted = default_scheduler();
    boosted.set_vuln_history("/about", 0.8);
    boosted.add_endpoint("https://app.com/about", "GET");
    let boosted_score = boosted.targets()[0].priority_score;

    assert!(
        boosted_score > baseline_score,
        "vuln history should increase priority: {boosted_score} > {baseline_score}"
    );
}

#[test]
fn business_criticality_affects_score() {
    let mut baseline = default_scheduler();
    baseline.add_endpoint("https://app.com/checkout", "POST");
    let baseline_score = baseline.targets()[0].priority_score;

    let mut boosted = default_scheduler();
    boosted.set_business_criticality("/checkout", 1.0);
    boosted.add_endpoint("https://app.com/checkout", "POST");
    let boosted_score = boosted.targets()[0].priority_score;

    assert!(
        boosted_score > baseline_score,
        "business criticality should increase priority: {boosted_score} > {baseline_score}"
    );
}

#[test]
fn stats_tracking() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/auth/login", "POST");
    scheduler.add_endpoint("https://app.com/api/v1/users", "GET");
    scheduler.add_endpoint("https://app.com/bundle.js", "GET");

    let stats = scheduler.stats();
    assert_eq!(stats.total_endpoints, 3);
    assert_eq!(stats.skipped_endpoints, 1);
    assert!(stats.highest_priority > 0.0);
    assert!(stats.average_priority > 0.0);
    assert_eq!(stats.category_counts.get("Authentication"), Some(&1));
    assert_eq!(stats.category_counts.get("ApiEndpoint"), Some(&1));
    assert_eq!(stats.category_counts.get("StaticAsset"), Some(&1));
}

#[test]
fn clear_resets_state() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/auth/login", "POST");
    scheduler.add_endpoint("https://app.com/api/v1/users", "GET");
    assert_eq!(scheduler.target_count(), 2);

    scheduler.clear();
    assert_eq!(scheduler.target_count(), 0);
    assert!(scheduler.targets().is_empty());
}

#[test]
fn known_safe_patterns_skip_matching_urls() {
    let config = SmartSchedulerConfig::default()
        .with_safe_pattern("healthcheck".to_string())
        .with_safe_pattern("/status".to_string());
    let mut scheduler = scheduler_with_config(config);

    let hc = scheduler.add_endpoint("https://app.com/healthcheck", "GET");
    assert!(hc.skipped);
    assert!(hc.skip_reason.as_deref().unwrap().contains("safe pattern"));

    let status = scheduler.add_endpoint("https://app.com/status", "GET");
    assert!(status.skipped);
}

#[test]
fn peek_next_does_not_remove() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/auth/login", "POST");

    let peeked = scheduler.peek_next().expect("should have target");
    assert_eq!(peeked.category, EndpointCategory::Authentication);
    assert_eq!(scheduler.target_count(), 1);
}

#[test]
fn active_and_skipped_partition_correctly() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/auth/login", "POST");
    scheduler.add_endpoint("https://app.com/bundle.js", "GET");
    scheduler.add_endpoint("https://cdn.example.com/font.woff", "GET");

    let active = scheduler.active_targets();
    let skipped = scheduler.skipped_targets();

    assert_eq!(active.len(), 1);
    assert_eq!(skipped.len(), 2);
    assert_eq!(active.len() + skipped.len(), scheduler.target_count());
}

#[test]
fn scores_clamped_to_unit_interval() {
    let mut scheduler = default_scheduler();
    scheduler.set_tech_risk("app.com", 5.0);
    scheduler.set_vuln_history("/about", -2.0);
    scheduler.set_business_criticality("/about", 100.0);

    scheduler.add_endpoint("https://app.com/about", "GET");

    let target = &scheduler.targets()[0];
    assert!(target.priority_score >= 0.0);
    assert!(target.priority_score <= 1.0);
    assert!(target.tech_risk_score >= 0.0);
    assert!(target.tech_risk_score <= 1.0);
}

#[test]
fn auth_higher_than_api_higher_than_static() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/auth/login", "POST");
    scheduler.add_endpoint("https://app.com/api/v1/data", "GET");
    scheduler.add_endpoint("https://app.com/about", "GET");

    let auth_score = scheduler.targets()[0].priority_score;
    let api_score = scheduler.targets()[1].priority_score;
    let unknown_score = scheduler.targets()[2].priority_score;

    assert!(
        auth_score > api_score,
        "auth ({auth_score}) should outrank api ({api_score})"
    );
    assert!(
        api_score > unknown_score,
        "api ({api_score}) should outrank unknown ({unknown_score})"
    );
}

#[test]
fn empty_scheduler_returns_none() {
    let mut scheduler = default_scheduler();
    assert!(scheduler.next_target().is_none());
    assert!(scheduler.peek_next().is_none());
    assert_eq!(scheduler.target_count(), 0);

    let stats = scheduler.stats();
    assert_eq!(stats.total_endpoints, 0);
    assert!((stats.average_priority - 0.0).abs() < f64::EPSILON);
}

#[test]
fn upload_endpoint_classified_correctly() {
    let upload_urls = [
        "https://app.com/upload/avatar",
        "https://app.com/import/csv",
        "https://app.com/attach/document",
    ];

    for url in &upload_urls {
        assert_eq!(
            SmartScheduler::classify_endpoint(url, "POST"),
            EndpointCategory::FileUpload,
            "expected FileUpload for {url}"
        );
    }
}

#[test]
fn method_stored_uppercase() {
    let mut scheduler = default_scheduler();
    scheduler.add_endpoint("https://app.com/api/v1/data", "get");
    assert_eq!(scheduler.targets()[0].method, "GET");

    scheduler.add_endpoint("https://app.com/auth/login", "post");
    assert_eq!(scheduler.targets()[1].method, "POST");
}
