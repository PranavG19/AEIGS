use super::platform_checker::*;

#[test]
fn default_config_has_sane_values() {
    let config = PlatformCheckerConfig::default();
    assert_eq!(config.concurrency, 10);
    assert_eq!(config.timeout_secs, 10);
    assert_eq!(config.delay_between_ms, 100);
    assert!(!config.user_agents.is_empty());
}

#[test]
fn all_platforms_returns_at_least_50() {
    let platforms = all_platforms();
    assert!(platforms.len() >= 50, "expected 50+ platforms, got {}", platforms.len());
}

#[test]
fn platform_url_templates_contain_placeholder() {
    for p in all_platforms() {
        assert!(
            p.url_template.contains("{}"),
            "Platform {} missing {{}} in url_template: {}",
            p.name,
            p.url_template,
        );
    }
}

#[test]
fn platform_names_are_unique() {
    let platforms = all_platforms();
    let mut names: Vec<&str> = platforms.iter().map(|p| p.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), platforms.len(), "duplicate platform names detected");
}

#[test]
fn platform_checker_creation() {
    let checker = PlatformChecker::new(PlatformCheckerConfig::default());
    assert!(checker.platform_count() >= 50);
}

#[test]
fn platform_checker_with_custom_platforms() {
    let custom = vec![PlatformDef {
        name: "TestPlatform",
        kind: PlatformKind::Other,
        url_template: "https://test.example.com/{}",
        detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
    }];
    let checker = PlatformChecker::new(PlatformCheckerConfig::default())
        .with_custom_platforms(custom);
    assert_eq!(checker.platform_count(), 1);
}

#[test]
fn check_status_display() {
    assert_eq!(CheckStatus::Exists.to_string(), "Exists");
    assert_eq!(CheckStatus::NotFound.to_string(), "Not Found");
    assert_eq!(CheckStatus::Suspended.to_string(), "Suspended");
    assert_eq!(CheckStatus::RateLimited.to_string(), "Rate Limited");
    assert_eq!(CheckStatus::Error.to_string(), "Error");
    assert_eq!(CheckStatus::Unknown.to_string(), "Unknown");
}

#[test]
fn platform_kind_display() {
    assert_eq!(PlatformKind::Developer.to_string(), "Developer");
    assert_eq!(PlatformKind::Social.to_string(), "Social");
    assert_eq!(PlatformKind::Professional.to_string(), "Professional");
    assert_eq!(PlatformKind::Gaming.to_string(), "Gaming");
    assert_eq!(PlatformKind::Messaging.to_string(), "Messaging");
    assert_eq!(PlatformKind::Forum.to_string(), "Forum");
    assert_eq!(PlatformKind::Blog.to_string(), "Blog");
    assert_eq!(PlatformKind::Media.to_string(), "Media");
    assert_eq!(PlatformKind::Other.to_string(), "Other");
}

#[test]
fn filter_existing_returns_only_exists() {
    let results = vec![
        PlatformResult {
            username: "test".into(),
            platform_name: "GitHub".into(),
            kind: PlatformKind::Developer,
            url: "https://api.github.com/users/test".into(),
            status: CheckStatus::Exists,
            profile_data: None,
            response_time_ms: 50,
            http_status: Some(200),
        },
        PlatformResult {
            username: "test".into(),
            platform_name: "GitLab".into(),
            kind: PlatformKind::Developer,
            url: "https://gitlab.com/api/v4/users?username=test".into(),
            status: CheckStatus::NotFound,
            profile_data: None,
            response_time_ms: 60,
            http_status: Some(404),
        },
        PlatformResult {
            username: "test".into(),
            platform_name: "Reddit".into(),
            kind: PlatformKind::Social,
            url: "https://www.reddit.com/user/test/about.json".into(),
            status: CheckStatus::Exists,
            profile_data: None,
            response_time_ms: 70,
            http_status: Some(200),
        },
    ];
    let existing = PlatformChecker::filter_existing(&results);
    assert_eq!(existing.len(), 2);
    assert_eq!(existing[0].platform_name, "GitHub");
    assert_eq!(existing[1].platform_name, "Reddit");
}

#[test]
fn group_by_kind_creates_correct_groups() {
    let results = vec![
        PlatformResult {
            username: "test".into(),
            platform_name: "GitHub".into(),
            kind: PlatformKind::Developer,
            url: "https://api.github.com/users/test".into(),
            status: CheckStatus::Exists,
            profile_data: None,
            response_time_ms: 50,
            http_status: Some(200),
        },
        PlatformResult {
            username: "test".into(),
            platform_name: "Reddit".into(),
            kind: PlatformKind::Social,
            url: "https://www.reddit.com/user/test/about.json".into(),
            status: CheckStatus::Exists,
            profile_data: None,
            response_time_ms: 70,
            http_status: Some(200),
        },
        PlatformResult {
            username: "test".into(),
            platform_name: "BitBucket".into(),
            kind: PlatformKind::Developer,
            url: "https://api.bitbucket.org/2.0/users/test".into(),
            status: CheckStatus::NotFound,
            profile_data: None,
            response_time_ms: 60,
            http_status: Some(404),
        },
    ];
    let groups = PlatformChecker::group_by_kind(&results);
    assert_eq!(groups.get(&PlatformKind::Developer).unwrap().len(), 2);
    assert_eq!(groups.get(&PlatformKind::Social).unwrap().len(), 1);
}

#[test]
fn profile_data_default_is_empty() {
    let pd = ProfileData::default();
    assert!(pd.display_name.is_none());
    assert!(pd.bio.is_none());
    assert!(pd.avatar_url.is_none());
    assert!(pd.follower_count.is_none());
    assert!(pd.extra.is_empty());
}

#[test]
fn platform_result_serialization_roundtrip() {
    let result = PlatformResult {
        username: "octocat".into(),
        platform_name: "GitHub".into(),
        kind: PlatformKind::Developer,
        url: "https://api.github.com/users/octocat".into(),
        status: CheckStatus::Exists,
        profile_data: Some(ProfileData {
            display_name: Some("The Octocat".into()),
            bio: Some("GitHub mascot".into()),
            avatar_url: Some("https://avatars.githubusercontent.com/u/583231".into()),
            follower_count: Some(10000),
            extra: Default::default(),
        }),
        response_time_ms: 42,
        http_status: Some(200),
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let deserialized: PlatformResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.username, "octocat");
    assert_eq!(deserialized.platform_name, "GitHub");
    assert_eq!(deserialized.status, CheckStatus::Exists);
    assert_eq!(deserialized.profile_data.as_ref().unwrap().display_name.as_deref(), Some("The Octocat"));
}

#[test]
fn detection_methods_cover_all_variants() {
    let status_code = DetectionMethod::StatusCode { exists: 200, not_found: 404 };
    let json_field = DetectionMethod::JsonField { path: "data.name", exists_value: None };
    let body_contains = DetectionMethod::BodyContains { not_found_marker: "not found" };
    let json_array = DetectionMethod::JsonArrayNonEmpty;
    let redirect = DetectionMethod::RedirectDetection { login_fragment: "/login" };

    assert!(matches!(status_code, DetectionMethod::StatusCode { .. }));
    assert!(matches!(json_field, DetectionMethod::JsonField { .. }));
    assert!(matches!(body_contains, DetectionMethod::BodyContains { .. }));
    assert!(matches!(json_array, DetectionMethod::JsonArrayNonEmpty));
    assert!(matches!(redirect, DetectionMethod::RedirectDetection { .. }));
}

#[test]
fn developer_platforms_at_least_10() {
    let platforms = all_platforms();
    let dev_count = platforms.iter().filter(|p| matches!(p.kind, PlatformKind::Developer)).count();
    assert!(dev_count >= 10, "expected 10+ dev platforms, got {dev_count}");
}

#[test]
fn social_platforms_at_least_5() {
    let platforms = all_platforms();
    let social_count = platforms.iter().filter(|p| matches!(p.kind, PlatformKind::Social)).count();
    assert!(social_count >= 5, "expected 5+ social platforms, got {social_count}");
}

#[tokio::test]
async fn check_username_runs_without_panic() {
    let config = PlatformCheckerConfig {
        concurrency: 2,
        timeout_secs: 2,
        delay_between_ms: 0,
        user_agents: vec!["test-agent/1.0".into()],
    };
    let custom = vec![PlatformDef {
        name: "Nonexistent",
        kind: PlatformKind::Other,
        url_template: "http://127.0.0.1:1/{}", 
        detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
    }];
    let checker = PlatformChecker::new(config).with_custom_platforms(custom);
    let results = checker.check_username("testuser").await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, CheckStatus::Error);
}

#[tokio::test]
async fn check_username_respects_concurrency() {
    let config = PlatformCheckerConfig {
        concurrency: 1,
        timeout_secs: 1,
        delay_between_ms: 0,
        user_agents: vec!["test-agent/1.0".into()],
    };
    let custom = vec![
        PlatformDef {
            name: "A",
            kind: PlatformKind::Other,
            url_template: "http://127.0.0.1:1/a/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
        PlatformDef {
            name: "B",
            kind: PlatformKind::Other,
            url_template: "http://127.0.0.1:1/b/{}",
            detection: DetectionMethod::StatusCode { exists: 200, not_found: 404 },
        },
    ];
    let checker = PlatformChecker::new(config).with_custom_platforms(custom);
    let results = checker.check_username("user").await;
    assert_eq!(results.len(), 2);
}
