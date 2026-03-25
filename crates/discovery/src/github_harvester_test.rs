use super::github_harvester::*;
use std::collections::HashSet;

#[test]
fn default_config_values() {
    let config = GitHubHarvesterConfig::default();
    assert_eq!(config.max_repos, 100);
    assert!(config.scan_commits);
    assert_eq!(config.max_commits_per_repo, 30);
    assert!(config.scan_secrets);
    assert_eq!(config.timeout_secs, 15);
}

#[test]
fn secret_patterns_compile() {
    let patterns = secret_patterns();
    assert!(patterns.len() >= 15, "expected 15+ patterns, got {}", patterns.len());
    for sp in &patterns {
        let compiled = regex::Regex::new(sp.regex);
        assert!(compiled.is_ok(), "Pattern '{}' failed to compile: {:?}", sp.name, compiled.err());
    }
}

#[test]
fn aws_key_pattern_matches() {
    let patterns = secret_patterns();
    let aws_pat = patterns.iter().find(|p| p.name == "AWS Access Key").unwrap();
    let re = regex::Regex::new(aws_pat.regex).unwrap();
    assert!(re.is_match("AKIAIOSFODNN7EXAMPLE"));
    assert!(!re.is_match("notakey"));
}

#[test]
fn github_token_pattern_matches() {
    let patterns = secret_patterns();
    let gh_pat = patterns.iter().find(|p| p.name == "GitHub Token (classic)").unwrap();
    let re = regex::Regex::new(gh_pat.regex).unwrap();
    assert!(re.is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"));
    assert!(!re.is_match("ghr_short"));
}

#[test]
fn generic_password_pattern_matches() {
    let patterns = secret_patterns();
    let pw_pat = patterns.iter().find(|p| p.name == "Generic Password").unwrap();
    let re = regex::Regex::new(pw_pat.regex).unwrap();
    assert!(re.is_match(r#"password="supersecretpassword""#));
    assert!(re.is_match(r#"PASSWORD='mypassword123'"#));
    assert!(!re.is_match("password="));
}

#[test]
fn private_key_pattern_matches() {
    let patterns = secret_patterns();
    let pk_pat = patterns.iter().find(|p| p.name == "Private Key Header").unwrap();
    let re = regex::Regex::new(pk_pat.regex).unwrap();
    assert!(re.is_match("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(re.is_match("-----BEGIN PRIVATE KEY-----"));
    assert!(re.is_match("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn harvester_creation() {
    let harvester = GitHubHarvester::new(GitHubHarvesterConfig::default());
    assert!(!harvester.compiled_patterns.is_empty());
}

#[test]
fn harvester_without_secrets_has_no_patterns() {
    let config = GitHubHarvesterConfig {
        scan_secrets: false,
        ..GitHubHarvesterConfig::default()
    };
    let harvester = GitHubHarvester::new(config);
    assert!(harvester.compiled_patterns.is_empty());
}

#[test]
fn parse_commit_datetime_extracts_hour_and_day() {
    let (hour, _dow) = crate::github_harvester::parse_commit_datetime("2024-01-15T14:30:00Z").unwrap();
    assert_eq!(hour, 14);
}

#[test]
fn parse_commit_datetime_rejects_short_string() {
    assert!(crate::github_harvester::parse_commit_datetime("2024").is_none());
}

#[test]
fn estimate_timezone_returns_none_for_sparse_data() {
    let hist = [0u32; 24];
    assert!(crate::github_harvester::estimate_timezone(&hist).is_none());
}

#[test]
fn estimate_timezone_detects_us_eastern() {
    let mut hist = [0u32; 24];
    hist[14] = 50;
    hist[15] = 40;
    hist[13] = 30;
    let tz = crate::github_harvester::estimate_timezone(&hist);
    assert!(tz.is_some());
    assert!(tz.unwrap().contains("US Eastern"));
}

#[test]
fn estimate_timezone_detects_us_pacific() {
    let mut hist = [0u32; 24];
    hist[18] = 60;
    hist[17] = 40;
    let tz = crate::github_harvester::estimate_timezone(&hist);
    assert!(tz.is_some());
    assert!(tz.unwrap().contains("US Pacific"));
}

#[test]
fn estimate_timezone_detects_western_europe() {
    let mut hist = [0u32; 24];
    hist[10] = 80;
    hist[9] = 30;
    let tz = crate::github_harvester::estimate_timezone(&hist);
    assert!(tz.is_some());
    assert!(tz.unwrap().contains("Western Europe"));
}

#[test]
fn build_language_breakdown_counts_correctly() {
    let repos = vec![
        GitHubRepo {
            name: "a".into(), full_name: "u/a".into(), description: None,
            language: Some("Rust".into()), stargazers_count: 10, forks_count: 2,
            fork: false, created_at: "".into(), updated_at: "".into(),
            html_url: "".into(), topics: vec![],
        },
        GitHubRepo {
            name: "b".into(), full_name: "u/b".into(), description: None,
            language: Some("Rust".into()), stargazers_count: 5, forks_count: 1,
            fork: false, created_at: "".into(), updated_at: "".into(),
            html_url: "".into(), topics: vec![],
        },
        GitHubRepo {
            name: "c".into(), full_name: "u/c".into(), description: None,
            language: Some("Python".into()), stargazers_count: 3, forks_count: 0,
            fork: false, created_at: "".into(), updated_at: "".into(),
            html_url: "".into(), topics: vec![],
        },
    ];
    let langs = crate::github_harvester::build_language_breakdown(&repos);
    assert_eq!(*langs.get("Rust").unwrap(), 2);
    assert_eq!(*langs.get("Python").unwrap(), 1);
}

#[test]
fn commit_email_equality() {
    let e1 = CommitEmail {
        email: "user@example.com".into(),
        committer_name: "User".into(),
        repo: "repo".into(),
        commit_sha: "abc123".into(),
    };
    let e2 = e1.clone();
    assert_eq!(e1, e2);

    let mut set = HashSet::new();
    set.insert(e1);
    set.insert(e2);
    assert_eq!(set.len(), 1);
}

#[test]
fn github_harvester_error_display() {
    assert_eq!(
        GitHubHarvesterError::UserNotFound("ghost".into()).to_string(),
        "GitHub user not found: ghost"
    );
    assert_eq!(
        GitHubHarvesterError::RateLimited.to_string(),
        "GitHub API rate limit exceeded"
    );
    assert!(GitHubHarvesterError::Network("timeout".into()).to_string().contains("timeout"));
    assert!(GitHubHarvesterError::ParseError("bad json".into()).to_string().contains("bad json"));
}

#[test]
fn github_profile_serialization_roundtrip() {
    let profile = GitHubProfile {
        login: "octocat".into(),
        name: Some("The Octocat".into()),
        bio: Some("GitHub mascot".into()),
        company: Some("@github".into()),
        location: Some("San Francisco".into()),
        email: None,
        blog: Some("https://github.blog".into()),
        twitter_username: None,
        public_repos: 8,
        public_gists: 0,
        followers: 10000,
        following: 0,
        created_at: "2011-01-25T18:44:36Z".into(),
        avatar_url: "https://avatars.githubusercontent.com/u/583231".into(),
    };
    let json = serde_json::to_string(&profile).unwrap();
    let deserialized: GitHubProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.login, "octocat");
    assert_eq!(deserialized.followers, 10000);
}

#[test]
fn github_repo_serialization_roundtrip() {
    let repo = GitHubRepo {
        name: "hello-world".into(),
        full_name: "octocat/hello-world".into(),
        description: Some("My first repo".into()),
        language: Some("Ruby".into()),
        stargazers_count: 1000,
        forks_count: 500,
        fork: false,
        created_at: "2011-01-26T19:01:12Z".into(),
        updated_at: "2024-01-01T00:00:00Z".into(),
        html_url: "https://github.com/octocat/hello-world".into(),
        topics: vec!["demo".into()],
    };
    let json = serde_json::to_string(&repo).unwrap();
    let deserialized: GitHubRepo = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, "hello-world");
    assert!(!deserialized.fork);
    assert_eq!(deserialized.topics.len(), 1);
}

#[test]
fn activity_pattern_default_is_zeroed() {
    let ap = ActivityPattern::default();
    assert_eq!(ap.hour_histogram.iter().sum::<u32>(), 0);
    assert_eq!(ap.day_histogram.iter().sum::<u32>(), 0);
    assert!(ap.estimated_timezone.is_none());
    assert_eq!(ap.total_commits_analyzed, 0);
}

#[test]
fn day_of_week_known_dates() {
    assert_eq!(crate::github_harvester::day_of_week(2024, 1, 1), 0);
    assert_eq!(crate::github_harvester::day_of_week(2024, 1, 7), 6);
}

#[tokio::test]
async fn harvest_nonexistent_host_returns_network_error() {
    let config = GitHubHarvesterConfig {
        timeout_secs: 1,
        scan_commits: false,
        scan_secrets: false,
        ..GitHubHarvesterConfig::default()
    };
    let harvester = GitHubHarvester::new(config);
    let result = harvester.fetch_profile("__nonexistent_test_user_xyz__").await;
    assert!(result.is_err());
}

#[test]
fn extract_commit_data_from_json() {
    let commit_json = serde_json::json!({
        "sha": "abc123def456",
        "commit": {
            "author": {
                "name": "John Doe",
                "email": "john@example.com",
                "date": "2024-03-15T14:30:00Z"
            },
            "message": "fix: update config"
        }
    });

    let mut emails = HashSet::new();
    let mut activity = ActivityPattern::default();

    GitHubHarvester::extract_commit_data(&commit_json, "test-repo", &mut emails, &mut activity);

    assert_eq!(emails.len(), 1);
    let email = emails.iter().next().unwrap();
    assert_eq!(email.email, "john@example.com");
    assert_eq!(email.committer_name, "John Doe");
    assert_eq!(activity.total_commits_analyzed, 1);
    assert_eq!(activity.hour_histogram[14], 1);
}

#[test]
fn extract_commit_data_skips_noreply() {
    let commit_json = serde_json::json!({
        "sha": "abc123",
        "commit": {
            "author": {
                "name": "Bot",
                "email": "bot@users.noreply.github.com",
                "date": "2024-03-15T10:00:00Z"
            },
            "message": "chore: auto-update"
        }
    });

    let mut emails = HashSet::new();
    let mut activity = ActivityPattern::default();

    GitHubHarvester::extract_commit_data(&commit_json, "repo", &mut emails, &mut activity);
    assert_eq!(emails.len(), 0);
    assert_eq!(activity.total_commits_analyzed, 1);
}

#[test]
fn scan_commit_for_secrets_finds_aws_key() {
    let config = GitHubHarvesterConfig::default();
    let harvester = GitHubHarvester::new(config);

    let commit_json = serde_json::json!({
        "sha": "deadbeef",
        "commit": {
            "message": "added config with AKIAIOSFODNN7EXAMPLE key",
            "author": {
                "name": "Dev",
                "email": "dev@test.com",
                "date": "2024-01-01T00:00:00Z"
            }
        }
    });

    let mut secrets = Vec::new();
    harvester.scan_commit_for_secrets(&commit_json, "leaky-repo", &mut secrets);

    assert!(!secrets.is_empty());
    assert_eq!(secrets[0].pattern_name, "AWS Access Key");
    assert!(secrets[0].matched_text.contains("AKIAIOSFODNN7EXAMPLE"));
    assert_eq!(secrets[0].repo, "leaky-repo");
}
