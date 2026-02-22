use std::collections::HashSet;

use crate::brute_forcer::{
    BruteForceError, DirectoryBruster, is_baseline_match, is_interesting_path, validate_base_url,
};

#[test]
fn new_rejects_non_localhost() {
    let result = DirectoryBruster::new("http://example.com", vec!["admin".to_string()]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        BruteForceError::NonLocalhostTarget(_)
    ));
}

#[test]
fn new_rejects_invalid_url() {
    let result = DirectoryBruster::new("not a url", vec!["admin".to_string()]);
    assert!(result.is_err());
}

#[test]
fn new_accepts_localhost() {
    let result = DirectoryBruster::new("http://localhost:3000", vec!["admin".to_string()]);
    assert!(result.is_ok());
}

#[test]
fn new_accepts_127_0_0_1() {
    let result = DirectoryBruster::new("http://127.0.0.1:8080", vec!["admin".to_string()]);
    assert!(result.is_ok());
}

#[test]
fn builder_with_extensions() {
    let bruster = DirectoryBruster::new("http://localhost:3000", vec!["index".to_string()])
        .unwrap()
        .with_extensions(vec![".php".to_string(), ".html".to_string()]);
    let candidates = bruster.build_candidate_paths();
    assert_eq!(candidates, vec!["index", "index.php", "index.html"]);
}

#[test]
fn builder_with_concurrency_clamps_to_one() {
    let bruster = DirectoryBruster::new("http://localhost:3000", vec!["a".to_string()])
        .unwrap()
        .with_concurrency(0);
    assert_eq!(bruster.concurrency, 1);
}

#[test]
fn builder_with_filter_codes() {
    let mut codes = HashSet::new();
    codes.insert(403);
    codes.insert(404);
    let bruster = DirectoryBruster::new("http://localhost:3000", vec!["a".to_string()])
        .unwrap()
        .with_filter_codes(codes.clone());
    assert_eq!(bruster.filter_status_codes, codes);
}

#[test]
fn build_candidate_paths_no_extensions() {
    let bruster = DirectoryBruster::new(
        "http://localhost:3000",
        vec!["admin".to_string(), "backup".to_string()],
    )
    .unwrap();
    let candidates = bruster.build_candidate_paths();
    assert_eq!(candidates, vec!["admin", "backup"]);
}

#[test]
fn build_candidate_paths_with_extensions() {
    let bruster = DirectoryBruster::new("http://localhost:3000", vec!["test".to_string()])
        .unwrap()
        .with_extensions(vec![".php".to_string(), ".bak".to_string()]);
    let candidates = bruster.build_candidate_paths();
    assert_eq!(candidates, vec!["test", "test.php", "test.bak"]);
}

#[test]
fn build_candidate_paths_empty_wordlist() {
    let bruster = DirectoryBruster::new("http://localhost:3000", Vec::new()).unwrap();
    let candidates = bruster.build_candidate_paths();
    assert!(candidates.is_empty());
}

#[test]
fn base_url_trailing_slash_stripped() {
    let bruster =
        DirectoryBruster::new("http://localhost:3000/", vec!["admin".to_string()]).unwrap();
    assert_eq!(bruster.base_url, "http://localhost:3000");
}

#[test]
fn validate_base_url_localhost_ok() {
    assert!(validate_base_url("http://localhost:3000").is_ok());
    assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
    assert!(validate_base_url("http://[::1]:9090").is_ok());
}

#[test]
fn validate_base_url_remote_rejected() {
    assert!(validate_base_url("http://example.com").is_err());
    assert!(validate_base_url("https://google.com").is_err());
}

#[test]
fn validate_base_url_garbage_rejected() {
    assert!(validate_base_url("").is_err());
    assert!(validate_base_url("ftp://").is_err());
}

#[test]
fn is_baseline_match_exact() {
    assert!(is_baseline_match(1024, Some(1024)));
}

#[test]
fn is_baseline_match_within_tolerance() {
    assert!(is_baseline_match(1060, Some(1024)));
    assert!(is_baseline_match(1024, Some(1060)));
}

#[test]
fn is_baseline_match_outside_tolerance() {
    assert!(!is_baseline_match(2000, Some(1024)));
}

#[test]
fn is_baseline_match_no_baseline() {
    assert!(!is_baseline_match(1024, None));
}

#[test]
fn interesting_path_admin() {
    assert!(is_interesting_path("admin"));
    assert!(is_interesting_path("wp-admin"));
    assert!(is_interesting_path("/admin/dashboard"));
}

#[test]
fn interesting_path_dotenv() {
    assert!(is_interesting_path(".env"));
    assert!(is_interesting_path(".env.bak"));
}

#[test]
fn interesting_path_git() {
    assert!(is_interesting_path(".git/config"));
    assert!(is_interesting_path(".git/HEAD"));
}

#[test]
fn interesting_path_secrets() {
    assert!(is_interesting_path("secret.txt"));
    assert!(is_interesting_path(".aws/credentials"));
    assert!(is_interesting_path("id_rsa"));
}

#[test]
fn interesting_path_case_insensitive() {
    assert!(is_interesting_path("ADMIN"));
    assert!(is_interesting_path("Config.XML"));
    assert!(is_interesting_path("BACKUP.zip"));
}

#[test]
fn not_interesting_path() {
    assert!(!is_interesting_path("index.html"));
    assert!(!is_interesting_path("style.css"));
    assert!(!is_interesting_path("app.js"));
}

#[test]
fn run_with_empty_wordlist_returns_empty() {
    let bruster = DirectoryBruster::new("http://localhost:3000", Vec::new()).unwrap();
    let results = bruster.run();
    assert!(results.is_empty());
}

#[test]
fn default_filter_codes_contains_404() {
    let bruster =
        DirectoryBruster::new("http://localhost:3000", vec!["admin".to_string()]).unwrap();
    assert!(bruster.filter_status_codes.contains(&404));
}

#[test]
fn with_default_wordlist_constructor() {
    let bruster = DirectoryBruster::with_default_wordlist("http://localhost:3000").unwrap();
    assert!(!bruster.wordlist.is_empty());
}
