use super::github_scanner_v3::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

#[test]
fn entropy_of_empty_data_is_zero() {
    let result = calculate_shannon_entropy(&[]);
    assert!((result - 0.0).abs() < f64::EPSILON);
}

#[test]
fn entropy_of_single_byte_repeated_is_zero() {
    let data = vec![0xAAu8; 1024];
    let result = calculate_shannon_entropy(&data);
    assert!((result - 0.0).abs() < f64::EPSILON);
}

#[test]
fn entropy_of_two_equally_distributed_bytes_is_one() {
    let mut data = Vec::with_capacity(1000);
    for _ in 0..500 {
        data.push(0x00);
        data.push(0xFF);
    }
    let result = calculate_shannon_entropy(&data);
    assert!((result - 1.0).abs() < 0.001, "expected ~1.0, got {result}");
}

#[test]
fn entropy_of_uniform_256_values_is_eight() {
    let mut data = Vec::with_capacity(256 * 100);
    for _ in 0..100 {
        for b in 0u8..=255 {
            data.push(b);
        }
    }
    let result = calculate_shannon_entropy(&data);
    assert!((result - 8.0).abs() < 0.001, "expected ~8.0, got {result}");
}

#[test]
fn entropy_of_ascii_text_is_moderate() {
    let text = b"The quick brown fox jumps over the lazy dog";
    let result = calculate_shannon_entropy(text);
    assert!(
        result > 3.5 && result < 5.0,
        "expected 3.5–5.0, got {result}"
    );
}

#[test]
fn entropy_of_hex_string_is_high() {
    let hex = b"a3f8c9e1d5b07624a3f8c9e1d5b07624a3f8c9e1d5b07624";
    let result = calculate_shannon_entropy(hex);
    assert!(result > 3.0, "hex entropy should be > 3.0, got {result}");
}

// ---------------------------------------------------------------------------
// Entropy risk classification
// ---------------------------------------------------------------------------

#[test]
fn classify_entropy_critical() {
    assert_eq!(classify_entropy_risk(7.9), ScanRisk::Critical);
    assert_eq!(classify_entropy_risk(7.5), ScanRisk::Critical);
}

#[test]
fn classify_entropy_high() {
    assert_eq!(classify_entropy_risk(7.0), ScanRisk::High);
    assert_eq!(classify_entropy_risk(6.5), ScanRisk::High);
}

#[test]
fn classify_entropy_medium() {
    assert_eq!(classify_entropy_risk(5.5), ScanRisk::Medium);
    assert_eq!(classify_entropy_risk(5.0), ScanRisk::Medium);
}

#[test]
fn classify_entropy_low_and_info() {
    assert_eq!(classify_entropy_risk(4.0), ScanRisk::Low);
    assert_eq!(classify_entropy_risk(2.0), ScanRisk::Info);
    assert_eq!(classify_entropy_risk(0.0), ScanRisk::Info);
}

// ---------------------------------------------------------------------------
// Secret pattern matching
// ---------------------------------------------------------------------------

#[test]
fn patterns_all_compile() {
    let patterns = build_secret_patterns();
    assert!(
        patterns.len() >= 16,
        "expected 16+ patterns, got {}",
        patterns.len()
    );
}

#[test]
fn aws_access_key_detected() {
    let patterns = build_secret_patterns();
    let aws_pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::AwsAccessKey)
        .expect("AwsAccessKey pattern missing");
    assert!(aws_pat.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
    assert!(!aws_pat.regex.is_match("notakey"));
}

#[test]
fn aws_secret_key_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::AwsSecretKey)
        .expect("AwsSecretKey pattern missing");
    assert!(pat
        .regex
        .is_match("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    assert!(!pat.regex.is_match("not_a_secret"));
}

#[test]
fn github_classic_token_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::GitHubTokenClassic)
        .expect("GitHubTokenClassic pattern missing");
    assert!(pat
        .regex
        .is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"));
    assert!(!pat.regex.is_match("ghp_short"));
}

#[test]
fn github_fine_grained_token_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::GitHubTokenFineGrained)
        .expect("GitHubTokenFineGrained pattern missing");
    assert!(pat.regex.is_match("github_pat_11ABCDEF0123456789abcdef"));
    assert!(!pat.regex.is_match("github_pat_short"));
}

#[test]
fn rsa_private_key_header_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::PrivateKeyRsa)
        .expect("PrivateKeyRsa pattern missing");
    assert!(pat.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(!pat.regex.is_match("-----BEGIN PUBLIC KEY-----"));
}

#[test]
fn ec_private_key_header_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::PrivateKeyEc)
        .expect("PrivateKeyEc pattern missing");
    assert!(pat.regex.is_match("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn jwt_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::JsonWebToken)
        .expect("JsonWebToken pattern missing");
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    assert!(pat.regex.is_match(token));
    assert!(!pat.regex.is_match("eyJshort.nope.bad"));
}

#[test]
fn stripe_secret_key_detected() {
    let patterns = build_secret_patterns();
    let pat = patterns
        .iter()
        .find(|p| p.secret_type == SecretType::StripeSecretKey)
        .expect("StripeSecretKey pattern missing");
    assert!(pat.regex.is_match("sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
    assert!(!pat.regex.is_match("sk_test_short"));
}

// ---------------------------------------------------------------------------
// Git log JSON parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_valid_git_log_json() {
    let json = r#"[
        {
            "sha": "abc123",
            "author": "Akira Tanaka",
            "email": "akira@example.com",
            "date": "2024-06-15T10:30:00Z",
            "message": "fix: resolve null pointer in auth flow",
            "files": ["src/auth.rs", "tests/auth_test.rs"]
        },
        {
            "sha": "def456",
            "author": "Lucia Fernandez",
            "email": "lucia@example.com",
            "date": "2024-06-14T08:00:00Z",
            "message": "feat: add OAuth2 support",
            "files": ["src/oauth.rs"]
        }
    ]"#;

    let commits = parse_git_log_json(json);
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0].sha, "abc123");
    assert_eq!(commits[0].author, "Akira Tanaka");
    assert_eq!(commits[0].email, "akira@example.com");
    assert_eq!(commits[0].files_changed.len(), 2);
    assert_eq!(commits[1].message, "feat: add OAuth2 support");
}

#[test]
fn parse_empty_json_array() {
    let commits = parse_git_log_json("[]");
    assert!(commits.is_empty());
}

#[test]
fn parse_malformed_json_returns_empty() {
    let commits = parse_git_log_json("this is not json");
    assert!(commits.is_empty());
}

#[test]
fn parse_git_log_skips_entries_missing_required_fields() {
    let json = r#"[
        {"sha": "aaa111", "author": "Test"},
        {
            "sha": "bbb222",
            "author": "Mei Kobayashi",
            "email": "mei@example.jp",
            "date": "2024-01-01T00:00:00Z",
            "message": "chore: cleanup",
            "files": []
        }
    ]"#;
    let commits = parse_git_log_json(json);
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].sha, "bbb222");
}

// ---------------------------------------------------------------------------
// Branch detection
// ---------------------------------------------------------------------------

#[test]
fn detect_active_branch_with_remote() {
    let output = "* main       abc1234 latest commit message\n";
    let mut refs = HashMap::new();
    refs.insert("origin/main".to_string(), "abc1234".to_string());

    let branches = detect_deleted_branches(output, &refs);
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].name, "main");
    assert_eq!(branches[0].status, BranchStatus::Active);
    assert!(branches[0].remote_tracking.is_some());
}

#[test]
fn detect_orphaned_branch_without_remote() {
    let output = "  feature-abandoned  def5678 old work\n";
    let refs: HashMap<String, String> = HashMap::new();

    let branches = detect_deleted_branches(output, &refs);
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].status, BranchStatus::Orphaned);
    assert!(branches[0].remote_tracking.is_none());
}

#[test]
fn detect_gone_branch() {
    let output = "  stale-feature  aaa1111 [origin/stale-feature: gone] old stuff\n";
    let refs: HashMap<String, String> = HashMap::new();

    let branches = detect_deleted_branches(output, &refs);
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].status, BranchStatus::DeletedRemote);
}

#[test]
fn detect_force_pushed_branch() {
    let output = "  feature-x  aaa1111 [ahead 3, behind 2] diverged\n";
    let mut refs = HashMap::new();
    refs.insert("origin/feature-x".to_string(), "bbb2222".to_string());

    let branches = detect_deleted_branches(output, &refs);
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].status, BranchStatus::ForcePushed);
    assert_eq!(branches[0].ahead, 3);
    assert_eq!(branches[0].behind, 2);
}

#[test]
fn remotes_lines_are_skipped() {
    let output = "  remotes/origin/main  abc1234 msg\n  local  def5678 msg\n";
    let refs: HashMap<String, String> = HashMap::new();
    let branches = detect_deleted_branches(output, &refs);
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].name, "local");
}

// ---------------------------------------------------------------------------
// High entropy string extraction
// ---------------------------------------------------------------------------

#[test]
fn extract_high_entropy_finds_random_token() {
    let content = "normal text here\nAWS_KEY=A3F8C9E1D5B07624A3F8C9E1D5B07624A3F8C9E1\nmore text";
    let results = extract_high_entropy_strings(content, 3.0, 20);
    assert!(
        !results.is_empty(),
        "should find at least one high-entropy token"
    );
    assert_eq!(results[0].line_number, 2);
}

#[test]
fn extract_high_entropy_skips_short_tokens() {
    let content = "abc 12345 short";
    let results = extract_high_entropy_strings(content, 2.0, 20);
    assert!(results.is_empty());
}

#[test]
fn extract_high_entropy_respects_threshold() {
    let content = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let results = extract_high_entropy_strings(content, 1.0, 10);
    assert!(
        results.is_empty(),
        "repeated single char should have entropy 0, below threshold"
    );
}

// ---------------------------------------------------------------------------
// Blob scanning
// ---------------------------------------------------------------------------

#[test]
fn scan_blob_finds_aws_key() {
    let patterns = build_secret_patterns();
    let content = "config_value = AKIAIOSFODNN7EXAMPLE\n";
    let findings = scan_blob_for_secrets(content, "config.yaml", Some("abc123"), &patterns);
    assert!(
        findings
            .iter()
            .any(|f| f.secret_type == SecretType::AwsAccessKey),
        "should detect AWS access key"
    );
    assert!(findings.iter().any(|f| f.line_number == 1));
    assert!(findings.iter().any(|f| f.file_path == "config.yaml"));
    assert!(findings
        .iter()
        .any(|f| f.commit_sha.as_deref() == Some("abc123")));
}

#[test]
fn scan_blob_finds_jwt() {
    let patterns = build_secret_patterns();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let content = format!("Authorization: Bearer {jwt}\n");
    let findings = scan_blob_for_secrets(&content, "request.log", None, &patterns);
    assert!(
        findings
            .iter()
            .any(|f| f.secret_type == SecretType::JsonWebToken),
        "should detect JWT"
    );
}

#[test]
fn scan_blob_returns_empty_for_clean_file() {
    let patterns = build_secret_patterns();
    let content = "fn main() {\n    println!(\"Hello, world!\");\n}\n";
    let findings = scan_blob_for_secrets(content, "main.rs", None, &patterns);
    assert!(
        findings.is_empty(),
        "clean source should produce no findings"
    );
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

#[test]
fn build_report_computes_stats_correctly() {
    let commits = vec![CommitRecord {
        sha: "aaa".to_string(),
        author: "Ren Nakamura".to_string(),
        email: "ren@example.jp".to_string(),
        date: "2024-01-01T00:00:00Z".to_string(),
        message: "init".to_string(),
        files_changed: vec!["README.md".to_string()],
    }];

    let branches = vec![
        BranchInfo {
            name: "main".to_string(),
            status: BranchStatus::Active,
            last_commit_sha: Some("aaa".to_string()),
            remote_tracking: Some("origin/main".to_string()),
            ahead: 0,
            behind: 0,
        },
        BranchInfo {
            name: "old-feature".to_string(),
            status: BranchStatus::DeletedRemote,
            last_commit_sha: Some("bbb".to_string()),
            remote_tracking: None,
            ahead: 0,
            behind: 0,
        },
    ];

    let entropy_results = vec![EntropyResult {
        file_path: "secrets.env".to_string(),
        entropy: 7.8,
        size_bytes: 512,
        risk: ScanRisk::Critical,
        high_entropy_strings: vec![],
    }];

    let secret_findings = vec![SecretFinding {
        secret_type: SecretType::AwsAccessKey,
        matched_text: "AKIAIOSFODNN7EXAMPLE".to_string(),
        file_path: "config.yml".to_string(),
        line_number: 5,
        commit_sha: Some("aaa".to_string()),
        risk: ScanRisk::Critical,
        context: "aws_key=AKIAIOSFODNN7EXAMPLE1".to_string(),
    }];

    let report = build_git_scan_report(
        "https://github.com/example/repo",
        &commits,
        branches,
        entropy_results,
        secret_findings,
    );

    assert_eq!(report.repository, "https://github.com/example/repo");
    assert_eq!(report.commits_scanned, 1);
    assert_eq!(report.overall_risk, ScanRisk::Critical);
    assert_eq!(report.stats.total_secrets_found, 1);
    assert_eq!(report.stats.high_entropy_files, 1);
    assert_eq!(report.stats.deleted_branches, 1);
    assert_eq!(report.stats.force_pushed_branches, 0);
    assert_eq!(report.stats.risk_distribution.get("critical"), Some(&1));
}

#[test]
fn build_report_with_no_findings_has_info_risk() {
    let report = build_git_scan_report("repo", &[], Vec::new(), Vec::new(), Vec::new());
    assert_eq!(report.overall_risk, ScanRisk::Info);
    assert_eq!(report.stats.total_secrets_found, 0);
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

#[test]
fn secret_type_display() {
    assert_eq!(SecretType::AwsAccessKey.to_string(), "AWS Access Key");
    assert_eq!(SecretType::JsonWebToken.to_string(), "JSON Web Token");
    assert_eq!(
        SecretType::GenericHighEntropy.to_string(),
        "Generic High-Entropy String"
    );
    assert_eq!(SecretType::PrivateKeyRsa.to_string(), "RSA Private Key");
    assert_eq!(
        SecretType::GitHubTokenFineGrained.to_string(),
        "GitHub Token (fine-grained)"
    );
}

#[test]
fn branch_status_display() {
    assert_eq!(BranchStatus::Active.to_string(), "active");
    assert_eq!(BranchStatus::DeletedRemote.to_string(), "deleted-remote");
    assert_eq!(BranchStatus::ForcePushed.to_string(), "force-pushed");
    assert_eq!(BranchStatus::Orphaned.to_string(), "orphaned");
    assert_eq!(BranchStatus::Merged.to_string(), "merged");
    assert_eq!(BranchStatus::Stale.to_string(), "stale");
}

#[test]
fn scan_risk_display() {
    assert_eq!(ScanRisk::Info.to_string(), "info");
    assert_eq!(ScanRisk::Low.to_string(), "low");
    assert_eq!(ScanRisk::Medium.to_string(), "medium");
    assert_eq!(ScanRisk::High.to_string(), "high");
    assert_eq!(ScanRisk::Critical.to_string(), "critical");
}

#[test]
fn scan_risk_ordering() {
    assert!(ScanRisk::Critical > ScanRisk::High);
    assert!(ScanRisk::High > ScanRisk::Medium);
    assert!(ScanRisk::Medium > ScanRisk::Low);
    assert!(ScanRisk::Low > ScanRisk::Info);
}
