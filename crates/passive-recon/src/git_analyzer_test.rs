use super::git_analyzer::*;

fn make_probe(path: &str, status: u16, body: &str) -> ProbeResult {
    ProbeResult {
        path: path.to_string(),
        status_code: status,
        body: body.to_string(),
        content_type: None,
    }
}

#[test]
fn test_git_exposed_via_head() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![make_probe(
        "https://target.local/.git/HEAD",
        200,
        "ref: refs/heads/main\n",
    )];

    let result = analyzer.analyze(&probes);
    assert!(result.git_exposed);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, GitFindingCategory::HeadExposure)));
}

#[test]
fn test_git_not_exposed_on_404() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![make_probe(
        "https://target.local/.git/HEAD",
        404,
        "Not Found",
    )];

    let result = analyzer.analyze(&probes);
    assert!(!result.git_exposed);
    assert!(result.findings.is_empty());
}

#[test]
fn test_config_exposure() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let config_body = r#"[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://github.com/corp/secret-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"#;
    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe("https://target.local/.git/config", 200, config_body),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result.git_exposed);
    let config_finding = result
        .findings
        .iter()
        .find(|f| matches!(f.category, GitFindingCategory::ConfigExposure))
        .expect("should find config exposure");
    assert!(config_finding.evidence.contains("origin"));
    assert_eq!(config_finding.severity, GitExposureSeverity::Critical);
}

#[test]
fn test_branch_enumeration_from_refs() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe(
            "https://target.local/.git/refs/heads/main",
            200,
            "abc123def456abc123def456abc123def456abc1\n",
        ),
        make_probe(
            "https://target.local/.git/refs/heads/develop",
            200,
            "def456abc123def456abc123def456abc123def4\n",
        ),
        make_probe(
            "https://target.local/.git/refs/heads/staging",
            404,
            "Not Found",
        ),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result.git_exposed);
    assert_eq!(result.discovered_branches.len(), 2);

    let main_branch = result.discovered_branches.iter().find(|b| b.name == "main");
    assert!(main_branch.is_some());
    assert!(main_branch.unwrap().is_active);

    let dev_branch = result
        .discovered_branches
        .iter()
        .find(|b| b.name == "develop");
    assert!(dev_branch.is_some());
    assert!(!dev_branch.unwrap().is_active);
}

#[test]
fn test_packed_refs_enumeration() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let packed_refs = "# pack-refs with: peeled fully-peeled sorted\n\
        abc123def456abc123def456abc123def456abc1 refs/heads/feature-auth\n\
        def456abc123def456abc123def456abc123def4 refs/tags/v1.0.0\n\
        111222333444555666777888999000aaabbbccc1 refs/heads/hotfix-payment\n";

    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe("https://target.local/.git/packed-refs", 200, packed_refs),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result.discovered_branches.len() >= 2);
    assert!(result
        .discovered_branches
        .iter()
        .any(|b| b.name == "feature-auth"));
    assert!(result
        .discovered_branches
        .iter()
        .any(|b| b.name == "hotfix-payment"));
}

#[test]
fn test_reflog_leakage() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let reflog = "0000000000000000000000000000000000000000 abc123def456abc123def456abc123def456abc1 Dev User <dev@corp.com> 1700000000 +0000\tcommit (initial): initial commit\n\
        abc123def456abc123def456abc123def456abc1 def456abc123def456abc123def456abc123def4 Dev User <dev@corp.com> 1700001000 +0000\tcommit: add database config\n";

    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe("https://target.local/.git/logs/HEAD", 200, reflog),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, GitFindingCategory::RefLogLeakage)));
    assert!(!result.reconstructed_commits.is_empty());
}

#[test]
fn test_secret_in_reflog() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let reflog_with_secret = "000 abc123def456abc123def456abc123def456abc1 Dev <d@c.com> 1700000000 +0000\tcommit: add config with AKIA1234567890ABCDEF key\n";

    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe(
            "https://target.local/.git/logs/HEAD",
            200,
            reflog_with_secret,
        ),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, GitFindingCategory::SecretInCommit)));
}

#[test]
fn test_pack_file_exposure() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let pack_info = "P pack-abc123def456abc123def456abc123def456ab.pack\n";

    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe(
            "https://target.local/.git/objects/info/packs",
            200,
            pack_info,
        ),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, GitFindingCategory::PackFileExposure)));
}

#[test]
fn test_sensitive_file_detection_in_reflog() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let reflog = "000 abc Dev <d@c.com> 1700000000 +0000\tcommit: remove .env file from repo\n\
        abc def Dev <d@c.com> 1700001000 +0000\tcommit: delete credentials.json\n";

    let probes = vec![
        make_probe(
            "https://target.local/.git/HEAD",
            200,
            "ref: refs/heads/main\n",
        ),
        make_probe("https://target.local/.git/logs/HEAD", 200, reflog),
    ];

    let result = analyzer.analyze(&probes);
    assert!(!result.recoverable_files.is_empty());
    assert!(result.recoverable_files.iter().any(|f| f.path == ".env"));
}

#[test]
fn test_non_default_branch_finding() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![make_probe(
        "https://target.local/.git/HEAD",
        200,
        "ref: refs/heads/feature-experimental\n",
    )];

    let result = analyzer.analyze(&probes);
    assert!(result.git_exposed);
    let non_default = result
        .findings
        .iter()
        .find(|f| f.description.contains("feature-experimental"));
    assert!(non_default.is_some());
}

#[test]
fn test_detached_head_state() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![make_probe(
        "https://target.local/.git/HEAD",
        200,
        "abc123def456abc123def456abc123def456abc1",
    )];

    let result = analyzer.analyze(&probes);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("Detached HEAD")));
}

#[test]
fn test_probe_paths_generation() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let paths = analyzer.probe_paths();
    assert!(paths.len() >= 15);
    assert!(paths.iter().any(|p| p.contains(".git/HEAD")));
    assert!(paths.iter().any(|p| p.contains(".git/config")));
    assert!(paths.iter().any(|p| p.contains("packed-refs")));
}

#[test]
fn test_severity_display() {
    assert_eq!(GitExposureSeverity::Critical.to_string(), "critical");
    assert_eq!(GitExposureSeverity::High.to_string(), "high");
    assert_eq!(GitExposureSeverity::Medium.to_string(), "medium");
    assert_eq!(GitExposureSeverity::Low.to_string(), "low");
    assert_eq!(GitExposureSeverity::Info.to_string(), "info");
}

#[test]
fn test_category_display() {
    assert_eq!(
        GitFindingCategory::HeadExposure.to_string(),
        "HEAD Exposure"
    );
    assert_eq!(
        GitFindingCategory::PackFileExposure.to_string(),
        "Pack File Exposure"
    );
    assert_eq!(
        GitFindingCategory::SecretInCommit.to_string(),
        "Secret in Commit"
    );
}

#[test]
fn test_object_leakage() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![make_probe(
        "https://target.local/.git/objects/ab/cd1234",
        200,
        "x\x01binary-git-object-data-blob",
    )];

    let result = analyzer.analyze(&probes);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, GitFindingCategory::ObjectLeakage)));
}

#[test]
fn test_full_analysis_comprehensive() {
    let analyzer = GitAnalyzer::new("https://target.local");
    let probes = vec![
        make_probe("https://target.local/.git/HEAD", 200, "ref: refs/heads/main\n"),
        make_probe(
            "https://target.local/.git/config",
            200,
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/corp/app.git\n",
        ),
        make_probe(
            "https://target.local/.git/refs/heads/main",
            200,
            "aabbccddee11223344556677889900aabbccddee\n",
        ),
        make_probe(
            "https://target.local/.git/refs/heads/develop",
            200,
            "1122334455667788990011223344556677889900\n",
        ),
        make_probe(
            "https://target.local/.git/logs/HEAD",
            200,
            "000 aabb Dev <d@c.com> 1700000000 +0000\tcommit: added .env with postgres://db:pass@host/db\n",
        ),
        make_probe(
            "https://target.local/.git/objects/info/packs",
            200,
            "P pack-aabbccdd.pack\n",
        ),
    ];

    let result = analyzer.analyze(&probes);
    assert!(result.git_exposed);
    assert!(result.findings.len() >= 4);
    assert!(!result.discovered_branches.is_empty());
    assert!(!result.reconstructed_commits.is_empty());
}

#[test]
fn test_url_trailing_slash_normalization() {
    let analyzer = GitAnalyzer::new("https://target.local/");
    let paths = analyzer.probe_paths();
    for p in &paths {
        let after_scheme = p.split("://").nth(1).unwrap_or(p);
        assert!(!after_scheme.contains("//"), "double slash in path: {}", p);
    }
}
