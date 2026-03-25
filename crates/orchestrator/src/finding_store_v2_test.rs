use super::*;

fn sample_store() -> FindingStoreV2 {
    FindingStoreV2::with_default_config()
}

fn add_sample(store: &mut FindingStoreV2, url: &str, severity: Severity) -> u64 {
    store.add_finding(
        url,
        "CWE-79",
        "CrossSiteScripting",
        severity,
        "XSS in input",
        "Reflected payload in response body".to_owned(),
        "<script>alert(1)</script>".to_owned(),
        0.85,
    )
}

#[test]
fn string_interner_basics() {
    let mut interner = StringInterner::new();
    assert!(interner.is_empty());

    let id = interner.intern("hello");
    assert_eq!(id, 0);
    assert_eq!(interner.len(), 1);
    assert_eq!(interner.resolve(id), Some("hello"));
    assert_eq!(interner.resolve(999), None);
}

#[test]
fn string_interner_deduplication() {
    let mut interner = StringInterner::new();
    let id_a = interner.intern("/api/users");
    let id_b = interner.intern("/api/users");
    let id_c = interner.intern("/api/login");

    assert_eq!(id_a, id_b);
    assert_ne!(id_a, id_c);
    assert_eq!(interner.len(), 2);
}

#[test]
fn default_config_values() {
    let config = FindingStoreConfig::default();
    assert_eq!(config.max_memory_findings, 10_000);
    assert!(config.spill_to_disk);
    assert!(config.spill_path.is_none());
    assert!(config.enable_indexing);
}

#[test]
fn config_builder_pattern() {
    let config = FindingStoreConfig::default()
        .with_max_memory(500)
        .with_spill_to_disk(false)
        .with_spill_path(PathBuf::from("/tmp/test"))
        .with_indexing(false);

    assert_eq!(config.max_memory_findings, 500);
    assert!(!config.spill_to_disk);
    assert_eq!(config.spill_path, Some(PathBuf::from("/tmp/test")));
    assert!(!config.enable_indexing);
}

#[test]
fn add_finding_returns_incrementing_ids() {
    let mut store = sample_store();
    let id0 = add_sample(&mut store, "/a", Severity::Low);
    let id1 = add_sample(&mut store, "/b", Severity::Medium);
    let id2 = add_sample(&mut store, "/c", Severity::High);

    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn get_finding_by_id() {
    let mut store = sample_store();
    let id = add_sample(&mut store, "/api/data", Severity::Critical);

    let finding = store.get_finding(id).expect("finding should exist");
    assert_eq!(finding.id, id);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, 0.85);
    assert!(store.get_finding(999).is_none());
}

#[test]
fn find_by_url_returns_matches() {
    let mut store = sample_store();
    store.add_finding(
        "/api/users",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi",
        "desc".to_owned(),
        "ev".to_owned(),
        0.9,
    );
    store.add_finding(
        "/api/login",
        "CWE-79",
        "XSS",
        Severity::Medium,
        "XSS",
        "desc".to_owned(),
        "ev".to_owned(),
        0.7,
    );
    store.add_finding(
        "/api/users",
        "CWE-79",
        "XSS",
        Severity::Low,
        "XSS",
        "desc".to_owned(),
        "ev".to_owned(),
        0.6,
    );

    let results = store.find_by_url("/api/users");
    assert_eq!(results.len(), 2);

    let results_login = store.find_by_url("/api/login");
    assert_eq!(results_login.len(), 1);

    let results_none = store.find_by_url("/nonexistent");
    assert!(results_none.is_empty());
}

#[test]
fn find_by_severity() {
    let mut store = sample_store();
    add_sample(&mut store, "/a", Severity::High);
    add_sample(&mut store, "/b", Severity::Low);
    add_sample(&mut store, "/c", Severity::High);

    let highs = store.find_by_severity(Severity::High);
    assert_eq!(highs.len(), 2);

    let lows = store.find_by_severity(Severity::Low);
    assert_eq!(lows.len(), 1);

    let crits = store.find_by_severity(Severity::Critical);
    assert!(crits.is_empty());
}

#[test]
fn find_by_cwe() {
    let mut store = sample_store();
    store.add_finding(
        "/a",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi",
        "d".to_owned(),
        "e".to_owned(),
        0.9,
    );
    store.add_finding(
        "/b",
        "CWE-79",
        "XSS",
        Severity::Medium,
        "XSS",
        "d".to_owned(),
        "e".to_owned(),
        0.8,
    );
    store.add_finding(
        "/c",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi",
        "d".to_owned(),
        "e".to_owned(),
        0.7,
    );

    assert_eq!(store.find_by_cwe("CWE-89").len(), 2);
    assert_eq!(store.find_by_cwe("CWE-79").len(), 1);
    assert!(store.find_by_cwe("CWE-999").is_empty());
}

#[test]
fn find_by_vuln_class() {
    let mut store = sample_store();
    store.add_finding(
        "/a",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi",
        "d".to_owned(),
        "e".to_owned(),
        0.9,
    );
    store.add_finding(
        "/b",
        "CWE-79",
        "CrossSiteScripting",
        Severity::Medium,
        "XSS",
        "d".to_owned(),
        "e".to_owned(),
        0.8,
    );

    assert_eq!(store.find_by_vuln_class("SqlInjection").len(), 1);
    assert_eq!(store.find_by_vuln_class("CrossSiteScripting").len(), 1);
    assert!(store.find_by_vuln_class("SSRF").is_empty());
}

#[test]
fn interning_deduplicates_repeated_urls() {
    let mut store = sample_store();
    for _ in 0..100 {
        add_sample(&mut store, "/api/users", Severity::Medium);
    }

    assert_eq!(store.len(), 100);
    let stats = store.stats();
    assert_eq!(stats.unique_urls, 1);
    assert_eq!(stats.interned_strings, 4);
}

#[test]
fn json_serialization_resolves_interned_strings() {
    let mut store = sample_store();
    store.add_finding(
        "https://example.com/login",
        "CWE-287",
        "BrokenAuth",
        Severity::Critical,
        "Auth bypass",
        "No token validation".to_owned(),
        "curl -X POST ...".to_owned(),
        0.95,
    );

    let json = store.to_json();
    assert!(json.contains("https://example.com/login"));
    assert!(json.contains("CWE-287"));
    assert!(json.contains("BrokenAuth"));
    assert!(json.contains("Auth bypass"));
    assert!(json.contains("No token validation"));
    assert!(json.contains("Critical"));
    assert!(json.contains("0.95"));

    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).expect("valid JSON array");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["url"], "https://example.com/login");
}

#[test]
fn spill_to_disk_writes_oldest_findings() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spill_path = tmp.path().join("spill.jsonl");

    let config = FindingStoreConfig::default()
        .with_max_memory(10)
        .with_spill_to_disk(true)
        .with_spill_path(spill_path.clone());

    let mut store = FindingStoreV2::new(config);
    for i in 0..10 {
        store.add_finding(
            &format!("/endpoint/{i}"),
            "CWE-79",
            "XSS",
            Severity::Medium,
            "XSS finding",
            format!("desc {i}"),
            format!("evidence {i}"),
            0.5 + (i as f64) * 0.01,
        );
    }
    assert_eq!(store.len(), 10);

    let spilled = store.spill_to_disk().expect("spill should succeed");
    assert_eq!(spilled, 5);
    assert_eq!(store.len(), 5);
    assert_eq!(store.spilled_count, 5);

    let content = std::fs::read_to_string(&spill_path).expect("read spill file");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 5);

    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    assert_eq!(first["id"], 0);
}

#[test]
fn auto_spill_on_add_when_at_capacity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spill_path = tmp.path().join("auto_spill.jsonl");

    let config = FindingStoreConfig::default()
        .with_max_memory(4)
        .with_spill_to_disk(true)
        .with_spill_path(spill_path.clone());

    let mut store = FindingStoreV2::new(config);
    for i in 0..4 {
        add_sample(&mut store, &format!("/ep/{i}"), Severity::Low);
    }
    assert_eq!(store.len(), 4);

    add_sample(&mut store, "/ep/overflow", Severity::High);
    assert!(store.len() <= 4);
    assert!(store.spilled_count > 0);
    assert!(spill_path.exists());
}

#[test]
fn stats_accuracy() {
    let mut store = sample_store();
    store.add_finding(
        "/a",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi",
        "d".to_owned(),
        "e".to_owned(),
        0.9,
    );
    store.add_finding(
        "/b",
        "CWE-79",
        "XSS",
        Severity::Medium,
        "XSS",
        "d".to_owned(),
        "e".to_owned(),
        0.8,
    );
    store.add_finding(
        "/a",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi2",
        "d".to_owned(),
        "e".to_owned(),
        0.7,
    );

    let stats = store.stats();
    assert_eq!(stats.total_findings, 3);
    assert_eq!(stats.in_memory_findings, 3);
    assert_eq!(stats.spilled_findings, 0);
    assert_eq!(stats.unique_urls, 2);
    assert_eq!(stats.unique_cwes, 2);
    assert_eq!(stats.unique_vuln_classes, 2);
    assert_eq!(stats.severity_counts["High"], 2);
    assert_eq!(stats.severity_counts["Medium"], 1);
    assert!(stats.memory_estimate_bytes > 0);
}

#[test]
fn clear_empties_store() {
    let mut store = sample_store();
    add_sample(&mut store, "/a", Severity::High);
    add_sample(&mut store, "/b", Severity::Low);
    assert_eq!(store.len(), 2);

    store.clear();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
    assert!(store.find_by_severity(Severity::High).is_empty());
    assert!(store.find_by_url("/a").is_empty());
}

#[test]
fn empty_store_is_empty() {
    let store = sample_store();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.find_by_url("/anything").is_empty());
    assert!(store.find_by_severity(Severity::Critical).is_empty());

    let stats = store.stats();
    assert_eq!(stats.total_findings, 0);
    assert_eq!(stats.in_memory_findings, 0);
}

#[test]
fn severity_ordering() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn severity_display() {
    assert_eq!(Severity::Info.to_string(), "Info");
    assert_eq!(Severity::Low.to_string(), "Low");
    assert_eq!(Severity::Medium.to_string(), "Medium");
    assert_eq!(Severity::High.to_string(), "High");
    assert_eq!(Severity::Critical.to_string(), "Critical");
}

#[test]
fn multiple_findings_same_url() {
    let mut store = sample_store();
    store.add_finding(
        "/api/data",
        "CWE-89",
        "SqlInjection",
        Severity::High,
        "SQLi",
        "d1".to_owned(),
        "e1".to_owned(),
        0.9,
    );
    store.add_finding(
        "/api/data",
        "CWE-79",
        "XSS",
        Severity::Medium,
        "XSS",
        "d2".to_owned(),
        "e2".to_owned(),
        0.7,
    );
    store.add_finding(
        "/api/data",
        "CWE-22",
        "PathTraversal",
        Severity::High,
        "Traversal",
        "d3".to_owned(),
        "e3".to_owned(),
        0.8,
    );

    let results = store.find_by_url("/api/data");
    assert_eq!(results.len(), 3);

    let ids: Vec<u64> = results.iter().map(|f| f.id).collect();
    assert_eq!(ids, vec![0, 1, 2]);
}

#[test]
fn resolve_helpers_return_correct_strings() {
    let mut store = sample_store();
    store.add_finding(
        "https://target.local/api/v1",
        "CWE-352",
        "CSRF",
        Severity::Medium,
        "Missing CSRF token",
        "No anti-forgery token in form".to_owned(),
        "POST /api/v1/transfer".to_owned(),
        0.75,
    );

    let finding = store.get_finding(0).expect("finding exists");
    assert_eq!(
        store.resolve_url(finding),
        Some("https://target.local/api/v1")
    );
    assert_eq!(store.resolve_cwe(finding), Some("CWE-352"));
    assert_eq!(store.resolve_vuln_class(finding), Some("CSRF"));
    assert_eq!(store.resolve_title(finding), Some("Missing CSRF token"));
}

#[test]
fn spill_empty_store_returns_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = FindingStoreConfig::default()
        .with_max_memory(100)
        .with_spill_path(tmp.path().join("empty.jsonl"));
    let mut store = FindingStoreV2::new(config);

    let spilled = store.spill_to_disk().expect("no error on empty");
    assert_eq!(spilled, 0);
}

#[test]
fn indices_rebuilt_after_spill() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = FindingStoreConfig::default()
        .with_max_memory(100)
        .with_spill_path(tmp.path().join("rebuild.jsonl"));

    let mut store = FindingStoreV2::new(config);
    for i in 0..6 {
        let severity = if i % 2 == 0 {
            Severity::High
        } else {
            Severity::Low
        };
        store.add_finding(
            &format!("/ep/{i}"),
            "CWE-79",
            "XSS",
            severity,
            "title",
            format!("d{i}"),
            format!("e{i}"),
            0.5,
        );
    }

    store.spill_to_disk().expect("spill");
    assert_eq!(store.len(), 3);

    let highs = store.find_by_severity(Severity::High);
    let lows = store.find_by_severity(Severity::Low);
    assert_eq!(highs.len() + lows.len(), 3);

    for f in &highs {
        assert_eq!(f.severity, Severity::High);
    }
    for f in &lows {
        assert_eq!(f.severity, Severity::Low);
    }
}

#[test]
fn json_output_is_valid_array() {
    let mut store = sample_store();
    add_sample(&mut store, "/x", Severity::Info);
    add_sample(&mut store, "/y", Severity::Critical);

    let json = store.to_json();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0]["severity"], "Info");
    assert_eq!(parsed[1]["severity"], "Critical");
}

#[test]
fn indexing_disabled_falls_back_to_empty_queries() {
    let config = FindingStoreConfig::default().with_indexing(false);
    let mut store = FindingStoreV2::new(config);
    add_sample(&mut store, "/api/users", Severity::High);

    assert!(store.find_by_url("/api/users").is_empty());
    assert!(store.find_by_severity(Severity::High).is_empty());
    assert_eq!(store.len(), 1);

    let finding = store.get_finding(0).expect("still retrievable by id");
    assert_eq!(finding.severity, Severity::High);
}
