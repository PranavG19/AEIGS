use super::ct_monitor_v2::*;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fixture_crtsh_json_basic() -> &'static str {
    r#"[
        {
            "id": 10001,
            "issuer_ca_id": 100,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "www.example.com",
            "name_value": "www.example.com\nexample.com",
            "serial_number": "serial-aaa-111",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
            "entry_timestamp": "2024-01-01T12:00:00",
            "result_count": 2
        },
        {
            "id": 10002,
            "issuer_ca_id": 100,
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert SHA2",
            "common_name": "api.example.com",
            "name_value": "api.example.com\nstaging.example.com",
            "serial_number": "serial-bbb-222",
            "not_before": "2024-02-01T00:00:00",
            "not_after": "2025-02-01T00:00:00",
            "entry_timestamp": "2024-02-01T12:00:00",
            "result_count": 2
        }
    ]"#
}

fn fixture_crtsh_json_wildcard() -> &'static str {
    r#"[
        {
            "id": 20001,
            "issuer_ca_id": 200,
            "issuer_name": "C=US, O=Sectigo, CN=Sectigo RSA",
            "common_name": "*.example.com",
            "name_value": "*.example.com\nexample.com",
            "serial_number": "serial-wild-001",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "entry_timestamp": "2024-01-01T00:00:00",
            "result_count": 1
        }
    ]"#
}

fn fixture_crtsh_json_expired() -> &'static str {
    r#"[
        {
            "id": 30001,
            "issuer_ca_id": 300,
            "issuer_name": "C=US, O=GoDaddy, CN=GoDaddy Secure",
            "common_name": "old.example.com",
            "name_value": "old.example.com",
            "serial_number": "serial-exp-001",
            "not_before": "2022-01-01T00:00:00",
            "not_after": "2023-01-01T00:00:00",
            "entry_timestamp": "2022-01-01T00:00:00",
            "result_count": 1
        }
    ]"#
}

fn fixture_crtsh_json_self_signed() -> &'static str {
    r#"[
        {
            "id": 40001,
            "issuer_ca_id": 0,
            "issuer_name": "CN=internal.test.local",
            "common_name": "internal.test.local",
            "name_value": "internal.test.local\nlocalhost",
            "serial_number": "serial-self-001",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2034-01-01T00:00:00",
            "entry_timestamp": "2024-01-01T00:00:00",
            "result_count": 1
        }
    ]"#
}

fn fixture_crtsh_json_many_sans() -> String {
    let mut sans_lines = Vec::new();
    for i in 0..120 {
        sans_lines.push(format!("sub{i}.example.com"));
    }
    let name_value = sans_lines.join("\\n");
    format!(
        r#"[{{"id": 50001, "issuer_ca_id": 100, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "example.com", "name_value": "{name_value}", "serial_number": "serial-many-001", "not_before": "2024-01-01T00:00:00", "not_after": "2025-01-01T00:00:00", "entry_timestamp": "2024-01-01T00:00:00", "result_count": 1}}]"#
    )
}

fn make_cert(
    serial: &str,
    cn: &str,
    issuer_org: &str,
    issuer_cn: &str,
    not_before: &str,
    not_after: &str,
    sans: Vec<&str>,
    is_wildcard: bool,
) -> CertInfo {
    CertInfo {
        serial: serial.to_string(),
        fingerprint: format!("fp:{serial}"),
        subject_cn: cn.to_string(),
        sans: sans.into_iter().map(|s| s.to_string()).collect(),
        issuer: CertIssuer {
            organization: issuer_org.to_string(),
            common_name: issuer_cn.to_string(),
            country: "US".to_string(),
        },
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        is_wildcard,
        crtsh_id: 0,
    }
}

// ---------------------------------------------------------------------------
// crt.sh URL building
// ---------------------------------------------------------------------------

#[test]
fn build_url_domain_mode() {
    let q = CrtShQuery::domain("example.com");
    let url = build_crtsh_query_url(&q);
    assert_eq!(url, "https://crt.sh/?q=%.example.com&output=json");
}

#[test]
fn build_url_wildcard_mode() {
    let q = CrtShQuery::wildcard("example.com");
    let url = build_crtsh_query_url(&q);
    assert_eq!(url, "https://crt.sh/?q=*.example.com&output=json");
}

#[test]
fn build_url_organization_mode() {
    let q = CrtShQuery::organization("Acme Corp");
    let url = build_crtsh_query_url(&q);
    assert_eq!(url, "https://crt.sh/?q=O=Acme Corp&output=json");
}

#[test]
fn build_url_exclude_expired() {
    let q = CrtShQuery::domain("example.com").with_exclude_expired(true);
    let url = build_crtsh_query_url(&q);
    assert!(url.contains("&exclude=expired"));
}

#[test]
fn build_url_domain_lowercased() {
    let q = CrtShQuery::domain("Example.COM");
    assert_eq!(q.search_term, "example.com");
}

// ---------------------------------------------------------------------------
// JSON response parsing — valid
// ---------------------------------------------------------------------------

#[test]
fn parse_basic_response_extracts_certs() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].subject_cn, "www.example.com");
    assert_eq!(certs[1].subject_cn, "api.example.com");
}

#[test]
fn parse_basic_response_extracts_issuer() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    assert_eq!(certs[0].issuer.organization, "Let's Encrypt");
    assert_eq!(certs[0].issuer.common_name, "R3");
    assert_eq!(certs[0].issuer.country, "US");
}

#[test]
fn parse_basic_response_extracts_sans() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    assert!(certs[0].sans.contains(&"www.example.com".to_string()));
    assert!(certs[0].sans.contains(&"example.com".to_string()));
}

#[test]
fn parse_basic_response_serials() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    assert_eq!(certs[0].serial, "serial-aaa-111");
    assert_eq!(certs[1].serial, "serial-bbb-222");
}

#[test]
fn parse_basic_response_fingerprints() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    assert_eq!(certs[0].fingerprint, "crtsh:10001");
    assert_eq!(certs[1].fingerprint, "crtsh:10002");
}

#[test]
fn parse_wildcard_response_detects_wildcard() {
    let certs = parse_crtsh_response(fixture_crtsh_json_wildcard()).unwrap();
    assert_eq!(certs.len(), 1);
    assert!(certs[0].is_wildcard);
    assert_eq!(certs[0].subject_cn, "*.example.com");
}

// ---------------------------------------------------------------------------
// JSON response parsing — empty and malformed
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_array_returns_empty_vec() {
    let certs = parse_crtsh_response("[]").unwrap();
    assert!(certs.is_empty());
}

#[test]
fn parse_malformed_json_returns_error() {
    let result = parse_crtsh_response("{{{not valid");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("JSON parse error"));
}

#[test]
fn parse_sparse_fields_uses_defaults() {
    let json = r#"[{"id": 99, "common_name": "sparse.test.com"}]"#;
    let certs = parse_crtsh_response(json).unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].subject_cn, "sparse.test.com");
    assert!(certs[0].serial.is_empty());
    assert_eq!(certs[0].issuer.organization, "");
}

// ---------------------------------------------------------------------------
// extract_sans_from_cert
// ---------------------------------------------------------------------------

#[test]
fn extract_sans_splits_newlines() {
    let sans = extract_sans_from_cert("a.com\nb.com\nc.com");
    assert_eq!(sans.len(), 3);
    assert!(sans.contains(&"a.com".to_string()));
}

#[test]
fn extract_sans_deduplicates() {
    let sans = extract_sans_from_cert("a.com\nb.com\na.com");
    assert_eq!(sans.len(), 2);
}

#[test]
fn extract_sans_trims_whitespace() {
    let sans = extract_sans_from_cert("  a.com  \n  b.com  \n\n");
    assert_eq!(sans.len(), 2);
    assert!(sans.contains(&"a.com".to_string()));
}

#[test]
fn extract_sans_empty_string() {
    let sans = extract_sans_from_cert("");
    assert!(sans.is_empty());
}

// ---------------------------------------------------------------------------
// Certificate analysis
// ---------------------------------------------------------------------------

#[test]
fn analyze_detects_expired_cert() {
    let cert = make_cert(
        "exp-1",
        "old.example.com",
        "GoDaddy",
        "GoDaddy Secure",
        "2022-01-01",
        "2023-01-01",
        vec!["old.example.com"],
        false,
    );
    let analysis = analyze_certificate(&cert, "2024-06-15", "example.com");
    assert!(analysis.risks.contains(&CertRisk::Expired));
    assert!(analysis.risk_score > 0.0);
}

#[test]
fn analyze_detects_self_signed() {
    let cert = make_cert(
        "self-1",
        "myserver.local",
        "",
        "myserver.local",
        "2024-01-01",
        "2034-01-01",
        vec!["myserver.local"],
        false,
    );
    let analysis = analyze_certificate(&cert, "2024-06-15", "example.com");
    assert!(analysis.risks.contains(&CertRisk::SelfSigned));
}

#[test]
fn analyze_detects_unknown_ca() {
    let cert = make_cert(
        "unk-1",
        "site.example.com",
        "Shady Certs LLC",
        "ShadyCA Root",
        "2024-01-01",
        "2025-01-01",
        vec!["site.example.com"],
        false,
    );
    let analysis = analyze_certificate(&cert, "2024-06-15", "example.com");
    assert!(analysis.risks.contains(&CertRisk::UnknownCA));
}

#[test]
fn analyze_known_ca_no_unknown_risk() {
    let cert = make_cert(
        "ok-1",
        "site.example.com",
        "DigiCert Inc",
        "DigiCert SHA2",
        "2024-01-01",
        "2025-01-01",
        vec!["site.example.com"],
        false,
    );
    let analysis = analyze_certificate(&cert, "2024-06-15", "example.com");
    assert!(!analysis.risks.contains(&CertRisk::UnknownCA));
}

#[test]
fn analyze_detects_wildcard() {
    let cert = make_cert(
        "wild-1",
        "*.example.com",
        "Let's Encrypt",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["*.example.com", "example.com"],
        true,
    );
    let analysis = analyze_certificate(&cert, "2024-06-15", "example.com");
    assert!(analysis.risks.contains(&CertRisk::WildcardAbuse));
    assert!(analysis
        .alerts
        .iter()
        .any(|a| a.alert_type == CertAlertType::WildcardCert));
}

#[test]
fn analyze_detects_too_many_sans() {
    let many_sans: Vec<String> = (0..120).map(|i| format!("sub{i}.example.com")).collect();
    let cert = CertInfo {
        serial: "many-1".to_string(),
        fingerprint: "fp:many-1".to_string(),
        subject_cn: "example.com".to_string(),
        sans: many_sans,
        issuer: CertIssuer {
            organization: "Let's Encrypt".to_string(),
            common_name: "R3".to_string(),
            country: "US".to_string(),
        },
        not_before: "2024-01-01".to_string(),
        not_after: "2025-01-01".to_string(),
        is_wildcard: false,
        crtsh_id: 0,
    };
    let analysis = analyze_certificate(&cert, "2024-06-15", "example.com");
    assert!(analysis.risks.contains(&CertRisk::TooManySans));
}

#[test]
fn analyze_detects_short_lived_cert() {
    let cert = make_cert(
        "short-1",
        "temp.example.com",
        "Let's Encrypt",
        "R3",
        "2024-06-01",
        "2024-06-05",
        vec!["temp.example.com"],
        false,
    );
    let analysis = analyze_certificate(&cert, "2024-06-02", "example.com");
    assert!(analysis.risks.contains(&CertRisk::ShortLived));
}

// ---------------------------------------------------------------------------
// Phishing cert detection
// ---------------------------------------------------------------------------

#[test]
fn detect_phishing_typosquat() {
    let cert = make_cert(
        "phish-1",
        "examp1e.com",
        "Shady CA",
        "ShadyRoot",
        "2024-01-01",
        "2025-01-01",
        vec!["examp1e.com"],
        false,
    );
    let result = detect_phishing_cert(&cert, "example.com");
    assert!(result.is_phishing);
    assert!(result.max_similarity >= 0.75);
    assert!(!result.suspicious_domains.is_empty());
}

#[test]
fn detect_phishing_exact_match_not_flagged() {
    let cert = make_cert(
        "legit-1",
        "example.com",
        "DigiCert",
        "DigiCert SHA2",
        "2024-01-01",
        "2025-01-01",
        vec!["example.com", "www.example.com"],
        false,
    );
    let result = detect_phishing_cert(&cert, "example.com");
    assert!(!result.is_phishing);
}

#[test]
fn detect_phishing_completely_different_domain() {
    let cert = make_cert(
        "other-1",
        "totallyunrelated.org",
        "Let's Encrypt",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["totallyunrelated.org"],
        false,
    );
    let result = detect_phishing_cert(&cert, "example.com");
    assert!(!result.is_phishing);
    assert!(result.max_similarity < 0.75);
}

#[test]
fn detect_phishing_homoglyph_attack() {
    let cert = make_cert(
        "homo-1",
        "exarnple.com",
        "Shady CA",
        "ShadyRoot",
        "2024-01-01",
        "2025-01-01",
        vec!["exarnple.com"],
        false,
    );
    let result = detect_phishing_cert(&cert, "example.com");
    assert!(result.max_similarity > 0.7);
}

#[test]
fn detect_phishing_wildcard_stripped() {
    let cert = make_cert(
        "wphish-1",
        "*.examp1e.com",
        "Shady CA",
        "ShadyRoot",
        "2024-01-01",
        "2025-01-01",
        vec!["*.examp1e.com"],
        true,
    );
    let result = detect_phishing_cert(&cert, "example.com");
    assert!(result.is_phishing);
}

// ---------------------------------------------------------------------------
// Domain similarity calculation
// ---------------------------------------------------------------------------

#[test]
fn similarity_identical_domains() {
    let sim = calculate_domain_similarity("example.com", "example.com");
    assert!((sim - 1.0).abs() < f64::EPSILON);
}

#[test]
fn similarity_empty_strings() {
    let sim = calculate_domain_similarity("", "");
    assert!((sim - 0.0).abs() < f64::EPSILON);
}

#[test]
fn similarity_one_empty() {
    let sim = calculate_domain_similarity("example.com", "");
    assert!((sim - 0.0).abs() < f64::EPSILON);
}

#[test]
fn similarity_close_domains() {
    let sim = calculate_domain_similarity("examp1e.com", "example.com");
    assert!(sim > 0.7, "expected high similarity, got {sim}");
}

#[test]
fn similarity_distant_domains() {
    let sim = calculate_domain_similarity("zzzzzzz.org", "example.com");
    assert!(sim < 0.5, "expected low similarity, got {sim}");
}

#[test]
fn similarity_symmetric() {
    let sim_ab = calculate_domain_similarity("example.com", "examp1e.com");
    let sim_ba = calculate_domain_similarity("examp1e.com", "example.com");
    assert!((sim_ab - sim_ba).abs() < 0.01);
}

// ---------------------------------------------------------------------------
// Cert delta computation
// ---------------------------------------------------------------------------

#[test]
fn delta_first_scan_all_new() {
    let mut state = CertMonitorState::new("example.com");
    let certs = vec![
        make_cert(
            "s1",
            "a.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["a.example.com"],
            false,
        ),
        make_cert(
            "s2",
            "b.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["b.example.com"],
            false,
        ),
    ];

    let delta = state.ingest(&certs);
    assert_eq!(delta.new_count(), 2);
    assert_eq!(delta.removed_count(), 0);
    assert_eq!(delta.unchanged_count, 0);
    assert!(delta.has_changes());
    assert_eq!(state.known_cert_count(), 2);
    assert_eq!(state.scan_count(), 1);
}

#[test]
fn delta_second_scan_no_changes() {
    let mut state = CertMonitorState::new("example.com");
    let certs = vec![make_cert(
        "s1",
        "a.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["a.example.com"],
        false,
    )];

    state.ingest(&certs);
    let delta = state.ingest(&certs);
    assert_eq!(delta.new_count(), 0);
    assert_eq!(delta.removed_count(), 0);
    assert_eq!(delta.unchanged_count, 1);
    assert!(!delta.has_changes());
    assert_eq!(state.scan_count(), 2);
}

#[test]
fn delta_detects_new_and_removed() {
    let mut state = CertMonitorState::new("example.com");

    let scan1 = vec![
        make_cert(
            "s1",
            "a.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["a.example.com"],
            false,
        ),
        make_cert(
            "s2",
            "b.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["b.example.com"],
            false,
        ),
    ];
    state.ingest(&scan1);

    let scan2 = vec![
        make_cert(
            "s2",
            "b.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["b.example.com"],
            false,
        ),
        make_cert(
            "s3",
            "c.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["c.example.com"],
            false,
        ),
    ];
    let delta = state.ingest(&scan2);

    assert_eq!(delta.new_count(), 1);
    assert_eq!(delta.new_certs[0].serial, "s3");
    assert_eq!(delta.removed_count(), 1);
    assert_eq!(delta.removed_serials[0], "s1");
    assert_eq!(delta.unchanged_count, 1);
    assert!(delta.has_changes());
    assert_eq!(state.known_cert_count(), 2);
    assert!(state.contains_serial("s2"));
    assert!(state.contains_serial("s3"));
    assert!(!state.contains_serial("s1"));
}

#[test]
fn delta_empty_scan_removes_all() {
    let mut state = CertMonitorState::new("example.com");
    let scan1 = vec![make_cert(
        "s1",
        "a.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["a.example.com"],
        false,
    )];
    state.ingest(&scan1);

    let delta = state.ingest(&[]);
    assert_eq!(delta.new_count(), 0);
    assert_eq!(delta.removed_count(), 1);
    assert_eq!(state.known_cert_count(), 0);
}

// ---------------------------------------------------------------------------
// Risk assessment
// ---------------------------------------------------------------------------

#[test]
fn assess_risk_expired_cert() {
    let cert = make_cert(
        "r1",
        "old.example.com",
        "GoDaddy",
        "GoDaddy Secure",
        "2022-01-01",
        "2023-01-01",
        vec!["old.example.com"],
        false,
    );
    let risks = assess_cert_risk(&cert, "2024-06-15");
    assert!(risks.contains(&CertRisk::Expired));
}

#[test]
fn assess_risk_valid_cert_minimal_risks() {
    let cert = make_cert(
        "r2",
        "good.example.com",
        "DigiCert Inc",
        "DigiCert SHA2",
        "2024-01-01",
        "2025-06-01",
        vec!["good.example.com"],
        false,
    );
    let risks = assess_cert_risk(&cert, "2024-06-15");
    assert!(!risks.contains(&CertRisk::Expired));
    assert!(!risks.contains(&CertRisk::SelfSigned));
    assert!(!risks.contains(&CertRisk::UnknownCA));
}

#[test]
fn assess_risk_self_signed() {
    let cert = make_cert(
        "r3",
        "mybox.local",
        "",
        "mybox.local",
        "2024-01-01",
        "2034-01-01",
        vec!["mybox.local"],
        false,
    );
    let risks = assess_cert_risk(&cert, "2024-06-15");
    assert!(risks.contains(&CertRisk::SelfSigned));
    assert!(risks.contains(&CertRisk::UnknownCA));
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

#[test]
fn report_basic_stats() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    let report = build_ct_monitor_report("example.com", &certs, "2024-03-15", None);

    assert_eq!(report.domain, "example.com");
    assert_eq!(report.total_certs, 2);
    assert_eq!(report.wildcard_count, 0);
    assert_eq!(report.risk_scores.len(), 2);
}

#[test]
fn report_with_expired_certs() {
    let certs = parse_crtsh_response(fixture_crtsh_json_expired()).unwrap();
    let report = build_ct_monitor_report("example.com", &certs, "2024-06-15", None);

    assert_eq!(report.expired_count, 1);
    assert!(report
        .alerts
        .iter()
        .any(|a| a.alert_type == CertAlertType::SuspiciousCert));
}

#[test]
fn report_with_wildcard_certs() {
    let certs = parse_crtsh_response(fixture_crtsh_json_wildcard()).unwrap();
    let report = build_ct_monitor_report("example.com", &certs, "2024-06-15", None);

    assert_eq!(report.wildcard_count, 1);
    assert!(report
        .alerts
        .iter()
        .any(|a| a.alert_type == CertAlertType::WildcardCert));
}

#[test]
fn report_issuer_distribution() {
    let certs = parse_crtsh_response(fixture_crtsh_json_basic()).unwrap();
    let report = build_ct_monitor_report("example.com", &certs, "2024-03-15", None);

    assert!(report.issuer_distribution.contains_key("Let's Encrypt"));
    assert!(report.issuer_distribution.contains_key("DigiCert Inc"));
}

#[test]
fn report_with_delta_generates_new_cert_alerts() {
    let certs = vec![make_cert(
        "ns1",
        "new.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["new.example.com"],
        false,
    )];
    let delta = CertDelta {
        new_certs: certs.clone(),
        removed_serials: vec!["old-serial-gone".to_string()],
        unchanged_count: 0,
    };

    let report = build_ct_monitor_report("example.com", &certs, "2024-06-15", Some(delta));
    assert!(report
        .alerts
        .iter()
        .any(|a| a.alert_type == CertAlertType::NewCert));
    assert!(report
        .alerts
        .iter()
        .any(|a| a.alert_type == CertAlertType::RevokedCert));
}

#[test]
fn report_max_and_average_risk_scores() {
    let certs = vec![
        make_cert(
            "sc1",
            "a.example.com",
            "DigiCert",
            "DigiCert SHA2",
            "2024-01-01",
            "2025-01-01",
            vec!["a.example.com"],
            false,
        ),
        make_cert(
            "sc2",
            "old.example.com",
            "GoDaddy",
            "GoDaddy Secure",
            "2022-01-01",
            "2023-01-01",
            vec!["old.example.com"],
            false,
        ),
    ];
    let report = build_ct_monitor_report("example.com", &certs, "2024-06-15", None);

    assert!(report.max_risk_score() > 0.0);
    assert!(report.average_risk_score() > 0.0);
    assert!(report.max_risk_score() >= report.average_risk_score());
}

#[test]
fn report_empty_certs() {
    let report = build_ct_monitor_report("example.com", &[], "2024-06-15", None);
    assert_eq!(report.total_certs, 0);
    assert_eq!(report.wildcard_count, 0);
    assert_eq!(report.expired_count, 0);
    assert!(report.alerts.is_empty());
    assert!((report.max_risk_score() - 0.0).abs() < f64::EPSILON);
    assert!((report.average_risk_score() - 0.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

#[test]
fn cert_alert_type_display() {
    assert_eq!(format!("{}", CertAlertType::NewCert), "new-cert");
    assert_eq!(format!("{}", CertAlertType::RevokedCert), "revoked-cert");
    assert_eq!(format!("{}", CertAlertType::ExpiringSoon), "expiring-soon");
    assert_eq!(
        format!("{}", CertAlertType::SuspiciousCert),
        "suspicious-cert"
    );
    assert_eq!(format!("{}", CertAlertType::WildcardCert), "wildcard-cert");
    assert_eq!(format!("{}", CertAlertType::PhishingCert), "phishing-cert");
}

#[test]
fn cert_risk_display() {
    assert_eq!(format!("{}", CertRisk::SelfSigned), "self-signed");
    assert_eq!(format!("{}", CertRisk::Expired), "expired");
    assert_eq!(format!("{}", CertRisk::WeakKey), "weak-key");
    assert_eq!(format!("{}", CertRisk::UnknownCA), "unknown-ca");
    assert_eq!(format!("{}", CertRisk::TooManySans), "too-many-sans");
    assert_eq!(format!("{}", CertRisk::ShortLived), "short-lived");
    assert_eq!(format!("{}", CertRisk::WildcardAbuse), "wildcard-abuse");
    assert_eq!(format!("{}", CertRisk::PhishingDomain), "phishing-domain");
}

#[test]
fn alert_severity_display() {
    assert_eq!(format!("{}", AlertSeverity::Info), "INFO");
    assert_eq!(format!("{}", AlertSeverity::Low), "LOW");
    assert_eq!(format!("{}", AlertSeverity::Medium), "MEDIUM");
    assert_eq!(format!("{}", AlertSeverity::High), "HIGH");
    assert_eq!(format!("{}", AlertSeverity::Critical), "CRITICAL");
}

#[test]
fn cert_issuer_display_with_org() {
    let issuer = CertIssuer {
        organization: "DigiCert".to_string(),
        common_name: "DigiCert SHA2".to_string(),
        country: "US".to_string(),
    };
    let display = format!("{issuer}");
    assert!(display.contains("DigiCert SHA2"));
    assert!(display.contains("DigiCert"));
}

#[test]
fn cert_issuer_display_without_org() {
    let issuer = CertIssuer {
        organization: String::new(),
        common_name: "SelfSignedRoot".to_string(),
        country: String::new(),
    };
    let display = format!("{issuer}");
    assert_eq!(display, "SelfSignedRoot");
}

#[test]
fn cert_info_display() {
    let cert = make_cert(
        "display-serial-12345678",
        "www.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["www.example.com", "example.com"],
        false,
    );
    let display = format!("{cert}");
    assert!(display.contains("www.example.com"));
    assert!(display.contains("display-seri..."));
    assert!(display.contains("SANs=2"));
}

#[test]
fn cert_monitor_state_display() {
    let state = CertMonitorState::new("example.com");
    let display = format!("{state}");
    assert!(display.contains("example.com"));
    assert!(display.contains("known=0"));
    assert!(display.contains("scans=0"));
}

#[test]
fn cert_delta_display() {
    let delta = CertDelta {
        new_certs: vec![make_cert(
            "d1",
            "new.example.com",
            "LE",
            "R3",
            "2024-01-01",
            "2025-01-01",
            vec!["new.example.com"],
            false,
        )],
        removed_serials: vec!["old-serial".to_string()],
        unchanged_count: 5,
    };
    let display = format!("{delta}");
    assert!(display.contains("+1 new"));
    assert!(display.contains("-1 removed"));
    assert!(display.contains("5 unchanged"));
}

#[test]
fn ct_monitor_report_display() {
    let report = build_ct_monitor_report("example.com", &[], "2024-06-15", None);
    let display = format!("{report}");
    assert!(display.contains("CT Report[example.com]"));
    assert!(display.contains("0 certs"));
}

#[test]
fn crtsh_query_display() {
    let q = CrtShQuery::domain("example.com");
    let display = format!("{q}");
    assert!(display.contains("domain"));
    assert!(display.contains("example.com"));
}

#[test]
fn search_mode_display() {
    assert_eq!(format!("{}", CrtShSearchMode::Domain), "domain");
    assert_eq!(format!("{}", CrtShSearchMode::Wildcard), "wildcard");
    assert_eq!(format!("{}", CrtShSearchMode::Organization), "organization");
}

// ---------------------------------------------------------------------------
// CertIssuer::is_known_ca
// ---------------------------------------------------------------------------

#[test]
fn known_ca_lets_encrypt() {
    let issuer = CertIssuer {
        organization: "Let's Encrypt".to_string(),
        common_name: "R3".to_string(),
        country: "US".to_string(),
    };
    assert!(issuer.is_known_ca());
}

#[test]
fn known_ca_unknown_issuer() {
    let issuer = CertIssuer {
        organization: "Evil Corp Certificates".to_string(),
        common_name: "EvilRoot".to_string(),
        country: "XX".to_string(),
    };
    assert!(!issuer.is_known_ca());
}

// ---------------------------------------------------------------------------
// CertInfo::all_domains
// ---------------------------------------------------------------------------

#[test]
fn all_domains_includes_cn_and_sans() {
    let cert = make_cert(
        "ad-1",
        "www.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["www.example.com", "example.com", "api.example.com"],
        false,
    );
    let domains = cert.all_domains();
    assert_eq!(domains.len(), 3);
    assert_eq!(domains[0], "www.example.com");
    assert!(domains.contains(&"api.example.com".to_string()));
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[test]
fn error_display_json() {
    let bad: Result<Vec<CrtShJsonEntry>, _> = serde_json::from_str("{bad}");
    let err = CtMonitorV2Error::JsonParse(bad.unwrap_err());
    assert!(err.to_string().starts_with("JSON parse error"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn error_display_invalid_input() {
    let err = CtMonitorV2Error::InvalidInput("bad domain".into());
    assert_eq!(err.to_string(), "Invalid input: bad domain");
    assert!(std::error::Error::source(&err).is_none());
}

// ---------------------------------------------------------------------------
// is_cert_expired
// ---------------------------------------------------------------------------

#[test]
fn cert_not_expired_before_not_after() {
    let cert = make_cert(
        "ne-1",
        "good.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["good.example.com"],
        false,
    );
    assert!(!is_cert_expired(&cert, "2024-06-15"));
}

#[test]
fn cert_expired_after_not_after() {
    let cert = make_cert(
        "ne-2",
        "expired.example.com",
        "LE",
        "R3",
        "2022-01-01",
        "2023-06-01",
        vec!["expired.example.com"],
        false,
    );
    assert!(is_cert_expired(&cert, "2024-01-01"));
}

#[test]
fn cert_not_expired_on_exact_date() {
    let cert = make_cert(
        "ne-3",
        "edge.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2024-06-15",
        vec!["edge.example.com"],
        false,
    );
    assert!(!is_cert_expired(&cert, "2024-06-15"));
}

// ---------------------------------------------------------------------------
// AlertSeverity ordering
// ---------------------------------------------------------------------------

#[test]
fn alert_severity_ordering() {
    assert!(AlertSeverity::Info < AlertSeverity::Low);
    assert!(AlertSeverity::Low < AlertSeverity::Medium);
    assert!(AlertSeverity::Medium < AlertSeverity::High);
    assert!(AlertSeverity::High < AlertSeverity::Critical);
}

// ---------------------------------------------------------------------------
// Parsing from crt.sh with many SANs
// ---------------------------------------------------------------------------

#[test]
fn parse_many_sans_cert() {
    let json = fixture_crtsh_json_many_sans();
    let certs = parse_crtsh_response(&json).unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].san_count(), 120);
}

// ---------------------------------------------------------------------------
// CertIssuer::parse_from_dn edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_dn_full() {
    let issuer = CertIssuer::parse_from_dn("C=US, O=DigiCert Inc, CN=DigiCert SHA2");
    assert_eq!(issuer.country, "US");
    assert_eq!(issuer.organization, "DigiCert Inc");
    assert_eq!(issuer.common_name, "DigiCert SHA2");
}

#[test]
fn parse_dn_empty() {
    let issuer = CertIssuer::parse_from_dn("");
    assert!(issuer.country.is_empty());
    assert!(issuer.organization.is_empty());
    assert!(issuer.common_name.is_empty());
}

#[test]
fn parse_dn_cn_only() {
    let issuer = CertIssuer::parse_from_dn("CN=SelfSigned");
    assert_eq!(issuer.common_name, "SelfSigned");
    assert!(issuer.organization.is_empty());
}

// ---------------------------------------------------------------------------
// CertAlert display
// ---------------------------------------------------------------------------

#[test]
fn cert_alert_display() {
    let cert = make_cert(
        "alert-1",
        "test.example.com",
        "LE",
        "R3",
        "2024-01-01",
        "2025-01-01",
        vec!["test.example.com"],
        false,
    );
    let alert = CertAlert {
        alert_type: CertAlertType::NewCert,
        cert,
        description: "New cert detected".to_string(),
        severity: AlertSeverity::Info,
    };
    let display = format!("{alert}");
    assert!(display.contains("[INFO]"));
    assert!(display.contains("new-cert"));
    assert!(display.contains("test.example.com"));
}

// ---------------------------------------------------------------------------
// Report critical alert count
// ---------------------------------------------------------------------------

#[test]
fn report_critical_alert_count() {
    let cert = make_cert(
        "crit-1",
        "examp1e.com",
        "Shady CA",
        "ShadyRoot",
        "2022-01-01",
        "2023-01-01",
        vec!["examp1e.com"],
        false,
    );
    let report = build_ct_monitor_report("example.com", &[cert], "2024-06-15", None);
    assert!(report.critical_alert_count() > 0 || report.alert_count() > 0);
}

// ---------------------------------------------------------------------------
// Self-signed cert parsing round-trip
// ---------------------------------------------------------------------------

#[test]
fn parse_self_signed_fixture() {
    let certs = parse_crtsh_response(fixture_crtsh_json_self_signed()).unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].subject_cn, "internal.test.local");
    assert_eq!(certs[0].issuer.common_name, "internal.test.local");
    assert!(certs[0].issuer.organization.is_empty());
}
