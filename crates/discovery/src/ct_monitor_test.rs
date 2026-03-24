use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::ct_monitor::*;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fixture_crtsh_basic() -> &'static str {
    r#"[
        {
            "id": 1001,
            "issuer_ca_id": 100,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "www.example.com",
            "name_value": "www.example.com\nexample.com",
            "serial_number": "abcdef1234567890",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
            "entry_timestamp": "2024-01-01T12:00:00"
        },
        {
            "id": 1002,
            "issuer_ca_id": 100,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "api.example.com",
            "name_value": "api.example.com\nstaging.example.com",
            "serial_number": "1234567890abcdef",
            "not_before": "2024-02-01T00:00:00",
            "not_after": "2024-05-01T00:00:00",
            "entry_timestamp": "2024-02-01T12:00:00"
        }
    ]"#
}

fn fixture_crtsh_wildcards() -> &'static str {
    r#"[
        {
            "id": 2001,
            "issuer_ca_id": 200,
            "issuer_name": "DigiCert",
            "common_name": "*.example.com",
            "name_value": "*.example.com\nexample.com\n*.api.example.com",
            "serial_number": "aaa111",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "entry_timestamp": "2024-01-01T00:00:00"
        }
    ]"#
}

fn fixture_crtsh_duplicates() -> &'static str {
    r#"[
        {
            "id": 3001,
            "issuer_ca_id": 100,
            "issuer_name": "Let's Encrypt",
            "common_name": "mail.example.com",
            "name_value": "mail.example.com\nsmtp.example.com",
            "serial_number": "bbb222",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-06-01T00:00:00",
            "entry_timestamp": "2024-01-01T00:00:00"
        },
        {
            "id": 3002,
            "issuer_ca_id": 100,
            "issuer_name": "Let's Encrypt",
            "common_name": "mail.example.com",
            "name_value": "mail.example.com\nsmtp.example.com\nimap.example.com",
            "serial_number": "ccc333",
            "not_before": "2024-03-01T00:00:00",
            "not_after": "2024-09-01T00:00:00",
            "entry_timestamp": "2024-03-01T00:00:00"
        }
    ]"#
}

fn fixture_crtsh_mixed_domains() -> &'static str {
    r#"[
        {
            "id": 4001,
            "issuer_ca_id": 300,
            "issuer_name": "Comodo",
            "common_name": "cdn.other-domain.com",
            "name_value": "cdn.other-domain.com\nwww.example.com\nstatic.example.com",
            "serial_number": "ddd444",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-12-31T00:00:00",
            "entry_timestamp": "2024-01-01T00:00:00"
        }
    ]"#
}

fn fixture_crtsh_empty() -> &'static str {
    "[]"
}

fn fixture_crtsh_large() -> String {
    let mut entries = Vec::new();
    for i in 0..150 {
        entries.push(format!(
            r#"{{
                "id": {id},
                "issuer_ca_id": 100,
                "issuer_name": "LE",
                "common_name": "sub{i}.example.com",
                "name_value": "sub{i}.example.com\nalt{i}.example.com",
                "serial_number": "seq{i:04}",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2025-01-01T00:00:00",
                "entry_timestamp": "2024-01-01T00:00:00"
            }}"#,
            id = 5000 + i,
            i = i
        ));
    }
    format!("[{}]", entries.join(","))
}

fn fixture_crtsh_malformed_names() -> &'static str {
    r#"[
        {
            "id": 6001,
            "issuer_ca_id": 100,
            "issuer_name": "LE",
            "common_name": "  *.example.com  ",
            "name_value": "  valid.example.com  \n\n  *.deep.example.com\n  \n-.example.com\nexample.com.",
            "serial_number": "fff666",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "entry_timestamp": "2024-01-01T00:00:00"
        }
    ]"#
}

fn fixture_crtsh_sparse_fields() -> &'static str {
    r#"[
        {
            "id": 7001,
            "common_name": "sparse.example.com",
            "name_value": "sparse.example.com"
        }
    ]"#
}

// ---------------------------------------------------------------------------
// CrtShClient — construction
// ---------------------------------------------------------------------------

#[test]
fn client_new_strips_wildcard_prefix() {
    let c = CrtShClient::new("*.example.com");
    assert_eq!(c.base_domain(), "example.com");
}

#[test]
fn client_new_lowercases_domain() {
    let c = CrtShClient::new("Example.COM");
    assert_eq!(c.base_domain(), "example.com");
}

#[test]
fn client_query_url_format() {
    let c = CrtShClient::new("example.com");
    assert_eq!(c.query_url(), "https://crt.sh/?q=%.example.com&output=json");
}

// ---------------------------------------------------------------------------
// parse_response — basic
// ---------------------------------------------------------------------------

#[test]
fn parse_basic_response_extracts_subdomains() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_basic()).unwrap();

    let names: Vec<&str> = subs.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"www.example.com"));
    assert!(names.contains(&"api.example.com"));
    assert!(names.contains(&"staging.example.com"));
    assert!(names.contains(&"example.com"));
}

#[test]
fn parse_basic_response_source_tags() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_basic()).unwrap();

    let www = subs.iter().find(|s| s.name == "www.example.com").unwrap();
    assert_eq!(www.source, CtSource::CommonName);

    let staging = subs
        .iter()
        .find(|s| s.name == "staging.example.com")
        .unwrap();
    assert_eq!(staging.source, CtSource::SubjectAltName);
}

#[test]
fn parse_response_sorted_alphabetically() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_basic()).unwrap();
    let names: Vec<&str> = subs.iter().map(|s| s.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

// ---------------------------------------------------------------------------
// parse_response — wildcards
// ---------------------------------------------------------------------------

#[test]
fn wildcard_cn_stripped_and_base_kept() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_wildcards()).unwrap();

    let names: Vec<&str> = subs.iter().map(|s| s.name.as_str()).collect();
    // *.example.com → example.com after stripping
    assert!(names.contains(&"example.com"));
    // *.api.example.com → api.example.com after stripping
    assert!(names.contains(&"api.example.com"));
    // No raw wildcard entries
    assert!(!names.iter().any(|n| n.contains('*')));
}

// ---------------------------------------------------------------------------
// parse_response — deduplication
// ---------------------------------------------------------------------------

#[test]
fn duplicate_entries_deduplicated() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_duplicates()).unwrap();

    let mail_count = subs.iter().filter(|s| s.name == "mail.example.com").count();
    assert_eq!(mail_count, 1, "mail.example.com should appear exactly once");

    let smtp_count = subs.iter().filter(|s| s.name == "smtp.example.com").count();
    assert_eq!(smtp_count, 1);

    // imap appears only in second cert
    assert!(subs.iter().any(|s| s.name == "imap.example.com"));
}

#[test]
fn count_unique_matches_extract_length() {
    let c = CrtShClient::new("example.com");
    let entries: Vec<CrtShEntry> = serde_json::from_str(fixture_crtsh_duplicates()).unwrap();
    let count = c.count_unique(&entries);
    let subs = c.extract_subdomains(&entries);
    assert_eq!(count, subs.len());
}

// ---------------------------------------------------------------------------
// parse_response — cross-domain filtering
// ---------------------------------------------------------------------------

#[test]
fn filters_out_other_domains() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_mixed_domains()).unwrap();

    let names: Vec<&str> = subs.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"www.example.com"));
    assert!(names.contains(&"static.example.com"));
    assert!(!names.contains(&"cdn.other-domain.com"));
}

// ---------------------------------------------------------------------------
// parse_response — empty & edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_response_returns_empty_vec() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_empty()).unwrap();
    assert!(subs.is_empty());
}

#[test]
fn invalid_json_returns_error() {
    let c = CrtShClient::new("example.com");
    let result = c.parse_response("not valid json {{{");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("JSON parse error"));
}

#[test]
fn malformed_names_handled_gracefully() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_malformed_names()).unwrap();

    let names: Vec<&str> = subs.iter().map(|s| s.name.as_str()).collect();
    // Trimmed + stripped wildcard
    assert!(names.contains(&"valid.example.com"));
    assert!(names.contains(&"example.com"));
    // deep.example.com from *.deep.example.com
    assert!(names.contains(&"deep.example.com"));
    // -.example.com should be rejected (starts with hyphen)
    assert!(!names.iter().any(|n| n.starts_with('-')));
    // No wildcard residue
    assert!(!names.iter().any(|n| n.contains('*')));
}

#[test]
fn sparse_fields_still_parse() {
    let c = CrtShClient::new("example.com");
    let subs = c.parse_response(fixture_crtsh_sparse_fields()).unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].name, "sparse.example.com");
}

// ---------------------------------------------------------------------------
// parse_response — large dataset
// ---------------------------------------------------------------------------

#[test]
fn large_response_deduplicates_correctly() {
    let c = CrtShClient::new("example.com");
    let json = fixture_crtsh_large();
    let subs = c.parse_response(&json).unwrap();

    // 150 entries × (1 CN + 1 SAN unique each) = 300 unique subdomains
    assert_eq!(subs.len(), 300);

    // Verify no duplicates
    let mut seen = std::collections::HashSet::new();
    for s in &subs {
        assert!(seen.insert(&s.name), "duplicate found: {}", s.name);
    }
}

// ---------------------------------------------------------------------------
// CtSource display
// ---------------------------------------------------------------------------

#[test]
fn ct_source_display() {
    assert_eq!(format!("{}", CtSource::CommonName), "CN");
    assert_eq!(format!("{}", CtSource::SubjectAltName), "SAN");
}

// ---------------------------------------------------------------------------
// CtMonitorError display & source
// ---------------------------------------------------------------------------

#[test]
fn error_display_json_parse() {
    let bad: Result<Vec<CrtShEntry>, _> = serde_json::from_str("{bad}");
    let err = CtMonitorError::JsonParse(bad.unwrap_err());
    let msg = err.to_string();
    assert!(msg.starts_with("JSON parse error"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn error_display_invalid_domain() {
    let err = CtMonitorError::InvalidDomain("oops".into());
    assert_eq!(err.to_string(), "Invalid domain: oops");
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn error_display_http() {
    let err = CtMonitorError::HttpError("timeout".into());
    assert_eq!(err.to_string(), "HTTP error: timeout");
    assert!(std::error::Error::source(&err).is_none());
}

// ---------------------------------------------------------------------------
// DnsResult methods
// ---------------------------------------------------------------------------

#[test]
fn dns_result_is_resolved_true_when_addresses() {
    let r = build_dns_result(
        "www.example.com",
        vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        Vec::new(),
        None,
    );
    assert!(r.is_resolved());
}

#[test]
fn dns_result_is_resolved_false_when_empty() {
    let r = build_dns_result(
        "bad.example.com",
        Vec::new(),
        Vec::new(),
        Some("NXDOMAIN".into()),
    );
    assert!(!r.is_resolved());
}

#[test]
fn dns_result_final_cname_empty_chain() {
    let r = build_dns_result("a.example.com", Vec::new(), Vec::new(), None);
    assert!(r.final_cname().is_none());
}

#[test]
fn dns_result_final_cname_returns_last() {
    let r = build_dns_result(
        "app.example.com",
        Vec::new(),
        vec!["step1.cdn.com".into(), "step2.cdn.com".into()],
        None,
    );
    assert_eq!(r.final_cname(), Some("step2.cdn.com"));
}

#[test]
fn takeover_indicator_positive() {
    let r = build_dns_result(
        "old.example.com",
        Vec::new(),
        vec!["old.example.com.herokudns.com".into()],
        Some("NXDOMAIN".into()),
    );
    assert!(r.has_takeover_indicator());
}

#[test]
fn takeover_indicator_negative_resolved() {
    let r = build_dns_result(
        "ok.example.com",
        vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        vec!["ok.example.com.herokudns.com".into()],
        None,
    );
    assert!(
        !r.has_takeover_indicator(),
        "resolved hosts are not takeover candidates"
    );
}

#[test]
fn takeover_indicator_negative_no_dangling() {
    let r = build_dns_result(
        "gone.example.com",
        Vec::new(),
        vec!["internal.corp.example.com".into()],
        Some("NXDOMAIN".into()),
    );
    assert!(
        !r.has_takeover_indicator(),
        "non-cloud CNAMEs are not takeover candidates"
    );
}

#[test]
fn takeover_indicator_various_providers() {
    let providers = [
        "old.s3.amazonaws.com",
        "site.azurewebsites.net",
        "cdn.cloudfront.net",
        "app.herokuapp.com",
        "user.github.io",
        "help.zendesk.com",
        "store.shopify.com",
        "edge.fastly.net",
        "blog.ghost.io",
        "site.surge.sh",
    ];

    for provider in providers {
        let r = build_dns_result(
            "test.example.com",
            Vec::new(),
            vec![provider.to_string()],
            Some("NXDOMAIN".into()),
        );
        assert!(
            r.has_takeover_indicator(),
            "should detect takeover for {provider}"
        );
    }
}

// ---------------------------------------------------------------------------
// BulkDnsResolver construction
// ---------------------------------------------------------------------------

#[test]
fn resolver_default_concurrency() {
    let r = BulkDnsResolver::default();
    assert_eq!(r.max_concurrency(), 50);
    assert_eq!(r.timeout(), Duration::from_secs(5));
}

#[test]
fn resolver_custom_concurrency() {
    let r = BulkDnsResolver::new(10);
    assert_eq!(r.max_concurrency(), 10);
}

#[test]
fn resolver_zero_concurrency_clamped_to_one() {
    let r = BulkDnsResolver::new(0);
    assert_eq!(r.max_concurrency(), 1);
}

#[test]
fn resolver_builder_methods() {
    let r = BulkDnsResolver::new(20)
        .with_timeout(Duration::from_secs(10))
        .with_max_cname_depth(5);
    assert_eq!(r.timeout(), Duration::from_secs(10));
    assert_eq!(r.max_concurrency(), 20);
}

// ---------------------------------------------------------------------------
// BulkDnsResolver — group_by_cname
// ---------------------------------------------------------------------------

#[test]
fn group_by_cname_clusters_correctly() {
    let results = vec![
        build_dns_result(
            "a.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            vec!["cdn.cloudfront.net".into()],
            None,
        ),
        build_dns_result(
            "b.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
            vec!["cdn.cloudfront.net".into()],
            None,
        ),
        build_dns_result(
            "c.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))],
            vec!["lb.heroku.com".into()],
            None,
        ),
        build_dns_result(
            "d.example.com",
            Vec::new(),
            Vec::new(),
            Some("NXDOMAIN".into()),
        ),
    ];

    let groups = BulkDnsResolver::group_by_cname(&results);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups["cdn.cloudfront.net"].len(), 2);
    assert_eq!(groups["lb.heroku.com"].len(), 1);
}

// ---------------------------------------------------------------------------
// BulkDnsResolver — find_takeover_candidates
// ---------------------------------------------------------------------------

#[test]
fn find_takeover_candidates_filters() {
    let results = vec![
        build_dns_result(
            "alive.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            vec!["alive.herokuapp.com".into()],
            None,
        ),
        build_dns_result(
            "dead.example.com",
            Vec::new(),
            vec!["dead.herokuapp.com".into()],
            Some("NXDOMAIN".into()),
        ),
        build_dns_result(
            "internal.example.com",
            Vec::new(),
            vec!["internal.corp.net".into()],
            Some("NXDOMAIN".into()),
        ),
    ];

    let candidates = BulkDnsResolver::find_takeover_candidates(&results);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].hostname, "dead.example.com");
}

// ---------------------------------------------------------------------------
// BulkDnsResolver — resolve_batch (integration-lite, uses real DNS)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_batch_empty_input() {
    let resolver = BulkDnsResolver::new(4);
    let results = resolver.resolve_batch(&[]).await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn resolve_batch_localhost() {
    let resolver = BulkDnsResolver::new(4).with_timeout(Duration::from_secs(3));
    let results = resolver.resolve_batch(&["localhost".to_string()]).await;
    assert_eq!(results.len(), 1);
    assert!(results[0].is_resolved(), "localhost should resolve");
    assert!(
        results[0].addresses.iter().any(|a| {
            *a == IpAddr::V4(Ipv4Addr::LOCALHOST) || *a == IpAddr::V6(Ipv6Addr::LOCALHOST)
        }),
        "should contain 127.0.0.1 or ::1"
    );
}

#[tokio::test]
async fn resolve_batch_invalid_host() {
    let resolver = BulkDnsResolver::new(4).with_timeout(Duration::from_secs(3));
    let results = resolver
        .resolve_batch(&["this-domain-definitely-does-not-exist-xyz123.invalid".to_string()])
        .await;
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_resolved());
    assert!(results[0].error.is_some());
}

// ---------------------------------------------------------------------------
// DnsResult — IPv6 support
// ---------------------------------------------------------------------------

#[test]
fn dns_result_ipv6_counts_as_resolved() {
    let r = build_dns_result(
        "v6.example.com",
        vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))],
        Vec::new(),
        None,
    );
    assert!(r.is_resolved());
}

// ---------------------------------------------------------------------------
// is_valid_subdomain edge cases (tested indirectly through CrtShClient)
// ---------------------------------------------------------------------------

#[test]
fn rejects_completely_unrelated_domain() {
    let c = CrtShClient::new("example.com");
    let json = r#"[{
        "id": 9001,
        "issuer_ca_id": 1,
        "issuer_name": "X",
        "common_name": "evil.attacker.com",
        "name_value": "evil.attacker.com",
        "serial_number": "xxx",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00",
        "entry_timestamp": "2024-01-01T00:00:00"
    }]"#;
    let subs = c.parse_response(json).unwrap();
    assert!(subs.is_empty());
}

#[test]
fn rejects_suffix_collision() {
    // notexample.com should NOT pass as a subdomain of example.com
    let c = CrtShClient::new("example.com");
    let json = r#"[{
        "id": 9002,
        "issuer_ca_id": 1,
        "issuer_name": "X",
        "common_name": "notexample.com",
        "name_value": "notexample.com",
        "serial_number": "yyy",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00",
        "entry_timestamp": "2024-01-01T00:00:00"
    }]"#;
    let subs = c.parse_response(json).unwrap();
    assert!(subs.is_empty(), "notexample.com must not match example.com");
}

#[test]
fn accepts_exact_base_domain() {
    let c = CrtShClient::new("example.com");
    let json = r#"[{
        "id": 9003,
        "issuer_ca_id": 1,
        "issuer_name": "X",
        "common_name": "example.com",
        "name_value": "example.com",
        "serial_number": "zzz",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00",
        "entry_timestamp": "2024-01-01T00:00:00"
    }]"#;
    let subs = c.parse_response(json).unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].name, "example.com");
}

#[test]
fn deeply_nested_subdomain_accepted() {
    let c = CrtShClient::new("example.com");
    let json = r#"[{
        "id": 9004,
        "issuer_ca_id": 1,
        "issuer_name": "X",
        "common_name": "a.b.c.d.example.com",
        "name_value": "a.b.c.d.example.com",
        "serial_number": "deep",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00",
        "entry_timestamp": "2024-01-01T00:00:00"
    }]"#;
    let subs = c.parse_response(json).unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].name, "a.b.c.d.example.com");
}
