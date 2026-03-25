use crate::subdomain_enum::*;

// ===== crt.sh parser =====

#[test]
fn crtsh_parses_name_value_field() {
    let json = r#"[
        {"name_value": "api.example.com\nwww.example.com", "common_name": "example.com"},
        {"name_value": "*.staging.example.com", "common_name": "staging.example.com"}
    ]"#;
    let results = parse_crtsh_response(json, "example.com");
    assert!(results.contains(&"api.example.com".to_string()));
    assert!(results.contains(&"www.example.com".to_string()));
    assert!(results.contains(&"staging.example.com".to_string()));
}

#[test]
fn crtsh_strips_wildcard_prefix() {
    let json = r#"[{"name_value": "*.cdn.example.com", "common_name": "cdn.example.com"}]"#;
    let results = parse_crtsh_response(json, "example.com");
    assert!(results.contains(&"cdn.example.com".to_string()));
}

#[test]
fn crtsh_handles_invalid_json() {
    let results = parse_crtsh_response("not json", "example.com");
    assert!(results.is_empty());
}

#[test]
fn crtsh_ignores_unrelated_domains() {
    let json = r#"[{"name_value": "evil.attacker.com", "common_name": "attacker.com"}]"#;
    let results = parse_crtsh_response(json, "example.com");
    assert!(results.is_empty());
}

// ===== SecurityTrails parser =====

#[test]
fn securitytrails_builds_full_subdomains() {
    let json = r#"{"subdomains": ["www", "api", "mail", "staging"], "endpoint": "/v1/domain/example.com/subdomains"}"#;
    let results = parse_securitytrails_response(json, "example.com");
    assert_eq!(results.len(), 4);
    assert!(results.contains(&"www.example.com".to_string()));
    assert!(results.contains(&"api.example.com".to_string()));
    assert!(results.contains(&"mail.example.com".to_string()));
    assert!(results.contains(&"staging.example.com".to_string()));
}

#[test]
fn securitytrails_handles_empty_array() {
    let json = r#"{"subdomains": [], "endpoint": "/v1/domain/example.com/subdomains"}"#;
    let results = parse_securitytrails_response(json, "example.com");
    assert!(results.is_empty());
}

// ===== DNSDumpster parser =====

#[test]
fn dnsdumpster_extracts_from_html() {
    let html = r#"
        <table>
            <tr><td class="col-md-4">api.example.com<br>192.168.1.1</td></tr>
            <tr><td class="col-md-4">staging.example.com<br>10.0.0.1</td></tr>
            <tr><td class="col-md-4">unrelated.other.com<br>8.8.8.8</td></tr>
        </table>
    "#;
    let results = parse_dnsdumpster_response(html, "example.com");
    assert!(results.contains(&"api.example.com".to_string()));
    assert!(results.contains(&"staging.example.com".to_string()));
    assert!(!results.iter().any(|s| s.contains("other.com")));
}

#[test]
fn dnsdumpster_handles_deep_subdomains() {
    let html = "<td>deep.sub.level.example.com</td>";
    let results = parse_dnsdumpster_response(html, "example.com");
    assert!(results.contains(&"deep.sub.level.example.com".to_string()));
}

// ===== VirusTotal parser =====

#[test]
fn virustotal_extracts_from_data_array() {
    let json = r#"{
        "data": [
            {"id": "api.example.com", "type": "domain"},
            {"id": "cdn.example.com", "type": "domain"},
            {"id": "unrelated.evil.com", "type": "domain"}
        ]
    }"#;
    let results = parse_virustotal_response(json, "example.com");
    assert_eq!(results.len(), 2);
    assert!(results.contains(&"api.example.com".to_string()));
    assert!(results.contains(&"cdn.example.com".to_string()));
}

#[test]
fn virustotal_handles_missing_data_key() {
    let json = r#"{"error": "not found"}"#;
    let results = parse_virustotal_response(json, "example.com");
    assert!(results.is_empty());
}

// ===== Wayback Machine parser =====

#[test]
fn wayback_extracts_hosts_from_cdx() {
    let cdx = "com,example)/about 20200101 https://about.example.com/page text/html 200\n\
                com,example)/api 20200201 https://api.example.com/v1 application/json 200\n\
                com,evil)/hack 20200301 https://evil.com/attack text/html 200";
    let results = parse_wayback_response(cdx, "example.com");
    assert!(results.contains(&"about.example.com".to_string()));
    assert!(results.contains(&"api.example.com".to_string()));
    assert!(!results.iter().any(|s| s.contains("evil.com")));
}

#[test]
fn wayback_handles_plain_url_list() {
    let urls = "https://blog.example.com/post/1\nhttps://shop.example.com/item/42\n";
    let results = parse_wayback_response(urls, "example.com");
    assert!(results.contains(&"blog.example.com".to_string()));
    assert!(results.contains(&"shop.example.com".to_string()));
}

#[test]
fn wayback_handles_empty_input() {
    let results = parse_wayback_response("", "example.com");
    assert!(results.is_empty());
}

// ===== DNS Zone Transfer parser =====

#[test]
fn zone_transfer_parses_axfr_records() {
    let axfr = "example.com.         3600 IN SOA ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 3600\n\
                ns1.example.com.     3600 IN A   1.2.3.4\n\
                mail.example.com.    3600 IN MX  10 mail.example.com.\n\
                internal.example.com. 3600 IN A  10.0.0.5\n\
                ; comment line\n";
    let results = parse_zone_transfer_output(axfr, "example.com");
    assert!(results.contains(&"ns1.example.com".to_string()));
    assert!(results.contains(&"mail.example.com".to_string()));
    assert!(results.contains(&"internal.example.com".to_string()));
}

#[test]
fn zone_transfer_ignores_non_matching_records() {
    let axfr = "other.net. 3600 IN A 8.8.8.8\n";
    let results = parse_zone_transfer_output(axfr, "example.com");
    assert!(results.is_empty());
}

// ===== DNS Record Extraction parser =====

#[test]
fn dns_records_extracts_from_txt_mx_ns() {
    let dns = "example.com. IN TXT \"v=spf1 include:mail.example.com include:spf.example.com ~all\"\n\
               example.com. IN MX 10 mx1.example.com.\n\
               example.com. IN NS ns1.example.com.\n\
               example.com. IN NS ns2.example.com.";
    let results = parse_dns_record_output(dns, "example.com");
    assert!(results.contains(&"mail.example.com".to_string()));
    assert!(results.contains(&"spf.example.com".to_string()));
    assert!(results.contains(&"mx1.example.com".to_string()));
    assert!(results.contains(&"ns1.example.com".to_string()));
    assert!(results.contains(&"ns2.example.com".to_string()));
}

// ===== Search Engine Dork parser =====

#[test]
fn search_dork_extracts_hosts_from_urls() {
    let dork = "https://admin.example.com/login\nhttps://portal.example.com/dashboard\nhttps://unrelated.com/page";
    let results = parse_search_dork_results(dork, "example.com");
    assert!(results.contains(&"admin.example.com".to_string()));
    assert!(results.contains(&"portal.example.com".to_string()));
    assert!(!results.iter().any(|s| s.contains("unrelated.com")));
}

#[test]
fn search_dork_skips_invalid_urls() {
    let dork = "not-a-url\nhttps://valid.example.com/path\n\n";
    let results = parse_search_dork_results(dork, "example.com");
    assert_eq!(results.len(), 1);
    assert!(results.contains(&"valid.example.com".to_string()));
}

// ===== Source Code Reference parser =====

#[test]
fn source_code_extracts_subdomains_from_js() {
    let js = r#"
        const API_URL = "https://api.example.com/v2";
        const CDN_URL = "https://cdn.example.com/assets";
        fetch("https://internal.example.com/graphql");
        // unrelated: https://other-site.com/api
    "#;
    let results = parse_source_code_references(js, "example.com");
    assert!(results.contains(&"api.example.com".to_string()));
    assert!(results.contains(&"cdn.example.com".to_string()));
    assert!(results.contains(&"internal.example.com".to_string()));
    assert!(!results.iter().any(|s| s.contains("other-site.com")));
}

#[test]
fn source_code_excludes_bare_parent_domain() {
    let html = r#"<a href="https://example.com">Home</a>"#;
    let results = parse_source_code_references(html, "example.com");
    assert!(results.is_empty());
}

// ===== Favicon Hash parser =====

#[test]
fn favicon_parses_hash_colon_hostname() {
    let output =
        "-1234567890:admin.example.com\n-1234567890:panel.example.com\n9876543210:evil.com";
    let results = parse_favicon_hash_output(output, "example.com");
    assert!(results.contains(&"admin.example.com".to_string()));
    assert!(results.contains(&"panel.example.com".to_string()));
    assert!(!results.iter().any(|s| s.contains("evil.com")));
}

#[test]
fn favicon_parses_bare_hostnames() {
    let output = "login.example.com\nwww.example.com\n";
    let results = parse_favicon_hash_output(output, "example.com");
    assert!(results.contains(&"login.example.com".to_string()));
    assert!(results.contains(&"www.example.com".to_string()));
}

// ===== Normalization =====

#[test]
fn normalize_strips_trailing_dot_and_wildcard() {
    assert_eq!(normalize_domain("*.Example.COM."), "example.com");
    assert_eq!(normalize_domain("  SUB.Example.com  "), "sub.example.com");
}

#[test]
fn is_valid_subdomain_checks_parent_relationship() {
    assert!(is_valid_subdomain("api.example.com", "example.com"));
    assert!(is_valid_subdomain("deep.sub.example.com", "example.com"));
    assert!(is_valid_subdomain("example.com", "example.com"));
    assert!(!is_valid_subdomain("notexample.com", "example.com"));
    assert!(!is_valid_subdomain("evil.com", "example.com"));
    assert!(!is_valid_subdomain("", "example.com"));
}

// ===== Enumerator integration =====

#[test]
fn enumerator_deduplicates_across_sources() {
    let mut enumerator = SubdomainEnumerator::new("example.com");

    let crtsh = r#"[{"name_value": "api.example.com", "common_name": "api.example.com"}]"#;
    let vt = r#"{"data": [{"id": "api.example.com", "type": "domain"}, {"id": "cdn.example.com", "type": "domain"}]}"#;

    enumerator.ingest_crtsh(crtsh);
    enumerator.ingest_virustotal(vt);

    assert_eq!(enumerator.count(), 2);

    let api_result = enumerator
        .results()
        .into_iter()
        .find(|s| s.subdomain == "api.example.com")
        .expect("api.example.com should exist");

    assert!(api_result.sources.contains(&SubdomainSource::CrtSh));
    assert!(api_result.sources.contains(&SubdomainSource::VirusTotal));
    assert_eq!(api_result.sources.len(), 2);
}

#[test]
fn enumerator_confidence_increases_with_sources() {
    let mut enumerator = SubdomainEnumerator::new("example.com");

    let subs = vec!["api.example.com".to_string()];
    enumerator.ingest(&subs, SubdomainSource::CrtSh);
    let c1 = enumerator.results()[0].confidence;

    enumerator.ingest(&subs, SubdomainSource::VirusTotal);
    let c2 = enumerator.results()[0].confidence;

    enumerator.ingest(&subs, SubdomainSource::DnsDumpster);
    let c3 = enumerator.results()[0].confidence;

    assert!(
        c2 > c1,
        "two sources should have higher confidence than one"
    );
    assert!(
        c3 > c2,
        "three sources should have higher confidence than two"
    );
}

#[test]
fn enumerator_high_confidence_filters() {
    let mut enumerator = SubdomainEnumerator::new("example.com");

    let multi = vec!["api.example.com".to_string()];
    enumerator.ingest(&multi, SubdomainSource::CrtSh);
    enumerator.ingest(&multi, SubdomainSource::VirusTotal);
    enumerator.ingest(&multi, SubdomainSource::DnsDumpster);

    let single = vec!["rare.example.com".to_string()];
    enumerator.ingest(&single, SubdomainSource::WaybackMachine);

    let high = enumerator.high_confidence(3);
    assert_eq!(high.len(), 1);
    assert_eq!(high[0].subdomain, "api.example.com");
}

#[test]
fn enumerator_results_sorted_by_confidence_desc() {
    let mut enumerator = SubdomainEnumerator::new("example.com");

    let s1 = vec!["low.example.com".to_string()];
    enumerator.ingest(&s1, SubdomainSource::CrtSh);

    let s2 = vec!["high.example.com".to_string()];
    enumerator.ingest(&s2, SubdomainSource::CrtSh);
    enumerator.ingest(&s2, SubdomainSource::VirusTotal);
    enumerator.ingest(&s2, SubdomainSource::DnsDumpster);

    let results = enumerator.results();
    assert_eq!(results[0].subdomain, "high.example.com");
    assert_eq!(results[1].subdomain, "low.example.com");
}

#[test]
fn enumerator_tracks_first_seen_source() {
    let mut enumerator = SubdomainEnumerator::new("example.com");

    let subs = vec!["api.example.com".to_string()];
    enumerator.ingest(&subs, SubdomainSource::WaybackMachine);
    enumerator.ingest(&subs, SubdomainSource::CrtSh);

    let result = enumerator
        .results()
        .into_iter()
        .find(|s| s.subdomain == "api.example.com")
        .unwrap();
    assert_eq!(result.first_seen_source, SubdomainSource::WaybackMachine);
}

#[test]
fn confidence_for_source_count_monotonically_increases() {
    let mut prev = 0.0;
    for count in 1..=10 {
        let current = confidence_for_source_count(count);
        assert!(current > prev, "confidence should increase: count={count}");
        prev = current;
    }
}

#[test]
fn confidence_bounds() {
    assert_eq!(confidence_for_source_count(0), 0.0);
    assert!(confidence_for_source_count(1) > 0.0);
    assert!(confidence_for_source_count(10) <= 1.0);
}

#[test]
fn generate_dork_queries_produces_five_queries() {
    let queries = generate_dork_queries("example.com");
    assert_eq!(queries.len(), 5);
    for q in &queries {
        assert!(q.contains("example.com"));
    }
}

#[test]
fn subdomain_source_display_coverage() {
    let all_sources = vec![
        SubdomainSource::CrtSh,
        SubdomainSource::SecurityTrails,
        SubdomainSource::DnsDumpster,
        SubdomainSource::VirusTotal,
        SubdomainSource::WaybackMachine,
        SubdomainSource::DnsZoneTransfer,
        SubdomainSource::DnsRecordExtraction,
        SubdomainSource::SearchEngineDork,
        SubdomainSource::SourceCodeReference,
        SubdomainSource::FaviconHash,
    ];
    for source in all_sources {
        let display = format!("{source}");
        assert!(!display.is_empty());
    }
}

#[test]
fn enumerator_full_pipeline_ten_sources() {
    let mut e = SubdomainEnumerator::new("target.io");

    e.ingest_crtsh(r#"[{"name_value": "api.target.io", "common_name": "api.target.io"}]"#);
    e.ingest_securitytrails(r#"{"subdomains": ["www", "api"]}"#);
    e.ingest_dnsdumpster("<td>cdn.target.io</td>");
    e.ingest_virustotal(r#"{"data": [{"id": "api.target.io", "type": "domain"}]}"#);
    e.ingest_wayback("https://blog.target.io/hello\n");
    e.ingest_zone_transfer("internal.target.io. 3600 IN A 10.0.0.1\n");
    e.ingest_dns_records("target.io IN MX 10 mx.target.io.\n");
    e.ingest_search_dork("https://admin.target.io/login\n");
    e.ingest_source_code(r#"var url = "https://ws.target.io/socket";"#);
    e.ingest_favicon_hashes("-123:panel.target.io\n");

    assert!(
        e.count() >= 8,
        "expected at least 8 unique subdomains, got {}",
        e.count()
    );

    let api = e
        .results()
        .into_iter()
        .find(|s| s.subdomain == "api.target.io")
        .unwrap();
    assert!(
        api.sources.len() >= 3,
        "api.target.io seen by crtsh+securitytrails+virustotal"
    );
}

#[test]
fn enumerator_normalizes_target_domain() {
    let e = SubdomainEnumerator::new("  Example.COM.  ");
    assert_eq!(e.target_domain(), "example.com");
}
