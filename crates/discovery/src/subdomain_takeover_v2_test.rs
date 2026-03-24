use super::subdomain_takeover_v2::*;
use std::collections::HashMap;

fn make_chain(links: Vec<(&str, &str)>, is_dangling: bool) -> CnameChain {
    CnameChain {
        links: links
            .into_iter()
            .map(|(s, t)| CnameLink {
                source: s.to_string(),
                target: t.to_string(),
            })
            .collect(),
        is_dangling,
    }
}

fn make_dns_result(subdomain: &str, chain: CnameChain, a_records: Vec<&str>) -> DnsResult {
    DnsResult {
        subdomain: subdomain.to_string(),
        cname_chain: chain,
        a_records: a_records.into_iter().map(String::from).collect(),
        error: None,
    }
}

#[test]
fn signature_database_has_at_least_10_services() {
    let sigs = build_signature_database();
    let unique_services: std::collections::HashSet<_> = sigs.iter().map(|s| &s.service).collect();
    assert!(
        unique_services.len() >= 10,
        "Expected >=10 unique services, got {}",
        unique_services.len()
    );
}

#[test]
fn signature_database_has_20_entries() {
    let sigs = build_signature_database();
    assert_eq!(sigs.len(), 20);
}

#[test]
fn identify_service_github_pages() {
    let sigs = build_signature_database();
    let result = identify_service("myuser.github.io", &sigs);
    assert_eq!(result, Some(CloudService::GithubPages));
}

#[test]
fn identify_service_heroku() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("myapp.herokudns.com", &sigs),
        Some(CloudService::Heroku)
    );
    assert_eq!(
        identify_service("myapp.herokuapp.com", &sigs),
        Some(CloudService::Heroku)
    );
}

#[test]
fn identify_service_aws_s3() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("mybucket.s3.amazonaws.com", &sigs),
        Some(CloudService::AwsS3)
    );
}

#[test]
fn identify_service_azure() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("mysite.azurewebsites.net", &sigs),
        Some(CloudService::AzureWebsites)
    );
}

#[test]
fn identify_service_shopify() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("mystore.myshopify.com", &sigs),
        Some(CloudService::Shopify)
    );
}

#[test]
fn identify_service_fastly() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("cdn.fastly.net", &sigs),
        Some(CloudService::Fastly)
    );
}

#[test]
fn identify_service_netlify() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("myapp.netlify.app", &sigs),
        Some(CloudService::Netlify)
    );
}

#[test]
fn identify_service_pantheon() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("mysite.pantheonsite.io", &sigs),
        Some(CloudService::Pantheon)
    );
}

#[test]
fn identify_service_tumblr() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("blog.tumblr.com", &sigs),
        Some(CloudService::Tumblr)
    );
}

#[test]
fn identify_service_unknown_returns_none() {
    let sigs = build_signature_database();
    assert_eq!(identify_service("example.com", &sigs), None);
}

#[test]
fn identify_service_case_insensitive() {
    let sigs = build_signature_database();
    assert_eq!(
        identify_service("MyUser.GitHub.IO", &sigs),
        Some(CloudService::GithubPages)
    );
}

#[test]
fn cname_chain_depth() {
    let chain = make_chain(
        vec![
            ("a.example.com", "b.github.io"),
            ("b.github.io", "c.github.io"),
            ("c.github.io", "d.github.io"),
        ],
        false,
    );
    assert_eq!(chain.depth(), 3);
}

#[test]
fn cname_chain_terminal() {
    let chain = make_chain(vec![("a.com", "b.com"), ("b.com", "c.com")], false);
    assert_eq!(chain.terminal(), Some("c.com"));
}

#[test]
fn cname_chain_root() {
    let chain = make_chain(vec![("a.com", "b.com")], false);
    assert_eq!(chain.root(), Some("a.com"));
}

#[test]
fn empty_chain_depth_zero() {
    let chain = CnameChain {
        links: vec![],
        is_dangling: false,
    };
    assert_eq!(chain.depth(), 0);
    assert_eq!(chain.terminal(), None);
    assert_eq!(chain.root(), None);
}

#[test]
fn dangling_cname_detection() {
    let chain = make_chain(vec![("sub.example.com", "old.herokuapp.com")], true);
    assert!(is_dangling_cname(&chain, &[]));
}

#[test]
fn non_dangling_cname_with_a_records() {
    let chain = make_chain(vec![("sub.example.com", "target.com")], false);
    assert!(!is_dangling_cname(&chain, &["1.2.3.4".to_string()]));
}

#[test]
fn empty_chain_not_dangling() {
    let chain = CnameChain {
        links: vec![],
        is_dangling: false,
    };
    assert!(!is_dangling_cname(&chain, &[]));
}

#[test]
fn http_fingerprint_github_pages() {
    let sigs = build_signature_database();
    let body = "There isn't a GitHub Pages site here.";
    let result = check_http_fingerprint(body, &CloudService::GithubPages, &sigs);
    assert!(result.is_some());
    assert!(result.unwrap().contains("GitHub Pages"));
}

#[test]
fn http_fingerprint_s3_no_such_bucket() {
    let sigs = build_signature_database();
    let body = "<Error><Code>NoSuchBucket</Code></Error>";
    let result = check_http_fingerprint(body, &CloudService::AwsS3, &sigs);
    assert!(result.is_some());
}

#[test]
fn http_fingerprint_no_match() {
    let sigs = build_signature_database();
    let body = "Welcome to our awesome site!";
    let result = check_http_fingerprint(body, &CloudService::GithubPages, &sigs);
    assert!(result.is_none());
}

#[test]
fn confidence_confirmed_with_http_match() {
    let sigs = build_signature_database();
    let chain = make_chain(vec![("sub.com", "old.github.io")], true);
    let http_match = Some("fingerprint".to_string());
    let confidence = assess_confidence(&chain, &[], &CloudService::GithubPages, &http_match, &sigs);
    assert_eq!(confidence, TakeoverConfidence::Confirmed);
}

#[test]
fn confidence_likely_dangling_no_http() {
    let sigs = build_signature_database();
    let chain = make_chain(vec![("sub.com", "old.github.io")], true);
    let confidence = assess_confidence(&chain, &[], &CloudService::GithubPages, &None, &sigs);
    assert_eq!(confidence, TakeoverConfidence::Likely);
}

#[test]
fn confidence_possible_for_edge_case_service() {
    let sigs = build_signature_database();
    let chain = make_chain(vec![("sub.com", "old.elasticbeanstalk.com")], true);
    let confidence = assess_confidence(
        &chain,
        &[],
        &CloudService::AwsElasticBeanstalk,
        &None,
        &sigs,
    );
    assert_eq!(confidence, TakeoverConfidence::Possible);
}

#[test]
fn confidence_ordering() {
    assert!(TakeoverConfidence::Confirmed > TakeoverConfidence::Likely);
    assert!(TakeoverConfidence::Likely > TakeoverConfidence::Possible);
}

#[test]
fn priority_score_confirmed_higher_than_likely() {
    let score_confirmed =
        compute_priority(TakeoverConfidence::Confirmed, &CloudService::GithubPages);
    let score_likely = compute_priority(TakeoverConfidence::Likely, &CloudService::GithubPages);
    let score_possible = compute_priority(TakeoverConfidence::Possible, &CloudService::GithubPages);
    assert!(score_confirmed > score_likely);
    assert!(score_likely > score_possible);
}

#[test]
fn analyze_dns_result_finds_github_takeover() {
    let sigs = build_signature_database();
    let chain = make_chain(vec![("blog.example.com", "olduser.github.io")], true);
    let dns = make_dns_result("blog.example.com", chain, vec![]);
    let body = "There isn't a GitHub Pages site here.";

    let finding = analyze_dns_result(&dns, &sigs, Some(body));
    assert!(finding.is_some());
    let finding = finding.unwrap();
    assert_eq!(finding.service, CloudService::GithubPages);
    assert_eq!(finding.confidence, TakeoverConfidence::Confirmed);
    assert!(finding.priority_score > 0.0);
}

#[test]
fn analyze_dns_result_no_cname_returns_none() {
    let sigs = build_signature_database();
    let chain = CnameChain {
        links: vec![],
        is_dangling: false,
    };
    let dns = make_dns_result("example.com", chain, vec!["1.2.3.4"]);
    let finding = analyze_dns_result(&dns, &sigs, None);
    assert!(finding.is_none());
}

#[test]
fn analyze_batch_sorts_by_priority() {
    let sigs = build_signature_database();

    let chain1 = make_chain(vec![("a.example.com", "old.github.io")], true);
    let dns1 = make_dns_result("a.example.com", chain1, vec![]);

    let chain2 = make_chain(vec![("b.example.com", "old.herokuapp.com")], false);
    let dns2 = make_dns_result("b.example.com", chain2, vec!["1.2.3.4"]);

    let mut http_bodies = HashMap::new();
    http_bodies.insert(
        "a.example.com".to_string(),
        "There isn't a GitHub Pages site here.".to_string(),
    );

    let findings = analyze_batch(&[dns1, dns2], &sigs, &http_bodies);
    assert_eq!(findings.len(), 2);
    assert!(findings[0].priority_score >= findings[1].priority_score);
}

#[test]
fn parse_cname_chain_basic() {
    let records = vec![
        ("a.com".to_string(), "b.com".to_string()),
        ("b.com".to_string(), "c.com".to_string()),
    ];
    let chain = parse_cname_chain(&records, 10);
    assert_eq!(chain.depth(), 2);
    assert_eq!(chain.terminal(), Some("c.com"));
}

#[test]
fn parse_cname_chain_respects_max_depth() {
    let records = vec![
        ("a.com".to_string(), "b.com".to_string()),
        ("b.com".to_string(), "c.com".to_string()),
        ("c.com".to_string(), "d.com".to_string()),
    ];
    let chain = parse_cname_chain(&records, 2);
    assert_eq!(chain.depth(), 2);
}

#[test]
fn parse_cname_chain_deduplicates() {
    let records = vec![
        ("a.com".to_string(), "b.com".to_string()),
        ("a.com".to_string(), "b.com".to_string()),
    ];
    let chain = parse_cname_chain(&records, 10);
    assert_eq!(chain.depth(), 1);
}

#[test]
fn resolve_cname_chain_three_levels() {
    let mut lookup = HashMap::new();
    lookup.insert("a.example.com".to_string(), "b.cdn.com".to_string());
    lookup.insert("b.cdn.com".to_string(), "c.provider.net".to_string());
    lookup.insert("c.provider.net".to_string(), "d.github.io".to_string());

    let chain = resolve_cname_chain("a.example.com", &lookup, 10);
    assert_eq!(chain.depth(), 3);
    assert_eq!(chain.terminal(), Some("d.github.io"));
    assert!(chain.is_dangling);
}

#[test]
fn resolve_cname_chain_detects_cycle() {
    let mut lookup = HashMap::new();
    lookup.insert("a.com".to_string(), "b.com".to_string());
    lookup.insert("b.com".to_string(), "a.com".to_string());

    let chain = resolve_cname_chain("a.com", &lookup, 10);
    assert_eq!(chain.depth(), 2);
}

#[test]
fn resolve_cname_chain_respects_depth_limit() {
    let mut lookup = HashMap::new();
    lookup.insert("a.com".to_string(), "b.com".to_string());
    lookup.insert("b.com".to_string(), "c.com".to_string());
    lookup.insert("c.com".to_string(), "d.com".to_string());

    let chain = resolve_cname_chain("a.com", &lookup, 2);
    assert_eq!(chain.depth(), 2);
}

#[test]
fn group_by_service_groups_correctly() {
    let sigs = build_signature_database();
    let chain1 = make_chain(vec![("a.com", "old.github.io")], true);
    let chain2 = make_chain(vec![("b.com", "old2.github.io")], true);
    let chain3 = make_chain(vec![("c.com", "old.herokuapp.com")], true);

    let dns1 = make_dns_result("a.com", chain1, vec![]);
    let dns2 = make_dns_result("b.com", chain2, vec![]);
    let dns3 = make_dns_result("c.com", chain3, vec![]);

    let findings = analyze_batch(&[dns1, dns2, dns3], &sigs, &HashMap::new());
    let groups = group_by_service(&findings);
    assert!(groups.contains_key(&CloudService::GithubPages));
    assert!(groups.contains_key(&CloudService::Heroku));
    assert_eq!(groups[&CloudService::GithubPages].len(), 2);
}

#[test]
fn filter_by_confidence_level() {
    let sigs = build_signature_database();

    let chain1 = make_chain(vec![("a.com", "old.github.io")], true);
    let dns1 = make_dns_result("a.com", chain1, vec![]);

    let chain2 = make_chain(vec![("b.com", "old.elasticbeanstalk.com")], true);
    let dns2 = make_dns_result("b.com", chain2, vec![]);

    let mut http_bodies = HashMap::new();
    http_bodies.insert(
        "a.com".to_string(),
        "There isn't a GitHub Pages site here.".to_string(),
    );

    let findings = analyze_batch(&[dns1, dns2], &sigs, &http_bodies);
    let confirmed = filter_by_confidence(&findings, TakeoverConfidence::Confirmed);
    assert_eq!(confirmed.len(), 1);
    assert_eq!(confirmed[0].subdomain, "a.com");
}

#[test]
fn summarize_findings_counts() {
    let sigs = build_signature_database();

    let chain1 = make_chain(vec![("a.com", "old.github.io")], true);
    let dns1 = make_dns_result("a.com", chain1, vec![]);
    let chain2 = make_chain(vec![("b.com", "old.herokuapp.com")], true);
    let dns2 = make_dns_result("b.com", chain2, vec![]);

    let mut http_bodies = HashMap::new();
    http_bodies.insert(
        "a.com".to_string(),
        "There isn't a GitHub Pages site here.".to_string(),
    );

    let findings = analyze_batch(&[dns1, dns2], &sigs, &http_bodies);
    let summary = summarize_findings(100, &findings);
    assert_eq!(summary.total_checked, 100);
    assert_eq!(summary.total_findings, 2);
    assert_eq!(summary.confirmed, 1);
    assert!(summary.likely >= 1);
}

#[test]
fn validate_subdomain_valid() {
    assert!(validate_subdomain("blog.example.com"));
    assert!(validate_subdomain("a.b.c.example.com"));
    assert!(validate_subdomain("my-app.example.com"));
}

#[test]
fn validate_subdomain_invalid() {
    assert!(!validate_subdomain(""));
    assert!(!validate_subdomain("example"));
    assert!(!validate_subdomain("-bad.com"));
    assert!(!validate_subdomain("bad-.com"));
    assert!(!validate_subdomain("bad..com"));
    assert!(!validate_subdomain("bad com.test"));
}

#[test]
fn validate_subdomain_too_long() {
    let long_label = "a".repeat(64);
    let subdomain = format!("{}.example.com", long_label);
    assert!(!validate_subdomain(&subdomain));
}

#[test]
fn extract_base_domain_works() {
    assert_eq!(
        extract_base_domain("blog.sub.example.com"),
        Some("example.com".to_string())
    );
    assert_eq!(
        extract_base_domain("example.com"),
        Some("example.com".to_string())
    );
    assert_eq!(extract_base_domain("localhost"), None);
}

#[test]
fn cloud_service_display() {
    assert_eq!(format!("{}", CloudService::GithubPages), "GitHub Pages");
    assert_eq!(format!("{}", CloudService::AwsS3), "AWS S3");
    assert_eq!(
        format!("{}", CloudService::Unknown("test".to_string())),
        "Unknown(test)"
    );
}

#[test]
fn takeover_confidence_display() {
    assert_eq!(format!("{}", TakeoverConfidence::Confirmed), "confirmed");
    assert_eq!(format!("{}", TakeoverConfidence::Likely), "likely");
    assert_eq!(format!("{}", TakeoverConfidence::Possible), "possible");
}

#[test]
fn takeover_config_builder() {
    let config = TakeoverConfig::default()
        .with_concurrency(100)
        .with_max_cname_depth(5)
        .with_verify_http(false)
        .with_user_agent("Custom/1.0".to_string());

    assert_eq!(config.concurrency, 100);
    assert_eq!(config.max_cname_depth, 5);
    assert!(!config.verify_http);
    assert_eq!(config.user_agent, "Custom/1.0");
}

#[test]
fn takeover_config_default_values() {
    let config = TakeoverConfig::default();
    assert_eq!(config.concurrency, 50);
    assert_eq!(config.max_cname_depth, 10);
    assert!(config.verify_http);
}

#[test]
fn priority_score_ranges() {
    assert_eq!(TakeoverConfidence::Possible.priority_score(), 0.3);
    assert_eq!(TakeoverConfidence::Likely.priority_score(), 0.7);
    assert_eq!(TakeoverConfidence::Confirmed.priority_score(), 1.0);
}

#[test]
fn identify_all_major_services() {
    let sigs = build_signature_database();
    let test_cases = vec![
        ("myuser.github.io", CloudService::GithubPages),
        ("myapp.herokudns.com", CloudService::Heroku),
        ("mybucket.s3.amazonaws.com", CloudService::AwsS3),
        (
            "myapp.elasticbeanstalk.com",
            CloudService::AwsElasticBeanstalk,
        ),
        ("dist.cloudfront.net", CloudService::AwsCloudFront),
        ("mysite.azurewebsites.net", CloudService::AzureWebsites),
        ("app.trafficmanager.net", CloudService::AzureTrafficManager),
        ("shop.myshopify.com", CloudService::Shopify),
        ("cdn.fastly.net", CloudService::Fastly),
        ("site.pantheonsite.io", CloudService::Pantheon),
        ("blog.tumblr.com", CloudService::Tumblr),
        ("site.wordpress.com", CloudService::WordPress),
        ("blog.ghost.io", CloudService::Ghost),
        ("site.surge.sh", CloudService::Surge),
        ("page.bitbucket.io", CloudService::Bitbucket),
        ("help.zendesk.com", CloudService::Zendesk),
        ("docs.readme.io", CloudService::Readme),
        ("site.cargocollective.com", CloudService::CargoCollective),
        ("app.fly.dev", CloudService::Fly),
        ("site.netlify.app", CloudService::Netlify),
    ];

    for (cname, expected_service) in test_cases {
        let result = identify_service(cname, &sigs);
        assert_eq!(
            result,
            Some(expected_service),
            "Failed to identify service for CNAME: {}",
            cname
        );
    }
}

#[test]
fn http_timeout_config() {
    use std::time::Duration;
    let config = TakeoverConfig::default().with_http_timeout(Duration::from_secs(30));
    assert_eq!(config.http_timeout, Duration::from_secs(30));
}

#[test]
fn analyze_batch_empty_input() {
    let sigs = build_signature_database();
    let findings = analyze_batch(&[], &sigs, &HashMap::new());
    assert!(findings.is_empty());
}

#[test]
fn summarize_empty_findings() {
    let summary = summarize_findings(0, &[]);
    assert_eq!(summary.total_checked, 0);
    assert_eq!(summary.total_findings, 0);
    assert_eq!(summary.confirmed, 0);
    assert_eq!(summary.likely, 0);
    assert_eq!(summary.possible, 0);
}
