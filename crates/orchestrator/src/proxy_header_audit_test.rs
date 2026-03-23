use crate::proxy_header_audit::*;

#[test]
fn empty_headers_no_issues() {
    let issues = analyze_proxy_headers(&[]);
    assert!(issues.is_empty());
}

#[test]
fn via_header_detected() {
    let headers = vec![("via", "1.1 varnish")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::ViaProxyLeak {
        value: "1.1 varnish".to_string(),
    }));
}

#[test]
fn multiple_via_headers_proxy_chain_length() {
    let headers = vec![("via", "1.1 proxy1"), ("via", "1.0 proxy2")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::ProxyChainLength { count: 2 }));
}

#[test]
fn single_via_no_chain_length() {
    let headers = vec![("via", "1.1 proxy1")];
    let issues = analyze_proxy_headers(&headers);
    let chain: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, ProxyHeaderIssue::ProxyChainLength { .. }))
        .collect();
    assert!(chain.is_empty());
}

#[test]
fn age_header_present() {
    let headers = vec![("age", "3600")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::AgePresent {
        seconds: "3600".to_string(),
    }));
}

#[test]
fn x_cache_hit_detected() {
    let headers = vec![("x-cache", "HIT")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::XCacheHit {
        status: "HIT".to_string(),
    }));
}

#[test]
fn x_cache_miss_detected() {
    let headers = vec![("x-cache", "MISS")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::XCacheHit {
        status: "MISS".to_string(),
    }));
}

#[test]
fn x_forwarded_for_with_ips() {
    let headers = vec![("x-forwarded-for", "203.0.113.50, 70.41.3.18")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::XForwardedFor {
        ips: "203.0.113.50, 70.41.3.18".to_string(),
    }));
}

#[test]
fn x_forwarded_for_internal_ip_10() {
    let headers = vec![("x-forwarded-for", "10.0.0.1, 203.0.113.50")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::InternalIpLeak {
        ip: "10.0.0.1".to_string(),
    }));
}

#[test]
fn x_forwarded_for_internal_ip_192_168() {
    let headers = vec![("x-forwarded-for", "192.168.1.1")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::InternalIpLeak {
        ip: "192.168.1.1".to_string(),
    }));
}

#[test]
fn x_forwarded_for_internal_ip_172_16() {
    let headers = vec![("x-forwarded-for", "172.16.0.1")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::InternalIpLeak {
        ip: "172.16.0.1".to_string(),
    }));
}

#[test]
fn x_forwarded_for_internal_ip_172_31() {
    let headers = vec![("x-forwarded-for", "172.31.255.1")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::InternalIpLeak {
        ip: "172.31.255.1".to_string(),
    }));
}

#[test]
fn x_forwarded_for_172_32_not_internal() {
    let headers = vec![("x-forwarded-for", "172.32.0.1")];
    let issues = analyze_proxy_headers(&headers);
    let internal: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, ProxyHeaderIssue::InternalIpLeak { .. }))
        .collect();
    assert!(internal.is_empty());
}

#[test]
fn x_forwarded_host_detected() {
    let headers = vec![("x-forwarded-host", "internal.corp.example.com")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::XForwardedHost {
        host: "internal.corp.example.com".to_string(),
    }));
}

#[test]
fn x_real_ip_detected() {
    let headers = vec![("x-real-ip", "203.0.113.50")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::XRealIp {
        ip: "203.0.113.50".to_string(),
    }));
}

#[test]
fn cdn_cloudflare_via() {
    let headers = vec![("via", "1.1 cloudflare")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::CdnIdentified {
        cdn: "cloudflare".to_string(),
    }));
}

#[test]
fn cdn_akamai_server() {
    let headers = vec![("server", "akamai ghost")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::CdnIdentified {
        cdn: "akamai".to_string(),
    }));
}

#[test]
fn cdn_cloudfront_via() {
    let headers = vec![("via", "1.1 cloudfront.net")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::CdnIdentified {
        cdn: "cloudfront".to_string(),
    }));
}

#[test]
fn cdn_fastly_server() {
    let headers = vec![("server", "fastly")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::CdnIdentified {
        cdn: "fastly".to_string(),
    }));
}

#[test]
fn server_timing_leak() {
    let headers = vec![("server-timing", "db;dur=53, app;dur=47.2")];
    let issues = analyze_proxy_headers(&headers);
    assert!(issues.contains(&ProxyHeaderIssue::ServerTimingLeak {
        value: "db;dur=53, app;dur=47.2".to_string(),
    }));
}

#[test]
fn display_via_proxy_leak() {
    let issue = ProxyHeaderIssue::ViaProxyLeak {
        value: "1.1 varnish".to_string(),
    };
    assert_eq!(issue.to_string(), "via_proxy_leak:1.1 varnish");
}

#[test]
fn display_age_present() {
    let issue = ProxyHeaderIssue::AgePresent {
        seconds: "3600".to_string(),
    };
    assert_eq!(issue.to_string(), "age_present:3600");
}

#[test]
fn display_x_cache_hit() {
    let issue = ProxyHeaderIssue::XCacheHit {
        status: "HIT".to_string(),
    };
    assert_eq!(issue.to_string(), "x_cache_hit:HIT");
}

#[test]
fn display_x_forwarded_for() {
    let issue = ProxyHeaderIssue::XForwardedFor {
        ips: "10.0.0.1".to_string(),
    };
    assert_eq!(issue.to_string(), "x_forwarded_for:10.0.0.1");
}

#[test]
fn display_x_forwarded_host() {
    let issue = ProxyHeaderIssue::XForwardedHost {
        host: "internal.corp".to_string(),
    };
    assert_eq!(issue.to_string(), "x_forwarded_host:internal.corp");
}

#[test]
fn display_x_real_ip() {
    let issue = ProxyHeaderIssue::XRealIp {
        ip: "10.0.0.5".to_string(),
    };
    assert_eq!(issue.to_string(), "x_real_ip:10.0.0.5");
}

#[test]
fn display_cdn_identified() {
    let issue = ProxyHeaderIssue::CdnIdentified {
        cdn: "cloudflare".to_string(),
    };
    assert_eq!(issue.to_string(), "cdn_identified:cloudflare");
}

#[test]
fn display_internal_ip_leak() {
    let issue = ProxyHeaderIssue::InternalIpLeak {
        ip: "192.168.1.1".to_string(),
    };
    assert_eq!(issue.to_string(), "internal_ip_leak:192.168.1.1");
}

#[test]
fn display_proxy_chain_length() {
    let issue = ProxyHeaderIssue::ProxyChainLength { count: 3 };
    assert_eq!(issue.to_string(), "proxy_chain_length:3");
}

#[test]
fn display_server_timing_leak() {
    let issue = ProxyHeaderIssue::ServerTimingLeak {
        value: "db;dur=53".to_string(),
    };
    assert_eq!(issue.to_string(), "server_timing_leak:db;dur=53");
}

#[test]
fn severity_via_proxy_leak() {
    let issue = ProxyHeaderIssue::ViaProxyLeak {
        value: "1.1 proxy".to_string(),
    };
    assert!((proxy_header_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_age_present() {
    let issue = ProxyHeaderIssue::AgePresent {
        seconds: "60".to_string(),
    };
    assert!((proxy_header_severity(&issue) - 1.5).abs() < f64::EPSILON);
}

#[test]
fn severity_x_cache_hit() {
    let issue = ProxyHeaderIssue::XCacheHit {
        status: "HIT".to_string(),
    };
    assert!((proxy_header_severity(&issue) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_internal_ip_leak() {
    let issue = ProxyHeaderIssue::InternalIpLeak {
        ip: "10.0.0.1".to_string(),
    };
    assert!((proxy_header_severity(&issue) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_server_timing_leak() {
    let issue = ProxyHeaderIssue::ServerTimingLeak {
        value: "db;dur=53".to_string(),
    };
    assert!((proxy_header_severity(&issue) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn to_operations_count_matches_issues() {
    let issues = vec![
        ProxyHeaderIssue::ViaProxyLeak {
            value: "1.1 proxy".to_string(),
        },
        ProxyHeaderIssue::AgePresent {
            seconds: "300".to_string(),
        },
        ProxyHeaderIssue::XCacheHit {
            status: "HIT".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = proxy_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
}

#[test]
fn to_operations_sequence_increments() {
    let issues = vec![
        ProxyHeaderIssue::XForwardedFor {
            ips: "1.2.3.4".to_string(),
        },
        ProxyHeaderIssue::XRealIp {
            ip: "5.6.7.8".to_string(),
        },
    ];
    let mut seq = 10;
    let ops = proxy_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
}

#[test]
fn to_operations_empty_issues_empty_result() {
    let mut seq = 5;
    let ops = proxy_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn to_operations_uses_information_disclosure() {
    let issues = vec![ProxyHeaderIssue::ViaProxyLeak {
        value: "1.1 squid".to_string(),
    }];
    let mut seq = 0;
    let ops = proxy_header_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            confidence,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::InformationDisclosure
            );
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn combined_headers_all_detected() {
    let headers = vec![
        ("via", "1.1 cloudflare"),
        ("age", "120"),
        ("x-cache", "HIT"),
        ("x-forwarded-for", "10.0.0.1"),
        ("x-forwarded-host", "app.internal"),
        ("x-real-ip", "203.0.113.50"),
        ("server-timing", "miss"),
    ];
    let issues = analyze_proxy_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::ViaProxyLeak { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::AgePresent { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::XCacheHit { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::XForwardedFor { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::XForwardedHost { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::XRealIp { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::ServerTimingLeak { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::CdnIdentified { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ProxyHeaderIssue::InternalIpLeak { .. }))
    );
}
