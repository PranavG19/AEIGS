use super::bgp_history::*;

#[test]
fn parse_as_path_simple() {
    let path = parse_as_path("15169 3356 1299 13335");
    assert_eq!(path, vec![15169, 3356, 1299, 13335]);
}

#[test]
fn parse_as_path_with_as_prefix() {
    let path = parse_as_path("AS15169 AS3356 AS1299");
    assert_eq!(path, vec![15169, 3356, 1299]);
}

#[test]
fn parse_as_path_empty() {
    let path = parse_as_path("");
    assert!(path.is_empty());
}

#[test]
fn analyze_as_path_normal() {
    let analysis = analyze_as_path("1.0.0.0/24", &[15169, 3356, 13335]);
    assert_eq!(analysis.origin_asn, 13335);
    assert_eq!(analysis.path_length, 3);
    assert!(!analysis.has_prepending);
    assert!(analysis.anomalies.is_empty());
    assert_eq!(analysis.transit_asns, vec![3356]);
    assert_eq!(analysis.upstream_asns, vec![3356]);
}

#[test]
fn analyze_as_path_prepending() {
    let analysis = analyze_as_path("10.0.0.0/8", &[100, 200, 300, 300, 300, 300, 300]);
    assert!(analysis.has_prepending);
    assert!(analysis.prepend_count >= 3);
    assert!(analysis.anomalies.iter().any(|a| a.contains("prepending")));
}

#[test]
fn analyze_as_path_long() {
    let path: Vec<u32> = (1..=12).collect();
    let analysis = analyze_as_path("192.168.0.0/16", &path);
    assert!(analysis.anomalies.iter().any(|a| a.contains("long")));
}

#[test]
fn parse_routeviews_text_basic() {
    let text = "10.0.0.0/8 15169 3356 1299\n\
                172.16.0.0/12 15169 3356\n\
                # comment line\n";
    let prefixes = parse_routeviews_text(text);
    assert_eq!(prefixes.len(), 2);
    assert_eq!(prefixes[0].prefix, "10.0.0.0/8");
    assert_eq!(prefixes[0].origin_asn, 1299);
    assert_eq!(prefixes[0].as_path, vec![15169, 3356, 1299]);
    assert_eq!(prefixes[0].source, BgpSource::RouteViews);
}

#[test]
fn parse_routeviews_text_empty() {
    let prefixes = parse_routeviews_text("");
    assert!(prefixes.is_empty());
}

#[test]
fn parse_ripe_ris_prefix_format() {
    let json = r#"{
        "data": {
            "prefixes": [
                {
                    "prefix": "1.0.0.0/24",
                    "origin": "AS13335",
                    "timelines": [{"starttime": "2020-01-01", "endtime": "2024-01-01"}]
                }
            ]
        }
    }"#;
    let prefixes = parse_ripe_ris_response(json);
    assert_eq!(prefixes.len(), 1);
    assert_eq!(prefixes[0].prefix, "1.0.0.0/24");
    assert_eq!(prefixes[0].origin_asn, 13335);
    assert_eq!(prefixes[0].prefix_length, 24);
    assert_eq!(prefixes[0].source, BgpSource::RipeRis);
}

#[test]
fn parse_ripe_ris_invalid() {
    let prefixes = parse_ripe_ris_response("not json");
    assert!(prefixes.is_empty());
}

#[test]
fn detect_ip_reuse_no_changes() {
    let prefixes = vec![BgpPrefix {
        prefix: "10.0.0.0/8".to_string(),
        prefix_length: 8,
        origin_asn: 100,
        as_path: vec![100],
        next_hop: None,
        first_seen: Some("2020-01-01".to_string()),
        last_seen: None,
        source: BgpSource::RipeRis,
    }];
    let reuse = detect_ip_reuse("10.0.0.0/8", &prefixes);
    assert_eq!(reuse.owner_changes, 0);
    assert_eq!(reuse.risk, BgpRisk::Info);
}

#[test]
fn detect_ip_reuse_multiple_owners() {
    let prefixes = vec![
        BgpPrefix {
            prefix: "10.0.0.0/8".to_string(),
            prefix_length: 8,
            origin_asn: 100,
            as_path: vec![100],
            next_hop: None,
            first_seen: Some("2019-01-01".to_string()),
            last_seen: None,
            source: BgpSource::RipeRis,
        },
        BgpPrefix {
            prefix: "10.0.0.0/8".to_string(),
            prefix_length: 8,
            origin_asn: 200,
            as_path: vec![200],
            next_hop: None,
            first_seen: Some("2020-01-01".to_string()),
            last_seen: None,
            source: BgpSource::RipeRis,
        },
        BgpPrefix {
            prefix: "10.0.0.0/8".to_string(),
            prefix_length: 8,
            origin_asn: 300,
            as_path: vec![300],
            next_hop: None,
            first_seen: Some("2021-01-01".to_string()),
            last_seen: None,
            source: BgpSource::RipeRis,
        },
    ];
    let reuse = detect_ip_reuse("10.0.0.0/8", &prefixes);
    assert_eq!(reuse.owner_changes, 2);
    assert_eq!(reuse.risk, BgpRisk::Medium);
    assert_eq!(reuse.current_owner, Some(300));
}

#[test]
fn detect_route_changes_origin_change() {
    let old = vec![BgpPrefix {
        prefix: "10.0.0.0/8".to_string(),
        prefix_length: 8,
        origin_asn: 100,
        as_path: vec![200, 100],
        next_hop: None,
        first_seen: None,
        last_seen: None,
        source: BgpSource::RipeRis,
    }];
    let new = vec![BgpPrefix {
        prefix: "10.0.0.0/8".to_string(),
        prefix_length: 8,
        origin_asn: 999,
        as_path: vec![200, 999],
        next_hop: None,
        first_seen: None,
        last_seen: None,
        source: BgpSource::RipeRis,
    }];
    let changes = detect_route_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].change_type, RouteChangeType::OriginChange);
    assert_eq!(changes[0].old_asn, Some(100));
    assert_eq!(changes[0].new_asn, 999);
}

#[test]
fn detect_route_changes_withdrawal() {
    let old = vec![BgpPrefix {
        prefix: "10.0.0.0/8".to_string(),
        prefix_length: 8,
        origin_asn: 100,
        as_path: vec![100],
        next_hop: None,
        first_seen: None,
        last_seen: None,
        source: BgpSource::RipeRis,
    }];
    let new: Vec<BgpPrefix> = vec![];
    let changes = detect_route_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].change_type, RouteChangeType::Withdrawal);
}

#[test]
fn detect_route_changes_announcement() {
    let old: Vec<BgpPrefix> = vec![];
    let new = vec![BgpPrefix {
        prefix: "192.168.0.0/16".to_string(),
        prefix_length: 16,
        origin_asn: 500,
        as_path: vec![500],
        next_hop: None,
        first_seen: None,
        last_seen: None,
        source: BgpSource::RouteViews,
    }];
    let changes = detect_route_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].change_type, RouteChangeType::Announcement);
}

#[test]
fn detect_route_changes_no_change() {
    let same = vec![BgpPrefix {
        prefix: "10.0.0.0/8".to_string(),
        prefix_length: 8,
        origin_asn: 100,
        as_path: vec![200, 100],
        next_hop: None,
        first_seen: None,
        last_seen: None,
        source: BgpSource::RipeRis,
    }];
    let changes = detect_route_changes(&same, &same);
    assert!(changes.is_empty());
}

#[test]
fn build_bgp_report_aggregates() {
    let prefixes = vec![BgpPrefix {
        prefix: "10.0.0.0/8".to_string(),
        prefix_length: 8,
        origin_asn: 100,
        as_path: vec![200, 100],
        next_hop: None,
        first_seen: None,
        last_seen: None,
        source: BgpSource::RipeRis,
    }];
    let changes = vec![BgpRouteChange {
        prefix: "10.0.0.0/8".to_string(),
        change_type: RouteChangeType::OriginChange,
        old_asn: Some(50),
        new_asn: 100,
        old_path: vec![200, 50],
        new_path: vec![200, 100],
        timestamp: "2024-01-01".to_string(),
        source: BgpSource::RipeRis,
    }];
    let reuse = vec![IpReuseRecord {
        ip_prefix: "10.0.0.0/8".to_string(),
        historical_owners: vec![(50, "2020".into()), (100, "2024".into())],
        current_owner: Some(100),
        owner_changes: 1,
        risk: BgpRisk::Low,
    }];

    let report = build_bgp_report(
        vec!["10.0.0.0/8".to_string()],
        vec![AutonomousSystem {
            asn: 100,
            name: Some("TestAS".to_string()),
            country: Some("US".to_string()),
            description: None,
            prefix_count: 10,
        }],
        prefixes,
        changes,
        reuse,
    );
    assert_eq!(report.total_prefixes, 1);
    assert_eq!(report.total_changes, 1);
    assert_eq!(report.path_analyses.len(), 1);
    assert!(!report.risk_summary.is_empty());
}

#[test]
fn bgp_source_display() {
    assert_eq!(BgpSource::RipeRis.to_string(), "RIPE RIS");
    assert_eq!(BgpSource::RouteViews.to_string(), "RouteViews");
}

#[test]
fn route_change_type_display() {
    assert_eq!(RouteChangeType::Hijack.to_string(), "Possible Hijack");
    assert_eq!(RouteChangeType::OriginChange.to_string(), "Origin Change");
}

#[test]
fn bgp_risk_ordering() {
    assert!(BgpRisk::Critical > BgpRisk::High);
    assert!(BgpRisk::High > BgpRisk::Medium);
    assert!(BgpRisk::Medium > BgpRisk::Low);
}
