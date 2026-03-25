use super::temporal_correlator::*;

#[test]
fn test_artifact_type_display() {
    assert_eq!(ArtifactType::Domain.to_string(), "Domain");
    assert_eq!(ArtifactType::IpAddress.to_string(), "IP Address");
    assert_eq!(ArtifactType::Certificate.to_string(), "Certificate");
    assert_eq!(ArtifactType::Asn.to_string(), "ASN");
    assert_eq!(ArtifactType::Nameserver.to_string(), "Nameserver");
    assert_eq!(ArtifactType::SubnetBlock.to_string(), "Subnet Block");
}

#[test]
fn test_data_source_display() {
    assert_eq!(DataSource::DnsHistory.to_string(), "DNS History");
    assert_eq!(DataSource::CertificateTransparency.to_string(), "CT Log");
    assert_eq!(DataSource::BgpAnnouncement.to_string(), "BGP Announcement");
}

#[test]
fn test_correlation_confidence_ordering() {
    assert!(CorrelationConfidence::Low < CorrelationConfidence::Medium);
    assert!(CorrelationConfidence::Medium < CorrelationConfidence::High);
    assert!(CorrelationConfidence::High < CorrelationConfidence::Definitive);
}

#[test]
fn test_default_config() {
    let config = CorrelatorConfig::default();
    assert_eq!(config.max_temporal_gap_ms, 7 * 24 * 3600 * 1000);
    assert_eq!(config.subnet_mask_bits, 24);
    assert_eq!(config.min_co_occurrence_count, 2);
    assert_eq!(config.sequential_registration_window_ms, 72 * 3600 * 1000);
}

#[test]
fn test_config_builder() {
    let config = CorrelatorConfig::default()
        .with_max_temporal_gap_ms(1_000_000)
        .with_subnet_mask_bits(16)
        .with_min_co_occurrence_count(3)
        .with_sequential_registration_window_ms(48 * 3600 * 1000);
    assert_eq!(config.max_temporal_gap_ms, 1_000_000);
    assert_eq!(config.subnet_mask_bits, 16);
    assert_eq!(config.min_co_occurrence_count, 3);
    assert_eq!(config.sequential_registration_window_ms, 48 * 3600 * 1000);
}

#[test]
fn test_subnet_mask_bits_clamped() {
    let config = CorrelatorConfig::default().with_subnet_mask_bits(64);
    assert_eq!(config.subnet_mask_bits, 32);
}

#[test]
fn test_min_co_occurrence_floor() {
    let config = CorrelatorConfig::default().with_min_co_occurrence_count(0);
    assert_eq!(config.min_co_occurrence_count, 1);
}

#[test]
fn test_ingest_dns_records() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let records = vec![
        DnsRecord {
            domain: "evil.com".to_string(),
            resolved_ip: "1.2.3.4".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 1000,
            source: DataSource::DnsHistory,
        },
        DnsRecord {
            domain: "evil.com".to_string(),
            resolved_ip: "5.6.7.8".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 2000,
            source: DataSource::DnsHistory,
        },
    ];
    correlator.ingest_dns_records(&records);

    assert_eq!(correlator.artifacts().len(), 3);
    assert_eq!(correlator.edges().len(), 2);

    let domain = correlator
        .artifacts()
        .iter()
        .find(|a| a.value == "evil.com")
        .unwrap();
    assert_eq!(domain.artifact_type, ArtifactType::Domain);
    assert_eq!(domain.first_seen_ms, 1000);
    assert_eq!(domain.last_seen_ms, 2000);
}

#[test]
fn test_ingest_whois_snapshots() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let snapshots = vec![WhoisSnapshot {
        domain: "malware.net".to_string(),
        registrar: "ShadyRegistrar Inc".to_string(),
        registrant_org: Some("Shell Corp LLC".to_string()),
        nameservers: vec![
            "ns1.dns-host.com".to_string(),
            "ns2.dns-host.com".to_string(),
        ],
        creation_date_ms: 5000,
        expiry_date_ms: 100_000,
        snapshot_timestamp_ms: 10_000,
    }];
    correlator.ingest_whois_snapshots(&snapshots);

    assert_eq!(correlator.artifacts().len(), 5);
    let registrar = correlator
        .artifacts()
        .iter()
        .find(|a| a.artifact_type == ArtifactType::Registrar)
        .unwrap();
    assert_eq!(registrar.value, "ShadyRegistrar Inc");
}

#[test]
fn test_ingest_ct_logs() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let entries = vec![CtLogEntry {
        fingerprint: "abc123def456".to_string(),
        domains: vec!["site-a.com".to_string(), "site-b.com".to_string()],
        issuer: "Let's Encrypt".to_string(),
        not_before_ms: 1000,
        not_after_ms: 90_000,
        log_timestamp_ms: 1500,
    }];
    correlator.ingest_ct_logs(&entries);

    assert_eq!(correlator.artifacts().len(), 3);
    let cert_edges: Vec<_> = correlator
        .edges()
        .iter()
        .filter(|e| e.relationship == TemporalRelationship::SharedCertificate)
        .collect();
    assert_eq!(cert_edges.len(), 2);
}

#[test]
fn test_ingest_bgp_announcements() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let announcements = vec![BgpAnnouncement {
        prefix: "192.168.0.0/16".to_string(),
        asn: 64512,
        as_name: Some("Evil ISP".to_string()),
        first_seen_ms: 1000,
        last_seen_ms: 50_000,
    }];
    correlator.ingest_bgp_announcements(&announcements);

    assert_eq!(correlator.artifacts().len(), 2);
    let asn = correlator
        .artifacts()
        .iter()
        .find(|a| a.artifact_type == ArtifactType::Asn)
        .unwrap();
    assert_eq!(asn.value, "AS64512");
}

#[test]
fn test_detect_sequential_registrations() {
    let config =
        CorrelatorConfig::default().with_sequential_registration_window_ms(48 * 3600 * 1000);
    let mut correlator = TemporalCorrelator::new(config);
    let hour = 3600 * 1000_u64;
    let snapshots = vec![
        WhoisSnapshot {
            domain: "c2-alpha.com".to_string(),
            registrar: "Reg A".to_string(),
            registrant_org: None,
            nameservers: vec![],
            creation_date_ms: 1000,
            expiry_date_ms: 100_000,
            snapshot_timestamp_ms: 1000,
        },
        WhoisSnapshot {
            domain: "c2-bravo.com".to_string(),
            registrar: "Reg B".to_string(),
            registrant_org: None,
            nameservers: vec![],
            creation_date_ms: 1000 + 12 * hour,
            expiry_date_ms: 200_000,
            snapshot_timestamp_ms: 1000 + 12 * hour,
        },
    ];
    correlator.ingest_whois_snapshots(&snapshots);
    let result = correlator.correlate();

    let seq_edges: Vec<_> = result
        .edges
        .iter()
        .filter(|e| e.relationship == TemporalRelationship::SequentialRegistration)
        .collect();
    assert!(
        !seq_edges.is_empty(),
        "Should detect sequential registrations"
    );
}

#[test]
fn test_detect_domain_rotation_pattern() {
    let config =
        CorrelatorConfig::default().with_sequential_registration_window_ms(72 * 3600 * 1000);
    let mut correlator = TemporalCorrelator::new(config);
    let hour = 3600 * 1000_u64;

    let snapshots = vec![
        WhoisSnapshot {
            domain: "rotate-1.com".to_string(),
            registrar: "Reg X".to_string(),
            registrant_org: None,
            nameservers: vec!["ns.shared.com".to_string()],
            creation_date_ms: 1000,
            expiry_date_ms: 1_000_000,
            snapshot_timestamp_ms: 1000,
        },
        WhoisSnapshot {
            domain: "rotate-2.com".to_string(),
            registrar: "Reg X".to_string(),
            registrant_org: None,
            nameservers: vec!["ns.shared.com".to_string()],
            creation_date_ms: 1000 + 24 * hour,
            expiry_date_ms: 1_000_000,
            snapshot_timestamp_ms: 1000 + 24 * hour,
        },
        WhoisSnapshot {
            domain: "rotate-3.com".to_string(),
            registrar: "Reg X".to_string(),
            registrant_org: None,
            nameservers: vec!["ns.shared.com".to_string()],
            creation_date_ms: 1000 + 48 * hour,
            expiry_date_ms: 1_000_000,
            snapshot_timestamp_ms: 1000 + 48 * hour,
        },
    ];
    correlator.ingest_whois_snapshots(&snapshots);
    let result = correlator.correlate();

    let rotation = result
        .patterns
        .iter()
        .find(|p| p.pattern_type == ReusePatternType::DomainRotation);
    assert!(rotation.is_some(), "Should detect domain rotation pattern");
    let rotation = rotation.unwrap();
    assert!(rotation.involved_artifacts.len() >= 2);
}

#[test]
fn test_detect_nameserver_pivot_pattern() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());

    let snapshots = vec![
        WhoisSnapshot {
            domain: "ns-pivot-a.com".to_string(),
            registrar: "Reg A".to_string(),
            registrant_org: None,
            nameservers: vec!["ns.evil-dns.org".to_string()],
            creation_date_ms: 1000,
            expiry_date_ms: 500_000,
            snapshot_timestamp_ms: 1000,
        },
        WhoisSnapshot {
            domain: "ns-pivot-b.com".to_string(),
            registrar: "Reg B".to_string(),
            registrant_org: None,
            nameservers: vec!["ns.evil-dns.org".to_string()],
            creation_date_ms: 2000,
            expiry_date_ms: 600_000,
            snapshot_timestamp_ms: 2000,
        },
    ];
    correlator.ingest_whois_snapshots(&snapshots);
    let result = correlator.correlate();

    let ns_pivot = result
        .patterns
        .iter()
        .find(|p| p.pattern_type == ReusePatternType::NameserverPivot);
    assert!(ns_pivot.is_some(), "Should detect nameserver pivot pattern");
}

#[test]
fn test_detect_subnet_reuse() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let records = vec![
        DnsRecord {
            domain: "site-a.com".to_string(),
            resolved_ip: "10.0.1.5".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 1000,
            source: DataSource::DnsHistory,
        },
        DnsRecord {
            domain: "site-a.com".to_string(),
            resolved_ip: "10.0.1.5".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 5000,
            source: DataSource::PassiveDns,
        },
        DnsRecord {
            domain: "site-b.com".to_string(),
            resolved_ip: "10.0.1.200".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 1500,
            source: DataSource::DnsHistory,
        },
        DnsRecord {
            domain: "site-b.com".to_string(),
            resolved_ip: "10.0.1.200".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 4000,
            source: DataSource::PassiveDns,
        },
    ];
    correlator.ingest_dns_records(&records);
    let result = correlator.correlate();

    let subnet_edges: Vec<_> = result
        .edges
        .iter()
        .filter(|e| e.relationship == TemporalRelationship::SameSubnet)
        .collect();
    assert!(!subnet_edges.is_empty(), "Should detect same /24 subnet");
}

#[test]
fn test_detect_ip_reuse_across_domains() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let records = vec![
        DnsRecord {
            domain: "old-c2.com".to_string(),
            resolved_ip: "8.8.8.8".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 1000,
            source: DataSource::DnsHistory,
        },
        DnsRecord {
            domain: "new-c2.com".to_string(),
            resolved_ip: "8.8.8.8".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 5000,
            source: DataSource::DnsHistory,
        },
    ];
    correlator.ingest_dns_records(&records);
    let result = correlator.correlate();

    let reuse_edges: Vec<_> = result
        .edges
        .iter()
        .filter(|e| e.relationship == TemporalRelationship::IpReuse)
        .collect();
    assert!(
        !reuse_edges.is_empty(),
        "Should detect IP reuse across domains"
    );
}

#[test]
fn test_full_correlation_pipeline() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let hour = 3600 * 1000_u64;

    correlator.ingest_dns_records(&[
        DnsRecord {
            domain: "target.com".to_string(),
            resolved_ip: "192.168.1.10".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 1000,
            source: DataSource::DnsHistory,
        },
        DnsRecord {
            domain: "target.com".to_string(),
            resolved_ip: "192.168.1.20".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 50_000,
            source: DataSource::PassiveDns,
        },
    ]);

    correlator.ingest_whois_snapshots(&[WhoisSnapshot {
        domain: "target.com".to_string(),
        registrar: "GoDaddy".to_string(),
        registrant_org: Some("Target Corp".to_string()),
        nameservers: vec!["ns1.target.com".to_string()],
        creation_date_ms: 500,
        expiry_date_ms: 1_000_000,
        snapshot_timestamp_ms: 1000,
    }]);

    correlator.ingest_ct_logs(&[CtLogEntry {
        fingerprint: "cert-target-001".to_string(),
        domains: vec!["target.com".to_string(), "www.target.com".to_string()],
        issuer: "Let's Encrypt".to_string(),
        not_before_ms: 800,
        not_after_ms: 800 + 90 * 24 * hour,
        log_timestamp_ms: 900,
    }]);

    correlator.ingest_bgp_announcements(&[BgpAnnouncement {
        prefix: "192.168.1.0/24".to_string(),
        asn: 12345,
        as_name: Some("Target ISP".to_string()),
        first_seen_ms: 500,
        last_seen_ms: 200_000,
    }]);

    let result = correlator.correlate();
    assert!(!result.artifacts.is_empty());
    assert!(!result.edges.is_empty());
    assert!(result.timeline_span_ms > 0);
}

#[test]
fn test_empty_correlator() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let result = correlator.correlate();
    assert!(result.artifacts.is_empty());
    assert!(result.edges.is_empty());
    assert!(result.patterns.is_empty());
    assert_eq!(result.timeline_span_ms, 0);
}

#[test]
fn test_artifact_deduplication() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let records = vec![
        DnsRecord {
            domain: "dedup.com".to_string(),
            resolved_ip: "1.1.1.1".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 1000,
            source: DataSource::DnsHistory,
        },
        DnsRecord {
            domain: "dedup.com".to_string(),
            resolved_ip: "1.1.1.1".to_string(),
            record_type: "A".to_string(),
            timestamp_ms: 5000,
            source: DataSource::PassiveDns,
        },
    ];
    correlator.ingest_dns_records(&records);

    assert_eq!(correlator.artifacts().len(), 2);
    let domain = correlator
        .artifacts()
        .iter()
        .find(|a| a.value == "dedup.com")
        .unwrap();
    assert_eq!(domain.first_seen_ms, 1000);
    assert_eq!(domain.last_seen_ms, 5000);
    assert_eq!(domain.sources.len(), 2);
}

#[test]
fn test_registrar_clustering_pattern() {
    let mut correlator = TemporalCorrelator::new(CorrelatorConfig::default());
    let snapshots = vec![
        WhoisSnapshot {
            domain: "cluster-1.com".to_string(),
            registrar: "BulletProof Hosting".to_string(),
            registrant_org: None,
            nameservers: vec![],
            creation_date_ms: 1000,
            expiry_date_ms: 500_000,
            snapshot_timestamp_ms: 1000,
        },
        WhoisSnapshot {
            domain: "cluster-2.com".to_string(),
            registrar: "BulletProof Hosting".to_string(),
            registrant_org: None,
            nameservers: vec![],
            creation_date_ms: 2000,
            expiry_date_ms: 600_000,
            snapshot_timestamp_ms: 2000,
        },
    ];
    correlator.ingest_whois_snapshots(&snapshots);
    let result = correlator.correlate();

    let clustering = result
        .patterns
        .iter()
        .find(|p| p.pattern_type == ReusePatternType::RegistrarClustering);
    assert!(
        clustering.is_some(),
        "Should detect registrar clustering pattern"
    );
}

#[test]
fn test_temporal_relationship_display() {
    assert_eq!(TemporalRelationship::ResolvedTo.to_string(), "Resolved To");
    assert_eq!(
        TemporalRelationship::SharedCertificate.to_string(),
        "Shared Certificate"
    );
    assert_eq!(TemporalRelationship::SameAsn.to_string(), "Same ASN");
    assert_eq!(
        TemporalRelationship::SequentialRegistration.to_string(),
        "Sequential Registration"
    );
    assert_eq!(TemporalRelationship::IpReuse.to_string(), "IP Reuse");
}

#[test]
fn test_reuse_pattern_type_display() {
    assert_eq!(
        ReusePatternType::DomainRotation.to_string(),
        "Domain Rotation"
    );
    assert_eq!(ReusePatternType::IpRecycling.to_string(), "IP Recycling");
    assert_eq!(
        ReusePatternType::ShadowInfrastructure.to_string(),
        "Shadow Infrastructure"
    );
}
