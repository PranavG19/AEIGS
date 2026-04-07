use super::org_mapper::*;

#[test]
fn test_extract_base_domain_simple() {
    assert_eq!(extract_base_domain("www.example.com"), "example.com");
}

#[test]
fn test_extract_base_domain_wildcard() {
    assert_eq!(extract_base_domain("*.example.com"), "example.com");
}

#[test]
fn test_extract_base_domain_deep_subdomain() {
    assert_eq!(extract_base_domain("a.b.c.example.com"), "example.com");
}

#[test]
fn test_extract_base_domain_already_base() {
    assert_eq!(extract_base_domain("example.com"), "example.com");
}

#[test]
fn test_enumerate_domains_from_ct() {
    let entries = vec![
        ("*.example.com", "Let's Encrypt", "2024-01-01"),
        ("api.example.com", "DigiCert", "2024-02-01"),
        ("*.other.org", "Cloudflare", "2024-03-01"),
    ];
    let domains = enumerate_domains_from_ct(&entries);
    assert_eq!(domains.len(), 2);
    assert_eq!(domains[0].domain, "example.com");
    assert_eq!(domains[1].domain, "other.org");
    assert!(domains[0].confidence > 0.9);
}

#[test]
fn test_enumerate_domains_dedup() {
    let entries = vec![
        ("a.test.com", "Let's Encrypt", "2024-01-01"),
        ("b.test.com", "Let's Encrypt", "2024-01-02"),
        ("c.test.com", "Let's Encrypt", "2024-01-03"),
    ];
    let domains = enumerate_domains_from_ct(&entries);
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "test.com");
}

#[test]
fn test_enumerate_domains_ct_confidence_varies() {
    let entries = vec![
        ("a.high.com", "Let's Encrypt Authority", "2024-01-01"),
        ("b.med.com", "Unknown CA", "2024-01-01"),
    ];
    let domains = enumerate_domains_from_ct(&entries);
    assert!(domains[0].confidence > domains[1].confidence);
}

#[test]
fn test_map_ip_ranges() {
    let asn_entries = vec![
        (13335, "104.16.0.0/12", "Cloudflare Inc", "US", 1048576),
        (15169, "8.8.8.0/24", "Google LLC", "US", 256),
    ];
    let ranges = map_ip_ranges(&asn_entries);
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].cidr, "104.16.0.0/12");
    assert_eq!(ranges[0].asn, Some(13335));
    assert_eq!(ranges[0].num_hosts, 1048576);
    assert_eq!(ranges[1].as_name, Some("Google LLC".to_string()));
}

#[test]
fn test_parse_bgp_prefixes() {
    let raw = vec![
        ("192.168.0.0/16", 64512_u32, "Private AS", true),
        ("10.0.0.0/8", 64513, "Internal AS", false),
    ];
    let prefixes = parse_bgp_prefixes(&raw);
    assert_eq!(prefixes.len(), 2);
    assert!(prefixes[0].announced);
    assert!(!prefixes[1].announced);
    assert_eq!(prefixes[0].asn, 64512);
}

#[test]
fn test_discover_email_format_first_dot_last() {
    let emails = vec![
        "john.doe@acme.com",
        "jane.smith@acme.com",
        "bob.jones@acme.com",
    ];
    let fmt = discover_email_format(&emails, "acme.com");
    assert_eq!(fmt, Some("first.last".to_string()));
}

#[test]
fn test_discover_email_format_underscore() {
    let emails = vec!["john_doe@test.org", "jane_smith@test.org"];
    let fmt = discover_email_format(&emails, "test.org");
    assert_eq!(fmt, Some("first_last".to_string()));
}

#[test]
fn test_discover_email_format_no_match() {
    let emails = vec!["john@other.com"];
    let fmt = discover_email_format(&emails, "acme.com");
    assert!(fmt.is_none());
}

#[test]
fn test_discover_email_format_empty() {
    let fmt = discover_email_format(&[], "acme.com");
    assert!(fmt.is_none());
}

#[test]
fn test_extract_tech_from_job_postings() {
    let postings = vec![
        "We're looking for a Python engineer with experience in Django and PostgreSQL. AWS required.",
        "Senior Python developer. Must know Docker, Kubernetes, and React.",
        "Full stack engineer: TypeScript, React, PostgreSQL, AWS.",
    ];
    let stack = extract_tech_from_job_postings(&postings);
    assert!(!stack.is_empty());
    let tech_names: Vec<_> = stack.iter().map(|t| t.technology.as_str()).collect();
    assert!(tech_names.contains(&"python"));
    assert!(tech_names.contains(&"react"));
    assert!(tech_names.contains(&"aws"));
}

#[test]
fn test_extract_tech_from_job_postings_confidence() {
    let postings = vec!["Python Django AWS", "Python Flask AWS", "Python React AWS"];
    let stack = extract_tech_from_job_postings(&postings);
    let python = stack.iter().find(|t| t.technology == "python").unwrap();
    assert!((python.confidence - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_extract_tech_sorted_by_confidence() {
    let postings = vec![
        "Python AWS Docker Redis Kafka",
        "Python AWS Docker",
        "Python AWS",
    ];
    let stack = extract_tech_from_job_postings(&postings);
    for i in 1..stack.len() {
        assert!(stack[i - 1].confidence >= stack[i].confidence);
    }
}

#[test]
fn test_extract_tech_evidence_type() {
    let postings = vec!["We use Rust and PostgreSQL"];
    let stack = extract_tech_from_job_postings(&postings);
    for item in &stack {
        assert_eq!(item.evidence[0].source_type, TechEvidenceType::JobPosting);
    }
}

#[test]
fn test_detect_vendors_from_dns_mx_google() {
    let vendors = detect_vendors_from_dns(
        &["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
        None,
        &[],
    );
    assert!(vendors.iter().any(|v| v.vendor_name == "Google Workspace"));
    assert!(vendors
        .iter()
        .all(|v| v.service_type == VendorServiceType::EmailProvider));
}

#[test]
fn test_detect_vendors_from_dns_spf() {
    let vendors = detect_vendors_from_dns(
        &[],
        Some("v=spf1 include:_spf.google.com include:sendgrid.net ~all"),
        &[],
    );
    assert!(vendors.iter().any(|v| v.vendor_name == "Google Workspace"));
    assert!(vendors.iter().any(|v| v.vendor_name == "SendGrid"));
}

#[test]
fn test_detect_vendors_from_dns_cname() {
    let vendors = detect_vendors_from_dns(
        &[],
        None,
        &[
            ("cdn.example.com", "d123.cloudfront.net"),
            ("auth.example.com", "login.auth0.com"),
        ],
    );
    assert!(vendors.iter().any(|v| v.vendor_name == "AWS CloudFront"));
    assert!(vendors.iter().any(|v| v.vendor_name == "Auth0"));
}

#[test]
fn test_detect_vendors_from_dns_combined() {
    let vendors = detect_vendors_from_dns(
        &["mail.protonmail.ch"],
        Some("v=spf1 include:spf.protection.outlook.com ~all"),
        &[("app.example.com", "cname.vercel-dns.com")],
    );
    assert!(vendors.len() >= 3);
}

#[test]
fn test_detect_vendors_from_js() {
    let urls = vec![
        "https://www.google-analytics.com/analytics.js",
        "https://js.stripe.com/v3/",
        "https://cdn.segment.com/analytics.js/v1/key/analytics.min.js",
        "https://widget.intercom.io/widget/abc",
    ];
    let vendors = detect_vendors_from_js(&urls);
    assert_eq!(vendors.len(), 4);
    assert!(vendors.iter().any(|v| v.vendor_name == "Google Analytics"));
    assert!(vendors.iter().any(|v| v.vendor_name == "Stripe"));
    assert!(vendors.iter().any(|v| v.vendor_name == "Segment"));
    assert!(vendors.iter().any(|v| v.vendor_name == "Intercom"));
}

#[test]
fn test_detect_vendors_from_js_dedup() {
    let urls = vec![
        "https://www.google-analytics.com/analytics.js",
        "https://www.google-analytics.com/ga.js",
    ];
    let vendors = detect_vendors_from_js(&urls);
    assert_eq!(vendors.len(), 1);
}

#[test]
fn test_identify_subsidiaries_shared_ns() {
    let shared_ns: Vec<(&str, &[&str])> = vec![("SubCo", &["ns1.example.com", "ns2.example.com"])];
    let subs = identify_subsidiaries(&shared_ns, &[], &[]);
    assert_eq!(subs.len(), 1);
    assert_eq!(
        subs[0].relationship,
        SubsidiaryRelationship::SharedInfrastructure
    );
}

#[test]
fn test_identify_subsidiaries_known_acquisition() {
    let subs = identify_subsidiaries(&[], &[], &[("TargetCo", "acquisition", Some("2023-06"))]);
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].relationship, SubsidiaryRelationship::Acquisition);
    assert!(subs[0].confidence > 0.85);
}

#[test]
fn test_identify_subsidiaries_combined() {
    let shared_ns: Vec<(&str, &[&str])> = vec![("SubCo", &["ns1.parent.com"])];
    let shared_asn = vec![("SubCo", 12345_u32)];
    let acquisitions = vec![("SubCo", "acquisition", Some("2024-01"))];
    let subs = identify_subsidiaries(&shared_ns, &shared_asn, &acquisitions);
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].relationship, SubsidiaryRelationship::Acquisition);
}

#[test]
fn test_assess_ma_security_acquisition() {
    let events = vec![("TargetCo", "acquisition", Some("2023-06"))];
    let ma_events = assess_ma_security(&events);
    assert_eq!(ma_events.len(), 1);
    assert_eq!(ma_events[0].event_type, MaEventType::Acquisition);
    assert!(ma_events[0].security_implications.len() >= 3);
    assert!(ma_events[0].risk_score > 0.7);
}

#[test]
fn test_assess_ma_security_merger() {
    let events = vec![("MergeCo", "merger", None)];
    let ma_events = assess_ma_security(&events);
    assert_eq!(ma_events[0].event_type, MaEventType::Merger);
    assert!(ma_events[0].date.is_none());
}

#[test]
fn test_assess_ma_security_divestiture() {
    let events = vec![("SpunOff", "divestiture", Some("2024-01"))];
    let ma_events = assess_ma_security(&events);
    assert_eq!(ma_events[0].event_type, MaEventType::Divestiture);
    assert!(ma_events[0]
        .security_implications
        .iter()
        .any(|s| s.contains("credential")));
}

#[test]
fn test_build_org_footprint() {
    let footprint = build_org_footprint(
        "example.com",
        vec![OwnedDomain {
            domain: "example.com".to_string(),
            registrar: None,
            registration_date: None,
            expiry_date: None,
            nameservers: vec![],
            source: DomainSource::Manual,
            confidence: 1.0,
        }],
        vec![IpRange {
            cidr: "1.2.3.0/24".to_string(),
            asn: Some(12345),
            as_name: Some("Test".to_string()),
            country: Some("US".to_string()),
            num_hosts: 256,
        }],
        vec![],
        vec![OrgEmployee {
            name: "John".to_string(),
            title: None,
            department: None,
            email: None,
            source: EmployeeSource::LinkedIn,
            confidence: 0.9,
        }],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        Some("first.last".to_string()),
    );
    assert_eq!(footprint.primary_domain, "example.com");
    assert!(footprint.total_exposure_score > 0.0);
    assert_eq!(footprint.email_format, Some("first.last".to_string()));
}

#[test]
fn test_build_org_footprint_empty() {
    let footprint = build_org_footprint(
        "empty.com",
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        None,
    );
    assert!((footprint.total_exposure_score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_domain_source_display() {
    assert_eq!(DomainSource::ReverseWhois.to_string(), "Reverse WHOIS");
    assert_eq!(
        DomainSource::CertificateTransparency.to_string(),
        "Certificate Transparency"
    );
}

#[test]
fn test_employee_source_display() {
    assert_eq!(EmployeeSource::LinkedIn.to_string(), "LinkedIn");
    assert_eq!(EmployeeSource::GitHubOrg.to_string(), "GitHub Org");
}

#[test]
fn test_tech_category_display() {
    assert_eq!(TechCategory::Container.to_string(), "Container");
    assert_eq!(TechCategory::MessageQueue.to_string(), "Message Queue");
}

#[test]
fn test_vendor_service_type_display() {
    assert_eq!(VendorServiceType::CdnProvider.to_string(), "CDN Provider");
    assert_eq!(
        VendorServiceType::PaymentProcessor.to_string(),
        "Payment Processor"
    );
}

#[test]
fn test_subsidiary_relationship_display() {
    assert_eq!(
        SubsidiaryRelationship::Acquisition.to_string(),
        "Acquisition"
    );
    assert_eq!(
        SubsidiaryRelationship::SharedInfrastructure.to_string(),
        "Shared Infrastructure"
    );
}

#[test]
fn test_ma_event_type_display() {
    assert_eq!(MaEventType::SpinOff.to_string(), "Spin-off");
    assert_eq!(MaEventType::Divestiture.to_string(), "Divestiture");
}

#[test]
fn test_tech_evidence_type_display() {
    assert_eq!(TechEvidenceType::JobPosting.to_string(), "Job Posting");
    assert_eq!(TechEvidenceType::JsInclude.to_string(), "JS Include");
}
