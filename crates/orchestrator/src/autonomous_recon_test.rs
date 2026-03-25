use super::*;
use std::collections::HashSet;

fn make_finding(id: u64, ftype: FindingType, value: &str, source: IntelSource) -> IntelFinding {
    IntelFinding {
        id,
        finding_type: ftype,
        value: value.to_string(),
        source,
        confidence: 0.85,
        timestamp_ms: 1000,
        parent_id: None,
        metadata: HashMap::new(),
    }
}

#[test]
fn recon_phase_display() {
    assert_eq!(ReconPhase::Discover.to_string(), "Discover");
    assert_eq!(ReconPhase::Enumerate.to_string(), "Enumerate");
    assert_eq!(ReconPhase::Correlate.to_string(), "Correlate");
    assert_eq!(ReconPhase::Assess.to_string(), "Assess");
    assert_eq!(ReconPhase::Report.to_string(), "Report");
}

#[test]
fn recon_phase_cycle() {
    let mut phase = ReconPhase::Discover;
    phase = phase.next();
    assert_eq!(phase, ReconPhase::Enumerate);
    phase = phase.next();
    assert_eq!(phase, ReconPhase::Correlate);
    phase = phase.next();
    assert_eq!(phase, ReconPhase::Assess);
    phase = phase.next();
    assert_eq!(phase, ReconPhase::Report);
    phase = phase.next();
    assert_eq!(phase, ReconPhase::Discover);
}

#[test]
fn intel_source_display() {
    assert_eq!(IntelSource::WebSearch.to_string(), "Web Search");
    assert_eq!(IntelSource::Dns.to_string(), "DNS");
    assert_eq!(
        IntelSource::CertificateTransparency.to_string(),
        "Certificate Transparency"
    );
}

#[test]
fn default_config() {
    let cfg = ReconConfig::default();
    assert_eq!(cfg.max_iterations, 10);
    assert_eq!(cfg.convergence_threshold, 3);
    assert_eq!(cfg.max_findings, 500);
    assert!(cfg.enabled_sources.contains(&IntelSource::WebSearch));
    assert!(cfg.enabled_sources.contains(&IntelSource::Dns));
}

#[test]
fn config_builder_pattern() {
    let cfg = ReconConfig::default()
        .with_target("example.com")
        .with_max_iterations(5)
        .with_convergence_threshold(2)
        .with_all_sources();
    assert_eq!(cfg.target, "example.com");
    assert_eq!(cfg.max_iterations, 5);
    assert_eq!(cfg.convergence_threshold, 2);
    assert!(cfg.enabled_sources.contains(&IntelSource::DarkWeb));
    assert!(cfg.enabled_sources.contains(&IntelSource::JobPostings));
}

#[test]
fn controller_initial_state() {
    let cfg = ReconConfig::default().with_target("example.com");
    let ctrl = AutonomousReconController::new(cfg);
    assert_eq!(ctrl.phase(), ReconPhase::Discover);
    assert_eq!(ctrl.iteration(), 0);
    assert_eq!(ctrl.finding_count(), 0);
    assert!(!ctrl.has_converged());
    assert!(!ctrl.is_complete());
}

#[test]
fn controller_ingest_deduplicates() {
    let cfg = ReconConfig::default().with_target("example.com");
    let mut ctrl = AutonomousReconController::new(cfg);

    let f1 = make_finding(0, FindingType::Domain, "sub.example.com", IntelSource::Dns);
    let f2 = make_finding(0, FindingType::Domain, "sub.example.com", IntelSource::Dns);
    let f3 = make_finding(0, FindingType::IpAddress, "1.2.3.4", IntelSource::WebSearch);

    let new_count = ctrl.ingest_findings(vec![f1, f2, f3]);
    assert_eq!(new_count, 2);
    assert_eq!(ctrl.finding_count(), 2);
    assert_eq!(ctrl.findings()[0].id, 1);
    assert_eq!(ctrl.findings()[1].id, 2);
}

#[test]
fn controller_convergence_detection() {
    let cfg = ReconConfig::default()
        .with_target("example.com")
        .with_convergence_threshold(2);
    let mut ctrl = AutonomousReconController::new(cfg);

    ctrl.ingest_findings(vec![]);
    assert!(!ctrl.has_converged());
    ctrl.ingest_findings(vec![]);
    assert!(ctrl.has_converged());
    assert!(ctrl.is_complete());
}

#[test]
fn controller_convergence_resets_on_new_findings() {
    let cfg = ReconConfig::default()
        .with_target("example.com")
        .with_convergence_threshold(3);
    let mut ctrl = AutonomousReconController::new(cfg);

    ctrl.ingest_findings(vec![]);
    ctrl.ingest_findings(vec![]);

    let f = make_finding(0, FindingType::Domain, "new.example.com", IntelSource::Dns);
    ctrl.ingest_findings(vec![f]);
    assert!(!ctrl.has_converged());
}

#[test]
fn controller_max_findings_limit() {
    let mut cfg = ReconConfig::default().with_target("example.com");
    cfg.max_findings = 3;
    let mut ctrl = AutonomousReconController::new(cfg);

    let findings: Vec<IntelFinding> = (0..5)
        .map(|i| {
            make_finding(
                0,
                FindingType::IpAddress,
                &format!("10.0.0.{i}"),
                IntelSource::Dns,
            )
        })
        .collect();
    let new_count = ctrl.ingest_findings(findings);
    assert_eq!(new_count, 3);
    assert_eq!(ctrl.finding_count(), 3);
}

#[test]
fn controller_max_iterations_complete() {
    let cfg = ReconConfig::default()
        .with_target("example.com")
        .with_max_iterations(2);
    let mut ctrl = AutonomousReconController::new(cfg);

    for _ in 0..10 {
        ctrl.advance_phase();
    }
    assert!(ctrl.iteration() >= 2);
    assert!(ctrl.is_complete());
}

#[test]
fn controller_advance_phase_tracks_duration() {
    let cfg = ReconConfig::default().with_target("example.com");
    let mut ctrl = AutonomousReconController::new(cfg);

    assert_eq!(ctrl.phase(), ReconPhase::Discover);
    ctrl.advance_phase();
    assert_eq!(ctrl.phase(), ReconPhase::Enumerate);
    assert!(ctrl.phase_durations_ms.contains_key("Discover"));
}

#[test]
fn controller_run_cycle_with() {
    let cfg = ReconConfig::default()
        .with_target("example.com")
        .with_all_sources();
    let mut ctrl = AutonomousReconController::new(cfg);

    let total = ctrl.run_cycle_with(|_target, _queries| {
        vec![make_finding(
            0,
            FindingType::Domain,
            &format!("sub-{}.example.com", rand::random::<u32>()),
            IntelSource::Dns,
        )]
    });
    assert!(total > 0);
    assert_eq!(ctrl.phase(), ReconPhase::Discover);
    assert_eq!(ctrl.iteration(), 1);
}

#[test]
fn parse_recon_queries_valid_xml() {
    let response = r#"
        <query source="WebSearch" priority="0.9">
            <text>site:example.com filetype:pdf</text>
            <rationale>Find public PDF documents</rationale>
        </query>
        <query source="Dns" priority="0.8">
            <text>example.com</text>
            <rationale>Enumerate DNS records</rationale>
        </query>
    "#;
    let queries = parse_recon_queries(response);
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[0].priority, 0.9);
    assert_eq!(queries[0].source, IntelSource::WebSearch);
    assert_eq!(queries[0].query_text, "site:example.com filetype:pdf");
    assert_eq!(queries[1].source, IntelSource::Dns);
}

#[test]
fn parse_recon_queries_clamps_priority() {
    let response = r#"
        <query source="WebSearch" priority="1.5">
            <text>test</text>
            <rationale>Over limit</rationale>
        </query>
    "#;
    let queries = parse_recon_queries(response);
    assert_eq!(queries[0].priority, 1.0);
}

#[test]
fn parse_recon_queries_invalid_source_skipped() {
    let response = r#"
        <query source="InvalidSource" priority="0.5">
            <text>test</text>
            <rationale>Bad source</rationale>
        </query>
    "#;
    let queries = parse_recon_queries(response);
    assert!(queries.is_empty());
}

#[test]
fn parse_recon_queries_empty_response() {
    let queries = parse_recon_queries("");
    assert!(queries.is_empty());
}

#[test]
fn parse_recon_queries_sorted_by_priority() {
    let response = r#"
        <query source="Dns" priority="0.3">
            <text>low</text>
            <rationale>Low</rationale>
        </query>
        <query source="WebSearch" priority="0.9">
            <text>high</text>
            <rationale>High</rationale>
        </query>
        <query source="Whois" priority="0.6">
            <text>mid</text>
            <rationale>Mid</rationale>
        </query>
    "#;
    let queries = parse_recon_queries(response);
    assert_eq!(queries.len(), 3);
    assert_eq!(queries[0].priority, 0.9);
    assert_eq!(queries[1].priority, 0.6);
    assert_eq!(queries[2].priority, 0.3);
}

#[test]
fn derive_followup_email() {
    let finding = make_finding(
        1,
        FindingType::EmailAddress,
        "admin@example.com",
        IntelSource::WebSearch,
    );
    let queries = derive_followup_queries(&finding);
    assert!(queries.len() >= 3);
    assert!(queries.iter().any(|q| q.source == IntelSource::WebSearch));
    assert!(queries.iter().any(|q| q.source == IntelSource::PasteSite));
    assert!(queries
        .iter()
        .any(|q| q.source == IntelSource::CodeRepository));
    assert!(queries.iter().all(|q| q.derived_from == Some(1)));
}

#[test]
fn derive_followup_domain() {
    let finding = make_finding(2, FindingType::Domain, "example.com", IntelSource::Dns);
    let queries = derive_followup_queries(&finding);
    assert!(queries.len() >= 3);
    assert!(queries.iter().any(|q| q.source == IntelSource::Dns));
    assert!(queries
        .iter()
        .any(|q| q.source == IntelSource::CertificateTransparency));
    assert!(queries.iter().any(|q| q.source == IntelSource::Whois));
}

#[test]
fn derive_followup_username() {
    let finding = make_finding(
        3,
        FindingType::Username,
        "johndoe",
        IntelSource::SocialMedia,
    );
    let queries = derive_followup_queries(&finding);
    assert!(queries.len() >= 2);
    assert!(queries.iter().any(|q| q.source == IntelSource::SocialMedia));
}

#[test]
fn derive_followup_ip() {
    let finding = make_finding(4, FindingType::IpAddress, "1.2.3.4", IntelSource::Dns);
    let queries = derive_followup_queries(&finding);
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].source, IntelSource::WebSearch);
}

#[test]
fn derive_followup_technology() {
    let finding = make_finding(
        5,
        FindingType::Technology,
        "Apache 2.4.49",
        IntelSource::WebSearch,
    );
    let queries = derive_followup_queries(&finding);
    assert_eq!(queries.len(), 1);
    assert!(queries[0].query_text.contains("CVE"));
}

#[test]
fn correlate_email_to_domain() {
    let findings = vec![
        make_finding(1, FindingType::Domain, "example.com", IntelSource::Dns),
        make_finding(
            2,
            FindingType::EmailAddress,
            "admin@example.com",
            IntelSource::WebSearch,
        ),
    ];
    let correlations = correlate_findings(&findings);
    assert_eq!(correlations.len(), 1);
    assert!(correlations[0].2.contains("belongs to domain"));
}

#[test]
fn correlate_subdomain_to_domain() {
    let findings = vec![
        make_finding(1, FindingType::Domain, "example.com", IntelSource::Dns),
        make_finding(
            2,
            FindingType::Subdomain,
            "api.example.com",
            IntelSource::Dns,
        ),
    ];
    let correlations = correlate_findings(&findings);
    assert_eq!(correlations.len(), 1);
    assert!(correlations[0].2.contains("subdomain"));
}

#[test]
fn correlate_same_subnet_ips() {
    let findings = vec![
        make_finding(1, FindingType::IpAddress, "10.0.1.5", IntelSource::Dns),
        make_finding(2, FindingType::IpAddress, "10.0.1.12", IntelSource::Dns),
    ];
    let correlations = correlate_findings(&findings);
    assert_eq!(correlations.len(), 1);
    assert!(correlations[0].2.contains("/24 subnet"));
}

#[test]
fn correlate_no_relationship() {
    let findings = vec![
        make_finding(1, FindingType::Technology, "nginx", IntelSource::WebSearch),
        make_finding(2, FindingType::OpenPort, "443", IntelSource::WebSearch),
    ];
    let correlations = correlate_findings(&findings);
    assert!(correlations.is_empty());
}

#[test]
fn confidence_summary_empty() {
    let summary = ConfidenceSummary::from_findings(&[]);
    assert_eq!(summary.mean, 0.0);
    assert_eq!(summary.median, 0.0);
    assert_eq!(summary.high_confidence_count, 0);
}

#[test]
fn confidence_summary_computed() {
    let findings = vec![
        make_finding_with_confidence(0.9),
        make_finding_with_confidence(0.3),
        make_finding_with_confidence(0.7),
    ];
    let summary = ConfidenceSummary::from_findings(&findings);
    let expected_mean = (0.9 + 0.3 + 0.7) / 3.0;
    assert!((summary.mean - expected_mean).abs() < 0.001);
    assert!((summary.median - 0.7).abs() < 0.001);
    assert_eq!(summary.high_confidence_count, 1);
    assert_eq!(summary.low_confidence_count, 1);
}

fn make_finding_with_confidence(conf: f64) -> IntelFinding {
    IntelFinding {
        id: 0,
        finding_type: FindingType::Domain,
        value: format!("test-{conf}"),
        source: IntelSource::Dns,
        confidence: conf,
        timestamp_ms: 1000,
        parent_id: None,
        metadata: HashMap::new(),
    }
}

#[test]
fn prompt_builder_empty_findings() {
    let builder = ReconPromptBuilder::new("example.com", ReconPhase::Discover);
    let prompt = builder.build_prompt();
    assert!(prompt.contains("example.com"));
    assert!(prompt.contains("Discover"));
    assert!(prompt.contains("No findings yet"));
}

#[test]
fn prompt_builder_with_findings() {
    let findings = vec![
        make_finding(1, FindingType::Domain, "sub.example.com", IntelSource::Dns),
        make_finding(
            2,
            FindingType::EmailAddress,
            "admin@example.com",
            IntelSource::WebSearch,
        ),
    ];
    let builder =
        ReconPromptBuilder::new("example.com", ReconPhase::Enumerate).with_findings(findings);
    let prompt = builder.build_prompt();
    assert!(prompt.contains("Enumerate"));
    assert!(prompt.contains("Findings So Far: 2"));
}

#[test]
fn generate_report_structure() {
    let cfg = ReconConfig::default().with_target("example.com");
    let mut ctrl = AutonomousReconController::new(cfg);

    let f1 = make_finding(0, FindingType::Domain, "sub.example.com", IntelSource::Dns);
    let f2 = make_finding(
        0,
        FindingType::EmailAddress,
        "admin@example.com",
        IntelSource::WebSearch,
    );
    ctrl.ingest_findings(vec![f1, f2]);

    let report = ctrl.generate_report();
    assert_eq!(report.target, "example.com");
    assert_eq!(report.findings.len(), 2);
    assert!(report.source_counts.contains_key("DNS"));
    assert!(report.source_counts.contains_key("Web Search"));
    assert!(report.finding_type_counts.contains_key("Domain"));
    assert!(report.finding_type_counts.contains_key("Email Address"));
    assert!(report.generated_at_ms > 0);
}

#[test]
fn intel_source_parse_aliases() {
    assert_eq!(parse_intel_source("DNS"), Some(IntelSource::Dns));
    assert_eq!(parse_intel_source("Dns"), Some(IntelSource::Dns));
    assert_eq!(parse_intel_source("WHOIS"), Some(IntelSource::Whois));
    assert_eq!(
        parse_intel_source("CT"),
        Some(IntelSource::CertificateTransparency)
    );
    assert_eq!(
        parse_intel_source("GitHub"),
        Some(IntelSource::CodeRepository)
    );
    assert_eq!(parse_intel_source("Pastebin"), Some(IntelSource::PasteSite));
    assert_eq!(parse_intel_source("Unknown"), None);
}

#[test]
fn finding_type_display() {
    assert_eq!(FindingType::Domain.to_string(), "Domain");
    assert_eq!(FindingType::EmailAddress.to_string(), "Email Address");
    assert_eq!(FindingType::IpAddress.to_string(), "IP Address");
    assert_eq!(FindingType::SocialProfile.to_string(), "Social Profile");
    assert_eq!(FindingType::ApiEndpoint.to_string(), "API Endpoint");
    assert_eq!(FindingType::CodeRepo.to_string(), "Code Repository");
}

#[test]
fn controller_process_llm_response_filters_disabled_sources() {
    let cfg = ReconConfig {
        target: "example.com".to_string(),
        enabled_sources: {
            let mut s = HashSet::new();
            s.insert(IntelSource::Dns);
            s
        },
        ..ReconConfig::default()
    };
    let mut ctrl = AutonomousReconController::new(cfg);

    let response = r#"
        <query source="WebSearch" priority="0.9">
            <text>example.com site:github.com</text>
            <rationale>Find repos</rationale>
        </query>
        <query source="Dns" priority="0.8">
            <text>example.com</text>
            <rationale>DNS enum</rationale>
        </query>
    "#;
    let queries = ctrl.process_llm_response(response);
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].source, IntelSource::Dns);
}
