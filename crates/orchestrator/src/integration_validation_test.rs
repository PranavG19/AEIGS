use aegis_protocol::finding::VulnerabilityClass;
use clap::Parser;

use crate::scan_config::ScanConfig;

fn localhost_config() -> ScanConfig {
    ScanConfig {
        preset: None,
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-integration-validation.sarif"),
        report_format: "developer".to_string(),
        source_dir: None,
        verbose: false,
        stealth: crate::scan_config::StealthOptions {
            persona: "chrome".to_string(),
            stealth: false,
            stealth_level: "default".to_string(),
            max_rps: None,
            skip_evasion: false,
            accept_self_signed: false,
            persona_catalog: None,
        },
        pipeline: crate::scan_config::PipelineOptions {
            max_iterations: 1,
            convergence_threshold: 2,
            skip_fingerprint: false,
            skip_crawl: false,
            paranoia_sweep: false,
            resume: false,
            interactive: false,
            headless_crawl: false,
        },
        llm: crate::scan_config::LlmOptions {
            no_llm: false,
            bypass_corpus: None,
            python_cmd: "python3".to_string(),
        },
        audit: crate::scan_config::AuditOptions {
            no_audit: false,
            scope_attestation: None,
            signed_config: None,
            i_am_authorized: false,
        },
        scope: crate::scan_config::ScopeOptions {
            include_endpoints: None,
            exclude_endpoints: None,
            context_file: None,
            graph_db: None,
            history_db: None,
            export_graph: None,
            vuln_db: None,
            seclists_path: None,
        },
        auth: crate::scan_config::AuthOptions {
            auth_flow: None,
            auth_input: Vec::new(),
        },
        distributed: crate::scan_config::DistributedOptions {
            distributed: false,
            coordinator_addr: "127.0.0.1:9100".to_string(),
            workers: 1,
            worker_connect: None,
            worker_id: "worker-0".to_string(),
        },
        telemetry: false,
        dalfox_blind_xss: None,
        amass_active: false,
    }
}

// --- Test 1: scan_config_with_all_new_flags_parses_correctly ---

#[test]
fn scan_config_with_all_new_flags_parses_correctly() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:3000",
        "--i-am-authorized",
        "--interactive",
        "--skip-crawl",
        "--telemetry",
    ])
    .unwrap();

    assert!(config.audit.i_am_authorized);
    assert!(config.pipeline.interactive);
    assert!(config.pipeline.skip_crawl);
    assert!(config.telemetry);
    assert_eq!(config.target, "http://localhost:3000");
}

#[test]
fn scan_config_new_flags_default_to_false() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:3000"]).unwrap();

    assert!(!config.audit.i_am_authorized);
    assert!(!config.pipeline.interactive);
    assert!(!config.pipeline.skip_crawl);
    assert!(!config.telemetry);
}

// --- Test 2: scan_pipeline_runs_all_phases_in_order ---

#[tokio::test]
async fn scan_pipeline_runs_all_phases_in_order() {
    let config = localhost_config();
    let result = crate::pipeline::run_scan(config).await;
    assert!(result.is_ok(), "scan failed: {:?}", result.err());
    let summary = result.unwrap();
    assert!(
        summary.phases_completed >= 5,
        "expected at least 5 phases, got {}",
        summary.phases_completed
    );
    assert!(
        summary.total_operations >= 1,
        "expected at least 1 operation, got {}",
        summary.total_operations
    );
    assert!(!summary.sarif_path.is_empty());
}

// --- Test 3: scan_with_telemetry_produces_telemetry_file ---

#[tokio::test]
async fn scan_with_telemetry_produces_telemetry_file() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("telemetry-validation.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.telemetry = true;

    let summary = crate::pipeline::run_scan(config).await.unwrap();
    assert!(
        summary.telemetry_path.is_some(),
        "telemetry_path should be set"
    );

    let path = summary.telemetry_path.unwrap();
    assert!(
        std::path::Path::new(&path).exists(),
        "telemetry file should exist at {path}"
    );

    let contents = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();
    assert!(!events.is_empty(), "telemetry file should contain events");

    let has_start = events
        .iter()
        .any(|e| e["event_type"].as_str() == Some("ScanStarted"));
    let has_end = events
        .iter()
        .any(|e| e["event_type"].as_str() == Some("ScanCompleted"));
    assert!(has_start, "missing ScanStarted event");
    assert!(has_end, "missing ScanCompleted event");
}

// --- Test 4: new_vulnerability_classes_are_fuzzable ---

#[test]
fn new_vulnerability_classes_are_fuzzable() {
    use aegis_fuzzing::scheduler::is_fuzzable;

    let new_fuzzable_classes = [
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::MassAssignment,
    ];

    for class in &new_fuzzable_classes {
        assert!(
            is_fuzzable(*class),
            "{class} should be fuzzable but is_fuzzable returned false"
        );
    }
}

#[test]
fn original_vulnerability_classes_still_fuzzable() {
    use aegis_fuzzing::scheduler::is_fuzzable;

    let original_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
    ];

    for class in &original_classes {
        assert!(
            is_fuzzable(*class),
            "{class} should be fuzzable but is_fuzzable returned false"
        );
    }
}

// --- Test 5: cvss_scores_computed_for_all_classes ---

#[test]
fn cvss_scores_computed_for_all_classes() {
    use aegis_compliance::class_mapper::default_cvss_for_class;
    use aegis_compliance::cvss_scorer::compute_cvss;

    let all_classes = all_vulnerability_classes();

    for class in &all_classes {
        let metrics = default_cvss_for_class(*class);
        let result = compute_cvss(&metrics);
        assert!(result.score > 0.0, "{class} produced a zero CVSS score");
    }
}

#[test]
fn critical_classes_score_at_least_nine() {
    use aegis_compliance::class_mapper::default_cvss_for_class;
    use aegis_compliance::cvss_scorer::compute_cvss;

    let critical_classes = [
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::InsecureDeserialization,
    ];

    for class in &critical_classes {
        let metrics = default_cvss_for_class(*class);
        let result = compute_cvss(&metrics);
        assert!(
            result.score >= 9.0,
            "{class} should score >= 9.0, got {:.1}",
            result.score
        );
    }
}

// --- Test 6: compliance_mapping_covers_all_classes ---

#[test]
fn compliance_mapping_covers_all_classes() {
    use aegis_compliance::compliance_mapper::map_to_compliance;

    let all_classes = all_vulnerability_classes();

    for class in &all_classes {
        let mapping = map_to_compliance(*class);
        assert!(!mapping.cwe.is_empty(), "{class} has no CWE mapping");
        assert!(
            mapping.cwe.starts_with("CWE-"),
            "{class} CWE mapping should start with 'CWE-', got '{}'",
            mapping.cwe
        );
    }
}

#[test]
fn injection_classes_map_to_a03_2021() {
    use aegis_compliance::compliance_mapper::map_to_compliance;

    let injection_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::ServerSideTemplateInjection,
    ];

    for class in &injection_classes {
        let mapping = map_to_compliance(*class);
        let owasp = mapping
            .owasp_2021
            .as_ref()
            .unwrap_or_else(|| panic!("{class} should have OWASP 2021 mapping"));
        assert!(
            owasp.contains("A03:2021"),
            "{class} should map to A03:2021 Injection, got '{owasp}'"
        );
    }
}

// --- Test 7: discovery_modules_have_reasonable_defaults ---

#[test]
fn default_wordlist_has_sufficient_entries() {
    let wordlist = aegis_discovery::default_wordlist();
    assert!(
        wordlist.len() > 1500,
        "default wordlist should have > 1500 entries, got {}",
        wordlist.len()
    );
}

#[test]
fn common_params_has_sufficient_entries() {
    let param_count = aegis_discovery::COMMON_PARAMS.len();
    assert!(
        param_count > 50,
        "COMMON_PARAMS should have > 50 entries, got {param_count}"
    );
}

#[test]
fn vhost_prefixes_has_sufficient_entries() {
    let prefix_count = aegis_discovery::VHOST_PREFIXES.len();
    assert!(
        prefix_count > 25,
        "VHOST_PREFIXES should have > 25 entries, got {prefix_count}"
    );
}

#[test]
fn sensitive_paths_has_sufficient_entries() {
    let path_count = aegis_discovery::SENSITIVE_PATHS.len();
    assert!(
        path_count > 30,
        "SENSITIVE_PATHS should have > 30 entries, got {path_count}"
    );
}

// --- Test 8: exploiter_tools_all_registered ---

#[test]
fn exploiter_tools_all_registered() {
    use aegis_exploiter::{
        AmassWrapper, DalfoxWrapper, FeroxbusterWrapper, GauWrapper, HttpxWrapper, JwtTester,
        NmapWrapper, NucleiWrapper, SqlmapWrapper, SubfinderWrapper, ToolRunner, ToolWrapper,
        TrufflehogWrapper,
    };

    let tools: Vec<Box<dyn ToolWrapper>> = vec![
        Box::new(SqlmapWrapper),
        Box::new(NucleiWrapper::new()),
        Box::new(SubfinderWrapper),
        Box::new(NmapWrapper::new()),
        Box::new(JwtTester),
        Box::new(HttpxWrapper),
        Box::new(GauWrapper),
        Box::new(FeroxbusterWrapper),
        Box::new(TrufflehogWrapper),
        Box::new(DalfoxWrapper),
        Box::new(AmassWrapper),
    ];

    let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(
        names.len(),
        unique.len(),
        "duplicate tool names: {names:?}"
    );
    assert_eq!(
        tools.len(),
        11,
        "tool count mismatch — update this test when adding a new wrapper"
    );

    let runner = tools
        .into_iter()
        .fold(ToolRunner::new(), |r, tool| r.register(tool));

    let _ = runner;
}

// --- Test 9: report_generator_produces_complete_report ---

#[test]
fn report_generator_produces_complete_report() {
    use aegis_compliance::report_generator::{FindingInput, ReportInput, generate_full_report};

    let input = ReportInput {
        target_url: "http://localhost:3000".to_string(),
        scan_duration_secs: 120,
        total_findings: 3,
        critical_count: 1,
        high_count: 1,
        medium_count: 1,
        low_count: 0,
        tech_stack: vec!["express".to_string(), "node.js".to_string()],
        defenses_detected: vec!["WAF".to_string()],
        findings: vec![
            FindingInput {
                vulnerability_class: "Command Injection".to_string(),
                endpoint: "/api/exec".to_string(),
                parameter: Some("cmd".to_string()),
                evidence: "Response included shell output after command payload".to_string(),
                cvss_score: 9.8,
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                owasp_category: Some("A03:2021 Injection".to_string()),
                poc_command: Some("curl 'http://localhost:3000/api/exec?cmd=id'".to_string()),
            },
            FindingInput {
                vulnerability_class: "SQL Injection".to_string(),
                endpoint: "/api/users".to_string(),
                parameter: Some("id".to_string()),
                evidence: "Database error in response body".to_string(),
                cvss_score: 8.6,
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string(),
                owasp_category: Some("A03:2021 Injection".to_string()),
                poc_command: None,
            },
            FindingInput {
                vulnerability_class: "Missing Security Header".to_string(),
                endpoint: "/".to_string(),
                parameter: None,
                evidence: "CSP header not present".to_string(),
                cvss_score: 5.3,
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N".to_string(),
                owasp_category: Some("A05:2021 Security Misconfig".to_string()),
                poc_command: None,
            },
        ],
    };

    let report = generate_full_report(&input);

    assert!(
        !report.executive_summary.is_empty(),
        "executive summary should not be empty"
    );
    assert!(
        report.executive_summary.contains("critical"),
        "executive summary should mention critical findings"
    );

    assert_eq!(
        report.findings.len(),
        3,
        "should produce a narrative per finding"
    );
    for narrative in &report.findings {
        assert!(!narrative.title.is_empty());
        assert!(!narrative.description.is_empty());
        assert!(!narrative.impact.is_empty());
        assert!(!narrative.remediation.is_empty());
    }

    assert!(
        !report.remediation_roadmap.is_empty(),
        "remediation roadmap should not be empty"
    );
    assert!(
        report.remediation_roadmap.contains("Immediate"),
        "roadmap should have immediate section for critical/high findings"
    );

    assert!(
        !report.methodology.is_empty(),
        "methodology should not be empty"
    );
    assert!(
        !report.compliance_summary.is_empty(),
        "compliance summary should not be empty"
    );
}

// --- Test 10: header_analyzer_catches_common_issues ---

#[test]
fn header_analyzer_catches_missing_hsts_csp_xframe() {
    use aegis_fuzzing::header_analyzer::{HeaderIssue, SecurityHeaderAnalyzer};

    let headers: Vec<(String, String)> = vec![
        ("Content-Type".to_string(), "text/html".to_string()),
        ("Server".to_string(), "nginx".to_string()),
    ];

    let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);

    let header_names: Vec<&str> = findings.iter().map(|f| f.header_name.as_str()).collect();
    assert!(
        header_names.contains(&"Strict-Transport-Security"),
        "should flag missing HSTS, got headers: {header_names:?}"
    );
    assert!(
        header_names.contains(&"Content-Security-Policy"),
        "should flag missing CSP, got headers: {header_names:?}"
    );
    assert!(
        header_names.contains(&"X-Frame-Options"),
        "should flag missing X-Frame-Options, got headers: {header_names:?}"
    );

    for finding in &findings {
        assert_eq!(
            finding.issue,
            HeaderIssue::Missing,
            "{} should be flagged as Missing",
            finding.header_name
        );
    }
}

#[test]
fn header_analyzer_passes_with_all_headers_present() {
    use aegis_fuzzing::header_analyzer::SecurityHeaderAnalyzer;

    let headers: Vec<(String, String)> = vec![
        (
            "Strict-Transport-Security".to_string(),
            "max-age=31536000; includeSubDomains".to_string(),
        ),
        (
            "Content-Security-Policy".to_string(),
            "default-src 'self'".to_string(),
        ),
        ("X-Frame-Options".to_string(), "DENY".to_string()),
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ("Referrer-Policy".to_string(), "strict-origin".to_string()),
        (
            "Permissions-Policy".to_string(),
            "geolocation=()".to_string(),
        ),
    ];

    let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
    assert!(
        findings.is_empty(),
        "no findings expected with all security headers present, got: {:?}",
        findings.iter().map(|f| &f.header_name).collect::<Vec<_>>()
    );
}

// --- Helper: enumerate all 34 VulnerabilityClass variants ---

fn all_vulnerability_classes() -> Vec<VulnerabilityClass> {
    vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::WeakCryptography,
        VulnerabilityClass::MassAssignment,
    ]
}
