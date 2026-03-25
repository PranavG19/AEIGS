use aegis_protocol::finding::VulnerabilityClass;

use crate::html_report::{
    HtmlReportConfig, generate_html_report, html_escape, severity_color, severity_rating,
};
use crate::report_format::{DefenseSummary, ReportMetadata};
use crate::sarif_emitter::{SarifFinding, SarifLevel};

fn sample_finding(
    rule_id: &str,
    vuln_class: VulnerabilityClass,
    severity: f64,
    composite: f64,
) -> SarifFinding {
    SarifFinding {
        rule_id: rule_id.to_string(),
        rule_description: format!("Test finding {rule_id}"),
        level: SarifLevel::Error,
        message: format!("Found {}", vuln_class),
        uri: Some("https://example.com/api/test".to_string()),
        logical_location_name: None,
        logical_location_kind: None,
        severity,
        confidence: 0.9,
        composite_score: composite,
        vulnerability_class: Some(vuln_class),
        related_locations: vec![],
        defense_context: None,
        evidence_level: Some("Confirmed".to_string()),
        cve_id: None,
        mitigation_rank: None,
        suppression_kind: None,
        suppression_message: None,
        endpoint: Some("/api/test".to_string()),
        http_method: Some("POST".to_string()),
        parameter_name: Some("query".to_string()),
    }
}

#[test]
fn html_report_contains_structural_tags() {
    let findings = vec![
        sample_finding("SQL-001", VulnerabilityClass::SqlInjection, 85.0, 80.0),
        sample_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            55.0,
            45.0,
        ),
    ];
    let config = HtmlReportConfig::default();
    let html = generate_html_report(&findings, &config, None, None);

    assert!(html.contains("<!DOCTYPE html>"), "missing DOCTYPE");
    assert!(html.contains("<html"), "missing <html> tag");
    assert!(html.contains("<head>"), "missing <head> tag");
    assert!(html.contains("<body>"), "missing <body> tag");
    assert!(html.contains("</html>"), "missing closing </html>");
    assert!(html.contains("<title>"), "missing <title> tag");
    assert!(html.contains("<style>"), "missing embedded CSS");
    assert!(html.contains("<script>"), "missing embedded JS");
}

#[test]
fn html_report_with_empty_findings_produces_valid_document() {
    let config = HtmlReportConfig::default();
    let html = generate_html_report(&[], &config, None, None);

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("<html"));
    assert!(html.contains("</html>"));
    assert!(html.contains("Total Findings"));
    assert!(
        html.contains("No findings to display."),
        "empty report should show placeholder text"
    );
}

#[test]
fn severity_badges_appear_for_each_threshold() {
    let findings = vec![
        sample_finding("CRIT-001", VulnerabilityClass::CommandInjection, 90.0, 75.0),
        sample_finding("HIGH-001", VulnerabilityClass::SqlInjection, 60.0, 50.0),
        sample_finding(
            "MED-001",
            VulnerabilityClass::CrossSiteScripting,
            30.0,
            25.0,
        ),
        sample_finding("LOW-001", VulnerabilityClass::OpenRedirect, 10.0, 10.0),
    ];
    let config = HtmlReportConfig::default();
    let html = generate_html_report(&findings, &config, None, None);

    assert!(
        html.contains("badge-critical"),
        "missing critical badge class"
    );
    assert!(html.contains("badge-high"), "missing high badge class");
    assert!(html.contains("badge-medium"), "missing medium badge class");
    assert!(html.contains("badge-low"), "missing low badge class");

    assert!(
        html.contains(r#"data-severity="Critical""#),
        "table row missing Critical data attr"
    );
    assert!(
        html.contains(r#"data-severity="High""#),
        "table row missing High data attr"
    );
    assert!(
        html.contains(r#"data-severity="Medium""#),
        "table row missing Medium data attr"
    );
    assert!(
        html.contains(r#"data-severity="Low""#),
        "table row missing Low data attr"
    );
}

#[test]
fn html_escape_handles_special_characters() {
    assert_eq!(html_escape("&"), "&amp;");
    assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    assert_eq!(html_escape(r#"a"b"#), "a&quot;b");
    assert_eq!(html_escape("a'b"), "a&#x27;b");
    assert_eq!(
        html_escape(r#"<div class="x">&</div>"#),
        "&lt;div class=&quot;x&quot;&gt;&amp;&lt;/div&gt;"
    );
    assert_eq!(html_escape("plain text"), "plain text");
    assert_eq!(html_escape(""), "");
}

#[test]
fn attack_chain_svg_included_when_configured() {
    let findings = vec![
        sample_finding("SQL-001", VulnerabilityClass::SqlInjection, 80.0, 75.0),
        sample_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            50.0,
            45.0,
        ),
    ];

    let config_with = HtmlReportConfig {
        include_attack_chain: true,
        ..HtmlReportConfig::default()
    };
    let html_with = generate_html_report(&findings, &config_with, None, None);
    assert!(
        html_with.contains("<svg"),
        "SVG should be present when attack chain is enabled"
    );
    assert!(
        html_with.contains("attack-chain-section"),
        "attack chain section missing"
    );
    assert!(html_with.contains("arrowhead"), "SVG arrow marker missing");

    let config_without = HtmlReportConfig {
        include_attack_chain: false,
        ..HtmlReportConfig::default()
    };
    let html_without = generate_html_report(&findings, &config_without, None, None);
    assert!(
        !html_without.contains("<svg"),
        "SVG should be absent when attack chain is disabled"
    );
}

#[test]
fn finding_cards_contain_expected_content() {
    let findings = vec![sample_finding(
        "SQLI-042",
        VulnerabilityClass::SqlInjection,
        85.0,
        80.0,
    )];
    let config = HtmlReportConfig {
        include_remediation: true,
        ..HtmlReportConfig::default()
    };
    let html = generate_html_report(&findings, &config, None, None);

    assert!(html.contains("SQLI-042"), "rule_id not in output");
    assert!(
        html.contains("Found SQL Injection"),
        "finding message not in output"
    );
    assert!(html.contains("CWE-89"), "CWE mapping not in output");
    assert!(
        html.contains("parameterized queries"),
        "remediation text not in output"
    );
    assert!(html.contains("/api/test"), "endpoint not in output");
    assert!(html.contains("POST"), "http_method not in output");
    assert!(html.contains("query"), "parameter_name not in output");
    assert!(html.contains("Confirmed"), "evidence_level not in output");
    assert!(html.contains("T1190"), "ATT&amp;CK technique not in output");
}

#[test]
fn severity_rating_thresholds() {
    assert_eq!(severity_rating(100.0), "Critical");
    assert_eq!(severity_rating(70.0), "Critical");
    assert_eq!(severity_rating(69.9), "High");
    assert_eq!(severity_rating(40.0), "High");
    assert_eq!(severity_rating(39.9), "Medium");
    assert_eq!(severity_rating(20.0), "Medium");
    assert_eq!(severity_rating(19.9), "Low");
    assert_eq!(severity_rating(0.0), "Low");
}

#[test]
fn severity_color_mapping() {
    assert_eq!(severity_color("Critical"), "#ff4444");
    assert_eq!(severity_color("High"), "#ff8c00");
    assert_eq!(severity_color("Medium"), "#ffd700");
    assert_eq!(severity_color("Low"), "#44ff44");
    assert_eq!(severity_color("Unknown"), "#888888");
}

#[test]
fn report_includes_metadata_when_provided() {
    let findings = vec![sample_finding(
        "A-1",
        VulnerabilityClass::PathTraversal,
        50.0,
        45.0,
    )];
    let config = HtmlReportConfig::default();
    let meta = ReportMetadata {
        target_url: "https://target.example.com".to_string(),
        total_duration_secs: 123.4,
        phases_completed: 5,
    };
    let html = generate_html_report(&findings, &config, Some(&meta), None);

    assert!(
        html.contains("target.example.com"),
        "target URL not in output"
    );
    assert!(html.contains("123.4"), "duration not in output");
    assert!(html.contains("Phases Completed"), "phases label missing");
}

#[test]
fn report_includes_defense_summary() {
    let findings = vec![sample_finding(
        "A-1",
        VulnerabilityClass::PathTraversal,
        50.0,
        45.0,
    )];
    let config = HtmlReportConfig::default();
    let defense = DefenseSummary {
        has_waf: true,
        waf_vendor: Some("Cloudflare".to_string()),
        has_rate_limiting: false,
        has_bot_detection: true,
    };
    let html = generate_html_report(&findings, &config, None, Some(&defense));

    assert!(html.contains("Defense Posture"), "defense section missing");
    assert!(html.contains("Cloudflare"), "WAF vendor not in output");
    assert!(
        html.contains("Bot Detection"),
        "bot detection label missing"
    );
    assert!(
        html.contains("indicator-active"),
        "active indicator missing"
    );
    assert!(
        html.contains("indicator-inactive"),
        "inactive indicator missing"
    );
}

#[test]
fn remediation_excluded_when_not_configured() {
    let findings = vec![sample_finding(
        "XSS-001",
        VulnerabilityClass::CrossSiteScripting,
        55.0,
        45.0,
    )];
    let config = HtmlReportConfig {
        include_remediation: false,
        ..HtmlReportConfig::default()
    };
    let html = generate_html_report(&findings, &config, None, None);

    assert!(
        !html.contains(r#"<div class="remediation-box">"#),
        "remediation box should be absent when disabled"
    );
}

#[test]
fn findings_table_has_sortable_headers() {
    let findings = vec![sample_finding(
        "A-1",
        VulnerabilityClass::SqlInjection,
        80.0,
        75.0,
    )];
    let config = HtmlReportConfig::default();
    let html = generate_html_report(&findings, &config, None, None);

    assert!(html.contains("findings-table"), "table class missing");
    assert!(html.contains("data-sort="), "sortable headers missing");
    assert!(html.contains("<thead>"), "thead missing");
    assert!(html.contains("<tbody>"), "tbody missing");
    assert!(html.contains("finding-filter"), "filter input missing");
    assert!(
        html.contains("severity-filter"),
        "severity filter select missing"
    );
}

#[test]
fn custom_title_and_version_appear_in_output() {
    let config = HtmlReportConfig {
        title: "My Custom Report".to_string(),
        tool_version: "2.3.4".to_string(),
        ..HtmlReportConfig::default()
    };
    let html = generate_html_report(&[], &config, None, None);

    assert!(
        html.contains("My Custom Report"),
        "custom title not in output"
    );
    assert!(html.contains("2.3.4"), "custom version not in output");
}

#[test]
fn attack_chain_svg_deduplicates_classes() {
    let findings = vec![
        sample_finding("SQL-001", VulnerabilityClass::SqlInjection, 80.0, 75.0),
        sample_finding("SQL-002", VulnerabilityClass::SqlInjection, 70.0, 65.0),
        sample_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            50.0,
            45.0,
        ),
    ];
    let config = HtmlReportConfig {
        include_attack_chain: true,
        ..HtmlReportConfig::default()
    };
    let html = generate_html_report(&findings, &config, None, None);

    let sql_rect_count = html.matches("SQL Injection").count();
    // The SVG should contain exactly one node for SQL Injection (deduplicated),
    // but the finding cards / table will also mention it. The SVG section itself
    // should have at most one rect label for it.
    let svg_section_start = html.find("attack-chain-section").unwrap();
    let svg_section_end = html[svg_section_start..].find("</section>").unwrap() + svg_section_start;
    let svg_section = &html[svg_section_start..svg_section_end];
    let svg_sql_count = svg_section.matches("SQL Injection").count();
    assert_eq!(
        svg_sql_count, 1,
        "SVG should deduplicate vulnerability classes, found {} occurrences",
        svg_sql_count,
    );
    assert!(sql_rect_count >= 1, "SQL Injection should appear somewhere");
}

#[test]
fn html_escape_preserves_multibyte_characters() {
    let input = "café <script> — naïve & 日本語";
    let escaped = html_escape(input);
    assert!(escaped.contains("café"));
    assert!(escaped.contains("&lt;script&gt;"));
    assert!(escaped.contains("naïve"));
    assert!(escaped.contains("&amp;"));
    assert!(escaped.contains("日本語"));
}
