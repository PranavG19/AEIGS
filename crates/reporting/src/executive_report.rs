use serde::{Deserialize, Serialize};
use std::fmt::Write;

/// Effort estimate for a remediation item.
///
/// Granularity moves from hours (config changes, header additions)
/// through days (code-level fixes) to weeks (architectural rework).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EffortEstimate {
    Hours(u32),
    Days(u32),
    Weeks(u32),
}

/// Compliance framework identifiers supported by the executive report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceFramework {
    OwaspTop10,
    PciDss,
    Nist80053,
}

/// Summary of a single finding, pre-processed for executive consumption.
///
/// Decoupled from `SarifFinding` so callers can construct these from
/// any finding source without pulling in SARIF types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: String,
    pub title: String,
    pub vulnerability_class: String,
    pub composite_score: f64,
    pub endpoint: String,
    pub business_impact: String,
    pub remediation: String,
    pub effort_estimate: EffortEstimate,
}

/// Snapshot of the previous scan for trend comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousScanData {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub risk_score: f64,
    pub scan_date: String,
}

/// All inputs needed to produce an executive report.
///
/// Constructed by the orchestrator after a scan completes.
/// `previous_scan` enables trend analysis when historical data exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveReportInput {
    pub findings: Vec<FindingSummary>,
    pub target_url: String,
    pub scan_duration_secs: f64,
    pub total_endpoints: usize,
    pub tested_endpoints: usize,
    pub previous_scan: Option<PreviousScanData>,
    pub compliance_frameworks: Vec<ComplianceFramework>,
}

/// Security posture score with severity breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDashboard {
    pub overall_score: u32,
    pub posture_rating: String,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

/// A top finding elevated to the executive summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub composite_score: f64,
    pub endpoint: String,
    pub business_impact: String,
}

/// Attack surface coverage metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceSummary {
    pub total_endpoints: usize,
    pub tested_endpoints: usize,
    pub coverage_percent: f64,
    pub untested_count: usize,
}

/// Delta between the current and previous scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub previous_scan_date: String,
    pub previous_finding_count: usize,
    pub current_finding_count: usize,
    pub delta_findings: i64,
    pub previous_risk_score: f64,
    pub current_risk_score: f64,
    pub score_delta: f64,
    pub trend_direction: String,
}

/// A single item on the prioritized remediation roadmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationItem {
    pub priority: usize,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub remediation: String,
    pub effort_estimate: EffortEstimate,
}

/// Per-framework compliance mapping result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub framework: String,
    pub violated_categories: Vec<String>,
    pub violation_count: usize,
    pub status: String,
}

/// The complete executive report, ready for rendering.
///
/// Each section addresses a different stakeholder concern:
/// risk posture, critical findings, surface coverage, historical
/// trends, remediation planning, and compliance standing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveReport {
    pub risk_dashboard: RiskDashboard,
    pub top_findings: Vec<TopFinding>,
    pub attack_surface: AttackSurfaceSummary,
    pub trend_analysis: Option<TrendAnalysis>,
    pub remediation_roadmap: Vec<RemediationItem>,
    pub compliance_status: Vec<ComplianceStatus>,
}

/// Build a complete executive report from scan results.
pub fn generate_executive_report(input: &ExecutiveReportInput) -> ExecutiveReport {
    let risk_dashboard = build_risk_dashboard(&input.findings);
    let top_findings = build_top_findings(&input.findings);
    let attack_surface = build_attack_surface(input.total_endpoints, input.tested_endpoints);
    let trend_analysis =
        build_trend_analysis(&input.findings, &risk_dashboard, &input.previous_scan);
    let remediation_roadmap = build_remediation_roadmap(&input.findings);
    let compliance_status = build_compliance_status(&input.findings, &input.compliance_frameworks);

    ExecutiveReport {
        risk_dashboard,
        top_findings,
        attack_surface,
        trend_analysis,
        remediation_roadmap,
        compliance_status,
    }
}

/// Render the executive report as pretty-printed JSON.
pub fn render_json(report: &ExecutiveReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Render the executive report as a self-contained HTML document.
pub fn render_html(report: &ExecutiveReport) -> String {
    let mut html = String::with_capacity(4096);
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
    html.push_str("<title>AEGIS Executive Security Report</title>");
    append_html_style(&mut html);
    html.push_str("</head><body>");
    append_html_header(&mut html, report);
    append_html_risk_dashboard(&mut html, &report.risk_dashboard);
    append_html_top_findings(&mut html, &report.top_findings);
    append_html_attack_surface(&mut html, &report.attack_surface);
    append_html_trend_analysis(&mut html, &report.trend_analysis);
    append_html_remediation(&mut html, &report.remediation_roadmap);
    append_html_compliance(&mut html, &report.compliance_status);
    html.push_str("</body></html>");
    html
}

/// Render the executive report as PDF-ready markdown.
pub fn render_markdown(report: &ExecutiveReport) -> String {
    let mut md = String::with_capacity(4096);
    md.push_str("# AEGIS Executive Security Report\n\n");
    append_md_risk_dashboard(&mut md, &report.risk_dashboard);
    append_md_top_findings(&mut md, &report.top_findings);
    append_md_attack_surface(&mut md, &report.attack_surface);
    append_md_trend_analysis(&mut md, &report.trend_analysis);
    append_md_remediation(&mut md, &report.remediation_roadmap);
    append_md_compliance(&mut md, &report.compliance_status);
    md
}

fn severity_rating(composite: f64) -> &'static str {
    if composite >= 70.0 {
        "Critical"
    } else if composite >= 40.0 {
        "High"
    } else if composite >= 20.0 {
        "Medium"
    } else {
        "Low"
    }
}

fn posture_rating(score: u32) -> &'static str {
    if score >= 90 {
        "Excellent"
    } else if score >= 70 {
        "Low"
    } else if score >= 40 {
        "Medium"
    } else if score >= 20 {
        "High"
    } else {
        "Critical"
    }
}

fn compute_overall_score(findings: &[FindingSummary]) -> u32 {
    if findings.is_empty() {
        return 100;
    }
    let penalty: f64 = findings
        .iter()
        .map(|f| f.composite_score.clamp(0.0, 100.0))
        .sum();
    let normalized = (penalty / findings.len() as f64).clamp(0.0, 100.0);
    let score = (100.0 - normalized).clamp(0.0, 100.0);
    score.round() as u32
}

fn count_severity(findings: &[FindingSummary]) -> (usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for f in findings {
        match severity_rating(f.composite_score) {
            "Critical" => critical += 1,
            "High" => high += 1,
            "Medium" => medium += 1,
            _ => low += 1,
        }
    }
    (critical, high, medium, low)
}

fn build_risk_dashboard(findings: &[FindingSummary]) -> RiskDashboard {
    let overall_score = compute_overall_score(findings);
    let rating = posture_rating(overall_score).to_string();
    let (critical, high, medium, low) = count_severity(findings);

    RiskDashboard {
        overall_score,
        posture_rating: rating,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
    }
}

fn build_top_findings(findings: &[FindingSummary]) -> Vec<TopFinding> {
    let mut sorted: Vec<&FindingSummary> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted
        .into_iter()
        .take(5)
        .map(|f| TopFinding {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: severity_rating(f.composite_score).to_string(),
            composite_score: f.composite_score,
            endpoint: f.endpoint.clone(),
            business_impact: f.business_impact.clone(),
        })
        .collect()
}

fn build_attack_surface(total: usize, tested: usize) -> AttackSurfaceSummary {
    let coverage = if total == 0 {
        0.0
    } else {
        (tested as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    };
    let untested = total.saturating_sub(tested);

    AttackSurfaceSummary {
        total_endpoints: total,
        tested_endpoints: tested,
        coverage_percent: (coverage * 10.0).round() / 10.0,
        untested_count: untested,
    }
}

fn build_trend_analysis(
    findings: &[FindingSummary],
    dashboard: &RiskDashboard,
    previous: &Option<PreviousScanData>,
) -> Option<TrendAnalysis> {
    let prev = previous.as_ref()?;
    let current_count = findings.len();
    let delta = current_count as i64 - prev.total_findings as i64;
    let current_risk = dashboard.overall_score as f64;
    let score_delta = current_risk - prev.risk_score;
    let direction = trend_direction(score_delta);

    Some(TrendAnalysis {
        previous_scan_date: prev.scan_date.clone(),
        previous_finding_count: prev.total_findings,
        current_finding_count: current_count,
        delta_findings: delta,
        previous_risk_score: prev.risk_score,
        current_risk_score: current_risk,
        score_delta,
        trend_direction: direction.to_string(),
    })
}

fn trend_direction(score_delta: f64) -> &'static str {
    if score_delta > 5.0 {
        "Improving"
    } else if score_delta < -5.0 {
        "Degrading"
    } else {
        "Stable"
    }
}

fn build_remediation_roadmap(findings: &[FindingSummary]) -> Vec<RemediationItem> {
    let mut sorted: Vec<&FindingSummary> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted
        .into_iter()
        .enumerate()
        .map(|(i, f)| RemediationItem {
            priority: i + 1,
            finding_id: f.id.clone(),
            title: f.title.clone(),
            severity: severity_rating(f.composite_score).to_string(),
            remediation: f.remediation.clone(),
            effort_estimate: f.effort_estimate.clone(),
        })
        .collect()
}

fn build_compliance_status(
    findings: &[FindingSummary],
    frameworks: &[ComplianceFramework],
) -> Vec<ComplianceStatus> {
    frameworks
        .iter()
        .map(|fw| compliance_for_framework(findings, fw))
        .collect()
}

fn compliance_for_framework(
    findings: &[FindingSummary],
    framework: &ComplianceFramework,
) -> ComplianceStatus {
    let (name, mapper): (&str, fn(&str) -> Option<&'static str>) = match framework {
        ComplianceFramework::OwaspTop10 => ("OWASP Top 10 2021", map_owasp_category),
        ComplianceFramework::PciDss => ("PCI-DSS 4.0", map_pci_category),
        ComplianceFramework::Nist80053 => ("NIST 800-53", map_nist_category),
    };

    let mut categories: Vec<String> = Vec::new();
    for f in findings {
        if let Some(cat) = mapper(&f.vulnerability_class) {
            let owned = cat.to_string();
            if !categories.contains(&owned) {
                categories.push(owned);
            }
        }
    }
    categories.sort();
    let count = categories.len();
    let status = compliance_status_label(count);

    ComplianceStatus {
        framework: name.to_string(),
        violated_categories: categories,
        violation_count: count,
        status: status.to_string(),
    }
}

fn compliance_status_label(violation_count: usize) -> &'static str {
    if violation_count == 0 {
        "Compliant"
    } else if violation_count <= 2 {
        "Partial"
    } else {
        "Non-Compliant"
    }
}

fn map_owasp_category(vuln_class: &str) -> Option<&'static str> {
    match vuln_class {
        "SqlInjection"
        | "NoSqlInjection"
        | "CommandInjection"
        | "ServerSideTemplateInjection"
        | "XmlExternalEntity" => Some("A03:2021 Injection"),
        "CrossSiteScripting" => Some("A03:2021 Injection"),
        "BrokenAuthentication" | "JwtVulnerability" => {
            Some("A07:2021 Identification and Authentication Failures")
        }
        "BrokenAuthorization" | "InsecureDirectObjectReference" => {
            Some("A01:2021 Broken Access Control")
        }
        "SecurityMisconfiguration" | "CloudMisconfiguration" | "MissingSecurityHeader" => {
            Some("A05:2021 Security Misconfiguration")
        }
        "SensitiveDataExposure" | "InformationDisclosure" | "WeakCryptography" => {
            Some("A02:2021 Cryptographic Failures")
        }
        "InsecureDeserialization" => Some("A08:2021 Software and Data Integrity Failures"),
        "KnownVulnerableDependency" => Some("A06:2021 Vulnerable and Outdated Components"),
        "ServerSideRequestForgery" => Some("A10:2021 Server-Side Request Forgery"),
        "PathTraversal" => Some("A01:2021 Broken Access Control"),
        "OpenRedirect" | "Clickjacking" => Some("A01:2021 Broken Access Control"),
        _ => None,
    }
}

fn map_pci_category(vuln_class: &str) -> Option<&'static str> {
    match vuln_class {
        "SqlInjection" | "NoSqlInjection" | "CommandInjection" | "CrossSiteScripting"
        | "XmlExternalEntity" => Some("Req 6.2: Prevent common coding vulnerabilities"),
        "BrokenAuthentication" | "JwtVulnerability" => {
            Some("Req 8: Identify and authenticate access")
        }
        "BrokenAuthorization" | "InsecureDirectObjectReference" => {
            Some("Req 7: Restrict access by business need-to-know")
        }
        "SensitiveDataExposure" | "WeakCryptography" => {
            Some("Req 4: Encrypt transmission of cardholder data")
        }
        "KnownVulnerableDependency" => {
            Some("Req 6.3: Identify and manage security vulnerabilities")
        }
        "SecurityMisconfiguration" | "MissingSecurityHeader" => {
            Some("Req 2: Apply secure configurations")
        }
        _ => None,
    }
}

fn map_nist_category(vuln_class: &str) -> Option<&'static str> {
    match vuln_class {
        "SqlInjection" | "NoSqlInjection" | "CommandInjection" | "CrossSiteScripting"
        | "XmlExternalEntity" => Some("SI-10: Information Input Validation"),
        "BrokenAuthentication" | "JwtVulnerability" => {
            Some("IA-2: Identification and Authentication")
        }
        "BrokenAuthorization" | "InsecureDirectObjectReference" => Some("AC-3: Access Enforcement"),
        "SensitiveDataExposure" | "WeakCryptography" => Some("SC-13: Cryptographic Protection"),
        "SecurityMisconfiguration" | "MissingSecurityHeader" => {
            Some("CM-6: Configuration Settings")
        }
        "KnownVulnerableDependency" => Some("SI-2: Flaw Remediation"),
        _ => None,
    }
}

fn format_effort(estimate: &EffortEstimate) -> String {
    match estimate {
        EffortEstimate::Hours(n) => format!("{n}h"),
        EffortEstimate::Days(n) => format!("{n}d"),
        EffortEstimate::Weeks(n) => format!("{n}w"),
    }
}

fn append_html_style(html: &mut String) {
    html.push_str("<style>");
    html.push_str("body{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:2rem;color:#1a1a2e;}");
    html.push_str("h1{border-bottom:3px solid #e94560;}h2{color:#0f3460;}");
    html.push_str("table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}");
    html.push_str("th{background:#0f3460;color:#fff;}.critical{color:#e94560;font-weight:bold;}");
    html.push_str(
        ".high{color:#f39c12;font-weight:bold;}.medium{color:#3498db;}.low{color:#27ae60;}",
    );
    html.push_str("</style>");
}

fn append_html_header(html: &mut String, report: &ExecutiveReport) {
    let _ = write!(
        html,
        "<h1>AEGIS Executive Security Report</h1><p>Security Posture: <strong>{}</strong> (Score: {}/100)</p>",
        report.risk_dashboard.posture_rating, report.risk_dashboard.overall_score
    );
}

fn append_html_risk_dashboard(html: &mut String, dash: &RiskDashboard) {
    html.push_str("<h2>Risk Dashboard</h2><table><tr><th>Severity</th><th>Count</th></tr>");
    let _ = write!(
        html,
        "<tr><td class=\"critical\">Critical</td><td>{}</td></tr>",
        dash.critical_count
    );
    let _ = write!(
        html,
        "<tr><td class=\"high\">High</td><td>{}</td></tr>",
        dash.high_count
    );
    let _ = write!(
        html,
        "<tr><td class=\"medium\">Medium</td><td>{}</td></tr>",
        dash.medium_count
    );
    let _ = write!(
        html,
        "<tr><td class=\"low\">Low</td><td>{}</td></tr>",
        dash.low_count
    );
    html.push_str("</table>");
}

fn append_html_top_findings(html: &mut String, findings: &[TopFinding]) {
    html.push_str("<h2>Top Critical Findings</h2>");
    if findings.is_empty() {
        html.push_str("<p>No findings.</p>");
        return;
    }
    html.push_str("<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Score</th><th>Endpoint</th><th>Impact</th></tr>");
    for f in findings {
        let css = severity_css_class(&f.severity);
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{:.1}</td><td>{}</td><td>{}</td></tr>",
            f.id, f.title, css, f.severity, f.composite_score, f.endpoint, f.business_impact
        );
    }
    html.push_str("</table>");
}

fn append_html_attack_surface(html: &mut String, surface: &AttackSurfaceSummary) {
    let _ = write!(
        html,
        "<h2>Attack Surface</h2><p>Tested {}/{} endpoints ({:.1}% coverage). {} untested.</p>",
        surface.tested_endpoints,
        surface.total_endpoints,
        surface.coverage_percent,
        surface.untested_count
    );
}

fn append_html_trend_analysis(html: &mut String, trend: &Option<TrendAnalysis>) {
    html.push_str("<h2>Trend Analysis</h2>");
    match trend {
        Some(t) => {
            let _ = write!(
                html,
                "<p>Compared to scan on {}: findings {} ({}→{}), score delta {:+.1}, trend: <strong>{}</strong></p>",
                t.previous_scan_date,
                delta_label(t.delta_findings),
                t.previous_finding_count,
                t.current_finding_count,
                t.score_delta,
                t.trend_direction
            );
        }
        None => html.push_str("<p>No previous scan data available.</p>"),
    }
}

fn append_html_remediation(html: &mut String, items: &[RemediationItem]) {
    html.push_str("<h2>Remediation Roadmap</h2>");
    if items.is_empty() {
        html.push_str("<p>No remediations needed.</p>");
        return;
    }
    html.push_str("<table><tr><th>#</th><th>Finding</th><th>Severity</th><th>Remediation</th><th>Effort</th></tr>");
    for item in items {
        let css = severity_css_class(&item.severity);
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
            item.priority,
            item.title,
            css,
            item.severity,
            item.remediation,
            format_effort(&item.effort_estimate)
        );
    }
    html.push_str("</table>");
}

fn append_html_compliance(html: &mut String, statuses: &[ComplianceStatus]) {
    html.push_str("<h2>Compliance Status</h2>");
    if statuses.is_empty() {
        html.push_str("<p>No compliance frameworks selected.</p>");
        return;
    }
    html.push_str(
        "<table><tr><th>Framework</th><th>Status</th><th>Violations</th><th>Categories</th></tr>",
    );
    for s in statuses {
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            s.framework,
            s.status,
            s.violation_count,
            s.violated_categories.join(", ")
        );
    }
    html.push_str("</table>");
}

fn severity_css_class(severity: &str) -> &str {
    match severity {
        "Critical" => "critical",
        "High" => "high",
        "Medium" => "medium",
        _ => "low",
    }
}

fn delta_label(delta: i64) -> String {
    if delta > 0 {
        format!("+{delta}")
    } else if delta < 0 {
        format!("{delta}")
    } else {
        "unchanged".to_string()
    }
}

fn append_md_risk_dashboard(md: &mut String, dash: &RiskDashboard) {
    let _ = writeln!(md, "## Risk Dashboard\n");
    let _ = writeln!(md, "| Metric | Value |");
    let _ = writeln!(md, "|--------|-------|");
    let _ = writeln!(md, "| Overall Score | {}/100 |", dash.overall_score);
    let _ = writeln!(md, "| Posture Rating | {} |", dash.posture_rating);
    let _ = writeln!(md, "| Critical | {} |", dash.critical_count);
    let _ = writeln!(md, "| High | {} |", dash.high_count);
    let _ = writeln!(md, "| Medium | {} |", dash.medium_count);
    let _ = writeln!(md, "| Low | {} |", dash.low_count);
    md.push('\n');
}

fn append_md_top_findings(md: &mut String, findings: &[TopFinding]) {
    let _ = writeln!(md, "## Top Critical Findings\n");
    if findings.is_empty() {
        let _ = writeln!(md, "No findings.\n");
        return;
    }
    let _ = writeln!(md, "| ID | Title | Severity | Score | Endpoint | Impact |");
    let _ = writeln!(md, "|----|-------|----------|-------|----------|--------|");
    for f in findings {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {:.1} | {} | {} |",
            f.id, f.title, f.severity, f.composite_score, f.endpoint, f.business_impact
        );
    }
    md.push('\n');
}

fn append_md_attack_surface(md: &mut String, surface: &AttackSurfaceSummary) {
    let _ = writeln!(md, "## Attack Surface\n");
    let _ = writeln!(md, "- **Total endpoints:** {}", surface.total_endpoints);
    let _ = writeln!(
        md,
        "- **Tested:** {} ({:.1}%)",
        surface.tested_endpoints, surface.coverage_percent
    );
    let _ = writeln!(md, "- **Untested:** {}\n", surface.untested_count);
}

fn append_md_trend_analysis(md: &mut String, trend: &Option<TrendAnalysis>) {
    let _ = writeln!(md, "## Trend Analysis\n");
    match trend {
        Some(t) => {
            let _ = writeln!(md, "- **Previous scan:** {}", t.previous_scan_date);
            let _ = writeln!(
                md,
                "- **Finding delta:** {} ({}→{})",
                delta_label(t.delta_findings),
                t.previous_finding_count,
                t.current_finding_count
            );
            let _ = writeln!(md, "- **Score delta:** {:+.1}", t.score_delta);
            let _ = writeln!(md, "- **Trend:** {}\n", t.trend_direction);
        }
        None => {
            let _ = writeln!(md, "No previous scan data available.\n");
        }
    }
}

fn append_md_remediation(md: &mut String, items: &[RemediationItem]) {
    let _ = writeln!(md, "## Remediation Roadmap\n");
    if items.is_empty() {
        let _ = writeln!(md, "No remediations needed.\n");
        return;
    }
    let _ = writeln!(md, "| # | Finding | Severity | Remediation | Effort |");
    let _ = writeln!(md, "|---|---------|----------|-------------|--------|");
    for item in items {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} |",
            item.priority,
            item.title,
            item.severity,
            item.remediation,
            format_effort(&item.effort_estimate)
        );
    }
    md.push('\n');
}

fn append_md_compliance(md: &mut String, statuses: &[ComplianceStatus]) {
    let _ = writeln!(md, "## Compliance Status\n");
    if statuses.is_empty() {
        let _ = writeln!(md, "No compliance frameworks selected.\n");
        return;
    }
    let _ = writeln!(md, "| Framework | Status | Violations | Categories |");
    let _ = writeln!(md, "|-----------|--------|------------|------------|");
    for s in statuses {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} |",
            s.framework,
            s.status,
            s.violation_count,
            s.violated_categories.join(", ")
        );
    }
    md.push('\n');
}
