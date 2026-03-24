use std::fmt::Write;

use serde::{Deserialize, Serialize};

/// HTTP request captured as evidence for a vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestEvidence {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// HTTP response captured as evidence for a vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseEvidence {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub response_time_ms: Option<u64>,
}

/// A single timestamped event in the finding's discovery timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub confidence: Option<f64>,
}

/// MITRE ATT&CK technique and tactic mapping for a vulnerability class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub cwe_id: String,
}

/// Complete evidence bundle for a single vulnerability finding.
///
/// Contains the HTTP exchange, reproduction instructions, timeline,
/// related findings for chaining, and MITRE ATT&CK mapping. Designed
/// for serialization into per-finding evidence exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub finding_id: String,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub request: Option<HttpRequestEvidence>,
    pub response: Option<HttpResponseEvidence>,
    pub curl_command: String,
    pub screenshot_path: Option<String>,
    pub timeline: Vec<TimelineEvent>,
    pub related_finding_ids: Vec<String>,
    pub attack_mapping: AttackMapping,
    pub reproduction_steps: Vec<String>,
}

/// Incremental builder for assembling an `EvidencePackage`.
pub struct EvidenceBuilder {
    finding_id: String,
    vulnerability_class: String,
    endpoint: String,
    request: Option<HttpRequestEvidence>,
    response: Option<HttpResponseEvidence>,
    screenshot_path: Option<String>,
    timeline: Vec<TimelineEvent>,
    related_finding_ids: Vec<String>,
    reproduction_steps: Vec<String>,
}

impl EvidenceBuilder {
    pub fn new(finding_id: &str, vuln_class: &str, endpoint: &str) -> Self {
        Self {
            finding_id: finding_id.to_string(),
            vulnerability_class: vuln_class.to_string(),
            endpoint: endpoint.to_string(),
            request: None,
            response: None,
            screenshot_path: None,
            timeline: Vec::new(),
            related_finding_ids: Vec::new(),
            reproduction_steps: Vec::new(),
        }
    }

    pub fn with_request(mut self, req: HttpRequestEvidence) -> Self {
        self.request = Some(req);
        self
    }

    pub fn with_response(mut self, resp: HttpResponseEvidence) -> Self {
        self.response = Some(resp);
        self
    }

    pub fn with_screenshot(mut self, path: &str) -> Self {
        self.screenshot_path = Some(path.to_string());
        self
    }

    pub fn with_timeline_event(mut self, event: TimelineEvent) -> Self {
        self.timeline.push(event);
        self
    }

    pub fn with_related_finding(mut self, id: &str) -> Self {
        self.related_finding_ids.push(id.to_string());
        self
    }

    pub fn with_reproduction_step(mut self, step: &str) -> Self {
        self.reproduction_steps.push(step.to_string());
        self
    }

    /// Consume the builder and produce a finalized `EvidencePackage`.
    ///
    /// Generates the curl command from the stored request (if present)
    /// and resolves the ATT&CK mapping from the vulnerability class.
    pub fn build(self) -> EvidencePackage {
        let curl_command = self
            .request
            .as_ref()
            .map(generate_curl_command)
            .unwrap_or_default();

        let attack_mapping = generate_attack_mapping(&self.vulnerability_class);

        EvidencePackage {
            finding_id: self.finding_id,
            vulnerability_class: self.vulnerability_class,
            endpoint: self.endpoint,
            request: self.request,
            response: self.response,
            curl_command,
            screenshot_path: self.screenshot_path,
            timeline: self.timeline,
            related_finding_ids: self.related_finding_ids,
            attack_mapping,
            reproduction_steps: self.reproduction_steps,
        }
    }
}

/// Build a curl command string from an HTTP request evidence record.
///
/// Handles method (`-X`), headers (`-H`), request body (`-d`), and URL.
/// GET requests omit the `-X` flag since curl defaults to GET.
pub fn generate_curl_command(req: &HttpRequestEvidence) -> String {
    let mut parts = vec!["curl".to_string()];

    if req.method != "GET" {
        parts.push(format!("-X {}", req.method));
    }

    for (name, value) in &req.headers {
        parts.push(format!("-H '{}: {}'", name, value));
    }

    if let Some(body) = &req.body {
        parts.push(format!("-d '{}'", body));
    }

    parts.push(format!("'{}'", req.url));
    parts.join(" ")
}

/// Map a vulnerability class name to its MITRE ATT&CK technique and tactic.
///
/// Falls back to T1190 "Exploit Public-Facing Application" for
/// unrecognised class strings.
pub fn generate_attack_mapping(vuln_class: &str) -> AttackMapping {
    let (technique_id, technique_name, tactic, cwe_id) = match vuln_class {
        "SqlInjection" | "SQL Injection" => (
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
            "CWE-89",
        ),
        "CrossSiteScripting" | "XSS" | "Cross-Site Scripting" => {
            ("T1189", "Drive-by Compromise", "Initial Access", "CWE-79")
        }
        "CommandInjection" | "Command Injection" => (
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "CWE-78",
        ),
        "PathTraversal" | "Path Traversal" => (
            "T1083",
            "File and Directory Discovery",
            "Discovery",
            "CWE-22",
        ),
        "ServerSideRequestForgery" | "SSRF" => ("T1090", "Proxy", "Command and Control", "CWE-918"),
        "InsecureDeserialization" => (
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
            "CWE-502",
        ),
        "BrokenAuthentication" => ("T1078", "Valid Accounts", "Defense Evasion", "CWE-287"),
        "BrokenAuthorization" => (
            "T1548",
            "Abuse Elevation Control Mechanism",
            "Privilege Escalation",
            "CWE-863",
        ),
        "ServerSideTemplateInjection" | "SSTI" => {
            ("T1221", "Template Injection", "Defense Evasion", "CWE-1336")
        }
        "OpenRedirect" => ("T1204", "User Execution", "Execution", "CWE-601"),
        "KnownVulnerableDependency" => (
            "T1195",
            "Supply Chain Compromise",
            "Initial Access",
            "CWE-1395",
        ),
        _ => (
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
            "CWE-0",
        ),
    };

    AttackMapping {
        technique_id: technique_id.to_string(),
        technique_name: technique_name.to_string(),
        tactic: tactic.to_string(),
        cwe_id: cwe_id.to_string(),
    }
}

/// Serialize an evidence package to pretty-printed JSON.
pub fn render_evidence_json(package: &EvidencePackage) -> String {
    serde_json::to_string_pretty(package).unwrap_or_default()
}

/// Render an evidence package as a human-readable Markdown report.
pub fn render_evidence_markdown(package: &EvidencePackage) -> String {
    let mut md = String::new();

    let _ = writeln!(md, "# Evidence: {}", package.finding_id);
    let _ = writeln!(md);
    let _ = writeln!(md, "**Vulnerability:** {}", package.vulnerability_class);
    let _ = writeln!(md, "**Endpoint:** {}", package.endpoint);
    let _ = writeln!(md);

    let _ = writeln!(md, "## ATT&CK Mapping");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "- **Technique:** {} ({})",
        package.attack_mapping.technique_name, package.attack_mapping.technique_id
    );
    let _ = writeln!(md, "- **Tactic:** {}", package.attack_mapping.tactic);
    let _ = writeln!(md, "- **CWE:** {}", package.attack_mapping.cwe_id);
    let _ = writeln!(md);

    if let Some(req) = &package.request {
        let _ = writeln!(md, "## HTTP Request");
        let _ = writeln!(md);
        let _ = writeln!(md, "```");
        let _ = writeln!(md, "{} {}", req.method, req.url);
        for (name, value) in &req.headers {
            let _ = writeln!(md, "{name}: {value}");
        }
        if let Some(body) = &req.body {
            let _ = writeln!(md);
            let _ = writeln!(md, "{body}");
        }
        let _ = writeln!(md, "```");
        let _ = writeln!(md);
    }

    if let Some(resp) = &package.response {
        let _ = writeln!(md, "## HTTP Response");
        let _ = writeln!(md);
        let _ = writeln!(md, "```");
        let _ = writeln!(md, "Status: {}", resp.status_code);
        for (name, value) in &resp.headers {
            let _ = writeln!(md, "{name}: {value}");
        }
        if let Some(body) = &resp.body {
            let _ = writeln!(md);
            let _ = writeln!(md, "{body}");
        }
        let _ = writeln!(md, "```");
        let _ = writeln!(md);
    }

    let _ = writeln!(md, "## Reproduction");
    let _ = writeln!(md);
    let _ = writeln!(md, "```bash");
    let _ = writeln!(md, "{}", package.curl_command);
    let _ = writeln!(md, "```");
    let _ = writeln!(md);

    if !package.reproduction_steps.is_empty() {
        let _ = writeln!(md, "### Steps");
        let _ = writeln!(md);
        for (i, step) in package.reproduction_steps.iter().enumerate() {
            let _ = writeln!(md, "{}. {step}", i + 1);
        }
        let _ = writeln!(md);
    }

    if !package.timeline.is_empty() {
        let _ = writeln!(md, "## Timeline");
        let _ = writeln!(md);
        for event in &package.timeline {
            let confidence_suffix = event
                .confidence
                .map(|c| format!(" (confidence: {c:.2})"))
                .unwrap_or_default();
            let _ = writeln!(
                md,
                "- **{}** [{}]: {}{}",
                event.timestamp, event.event_type, event.description, confidence_suffix
            );
        }
        let _ = writeln!(md);
    }

    if !package.related_finding_ids.is_empty() {
        let _ = writeln!(md, "## Related Findings");
        let _ = writeln!(md);
        for id in &package.related_finding_ids {
            let _ = writeln!(md, "- {id}");
        }
        let _ = writeln!(md);
    }

    if let Some(screenshot) = &package.screenshot_path {
        let _ = writeln!(md, "## Screenshot");
        let _ = writeln!(md);
        let _ = writeln!(md, "![Evidence screenshot]({screenshot})");
        let _ = writeln!(md);
    }

    md
}
