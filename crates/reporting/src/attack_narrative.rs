use std::fmt::Write;

use serde::{Deserialize, Serialize};

/// An HTTP request or response captured during exploitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpExchange {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub status_code: Option<u16>,
}

/// A single step in an attack chain with optional HTTP evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_number: u32,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub technique: String,
    pub description: String,
    pub http_request: Option<HttpExchange>,
    pub http_response: Option<HttpExchange>,
}

/// A complete attack narrative built from chain analysis.
///
/// Contains the human-readable story, mermaid diagram, and technical
/// appendix with raw HTTP exchanges for each exploitation step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNarrative {
    pub title: String,
    pub severity: String,
    pub summary: String,
    pub attack_vector: String,
    pub steps: Vec<AttackStep>,
    pub impact: String,
    pub remediation: String,
    pub mermaid_diagram: String,
    pub technical_appendix: String,
}

/// Raw input describing an attack step before narrative generation.
#[derive(Debug, Clone)]
pub struct AttackStepInput {
    pub vulnerability_class: String,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub technique: String,
    pub request: Option<HttpExchange>,
    pub response: Option<HttpExchange>,
}

/// Input bundle for generating a complete attack narrative from chain data.
#[derive(Debug, Clone)]
pub struct ChainNarrativeInput {
    pub chain_id: String,
    pub steps: Vec<AttackStepInput>,
    pub target_asset: String,
    pub overall_difficulty: f64,
}

/// Build a full attack narrative from chain input data.
pub fn generate_narrative(input: &ChainNarrativeInput) -> AttackNarrative {
    let steps = build_attack_steps(&input.steps);
    let severity = severity_from_difficulty(input.overall_difficulty);
    let summary = generate_summary(&input.steps, &input.target_asset);
    let attack_vector = derive_attack_vector(&input.steps);
    let impact = derive_impact(&input.steps, &input.target_asset);
    let remediation = derive_remediation(&input.steps);
    let mermaid_diagram = generate_mermaid_diagram(&steps);
    let technical_appendix = generate_technical_appendix(&steps);

    AttackNarrative {
        title: format!("Attack Chain {}", input.chain_id),
        severity,
        summary,
        attack_vector,
        steps,
        impact,
        remediation,
        mermaid_diagram,
        technical_appendix,
    }
}

/// Generate a mermaid flowchart from attack steps.
///
/// Produces a `graph TD` with one node per step, connected by arrows
/// labeled with the exploitation technique used at each transition.
pub fn generate_mermaid_diagram(steps: &[AttackStep]) -> String {
    let mut diagram = String::from("graph TD\n");

    for step in steps {
        let node_id = format!("S{}", step.step_number);
        let label = format!("{}: {}", step.vulnerability_class, step.endpoint);
        let _ = writeln!(diagram, "    {node_id}[\"{label}\"]");
    }

    for window in steps.windows(2) {
        let from_id = format!("S{}", window[0].step_number);
        let to_id = format!("S{}", window[1].step_number);
        let edge_label = &window[1].technique;
        let _ = writeln!(diagram, "    {from_id} -->|{edge_label}| {to_id}");
    }

    diagram
}

/// Format all HTTP exchanges from attack steps into a technical appendix.
pub fn generate_technical_appendix(steps: &[AttackStep]) -> String {
    let mut appendix = String::new();

    for step in steps {
        let _ = writeln!(
            appendix,
            "--- Step {} ({}) ---",
            step.step_number, step.vulnerability_class
        );

        if let Some(req) = &step.http_request {
            let _ = writeln!(appendix, "Request:");
            let _ = writeln!(appendix, "  {} {}", req.method, req.url);
            for (name, value) in &req.headers {
                let _ = writeln!(appendix, "  {name}: {value}");
            }
            if let Some(body) = &req.body {
                let _ = writeln!(appendix, "  Body: {body}");
            }
        }

        if let Some(resp) = &step.http_response {
            let status = resp
                .status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let _ = writeln!(appendix, "Response (status {status}):");
            for (name, value) in &resp.headers {
                let _ = writeln!(appendix, "  {name}: {value}");
            }
            if let Some(body) = &resp.body {
                let _ = writeln!(appendix, "  Body: {body}");
            }
        }

        let _ = writeln!(appendix);
    }

    appendix
}

/// Create a natural-language summary from attack step inputs.
///
/// Produces prose like: "An attacker could exploit the SQL Injection on
/// /api/login to extract session tokens, then leverage the Broken
/// Authorization on /api/users/{id} to access any user's profile,
/// ultimately reaching the target asset: user database containing PII."
pub fn generate_summary(steps: &[AttackStepInput], target: &str) -> String {
    if steps.is_empty() {
        return format!("No exploitation steps identified for the target asset: {target}.");
    }

    let mut parts = Vec::with_capacity(steps.len());

    for (i, step) in steps.iter().enumerate() {
        let param_clause = step
            .parameter
            .as_ref()
            .map(|p| format!(" via the {p} parameter"))
            .unwrap_or_default();

        let action = action_verb_for(&step.vulnerability_class);

        if i == 0 {
            parts.push(format!(
                "An attacker could exploit the {} on {}{param_clause} to {action}",
                step.vulnerability_class, step.endpoint
            ));
        } else {
            parts.push(format!(
                "then leverage the {} on {}{param_clause} to {action}",
                step.vulnerability_class, step.endpoint
            ));
        }
    }

    let chain_text = parts.join(", ");
    format!("{chain_text}, ultimately reaching the target asset: {target}.")
}

fn build_attack_steps(inputs: &[AttackStepInput]) -> Vec<AttackStep> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let description = format!(
                "Exploit {} on {} using {}.",
                input.vulnerability_class, input.endpoint, input.technique
            );
            AttackStep {
                step_number: (i + 1) as u32,
                vulnerability_class: input.vulnerability_class.clone(),
                endpoint: input.endpoint.clone(),
                technique: input.technique.clone(),
                description,
                http_request: input.request.clone(),
                http_response: input.response.clone(),
            }
        })
        .collect()
}

fn severity_from_difficulty(difficulty: f64) -> String {
    if difficulty <= 2.0 {
        "Critical".to_string()
    } else if difficulty <= 5.0 {
        "High".to_string()
    } else if difficulty <= 8.0 {
        "Medium".to_string()
    } else {
        "Low".to_string()
    }
}

fn derive_attack_vector(steps: &[AttackStepInput]) -> String {
    match steps.first() {
        Some(step) => format!(
            "Initial access via {} on {}",
            step.vulnerability_class, step.endpoint
        ),
        None => "No attack vector identified.".to_string(),
    }
}

fn derive_impact(steps: &[AttackStepInput], target_asset: &str) -> String {
    let vuln_list: Vec<&str> = steps
        .iter()
        .map(|s| s.vulnerability_class.as_str())
        .collect();
    let unique_count = {
        let mut seen = std::collections::HashSet::new();
        for v in &vuln_list {
            seen.insert(*v);
        }
        seen.len()
    };

    format!(
        "Chaining {count} vulnerabilit{plural} ({vulns}) grants access to {target_asset}.",
        count = unique_count,
        plural = if unique_count == 1 { "y" } else { "ies" },
        vulns = vuln_list.join(", ")
    )
}

fn derive_remediation(steps: &[AttackStepInput]) -> String {
    let mut remediation_items = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        let advice = remediation_for_class(&step.vulnerability_class);
        remediation_items.push(format!(
            "{}. Fix {} on {}: {advice}",
            i + 1,
            step.vulnerability_class,
            step.endpoint
        ));
    }

    remediation_items.join("\n")
}

fn action_verb_for(vulnerability_class: &str) -> &'static str {
    match vulnerability_class {
        "SQL Injection" => "extract sensitive data",
        "Cross-Site Scripting" => "steal session tokens",
        "Command Injection" => "execute arbitrary commands",
        "Path Traversal" => "read restricted files",
        "Server-Side Request Forgery" => "reach internal services",
        "Broken Authentication" => "bypass login controls",
        "Broken Authorization" => "escalate privileges",
        "Insecure Direct Object Reference" => "access other users' resources",
        "Server-Side Template Injection" => "execute server-side code",
        "Information Disclosure" => "gather internal details",
        _ => "compromise the application",
    }
}

fn remediation_for_class(vulnerability_class: &str) -> &'static str {
    match vulnerability_class {
        "SQL Injection" => {
            "Use parameterized queries or prepared statements instead of string concatenation."
        }
        "Cross-Site Scripting" => {
            "Apply context-aware output encoding and use a Content Security Policy."
        }
        "Command Injection" => {
            "Avoid shell invocation; use language-native APIs with allow-listed arguments."
        }
        "Path Traversal" => {
            "Canonicalize paths and validate they remain within the expected base directory."
        }
        "Server-Side Request Forgery" => {
            "Restrict outbound requests to an allow-listed set of hosts and schemes."
        }
        "Broken Authentication" => {
            "Enforce strong credential policies and implement multi-factor authentication."
        }
        "Broken Authorization" => "Apply least-privilege access control checks on every request.",
        "Insecure Direct Object Reference" => {
            "Enforce authorization checks on every object access; use indirect references."
        }
        _ => "Review the implementation and apply defense-in-depth principles.",
    }
}
