use std::fmt::Write;

pub fn generate_finding_narrative(
    rule_id: &str,
    vulnerability_class: Option<&str>,
    composite_score: f64,
    defense_context: Option<&str>,
) -> String {
    let severity_label = severity_from_score(composite_score);
    let vuln_description = vulnerability_class
        .map(|vc| format!("{vc} detected"))
        .unwrap_or_else(|| "Potential vulnerability detected".to_string());

    let mut narrative = format!(
        "Finding {rule_id}: {vuln_description} with {severity_label} confidence (score: {composite_score:.1}/100)."
    );

    if let Some(vc) = vulnerability_class {
        let explanation = vulnerability_explanation(vc);
        let _ = write!(narrative, " {explanation}");
    }

    if let Some(defense) = defense_context {
        let _ = write!(
            narrative,
            " Despite {defense}, this endpoint remains exploitable."
        );
    }

    narrative
}

pub fn translate_centrality_to_narrative(node_label: &str, centrality: f64) -> String {
    let percentage = (centrality * 100.0).round() as u64;

    if centrality > 0.7 {
        format!(
            "The endpoint '{node_label}' (centrality: {centrality:.2}) is a critical chokepoint \
             — {percentage}% of attack paths pass through it. Hardening this single component \
             would significantly reduce the attack surface."
        )
    } else if centrality > 0.3 {
        format!(
            "The endpoint '{node_label}' (centrality: {centrality:.2}) is moderately connected \
             — {percentage}% of attack paths involve it. Strengthening this component would \
             reduce overall exposure."
        )
    } else {
        format!(
            "The endpoint '{node_label}' (centrality: {centrality:.2}) has limited connectivity \
             — {percentage}% of attack paths involve it."
        )
    }
}

pub fn generate_executive_summary(
    total_findings: usize,
    critical_count: usize,
    high_count: usize,
    defenses_detected: &[String],
) -> String {
    let mut summary = format!(
        "Scan complete: {total_findings} findings identified ({critical_count} critical, {high_count} high)."
    );

    if !defenses_detected.is_empty() {
        let defense_list = defenses_detected.join(", ");
        let _ = write!(summary, " Active defenses detected: {defense_list}.");
    }

    if critical_count > 0 {
        let _ = write!(
            summary,
            " Immediate remediation recommended for critical findings."
        );
    }

    summary
}

fn severity_from_score(score: f64) -> &'static str {
    if score >= 70.0 {
        "high"
    } else if score >= 40.0 {
        "medium"
    } else {
        "low"
    }
}

pub fn summarize_attack_paths(
    entry_count: usize,
    asset_count: usize,
    total_paths: usize,
) -> String {
    format!(
        "Discovered {total_paths} attack paths from {entry_count} entry points \
         to {asset_count} critical assets."
    )
}

pub fn describe_defense_impact(defense_name: &str, score_reduction_pct: f64) -> String {
    format!("{defense_name} reduces risk by {score_reduction_pct:.0}%.")
}

/// Structured actionable narrative for a single finding.
#[derive(Debug, Clone)]
pub struct ActionableNarrative {
    pub what: String,
    pub why_it_matters: String,
    pub how_to_fix: String,
    pub confidence_note: String,
}

/// Input context used to generate an actionable narrative.
#[derive(Debug, Clone)]
pub struct NarrativeContext {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub vulnerability_class: String,
    pub severity: f64,
    pub confidence: f64,
    pub is_authenticated: bool,
    pub accesses_pii: bool,
    pub defense_context: Option<String>,
    pub calibration_note: Option<String>,
}

/// Generate a structured four-section narrative for a finding.
pub fn generate_actionable_narrative(ctx: &NarrativeContext) -> ActionableNarrative {
    let what = if ctx.parameter.is_empty() {
        format!(
            "{} detected in {} {}",
            ctx.vulnerability_class, ctx.method, ctx.endpoint
        )
    } else {
        format!(
            "{} in the {} parameter of {} {}",
            ctx.vulnerability_class, ctx.parameter, ctx.method, ctx.endpoint
        )
    };

    let why_it_matters = build_why_it_matters(ctx);
    let how_to_fix = remediation_advice(&ctx.vulnerability_class).to_string();
    let confidence_note = build_confidence_note(ctx);

    ActionableNarrative {
        what,
        why_it_matters,
        how_to_fix,
        confidence_note,
    }
}

fn build_why_it_matters(ctx: &NarrativeContext) -> String {
    let mut parts: Vec<String> = Vec::new();

    if !ctx.is_authenticated {
        parts.push("This endpoint is accessible without authentication.".to_string());
    }
    if ctx.accesses_pii {
        parts.push(
            "This endpoint accesses data containing personally identifiable information."
                .to_string(),
        );
    }

    let severity_label = severity_label_from_score(ctx.severity);
    parts.push(format!(
        "Severity: {:.1}/10 ({severity_label}).",
        ctx.severity
    ));

    if let Some(ref defense) = ctx.defense_context {
        parts.push(format!(
            "Active defense: {defense}. Despite this, the endpoint remains exploitable."
        ));
    }

    parts.join(" ")
}

fn build_confidence_note(ctx: &NarrativeContext) -> String {
    let pct = (ctx.confidence * 100.0).round() as u64;
    let mut note = format!("Confidence: {pct}%.");

    if let Some(ref calibration) = ctx.calibration_note {
        note.push(' ');
        note.push_str(calibration);
    }

    if ctx.confidence < 0.5 {
        note.push_str(" This finding has low confidence and should be manually verified.");
    }

    note
}

fn severity_label_from_score(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else {
        "low"
    }
}

/// Map a vulnerability class display name to remediation guidance.
pub fn remediation_advice(vulnerability_class: &str) -> &'static str {
    match vulnerability_class {
        "SQL Injection" => {
            "Use parameterized queries or prepared statements. \
             Never concatenate user input into SQL strings."
        }
        "Cross-Site Scripting" => {
            "Encode all user-controlled output. \
             Use Content-Security-Policy headers. Sanitize HTML input."
        }
        "Command Injection" => {
            "Avoid shell commands with user input. \
             Use language-native APIs instead of system() calls."
        }
        "Path Traversal" => {
            "Validate and canonicalize file paths. \
             Use an allowlist of permitted directories."
        }
        "Server-Side Request Forgery" => {
            "Validate and allowlist destination URLs. Block internal network ranges."
        }
        "Broken Authentication" => {
            "Implement proper session management. Use secure, httpOnly cookies."
        }
        "Broken Authorization" => {
            "Enforce access controls at the server side. \
             Verify authorization for every request."
        }
        _ => {
            "Review the implementation for security weaknesses. Apply defense-in-depth principles."
        }
    }
}

fn vulnerability_explanation(vulnerability_class: &str) -> &'static str {
    match vulnerability_class {
        "SQL Injection" => {
            "This vulnerability allows an attacker to manipulate database queries through user-controlled input."
        }
        "Cross-Site Scripting" => {
            "This vulnerability allows an attacker to inject malicious scripts into web pages viewed by other users."
        }
        "Command Injection" => {
            "This vulnerability allows an attacker to execute arbitrary system commands on the host."
        }
        "Path Traversal" => {
            "This vulnerability allows an attacker to access files outside the intended directory."
        }
        "Authentication Bypass" => {
            "This vulnerability allows an attacker to circumvent authentication controls."
        }
        "SSRF" => {
            "This vulnerability allows an attacker to make the server issue requests to unintended locations."
        }
        _ => {
            "This vulnerability may allow an attacker to compromise system integrity or confidentiality."
        }
    }
}
