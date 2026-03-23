use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const DANGEROUS_PATTERNS: &[(&str, &str, f64)] = &[
    ("eval(", "eval", 6.0),
    ("innerhtml", "innerHTML", 5.0),
    ("document.write(", "document.write", 5.0),
    ("outerhtml", "outerHTML", 4.5),
    ("insertadjacenthtml(", "insertAdjacentHTML", 4.5),
    (".html(", "jQuery.html", 4.0),
    ("dangerouslysetinnerhtml", "dangerouslySetInnerHTML", 4.0),
    ("new function(", "Function_constructor", 5.5),
    ("settimeout(", "setTimeout_string", 3.0),
    ("setinterval(", "setInterval_string", 3.0),
];

#[derive(Debug, Clone)]
pub struct DangerousJsIssue {
    pub pattern: String,
    pub severity: f64,
}

pub fn audit_dangerous_js(target: &str) -> Vec<DangerousJsIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    find_dangerous_js(&body)
}

pub(crate) fn find_dangerous_js(html: &str) -> Vec<DangerousJsIssue> {
    let mut issues = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag_lower = &lower[abs_start..abs_start + tag_end + 1];

        if tag_lower.contains("src=") {
            search_from = abs_start + tag_end + 1;
            continue;
        }

        let script_end = lower[abs_start + tag_end + 1..]
            .find("</script>")
            .map(|e| abs_start + tag_end + 1 + e)
            .unwrap_or(lower.len());

        let script_body = &lower[abs_start + tag_end + 1..script_end];
        search_from = script_end;

        let mut seen = HashSet::new();
        for (pattern, name, severity) in DANGEROUS_PATTERNS {
            if script_body.contains(pattern) && seen.insert(*name) {
                issues.push(DangerousJsIssue {
                    pattern: name.to_string(),
                    severity: *severity,
                });
            }
        }
    }

    issues
}

pub fn dangerous_js_to_operations(
    issues: &[DangerousJsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::CrossSiteScripting,
        max_severity,
        0.7,
    )]
}
