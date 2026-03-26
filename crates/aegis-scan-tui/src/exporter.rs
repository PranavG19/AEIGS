use std::io::Write;
use std::path::Path;

use crate::app::App;

/// Build the JSON report value from app state.
fn build_report(app: &App) -> serde_json::Value {
    let findings_json: Vec<serde_json::Value> = app
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "severity": f.severity.label(),
                "type": f.vuln_type,
                "endpoint": f.endpoint,
                "method": f.method,
                "confidence": f.confidence,
                "description": f.description,
                "evidence": {
                    "request": f.evidence_request,
                    "response": f.evidence_response,
                },
                "curl_command": f.curl_command,
                "remediation": f.remediation,
                "cvss": {
                    "score": f.cvss_score,
                    "vector": f.cvss_vector,
                },
                "cwe_id": f.cwe_id,
                "attack_technique": f.attack_technique,
            })
        })
        .collect();

    serde_json::json!({
        "target": app.target_url,
        "profile": app.profile.label(),
        "elapsed_seconds": app.elapsed_secs(),
        "request_count": app.request_count,
        "endpoints_discovered": app.endpoints_discovered,
        "risk_score": app.risk_score,
        "risk_grade": app.risk_grade(),
        "findings_count": app.findings.len(),
        "severity_counts": {
            "critical": app.severity_counts()[0],
            "high": app.severity_counts()[1],
            "medium": app.severity_counts()[2],
            "low": app.severity_counts()[3],
            "info": app.severity_counts()[4],
        },
        "findings": findings_json,
        "attack_chains": app.attack_chains.iter().map(|c| {
            serde_json::json!({
                "total_severity": c.total_severity,
                "nodes": c.nodes.iter().map(|n| {
                    serde_json::json!({
                        "label": n.label,
                        "finding_id": n.finding_id,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

/// Export findings to a JSON file in the current directory.
pub fn export_findings(app: &App) -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let filename = format!("aegis-report-{timestamp}.json");
    write_report(app, Path::new(&filename))?;
    Ok(filename)
}

/// Export findings to a specific path. Used by tests.
#[cfg(test)]
pub fn export_to_path(app: &App, path: &Path) -> Result<(), String> {
    write_report(app, path)
}

fn write_report(app: &App, path: &Path) -> Result<(), String> {
    let report = build_report(app);
    let json_str = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;
    let display = path.display();
    let mut file =
        std::fs::File::create(path).map_err(|e| format!("Failed to create {display}: {e}"))?;
    file.write_all(json_str.as_bytes())
        .map_err(|e| format!("Failed to write {display}: {e}"))?;
    Ok(())
}

#[cfg(test)]
#[path = "exporter_test.rs"]
mod exporter_test;
