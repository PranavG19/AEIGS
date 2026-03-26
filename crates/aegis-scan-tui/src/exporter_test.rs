use crate::app::{App, AttackChain, ChainNode, Finding, ScanProfile, Severity};

#[test]
fn export_creates_valid_json() {
    let mut app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    let f = Finding {
        id: 0,
        severity: Severity::High,
        vuln_type: "XSS".to_string(),
        endpoint: "/search".to_string(),
        method: "GET".to_string(),
        confidence: 0.91,
        discovered_at: std::time::Instant::now(),
        description: "test".to_string(),
        evidence_request: "GET /".to_string(),
        evidence_response: "200 OK".to_string(),
        curl_command: "curl http://x".to_string(),
        remediation: "fix".to_string(),
        cvss_score: 7.5,
        cvss_vector: "CVSS:3.1/AV:N".to_string(),
        cwe_id: "CWE-79".to_string(),
        attack_technique: "T1189".to_string(),
    };
    app.findings.push(f);
    app.attack_chains.push(AttackChain {
        nodes: vec![ChainNode {
            label: "XSS".to_string(),
            finding_id: 0,
        }],
        total_severity: 7.5,
    });

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let result = super::export_to_path(&app, &path);
    assert!(result.is_ok(), "export failed: {:?}", result.err());

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["target"], "http://example.com");
    assert_eq!(parsed["findings_count"], 1);
    assert_eq!(parsed["findings"][0]["type"], "XSS");
}

#[test]
fn export_empty_findings() {
    let app = App::new("http://example.com".to_string(), ScanProfile::Quick);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty-report.json");
    let result = super::export_to_path(&app, &path);
    assert!(result.is_ok());

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["findings_count"], 0);
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn export_includes_attack_chains() {
    let mut app = App::new("http://target.local".to_string(), ScanProfile::Deep);
    app.attack_chains.push(AttackChain {
        nodes: vec![
            ChainNode {
                label: "SQLi".to_string(),
                finding_id: 0,
            },
            ChainNode {
                label: "RCE".to_string(),
                finding_id: 1,
            },
        ],
        total_severity: 19.6,
    });

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chains.json");
    super::export_to_path(&app, &path).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let chains = parsed["attack_chains"].as_array().unwrap();
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0]["nodes"].as_array().unwrap().len(), 2);
}

#[test]
fn export_severity_counts_correct() {
    let mut app = App::new("http://target.local".to_string(), ScanProfile::Quick);
    for (i, sev) in [
        Severity::Critical,
        Severity::High,
        Severity::High,
        Severity::Medium,
    ]
    .iter()
    .enumerate()
    {
        app.findings.push(Finding {
            id: i as u64,
            severity: *sev,
            vuln_type: format!("vuln-{i}"),
            endpoint: "/".to_string(),
            method: "GET".to_string(),
            confidence: 0.8,
            discovered_at: std::time::Instant::now(),
            description: String::new(),
            evidence_request: String::new(),
            evidence_response: String::new(),
            curl_command: String::new(),
            remediation: String::new(),
            cvss_score: 5.0,
            cvss_vector: String::new(),
            cwe_id: String::new(),
            attack_technique: String::new(),
        });
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("counts.json");
    super::export_to_path(&app, &path).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["severity_counts"]["critical"], 1);
    assert_eq!(parsed["severity_counts"]["high"], 2);
    assert_eq!(parsed["severity_counts"]["medium"], 1);
}
