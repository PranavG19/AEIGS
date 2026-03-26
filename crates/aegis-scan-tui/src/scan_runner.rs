use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use rand::Rng;

use crate::app::{
    AttackChain, ChainNode, Finding, LogLevel, ScanPhase, ScanProfile, Severity,
};
use crate::event::TuiEvent;

/// Spawn a background thread that drives scan events into the TUI.
pub fn spawn_scan(
    target: String,
    profile: ScanProfile,
    _demo: bool,
    tx: Sender<TuiEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        run_demo_scan(&target, profile, &tx);
    })
}

struct DemoFinding {
    severity: Severity,
    vuln_type: &'static str,
    endpoint: &'static str,
    method: &'static str,
    confidence: f64,
    cvss_score: f64,
    cvss_vector: &'static str,
    cwe_id: &'static str,
    attack_technique: &'static str,
    remediation: &'static str,
}

/// Demo mode: generates realistic fake scan events on a realistic schedule.
fn run_demo_scan(target: &str, _profile: ScanProfile, tx: &Sender<TuiEvent>) {
    let mut finding_id: u64 = 0;
    let mut rng = rand::rng();

    let send = |tx: &Sender<TuiEvent>, evt: TuiEvent| -> bool { tx.send(evt).is_ok() };

    if !send(
        tx,
        TuiEvent::Log {
            level: LogLevel::Info,
            message: format!("Starting scan against {target}"),
        },
    ) {
        return;
    }

    let phases = [
        (ScanPhase::Recon, "Passive Recon", "Dependency Analyzer", "Filesystem Walker", 800, 1500),
        (ScanPhase::Crawl, "Web Crawler", "Page Fetcher", "Form Extractor", 600, 1200),
        (ScanPhase::Enumerate, "Route Discovery", "Auth Matrix", "GraphQL Scanner", 500, 1000),
        (ScanPhase::Fuzz, "Fuzz Engine", "Payload Mutator", "Anomaly Oracle", 300, 800),
        (ScanPhase::Exploit, "SQLMap Wrapper", "Nuclei Scanner", "JWT Tester", 400, 900),
        (ScanPhase::Chain, "Chain Synthesis", "Path Analyzer", "Impact Scorer", 300, 600),
        (ScanPhase::Report, "SARIF Emitter", "Risk Scorer", "Narrative Builder", 200, 500),
    ];

    let demo_endpoints = [
        ("GET", "/api/v1/users"),
        ("POST", "/api/v1/login"),
        ("GET", "/api/v1/products"),
        ("PUT", "/api/v1/users/{id}"),
        ("DELETE", "/api/v1/sessions"),
        ("GET", "/api/v1/admin/config"),
        ("POST", "/api/v1/upload"),
        ("GET", "/api/v1/search?q="),
        ("PATCH", "/api/v1/profile"),
        ("GET", "/api/v1/export"),
        ("POST", "/api/v1/payment"),
        ("GET", "/api/internal/debug"),
        ("POST", "/api/v1/register"),
        ("GET", "/api/v1/orders/{id}"),
        ("POST", "/api/v1/webhook"),
        ("GET", "/graphql"),
    ];

    let demo_findings = vec![
        DemoFinding {
            severity: Severity::Critical,
            vuln_type: "SQL Injection",
            endpoint: "POST /api/v1/login",
            method: "POST",
            confidence: 0.95,
            cvss_score: 9.8,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id: "CWE-89",
            attack_technique: "T1190",
            remediation: "Use parameterized queries instead of string concatenation in SQL statements.",
        },
        DemoFinding {
            severity: Severity::Critical,
            vuln_type: "Remote Code Execution",
            endpoint: "POST /api/v1/upload",
            method: "POST",
            confidence: 0.88,
            cvss_score: 9.8,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cwe_id: "CWE-94",
            attack_technique: "T1059",
            remediation: "Validate file types server-side. Disable script execution in upload directories.",
        },
        DemoFinding {
            severity: Severity::High,
            vuln_type: "Stored XSS",
            endpoint: "GET /api/v1/search?q=",
            method: "GET",
            confidence: 0.91,
            cvss_score: 7.5,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cwe_id: "CWE-79",
            attack_technique: "T1189",
            remediation: "Sanitize all user input and apply Content-Security-Policy headers.",
        },
        DemoFinding {
            severity: Severity::High,
            vuln_type: "Broken Authentication",
            endpoint: "POST /api/v1/login",
            method: "POST",
            confidence: 0.82,
            cvss_score: 8.1,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cwe_id: "CWE-287",
            attack_technique: "T1078",
            remediation: "Implement rate limiting, account lockout, and multi-factor authentication.",
        },
        DemoFinding {
            severity: Severity::High,
            vuln_type: "IDOR",
            endpoint: "GET /api/v1/orders/{id}",
            method: "GET",
            confidence: 0.78,
            cvss_score: 7.1,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cwe_id: "CWE-639",
            attack_technique: "T1565",
            remediation: "Enforce object-level authorization checks before returning data.",
        },
        DemoFinding {
            severity: Severity::Medium,
            vuln_type: "CSRF",
            endpoint: "PATCH /api/v1/profile",
            method: "PATCH",
            confidence: 0.85,
            cvss_score: 6.5,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            cwe_id: "CWE-352",
            attack_technique: "T1185",
            remediation: "Implement anti-CSRF tokens on all state-changing requests.",
        },
        DemoFinding {
            severity: Severity::Medium,
            vuln_type: "Information Disclosure",
            endpoint: "GET /api/internal/debug",
            method: "GET",
            confidence: 0.92,
            cvss_score: 5.3,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id: "CWE-200",
            attack_technique: "T1005",
            remediation: "Remove debug endpoints from production. Restrict internal APIs by IP.",
        },
        DemoFinding {
            severity: Severity::Medium,
            vuln_type: "SSRF",
            endpoint: "POST /api/v1/webhook",
            method: "POST",
            confidence: 0.71,
            cvss_score: 6.1,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cwe_id: "CWE-918",
            attack_technique: "T1210",
            remediation: "Validate and whitelist webhook destination URLs. Block internal network ranges.",
        },
        DemoFinding {
            severity: Severity::Low,
            vuln_type: "Missing Security Headers",
            endpoint: "GET /api/v1/users",
            method: "GET",
            confidence: 0.97,
            cvss_score: 3.1,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cwe_id: "CWE-693",
            attack_technique: "T1189",
            remediation: "Add X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy headers.",
        },
        DemoFinding {
            severity: Severity::Low,
            vuln_type: "Verbose Error Messages",
            endpoint: "GET /api/v1/products",
            method: "GET",
            confidence: 0.89,
            cvss_score: 2.6,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id: "CWE-209",
            attack_technique: "T1005",
            remediation: "Return generic error messages. Log detailed errors server-side only.",
        },
    ];

    for (phase_idx, &(phase, phase_name, mod1, mod2, min_delay, max_delay)) in
        phases.iter().enumerate()
    {
        if !send(tx, TuiEvent::PhaseChanged { phase, progress: 0.0 }) {
            return;
        }
        if !send(tx, TuiEvent::Log {
            level: LogLevel::Info,
            message: format!("Phase: {} — starting {phase_name}", phase.label()),
        }) {
            return;
        }
        if !send(tx, TuiEvent::ModuleStarted { name: mod1.to_string() }) {
            return;
        }
        if !send(tx, TuiEvent::ModuleStarted { name: mod2.to_string() }) {
            return;
        }

        let steps = 10;
        for step in 0..steps {
            let delay = rng.random_range(min_delay..=max_delay);
            thread::sleep(Duration::from_millis(delay));

            let progress = (step + 1) as f64 / steps as f64;
            if !send(tx, TuiEvent::PhaseProgress { phase, progress }) {
                return;
            }

            for _ in 0..rng.random_range(1u32..=4) {
                if !send(tx, TuiEvent::RequestMade) {
                    return;
                }
            }

            if phase_idx <= 2 {
                let ep_idx = rng.random_range(0..demo_endpoints.len());
                let (method, path) = demo_endpoints[ep_idx];
                if !send(tx, TuiEvent::EndpointDiscovered {
                    endpoint: path.to_string(),
                    method: method.to_string(),
                }) {
                    return;
                }
            }

            if phase_idx >= 3
                && step % 3 == 2
                && let Some(demo_f) = demo_findings.get(finding_id as usize)
            {
                let finding = Finding {
                    id: finding_id,
                    severity: demo_f.severity,
                    vuln_type: demo_f.vuln_type.to_string(),
                    endpoint: demo_f.endpoint.to_string(),
                    method: demo_f.method.to_string(),
                    confidence: demo_f.confidence,
                    discovered_at: std::time::Instant::now(),
                    description: format!(
                        "Detected {} vulnerability on endpoint {}. The application fails to properly validate input, allowing an attacker to exploit the {} weakness.",
                        demo_f.vuln_type, demo_f.endpoint, demo_f.vuln_type
                    ),
                    evidence_request: format!(
                        "{} {} HTTP/1.1\nHost: target\nContent-Type: application/json\n\n{{\"payload\": \"<test>\"}}",
                        demo_f.method, demo_f.endpoint
                    ),
                    evidence_response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"error\":\"<test> reflected\"}".to_string(),
                    curl_command: format!(
                        "curl -X {} '{}{}' -H 'Content-Type: application/json' -d '{{\"payload\": \"test\"}}'",
                        demo_f.method, "http://target", demo_f.endpoint
                    ),
                    remediation: demo_f.remediation.to_string(),
                    cvss_score: demo_f.cvss_score,
                    cvss_vector: demo_f.cvss_vector.to_string(),
                    cwe_id: demo_f.cwe_id.to_string(),
                    attack_technique: demo_f.attack_technique.to_string(),
                };
                finding_id += 1;
                if !send(tx, TuiEvent::FindingConfirmed(Box::new(finding))) {
                    return;
                }
            }

            if rng.random_range(0u32..10) < 3 {
                let stealth = rng.random_range(70u8..=99);
                if !send(tx, TuiEvent::StealthUpdate { score: stealth }) {
                    return;
                }
            }
        }

        if !send(tx, TuiEvent::ModuleStopped { name: mod1.to_string() }) {
            return;
        }
        if !send(tx, TuiEvent::ModuleStopped { name: mod2.to_string() }) {
            return;
        }
        if !send(tx, TuiEvent::PhaseProgress { phase, progress: 1.0 }) {
            return;
        }
    }

    if finding_id >= 3 {
        let chain = AttackChain {
            nodes: vec![
                ChainNode {
                    label: "SQL Injection".to_string(),
                    finding_id: 0,
                },
                ChainNode {
                    label: "Broken Auth".to_string(),
                    finding_id: 3,
                },
                ChainNode {
                    label: "IDOR → Data Exfil".to_string(),
                    finding_id: 4,
                },
            ],
            total_severity: 25.0,
        };
        let _ = send(tx, TuiEvent::ChainDiscovered(chain));
    }

    if finding_id >= 2 {
        let chain2 = AttackChain {
            nodes: vec![
                ChainNode {
                    label: "RCE via Upload".to_string(),
                    finding_id: 1,
                },
                ChainNode {
                    label: "SSRF Pivot".to_string(),
                    finding_id: 7,
                },
                ChainNode {
                    label: "Internal Access".to_string(),
                    finding_id: 6,
                },
            ],
            total_severity: 22.0,
        };
        let _ = send(tx, TuiEvent::ChainDiscovered(chain2));
    }

    let _ = send(tx, TuiEvent::ScanComplete);
}

#[cfg(test)]
#[path = "scan_runner_test.rs"]
mod scan_runner_test;
