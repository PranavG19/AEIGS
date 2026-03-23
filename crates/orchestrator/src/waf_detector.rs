use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

const WAF_SIGNATURES: &[(&str, &str)] = &[
    ("cloudflare", "cf-ray"),
    ("akamai", "x-akamai-transformed"),
    ("aws-waf", "x-amzn-requestid"),
    ("sucuri", "x-sucuri-id"),
    ("incapsula", "x-cdn"),
    ("stackpath", "x-sp-"),
    ("barracuda", "barra_counter_session"),
    ("f5-bigip", "x-wa-info"),
    ("fortiweb", "fortiwafsid"),
    ("wallarm", "x-wallarm-"),
];

const WAF_SERVER_VALUES: &[(&str, &str)] = &[
    ("cloudflare", "cloudflare"),
    ("nginx", "nginx"),
    ("apache", "apache"),
    ("microsoft-iis", "microsoft-iis"),
    ("openresty", "openresty"),
    ("litespeed", "litespeed"),
    ("envoy", "envoy"),
    ("varnish", "varnish"),
];

#[derive(Debug, Clone)]
pub struct WafDetection {
    pub waf_name: String,
    pub evidence: String,
}

pub fn detect_waf(target: &str) -> Vec<WafDetection> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut detections = Vec::new();
    let headers = resp.headers();

    for (waf, sig_header) in WAF_SIGNATURES {
        for (name, _value) in headers.iter() {
            if name.as_str().contains(sig_header) {
                detections.push(WafDetection {
                    waf_name: waf.to_string(),
                    evidence: format!("header: {}", name.as_str()),
                });
                break;
            }
        }
    }

    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let lower = server.to_ascii_lowercase();
        for (name, pattern) in WAF_SERVER_VALUES {
            if lower.contains(pattern) {
                detections.push(WafDetection {
                    waf_name: name.to_string(),
                    evidence: format!("server: {server}"),
                });
                break;
            }
        }
    }

    detections
}

pub fn waf_to_operations(detections: &[WafDetection], seq: &mut u64) -> Vec<OperationLogEntry> {
    detections
        .iter()
        .map(|d| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Defense,
                    properties: vec![
                        ("waf_name".to_string(), d.waf_name.clone()),
                        ("evidence".to_string(), d.evidence.clone()),
                        ("source".to_string(), "waf_detect".to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

const WAF_BYPASS_TECHNIQUES: &[(&str, &str)] = &[
    ("cloudflare", "origin IP discovery via DNS history"),
    ("aws-waf", "payload chunking with Transfer-Encoding"),
    ("sucuri", "double URL encoding bypass"),
    ("incapsula", "HTTP/2 header smuggling"),
    ("modsecurity", "Unicode normalization bypass"),
    ("f5-bigip", "request splitting via malformed Content-Length"),
];

const DEBUG_HEADERS: &[&str] = &[
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-waf-debug",
    "x-waf-mode",
    "x-firewall-debug",
    "x-powered-by-waf",
    "x-waf-event-info",
];

const CDN_ONLY_SIGNATURES: &[(&str, &str)] = &[
    ("fastly", "x-served-by"),
    ("keycdn", "x-cache"),
    ("bunnycdn", "cdn-pullzone"),
    ("cloudfront", "x-amz-cf-id"),
];

const LEARNING_MODE_INDICATORS: &[(&str, &str)] = &[
    ("modsecurity", "mod_security: detection only"),
    ("cloudflare", "simulate"),
    ("aws-waf", "count"),
];

const OUTDATED_WAF_PATTERNS: &[(&str, &str)] = &[
    ("modsecurity", "modsecurity/2."),
    ("nginx", "nginx/1.1"),
    ("nginx", "nginx/1.0"),
    ("apache", "apache/2.2"),
    ("microsoft-iis", "microsoft-iis/6"),
    ("microsoft-iis", "microsoft-iis/7"),
];

#[derive(Debug, Clone, PartialEq)]
pub enum WafIssue {
    WafDetected { name: String, evidence: String },
    WafBypassPossible { name: String, technique: String },
    NoWafDetected,
    MultipleWafs { names: Vec<String> },
    OutdatedWaf { name: String, evidence: String },
    WafInLearningMode { name: String },
    CdnWithoutWaf { cdn: String },
    WafHeaderLeakage { header: String, value: String },
}

impl fmt::Display for WafIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafIssue::WafDetected { name, evidence } => {
                write!(f, "WAF detected: {name} (evidence: {evidence})")
            }
            WafIssue::WafBypassPossible { name, technique } => {
                write!(f, "WAF bypass possible for {name}: {technique}")
            }
            WafIssue::NoWafDetected => write!(f, "No WAF protection detected"),
            WafIssue::MultipleWafs { names } => {
                write!(f, "Multiple WAFs detected: {}", names.join(", "))
            }
            WafIssue::OutdatedWaf { name, evidence } => {
                write!(f, "Outdated WAF: {name} (evidence: {evidence})")
            }
            WafIssue::WafInLearningMode { name } => {
                write!(f, "WAF in learning/detection-only mode: {name}")
            }
            WafIssue::CdnWithoutWaf { cdn } => {
                write!(f, "CDN without WAF rules: {cdn}")
            }
            WafIssue::WafHeaderLeakage { header, value } => {
                write!(f, "WAF header leakage: {header}: {value}")
            }
        }
    }
}

pub fn waf_issue_severity(issue: &WafIssue) -> f64 {
    match issue {
        WafIssue::WafDetected { .. } => 0.0,
        WafIssue::WafBypassPossible { .. } => 6.0,
        WafIssue::NoWafDetected => 4.0,
        WafIssue::MultipleWafs { .. } => 2.0,
        WafIssue::OutdatedWaf { .. } => 5.0,
        WafIssue::WafInLearningMode { .. } => 7.0,
        WafIssue::CdnWithoutWaf { .. } => 3.0,
        WafIssue::WafHeaderLeakage { .. } => 5.5,
    }
}

pub fn analyze_waf_headers(headers: &[(&str, &str)]) -> Vec<WafIssue> {
    let mut issues = Vec::new();
    let mut detected_wafs: Vec<String> = Vec::new();

    for (waf_name, sig_header) in WAF_SIGNATURES {
        for &(name, _) in headers {
            if name.to_ascii_lowercase().contains(sig_header) {
                let waf = waf_name.to_string();
                if !detected_wafs.contains(&waf) {
                    detected_wafs.push(waf.clone());
                    issues.push(WafIssue::WafDetected {
                        name: waf,
                        evidence: format!("header: {name}"),
                    });
                }
                break;
            }
        }
    }

    for &(name, value) in headers {
        if name.eq_ignore_ascii_case("server") {
            let lower = value.to_ascii_lowercase();
            for (waf_name, pattern) in WAF_SERVER_VALUES {
                if lower.contains(pattern) {
                    let waf = waf_name.to_string();
                    if !detected_wafs.contains(&waf) {
                        detected_wafs.push(waf.clone());
                        issues.push(WafIssue::WafDetected {
                            name: waf,
                            evidence: format!("server: {value}"),
                        });
                    }
                    break;
                }
            }

            for (waf_name, outdated_pattern) in OUTDATED_WAF_PATTERNS {
                if lower.contains(outdated_pattern) {
                    issues.push(WafIssue::OutdatedWaf {
                        name: waf_name.to_string(),
                        evidence: value.to_string(),
                    });
                    break;
                }
            }
        }
    }

    for waf in &detected_wafs {
        for (bypass_waf, technique) in WAF_BYPASS_TECHNIQUES {
            if waf == bypass_waf {
                issues.push(WafIssue::WafBypassPossible {
                    name: waf.clone(),
                    technique: technique.to_string(),
                });
                break;
            }
        }
    }

    for &(name, value) in headers {
        let lower_name = name.to_ascii_lowercase();
        for debug_header in DEBUG_HEADERS {
            if lower_name == *debug_header {
                issues.push(WafIssue::WafHeaderLeakage {
                    header: name.to_string(),
                    value: value.to_string(),
                });
                break;
            }
        }
    }

    let mut cdn_detected: Option<String> = None;
    for (cdn_name, cdn_header) in CDN_ONLY_SIGNATURES {
        for &(name, _) in headers {
            if name.to_ascii_lowercase().contains(cdn_header) {
                cdn_detected = Some(cdn_name.to_string());
                break;
            }
        }
        if cdn_detected.is_some() {
            break;
        }
    }
    let has_cdn = cdn_detected.is_some();
    if let Some(cdn) = cdn_detected
        && detected_wafs.is_empty()
    {
        issues.push(WafIssue::CdnWithoutWaf { cdn });
    }

    for &(name, value) in headers {
        let lower_name = name.to_ascii_lowercase();
        let lower_value = value.to_ascii_lowercase();
        for (waf_name, indicator) in LEARNING_MODE_INDICATORS {
            if (lower_name.contains("waf")
                || lower_name.contains("security")
                || lower_name.contains("server"))
                && lower_value.contains(indicator)
            {
                issues.push(WafIssue::WafInLearningMode {
                    name: waf_name.to_string(),
                });
                break;
            }
        }
    }

    if detected_wafs.len() > 1 {
        issues.push(WafIssue::MultipleWafs {
            names: detected_wafs.clone(),
        });
    }

    if detected_wafs.is_empty() && !has_cdn {
        let has_any_waf_hint = headers.iter().any(|&(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower.contains("waf") || lower.contains("firewall")
        });
        if !has_any_waf_hint {
            issues.push(WafIssue::NoWafDetected);
        }
    }

    issues
}

pub fn waf_issues_to_operations(issues: &[WafIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                waf_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}
