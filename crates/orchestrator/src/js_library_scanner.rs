use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const LIBRARY_PATTERNS: &[LibrarySignature] = &[
    LibrarySignature {
        name: "jQuery",
        patterns: &["jquery", "jQuery"],
        version_regex: r"jquery[/-](\d+\.\d+\.\d+)",
        min_safe: "3.5.0",
    },
    LibrarySignature {
        name: "AngularJS",
        patterns: &["angular.min.js", "angular.js"],
        version_regex: r"angular[/-](\d+\.\d+\.\d+)",
        min_safe: "1.8.0",
    },
    LibrarySignature {
        name: "Bootstrap",
        patterns: &["bootstrap.min.js", "bootstrap.js"],
        version_regex: r"bootstrap[/-](\d+\.\d+\.\d+)",
        min_safe: "5.2.0",
    },
    LibrarySignature {
        name: "Lodash",
        patterns: &["lodash.min.js", "lodash.js", "lodash-", "lodash/"],
        version_regex: r"lodash[/-](\d+\.\d+\.\d+)",
        min_safe: "4.17.21",
    },
    LibrarySignature {
        name: "Moment.js",
        patterns: &["moment.min.js", "moment.js"],
        version_regex: r"moment[/-](\d+\.\d+\.\d+)",
        min_safe: "2.29.4",
    },
    LibrarySignature {
        name: "Vue.js",
        patterns: &["vue.min.js", "vue.js", "vue@"],
        version_regex: r"vue[/@](\d+\.\d+\.\d+)",
        min_safe: "3.2.0",
    },
    LibrarySignature {
        name: "React",
        patterns: &["react.production.min.js", "react.development.js"],
        version_regex: r"react[/@-](\d+\.\d+\.\d+)",
        min_safe: "18.0.0",
    },
    LibrarySignature {
        name: "Handlebars",
        patterns: &["handlebars.min.js", "handlebars.js"],
        version_regex: r"handlebars[/-](\d+\.\d+\.\d+)",
        min_safe: "4.7.7",
    },
    LibrarySignature {
        name: "DOMPurify",
        patterns: &["purify.min.js", "dompurify"],
        version_regex: r"dompurify[/@-](\d+\.\d+\.\d+)",
        min_safe: "3.0.0",
    },
];

struct LibrarySignature {
    name: &'static str,
    patterns: &'static [&'static str],
    version_regex: &'static str,
    min_safe: &'static str,
}

#[derive(Debug, Clone)]
pub struct JsLibraryFinding {
    pub library: String,
    pub version: Option<String>,
    pub min_safe_version: String,
    pub outdated: bool,
}

pub fn scan_js_libraries(target: &str) -> Vec<JsLibraryFinding> {
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
    let body = match resp.text() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    detect_libraries(&body)
}

pub(crate) fn detect_libraries(html: &str) -> Vec<JsLibraryFinding> {
    let lower = html.to_ascii_lowercase();
    let mut findings = Vec::new();

    for sig in LIBRARY_PATTERNS {
        let matched = sig.patterns.iter().any(|p| lower.contains(p));
        if !matched {
            continue;
        }
        let version = extract_version(html, sig.version_regex);
        let outdated = version
            .as_ref()
            .map(|v| is_version_below(v, sig.min_safe))
            .unwrap_or(false);

        findings.push(JsLibraryFinding {
            library: sig.name.to_string(),
            version,
            min_safe_version: sig.min_safe.to_string(),
            outdated,
        });
    }

    findings
}

pub(crate) fn extract_version(text: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    if let Some(cap) = re.captures(text) {
        return cap.get(1).map(|m| m.as_str().to_string());
    }
    let lower = text.to_ascii_lowercase();
    re.captures(&lower)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

pub(crate) fn is_version_below(version: &str, min_safe: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    let v = parse(version);
    let m = parse(min_safe);
    for i in 0..v.len().max(m.len()) {
        let a = v.get(i).copied().unwrap_or(0);
        let b = m.get(i).copied().unwrap_or(0);
        if a < b {
            return true;
        }
        if a > b {
            return false;
        }
    }
    false
}

fn library_severity(finding: &JsLibraryFinding) -> f64 {
    if finding.outdated {
        match finding.library.as_str() {
            "jQuery" | "AngularJS" => 6.0,
            "Handlebars" | "DOMPurify" => 5.5,
            "Lodash" | "Moment.js" => 4.0,
            _ => 5.0,
        }
    } else {
        2.0
    }
}

pub fn js_library_findings_to_operations(
    findings: &[JsLibraryFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    let outdated: Vec<_> = findings.iter().filter(|f| f.outdated).collect();
    if outdated.is_empty() {
        return Vec::new();
    }

    let max_severity = outdated
        .iter()
        .map(|f| library_severity(f))
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::KnownVulnerableDependency,
        max_severity,
        0.75,
    )]
}
