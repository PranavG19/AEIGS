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

#[derive(Debug, Clone, PartialEq)]
pub enum JsLibraryIssue {
    OutdatedLibrary {
        library: String,
        version: String,
        min_safe: String,
    },
    KnownVulnerable {
        library: String,
        cve_pattern: String,
    },
    EndOfLife {
        library: String,
    },
    UnversionedLibrary {
        library: String,
    },
    MultipleVersions {
        library: String,
    },
    CdnWithoutSri {
        library: String,
        cdn_url: String,
    },
    DebugBuild {
        library: String,
    },
    DeprecatedLibrary {
        library: String,
        replacement: String,
    },
}

impl std::fmt::Display for JsLibraryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsLibraryIssue::OutdatedLibrary {
                library,
                version,
                min_safe,
            } => {
                write!(
                    f,
                    "{} {} is outdated (min safe: {})",
                    library, version, min_safe
                )
            }
            JsLibraryIssue::KnownVulnerable {
                library,
                cve_pattern,
            } => {
                write!(f, "{} has known vulnerability: {}", library, cve_pattern)
            }
            JsLibraryIssue::EndOfLife { library } => {
                write!(f, "{} is end-of-life", library)
            }
            JsLibraryIssue::UnversionedLibrary { library } => {
                write!(f, "{} detected without version information", library)
            }
            JsLibraryIssue::MultipleVersions { library } => {
                write!(f, "Multiple versions of {} detected", library)
            }
            JsLibraryIssue::CdnWithoutSri { library, cdn_url } => {
                write!(f, "{} from CDN {} without SRI", library, cdn_url)
            }
            JsLibraryIssue::DebugBuild { library } => {
                write!(f, "{} debug build detected in production", library)
            }
            JsLibraryIssue::DeprecatedLibrary {
                library,
                replacement,
            } => {
                write!(f, "{} is deprecated, consider {}", library, replacement)
            }
        }
    }
}

const EOL_LIBRARIES: &[&str] = &["AngularJS", "Moment.js"];
const DEPRECATED_LIBS: &[(&str, &str)] =
    &[("AngularJS", "Angular"), ("Moment.js", "date-fns or Luxon")];
const VULNERABLE_PATTERNS: &[(&str, &str, &str)] = &[
    ("jQuery", "1.", "CVE-2020-11022"),
    ("jQuery", "2.", "CVE-2020-11023"),
    ("AngularJS", "1.", "CVE-2022-25869"),
    ("Lodash", "4.17.1", "CVE-2021-23337"),
    ("Handlebars", "4.0", "CVE-2021-23369"),
];

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

pub fn detect_libraries(html: &str) -> Vec<JsLibraryFinding> {
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

pub fn extract_version(text: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    if let Some(cap) = re.captures(text) {
        return cap.get(1).map(|m| m.as_str().to_string());
    }
    let lower = text.to_ascii_lowercase();
    re.captures(&lower)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

pub fn is_version_below(version: &str, min_safe: &str) -> bool {
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

pub fn library_severity(finding: &JsLibraryFinding) -> f64 {
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

pub fn js_library_issue_severity(issue: &JsLibraryIssue) -> f64 {
    match issue {
        JsLibraryIssue::KnownVulnerable { .. } => 8.0,
        JsLibraryIssue::OutdatedLibrary { .. } => 6.0,
        JsLibraryIssue::EndOfLife { .. } => 5.5,
        JsLibraryIssue::DeprecatedLibrary { .. } => 5.0,
        JsLibraryIssue::CdnWithoutSri { .. } => 4.5,
        JsLibraryIssue::DebugBuild { .. } => 4.0,
        JsLibraryIssue::UnversionedLibrary { .. } => 3.5,
        JsLibraryIssue::MultipleVersions { .. } => 3.0,
    }
}

pub fn analyze_js_libraries(findings: &[JsLibraryFinding], html: &str) -> Vec<JsLibraryIssue> {
    let mut issues = Vec::new();
    let lower = html.to_ascii_lowercase();

    for finding in findings {
        if finding.outdated {
            issues.push(JsLibraryIssue::OutdatedLibrary {
                library: finding.library.clone(),
                version: finding.version.clone().unwrap_or_default(),
                min_safe: finding.min_safe_version.clone(),
            });
        }

        if finding.version.is_none() {
            issues.push(JsLibraryIssue::UnversionedLibrary {
                library: finding.library.clone(),
            });
        }

        if EOL_LIBRARIES.contains(&finding.library.as_str()) {
            issues.push(JsLibraryIssue::EndOfLife {
                library: finding.library.clone(),
            });
        }

        if let Some((_, replacement)) = DEPRECATED_LIBS
            .iter()
            .find(|(lib, _)| *lib == finding.library)
        {
            issues.push(JsLibraryIssue::DeprecatedLibrary {
                library: finding.library.clone(),
                replacement: replacement.to_string(),
            });
        }

        // Check for known vulnerable version patterns
        if let Some(ref version) = finding.version {
            for &(lib, ver_prefix, cve) in VULNERABLE_PATTERNS {
                if finding.library == lib && version.starts_with(ver_prefix) {
                    issues.push(JsLibraryIssue::KnownVulnerable {
                        library: finding.library.clone(),
                        cve_pattern: cve.to_string(),
                    });
                    break;
                }
            }
        }

        // Check for debug builds
        let lib_lower = finding.library.to_ascii_lowercase();
        if lower.contains(&format!("{lib_lower}.js"))
            && !lower.contains(&format!("{lib_lower}.min.js"))
        {
            issues.push(JsLibraryIssue::DebugBuild {
                library: finding.library.clone(),
            });
        }
    }

    // Check for CDN without SRI
    let cdn_patterns = ["cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com"];
    for cdn in &cdn_patterns {
        if lower.contains(cdn) && !lower.contains("integrity=") {
            issues.push(JsLibraryIssue::CdnWithoutSri {
                library: "unknown".to_string(),
                cdn_url: cdn.to_string(),
            });
        }
    }

    // Check for multiple versions of same library
    let mut lib_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for finding in findings {
        *lib_counts.entry(&finding.library).or_insert(0) += 1;
    }
    for (lib, count) in lib_counts {
        if count > 1 {
            issues.push(JsLibraryIssue::MultipleVersions {
                library: lib.to_string(),
            });
        }
    }

    issues
}

pub fn js_library_issues_to_operations(
    issues: &[JsLibraryIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::KnownVulnerableDependency,
                js_library_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}
