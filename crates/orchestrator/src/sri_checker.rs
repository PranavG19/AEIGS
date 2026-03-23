use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone)]
pub struct SriIssue {
    pub tag: String,
    pub src: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SriCheckIssue {
    MissingSri {
        tag: String,
        src: String,
    },
    WeakHashAlgorithm {
        tag: String,
        src: String,
        algorithm: String,
    },
    MissingCrossorigin {
        tag: String,
        src: String,
    },
    HttpResource {
        tag: String,
        src: String,
    },
    MixedContent {
        src: String,
    },
    ProtocolRelative {
        tag: String,
        src: String,
    },
    ThirdPartyCdn {
        tag: String,
        src: String,
        cdn: String,
    },
    DynamicSrc {
        tag: String,
    },
    InlineIntegrityMismatch {
        tag: String,
        src: String,
    },
    ExcessiveExternalResources {
        count: usize,
    },
}

impl fmt::Display for SriCheckIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSri { tag, src } => write!(f, "missing_sri:{tag}:{src}"),
            Self::WeakHashAlgorithm {
                tag,
                src,
                algorithm,
            } => {
                write!(f, "weak_hash:{tag}:{src}:{algorithm}")
            }
            Self::MissingCrossorigin { tag, src } => {
                write!(f, "missing_crossorigin:{tag}:{src}")
            }
            Self::HttpResource { tag, src } => write!(f, "http_resource:{tag}:{src}"),
            Self::MixedContent { src } => write!(f, "mixed_content:{src}"),
            Self::ProtocolRelative { tag, src } => {
                write!(f, "protocol_relative:{tag}:{src}")
            }
            Self::ThirdPartyCdn { tag, src, cdn } => {
                write!(f, "third_party_cdn:{tag}:{src}:{cdn}")
            }
            Self::DynamicSrc { tag } => write!(f, "dynamic_src:{tag}"),
            Self::InlineIntegrityMismatch { tag, src } => {
                write!(f, "integrity_mismatch:{tag}:{src}")
            }
            Self::ExcessiveExternalResources { count } => {
                write!(f, "excessive_external:{count}")
            }
        }
    }
}

const KNOWN_CDNS: &[&str] = &[
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "code.jquery.com",
];

pub fn sri_check_severity(issue: &SriCheckIssue) -> f64 {
    match issue {
        SriCheckIssue::HttpResource { .. } => 7.0,
        SriCheckIssue::MixedContent { .. } => 6.5,
        SriCheckIssue::InlineIntegrityMismatch { .. } => 6.0,
        SriCheckIssue::MissingSri { .. } => 5.0,
        SriCheckIssue::ThirdPartyCdn { .. } => 5.0,
        SriCheckIssue::WeakHashAlgorithm { .. } => 4.0,
        SriCheckIssue::MissingCrossorigin { .. } => 3.5,
        SriCheckIssue::ProtocolRelative { .. } => 3.5,
        SriCheckIssue::DynamicSrc { .. } => 3.0,
        SriCheckIssue::ExcessiveExternalResources { .. } => 4.5,
    }
}

pub fn check_sri(target: &str) -> Vec<SriIssue> {
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

    find_missing_sri(&body)
}

pub fn find_missing_sri(html: &str) -> Vec<SriIssue> {
    let mut issues = Vec::new();

    for (tag_name, attr) in &[("script", "src"), ("link", "href")] {
        for tag in TagIter::new(html, tag_name) {
            let Some(src_val) = html_parser::extract_attr(tag.original, &tag.lower, attr) else {
                continue;
            };
            if !is_external_resource(&src_val) {
                continue;
            }
            if *tag_name == "link" && !is_stylesheet(&tag.lower) {
                continue;
            }
            if tag.lower.contains("integrity") {
                continue;
            }
            issues.push(SriIssue {
                tag: tag_name.to_string(),
                src: src_val,
            });
        }
    }

    issues
}

pub fn is_external_resource(src: &str) -> bool {
    src.starts_with("http://") || src.starts_with("https://") || src.starts_with("//")
}

pub fn is_stylesheet(tag_lower: &str) -> bool {
    tag_lower.contains("rel=\"stylesheet\"") || tag_lower.contains("rel='stylesheet'")
}

pub fn sri_findings_to_operations(issues: &[SriIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let severity = if issues.len() > 3 { 4.5 } else { 3.5 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        severity,
        0.9,
    )]
}

pub fn analyze_sri(html: &str) -> Vec<SriCheckIssue> {
    let mut issues = Vec::new();
    let mut missing_sri_count: usize = 0;

    for (tag_name, attr) in &[("script", "src"), ("link", "href")] {
        for tag in TagIter::new(html, tag_name) {
            let Some(src_val) = html_parser::extract_attr(tag.original, &tag.lower, attr) else {
                continue;
            };

            if *tag_name == "link" && !is_stylesheet(&tag.lower) {
                continue;
            }

            let is_dynamic =
                src_val.contains("${") || src_val.contains("{{") || src_val.contains("%7B");
            if is_dynamic {
                issues.push(SriCheckIssue::DynamicSrc {
                    tag: tag_name.to_string(),
                });
                continue;
            }

            if !is_external_resource(&src_val) {
                continue;
            }

            let has_integrity = tag.lower.contains("integrity");
            let has_crossorigin = tag.lower.contains("crossorigin");

            if src_val.starts_with("//") {
                issues.push(SriCheckIssue::ProtocolRelative {
                    tag: tag_name.to_string(),
                    src: src_val.clone(),
                });
            }

            if src_val.starts_with("http://") {
                issues.push(SriCheckIssue::HttpResource {
                    tag: tag_name.to_string(),
                    src: src_val.clone(),
                });
            }

            if !has_integrity {
                missing_sri_count += 1;
                issues.push(SriCheckIssue::MissingSri {
                    tag: tag_name.to_string(),
                    src: src_val.clone(),
                });

                if let Some(cdn) = detect_known_cdn(&src_val) {
                    issues.push(SriCheckIssue::ThirdPartyCdn {
                        tag: tag_name.to_string(),
                        src: src_val.clone(),
                        cdn: cdn.to_string(),
                    });
                }
            } else {
                let integrity_val =
                    html_parser::extract_attr(tag.original, &tag.lower, "integrity");

                if let Some(ref iv) = integrity_val {
                    if !is_valid_integrity_format(iv) {
                        issues.push(SriCheckIssue::InlineIntegrityMismatch {
                            tag: tag_name.to_string(),
                            src: src_val.clone(),
                        });
                    } else if iv.starts_with("sha256-") {
                        issues.push(SriCheckIssue::WeakHashAlgorithm {
                            tag: tag_name.to_string(),
                            src: src_val.clone(),
                            algorithm: "sha256".to_string(),
                        });
                    }
                }

                if !has_crossorigin {
                    issues.push(SriCheckIssue::MissingCrossorigin {
                        tag: tag_name.to_string(),
                        src: src_val.clone(),
                    });
                }
            }
        }
    }

    if missing_sri_count > 5 {
        issues.push(SriCheckIssue::ExcessiveExternalResources {
            count: missing_sri_count,
        });
    }

    issues
}

fn detect_known_cdn(src: &str) -> Option<&'static str> {
    let normalized = if src.starts_with("//") {
        format!("https:{src}")
    } else {
        src.to_string()
    };
    let after_scheme = normalized.split("//").nth(1)?;
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    let host_lower = host.to_ascii_lowercase();
    KNOWN_CDNS.iter().find(|cdn| host_lower == **cdn).copied()
}

fn is_valid_integrity_format(value: &str) -> bool {
    value.starts_with("sha256-") || value.starts_with("sha384-") || value.starts_with("sha512-")
}

pub fn sri_check_to_operations(issues: &[SriCheckIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                sri_check_severity(issue),
                0.5,
            )
        })
        .collect()
}
