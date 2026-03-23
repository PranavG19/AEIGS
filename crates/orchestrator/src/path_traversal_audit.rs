use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PathTraversalIssue {
    TraversalSucceeded {
        param: String,
        payload: String,
        indicator: String,
    },
    EncodedTraversalSucceeded {
        param: String,
        encoding: String,
    },
    NullByteInjection {
        param: String,
    },
}

impl std::fmt::Display for PathTraversalIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TraversalSucceeded { param, payload, .. } => {
                write!(f, "path_traversal:{param}:{payload}")
            }
            Self::EncodedTraversalSucceeded { param, encoding } => {
                write!(f, "encoded_path_traversal:{param}:{encoding}")
            }
            Self::NullByteInjection { param } => {
                write!(f, "null_byte_injection:{param}")
            }
        }
    }
}

const FILE_PARAMS: &[&str] = &[
    "file", "path", "page", "document", "folder", "dir", "include", "template", "load", "read",
];

const TRAVERSAL_PAYLOADS: &[(&str, &str)] = &[
    ("../../../etc/passwd", "root:"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("....//....//....//etc/passwd", "root:"),
];

const ENCODED_PAYLOADS: &[(&str, &str, &str)] = &[
    (
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "url_encoded",
        "root:",
    ),
    (
        "..%252f..%252f..%252fetc%252fpasswd",
        "double_encoded",
        "root:",
    ),
    (
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "utf8_overlong",
        "root:",
    ),
];

const NULL_PAYLOAD: &str = "....//....//etc/passwd%00.png";

#[derive(Debug, Clone, PartialEq)]
pub enum PathTraversalSecurityIssue {
    DotDotSlashInUrl {
        url: String,
        pattern: String,
    },
    EncodedTraversal {
        url: String,
        encoding_type: String,
    },
    DoubleEncodedTraversal {
        url: String,
    },
    NullByteTraversal {
        url: String,
    },
    UnicodeTraversal {
        url: String,
        unicode_pattern: String,
    },
    BackslashTraversal {
        url: String,
    },
    AbsolutePathInParam {
        url: String,
        path: String,
    },
    FileProtocolAccess {
        url: String,
    },
    PathTraversalInBody {
        body_snippet: String,
    },
    SymlinkTraversal {
        url: String,
        symlink_indicator: String,
    },
}

impl std::fmt::Display for PathTraversalSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DotDotSlashInUrl { pattern, .. } => {
                write!(f, "dot_dot_slash_in_url:{pattern}")
            }
            Self::EncodedTraversal { encoding_type, .. } => {
                write!(f, "encoded_traversal:{encoding_type}")
            }
            Self::DoubleEncodedTraversal { .. } => {
                write!(f, "double_encoded_traversal")
            }
            Self::NullByteTraversal { .. } => {
                write!(f, "null_byte_traversal")
            }
            Self::UnicodeTraversal {
                unicode_pattern, ..
            } => {
                write!(f, "unicode_traversal:{unicode_pattern}")
            }
            Self::BackslashTraversal { .. } => {
                write!(f, "backslash_traversal")
            }
            Self::AbsolutePathInParam { path, .. } => {
                write!(f, "absolute_path_in_param:{path}")
            }
            Self::FileProtocolAccess { .. } => {
                write!(f, "file_protocol_access")
            }
            Self::PathTraversalInBody { body_snippet } => {
                write!(f, "path_traversal_in_body:{body_snippet}")
            }
            Self::SymlinkTraversal {
                symlink_indicator, ..
            } => {
                write!(f, "symlink_traversal:{symlink_indicator}")
            }
        }
    }
}

pub fn analyze_path_traversal_security(body: &str, url: &str) -> Vec<PathTraversalSecurityIssue> {
    let mut issues = Vec::new();

    // 1. DotDotSlashInUrl
    if url.contains("../") {
        issues.push(PathTraversalSecurityIssue::DotDotSlashInUrl {
            url: url.to_string(),
            pattern: "../".to_string(),
        });
    }
    if url.contains("..\\") {
        issues.push(PathTraversalSecurityIssue::DotDotSlashInUrl {
            url: url.to_string(),
            pattern: "..\\".to_string(),
        });
    }
    if url.contains("....//") {
        issues.push(PathTraversalSecurityIssue::DotDotSlashInUrl {
            url: url.to_string(),
            pattern: "....//".to_string(),
        });
    }

    // 2. EncodedTraversal
    if url.contains("%2e%2e%2f") || url.contains("%2e%2e/") {
        issues.push(PathTraversalSecurityIssue::EncodedTraversal {
            url: url.to_string(),
            encoding_type: "url_encoded".to_string(),
        });
    }
    if url.contains("%252e") || url.contains("%252f") {
        issues.push(PathTraversalSecurityIssue::EncodedTraversal {
            url: url.to_string(),
            encoding_type: "partial_encoded".to_string(),
        });
    }

    // 3. DoubleEncodedTraversal
    if url.contains("%252f") || url.contains("%255c") {
        issues.push(PathTraversalSecurityIssue::DoubleEncodedTraversal {
            url: url.to_string(),
        });
    }

    // 4. NullByteTraversal
    if url.contains("%00") || url.contains("\0") {
        issues.push(PathTraversalSecurityIssue::NullByteTraversal {
            url: url.to_string(),
        });
    }

    // 5. UnicodeTraversal
    if url.contains("\\u002e") || url.contains("%u002e") {
        issues.push(PathTraversalSecurityIssue::UnicodeTraversal {
            url: url.to_string(),
            unicode_pattern: "\\u002e".to_string(),
        });
    }
    if url.contains("\\u002f") || url.contains("%u002f") {
        issues.push(PathTraversalSecurityIssue::UnicodeTraversal {
            url: url.to_string(),
            unicode_pattern: "\\u002f".to_string(),
        });
    }
    if url.contains("%c0%ae") || url.contains("%c0%af") {
        issues.push(PathTraversalSecurityIssue::UnicodeTraversal {
            url: url.to_string(),
            unicode_pattern: "utf8_overlong".to_string(),
        });
    }

    // 6. BackslashTraversal
    if url.contains("..\\..\\") || url.contains("..\\") {
        issues.push(PathTraversalSecurityIssue::BackslashTraversal {
            url: url.to_string(),
        });
    }

    // 7. AbsolutePathInParam
    if url.contains("/etc/") || url.contains("/usr/") || url.contains("/var/") {
        let path = if url.contains("/etc/") {
            "/etc/".to_string()
        } else if url.contains("/usr/") {
            "/usr/".to_string()
        } else {
            "/var/".to_string()
        };
        issues.push(PathTraversalSecurityIssue::AbsolutePathInParam {
            url: url.to_string(),
            path,
        });
    }
    if url.contains("C:\\") || url.contains("c:\\") || url.contains("C:/") {
        issues.push(PathTraversalSecurityIssue::AbsolutePathInParam {
            url: url.to_string(),
            path: "C:\\".to_string(),
        });
    }

    // 8. FileProtocolAccess
    if url.contains("file://") || url.contains("file:/") {
        issues.push(PathTraversalSecurityIssue::FileProtocolAccess {
            url: url.to_string(),
        });
    }

    // 9. PathTraversalInBody
    if body.contains("root:x:0:0:") {
        issues.push(PathTraversalSecurityIssue::PathTraversalInBody {
            body_snippet: "root:x:0:0:".to_string(),
        });
    }
    if body.contains("[fonts]") || body.contains("[extensions]") {
        issues.push(PathTraversalSecurityIssue::PathTraversalInBody {
            body_snippet: "win.ini".to_string(),
        });
    }
    if body.contains("/bin/bash") || body.contains("/bin/sh") {
        issues.push(PathTraversalSecurityIssue::PathTraversalInBody {
            body_snippet: "shell_path".to_string(),
        });
    }

    // 10. SymlinkTraversal
    if body.contains("-> /") || body.contains("symbolic link") {
        issues.push(PathTraversalSecurityIssue::SymlinkTraversal {
            url: url.to_string(),
            symlink_indicator: "symlink_detected".to_string(),
        });
    }
    if body.contains("lrwxrwxrwx") {
        issues.push(PathTraversalSecurityIssue::SymlinkTraversal {
            url: url.to_string(),
            symlink_indicator: "ls_output".to_string(),
        });
    }

    issues
}

pub fn path_traversal_security_severity(issue: &PathTraversalSecurityIssue) -> f64 {
    match issue {
        PathTraversalSecurityIssue::PathTraversalInBody { .. } => 9.5,
        PathTraversalSecurityIssue::DotDotSlashInUrl { .. } => 8.5,
        PathTraversalSecurityIssue::AbsolutePathInParam { .. } => 8.5,
        PathTraversalSecurityIssue::FileProtocolAccess { .. } => 8.0,
        PathTraversalSecurityIssue::EncodedTraversal { .. } => 7.5,
        PathTraversalSecurityIssue::DoubleEncodedTraversal { .. } => 7.5,
        PathTraversalSecurityIssue::NullByteTraversal { .. } => 7.0,
        PathTraversalSecurityIssue::UnicodeTraversal { .. } => 7.0,
        PathTraversalSecurityIssue::BackslashTraversal { .. } => 6.5,
        PathTraversalSecurityIssue::SymlinkTraversal { .. } => 6.0,
    }
}

pub fn path_traversal_security_to_operations(
    issues: &[PathTraversalSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::PathTraversal,
                path_traversal_security_severity(issue),
                0.5,
            )
        })
        .collect()
}

pub fn audit_path_traversal(target: &str) -> Vec<PathTraversalIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut issues = Vec::new();

    for &param in FILE_PARAMS {
        for &(payload, indicator) in TRAVERSAL_PAYLOADS {
            let url = format!("{base}?{param}={payload}");
            if let Ok(resp) = client.get(&url).send()
                && resp.status().is_success()
                && let Ok(body) = resp.text()
                && body.contains(indicator)
            {
                issues.push(PathTraversalIssue::TraversalSucceeded {
                    param: param.to_string(),
                    payload: payload.to_string(),
                    indicator: indicator.to_string(),
                });
                break;
            }
        }

        for &(payload, encoding, indicator) in ENCODED_PAYLOADS {
            let url = format!("{base}?{param}={payload}");
            if let Ok(resp) = client.get(&url).send()
                && resp.status().is_success()
                && let Ok(body) = resp.text()
                && body.contains(indicator)
            {
                issues.push(PathTraversalIssue::EncodedTraversalSucceeded {
                    param: param.to_string(),
                    encoding: encoding.to_string(),
                });
                break;
            }
        }

        let null_url = format!("{base}?{param}={NULL_PAYLOAD}");
        if let Ok(resp) = client.get(&null_url).send()
            && resp.status().is_success()
            && let Ok(body) = resp.text()
            && body.contains("root:")
        {
            issues.push(PathTraversalIssue::NullByteInjection {
                param: param.to_string(),
            });
        }
    }

    issues
}

pub fn analyze_traversal_response(
    param: &str,
    payload: &str,
    indicator: &str,
    status: u16,
    body: &str,
) -> Option<PathTraversalIssue> {
    if !(200..300).contains(&status) {
        return None;
    }
    if !body.contains(indicator) {
        return None;
    }
    Some(PathTraversalIssue::TraversalSucceeded {
        param: param.to_string(),
        payload: payload.to_string(),
        indicator: indicator.to_string(),
    })
}

pub(crate) fn path_traversal_severity(issue: &PathTraversalIssue) -> f64 {
    match issue {
        PathTraversalIssue::TraversalSucceeded { .. } => 9.0,
        PathTraversalIssue::EncodedTraversalSucceeded { .. } => 8.5,
        PathTraversalIssue::NullByteInjection { .. } => 8.0,
    }
}

pub fn path_traversal_to_operations(
    issues: &[PathTraversalIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::PathTraversal,
                path_traversal_severity(issue),
                0.95,
            )
        })
        .collect()
}
