use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MethodOverrideIssue {
    HeaderOverrideAccepted { header: String, method: String },
    QueryParamOverrideAccepted { param: String, method: String },
    MethodChangeAltersResponse { override_type: String, method: String },
}

impl std::fmt::Display for MethodOverrideIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderOverrideAccepted { header, method } => {
                write!(f, "method_override_header:{header}={method}")
            }
            Self::QueryParamOverrideAccepted { param, method } => {
                write!(f, "method_override_param:{param}={method}")
            }
            Self::MethodChangeAltersResponse {
                override_type,
                method,
            } => {
                write!(f, "method_override_effect:{override_type}={method}")
            }
        }
    }
}

const OVERRIDE_HEADERS: &[&str] = &[
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
];

const OVERRIDE_PARAMS: &[&str] = &["_method", "method"];

const TEST_METHODS: &[&str] = &["DELETE", "PUT", "PATCH"];

pub fn audit_method_override(target: &str) -> Vec<MethodOverrideIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let baseline = match client.get(target).send() {
        Ok(r) => r.status().as_u16(),
        Err(_) => return Vec::new(),
    };

    let mut issues = Vec::new();

    for header in OVERRIDE_HEADERS {
        for method in TEST_METHODS {
            if let Ok(resp) = client.get(target).header(*header, *method).send() {
                let status = resp.status().as_u16();
                if status != baseline {
                    issues.push(MethodOverrideIssue::HeaderOverrideAccepted {
                        header: header.to_string(),
                        method: method.to_string(),
                    });
                    break;
                }
            }
        }
    }

    for param in OVERRIDE_PARAMS {
        for method in TEST_METHODS {
            let url = format!("{target}?{param}={method}");
            if let Ok(resp) = client.get(&url).send() {
                let status = resp.status().as_u16();
                if status != baseline {
                    issues.push(MethodOverrideIssue::QueryParamOverrideAccepted {
                        param: param.to_string(),
                        method: method.to_string(),
                    });
                    break;
                }
            }
        }
    }

    issues
}

pub fn analyze_method_override(
    baseline_status: u16,
    override_status: u16,
    override_type: &str,
    method: &str,
) -> Vec<MethodOverrideIssue> {
    let mut issues = Vec::new();

    if baseline_status != override_status {
        if override_type.starts_with("header:") {
            let header = override_type.strip_prefix("header:").unwrap_or(override_type);
            issues.push(MethodOverrideIssue::HeaderOverrideAccepted {
                header: header.to_string(),
                method: method.to_string(),
            });
        } else if override_type.starts_with("param:") {
            let param = override_type.strip_prefix("param:").unwrap_or(override_type);
            issues.push(MethodOverrideIssue::QueryParamOverrideAccepted {
                param: param.to_string(),
                method: method.to_string(),
            });
        }

        if override_status < 300 && baseline_status >= 400
            || override_status >= 400 && baseline_status < 300
        {
            issues.push(MethodOverrideIssue::MethodChangeAltersResponse {
                override_type: override_type.to_string(),
                method: method.to_string(),
            });
        }
    }

    issues
}

pub fn method_override_severity(issue: &MethodOverrideIssue) -> f64 {
    match issue {
        MethodOverrideIssue::MethodChangeAltersResponse { .. } => 7.0,
        MethodOverrideIssue::HeaderOverrideAccepted { .. } => 5.5,
        MethodOverrideIssue::QueryParamOverrideAccepted { .. } => 5.0,
    }
}

pub fn method_override_to_operations(
    issues: &[MethodOverrideIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                method_override_severity(issue),
                0.8,
            )
        })
        .collect()
}
