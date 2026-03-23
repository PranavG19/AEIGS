use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MethodOverrideIssue {
    HeaderOverrideAccepted {
        header: String,
        method: String,
    },
    QueryParamOverrideAccepted {
        param: String,
        method: String,
    },
    MethodChangeAltersResponse {
        override_type: String,
        method: String,
    },
    ContentTypeOverride {
        content_type: String,
    },
    CustomHeaderAccepted {
        header: String,
    },
    MultipleOverridesAccepted,
    OverrideBypassesAuth {
        override_type: String,
        method: String,
    },
    OverrideEnablesWrite {
        method: String,
    },
    TraceMethodViaOverride {
        override_type: String,
    },
    OverrideIgnoresCase {
        header: String,
    },
    BodyOverrideAccepted {
        param: String,
    },
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
            Self::ContentTypeOverride { content_type } => {
                write!(f, "method_override_content_type:{content_type}")
            }
            Self::CustomHeaderAccepted { header } => {
                write!(f, "method_override_custom_header:{header}")
            }
            Self::MultipleOverridesAccepted => {
                write!(f, "method_override_multiple_accepted")
            }
            Self::OverrideBypassesAuth {
                override_type,
                method,
            } => {
                write!(f, "method_override_auth_bypass:{override_type}={method}")
            }
            Self::OverrideEnablesWrite { method } => {
                write!(f, "method_override_enables_write:{method}")
            }
            Self::TraceMethodViaOverride { override_type } => {
                write!(f, "method_override_trace:{override_type}")
            }
            Self::OverrideIgnoresCase { header } => {
                write!(f, "method_override_case_insensitive:{header}")
            }
            Self::BodyOverrideAccepted { param } => {
                write!(f, "method_override_body:{param}")
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

const WRITE_METHODS: &[&str] = &["DELETE", "PUT", "PATCH", "POST"];

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

    if baseline_status == override_status {
        return issues;
    }

    if override_type.starts_with("header:") {
        let header = override_type
            .strip_prefix("header:")
            .unwrap_or(override_type);
        issues.push(MethodOverrideIssue::HeaderOverrideAccepted {
            header: header.to_string(),
            method: method.to_string(),
        });
    } else if override_type.starts_with("param:") {
        let param = override_type
            .strip_prefix("param:")
            .unwrap_or(override_type);
        issues.push(MethodOverrideIssue::QueryParamOverrideAccepted {
            param: param.to_string(),
            method: method.to_string(),
        });
    } else if override_type.starts_with("content-type:") {
        let ct = override_type
            .strip_prefix("content-type:")
            .unwrap_or(override_type);
        issues.push(MethodOverrideIssue::ContentTypeOverride {
            content_type: ct.to_string(),
        });
    } else if override_type.starts_with("custom-header:") {
        let header = override_type
            .strip_prefix("custom-header:")
            .unwrap_or(override_type);
        issues.push(MethodOverrideIssue::CustomHeaderAccepted {
            header: header.to_string(),
        });
    } else if override_type.starts_with("body:") {
        let param = override_type.strip_prefix("body:").unwrap_or(override_type);
        issues.push(MethodOverrideIssue::BodyOverrideAccepted {
            param: param.to_string(),
        });
    } else if override_type.starts_with("case-header:") {
        let header = override_type
            .strip_prefix("case-header:")
            .unwrap_or(override_type);
        issues.push(MethodOverrideIssue::OverrideIgnoresCase {
            header: header.to_string(),
        });
    } else if override_type == "multi" {
        issues.push(MethodOverrideIssue::MultipleOverridesAccepted);
    }

    if override_status < 300 && baseline_status >= 400
        || override_status >= 400 && baseline_status < 300
    {
        issues.push(MethodOverrideIssue::MethodChangeAltersResponse {
            override_type: override_type.to_string(),
            method: method.to_string(),
        });
    }

    if (baseline_status == 401 || baseline_status == 403) && (200..300).contains(&override_status) {
        issues.push(MethodOverrideIssue::OverrideBypassesAuth {
            override_type: override_type.to_string(),
            method: method.to_string(),
        });
    }

    if (200..300).contains(&baseline_status)
        && (200..300).contains(&override_status)
        && override_status != baseline_status
        && WRITE_METHODS.contains(&method.to_uppercase().as_str())
    {
        issues.push(MethodOverrideIssue::OverrideEnablesWrite {
            method: method.to_string(),
        });
    }

    let method_upper = method.to_uppercase();
    if method_upper == "TRACE" && override_status != baseline_status {
        issues.push(MethodOverrideIssue::TraceMethodViaOverride {
            override_type: override_type.to_string(),
        });
    }

    issues
}

pub fn method_override_severity(issue: &MethodOverrideIssue) -> f64 {
    match issue {
        MethodOverrideIssue::OverrideBypassesAuth { .. } => 9.0,
        MethodOverrideIssue::TraceMethodViaOverride { .. } => 8.0,
        MethodOverrideIssue::OverrideEnablesWrite { .. } => 7.5,
        MethodOverrideIssue::MethodChangeAltersResponse { .. } => 7.0,
        MethodOverrideIssue::MultipleOverridesAccepted => 6.5,
        MethodOverrideIssue::ContentTypeOverride { .. } => 6.0,
        MethodOverrideIssue::HeaderOverrideAccepted { .. } => 5.5,
        MethodOverrideIssue::BodyOverrideAccepted { .. } => 5.5,
        MethodOverrideIssue::CustomHeaderAccepted { .. } => 5.0,
        MethodOverrideIssue::QueryParamOverrideAccepted { .. } => 5.0,
        MethodOverrideIssue::OverrideIgnoresCase { .. } => 4.5,
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
                0.5,
            )
        })
        .collect()
}
