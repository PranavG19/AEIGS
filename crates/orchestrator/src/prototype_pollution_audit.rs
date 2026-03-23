use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum PrototypePollutionIssue {
    ProtoPropertyDetected { context: String },
    ConstructorPrototypeDetected { context: String },
    ObjectAssignUnsafe { location: String },
    SetPrototypeOfDetected { location: String },
    RecursiveMergeUnsafe { function_name: String },
    JsonParseUnsanitized { context: String },
    LodashMergeDetected { variant: String },
    JqueryExtendDetected { deep: bool },
    UrlParameterPollution { parameter: String },
    GadgetChainDetected { gadget_type: String },
}

impl std::fmt::Display for PrototypePollutionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtoPropertyDetected { context } => {
                write!(f, "proto_property_detected:{context}")
            }
            Self::ConstructorPrototypeDetected { context } => {
                write!(f, "constructor_prototype_detected:{context}")
            }
            Self::ObjectAssignUnsafe { location } => {
                write!(f, "object_assign_unsafe:{location}")
            }
            Self::SetPrototypeOfDetected { location } => {
                write!(f, "set_prototype_of_detected:{location}")
            }
            Self::RecursiveMergeUnsafe { function_name } => {
                write!(f, "recursive_merge_unsafe:{function_name}")
            }
            Self::JsonParseUnsanitized { context } => {
                write!(f, "json_parse_unsanitized:{context}")
            }
            Self::LodashMergeDetected { variant } => {
                write!(f, "lodash_merge_detected:{variant}")
            }
            Self::JqueryExtendDetected { deep } => {
                write!(f, "jquery_extend_detected:{deep}")
            }
            Self::UrlParameterPollution { parameter } => {
                write!(f, "url_parameter_pollution:{parameter}")
            }
            Self::GadgetChainDetected { gadget_type } => {
                write!(f, "gadget_chain_detected:{gadget_type}")
            }
        }
    }
}

pub fn prototype_pollution_severity(issue: &PrototypePollutionIssue) -> f64 {
    match issue {
        PrototypePollutionIssue::GadgetChainDetected { .. } => 9.0,
        PrototypePollutionIssue::ProtoPropertyDetected { .. } => 8.5,
        PrototypePollutionIssue::ConstructorPrototypeDetected { .. } => 8.0,
        PrototypePollutionIssue::SetPrototypeOfDetected { .. } => 7.5,
        PrototypePollutionIssue::JsonParseUnsanitized { .. } => 7.0,
        PrototypePollutionIssue::RecursiveMergeUnsafe { .. } => 6.5,
        PrototypePollutionIssue::ObjectAssignUnsafe { .. } => 6.0,
        PrototypePollutionIssue::LodashMergeDetected { .. } => 6.0,
        PrototypePollutionIssue::JqueryExtendDetected { deep: true } => 6.5,
        PrototypePollutionIssue::JqueryExtendDetected { deep: false } => 5.5,
        PrototypePollutionIssue::UrlParameterPollution { .. } => 5.0,
    }
}

pub fn audit_prototype_pollution(target: &str) -> Vec<PrototypePollutionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_prototype_pollution(&body)
}

pub fn analyze_prototype_pollution(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();

    issues.extend(detect_proto_property(body));
    issues.extend(detect_constructor_prototype(body));
    issues.extend(detect_object_assign(body));
    issues.extend(detect_set_prototype_of(body));
    issues.extend(detect_recursive_merge(body));
    issues.extend(detect_json_parse_unsanitized(body));
    issues.extend(detect_lodash_merge(body));
    issues.extend(detect_jquery_extend(body));
    issues.extend(detect_url_parameter_pollution(body));
    issues.extend(detect_gadget_chains(body));

    issues
}

fn detect_proto_property(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let patterns = [
        "__proto__[",
        "[__proto__]",
        "__proto__.",
        "['__proto__']",
        "[\"__proto__\"]",
    ];

    for pattern in &patterns {
        if body.contains(pattern) {
            let context = extract_context(body, pattern);
            issues.push(PrototypePollutionIssue::ProtoPropertyDetected { context });
        }
    }

    issues
}

fn detect_constructor_prototype(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let patterns = [
        "constructor.prototype",
        "constructor[\"prototype\"]",
        "constructor['prototype']",
        "constructor[prototype]",
    ];

    for pattern in &patterns {
        if body.contains(pattern) {
            let context = extract_context(body, pattern);
            issues.push(PrototypePollutionIssue::ConstructorPrototypeDetected { context });
        }
    }

    issues
}

fn detect_object_assign(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();

    if body.contains("Object.assign") {
        for line in body.lines() {
            if line.contains("Object.assign") && !line.contains("hasOwnProperty") {
                let location = extract_location(line);
                issues.push(PrototypePollutionIssue::ObjectAssignUnsafe { location });
                break;
            }
        }
    }

    issues
}

fn detect_set_prototype_of(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let patterns = ["Object.setPrototypeOf", "setPrototypeOf"];

    for pattern in &patterns {
        if body.contains(pattern) {
            let location = extract_context(body, pattern);
            issues.push(PrototypePollutionIssue::SetPrototypeOfDetected { location });
        }
    }

    issues
}

fn detect_recursive_merge(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let merge_patterns = [
        ("deepMerge", "deep_merge"),
        ("merge(", "merge"),
        ("extend(", "extend"),
        ("assign(", "assign"),
        ("clone(", "clone"),
    ];

    for (pattern, name) in &merge_patterns {
        if body.contains(pattern) {
            for line in body.lines() {
                if line.contains(pattern)
                    && line.contains("function")
                    && !line.contains("hasOwnProperty")
                {
                    issues.push(PrototypePollutionIssue::RecursiveMergeUnsafe {
                        function_name: name.to_string(),
                    });
                    break;
                }
            }
        }
    }

    issues
}

fn detect_json_parse_unsanitized(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();

    if body.contains("JSON.parse") {
        for line in body.lines() {
            if line.contains("JSON.parse") {
                let has_sanitization = line.contains("delete")
                    || line.contains("filter")
                    || line.contains("sanitize")
                    || line.contains("validate");

                if !has_sanitization {
                    let context = extract_location(line);
                    issues.push(PrototypePollutionIssue::JsonParseUnsanitized { context });
                    break;
                }
            }
        }
    }

    issues
}

fn detect_lodash_merge(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let lodash_patterns = [
        ("_.merge", "merge"),
        ("_.defaultsDeep", "defaults_deep"),
        ("lodash.merge", "merge"),
        ("lodash.defaultsDeep", "defaults_deep"),
        (".merge(", "merge"),
        (".defaultsDeep(", "defaults_deep"),
    ];

    for (pattern, variant) in &lodash_patterns {
        if body.contains(pattern) {
            issues.push(PrototypePollutionIssue::LodashMergeDetected {
                variant: variant.to_string(),
            });
        }
    }

    issues
}

fn detect_jquery_extend(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();

    if body.contains("$.extend") || body.contains("jQuery.extend") {
        let deep = body.contains("$.extend(true") || body.contains("jQuery.extend(true");
        issues.push(PrototypePollutionIssue::JqueryExtendDetected { deep });
    }

    issues
}

fn detect_url_parameter_pollution(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let param_patterns = [
        "?__proto__",
        "&__proto__",
        "?constructor[prototype]",
        "&constructor[prototype]",
        "?constructor.prototype",
        "&constructor.prototype",
    ];

    for pattern in &param_patterns {
        if body.contains(pattern) {
            let parameter = pattern
                .trim_start_matches('?')
                .trim_start_matches('&')
                .to_string();
            issues.push(PrototypePollutionIssue::UrlParameterPollution { parameter });
        }
    }

    issues
}

fn detect_gadget_chains(body: &str) -> Vec<PrototypePollutionIssue> {
    let mut issues = Vec::new();
    let gadget_patterns = [
        ("innerHTML", "inner_html"),
        (".eval(", "eval"),
        ("document.write", "document_write"),
        ("setTimeout", "set_timeout"),
        ("setInterval", "set_interval"),
        ("Function(", "function_constructor"),
    ];

    let has_proto = body.contains("__proto__") || body.contains("constructor.prototype");

    if has_proto {
        for (pattern, gadget_type) in &gadget_patterns {
            if body.contains(pattern) {
                issues.push(PrototypePollutionIssue::GadgetChainDetected {
                    gadget_type: gadget_type.to_string(),
                });
            }
        }
    }

    issues
}

fn extract_context(body: &str, pattern: &str) -> String {
    if let Some(pos) = body.find(pattern) {
        let start = pos.saturating_sub(20);
        let end = (pos + pattern.len() + 20).min(body.len());
        truncate(&body[start..end], 50)
    } else {
        "unknown".to_string()
    }
}

fn extract_location(line: &str) -> String {
    truncate(line.trim(), 60)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

pub fn prototype_pollution_to_operations(
    issues: &[PrototypePollutionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::PrototypePollution,
                prototype_pollution_severity(issue),
                0.7,
            )
        })
        .collect()
}
