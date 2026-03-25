use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVersionSpec {
    pub version: String,
    pub spec: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldChangeType {
    Added,
    Removed,
    TypeChanged,
    ConstraintAdded,
    ConstraintRemoved,
}

impl std::fmt::Display for FieldChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::TypeChanged => "type_changed",
            Self::ConstraintAdded => "constraint_added",
            Self::ConstraintRemoved => "constraint_removed",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDiff {
    pub path: String,
    pub method: String,
    pub field_name: String,
    pub change_type: FieldChangeType,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub security_impact: SecurityImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityImpact {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SecurityImpact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDiff {
    pub path: String,
    pub method: String,
    pub old_auth: Vec<String>,
    pub new_auth: Vec<String>,
    pub auth_added: bool,
    pub auth_removed: bool,
    pub security_impact: SecurityImpact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecatedEndpoint {
    pub path: String,
    pub method: String,
    pub deprecated_in_version: String,
    pub still_accessible: bool,
    pub security_impact: SecurityImpact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseFieldDiff {
    pub path: String,
    pub method: String,
    pub status_code: String,
    pub fields_added: Vec<String>,
    pub fields_removed: Vec<String>,
    pub potential_data_leak: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDiff {
    pub path: String,
    pub method: String,
    pub old_has_rate_limit: bool,
    pub new_has_rate_limit: bool,
    pub security_impact: SecurityImpact,
}

#[derive(Debug, Clone)]
pub struct VersionSecurityDiffReport {
    pub old_version: String,
    pub new_version: String,
    pub field_diffs: Vec<FieldDiff>,
    pub auth_diffs: Vec<AuthDiff>,
    pub deprecated_endpoints: Vec<DeprecatedEndpoint>,
    pub response_diffs: Vec<ResponseFieldDiff>,
    pub rate_limit_diffs: Vec<RateLimitDiff>,
    pub endpoints_only_in_old: Vec<(String, String)>,
    pub endpoints_only_in_new: Vec<(String, String)>,
    pub security_regressions: usize,
    pub security_improvements: usize,
}

pub struct ApiVersionDiffer;

impl ApiVersionDiffer {
    pub fn diff(old: &ApiVersionSpec, new: &ApiVersionSpec) -> VersionSecurityDiffReport {
        let old_endpoints = Self::extract_endpoints(&old.spec);
        let new_endpoints = Self::extract_endpoints(&new.spec);

        let old_set: HashSet<_> = old_endpoints
            .iter()
            .map(|(p, m)| (p.as_str(), m.as_str()))
            .collect();
        let new_set: HashSet<_> = new_endpoints
            .iter()
            .map(|(p, m)| (p.as_str(), m.as_str()))
            .collect();

        let only_in_old: Vec<(String, String)> = old_set
            .difference(&new_set)
            .map(|(p, m)| (p.to_string(), m.to_string()))
            .collect();

        let only_in_new: Vec<(String, String)> = new_set
            .difference(&old_set)
            .map(|(p, m)| (p.to_string(), m.to_string()))
            .collect();

        let common: Vec<(String, String)> = old_set
            .intersection(&new_set)
            .map(|(p, m)| (p.to_string(), m.to_string()))
            .collect();

        let field_diffs = Self::diff_request_fields(&old.spec, &new.spec, &common);
        let auth_diffs = Self::diff_auth(&old.spec, &new.spec, &common);
        let deprecated_endpoints = Self::find_deprecated(&new.spec, &new.version);
        let response_diffs = Self::diff_response_fields(&old.spec, &new.spec, &common);
        let rate_limit_diffs = Self::diff_rate_limits(&old.spec, &new.spec, &common);

        let security_regressions = auth_diffs.iter().filter(|d| d.auth_removed).count()
            + field_diffs
                .iter()
                .filter(|d| d.change_type == FieldChangeType::ConstraintRemoved)
                .count()
            + rate_limit_diffs
                .iter()
                .filter(|d| d.old_has_rate_limit && !d.new_has_rate_limit)
                .count()
            + response_diffs
                .iter()
                .filter(|d| d.potential_data_leak)
                .count();

        let security_improvements = auth_diffs.iter().filter(|d| d.auth_added).count()
            + field_diffs
                .iter()
                .filter(|d| d.change_type == FieldChangeType::ConstraintAdded)
                .count()
            + rate_limit_diffs
                .iter()
                .filter(|d| !d.old_has_rate_limit && d.new_has_rate_limit)
                .count();

        VersionSecurityDiffReport {
            old_version: old.version.clone(),
            new_version: new.version.clone(),
            field_diffs,
            auth_diffs,
            deprecated_endpoints,
            response_diffs,
            rate_limit_diffs,
            endpoints_only_in_old: only_in_old,
            endpoints_only_in_new: only_in_new,
            security_regressions,
            security_improvements,
        }
    }

    fn extract_endpoints(spec: &serde_json::Value) -> Vec<(String, String)> {
        let mut endpoints = Vec::new();
        let http_methods = ["get", "post", "put", "delete", "patch"];

        if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
            for (path, path_item) in paths {
                if let Some(obj) = path_item.as_object() {
                    for method in &http_methods {
                        if obj.contains_key(*method) {
                            endpoints.push((path.clone(), method.to_uppercase()));
                        }
                    }
                }
            }
        }

        endpoints
    }

    fn get_operation<'a>(
        spec: &'a serde_json::Value,
        path: &str,
        method: &str,
    ) -> Option<&'a serde_json::Value> {
        spec.get("paths")?
            .get(path)?
            .get(method.to_lowercase().as_str())
    }

    fn diff_request_fields(
        old_spec: &serde_json::Value,
        new_spec: &serde_json::Value,
        common: &[(String, String)],
    ) -> Vec<FieldDiff> {
        let mut diffs = Vec::new();

        for (path, method) in common {
            let old_op = Self::get_operation(old_spec, path, method);
            let new_op = Self::get_operation(new_spec, path, method);

            let old_params = Self::extract_param_names(old_op);
            let new_params = Self::extract_param_names(new_op);

            for param in old_params.difference(&new_params) {
                diffs.push(FieldDiff {
                    path: path.clone(),
                    method: method.clone(),
                    field_name: param.clone(),
                    change_type: FieldChangeType::Removed,
                    old_value: Some("present".to_string()),
                    new_value: None,
                    security_impact: SecurityImpact::Low,
                });
            }

            for param in new_params.difference(&old_params) {
                diffs.push(FieldDiff {
                    path: path.clone(),
                    method: method.clone(),
                    field_name: param.clone(),
                    change_type: FieldChangeType::Added,
                    old_value: None,
                    new_value: Some("present".to_string()),
                    security_impact: SecurityImpact::Low,
                });
            }

            let old_body_fields = Self::extract_body_field_schemas(old_op);
            let new_body_fields = Self::extract_body_field_schemas(new_op);

            let old_field_names: HashSet<_> = old_body_fields.keys().collect();
            let new_field_names: HashSet<_> = new_body_fields.keys().collect();

            for field in old_field_names.difference(&new_field_names) {
                diffs.push(FieldDiff {
                    path: path.clone(),
                    method: method.clone(),
                    field_name: field.to_string(),
                    change_type: FieldChangeType::Removed,
                    old_value: Some("present".to_string()),
                    new_value: None,
                    security_impact: SecurityImpact::Low,
                });
            }

            for field in new_field_names.difference(&old_field_names) {
                diffs.push(FieldDiff {
                    path: path.clone(),
                    method: method.clone(),
                    field_name: field.to_string(),
                    change_type: FieldChangeType::Added,
                    old_value: None,
                    new_value: Some("present".to_string()),
                    security_impact: SecurityImpact::Low,
                });
            }

            for field in old_field_names.intersection(&new_field_names) {
                let old_schema = &old_body_fields[*field];
                let new_schema = &new_body_fields[*field];

                let old_type = old_schema
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let new_type = new_schema
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                if old_type != new_type {
                    diffs.push(FieldDiff {
                        path: path.clone(),
                        method: method.clone(),
                        field_name: field.to_string(),
                        change_type: FieldChangeType::TypeChanged,
                        old_value: Some(old_type.to_string()),
                        new_value: Some(new_type.to_string()),
                        security_impact: SecurityImpact::Medium,
                    });
                }

                let constraint_keys = [
                    "maxLength",
                    "minLength",
                    "minimum",
                    "maximum",
                    "pattern",
                    "format",
                    "maxItems",
                ];
                for key in &constraint_keys {
                    let old_has = old_schema.get(*key).is_some();
                    let new_has = new_schema.get(*key).is_some();

                    if old_has && !new_has {
                        diffs.push(FieldDiff {
                            path: path.clone(),
                            method: method.clone(),
                            field_name: format!("{field}.{key}"),
                            change_type: FieldChangeType::ConstraintRemoved,
                            old_value: old_schema.get(*key).map(|v| v.to_string()),
                            new_value: None,
                            security_impact: SecurityImpact::High,
                        });
                    } else if !old_has && new_has {
                        diffs.push(FieldDiff {
                            path: path.clone(),
                            method: method.clone(),
                            field_name: format!("{field}.{key}"),
                            change_type: FieldChangeType::ConstraintAdded,
                            old_value: None,
                            new_value: new_schema.get(*key).map(|v| v.to_string()),
                            security_impact: SecurityImpact::None,
                        });
                    }
                }
            }
        }

        diffs
    }

    fn extract_param_names(operation: Option<&serde_json::Value>) -> HashSet<String> {
        let mut names = HashSet::new();
        if let Some(op) = operation
            && let Some(params) = op.get("parameters").and_then(|p| p.as_array())
        {
            for param in params {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    names.insert(name.to_string());
                }
            }
        }
        names
    }

    fn extract_body_field_schemas(
        operation: Option<&serde_json::Value>,
    ) -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();
        if let Some(op) = operation
            && let Some(body) = op.get("requestBody")
            && let Some(content) = body.get("content").and_then(|c| c.as_object())
        {
            for (_media, media_obj) in content {
                if let Some(props) = media_obj
                    .get("schema")
                    .and_then(|s| s.get("properties"))
                    .and_then(|p| p.as_object())
                {
                    for (name, schema) in props {
                        fields.insert(name.clone(), schema.clone());
                    }
                }
            }
        }
        fields
    }

    fn diff_auth(
        old_spec: &serde_json::Value,
        new_spec: &serde_json::Value,
        common: &[(String, String)],
    ) -> Vec<AuthDiff> {
        let mut diffs = Vec::new();

        for (path, method) in common {
            let old_auth = Self::get_auth_schemes(old_spec, path, method);
            let new_auth = Self::get_auth_schemes(new_spec, path, method);

            if old_auth != new_auth {
                let auth_added = old_auth.is_empty() && !new_auth.is_empty();
                let auth_removed = !old_auth.is_empty() && new_auth.is_empty();

                let security_impact = if auth_removed {
                    SecurityImpact::Critical
                } else if auth_added {
                    SecurityImpact::None
                } else {
                    SecurityImpact::Medium
                };

                diffs.push(AuthDiff {
                    path: path.clone(),
                    method: method.clone(),
                    old_auth,
                    new_auth,
                    auth_added,
                    auth_removed,
                    security_impact,
                });
            }
        }

        diffs
    }

    fn get_auth_schemes(spec: &serde_json::Value, path: &str, method: &str) -> Vec<String> {
        let operation = Self::get_operation(spec, path, method);
        let global_security = spec.get("security");

        if let Some(op) = operation
            && let Some(sec) = op.get("security").and_then(|s| s.as_array())
        {
            return sec
                .iter()
                .filter_map(|s| s.as_object())
                .flat_map(|o| o.keys().cloned())
                .collect();
        }

        if let Some(sec) = global_security.and_then(|s| s.as_array()) {
            return sec
                .iter()
                .filter_map(|s| s.as_object())
                .flat_map(|o| o.keys().cloned())
                .collect();
        }

        Vec::new()
    }

    fn find_deprecated(spec: &serde_json::Value, version: &str) -> Vec<DeprecatedEndpoint> {
        let mut deprecated = Vec::new();
        let http_methods = ["get", "post", "put", "delete", "patch"];

        if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
            for (path, path_item) in paths {
                if let Some(obj) = path_item.as_object() {
                    for method in &http_methods {
                        if let Some(op) = obj.get(*method)
                            && op
                                .get("deprecated")
                                .and_then(|d| d.as_bool())
                                .unwrap_or(false)
                        {
                            deprecated.push(DeprecatedEndpoint {
                                path: path.clone(),
                                method: method.to_uppercase(),
                                deprecated_in_version: version.to_string(),
                                still_accessible: true,
                                security_impact: SecurityImpact::Medium,
                            });
                        }
                    }
                }
            }
        }

        deprecated
    }

    fn diff_response_fields(
        old_spec: &serde_json::Value,
        new_spec: &serde_json::Value,
        common: &[(String, String)],
    ) -> Vec<ResponseFieldDiff> {
        let mut diffs = Vec::new();

        for (path, method) in common {
            let old_op = Self::get_operation(old_spec, path, method);
            let new_op = Self::get_operation(new_spec, path, method);

            let old_responses = Self::extract_response_fields(old_op);
            let new_responses = Self::extract_response_fields(new_op);

            let all_status_codes: HashSet<_> =
                old_responses.keys().chain(new_responses.keys()).collect();

            for status in all_status_codes {
                let old_fields: HashSet<_> = old_responses
                    .get(status)
                    .map(|f| f.iter().collect())
                    .unwrap_or_default();
                let new_fields: HashSet<_> = new_responses
                    .get(status)
                    .map(|f| f.iter().collect())
                    .unwrap_or_default();

                let added: Vec<String> = new_fields
                    .difference(&old_fields)
                    .map(|s| s.to_string())
                    .collect();
                let removed: Vec<String> = old_fields
                    .difference(&new_fields)
                    .map(|s| s.to_string())
                    .collect();

                if !added.is_empty() || !removed.is_empty() {
                    let sensitive_patterns = [
                        "password",
                        "secret",
                        "token",
                        "ssn",
                        "email",
                        "phone",
                        "credit_card",
                        "address",
                        "salary",
                    ];

                    let potential_data_leak = old_responses.contains_key(status)
                        && !added.is_empty()
                        && added.iter().any(|f| {
                            let lower = f.to_lowercase();
                            sensitive_patterns.iter().any(|p| lower.contains(p))
                        });

                    diffs.push(ResponseFieldDiff {
                        path: path.clone(),
                        method: method.clone(),
                        status_code: status.clone(),
                        fields_added: added,
                        fields_removed: removed,
                        potential_data_leak,
                    });
                }
            }
        }

        diffs
    }

    fn extract_response_fields(
        operation: Option<&serde_json::Value>,
    ) -> HashMap<String, Vec<String>> {
        let mut result = HashMap::new();

        let op = match operation {
            Some(o) => o,
            None => return result,
        };

        let responses = match op.get("responses").and_then(|r| r.as_object()) {
            Some(r) => r,
            None => return result,
        };

        for (status, response) in responses {
            let mut fields = Vec::new();
            if let Some(content) = response.get("content").and_then(|c| c.as_object()) {
                for (_media, media_obj) in content {
                    if let Some(props) = media_obj
                        .get("schema")
                        .and_then(|s| s.get("properties"))
                        .and_then(|p| p.as_object())
                    {
                        for name in props.keys() {
                            fields.push(name.clone());
                        }
                    }
                }
            }
            if !fields.is_empty() {
                result.insert(status.clone(), fields);
            }
        }

        result
    }

    fn diff_rate_limits(
        old_spec: &serde_json::Value,
        new_spec: &serde_json::Value,
        common: &[(String, String)],
    ) -> Vec<RateLimitDiff> {
        let mut diffs = Vec::new();

        for (path, method) in common {
            let old_has = Self::has_rate_limit_headers(Self::get_operation(old_spec, path, method));
            let new_has = Self::has_rate_limit_headers(Self::get_operation(new_spec, path, method));

            if old_has != new_has {
                let security_impact = if old_has && !new_has {
                    SecurityImpact::High
                } else {
                    SecurityImpact::None
                };

                diffs.push(RateLimitDiff {
                    path: path.clone(),
                    method: method.clone(),
                    old_has_rate_limit: old_has,
                    new_has_rate_limit: new_has,
                    security_impact,
                });
            }
        }

        diffs
    }

    fn has_rate_limit_headers(operation: Option<&serde_json::Value>) -> bool {
        let op = match operation {
            Some(o) => o,
            None => return false,
        };

        if let Some(responses) = op.get("responses").and_then(|r| r.as_object()) {
            for (_code, response) in responses {
                if let Some(headers) = response.get("headers").and_then(|h| h.as_object()) {
                    for header in headers.keys() {
                        let lower = header.to_lowercase();
                        if lower.contains("ratelimit")
                            || lower.contains("rate-limit")
                            || lower == "retry-after"
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}
