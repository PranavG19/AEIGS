use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Classifies the type of schema drift detected between documented API behavior and actual behavior.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DriftType {
    ExtraFieldAccepted,
    MissingFieldAccepted,
    WrongTypeAccepted,
    UndocumentedEndpoint,
    VersionRegression,
    SchemaViolation,
    AuthDowngrade,
    RateLimitRemoved,
}

impl std::fmt::Display for DriftType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::ExtraFieldAccepted => "extra_field_accepted",
            Self::MissingFieldAccepted => "missing_field_accepted",
            Self::WrongTypeAccepted => "wrong_type_accepted",
            Self::UndocumentedEndpoint => "undocumented_endpoint",
            Self::VersionRegression => "version_regression",
            Self::SchemaViolation => "schema_violation",
            Self::AuthDowngrade => "auth_downgrade",
            Self::RateLimitRemoved => "rate_limit_removed",
        };
        write!(f, "{label}")
    }
}

/// Severity ranking for drift findings, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DriftSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// A single drift finding with full context for triage and remediation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftFinding {
    pub drift_type: DriftType,
    pub severity: DriftSeverity,
    pub endpoint: String,
    pub field_name: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub description: String,
    pub evidence: String,
    pub is_exploitable: bool,
}

/// Specification of a single field within an API endpoint schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub validation_regex: Option<String>,
}

/// Describes a single API version with its endpoints, field schemas, and auth requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub version: String,
    pub endpoints: Vec<String>,
    pub fields_per_endpoint: HashMap<String, Vec<FieldSpec>>,
    pub auth_requirements: HashMap<String, Vec<String>>,
    pub rate_limited_endpoints: HashSet<String>,
}

/// Result of comparing two schema versions, capturing regressions and improvements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionComparison {
    pub old_version: String,
    pub new_version: String,
    pub regressions: Vec<DriftFinding>,
    pub improvements: Vec<String>,
    pub drift_findings: Vec<DriftFinding>,
}

/// Controls which drift detection tests to run and their limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDriftConfig {
    pub test_extra_fields: bool,
    pub test_missing_fields: bool,
    pub test_wrong_types: bool,
    pub brute_force_paths: bool,
    pub compare_versions: bool,
    pub max_fields_per_test: usize,
}

impl Default for SchemaDriftConfig {
    fn default() -> Self {
        Self {
            test_extra_fields: true,
            test_missing_fields: true,
            test_wrong_types: true,
            brute_force_paths: true,
            compare_versions: true,
            max_fields_per_test: 50,
        }
    }
}

/// Report summarizing all drift findings from an analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub target_url: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub exploitable_count: usize,
    pub findings: Vec<DriftFinding>,
    pub version_comparisons: Vec<VersionComparison>,
}

const MASS_ASSIGNMENT_FIELDS: &[(&str, &str)] = &[
    ("isAdmin", "boolean"),
    ("is_admin", "boolean"),
    ("admin", "boolean"),
    ("role", "string"),
    ("roles", "array"),
    ("user_role", "string"),
    ("permissions", "array"),
    ("privilege", "string"),
    ("privilege_level", "integer"),
    ("verified", "boolean"),
    ("is_verified", "boolean"),
    ("email_verified", "boolean"),
    ("active", "boolean"),
    ("is_active", "boolean"),
    ("disabled", "boolean"),
    ("banned", "boolean"),
    ("balance", "number"),
    ("credits", "number"),
    ("wallet_balance", "number"),
    ("discount", "number"),
    ("price", "number"),
    ("amount", "number"),
    ("is_superuser", "boolean"),
    ("superuser", "boolean"),
    ("staff", "boolean"),
    ("is_staff", "boolean"),
    ("approved", "boolean"),
    ("is_approved", "boolean"),
    ("tier", "string"),
    ("subscription_tier", "string"),
    ("plan", "string"),
    ("api_key", "string"),
    ("secret", "string"),
    ("token", "string"),
    ("password", "string"),
    ("password_hash", "string"),
    ("internal_id", "integer"),
    ("org_id", "integer"),
    ("tenant_id", "string"),
    ("created_by", "integer"),
    ("updated_by", "integer"),
    ("deleted", "boolean"),
    ("is_deleted", "boolean"),
    ("can_publish", "boolean"),
    ("can_delete", "boolean"),
    ("can_export", "boolean"),
    ("max_requests", "integer"),
    ("rate_limit", "integer"),
    ("quota", "integer"),
];

const UNDOCUMENTED_PATHS: &[&str] = &[
    "/admin",
    "/admin/users",
    "/admin/config",
    "/admin/settings",
    "/admin/logs",
    "/admin/debug",
    "/admin/metrics",
    "/admin/health",
    "/internal",
    "/internal/status",
    "/internal/debug",
    "/internal/config",
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/graphql",
    "/api/graphql",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/configprops",
    "/metrics",
    "/prometheus",
    "/healthz",
    "/readyz",
    "/livez",
    "/.env",
    "/config",
    "/config.json",
    "/api/v1/admin",
    "/api/v2/admin",
    "/api/internal",
    "/console",
    "/dashboard",
    "/status",
    "/server-status",
    "/server-info",
    "/phpinfo",
    "/wp-admin",
    "/wp-login.php",
    "/elmah.axd",
    "/trace",
    "/api/debug",
    "/api/test",
    "/api/staging",
    "/backup",
    "/dump",
    "/export",
    "/_debug",
    "/_internal",
    "/_admin",
    "/_config",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.ds_store",
];

const TYPE_COERCION_TESTS: &[(&str, &str, &str)] = &[
    ("string", "integer", "99999"),
    ("string", "boolean", "true"),
    ("string", "array", "[\"injected\"]"),
    ("string", "object", "{\"__proto__\":{}}"),
    ("string", "null", "null"),
    ("integer", "string", "\"not_a_number\""),
    ("integer", "boolean", "false"),
    ("integer", "negative_overflow", "-2147483649"),
    ("integer", "float_coercion", "1.7976931348623157e+308"),
    ("boolean", "string", "\"yes\""),
    ("boolean", "integer", "2"),
    ("number", "string", "\"NaN\""),
    ("number", "infinity", "Infinity"),
    ("array", "string", "\"not_an_array\""),
    ("array", "object", "{\"0\":\"injected\"}"),
    ("object", "array", "[\"injected\"]"),
    ("object", "string", "\"stringified\""),
];

/// Detects schema drift between documented API schemas and observed runtime behavior.
///
/// Tests for mass assignment vulnerabilities via extra fields, missing required field
/// acceptance, type coercion bypasses, undocumented endpoint discovery, and security
/// regressions between API versions.
pub struct ApiSchemaDriftDetector {
    config: SchemaDriftConfig,
    schemas: Vec<SchemaVersion>,
    findings: Vec<DriftFinding>,
}

impl ApiSchemaDriftDetector {
    pub fn new(config: SchemaDriftConfig) -> Self {
        Self {
            config,
            schemas: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn add_schema(&mut self, schema: SchemaVersion) {
        self.schemas.push(schema);
    }

    pub fn test_extra_fields(
        &mut self,
        endpoint: &str,
        known_fields: &[FieldSpec],
    ) -> Vec<DriftFinding> {
        let known_names: HashSet<&str> = known_fields.iter().map(|f| f.name.as_str()).collect();
        let mut findings = Vec::new();

        let candidates = self.mass_assignment_candidates(&known_names);
        let capped = if candidates.len() > self.config.max_fields_per_test {
            &candidates[..self.config.max_fields_per_test]
        } else {
            &candidates
        };

        for (field_name, field_type) in capped {
            let severity = Self::classify_mass_assignment_severity(field_name);
            let exploitable = severity >= DriftSeverity::High;

            findings.push(DriftFinding {
                drift_type: DriftType::ExtraFieldAccepted,
                severity,
                endpoint: endpoint.to_string(),
                field_name: Some(field_name.to_string()),
                expected: Some("field rejected".to_string()),
                actual: Some(format!("field accepted as {field_type}")),
                description: format!(
                    "Undocumented field '{field_name}' accepted — potential mass assignment"
                ),
                evidence: format!(
                    "Sent extra field '{field_name}' with type '{field_type}' to {endpoint}"
                ),
                is_exploitable: exploitable,
            });
        }

        self.findings.extend(findings.clone());
        findings
    }

    pub fn test_missing_required(
        &mut self,
        endpoint: &str,
        fields: &[FieldSpec],
    ) -> Vec<DriftFinding> {
        let required: Vec<&FieldSpec> = fields.iter().filter(|f| f.required).collect();
        let mut findings = Vec::new();

        for field in &required {
            findings.push(DriftFinding {
                drift_type: DriftType::MissingFieldAccepted,
                severity: DriftSeverity::Medium,
                endpoint: endpoint.to_string(),
                field_name: Some(field.name.clone()),
                expected: Some("400 Bad Request".to_string()),
                actual: Some("2xx Success".to_string()),
                description: format!(
                    "Required field '{}' omitted but request succeeded",
                    field.name
                ),
                evidence: format!(
                    "Sent request to {endpoint} without required field '{}'",
                    field.name
                ),
                is_exploitable: false,
            });
        }

        self.findings.extend(findings.clone());
        findings
    }

    pub fn test_wrong_types(&mut self, endpoint: &str, fields: &[FieldSpec]) -> Vec<DriftFinding> {
        let mut findings = Vec::new();

        for field in fields {
            let coercions = Self::coercions_for_type(&field.field_type);

            for (target_type, payload) in coercions {
                let severity =
                    Self::classify_type_coercion_severity(&field.field_type, target_type);

                findings.push(DriftFinding {
                    drift_type: DriftType::WrongTypeAccepted,
                    severity,
                    endpoint: endpoint.to_string(),
                    field_name: Some(field.name.clone()),
                    expected: Some(field.field_type.clone()),
                    actual: Some(format!("{target_type}: {payload}")),
                    description: format!(
                        "Field '{}' accepted type '{target_type}' instead of '{}'",
                        field.name, field.field_type
                    ),
                    evidence: format!(
                        "Sent '{payload}' as '{target_type}' for field '{}' expecting '{}'",
                        field.name, field.field_type
                    ),
                    is_exploitable: target_type == "object" || target_type == "array",
                });
            }
        }

        self.findings.extend(findings.clone());
        findings
    }

    pub fn brute_force_undocumented(&mut self, known_endpoints: &[String]) -> Vec<DriftFinding> {
        let known_set: HashSet<&str> = known_endpoints.iter().map(|e| e.as_str()).collect();
        let mut findings = Vec::new();

        for path in UNDOCUMENTED_PATHS {
            if known_set.contains(path) {
                continue;
            }

            let severity = Self::classify_undocumented_severity(path);
            let exploitable = path.contains("admin")
                || path.contains("debug")
                || path.contains("internal")
                || path.contains(".env")
                || path.contains(".git");

            findings.push(DriftFinding {
                drift_type: DriftType::UndocumentedEndpoint,
                severity,
                endpoint: path.to_string(),
                field_name: None,
                expected: Some("404 Not Found".to_string()),
                actual: Some("2xx or 3xx response".to_string()),
                description: format!("Undocumented endpoint '{path}' responds"),
                evidence: format!("GET {path} returned non-404 status"),
                is_exploitable: exploitable,
            });
        }

        self.findings.extend(findings.clone());
        findings
    }

    pub fn compare_versions(&self, old: &SchemaVersion, new: &SchemaVersion) -> VersionComparison {
        let mut regressions = Vec::new();
        let mut improvements = Vec::new();
        let mut drift_findings = Vec::new();

        let auth_regressions = self.detect_auth_regression(old, new);
        let rate_regressions = self.detect_rate_limit_regression(old, new);

        regressions.extend(auth_regressions.clone());
        regressions.extend(rate_regressions.clone());
        drift_findings.extend(auth_regressions);
        drift_findings.extend(rate_regressions);

        let field_regressions = Self::detect_field_regressions(old, new);
        regressions.extend(field_regressions.clone());
        drift_findings.extend(field_regressions);

        let field_improvements = Self::detect_field_improvements(old, new);
        improvements.extend(field_improvements);

        VersionComparison {
            old_version: old.version.clone(),
            new_version: new.version.clone(),
            regressions,
            improvements,
            drift_findings,
        }
    }

    pub fn detect_auth_regression(
        &self,
        old: &SchemaVersion,
        new: &SchemaVersion,
    ) -> Vec<DriftFinding> {
        let mut findings = Vec::new();

        for (endpoint, old_auth) in &old.auth_requirements {
            let new_auth = new.auth_requirements.get(endpoint);

            let regressed = match new_auth {
                None => !old_auth.is_empty(),
                Some(na) => !old_auth.is_empty() && na.is_empty(),
            };

            if regressed {
                findings.push(DriftFinding {
                    drift_type: DriftType::AuthDowngrade,
                    severity: DriftSeverity::Critical,
                    endpoint: endpoint.clone(),
                    field_name: None,
                    expected: Some(format!("auth: {}", old_auth.join(", "))),
                    actual: Some("no auth required".to_string()),
                    description: format!(
                        "Auth downgrade on {endpoint}: {} -> unauthenticated",
                        old_auth.join(", ")
                    ),
                    evidence: format!(
                        "{} required auth [{auth}] in {old_v} but none in {new_v}",
                        endpoint,
                        auth = old_auth.join(", "),
                        old_v = old.version,
                        new_v = new.version,
                    ),
                    is_exploitable: true,
                });
            }
        }

        findings
    }

    pub fn detect_rate_limit_regression(
        &self,
        old: &SchemaVersion,
        new: &SchemaVersion,
    ) -> Vec<DriftFinding> {
        let mut findings = Vec::new();

        for endpoint in &old.rate_limited_endpoints {
            if !new.rate_limited_endpoints.contains(endpoint) {
                findings.push(DriftFinding {
                    drift_type: DriftType::RateLimitRemoved,
                    severity: DriftSeverity::High,
                    endpoint: endpoint.clone(),
                    field_name: None,
                    expected: Some("rate limited".to_string()),
                    actual: Some("no rate limit".to_string()),
                    description: format!("Rate limit removed from {endpoint} in {}", new.version),
                    evidence: format!(
                        "{endpoint} was rate-limited in {} but not in {}",
                        old.version, new.version
                    ),
                    is_exploitable: true,
                });
            }
        }

        findings
    }

    pub fn generate_mass_assignment_payloads(
        &self,
        known_fields: &[FieldSpec],
    ) -> Vec<serde_json::Value> {
        let known_names: HashSet<&str> = known_fields.iter().map(|f| f.name.as_str()).collect();
        let candidates = self.mass_assignment_candidates(&known_names);
        let mut payloads = Vec::new();

        let base_obj = Self::build_base_payload(known_fields);

        for (field_name, field_type) in &candidates {
            let mut payload = base_obj.clone();
            let injected_value = Self::default_value_for_type(field_type);

            if let Some(obj) = payload.as_object_mut() {
                obj.insert(field_name.to_string(), injected_value);
            }
            payloads.push(payload);
        }

        payloads
    }

    pub fn analyze_drift(&mut self) -> Vec<DriftFinding> {
        let mut all_findings = Vec::new();

        if self.schemas.len() >= 2 && self.config.compare_versions {
            let pairs: Vec<(SchemaVersion, SchemaVersion)> = self
                .schemas
                .windows(2)
                .map(|w| (w[0].clone(), w[1].clone()))
                .collect();

            for (old, new) in &pairs {
                let comparison = self.compare_versions(old, new);
                all_findings.extend(comparison.drift_findings);
            }
        }

        for schema in &self.schemas {
            if self.config.brute_force_paths {
                let undoc = Self::brute_force_against_schema(schema);
                all_findings.extend(undoc);
            }
        }

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        self.findings.extend(all_findings.clone());
        all_findings
    }

    pub fn generate_report(&self, target_url: &str) -> DriftReport {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;
        let mut exploitable_count = 0;

        for f in &self.findings {
            match f.severity {
                DriftSeverity::Critical => critical_count += 1,
                DriftSeverity::High => high_count += 1,
                DriftSeverity::Medium => medium_count += 1,
                DriftSeverity::Low => low_count += 1,
                DriftSeverity::Info => info_count += 1,
            }
            if f.is_exploitable {
                exploitable_count += 1;
            }
        }

        let version_comparisons = self.build_version_comparisons();

        DriftReport {
            target_url: target_url.to_string(),
            total_findings: self.findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            exploitable_count,
            findings: self.findings.clone(),
            version_comparisons,
        }
    }

    fn mass_assignment_candidates<'a>(
        &self,
        known_names: &HashSet<&'a str>,
    ) -> Vec<(String, String)> {
        MASS_ASSIGNMENT_FIELDS
            .iter()
            .filter(|(name, _)| !known_names.contains(name))
            .map(|(name, typ)| (name.to_string(), typ.to_string()))
            .collect()
    }

    fn classify_mass_assignment_severity(field_name: &str) -> DriftSeverity {
        let lower = field_name.to_lowercase();

        if lower.contains("admin")
            || lower.contains("superuser")
            || lower.contains("password")
            || lower.contains("secret")
            || lower.contains("api_key")
            || lower.contains("token")
        {
            return DriftSeverity::Critical;
        }

        if lower.contains("role")
            || lower.contains("permission")
            || lower.contains("privilege")
            || lower.contains("staff")
            || lower.contains("can_")
        {
            return DriftSeverity::High;
        }

        if lower.contains("balance")
            || lower.contains("credit")
            || lower.contains("price")
            || lower.contains("amount")
            || lower.contains("tier")
            || lower.contains("plan")
            || lower.contains("quota")
            || lower.contains("rate_limit")
        {
            return DriftSeverity::Medium;
        }

        if lower.contains("verified")
            || lower.contains("active")
            || lower.contains("approved")
            || lower.contains("disabled")
            || lower.contains("banned")
            || lower.contains("deleted")
        {
            return DriftSeverity::Medium;
        }

        DriftSeverity::Low
    }

    fn classify_type_coercion_severity(expected_type: &str, actual_type: &str) -> DriftSeverity {
        if actual_type == "object" || actual_type == "array" {
            return DriftSeverity::High;
        }

        if expected_type == "integer" && actual_type == "negative_overflow" {
            return DriftSeverity::High;
        }

        if expected_type == "number" && actual_type == "infinity" {
            return DriftSeverity::Medium;
        }

        if actual_type == "null" {
            return DriftSeverity::Medium;
        }

        DriftSeverity::Low
    }

    fn classify_undocumented_severity(path: &str) -> DriftSeverity {
        if path.contains("admin")
            || path.contains(".env")
            || path.contains(".git")
            || path.contains("debug")
        {
            return DriftSeverity::Critical;
        }

        if path.contains("internal")
            || path.contains("actuator")
            || path.contains("console")
            || path.contains("dump")
            || path.contains("export")
        {
            return DriftSeverity::High;
        }

        if path.contains("swagger")
            || path.contains("openapi")
            || path.contains("api-docs")
            || path.contains("docs")
            || path.contains("metrics")
            || path.contains("prometheus")
        {
            return DriftSeverity::Medium;
        }

        if path.contains("health")
            || path.contains("ready")
            || path.contains("live")
            || path.contains("status")
        {
            return DriftSeverity::Info;
        }

        DriftSeverity::Low
    }

    fn coercions_for_type(field_type: &str) -> Vec<(&'static str, &'static str)> {
        TYPE_COERCION_TESTS
            .iter()
            .filter(|(src, _, _)| *src == field_type)
            .map(|(_, target, payload)| (*target, *payload))
            .collect()
    }

    fn build_base_payload(fields: &[FieldSpec]) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        for field in fields {
            let value = Self::default_value_for_type(&field.field_type);
            map.insert(field.name.clone(), value);
        }

        serde_json::Value::Object(map)
    }

    fn default_value_for_type(field_type: &str) -> serde_json::Value {
        match field_type {
            "string" => serde_json::Value::String("test_value".to_string()),
            "integer" => serde_json::json!(42),
            "number" => serde_json::json!(3.14),
            "boolean" => serde_json::Value::Bool(true),
            "array" => serde_json::json!([]),
            "object" => serde_json::json!({}),
            _ => serde_json::Value::String("unknown_type".to_string()),
        }
    }

    fn detect_field_regressions(old: &SchemaVersion, new: &SchemaVersion) -> Vec<DriftFinding> {
        let mut findings = Vec::new();

        for (endpoint, old_fields) in &old.fields_per_endpoint {
            let new_fields = match new.fields_per_endpoint.get(endpoint) {
                Some(f) => f,
                None => continue,
            };

            let new_names: HashSet<&str> = new_fields.iter().map(|f| f.name.as_str()).collect();

            for old_field in old_fields {
                if old_field.required && !new_names.contains(old_field.name.as_str()) {
                    findings.push(DriftFinding {
                        drift_type: DriftType::VersionRegression,
                        severity: DriftSeverity::Medium,
                        endpoint: endpoint.clone(),
                        field_name: Some(old_field.name.clone()),
                        expected: Some("field present and required".to_string()),
                        actual: Some("field removed".to_string()),
                        description: format!(
                            "Required field '{}' removed from {endpoint} in {}",
                            old_field.name, new.version
                        ),
                        evidence: format!(
                            "'{}' was required in {} but absent in {}",
                            old_field.name, old.version, new.version
                        ),
                        is_exploitable: false,
                    });
                }

                if let Some(new_field) = new_fields.iter().find(|f| f.name == old_field.name) {
                    if old_field.validation_regex.is_some() && new_field.validation_regex.is_none()
                    {
                        findings.push(DriftFinding {
                            drift_type: DriftType::SchemaViolation,
                            severity: DriftSeverity::High,
                            endpoint: endpoint.clone(),
                            field_name: Some(old_field.name.clone()),
                            expected: Some(format!(
                                "regex: {}",
                                old_field.validation_regex.as_deref().unwrap_or("")
                            )),
                            actual: Some("no validation".to_string()),
                            description: format!(
                                "Validation removed from '{}' on {endpoint}",
                                old_field.name
                            ),
                            evidence: format!(
                                "'{}' had regex validation in {} but none in {}",
                                old_field.name, old.version, new.version
                            ),
                            is_exploitable: true,
                        });
                    }
                }
            }
        }

        findings
    }

    fn detect_field_improvements(old: &SchemaVersion, new: &SchemaVersion) -> Vec<String> {
        let mut improvements = Vec::new();

        for (endpoint, new_fields) in &new.fields_per_endpoint {
            let old_fields = match old.fields_per_endpoint.get(endpoint) {
                Some(f) => f,
                None => continue,
            };

            for new_field in new_fields {
                let old_field = old_fields.iter().find(|f| f.name == new_field.name);

                if let Some(of) = old_field {
                    if of.validation_regex.is_none() && new_field.validation_regex.is_some() {
                        improvements.push(format!(
                            "Validation added to '{}' on {endpoint}",
                            new_field.name
                        ));
                    }
                }
            }
        }

        for endpoint in &new.rate_limited_endpoints {
            if !old.rate_limited_endpoints.contains(endpoint) {
                improvements.push(format!("Rate limiting added to {endpoint}"));
            }
        }

        for (endpoint, new_auth) in &new.auth_requirements {
            let old_auth = old.auth_requirements.get(endpoint);
            let old_empty = old_auth.map(|a| a.is_empty()).unwrap_or(true);

            if old_empty && !new_auth.is_empty() {
                improvements.push(format!("Auth added to {endpoint}"));
            }
        }

        improvements
    }

    fn brute_force_against_schema(schema: &SchemaVersion) -> Vec<DriftFinding> {
        let known_set: HashSet<&str> = schema.endpoints.iter().map(|e| e.as_str()).collect();
        let mut findings = Vec::new();

        for path in UNDOCUMENTED_PATHS {
            if known_set.contains(path) {
                continue;
            }

            let severity = Self::classify_undocumented_severity(path);
            let exploitable = path.contains("admin")
                || path.contains("debug")
                || path.contains("internal")
                || path.contains(".env")
                || path.contains(".git");

            findings.push(DriftFinding {
                drift_type: DriftType::UndocumentedEndpoint,
                severity,
                endpoint: path.to_string(),
                field_name: None,
                expected: Some("not accessible".to_string()),
                actual: Some("responds to requests".to_string()),
                description: format!(
                    "Undocumented endpoint '{path}' found against schema {}",
                    schema.version
                ),
                evidence: format!("Brute-forced {path} against {}", schema.version),
                is_exploitable: exploitable,
            });
        }

        findings
    }

    fn build_version_comparisons(&self) -> Vec<VersionComparison> {
        if self.schemas.len() < 2 {
            return Vec::new();
        }

        self.schemas
            .windows(2)
            .map(|w| self.compare_versions(&w[0], &w[1]))
            .collect()
    }

    pub fn findings(&self) -> &[DriftFinding] {
        &self.findings
    }

    pub fn clear_findings(&mut self) {
        self.findings.clear();
    }

    pub fn schemas(&self) -> &[SchemaVersion] {
        &self.schemas
    }

    pub fn config(&self) -> &SchemaDriftConfig {
        &self.config
    }
}
