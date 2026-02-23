use serde_json::{Map, Value};

const CRITICAL_SEVERITY: f64 = 9.0;
const HIGH_SEVERITY: f64 = 7.0;

const PRIVILEGE_FIELDS: &[&str] = &[
    "role",
    "isAdmin",
    "is_admin",
    "admin",
    "type",
    "user_type",
    "permissions",
    "verified",
    "active",
    "email_verified",
    "plan",
    "subscription",
    "level",
    "access_level",
    "group",
    "is_staff",
    "is_superuser",
    "privilege",
];

const CRITICAL_FIELDS: &[&str] = &[
    "isAdmin",
    "is_admin",
    "admin",
    "is_staff",
    "is_superuser",
    "role",
    "permissions",
    "privilege",
];

const BODY_ACCEPTING_METHODS: &[&str] = &["POST", "PUT", "PATCH"];

#[derive(Debug, Clone)]
pub struct MassAssignmentFinding {
    pub endpoint: String,
    pub method: String,
    pub field: String,
    pub injected_value: String,
    pub severity: f64,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct MassAssignmentPayload {
    pub body: String,
    pub injected_field: String,
    pub injected_value: String,
}

pub struct MassAssignmentTester;

impl MassAssignmentTester {
    pub fn test_mass_assignment(
        endpoint: &str,
        method: &str,
        base_body_json: Option<&str>,
    ) -> Vec<MassAssignmentFinding> {
        if !is_mass_assignment_candidate(method) {
            return Vec::new();
        }

        let payloads = generate_mass_assignment_payloads(base_body_json);
        let method_upper = method.to_uppercase();

        payloads
            .into_iter()
            .map(|p| {
                let severity = severity_for_field(&p.injected_field);
                let evidence = format!(
                    "Injected privilege field '{field}' with value {value} into {method} {endpoint}",
                    field = p.injected_field,
                    value = p.injected_value,
                    method = method_upper,
                    endpoint = endpoint,
                );
                MassAssignmentFinding {
                    endpoint: endpoint.to_string(),
                    method: method_upper.clone(),
                    field: p.injected_field,
                    injected_value: p.injected_value,
                    severity,
                    evidence,
                }
            })
            .collect()
    }
}

pub fn is_mass_assignment_candidate(method: &str) -> bool {
    let upper = method.to_uppercase();
    BODY_ACCEPTING_METHODS.contains(&upper.as_str())
}

pub fn generate_mass_assignment_payloads(base_body: Option<&str>) -> Vec<MassAssignmentPayload> {
    let base: Value = base_body
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or_else(|| Value::Object(Map::new()));

    let mut payloads = Vec::new();

    for &field in PRIVILEGE_FIELDS {
        for (value_repr, json_value) in test_values_for_field(field) {
            let mut obj = base.clone();
            if let Value::Object(ref mut map) = obj {
                map.insert(field.to_string(), json_value);
            }
            payloads.push(MassAssignmentPayload {
                body: serde_json::to_string(&obj).unwrap_or_default(),
                injected_field: field.to_string(),
                injected_value: value_repr,
            });
        }
    }

    payloads
}

fn test_values_for_field(field: &str) -> Vec<(String, Value)> {
    match field {
        "isAdmin" | "is_admin" | "admin" | "verified" | "active" | "email_verified"
        | "is_staff" | "is_superuser" => vec![
            ("true".to_string(), Value::Bool(true)),
            ("1".to_string(), Value::Number(1.into())),
        ],
        "role" | "type" | "user_type" | "plan" | "group" | "privilege" => vec![
            ("\"admin\"".to_string(), Value::String("admin".to_string())),
            (
                "\"superuser\"".to_string(),
                Value::String("superuser".to_string()),
            ),
        ],
        "level" | "access_level" => vec![
            ("999".to_string(), Value::Number(999.into())),
            ("0".to_string(), Value::Number(0.into())),
        ],
        "permissions" => vec![
            ("\"admin\"".to_string(), Value::String("admin".to_string())),
            (
                "\"superuser\"".to_string(),
                Value::String("superuser".to_string()),
            ),
        ],
        "subscription" => vec![
            ("\"admin\"".to_string(), Value::String("admin".to_string())),
            (
                "\"superuser\"".to_string(),
                Value::String("superuser".to_string()),
            ),
        ],
        _ => vec![("true".to_string(), Value::Bool(true))],
    }
}

fn severity_for_field(field: &str) -> f64 {
    if CRITICAL_FIELDS.contains(&field) {
        CRITICAL_SEVERITY
    } else {
        HIGH_SEVERITY
    }
}

#[cfg(test)]
#[path = "mass_assignment_tester_test.rs"]
mod mass_assignment_tester_test;
