use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MassAssignIssue {
    ReflectedAdminField { field: String, endpoint: String },
    ReflectedRoleField { field: String, endpoint: String },
    AcceptsUnknownFields { endpoint: String, count: usize },
}

impl std::fmt::Display for MassAssignIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReflectedAdminField { field, endpoint } => {
                write!(f, "reflected_admin_field:{field}@{endpoint}")
            }
            Self::ReflectedRoleField { field, endpoint } => {
                write!(f, "reflected_role_field:{field}@{endpoint}")
            }
            Self::AcceptsUnknownFields { endpoint, count } => {
                write!(f, "accepts_unknown_fields:{count}@{endpoint}")
            }
        }
    }
}

const ADMIN_FIELDS: &[&str] = &["admin", "is_admin", "isAdmin", "is_superuser", "superuser"];

const ROLE_FIELDS: &[&str] = &[
    "role",
    "user_role",
    "userRole",
    "permission",
    "permissions",
    "group",
    "access_level",
    "accessLevel",
    "privilege",
];

const CANARY_FIELDS: &[&str] = &["__test_field_aegis", "__canary_param"];

pub fn analyze_mass_assignment(
    endpoint: &str,
    sent_fields: &[&str],
    response_body: &str,
) -> Vec<MassAssignIssue> {
    let mut issues = Vec::new();
    let body_lower = response_body.to_ascii_lowercase();

    for &field in sent_fields {
        let field_lower = field.to_ascii_lowercase();
        if !body_lower.contains(&format!("\"{field_lower}\"")) {
            continue;
        }

        if ADMIN_FIELDS
            .iter()
            .any(|a| a.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::ReflectedAdminField {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
        } else if ROLE_FIELDS
            .iter()
            .any(|r| r.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::ReflectedRoleField {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
        }
    }

    let canary_count = CANARY_FIELDS
        .iter()
        .filter(|c| body_lower.contains(&c.to_ascii_lowercase()))
        .count();
    if canary_count > 0 {
        issues.push(MassAssignIssue::AcceptsUnknownFields {
            endpoint: endpoint.to_string(),
            count: canary_count,
        });
    }

    issues
}

pub(crate) fn mass_assign_severity(issue: &MassAssignIssue) -> f64 {
    match issue {
        MassAssignIssue::ReflectedAdminField { .. } => 9.0,
        MassAssignIssue::ReflectedRoleField { .. } => 7.0,
        MassAssignIssue::AcceptsUnknownFields { .. } => 4.5,
    }
}

pub fn mass_assign_to_operations(
    issues: &[MassAssignIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::MassAssignment,
                mass_assign_severity(issue),
                0.85,
            )
        })
        .collect()
}
