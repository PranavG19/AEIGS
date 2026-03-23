use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MassAssignIssue {
    ReflectedAdminField { field: String, endpoint: String },
    ReflectedRoleField { field: String, endpoint: String },
    AcceptsUnknownFields { endpoint: String, count: usize },
    PasswordFieldReflected { field: String, endpoint: String },
    InternalIdExposed { field: String, endpoint: String },
    NestedObjectInjection { path: String, endpoint: String },
    ArrayFieldManipulation { field: String, endpoint: String },
    MetadataFieldReflected { field: String, endpoint: String },
    TimestampFieldOverwrite { field: String, endpoint: String },
    StatusFieldManipulation { field: String, endpoint: String },
    PriceFieldReflected { field: String, endpoint: String },
    TypeFieldConfusion { field: String, endpoint: String },
    HiddenFieldAccepted { field: String, endpoint: String },
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
            Self::PasswordFieldReflected { field, endpoint } => {
                write!(f, "password_reflected:{field}@{endpoint}")
            }
            Self::InternalIdExposed { field, endpoint } => {
                write!(f, "internal_id_exposed:{field}@{endpoint}")
            }
            Self::NestedObjectInjection { path, endpoint } => {
                write!(f, "nested_object_injection:{path}@{endpoint}")
            }
            Self::ArrayFieldManipulation { field, endpoint } => {
                write!(f, "array_field_manipulation:{field}@{endpoint}")
            }
            Self::MetadataFieldReflected { field, endpoint } => {
                write!(f, "metadata_field_reflected:{field}@{endpoint}")
            }
            Self::TimestampFieldOverwrite { field, endpoint } => {
                write!(f, "timestamp_field_overwrite:{field}@{endpoint}")
            }
            Self::StatusFieldManipulation { field, endpoint } => {
                write!(f, "status_field_manipulation:{field}@{endpoint}")
            }
            Self::PriceFieldReflected { field, endpoint } => {
                write!(f, "price_reflected:{field}@{endpoint}")
            }
            Self::TypeFieldConfusion { field, endpoint } => {
                write!(f, "type_field_confusion:{field}@{endpoint}")
            }
            Self::HiddenFieldAccepted { field, endpoint } => {
                write!(f, "hidden_field_accepted:{field}@{endpoint}")
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

const PASSWORD_FIELDS: &[&str] = &["password", "passwd", "secret", "api_key", "apiKey", "token"];

const INTERNAL_ID_FIELDS: &[&str] = &["_id", "internal_id", "internalId", "uuid", "guid", "pk"];

const ARRAY_FIELDS: &[&str] = &["items", "tags", "roles"];

const METADATA_FIELDS: &[&str] = &[
    "created_at",
    "createdAt",
    "updated_at",
    "updatedAt",
    "version",
    "_v",
];

const TIMESTAMP_FIELDS: &[&str] = &["timestamp", "expires_at", "expiresAt", "valid_until", "ttl"];

const STATUS_FIELDS: &[&str] = &[
    "status", "state", "active", "enabled", "verified", "approved",
];

const PRICE_FIELDS: &[&str] = &["price", "amount", "cost", "total", "balance", "credit"];

const TYPE_FIELDS: &[&str] = &["type", "_type", "__type", "kind", "class", "category"];

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

pub fn mass_assign_severity(issue: &MassAssignIssue) -> f64 {
    match issue {
        MassAssignIssue::ReflectedAdminField { .. } => 9.0,
        MassAssignIssue::ReflectedRoleField { .. } => 7.0,
        MassAssignIssue::AcceptsUnknownFields { .. } => 4.5,
        MassAssignIssue::PasswordFieldReflected { .. } => 9.5,
        MassAssignIssue::InternalIdExposed { .. } => 7.5,
        MassAssignIssue::NestedObjectInjection { .. } => 8.0,
        MassAssignIssue::ArrayFieldManipulation { .. } => 6.0,
        MassAssignIssue::MetadataFieldReflected { .. } => 5.0,
        MassAssignIssue::TimestampFieldOverwrite { .. } => 5.5,
        MassAssignIssue::StatusFieldManipulation { .. } => 7.0,
        MassAssignIssue::PriceFieldReflected { .. } => 8.5,
        MassAssignIssue::TypeFieldConfusion { .. } => 6.5,
        MassAssignIssue::HiddenFieldAccepted { .. } => 4.0,
    }
}

pub fn analyze_mass_assignment_advanced(
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

        // PasswordFieldReflected
        if PASSWORD_FIELDS
            .iter()
            .any(|p| p.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::PasswordFieldReflected {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // InternalIdExposed
        if INTERNAL_ID_FIELDS
            .iter()
            .any(|id| id.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::InternalIdExposed {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // NestedObjectInjection - field contains . or [
        if field.contains('.') || field.contains('[') {
            issues.push(MassAssignIssue::NestedObjectInjection {
                path: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // ArrayFieldManipulation - field ends with [] or matches array patterns
        if field.ends_with("[]")
            || ARRAY_FIELDS
                .iter()
                .any(|a| a.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::ArrayFieldManipulation {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // MetadataFieldReflected
        if METADATA_FIELDS
            .iter()
            .any(|m| m.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::MetadataFieldReflected {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // TimestampFieldOverwrite
        if TIMESTAMP_FIELDS
            .iter()
            .any(|t| t.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::TimestampFieldOverwrite {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // StatusFieldManipulation
        if STATUS_FIELDS
            .iter()
            .any(|s| s.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::StatusFieldManipulation {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // PriceFieldReflected
        if PRICE_FIELDS
            .iter()
            .any(|p| p.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::PriceFieldReflected {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // TypeFieldConfusion
        if TYPE_FIELDS
            .iter()
            .any(|t| t.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::TypeFieldConfusion {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
            continue;
        }

        // HiddenFieldAccepted - starts with _ or __ (but not admin/canary fields)
        if (field.starts_with('_') || field.starts_with("__"))
            && !ADMIN_FIELDS
                .iter()
                .any(|a| a.to_ascii_lowercase() == field_lower)
            && !CANARY_FIELDS
                .iter()
                .any(|c| c.to_ascii_lowercase() == field_lower)
        {
            issues.push(MassAssignIssue::HiddenFieldAccepted {
                field: field.to_string(),
                endpoint: endpoint.to_string(),
            });
        }
    }

    issues
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
