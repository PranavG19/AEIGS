use std::collections::{BTreeMap, HashMap, HashSet};

use crate::auth_matrix::PrivilegeLevel;

/// Maximum fields to test per type to avoid combinatorial explosion.
const MAX_FIELDS_PER_TYPE: usize = 256;

/// Maximum nesting depth for nested object authorization probes.
const MAX_NESTING_DEPTH: usize = 8;

/// Maximum connection page size for pagination authorization tests.
const MAX_PAGE_SIZE: usize = 1000;

/// Sensitive field patterns that indicate data requiring authorization checks.
const SENSITIVE_FIELD_PATTERNS: &[&str] = &[
    "password",
    "passwordHash",
    "password_hash",
    "secret",
    "secretKey",
    "secret_key",
    "token",
    "accessToken",
    "access_token",
    "refreshToken",
    "refresh_token",
    "apiKey",
    "api_key",
    "ssn",
    "socialSecurity",
    "social_security",
    "creditCard",
    "credit_card",
    "cardNumber",
    "card_number",
    "cvv",
    "cvc",
    "bankAccount",
    "bank_account",
    "routingNumber",
    "routing_number",
    "salary",
    "compensation",
    "taxId",
    "tax_id",
    "driverLicense",
    "driver_license",
    "medicalRecord",
    "medical_record",
    "diagnosis",
    "prescription",
    "internalNotes",
    "internal_notes",
    "adminNotes",
    "admin_notes",
    "privateKey",
    "private_key",
    "twoFactorSecret",
    "two_factor_secret",
    "totpSeed",
    "totp_seed",
    "encryptionKey",
    "encryption_key",
    "revenue",
    "totalRevenue",
    "total_revenue",
    "profit",
    "margin",
    "costPrice",
    "cost_price",
    "wholesalePrice",
    "wholesale_price",
];

/// Fields that are typically admin-only.
const ADMIN_ONLY_FIELDS: &[&str] = &[
    "isAdmin",
    "is_admin",
    "role",
    "roles",
    "permissions",
    "isBanned",
    "is_banned",
    "isSuspended",
    "is_suspended",
    "deletedAt",
    "deleted_at",
    "lastLoginIp",
    "last_login_ip",
    "loginAttempts",
    "login_attempts",
    "auditLog",
    "audit_log",
    "featureFlags",
    "feature_flags",
    "internalId",
    "internal_id",
    "debugInfo",
    "debug_info",
    "rawData",
    "raw_data",
    "systemMetadata",
    "system_metadata",
    "analyticsData",
    "analytics_data",
    "billingInfo",
    "billing_info",
    "subscriptionDetails",
    "subscription_details",
    "tenantConfig",
    "tenant_config",
];

/// Computed fields that may leak aggregate data to unauthorized roles.
pub(crate) const COMPUTED_FIELD_PATTERNS: &[&str] = &[
    "totalRevenue",
    "total_revenue",
    "totalUsers",
    "total_users",
    "totalOrders",
    "total_orders",
    "averageOrderValue",
    "average_order_value",
    "conversionRate",
    "conversion_rate",
    "churnRate",
    "churn_rate",
    "monthlyRecurringRevenue",
    "mrr",
    "annualRecurringRevenue",
    "arr",
    "lifetimeValue",
    "ltv",
    "customerAcquisitionCost",
    "cac",
    "netPromoterScore",
    "nps",
    "activeSubscriptions",
    "active_subscriptions",
    "dailyActiveUsers",
    "dau",
    "monthlyActiveUsers",
    "mau",
    "serverLoad",
    "server_load",
    "errorRate",
    "error_rate",
    "uptimePercentage",
    "uptime_percentage",
];

// ─── Core Types ──────────────────────────────────────────────────────────────

/// A GraphQL type with its fields for authorization testing.
#[derive(Debug, Clone)]
pub struct GraphQlTypeDefinition {
    /// Type name (e.g., "User", "Order").
    pub name: String,
    /// Fields on this type, with their return type strings.
    pub fields: Vec<GraphQlFieldDefinition>,
}

/// A single field on a GraphQL type.
#[derive(Debug, Clone)]
pub struct GraphQlFieldDefinition {
    /// Field name.
    pub name: String,
    /// Return type (e.g., "String", "CreditCard", "[Order]").
    pub return_type: String,
    /// Arguments this field accepts.
    pub arguments: Vec<(String, String)>,
    /// Whether this field requires specific auth directives.
    pub has_auth_directive: bool,
    /// The auth directive name, if present (e.g., "@auth", "@hasRole").
    pub auth_directive: Option<String>,
}

/// A role used for authorization testing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthRole {
    /// Human label for this role.
    pub label: String,
    /// Privilege level.
    pub privilege_level: PrivilegeLevel,
    /// Bearer token or auth header value (None = unauthenticated).
    pub auth_header: Option<String>,
}

impl AuthRole {
    pub fn unauthenticated() -> Self {
        Self {
            label: "anonymous".to_string(),
            privilege_level: PrivilegeLevel::Unauthenticated,
            auth_header: None,
        }
    }

    pub fn user(token: &str) -> Self {
        Self {
            label: "user".to_string(),
            privilege_level: PrivilegeLevel::User,
            auth_header: Some(format!("Bearer {token}")),
        }
    }

    pub fn admin(token: &str) -> Self {
        Self {
            label: "admin".to_string(),
            privilege_level: PrivilegeLevel::Admin,
            auth_header: Some(format!("Bearer {token}")),
        }
    }
}

/// Result of a single field authorization probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldAuthResult {
    /// Field returned data successfully.
    DataReturned,
    /// Field returned null (may or may not indicate auth enforcement).
    NullReturned,
    /// Server returned an authorization/authentication error.
    AuthError(String),
    /// Server returned a generic error (not clearly auth-related).
    OtherError(String),
    /// Field does not exist on this type.
    FieldNotFound,
}

impl FieldAuthResult {
    /// Whether this result indicates the field returned accessible data.
    pub fn is_accessible(&self) -> bool {
        matches!(self, Self::DataReturned)
    }

    /// Whether this result indicates access was denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::AuthError(_))
    }
}

/// A single cell in the role-based comparison matrix.
#[derive(Debug, Clone)]
pub struct FieldAuthMatrixEntry {
    pub type_name: String,
    pub field_name: String,
    pub role_label: String,
    pub privilege_level: PrivilegeLevel,
    pub result: FieldAuthResult,
}

/// An authorization anomaly detected by comparing field access across roles.
#[derive(Debug, Clone)]
pub struct FieldAuthAnomaly {
    /// Type containing the field.
    pub type_name: String,
    /// Field that has inconsistent authorization.
    pub field_name: String,
    /// The lower-privilege role that gained access.
    pub low_role: String,
    pub low_privilege: PrivilegeLevel,
    /// The higher-privilege role for comparison.
    pub high_role: String,
    pub high_privilege: PrivilegeLevel,
    /// Classification of this anomaly.
    pub pattern: FieldAuthPattern,
    /// Severity (0.0-1.0) based on field sensitivity and privilege gap.
    pub severity: f64,
    /// Human-readable description.
    pub description: String,
}

/// The 10 field authorization test patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldAuthPattern {
    /// Pattern 1: Scalar field accessible to wrong role.
    ScalarFieldExposure,
    /// Pattern 2: Nested object fields accessible through parent query.
    NestedObjectTraversal,
    /// Pattern 3: Connection/edge pagination leaking records.
    ConnectionPaginationLeak,
    /// Pattern 4: Mutation input fields that set privileged values.
    MutationFieldEscalation,
    /// Pattern 5: Computed/aggregate fields leaking business metrics.
    ComputedFieldLeakage,
    /// Pattern 6: @skip/@include directives bypassing auth directives.
    DirectiveAuthBypass,
    /// Pattern 7: Inline fragment type-narrowing to access restricted fields.
    InlineFragmentBypass,
    /// Pattern 8: Field alias used to rename restricted fields past filters.
    FieldAliasBypass,
    /// Pattern 9: Interface/union type revealing fields from restricted types.
    InterfaceUnionLeak,
    /// Pattern 10: Introspection metadata leaking field-level auth info.
    IntrospectionMetadataLeak,
}

impl std::fmt::Display for FieldAuthPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::ScalarFieldExposure => "scalar-field-exposure",
            Self::NestedObjectTraversal => "nested-object-traversal",
            Self::ConnectionPaginationLeak => "connection-pagination-leak",
            Self::MutationFieldEscalation => "mutation-field-escalation",
            Self::ComputedFieldLeakage => "computed-field-leakage",
            Self::DirectiveAuthBypass => "directive-auth-bypass",
            Self::InlineFragmentBypass => "inline-fragment-bypass",
            Self::FieldAliasBypass => "field-alias-bypass",
            Self::InterfaceUnionLeak => "interface-union-leak",
            Self::IntrospectionMetadataLeak => "introspection-metadata-leak",
        };
        write!(f, "{label}")
    }
}

// ─── Pattern 1: Scalar Field Authorization ───────────────────────────────────

/// A probe query for testing scalar field access at a specific role.
#[derive(Debug, Clone)]
pub struct ScalarFieldProbe {
    /// The GraphQL query string.
    pub query: String,
    /// Type being tested.
    pub type_name: String,
    /// Field being tested.
    pub field_name: String,
    /// Role this probe targets.
    pub role: AuthRole,
    /// Whether this field is classified as sensitive.
    pub is_sensitive: bool,
    /// Whether this field is classified as admin-only.
    pub is_admin_only: bool,
}

/// Generate scalar field probes for every field on a type, for each role.
///
/// Produces one query per (field, role) pair. Sensitive and admin-only
/// fields are flagged so anomaly detection can weight severity correctly.
pub fn generate_scalar_field_probes(
    type_def: &GraphQlTypeDefinition,
    roles: &[AuthRole],
    entry_field: &str,
) -> Vec<ScalarFieldProbe> {
    let mut probes = Vec::new();
    let fields = &type_def.fields[..type_def.fields.len().min(MAX_FIELDS_PER_TYPE)];

    for field in fields {
        let is_sensitive = is_sensitive_field(&field.name);
        let is_admin = is_admin_only_field(&field.name);

        for role in roles {
            let query = format!(
                "{{ {entry_field} {{ {field_name} }} }}",
                field_name = field.name
            );
            probes.push(ScalarFieldProbe {
                query,
                type_name: type_def.name.clone(),
                field_name: field.name.clone(),
                role: role.clone(),
                is_sensitive,
                is_admin_only: is_admin,
            });
        }
    }

    probes
}

// ─── Pattern 2: Nested Object Authorization ──────────────────────────────────

/// A probe for testing nested object field traversal authorization.
#[derive(Debug, Clone)]
pub struct NestedObjectProbe {
    /// The GraphQL query string with nested selection.
    pub query: String,
    /// The path traversed (e.g., ["user", "creditCard", "number"]).
    pub field_path: Vec<String>,
    /// Target role for this probe.
    pub role: AuthRole,
    /// Nesting depth.
    pub depth: usize,
}

/// Common nested paths that should require authorization at each level.
pub(crate) const SENSITIVE_NESTED_PATHS: &[&[&str]] = &[
    &["user", "creditCard", "number"],
    &["user", "creditCard", "cvv"],
    &["user", "bankAccount", "accountNumber"],
    &["user", "bankAccount", "routingNumber"],
    &["user", "medicalRecord", "diagnosis"],
    &["user", "paymentMethods", "last4"],
    &["user", "addresses", "full"],
    &["order", "payment", "cardNumber"],
    &["order", "customer", "ssn"],
    &["organization", "billing", "stripeCustomerId"],
    &["team", "members", "salary"],
    &["project", "secrets", "value"],
    &["account", "apiKeys", "secret"],
    &["user", "sessions", "token"],
    &["user", "twoFactor", "secret"],
];

/// Generate nested object authorization probes.
///
/// Builds queries that traverse nested object relationships to test
/// whether authorization is enforced at each level of the object graph.
pub fn generate_nested_object_probes(
    custom_paths: &[Vec<String>],
    roles: &[AuthRole],
) -> Vec<NestedObjectProbe> {
    let mut probes = Vec::new();

    let default_paths: Vec<Vec<String>> = SENSITIVE_NESTED_PATHS
        .iter()
        .map(|path| path.iter().map(|s| s.to_string()).collect())
        .collect();

    let paths = if custom_paths.is_empty() {
        &default_paths
    } else {
        custom_paths
    };

    for path in paths {
        if path.is_empty() || path.len() > MAX_NESTING_DEPTH {
            continue;
        }
        let query = build_nested_query(path);
        for role in roles {
            probes.push(NestedObjectProbe {
                query: query.clone(),
                field_path: path.clone(),
                role: role.clone(),
                depth: path.len(),
            });
        }
    }

    probes
}

/// Build a nested GraphQL query from a field path.
fn build_nested_query(path: &[String]) -> String {
    if path.is_empty() {
        return "{ __typename }".to_string();
    }
    let mut query = path.last().unwrap().clone();
    for field in path.iter().rev().skip(1) {
        query = format!("{field} {{ {query} }}");
    }
    format!("{{ {query} }}")
}

// ─── Pattern 3: Connection/Edge Pagination Authorization ─────────────────────

/// A probe for testing connection-based pagination authorization.
#[derive(Debug, Clone)]
pub struct ConnectionPaginationProbe {
    /// The GraphQL query exercising pagination.
    pub query: String,
    /// The connection field being paginated.
    pub connection_field: String,
    /// Page size requested.
    pub page_size: usize,
    /// Target role.
    pub role: AuthRole,
    /// Pagination technique.
    pub technique: PaginationTechnique,
}

/// Pagination technique for connection authorization testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginationTechnique {
    /// Standard Relay-style first/after cursor pagination.
    RelayCursor,
    /// Offset/limit pagination.
    OffsetLimit,
    /// Requesting all records with a very large page size.
    ExcessivePageSize,
    /// Iterating with `after` cursor to enumerate all pages.
    CursorEnumeration,
    /// Using `last`/`before` for reverse pagination.
    ReversePagination,
}

/// Common connection fields that may require role-based filtering.
pub(crate) const CONNECTION_FIELDS: &[&str] = &[
    "users",
    "orders",
    "transactions",
    "payments",
    "invoices",
    "auditLogs",
    "apiKeys",
    "sessions",
    "teams",
    "organizations",
    "members",
    "employees",
    "customers",
    "subscriptions",
    "tickets",
    "reports",
];

/// Generate connection pagination authorization probes.
///
/// Tests whether a lower-privilege role can paginate through records
/// that should be filtered by ownership or role. Produces standard
/// cursor, offset, excessive page size, and reverse pagination variants.
pub fn generate_connection_pagination_probes(
    custom_fields: &[&str],
    roles: &[AuthRole],
) -> Vec<ConnectionPaginationProbe> {
    let mut probes = Vec::new();

    let fields: Vec<&str> = if custom_fields.is_empty() {
        CONNECTION_FIELDS.to_vec()
    } else {
        custom_fields.to_vec()
    };

    for field in &fields {
        for role in roles {
            probes.push(ConnectionPaginationProbe {
                query: format!(
                    "{{ {field}(first: 10) {{ edges {{ node {{ id }} cursor }} pageInfo {{ hasNextPage endCursor }} totalCount }} }}"
                ),
                connection_field: field.to_string(),
                page_size: 10,
                role: role.clone(),
                technique: PaginationTechnique::RelayCursor,
            });

            probes.push(ConnectionPaginationProbe {
                query: format!("{{ {field}(limit: 50, offset: 0) {{ id }} }}"),
                connection_field: field.to_string(),
                page_size: 50,
                role: role.clone(),
                technique: PaginationTechnique::OffsetLimit,
            });

            probes.push(ConnectionPaginationProbe {
                query: format!(
                    "{{ {field}(first: {MAX_PAGE_SIZE}) {{ edges {{ node {{ id }} }} totalCount }} }}"
                ),
                connection_field: field.to_string(),
                page_size: MAX_PAGE_SIZE,
                role: role.clone(),
                technique: PaginationTechnique::ExcessivePageSize,
            });

            probes.push(ConnectionPaginationProbe {
                query: format!(
                    "{{ {field}(first: 100, after: \"cursor_placeholder\") {{ edges {{ node {{ id }} cursor }} pageInfo {{ hasNextPage endCursor }} }} }}"
                ),
                connection_field: field.to_string(),
                page_size: 100,
                role: role.clone(),
                technique: PaginationTechnique::CursorEnumeration,
            });

            probes.push(ConnectionPaginationProbe {
                query: format!(
                    "{{ {field}(last: 10, before: \"cursor_placeholder\") {{ edges {{ node {{ id }} }} pageInfo {{ hasPreviousPage startCursor }} }} }}"
                ),
                connection_field: field.to_string(),
                page_size: 10,
                role: role.clone(),
                technique: PaginationTechnique::ReversePagination,
            });
        }
    }

    probes
}

// ─── Pattern 4: Mutation Field Escalation ────────────────────────────────────

/// A probe for testing whether mutation input fields allow privilege escalation.
#[derive(Debug, Clone)]
pub struct MutationFieldProbe {
    /// The mutation query with escalation field injected.
    pub query: String,
    /// Mutation name.
    pub mutation_name: String,
    /// Escalation field injected.
    pub escalation_field: String,
    /// Value set for the escalation field.
    pub escalation_value: String,
    /// Target role.
    pub role: AuthRole,
    /// Category of escalation.
    pub category: MutationEscalationCategory,
}

/// Category of mutation field escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationEscalationCategory {
    /// Setting admin/role fields (isAdmin, role).
    RoleEscalation,
    /// Setting ownership fields (ownerId, tenantId).
    OwnershipTampering,
    /// Setting internal fields (internalId, createdAt).
    InternalFieldOverwrite,
    /// Setting financial fields (balance, credits).
    FinancialTampering,
    /// Setting verification fields (emailVerified, isVerified).
    VerificationBypass,
}

/// Escalation field definitions: (field_name, value, category).
pub(crate) const ESCALATION_FIELDS: &[(&str, &str, MutationEscalationCategory)] = &[
    (
        "isAdmin",
        "true",
        MutationEscalationCategory::RoleEscalation,
    ),
    (
        "is_admin",
        "true",
        MutationEscalationCategory::RoleEscalation,
    ),
    (
        "role",
        "\"admin\"",
        MutationEscalationCategory::RoleEscalation,
    ),
    (
        "roles",
        "[\"admin\", \"superuser\"]",
        MutationEscalationCategory::RoleEscalation,
    ),
    (
        "permissions",
        "[\"*\"]",
        MutationEscalationCategory::RoleEscalation,
    ),
    (
        "ownerId",
        "\"attacker-id\"",
        MutationEscalationCategory::OwnershipTampering,
    ),
    (
        "owner_id",
        "\"attacker-id\"",
        MutationEscalationCategory::OwnershipTampering,
    ),
    (
        "tenantId",
        "\"other-tenant\"",
        MutationEscalationCategory::OwnershipTampering,
    ),
    (
        "tenant_id",
        "\"other-tenant\"",
        MutationEscalationCategory::OwnershipTampering,
    ),
    (
        "organizationId",
        "\"other-org\"",
        MutationEscalationCategory::OwnershipTampering,
    ),
    (
        "internalId",
        "\"injected-internal\"",
        MutationEscalationCategory::InternalFieldOverwrite,
    ),
    (
        "createdAt",
        "\"2020-01-01T00:00:00Z\"",
        MutationEscalationCategory::InternalFieldOverwrite,
    ),
    (
        "updatedAt",
        "\"2020-01-01T00:00:00Z\"",
        MutationEscalationCategory::InternalFieldOverwrite,
    ),
    (
        "deletedAt",
        "null",
        MutationEscalationCategory::InternalFieldOverwrite,
    ),
    (
        "balance",
        "999999",
        MutationEscalationCategory::FinancialTampering,
    ),
    (
        "credits",
        "999999",
        MutationEscalationCategory::FinancialTampering,
    ),
    (
        "plan",
        "\"enterprise\"",
        MutationEscalationCategory::FinancialTampering,
    ),
    (
        "emailVerified",
        "true",
        MutationEscalationCategory::VerificationBypass,
    ),
    (
        "email_verified",
        "true",
        MutationEscalationCategory::VerificationBypass,
    ),
    (
        "isVerified",
        "true",
        MutationEscalationCategory::VerificationBypass,
    ),
    (
        "phoneVerified",
        "true",
        MutationEscalationCategory::VerificationBypass,
    ),
];

/// Generate mutation field escalation probes.
///
/// For each mutation and role, injects privileged fields (isAdmin, role,
/// tenantId, balance, etc.) into the mutation input to test whether the
/// server accepts and applies values that should be server-controlled.
pub fn generate_mutation_field_probes(
    mutation_names: &[&str],
    roles: &[AuthRole],
) -> Vec<MutationFieldProbe> {
    let mut probes = Vec::new();

    for mutation in mutation_names {
        for (field, value, category) in ESCALATION_FIELDS {
            for role in roles {
                let query = format!(
                    "mutation {{ {mutation}(input: {{ name: \"test\", {field}: {value} }}) {{ id {field} }} }}"
                );
                probes.push(MutationFieldProbe {
                    query,
                    mutation_name: mutation.to_string(),
                    escalation_field: field.to_string(),
                    escalation_value: value.to_string(),
                    role: role.clone(),
                    category: *category,
                });
            }
        }
    }

    probes
}

// ─── Pattern 5: Computed Field Leakage ───────────────────────────────────────

/// A probe for testing computed/aggregate field access.
#[derive(Debug, Clone)]
pub struct ComputedFieldProbe {
    /// The GraphQL query requesting the computed field.
    pub query: String,
    /// The computed field name.
    pub field_name: String,
    /// Parent type name.
    pub parent_type: String,
    /// Target role.
    pub role: AuthRole,
    /// Whether this field exposes business metrics.
    pub is_business_metric: bool,
}

/// Generate computed field leakage probes.
///
/// Tests whether aggregate/computed fields (totalRevenue, dailyActiveUsers,
/// conversionRate) are accessible to roles that should not see business metrics.
pub fn generate_computed_field_probes(
    parent_type: &str,
    entry_field: &str,
    custom_fields: &[&str],
    roles: &[AuthRole],
) -> Vec<ComputedFieldProbe> {
    let mut probes = Vec::new();

    let fields: Vec<&str> = if custom_fields.is_empty() {
        COMPUTED_FIELD_PATTERNS.to_vec()
    } else {
        custom_fields.to_vec()
    };

    for field in &fields {
        let is_metric = is_computed_business_metric(field);
        for role in roles {
            let query = format!("{{ {entry_field} {{ {field} }} }}");
            probes.push(ComputedFieldProbe {
                query,
                field_name: field.to_string(),
                parent_type: parent_type.to_string(),
                role: role.clone(),
                is_business_metric: is_metric,
            });
        }
    }

    probes
}

// ─── Pattern 6: Directive Auth Bypass ────────────────────────────────────────

/// A probe for testing @skip/@include directive auth bypass.
#[derive(Debug, Clone)]
pub struct DirectiveBypassProbe {
    /// The GraphQL query with the directive bypass attempt.
    pub query: String,
    /// The field targeted for bypass.
    pub target_field: String,
    /// Type containing the field.
    pub type_name: String,
    /// Target role.
    pub role: AuthRole,
    /// The bypass technique.
    pub technique: DirectiveBypassTechnique,
}

/// Technique for directive-based authorization bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectiveBypassTechnique {
    /// @skip(if: false) on an auth-protected field — should the auth still apply?
    SkipFalse,
    /// @include(if: true) on an auth-protected field.
    IncludeTrue,
    /// @skip with a variable set to false at query time.
    SkipVariable,
    /// @include with a variable set to true at query time.
    IncludeVariable,
    /// Combining @skip and @include to create ambiguous resolution.
    CombinedDirectives,
}

/// Generate directive authorization bypass probes.
///
/// Tests whether @skip(if: false) and @include(if: true) can circumvent
/// field-level authorization directives. Some GraphQL implementations
/// evaluate skip/include before auth directives, creating a bypass.
pub fn generate_directive_bypass_probes(
    type_name: &str,
    entry_field: &str,
    protected_fields: &[&str],
    roles: &[AuthRole],
) -> Vec<DirectiveBypassProbe> {
    let mut probes = Vec::new();

    for field in protected_fields {
        for role in roles {
            probes.push(DirectiveBypassProbe {
                query: format!("{{ {entry_field} {{ {field} @skip(if: false) }} }}"),
                target_field: field.to_string(),
                type_name: type_name.to_string(),
                role: role.clone(),
                technique: DirectiveBypassTechnique::SkipFalse,
            });

            probes.push(DirectiveBypassProbe {
                query: format!("{{ {entry_field} {{ {field} @include(if: true) }} }}"),
                target_field: field.to_string(),
                type_name: type_name.to_string(),
                role: role.clone(),
                technique: DirectiveBypassTechnique::IncludeTrue,
            });

            probes.push(DirectiveBypassProbe {
                query: format!(
                    "query($skip: Boolean!) {{ {entry_field} {{ {field} @skip(if: $skip) }} }}"
                ),
                target_field: field.to_string(),
                type_name: type_name.to_string(),
                role: role.clone(),
                technique: DirectiveBypassTechnique::SkipVariable,
            });

            probes.push(DirectiveBypassProbe {
                query: format!(
                    "query($inc: Boolean!) {{ {entry_field} {{ {field} @include(if: $inc) }} }}"
                ),
                target_field: field.to_string(),
                type_name: type_name.to_string(),
                role: role.clone(),
                technique: DirectiveBypassTechnique::IncludeVariable,
            });

            probes.push(DirectiveBypassProbe {
                query: format!(
                    "{{ {entry_field} {{ {field} @skip(if: false) @include(if: true) }} }}"
                ),
                target_field: field.to_string(),
                type_name: type_name.to_string(),
                role: role.clone(),
                technique: DirectiveBypassTechnique::CombinedDirectives,
            });
        }
    }

    probes
}

// ─── Pattern 7: Inline Fragment Bypass ───────────────────────────────────────

/// A probe for testing inline fragment type-narrowing authorization bypass.
#[derive(Debug, Clone)]
pub struct InlineFragmentProbe {
    /// The GraphQL query using inline fragments.
    pub query: String,
    /// The target type used in the inline fragment.
    pub target_type: String,
    /// Fields accessed via the fragment.
    pub fragment_fields: Vec<String>,
    /// Target role.
    pub role: AuthRole,
}

/// Generate inline fragment bypass probes.
///
/// Uses `... on ConcreteType { restrictedField }` to test whether
/// type narrowing via inline fragments can access fields that are
/// restricted on the abstract type but exposed on the concrete type.
pub fn generate_inline_fragment_probes(
    entry_field: &str,
    interface_type: &str,
    concrete_types: &[(&str, &[&str])],
    roles: &[AuthRole],
) -> Vec<InlineFragmentProbe> {
    let mut probes = Vec::new();

    for (concrete_type, fields) in concrete_types {
        let field_selection = fields.join(" ");
        for role in roles {
            let query =
                format!("{{ {entry_field} {{ ... on {concrete_type} {{ {field_selection} }} }} }}");
            probes.push(InlineFragmentProbe {
                query,
                target_type: concrete_type.to_string(),
                fragment_fields: fields.iter().map(|f| f.to_string()).collect(),
                role: role.clone(),
            });
        }
    }

    let _ = interface_type;

    probes
}

// ─── Pattern 8: Field Alias Bypass ───────────────────────────────────────────

/// A probe for testing field alias authorization bypass.
#[derive(Debug, Clone)]
pub struct FieldAliasProbe {
    /// The GraphQL query using field aliases.
    pub query: String,
    /// The restricted field being aliased.
    pub original_field: String,
    /// The alias name used.
    pub alias: String,
    /// Target role.
    pub role: AuthRole,
}

/// Generate field alias bypass probes.
///
/// Some authorization middleware filters based on field names in the
/// query AST. Aliasing a restricted field (`safeField: restrictedField`)
/// may bypass string-based authorization checks.
pub fn generate_field_alias_probes(
    entry_field: &str,
    restricted_fields: &[&str],
    roles: &[AuthRole],
) -> Vec<FieldAliasProbe> {
    let mut probes = Vec::new();

    let alias_prefixes = ["safe", "public", "my", "get", "fetch", "load"];

    for field in restricted_fields {
        for prefix in &alias_prefixes {
            let capitalized = capitalize_first(field);
            let alias = format!("{prefix}{capitalized}");
            for role in roles {
                let query = format!("{{ {entry_field} {{ {alias}: {field} }} }}");
                probes.push(FieldAliasProbe {
                    query,
                    original_field: field.to_string(),
                    alias: alias.clone(),
                    role: role.clone(),
                });
            }
        }
    }

    probes
}

// ─── Pattern 9: Interface/Union Leak ─────────────────────────────────────────

/// A probe for testing interface/union type authorization leaks.
#[derive(Debug, Clone)]
pub struct InterfaceUnionProbe {
    /// The GraphQL query using union/interface resolution.
    pub query: String,
    /// The union or interface type name.
    pub abstract_type: String,
    /// Concrete types queried through the union/interface.
    pub concrete_types: Vec<String>,
    /// Target role.
    pub role: AuthRole,
    /// Probe technique.
    pub technique: InterfaceUnionTechnique,
}

/// Technique for probing interface/union authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceUnionTechnique {
    /// Query __typename to discover available concrete types.
    TypenameDiscovery,
    /// Use inline fragments for each concrete type to access restricted fields.
    ExhaustiveFragments,
    /// Use named fragments spread across concrete types.
    NamedFragmentSpread,
}

/// Generate interface/union authorization leak probes.
///
/// Tests whether querying a union type reveals restricted concrete types
/// or exposes fields from types the role should not access.
pub fn generate_interface_union_probes(
    entry_field: &str,
    abstract_type: &str,
    concrete_types: &[(&str, &[&str])],
    roles: &[AuthRole],
) -> Vec<InterfaceUnionProbe> {
    let mut probes = Vec::new();
    let type_names: Vec<String> = concrete_types.iter().map(|(n, _)| n.to_string()).collect();

    for role in roles {
        probes.push(InterfaceUnionProbe {
            query: format!("{{ {entry_field} {{ __typename }} }}"),
            abstract_type: abstract_type.to_string(),
            concrete_types: type_names.clone(),
            role: role.clone(),
            technique: InterfaceUnionTechnique::TypenameDiscovery,
        });

        let fragments: Vec<String> = concrete_types
            .iter()
            .map(|(t, fields)| {
                let selection = if fields.is_empty() {
                    "id __typename".to_string()
                } else {
                    fields.join(" ")
                };
                format!("... on {t} {{ {selection} }}")
            })
            .collect();
        probes.push(InterfaceUnionProbe {
            query: format!(
                "{{ {entry_field} {{ {fragments} }} }}",
                fragments = fragments.join(" ")
            ),
            abstract_type: abstract_type.to_string(),
            concrete_types: type_names.clone(),
            role: role.clone(),
            technique: InterfaceUnionTechnique::ExhaustiveFragments,
        });

        let mut named_fragments = Vec::new();
        let mut spreads = Vec::new();
        for (i, (t, fields)) in concrete_types.iter().enumerate() {
            let frag_name = format!("F{i}");
            let selection = if fields.is_empty() {
                "id __typename".to_string()
            } else {
                fields.join(" ")
            };
            named_fragments.push(format!("fragment {frag_name} on {t} {{ {selection} }}"));
            spreads.push(format!("...{frag_name}"));
        }
        probes.push(InterfaceUnionProbe {
            query: format!(
                "{{ {entry_field} {{ {spreads} }} }}\n{fragments}",
                spreads = spreads.join(" "),
                fragments = named_fragments.join("\n")
            ),
            abstract_type: abstract_type.to_string(),
            concrete_types: type_names.clone(),
            role: role.clone(),
            technique: InterfaceUnionTechnique::NamedFragmentSpread,
        });
    }

    probes
}

// ─── Pattern 10: Introspection Metadata Leak ─────────────────────────────────

/// A probe for testing whether introspection reveals authorization metadata.
#[derive(Debug, Clone)]
pub struct IntrospectionMetadataProbe {
    /// The introspection query string.
    pub query: String,
    /// Target type to inspect.
    pub target_type: String,
    /// Target role.
    pub role: AuthRole,
    /// What metadata this probe looks for.
    pub metadata_target: IntrospectionTarget,
}

/// What introspection metadata is being probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntrospectionTarget {
    /// Field-level descriptions that mention authorization requirements.
    FieldDescriptions,
    /// Directive definitions that reveal auth directive parameters.
    AuthDirectives,
    /// Deprecated fields that may still be accessible.
    DeprecatedFields,
    /// Argument defaults that reveal internal authorization logic.
    ArgumentDefaults,
}

/// Generate introspection metadata leak probes.
///
/// Queries __type and __schema to extract field descriptions, directive
/// definitions, and deprecated markers that may reveal authorization
/// boundaries to unauthorized roles.
pub fn generate_introspection_metadata_probes(
    type_names: &[&str],
    roles: &[AuthRole],
) -> Vec<IntrospectionMetadataProbe> {
    let mut probes = Vec::new();

    for type_name in type_names {
        for role in roles {
            probes.push(IntrospectionMetadataProbe {
                query: format!(
                    "{{ __type(name: \"{type_name}\") {{ name fields {{ name description type {{ name }} }} }} }}"
                ),
                target_type: type_name.to_string(),
                role: role.clone(),
                metadata_target: IntrospectionTarget::FieldDescriptions,
            });

            probes.push(IntrospectionMetadataProbe {
                query: "{ __schema { directives { name description args { name defaultValue } locations } } }".to_string(),
                target_type: type_name.to_string(),
                role: role.clone(),
                metadata_target: IntrospectionTarget::AuthDirectives,
            });

            probes.push(IntrospectionMetadataProbe {
                query: format!(
                    "{{ __type(name: \"{type_name}\") {{ fields(includeDeprecated: true) {{ name isDeprecated deprecationReason }} }} }}"
                ),
                target_type: type_name.to_string(),
                role: role.clone(),
                metadata_target: IntrospectionTarget::DeprecatedFields,
            });

            probes.push(IntrospectionMetadataProbe {
                query: format!(
                    "{{ __type(name: \"{type_name}\") {{ fields {{ name args {{ name defaultValue description }} }} }} }}"
                ),
                target_type: type_name.to_string(),
                role: role.clone(),
                metadata_target: IntrospectionTarget::ArgumentDefaults,
            });
        }
    }

    probes
}

// ─── Role-Based Comparison Matrix ────────────────────────────────────────────

/// The full role-based field authorization comparison matrix.
#[derive(Debug)]
pub struct FieldAuthMatrix {
    entries: Vec<FieldAuthMatrixEntry>,
    roles: Vec<AuthRole>,
}

impl FieldAuthMatrix {
    pub fn new(roles: Vec<AuthRole>) -> Self {
        Self {
            entries: Vec::new(),
            roles,
        }
    }

    /// Record a field authorization result for a specific role.
    pub fn record(&mut self, entry: FieldAuthMatrixEntry) {
        self.entries.push(entry);
    }

    /// Record multiple entries at once.
    pub fn record_batch(&mut self, entries: Vec<FieldAuthMatrixEntry>) {
        self.entries.extend(entries);
    }

    /// Get all entries for a specific type and field.
    pub fn entries_for_field(
        &self,
        type_name: &str,
        field_name: &str,
    ) -> Vec<&FieldAuthMatrixEntry> {
        self.entries
            .iter()
            .filter(|e| e.type_name == type_name && e.field_name == field_name)
            .collect()
    }

    /// Get the result for a specific (type, field, role) triple.
    pub fn result_for(
        &self,
        type_name: &str,
        field_name: &str,
        role_label: &str,
    ) -> Option<&FieldAuthResult> {
        self.entries
            .iter()
            .find(|e| {
                e.type_name == type_name && e.field_name == field_name && e.role_label == role_label
            })
            .map(|e| &e.result)
    }

    /// Build a tabular view: (type, field) → {role → result}.
    pub fn build_table(&self) -> BTreeMap<(String, String), BTreeMap<String, FieldAuthResult>> {
        let mut table: BTreeMap<(String, String), BTreeMap<String, FieldAuthResult>> =
            BTreeMap::new();
        for entry in &self.entries {
            table
                .entry((entry.type_name.clone(), entry.field_name.clone()))
                .or_default()
                .insert(entry.role_label.clone(), entry.result.clone());
        }
        table
    }

    pub fn roles(&self) -> &[AuthRole] {
        &self.roles
    }

    pub fn entries(&self) -> &[FieldAuthMatrixEntry] {
        &self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Detect authorization anomalies by comparing access across privilege levels.
    ///
    /// An anomaly occurs when a lower-privilege role can access a field
    /// that a higher-privilege role also accesses, but the field is
    /// classified as sensitive, admin-only, or computed.
    pub fn detect_anomalies(&self) -> Vec<FieldAuthAnomaly> {
        let mut anomalies = Vec::new();
        let table = self.build_table();

        let role_map: HashMap<&str, &AuthRole> =
            self.roles.iter().map(|r| (r.label.as_str(), r)).collect();

        for ((type_name, field_name), role_results) in &table {
            for (low_label, low_result) in role_results {
                let Some(low_role) = role_map.get(low_label.as_str()) else {
                    continue;
                };
                if !low_result.is_accessible() {
                    continue;
                }

                for (high_label, high_result) in role_results {
                    let Some(high_role) = role_map.get(high_label.as_str()) else {
                        continue;
                    };
                    if low_role.privilege_level >= high_role.privilege_level {
                        continue;
                    }
                    if !high_result.is_accessible() {
                        continue;
                    }

                    let pattern = classify_field_anomaly(field_name);
                    let severity = compute_severity(
                        field_name,
                        low_role.privilege_level,
                        high_role.privilege_level,
                    );

                    let description = format!(
                        "{type_name}.{field_name} accessible to {low_label} ({}) — expected {} or higher",
                        low_role.privilege_level, high_role.privilege_level
                    );

                    anomalies.push(FieldAuthAnomaly {
                        type_name: type_name.clone(),
                        field_name: field_name.clone(),
                        low_role: low_label.clone(),
                        low_privilege: low_role.privilege_level,
                        high_role: high_label.clone(),
                        high_privilege: high_role.privilege_level,
                        pattern,
                        severity,
                        description,
                    });
                }
            }
        }

        anomalies
    }

    /// Count unique (type, field) pairs in the matrix.
    pub fn field_count(&self) -> usize {
        let unique: HashSet<(&str, &str)> = self
            .entries
            .iter()
            .map(|e| (e.type_name.as_str(), e.field_name.as_str()))
            .collect();
        unique.len()
    }
}

// ─── Aggregate Engine ────────────────────────────────────────────────────────

/// Configuration for the field authorization test engine.
#[derive(Debug, Clone)]
pub struct FieldAuthConfig {
    /// Roles to test.
    pub roles: Vec<AuthRole>,
    /// Enable scalar field probing (Pattern 1).
    pub enable_scalar: bool,
    /// Enable nested object traversal (Pattern 2).
    pub enable_nested: bool,
    /// Enable connection pagination (Pattern 3).
    pub enable_connection: bool,
    /// Enable mutation field escalation (Pattern 4).
    pub enable_mutation: bool,
    /// Enable computed field leakage (Pattern 5).
    pub enable_computed: bool,
    /// Enable directive bypass (Pattern 6).
    pub enable_directive: bool,
    /// Enable inline fragment bypass (Pattern 7).
    pub enable_inline_fragment: bool,
    /// Enable field alias bypass (Pattern 8).
    pub enable_alias: bool,
    /// Enable interface/union leak (Pattern 9).
    pub enable_interface_union: bool,
    /// Enable introspection metadata leak (Pattern 10).
    pub enable_introspection: bool,
}

impl Default for FieldAuthConfig {
    fn default() -> Self {
        Self {
            roles: vec![
                AuthRole::unauthenticated(),
                AuthRole::user("user-token"),
                AuthRole::admin("admin-token"),
            ],
            enable_scalar: true,
            enable_nested: true,
            enable_connection: true,
            enable_mutation: true,
            enable_computed: true,
            enable_directive: true,
            enable_inline_fragment: true,
            enable_alias: true,
            enable_interface_union: true,
            enable_introspection: true,
        }
    }
}

/// Full result from the field authorization test engine.
#[derive(Debug)]
pub struct FieldAuthTestSuite {
    /// Scalar field probes (Pattern 1).
    pub scalar_probes: Vec<ScalarFieldProbe>,
    /// Nested object probes (Pattern 2).
    pub nested_probes: Vec<NestedObjectProbe>,
    /// Connection pagination probes (Pattern 3).
    pub connection_probes: Vec<ConnectionPaginationProbe>,
    /// Mutation field escalation probes (Pattern 4).
    pub mutation_probes: Vec<MutationFieldProbe>,
    /// Computed field leakage probes (Pattern 5).
    pub computed_probes: Vec<ComputedFieldProbe>,
    /// Directive bypass probes (Pattern 6).
    pub directive_probes: Vec<DirectiveBypassProbe>,
    /// Inline fragment probes (Pattern 7).
    pub inline_fragment_probes: Vec<InlineFragmentProbe>,
    /// Field alias probes (Pattern 8).
    pub alias_probes: Vec<FieldAliasProbe>,
    /// Interface/union probes (Pattern 9).
    pub interface_union_probes: Vec<InterfaceUnionProbe>,
    /// Introspection metadata probes (Pattern 10).
    pub introspection_probes: Vec<IntrospectionMetadataProbe>,
    /// Total probe count.
    pub total_probe_count: usize,
}

/// Union type definition for field auth testing: (entry_field, interface_name, concrete_types).
pub type UnionTypeSpec<'a> = (&'a str, &'a str, &'a [(&'a str, &'a [&'a str])]);

/// Run the full field authorization test engine.
///
/// Generates probes for all 10 field authorization patterns. This is a
/// probe generation engine — no network requests are made. The caller
/// sends generated probes, collects responses, and feeds them into a
/// `FieldAuthMatrix` for anomaly detection.
pub fn run_field_auth_engine(
    config: &FieldAuthConfig,
    type_defs: &[GraphQlTypeDefinition],
    mutation_names: &[&str],
    protected_fields: &[&str],
    connection_fields: &[&str],
    union_types: &[UnionTypeSpec<'_>],
) -> FieldAuthTestSuite {
    let roles = &config.roles;

    let scalar_probes = if config.enable_scalar {
        type_defs
            .iter()
            .flat_map(|td| {
                let entry = td.name[..1].to_lowercase() + &td.name[1..];
                generate_scalar_field_probes(td, roles, &entry)
            })
            .collect()
    } else {
        Vec::new()
    };

    let nested_probes = if config.enable_nested {
        generate_nested_object_probes(&[], roles)
    } else {
        Vec::new()
    };

    let connection_probes = if config.enable_connection {
        generate_connection_pagination_probes(connection_fields, roles)
    } else {
        Vec::new()
    };

    let mutation_probes = if config.enable_mutation {
        generate_mutation_field_probes(mutation_names, roles)
    } else {
        Vec::new()
    };

    let computed_probes = if config.enable_computed {
        type_defs
            .iter()
            .flat_map(|td| {
                let entry = td.name[..1].to_lowercase() + &td.name[1..];
                generate_computed_field_probes(&td.name, &entry, &[], roles)
            })
            .collect()
    } else {
        Vec::new()
    };

    let directive_probes = if config.enable_directive && !protected_fields.is_empty() {
        type_defs
            .iter()
            .flat_map(|td| {
                let entry = td.name[..1].to_lowercase() + &td.name[1..];
                generate_directive_bypass_probes(&td.name, &entry, protected_fields, roles)
            })
            .collect()
    } else {
        Vec::new()
    };

    let inline_fragment_probes = if config.enable_inline_fragment {
        union_types
            .iter()
            .flat_map(|(entry, iface, concretes)| {
                generate_inline_fragment_probes(entry, iface, concretes, roles)
            })
            .collect()
    } else {
        Vec::new()
    };

    let alias_probes = if config.enable_alias && !protected_fields.is_empty() {
        type_defs
            .iter()
            .flat_map(|td| {
                let entry = td.name[..1].to_lowercase() + &td.name[1..];
                generate_field_alias_probes(&entry, protected_fields, roles)
            })
            .collect()
    } else {
        Vec::new()
    };

    let interface_union_probes = if config.enable_interface_union {
        union_types
            .iter()
            .flat_map(|(entry, iface, concretes)| {
                generate_interface_union_probes(entry, iface, concretes, roles)
            })
            .collect()
    } else {
        Vec::new()
    };

    let introspection_probes = if config.enable_introspection {
        let type_names: Vec<&str> = type_defs.iter().map(|td| td.name.as_str()).collect();
        generate_introspection_metadata_probes(&type_names, roles)
    } else {
        Vec::new()
    };

    let total_probe_count = scalar_probes.len()
        + nested_probes.len()
        + connection_probes.len()
        + mutation_probes.len()
        + computed_probes.len()
        + directive_probes.len()
        + inline_fragment_probes.len()
        + alias_probes.len()
        + interface_union_probes.len()
        + introspection_probes.len();

    FieldAuthTestSuite {
        scalar_probes,
        nested_probes,
        connection_probes,
        mutation_probes,
        computed_probes,
        directive_probes,
        inline_fragment_probes,
        alias_probes,
        interface_union_probes,
        introspection_probes,
        total_probe_count,
    }
}

// ─── Response Analysis ───────────────────────────────────────────────────────

/// Parse a GraphQL response to determine the field authorization result.
///
/// Inspects the JSON response for data presence, null values, and error
/// messages to classify the result as accessible, denied, or errored.
pub fn classify_response(response_json: &str, field_name: &str) -> FieldAuthResult {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(response_json) else {
        return FieldAuthResult::OtherError("invalid JSON".to_string());
    };

    if let Some(errors) = value.get("errors").and_then(|e| e.as_array()) {
        for error in errors {
            let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("");
            let lower = msg.to_lowercase();
            if lower.contains("unauthorized")
                || lower.contains("forbidden")
                || lower.contains("not authenticated")
                || lower.contains("access denied")
                || lower.contains("permission denied")
                || lower.contains("not authorized")
                || lower.contains("authentication required")
            {
                return FieldAuthResult::AuthError(msg.to_string());
            }

            if lower.contains("cannot query field") && lower.contains(&field_name.to_lowercase()) {
                return FieldAuthResult::FieldNotFound;
            }
        }

        let has_data = value.get("data").is_some_and(|d| !d.is_null());
        if !has_data {
            let msg = errors
                .first()
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return FieldAuthResult::OtherError(msg);
        }
    }

    if let Some(data) = value.get("data") {
        if data.is_null() {
            return FieldAuthResult::NullReturned;
        }
        if contains_non_null_field(data, field_name) {
            return FieldAuthResult::DataReturned;
        }
        if contains_null_field(data, field_name) {
            return FieldAuthResult::NullReturned;
        }
        return FieldAuthResult::DataReturned;
    }

    FieldAuthResult::OtherError("no data or errors in response".to_string())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_FIELD_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
}

fn is_admin_only_field(name: &str) -> bool {
    ADMIN_ONLY_FIELDS.contains(&name)
}

fn is_computed_business_metric(name: &str) -> bool {
    COMPUTED_FIELD_PATTERNS.contains(&name)
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

fn contains_non_null_field(value: &serde_json::Value, field_name: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(field_name) {
                return !v.is_null();
            }
            map.values().any(|v| contains_non_null_field(v, field_name))
        }
        serde_json::Value::Array(arr) => arr.iter().any(|v| contains_non_null_field(v, field_name)),
        _ => false,
    }
}

fn contains_null_field(value: &serde_json::Value, field_name: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(field_name) {
                return v.is_null();
            }
            map.values().any(|v| contains_null_field(v, field_name))
        }
        serde_json::Value::Array(arr) => arr.iter().any(|v| contains_null_field(v, field_name)),
        _ => false,
    }
}

fn classify_field_anomaly(field_name: &str) -> FieldAuthPattern {
    if is_computed_business_metric(field_name) {
        FieldAuthPattern::ComputedFieldLeakage
    } else {
        FieldAuthPattern::ScalarFieldExposure
    }
}

fn compute_severity(field_name: &str, low: PrivilegeLevel, high: PrivilegeLevel) -> f64 {
    let base: f64 = if is_sensitive_field(field_name) {
        0.9
    } else if is_admin_only_field(field_name) {
        0.8
    } else if is_computed_business_metric(field_name) {
        0.7
    } else {
        0.5
    };

    let gap_bonus: f64 = match (low, high) {
        (PrivilegeLevel::Unauthenticated, PrivilegeLevel::Admin) => 0.1,
        (PrivilegeLevel::Unauthenticated, _) => 0.08,
        (PrivilegeLevel::User, PrivilegeLevel::Admin) => 0.05,
        _ => 0.0,
    };

    (base + gap_bonus).min(1.0)
}

/// Parse a GraphQL introspection response to extract type definitions.
///
/// Converts __type introspection results into `GraphQlTypeDefinition` structs
/// suitable for feeding into the field auth engine.
pub fn parse_introspection_types(introspection_json: &str) -> Vec<GraphQlTypeDefinition> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(introspection_json) else {
        return Vec::new();
    };

    let Some(types) = value
        .pointer("/data/__schema/types")
        .and_then(|t| t.as_array())
    else {
        return Vec::new();
    };

    let mut defs = Vec::new();

    for type_val in types {
        let Some(name) = type_val.get("name").and_then(|n| n.as_str()) else {
            continue;
        };

        if name.starts_with("__") {
            continue;
        }

        let kind = type_val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if kind != "OBJECT" {
            continue;
        }

        let fields = type_val
            .get("fields")
            .and_then(|f| f.as_array())
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|field| {
                        let fname = field.get("name")?.as_str()?;
                        let ftype = extract_type_name(field.get("type")?);
                        let args = field
                            .get("args")
                            .and_then(|a| a.as_array())
                            .map(|args| {
                                args.iter()
                                    .filter_map(|arg| {
                                        let aname = arg.get("name")?.as_str()?.to_string();
                                        let atype = extract_type_name(arg.get("type")?);
                                        Some((aname, atype))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let desc = field
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("");
                        let has_auth = desc.to_lowercase().contains("auth")
                            || desc.to_lowercase().contains("admin")
                            || desc.to_lowercase().contains("permission");
                        Some(GraphQlFieldDefinition {
                            name: fname.to_string(),
                            return_type: ftype,
                            arguments: args,
                            has_auth_directive: has_auth,
                            auth_directive: if has_auth {
                                Some("@auth".to_string())
                            } else {
                                None
                            },
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        defs.push(GraphQlTypeDefinition {
            name: name.to_string(),
            fields,
        });
    }

    defs
}

fn extract_type_name(type_val: &serde_json::Value) -> String {
    if let Some(name) = type_val.get("name").and_then(|n| n.as_str()) {
        return name.to_string();
    }
    if let Some(of_type) = type_val.get("ofType") {
        let inner = extract_type_name(of_type);
        let kind = type_val.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        return match kind {
            "NON_NULL" => format!("{inner}!"),
            "LIST" => format!("[{inner}]"),
            _ => inner,
        };
    }
    "Unknown".to_string()
}
