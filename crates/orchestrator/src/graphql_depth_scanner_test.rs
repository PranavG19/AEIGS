use crate::graphql_depth_scanner::*;

// --- analyze_graphql_depth: individual variant detection ---

#[test]
fn empty_body_returns_empty() {
    let issues = analyze_graphql_depth("");
    assert!(issues.is_empty());
}

#[test]
fn non_graphql_body_returns_empty() {
    let body = "<html><head><title>Test</title></head><body>Hello</body></html>";
    let issues = analyze_graphql_depth(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_unlimited_query_depth() {
    let body = r#"{"data": {"graphql": true, "endpoint": "/graphql"}}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::UnlimitedQueryDepth));
}

#[test]
fn depth_limit_present_suppresses_issue() {
    let body = r#"{"graphql": true, "depthLimit": 10, "complexity": 100, "rateLimit": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(!issues.contains(&GraphqlDepthIssue::UnlimitedQueryDepth));
}

#[test]
fn max_depth_present_suppresses_issue() {
    let body = r#"{"graphql": true, "maxDepth": 5, "complexity": 50, "rateLimit": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(!issues.contains(&GraphqlDepthIssue::UnlimitedQueryDepth));
}

#[test]
fn detects_batching_enabled() {
    let body = r#"[{"query": "{ users { id } }"}, {"query": "{ posts { id } }"}] graphql batch"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::BatchingEnabled));
}

#[test]
fn detects_introspection_enabled() {
    let body = r#"{"data": {"__schema": {"types": []}}, "graphql": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::IntrospectionEnabled));
}

#[test]
fn detects_introspection_via_type() {
    let body = r#"{"data": {"__type": {"name": "User"}}, "graphql": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::IntrospectionEnabled));
}

#[test]
fn detects_field_suggestions_enabled() {
    let body = r#"{"errors": [{"message": "Did you mean 'username'?"}], "graphql": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::FieldSuggestionsEnabled));
}

#[test]
fn detects_no_complexity_limit() {
    let body = r#"{"graphql": true, "depthLimit": 10, "x-ratelimit": "100"}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::NoComplexityLimit));
}

#[test]
fn complexity_present_suppresses_issue() {
    let body = r#"{"graphql": true, "complexity": 1000, "rateLimit": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(!issues.contains(&GraphqlDepthIssue::NoComplexityLimit));
}

#[test]
fn detects_debug_mode_enabled() {
    let body = r#"{"errors": [{"message": "Internal Server Error", "stacktrace": "at resolver.js:42"}], "graphql": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::DebugModeEnabled));
}

#[test]
fn detects_debug_mode_via_debug_flag() {
    let body = r#"{"graphql": true, "extensions": {"tracing": {"version": 1}}, "debug": true}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::DebugModeEnabled));
}

#[test]
fn detects_no_rate_limit() {
    let body = r#"{"graphql": true, "depthLimit": 10, "complexity": 100}"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::NoRateLimit));
}

#[test]
fn rate_limit_present_suppresses_issue() {
    let body = r#"{"graphql": true, "x-ratelimit": "100/hour"}"#;
    let issues = analyze_graphql_depth(body);
    assert!(!issues.contains(&GraphqlDepthIssue::NoRateLimit));
}

#[test]
fn detects_playground_exposed() {
    let body = r#"<html><title>GraphQL Playground</title><body>graphql</body></html>"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::PlaygroundExposed));
}

#[test]
fn detects_graphiql_exposed() {
    let body = r#"<html><title>GraphiQL</title><body>graphql explorer</body></html>"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::PlaygroundExposed));
}

#[test]
fn detects_altair_exposed() {
    let body = r#"<html><title>Altair GraphQL Client</title><body>graphql</body></html>"#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::PlaygroundExposed));
}

// --- Display tests ---

#[test]
fn display_depth_variants() {
    assert_eq!(
        GraphqlDepthIssue::UnlimitedQueryDepth.to_string(),
        "unlimited_query_depth"
    );
    assert_eq!(
        GraphqlDepthIssue::BatchingEnabled.to_string(),
        "batching_enabled"
    );
    assert_eq!(
        GraphqlDepthIssue::IntrospectionEnabled.to_string(),
        "introspection_enabled"
    );
    assert_eq!(
        GraphqlDepthIssue::FieldSuggestionsEnabled.to_string(),
        "field_suggestions_enabled"
    );
    assert_eq!(
        GraphqlDepthIssue::NoComplexityLimit.to_string(),
        "no_complexity_limit"
    );
    assert_eq!(
        GraphqlDepthIssue::DebugModeEnabled.to_string(),
        "debug_mode_enabled"
    );
    assert_eq!(GraphqlDepthIssue::NoRateLimit.to_string(), "no_rate_limit");
    assert_eq!(
        GraphqlDepthIssue::PlaygroundExposed.to_string(),
        "playground_exposed"
    );
}

// --- Severity tests ---

#[test]
fn severity_introspection_highest() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::IntrospectionEnabled),
        7.5
    );
}

#[test]
fn severity_unlimited_depth() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::UnlimitedQueryDepth),
        7.0
    );
}

#[test]
fn severity_no_complexity() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::NoComplexityLimit),
        6.5
    );
}

#[test]
fn severity_batching() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::BatchingEnabled),
        6.5
    );
}

#[test]
fn severity_debug_mode() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::DebugModeEnabled),
        6.0
    );
}

#[test]
fn severity_field_suggestions() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::FieldSuggestionsEnabled),
        5.5
    );
}

#[test]
fn severity_playground() {
    assert_eq!(
        graphql_depth_severity(&GraphqlDepthIssue::PlaygroundExposed),
        5.0
    );
}

#[test]
fn severity_no_rate_limit() {
    assert_eq!(graphql_depth_severity(&GraphqlDepthIssue::NoRateLimit), 5.0);
}

#[test]
fn severity_ordering_complete() {
    let ordered = vec![
        GraphqlDepthIssue::IntrospectionEnabled,
        GraphqlDepthIssue::UnlimitedQueryDepth,
        GraphqlDepthIssue::NoComplexityLimit,
        GraphqlDepthIssue::BatchingEnabled,
        GraphqlDepthIssue::DebugModeEnabled,
        GraphqlDepthIssue::FieldSuggestionsEnabled,
        GraphqlDepthIssue::PlaygroundExposed,
        GraphqlDepthIssue::NoRateLimit,
    ];
    for window in ordered.windows(2) {
        assert!(
            graphql_depth_severity(&window[0]) >= graphql_depth_severity(&window[1]),
            "{} ({}) should be >= {} ({})",
            window[0],
            graphql_depth_severity(&window[0]),
            window[1],
            graphql_depth_severity(&window[1])
        );
    }
}

// --- Operations tests ---

#[test]
fn depth_to_operations_creates_entries() {
    let issues = vec![
        GraphqlDepthIssue::UnlimitedQueryDepth,
        GraphqlDepthIssue::IntrospectionEnabled,
    ];
    let mut seq = 0;
    let ops = graphql_depth_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn depth_to_operations_empty() {
    let mut seq = 5;
    let ops = graphql_depth_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn depth_to_operations_vuln_class() {
    let issues = vec![GraphqlDepthIssue::IntrospectionEnabled];
    let mut seq = 0;
    let ops = graphql_depth_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn depth_to_operations_sequence_increments() {
    let issues = vec![
        GraphqlDepthIssue::UnlimitedQueryDepth,
        GraphqlDepthIssue::BatchingEnabled,
        GraphqlDepthIssue::IntrospectionEnabled,
    ];
    let mut seq = 10;
    let ops = graphql_depth_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn depth_to_operations_severity_matches() {
    let issues = vec![GraphqlDepthIssue::IntrospectionEnabled];
    let mut seq = 0;
    let ops = graphql_depth_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 7.5);
        }
        _ => panic!("expected AddFinding"),
    }
}

// --- scan_graphql_depth localhost guard ---

#[test]
fn scan_skips_localhost() {
    let findings = scan_graphql_depth("http://localhost:4000/graphql");
    assert!(findings.is_empty());
}

#[test]
fn scan_skips_loopback() {
    let findings = scan_graphql_depth("http://127.0.0.1:4000/graphql");
    assert!(findings.is_empty());
}

#[test]
fn scan_skips_invalid() {
    let findings = scan_graphql_depth("not-a-url");
    assert!(findings.is_empty());
}

// --- analyze_graphql_security: individual variant detection ---

#[test]
fn security_empty_body_returns_empty() {
    let issues = analyze_graphql_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_non_graphql_body_returns_empty() {
    let body = "<html><body>Normal page</body></html>";
    let issues = analyze_graphql_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_detects_graphql_injection() {
    let body = r#"
        const query = "query { user(id: " + userInput + ") { name } }";
        fetch('/graphql', { body: query });
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::GraphqlInjection));
}

#[test]
fn security_detects_graphql_injection_template() {
    let body = r#"
        const query = `query { user(id: ${userId}) { name } }`;
        fetch('/graphql', { body: query });
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::GraphqlInjection));
}

#[test]
fn security_detects_graphql_exfiltration() {
    let body = r#"
        query {
            users {
                edges {
                    node {
                        email
                        ssn
                    }
                }
            }
        }
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::GraphqlExfiltration));
}

#[test]
fn security_detects_graphql_dos() {
    let body = r#"
        query {
            posts {
                ... on Post {
                    comments {
                        recursive nested depth query
                    }
                }
            }
        }
        graphql endpoint
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::GraphqlDos));
}

#[test]
fn security_detects_graphql_auth_bypass() {
    let body = r#"
        mutation {
            deleteUser(id: "123") {
                success
            }
        }
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::GraphqlAuthBypass));
}

#[test]
fn security_auth_bypass_suppressed_with_authorization() {
    let body = r#"
        mutation {
            deleteUser(id: "123") {
                success
            }
        }
        headers: { "Authorization": "Bearer token" }
    "#;
    let issues = analyze_graphql_security(body);
    assert!(!issues.contains(&GraphqlSecurityIssue::GraphqlAuthBypass));
}

#[test]
fn security_detects_subscription_abuse() {
    let body = r#"
        subscription {
            newMessage {
                content
            }
        }
        ws://example.com/graphql
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::SubscriptionAbuse));
}

#[test]
fn security_detects_fragment_spread() {
    let body = r#"
        query {
            ...UserFields
        }
        fragment UserFields on User {
            name
            friends {
                ...UserFields
            }
        }
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::FragmentSpread));
}

#[test]
fn security_detects_alias_abuse() {
    let body = r#"
        query {
            a1: user(id: "1") { name }
            a2: user(id: "2") { name }
            alias a3: user(id: "3") { name }
        }
        graphql endpoint
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::AliasAbuse));
}

#[test]
fn security_detects_directive_overload() {
    let body = r#"
        query {
            user @directive(if: true) {
                name
            }
        }
        graphql schema directive
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::DirectiveOverload));
}

#[test]
fn security_detects_persisted_query_bypass() {
    let body = r#"
        {
            "query": "{ user { id } }",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "abc123"
                }
            }
        }
        graphql endpoint
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::PersistedQueryBypass));
}

#[test]
fn security_detects_schema_stitching_leak() {
    let body = r#"
        query {
            _service {
                sdl
            }
            _entities(representations: []) {
                ... on User { id }
            }
        }
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::SchemaStitchingLeak));
}

// --- Security Display tests ---

#[test]
fn security_display_variants() {
    assert_eq!(
        GraphqlSecurityIssue::GraphqlInjection.to_string(),
        "graphql_injection"
    );
    assert_eq!(
        GraphqlSecurityIssue::GraphqlExfiltration.to_string(),
        "graphql_exfiltration"
    );
    assert_eq!(GraphqlSecurityIssue::GraphqlDos.to_string(), "graphql_dos");
    assert_eq!(
        GraphqlSecurityIssue::GraphqlAuthBypass.to_string(),
        "graphql_auth_bypass"
    );
    assert_eq!(
        GraphqlSecurityIssue::SubscriptionAbuse.to_string(),
        "subscription_abuse"
    );
    assert_eq!(
        GraphqlSecurityIssue::FragmentSpread.to_string(),
        "fragment_spread"
    );
    assert_eq!(GraphqlSecurityIssue::AliasAbuse.to_string(), "alias_abuse");
    assert_eq!(
        GraphqlSecurityIssue::DirectiveOverload.to_string(),
        "directive_overload"
    );
    assert_eq!(
        GraphqlSecurityIssue::PersistedQueryBypass.to_string(),
        "persisted_query_bypass"
    );
    assert_eq!(
        GraphqlSecurityIssue::SchemaStitchingLeak.to_string(),
        "schema_stitching_leak"
    );
}

// --- Security Severity tests ---

#[test]
fn security_severity_injection() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::GraphqlInjection),
        8.5
    );
}

#[test]
fn security_severity_auth_bypass() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::GraphqlAuthBypass),
        8.0
    );
}

#[test]
fn security_severity_exfiltration() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::GraphqlExfiltration),
        7.5
    );
}

#[test]
fn security_severity_dos() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::GraphqlDos),
        7.0
    );
}

#[test]
fn security_severity_schema_stitching() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::SchemaStitchingLeak),
        7.0
    );
}

#[test]
fn security_severity_subscription_abuse() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::SubscriptionAbuse),
        6.5
    );
}

#[test]
fn security_severity_alias_abuse() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::AliasAbuse),
        6.0
    );
}

#[test]
fn security_severity_fragment_spread() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::FragmentSpread),
        6.0
    );
}

#[test]
fn security_severity_directive_overload() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::DirectiveOverload),
        5.5
    );
}

#[test]
fn security_severity_persisted_query_bypass() {
    assert_eq!(
        graphql_security_severity(&GraphqlSecurityIssue::PersistedQueryBypass),
        5.5
    );
}

#[test]
fn security_severity_ordering_complete() {
    let ordered = vec![
        GraphqlSecurityIssue::GraphqlInjection,
        GraphqlSecurityIssue::GraphqlAuthBypass,
        GraphqlSecurityIssue::GraphqlExfiltration,
        GraphqlSecurityIssue::SchemaStitchingLeak,
        GraphqlSecurityIssue::GraphqlDos,
        GraphqlSecurityIssue::SubscriptionAbuse,
        GraphqlSecurityIssue::AliasAbuse,
        GraphqlSecurityIssue::FragmentSpread,
        GraphqlSecurityIssue::DirectiveOverload,
        GraphqlSecurityIssue::PersistedQueryBypass,
    ];
    for window in ordered.windows(2) {
        assert!(
            graphql_security_severity(&window[0]) >= graphql_security_severity(&window[1]),
            "{} ({}) should be >= {} ({})",
            window[0],
            graphql_security_severity(&window[0]),
            window[1],
            graphql_security_severity(&window[1])
        );
    }
}

// --- Security Operations tests ---

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        GraphqlSecurityIssue::GraphqlInjection,
        GraphqlSecurityIssue::GraphqlExfiltration,
    ];
    let mut seq = 0;
    let ops = graphql_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty() {
    let mut seq = 7;
    let ops = graphql_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 7);
}

#[test]
fn security_to_operations_vuln_class() {
    let issues = vec![GraphqlSecurityIssue::GraphqlInjection];
    let mut seq = 0;
    let ops = graphql_security_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::GraphQlAbuse
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn security_to_operations_severity_matches() {
    let issues = vec![GraphqlSecurityIssue::GraphqlInjection];
    let mut seq = 0;
    let ops = graphql_security_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 8.5);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn security_to_operations_sequence_increments() {
    let issues = vec![
        GraphqlSecurityIssue::GraphqlInjection,
        GraphqlSecurityIssue::GraphqlAuthBypass,
    ];
    let mut seq = 20;
    let ops = graphql_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 22);
    assert_eq!(ops[0].sequence_number, 21);
    assert_eq!(ops[1].sequence_number, 22);
}

#[test]
fn security_to_operations_confidence_half() {
    let issues = vec![GraphqlSecurityIssue::GraphqlDos];
    let mut seq = 0;
    let ops = graphql_security_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert_eq!(confidence.value(), 0.5);
        }
        _ => panic!("expected AddFinding"),
    }
}

// --- Combined detection tests ---

#[test]
fn depth_multiple_issues_detected() {
    let body = r#"
        {
            "data": {
                "__schema": {
                    "types": []
                }
            },
            "graphql": true,
            "playground": true,
            "errors": [{"message": "Did you mean 'username'?"}]
        }
    "#;
    let issues = analyze_graphql_depth(body);
    assert!(issues.contains(&GraphqlDepthIssue::IntrospectionEnabled));
    assert!(issues.contains(&GraphqlDepthIssue::PlaygroundExposed));
    assert!(issues.contains(&GraphqlDepthIssue::FieldSuggestionsEnabled));
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"
        query {
            _service { sdl }
        }
        mutation {
            deleteUser(id: "1") { ok }
        }
    "#;
    let issues = analyze_graphql_security(body);
    assert!(issues.contains(&GraphqlSecurityIssue::SchemaStitchingLeak));
    assert!(issues.contains(&GraphqlSecurityIssue::GraphqlAuthBypass));
}

#[test]
fn detects_query_bracket_pattern() {
    let body = r#"query { users { id name } }"#;
    let issues = analyze_graphql_depth(body);
    assert!(!issues.is_empty());
}
