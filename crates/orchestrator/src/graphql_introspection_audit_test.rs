use crate::graphql_introspection_audit::*;

#[test]
fn introspection_enabled_detected() {
    let body = r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#;
    let issues = analyze_graphql_response("/graphql", body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::IntrospectionEnabled { .. })));
}

#[test]
fn introspection_disabled_clean() {
    let body = r#"{"errors":[{"message":"Introspection is disabled"}]}"#;
    let issues = analyze_graphql_response("/graphql", body, "");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::IntrospectionEnabled { .. })));
}

#[test]
fn suggestions_enabled_detected() {
    let err = r#"{"errors":[{"message":"Cannot query field 'xyz'. Did you mean 'abc'?"}]}"#;
    let issues = analyze_graphql_response("/graphql", "", err);
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::SuggestionsEnabled { .. })));
}

#[test]
fn no_suggestions_clean() {
    let err = r#"{"errors":[{"message":"Unknown field"}]}"#;
    let issues = analyze_graphql_response("/graphql", "", err);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::SuggestionsEnabled { .. })));
}

#[test]
fn debug_mode_stack_trace() {
    let err = r#"{"errors":[{"extensions":{"stack":"Error at resolver..."}}]}"#;
    let issues = analyze_graphql_response("/graphql", "", err);
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::DebugModeEnabled { .. })));
}

#[test]
fn debug_mode_debug_field() {
    let err = r#"{"errors":[{"message":"error"}],"debug":true}"#;
    let issues = analyze_graphql_response("/graphql", "", err);
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::DebugModeEnabled { .. })));
}

#[test]
fn sensitive_type_admin() {
    let body = r#"{"data":{"__schema":{"types":[{"name":"Query"},{"name":"AdminUser"}]}}}"#;
    let issues = analyze_graphql_response("/graphql", body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::SensitiveTypesExposed { type_name } if type_name == "admin")));
}

#[test]
fn sensitive_type_internal() {
    let body = r#"{"data":{"__schema":{"types":[{"name":"InternalConfig"}]}}}"#;
    let issues = analyze_graphql_response("/graphql", body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::SensitiveTypesExposed { type_name } if type_name == "internal")));
}

#[test]
fn no_sensitive_types_clean() {
    let body = r#"{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"Post"}]}}}"#;
    let issues = analyze_graphql_response("/graphql", body, "");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::SensitiveTypesExposed { .. })));
}

#[test]
fn empty_bodies_clean() {
    let issues = analyze_graphql_response("/graphql", "", "");
    assert!(issues.is_empty());
}

#[test]
fn severity_ordering() {
    assert!(
        graphql_intro_severity(&GraphqlIntroIssue::SensitiveTypesExposed {
            type_name: "x".to_string()
        }) > graphql_intro_severity(&GraphqlIntroIssue::IntrospectionEnabled {
            endpoint: "x".to_string()
        })
    );
    assert!(
        graphql_intro_severity(&GraphqlIntroIssue::IntrospectionEnabled {
            endpoint: "x".to_string()
        }) > graphql_intro_severity(&GraphqlIntroIssue::DebugModeEnabled {
            endpoint: "x".to_string()
        })
    );
    assert!(
        graphql_intro_severity(&GraphqlIntroIssue::DebugModeEnabled {
            endpoint: "x".to_string()
        }) > graphql_intro_severity(&GraphqlIntroIssue::SuggestionsEnabled {
            endpoint: "x".to_string()
        })
    );
}

#[test]
fn operations_generated() {
    let issues = vec![
        GraphqlIntroIssue::IntrospectionEnabled {
            endpoint: "/graphql".to_string(),
        },
        GraphqlIntroIssue::SuggestionsEnabled {
            endpoint: "/graphql".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = graphql_intro_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = graphql_intro_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        GraphqlIntroIssue::IntrospectionEnabled {
            endpoint: "/gql".to_string()
        }
        .to_string(),
        "graphql_introspection_enabled:/gql"
    );
    assert_eq!(
        GraphqlIntroIssue::SuggestionsEnabled {
            endpoint: "/gql".to_string()
        }
        .to_string(),
        "graphql_suggestions_enabled:/gql"
    );
    assert_eq!(
        GraphqlIntroIssue::DebugModeEnabled {
            endpoint: "/gql".to_string()
        }
        .to_string(),
        "graphql_debug_mode:/gql"
    );
    assert_eq!(
        GraphqlIntroIssue::SensitiveTypesExposed {
            type_name: "admin".to_string()
        }
        .to_string(),
        "graphql_sensitive_type:admin"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_graphql_introspection("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_graphql_introspection("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn combined_introspection_and_suggestions() {
    let intro = r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#;
    let err = r#"{"errors":[{"message":"Did you mean 'user'?"}]}"#;
    let issues = analyze_graphql_response("/graphql", intro, err);
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::IntrospectionEnabled { .. })));
    assert!(issues
        .iter()
        .any(|i| matches!(i, GraphqlIntroIssue::SuggestionsEnabled { .. })));
}
