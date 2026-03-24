use crate::auth_matrix::PrivilegeLevel;
use crate::graphql_field_auth::*;

fn default_roles() -> Vec<AuthRole> {
    vec![
        AuthRole::unauthenticated(),
        AuthRole::user("user-tok"),
        AuthRole::admin("admin-tok"),
    ]
}

fn sample_type_def() -> GraphQlTypeDefinition {
    GraphQlTypeDefinition {
        name: "User".to_string(),
        fields: vec![
            GraphQlFieldDefinition {
                name: "id".to_string(),
                return_type: "ID!".to_string(),
                arguments: vec![],
                has_auth_directive: false,
                auth_directive: None,
            },
            GraphQlFieldDefinition {
                name: "email".to_string(),
                return_type: "String".to_string(),
                arguments: vec![],
                has_auth_directive: false,
                auth_directive: None,
            },
            GraphQlFieldDefinition {
                name: "passwordHash".to_string(),
                return_type: "String".to_string(),
                arguments: vec![],
                has_auth_directive: true,
                auth_directive: Some("@auth".to_string()),
            },
            GraphQlFieldDefinition {
                name: "isAdmin".to_string(),
                return_type: "Boolean".to_string(),
                arguments: vec![],
                has_auth_directive: true,
                auth_directive: Some("@hasRole(role: ADMIN)".to_string()),
            },
            GraphQlFieldDefinition {
                name: "totalRevenue".to_string(),
                return_type: "Float".to_string(),
                arguments: vec![],
                has_auth_directive: false,
                auth_directive: None,
            },
        ],
    }
}

// ─── Pattern 1: Scalar Field Probes ──────────────────────────────────────────

#[test]
fn scalar_probes_generates_one_per_field_per_role() {
    let roles = default_roles();
    let td = sample_type_def();
    let probes = generate_scalar_field_probes(&td, &roles, "user");
    assert_eq!(probes.len(), td.fields.len() * roles.len());
}

#[test]
fn scalar_probes_flags_sensitive_fields() {
    let roles = vec![AuthRole::user("tok")];
    let td = sample_type_def();
    let probes = generate_scalar_field_probes(&td, &roles, "me");
    let pw_probe = probes
        .iter()
        .find(|p| p.field_name == "passwordHash")
        .unwrap();
    assert!(pw_probe.is_sensitive);
    assert!(!pw_probe.is_admin_only);
}

#[test]
fn scalar_probes_flags_admin_fields() {
    let roles = vec![AuthRole::admin("tok")];
    let td = sample_type_def();
    let probes = generate_scalar_field_probes(&td, &roles, "user");
    let admin_probe = probes.iter().find(|p| p.field_name == "isAdmin").unwrap();
    assert!(admin_probe.is_admin_only);
}

#[test]
fn scalar_probes_contain_valid_queries() {
    let roles = vec![AuthRole::unauthenticated()];
    let td = sample_type_def();
    let probes = generate_scalar_field_probes(&td, &roles, "viewer");
    for probe in &probes {
        assert!(probe.query.starts_with("{ viewer { "));
        assert!(probe.query.ends_with(" } }"));
    }
}

// ─── Pattern 2: Nested Object Authorization ──────────────────────────────────

#[test]
fn nested_probes_uses_default_paths() {
    let roles = default_roles();
    let probes = generate_nested_object_probes(&[], &roles);
    assert!(!probes.is_empty());
    assert_eq!(probes.len(), SENSITIVE_NESTED_PATHS.len() * roles.len());
}

#[test]
fn nested_probes_builds_correct_query_structure() {
    let roles = vec![AuthRole::user("tok")];
    let custom = vec![vec![
        "user".to_string(),
        "creditCard".to_string(),
        "number".to_string(),
    ]];
    let probes = generate_nested_object_probes(&custom, &roles);
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].query, "{ user { creditCard { number } } }");
    assert_eq!(probes[0].depth, 3);
}

#[test]
fn nested_probes_skips_empty_paths() {
    let roles = vec![AuthRole::user("tok")];
    let custom = vec![vec![], vec!["a".to_string()]];
    let probes = generate_nested_object_probes(&custom, &roles);
    assert_eq!(probes.len(), 1);
}

#[test]
fn nested_probes_respects_depth_limit() {
    let roles = vec![AuthRole::user("tok")];
    let deep: Vec<String> = (0..20).map(|i| format!("f{i}")).collect();
    let probes = generate_nested_object_probes(&[deep], &roles);
    assert!(probes.is_empty());
}

// ─── Pattern 3: Connection Pagination ────────────────────────────────────────

#[test]
fn connection_probes_generates_all_techniques() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_connection_pagination_probes(&["users"], &roles);
    assert_eq!(probes.len(), 5);
    let techniques: Vec<PaginationTechnique> = probes.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&PaginationTechnique::RelayCursor));
    assert!(techniques.contains(&PaginationTechnique::OffsetLimit));
    assert!(techniques.contains(&PaginationTechnique::ExcessivePageSize));
    assert!(techniques.contains(&PaginationTechnique::CursorEnumeration));
    assert!(techniques.contains(&PaginationTechnique::ReversePagination));
}

#[test]
fn connection_probes_uses_defaults_when_empty() {
    let roles = vec![AuthRole::unauthenticated()];
    let probes = generate_connection_pagination_probes(&[], &roles);
    assert_eq!(probes.len(), CONNECTION_FIELDS.len() * 5);
}

#[test]
fn connection_excessive_page_size_uses_max() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_connection_pagination_probes(&["orders"], &roles);
    let excessive = probes
        .iter()
        .find(|p| p.technique == PaginationTechnique::ExcessivePageSize)
        .unwrap();
    assert_eq!(excessive.page_size, 1000);
    assert!(excessive.query.contains("1000"));
}

// ─── Pattern 4: Mutation Field Escalation ────────────────────────────────────

#[test]
fn mutation_probes_generates_all_escalation_fields() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_mutation_field_probes(&["updateUser"], &roles);
    assert_eq!(probes.len(), ESCALATION_FIELDS.len());
}

#[test]
fn mutation_probes_cover_all_categories() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_mutation_field_probes(&["updateProfile"], &roles);
    let categories: std::collections::HashSet<_> = probes
        .iter()
        .map(|p| match p.category {
            MutationEscalationCategory::RoleEscalation => "role",
            MutationEscalationCategory::OwnershipTampering => "ownership",
            MutationEscalationCategory::InternalFieldOverwrite => "internal",
            MutationEscalationCategory::FinancialTampering => "financial",
            MutationEscalationCategory::VerificationBypass => "verification",
        })
        .collect();
    assert!(categories.len() >= 4);
}

#[test]
fn mutation_probes_inject_correct_values() {
    let roles = vec![AuthRole::admin("tok")];
    let probes = generate_mutation_field_probes(&["updateUser"], &roles);
    let admin_probe = probes
        .iter()
        .find(|p| p.escalation_field == "isAdmin")
        .unwrap();
    assert!(admin_probe.query.contains("isAdmin: true"));
}

// ─── Pattern 5: Computed Field Leakage ───────────────────────────────────────

#[test]
fn computed_probes_uses_default_patterns() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_computed_field_probes("Dashboard", "dashboard", &[], &roles);
    assert_eq!(probes.len(), COMPUTED_FIELD_PATTERNS.len());
}

#[test]
fn computed_probes_flags_business_metrics() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_computed_field_probes("Stats", "stats", &["totalRevenue"], &roles);
    assert_eq!(probes.len(), 1);
    assert!(probes[0].is_business_metric);
}

#[test]
fn computed_probes_custom_fields() {
    let roles = default_roles();
    let probes = generate_computed_field_probes("Report", "report", &["customMetric"], &roles);
    assert_eq!(probes.len(), roles.len());
    assert!(!probes[0].is_business_metric);
}

// ─── Pattern 6: Directive Auth Bypass ────────────────────────────────────────

#[test]
fn directive_probes_generates_five_techniques() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_directive_bypass_probes("User", "me", &["secretField"], &roles);
    assert_eq!(probes.len(), 5);
}

#[test]
fn directive_probes_skip_false_syntax() {
    let roles = vec![AuthRole::unauthenticated()];
    let probes = generate_directive_bypass_probes("User", "user", &["salary"], &roles);
    let skip = probes
        .iter()
        .find(|p| p.technique == DirectiveBypassTechnique::SkipFalse)
        .unwrap();
    assert!(skip.query.contains("@skip(if: false)"));
}

#[test]
fn directive_probes_combined_directive() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_directive_bypass_probes("User", "me", &["ssn"], &roles);
    let combined = probes
        .iter()
        .find(|p| p.technique == DirectiveBypassTechnique::CombinedDirectives)
        .unwrap();
    assert!(
        combined
            .query
            .contains("@skip(if: false) @include(if: true)")
    );
}

// ─── Pattern 7: Inline Fragment Bypass ───────────────────────────────────────

#[test]
fn inline_fragment_probes_per_role() {
    let roles = default_roles();
    let concretes: Vec<(&str, &[&str])> =
        vec![("AdminUser", &["permissions", "auditLog"] as &[&str])];
    let probes = generate_inline_fragment_probes("user", "User", &concretes, &roles);
    assert_eq!(probes.len(), roles.len());
}

#[test]
fn inline_fragment_query_structure() {
    let roles = vec![AuthRole::user("tok")];
    let concretes: Vec<(&str, &[&str])> = vec![("AdminUser", &["secretData"] as &[&str])];
    let probes = generate_inline_fragment_probes("node", "Node", &concretes, &roles);
    assert!(probes[0].query.contains("... on AdminUser { secretData }"));
}

// ─── Pattern 8: Field Alias Bypass ───────────────────────────────────────────

#[test]
fn alias_probes_generates_six_prefixes_per_field() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_field_alias_probes("me", &["passwordHash"], &roles);
    assert_eq!(probes.len(), 6);
}

#[test]
fn alias_probes_uses_capitalized_alias() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_field_alias_probes("user", &["ssn"], &roles);
    let aliases: Vec<&str> = probes.iter().map(|p| p.alias.as_str()).collect();
    assert!(aliases.contains(&"safeSsn"));
    assert!(aliases.contains(&"publicSsn"));
}

// ─── Pattern 9: Interface/Union Leak ─────────────────────────────────────────

#[test]
fn interface_union_probes_three_techniques() {
    let roles = vec![AuthRole::user("tok")];
    let concretes: Vec<(&str, &[&str])> = vec![
        ("CreditCard", &["number"] as &[&str]),
        ("BankTransfer", &["accountNumber"] as &[&str]),
    ];
    let probes = generate_interface_union_probes("payment", "PaymentMethod", &concretes, &roles);
    assert_eq!(probes.len(), 3);
    let techniques: Vec<InterfaceUnionTechnique> = probes.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&InterfaceUnionTechnique::TypenameDiscovery));
    assert!(techniques.contains(&InterfaceUnionTechnique::ExhaustiveFragments));
    assert!(techniques.contains(&InterfaceUnionTechnique::NamedFragmentSpread));
}

#[test]
fn interface_union_typename_discovery_query() {
    let roles = vec![AuthRole::unauthenticated()];
    let concretes: Vec<(&str, &[&str])> = vec![("Admin", &["secret"] as &[&str])];
    let probes = generate_interface_union_probes("node", "Node", &concretes, &roles);
    let typename = probes
        .iter()
        .find(|p| p.technique == InterfaceUnionTechnique::TypenameDiscovery)
        .unwrap();
    assert_eq!(typename.query, "{ node { __typename } }");
}

// ─── Pattern 10: Introspection Metadata Leak ─────────────────────────────────

#[test]
fn introspection_probes_four_targets_per_type() {
    let roles = vec![AuthRole::user("tok")];
    let probes = generate_introspection_metadata_probes(&["User"], &roles);
    assert_eq!(probes.len(), 4);
}

#[test]
fn introspection_probes_scale_with_types() {
    let roles = default_roles();
    let probes = generate_introspection_metadata_probes(&["User", "Order"], &roles);
    assert_eq!(probes.len(), 2 * 4 * roles.len());
}

#[test]
fn introspection_probes_include_deprecated_query() {
    let roles = vec![AuthRole::unauthenticated()];
    let probes = generate_introspection_metadata_probes(&["Post"], &roles);
    let deprecated = probes
        .iter()
        .find(|p| p.metadata_target == IntrospectionTarget::DeprecatedFields)
        .unwrap();
    assert!(deprecated.query.contains("includeDeprecated: true"));
}

// ─── Response Analysis ───────────────────────────────────────────────────────

#[test]
fn classify_response_data_returned() {
    let json = r#"{"data":{"user":{"email":"a@b.com"}}}"#;
    let result = classify_response(json, "email");
    assert_eq!(result, FieldAuthResult::DataReturned);
}

#[test]
fn classify_response_auth_error() {
    let json = r#"{"errors":[{"message":"Unauthorized access"}]}"#;
    let result = classify_response(json, "secret");
    assert!(matches!(result, FieldAuthResult::AuthError(_)));
}

#[test]
fn classify_response_forbidden() {
    let json = r#"{"errors":[{"message":"Forbidden: insufficient permissions"}]}"#;
    let result = classify_response(json, "salary");
    assert!(matches!(result, FieldAuthResult::AuthError(_)));
}

#[test]
fn classify_response_field_not_found() {
    let json = r#"{"errors":[{"message":"Cannot query field \"fakeField\" on type \"User\""}]}"#;
    let result = classify_response(json, "fakeField");
    assert_eq!(result, FieldAuthResult::FieldNotFound);
}

#[test]
fn classify_response_null_data() {
    let json = r#"{"data":null}"#;
    let result = classify_response(json, "anything");
    assert_eq!(result, FieldAuthResult::NullReturned);
}

#[test]
fn classify_response_null_field() {
    let json = r#"{"data":{"user":{"secret":null}}}"#;
    let result = classify_response(json, "secret");
    assert_eq!(result, FieldAuthResult::NullReturned);
}

#[test]
fn classify_response_invalid_json() {
    let result = classify_response("not json at all", "field");
    assert!(matches!(result, FieldAuthResult::OtherError(_)));
}

#[test]
fn classify_response_permission_denied() {
    let json = r#"{"errors":[{"message":"Permission denied for field salary"}]}"#;
    let result = classify_response(json, "salary");
    assert!(matches!(result, FieldAuthResult::AuthError(_)));
}

// ─── Field Auth Matrix ───────────────────────────────────────────────────────

#[test]
fn matrix_record_and_retrieve() {
    let roles = default_roles();
    let mut matrix = FieldAuthMatrix::new(roles);
    matrix.record(FieldAuthMatrixEntry {
        type_name: "User".to_string(),
        field_name: "email".to_string(),
        role_label: "anonymous".to_string(),
        privilege_level: PrivilegeLevel::Unauthenticated,
        result: FieldAuthResult::AuthError("unauthorized".to_string()),
    });
    matrix.record(FieldAuthMatrixEntry {
        type_name: "User".to_string(),
        field_name: "email".to_string(),
        role_label: "admin".to_string(),
        privilege_level: PrivilegeLevel::Admin,
        result: FieldAuthResult::DataReturned,
    });
    assert_eq!(matrix.entry_count(), 2);
    assert_eq!(matrix.field_count(), 1);
}

#[test]
fn matrix_detects_anomaly_when_low_priv_accesses_sensitive() {
    let roles = default_roles();
    let mut matrix = FieldAuthMatrix::new(roles);
    matrix.record_batch(vec![
        FieldAuthMatrixEntry {
            type_name: "User".to_string(),
            field_name: "passwordHash".to_string(),
            role_label: "anonymous".to_string(),
            privilege_level: PrivilegeLevel::Unauthenticated,
            result: FieldAuthResult::DataReturned,
        },
        FieldAuthMatrixEntry {
            type_name: "User".to_string(),
            field_name: "passwordHash".to_string(),
            role_label: "admin".to_string(),
            privilege_level: PrivilegeLevel::Admin,
            result: FieldAuthResult::DataReturned,
        },
    ]);
    let anomalies = matrix.detect_anomalies();
    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].field_name, "passwordHash");
    assert_eq!(anomalies[0].low_role, "anonymous");
    assert!(anomalies[0].severity > 0.9);
}

#[test]
fn matrix_no_anomaly_when_denied() {
    let roles = default_roles();
    let mut matrix = FieldAuthMatrix::new(roles);
    matrix.record_batch(vec![
        FieldAuthMatrixEntry {
            type_name: "User".to_string(),
            field_name: "salary".to_string(),
            role_label: "anonymous".to_string(),
            privilege_level: PrivilegeLevel::Unauthenticated,
            result: FieldAuthResult::AuthError("denied".to_string()),
        },
        FieldAuthMatrixEntry {
            type_name: "User".to_string(),
            field_name: "salary".to_string(),
            role_label: "admin".to_string(),
            privilege_level: PrivilegeLevel::Admin,
            result: FieldAuthResult::DataReturned,
        },
    ]);
    let anomalies = matrix.detect_anomalies();
    assert!(anomalies.is_empty());
}

#[test]
fn matrix_build_table() {
    let roles = default_roles();
    let mut matrix = FieldAuthMatrix::new(roles);
    matrix.record(FieldAuthMatrixEntry {
        type_name: "Order".to_string(),
        field_name: "total".to_string(),
        role_label: "user".to_string(),
        privilege_level: PrivilegeLevel::User,
        result: FieldAuthResult::DataReturned,
    });
    let table = matrix.build_table();
    assert!(table.contains_key(&("Order".to_string(), "total".to_string())));
}

#[test]
fn matrix_result_for() {
    let roles = default_roles();
    let mut matrix = FieldAuthMatrix::new(roles);
    matrix.record(FieldAuthMatrixEntry {
        type_name: "User".to_string(),
        field_name: "name".to_string(),
        role_label: "user".to_string(),
        privilege_level: PrivilegeLevel::User,
        result: FieldAuthResult::DataReturned,
    });
    let result = matrix.result_for("User", "name", "user").unwrap();
    assert!(result.is_accessible());
    assert!(matrix.result_for("User", "name", "admin").is_none());
}

// ─── Aggregate Engine ────────────────────────────────────────────────────────

#[test]
fn engine_generates_probes_for_all_patterns() {
    let td = sample_type_def();
    let config = FieldAuthConfig::default();
    let concretes: Vec<(&str, &[&str])> = vec![("AdminUser", &["auditLog"] as &[&str])];
    let union_types: Vec<(&str, &str, &[(&str, &[&str])])> =
        vec![("user", "Actor", concretes.as_slice())];
    let suite = run_field_auth_engine(
        &config,
        &[td],
        &["updateUser", "createUser"],
        &["passwordHash", "isAdmin"],
        &["users", "orders"],
        &union_types,
    );
    assert!(suite.scalar_probes.len() > 0);
    assert!(suite.nested_probes.len() > 0);
    assert!(suite.connection_probes.len() > 0);
    assert!(suite.mutation_probes.len() > 0);
    assert!(suite.computed_probes.len() > 0);
    assert!(suite.directive_probes.len() > 0);
    assert!(suite.inline_fragment_probes.len() > 0);
    assert!(suite.alias_probes.len() > 0);
    assert!(suite.interface_union_probes.len() > 0);
    assert!(suite.introspection_probes.len() > 0);
    assert!(suite.total_probe_count > 100);
}

#[test]
fn engine_total_probe_count_matches_sum() {
    let td = sample_type_def();
    let config = FieldAuthConfig::default();
    let suite = run_field_auth_engine(&config, &[td], &["updateUser"], &["secret"], &[], &[]);
    let manual_sum = suite.scalar_probes.len()
        + suite.nested_probes.len()
        + suite.connection_probes.len()
        + suite.mutation_probes.len()
        + suite.computed_probes.len()
        + suite.directive_probes.len()
        + suite.inline_fragment_probes.len()
        + suite.alias_probes.len()
        + suite.interface_union_probes.len()
        + suite.introspection_probes.len();
    assert_eq!(suite.total_probe_count, manual_sum);
}

#[test]
fn engine_respects_disabled_patterns() {
    let td = sample_type_def();
    let config = FieldAuthConfig {
        enable_scalar: false,
        enable_nested: false,
        enable_connection: false,
        enable_mutation: false,
        enable_computed: false,
        enable_directive: false,
        enable_inline_fragment: false,
        enable_alias: false,
        enable_interface_union: false,
        enable_introspection: false,
        ..Default::default()
    };
    let suite = run_field_auth_engine(&config, &[td], &[], &[], &[], &[]);
    assert_eq!(suite.total_probe_count, 0);
}

// ─── Auth Role Construction ──────────────────────────────────────────────────

#[test]
fn auth_role_unauthenticated_has_no_header() {
    let role = AuthRole::unauthenticated();
    assert!(role.auth_header.is_none());
    assert_eq!(role.privilege_level, PrivilegeLevel::Unauthenticated);
}

#[test]
fn auth_role_user_has_bearer_header() {
    let role = AuthRole::user("my-token-123");
    assert_eq!(role.auth_header, Some("Bearer my-token-123".to_string()));
    assert_eq!(role.privilege_level, PrivilegeLevel::User);
}

#[test]
fn auth_role_admin_has_bearer_header() {
    let role = AuthRole::admin("admin-tok");
    assert_eq!(role.auth_header, Some("Bearer admin-tok".to_string()));
    assert_eq!(role.privilege_level, PrivilegeLevel::Admin);
}

// ─── FieldAuthResult methods ─────────────────────────────────────────────────

#[test]
fn field_auth_result_accessors() {
    assert!(FieldAuthResult::DataReturned.is_accessible());
    assert!(!FieldAuthResult::DataReturned.is_denied());
    assert!(!FieldAuthResult::NullReturned.is_accessible());
    assert!(!FieldAuthResult::NullReturned.is_denied());
    assert!(FieldAuthResult::AuthError("no".to_string()).is_denied());
    assert!(!FieldAuthResult::AuthError("no".to_string()).is_accessible());
    assert!(!FieldAuthResult::FieldNotFound.is_accessible());
}

// ─── FieldAuthPattern Display ────────────────────────────────────────────────

#[test]
fn field_auth_pattern_display() {
    assert_eq!(
        format!("{}", FieldAuthPattern::ScalarFieldExposure),
        "scalar-field-exposure"
    );
    assert_eq!(
        format!("{}", FieldAuthPattern::NestedObjectTraversal),
        "nested-object-traversal"
    );
    assert_eq!(
        format!("{}", FieldAuthPattern::DirectiveAuthBypass),
        "directive-auth-bypass"
    );
    assert_eq!(
        format!("{}", FieldAuthPattern::IntrospectionMetadataLeak),
        "introspection-metadata-leak"
    );
}

// ─── Introspection Parsing ───────────────────────────────────────────────────

#[test]
fn parse_introspection_types_extracts_objects() {
    let json = r#"{"data":{"__schema":{"types":[
        {"name":"User","kind":"OBJECT","fields":[
            {"name":"id","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID","ofType":null}},"args":[],"description":null},
            {"name":"email","type":{"kind":"SCALAR","name":"String","ofType":null},"args":[],"description":"Requires auth to view"}
        ]},
        {"name":"__Schema","kind":"OBJECT","fields":[]},
        {"name":"String","kind":"SCALAR","fields":null}
    ]}}}"#;
    let types = parse_introspection_types(json);
    assert_eq!(types.len(), 1);
    assert_eq!(types[0].name, "User");
    assert_eq!(types[0].fields.len(), 2);
    assert_eq!(types[0].fields[0].return_type, "ID!");
    assert!(types[0].fields[1].has_auth_directive);
}

#[test]
fn parse_introspection_types_handles_empty() {
    let types = parse_introspection_types("{}");
    assert!(types.is_empty());
}

#[test]
fn parse_introspection_types_skips_internal() {
    let json = r#"{"data":{"__schema":{"types":[
        {"name":"__Type","kind":"OBJECT","fields":[{"name":"name","type":{"kind":"SCALAR","name":"String","ofType":null},"args":[],"description":null}]}
    ]}}}"#;
    let types = parse_introspection_types(json);
    assert!(types.is_empty());
}

// ─── Edge Cases ──────────────────────────────────────────────────────────────

#[test]
fn nested_query_single_field() {
    let roles = vec![AuthRole::user("tok")];
    let custom = vec![vec!["me".to_string()]];
    let probes = generate_nested_object_probes(&custom, &roles);
    assert_eq!(probes[0].query, "{ me }");
}

#[test]
fn alias_probes_multiple_fields_multiple_roles() {
    let roles = default_roles();
    let probes = generate_field_alias_probes("user", &["secret", "token"], &roles);
    assert_eq!(probes.len(), 2 * 6 * roles.len());
}

#[test]
fn matrix_multi_anomaly_detection() {
    let roles = default_roles();
    let mut matrix = FieldAuthMatrix::new(roles);
    for field in &["passwordHash", "creditCard", "ssn"] {
        matrix.record_batch(vec![
            FieldAuthMatrixEntry {
                type_name: "User".to_string(),
                field_name: field.to_string(),
                role_label: "anonymous".to_string(),
                privilege_level: PrivilegeLevel::Unauthenticated,
                result: FieldAuthResult::DataReturned,
            },
            FieldAuthMatrixEntry {
                type_name: "User".to_string(),
                field_name: field.to_string(),
                role_label: "user".to_string(),
                privilege_level: PrivilegeLevel::User,
                result: FieldAuthResult::DataReturned,
            },
            FieldAuthMatrixEntry {
                type_name: "User".to_string(),
                field_name: field.to_string(),
                role_label: "admin".to_string(),
                privilege_level: PrivilegeLevel::Admin,
                result: FieldAuthResult::DataReturned,
            },
        ]);
    }
    let anomalies = matrix.detect_anomalies();
    assert!(anomalies.len() >= 6);
}
