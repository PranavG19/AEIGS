use super::*;

fn make_param(name: &str, loc: ParamLocation, slot: SlotType) -> ApiParameter {
    ApiParameter {
        name: name.to_string(),
        location: loc,
        slot_type: slot,
        constraint: ParamConstraint::default(),
    }
}

fn _make_constrained_param(
    name: &str,
    loc: ParamLocation,
    slot: SlotType,
    constraint: ParamConstraint,
) -> ApiParameter {
    ApiParameter {
        name: name.to_string(),
        location: loc,
        slot_type: slot,
        constraint,
    }
}

fn sample_endpoint() -> ApiEndpoint {
    ApiEndpoint {
        method: HttpMethod::Get,
        path_template: "/api/users/{user_id}".into(),
        parameters: vec![
            make_param("user_id", ParamLocation::Path, SlotType::Integer),
            make_param("fields", ParamLocation::Query, SlotType::String),
        ],
        request_body: None,
        response_codes: vec![200, 404],
    }
}

fn sample_post_endpoint() -> ApiEndpoint {
    ApiEndpoint {
        method: HttpMethod::Post,
        path_template: "/api/users".into(),
        parameters: vec![],
        request_body: Some(RequestBody {
            content_type: "application/json".into(),
            schema: vec![
                BodyField {
                    name: "email".into(),
                    slot_type: SlotType::Email,
                    constraint: ParamConstraint {
                        required: true,
                        ..Default::default()
                    },
                    nested: vec![],
                },
                BodyField {
                    name: "name".into(),
                    slot_type: SlotType::String,
                    constraint: ParamConstraint {
                        max_length: Some(100),
                        ..Default::default()
                    },
                    nested: vec![],
                },
            ],
        }),
        response_codes: vec![201, 400, 409],
    }
}

#[test]
fn slot_type_display_all() {
    let types = [
        SlotType::String,
        SlotType::Integer,
        SlotType::Float,
        SlotType::Boolean,
        SlotType::Email,
        SlotType::Url,
        SlotType::Uuid,
        SlotType::Date,
        SlotType::DateTime,
        SlotType::IpAddress,
        SlotType::Json,
        SlotType::Array,
        SlotType::Enum,
    ];
    for t in &types {
        assert!(!t.to_string().is_empty());
    }
}

#[test]
fn symbol_display() {
    assert_eq!(Symbol::Terminal("hello".into()).to_string(), "'hello'");
    assert_eq!(Symbol::NonTerminal("rule".into()).to_string(), "<rule>");
    assert_eq!(
        Symbol::TypedSlot(SlotType::Integer).to_string(),
        "[integer]"
    );
}

#[test]
fn http_method_display() {
    assert_eq!(HttpMethod::Get.to_string(), "GET");
    assert_eq!(HttpMethod::Post.to_string(), "POST");
    assert_eq!(HttpMethod::Put.to_string(), "PUT");
    assert_eq!(HttpMethod::Patch.to_string(), "PATCH");
    assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
}

#[test]
fn param_location_display() {
    assert_eq!(ParamLocation::Path.to_string(), "path");
    assert_eq!(ParamLocation::Query.to_string(), "query");
    assert_eq!(ParamLocation::Header.to_string(), "header");
    assert_eq!(ParamLocation::Cookie.to_string(), "cookie");
}

#[test]
fn mutation_strategy_all() {
    let strategies = MutationStrategy::all();
    assert_eq!(strategies.len(), 9);
    for s in strategies {
        assert!(!s.to_string().is_empty());
    }
}

#[test]
fn boundary_values_string_non_empty() {
    let values = boundary_values(SlotType::String);
    assert!(
        values.len() >= 15,
        "String should have 15+ boundary values, got {}",
        values.len()
    );
    assert!(
        values.contains(&String::new()),
        "Should include empty string"
    );
    assert!(
        values.iter().any(|v| v.len() > 1000),
        "Should include very long string"
    );
}

#[test]
fn boundary_values_integer_non_empty() {
    let values = boundary_values(SlotType::Integer);
    assert!(values.len() >= 10);
    assert!(values.contains(&"0".to_string()));
    assert!(values.contains(&"-1".to_string()));
    assert!(values.iter().any(|v| v.contains("2147483647")));
}

#[test]
fn boundary_values_float_includes_special() {
    let values = boundary_values(SlotType::Float);
    assert!(values.iter().any(|v| v.contains("NaN")));
    assert!(values.iter().any(|v| v.contains("Infinity")));
    assert!(values.iter().any(|v| v.contains("-0")));
}

#[test]
fn boundary_values_email_includes_attacks() {
    let values = boundary_values(SlotType::Email);
    assert!(values.iter().any(|v| v.contains("script")));
    assert!(
        values
            .iter()
            .any(|v| v.contains("\\r\\n") || v.contains("\r\n"))
    );
}

#[test]
fn boundary_values_url_includes_ssrf() {
    let values = boundary_values(SlotType::Url);
    assert!(values.iter().any(|v| v.contains("169.254.169.254")));
    assert!(values.iter().any(|v| v.contains("file://")));
    assert!(values.iter().any(|v| v.contains("javascript:")));
}

#[test]
fn boundary_values_uuid_includes_injection() {
    let values = boundary_values(SlotType::Uuid);
    assert!(values.iter().any(|v| v.contains("OR")));
    assert!(values.iter().any(|v| v.contains("etc/passwd")));
}

#[test]
fn boundary_values_json_includes_proto_pollution() {
    let values = boundary_values(SlotType::Json);
    assert!(values.iter().any(|v| v.contains("__proto__")));
    assert!(values.iter().any(|v| v.contains("constructor")));
}

#[test]
fn boundary_values_ip_includes_bypass() {
    let values = boundary_values(SlotType::IpAddress);
    assert!(values.iter().any(|v| v.contains("169.254")));
    assert!(values.iter().any(|v| v.contains("0x7f")));
    assert!(values.iter().any(|v| v.contains("::1")));
}

#[test]
fn boundary_values_all_types_have_values() {
    let types = [
        SlotType::String,
        SlotType::Integer,
        SlotType::Float,
        SlotType::Boolean,
        SlotType::Email,
        SlotType::Url,
        SlotType::Uuid,
        SlotType::Date,
        SlotType::DateTime,
        SlotType::IpAddress,
        SlotType::Json,
        SlotType::Array,
        SlotType::Enum,
    ];
    for t in &types {
        let values = boundary_values(*t);
        assert!(
            values.len() >= 5,
            "Type {} should have at least 5 boundary values, got {}",
            t,
            values.len()
        );
    }
}

#[test]
fn type_confusion_integer() {
    let confused = type_confusion_values(SlotType::Integer);
    assert!(confused.len() >= 5);
    assert!(confused.iter().any(|(_, v)| v == "true"));
    assert!(confused.iter().any(|(_, v)| v == "null"));
    assert!(
        confused
            .iter()
            .any(|(_, v)| v.starts_with('[') || v.starts_with('{'))
    );
}

#[test]
fn type_confusion_string() {
    let confused = type_confusion_values(SlotType::String);
    assert!(confused.len() >= 4);
    assert!(confused.iter().any(|(_, v)| v == "42"));
}

#[test]
fn type_confusion_boolean() {
    let confused = type_confusion_values(SlotType::Boolean);
    assert!(confused.len() >= 3);
}

#[test]
fn type_confusion_json() {
    let confused = type_confusion_values(SlotType::Json);
    assert!(confused.iter().any(|(_, v)| v.contains('<')));
}

#[test]
fn constraint_violations_max_length() {
    let constraint = ParamConstraint {
        max_length: Some(10),
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::String, &constraint);
    assert!(
        violations
            .iter()
            .any(|(name, _)| name.contains("max_length"))
    );
    let over = violations
        .iter()
        .find(|(n, _)| n.contains("max_length"))
        .unwrap();
    assert!(over.1.len() > 10);
}

#[test]
fn constraint_violations_min_length() {
    let constraint = ParamConstraint {
        min_length: Some(5),
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::String, &constraint);
    assert!(
        violations
            .iter()
            .any(|(name, _)| name.contains("min_length"))
    );
    let under = violations
        .iter()
        .find(|(n, _)| n.contains("min_length"))
        .unwrap();
    assert!(under.1.len() < 5);
}

#[test]
fn constraint_violations_max_value() {
    let constraint = ParamConstraint {
        max_value: Some(100.0),
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::Integer, &constraint);
    assert!(
        violations
            .iter()
            .any(|(name, _)| name.contains("max_value"))
    );
}

#[test]
fn constraint_violations_enum() {
    let constraint = ParamConstraint {
        enum_values: vec!["admin".into(), "user".into()],
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::Enum, &constraint);
    assert!(violations.iter().any(|(name, _)| name.contains("enum")));
    assert!(violations.iter().any(|(_, v)| v.contains("DEFINITELY_NOT")));
}

#[test]
fn constraint_violations_required() {
    let constraint = ParamConstraint {
        required: true,
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::String, &constraint);
    assert!(
        violations
            .iter()
            .any(|(name, _)| name.contains("missing_required"))
    );
}

#[test]
fn constraint_violations_non_nullable() {
    let constraint = ParamConstraint {
        nullable: false,
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::String, &constraint);
    assert!(
        violations
            .iter()
            .any(|(name, _)| name.contains("null_non_nullable"))
    );
}

#[test]
fn injection_payloads_string_has_sqli_and_xss() {
    let payloads = injection_payloads(SlotType::String);
    assert!(payloads.iter().any(|(name, _)| name.contains("sqli")));
    assert!(payloads.iter().any(|(name, _)| name.contains("xss")));
    assert!(payloads.iter().any(|(name, _)| name.contains("ssti")));
    assert!(payloads.iter().any(|(name, _)| name.contains("cmdi")));
}

#[test]
fn injection_payloads_email_specific() {
    let payloads = injection_payloads(SlotType::Email);
    assert!(payloads.iter().any(|(name, _)| name.contains("email")));
    assert!(payloads.iter().any(|(_, v)| v.contains("@")));
}

#[test]
fn injection_payloads_url_ssrf() {
    let payloads = injection_payloads(SlotType::Url);
    assert!(payloads.iter().any(|(_, v)| v.contains("169.254")));
    assert!(payloads.iter().any(|(_, v)| v.contains("javascript:")));
}

#[test]
fn injection_payloads_json_nosql() {
    let payloads = injection_payloads(SlotType::Json);
    assert!(payloads.iter().any(|(name, _)| name.contains("nosql")));
    assert!(payloads.iter().any(|(_, v)| v.contains("$ne")));
    assert!(payloads.iter().any(|(_, v)| v.contains("__proto__")));
}

#[test]
fn format_string_payloads_non_empty() {
    let payloads = format_string_payloads();
    assert!(payloads.len() >= 10);
    assert!(payloads.iter().any(|(_, v)| v.contains("%s")));
    assert!(
        payloads
            .iter()
            .any(|(_, v)| v.contains("${") || v.contains("#{") || v.contains("{{"))
    );
}

#[test]
fn extract_grammar_single_endpoint() {
    let endpoints = vec![sample_endpoint()];
    let rules = extract_grammar(&endpoints);
    assert!(rules.len() >= 2);

    let api_rule = rules.iter().find(|r| r.name == "api").unwrap();
    assert_eq!(api_rule.expansions.len(), 1);

    let endpoint_rule = rules.iter().find(|r| r.name == "endpoint_0").unwrap();
    assert!(!endpoint_rule.expansions.is_empty());
    let symbols = &endpoint_rule.expansions[0].symbols;
    assert!(
        symbols
            .iter()
            .any(|s| matches!(s, Symbol::Terminal(t) if t == "GET"))
    );
    assert!(
        symbols
            .iter()
            .any(|s| matches!(s, Symbol::TypedSlot(SlotType::Integer)))
    );
}

#[test]
fn extract_grammar_multiple_endpoints() {
    let endpoints = vec![sample_endpoint(), sample_post_endpoint()];
    let rules = extract_grammar(&endpoints);

    let api_rule = rules.iter().find(|r| r.name == "api").unwrap();
    assert_eq!(api_rule.expansions.len(), 2);
}

#[test]
fn extract_grammar_query_params() {
    let endpoint = ApiEndpoint {
        method: HttpMethod::Get,
        path_template: "/search".into(),
        parameters: vec![
            make_param("q", ParamLocation::Query, SlotType::String),
            make_param("page", ParamLocation::Query, SlotType::Integer),
        ],
        request_body: None,
        response_codes: vec![200],
    };
    let rules = extract_grammar(&[endpoint]);
    let ep_rule = rules.iter().find(|r| r.name == "endpoint_0").unwrap();
    let symbols = &ep_rule.expansions[0].symbols;
    assert!(
        symbols
            .iter()
            .any(|s| matches!(s, Symbol::Terminal(t) if t == "?"))
    );
    assert!(
        symbols
            .iter()
            .any(|s| matches!(s, Symbol::Terminal(t) if t == "q="))
    );
    assert!(
        symbols
            .iter()
            .any(|s| matches!(s, Symbol::Terminal(t) if t == "page="))
    );
}

#[test]
fn generate_test_cases_non_empty() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    assert!(
        cases.len() >= 50,
        "Should generate 50+ test cases for 2-param endpoint, got {}",
        cases.len()
    );
}

#[test]
fn generate_test_cases_covers_strategies() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    let strategies: std::collections::HashSet<String> =
        cases.iter().map(|c| c.strategy.to_string()).collect();
    assert!(strategies.contains("boundary"));
    assert!(strategies.contains("type_confusion"));
    assert!(strategies.contains("payload_injection"));
    assert!(strategies.contains("format_string"));
}

#[test]
fn generate_test_cases_targets_all_params() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    let params: std::collections::HashSet<String> =
        cases.iter().map(|c| c.target_param.clone()).collect();
    assert!(params.contains("user_id"), "Should target user_id param");
    assert!(params.contains("fields"), "Should target fields param");
}

#[test]
fn generate_test_cases_correct_method() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    for case in &cases {
        assert_eq!(case.method, HttpMethod::Get);
    }
}

#[test]
fn generate_test_cases_post_with_body() {
    let endpoint = sample_post_endpoint();
    let cases = generate_test_cases(&endpoint);
    let body_cases: Vec<&GeneratedTestCase> = cases.iter().filter(|c| c.body.is_some()).collect();
    assert!(
        !body_cases.is_empty(),
        "POST endpoint should generate body test cases"
    );
    for case in &body_cases {
        assert!(case.headers.contains_key("Content-Type"));
    }
}

#[test]
fn generate_test_cases_other_params_have_defaults() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    let user_id_cases: Vec<&GeneratedTestCase> = cases
        .iter()
        .filter(|c| c.target_param == "fields")
        .collect();
    for case in &user_id_cases {
        assert!(
            case.parameters.contains_key("user_id"),
            "Non-target params should have default values"
        );
        assert_eq!(case.parameters["user_id"], "1");
    }
}

#[test]
fn generate_test_cases_has_descriptions() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    for case in &cases {
        assert!(
            !case.description.is_empty(),
            "Every test case needs a description"
        );
    }
}

#[test]
fn summarize_generation_correct() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    let summary = summarize_generation(&cases);
    assert_eq!(summary.total_cases, cases.len());
    assert_eq!(summary.endpoints_covered, 1);
    assert!(summary.by_strategy.len() >= 3);
    assert!(summary.by_param.len() == 2);
}

#[test]
fn default_value_all_types() {
    let types = [
        SlotType::String,
        SlotType::Integer,
        SlotType::Float,
        SlotType::Boolean,
        SlotType::Email,
        SlotType::Url,
        SlotType::Uuid,
        SlotType::Date,
        SlotType::DateTime,
        SlotType::IpAddress,
        SlotType::Json,
        SlotType::Array,
        SlotType::Enum,
    ];
    for t in &types {
        let val = default_value(*t);
        assert!(
            !val.is_empty(),
            "Default value for {} should not be empty",
            t
        );
    }
}

#[test]
fn truncate_display_short() {
    assert_eq!(truncate_display("hello", 10), "hello");
}

#[test]
fn truncate_display_long() {
    let long = "A".repeat(100);
    let truncated = truncate_display(&long, 10);
    assert!(truncated.len() <= 15);
    assert!(truncated.ends_with("..."));
}

#[test]
fn constraint_default() {
    let c = ParamConstraint::default();
    assert!(c.min_length.is_none());
    assert!(c.max_length.is_none());
    assert!(c.min_value.is_none());
    assert!(c.max_value.is_none());
    assert!(c.pattern.is_none());
    assert!(c.enum_values.is_empty());
    assert!(!c.required);
    assert!(!c.nullable);
}

#[test]
fn body_field_injection_targets() {
    let endpoint = sample_post_endpoint();
    let cases = generate_test_cases(&endpoint);
    let body_targets: std::collections::HashSet<String> = cases
        .iter()
        .filter(|c| c.body.is_some())
        .map(|c| c.target_param.clone())
        .collect();
    assert!(
        body_targets.contains("email"),
        "Should inject into email field"
    );
    assert!(
        body_targets.contains("name"),
        "Should inject into name field"
    );
}

#[test]
fn generation_summary_strategy_counts() {
    let endpoint = sample_endpoint();
    let cases = generate_test_cases(&endpoint);
    let summary = summarize_generation(&cases);

    let total_from_strategies: usize = summary.by_strategy.values().sum();
    assert_eq!(total_from_strategies, summary.total_cases);
}

#[test]
fn constraint_violations_combined() {
    let constraint = ParamConstraint {
        min_length: Some(5),
        max_length: Some(50),
        min_value: Some(0.0),
        max_value: Some(100.0),
        enum_values: vec!["a".into(), "b".into()],
        required: true,
        nullable: false,
        ..Default::default()
    };
    let violations = constraint_violations(SlotType::String, &constraint);
    assert!(
        violations.len() >= 6,
        "Combined constraints should produce 6+ violations, got {}",
        violations.len()
    );
}
