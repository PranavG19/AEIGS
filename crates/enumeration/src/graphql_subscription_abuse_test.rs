use crate::graphql_subscription_abuse::*;

// ─── Subscription Enumeration Tests ──────────────────────────────────────────

#[test]
fn introspection_query_targets_subscription_type() {
    let query = build_subscription_introspection_query();
    assert!(query.contains("subscriptionType"));
    assert!(query.contains("fields"));
    assert!(query.contains("args"));
    assert!(query.contains("__schema"));
}

#[test]
fn field_introspection_query_targets_subscription_type_name() {
    let query = build_field_introspection_query("onMessage");
    assert!(query.contains("Subscription"));
    assert!(query.contains("fields"));
}

#[test]
fn parse_introspection_extracts_subscription_fields() {
    let response = r#"{
        "data": {
            "__schema": {
                "subscriptionType": {
                    "name": "Subscription",
                    "fields": [
                        {
                            "name": "onMessage",
                            "description": "New message event",
                            "args": [
                                {
                                    "name": "channelId",
                                    "type": { "name": "ID", "kind": "SCALAR" }
                                }
                            ],
                            "type": {
                                "name": null,
                                "kind": "NON_NULL",
                                "ofType": {
                                    "name": "Message",
                                    "kind": "OBJECT",
                                    "fields": [
                                        { "name": "id", "type": { "name": "ID" } },
                                        { "name": "content", "type": { "name": "String" } }
                                    ]
                                }
                            }
                        },
                        {
                            "name": "onNotification",
                            "description": null,
                            "args": [],
                            "type": {
                                "name": "Notification",
                                "kind": "OBJECT",
                                "ofType": null
                            }
                        }
                    ]
                }
            }
        }
    }"#;

    let subs = parse_subscription_introspection(response);
    assert_eq!(subs.len(), 2);

    let on_msg = subs.iter().find(|s| s.field_name == "onMessage").unwrap();
    assert_eq!(
        on_msg.discovery_method,
        SubscriptionDiscoveryMethod::Introspection
    );
    assert_eq!(on_msg.arguments.len(), 1);
    assert_eq!(on_msg.arguments[0].name, "channelId");
    assert_eq!(on_msg.return_fields.len(), 2);
    assert!(on_msg.return_fields.contains(&"id".to_string()));
    assert!(on_msg.return_fields.contains(&"content".to_string()));

    let on_notif = subs
        .iter()
        .find(|s| s.field_name == "onNotification")
        .unwrap();
    assert!(on_notif.arguments.is_empty());
}

#[test]
fn parse_introspection_handles_invalid_json() {
    let subs = parse_subscription_introspection("not json at all");
    assert!(subs.is_empty());
}

#[test]
fn parse_introspection_handles_missing_subscription_type() {
    let response = r#"{"data": {"__schema": {"subscriptionType": null}}}"#;
    let subs = parse_subscription_introspection(response);
    assert!(subs.is_empty());
}

#[test]
fn blind_probes_cover_all_enumeration_fields() {
    let probes = generate_blind_probes(&[]);
    assert_eq!(probes.len(), SUBSCRIPTION_ENUMERATION_FIELDS.len());
    for probe in &probes {
        assert!(probe.query.starts_with("subscription {"));
        assert!(probe.query.contains("__typename"));
        assert_eq!(probe.technique, SubscriptionDiscoveryMethod::BlindProbe);
    }
}

#[test]
fn blind_probes_include_additional_fields() {
    let probes = generate_blind_probes(&["customEvent", "anotherEvent"]);
    assert_eq!(probes.len(), SUBSCRIPTION_ENUMERATION_FIELDS.len() + 2);
    let custom_count = probes
        .iter()
        .filter(|p| p.target_field == "customEvent")
        .count();
    assert_eq!(custom_count, 1);
}

#[test]
fn suggestion_probes_use_misspelled_names() {
    let probes = generate_suggestion_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(
            probe.technique,
            SubscriptionDiscoveryMethod::FieldSuggestion
        );
        assert!(probe.query.contains("subscription"));
    }
}

#[test]
fn enumerate_subscriptions_combines_all_methods() {
    let result = enumerate_subscriptions(None, &["extraField"]);
    assert!(!result.introspection_queries.is_empty());
    assert!(!result.blind_probes.is_empty());
    assert!(!result.suggestion_probes.is_empty());
    let extra = result
        .blind_probes
        .iter()
        .any(|p| p.target_field == "extraField");
    assert!(extra);
}

// ─── Authorization Bypass Tests ──────────────────────────────────────────────

#[test]
fn auth_bypass_generates_seven_token_variants() {
    let tests = generate_auth_bypass_tests("onMessage", "id __typename");
    assert_eq!(tests.len(), 7);

    let has_no_token = tests.iter().any(|t| t.token == AuthBypassToken::NoToken);
    let has_empty = tests.iter().any(|t| t.token == AuthBypassToken::EmptyToken);
    assert!(has_no_token);
    assert!(has_empty);

    let has_expired = tests
        .iter()
        .any(|t| matches!(t.token, AuthBypassToken::ExpiredToken(_)));
    let has_wrong_role = tests
        .iter()
        .any(|t| matches!(t.token, AuthBypassToken::WrongRole(_)));
    let has_wrong_tenant = tests
        .iter()
        .any(|t| matches!(t.token, AuthBypassToken::WrongTenant(_)));
    let has_malformed = tests
        .iter()
        .any(|t| matches!(t.token, AuthBypassToken::MalformedToken(_)));
    let has_tampered = tests
        .iter()
        .any(|t| matches!(t.token, AuthBypassToken::TamperedClaims(_)));
    assert!(has_expired);
    assert!(has_wrong_role);
    assert!(has_wrong_tenant);
    assert!(has_malformed);
    assert!(has_tampered);
}

#[test]
fn auth_bypass_queries_contain_target_field() {
    let tests = generate_auth_bypass_tests("onPayment", "amount currency");
    for test in &tests {
        assert!(test.query.contains("onPayment"));
        assert!(test.query.contains("amount"));
        assert_eq!(test.target_field, "onPayment");
    }
}

#[test]
fn auth_bypass_suite_scales_with_field_count() {
    let tests = generate_auth_bypass_suite(&["onMessage", "onOrder"]);
    assert_eq!(tests.len(), 14);
}

#[test]
fn auth_bypass_tampered_jwt_uses_alg_none() {
    let tests = generate_auth_bypass_tests("onEvent", "id");
    let tampered = tests
        .iter()
        .find(|t| matches!(t.token, AuthBypassToken::TamperedClaims(_)))
        .unwrap();
    if let AuthBypassToken::TamperedClaims(jwt) = &tampered.token {
        assert!(jwt.contains("eyJhbGciOiJub25lI"));
    }
}

// ─── Data Exfiltration Tests ─────────────────────────────────────────────────

#[test]
fn exfiltration_generates_four_techniques() {
    let subs = generate_exfiltration_subscriptions("onUserUpdate", &[]);
    assert_eq!(subs.len(), 4);

    let techniques: Vec<ExfiltrationTechnique> = subs.iter().map(|s| s.technique).collect();
    assert!(techniques.contains(&ExfiltrationTechnique::PassiveCollection));
    assert!(techniques.contains(&ExfiltrationTechnique::BroadFilter));
    assert!(techniques.contains(&ExfiltrationTechnique::SensitiveFieldRequest));
    assert!(techniques.contains(&ExfiltrationTechnique::CrossUserData));
}

#[test]
fn exfiltration_sensitive_probe_requests_credentials() {
    let subs = generate_exfiltration_subscriptions("onData", &[]);
    let sensitive = subs
        .iter()
        .find(|s| s.technique == ExfiltrationTechnique::SensitiveFieldRequest)
        .unwrap();
    assert!(sensitive.query.contains("password"));
    assert!(sensitive.query.contains("token"));
    assert!(sensitive.query.contains("apiKey"));
}

#[test]
fn exfiltration_uses_known_fields_when_provided() {
    let subs = generate_exfiltration_subscriptions("onEvent", &["customField", "secretData"]);
    let passive = subs
        .iter()
        .find(|s| s.technique == ExfiltrationTechnique::PassiveCollection)
        .unwrap();
    assert!(passive.query.contains("customField"));
    assert!(passive.query.contains("secretData"));
}

#[test]
fn exfiltration_cross_user_requests_role_and_permissions() {
    let subs = generate_exfiltration_subscriptions("onUpdate", &[]);
    let cross = subs
        .iter()
        .find(|s| s.technique == ExfiltrationTechnique::CrossUserData)
        .unwrap();
    assert!(cross.query.contains("role"));
    assert!(cross.query.contains("permissions"));
    assert!(cross.query.contains("email"));
}

// ─── Resource Exhaustion Tests ───────────────────────────────────────────────

#[test]
fn exhaustion_generates_four_techniques() {
    let payloads = generate_exhaustion_payloads(&["onMessage"], 32);
    assert_eq!(payloads.len(), 4);

    let techniques: Vec<ExhaustionTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&ExhaustionTechnique::ConnectionFlood));
    assert!(techniques.contains(&ExhaustionTechnique::FieldDiversification));
    assert!(techniques.contains(&ExhaustionTechnique::DeepSelectionExhaustion));
    assert!(techniques.contains(&ExhaustionTechnique::RapidCycling));
}

#[test]
fn exhaustion_caps_at_max_concurrent() {
    let payloads = generate_exhaustion_payloads(&["onMessage"], 10_000);
    let flood = payloads
        .iter()
        .find(|p| p.technique == ExhaustionTechnique::ConnectionFlood)
        .unwrap();
    assert_eq!(flood.concurrency, 256);
    assert_eq!(flood.queries.len(), 256);
}

#[test]
fn exhaustion_empty_fields_returns_empty() {
    let payloads = generate_exhaustion_payloads(&[], 32);
    assert!(payloads.is_empty());
}

#[test]
fn exhaustion_high_concurrency_rates_critical_impact() {
    let payloads = generate_exhaustion_payloads(&["onEvent"], 100);
    let flood = payloads
        .iter()
        .find(|p| p.technique == ExhaustionTechnique::ConnectionFlood)
        .unwrap();
    assert_eq!(flood.impact, ResourceImpact::Critical);
}

#[test]
fn exhaustion_deep_selection_caps_at_32_queries() {
    let payloads = generate_exhaustion_payloads(&["onMessage"], 100);
    let deep = payloads
        .iter()
        .find(|p| p.technique == ExhaustionTechnique::DeepSelectionExhaustion)
        .unwrap();
    assert!(deep.queries.len() <= 32);
    assert!(deep.queries[0].contains("edges"));
    assert!(deep.queries[0].contains("node"));
}

#[test]
fn exhaustion_field_diversification_cycles_fields() {
    let payloads = generate_exhaustion_payloads(&["fieldA", "fieldB"], 6);
    let diverse = payloads
        .iter()
        .find(|p| p.technique == ExhaustionTechnique::FieldDiversification)
        .unwrap();
    assert_eq!(diverse.queries.len(), 6);
    let a_count = diverse
        .queries
        .iter()
        .filter(|q| q.contains("fieldA"))
        .count();
    let b_count = diverse
        .queries
        .iter()
        .filter(|q| q.contains("fieldB"))
        .count();
    assert_eq!(a_count, 3);
    assert_eq!(b_count, 3);
}

// ─── Subscription Injection Tests ────────────────────────────────────────────

#[test]
fn injection_generates_payloads_for_default_args() {
    let payloads = generate_injection_payloads("onMessage", &[]);
    assert!(!payloads.is_empty());
    let default_args: Vec<&str> = payloads
        .iter()
        .map(|p| p.target_argument.as_str())
        .collect();
    assert!(default_args.contains(&"filter"));
    assert!(default_args.contains(&"where"));
}

#[test]
fn injection_generates_payloads_for_custom_args() {
    let payloads = generate_injection_payloads("onEvent", &["customArg"]);
    for p in &payloads {
        assert_eq!(p.target_argument, "customArg");
    }
}

#[test]
fn injection_classifies_sql_injection() {
    let payloads = generate_injection_payloads("onMsg", &["filter"]);
    let sql_injections: Vec<_> = payloads
        .iter()
        .filter(|p| p.injection_type == InjectionType::SqlInjection)
        .collect();
    assert!(!sql_injections.is_empty());
}

#[test]
fn injection_classifies_nosql_injection() {
    let payloads = generate_injection_payloads("onMsg", &["filter"]);
    let nosql: Vec<_> = payloads
        .iter()
        .filter(|p| p.injection_type == InjectionType::NoSqlInjection)
        .collect();
    assert!(!nosql.is_empty());
}

#[test]
fn injection_classifies_template_injection() {
    let payloads = generate_injection_payloads("onMsg", &["filter"]);
    let tmpl: Vec<_> = payloads
        .iter()
        .filter(|p| p.injection_type == InjectionType::TemplateInjection)
        .collect();
    assert!(!tmpl.is_empty());
}

#[test]
fn injection_classifies_xss() {
    let payloads = generate_injection_payloads("onMsg", &["filter"]);
    let xss: Vec<_> = payloads
        .iter()
        .filter(|p| p.injection_type == InjectionType::CrossSiteScripting)
        .collect();
    assert!(!xss.is_empty());
}

#[test]
fn injection_queries_are_valid_subscription_format() {
    let payloads = generate_injection_payloads("onEvent", &["input"]);
    for p in &payloads {
        assert!(p.query.starts_with("subscription {"));
        assert!(p.query.contains("onEvent"));
    }
}

// ─── Cross-Tenant Leakage Tests ──────────────────────────────────────────────

#[test]
fn cross_tenant_generates_probes_for_all_tenant_args() {
    let probes = generate_cross_tenant_probes("onUpdate", &[]);
    assert!(!probes.is_empty());
    let args: HashSet<&str> = probes.iter().map(|p| p.tenant_argument.as_str()).collect();
    assert!(args.contains("tenantId"));
    assert!(args.contains("orgId"));
    assert!(args.contains("workspaceId"));
}

#[test]
fn cross_tenant_uses_custom_args_when_provided() {
    let probes = generate_cross_tenant_probes("onEvent", &["myTenantArg"]);
    for p in &probes {
        assert_eq!(p.tenant_argument, "myTenantArg");
    }
}

#[test]
fn cross_tenant_includes_omitted_tenant_technique() {
    let probes = generate_cross_tenant_probes("onMsg", &["tenantId"]);
    let omitted = probes
        .iter()
        .filter(|p| p.technique == TenantLeakageTechnique::OmittedTenantId)
        .count();
    assert!(omitted >= 1);
}

#[test]
fn cross_tenant_includes_null_tenant_technique() {
    let probes = generate_cross_tenant_probes("onMsg", &["orgId"]);
    let null_probes = probes
        .iter()
        .filter(|p| p.technique == TenantLeakageTechnique::NullTenantId)
        .count();
    assert!(null_probes >= 1);
}

#[test]
fn cross_tenant_includes_wildcard_technique() {
    let probes = generate_cross_tenant_probes("onMsg", &["tenantId"]);
    let wildcards: Vec<_> = probes
        .iter()
        .filter(|p| p.technique == TenantLeakageTechnique::WildcardTenant)
        .collect();
    assert!(!wildcards.is_empty());
    assert!(wildcards.iter().any(|p| p.foreign_tenant_id == "*"));
}

// ─── Subscription Replay Tests ───────────────────────────────────────────────

#[test]
fn replay_generates_five_techniques() {
    let payloads = generate_replay_payloads("onMessage");
    assert_eq!(payloads.len(), 5);

    let techniques: Vec<ReplayTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&ReplayTechnique::ConnectionInitReplay));
    assert!(techniques.contains(&ReplayTechnique::SubscribeReplay));
    assert!(techniques.contains(&ReplayTechnique::SubscriptionIdTampering));
    assert!(techniques.contains(&ReplayTechnique::LateAuthRemoval));
    assert!(techniques.contains(&ReplayTechnique::OutOfOrderSubscribe));
}

#[test]
fn replay_connection_init_contains_auth_payload() {
    let payloads = generate_replay_payloads("onEvent");
    let init = payloads
        .iter()
        .find(|p| p.technique == ReplayTechnique::ConnectionInitReplay)
        .unwrap();
    assert!(init.message.contains("connection_init"));
    assert!(init.message.contains("authorization"));
}

#[test]
fn replay_subscribe_contains_query() {
    let payloads = generate_replay_payloads("onData");
    let sub = payloads
        .iter()
        .find(|p| p.technique == ReplayTechnique::SubscribeReplay)
        .unwrap();
    assert!(sub.message.contains("subscribe"));
    assert!(sub.message.contains("onData"));
}

#[test]
fn replay_id_tampering_uses_hijacked_id() {
    let payloads = generate_replay_payloads("onMsg");
    let tamper = payloads
        .iter()
        .find(|p| p.technique == ReplayTechnique::SubscriptionIdTampering)
        .unwrap();
    assert!(tamper.message.contains("hijacked-session-id"));
}

// ─── Aggregate Engine Tests ──────────────────────────────────────────────────

#[test]
fn aggregate_engine_runs_all_modules() {
    let config = SubscriptionAbuseConfig::default();
    let result = run_subscription_abuse_engine(&config, None, &["onMessage", "onOrder"]);

    assert!(!result.enumeration.blind_probes.is_empty());
    assert!(!result.auth_bypass_tests.is_empty());
    assert!(!result.exfiltration_subs.is_empty());
    assert!(!result.exhaustion_payloads.is_empty());
    assert!(!result.injection_payloads.is_empty());
    assert!(!result.cross_tenant_probes.is_empty());
    assert!(!result.replay_payloads.is_empty());
    assert!(result.total_payload_count > 0);
}

#[test]
fn aggregate_engine_all_disabled() {
    let config = SubscriptionAbuseConfig {
        enable_enumeration: false,
        enable_auth_bypass: false,
        enable_exfiltration: false,
        enable_exhaustion: false,
        enable_injection: false,
        enable_cross_tenant: false,
        enable_replay: false,
        exhaustion_concurrency: 0,
    };
    let result = run_subscription_abuse_engine(&config, None, &[]);
    assert!(result.auth_bypass_tests.is_empty());
    assert!(result.exfiltration_subs.is_empty());
    assert!(result.exhaustion_payloads.is_empty());
    assert!(result.injection_payloads.is_empty());
    assert!(result.cross_tenant_probes.is_empty());
    assert!(result.replay_payloads.is_empty());
}

#[test]
fn aggregate_engine_with_introspection_data() {
    let introspection = r#"{
        "data": {
            "__schema": {
                "subscriptionType": {
                    "name": "Subscription",
                    "fields": [
                        {
                            "name": "liveChat",
                            "args": [{ "name": "roomId", "type": { "name": "ID", "kind": "NON_NULL" } }],
                            "type": { "name": "ChatMessage", "kind": "OBJECT" }
                        }
                    ]
                }
            }
        }
    }"#;

    let config = SubscriptionAbuseConfig::default();
    let result = run_subscription_abuse_engine(&config, Some(introspection), &[]);

    assert_eq!(result.enumeration.subscriptions.len(), 1);
    assert_eq!(result.enumeration.subscriptions[0].field_name, "liveChat");
    assert!(result.enumeration.subscriptions[0].arguments[0].required);
}

#[test]
fn total_payload_count_is_consistent() {
    let config = SubscriptionAbuseConfig {
        enable_enumeration: true,
        enable_auth_bypass: true,
        enable_exfiltration: false,
        enable_exhaustion: false,
        enable_injection: false,
        enable_cross_tenant: false,
        enable_replay: false,
        exhaustion_concurrency: 0,
    };
    let result = run_subscription_abuse_engine(&config, None, &["onTest"]);

    let manual_count = result.auth_bypass_tests.len()
        + result.enumeration.blind_probes.len()
        + result.enumeration.suggestion_probes.len();
    assert_eq!(result.total_payload_count, manual_count);
}

use std::collections::HashSet;
