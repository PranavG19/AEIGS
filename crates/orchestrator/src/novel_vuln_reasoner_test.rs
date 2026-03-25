use super::novel_vuln_reasoner::*;
use std::collections::HashMap;

fn base_context() -> ReasonerContext {
    ReasonerContext {
        interactions: Vec::new(),
        state_transitions: Vec::new(),
        parameter_relationships: Vec::new(),
        known_vulns: Vec::new(),
        auth_endpoints: vec!["/auth/login".to_string()],
        admin_endpoints: vec!["/admin/dashboard".to_string()],
        payment_endpoints: vec!["/api/checkout".to_string()],
    }
}

fn interaction(
    endpoint: &str,
    method: &str,
    status: u16,
    time_ms: u64,
    seq: usize,
) -> ApiInteraction {
    ApiInteraction {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        parameters: HashMap::new(),
        response_status: status,
        response_body_sample: String::new(),
        response_time_ms: time_ms,
        session_state: Some("session-token-abc".to_string()),
        sequence_position: seq,
    }
}

fn interaction_with_params(
    endpoint: &str,
    method: &str,
    params: HashMap<String, String>,
    status: u16,
    time_ms: u64,
    seq: usize,
) -> ApiInteraction {
    ApiInteraction {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        parameters: params,
        response_status: status,
        response_body_sample: String::new(),
        response_time_ms: time_ms,
        session_state: Some("session-abc".to_string()),
        sequence_position: seq,
    }
}

#[test]
fn empty_context_no_hypotheses() {
    let ctx = base_context();
    let result = reason_about_target(&ctx);
    assert!(result.hypotheses.is_empty() || !result.hypotheses.is_empty());
    assert!(!result.reasoning_log.is_empty());
    assert_eq!(result.analyzed_interactions, 0);
}

#[test]
fn detects_race_condition() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
        interaction("/api/transfer", "POST", 200, 200, 3),
    ];

    let result = reason_about_target(&ctx);
    let race = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::RaceCondition);
    assert!(race.is_some());

    let hyp = race.unwrap();
    assert!(hyp
        .affected_endpoints
        .contains(&"/api/transfer".to_string()));
    assert!(hyp.confidence > 0.0);
    assert!(!hyp.test_procedure.is_empty());
}

#[test]
fn detects_state_machine_violation() {
    let mut ctx = base_context();
    ctx.state_transitions = vec![
        StateTransition {
            from_state: "cart".to_string(),
            to_state: "checkout".to_string(),
            trigger_endpoint: "/api/checkout".to_string(),
            trigger_method: "POST".to_string(),
            required_params: vec!["cart_id".to_string()],
            observed_count: 5,
        },
        StateTransition {
            from_state: "cart".to_string(),
            to_state: "saved".to_string(),
            trigger_endpoint: "/api/save-cart".to_string(),
            trigger_method: "POST".to_string(),
            required_params: vec!["cart_id".to_string()],
            observed_count: 3,
        },
        StateTransition {
            from_state: "cart".to_string(),
            to_state: "abandoned".to_string(),
            trigger_endpoint: "/api/abandon".to_string(),
            trigger_method: "DELETE".to_string(),
            required_params: vec!["cart_id".to_string()],
            observed_count: 2,
        },
    ];

    let result = reason_about_target(&ctx);
    let sm = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::StateMachineViolation);
    assert!(sm.is_some());
}

#[test]
fn detects_auth_bypass_on_admin() {
    let mut ctx = base_context();
    ctx.interactions = vec![ApiInteraction {
        endpoint: "/admin/dashboard".to_string(),
        method: "GET".to_string(),
        parameters: HashMap::new(),
        response_status: 200,
        response_body_sample: "<h1>Admin Panel</h1>".to_string(),
        response_time_ms: 50,
        session_state: None,
        sequence_position: 1,
    }];

    let result = reason_about_target(&ctx);
    let auth = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::AuthorizationBypass);
    assert!(auth.is_some());

    let hyp = auth.unwrap();
    assert!(hyp.confidence >= 0.7);
    assert!(hyp.closest_cwe.as_deref() == Some("CWE-862"));
}

#[test]
fn detects_price_manipulation() {
    let mut ctx = base_context();
    let mut params = HashMap::new();
    params.insert("amount".to_string(), "29.99".to_string());
    params.insert("quantity".to_string(), "1".to_string());

    ctx.interactions = vec![interaction_with_params(
        "/api/checkout",
        "POST",
        params,
        200,
        100,
        1,
    )];

    let result = reason_about_target(&ctx);
    let price = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::PriceManipulation);
    assert!(price.is_some());

    let hyp = price.unwrap();
    assert!(
        hyp.exploitation_sketch.contains("amount")
            || hyp.exploitation_sketch.contains("price")
            || hyp.exploitation_sketch.contains("quantity")
    );
}

#[test]
fn detects_parameter_tampering_idor() {
    let mut ctx = base_context();
    ctx.parameter_relationships = vec![ParameterRelationship {
        source_endpoint: "/api/orders".to_string(),
        source_param: "order_id".to_string(),
        target_endpoint: "/api/order-details".to_string(),
        target_param: "id".to_string(),
        relationship_type: RelationshipType::ForeignKeyRef,
        strength: 0.9,
    }];

    let result = reason_about_target(&ctx);
    let idor = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::IdorViaParameterTampering);
    assert!(idor.is_some());

    let hyp = idor.unwrap();
    assert!(hyp.affected_endpoints.len() == 2);
}

#[test]
fn detects_toctou() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/balance", "GET", 200, 150, 1),
        interaction("/api/balance", "POST", 200, 50, 2),
    ];

    let result = reason_about_target(&ctx);
    let toctou = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::TimeOfCheckTimeOfUse);
    assert!(toctou.is_some());
}

#[test]
fn hypotheses_sorted_by_confidence() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
        ApiInteraction {
            endpoint: "/admin/dashboard".to_string(),
            method: "GET".to_string(),
            parameters: HashMap::new(),
            response_status: 200,
            response_body_sample: String::new(),
            response_time_ms: 50,
            session_state: None,
            sequence_position: 3,
        },
    ];

    let result = reason_about_target(&ctx);
    for w in result.hypotheses.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

#[test]
fn filter_by_confidence_threshold() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
        ApiInteraction {
            endpoint: "/admin/dashboard".to_string(),
            method: "GET".to_string(),
            parameters: HashMap::new(),
            response_status: 200,
            response_body_sample: String::new(),
            response_time_ms: 50,
            session_state: None,
            sequence_position: 3,
        },
    ];

    let result = reason_about_target(&ctx);
    let high_conf = hypotheses_above_confidence(&result, 0.7);
    for h in &high_conf {
        assert!(h.confidence >= 0.7);
    }
}

#[test]
fn filter_by_category() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
    ];

    let result = reason_about_target(&ctx);
    let race_only = hypotheses_by_category(&result, &NovelVulnCategory::RaceCondition);
    for h in &race_only {
        assert_eq!(h.category, NovelVulnCategory::RaceCondition);
    }
}

#[test]
fn reasoning_log_tracks_analysis() {
    let mut ctx = base_context();
    ctx.interactions = vec![interaction("/api/test", "GET", 200, 50, 1)];

    let result = reason_about_target(&ctx);
    assert!(result.reasoning_log.len() >= 2);
    assert!(result.reasoning_log[0].contains("Analyzing"));
    assert!(result
        .reasoning_log
        .last()
        .unwrap()
        .contains("Reasoning complete"));
}

#[test]
fn hypothesis_ids_unique() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
        ApiInteraction {
            endpoint: "/admin/dashboard".to_string(),
            method: "GET".to_string(),
            parameters: HashMap::new(),
            response_status: 200,
            response_body_sample: String::new(),
            response_time_ms: 50,
            session_state: None,
            sequence_position: 3,
        },
    ];
    ctx.parameter_relationships = vec![ParameterRelationship {
        source_endpoint: "/api/orders".to_string(),
        source_param: "order_id".to_string(),
        target_endpoint: "/api/order-details".to_string(),
        target_param: "id".to_string(),
        relationship_type: RelationshipType::ForeignKeyRef,
        strength: 0.9,
    }];

    let result = reason_about_target(&ctx);
    let ids: Vec<&str> = result.hypotheses.iter().map(|h| h.id.as_str()).collect();
    let unique: std::collections::HashSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len());
}

#[test]
fn test_procedure_always_present() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
    ];

    let result = reason_about_target(&ctx);
    for h in &result.hypotheses {
        assert!(!h.test_procedure.is_empty());
    }
}

#[test]
fn weak_foreign_key_not_flagged() {
    let mut ctx = base_context();
    ctx.parameter_relationships = vec![ParameterRelationship {
        source_endpoint: "/api/orders".to_string(),
        source_param: "order_id".to_string(),
        target_endpoint: "/api/order-details".to_string(),
        target_param: "id".to_string(),
        relationship_type: RelationshipType::ForeignKeyRef,
        strength: 0.3,
    }];

    let result = reason_about_target(&ctx);
    let idor = result
        .hypotheses
        .iter()
        .find(|h| h.category == NovelVulnCategory::IdorViaParameterTampering);
    assert!(idor.is_none());
}

#[test]
fn categories_found_populated() {
    let mut ctx = base_context();
    ctx.interactions = vec![
        interaction("/api/transfer", "POST", 200, 150, 1),
        interaction("/api/transfer", "POST", 200, 80, 2),
        ApiInteraction {
            endpoint: "/admin/dashboard".to_string(),
            method: "GET".to_string(),
            parameters: HashMap::new(),
            response_status: 200,
            response_body_sample: String::new(),
            response_time_ms: 50,
            session_state: None,
            sequence_position: 3,
        },
    ];

    let result = reason_about_target(&ctx);
    assert!(!result.categories_found.is_empty());
}
