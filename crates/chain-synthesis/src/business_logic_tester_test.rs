use crate::business_logic_tester::{
    BusinessLogicProbe, FlawSeverity, LogicFlawType, ObservedRequest, StateMachineInferer,
};

fn checkout_sequence() -> Vec<ObservedRequest> {
    vec![
        ObservedRequest {
            method: "GET".into(),
            path: "/products".into(),
            parameters: vec![],
            status_code: 200,
            requires_auth: false,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/cart/add".into(),
            parameters: vec!["product_id".into(), "quantity".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "GET".into(),
            path: "/cart".into(),
            parameters: vec![],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/checkout".into(),
            parameters: vec!["cart_id".into(), "coupon_code".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/payment".into(),
            parameters: vec!["amount".into(), "order_id".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "GET".into(),
            path: "/confirmation".into(),
            parameters: vec!["order_id".into()],
            status_code: 200,
            requires_auth: true,
        },
    ]
}

fn admin_sequence() -> Vec<ObservedRequest> {
    vec![
        ObservedRequest {
            method: "POST".into(),
            path: "/login".into(),
            parameters: vec!["username".into(), "password".into()],
            status_code: 200,
            requires_auth: false,
        },
        ObservedRequest {
            method: "GET".into(),
            path: "/admin/dashboard".into(),
            parameters: vec![],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/admin/users".into(),
            parameters: vec!["user_id".into(), "role".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "DELETE".into(),
            path: "/admin/users".into(),
            parameters: vec!["user_id".into()],
            status_code: 200,
            requires_auth: true,
        },
    ]
}

fn refund_sequence() -> Vec<ObservedRequest> {
    vec![
        ObservedRequest {
            method: "GET".into(),
            path: "/products".into(),
            parameters: vec![],
            status_code: 200,
            requires_auth: false,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/purchase".into(),
            parameters: vec!["product_id".into(), "price".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/refund".into(),
            parameters: vec!["order_id".into()],
            status_code: 200,
            requires_auth: true,
        },
    ]
}

fn discount_sequence() -> Vec<ObservedRequest> {
    vec![
        ObservedRequest {
            method: "GET".into(),
            path: "/shop".into(),
            parameters: vec![],
            status_code: 200,
            requires_auth: false,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/apply-discount".into(),
            parameters: vec!["discount".into(), "item_id".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/pay".into(),
            parameters: vec!["total".into()],
            status_code: 200,
            requires_auth: true,
        },
    ]
}

fn inventory_sequence() -> Vec<ObservedRequest> {
    vec![
        ObservedRequest {
            method: "GET".into(),
            path: "/inventory".into(),
            parameters: vec!["item_id".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "POST".into(),
            path: "/inventory/update".into(),
            parameters: vec!["item_id".into(), "qty".into(), "unit_price".into()],
            status_code: 200,
            requires_auth: true,
        },
        ObservedRequest {
            method: "GET".into(),
            path: "/inventory/report".into(),
            parameters: vec![],
            status_code: 200,
            requires_auth: true,
        },
    ]
}

// ─── StateMachineInferer tests ───────────────────────────────────────────

#[test]
fn infer_states_from_checkout_sequence() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    assert_eq!(inferer.state_count(), 6);
}

#[test]
fn infer_transitions_from_checkout_sequence() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    assert_eq!(inferer.transition_count(), 5);
}

#[test]
fn infer_from_empty_sequence() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&[]);
    assert_eq!(inferer.state_count(), 0);
    assert_eq!(inferer.transition_count(), 0);
}

#[test]
fn infer_single_request_sequence() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&[ObservedRequest {
        method: "GET".into(),
        path: "/index".into(),
        parameters: vec![],
        status_code: 200,
        requires_auth: false,
    }]);
    assert_eq!(inferer.state_count(), 1);
    assert_eq!(inferer.transition_count(), 0);
}

#[test]
fn detect_skip_attacks_in_checkout() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    let skips = inferer.detect_skip_attacks();
    assert!(
        !skips.is_empty(),
        "should detect skip attacks in a 6-step flow"
    );
    let products_to_payment = skips
        .iter()
        .any(|s| s.from_state.contains("/products") && s.to_state.contains("/payment"));
    assert!(
        products_to_payment,
        "should detect skip from products to payment"
    );
}

#[test]
fn skip_attacks_include_skipped_states() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    let skips = inferer.detect_skip_attacks();
    for skip in &skips {
        assert!(
            !skip.skipped_states.is_empty(),
            "every skip attack must have at least one skipped state"
        );
    }
}

#[test]
fn entry_states_detected() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    let entries = inferer.entry_states();
    assert!(
        entries.iter().any(|e| e.contains("/products")),
        "GET:/products should be an entry state"
    );
}

#[test]
fn terminal_states_detected() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    let terminals = inferer.terminal_states();
    assert!(
        terminals.iter().any(|t| t.contains("/confirmation")),
        "GET:/confirmation should be a terminal state"
    );
}

#[test]
fn get_state_returns_node() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    let state = inferer.get_state("POST:/payment");
    assert!(state.is_some());
    assert_eq!(state.unwrap().endpoint, "/payment");
}

#[test]
fn get_state_returns_none_for_missing() {
    let inferer = StateMachineInferer::new();
    assert!(inferer.get_state("GET:/nonexistent").is_none());
}

#[test]
fn duplicate_ingestion_increments_observation_count() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    inferer.ingest_sequence(&seq);
    // State count stays the same — no duplicate nodes
    assert_eq!(inferer.state_count(), 6);
    // Transition count stays the same — edges are reused
    assert_eq!(inferer.transition_count(), 5);
}

#[test]
fn infer_admin_sequence() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&admin_sequence());
    assert_eq!(inferer.state_count(), 4);
    assert_eq!(inferer.transition_count(), 3);
}

#[test]
fn inner_graph_accessible() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    let g = inferer.inner_graph();
    assert_eq!(g.node_count(), 6);
    assert_eq!(g.edge_count(), 5);
}

#[test]
fn multiple_sequences_merge_states() {
    let mut inferer = StateMachineInferer::new();
    inferer.ingest_sequence(&checkout_sequence());
    inferer.ingest_sequence(&refund_sequence());
    // /products is shared but counted once; total unique states
    let states = inferer.states();
    assert!(
        states.len() >= 8,
        "should have >=8 unique states from two sequences"
    );
}

// ─── BusinessLogicProbe tests ────────────────────────────────────────────

#[test]
fn analyze_detects_skip_flaws() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    let flaws = BusinessLogicProbe::analyze(&inferer, &seq);
    let skip_flaws: Vec<_> = flaws
        .iter()
        .filter(|f| f.flaw_type == LogicFlawType::WorkflowSkip)
        .collect();
    assert!(!skip_flaws.is_empty(), "should detect workflow skip flaws");
}

#[test]
fn analyze_detects_manipulation_flaws() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    let flaws = BusinessLogicProbe::analyze(&inferer, &seq);
    let manipulation_flaws: Vec<_> = flaws
        .iter()
        .filter(|f| {
            matches!(
                f.flaw_type,
                LogicFlawType::PriceManipulation
                    | LogicFlawType::NegativeValue
                    | LogicFlawType::ZeroValue
                    | LogicFlawType::QuantityManipulation
                    | LogicFlawType::ParameterOverflow
            )
        })
        .collect();
    assert!(
        !manipulation_flaws.is_empty(),
        "should detect manipulation flaws"
    );
}

#[test]
fn analyze_detects_idor_flaws() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    let flaws = BusinessLogicProbe::analyze(&inferer, &seq);
    let idor_flaws: Vec<_> = flaws
        .iter()
        .filter(|f| f.flaw_type == LogicFlawType::Idor)
        .collect();
    assert!(!idor_flaws.is_empty(), "should detect IDOR flaws");
}

#[test]
fn skip_flaws_have_high_severity() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    let flaws = BusinessLogicProbe::detect_skip_flaws(&inferer);
    for flaw in &flaws {
        assert_eq!(flaw.severity, FlawSeverity::High);
    }
}

#[test]
fn manipulation_probes_have_correct_values() {
    let seq = checkout_sequence();
    let flaws = BusinessLogicProbe::detect_manipulation_flaws(&seq);
    let negative = flaws
        .iter()
        .find(|f| f.flaw_type == LogicFlawType::NegativeValue && f.affected_endpoint == "/payment");
    assert!(
        negative.is_some(),
        "should detect negative value on /payment"
    );
    let probe = &negative.unwrap().probe;
    assert_eq!(probe.manipulated_parameters.get("amount").unwrap(), "-1");
}

#[test]
fn idor_probes_target_id_parameters() {
    let seq = checkout_sequence();
    let flaws = BusinessLogicProbe::detect_idor_flaws(&seq);
    for flaw in &flaws {
        assert!(!flaw.probe.manipulated_parameters.is_empty());
        let has_id_param = flaw
            .probe
            .manipulated_parameters
            .keys()
            .any(|k| k.to_lowercase().contains("id"));
        assert!(
            has_id_param,
            "IDOR probe should target an id-like parameter"
        );
    }
}

#[test]
fn coupon_stacking_detected() {
    let seq = checkout_sequence();
    let flaws = BusinessLogicProbe::detect_coupon_stacking(&seq);
    assert!(!flaws.is_empty(), "checkout sequence has coupon_code param");
    assert_eq!(flaws[0].flaw_type, LogicFlawType::CouponStacking);
}

#[test]
fn coupon_stacking_not_detected_without_coupon() {
    let seq = admin_sequence();
    let flaws = BusinessLogicProbe::detect_coupon_stacking(&seq);
    assert!(flaws.is_empty(), "admin sequence has no coupon params");
}

#[test]
fn refund_cycle_detected() {
    let seq = refund_sequence();
    let flaws = BusinessLogicProbe::detect_refund_cycle(&seq);
    assert!(!flaws.is_empty(), "refund+purchase = refund cycle");
    assert_eq!(flaws[0].flaw_type, LogicFlawType::RefundCycleAbuse);
    assert_eq!(flaws[0].severity, FlawSeverity::Critical);
}

#[test]
fn refund_cycle_not_detected_without_purchase() {
    let seq = vec![ObservedRequest {
        method: "POST".into(),
        path: "/refund".into(),
        parameters: vec!["order_id".into()],
        status_code: 200,
        requires_auth: true,
    }];
    let flaws = BusinessLogicProbe::detect_refund_cycle(&seq);
    assert!(flaws.is_empty(), "no purchase endpoint → no refund cycle");
}

#[test]
fn discount_manipulation_detected() {
    let seq = discount_sequence();
    let flaws = BusinessLogicProbe::detect_manipulation_flaws(&seq);
    let discount_100 = flaws.iter().any(|f| {
        f.affected_endpoint == "/apply-discount"
            && f.probe.manipulated_parameters.get("discount") == Some(&"100".to_string())
    });
    assert!(discount_100, "should generate 100% discount probe");
}

#[test]
fn inventory_qty_manipulation_detected() {
    let seq = inventory_sequence();
    let flaws = BusinessLogicProbe::detect_manipulation_flaws(&seq);
    let overflow = flaws.iter().any(|f| {
        f.flaw_type == LogicFlawType::ParameterOverflow
            && f.affected_endpoint == "/inventory/update"
    });
    assert!(overflow, "should detect overflow on qty param");
}

#[test]
fn all_probes_have_non_empty_fields() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    let flaws = BusinessLogicProbe::analyze(&inferer, &seq);
    for flaw in &flaws {
        assert!(!flaw.description.is_empty());
        assert!(!flaw.affected_endpoint.is_empty());
        assert!(!flaw.probe.method.is_empty());
        assert!(!flaw.probe.path.is_empty());
        assert!(!flaw.probe.description.is_empty());
        assert!(!flaw.probe.expected_behavior.is_empty());
    }
}

#[test]
fn at_least_three_flaw_types_detected_in_checkout() {
    let mut inferer = StateMachineInferer::new();
    let seq = checkout_sequence();
    inferer.ingest_sequence(&seq);
    let flaws = BusinessLogicProbe::analyze(&inferer, &seq);
    let flaw_types: std::collections::HashSet<_> = flaws.iter().map(|f| f.flaw_type).collect();
    assert!(
        flaw_types.len() >= 3,
        "should detect at least 3 distinct flaw types, got: {:?}",
        flaw_types
    );
}

#[test]
fn flaw_severity_display() {
    assert_eq!(format!("{}", FlawSeverity::Low), "low");
    assert_eq!(format!("{}", FlawSeverity::Medium), "medium");
    assert_eq!(format!("{}", FlawSeverity::High), "high");
    assert_eq!(format!("{}", FlawSeverity::Critical), "critical");
}

#[test]
fn flaw_type_display() {
    assert_eq!(format!("{}", LogicFlawType::WorkflowSkip), "workflow-skip");
    assert_eq!(format!("{}", LogicFlawType::Idor), "idor");
    assert_eq!(
        format!("{}", LogicFlawType::CouponStacking),
        "coupon-stacking"
    );
    assert_eq!(
        format!("{}", LogicFlawType::RefundCycleAbuse),
        "refund-cycle-abuse"
    );
}

#[test]
fn flaw_severity_ordering() {
    assert!(FlawSeverity::Low < FlawSeverity::Medium);
    assert!(FlawSeverity::Medium < FlawSeverity::High);
    assert!(FlawSeverity::High < FlawSeverity::Critical);
}

#[test]
fn default_inferer() {
    let inferer = StateMachineInferer::default();
    assert_eq!(inferer.state_count(), 0);
}

#[test]
fn five_fixture_sequences_all_infer() {
    let sequences = vec![
        checkout_sequence(),
        admin_sequence(),
        refund_sequence(),
        discount_sequence(),
        inventory_sequence(),
    ];
    for (i, seq) in sequences.iter().enumerate() {
        let mut inferer = StateMachineInferer::new();
        inferer.ingest_sequence(seq);
        assert!(
            inferer.state_count() >= 2,
            "sequence {} should produce at least 2 states",
            i
        );
    }
}
