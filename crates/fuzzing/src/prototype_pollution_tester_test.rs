use crate::prototype_pollution_tester::*;

fn baseline_response() -> ResponseSnapshot {
    ResponseSnapshot {
        status_code: 200,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("x-request-id".into(), "abc123".into()),
        ],
        body: r#"{"success": true, "user": "guest"}"#.into(),
    }
}

// =========================================================
// Payload generation tests
// =========================================================

#[test]
fn generates_at_least_15_payloads() {
    let payloads = PrototypePollutionTester::generate_payloads();
    assert!(
        payloads.len() >= 15,
        "Expected >=15 payloads, got {}",
        payloads.len()
    );
}

#[test]
fn payloads_cover_at_least_3_injection_patterns() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let mut seen = std::collections::HashSet::new();
    for p in &payloads {
        seen.insert(p.pattern);
    }
    assert!(
        seen.len() >= 3,
        "Expected >=3 distinct patterns, got {}",
        seen.len()
    );
}

#[test]
fn payloads_cover_all_5_patterns() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let seen: std::collections::HashSet<_> = payloads.iter().map(|p| p.pattern).collect();
    for pattern in InjectionPattern::all() {
        assert!(seen.contains(pattern), "Missing pattern: {:?}", pattern);
    }
}

#[test]
fn all_payloads_have_valid_json_or_bracket_notation() {
    let payloads = PrototypePollutionTester::generate_payloads();
    for p in &payloads {
        assert!(!p.json_body.is_empty(), "Payload body is empty");
        assert!(
            p.json_body.starts_with('{'),
            "Payload should start with '{{': {}",
            p.json_body
        );
    }
}

#[test]
fn each_payload_has_description_and_keys() {
    let payloads = PrototypePollutionTester::generate_payloads();
    for p in &payloads {
        assert!(!p.description.is_empty());
        assert!(!p.polluted_key.is_empty());
    }
}

#[test]
fn direct_proto_payloads_contain_proto_key() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let direct: Vec<_> = payloads
        .iter()
        .filter(|p| p.pattern == InjectionPattern::DirectProto)
        .collect();
    assert!(!direct.is_empty());
    for p in &direct {
        assert!(
            p.json_body.contains("__proto__"),
            "DirectProto payload missing __proto__: {}",
            p.json_body
        );
    }
}

#[test]
fn constructor_payloads_contain_constructor_prototype() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let ctor: Vec<_> = payloads
        .iter()
        .filter(|p| p.pattern == InjectionPattern::ConstructorPrototype)
        .collect();
    assert!(!ctor.is_empty());
    for p in &ctor {
        assert!(
            p.json_body.contains("constructor") && p.json_body.contains("prototype"),
            "ConstructorPrototype payload missing keys: {}",
            p.json_body
        );
    }
}

#[test]
fn nested_merge_payloads_have_depth() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let nested: Vec<_> = payloads
        .iter()
        .filter(|p| p.pattern == InjectionPattern::NestedMerge)
        .collect();
    assert!(nested.len() >= 2, "Expected >=2 nested merge payloads");
}

// =========================================================
// Method filtering tests
// =========================================================

#[test]
fn payloads_for_get_returns_empty() {
    let payloads = PrototypePollutionTester::payloads_for_method("GET");
    assert!(payloads.is_empty());
}

#[test]
fn payloads_for_post_returns_all() {
    let all = PrototypePollutionTester::generate_payloads();
    let post = PrototypePollutionTester::payloads_for_method("POST");
    assert_eq!(all.len(), post.len());
}

#[test]
fn payloads_for_put_returns_all() {
    let put = PrototypePollutionTester::payloads_for_method("PUT");
    assert!(!put.is_empty());
}

#[test]
fn payloads_for_patch_returns_all() {
    let patch = PrototypePollutionTester::payloads_for_method("patch");
    assert!(!patch.is_empty());
}

// =========================================================
// Diff analysis tests
// =========================================================

#[test]
fn diff_detects_status_change() {
    let baseline = baseline_response();
    let polluted = ResponseSnapshot {
        status_code: 500,
        ..baseline.clone()
    };
    let diff = PrototypePollutionTester::analyze_diff(&baseline, &polluted);
    assert!(diff.status_changed);
    assert_eq!(diff.baseline_status, 200);
    assert_eq!(diff.polluted_status, 500);
}

#[test]
fn diff_detects_new_headers() {
    let baseline = baseline_response();
    let mut polluted = baseline.clone();
    polluted.headers.push(("x-polluted".into(), "true".into()));
    let diff = PrototypePollutionTester::analyze_diff(&baseline, &polluted);
    assert!(!diff.new_headers.is_empty());
    assert!(diff.new_headers.iter().any(|(k, _)| k == "x-polluted"));
}

#[test]
fn diff_detects_removed_headers() {
    let baseline = baseline_response();
    let polluted = ResponseSnapshot {
        headers: vec![("content-type".into(), "application/json".into())],
        ..baseline.clone()
    };
    let diff = PrototypePollutionTester::analyze_diff(&baseline, &polluted);
    assert!(diff.removed_headers.iter().any(|h| h == "x-request-id"));
}

#[test]
fn diff_detects_body_change() {
    let baseline = baseline_response();
    let polluted = ResponseSnapshot {
        body: r#"{"success": true, "user": "guest", "isAdmin": true}"#.into(),
        ..baseline.clone()
    };
    let diff = PrototypePollutionTester::analyze_diff(&baseline, &polluted);
    assert!(diff.body_content_changed);
    assert!(diff.body_length_delta > 0);
}

#[test]
fn diff_captures_new_body_tokens() {
    let baseline = baseline_response();
    let polluted = ResponseSnapshot {
        body: r#"{"success": true, "user": "guest", "isAdmin": true}"#.into(),
        ..baseline.clone()
    };
    let diff = PrototypePollutionTester::analyze_diff(&baseline, &polluted);
    assert!(diff.new_body_tokens.iter().any(|t| t.contains("isAdmin")));
}

#[test]
fn identical_responses_produce_clean_diff() {
    let baseline = baseline_response();
    let diff = PrototypePollutionTester::analyze_diff(&baseline, &baseline);
    assert!(!diff.status_changed);
    assert!(!diff.body_content_changed);
    assert!(diff.new_headers.is_empty());
    assert!(diff.removed_headers.is_empty());
    assert_eq!(diff.body_length_delta, 0);
}

// =========================================================
// Pollution detection tests
// =========================================================

#[test]
fn pollution_detected_on_status_change() {
    let payload = &PrototypePollutionTester::generate_payloads()[0];
    let diff = ResponseDiff {
        status_changed: true,
        baseline_status: 200,
        polluted_status: 500,
        new_headers: vec![],
        removed_headers: vec![],
        body_length_delta: 0,
        body_content_changed: false,
        new_body_tokens: vec![],
    };
    assert!(PrototypePollutionTester::is_pollution_detected(
        &diff, payload
    ));
}

#[test]
fn pollution_detected_on_new_headers() {
    let payload = &PrototypePollutionTester::generate_payloads()[0];
    let diff = ResponseDiff {
        status_changed: false,
        baseline_status: 200,
        polluted_status: 200,
        new_headers: vec![("x-polluted".into(), "true".into())],
        removed_headers: vec![],
        body_length_delta: 0,
        body_content_changed: false,
        new_body_tokens: vec![],
    };
    assert!(PrototypePollutionTester::is_pollution_detected(
        &diff, payload
    ));
}

#[test]
fn pollution_detected_on_body_token_match() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let canary = payloads
        .iter()
        .find(|p| p.polluted_key == "aegis_pp_canary")
        .unwrap();
    let diff = ResponseDiff {
        status_changed: false,
        baseline_status: 200,
        polluted_status: 200,
        new_headers: vec![],
        removed_headers: vec![],
        body_length_delta: 30,
        body_content_changed: true,
        new_body_tokens: vec!["aegis_pp_canary".into(), "polluted_42".into()],
    };
    assert!(PrototypePollutionTester::is_pollution_detected(
        &diff, canary
    ));
}

#[test]
fn no_pollution_on_clean_diff() {
    let payload = &PrototypePollutionTester::generate_payloads()[0];
    let diff = ResponseDiff {
        status_changed: false,
        baseline_status: 200,
        polluted_status: 200,
        new_headers: vec![],
        removed_headers: vec![],
        body_length_delta: 0,
        body_content_changed: false,
        new_body_tokens: vec![],
    };
    assert!(!PrototypePollutionTester::is_pollution_detected(
        &diff, payload
    ));
}

// =========================================================
// Severity scoring tests
// =========================================================

#[test]
fn severity_increases_on_status_change() {
    let payload = &PrototypePollutionTester::generate_payloads()[0];
    let base_diff = ResponseDiff {
        status_changed: false,
        baseline_status: 200,
        polluted_status: 200,
        new_headers: vec![],
        removed_headers: vec![],
        body_length_delta: 0,
        body_content_changed: false,
        new_body_tokens: vec![],
    };
    let status_diff = ResponseDiff {
        status_changed: true,
        polluted_status: 500,
        ..base_diff.clone()
    };
    let base_score = PrototypePollutionTester::score_severity(&base_diff, payload);
    let status_score = PrototypePollutionTester::score_severity(&status_diff, payload);
    assert!(status_score > base_score);
}

#[test]
fn severity_capped_at_10() {
    let payloads = PrototypePollutionTester::generate_payloads();
    let admin_payload = payloads
        .iter()
        .find(|p| p.polluted_key == "isAdmin")
        .unwrap();
    let diff = ResponseDiff {
        status_changed: true,
        baseline_status: 200,
        polluted_status: 500,
        new_headers: vec![("x-bad".into(), "true".into())],
        removed_headers: vec![],
        body_length_delta: 100,
        body_content_changed: true,
        new_body_tokens: vec!["admin".into()],
    };
    let score = PrototypePollutionTester::score_severity(&diff, admin_payload);
    assert!(score <= 10.0);
}

// =========================================================
// test_endpoint integration tests
// =========================================================

#[test]
fn test_endpoint_finds_pollution() {
    let baseline = baseline_response();
    let payload = PrototypePollutionTester::generate_payloads().remove(0);
    let polluted = ResponseSnapshot {
        status_code: 500,
        ..baseline.clone()
    };
    let findings = PrototypePollutionTester::test_endpoint(
        "http://localhost/api/user",
        "POST",
        &baseline,
        &[(payload, polluted)],
    );
    assert_eq!(findings.len(), 1);
    assert!(findings[0].severity > 5.0);
    assert!(
        findings[0]
            .evidence
            .contains("Prototype pollution detected")
    );
}

#[test]
fn test_endpoint_skips_clean_responses() {
    let baseline = baseline_response();
    let payload = PrototypePollutionTester::generate_payloads().remove(0);
    let clean = baseline.clone();
    let findings = PrototypePollutionTester::test_endpoint(
        "http://localhost/api/user",
        "POST",
        &baseline,
        &[(payload, clean)],
    );
    assert!(findings.is_empty());
}

// =========================================================
// Gadget verifier tests
// =========================================================

#[test]
fn gadget_payloads_has_at_least_5() {
    let gadgets = GadgetVerifier::gadget_payloads();
    assert!(
        gadgets.len() >= 5,
        "Expected >=5 gadget payloads, got {}",
        gadgets.len()
    );
}

#[test]
fn gadget_payloads_covers_all_types() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let types: std::collections::HashSet<_> = gadgets.iter().map(|g| g.gadget_type).collect();
    for gt in GadgetType::all() {
        assert!(types.contains(gt), "Missing gadget type: {:?}", gt);
    }
}

#[test]
fn verify_status_code_gadget() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let express = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::ExpressStatusOverride)
        .unwrap();
    let response = ResponseSnapshot {
        status_code: 503,
        headers: vec![],
        body: String::new(),
    };
    assert!(GadgetVerifier::verify_gadget(express, &response));
}

#[test]
fn verify_status_code_gadget_no_match() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let express = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::ExpressStatusOverride)
        .unwrap();
    let response = ResponseSnapshot {
        status_code: 200,
        headers: vec![],
        body: String::new(),
    };
    assert!(!GadgetVerifier::verify_gadget(express, &response));
}

#[test]
fn verify_header_injection_gadget() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let header_gadget = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::HttpHeaderInjection)
        .unwrap();
    let response = ResponseSnapshot {
        status_code: 200,
        headers: vec![("x-polluted".into(), "aegis-canary".into())],
        body: String::new(),
    };
    assert!(GadgetVerifier::verify_gadget(header_gadget, &response));
}

#[test]
fn verify_body_contains_gadget() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let rce = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::ChildProcessRce)
        .unwrap();
    let response = ResponseSnapshot {
        status_code: 200,
        headers: vec![],
        body: "output: rce executed".into(),
    };
    assert!(GadgetVerifier::verify_gadget(rce, &response));
}

#[test]
fn verify_body_regex_gadget() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let ejs = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::EjsTemplateRce)
        .unwrap();
    let response = ResponseSnapshot {
        status_code: 200,
        headers: vec![],
        body: "uid=1000(node) gid=1000(node)".into(),
    };
    assert!(GadgetVerifier::verify_gadget(ejs, &response));
}

#[test]
fn verify_body_regex_no_match() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let ejs = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::EjsTemplateRce)
        .unwrap();
    let response = ResponseSnapshot {
        status_code: 200,
        headers: vec![],
        body: "normal page content".into(),
    };
    assert!(!GadgetVerifier::verify_gadget(ejs, &response));
}

#[test]
fn verify_all_returns_matching_gadgets() {
    let gadgets = GadgetVerifier::gadget_payloads();
    let express = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::ExpressStatusOverride)
        .unwrap()
        .clone();
    let header = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::HttpHeaderInjection)
        .unwrap()
        .clone();

    let pairs = vec![
        (
            express,
            ResponseSnapshot {
                status_code: 503,
                headers: vec![],
                body: String::new(),
            },
        ),
        (
            header,
            ResponseSnapshot {
                status_code: 200,
                headers: vec![],
                body: String::new(),
            },
        ),
    ];
    let confirmed = GadgetVerifier::verify_all(&pairs);
    assert_eq!(confirmed.len(), 1);
    assert_eq!(confirmed[0].0, GadgetType::ExpressStatusOverride);
}

#[test]
fn findings_from_gadgets_builds_findings() {
    let baseline = baseline_response();
    let gadgets = GadgetVerifier::gadget_payloads();
    let express = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::ExpressStatusOverride)
        .unwrap()
        .clone();

    let response = ResponseSnapshot {
        status_code: 503,
        headers: vec![],
        body: String::new(),
    };
    let findings = GadgetVerifier::findings_from_gadgets(
        "http://localhost/api",
        "POST",
        &baseline,
        &[(express, response)],
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].gadget, Some(GadgetType::ExpressStatusOverride));
    assert!(findings[0].severity >= 7.0);
}

#[test]
fn findings_from_gadgets_skips_unconfirmed() {
    let baseline = baseline_response();
    let gadgets = GadgetVerifier::gadget_payloads();
    let express = gadgets
        .iter()
        .find(|g| g.gadget_type == GadgetType::ExpressStatusOverride)
        .unwrap()
        .clone();

    let response = ResponseSnapshot {
        status_code: 200,
        headers: vec![],
        body: String::new(),
    };
    let findings = GadgetVerifier::findings_from_gadgets(
        "http://localhost/api",
        "POST",
        &baseline,
        &[(express, response)],
    );
    assert!(findings.is_empty());
}

// =========================================================
// Gadget type metadata tests
// =========================================================

#[test]
fn gadget_severity_values_are_valid() {
    for gt in GadgetType::all() {
        let sev = gt.severity();
        assert!(
            sev >= 1.0 && sev <= 10.0,
            "{:?} severity {} out of range",
            gt,
            sev
        );
    }
}

#[test]
fn gadget_labels_are_unique() {
    let labels: Vec<_> = GadgetType::all().iter().map(|g| g.label()).collect();
    let unique: std::collections::HashSet<_> = labels.iter().collect();
    assert_eq!(labels.len(), unique.len());
}

#[test]
fn injection_pattern_labels_are_unique() {
    let labels: Vec<_> = InjectionPattern::all().iter().map(|p| p.label()).collect();
    let unique: std::collections::HashSet<_> = labels.iter().collect();
    assert_eq!(labels.len(), unique.len());
}

// =========================================================
// VerificationSignal::StatusCodeRange test
// =========================================================

#[test]
fn verify_status_code_range() {
    let gadget = GadgetPayload {
        gadget_type: GadgetType::ExpressStatusOverride,
        pollution_json: String::new(),
        verification_signal: VerificationSignal::StatusCodeRange { min: 500, max: 599 },
        description: "range test".into(),
    };
    let in_range = ResponseSnapshot {
        status_code: 503,
        headers: vec![],
        body: String::new(),
    };
    let out_of_range = ResponseSnapshot {
        status_code: 200,
        headers: vec![],
        body: String::new(),
    };
    assert!(GadgetVerifier::verify_gadget(&gadget, &in_range));
    assert!(!GadgetVerifier::verify_gadget(&gadget, &out_of_range));
}
