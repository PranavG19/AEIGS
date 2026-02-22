use super::*;

#[test]
fn dom_evidence_display_alert_fired() {
    assert_eq!(format!("{}", DomEvidence::AlertFired), "Alert Fired");
}

#[test]
fn dom_evidence_display_dom_mutation() {
    assert_eq!(format!("{}", DomEvidence::DomMutation), "DOM Mutation");
}

#[test]
fn dom_evidence_display_cookie_access() {
    assert_eq!(format!("{}", DomEvidence::CookieAccess), "Cookie Access");
}

#[test]
fn dom_evidence_display_navigation_attempt() {
    assert_eq!(
        format!("{}", DomEvidence::NavigationAttempt),
        "Navigation Attempt"
    );
}

#[test]
fn dom_evidence_display_fetch_to_external() {
    assert_eq!(
        format!("{}", DomEvidence::FetchToExternal),
        "Fetch to External"
    );
}

#[test]
fn dom_evidence_display_no_execution() {
    assert_eq!(format!("{}", DomEvidence::NoExecution), "No Execution");
}

#[test]
fn confidence_boost_alert_fired() {
    assert_eq!(confidence_boost_for_evidence(&DomEvidence::AlertFired), 0.3);
}

#[test]
fn confidence_boost_dom_mutation() {
    assert_eq!(
        confidence_boost_for_evidence(&DomEvidence::DomMutation),
        0.25
    );
}

#[test]
fn confidence_boost_cookie_access() {
    assert_eq!(
        confidence_boost_for_evidence(&DomEvidence::CookieAccess),
        0.3
    );
}

#[test]
fn confidence_boost_navigation_attempt() {
    assert_eq!(
        confidence_boost_for_evidence(&DomEvidence::NavigationAttempt),
        0.3
    );
}

#[test]
fn confidence_boost_fetch_to_external() {
    assert_eq!(
        confidence_boost_for_evidence(&DomEvidence::FetchToExternal),
        0.25
    );
}

#[test]
fn confidence_boost_no_execution() {
    assert_eq!(
        confidence_boost_for_evidence(&DomEvidence::NoExecution),
        -0.2
    );
}

#[test]
fn dom_verification_result_construction() {
    let result = DomVerificationResult {
        payload: "<script>alert(1)</script>".to_string(),
        endpoint: "/search?q=".to_string(),
        dom_executed: true,
        evidence: DomEvidence::AlertFired,
        confidence_boost: 0.3,
    };

    assert_eq!(result.payload, "<script>alert(1)</script>");
    assert_eq!(result.endpoint, "/search?q=");
    assert!(result.dom_executed);
    assert_eq!(result.evidence, DomEvidence::AlertFired);
    assert_eq!(result.confidence_boost, 0.3);
}

#[test]
fn dom_verification_result_no_execution() {
    let result = DomVerificationResult {
        payload: "<img src=x>".to_string(),
        endpoint: "/page".to_string(),
        dom_executed: false,
        evidence: DomEvidence::NoExecution,
        confidence_boost: -0.2,
    };

    assert!(!result.dom_executed);
    assert_eq!(result.evidence, DomEvidence::NoExecution);
    assert_eq!(result.confidence_boost, -0.2);
}

#[test]
fn dom_evidence_serialization_roundtrip() {
    let variants = [
        DomEvidence::AlertFired,
        DomEvidence::DomMutation,
        DomEvidence::CookieAccess,
        DomEvidence::NavigationAttempt,
        DomEvidence::FetchToExternal,
        DomEvidence::NoExecution,
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let deserialized: DomEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, deserialized);
    }
}

#[test]
fn dom_verification_result_serialization_roundtrip() {
    let result = DomVerificationResult {
        payload: "<script>alert(1)</script>".to_string(),
        endpoint: "/vuln".to_string(),
        dom_executed: true,
        evidence: DomEvidence::AlertFired,
        confidence_boost: 0.3,
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: DomVerificationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.payload, result.payload);
    assert_eq!(deserialized.endpoint, result.endpoint);
    assert_eq!(deserialized.dom_executed, result.dom_executed);
    assert_eq!(deserialized.evidence, result.evidence);
    assert_eq!(deserialized.confidence_boost, result.confidence_boost);
}

#[test]
fn dom_evidence_equality_and_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(DomEvidence::AlertFired);
    set.insert(DomEvidence::AlertFired);
    set.insert(DomEvidence::DomMutation);

    assert_eq!(set.len(), 2);
}

#[test]
fn instrumentation_js_contains_marker_flags() {
    assert!(INSTRUMENTATION_JS.contains("__aegis_xss_fired"));
    assert!(INSTRUMENTATION_JS.contains("__aegis_nav_attempt"));
    assert!(INSTRUMENTATION_JS.contains("__aegis_cookie_access"));
    assert!(INSTRUMENTATION_JS.contains("__aegis_external_fetch"));
}

#[test]
fn read_markers_js_returns_all_flags() {
    assert!(READ_MARKERS_JS.contains("xss_fired"));
    assert!(READ_MARKERS_JS.contains("nav_attempt"));
    assert!(READ_MARKERS_JS.contains("cookie_access"));
    assert!(READ_MARKERS_JS.contains("external_fetch"));
}

#[test]
fn check_dom_mutation_js_looks_for_scripts_and_event_handlers() {
    assert!(CHECK_DOM_MUTATION_JS.contains("script"));
    assert!(CHECK_DOM_MUTATION_JS.contains("onclick"));
    assert!(CHECK_DOM_MUTATION_JS.contains("onerror"));
}

#[test]
fn inject_payload_into_url_get_appends_query() {
    let result = inject_payload_into_url(
        "http://localhost:3000/search",
        "<script>alert(1)</script>",
        "GET",
    );
    assert!(result.starts_with("http://localhost:3000/search?q="));
    assert!(result.contains("q="));
}

#[test]
fn inject_payload_into_url_get_encodes_special_chars() {
    let result = inject_payload_into_url(
        "http://localhost:3000/search",
        "<script>alert(1)</script>",
        "GET",
    );
    assert!(!result.contains('<'));
    assert!(!result.contains('>'));
    assert!(result.contains("%3C"));
}

#[test]
fn inject_payload_into_url_post_returns_endpoint() {
    let endpoint = "http://localhost:3000/submit";
    let result = inject_payload_into_url(endpoint, "<script>alert(1)</script>", "POST");
    assert_eq!(result, endpoint);
}

#[test]
fn inject_payload_into_url_with_existing_query() {
    let result = inject_payload_into_url("http://localhost:3000/search?foo=bar", "test", "GET");
    assert!(result.starts_with("http://localhost:3000/search?foo=bar&q="));
}

#[test]
fn verify_xss_result_uses_confidence_boost_fn() {
    let variants = [
        DomEvidence::AlertFired,
        DomEvidence::DomMutation,
        DomEvidence::CookieAccess,
        DomEvidence::NavigationAttempt,
        DomEvidence::FetchToExternal,
        DomEvidence::NoExecution,
    ];

    for evidence in &variants {
        let dom_executed = *evidence != DomEvidence::NoExecution;
        let result = DomVerificationResult {
            payload: "test".to_string(),
            endpoint: "/test".to_string(),
            dom_executed,
            evidence: *evidence,
            confidence_boost: confidence_boost_for_evidence(evidence),
        };
        assert_eq!(
            result.confidence_boost,
            confidence_boost_for_evidence(evidence),
            "confidence_boost mismatch for {evidence}"
        );
    }
}
