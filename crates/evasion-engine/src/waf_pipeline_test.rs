use super::*;

#[test]
fn new_creates_pipeline() {
    let pipeline = WafPipeline::new();
    assert!(pipeline.detected_vendor().is_none());
    assert_eq!(pipeline.probes_sent(), 0);
    assert_eq!(pipeline.bypasses_achieved(), 0);
}

#[test]
fn with_seed_creates_deterministic_pipeline() {
    let pipeline = WafPipeline::with_seed(42);
    assert!(pipeline.detected_vendor().is_none());
    assert_eq!(pipeline.probes_sent(), 0);
}

#[test]
fn fingerprint_detects_cloudflare() {
    let mut pipeline = WafPipeline::new();
    let response = ResponseFingerprint {
        status_code: 403,
        headers: {
            let mut h = std::collections::HashMap::new();
            h.insert("server".to_string(), "cloudflare".to_string());
            h.insert("cf-ray".to_string(), "abc123".to_string());
            h
        },
        body_snippet: String::new(),
    };
    let result = pipeline.fingerprint_waf(&response);
    assert_eq!(result.primary_vendor, WafVendor::Cloudflare);
    assert!(pipeline.detected_vendor().is_some());
}

#[test]
fn learn_grammar_tracks_probes() {
    let mut pipeline = WafPipeline::new();
    let probes = vec![
        ProbeResult {
            payload: "<script>".to_string(),
            blocked: true,
            status_code: Some(403),
            strategy: crate::waf_grammar::ProbeStrategy::BinarySearch,
        },
        ProbeResult {
            payload: "hello".to_string(),
            blocked: false,
            status_code: Some(200),
            strategy: crate::waf_grammar::ProbeStrategy::BinarySearch,
        },
    ];
    pipeline.learn_grammar(&probes);
    assert_eq!(pipeline.probes_sent(), 2);
}

#[test]
fn evade_generates_strategy() {
    let mut pipeline = WafPipeline::with_seed(42);
    let result = pipeline.evade("<script>alert(1)</script>", "http://localhost:8080");
    assert!(!result.original_payload.is_empty());
    assert!(!result.evasion_strategy.techniques_applied.is_empty());
}

#[test]
fn record_outcome_tracks_bypasses() {
    let mut pipeline = WafPipeline::new();
    pipeline.record_outcome(
        EvasionOutcome::Success,
        &[EvasionTechnique::PayloadObfuscation],
    );
    assert_eq!(pipeline.bypasses_achieved(), 1);
}

#[test]
fn record_outcome_blocked_does_not_increment() {
    let mut pipeline = WafPipeline::new();
    pipeline.record_outcome(
        EvasionOutcome::Blocked,
        &[EvasionTechnique::PayloadObfuscation],
    );
    assert_eq!(pipeline.bypasses_achieved(), 0);
}

#[test]
fn suggest_probes_empty_without_grammar() {
    let pipeline = WafPipeline::new();
    assert!(pipeline.suggest_probes().is_empty());
}

#[test]
fn default_creates_pipeline() {
    let pipeline = WafPipeline::default();
    assert!(pipeline.detected_vendor().is_none());
}

#[test]
fn full_pipeline_flow() {
    let mut pipeline = WafPipeline::with_seed(42);

    let response = ResponseFingerprint {
        status_code: 403,
        headers: {
            let mut h = std::collections::HashMap::new();
            h.insert("server".to_string(), "cloudflare".to_string());
            h
        },
        body_snippet: String::new(),
    };
    let fp_result = pipeline.fingerprint_waf(&response);
    assert_eq!(fp_result.primary_vendor, WafVendor::Cloudflare);

    let probes = vec![
        ProbeResult {
            payload: "SELECT".to_string(),
            blocked: true,
            status_code: Some(403),
            strategy: crate::waf_grammar::ProbeStrategy::BinarySearch,
        },
        ProbeResult {
            payload: "sElEcT".to_string(),
            blocked: false,
            status_code: Some(200),
            strategy: crate::waf_grammar::ProbeStrategy::CaseMutation,
        },
    ];
    pipeline.learn_grammar(&probes);

    let result = pipeline.evade("SELECT * FROM users", "http://localhost:8080");
    assert!(result.vendor.is_some());
    assert_eq!(result.vendor.unwrap(), WafVendor::Cloudflare);

    pipeline.record_outcome(
        EvasionOutcome::Success,
        &result.evasion_strategy.techniques_applied,
    );
    assert_eq!(pipeline.bypasses_achieved(), 1);
}
