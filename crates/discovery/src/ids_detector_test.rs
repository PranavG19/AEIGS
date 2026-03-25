use crate::ids_detector::*;

#[test]
fn new_detector_builds_without_panic() {
    let _detector = IdsDetector::new();
}

#[test]
fn detect_rejects_non_localhost() {
    let detector = IdsDetector::new();
    let result = detector.detect("http://example.com");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        IdsError::NonLocalhostTarget(_)
    ));
}

#[test]
fn detect_rejects_invalid_url() {
    let detector = IdsDetector::new();
    let result = detector.detect("not-a-url");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdsError::InvalidUrl(_)));
}

#[test]
fn ids_severity_weights_ordered() {
    assert!(IdsSeverity::Low.weight() < IdsSeverity::Medium.weight());
    assert!(IdsSeverity::Medium.weight() < IdsSeverity::High.weight());
    assert!(IdsSeverity::High.weight() < IdsSeverity::Critical.weight());
}

#[test]
fn compute_confidence_empty_returns_zero() {
    let confidence = compute_ids_confidence(&[]);
    assert_eq!(confidence, 0.0);
}

#[test]
fn compute_confidence_single_critical() {
    let indicators = vec![IdsIndicator {
        indicator_type: IdsIndicatorType::HeaderLeakage,
        description: "Suricata header".to_string(),
        payload_trigger: None,
        severity: IdsSeverity::Critical,
    }];
    let confidence = compute_ids_confidence(&indicators);
    assert!(
        confidence >= 0.7,
        "critical should yield high confidence: {confidence}"
    );
}

#[test]
fn compute_confidence_capped_at_one() {
    let indicators: Vec<IdsIndicator> = (0..20)
        .map(|i| IdsIndicator {
            indicator_type: IdsIndicatorType::SignatureBlock,
            description: format!("block {i}"),
            payload_trigger: None,
            severity: IdsSeverity::Critical,
        })
        .collect();
    let confidence = compute_ids_confidence(&indicators);
    assert!(confidence <= 1.0);
}

#[test]
fn classify_ids_type_suricata_from_description() {
    let indicators = vec![IdsIndicator {
        indicator_type: IdsIndicatorType::HeaderLeakage,
        description: "x-suricata-action header found".to_string(),
        payload_trigger: None,
        severity: IdsSeverity::Critical,
    }];
    assert_eq!(classify_ids_type(&indicators), IdsType::Suricata);
}

#[test]
fn classify_ids_type_snort_from_description() {
    let indicators = vec![IdsIndicator {
        indicator_type: IdsIndicatorType::HeaderLeakage,
        description: "x-snort-action header detected".to_string(),
        payload_trigger: None,
        severity: IdsSeverity::Critical,
    }];
    assert_eq!(classify_ids_type(&indicators), IdsType::Snort);
}

#[test]
fn classify_ids_type_modsecurity() {
    let indicators = vec![IdsIndicator {
        indicator_type: IdsIndicatorType::ResponseModification,
        description: "ModSecurity block page".to_string(),
        payload_trigger: None,
        severity: IdsSeverity::High,
    }];
    assert_eq!(classify_ids_type(&indicators), IdsType::ModSecurity);
}

#[test]
fn classify_ids_type_inline_ips_from_drops() {
    let indicators = vec![IdsIndicator {
        indicator_type: IdsIndicatorType::TcpReset,
        description: "connection reset after payload".to_string(),
        payload_trigger: Some("test".into()),
        severity: IdsSeverity::High,
    }];
    assert_eq!(classify_ids_type(&indicators), IdsType::InlineIps);
}

#[test]
fn classify_ids_type_unknown_for_generic_blocks() {
    let indicators = vec![IdsIndicator {
        indicator_type: IdsIndicatorType::SignatureBlock,
        description: "generic block".to_string(),
        payload_trigger: None,
        severity: IdsSeverity::Medium,
    }];
    assert_eq!(classify_ids_type(&indicators), IdsType::Unknown);
}

#[test]
fn behavioral_profile_default_values() {
    let profile = BehavioralProfile::default();
    assert_eq!(profile.baseline_latency_ms, 0.0);
    assert_eq!(profile.payload_latency_ms, 0.0);
    assert_eq!(profile.connection_drop_rate, 0.0);
    assert!(profile.block_status_codes.is_empty());
    assert!(!profile.inline_analysis_detected);
}

#[test]
fn indicator_type_display() {
    assert_eq!(format!("{}", IdsIndicatorType::TcpReset), "TCP Reset");
    assert_eq!(
        format!("{}", IdsIndicatorType::ConnectionDrop),
        "Connection Drop"
    );
    assert_eq!(
        format!("{}", IdsIndicatorType::DelayedResponse),
        "Delayed Response"
    );
    assert_eq!(
        format!("{}", IdsIndicatorType::SignatureBlock),
        "Signature Block"
    );
}

#[test]
fn ids_type_display() {
    assert_eq!(format!("{}", IdsType::Snort), "Snort IDS");
    assert_eq!(format!("{}", IdsType::Suricata), "Suricata IDS/IPS");
    assert_eq!(format!("{}", IdsType::ModSecurity), "ModSecurity WAF");
    assert_eq!(format!("{}", IdsType::InlineIps), "Inline IPS");
}

#[test]
fn error_display_variants() {
    let e1 = IdsError::InvalidUrl("bad".into());
    assert!(format!("{e1}").contains("bad"));

    let e2 = IdsError::NonLocalhostTarget("remote".into());
    assert!(format!("{e2}").contains("remote"));

    let e3 = IdsError::HttpError("timeout".into());
    assert!(format!("{e3}").contains("timeout"));
}

#[test]
fn severity_display() {
    assert_eq!(format!("{}", IdsSeverity::Low), "Low");
    assert_eq!(format!("{}", IdsSeverity::High), "High");
}

#[test]
fn result_fields_construction() {
    let result = IdsDetectorResult {
        ids_detected: true,
        confidence: 0.9,
        indicators: vec![IdsIndicator {
            indicator_type: IdsIndicatorType::ConsistentBlockPattern,
            description: "consistent blocks".to_string(),
            payload_trigger: None,
            severity: IdsSeverity::Critical,
        }],
        ids_type: Some(IdsType::Suricata),
        behavioral_profile: BehavioralProfile::default(),
    };
    assert!(result.ids_detected);
    assert_eq!(result.ids_type, Some(IdsType::Suricata));
    assert_eq!(result.indicators.len(), 1);
}

#[test]
fn urlencoding_special_chars() {
    let encoded = super::ids_detector::urlencoding("' OR 1=1--");
    assert!(encoded.contains("%27"));
    assert!(encoded.contains("OR"));
    assert!(!encoded.contains("'"));
}

#[test]
fn urlencoding_preserves_alphanum() {
    let encoded = super::ids_detector::urlencoding("hello123");
    assert_eq!(encoded, "hello123");
}

#[test]
fn body_contains_ids_markers_positive() {
    assert!(super::ids_detector::body_contains_ids_markers(
        "Access Denied by security policy"
    ));
    assert!(super::ids_detector::body_contains_ids_markers(
        "<html>Blocked by ModSecurity</html>"
    ));
}

#[test]
fn body_contains_ids_markers_negative() {
    assert!(!super::ids_detector::body_contains_ids_markers(
        "<html><body>Welcome to our site</body></html>"
    ));
}
