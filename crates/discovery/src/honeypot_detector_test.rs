use crate::honeypot_detector::*;

#[test]
fn new_detector_builds_without_panic() {
    let _detector = HoneypotDetector::new();
}

#[test]
fn detect_rejects_non_localhost() {
    let detector = HoneypotDetector::new();
    let result = detector.detect("http://example.com");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, HoneypotError::NonLocalhostTarget(_)),
        "expected NonLocalhostTarget, got: {err}"
    );
}

#[test]
fn detect_rejects_invalid_url() {
    let detector = HoneypotDetector::new();
    let result = detector.detect("not-a-url");
    assert!(result.is_err());
}

#[test]
fn indicator_severity_weights_are_ordered() {
    assert!(IndicatorSeverity::Low.weight() < IndicatorSeverity::Medium.weight());
    assert!(IndicatorSeverity::Medium.weight() < IndicatorSeverity::High.weight());
    assert!(IndicatorSeverity::High.weight() < IndicatorSeverity::Critical.weight());
}

#[test]
fn compute_confidence_empty_indicators_returns_zero() {
    let confidence = compute_honeypot_confidence(&[]);
    assert_eq!(confidence, 0.0);
}

#[test]
fn compute_confidence_single_critical_indicator() {
    let indicators = vec![HoneypotIndicator {
        indicator_type: IndicatorType::KnownHoneypotFingerprint,
        description: "test".to_string(),
        severity: IndicatorSeverity::Critical,
    }];
    let confidence = compute_honeypot_confidence(&indicators);
    assert!(
        confidence >= 0.7,
        "critical indicator should yield high confidence, got {confidence}"
    );
}

#[test]
fn compute_confidence_multiple_low_indicators() {
    let indicators: Vec<HoneypotIndicator> = (0..5)
        .map(|i| HoneypotIndicator {
            indicator_type: IndicatorType::UnrealisticBehavior,
            description: format!("low indicator {i}"),
            severity: IndicatorSeverity::Low,
        })
        .collect();
    let confidence = compute_honeypot_confidence(&indicators);
    assert!(
        confidence > 0.0 && confidence < 1.0,
        "multiple low indicators: confidence={confidence}"
    );
}

#[test]
fn compute_confidence_capped_at_one() {
    let indicators: Vec<HoneypotIndicator> = (0..20)
        .map(|i| HoneypotIndicator {
            indicator_type: IndicatorType::KnownHoneypotFingerprint,
            description: format!("critical {i}"),
            severity: IndicatorSeverity::Critical,
        })
        .collect();
    let confidence = compute_honeypot_confidence(&indicators);
    assert!(confidence <= 1.0, "confidence should be capped at 1.0");
}

#[test]
fn classify_honeypot_type_ssh() {
    let indicators = vec![
        HoneypotIndicator {
            indicator_type: IndicatorType::SshHoneypotBanner,
            description: "Cowrie banner".to_string(),
            severity: IndicatorSeverity::Critical,
        },
        HoneypotIndicator {
            indicator_type: IndicatorType::SshHoneypotBanner,
            description: "Kippo banner".to_string(),
            severity: IndicatorSeverity::High,
        },
    ];
    let ht = classify_honeypot_type(&indicators);
    assert_eq!(ht, HoneypotType::SshHoneypot);
}

#[test]
fn classify_honeypot_type_web() {
    let indicators = vec![HoneypotIndicator {
        indicator_type: IndicatorType::KnownHoneypotFingerprint,
        description: "Glastopf".to_string(),
        severity: IndicatorSeverity::Critical,
    }];
    let ht = classify_honeypot_type(&indicators);
    assert_eq!(ht, HoneypotType::WebHoneypot);
}

#[test]
fn classify_honeypot_type_credential() {
    let indicators = vec![
        HoneypotIndicator {
            indicator_type: IndicatorType::CanaryToken,
            description: "AWS canary".to_string(),
            severity: IndicatorSeverity::Critical,
        },
        HoneypotIndicator {
            indicator_type: IndicatorType::CanaryToken,
            description: "HoneyDB".to_string(),
            severity: IndicatorSeverity::High,
        },
    ];
    let ht = classify_honeypot_type(&indicators);
    assert_eq!(ht, HoneypotType::CredentialHoneypot);
}

#[test]
fn classify_honeypot_type_interaction() {
    let indicators = vec![
        HoneypotIndicator {
            indicator_type: IndicatorType::FakeLoginPage,
            description: "fake login".to_string(),
            severity: IndicatorSeverity::High,
        },
        HoneypotIndicator {
            indicator_type: IndicatorType::DecoyEndpoint,
            description: "responds to everything".to_string(),
            severity: IndicatorSeverity::High,
        },
        HoneypotIndicator {
            indicator_type: IndicatorType::TooPermissive,
            description: "too many paths".to_string(),
            severity: IndicatorSeverity::Medium,
        },
    ];
    let ht = classify_honeypot_type(&indicators);
    assert_eq!(ht, HoneypotType::InteractionHoneypot);
}

#[test]
fn is_fake_login_page_minimal_form() {
    let body = r#"<html><body><form action="/login" method="post">
        <input type="text" name="admin">
        <input type="password" name="password">
        <button>Login</button>
    </form></body></html>"#;
    assert!(is_fake_login_page(body));
}

#[test]
fn is_fake_login_page_real_framework_not_flagged() {
    let body = r#"<html><head>
        <script src="/static/jquery.min.js"></script>
        <meta name="csrf-token" content="abc123">
    </head><body>
        <form action="/login" method="post">
            <input type="hidden" name="_token" value="abc123">
            <input type="text" name="username">
            <input type="password" name="password">
            <button>Sign In</button>
        </form>
        <script>console.log('loaded');</script>
    </body></html>"#;
    assert!(!is_fake_login_page(body));
}

#[test]
fn is_fake_login_page_no_form_returns_false() {
    let body = "<html><body><h1>Welcome</h1></body></html>";
    assert!(!is_fake_login_page(body));
}

#[test]
fn indicator_type_display() {
    assert_eq!(
        format!("{}", IndicatorType::FakeLoginPage),
        "Fake Login Page"
    );
    assert_eq!(format!("{}", IndicatorType::CanaryToken), "Canary Token");
    assert_eq!(
        format!("{}", IndicatorType::DecoyEndpoint),
        "Decoy Endpoint"
    );
}

#[test]
fn honeypot_type_display() {
    assert_eq!(
        format!("{}", HoneypotType::SshHoneypot),
        "SSH Honeypot (Cowrie/Kippo)"
    );
    assert_eq!(
        format!("{}", HoneypotType::WebHoneypot),
        "Web Honeypot (Glastopf/Snare)"
    );
}

#[test]
fn error_display_variants() {
    let e1 = HoneypotError::InvalidUrl("bad".into());
    assert!(format!("{e1}").contains("bad"));

    let e2 = HoneypotError::NonLocalhostTarget("example.com".into());
    assert!(format!("{e2}").contains("example.com"));

    let e3 = HoneypotError::HttpError("timeout".into());
    assert!(format!("{e3}").contains("timeout"));
}

#[test]
fn result_fields_populated_correctly() {
    let result = HoneypotDetectorResult {
        is_honeypot: true,
        confidence: 0.85,
        indicators: vec![HoneypotIndicator {
            indicator_type: IndicatorType::KnownHoneypotFingerprint,
            description: "Glastopf server header".to_string(),
            severity: IndicatorSeverity::Critical,
        }],
        honeypot_type: Some(HoneypotType::WebHoneypot),
    };
    assert!(result.is_honeypot);
    assert_eq!(result.confidence, 0.85);
    assert_eq!(result.indicators.len(), 1);
    assert_eq!(result.honeypot_type, Some(HoneypotType::WebHoneypot));
}

#[test]
fn indicator_severity_display() {
    assert_eq!(format!("{}", IndicatorSeverity::Low), "Low");
    assert_eq!(format!("{}", IndicatorSeverity::Critical), "Critical");
}
