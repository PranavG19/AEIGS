use crate::canary_scanner::{CanaryRisk, CanaryToken, CanaryTokenType};
use crate::deception_mapper::*;
use crate::honeypot_detector::*;

fn make_honeypot_result(
    is_honeypot: bool,
    indicators: Vec<HoneypotIndicator>,
) -> HoneypotDetectorResult {
    let confidence = if is_honeypot { 0.85 } else { 0.2 };
    HoneypotDetectorResult {
        is_honeypot,
        confidence,
        indicators,
        honeypot_type: if is_honeypot {
            Some(HoneypotType::WebHoneypot)
        } else {
            None
        },
    }
}

fn make_canary_token(location: &str) -> CanaryToken {
    CanaryToken {
        token_type: CanaryTokenType::AwsCredential,
        location: location.to_string(),
        value: "AKIAEXAMPLE...".to_string(),
        risk_level: CanaryRisk::Critical,
        description: "Test canary credential".to_string(),
        should_avoid: true,
    }
}

#[test]
fn mapper_builds_without_panic() {
    let _mapper = DeceptionMapper::new();
}

#[test]
fn build_map_empty_inputs() {
    let mapper = DeceptionMapper::new();
    let map = mapper.build_map(&[], None, None, &[]);
    assert!(map.endpoints.is_empty());
    assert!(map.canary_credentials.is_empty());
    assert!(map.honeypot_services.is_empty());
    assert_eq!(map.deception_coverage.total_endpoints, 0);
    assert_eq!(map.deception_coverage.deception_ratio, 0.0);
}

#[test]
fn build_map_classifies_real_endpoints() {
    let mapper = DeceptionMapper::new();
    let paths = vec!["/api/v1/users".to_string(), "/health".to_string()];
    let map = mapper.build_map(&paths, None, None, &[]);
    assert_eq!(map.endpoints.len(), 2);
    assert!(
        map.endpoints
            .iter()
            .all(|e| e.classification == EndpointType::Real),
        "common API paths should be classified as Real"
    );
    assert_eq!(map.safe_attack_paths.len(), 2);
    assert!(map.avoid_paths.is_empty());
}

#[test]
fn build_map_marks_canary_paths_as_avoid() {
    let mapper = DeceptionMapper::new();
    let paths = vec!["/.env".to_string(), "/api/v1/users".to_string()];
    let canary = make_canary_token("/.env");
    let map = mapper.build_map(&paths, None, None, &[canary]);

    let env_endpoint = map.endpoints.iter().find(|e| e.path == "/.env").unwrap();
    assert_eq!(env_endpoint.classification, EndpointType::CanaryProtected);

    assert!(map.avoid_paths.contains(&"/.env".to_string()));
    assert!(map.safe_attack_paths.contains(&"/api/v1/users".to_string()));
    assert_eq!(map.canary_credentials.len(), 1);
}

#[test]
fn build_map_honeypot_marks_decoy_endpoints() {
    let mapper = DeceptionMapper::new();
    let hp = make_honeypot_result(
        true,
        vec![HoneypotIndicator {
            indicator_type: IndicatorType::DecoyEndpoint,
            description: "responds to everything".to_string(),
            severity: crate::honeypot_detector::IndicatorSeverity::High,
        }],
    );
    let paths = vec!["/random-path".to_string()];
    let map = mapper.build_map(&paths, Some(&hp), None, &[]);

    assert_eq!(map.endpoints[0].classification, EndpointType::Decoy);
    assert!(map.avoid_paths.contains(&"/random-path".to_string()));
    assert_eq!(map.honeypot_services.len(), 1);
}

#[test]
fn build_map_honeypot_path_extraction() {
    let mapper = DeceptionMapper::new();
    let hp = make_honeypot_result(
        true,
        vec![HoneypotIndicator {
            indicator_type: IndicatorType::FakeLoginPage,
            description: "Login page at '/admin/login' appears fake".to_string(),
            severity: crate::honeypot_detector::IndicatorSeverity::High,
        }],
    );
    let paths = vec!["/admin/login".to_string(), "/api/v1/data".to_string()];
    let map = mapper.build_map(&paths, Some(&hp), None, &[]);

    let login = map
        .endpoints
        .iter()
        .find(|e| e.path == "/admin/login")
        .unwrap();
    assert_eq!(login.classification, EndpointType::Honeypot);
    assert!(map.avoid_paths.contains(&"/admin/login".to_string()));
}

#[test]
fn deception_coverage_computed_correctly() {
    let mapper = DeceptionMapper::new();
    let canary = make_canary_token("/.env");
    let hp = make_honeypot_result(
        true,
        vec![HoneypotIndicator {
            indicator_type: IndicatorType::DecoyEndpoint,
            description: "decoy".to_string(),
            severity: crate::honeypot_detector::IndicatorSeverity::High,
        }],
    );
    let paths = vec![
        "/.env".to_string(),
        "/api/v1/users".to_string(),
        "/unknown-path".to_string(),
    ];
    let map = mapper.build_map(&paths, Some(&hp), None, &[canary]);

    let cov = &map.deception_coverage;
    assert_eq!(cov.total_endpoints, 3);
    assert!(
        cov.deception_ratio > 0.0,
        "should have some deception ratio"
    );
}

#[test]
fn deception_coverage_display() {
    let cov = DeceptionCoverage {
        total_endpoints: 10,
        real_endpoints: 5,
        decoy_endpoints: 2,
        honeypot_endpoints: 1,
        canary_protected: 1,
        unknown_endpoints: 1,
        deception_ratio: 0.4,
    };
    let display = format!("{cov}");
    assert!(display.contains("10 endpoints"));
    assert!(display.contains("5 real"));
    assert!(display.contains("40%"));
}

#[test]
fn endpoint_type_display() {
    assert_eq!(format!("{}", EndpointType::Real), "Real");
    assert_eq!(format!("{}", EndpointType::Decoy), "Decoy");
    assert_eq!(format!("{}", EndpointType::Honeypot), "Honeypot");
    assert_eq!(
        format!("{}", EndpointType::CanaryProtected),
        "Canary-Protected"
    );
    assert_eq!(format!("{}", EndpointType::Unknown), "Unknown");
}

#[test]
fn deception_coverage_default() {
    let cov = DeceptionCoverage::default();
    assert_eq!(cov.total_endpoints, 0);
    assert_eq!(cov.deception_ratio, 0.0);
}

#[test]
fn multiple_canary_credentials_tracked() {
    let mapper = DeceptionMapper::new();
    let canaries = vec![
        make_canary_token("/.env"),
        make_canary_token("/config.json"),
    ];
    let paths = vec!["/.env".to_string(), "/config.json".to_string()];
    let map = mapper.build_map(&paths, None, None, &canaries);
    assert_eq!(map.canary_credentials.len(), 2);
    assert_eq!(map.avoid_paths.len(), 2);
}

#[test]
fn safe_paths_exclude_deception() {
    let mapper = DeceptionMapper::new();
    let canary = make_canary_token("/.env");
    let paths = vec![
        "/.env".to_string(),
        "/api/v1/users".to_string(),
        "/static/app.js".to_string(),
    ];
    let map = mapper.build_map(&paths, None, None, &[canary]);
    assert!(
        !map.safe_attack_paths.contains(&"/.env".to_string()),
        "canary path should not be in safe list"
    );
    assert_eq!(map.safe_attack_paths.len(), 2);
}

#[test]
fn non_honeypot_result_no_services() {
    let mapper = DeceptionMapper::new();
    let hp = make_honeypot_result(false, vec![]);
    let map = mapper.build_map(&["/test".to_string()], Some(&hp), None, &[]);
    assert!(map.honeypot_services.is_empty());
}

#[test]
fn endpoint_classification_evidence_populated() {
    let mapper = DeceptionMapper::new();
    let canary = make_canary_token("/.env");
    let paths = vec!["/.env".to_string()];
    let map = mapper.build_map(&paths, None, None, &[canary]);
    let endpoint = &map.endpoints[0];
    assert!(
        !endpoint.evidence.is_empty(),
        "evidence should be populated"
    );
}
