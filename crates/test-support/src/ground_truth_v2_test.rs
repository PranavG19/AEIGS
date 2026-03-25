use super::*;
use aegis_protocol::finding::VulnerabilityClass;

fn sample_manifest() -> GroundTruthManifest {
    let mut m = GroundTruthManifest::new("test-fixture");
    m.add(
        AnnotationBuilder::new("/api/search", VulnerabilityClass::SqlInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-89")
            .cvss(9.8)
            .parameter("q")
            .description("SQL injection in search")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/render", VulnerabilityClass::CrossSiteScripting)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-79")
            .cvss(6.1)
            .parameter("name")
            .description("Reflected XSS")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/exec", VulnerabilityClass::CommandInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-78")
            .cvss(9.8)
            .parameter("cmd")
            .description("Command injection")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/info", VulnerabilityClass::InformationDisclosure)
            .severity(GroundTruthSeverity::Low)
            .cwe("CWE-200")
            .description("Version info leaked")
            .expected_detected(false)
            .build(),
    );
    m
}

#[test]
fn new_manifest_has_version_2() {
    let m = GroundTruthManifest::new("test");
    assert_eq!(m.version, 2);
    assert_eq!(m.fixture_name, "test");
    assert!(m.annotations.is_empty());
}

#[test]
fn add_and_count() {
    let m = sample_manifest();
    assert_eq!(m.count(), 4);
}

#[test]
fn for_endpoint_filters_correctly() {
    let m = sample_manifest();
    let results = m.for_endpoint("/api/search");
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
}

#[test]
fn for_class_filters_correctly() {
    let m = sample_manifest();
    let results = m.for_class(VulnerabilityClass::CommandInjection);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].endpoint, "/api/exec");
}

#[test]
fn for_severity_filters_correctly() {
    let m = sample_manifest();
    let criticals = m.for_severity(GroundTruthSeverity::Critical);
    assert_eq!(criticals.len(), 2);
}

#[test]
fn endpoints_returns_sorted_unique() {
    let m = sample_manifest();
    let eps = m.endpoints();
    assert_eq!(eps.len(), 4);
    for window in eps.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn vulnerability_classes_returns_unique() {
    let m = sample_manifest();
    let classes = m.vulnerability_classes();
    assert_eq!(classes.len(), 4);
}

#[test]
fn severity_distribution() {
    let m = sample_manifest();
    let dist = m.severity_distribution();
    assert_eq!(dist[&GroundTruthSeverity::Critical], 2);
    assert_eq!(dist[&GroundTruthSeverity::High], 1);
    assert_eq!(dist[&GroundTruthSeverity::Low], 1);
}

#[test]
fn total_severity_score() {
    let m = sample_manifest();
    // 10.0 + 8.0 + 10.0 + 2.0 = 30.0
    let score = m.total_severity_score();
    assert!((score - 30.0).abs() < 0.001);
}

#[test]
fn severity_weights_are_ordered() {
    assert!(GroundTruthSeverity::Critical.weight() > GroundTruthSeverity::High.weight());
    assert!(GroundTruthSeverity::High.weight() > GroundTruthSeverity::Medium.weight());
    assert!(GroundTruthSeverity::Medium.weight() > GroundTruthSeverity::Low.weight());
    assert!(GroundTruthSeverity::Low.weight() > GroundTruthSeverity::Info.weight());
}

#[test]
fn json_roundtrip() {
    let m = sample_manifest();
    let json = m.to_json().unwrap();
    let parsed = GroundTruthManifest::from_json(&json).unwrap();
    assert_eq!(parsed.version, m.version);
    assert_eq!(parsed.fixture_name, m.fixture_name);
    assert_eq!(parsed.annotations.len(), m.annotations.len());
    assert_eq!(
        parsed.annotations[0].vulnerability_class,
        m.annotations[0].vulnerability_class
    );
}

#[test]
fn evaluate_perfect_recall() {
    let m = sample_manifest();
    // All 3 expected_detected=true findings found
    let findings = vec![
        ("/api/search".to_string(), VulnerabilityClass::SqlInjection),
        (
            "/api/render".to_string(),
            VulnerabilityClass::CrossSiteScripting,
        ),
        (
            "/api/exec".to_string(),
            VulnerabilityClass::CommandInjection,
        ),
    ];
    let eval = m.evaluate(&findings);
    assert_eq!(eval.true_positives.len(), 3);
    assert_eq!(eval.false_negatives.len(), 0);
    assert_eq!(eval.false_positives.len(), 0);
    assert!((eval.precision - 1.0).abs() < 0.001);
    assert!((eval.recall - 1.0).abs() < 0.001);
    assert!((eval.f1 - 1.0).abs() < 0.001);
}

#[test]
fn evaluate_with_false_positives() {
    let m = sample_manifest();
    let findings = vec![
        ("/api/search".to_string(), VulnerabilityClass::SqlInjection),
        (
            "/api/render".to_string(),
            VulnerabilityClass::CrossSiteScripting,
        ),
        (
            "/api/exec".to_string(),
            VulnerabilityClass::CommandInjection,
        ),
        // False positive — not in ground truth
        (
            "/api/login".to_string(),
            VulnerabilityClass::BrokenAuthentication,
        ),
    ];
    let eval = m.evaluate(&findings);
    assert_eq!(eval.true_positives.len(), 3);
    assert_eq!(eval.false_positives.len(), 1);
    assert_eq!(eval.false_negatives.len(), 0);
    assert!((eval.precision - 0.75).abs() < 0.001);
    assert!((eval.recall - 1.0).abs() < 0.001);
}

#[test]
fn evaluate_with_false_negatives() {
    let m = sample_manifest();
    // Only 1 of 3 expected findings found
    let findings = vec![("/api/search".to_string(), VulnerabilityClass::SqlInjection)];
    let eval = m.evaluate(&findings);
    assert_eq!(eval.true_positives.len(), 1);
    assert_eq!(eval.false_negatives.len(), 2);
    assert_eq!(eval.false_positives.len(), 0);
    assert!((eval.precision - 1.0).abs() < 0.001);
    let expected_recall = 1.0 / 3.0;
    assert!((eval.recall - expected_recall).abs() < 0.001);
}

#[test]
fn evaluate_empty_findings() {
    let m = sample_manifest();
    let eval = m.evaluate(&[]);
    assert_eq!(eval.true_positives.len(), 0);
    assert_eq!(eval.false_negatives.len(), 3); // 3 expected_detected=true
    assert!((eval.precision - 0.0).abs() < 0.001);
    assert!((eval.recall - 0.0).abs() < 0.001);
    assert!((eval.f1 - 0.0).abs() < 0.001);
}

#[test]
fn builder_defaults() {
    let ann = AnnotationBuilder::new("/test", VulnerabilityClass::SqlInjection).build();
    assert_eq!(ann.method, HttpMethod::Get);
    assert_eq!(ann.severity, GroundTruthSeverity::Medium);
    assert!(ann.expected_detected);
    assert!(ann.cvss_score.is_none());
    assert!(ann.parameter.is_none());
}

#[test]
fn builder_with_all_fields() {
    let ann = AnnotationBuilder::new("/api/test", VulnerabilityClass::CommandInjection)
        .method(HttpMethod::Post)
        .severity(GroundTruthSeverity::Critical)
        .cwe("CWE-78")
        .cvss(9.8)
        .parameter("cmd")
        .description("Test command injection")
        .expected_detected(false)
        .build();

    assert_eq!(ann.endpoint, "/api/test");
    assert_eq!(ann.method, HttpMethod::Post);
    assert_eq!(ann.severity, GroundTruthSeverity::Critical);
    assert_eq!(ann.cwe_id, "CWE-78");
    assert_eq!(ann.cvss_score, Some(9.8));
    assert_eq!(ann.parameter.as_deref(), Some("cmd"));
    assert!(!ann.expected_detected);
}

#[test]
fn express_ground_truth_has_12_annotations() {
    let m = express_ground_truth();
    assert_eq!(m.fixture_name, "express-vuln-app");
    assert_eq!(m.count(), 12);
}

#[test]
fn flask_ground_truth_has_8_annotations() {
    let m = flask_ground_truth();
    assert_eq!(m.fixture_name, "flask-vuln-app");
    assert_eq!(m.count(), 8);
}

#[test]
fn express_ground_truth_json_roundtrip() {
    let m = express_ground_truth();
    let json = m.to_json().unwrap();
    let parsed = GroundTruthManifest::from_json(&json).unwrap();
    assert_eq!(parsed.count(), m.count());
}

#[test]
fn expected_detected_false_excluded_from_evaluation() {
    let m = sample_manifest();
    // /api/info has expected_detected=false, should not count as false_negative
    let eval = m.evaluate(&[
        ("/api/search".to_string(), VulnerabilityClass::SqlInjection),
        (
            "/api/render".to_string(),
            VulnerabilityClass::CrossSiteScripting,
        ),
        (
            "/api/exec".to_string(),
            VulnerabilityClass::CommandInjection,
        ),
    ]);
    // /api/info not in expected set, so finding it would be a FP
    // Not finding it is correct behavior
    assert_eq!(eval.false_negatives.len(), 0);
}
