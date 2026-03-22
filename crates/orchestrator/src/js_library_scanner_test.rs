use crate::js_library_scanner::{
    JsLibraryFinding, detect_libraries, extract_version, is_version_below,
    js_library_findings_to_operations,
};

#[test]
fn detect_jquery_in_script_tag() {
    let html = r#"<html><head><script src="/js/jquery-3.2.1.min.js"></script></head></html>"#;
    let findings = detect_libraries(html);
    assert!(!findings.is_empty());
    let jq = findings.iter().find(|f| f.library == "jQuery").unwrap();
    assert_eq!(jq.version, Some("3.2.1".to_string()));
    assert!(jq.outdated);
}

#[test]
fn detect_jquery_safe_version() {
    let html = r#"<script src="https://cdn.example.com/jquery-3.7.1.min.js"></script>"#;
    let findings = detect_libraries(html);
    let jq = findings.iter().find(|f| f.library == "jQuery").unwrap();
    assert_eq!(jq.version, Some("3.7.1".to_string()));
    assert!(!jq.outdated);
}

#[test]
fn detect_angular_in_html() {
    let html = r#"<script src="/vendor/angular.min.js"></script>"#;
    let findings = detect_libraries(html);
    assert!(findings.iter().any(|f| f.library == "AngularJS"));
}

#[test]
fn detect_bootstrap() {
    let html = r#"<script src="/js/bootstrap-4.6.2/bootstrap.min.js"></script>"#;
    let findings = detect_libraries(html);
    let bs = findings.iter().find(|f| f.library == "Bootstrap").unwrap();
    assert_eq!(bs.version, Some("4.6.2".to_string()));
    assert!(bs.outdated);
}

#[test]
fn no_libraries_in_plain_html() {
    let html = r#"<html><body><p>Hello world</p></body></html>"#;
    let findings = detect_libraries(html);
    assert!(findings.is_empty());
}

#[test]
fn extract_version_from_path() {
    let version = extract_version(
        "https://cdn.example.com/jquery-3.6.0.min.js",
        r"jquery[/-](\d+\.\d+\.\d+)",
    );
    assert_eq!(version, Some("3.6.0".to_string()));
}

#[test]
fn extract_version_returns_none_for_no_match() {
    let version = extract_version("no version here", r"jquery[/-](\d+\.\d+\.\d+)");
    assert!(version.is_none());
}

#[test]
fn version_comparison_below() {
    assert!(is_version_below("3.2.1", "3.5.0"));
    assert!(is_version_below("1.7.0", "1.8.0"));
    assert!(is_version_below("4.17.20", "4.17.21"));
}

#[test]
fn version_comparison_equal_or_above() {
    assert!(!is_version_below("3.5.0", "3.5.0"));
    assert!(!is_version_below("3.6.0", "3.5.0"));
    assert!(!is_version_below("4.0.0", "3.5.0"));
}

#[test]
fn operations_empty_when_no_outdated() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: false,
    }];
    let mut seq = 0;
    let ops = js_library_findings_to_operations(&findings, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_for_outdated() {
    let findings = vec![JsLibraryFinding {
        library: "jQuery".to_string(),
        version: Some("3.2.1".to_string()),
        min_safe_version: "3.5.0".to_string(),
        outdated: true,
    }];
    let mut seq = 0;
    let ops = js_library_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn detect_vue_with_cdn_url() {
    let html = r#"<script src="https://cdn.jsdelivr.net/npm/vue@2.7.14/dist/vue.min.js"></script>"#;
    let findings = detect_libraries(html);
    let vue = findings.iter().find(|f| f.library == "Vue.js").unwrap();
    assert_eq!(vue.version, Some("2.7.14".to_string()));
    assert!(vue.outdated);
}

#[test]
fn detect_lodash() {
    let html = r#"<script src="/vendor/lodash-4.17.10.min.js"></script>"#;
    let findings = detect_libraries(html);
    let lodash = findings.iter().find(|f| f.library == "Lodash").unwrap();
    assert!(lodash.outdated);
}
