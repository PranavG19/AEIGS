use crate::prototype_pollution_audit::*;

#[test]
fn analyze_no_pollution() {
    let result = analyze_pollution_response("<html>safe</html>", "proto_bracket");
    assert!(result.is_none());
}

#[test]
fn analyze_proto_reflected() {
    let body = r#"{"aegispptest":"polluted42","other":"value"}"#;
    let result = analyze_pollution_response(body, "proto_bracket");
    assert!(matches!(
        result,
        Some(PrototypePollutionIssue::ProtoReflected { .. })
    ));
}

#[test]
fn analyze_constructor_reflected() {
    let body = r#"<script>var x = {"aegispptest":"polluted42"}</script>"#;
    let result = analyze_pollution_response(body, "constructor_bracket");
    assert!(matches!(
        result,
        Some(PrototypePollutionIssue::ConstructorReflected { .. })
    ));
}

#[test]
fn analyze_requires_both_key_and_value() {
    assert!(analyze_pollution_response("aegispptest but no value", "proto_dot").is_none());
    assert!(analyze_pollution_response("polluted42 but no key", "proto_dot").is_none());
}

#[test]
fn proto_dot_vector() {
    let body = "aegispptest=polluted42";
    let result = analyze_pollution_response(body, "proto_dot");
    assert_eq!(
        result,
        Some(PrototypePollutionIssue::ProtoReflected {
            vector: "proto_dot".to_string()
        })
    );
}

#[test]
fn constructor_dot_vector() {
    let body = "aegispptest=polluted42";
    let result = analyze_pollution_response(body, "constructor_dot");
    assert_eq!(
        result,
        Some(PrototypePollutionIssue::ConstructorReflected {
            vector: "constructor_dot".to_string()
        })
    );
}

#[test]
fn severity_proto_higher() {
    assert!(
        pollution_severity(&PrototypePollutionIssue::ProtoReflected {
            vector: "x".to_string()
        }) > pollution_severity(&PrototypePollutionIssue::ConstructorReflected {
            vector: "x".to_string()
        })
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = pollution_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        PrototypePollutionIssue::ProtoReflected {
            vector: "proto_bracket".to_string(),
        },
        PrototypePollutionIssue::ConstructorReflected {
            vector: "constructor_dot".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = pollution_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_proto_reflected() {
    let issue = PrototypePollutionIssue::ProtoReflected {
        vector: "proto_bracket".to_string(),
    };
    assert_eq!(issue.to_string(), "proto_reflected:proto_bracket");
}

#[test]
fn display_constructor_reflected() {
    let issue = PrototypePollutionIssue::ConstructorReflected {
        vector: "constructor_dot".to_string(),
    };
    assert_eq!(issue.to_string(), "constructor_reflected:constructor_dot");
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_prototype_pollution("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_prototype_pollution("http://127.0.0.1");
    assert!(issues.is_empty());
}
