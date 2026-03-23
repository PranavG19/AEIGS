use crate::deserialization_audit::*;

#[test]
fn empty_response_returns_empty() {
    let issues = analyze_deserialization_response("text/html", "");
    assert!(issues.is_empty());
}

#[test]
fn java_serialized_content_type_detected() {
    let issues = analyze_deserialization_response(
        "application/x-java-serialized-object; charset=utf-8",
        "",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::JavaSerializedContentType { .. }
    )));
}

#[test]
fn java_object_content_type_detected() {
    let issues = analyze_deserialization_response("application/x-java-object", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::JavaSerializedContentType { .. }
    )));
}

#[test]
fn php_serialized_body_detected() {
    let issues =
        analyze_deserialization_response("text/html", "<html>a:0:{}</html>");
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::PhpSerializedBody { .. }
    )));
}

#[test]
fn php_stdclass_detected() {
    let issues = analyze_deserialization_response(
        "text/html",
        "O:8:\"stdClass\":1:{s:4:\"name\";s:4:\"test\";}",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::PhpSerializedBody { .. }
    )));
}

#[test]
fn php_not_detected_in_json_content_type() {
    let issues = analyze_deserialization_response("application/json", "a:0:{}");
    assert!(!issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::PhpSerializedBody { .. }
    )));
}

#[test]
fn dotnet_viewstate_detected() {
    let body = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"/wEPDwUKLTE2M\" />";
    let issues = analyze_deserialization_response("text/html", body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::DotNetViewState { encrypted: false }
    )));
}

#[test]
fn dotnet_viewstate_encrypted_detected() {
    let body = "<input name=\"__VIEWSTATE\" value=\"abc\" />\
                <input name=\"__VIEWSTATEENCRYPTED\" value=\"\" />";
    let issues = analyze_deserialization_response("text/html", body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::DotNetViewState { encrypted: true }
    )));
}

#[test]
fn normal_html_no_issues() {
    let issues = analyze_deserialization_response(
        "text/html",
        "<html><body>Hello World</body></html>",
    );
    assert!(issues.is_empty());
}

#[test]
fn accepts_java_serialized_input() {
    let issues = analyze_accepts_serialized(
        "application/x-java-serialized-object",
        "",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::AcceptsSerializedInput { content_type }
            if content_type == "application/x-java-serialized-object"
    )));
}

#[test]
fn accepts_php_serialized_input() {
    let issues = analyze_accepts_serialized("", "application/x-php-serialized");
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::AcceptsSerializedInput { content_type }
            if content_type == "application/x-php-serialized"
    )));
}

#[test]
fn accepts_pickle_input() {
    let issues = analyze_accepts_serialized("application/python-pickle", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::AcceptsSerializedInput { content_type }
            if content_type == "application/python-pickle"
    )));
}

#[test]
fn no_serialized_accept_header() {
    let issues = analyze_accepts_serialized("application/json", "text/html");
    assert!(issues.is_empty());
}

#[test]
fn severity_ordering() {
    assert!(
        deserialization_severity(&DeserializationIssue::JavaRmiEndpoint)
            > deserialization_severity(&DeserializationIssue::JavaSerializedContentType {
                content_type: "test".into()
            })
    );
    assert!(
        deserialization_severity(&DeserializationIssue::DotNetViewState { encrypted: false })
            > deserialization_severity(&DeserializationIssue::DotNetViewState { encrypted: true })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        DeserializationIssue::JavaRmiEndpoint,
        DeserializationIssue::XmlRpcEndpoint,
    ];
    let mut seq = 50;
    let ops = deserialization_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 52);
}

#[test]
fn display_variants() {
    let issue = DeserializationIssue::JavaRmiEndpoint;
    assert_eq!(issue.to_string(), "java_rmi_endpoint");

    let issue = DeserializationIssue::DotNetViewState { encrypted: false };
    assert_eq!(issue.to_string(), "dotnet_viewstate:encrypted=false");

    let issue = DeserializationIssue::AcceptsSerializedInput {
        content_type: "application/python-pickle".into(),
    };
    assert_eq!(
        issue.to_string(),
        "accepts_serialized:application/python-pickle"
    );
}
