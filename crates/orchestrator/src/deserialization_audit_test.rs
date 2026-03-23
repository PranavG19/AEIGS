use crate::deserialization_audit::*;

#[test]
fn empty_response_returns_empty() {
    let issues = analyze_deserialization("");
    assert!(issues.is_empty());
}

#[test]
fn node_serialize_rce_detected() {
    let body = r#"{"user":"_$$ND_FUNC$$_function(){return 'pwned'}()"}"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::NodeSerializeRce))
    );
}

#[test]
fn node_serialize_keyword_detected() {
    let body = "Error: node-serialize deserialization failed";
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::NodeSerializeRce))
    );
}

#[test]
fn js_yaml_unsafe_load_detected() {
    let body = r#"const data = yaml.load(userInput);"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JsYamlUnsafeLoad))
    );
}

#[test]
fn js_yaml_safe_load_not_detected() {
    let body = r#"const data = yaml.safeLoad(userInput);"#;
    let issues = analyze_deserialization(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JsYamlUnsafeLoad))
    );
}

#[test]
fn eval_call_detected() {
    let body = r#"eval(req.body.code);"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::EvalCall))
    );
}

#[test]
fn function_constructor_detected() {
    let body = r#"const fn = new Function(userInput); fn();"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::FunctionConstructor))
    );
}

#[test]
fn function_constructor_without_new_detected() {
    let body = r#"const fn = Function(code);"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::FunctionConstructor))
    );
}

#[test]
fn template_literal_injection_detected() {
    let body = r#"const msg = `Hello ${userInput}`;"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::TemplateLiteralInjection))
    );
}

#[test]
fn dynamic_require_detected() {
    let body = r#"const mod = require(moduleName);"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::DynamicRequire))
    );
}

#[test]
fn static_require_not_detected() {
    let body = r#"const fs = require('fs'); const path = require("path");"#;
    let issues = analyze_deserialization(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::DynamicRequire))
    );
}

#[test]
fn json_parse_reviver_detected() {
    let body = r#"JSON.parse(text, reviver)"#;
    let issues = analyze_deserialization(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JsonParseReviver))
    );
}

#[test]
fn json_parse_without_reviver_not_detected() {
    let body = r#"JSON.parse(text)"#;
    let issues = analyze_deserialization(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JsonParseReviver))
    );
}

#[test]
fn java_serialized_content_type_detected() {
    let issues = analyze_content_type_headers("application/x-java-serialized-object", "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JavaSerializedContentType { .. }))
    );
}

#[test]
fn java_object_content_type_detected() {
    let issues = analyze_content_type_headers("application/x-java-object; charset=utf-8", "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JavaSerializedContentType { .. }))
    );
}

#[test]
fn python_pickle_content_type_detected() {
    let issues = analyze_content_type_headers("application/python-pickle", "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::PythonPickleContentType))
    );
}

#[test]
fn php_serialized_body_detected() {
    let issues = analyze_content_type_headers("text/html", "<html>a:0:{}</html>");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::PhpSerializedBody { .. }))
    );
}

#[test]
fn php_stdclass_detected() {
    let issues = analyze_content_type_headers(
        "text/html",
        "O:8:\"stdClass\":1:{s:4:\"name\";s:4:\"test\";}",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::PhpSerializedBody { .. }))
    );
}

#[test]
fn php_not_detected_in_json_content_type() {
    let issues = analyze_content_type_headers("application/json", "a:0:{}");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::PhpSerializedBody { .. }))
    );
}

#[test]
fn dotnet_viewstate_detected() {
    let body = "<input type=\"hidden\" name=\"__VIEWSTATE\" value=\"/wEPDwUKLTE2M\" />";
    let issues = analyze_content_type_headers("text/html", body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DeserializationIssue::DotNetViewState { encrypted: false }
    )));
}

#[test]
fn dotnet_viewstate_encrypted_detected() {
    let body = "<input name=\"__VIEWSTATE\" value=\"abc\" />\
                <input name=\"__VIEWSTATEENCRYPTED\" value=\"\" />";
    let issues = analyze_content_type_headers("text/html", body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::DotNetViewState { encrypted: true }))
    );
}

#[test]
fn normal_html_no_issues() {
    let issues = analyze_content_type_headers("text/html", "<html><body>Hello World</body></html>");
    assert!(issues.is_empty());
}

#[test]
fn accepts_java_serialized_input() {
    let issues = analyze_accepts_serialized("application/x-java-serialized-object", "");
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
fn severity_ordering_critical() {
    assert!(
        deserialization_severity(&DeserializationIssue::NodeSerializeRce)
            > deserialization_severity(&DeserializationIssue::JavaRmiEndpoint)
    );
    assert!(
        deserialization_severity(&DeserializationIssue::JavaRmiEndpoint)
            > deserialization_severity(&DeserializationIssue::EvalCall)
    );
}

#[test]
fn severity_ordering_high() {
    assert!(
        deserialization_severity(&DeserializationIssue::EvalCall)
            >= deserialization_severity(&DeserializationIssue::FunctionConstructor)
    );
    assert!(
        deserialization_severity(&DeserializationIssue::JsYamlUnsafeLoad)
            > deserialization_severity(&DeserializationIssue::DynamicRequire)
    );
}

#[test]
fn severity_ordering_viewstate() {
    assert!(
        deserialization_severity(&DeserializationIssue::DotNetViewState { encrypted: false })
            > deserialization_severity(&DeserializationIssue::DotNetViewState { encrypted: true })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        DeserializationIssue::NodeSerializeRce,
        DeserializationIssue::JavaRmiEndpoint,
    ];
    let mut seq = 0u64;
    let ops = deserialization_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_increments_sequence() {
    let issues = vec![DeserializationIssue::EvalCall];
    let mut seq = 50u64;
    let ops = deserialization_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 51);
}

#[test]
fn display_node_serialize() {
    let issue = DeserializationIssue::NodeSerializeRce;
    assert_eq!(issue.to_string(), "node_serialize_rce");
}

#[test]
fn display_js_yaml() {
    let issue = DeserializationIssue::JsYamlUnsafeLoad;
    assert_eq!(issue.to_string(), "js_yaml_unsafe_load");
}

#[test]
fn display_eval() {
    let issue = DeserializationIssue::EvalCall;
    assert_eq!(issue.to_string(), "eval_call");
}

#[test]
fn display_function_constructor() {
    let issue = DeserializationIssue::FunctionConstructor;
    assert_eq!(issue.to_string(), "function_constructor");
}

#[test]
fn display_template_literal() {
    let issue = DeserializationIssue::TemplateLiteralInjection;
    assert_eq!(issue.to_string(), "template_literal_injection");
}

#[test]
fn display_dynamic_require() {
    let issue = DeserializationIssue::DynamicRequire;
    assert_eq!(issue.to_string(), "dynamic_require");
}

#[test]
fn display_java_rmi() {
    let issue = DeserializationIssue::JavaRmiEndpoint;
    assert_eq!(issue.to_string(), "java_rmi_endpoint");
}

#[test]
fn display_dotnet_viewstate() {
    let issue = DeserializationIssue::DotNetViewState { encrypted: false };
    assert_eq!(issue.to_string(), "dotnet_viewstate:encrypted=false");
}

#[test]
fn display_accepts_serialized() {
    let issue = DeserializationIssue::AcceptsSerializedInput {
        content_type: "application/python-pickle".into(),
    };
    assert_eq!(
        issue.to_string(),
        "accepts_serialized:application/python-pickle"
    );
}

#[test]
fn display_json_parse_reviver() {
    let issue = DeserializationIssue::JsonParseReviver;
    assert_eq!(issue.to_string(), "json_parse_reviver");
}

#[test]
fn multiple_issues_detected() {
    let body = r#"
        eval(code);
        const fn = new Function(userInput);
        const msg = `Hello ${name}`;
    "#;
    let issues = analyze_deserialization(body);
    assert!(issues.len() >= 3);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::EvalCall))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::FunctionConstructor))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::TemplateLiteralInjection))
    );
}

#[test]
fn case_sensitive_node_serialize() {
    let body = "NODE-SERIALIZE";
    let issues = analyze_deserialization(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::NodeSerializeRce))
    );
}

#[test]
fn case_sensitive_yaml() {
    let body = "yaml.LOAD(data)";
    let issues = analyze_deserialization(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JsYamlUnsafeLoad))
    );
}

#[test]
fn java_ct_with_charset() {
    let issues = analyze_content_type_headers(
        "application/x-java-serialized-object; charset=ISO-8859-1",
        "",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::JavaSerializedContentType { .. }))
    );
}

#[test]
fn python_pickle_ct_with_charset() {
    let issues = analyze_content_type_headers("application/python-pickle; charset=utf-8", "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DeserializationIssue::PythonPickleContentType))
    );
}
