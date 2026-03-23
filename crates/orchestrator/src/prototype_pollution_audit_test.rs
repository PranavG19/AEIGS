use crate::prototype_pollution_audit::*;

#[test]
fn analyze_no_pollution() {
    let body = "<html><script>var x = {a: 1};</script></html>";
    let result = analyze_prototype_pollution(body);
    assert!(result.is_empty());
}

#[test]
fn detect_proto_bracket_notation() {
    let body = "obj[__proto__][polluted] = true";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::ProtoPropertyDetected { .. }))
    );
}

#[test]
fn detect_proto_dot_notation() {
    let body = "obj.__proto__.isAdmin = true";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::ProtoPropertyDetected { .. }))
    );
}

#[test]
fn detect_proto_string_bracket() {
    let body = "obj['__proto__']['polluted'] = 42";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::ProtoPropertyDetected { .. }))
    );
}

#[test]
fn detect_proto_double_quote_bracket() {
    let body = r#"obj["__proto__"]["polluted"] = 42"#;
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::ProtoPropertyDetected { .. }))
    );
}

#[test]
fn detect_constructor_prototype_dot() {
    let body = "obj.constructor.prototype.isAdmin = true";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::ConstructorPrototypeDetected { .. }
    )));
}

#[test]
fn detect_constructor_prototype_bracket_string() {
    let body = r#"obj.constructor["prototype"].polluted = 1"#;
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::ConstructorPrototypeDetected { .. }
    )));
}

#[test]
fn detect_constructor_prototype_bracket_identifier() {
    let body = "obj.constructor[prototype].polluted = 1";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::ConstructorPrototypeDetected { .. }
    )));
}

#[test]
fn detect_object_assign_unsafe() {
    let body = "function merge(a, b) { return Object.assign(a, b); }";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::ObjectAssignUnsafe { .. }))
    );
}

#[test]
fn object_assign_with_has_own_property_is_safe() {
    let body = "function merge(a, b) { if(b.hasOwnProperty(k)) Object.assign(a, b); }";
    let result = analyze_prototype_pollution(body);
    assert!(
        !result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::ObjectAssignUnsafe { .. }))
    );
}

#[test]
fn detect_set_prototype_of() {
    let body = "Object.setPrototypeOf(obj, malicious)";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::SetPrototypeOfDetected { .. }))
    );
}

#[test]
fn detect_recursive_merge_deep_merge() {
    let body = "function deepMerge(target, source) { for(let k in source) target[k] = source[k]; }";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::RecursiveMergeUnsafe { function_name }
        if function_name == "deep_merge"
    )));
}

#[test]
fn detect_recursive_merge_generic_merge() {
    let body = "function merge(a, b) { for(let k in b) a[k] = b[k]; }";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::RecursiveMergeUnsafe { function_name }
        if function_name == "merge"
    )));
}

#[test]
fn recursive_merge_with_has_own_property_is_safe() {
    let body = "function merge(a, b) { if(b.hasOwnProperty(k)) a[k] = b[k]; }";
    let result = analyze_prototype_pollution(body);
    assert!(
        !result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::RecursiveMergeUnsafe { .. }))
    );
}

#[test]
fn detect_json_parse_unsanitized() {
    let body = "const obj = JSON.parse(userInput);";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::JsonParseUnsanitized { .. }))
    );
}

#[test]
fn json_parse_with_sanitization_is_safe() {
    let body = "const obj = JSON.parse(userInput); delete obj.__proto__;";
    let result = analyze_prototype_pollution(body);
    assert!(
        !result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::JsonParseUnsanitized { .. }))
    );
}

#[test]
fn detect_lodash_merge() {
    let body = "const result = _.merge(target, source);";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::LodashMergeDetected { variant }
        if variant == "merge"
    )));
}

#[test]
fn detect_lodash_defaults_deep() {
    let body = "const result = _.defaultsDeep(target, source);";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::LodashMergeDetected { variant }
        if variant == "defaults_deep"
    )));
}

#[test]
fn detect_lodash_namespace() {
    let body = "const result = lodash.merge(target, source);";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::LodashMergeDetected { .. }))
    );
}

#[test]
fn detect_jquery_extend_shallow() {
    let body = "$.extend(target, source)";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::JqueryExtendDetected { deep: false }
    )));
}

#[test]
fn detect_jquery_extend_deep() {
    let body = "$.extend(true, target, source)";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::JqueryExtendDetected { deep: true }
    )));
}

#[test]
fn detect_jquery_namespace() {
    let body = "jQuery.extend(target, source)";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::JqueryExtendDetected { .. }))
    );
}

#[test]
fn detect_url_parameter_proto_question() {
    let body = "GET /api/user?__proto__[isAdmin]=true";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::UrlParameterPollution { .. }))
    );
}

#[test]
fn detect_url_parameter_proto_ampersand() {
    let body = "GET /api/user?id=1&__proto__[role]=admin";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::UrlParameterPollution { .. }))
    );
}

#[test]
fn detect_url_parameter_constructor() {
    let body = "GET /api?constructor[prototype][isAdmin]=true";
    let result = analyze_prototype_pollution(body);
    assert!(
        result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::UrlParameterPollution { .. }))
    );
}

#[test]
fn detect_gadget_chain_inner_html() {
    let body = "obj.__proto__.innerHTML = '<img src=x onerror=alert(1)>'";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::GadgetChainDetected { gadget_type }
        if gadget_type == "inner_html"
    )));
}

#[test]
fn detect_gadget_chain_eval() {
    let body = "obj.constructor.prototype.x = 'alert(1)'; obj.eval(obj.x)";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::GadgetChainDetected { gadget_type }
        if gadget_type == "eval"
    )));
}

#[test]
fn detect_gadget_chain_document_write() {
    let body = "obj.__proto__.value = '<script>alert(1)</script>'; document.write(obj.value)";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::GadgetChainDetected { gadget_type }
        if gadget_type == "document_write"
    )));
}

#[test]
fn detect_gadget_chain_set_timeout() {
    let body = "obj.__proto__.code = 'alert(1)'; setTimeout(obj.code, 100)";
    let result = analyze_prototype_pollution(body);
    assert!(result.iter().any(|i| matches!(
        i,
        PrototypePollutionIssue::GadgetChainDetected { gadget_type }
        if gadget_type == "set_timeout"
    )));
}

#[test]
fn gadget_without_pollution_not_detected() {
    let body = "document.write('<h1>Hello</h1>')";
    let result = analyze_prototype_pollution(body);
    assert!(
        !result
            .iter()
            .any(|i| matches!(i, PrototypePollutionIssue::GadgetChainDetected { .. }))
    );
}

#[test]
fn severity_gadget_chain_highest() {
    let gadget = PrototypePollutionIssue::GadgetChainDetected {
        gadget_type: "eval".to_string(),
    };
    let proto = PrototypePollutionIssue::ProtoPropertyDetected {
        context: "test".to_string(),
    };
    assert!(prototype_pollution_severity(&gadget) > prototype_pollution_severity(&proto));
}

#[test]
fn severity_proto_higher_than_constructor() {
    let proto = PrototypePollutionIssue::ProtoPropertyDetected {
        context: "test".to_string(),
    };
    let constructor = PrototypePollutionIssue::ConstructorPrototypeDetected {
        context: "test".to_string(),
    };
    assert!(prototype_pollution_severity(&proto) > prototype_pollution_severity(&constructor));
}

#[test]
fn severity_deep_extend_higher_than_shallow() {
    let deep = PrototypePollutionIssue::JqueryExtendDetected { deep: true };
    let shallow = PrototypePollutionIssue::JqueryExtendDetected { deep: false };
    assert!(prototype_pollution_severity(&deep) > prototype_pollution_severity(&shallow));
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0u64;
    let ops = prototype_pollution_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        PrototypePollutionIssue::ProtoPropertyDetected {
            context: "test".to_string(),
        },
        PrototypePollutionIssue::GadgetChainDetected {
            gadget_type: "eval".to_string(),
        },
    ];
    let mut seq = 0u64;
    let ops = prototype_pollution_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_proto_property_detected() {
    let issue = PrototypePollutionIssue::ProtoPropertyDetected {
        context: "test_context".to_string(),
    };
    assert_eq!(issue.to_string(), "proto_property_detected:test_context");
}

#[test]
fn display_constructor_prototype_detected() {
    let issue = PrototypePollutionIssue::ConstructorPrototypeDetected {
        context: "test_ctx".to_string(),
    };
    assert_eq!(issue.to_string(), "constructor_prototype_detected:test_ctx");
}

#[test]
fn display_object_assign_unsafe() {
    let issue = PrototypePollutionIssue::ObjectAssignUnsafe {
        location: "line_42".to_string(),
    };
    assert_eq!(issue.to_string(), "object_assign_unsafe:line_42");
}

#[test]
fn display_lodash_merge() {
    let issue = PrototypePollutionIssue::LodashMergeDetected {
        variant: "merge".to_string(),
    };
    assert_eq!(issue.to_string(), "lodash_merge_detected:merge");
}

#[test]
fn display_jquery_extend_deep() {
    let issue = PrototypePollutionIssue::JqueryExtendDetected { deep: true };
    assert_eq!(issue.to_string(), "jquery_extend_detected:true");
}

#[test]
fn display_gadget_chain() {
    let issue = PrototypePollutionIssue::GadgetChainDetected {
        gadget_type: "eval".to_string(),
    };
    assert_eq!(issue.to_string(), "gadget_chain_detected:eval");
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

#[test]
fn audit_skips_ipv6_loopback() {
    let issues = audit_prototype_pollution("http://[::1]:8080");
    assert!(issues.is_empty());
}
