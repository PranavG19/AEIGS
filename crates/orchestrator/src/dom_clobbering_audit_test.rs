use crate::dom_clobbering_audit::*;

#[test]
fn empty_html_no_issues() {
    assert!(analyze_dom_clobbering("").is_empty());
}

#[test]
fn safe_id_no_issue() {
    let html = r#"<div id="content">Hello</div>"#;
    assert!(analyze_dom_clobbering(html).is_empty());
}

#[test]
fn named_element_collision_cookie() {
    let html = r#"<img id="cookie" src="x">"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::NamedElementCollision { name, .. } if name == "cookie"
    )));
}

#[test]
fn named_element_collision_location() {
    let html = r#"<form id="location"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::NamedElementCollision { name, .. } if name == "location"
    )));
}

#[test]
fn named_element_collision_innerhtml() {
    let html = r#"<div name="innerHTML">evil</div>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::NamedElementCollision { name, .. } if name == "innerHTML"
    )));
}

#[test]
fn named_element_collision_window_name() {
    let html = r#"<img id="name" src="x">"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::NamedElementCollision { name, .. } if name == "name"
    )));
}

#[test]
fn named_element_collision_window_fetch() {
    let html = r#"<div id="fetch">x</div>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::NamedElementCollision { name, .. } if name == "fetch"
    )));
}

#[test]
fn form_element_clobbering_submit() {
    let html = r#"<form name="myForm"><input name="submit"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::FormElementClobbering { element_name, .. } if element_name == "submit"
    )));
}

#[test]
fn form_element_clobbering_action() {
    let html = r#"<form name="authForm"><input name="action" value="evil"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::FormElementClobbering { element_name, .. } if element_name == "action"
    )));
}

#[test]
fn form_element_clobbering_method() {
    let html = r#"<form name="f1"><button name="method"></button></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::FormElementClobbering { element_name, .. } if element_name == "method"
    )));
}

#[test]
fn form_element_safe_name() {
    let html = r#"<form name="myForm"><input name="username"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DomClobberingIssue::FormElementClobbering { .. }))
    );
}

#[test]
fn anchor_href_clobbering_with_href() {
    let html = r#"<a id="cookie" href="http://evil.com">click</a>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::AnchorHrefClobbering { id, has_href } if id == "cookie" && *has_href
    )));
}

#[test]
fn anchor_href_clobbering_without_href() {
    let html = r#"<a id="location">text</a>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::AnchorHrefClobbering { id, has_href } if id == "location" && !*has_href
    )));
}

#[test]
fn anchor_safe_id() {
    let html = r#"<a id="nav-link" href="/about">About</a>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DomClobberingIssue::AnchorHrefClobbering { .. }))
    );
}

#[test]
fn script_gadget_property_access() {
    let html = r#"<img id="navigator" src="x"><script>let x = window.navigator.apiUrl;</script>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::ScriptGadgetChain { clobbered_name, context }
        if clobbered_name == "navigator" && context == "property_access"
    )));
}

#[test]
fn script_gadget_bracket_access() {
    let html = r#"<div name="opener" src="x"></div><script>let x = opener["key"];</script>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::ScriptGadgetChain { context, .. } if context == "bracket_access"
    )));
}

#[test]
fn script_gadget_assignment() {
    let html = r#"<img id="fetch" href="x"><script>const url = =fetch;</script>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::ScriptGadgetChain { context, .. } if context == "assignment"
    )));
}

#[test]
fn dompurify_bypass_form_input_attributes() {
    let html = r#"<form><input name="attributes"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DomClobberingIssue::DompurifyBypassPattern { .. }))
    );
}

#[test]
fn dompurify_bypass_form_input_lastchild() {
    let html = r#"<form><input name="lastChild"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DomClobberingIssue::DompurifyBypassPattern { .. }))
    );
}

#[test]
fn missing_namespace_isolation() {
    let html = r#"<iframe id="cookie"></iframe>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::MissingNamespaceIsolation { id, .. } if id == "cookie"
    )));
}

#[test]
fn namespace_isolation_present() {
    let html =
        r#"<iframe id="document"></iframe><script>el.ownerDocument.getElementById('x');</script>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DomClobberingIssue::MissingNamespaceIsolation { .. }))
    );
}

#[test]
fn single_quote_attributes() {
    let html = "<div id='cookie'>x</div>";
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberingIssue::NamedElementCollision { name, .. } if name == "cookie"
    )));
}

#[test]
fn case_sensitive_matching() {
    let html = r#"<div id="Cookie">x</div>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues() {
    let html = r#"<img id="cookie"><form name="f"><input name="submit"></form><a id="location" href="x"></a>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.len() >= 3);
}

#[test]
fn severity_named_element_critical() {
    let issue = DomClobberingIssue::NamedElementCollision {
        element: "img".into(),
        name: "cookie".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 8.0);
}

#[test]
fn severity_named_element_non_critical() {
    let issue = DomClobberingIssue::NamedElementCollision {
        element: "div".into(),
        name: "title".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 5.5);
}

#[test]
fn severity_form_element() {
    let issue = DomClobberingIssue::FormElementClobbering {
        form_name: "f".into(),
        element_name: "submit".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 4.5);
}

#[test]
fn severity_anchor_with_href() {
    let issue = DomClobberingIssue::AnchorHrefClobbering {
        id: "cookie".into(),
        has_href: true,
    };
    assert_eq!(dom_clobbering_severity(&issue), 7.0);
}

#[test]
fn severity_anchor_without_href() {
    let issue = DomClobberingIssue::AnchorHrefClobbering {
        id: "location".into(),
        has_href: false,
    };
    assert_eq!(dom_clobbering_severity(&issue), 5.0);
}

#[test]
fn severity_script_gadget_property_access() {
    let issue = DomClobberingIssue::ScriptGadgetChain {
        clobbered_name: "config".into(),
        context: "property_access".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 8.5);
}

#[test]
fn severity_script_gadget_assignment() {
    let issue = DomClobberingIssue::ScriptGadgetChain {
        clobbered_name: "x".into(),
        context: "assignment".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 7.5);
}

#[test]
fn severity_dompurify_bypass() {
    let issue = DomClobberingIssue::DompurifyBypassPattern {
        pattern: "<form><input name=\"attributes\">".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 9.0);
}

#[test]
fn severity_missing_namespace() {
    let issue = DomClobberingIssue::MissingNamespaceIsolation {
        element: "iframe".into(),
        id: "document".into(),
    };
    assert_eq!(dom_clobbering_severity(&issue), 6.5);
}

#[test]
fn display_format_named_element() {
    let issue = DomClobberingIssue::NamedElementCollision {
        element: "img".into(),
        name: "cookie".into(),
    };
    assert_eq!(issue.to_string(), "named_element_collision:img:cookie");
}

#[test]
fn display_format_form_element() {
    let issue = DomClobberingIssue::FormElementClobbering {
        form_name: "myForm".into(),
        element_name: "submit".into(),
    };
    assert_eq!(issue.to_string(), "form_element_clobbering:myForm:submit");
}

#[test]
fn display_format_anchor_href() {
    let issue = DomClobberingIssue::AnchorHrefClobbering {
        id: "cookie".into(),
        has_href: true,
    };
    assert_eq!(issue.to_string(), "anchor_href_clobbering:cookie:true");
}

#[test]
fn display_format_script_gadget() {
    let issue = DomClobberingIssue::ScriptGadgetChain {
        clobbered_name: "config".into(),
        context: "property_access".into(),
    };
    assert_eq!(
        issue.to_string(),
        "script_gadget_chain:config:property_access"
    );
}

#[test]
fn to_operations_count() {
    let issues = vec![
        DomClobberingIssue::NamedElementCollision {
            element: "img".into(),
            name: "cookie".into(),
        },
        DomClobberingIssue::FormElementClobbering {
            form_name: "f".into(),
            element_name: "submit".into(),
        },
    ];
    let mut seq = 0u64;
    let ops = dom_clobbering_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_sequence_increments() {
    let issues = vec![DomClobberingIssue::NamedElementCollision {
        element: "div".into(),
        name: "location".into(),
    }];
    let mut seq = 42u64;
    let ops = dom_clobbering_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 43);
    assert_eq!(ops[0].sequence_number, 43);
}
