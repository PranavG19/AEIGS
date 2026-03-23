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
fn clobber_document_cookie() {
    let html = r#"<img id="cookie" src="x">"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "cookie")
    ));
}

#[test]
fn clobber_document_location() {
    let html = r#"<form id="location"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "location")
    ));
}

#[test]
fn clobber_innerhtml() {
    let html = r#"<div name="innerHTML">evil</div>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "innerHTML")
    ));
}

#[test]
fn clobber_window_name() {
    let html = r#"<img id="name" src="x">"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "name")
    ));
}

#[test]
fn clobber_window_fetch() {
    let html = r#"<div id="fetch">x</div>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "fetch")
    ));
}

#[test]
fn named_form_detected() {
    let html = r#"<form name="myForm" action="/submit"><input type="text"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        DomClobberIssue::NamedFormAccess { form_name } if form_name == "myForm"
    )));
}

#[test]
fn unnamed_form_no_issue() {
    let html = r#"<form action="/submit"><input type="text"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, DomClobberIssue::NamedFormAccess { .. })));
}

#[test]
fn anchor_id_override_dangerous() {
    let html = r#"<a id="cookie" href="http://evil.com">click</a>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues
        .iter()
        .any(|i| matches!(i, DomClobberIssue::AnchorIdOverride { id } if id == "cookie")));
}

#[test]
fn anchor_id_safe_no_issue() {
    let html = r#"<a id="nav-link" href="/about">About</a>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, DomClobberIssue::AnchorIdOverride { .. })));
}

#[test]
fn single_quote_attributes() {
    let html = "<div id='cookie'>x</div>";
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "cookie")
    ));
}

#[test]
fn case_insensitive_match() {
    let html = r#"<div id="Cookie">x</div>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.iter().any(
        |i| matches!(i, DomClobberIssue::ClobberedProperty { name, .. } if name == "Cookie")
    ));
}

#[test]
fn multiple_clobbers() {
    let html = r#"<img id="cookie"><div name="location"><form name="x"></form>"#;
    let issues = analyze_dom_clobbering(html);
    assert!(issues.len() >= 3);
}

#[test]
fn severity_critical_property() {
    let issue = DomClobberIssue::ClobberedProperty {
        element: "id".into(),
        name: "cookie".into(),
    };
    assert_eq!(dom_clobber_severity(&issue), 7.5);
}

#[test]
fn severity_non_critical_property() {
    let issue = DomClobberIssue::ClobberedProperty {
        element: "id".into(),
        name: "title".into(),
    };
    assert_eq!(dom_clobber_severity(&issue), 5.0);
}

#[test]
fn severity_named_form() {
    let issue = DomClobberIssue::NamedFormAccess {
        form_name: "x".into(),
    };
    assert_eq!(dom_clobber_severity(&issue), 4.0);
}

#[test]
fn severity_anchor_override() {
    let issue = DomClobberIssue::AnchorIdOverride { id: "x".into() };
    assert_eq!(dom_clobber_severity(&issue), 6.0);
}

#[test]
fn display_format() {
    let issue = DomClobberIssue::ClobberedProperty {
        element: "id".into(),
        name: "cookie".into(),
    };
    assert_eq!(issue.to_string(), "dom_clobber:id:cookie");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        DomClobberIssue::ClobberedProperty {
            element: "id".into(),
            name: "cookie".into(),
        },
        DomClobberIssue::NamedFormAccess {
            form_name: "f".into(),
        },
    ];
    let mut seq = 0;
    let ops = dom_clobber_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}
