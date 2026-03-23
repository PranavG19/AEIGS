use crate::inline_handler_audit::*;

#[test]
fn clean_html_no_issues() {
    let html = r#"<html><body><p>Clean page</p></body></html>"#;
    let issues = find_inline_handlers(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_onclick_on_div() {
    let html = r#"<div onclick="alert(1)">Click me</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::EventHandler {
            tag: "div".to_string(),
            handler: "onclick".to_string(),
        }
    );
}

#[test]
fn detects_onerror_on_img() {
    let html = r#"<img src="x" onerror="alert(1)">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::EventHandler {
            tag: "img".to_string(),
            handler: "onerror".to_string(),
        }
    );
}

#[test]
fn detects_onload_on_body() {
    let html = r#"<body onload="init()">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::EventHandler {
            tag: "body".to_string(),
            handler: "onload".to_string(),
        }
    );
}

#[test]
fn detects_onsubmit_on_form() {
    let html = r#"<form onsubmit="return validate()">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::EventHandler {
            tag: "form".to_string(),
            handler: "onsubmit".to_string(),
        }
    );
}

#[test]
fn case_insensitive_detection() {
    let html = r#"<DIV ONCLICK="alert(1)">text</DIV>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::EventHandler {
            tag: "div".to_string(),
            handler: "onclick".to_string(),
        }
    );
}

#[test]
fn detects_multiple_handlers_on_different_tags() {
    let html = r#"
        <div onclick="doA()">A</div>
        <span onmouseover="doB()">B</span>
        <input onfocus="doC()">
    "#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 3);
}

#[test]
fn one_issue_per_tag_instance_breaks_after_first_handler() {
    let html = r#"<div onclick="a()" onmouseover="b()">text</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn javascript_uri_in_href() {
    let html = r#"<a href="javascript:alert(1)">click</a>"#;
    let issues = find_inline_handlers(html);
    let js_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::JavascriptUri { .. }))
        .collect();
    assert_eq!(js_issues.len(), 1);
    assert_eq!(
        *js_issues[0],
        InlineHandlerIssue::JavascriptUri {
            tag: "a".to_string(),
        }
    );
}

#[test]
fn javascript_uri_in_action() {
    let html = r#"<form action="javascript:submit()">"#;
    let issues = find_inline_handlers(html);
    let js_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::JavascriptUri { .. }))
        .collect();
    assert_eq!(js_issues.len(), 1);
    assert_eq!(
        *js_issues[0],
        InlineHandlerIssue::JavascriptUri {
            tag: "form".to_string(),
        }
    );
}

#[test]
fn javascript_uri_in_src() {
    let html = r#"<img src="javascript:void(0)">"#;
    let issues = find_inline_handlers(html);
    let js_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::JavascriptUri { .. }))
        .collect();
    assert_eq!(js_issues.len(), 1);
}

#[test]
fn data_uri_in_src() {
    let html = r#"<img src="data:text/html,<script>alert(1)</script>">"#;
    let issues = find_inline_handlers(html);
    let data_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::DataUri { .. }))
        .collect();
    assert_eq!(data_issues.len(), 1);
    assert_eq!(
        *data_issues[0],
        InlineHandlerIssue::DataUri {
            tag: "img".to_string(),
        }
    );
}

#[test]
fn data_uri_not_detected_in_href() {
    let html = r#"<a href="data:text/html,hello">link</a>"#;
    let issues = find_inline_handlers(html);
    let data_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::DataUri { .. }))
        .collect();
    assert!(data_issues.is_empty());
}

#[test]
fn eval_in_handler_value() {
    let html = r#"<div onclick="eval(userInput)">go</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::UnsafeEvalInHandler {
            tag: "div".to_string(),
            handler: "onclick".to_string(),
        }
    );
}

#[test]
fn function_constructor_in_handler() {
    let html = r#"<button onclick="Function('return this')()">run</button>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::UnsafeEvalInHandler {
            tag: "button".to_string(),
            handler: "onclick".to_string(),
        }
    );
}

#[test]
fn settimeout_string_in_handler() {
    let html = r#"<body onload="setTimeout('alert(1)', 100)">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::UnsafeEvalInHandler {
            tag: "body".to_string(),
            handler: "onload".to_string(),
        }
    );
}

#[test]
fn innerhtml_in_handler() {
    let html = r#"<div onclick="this.innerHTML='<b>new</b>'">click</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::DomManipulationInHandler {
            tag: "div".to_string(),
            handler: "onclick".to_string(),
        }
    );
}

#[test]
fn outerhtml_in_handler() {
    let html = r#"<span onclick="this.outerHTML='<b>replaced</b>'">x</span>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::DomManipulationInHandler {
            tag: "span".to_string(),
            handler: "onclick".to_string(),
        }
    );
}

#[test]
fn document_write_in_handler() {
    let html = r#"<body onload="document.write('hello')">"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        InlineHandlerIssue::DomManipulationInHandler {
            tag: "body".to_string(),
            handler: "onload".to_string(),
        }
    );
}

#[test]
fn high_density_handlers_detected() {
    let mut html = String::new();
    for i in 0..12 {
        html.push_str(&format!(r#"<div onclick="fn{i}()">item {i}</div>"#));
    }
    let issues = find_inline_handlers(&html);
    let density_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::HighDensityHandlers { .. }))
        .collect();
    assert_eq!(density_issues.len(), 1);
    if let InlineHandlerIssue::HighDensityHandlers { count } = density_issues[0] {
        assert_eq!(*count, 12);
    } else {
        panic!("expected HighDensityHandlers");
    }
}

#[test]
fn no_high_density_for_ten_or_fewer() {
    let mut html = String::new();
    for i in 0..10 {
        html.push_str(&format!(r#"<div onclick="fn{i}()">item {i}</div>"#));
    }
    let issues = find_inline_handlers(&html);
    let density_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::HighDensityHandlers { .. }))
        .collect();
    assert!(density_issues.is_empty());
}

#[test]
fn display_event_handler() {
    let issue = InlineHandlerIssue::EventHandler {
        tag: "div".to_string(),
        handler: "onclick".to_string(),
    };
    assert_eq!(format!("{issue}"), "event_handler");
}

#[test]
fn display_javascript_uri() {
    let issue = InlineHandlerIssue::JavascriptUri {
        tag: "a".to_string(),
    };
    assert_eq!(format!("{issue}"), "javascript_uri");
}

#[test]
fn display_data_uri() {
    let issue = InlineHandlerIssue::DataUri {
        tag: "img".to_string(),
    };
    assert_eq!(format!("{issue}"), "data_uri");
}

#[test]
fn display_unsafe_eval() {
    let issue = InlineHandlerIssue::UnsafeEvalInHandler {
        tag: "div".to_string(),
        handler: "onclick".to_string(),
    };
    assert_eq!(format!("{issue}"), "unsafe_eval_in_handler");
}

#[test]
fn display_dom_manipulation() {
    let issue = InlineHandlerIssue::DomManipulationInHandler {
        tag: "span".to_string(),
        handler: "onmouseover".to_string(),
    };
    assert_eq!(format!("{issue}"), "dom_manipulation_in_handler");
}

#[test]
fn display_high_density() {
    let issue = InlineHandlerIssue::HighDensityHandlers { count: 15 };
    assert_eq!(format!("{issue}"), "high_density_handlers");
}

#[test]
fn severity_event_handler() {
    let issue = InlineHandlerIssue::EventHandler {
        tag: "div".to_string(),
        handler: "onclick".to_string(),
    };
    assert_eq!(inline_handler_severity(&issue), 2.5);
}

#[test]
fn severity_javascript_uri() {
    let issue = InlineHandlerIssue::JavascriptUri {
        tag: "a".to_string(),
    };
    assert_eq!(inline_handler_severity(&issue), 7.0);
}

#[test]
fn severity_data_uri() {
    let issue = InlineHandlerIssue::DataUri {
        tag: "img".to_string(),
    };
    assert_eq!(inline_handler_severity(&issue), 5.0);
}

#[test]
fn severity_unsafe_eval() {
    let issue = InlineHandlerIssue::UnsafeEvalInHandler {
        tag: "div".to_string(),
        handler: "onclick".to_string(),
    };
    assert_eq!(inline_handler_severity(&issue), 8.0);
}

#[test]
fn severity_dom_manipulation() {
    let issue = InlineHandlerIssue::DomManipulationInHandler {
        tag: "span".to_string(),
        handler: "onclick".to_string(),
    };
    assert_eq!(inline_handler_severity(&issue), 6.0);
}

#[test]
fn severity_high_density() {
    let issue = InlineHandlerIssue::HighDensityHandlers { count: 20 };
    assert_eq!(inline_handler_severity(&issue), 4.0);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = inline_handler_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        InlineHandlerIssue::EventHandler {
            tag: "div".to_string(),
            handler: "onclick".to_string(),
        },
        InlineHandlerIssue::JavascriptUri {
            tag: "a".to_string(),
        },
        InlineHandlerIssue::UnsafeEvalInHandler {
            tag: "button".to_string(),
            handler: "onclick".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = inline_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        InlineHandlerIssue::DataUri {
            tag: "img".to_string(),
        },
        InlineHandlerIssue::HighDensityHandlers { count: 15 },
    ];
    let mut seq = 10;
    let ops = inline_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
}

#[test]
fn eval_takes_priority_over_plain_event_handler() {
    let html = r#"<div onclick="eval('alert(1)')">go</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        InlineHandlerIssue::UnsafeEvalInHandler { .. }
    ));
}

#[test]
fn dom_manipulation_takes_priority_over_plain_event_handler() {
    let html = r#"<div onclick="this.innerHTML='injected'">go</div>"#;
    let issues = find_inline_handlers(html);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        InlineHandlerIssue::DomManipulationInHandler { .. }
    ));
}

#[test]
fn javascript_uri_and_event_handler_on_same_tag() {
    let html = r#"<a href="javascript:void(0)" onclick="doStuff()">link</a>"#;
    let issues = find_inline_handlers(html);
    let js_count = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::JavascriptUri { .. }))
        .count();
    let handler_count = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::EventHandler { .. }))
        .count();
    assert_eq!(js_count, 1);
    assert_eq!(handler_count, 1);
}

#[test]
fn normal_href_not_flagged_as_javascript_uri() {
    let html = r#"<a href="https://example.com">safe link</a>"#;
    let issues = find_inline_handlers(html);
    let js_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::JavascriptUri { .. }))
        .collect();
    assert!(js_issues.is_empty());
}

#[test]
fn normal_src_not_flagged_as_data_uri() {
    let html = r#"<img src="https://example.com/image.png">"#;
    let issues = find_inline_handlers(html);
    let data_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, InlineHandlerIssue::DataUri { .. }))
        .collect();
    assert!(data_issues.is_empty());
}
