use crate::dangerous_js_audit::*;

// ===== Original tests (13 tests) =====

#[test]
fn detects_eval() {
    let html = r#"<script>eval(userInput)</script>"#;
    let issues = find_dangerous_js(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].pattern, "eval");
}

#[test]
fn detects_innerhtml() {
    let html = r#"<script>element.innerHTML = data;</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "innerHTML"));
}

#[test]
fn detects_document_write() {
    let html = r#"<script>document.write('<p>' + name + '</p>')</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "document.write"));
}

#[test]
fn detects_jquery_html() {
    let html = r#"<script>$('#div').html(response)</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "jQuery.html"));
}

#[test]
fn detects_function_constructor() {
    let html = r#"<script>new Function(code)()</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.iter().any(|i| i.pattern == "Function_constructor"));
}

#[test]
fn skips_external_scripts() {
    let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.is_empty());
}

#[test]
fn no_issues_in_clean_script() {
    let html = r#"<script>console.log('hello');</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.is_empty());
}

#[test]
fn no_issues_without_scripts() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_patterns_in_one_script() {
    let html = r#"<script>eval(x); element.innerHTML = y;</script>"#;
    let issues = find_dangerous_js(html);
    assert!(issues.len() >= 2);
}

#[test]
fn deduplicates_same_pattern() {
    let html = r#"<script>eval(x); eval(y);</script>"#;
    let issues = find_dangerous_js(html);
    let eval_count = issues.iter().filter(|i| i.pattern == "eval").count();
    assert_eq!(eval_count, 1);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = dangerous_js_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![DangerousJsIssue {
        pattern: "eval".to_string(),
        severity: 6.0,
    }];
    let mut seq = 0;
    let ops = dangerous_js_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn case_insensitive() {
    let html = r#"<script>EVAL(userInput)</script>"#;
    let issues = find_dangerous_js(html);
    assert_eq!(issues.len(), 1);
}

// ===== Display tests (15 tests) =====

#[test]
fn display_eval_usage() {
    let issue = JsSecurityIssue::EvalUsage {
        context: "test".to_string(),
    };
    assert_eq!(issue.to_string(), "eval_usage:test");
}

#[test]
fn display_innerhtml_assignment() {
    let issue = JsSecurityIssue::InnerHtmlAssignment {
        context: "inline_script".to_string(),
    };
    assert_eq!(issue.to_string(), "innerhtml_assignment:inline_script");
}

#[test]
fn display_document_write() {
    let issue = JsSecurityIssue::DocumentWrite;
    assert_eq!(issue.to_string(), "document_write");
}

#[test]
fn display_outerhtml_assignment() {
    let issue = JsSecurityIssue::OuterHtmlAssignment;
    assert_eq!(issue.to_string(), "outerhtml_assignment");
}

#[test]
fn display_insert_adjacent_html() {
    let issue = JsSecurityIssue::InsertAdjacentHtml;
    assert_eq!(issue.to_string(), "insert_adjacent_html");
}

#[test]
fn display_jquery_html() {
    let issue = JsSecurityIssue::JQueryHtml;
    assert_eq!(issue.to_string(), "jquery_html");
}

#[test]
fn display_dangerously_set_inner_html() {
    let issue = JsSecurityIssue::DangerouslySetInnerHtml;
    assert_eq!(issue.to_string(), "dangerously_set_inner_html");
}

#[test]
fn display_function_constructor() {
    let issue = JsSecurityIssue::FunctionConstructor;
    assert_eq!(issue.to_string(), "function_constructor");
}

#[test]
fn display_settimeout_string() {
    let issue = JsSecurityIssue::SetTimeoutString;
    assert_eq!(issue.to_string(), "settimeout_string");
}

#[test]
fn display_setinterval_string() {
    let issue = JsSecurityIssue::SetIntervalString;
    assert_eq!(issue.to_string(), "setinterval_string");
}

#[test]
fn display_postmessage_no_origin_check() {
    let issue = JsSecurityIssue::PostMessageNoOriginCheck;
    assert_eq!(issue.to_string(), "postmessage_no_origin_check");
}

#[test]
fn display_json_parse_unsafe() {
    let issue = JsSecurityIssue::JsonParseUnsafe {
        context: "no_validation".to_string(),
    };
    assert_eq!(issue.to_string(), "json_parse_unsafe:no_validation");
}

#[test]
fn display_dom_xss_sink() {
    let issue = JsSecurityIssue::DomXssSink {
        sink: "location.href".to_string(),
    };
    assert_eq!(issue.to_string(), "dom_xss_sink:location.href");
}

#[test]
fn display_inline_event_handler() {
    let issue = JsSecurityIssue::InlineEventHandler {
        handler: "onclick".to_string(),
    };
    assert_eq!(issue.to_string(), "inline_event_handler:onclick");
}

#[test]
fn display_unsafe_url_scheme() {
    let issue = JsSecurityIssue::UnsafeUrlScheme {
        scheme: "javascript:".to_string(),
    };
    assert_eq!(issue.to_string(), "unsafe_url_scheme:javascript:");
}

// ===== Severity tests (15 tests) =====

#[test]
fn severity_eval_usage() {
    let issue = JsSecurityIssue::EvalUsage {
        context: "test".to_string(),
    };
    assert_eq!(js_security_severity(&issue), 7.0);
}

#[test]
fn severity_function_constructor() {
    let issue = JsSecurityIssue::FunctionConstructor;
    assert_eq!(js_security_severity(&issue), 6.5);
}

#[test]
fn severity_document_write() {
    let issue = JsSecurityIssue::DocumentWrite;
    assert_eq!(js_security_severity(&issue), 6.0);
}

#[test]
fn severity_innerhtml_assignment() {
    let issue = JsSecurityIssue::InnerHtmlAssignment {
        context: "test".to_string(),
    };
    assert_eq!(js_security_severity(&issue), 5.5);
}

#[test]
fn severity_dom_xss_sink() {
    let issue = JsSecurityIssue::DomXssSink {
        sink: "location.href".to_string(),
    };
    assert_eq!(js_security_severity(&issue), 5.5);
}

#[test]
fn severity_outerhtml_assignment() {
    let issue = JsSecurityIssue::OuterHtmlAssignment;
    assert_eq!(js_security_severity(&issue), 5.0);
}

#[test]
fn severity_insert_adjacent_html() {
    let issue = JsSecurityIssue::InsertAdjacentHtml;
    assert_eq!(js_security_severity(&issue), 5.0);
}

#[test]
fn severity_dangerously_set_inner_html() {
    let issue = JsSecurityIssue::DangerouslySetInnerHtml;
    assert_eq!(js_security_severity(&issue), 5.0);
}

#[test]
fn severity_postmessage_no_origin_check() {
    let issue = JsSecurityIssue::PostMessageNoOriginCheck;
    assert_eq!(js_security_severity(&issue), 5.0);
}

#[test]
fn severity_jquery_html() {
    let issue = JsSecurityIssue::JQueryHtml;
    assert_eq!(js_security_severity(&issue), 4.5);
}

#[test]
fn severity_unsafe_url_scheme() {
    let issue = JsSecurityIssue::UnsafeUrlScheme {
        scheme: "javascript:".to_string(),
    };
    assert_eq!(js_security_severity(&issue), 4.5);
}

#[test]
fn severity_inline_event_handler() {
    let issue = JsSecurityIssue::InlineEventHandler {
        handler: "onclick".to_string(),
    };
    assert_eq!(js_security_severity(&issue), 4.0);
}

#[test]
fn severity_json_parse_unsafe() {
    let issue = JsSecurityIssue::JsonParseUnsafe {
        context: "test".to_string(),
    };
    assert_eq!(js_security_severity(&issue), 3.5);
}

#[test]
fn severity_settimeout_string() {
    let issue = JsSecurityIssue::SetTimeoutString;
    assert_eq!(js_security_severity(&issue), 3.0);
}

#[test]
fn severity_setinterval_string() {
    let issue = JsSecurityIssue::SetIntervalString;
    assert_eq!(js_security_severity(&issue), 3.0);
}

// ===== analyze_js_security tests (32 tests) =====

#[test]
fn analyze_eval_detected() {
    let html = r#"<script>eval(userInput)</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::EvalUsage { context } if context == "inline_script"
    )));
}

#[test]
fn analyze_innerhtml_detected() {
    let html = r#"<script>element.innerHTML = data;</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::InnerHtmlAssignment { context } if context == "inline_script"
    )));
}

#[test]
fn analyze_document_write_detected() {
    let html = r#"<script>document.write('<p>test</p>')</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::DocumentWrite))
    );
}

#[test]
fn analyze_outerhtml_detected() {
    let html = r#"<script>element.outerHTML = content;</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::OuterHtmlAssignment))
    );
}

#[test]
fn analyze_insert_adjacent_html_detected() {
    let html = r#"<script>el.insertAdjacentHTML('beforeend', html)</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::InsertAdjacentHtml))
    );
}

#[test]
fn analyze_jquery_html_detected() {
    let html = r#"<script>$('#content').html(userHtml)</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::JQueryHtml))
    );
}

#[test]
fn analyze_dangerously_set_inner_html_detected() {
    let html = r#"<script>render(<div dangerouslySetInnerHTML={{__html: data}} />)</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::DangerouslySetInnerHtml))
    );
}

#[test]
fn analyze_function_constructor_detected() {
    let html = r#"<script>var fn = new Function(code); fn();</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::FunctionConstructor))
    );
}

#[test]
fn analyze_settimeout_with_string() {
    let html = r#"<script>setTimeout("alert('xss')", 1000)</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::SetTimeoutString))
    );
}

#[test]
fn analyze_settimeout_with_function_no_issue() {
    let html = r#"<script>setTimeout(function() { alert('ok'); }, 1000)</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::SetTimeoutString))
    );
}

#[test]
fn analyze_setinterval_with_string() {
    let html = r#"<script>setInterval('doSomething()', 500)</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::SetIntervalString))
    );
}

#[test]
fn analyze_postmessage_no_origin_check() {
    let html = r#"<script>window.postMessage(data, '*')</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::PostMessageNoOriginCheck))
    );
}

#[test]
fn analyze_postmessage_with_origin_no_issue() {
    let html = r#"<script>if (event.origin === 'https://trusted.com') { window.postMessage(data, event.origin) }</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::PostMessageNoOriginCheck))
    );
}

#[test]
fn analyze_json_parse_without_try() {
    let html = r#"<script>var obj = JSON.parse(userInput)</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::JsonParseUnsafe { context } if context == "no_try_catch"
    )));
}

#[test]
fn analyze_json_parse_with_try_no_issue() {
    let html = r#"<script>try { var obj = JSON.parse(userInput) } catch(e) {}</script>"#;
    let issues = analyze_js_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsSecurityIssue::JsonParseUnsafe { .. }))
    );
}

#[test]
fn analyze_dom_xss_location_href() {
    let html = r#"<script>location.href = userInput</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::DomXssSink { sink } if sink == "location.href"
    )));
}

#[test]
fn analyze_dom_xss_location_assign() {
    let html = r#"<script>location.assign(url)</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::DomXssSink { sink } if sink == "location.assign"
    )));
}

#[test]
fn analyze_dom_xss_window_open() {
    let html = r#"<script>window.open(userUrl)</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::DomXssSink { sink } if sink == "window.open"
    )));
}

#[test]
fn analyze_dom_xss_document_cookie() {
    let html = r#"<script>document.cookie = data</script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::DomXssSink { sink } if sink == "document.cookie"
    )));
}

#[test]
fn analyze_inline_handler_onclick() {
    let html = r#"<button onclick="handleClick()">Click</button>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::InlineEventHandler { handler } if handler == "onclick"
    )));
}

#[test]
fn analyze_inline_handler_onerror() {
    let html = r#"<img src="x" onerror="alert(1)">"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::InlineEventHandler { handler } if handler == "onerror"
    )));
}

#[test]
fn analyze_multiple_inline_handlers() {
    let html = r#"<div onclick="a()" onmouseover="b()"></div>"#;
    let issues = analyze_js_security(html);
    let handler_count = issues
        .iter()
        .filter(|i| matches!(i, JsSecurityIssue::InlineEventHandler { .. }))
        .count();
    assert!(handler_count >= 2);
}

#[test]
fn analyze_unsafe_scheme_javascript() {
    let html = r#"<a href="javascript:alert(1)">Click</a>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::UnsafeUrlScheme { scheme } if scheme == "javascript:"
    )));
}

#[test]
fn analyze_unsafe_scheme_vbscript() {
    let html = r#"<a href="vbscript:msgbox(1)">Click</a>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::UnsafeUrlScheme { scheme } if scheme == "vbscript:"
    )));
}

#[test]
fn analyze_unsafe_scheme_data_html() {
    let html = r#"<iframe src="data:text/html,<script>alert(1)</script>"></iframe>"#;
    let issues = analyze_js_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        JsSecurityIssue::UnsafeUrlScheme { scheme } if scheme == "data:text/html"
    )));
}

#[test]
fn analyze_no_issues_clean_html() {
    let html = r#"<html><body><script>console.log('safe');</script></body></html>"#;
    let issues = analyze_js_security(html);
    assert!(issues.is_empty());
}

#[test]
fn analyze_skips_external_scripts() {
    let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
    let issues = analyze_js_security(html);
    assert!(issues.is_empty());
}

#[test]
fn analyze_multiple_scripts_multiple_issues() {
    let html = r#"
        <script>eval(x)</script>
        <script>document.write(y)</script>
        <script>element.innerHTML = z</script>
    "#;
    let issues = analyze_js_security(html);
    assert!(issues.len() >= 3);
}

#[test]
fn analyze_combined_all_issue_types() {
    let html = r#"
        <script>
            eval(userInput);
            element.innerHTML = data;
            document.write(content);
            location.href = url;
            window.postMessage(msg, '*');
            JSON.parse(raw);
            setTimeout("alert(1)", 100);
        </script>
        <button onclick="click()">Test</button>
        <a href="javascript:void(0)">Link</a>
    "#;
    let issues = analyze_js_security(html);
    assert!(issues.len() >= 9);
}

// ===== js_security_to_operations tests (3 tests) =====

#[test]
fn js_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = js_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn js_operations_single_issue() {
    let issues = vec![JsSecurityIssue::EvalUsage {
        context: "test".to_string(),
    }];
    let mut seq = 0;
    let ops = js_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn js_operations_multiple_issues() {
    let issues = vec![
        JsSecurityIssue::EvalUsage {
            context: "test".to_string(),
        },
        JsSecurityIssue::DocumentWrite,
        JsSecurityIssue::DomXssSink {
            sink: "location.href".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = js_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
