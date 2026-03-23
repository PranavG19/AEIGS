use crate::jsonp_audit::*;

// --- CallbackParam ---

#[test]
fn callback_param_detected() {
    let html = r#"<script src="https://api.example.com/data?callback=handleData"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { param, .. } if param == "callback"))
    );
}

#[test]
fn jsonp_param_detected() {
    let html = r#"<script src="/api/feed?jsonp=cb123"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { param, .. } if param == "jsonp"))
    );
}

#[test]
fn cb_param_detected() {
    let html = r#"<script src="/api/v1?cb=myFunc"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { param, .. } if param == "cb"))
    );
}

#[test]
fn jsonpcallback_param_detected() {
    let html = r#"<script src="/api?jsonpcallback=fn1"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues.iter().any(
            |i| matches!(i, JsonpIssue::CallbackParam { param, .. } if param == "jsonpcallback")
        )
    );
}

#[test]
fn jsoncallback_param_detected() {
    let html = r#"<script src="/api?jsoncallback=fn2"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues.iter().any(
            |i| matches!(i, JsonpIssue::CallbackParam { param, .. } if param == "jsoncallback")
        )
    );
}

#[test]
fn underscore_callback_param_detected() {
    let html = r#"<script src="/api?_callback=fn3"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { param, .. } if param == "_callback"))
    );
}

#[test]
fn case_insensitive_param() {
    let html = r#"<script src="/api?CALLBACK=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { .. }))
    );
}

// --- JsonpEndpoint ---

#[test]
fn jsonp_endpoint_path() {
    let html = r#"<script src="/api/data.jsonp"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpEndpoint { .. }))
    );
}

#[test]
fn jsonp_in_path_without_callback_is_endpoint() {
    let html = r#"<script src="/jsonp/feed"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpEndpoint { .. }))
    );
}

#[test]
fn no_duplicate_endpoint_when_callback_present() {
    let html = r#"<script src="/jsonp/data?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpEndpoint { .. }))
    );
}

// --- UserControlledCallback ---

#[test]
fn user_controlled_callback_url_value() {
    let html = r#"<script src="/api?callback=http://evil.com/steal"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::UserControlledCallback { .. }))
    );
}

#[test]
fn user_controlled_callback_javascript_proto() {
    let html = r#"<script src="/api?callback=javascript:alert(1)"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::UserControlledCallback { .. }))
    );
}

#[test]
fn user_controlled_callback_double_quote() {
    let html = r#"<script src='/api?callback=fn"injected'></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::UserControlledCallback { .. }))
    );
}

#[test]
fn normal_callback_not_user_controlled() {
    let html = r#"<script src="/api?callback=handleData"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::UserControlledCallback { .. }))
    );
}

// --- SensitiveJsonpEndpoint ---

#[test]
fn sensitive_endpoint_user_path() {
    let html = r#"<script src="/api/user/data?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::SensitiveJsonpEndpoint { .. }))
    );
}

#[test]
fn sensitive_endpoint_account_path() {
    let html = r#"<script src="/account/info?jsonp=cb"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::SensitiveJsonpEndpoint { .. }))
    );
}

#[test]
fn sensitive_endpoint_profile_path() {
    let html = r#"<script src="/api/profile?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::SensitiveJsonpEndpoint { .. }))
    );
}

#[test]
fn sensitive_endpoint_auth_path() {
    let html = r#"<script src="/auth/token.jsonp"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::SensitiveJsonpEndpoint { .. }))
    );
}

#[test]
fn non_sensitive_path_no_flag() {
    let html = r#"<script src="/api/weather?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::SensitiveJsonpEndpoint { .. }))
    );
}

// --- CrossDomainJsonp ---

#[test]
fn cross_domain_https() {
    let html = r#"<script src="https://api.external.com/data?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CrossDomainJsonp { .. }))
    );
}

#[test]
fn cross_domain_http() {
    let html = r#"<script src="http://cdn.example.com/feed?jsonp=cb"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CrossDomainJsonp { .. }))
    );
}

#[test]
fn relative_path_not_cross_domain() {
    let html = r#"<script src="/api?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CrossDomainJsonp { .. }))
    );
}

// --- JsonpOverHttp ---

#[test]
fn jsonp_over_http_detected() {
    let html = r#"<script src="http://api.example.com/data?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpOverHttp { .. }))
    );
}

#[test]
fn jsonp_over_https_not_flagged() {
    let html = r#"<script src="https://api.example.com/data?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpOverHttp { .. }))
    );
}

// --- DynamicCallbackName ---

#[test]
fn dynamic_callback_with_plus() {
    let html = r#"<script src="/api?callback=window.cb+Date.now()"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::DynamicCallbackName { .. }))
    );
}

#[test]
fn dynamic_callback_with_dot() {
    let html = r#"<script src="/api?callback=app.handler.process"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::DynamicCallbackName { .. }))
    );
}

#[test]
fn dynamic_callback_with_brackets() {
    let html = r#"<script src="/api?callback=window[name]"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::DynamicCallbackName { .. }))
    );
}

#[test]
fn static_callback_not_dynamic() {
    let html = r#"<script src="/api?callback=handleData"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::DynamicCallbackName { .. }))
    );
}

// --- InlineJsonpHandler ---

#[test]
fn inline_ajax_jsonp() {
    let html = r#"<script>$.ajax({ url: "/api", dataType: "jsonp" });</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::InlineJsonpHandler))
    );
}

#[test]
fn inline_getjson_with_callback() {
    let html = r#"<script>$.getJSON("/api?callback=?", function(data) {});</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::InlineJsonpHandler))
    );
}

#[test]
fn inline_ajax_datatype_jsonp() {
    let html = r#"<script>$.ajax({ url: "/data", dataType: "jsonp", jsonp: "cb" });</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::InlineJsonpHandler))
    );
}

#[test]
fn inline_no_jsonp_not_flagged() {
    let html = r#"<script>$.ajax({ url: "/api", dataType: "json" });</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::InlineJsonpHandler))
    );
}

#[test]
fn inline_jsonp_only_reported_once() {
    let html = concat!(
        r#"<script>$.ajax({ url: "/a", dataType: "jsonp" });</script>"#,
        r#"<script>$.ajax({ url: "/b", dataType: "jsonp" });</script>"#,
    );
    let issues = find_jsonp_endpoints(html);
    let count = issues
        .iter()
        .filter(|i| matches!(i, JsonpIssue::InlineJsonpHandler))
        .count();
    assert_eq!(count, 1);
}

// --- JsonpWithoutReferrerCheck ---

#[test]
fn jsonp_without_referrer_check() {
    let html = r#"<script>$.getJSON("/api?callback=fn", handler);</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpWithoutReferrerCheck))
    );
}

#[test]
fn jsonp_with_referrer_check_not_flagged() {
    let html = r#"<script>if (document.referrer) { $.getJSON("/api?callback=fn"); }</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpWithoutReferrerCheck))
    );
}

#[test]
fn no_jsonp_content_no_referrer_issue() {
    let html = r#"<script>console.log("hello");</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpWithoutReferrerCheck))
    );
}

// --- Empty / basic cases ---

#[test]
fn no_scripts_no_issues() {
    let issues = find_jsonp_endpoints("<html><body>Hello</body></html>");
    assert!(issues.is_empty());
}

#[test]
fn normal_script_not_flagged() {
    let html = r#"<script src="/js/app.js"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues.is_empty());
}

#[test]
fn inline_script_without_jsonp_not_flagged() {
    let html = r#"<script>var x = 42;</script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_scripts_some_jsonp() {
    let html = concat!(
        r#"<script src="/js/app.js"></script>"#,
        r#"<script src="/api?callback=fn1"></script>"#,
        r#"<script src="/static/lib.js"></script>"#,
    );
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { .. }))
    );
}

// --- Display ---

#[test]
fn display_callback_param() {
    let issue = JsonpIssue::CallbackParam {
        url: "/api".to_string(),
        param: "callback".to_string(),
    };
    assert_eq!(issue.to_string(), "callback_param:callback:/api");
}

#[test]
fn display_jsonp_endpoint() {
    let issue = JsonpIssue::JsonpEndpoint {
        url: "/data.jsonp".to_string(),
    };
    assert_eq!(issue.to_string(), "jsonp_endpoint:/data.jsonp");
}

#[test]
fn display_user_controlled() {
    let issue = JsonpIssue::UserControlledCallback {
        url: "/api".to_string(),
    };
    assert_eq!(issue.to_string(), "user_controlled_callback:/api");
}

#[test]
fn display_sensitive() {
    let issue = JsonpIssue::SensitiveJsonpEndpoint {
        url: "/user".to_string(),
    };
    assert_eq!(issue.to_string(), "sensitive_jsonp_endpoint:/user");
}

#[test]
fn display_cross_domain() {
    let issue = JsonpIssue::CrossDomainJsonp {
        url: "https://x.com".to_string(),
    };
    assert_eq!(issue.to_string(), "cross_domain_jsonp:https://x.com");
}

#[test]
fn display_inline_handler() {
    assert_eq!(
        JsonpIssue::InlineJsonpHandler.to_string(),
        "inline_jsonp_handler"
    );
}

#[test]
fn display_without_referrer() {
    assert_eq!(
        JsonpIssue::JsonpWithoutReferrerCheck.to_string(),
        "jsonp_without_referrer_check"
    );
}

#[test]
fn display_dynamic_callback() {
    let issue = JsonpIssue::DynamicCallbackName {
        url: "/api".to_string(),
    };
    assert_eq!(issue.to_string(), "dynamic_callback_name:/api");
}

#[test]
fn display_over_http() {
    let issue = JsonpIssue::JsonpOverHttp {
        url: "http://x.com".to_string(),
    };
    assert_eq!(issue.to_string(), "jsonp_over_http:http://x.com");
}

// --- Severity ---

#[test]
fn severity_callback_param() {
    let issue = JsonpIssue::CallbackParam {
        url: String::new(),
        param: String::new(),
    };
    assert!((jsonp_severity(&issue) - 5.5).abs() < f64::EPSILON);
}

#[test]
fn severity_jsonp_endpoint() {
    let issue = JsonpIssue::JsonpEndpoint { url: String::new() };
    assert!((jsonp_severity(&issue) - 4.5).abs() < f64::EPSILON);
}

#[test]
fn severity_user_controlled() {
    let issue = JsonpIssue::UserControlledCallback { url: String::new() };
    assert!((jsonp_severity(&issue) - 7.0).abs() < f64::EPSILON);
}

#[test]
fn severity_sensitive() {
    let issue = JsonpIssue::SensitiveJsonpEndpoint { url: String::new() };
    assert!((jsonp_severity(&issue) - 6.0).abs() < f64::EPSILON);
}

#[test]
fn severity_cross_domain() {
    let issue = JsonpIssue::CrossDomainJsonp { url: String::new() };
    assert!((jsonp_severity(&issue) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_inline_handler() {
    assert!((jsonp_severity(&JsonpIssue::InlineJsonpHandler) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_without_referrer() {
    assert!((jsonp_severity(&JsonpIssue::JsonpWithoutReferrerCheck) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_dynamic_callback() {
    let issue = JsonpIssue::DynamicCallbackName { url: String::new() };
    assert!((jsonp_severity(&issue) - 5.5).abs() < f64::EPSILON);
}

#[test]
fn severity_over_http() {
    let issue = JsonpIssue::JsonpOverHttp { url: String::new() };
    assert!((jsonp_severity(&issue) - 4.5).abs() < f64::EPSILON);
}

// --- Operations ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = jsonp_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let html = r#"<script src="/api?callback=fn"></script>"#;
    let issues = find_jsonp_endpoints(html);
    let count = issues.len();
    let mut seq = 0;
    let ops = jsonp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), count);
    assert_eq!(seq, count as u64);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        JsonpIssue::CallbackParam {
            url: "/a".to_string(),
            param: "callback".to_string(),
        },
        JsonpIssue::JsonpEndpoint {
            url: "/b".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = jsonp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 7);
}

// --- URL truncation ---

#[test]
fn long_url_truncated() {
    let long_path = "a".repeat(200);
    let html = format!(r#"<script src="/api/{long_path}?callback=fn"></script>"#);
    let issues = find_jsonp_endpoints(&html);
    assert!(issues.iter().any(|i| match i {
        JsonpIssue::CallbackParam { url, .. } => url.len() <= 103,
        _ => false,
    }));
}

// --- Combined scenario ---

#[test]
fn multiple_issues_from_single_tag() {
    let html =
        r#"<script src="http://api.external.com/user/data?callback=http://evil.com"></script>"#;
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::UserControlledCallback { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::SensitiveJsonpEndpoint { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CrossDomainJsonp { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::JsonpOverHttp { .. }))
    );
}

#[test]
fn mixed_script_and_inline() {
    let html = concat!(
        r#"<script src="/api?callback=fn"></script>"#,
        r#"<script>$.ajax({ url: "/x", dataType: "jsonp" });</script>"#,
    );
    let issues = find_jsonp_endpoints(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::CallbackParam { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, JsonpIssue::InlineJsonpHandler))
    );
}
