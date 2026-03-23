use crate::method_override_audit::*;

// --- Basic detection: same status produces no issues ---

#[test]
fn same_status_no_issue() {
    let issues = analyze_method_override(200, 200, "header:X-HTTP-Method-Override", "DELETE");
    assert!(issues.is_empty());
}

#[test]
fn same_status_no_issue_param() {
    let issues = analyze_method_override(404, 404, "param:_method", "PUT");
    assert!(issues.is_empty());
}

#[test]
fn same_status_no_issue_content_type() {
    let issues = analyze_method_override(200, 200, "content-type:application/xml", "POST");
    assert!(issues.is_empty());
}

// --- Header override detection ---

#[test]
fn header_override_detected() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method-Override", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::HeaderOverrideAccepted { header, method }
            if header == "X-HTTP-Method-Override" && method == "DELETE"
    )));
}

#[test]
fn header_override_x_http_method() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method", "PUT");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::HeaderOverrideAccepted { header, method }
            if header == "X-HTTP-Method" && method == "PUT"
    )));
}

#[test]
fn header_override_x_method_override() {
    let issues = analyze_method_override(200, 500, "header:X-Method-Override", "PATCH");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::HeaderOverrideAccepted { header, method }
            if header == "X-Method-Override" && method == "PATCH"
    )));
}

// --- Query param override detection ---

#[test]
fn param_override_detected() {
    let issues = analyze_method_override(200, 405, "param:_method", "PUT");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::QueryParamOverrideAccepted { param, method }
            if param == "_method" && method == "PUT"
    )));
}

#[test]
fn param_override_method_param() {
    let issues = analyze_method_override(200, 301, "param:method", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::QueryParamOverrideAccepted { param, .. }
            if param == "method"
    )));
}

// --- MethodChangeAltersResponse detection ---

#[test]
fn response_alteration_detected_success_to_error() {
    let issues = analyze_method_override(200, 405, "header:X-Method-Override", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn response_alteration_detected_error_to_success() {
    let issues = analyze_method_override(404, 200, "header:X-HTTP-Method", "PUT");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn no_alteration_when_both_success() {
    let issues = analyze_method_override(200, 201, "header:X-HTTP-Method-Override", "PUT");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn no_alteration_when_both_error() {
    let issues = analyze_method_override(404, 405, "header:X-HTTP-Method-Override", "DELETE");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn response_alteration_403_to_200() {
    let issues = analyze_method_override(403, 200, "param:_method", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

// --- ContentTypeOverride detection ---

#[test]
fn content_type_override_detected() {
    let issues = analyze_method_override(200, 415, "content-type:application/xml", "POST");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::ContentTypeOverride { content_type }
            if content_type == "application/xml"
    )));
}

#[test]
fn content_type_override_multipart() {
    let issues = analyze_method_override(200, 500, "content-type:multipart/form-data", "POST");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::ContentTypeOverride { content_type }
            if content_type == "multipart/form-data"
    )));
}

#[test]
fn content_type_override_not_on_same_status() {
    let issues = analyze_method_override(200, 200, "content-type:text/plain", "GET");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::ContentTypeOverride { .. }))
    );
}

// --- CustomHeaderAccepted detection ---

#[test]
fn custom_header_detected() {
    let issues = analyze_method_override(200, 405, "custom-header:X-Forwarded-Method", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::CustomHeaderAccepted { header }
            if header == "X-Forwarded-Method"
    )));
}

#[test]
fn custom_header_not_on_same_status() {
    let issues = analyze_method_override(200, 200, "custom-header:X-Custom", "PUT");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::CustomHeaderAccepted { .. }))
    );
}

// --- MultipleOverridesAccepted detection ---

#[test]
fn multiple_overrides_detected() {
    let issues = analyze_method_override(200, 405, "multi", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MultipleOverridesAccepted))
    );
}

#[test]
fn multiple_overrides_not_on_same_status() {
    let issues = analyze_method_override(200, 200, "multi", "PUT");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MultipleOverridesAccepted))
    );
}

// --- OverrideBypassesAuth detection ---

#[test]
fn auth_bypass_from_401() {
    let issues = analyze_method_override(401, 200, "header:X-HTTP-Method-Override", "GET");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideBypassesAuth { override_type, method }
            if override_type == "header:X-HTTP-Method-Override" && method == "GET"
    )));
}

#[test]
fn auth_bypass_from_403() {
    let issues = analyze_method_override(403, 200, "param:_method", "PUT");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideBypassesAuth { override_type, .. }
            if override_type == "param:_method"
    )));
}

#[test]
fn auth_bypass_requires_2xx_response() {
    let issues = analyze_method_override(401, 301, "header:X-HTTP-Method", "GET");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideBypassesAuth { .. }))
    );
}

#[test]
fn auth_bypass_not_from_404() {
    let issues = analyze_method_override(404, 200, "header:X-HTTP-Method", "GET");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideBypassesAuth { .. }))
    );
}

#[test]
fn auth_bypass_403_to_204() {
    let issues = analyze_method_override(403, 204, "header:X-Method-Override", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideBypassesAuth { .. }))
    );
}

// --- OverrideEnablesWrite detection ---

#[test]
fn write_enabled_delete() {
    let issues = analyze_method_override(200, 204, "header:X-HTTP-Method-Override", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideEnablesWrite { method }
            if method == "DELETE"
    )));
}

#[test]
fn write_enabled_put() {
    let issues = analyze_method_override(200, 201, "param:_method", "PUT");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideEnablesWrite { method }
            if method == "PUT"
    )));
}

#[test]
fn write_enabled_patch() {
    let issues = analyze_method_override(200, 202, "header:X-HTTP-Method", "PATCH");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideEnablesWrite { method }
            if method == "PATCH"
    )));
}

#[test]
fn write_not_enabled_for_get() {
    let issues = analyze_method_override(200, 201, "header:X-HTTP-Method-Override", "GET");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideEnablesWrite { .. }))
    );
}

#[test]
fn write_not_enabled_when_error_response() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method-Override", "DELETE");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideEnablesWrite { .. }))
    );
}

#[test]
fn write_enabled_case_insensitive_method() {
    let issues = analyze_method_override(200, 201, "header:X-HTTP-Method-Override", "delete");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideEnablesWrite { method }
            if method == "delete"
    )));
}

#[test]
fn write_not_enabled_same_status() {
    let issues = analyze_method_override(200, 200, "header:X-HTTP-Method-Override", "DELETE");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideEnablesWrite { .. }))
    );
}

// --- TraceMethodViaOverride detection ---

#[test]
fn trace_detected() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method-Override", "TRACE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::TraceMethodViaOverride { override_type }
            if override_type == "header:X-HTTP-Method-Override"
    )));
}

#[test]
fn trace_not_detected_same_status() {
    let issues = analyze_method_override(200, 200, "header:X-HTTP-Method", "TRACE");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::TraceMethodViaOverride { .. }))
    );
}

#[test]
fn trace_case_insensitive() {
    let issues = analyze_method_override(200, 405, "param:_method", "trace");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::TraceMethodViaOverride { .. }))
    );
}

// --- OverrideIgnoresCase detection ---

#[test]
fn case_insensitive_header_detected() {
    let issues = analyze_method_override(200, 405, "case-header:x-http-method-override", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::OverrideIgnoresCase { header }
            if header == "x-http-method-override"
    )));
}

#[test]
fn case_insensitive_not_on_same_status() {
    let issues = analyze_method_override(200, 200, "case-header:x-method-override", "PUT");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideIgnoresCase { .. }))
    );
}

// --- BodyOverrideAccepted detection ---

#[test]
fn body_override_detected() {
    let issues = analyze_method_override(200, 405, "body:_method", "DELETE");
    assert!(issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::BodyOverrideAccepted { param }
            if param == "_method"
    )));
}

#[test]
fn body_override_not_on_same_status() {
    let issues = analyze_method_override(200, 200, "body:method", "PUT");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::BodyOverrideAccepted { .. }))
    );
}

// --- Edge cases ---

#[test]
fn empty_override_type_no_typed_issue() {
    let issues = analyze_method_override(200, 405, "", "DELETE");
    assert!(!issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::HeaderOverrideAccepted { .. }
            | MethodOverrideIssue::QueryParamOverrideAccepted { .. }
            | MethodOverrideIssue::ContentTypeOverride { .. }
            | MethodOverrideIssue::CustomHeaderAccepted { .. }
            | MethodOverrideIssue::BodyOverrideAccepted { .. }
            | MethodOverrideIssue::OverrideIgnoresCase { .. }
            | MethodOverrideIssue::MultipleOverridesAccepted
    )));
}

#[test]
fn empty_override_type_still_detects_alteration() {
    let issues = analyze_method_override(200, 500, "", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn unknown_prefix_no_typed_issue() {
    let issues = analyze_method_override(200, 405, "unknown:foo", "DELETE");
    assert!(!issues.iter().any(|i| matches!(
        i,
        MethodOverrideIssue::HeaderOverrideAccepted { .. }
            | MethodOverrideIssue::QueryParamOverrideAccepted { .. }
            | MethodOverrideIssue::ContentTypeOverride { .. }
            | MethodOverrideIssue::CustomHeaderAccepted { .. }
    )));
}

#[test]
fn empty_method_no_write_enable() {
    let issues = analyze_method_override(200, 201, "header:X-HTTP-Method-Override", "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideEnablesWrite { .. }))
    );
}

#[test]
fn empty_method_no_trace() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method-Override", "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::TraceMethodViaOverride { .. }))
    );
}

// --- Boundary conditions: status code edges ---

#[test]
fn boundary_299_to_300_is_alteration() {
    let issues = analyze_method_override(299, 300, "header:X-HTTP-Method", "PUT");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::HeaderOverrideAccepted { .. }))
    );
}

#[test]
fn boundary_300_to_299_no_alteration() {
    let issues = analyze_method_override(300, 299, "header:X-HTTP-Method", "PUT");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn boundary_399_to_200_is_alteration() {
    let issues = analyze_method_override(400, 200, "param:_method", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn boundary_301_vs_302_no_alteration() {
    let issues = analyze_method_override(301, 302, "header:X-HTTP-Method-Override", "GET");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

// --- Multiple issues from single input ---

#[test]
fn header_override_and_alteration_together() {
    let issues = analyze_method_override(200, 500, "header:X-HTTP-Method-Override", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::HeaderOverrideAccepted { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn auth_bypass_also_triggers_alteration() {
    let issues = analyze_method_override(401, 200, "header:X-HTTP-Method", "PUT");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideBypassesAuth { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

#[test]
fn auth_bypass_and_write_enable_together() {
    let issues = analyze_method_override(403, 201, "header:X-HTTP-Method-Override", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::OverrideBypassesAuth { .. }))
    );
}

#[test]
fn trace_and_header_override_together() {
    let issues = analyze_method_override(200, 405, "header:X-HTTP-Method-Override", "TRACE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::HeaderOverrideAccepted { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::TraceMethodViaOverride { .. }))
    );
}

#[test]
fn multi_override_plus_alteration() {
    let issues = analyze_method_override(200, 500, "multi", "DELETE");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MultipleOverridesAccepted))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MethodOverrideIssue::MethodChangeAltersResponse { .. }))
    );
}

// --- Severity ordering ---

#[test]
fn severity_ordering() {
    assert!(
        method_override_severity(&MethodOverrideIssue::MethodChangeAltersResponse {
            override_type: "header".into(),
            method: "DELETE".into()
        }) > method_override_severity(&MethodOverrideIssue::HeaderOverrideAccepted {
            header: "X-HTTP-Method-Override".into(),
            method: "DELETE".into()
        })
    );
    assert!(
        method_override_severity(&MethodOverrideIssue::HeaderOverrideAccepted {
            header: "X-HTTP-Method".into(),
            method: "PUT".into()
        }) > method_override_severity(&MethodOverrideIssue::QueryParamOverrideAccepted {
            param: "_method".into(),
            method: "PUT".into()
        })
    );
}

#[test]
fn severity_auth_bypass_highest() {
    let auth = method_override_severity(&MethodOverrideIssue::OverrideBypassesAuth {
        override_type: "header:X-HTTP-Method".into(),
        method: "GET".into(),
    });
    let trace = method_override_severity(&MethodOverrideIssue::TraceMethodViaOverride {
        override_type: "header:X-HTTP-Method".into(),
    });
    let write = method_override_severity(&MethodOverrideIssue::OverrideEnablesWrite {
        method: "DELETE".into(),
    });
    let alter = method_override_severity(&MethodOverrideIssue::MethodChangeAltersResponse {
        override_type: "header".into(),
        method: "DELETE".into(),
    });
    assert!(auth > trace);
    assert!(trace > write);
    assert!(write > alter);
}

#[test]
fn severity_multi_gt_content_type() {
    let multi = method_override_severity(&MethodOverrideIssue::MultipleOverridesAccepted);
    let ct = method_override_severity(&MethodOverrideIssue::ContentTypeOverride {
        content_type: "application/xml".into(),
    });
    assert!(multi > ct);
}

#[test]
fn severity_content_type_gt_header() {
    let ct = method_override_severity(&MethodOverrideIssue::ContentTypeOverride {
        content_type: "application/xml".into(),
    });
    let header = method_override_severity(&MethodOverrideIssue::HeaderOverrideAccepted {
        header: "X-HTTP-Method-Override".into(),
        method: "DELETE".into(),
    });
    assert!(ct > header);
}

#[test]
fn severity_body_eq_header() {
    let body = method_override_severity(&MethodOverrideIssue::BodyOverrideAccepted {
        param: "_method".into(),
    });
    let header = method_override_severity(&MethodOverrideIssue::HeaderOverrideAccepted {
        header: "X-HTTP-Method-Override".into(),
        method: "DELETE".into(),
    });
    assert!((body - header).abs() < f64::EPSILON);
}

#[test]
fn severity_custom_header_eq_param() {
    let custom = method_override_severity(&MethodOverrideIssue::CustomHeaderAccepted {
        header: "X-Forwarded-Method".into(),
    });
    let param = method_override_severity(&MethodOverrideIssue::QueryParamOverrideAccepted {
        param: "_method".into(),
        method: "PUT".into(),
    });
    assert!((custom - param).abs() < f64::EPSILON);
}

#[test]
fn severity_case_insensitive_lowest() {
    let case_insensitive = method_override_severity(&MethodOverrideIssue::OverrideIgnoresCase {
        header: "x-http-method-override".into(),
    });
    let param = method_override_severity(&MethodOverrideIssue::QueryParamOverrideAccepted {
        param: "_method".into(),
        method: "PUT".into(),
    });
    assert!(case_insensitive < param);
}

// --- Display format ---

#[test]
fn display_header_override() {
    let issue = MethodOverrideIssue::HeaderOverrideAccepted {
        header: "X-HTTP-Method-Override".into(),
        method: "DELETE".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_header:X-HTTP-Method-Override=DELETE"
    );
}

#[test]
fn display_param_override() {
    let issue = MethodOverrideIssue::QueryParamOverrideAccepted {
        param: "_method".into(),
        method: "PUT".into(),
    };
    assert_eq!(issue.to_string(), "method_override_param:_method=PUT");
}

#[test]
fn display_method_change() {
    let issue = MethodOverrideIssue::MethodChangeAltersResponse {
        override_type: "header:X-HTTP-Method".into(),
        method: "PATCH".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_effect:header:X-HTTP-Method=PATCH"
    );
}

#[test]
fn display_content_type_override() {
    let issue = MethodOverrideIssue::ContentTypeOverride {
        content_type: "application/xml".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_content_type:application/xml"
    );
}

#[test]
fn display_custom_header() {
    let issue = MethodOverrideIssue::CustomHeaderAccepted {
        header: "X-Forwarded-Method".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_custom_header:X-Forwarded-Method"
    );
}

#[test]
fn display_multiple_overrides() {
    let issue = MethodOverrideIssue::MultipleOverridesAccepted;
    assert_eq!(issue.to_string(), "method_override_multiple_accepted");
}

#[test]
fn display_auth_bypass() {
    let issue = MethodOverrideIssue::OverrideBypassesAuth {
        override_type: "header:X-HTTP-Method".into(),
        method: "GET".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_auth_bypass:header:X-HTTP-Method=GET"
    );
}

#[test]
fn display_enables_write() {
    let issue = MethodOverrideIssue::OverrideEnablesWrite {
        method: "DELETE".into(),
    };
    assert_eq!(issue.to_string(), "method_override_enables_write:DELETE");
}

#[test]
fn display_trace() {
    let issue = MethodOverrideIssue::TraceMethodViaOverride {
        override_type: "header:X-HTTP-Method-Override".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_trace:header:X-HTTP-Method-Override"
    );
}

#[test]
fn display_case_insensitive() {
    let issue = MethodOverrideIssue::OverrideIgnoresCase {
        header: "x-http-method-override".into(),
    };
    assert_eq!(
        issue.to_string(),
        "method_override_case_insensitive:x-http-method-override"
    );
}

#[test]
fn display_body_override() {
    let issue = MethodOverrideIssue::BodyOverrideAccepted {
        param: "_method".into(),
    };
    assert_eq!(issue.to_string(), "method_override_body:_method");
}

// --- Operations ---

#[test]
fn to_operations_produces_entries() {
    let issues = vec![MethodOverrideIssue::HeaderOverrideAccepted {
        header: "X-HTTP-Method-Override".into(),
        method: "DELETE".into(),
    }];
    let mut seq = 30;
    let ops = method_override_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 31);
}

#[test]
fn to_operations_multiple_issues() {
    let issues = vec![
        MethodOverrideIssue::HeaderOverrideAccepted {
            header: "X-HTTP-Method-Override".into(),
            method: "DELETE".into(),
        },
        MethodOverrideIssue::MethodChangeAltersResponse {
            override_type: "header:X-HTTP-Method-Override".into(),
            method: "DELETE".into(),
        },
        MethodOverrideIssue::TraceMethodViaOverride {
            override_type: "header:X-HTTP-Method".into(),
        },
    ];
    let mut seq = 10;
    let ops = method_override_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}

#[test]
fn to_operations_empty_issues() {
    let issues: Vec<MethodOverrideIssue> = vec![];
    let mut seq = 5;
    let ops = method_override_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn to_operations_one_per_issue() {
    let issues = vec![
        MethodOverrideIssue::OverrideBypassesAuth {
            override_type: "header:X-HTTP-Method".into(),
            method: "GET".into(),
        },
        MethodOverrideIssue::ContentTypeOverride {
            content_type: "application/xml".into(),
        },
        MethodOverrideIssue::OverrideIgnoresCase {
            header: "x-method-override".into(),
        },
        MethodOverrideIssue::BodyOverrideAccepted {
            param: "_method".into(),
        },
        MethodOverrideIssue::MultipleOverridesAccepted,
    ];
    let mut seq = 0;
    let ops = method_override_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 5);
    assert_eq!(seq, 5);
}

#[test]
fn to_operations_seq_increments_correctly() {
    let issues = vec![MethodOverrideIssue::OverrideEnablesWrite {
        method: "PUT".into(),
    }];
    let mut seq = 99;
    let ops = method_override_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 100);
}
