use crate::expose_headers_audit::*;

// --- Detection tests ---

#[test]
fn no_header_no_issues() {
    let issues = analyze_expose_headers(None);
    assert!(issues.is_empty());
}

#[test]
fn empty_value_no_issues() {
    let issues = analyze_expose_headers(Some(""));
    assert!(issues.is_empty());
}

#[test]
fn spaces_only_no_issues() {
    let issues = analyze_expose_headers(Some("   "));
    assert!(issues.is_empty());
}

#[test]
fn single_safe_header_no_issues() {
    let issues = analyze_expose_headers(Some("Content-Type"));
    assert!(issues.is_empty());
}

#[test]
fn multiple_safe_headers_no_issues() {
    let issues = analyze_expose_headers(Some("Content-Length, Content-Type, Accept"));
    assert!(issues.is_empty());
}

#[test]
fn wildcard_detected() {
    let issues = analyze_expose_headers(Some("*"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::WildcardExpose);
}

#[test]
fn wildcard_short_circuits_other_headers() {
    let issues = analyze_expose_headers(Some("*, Authorization, X-Api-Key"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::WildcardExpose);
}

#[test]
fn authorization_detected() {
    let issues = analyze_expose_headers(Some("Authorization"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::AuthorizationExposed);
}

#[test]
fn authorization_case_insensitive() {
    let issues = analyze_expose_headers(Some("authorization"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::AuthorizationExposed);
}

#[test]
fn api_key_x_api_key() {
    let issues = analyze_expose_headers(Some("X-Api-Key"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::ApiKeyExposed {
            header: "X-Api-Key".to_string()
        }
    );
}

#[test]
fn api_key_bare() {
    let issues = analyze_expose_headers(Some("api-key"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::ApiKeyExposed {
            header: "api-key".to_string()
        }
    );
}

#[test]
fn api_key_no_dash() {
    let issues = analyze_expose_headers(Some("apikey"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::ApiKeyExposed {
            header: "apikey".to_string()
        }
    );
}

#[test]
fn auth_token_x_auth_token() {
    let issues = analyze_expose_headers(Some("X-Auth-Token"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::AuthTokenExposed {
            header: "X-Auth-Token".to_string()
        }
    );
}

#[test]
fn auth_token_x_access_token() {
    let issues = analyze_expose_headers(Some("X-Access-Token"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::AuthTokenExposed {
            header: "X-Access-Token".to_string()
        }
    );
}

#[test]
fn set_cookie_detected() {
    let issues = analyze_expose_headers(Some("Set-Cookie"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::SetCookieExposed);
}

#[test]
fn csrf_token_detected() {
    let issues = analyze_expose_headers(Some("X-Csrf-Token"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::CsrfTokenExposed);
}

#[test]
fn request_id_x_request_id() {
    let issues = analyze_expose_headers(Some("X-Request-Id"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::RequestIdExposed {
            header: "X-Request-Id".to_string()
        }
    );
}

#[test]
fn request_id_amzn() {
    let issues = analyze_expose_headers(Some("X-Amzn-RequestId"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::RequestIdExposed {
            header: "X-Amzn-RequestId".to_string()
        }
    );
}

#[test]
fn trace_id_detected() {
    let issues = analyze_expose_headers(Some("X-Trace-Id"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::TraceIdExposed {
            header: "X-Trace-Id".to_string()
        }
    );
}

#[test]
fn debug_token_detected() {
    let issues = analyze_expose_headers(Some("X-Debug-Token"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::DebugTokenExposed);
}

#[test]
fn server_timing_detected() {
    let issues = analyze_expose_headers(Some("Server-Timing"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::ServerTimingExposed);
}

// --- Internal header prefix detection ---

#[test]
fn internal_header_x_internal_prefix() {
    let issues = analyze_expose_headers(Some("X-Internal-Service-Id"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::InternalHeaderExposed {
            header: "X-Internal-Service-Id".to_string()
        }
    );
}

#[test]
fn internal_header_x_backend_prefix() {
    let issues = analyze_expose_headers(Some("X-Backend-Server"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::InternalHeaderExposed {
            header: "X-Backend-Server".to_string()
        }
    );
}

#[test]
fn internal_header_x_upstream_prefix() {
    let issues = analyze_expose_headers(Some("X-Upstream-Latency"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::InternalHeaderExposed {
            header: "X-Upstream-Latency".to_string()
        }
    );
}

#[test]
fn internal_prefix_case_insensitive() {
    let issues = analyze_expose_headers(Some("x-internal-debug"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::InternalHeaderExposed {
            header: "x-internal-debug".to_string()
        }
    );
}

// --- Credential headers ---

#[test]
fn credential_cookie_detected() {
    let issues = analyze_expose_headers(Some("Cookie"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::CredentialHeaderExposed {
            header: "Cookie".to_string()
        }
    );
}

#[test]
fn credential_proxy_authorization_detected() {
    let issues = analyze_expose_headers(Some("Proxy-Authorization"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::CredentialHeaderExposed {
            header: "Proxy-Authorization".to_string()
        }
    );
}

#[test]
fn credential_www_authenticate_detected() {
    let issues = analyze_expose_headers(Some("WWW-Authenticate"));
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        ExposeHeaderIssue::CredentialHeaderExposed {
            header: "WWW-Authenticate".to_string()
        }
    );
}

// --- Excessive exposure ---

#[test]
fn excessive_exposure_at_threshold() {
    let headers = (0..10)
        .map(|i| format!("X-Custom-{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let issues = analyze_expose_headers(Some(&headers));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ExposeHeaderIssue::ExcessiveExposure { count: 10 }))
    );
}

#[test]
fn no_excessive_exposure_below_threshold() {
    let headers = (0..9)
        .map(|i| format!("X-Custom-{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let issues = analyze_expose_headers(Some(&headers));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ExposeHeaderIssue::ExcessiveExposure { .. }))
    );
}

#[test]
fn excessive_exposure_includes_sensitive_count() {
    let mut parts: Vec<String> = (0..9).map(|i| format!("X-Custom-{i}")).collect();
    parts.push("Authorization".to_string());
    let headers = parts.join(", ");
    let issues = analyze_expose_headers(Some(&headers));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ExposeHeaderIssue::ExcessiveExposure { count: 10 }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ExposeHeaderIssue::AuthorizationExposed))
    );
}

// --- Multiple sensitive headers ---

#[test]
fn multiple_sensitive_headers() {
    let issues = analyze_expose_headers(Some("Authorization, X-Api-Key, Content-Type"));
    assert_eq!(issues.len(), 2);
    assert!(issues.contains(&ExposeHeaderIssue::AuthorizationExposed));
    assert!(issues.contains(&ExposeHeaderIssue::ApiKeyExposed {
        header: "X-Api-Key".to_string()
    }));
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_expose_headers(Some("  Authorization  ,  Content-Type  "));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ExposeHeaderIssue::AuthorizationExposed);
}

// --- Display tests ---

#[test]
fn display_wildcard() {
    assert_eq!(
        ExposeHeaderIssue::WildcardExpose.to_string(),
        "wildcard_expose"
    );
}

#[test]
fn display_authorization() {
    assert_eq!(
        ExposeHeaderIssue::AuthorizationExposed.to_string(),
        "authorization_exposed"
    );
}

#[test]
fn display_api_key() {
    assert_eq!(
        ExposeHeaderIssue::ApiKeyExposed {
            header: "x-api-key".into()
        }
        .to_string(),
        "api_key_exposed"
    );
}

#[test]
fn display_auth_token() {
    assert_eq!(
        ExposeHeaderIssue::AuthTokenExposed {
            header: "x-auth-token".into()
        }
        .to_string(),
        "auth_token_exposed"
    );
}

#[test]
fn display_set_cookie() {
    assert_eq!(
        ExposeHeaderIssue::SetCookieExposed.to_string(),
        "set_cookie_exposed"
    );
}

#[test]
fn display_internal_header() {
    assert_eq!(
        ExposeHeaderIssue::InternalHeaderExposed {
            header: "x-internal-foo".into()
        }
        .to_string(),
        "internal_header_exposed"
    );
}

#[test]
fn display_excessive() {
    assert_eq!(
        ExposeHeaderIssue::ExcessiveExposure { count: 15 }.to_string(),
        "excessive_exposure"
    );
}

#[test]
fn display_credential() {
    assert_eq!(
        ExposeHeaderIssue::CredentialHeaderExposed {
            header: "cookie".into()
        }
        .to_string(),
        "credential_header_exposed"
    );
}

// --- Severity tests ---

#[test]
fn severity_wildcard() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::WildcardExpose),
        5.0
    );
}

#[test]
fn severity_authorization() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::AuthorizationExposed),
        7.0
    );
}

#[test]
fn severity_api_key() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::ApiKeyExposed {
            header: "x-api-key".into()
        }),
        6.5
    );
}

#[test]
fn severity_auth_token() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::AuthTokenExposed {
            header: "x-auth-token".into()
        }),
        6.5
    );
}

#[test]
fn severity_set_cookie() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::SetCookieExposed),
        6.0
    );
}

#[test]
fn severity_csrf_token() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::CsrfTokenExposed),
        5.0
    );
}

#[test]
fn severity_request_id() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::RequestIdExposed {
            header: "x-request-id".into()
        }),
        3.0
    );
}

#[test]
fn severity_trace_id() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::TraceIdExposed {
            header: "x-trace-id".into()
        }),
        3.5
    );
}

#[test]
fn severity_debug_token() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::DebugTokenExposed),
        5.0
    );
}

#[test]
fn severity_server_timing() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::ServerTimingExposed),
        3.5
    );
}

#[test]
fn severity_internal_header() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::InternalHeaderExposed {
            header: "x-internal-foo".into()
        }),
        4.0
    );
}

#[test]
fn severity_excessive() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::ExcessiveExposure { count: 12 }),
        4.5
    );
}

#[test]
fn severity_credential() {
    assert_eq!(
        expose_header_severity(&ExposeHeaderIssue::CredentialHeaderExposed {
            header: "cookie".into()
        }),
        6.0
    );
}

// --- to_operations tests ---

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = expose_headers_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = analyze_expose_headers(Some("Authorization, X-Api-Key"));
    let mut seq = 0;
    let ops = expose_headers_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        ExposeHeaderIssue::AuthorizationExposed,
        ExposeHeaderIssue::SetCookieExposed,
        ExposeHeaderIssue::DebugTokenExposed,
    ];
    let mut seq = 5;
    let ops = expose_headers_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn operations_single_issue() {
    let issues = vec![ExposeHeaderIssue::WildcardExpose];
    let mut seq = 0;
    let ops = expose_headers_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}
