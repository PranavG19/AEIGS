use crate::gateway_bypass::*;

#[test]
fn direct_access_probes_generated_for_backend_hosts() {
    let probes = generate_direct_access_probes(
        "https://api.example.com/v1",
        &["10.0.0.5", "backend.internal"],
    );
    assert!(probes.len() >= 8);
    assert!(
        probes
            .iter()
            .any(|p| p.technique == DirectAccessTechnique::HostHeaderOverride)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == DirectAccessTechnique::XForwardedHost)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == DirectAccessTechnique::XOriginalUrl)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == DirectAccessTechnique::XRewriteUrl)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == DirectAccessTechnique::InternalIpAccess)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == DirectAccessTechnique::AlternatePort)
    );
}

#[test]
fn direct_access_probes_include_internal_ips() {
    let probes = generate_direct_access_probes("https://api.example.com", &[]);
    let internal_probes: Vec<_> = probes
        .iter()
        .filter(|p| p.technique == DirectAccessTechnique::InternalIpAccess)
        .collect();
    assert!(internal_probes.len() >= 4);
    assert!(internal_probes.iter().any(|p| p.host_header == "127.0.0.1"));
    assert!(internal_probes.iter().any(|p| p.host_header == "10.0.0.1"));
}

#[test]
fn direct_access_probes_include_alternate_ports() {
    let probes = generate_direct_access_probes("https://api.example.com/v1", &[]);
    let port_probes: Vec<_> = probes
        .iter()
        .filter(|p| p.technique == DirectAccessTechnique::AlternatePort)
        .collect();
    assert!(port_probes.len() >= 5);
    assert!(port_probes.iter().any(|p| p.host_header.contains("8080")));
}

#[test]
fn evaluate_direct_access_bypass_detected() {
    let probe = &generate_direct_access_probes("https://api.example.com", &["backend.internal"])[0];
    let result = evaluate_direct_access(probe, 403, 200);
    assert!(result.bypassed);
    assert_eq!(result.severity, GatewayBypassSeverity::Critical);
    assert_eq!(result.gateway_status, Some(403));
    assert_eq!(result.direct_status, Some(200));
}

#[test]
fn evaluate_direct_access_no_bypass() {
    let probe = &generate_direct_access_probes("https://api.example.com", &["backend.internal"])[0];
    let result = evaluate_direct_access(probe, 200, 200);
    assert!(!result.bypassed);
}

#[test]
fn evaluate_direct_access_both_blocked() {
    let probe = &generate_direct_access_probes("https://api.example.com", &["backend.internal"])[0];
    let result = evaluate_direct_access(probe, 403, 403);
    assert!(!result.bypassed);
}

#[test]
fn path_norm_payloads_generated() {
    let payloads = generate_path_norm_payloads("/admin/dashboard");
    assert!(payloads.len() >= 10);
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::DotSegmentTraversal)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::DoubleUrlEncoding)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::UnicodeNormalization)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::BackslashSubstitution)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::NullByteInjection)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::SemicolonPathParam)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::CaseSwitching)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.technique == PathNormTechnique::DoubleSlash)
    );
}

#[test]
fn path_norm_dot_segment_payload_correct() {
    let payloads = generate_path_norm_payloads("/admin/secret");
    let dot_seg = payloads
        .iter()
        .find(|p| p.technique == PathNormTechnique::DotSegmentTraversal)
        .unwrap();
    assert!(dot_seg.manipulated_path.contains("/../"));
    assert!(dot_seg.manipulated_path.contains("admin/secret"));
}

#[test]
fn path_norm_double_encoding_payload() {
    let payloads = generate_path_norm_payloads("/admin");
    let enc = payloads
        .iter()
        .find(|p| p.technique == PathNormTechnique::DoubleUrlEncoding)
        .unwrap();
    assert!(enc.manipulated_path.contains("%252f"));
}

#[test]
fn path_norm_case_switching() {
    let payloads = generate_path_norm_payloads("/admin");
    let case_sw = payloads
        .iter()
        .find(|p| p.technique == PathNormTechnique::CaseSwitching)
        .unwrap();
    assert_ne!(case_sw.manipulated_path, "/admin");
}

#[test]
fn evaluate_path_norm_bypass_detected() {
    let probe = &generate_path_norm_payloads("/admin")[0];
    let result = evaluate_path_norm(probe, true, true);
    assert!(result.bypassed);
    assert_eq!(result.severity, GatewayBypassSeverity::Critical);
}

#[test]
fn evaluate_path_norm_no_bypass_gateway_allows() {
    let probe = &generate_path_norm_payloads("/admin")[0];
    let result = evaluate_path_norm(probe, false, true);
    assert!(!result.bypassed);
    assert_eq!(result.severity, GatewayBypassSeverity::Info);
}

#[test]
fn evaluate_path_norm_no_bypass_backend_blocks() {
    let probe = &generate_path_norm_payloads("/admin")[0];
    let result = evaluate_path_norm(probe, true, false);
    assert!(!result.bypassed);
}

#[test]
fn rate_limit_bypass_probes_generated() {
    let probes = generate_rate_limit_bypass_probes();
    assert!(probes.len() >= 7);
    assert!(
        probes
            .iter()
            .any(|p| p.technique == RateLimitBypassTechnique::XForwardedForRotation)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == RateLimitBypassTechnique::HttpMethodSwitch)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.technique == RateLimitBypassTechnique::OriginIpRotation)
    );
}

#[test]
fn rate_limit_probes_have_header_payloads() {
    let probes = generate_rate_limit_bypass_probes();
    for probe in &probes {
        assert!(!probe.header_payload.is_empty());
    }
}

#[test]
fn rate_limit_origin_rotation_has_multiple_headers() {
    let probes = generate_rate_limit_bypass_probes();
    let origin = probes
        .iter()
        .find(|p| p.technique == RateLimitBypassTechnique::OriginIpRotation)
        .unwrap();
    assert!(origin.header_payload.len() >= 2);
}

#[test]
fn evaluate_rate_limit_bypass_confirmed() {
    let probe = &generate_rate_limit_bypass_probes()[0];
    let result = evaluate_rate_limit_bypass(probe, 100, 500);
    assert!(result.bypassed);
    assert_eq!(result.severity, GatewayBypassSeverity::Critical);
}

#[test]
fn evaluate_rate_limit_bypass_not_bypassed() {
    let probe = &generate_rate_limit_bypass_probes()[0];
    let result = evaluate_rate_limit_bypass(probe, 100, 50);
    assert!(!result.bypassed);
}

#[test]
fn auth_forwarding_probes_generated() {
    let probes = generate_auth_forwarding_probes("Bearer eyJhbGciOiJSUzI1NiJ9.test.sig");
    assert!(probes.len() >= 7);
    assert!(
        probes
            .iter()
            .any(|p| p.issue_type == AuthForwardingIssue::TokenPassthrough)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.issue_type == AuthForwardingIssue::InternalHeaderInjection)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.issue_type == AuthForwardingIssue::AuthBypassViaHop)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.issue_type == AuthForwardingIssue::SessionFixationViaGateway)
    );
    assert!(
        probes
            .iter()
            .any(|p| p.issue_type == AuthForwardingIssue::CredentialLeakInProxy)
    );
}

#[test]
fn auth_forwarding_internal_header_injection_critical() {
    let probes = generate_auth_forwarding_probes("Bearer tok");
    let internal: Vec<_> = probes
        .iter()
        .filter(|p| p.issue_type == AuthForwardingIssue::InternalHeaderInjection)
        .collect();
    assert!(internal.len() >= 4);
    for probe in &internal {
        assert_eq!(probe.severity, GatewayBypassSeverity::Critical);
    }
}

#[test]
fn auth_forwarding_probes_contain_auth_header() {
    let token = "Bearer super_secret_token";
    let probes = generate_auth_forwarding_probes(token);
    let passthrough = probes
        .iter()
        .find(|p| p.issue_type == AuthForwardingIssue::TokenPassthrough)
        .unwrap();
    assert!(
        passthrough
            .proof_headers
            .get("Authorization")
            .unwrap()
            .contains("super_secret_token")
    );
}

#[test]
fn full_analysis_generates_all_categories() {
    let findings = run_gateway_bypass_analysis(
        "https://api.example.com",
        &["backend.internal"],
        &["/admin"],
        Some("Bearer token123"),
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == GatewayBypassCategory::DirectBackendAccess)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == GatewayBypassCategory::PathNormalizationDiff)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == GatewayBypassCategory::RateLimitBypass)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == GatewayBypassCategory::AuthForwardingIssue)
    );
}

#[test]
fn full_analysis_without_auth_skips_auth_findings() {
    let findings = run_gateway_bypass_analysis(
        "https://api.example.com",
        &["backend.internal"],
        &["/admin"],
        None,
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.category == GatewayBypassCategory::AuthForwardingIssue)
    );
}

#[test]
fn full_analysis_multiple_restricted_paths() {
    let findings = run_gateway_bypass_analysis(
        "https://api.example.com",
        &[],
        &["/admin", "/internal", "/debug"],
        None,
    );
    let norm_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == GatewayBypassCategory::PathNormalizationDiff)
        .collect();
    assert!(norm_findings.len() >= 30);
}

#[test]
fn display_impls_produce_expected_strings() {
    assert_eq!(format!("{}", GatewayBypassSeverity::Critical), "Critical");
    assert_eq!(
        format!("{}", DirectAccessTechnique::HostHeaderOverride),
        "Host Header Override"
    );
    assert_eq!(
        format!("{}", PathNormTechnique::DoubleUrlEncoding),
        "Double URL Encoding"
    );
    assert_eq!(
        format!("{}", RateLimitBypassTechnique::XForwardedForRotation),
        "X-Forwarded-For Rotation"
    );
    assert_eq!(
        format!("{}", AuthForwardingIssue::TokenPassthrough),
        "Token Passthrough"
    );
    assert_eq!(
        format!("{}", GatewayBypassCategory::DirectBackendAccess),
        "Direct Backend Access"
    );
    assert_eq!(
        format!("{}", PathNormTechnique::TrailingDotSegment),
        "Trailing Dot Segment"
    );
    assert_eq!(
        format!("{}", RateLimitBypassTechnique::HttpMethodSwitch),
        "HTTP Method Switch"
    );
}

#[test]
fn path_norm_semicolon_payload() {
    let payloads = generate_path_norm_payloads("/admin/secret");
    let semi = payloads
        .iter()
        .find(|p| p.technique == PathNormTechnique::SemicolonPathParam)
        .unwrap();
    assert!(semi.manipulated_path.contains(";bypass=true"));
}

#[test]
fn path_norm_null_byte_payload() {
    let payloads = generate_path_norm_payloads("/admin/secret");
    let null_byte = payloads
        .iter()
        .find(|p| p.technique == PathNormTechnique::NullByteInjection)
        .unwrap();
    assert!(null_byte.manipulated_path.contains("%00"));
}

#[test]
fn path_norm_double_slash_payload() {
    let payloads = generate_path_norm_payloads("/admin/secret");
    let ds = payloads
        .iter()
        .find(|p| p.technique == PathNormTechnique::DoubleSlash)
        .unwrap();
    assert!(ds.manipulated_path.contains("//"));
}
