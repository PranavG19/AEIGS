use crate::iframe_audit::{
    IframeIssue, analyze_iframes, iframe_findings_to_operations, iframe_severity,
};

// --- Detection tests ---

#[test]
fn detects_missing_sandbox() {
    let html = r#"<iframe src="https://example.com/embed"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingSandbox { .. }))
    );
}

#[test]
fn accepts_iframe_with_empty_sandbox() {
    let html = r#"<iframe src="/local" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingSandbox { .. }))
    );
}

#[test]
fn detects_overly_permissive_sandbox() {
    let html =
        r#"<iframe src="/x" sandbox="allow-scripts allow-top-navigation allow-popups"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::OverlyPermissiveSandbox { .. }))
    );
}

#[test]
fn allows_limited_sandbox_flags() {
    let html = r#"<iframe src="/x" sandbox="allow-scripts"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::OverlyPermissiveSandbox { .. }))
    );
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::AllowScriptsAndSameOrigin { .. }))
    );
}

#[test]
fn detects_allow_scripts_and_same_origin() {
    let html = r#"<iframe src="/x" sandbox="allow-scripts allow-same-origin"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::AllowScriptsAndSameOrigin { .. }))
    );
}

#[test]
fn scripts_and_same_origin_takes_priority_over_permissive() {
    let html = r#"<iframe src="/x" sandbox="allow-scripts allow-same-origin allow-top-navigation allow-popups"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::AllowScriptsAndSameOrigin { .. }))
    );
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::OverlyPermissiveSandbox { .. }))
    );
}

#[test]
fn detects_http_source() {
    let html = r#"<iframe src="http://insecure.example.com/embed" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::HttpSource { .. }))
    );
}

#[test]
fn detects_external_source_https() {
    let html = r#"<iframe src="https://external.example.com/embed" sandbox="" title="t" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::ExternalSource { .. }))
    );
}

#[test]
fn detects_external_source_http() {
    let html = r#"<iframe src="http://external.example.com/embed" sandbox="" title="t" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::ExternalSource { .. }))
    );
}

#[test]
fn no_external_for_relative_src() {
    let html =
        r#"<iframe src="/local/embed" sandbox="" title="t" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::ExternalSource { .. }))
    );
}

#[test]
fn detects_missing_title_on_external() {
    let html = r#"<iframe src="https://example.com/embed" sandbox="" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingTitle { .. }))
    );
}

#[test]
fn no_missing_title_when_present() {
    let html = r#"<iframe src="https://example.com/embed" sandbox="" title="Embed" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingTitle { .. }))
    );
}

#[test]
fn no_missing_title_for_local_src() {
    let html = r#"<iframe src="/local" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingTitle { .. }))
    );
}

#[test]
fn detects_data_uri_source() {
    let html = r#"<iframe src="data:text/html;base64,PGgxPmhlbGxvPC9oMT4=" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::DataUriSource))
    );
}

#[test]
fn detects_javascript_uri_source() {
    let html = r#"<iframe src="javascript:alert(1)" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::JavascriptUriSource))
    );
}

#[test]
fn detects_blob_source() {
    let html = r#"<iframe src="blob:https://example.com/abc-123" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::BlobSource { .. }))
    );
}

#[test]
fn detects_srcdoc_with_script_tag() {
    let html = "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\" sandbox=\"\"></iframe>";
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::SrcdocWithScript))
    );
}

#[test]
fn detects_srcdoc_with_onerror() {
    let html = r#"<iframe srcdoc="&lt;img onerror=alert(1)&gt;" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::SrcdocWithScript))
    );
}

#[test]
fn detects_srcdoc_with_onload() {
    let html = r#"<iframe srcdoc="&lt;body onload=alert(1)&gt;" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::SrcdocWithScript))
    );
}

#[test]
fn clean_srcdoc_no_finding() {
    let html = r#"<iframe srcdoc="<p>hello</p>" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::SrcdocWithScript))
    );
}

#[test]
fn detects_lazy_load_cross_origin() {
    let html = r#"<iframe src="https://example.com/embed" loading="lazy" sandbox="" title="t" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::LazyLoadCrossOrigin { .. }))
    );
}

#[test]
fn no_lazy_load_for_local_src() {
    let html = r#"<iframe src="/local" loading="lazy" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::LazyLoadCrossOrigin { .. }))
    );
}

#[test]
fn no_lazy_load_when_eager() {
    let html = r#"<iframe src="https://example.com/embed" loading="eager" sandbox="" title="t" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::LazyLoadCrossOrigin { .. }))
    );
}

#[test]
fn detects_missing_referrer_policy() {
    let html = r#"<iframe src="https://example.com/embed" sandbox="" title="t"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingReferrerPolicy { .. }))
    );
}

#[test]
fn no_missing_referrer_policy_when_present() {
    let html = r#"<iframe src="https://example.com/embed" sandbox="" title="t" referrerpolicy="no-referrer"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingReferrerPolicy { .. }))
    );
}

#[test]
fn no_missing_referrer_policy_for_local_src() {
    let html = r#"<iframe src="/local" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingReferrerPolicy { .. }))
    );
}

// --- Edge cases ---

#[test]
fn no_iframes_no_findings() {
    let html = r#"<html><body><p>No iframes</p></body></html>"#;
    let findings = analyze_iframes(html);
    assert!(findings.is_empty());
}

#[test]
fn self_closing_iframe() {
    let html = r#"<iframe src="https://example.com/embed" />"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingSandbox { .. }))
    );
}

#[test]
fn multiple_iframes_each_analyzed() {
    let html = r#"
        <iframe src="https://a.example.com" sandbox="" title="a" referrerpolicy="no-referrer"></iframe>
        <iframe src="https://b.example.com" sandbox="" title="b" referrerpolicy="no-referrer"></iframe>
    "#;
    let findings = analyze_iframes(html);
    let external_count = findings
        .iter()
        .filter(|f| matches!(f, IframeIssue::ExternalSource { .. }))
        .count();
    assert_eq!(external_count, 2);
}

#[test]
fn multiple_issues_on_same_iframe() {
    let html = r#"<iframe src="http://insecure.example.com/embed"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::MissingSandbox { .. }))
    );
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::HttpSource { .. }))
    );
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::ExternalSource { .. }))
    );
}

#[test]
fn data_uri_case_insensitive() {
    let html = r#"<iframe src="DATA:text/html;base64,PGgxPmhpPC9oMT4=" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::DataUriSource))
    );
}

#[test]
fn javascript_uri_case_insensitive() {
    let html = r#"<iframe src="JavaScript:void(0)" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, IframeIssue::JavascriptUriSource))
    );
}

// --- Display tests ---

#[test]
fn display_missing_sandbox() {
    let issue = IframeIssue::MissingSandbox { src: String::new() };
    assert_eq!(issue.to_string(), "missing_sandbox");
}

#[test]
fn display_overly_permissive_sandbox() {
    let issue = IframeIssue::OverlyPermissiveSandbox {
        src: String::new(),
        flags: String::new(),
    };
    assert_eq!(issue.to_string(), "overly_permissive_sandbox");
}

#[test]
fn display_allow_scripts_and_same_origin() {
    let issue = IframeIssue::AllowScriptsAndSameOrigin { src: String::new() };
    assert_eq!(issue.to_string(), "allow_scripts_and_same_origin");
}

#[test]
fn display_http_source() {
    let issue = IframeIssue::HttpSource { src: String::new() };
    assert_eq!(issue.to_string(), "http_source");
}

#[test]
fn display_external_source() {
    let issue = IframeIssue::ExternalSource { src: String::new() };
    assert_eq!(issue.to_string(), "external_source");
}

#[test]
fn display_missing_title() {
    let issue = IframeIssue::MissingTitle { src: String::new() };
    assert_eq!(issue.to_string(), "missing_title");
}

#[test]
fn display_data_uri_source() {
    assert_eq!(IframeIssue::DataUriSource.to_string(), "data_uri_source");
}

#[test]
fn display_javascript_uri_source() {
    assert_eq!(
        IframeIssue::JavascriptUriSource.to_string(),
        "javascript_uri_source"
    );
}

#[test]
fn display_blob_source() {
    let issue = IframeIssue::BlobSource { src: String::new() };
    assert_eq!(issue.to_string(), "blob_source");
}

#[test]
fn display_srcdoc_with_script() {
    assert_eq!(
        IframeIssue::SrcdocWithScript.to_string(),
        "srcdoc_with_script"
    );
}

#[test]
fn display_lazy_load_cross_origin() {
    let issue = IframeIssue::LazyLoadCrossOrigin { src: String::new() };
    assert_eq!(issue.to_string(), "lazy_load_cross_origin");
}

#[test]
fn display_missing_referrer_policy() {
    let issue = IframeIssue::MissingReferrerPolicy { src: String::new() };
    assert_eq!(issue.to_string(), "missing_referrer_policy");
}

// --- Severity tests ---

#[test]
fn severity_missing_sandbox() {
    assert_eq!(
        iframe_severity(&IframeIssue::MissingSandbox { src: String::new() }),
        4.5
    );
}

#[test]
fn severity_overly_permissive_sandbox() {
    assert_eq!(
        iframe_severity(&IframeIssue::OverlyPermissiveSandbox {
            src: String::new(),
            flags: String::new()
        }),
        3.5
    );
}

#[test]
fn severity_allow_scripts_and_same_origin() {
    assert_eq!(
        iframe_severity(&IframeIssue::AllowScriptsAndSameOrigin { src: String::new() }),
        6.0
    );
}

#[test]
fn severity_http_source() {
    assert_eq!(
        iframe_severity(&IframeIssue::HttpSource { src: String::new() }),
        5.0
    );
}

#[test]
fn severity_external_source() {
    assert_eq!(
        iframe_severity(&IframeIssue::ExternalSource { src: String::new() }),
        2.0
    );
}

#[test]
fn severity_missing_title() {
    assert_eq!(
        iframe_severity(&IframeIssue::MissingTitle { src: String::new() }),
        1.0
    );
}

#[test]
fn severity_data_uri() {
    assert_eq!(iframe_severity(&IframeIssue::DataUriSource), 7.0);
}

#[test]
fn severity_javascript_uri() {
    assert_eq!(iframe_severity(&IframeIssue::JavascriptUriSource), 8.0);
}

#[test]
fn severity_blob_source() {
    assert_eq!(
        iframe_severity(&IframeIssue::BlobSource { src: String::new() }),
        4.0
    );
}

#[test]
fn severity_srcdoc_with_script() {
    assert_eq!(iframe_severity(&IframeIssue::SrcdocWithScript), 7.5);
}

#[test]
fn severity_lazy_load_cross_origin() {
    assert_eq!(
        iframe_severity(&IframeIssue::LazyLoadCrossOrigin { src: String::new() }),
        2.5
    );
}

#[test]
fn severity_missing_referrer_policy() {
    assert_eq!(
        iframe_severity(&IframeIssue::MissingReferrerPolicy { src: String::new() }),
        2.0
    );
}

// --- Operations tests ---

#[test]
fn operations_empty_when_no_findings() {
    let mut seq = 0;
    let ops = iframe_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_per_finding() {
    let findings = vec![
        IframeIssue::MissingSandbox {
            src: "https://example.com".to_string(),
        },
        IframeIssue::HttpSource {
            src: "http://example.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = iframe_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_sequence_increments() {
    let findings = vec![
        IframeIssue::DataUriSource,
        IframeIssue::JavascriptUriSource,
        IframeIssue::SrcdocWithScript,
    ];
    let mut seq = 10;
    let ops = iframe_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
