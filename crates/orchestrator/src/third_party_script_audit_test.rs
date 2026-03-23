use crate::third_party_script_audit::*;

#[test]
fn empty_html_no_issues() {
    assert!(analyze_third_party_scripts("", "example.com").is_empty());
}

#[test]
fn same_site_script_no_issue() {
    let html = r#"<script src="https://example.com/app.js"></script>"#;
    assert!(analyze_third_party_scripts(html, "example.com").is_empty());
}

#[test]
fn subdomain_same_site_no_issue() {
    let html = r#"<script src="https://cdn.example.com/app.js"></script>"#;
    assert!(analyze_third_party_scripts(html, "example.com").is_empty());
}

#[test]
fn tracker_script_detected() {
    let html =
        r#"<script src="https://www.google-analytics.com/analytics.js"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::TrackerScript { .. })));
}

#[test]
fn facebook_tracker_detected() {
    let html = r#"<script src="https://connect.facebook.net/en_US/fbevents.js"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::TrackerScript { .. })));
}

#[test]
fn unknown_cdn_detected() {
    let html = r#"<script src="https://evil-cdn.example.net/lib.js"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::UnknownCdnScript { .. })));
}

#[test]
fn trusted_cdn_not_flagged_as_unknown() {
    let html =
        r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js" integrity="sha256-xxx"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::UnknownCdnScript { .. })));
}

#[test]
fn http_script_detected() {
    let html = r#"<script src="http://cdn.example.net/lib.js"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::HttpScript { .. })));
}

#[test]
fn no_sri_detected() {
    let html = r#"<script src="https://cdn.jsdelivr.net/npm/vue@3"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::NoSubresourceIntegrity { .. })));
}

#[test]
fn with_sri_not_flagged() {
    let html = r#"<script src="https://cdn.jsdelivr.net/npm/vue@3" integrity="sha384-abc"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::NoSubresourceIntegrity { .. })));
}

#[test]
fn protocol_relative_url() {
    let html = r#"<script src="//evil-cdn.example.net/lib.js"></script>"#;
    let issues = analyze_third_party_scripts(html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::UnknownCdnScript { .. })));
}

#[test]
fn inline_script_ignored() {
    let html = r#"<script>console.log('hello');</script>"#;
    assert!(analyze_third_party_scripts(html, "example.com").is_empty());
}

#[test]
fn relative_path_ignored() {
    let html = r#"<script src="/js/app.js"></script>"#;
    assert!(analyze_third_party_scripts(html, "example.com").is_empty());
}

#[test]
fn excessive_third_party_detected() {
    let mut html = String::new();
    for i in 0..12 {
        html.push_str(&format!(
            r#"<script src="https://domain{i}.example.net/lib.js"></script>"#
        ));
    }
    let issues = analyze_third_party_scripts(&html, "example.com");
    assert!(issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::ExcessiveThirdParty { count } if *count > 10)));
}

#[test]
fn not_excessive_under_threshold() {
    let mut html = String::new();
    for i in 0..5 {
        html.push_str(&format!(
            r#"<script src="https://domain{i}.example.net/lib.js"></script>"#
        ));
    }
    let issues = analyze_third_party_scripts(&html, "example.com");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ThirdPartyScriptIssue::ExcessiveThirdParty { .. })));
}

#[test]
fn severity_ordering() {
    assert!(
        third_party_script_severity(&ThirdPartyScriptIssue::HttpScript {
            url: "x".into()
        }) > third_party_script_severity(&ThirdPartyScriptIssue::UnknownCdnScript {
            domain: "x".into()
        })
    );
    assert!(
        third_party_script_severity(&ThirdPartyScriptIssue::UnknownCdnScript {
            domain: "x".into()
        }) > third_party_script_severity(&ThirdPartyScriptIssue::TrackerScript {
            domain: "x".into()
        })
    );
}

#[test]
fn display_format() {
    let issue = ThirdPartyScriptIssue::TrackerScript {
        domain: "google-analytics.com".into(),
    };
    assert_eq!(issue.to_string(), "tracker_script:google-analytics.com");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        ThirdPartyScriptIssue::TrackerScript {
            domain: "x".into(),
        },
        ThirdPartyScriptIssue::HttpScript {
            url: "y".into(),
        },
    ];
    let mut seq = 0;
    let ops = third_party_script_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}
